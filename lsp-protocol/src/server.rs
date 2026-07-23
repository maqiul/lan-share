//! LSP v3.0 服务端（UDP 传输）

use crate::crypto::{aead, KeyPair, SessionKeys};
use crate::diff_transfer::{DeltaComputer, FileSignature};
use crate::error::{LspError, Result};
use crate::protocol::*;
use crate::transport::UdpConnection;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// 服务端配置
pub struct ServerConfig {
    pub device_id: String,
    pub device_name: String,
    pub shared_dir: PathBuf,
    pub pin: String,
    pub max_streams: u32,
    pub max_frame_size: u32,
    pub use_encryption: bool,
    pub use_compression: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            device_id: Uuid::new_v4().to_string(),
            device_name: "LSP-Server".to_string(),
            shared_dir: PathBuf::from("./shared"),
            pin: "123456".to_string(),
            max_streams: 64,
            max_frame_size: MAX_FRAME_SIZE as u32,
            use_encryption: true,
            use_compression: true,
        }
    }
}

/// 会话状态
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionState { Hello, Authenticating, Established, Closing, Closed }

/// 流信息
pub struct StreamState {
    pub id: u32,
    pub stream_type: String,
    pub state: StreamLifecycle,
    pub send_window: u32,
    pub recv_window: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamLifecycle { Opening, Open, Closing, Closed }

/// 会话信息
pub struct Session {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub state: SessionState,
    pub permission: String,
    pub streams: HashMap<u32, StreamState>,
    pub next_stream_seq: HashMap<u32, u32>,
    pub session_keys: Option<SessionKeys>,
    pub capabilities: Vec<String>,
}

/// 文件锁
pub struct FileLock {
    pub path: String,
    pub session_id: String,
    pub mode: String,
    pub expires_at: i64,
}

/// LSP v3.0 服务端
pub struct LspServer {
    config: ServerConfig,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    file_locks: Arc<RwLock<HashMap<String, FileLock>>>,
}

impl LspServer {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            file_locks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 启动 UDP 服务端
    pub async fn serve(&self, addr: &str) -> Result<()> {
        let socket = crate::transport::bind_udp_socket(addr).await?;
        let socket = Arc::new(socket);
        info!("LSP UDP server listening on {}", addr);

        // 每个 peer 的消息通道
        let peer_channels: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let mut buf = [0u8; 65535];
        loop {
            let (len, src_addr) = socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();

            let channels = peer_channels.read().await;
            if let Some(tx) = channels.get(&src_addr) {
                // 已有 peer，转发数据
                let _ = tx.try_send(data);
            } else {
                drop(channels);
                // 新 peer，创建通道和处理任务
                let (tx, rx) = mpsc::channel(512);
                let _ = tx.try_send(data);
                peer_channels.write().await.insert(src_addr, tx);

                let socket_clone = socket.clone();
                let sessions = self.sessions.clone();
                let file_locks = self.file_locks.clone();
                let config = ServerConfig {
                    device_id: self.config.device_id.clone(),
                    device_name: self.config.device_name.clone(),
                    shared_dir: self.config.shared_dir.clone(),
                    pin: self.config.pin.clone(),
                    max_streams: self.config.max_streams,
                    max_frame_size: self.config.max_frame_size,
                    use_encryption: self.config.use_encryption,
                    use_compression: self.config.use_compression,
                };
                let channels_clone = peer_channels.clone();

                tokio::spawn(async move {
                    let conn = UdpConnection::from_peer(
                        socket_clone, src_addr, rx,
                        config.use_encryption, config.use_compression,
                    );
                    let conn = Arc::new(conn);
                    let retransmit_handle = UdpConnection::spawn_retransmit_timer(conn.clone());

                    let result = Self::handle_peer(
                        &conn, &config, &sessions, &file_locks,
                    ).await;

                    retransmit_handle.abort();

                    if let Err(e) = result {
                        warn!("Peer {} handler error: {}", src_addr, e);
                    }

                    // 清理
                    channels_clone.write().await.remove(&src_addr);
                    info!("Peer {} disconnected", src_addr);
                });
            }
        }
    }

    /// 处理单个 peer 的所有帧
    async fn handle_peer(
        conn: &UdpConnection,
        config: &ServerConfig,
        sessions: &Arc<RwLock<HashMap<String, Session>>>,
        file_locks: &Arc<RwLock<HashMap<String, FileLock>>>,
    ) -> Result<()> {
        let peer_addr = conn.peer_addr();
        info!("New peer: {}", peer_addr);

        let mut session_id = String::new();
        let key_pair = KeyPair::generate();
        let mut write_streams: std::collections::HashMap<u32, String> = std::collections::HashMap::new();

        loop {
            let frame = match conn.recv_frame().await {
                Ok(f) => f,
                Err(LspError::ConnectionClosed) => break,
                Err(e) => {
                    warn!("Recv error from {}: {}", peer_addr, e);
                    break;
                }
            };

            debug!("Received {:?} from {}", frame.frame_type, peer_addr);

            let responses = match frame.frame_type {
                FrameType::Hello => {
                    Self::handle_hello(&frame, &mut session_id, config, sessions).await?
                }
                FrameType::AuthInit => {
                    Self::handle_auth_init(&frame, &session_id, &key_pair, sessions).await?
                }
                FrameType::AuthResponse => {
                    Self::handle_auth_response(&frame, &session_id, config, sessions).await?
                }
                FrameType::StreamOpen => {
                    Self::handle_stream_open(&frame, &session_id, sessions).await?
                }
                FrameType::StreamClose => {
                    Self::handle_stream_close(&frame, &session_id, sessions).await?
                }
                FrameType::FileList => {
                    Self::handle_file_list(&frame, config).await?
                }
                FrameType::FileStat => {
                    Self::handle_file_stat(&frame, config).await?
                }
                FrameType::FileMkdir => {
                    Self::handle_file_mkdir(&frame, config).await?
                }
                FrameType::FileRename => {
                    Self::handle_file_rename(&frame, config).await?
                }
                FrameType::FileDelete => {
                    Self::handle_file_delete(&frame, config).await?
                }
                FrameType::ReadReq => {
                    Self::handle_read_req(&frame, config).await?
                }
                FrameType::WriteReq => {
                    Self::handle_write_req(&frame, &session_id, config, file_locks, &mut write_streams).await?
                }
                FrameType::WriteData => {
                    Self::handle_write_data(&frame, config, &write_streams).await?
                }
                FrameType::WriteCommit => {
                    Self::handle_write_commit(&frame, config, &mut write_streams).await?
                }
                FrameType::DeltaSync => {
                    Self::handle_delta_sync(&frame, config, &DeltaComputer::default()).await?
                }
                FrameType::DeltaData => {
                    Self::handle_delta_data(&frame, config, &DeltaComputer::default()).await?
                }
                FrameType::WindowUpdate => {
                    Self::handle_window_update(&frame, &session_id, sessions).await?
                }
                FrameType::Keepalive => {
                    vec![Frame::new(FrameType::KeepaliveAck, 0, 0, Bytes::new())]
                }
                FrameType::Goodbye => {
                    info!("Client {} sent GOODBYE", peer_addr);
                    break;
                }
                FrameType::Ack => vec![],
                _ => {
                    warn!("Unhandled frame type: {:?}", frame.frame_type);
                    vec![]
                }
            };

            for resp in responses {
                if let Err(e) = conn.send_frame(resp).await {
                    error!("Send error to {}: {}", peer_addr, e);
                    break;
                }
            }

            // AuthChallenge 发出后才激活加密（客户端此时也刚算出密钥）
            if frame.frame_type == FrameType::AuthInit {
                let sessions_guard = sessions.read().await;
                if let Some(session) = sessions_guard.get(&session_id) {
                    if let Some(ref keys) = session.session_keys {
                        conn.set_session_keys(keys.clone()).await;
                    }
                }
            }
        }

        // 清理会话
        if !session_id.is_empty() {
            sessions.write().await.remove(&session_id);
        }

        info!("Connection closed: {}", peer_addr);
        Ok(())
    }

    // 帧处理器

    async fn handle_hello(
        frame: &Frame, session_id: &mut String,
        config: &ServerConfig, sessions: &Arc<RwLock<HashMap<String, Session>>>,
    ) -> Result<Vec<Frame>> {
        let payload: HelloPayload = serde_json::from_slice(&frame.payload)?;
        info!("Hello from {} ({})", payload.device_info.name, payload.device_info.id);

        *session_id = Uuid::new_v4().to_string();

        let mut server_caps = vec![
            "stream_multiplex".to_string(), "file_watch".to_string(), "resume".to_string(),
        ];
        if config.use_encryption { server_caps.push("encryption".to_string()); }
        if config.use_compression { server_caps.push("compression".to_string()); }
        server_caps.push("delta_sync".to_string());
        server_caps.push("reliable_transport".to_string());

        let negotiated: Vec<String> = payload.capabilities.iter()
            .filter(|c| server_caps.contains(c)).cloned().collect();

        let session = Session {
            id: session_id.clone(),
            device_id: payload.device_info.id.clone(),
            device_name: payload.device_info.name.clone(),
            state: SessionState::Hello,
            permission: "none".to_string(),
            streams: HashMap::new(),
            next_stream_seq: HashMap::new(),
            session_keys: None,
            capabilities: negotiated.clone(),
        };

        sessions.write().await.insert(session_id.clone(), session);

        let ack = HelloAckPayload {
            version: PROTOCOL_VERSION,
            capabilities: negotiated,
            max_streams: config.max_streams,
            max_frame_size: config.max_frame_size,
            session_id: session_id.clone(),
        };

        Ok(vec![Frame::new(FrameType::HelloAck, 0, 0,
            Bytes::from(serde_json::to_vec(&ack)?))])
    }

    async fn handle_auth_init(
        frame: &Frame, session_id: &str, key_pair: &KeyPair,
        sessions: &Arc<RwLock<HashMap<String, Session>>>,
    ) -> Result<Vec<Frame>> {
        let payload: AuthInitPayload = serde_json::from_slice(&frame.payload)?;

        let client_pubkey_bytes = hex::decode(&payload.client_pubkey)
            .map_err(|e| LspError::Auth(format!("Invalid client pubkey: {}", e)))?;
        let mut client_pubkey = [0u8; 32];
        if client_pubkey_bytes.len() == 32 {
            client_pubkey.copy_from_slice(&client_pubkey_bytes);
        }

        // 真正的 X25519 ECDH
        let shared_secret = key_pair.compute_shared_secret(&client_pubkey);

        let handshake_hash = Sha256::digest(
            [&client_pubkey[..], &key_pair.public_key[..]].concat()
        );
        let mut hh = [0u8; 32];
        hh.copy_from_slice(&handshake_hash);
        let keys = SessionKeys::derive(&shared_secret, &hh);

        // 生成挑战
        let nonce = aead::generate_nonce();
        let challenge_data = b"lsp-auth-challenge";
        let (encrypted_challenge, _tag) = aead::encrypt(
            &keys.server_write_key, &nonce, b"", challenge_data,
        );

        let challenge = AuthChallengePayload {
            server_pubkey: hex::encode(&key_pair.public_key),
            nonce: hex::encode(nonce),
            encrypted_challenge: hex::encode(encrypted_challenge),
        };

        {
            let mut sessions = sessions.write().await;
            if let Some(session) = sessions.get_mut(session_id) {
                session.state = SessionState::Authenticating;
                session.session_keys = Some(keys);
            }
        }

        Ok(vec![Frame::new(FrameType::AuthChallenge, 0, 0,
            Bytes::from(serde_json::to_vec(&challenge)?))])
    }

    async fn handle_auth_response(
        frame: &Frame, session_id: &str,
        config: &ServerConfig, sessions: &Arc<RwLock<HashMap<String, Session>>>,
    ) -> Result<Vec<Frame>> {
        let payload: AuthResponsePayload = serde_json::from_slice(&frame.payload)?;

        let pin_hash = hex::encode(Sha256::digest(config.pin.as_bytes()));

        if payload.pin_proof != pin_hash {
            let fail = AuthFailPayload {
                reason: "Invalid PIN".to_string(),
                error_code: 0x02,
            };
            return Ok(vec![Frame::new(FrameType::AuthFail, 0, 0,
                Bytes::from(serde_json::to_vec(&fail)?))]);
        }

        let ok = AuthOkPayload {
            permission: "readwrite".to_string(),
            server_proof: "ok".to_string(),
        };

        {
            let mut sessions = sessions.write().await;
            if let Some(session) = sessions.get_mut(session_id) {
                session.state = SessionState::Established;
                session.permission = "readwrite".to_string();
                session.device_name = payload.device_name.clone();
            }
        }

        info!("Auth success for {}", payload.device_name);

        Ok(vec![Frame::new(FrameType::AuthOk, 0, 0,
            Bytes::from(serde_json::to_vec(&ok)?))])
    }

    async fn handle_stream_open(
        frame: &Frame, session_id: &str,
        sessions: &Arc<RwLock<HashMap<String, Session>>>,
    ) -> Result<Vec<Frame>> {
        let payload: StreamOpenPayload = serde_json::from_slice(&frame.payload)?;

        let stream_state = StreamState {
            id: frame.stream_id,
            stream_type: payload.stream_type.clone(),
            state: StreamLifecycle::Open,
            send_window: INITIAL_WINDOW_SIZE,
            recv_window: INITIAL_WINDOW_SIZE,
        };

        {
            let mut sessions = sessions.write().await;
            if let Some(session) = sessions.get_mut(session_id) {
                session.streams.insert(frame.stream_id, stream_state);
                session.next_stream_seq.insert(frame.stream_id, 1);
            }
        }

        info!("Stream {} opened (type: {})", frame.stream_id, payload.stream_type);
        Ok(vec![Frame::new(FrameType::StreamOpenAck, frame.stream_id, 0, Bytes::new())])
    }

    async fn handle_stream_close(
        frame: &Frame, session_id: &str,
        sessions: &Arc<RwLock<HashMap<String, Session>>>,
    ) -> Result<Vec<Frame>> {
        {
            let mut sessions = sessions.write().await;
            if let Some(session) = sessions.get_mut(session_id) {
                if let Some(stream) = session.streams.get_mut(&frame.stream_id) {
                    stream.state = StreamLifecycle::Closed;
                }
            }
        }
        info!("Stream {} closed", frame.stream_id);
        Ok(vec![])
    }

    async fn handle_file_list(frame: &Frame, config: &ServerConfig) -> Result<Vec<Frame>> {
        let payload: FileListPayload = serde_json::from_slice(&frame.payload)?;
        let dir_path = config.shared_dir.join(&payload.path);

        let mut entries = Vec::new();
        if dir_path.exists() && dir_path.is_dir() {
            let mut dir_entries = fs::read_dir(&dir_path).await?;
            while let Some(entry) = dir_entries.next_entry().await? {
                let metadata = entry.metadata().await?;
                let name = entry.file_name().to_string_lossy().to_string();
                let path = format!("{}/{}", payload.path, name);

                let created = metadata.created().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64).unwrap_or(0);
                let modified = metadata.modified().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64).unwrap_or(0);
                let accessed = metadata.accessed().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64).unwrap_or(0);

                entries.push(FileEntry {
                    name, path,
                    size: metadata.len(),
                    created, modified, accessed,
                    is_dir: metadata.is_dir(),
                    readonly: metadata.permissions().readonly(),
                    hidden: false, sha256: None, mime_type: None,
                });
            }
        }

        let total = entries.len() as u32;
        let resp = FileListRespPayload { path: payload.path, entries, total, has_more: false };

        Ok(vec![Frame::new(FrameType::FileListResp, frame.stream_id, 1,
            Bytes::from(serde_json::to_vec(&resp)?))])
    }

    async fn handle_file_stat(frame: &Frame, config: &ServerConfig) -> Result<Vec<Frame>> {
        let payload: FileStatPayload = serde_json::from_slice(&frame.payload)?;
        let file_path = config.shared_dir.join(&payload.path);

        if !file_path.exists() {
            let err = ErrorPayload { code: 0x04, message: "File not found".to_string(), stream_id: Some(frame.stream_id) };
            return Ok(vec![Frame::new(FrameType::Error, frame.stream_id, 1,
                Bytes::from(serde_json::to_vec(&err)?))]);
        }

        let metadata = fs::metadata(&file_path).await?;
        let name = file_path.file_name().unwrap().to_string_lossy().to_string();
        let modified = metadata.modified().ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64).unwrap_or(0);

        let entry = FileEntry {
            name, path: payload.path,
            size: metadata.len(),
            created: 0, modified, accessed: 0,
            is_dir: metadata.is_dir(),
            readonly: metadata.permissions().readonly(),
            hidden: false, sha256: None, mime_type: None,
        };

        let resp = FileStatRespPayload { entry };
        Ok(vec![Frame::new(FrameType::FileStatResp, frame.stream_id, 1,
            Bytes::from(serde_json::to_vec(&resp)?))])
    }

    async fn handle_file_mkdir(frame: &Frame, config: &ServerConfig) -> Result<Vec<Frame>> {
        let payload: FileMkdirPayload = serde_json::from_slice(&frame.payload)?;
        let dir_path = config.shared_dir.join(&payload.path);
        fs::create_dir_all(&dir_path).await?;
        info!("Directory created: {}", payload.path);
        Ok(vec![Frame::new(FrameType::Ack, frame.stream_id, 1, Bytes::new())])
    }

    async fn handle_file_rename(frame: &Frame, config: &ServerConfig) -> Result<Vec<Frame>> {
        let payload: FileRenamePayload = serde_json::from_slice(&frame.payload)?;
        let old_path = config.shared_dir.join(&payload.old_path);
        let new_path = config.shared_dir.join(&payload.new_path);

        if !old_path.exists() {
            let err = ErrorPayload { code: 0x04, message: "Source file not found".to_string(), stream_id: Some(frame.stream_id) };
            return Ok(vec![Frame::new(FrameType::Error, frame.stream_id, 1,
                Bytes::from(serde_json::to_vec(&err)?))]);
        }

        fs::rename(&old_path, &new_path).await?;
        info!("Renamed {} -> {}", payload.old_path, payload.new_path);
        Ok(vec![Frame::new(FrameType::Ack, frame.stream_id, 1, Bytes::new())])
    }

    async fn handle_file_delete(frame: &Frame, config: &ServerConfig) -> Result<Vec<Frame>> {
        let payload: FileDeletePayload = serde_json::from_slice(&frame.payload)?;
        let file_path = config.shared_dir.join(&payload.path);

        if !file_path.exists() {
            let err = ErrorPayload { code: 0x04, message: "File not found".to_string(), stream_id: Some(frame.stream_id) };
            return Ok(vec![Frame::new(FrameType::Error, frame.stream_id, 1,
                Bytes::from(serde_json::to_vec(&err)?))]);
        }

        if payload.recursive && file_path.is_dir() {
            fs::remove_dir_all(&file_path).await?;
        } else {
            fs::remove_file(&file_path).await?;
        }

        info!("Deleted: {}", payload.path);
        Ok(vec![Frame::new(FrameType::Ack, frame.stream_id, 1, Bytes::new())])
    }

    async fn handle_read_req(frame: &Frame, config: &ServerConfig) -> Result<Vec<Frame>> {
        let payload: ReadReqPayload = serde_json::from_slice(&frame.payload)?;
        let file_path = config.shared_dir.join(&payload.path);

        if !file_path.exists() {
            let err = ErrorPayload { code: 0x04, message: "File not found".to_string(), stream_id: Some(frame.stream_id) };
            return Ok(vec![Frame::new(FrameType::Error, frame.stream_id, frame.seq_num,
                Bytes::from(serde_json::to_vec(&err)?))]);
        }

        let file_data = fs::read(&file_path).await?;
        let offset = payload.offset as usize;
        let length = if payload.length == 0 { crate::protocol::DEFAULT_CHUNK_SIZE } else { payload.length as usize };
        let end = std::cmp::min(offset + length, file_data.len());

        if offset >= file_data.len() {
            let err = ErrorPayload { code: 0x07, message: "Offset out of range".to_string(), stream_id: Some(frame.stream_id) };
            return Ok(vec![Frame::new(FrameType::Error, frame.stream_id, frame.seq_num,
                Bytes::from(serde_json::to_vec(&err)?))]);
        }

        let chunk = &file_data[offset..end];
        let is_last = end >= file_data.len();

        Ok(vec![Frame::new(FrameType::ReadData, frame.stream_id, frame.seq_num,
            crate::protocol::encode_read_data(payload.offset, is_last, chunk))])
    }

    async fn handle_write_req(
        frame: &Frame, session_id: &str, config: &ServerConfig,
        file_locks: &Arc<RwLock<HashMap<String, FileLock>>>,
        write_streams: &mut std::collections::HashMap<u32, String>,
    ) -> Result<Vec<Frame>> {
        let payload: WriteReqPayload = serde_json::from_slice(&frame.payload)?;
        let file_path = config.shared_dir.join(&payload.path);

        {
            let locks = file_locks.read().await;
            if let Some(lock) = locks.get(&payload.path) {
                if lock.session_id != *session_id {
                    let err = ErrorPayload { code: 0x07, message: "File is locked".to_string(), stream_id: Some(frame.stream_id) };
                    return Ok(vec![Frame::new(FrameType::Error, frame.stream_id, frame.seq_num,
                        Bytes::from(serde_json::to_vec(&err)?))]);
                }
            }
        }

        // 记住 stream → path 映射
        write_streams.insert(frame.stream_id, payload.path.clone());

        let temp_path = file_path.with_extension("tmp");
        fs::write(&temp_path, &[]).await?;
        info!("Write started: {}", payload.path);

        let ack = AckPayload { stream_id: frame.stream_id, seq_num: frame.seq_num };
        Ok(vec![Frame::new(FrameType::Ack, frame.stream_id, frame.seq_num,
            Bytes::from(serde_json::to_vec(&ack)?))])
    }

    async fn handle_write_data(frame: &Frame, config: &ServerConfig,
        write_streams: &std::collections::HashMap<u32, String>,
    ) -> Result<Vec<Frame>> {
        // 二进制解码：offset(8B) + raw_data
        let (offset, data) = crate::protocol::decode_write_data(&frame.payload)?;

        // 通过 stream_id 查找写入路径
        if let Some(path) = write_streams.get(&frame.stream_id) {
            let temp_path = config.shared_dir.join(path).with_extension("tmp");
            use tokio::io::AsyncSeekExt;
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&temp_path)
                .await?;
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            use tokio::io::AsyncWriteExt;
            file.write_all(data).await?;
        } else {
            warn!("WriteData for unknown stream {}", frame.stream_id);
        }

        let ack = AckPayload { stream_id: frame.stream_id, seq_num: frame.seq_num };
        Ok(vec![Frame::new(FrameType::Ack, frame.stream_id, frame.seq_num,
            Bytes::from(serde_json::to_vec(&ack)?))])
    }

    async fn handle_write_commit(frame: &Frame, config: &ServerConfig,
        write_streams: &mut std::collections::HashMap<u32, String>,
    ) -> Result<Vec<Frame>> {
        let payload: WriteCommitPayload = serde_json::from_slice(&frame.payload)?;
        let file_path = config.shared_dir.join(&payload.path);
        let temp_path = file_path.with_extension("tmp");

        if temp_path.exists() {
            fs::rename(&temp_path, &file_path).await?;
            info!("Write committed: {}", payload.path);
        }

        // 清理 stream 映射
        write_streams.remove(&frame.stream_id);

        let ack = AckPayload { stream_id: frame.stream_id, seq_num: frame.seq_num };
        Ok(vec![Frame::new(FrameType::Ack, frame.stream_id, frame.seq_num,
            Bytes::from(serde_json::to_vec(&ack)?))])
    }

    async fn handle_delta_sync(
        frame: &Frame, config: &ServerConfig, _delta_computer: &DeltaComputer,
    ) -> Result<Vec<Frame>> {
        let payload: DeltaSyncPayload = serde_json::from_slice(&frame.payload)?;
        let file_path = config.shared_dir.join(&payload.path);

        let (exists, signature) = if file_path.exists() {
            let data = fs::read(&file_path).await?;
            let sig = FileSignature::compute(&data, payload.block_size);
            (true, sig)
        } else {
            (false, FileSignature { block_size: payload.block_size, file_size: 0, blocks: vec![] })
        };

        let blocks: Vec<DeltaBlockChecksum> = signature.blocks.iter().map(|b| {
            DeltaBlockChecksum { index: b.index, weak: b.weak, strong: hex::encode(&b.strong) }
        }).collect();

        let resp = DeltaSyncRespPayload {
            path: payload.path,
            block_size: signature.block_size,
            file_size: signature.file_size,
            blocks, exists,
        };

        Ok(vec![Frame::new(FrameType::DeltaSyncResp, frame.stream_id, frame.seq_num,
            Bytes::from(serde_json::to_vec(&resp)?))])
    }

    async fn handle_delta_data(
        frame: &Frame, config: &ServerConfig, delta_computer: &DeltaComputer,
    ) -> Result<Vec<Frame>> {
        // 二进制解码
        let (path, source_size, delta_size, instructions_payload) =
            crate::protocol::decode_delta_data(&frame.payload)?;
        let file_path = config.shared_dir.join(&path);

        let old_data = if file_path.exists() { fs::read(&file_path).await? } else { vec![] };

        let instructions: Vec<crate::diff_transfer::DeltaInstruction> = instructions_payload.iter().map(|inst| {
            match inst {
                DeltaInstructionPayload::Copy { block_index } => {
                    crate::diff_transfer::DeltaInstruction::Copy { block_index: *block_index }
                }
                DeltaInstructionPayload::Literal { data } => {
                    crate::diff_transfer::DeltaInstruction::Literal { data: data.clone() }
                }
            }
        }).collect();

        let delta = crate::diff_transfer::Delta {
            instructions,
            source_size,
            delta_size,
            ratio: 0.0,
        };

        let new_data = delta_computer.apply_delta(&old_data, &delta);

        let temp_path = file_path.with_extension("delta_tmp");
        fs::write(&temp_path, &new_data).await?;
        fs::rename(&temp_path, &file_path).await?;

        info!("Delta applied: {} ({} bytes)", path, new_data.len());

        Ok(vec![Frame::new(FrameType::Ack, frame.stream_id, frame.seq_num, Bytes::new())])
    }

    async fn handle_window_update(
        frame: &Frame, session_id: &str,
        sessions: &Arc<RwLock<HashMap<String, Session>>>,
    ) -> Result<Vec<Frame>> {
        let payload: WindowUpdatePayload = serde_json::from_slice(&frame.payload)?;

        {
            let mut sessions = sessions.write().await;
            if let Some(session) = sessions.get_mut(session_id) {
                if let Some(stream) = session.streams.get_mut(&payload.stream_id) {
                    stream.recv_window = payload.window_size;
                }
            }
        }

        debug!("Window update: stream {} -> {} bytes", payload.stream_id, payload.window_size);
        Ok(vec![])
    }
}
