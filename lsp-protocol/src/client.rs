//! LSP v3.0 客户端
//!
//! 基于 UDP 传输层，集成加密、可靠传输、流控、拥塞控制、压缩、差异传输。
//!
//! 并发模型：后台分发器持续从连接收帧，按 `stream_id` 将响应分发到各请求通道
//! （`stream_id == 0` 的握手/认证/心跳帧走控制通道）。多个操作可并发 in-flight。

use crate::diff_transfer::{DeltaComputer, FileSignature};
use crate::error::{LspError, Result};
use crate::protocol::*;
use crate::transport::UdpConnection;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// 流状态
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamState {
    Opening,
    Open,
    Closing,
    Closed,
}

/// 流信息
pub struct StreamInfo {
    pub id: u32,
    pub stream_type: String,
    pub state: StreamState,
}

/// LSP v3.0 客户端
pub struct LspClient {
    conn: Arc<UdpConnection>,
    device_id: String,
    device_name: String,
    session_id: Option<String>,
    next_stream_id: AtomicU32,
    streams: Arc<RwLock<HashMap<u32, StreamInfo>>>,
    capabilities: Vec<String>,
    delta_computer: DeltaComputer,
    /// 后台重传定时器 handle
    _retransmit_handle: Option<tokio::task::JoinHandle<()>>,
    /// 在途请求：stream_id → 帧发送端，分发器按 stream_id 转发响应
    pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Frame>>>>,
    /// 控制通道接收端（stream_id=0 的握手/认证/心跳帧）
    control_rx: Arc<Mutex<mpsc::UnboundedReceiver<Frame>>>,
    /// 后台分发器 handle
    _dispatcher: Option<tokio::task::JoinHandle<()>>,
    /// 连接存活标志（分发器退出时置 false）
    connected: Arc<AtomicBool>,
}

impl Drop for LspClient {
    fn drop(&mut self) {
        // 中止后台分发器与重传定时器，避免客户端被替换（重连）或销毁后任务泄漏
        if let Some(h) = self._dispatcher.take() {
            h.abort();
        }
        if let Some(h) = self._retransmit_handle.take() {
            h.abort();
        }
    }
}

/// 后台分发器：持续收帧并按 stream_id 路由
///
/// - `stream_id == 0` → 控制通道（握手/认证/心跳）
/// - `stream_id == N` → `pending[N]` 通道（业务请求）
///
/// 连接关闭时清空 `pending`，让所有等待者收到 `ConnectionClosed`。
async fn dispatcher_loop(
    conn: Arc<UdpConnection>,
    pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Frame>>>>,
    control_tx: mpsc::UnboundedSender<Frame>,
    connected: Arc<AtomicBool>,
) {
    loop {
        match conn.recv_frame().await {
            Ok(frame) => {
                let sid = frame.stream_id;
                if sid == 0 {
                    if control_tx.send(frame).is_err() {
                        break;
                    }
                } else {
                    let tx = pending.lock().await.get(&sid).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(frame);
                    }
                    // 未注册流的帧（如迟到的重传帧）直接丢弃
                }
            }
            Err(_) => break,
        }
    }
    // 连接关闭：清空在途请求，drop 所有发送端
    pending.lock().await.clear();
    connected.store(false, Ordering::Release);
    warn!("LSP dispatcher exited (connection closed)");
}

/// 单个请求等待响应的超时时间。
///
/// 服务端异常（重启/宕机）时，请求或握手在此时间内无响应即判为超时（transient 错误），
/// 触发上层自动重连。LAN 场景正常响应为毫秒级，10 秒阈值足够宽松，不会误伤正常操作。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

impl LspClient {
    /// 通过 UDP 连接到服务端
    pub async fn connect(
        addr: &str,
        device_id: String,
        device_name: String,
    ) -> Result<Self> {
        let conn = UdpConnection::connect_client(addr, true, true).await?;
        let conn = Arc::new(conn);

        // 启动后台重传定时器
        let retransmit_handle = UdpConnection::spawn_retransmit_timer(conn.clone());

        // 启动后台分发器
        let pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Frame>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let connected = Arc::new(AtomicBool::new(true));

        let dispatcher = {
            let conn = conn.clone();
            let pending = pending.clone();
            let connected = connected.clone();
            tokio::spawn(async move {
                dispatcher_loop(conn, pending, control_tx, connected).await;
            })
        };

        Ok(Self {
            conn,
            device_id,
            device_name,
            session_id: None,
            next_stream_id: AtomicU32::new(1),
            streams: Arc::new(RwLock::new(HashMap::new())),
            capabilities: vec![
                "stream_multiplex".to_string(),
                "file_watch".to_string(),
                "resume".to_string(),
                "encryption".to_string(),
                "compression".to_string(),
                "delta_sync".to_string(),
                "reliable_transport".to_string(),
            ],
            delta_computer: DeltaComputer::default(),
            _retransmit_handle: Some(retransmit_handle),
            pending,
            control_rx: Arc::new(Mutex::new(control_rx)),
            _dispatcher: Some(dispatcher),
            connected,
        })
    }

    fn next_stream_id(&self) -> u32 {
        self.next_stream_id.fetch_add(1, Ordering::SeqCst)
    }

    /// 发送帧
    async fn send_frame(&self, frame: Frame) -> Result<()> {
        self.conn.send_frame(frame).await
    }

    /// 发送可靠帧
    async fn send_reliable(&self, frame: Frame) -> Result<()> {
        self.conn.send_reliable(frame).await
    }

    /// 处理 ACK
    async fn handle_ack(&self, ack_seq: u32, stream_id: u32, bytes_acked: u32) {
        self.conn.handle_ack(ack_seq, stream_id, bytes_acked).await;
    }

    /// 连接是否存活
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    // ── 并发分发辅助 ──

    /// 为指定流注册接收通道
    async fn register_pending(&self, sid: u32) -> mpsc::UnboundedReceiver<Frame> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.pending.lock().await.insert(sid, tx);
        rx
    }

    /// 注销流接收通道
    async fn unregister_pending(&self, sid: u32) {
        self.pending.lock().await.remove(&sid);
    }

    /// 从流通道收一帧（带超时）
    ///
    /// 服务端异常（如重启、宕机）时，重传机制丢弃帧后不会主动通知等待者，
    /// 请求会永久挂起。加超时后，无响应即返回 transient 错误以触发上层重连。
    async fn recv_on_stream(rx: &mut mpsc::UnboundedReceiver<Frame>) -> Result<Frame> {
        tokio::time::timeout(REQUEST_TIMEOUT, rx.recv())
            .await
            .map_err(|_| LspError::Timeout("request timed out".to_string()))?
            .ok_or(LspError::ConnectionClosed)
    }

    /// 从控制通道收一帧（带超时，用于握手/认证阶段）
    async fn recv_on_control(&self) -> Result<Frame> {
        let mut guard = self.control_rx.lock().await;
        tokio::time::timeout(REQUEST_TIMEOUT, guard.recv())
            .await
            .map_err(|_| LspError::Timeout("control timed out".to_string()))?
            .ok_or(LspError::ConnectionClosed)
    }

    /// 握手 + 能力协商
    pub async fn handshake(&mut self) -> Result<()> {
        let hello = HelloPayload {
            version: PROTOCOL_VERSION,
            capabilities: self.capabilities.clone(),
            device_info: DeviceInfo {
                id: self.device_id.clone(),
                name: self.device_name.clone(),
                os: std::env::consts::OS.to_string(),
                version: "3.0.0".to_string(),
            },
        };

        let frame = Frame::new(
            FrameType::Hello,
            0,
            0,
            Bytes::from(serde_json::to_vec(&hello)?),
        );

        self.send_frame(frame).await?;

        let resp = self.recv_on_control().await?;
        if resp.frame_type != FrameType::HelloAck {
            return Err(LspError::Protocol("Expected HELLO_ACK".into()));
        }

        let ack: HelloAckPayload = serde_json::from_slice(&resp.payload)?;
        info!(
            "Connected to server, session: {}, capabilities: {:?}",
            ack.session_id, ack.capabilities
        );

        self.session_id = Some(ack.session_id);

        // 根据协商结果启用/禁用功能
        let _use_enc = ack.capabilities.contains(&"encryption".to_string());
        let _use_comp = ack.capabilities.contains(&"compression".to_string());

        Ok(())
    }

    /// 认证（X25519 密钥交换 + PIN 验证）
    pub async fn authenticate(&mut self, pin: &str) -> Result<String> {
        self.exchange_keys().await?;

        // 发送 PIN 证明
        let pin_hash = Sha256::digest(pin.as_bytes());
        let auth_resp = AuthResponsePayload {
            pin_proof: hex::encode(pin_hash),
            device_name: self.device_name.clone(),
            session_token: Uuid::new_v4().to_string(),
            auth_mode: "pin".to_string(),
            username: None,
            password: None,
        };
        self.finish_auth(auth_resp).await
    }

    /// 账号模式认证：发送用户名/密码（在 ECDH 加密通道内传输），由服务端验证器校验
    pub async fn authenticate_account(&mut self, username: &str, password: &str) -> Result<String> {
        self.exchange_keys().await?;

        let auth_resp = AuthResponsePayload {
            pin_proof: String::new(),
            device_name: self.device_name.clone(),
            session_token: Uuid::new_v4().to_string(),
            auth_mode: "account".to_string(),
            username: Some(username.to_string()),
            password: Some(password.to_string()),
        };
        self.finish_auth(auth_resp).await
    }

    /// 握手密钥交换：AuthInit → 接收 AuthChallenge → ECDH 派生会话密钥
    async fn exchange_keys(&mut self) -> Result<()> {
        // 1. 发送客户端公钥
        let auth_init = AuthInitPayload {
            client_pubkey: hex::encode(&self.conn.key_pair.public_key),
        };
        let frame = Frame::new(
            FrameType::AuthInit,
            0,
            1,
            Bytes::from(serde_json::to_vec(&auth_init)?),
        );
        self.send_frame(frame).await?;

        // 2. 接收服务端公钥 + 挑战
        let resp = self.recv_on_control().await?;
        if resp.frame_type != FrameType::AuthChallenge {
            return Err(LspError::Protocol("Expected AUTH_CHALLENGE".into()));
        }
        let challenge: AuthChallengePayload = serde_json::from_slice(&resp.payload)?;

        // 3. 计算共享密钥（真正的 X25519 ECDH）
        let server_pubkey_bytes = hex::decode(&challenge.server_pubkey)
            .map_err(|e| LspError::Auth(format!("Invalid server pubkey: {}", e)))?;
        let mut server_pubkey = [0u8; 32];
        if server_pubkey_bytes.len() == 32 {
            server_pubkey.copy_from_slice(&server_pubkey_bytes);
        }
        let shared_secret = self.conn.key_pair.compute_shared_secret(&server_pubkey);

        // 4. 派生会话密钥
        let handshake_hash = Sha256::digest(
            [&self.conn.key_pair.public_key[..], &server_pubkey[..]].concat(),
        );
        let mut hh = [0u8; 32];
        hh.copy_from_slice(&handshake_hash);

        let keys = crate::crypto::SessionKeys::derive(&shared_secret, &hh);
        self.conn.set_session_keys(keys).await;
        Ok(())
    }

    /// 发送 AuthResponse 并接收认证结果
    async fn finish_auth(&mut self, auth_resp: AuthResponsePayload) -> Result<String> {
        let frame = Frame::new(
            FrameType::AuthResponse,
            0,
            2,
            Bytes::from(serde_json::to_vec(&auth_resp)?),
        );
        self.send_frame(frame).await?;

        let resp = self.recv_on_control().await?;
        match resp.frame_type {
            FrameType::AuthOk => {
                let ok: AuthOkPayload = serde_json::from_slice(&resp.payload)?;
                info!("Authenticated, permission: {}", ok.permission);
                Ok(ok.permission)
            }
            FrameType::AuthFail => {
                let fail: AuthFailPayload = serde_json::from_slice(&resp.payload)?;
                Err(LspError::Auth(fail.reason))
            }
            _ => Err(LspError::Protocol(format!("Unexpected: {:?}", resp.frame_type))),
        }
    }

    /// 打开流（注册接收通道 → 发送 StreamOpen → 等待 StreamOpenAck）
    ///
    /// 返回流 ID 与该流的接收端，调用方持有接收端以接收后续响应帧。
    pub async fn open_stream(
        &self,
        stream_type: &str,
        params: serde_json::Value,
    ) -> Result<(u32, mpsc::UnboundedReceiver<Frame>)> {
        let stream_id = self.next_stream_id();
        let mut rx = self.register_pending(stream_id).await;

        let payload = StreamOpenPayload {
            stream_type: stream_type.to_string(),
            params,
        };

        let frame = Frame::new(
            FrameType::StreamOpen,
            stream_id,
            0,
            Bytes::from(serde_json::to_vec(&payload)?),
        );

        self.send_frame(frame).await?;

        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type != FrameType::StreamOpenAck {
            self.unregister_pending(stream_id).await;
            return Err(LspError::Protocol("Expected STREAM_OPEN_ACK".into()));
        }

        // 注册到传输层管理器
        self.conn.register_stream(stream_id).await;

        let stream_info = StreamInfo {
            id: stream_id,
            stream_type: stream_type.to_string(),
            state: StreamState::Open,
        };

        {
            let mut streams = self.streams.write().await;
            streams.insert(stream_id, stream_info);
        }

        info!("Stream {} opened (type: {})", stream_id, stream_type);
        Ok((stream_id, rx))
    }

    /// 关闭流
    pub async fn close_stream(&self, stream_id: u32) -> Result<()> {
        let frame = Frame::new(FrameType::StreamClose, stream_id, 0, Bytes::new())
            .with_flags(Flags::new().with(Flags::FIN));

        self.send_frame(frame).await?;
        self.conn.unregister_stream(stream_id).await;
        self.unregister_pending(stream_id).await;

        {
            let mut streams = self.streams.write().await;
            if let Some(stream) = streams.get_mut(&stream_id) {
                stream.state = StreamState::Closed;
            }
        }

        info!("Stream {} closed", stream_id);
        Ok(())
    }

    /// 列出文件
    pub async fn list_files(&self, path: &str, recursive: bool) -> Result<Vec<FileEntry>> {
        let (stream_id, mut rx) = self
            .open_stream("file_list", serde_json::json!({ "path": path, "recursive": recursive }))
            .await?;

        let payload = FileListPayload {
            path: path.to_string(),
            recursive,
        };

        let frame = Frame::new(
            FrameType::FileList,
            stream_id,
            1,
            Bytes::from(serde_json::to_vec(&payload)?),
        );

        self.send_frame(frame).await?;

        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type != FrameType::FileListResp {
            self.close_stream(stream_id).await?;
            return Err(LspError::Protocol("Expected FILE_LIST_RESP".into()));
        }

        let list_resp: FileListRespPayload = serde_json::from_slice(&resp.payload)?;
        self.close_stream(stream_id).await?;

        Ok(list_resp.entries)
    }

    /// 获取文件元数据（文件不存在时返回 `LspError::FileNotFound`）
    pub async fn stat_file(&self, path: &str) -> Result<FileEntry> {
        let (stream_id, mut rx) = self
            .open_stream("file_stat", serde_json::json!({ "path": path }))
            .await?;

        let payload = FileStatPayload {
            path: path.to_string(),
        };

        let frame = Frame::new(
            FrameType::FileStat,
            stream_id,
            1,
            Bytes::from(serde_json::to_vec(&payload)?),
        );

        self.send_frame(frame).await?;

        let resp = Self::recv_on_stream(&mut rx).await?;
        match resp.frame_type {
            FrameType::FileStatResp => {
                let stat_resp: FileStatRespPayload = serde_json::from_slice(&resp.payload)?;
                self.close_stream(stream_id).await?;
                Ok(stat_resp.entry)
            }
            FrameType::Error => {
                let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
                self.close_stream(stream_id).await?;
                if err.code == 0x04 {
                    Err(LspError::FileNotFound(err.message))
                } else {
                    Err(LspError::Transfer(err.message))
                }
            }
            _ => {
                self.close_stream(stream_id).await?;
                Err(LspError::Protocol("Expected FILE_STAT_RESP".into()))
            }
        }
    }

    /// 下载文件到本地路径（stop-and-wait + 断点续传 + 流控）
    pub async fn download_file(
        &self,
        remote_path: &str,
        local_path: PathBuf,
        offset: u64,
    ) -> Result<u64> {
        let (stream_id, mut rx) = self
            .open_stream(
                "download",
                serde_json::json!({ "path": remote_path, "offset": offset }),
            )
            .await?;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&local_path)
            .await?;

        let mut total_bytes = 0u64;

        loop {
            let payload = ReadReqPayload {
                path: remote_path.to_string(),
                offset: offset + total_bytes,
                length: DEFAULT_CHUNK_SIZE as u32,
            };

            let seq = (total_bytes / DEFAULT_CHUNK_SIZE as u64) as u32 + 1;
            let frame = Frame::new(
                FrameType::ReadReq,
                stream_id,
                seq,
                Bytes::from(serde_json::to_vec(&payload)?),
            );
            self.send_reliable(frame).await?;

            let resp = Self::recv_on_stream(&mut rx).await?;
            if resp.frame_type == FrameType::ReadData {
                let (_data_offset, is_last, data) = crate::protocol::decode_read_data(&resp.payload)?;
                file.write_all(data).await?;
                total_bytes += data.len() as u64;

                // 发送 ACK
                let ack = AckPayload { stream_id, seq_num: resp.seq_num };
                let ack_frame = Frame::new(
                    FrameType::Ack, stream_id, 0,
                    Bytes::from(serde_json::to_vec(&ack)?),
                );
                self.send_frame(ack_frame).await?;

                // 更新流控
                {
                    let mut mgr = self.conn.flow_ctrl_mgr.lock().await;
                    mgr.on_data_received(stream_id, data.len() as u32);
                    mgr.on_data_consumed(stream_id, data.len() as u32);
                }

                debug!("Downloaded {} bytes", total_bytes);

                if is_last {
                    break;
                }
            } else if resp.frame_type == FrameType::Error {
                let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
                self.close_stream(stream_id).await?;
                return Err(LspError::Transfer(err.message));
            } else {
                self.close_stream(stream_id).await?;
                return Err(LspError::Protocol(format!(
                    "Unexpected: {:?}",
                    resp.frame_type
                )));
            }
        }

        self.close_stream(stream_id).await?;
        info!("Download complete: {} bytes", total_bytes);
        Ok(total_bytes)
    }

    /// 范围读取文件到内存（供文件系统挂载使用）
    ///
    /// 从 `offset` 开始读取，`max_len == 0` 表示读到文件末尾，否则最多读 `max_len` 字节。
    /// 返回读取到的字节，不落盘。
    pub async fn read_range(
        &self,
        remote_path: &str,
        offset: u64,
        max_len: u64,
    ) -> Result<Vec<u8>> {
        let (stream_id, mut rx) = self
            .open_stream(
                "download",
                serde_json::json!({ "path": remote_path, "offset": offset }),
            )
            .await?;

        let mut buf: Vec<u8> = Vec::new();
        let mut cur_offset = offset;
        let mut seq = 1u32;

        loop {
            if max_len > 0 && buf.len() as u64 >= max_len {
                break;
            }

            let length = if max_len > 0 {
                ((max_len - buf.len() as u64).min(DEFAULT_CHUNK_SIZE as u64)) as u32
            } else {
                DEFAULT_CHUNK_SIZE as u32
            };

            let payload = ReadReqPayload {
                path: remote_path.to_string(),
                offset: cur_offset,
                length,
            };

            let frame = Frame::new(
                FrameType::ReadReq,
                stream_id,
                seq,
                Bytes::from(serde_json::to_vec(&payload)?),
            );
            self.send_reliable(frame).await?;

            let resp = Self::recv_on_stream(&mut rx).await?;
            if resp.frame_type == FrameType::ReadData {
                let (_data_offset, is_last, data) = crate::protocol::decode_read_data(&resp.payload)?;
                buf.extend_from_slice(data);
                cur_offset += data.len() as u64;

                // 发送 ACK
                let ack = AckPayload { stream_id, seq_num: resp.seq_num };
                let ack_frame = Frame::new(
                    FrameType::Ack, stream_id, 0,
                    Bytes::from(serde_json::to_vec(&ack)?),
                );
                self.send_frame(ack_frame).await?;

                // 更新流控
                {
                    let mut mgr = self.conn.flow_ctrl_mgr.lock().await;
                    mgr.on_data_received(stream_id, data.len() as u32);
                    mgr.on_data_consumed(stream_id, data.len() as u32);
                }

                seq += 1;

                if is_last {
                    break;
                }
            } else if resp.frame_type == FrameType::Error {
                let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
                self.close_stream(stream_id).await?;
                if err.code == 0x04 {
                    return Err(LspError::FileNotFound(err.message));
                }
                return Err(LspError::Transfer(err.message));
            } else {
                self.close_stream(stream_id).await?;
                return Err(LspError::Protocol(format!(
                    "Unexpected: {:?}",
                    resp.frame_type
                )));
            }
        }

        self.close_stream(stream_id).await?;
        debug!("Read range complete: {} bytes", buf.len());
        Ok(buf)
    }

    /// 上传文件（带流控 + 拥塞控制 + 压缩）
    pub async fn upload_file(&self, local_path: PathBuf, remote_path: &str) -> Result<u64> {
        let file_data = fs::read(&local_path).await?;
        let file_size = file_data.len() as u64;

        let mut hasher = Sha256::new();
        hasher.update(&file_data);
        let sha256 = hex::encode(hasher.finalize());

        let (stream_id, mut rx) = self
            .open_stream(
                "upload",
                serde_json::json!({ "path": remote_path, "size": file_size }),
            )
            .await?;

        // 发送写入请求
        let write_req = WriteReqPayload {
            path: remote_path.to_string(),
            size: file_size,
            sha256: sha256.clone(),
            overwrite: true,
        };

        let frame = Frame::new(
            FrameType::WriteReq,
            stream_id,
            1,
            Bytes::from(serde_json::to_vec(&write_req)?),
        );

        self.send_frame(frame).await?;

        // 等待 WriteReq 的 Ack
        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            self.close_stream(stream_id).await?;
            return Err(LspError::Transfer(err.message));
        }

        // 分块发送数据
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let mut offset = 0usize;
        let mut seq = 2u32;

        while offset < file_data.len() {
            // 检查流控
            if !self.conn.can_send(stream_id).await {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }

            let end = std::cmp::min(offset + chunk_size, file_data.len());
            let chunk = &file_data[offset..end];

            // 二进制编码：offset(8B) + raw_data
            let frame = Frame::new(
                FrameType::WriteData,
                stream_id,
                seq,
                crate::protocol::encode_write_data(offset as u64, chunk),
            );

            self.send_reliable(frame).await?;

            // 等待 ACK
            let resp = Self::recv_on_stream(&mut rx).await?;
            if resp.frame_type == FrameType::Ack {
                let ack: AckPayload = serde_json::from_slice(&resp.payload)?;
                self.handle_ack(ack.seq_num, stream_id, chunk.len() as u32)
                    .await;
            }

            offset = end;
            seq += 1;
            debug!("Uploaded {} / {} bytes", offset, file_size);
        }

        // 提交写入
        let commit = WriteCommitPayload {
            path: remote_path.to_string(),
            sha256,
        };

        let frame = Frame::new(
            FrameType::WriteCommit,
            stream_id,
            seq,
            Bytes::from(serde_json::to_vec(&commit)?),
        );

        self.send_frame(frame).await?;

        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            self.close_stream(stream_id).await?;
            return Err(LspError::Transfer(err.message));
        }

        self.close_stream(stream_id).await?;
        info!("Upload complete: {} bytes", file_size);
        Ok(file_size)
    }

    /// 上传内存数据到远端文件（供文件系统写回使用，无需本地落盘）
    ///
    /// 与 [`upload_file`](Self::upload_file) 协议一致（WriteReq → WriteData×N → WriteCommit），
    /// 但数据源为内存切片。`overwrite` 恒为 true：远端文件被整体替换。
    pub async fn upload_data(&self, data: &[u8], remote_path: &str) -> Result<u64> {
        let file_size = data.len() as u64;

        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = hex::encode(hasher.finalize());

        let (stream_id, mut rx) = self
            .open_stream(
                "upload",
                serde_json::json!({ "path": remote_path, "size": file_size }),
            )
            .await?;

        // 发送写入请求
        let write_req = WriteReqPayload {
            path: remote_path.to_string(),
            size: file_size,
            sha256: sha256.clone(),
            overwrite: true,
        };

        let frame = Frame::new(
            FrameType::WriteReq,
            stream_id,
            1,
            Bytes::from(serde_json::to_vec(&write_req)?),
        );

        self.send_frame(frame).await?;

        // 等待 WriteReq 的 Ack
        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            self.close_stream(stream_id).await?;
            return Err(LspError::Transfer(err.message));
        }

        // 分块发送数据
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let mut offset = 0usize;
        let mut seq = 2u32;

        while offset < data.len() {
            // 检查流控
            if !self.conn.can_send(stream_id).await {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }

            let end = std::cmp::min(offset + chunk_size, data.len());
            let chunk = &data[offset..end];

            // 二进制编码：offset(8B) + raw_data
            let frame = Frame::new(
                FrameType::WriteData,
                stream_id,
                seq,
                crate::protocol::encode_write_data(offset as u64, chunk),
            );

            self.send_reliable(frame).await?;

            // 等待 ACK
            let resp = Self::recv_on_stream(&mut rx).await?;
            if resp.frame_type == FrameType::Ack {
                let ack: AckPayload = serde_json::from_slice(&resp.payload)?;
                self.handle_ack(ack.seq_num, stream_id, chunk.len() as u32)
                    .await;
            }

            offset = end;
            seq += 1;
            debug!("Uploaded {} / {} bytes", offset, file_size);
        }

        // 提交写入
        let commit = WriteCommitPayload {
            path: remote_path.to_string(),
            sha256,
        };

        let frame = Frame::new(
            FrameType::WriteCommit,
            stream_id,
            seq,
            Bytes::from(serde_json::to_vec(&commit)?),
        );

        self.send_frame(frame).await?;

        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            self.close_stream(stream_id).await?;
            return Err(LspError::Transfer(err.message));
        }

        self.close_stream(stream_id).await?;
        info!("Upload (memory) complete: {} bytes", file_size);
        Ok(file_size)
    }

    /// 差异同步上传（只传变化部分）
    pub async fn delta_upload(&self, local_path: PathBuf, remote_path: &str) -> Result<u64> {
        let file_data = fs::read(&local_path).await?;

        let (stream_id, mut rx) = self
            .open_stream("delta_upload", serde_json::json!({ "path": remote_path }))
            .await?;

        // 1. 请求远端文件签名
        let delta_req = DeltaSyncPayload {
            path: remote_path.to_string(),
            block_size: crate::diff_transfer::DEFAULT_BLOCK_SIZE,
        };
        let frame = Frame::new(
            FrameType::DeltaSync,
            stream_id,
            1,
            Bytes::from(serde_json::to_vec(&delta_req)?),
        );
        self.send_frame(frame).await?;

        // 2. 接收签名
        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type != FrameType::DeltaSyncResp {
            self.close_stream(stream_id).await?;
            return Err(LspError::Protocol("Expected DELTA_SYNC_RESP".into()));
        }
        let sig_resp: DeltaSyncRespPayload = serde_json::from_slice(&resp.payload)?;

        // 3. 构建签名
        let signature = if sig_resp.exists {
            let blocks: Vec<crate::diff_transfer::BlockChecksum> = sig_resp
                .blocks
                .iter()
                .map(|b| {
                    let strong_bytes = hex::decode(&b.strong).unwrap_or_default();
                    let mut strong = [0u8; 8];
                    if strong_bytes.len() >= 8 {
                        strong.copy_from_slice(&strong_bytes[..8]);
                    }
                    crate::diff_transfer::BlockChecksum {
                        index: b.index,
                        weak: b.weak,
                        strong,
                    }
                })
                .collect();

            FileSignature {
                block_size: sig_resp.block_size,
                file_size: sig_resp.file_size,
                blocks,
            }
        } else {
            FileSignature {
                block_size: crate::diff_transfer::DEFAULT_BLOCK_SIZE,
                file_size: 0,
                blocks: vec![],
            }
        };

        // 4. 计算差异
        let delta = self.delta_computer.compute_delta(&file_data, &signature);
        info!(
            "Delta: {} instructions, ratio: {:.2}%, saved {} bytes",
            delta.instructions.len(),
            delta.ratio * 100.0,
            file_data.len() as u64 - delta.delta_size,
        );

        // 5. 发送差异数据（二进制编码）
        let instructions: Vec<DeltaInstructionPayload> = delta
            .instructions
            .iter()
            .map(|inst| match inst {
                crate::diff_transfer::DeltaInstruction::Copy { block_index } => {
                    DeltaInstructionPayload::Copy {
                        block_index: *block_index,
                    }
                }
                crate::diff_transfer::DeltaInstruction::Literal { data } => {
                    DeltaInstructionPayload::Literal {
                        data: data.clone(),
                    }
                }
            })
            .collect();

        let frame = Frame::new(
            FrameType::DeltaData,
            stream_id,
            2,
            crate::protocol::encode_delta_data(
                remote_path,
                delta.source_size,
                delta.delta_size,
                &instructions,
            ),
        );
        self.send_frame(frame).await?;

        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            self.close_stream(stream_id).await?;
            return Err(LspError::Transfer(err.message));
        }

        self.close_stream(stream_id).await?;
        info!(
            "Delta upload complete: {} bytes (saved {} bytes)",
            delta.delta_size,
            file_data.len() as u64 - delta.delta_size
        );
        Ok(delta.delta_size)
    }

    /// 删除文件
    pub async fn delete_file(&self, path: &str, recursive: bool) -> Result<()> {
        let (stream_id, mut rx) = self
            .open_stream("delete", serde_json::json!({ "path": path }))
            .await?;

        let payload = FileDeletePayload {
            path: path.to_string(),
            recursive,
        };

        let frame = Frame::new(
            FrameType::FileDelete,
            stream_id,
            1,
            Bytes::from(serde_json::to_vec(&payload)?),
        );

        self.send_frame(frame).await?;

        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            self.close_stream(stream_id).await?;
            return Err(LspError::Transfer(err.message));
        }

        self.close_stream(stream_id).await?;
        info!("File deleted: {}", path);
        Ok(())
    }

    /// 创建目录
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let (stream_id, mut rx) = self
            .open_stream("mkdir", serde_json::json!({ "path": path }))
            .await?;

        let payload = FileMkdirPayload {
            path: path.to_string(),
        };

        let frame = Frame::new(
            FrameType::FileMkdir,
            stream_id,
            1,
            Bytes::from(serde_json::to_vec(&payload)?),
        );

        self.send_frame(frame).await?;

        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            self.close_stream(stream_id).await?;
            return Err(LspError::Transfer(err.message));
        }

        self.close_stream(stream_id).await?;
        info!("Directory created: {}", path);
        Ok(())
    }

    /// 重命名/移动文件
    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        let (stream_id, mut rx) = self
            .open_stream(
                "rename",
                serde_json::json!({ "old": old_path, "new": new_path }),
            )
            .await?;

        let payload = FileRenamePayload {
            old_path: old_path.to_string(),
            new_path: new_path.to_string(),
        };

        let frame = Frame::new(
            FrameType::FileRename,
            stream_id,
            1,
            Bytes::from(serde_json::to_vec(&payload)?),
        );

        self.send_frame(frame).await?;

        let resp = Self::recv_on_stream(&mut rx).await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            self.close_stream(stream_id).await?;
            return Err(LspError::Transfer(err.message));
        }

        self.close_stream(stream_id).await?;
        info!("Renamed {} -> {}", old_path, new_path);
        Ok(())
    }

    /// 心跳
    pub async fn keepalive(&self) -> Result<()> {
        let frame = Frame::new(FrameType::Keepalive, 0, 0, Bytes::new());
        self.send_frame(frame).await?;

        let resp = self.recv_on_control().await?;
        if resp.frame_type != FrameType::KeepaliveAck {
            return Err(LspError::Protocol("Expected KEEPALIVE_ACK".into()));
        }

        Ok(())
    }

    /// 优雅断开
    pub async fn goodbye(&self) -> Result<()> {
        let frame = Frame::new(FrameType::Goodbye, 0, 0, Bytes::new());
        self.send_frame(frame).await?;
        info!("Sent GOODBYE");
        Ok(())
    }
}
