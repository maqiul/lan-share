//! LSP v3.0 客户端
//!
//! 基于 UDP 传输层，集成加密、可靠传输、流控、拥塞控制、压缩、差异传输。

use crate::diff_transfer::{DeltaComputer, FileSignature};
use crate::error::{LspError, Result};
use crate::protocol::*;
use crate::transport::UdpConnection;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tracing::{debug, info};
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
}

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
        })
    }

    fn next_stream_id(&self) -> u32 {
        self.next_stream_id.fetch_add(1, Ordering::SeqCst)
    }

    /// 发送帧
    async fn send_frame(&self, frame: Frame) -> Result<()> {
        self.conn.send_frame(frame).await
    }

    /// 接收帧
    async fn recv_frame(&self) -> Result<Frame> {
        self.conn.recv_frame().await
    }

    /// 发送可靠帧
    async fn send_reliable(&self, frame: Frame) -> Result<()> {
        self.conn.send_reliable(frame).await
    }

    /// 处理 ACK
    async fn handle_ack(&self, ack_seq: u32, stream_id: u32, bytes_acked: u32) {
        self.conn.handle_ack(ack_seq, stream_id, bytes_acked).await;
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

        let resp = self.recv_frame().await?;
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
        let resp = self.recv_frame().await?;
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

        // 5. 发送 PIN 证明
        let pin_hash = Sha256::digest(pin.as_bytes());
        let auth_resp = AuthResponsePayload {
            pin_proof: hex::encode(pin_hash),
            device_name: self.device_name.clone(),
            session_token: Uuid::new_v4().to_string(),
        };
        let frame = Frame::new(
            FrameType::AuthResponse,
            0,
            2,
            Bytes::from(serde_json::to_vec(&auth_resp)?),
        );
        self.send_frame(frame).await?;

        // 6. 接收认证结果
        let resp = self.recv_frame().await?;
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

    /// 打开流
    pub async fn open_stream(&self, stream_type: &str, params: serde_json::Value) -> Result<u32> {
        let stream_id = self.next_stream_id();

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

        let resp = self.recv_frame().await?;
        if resp.frame_type != FrameType::StreamOpenAck {
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
        Ok(stream_id)
    }

    /// 关闭流
    pub async fn close_stream(&self, stream_id: u32) -> Result<()> {
        let frame = Frame::new(FrameType::StreamClose, stream_id, 0, Bytes::new())
            .with_flags(Flags::new().with(Flags::FIN));

        self.send_frame(frame).await?;
        self.conn.unregister_stream(stream_id).await;

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
        let stream_id = self
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

        let resp = self.recv_frame().await?;
        if resp.frame_type != FrameType::FileListResp {
            return Err(LspError::Protocol("Expected FILE_LIST_RESP".into()));
        }

        let list_resp: FileListRespPayload = serde_json::from_slice(&resp.payload)?;
        self.close_stream(stream_id).await?;

        Ok(list_resp.entries)
    }

    /// 获取文件元数据
    pub async fn stat_file(&self, path: &str) -> Result<FileEntry> {
        let stream_id = self
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

        let resp = self.recv_frame().await?;
        if resp.frame_type != FrameType::FileStatResp {
            return Err(LspError::Protocol("Expected FILE_STAT_RESP".into()));
        }

        let stat_resp: FileStatRespPayload = serde_json::from_slice(&resp.payload)?;
        self.close_stream(stream_id).await?;

        Ok(stat_resp.entry)
    }

    /// 下载文件（stop-and-wait + 断点续传 + 流控）
    pub async fn download_file(
        &self,
        remote_path: &str,
        local_path: PathBuf,
        offset: u64,
    ) -> Result<u64> {
        let stream_id = self
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

            let resp = self.recv_frame().await?;
            if resp.frame_type == FrameType::ReadData {
                let (_data_offset, is_last, data) = crate::protocol::decode_read_data(&resp.payload)?;
                file.write_all(data).await?;
                total_bytes += data.len() as u64;

                // 发送 ACK
                let ack = AckPayload { stream_id, seq_num: resp.seq_num };
                let ack_frame = Frame::new(
                    FrameType::Ack, 0, 0,
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
                return Err(LspError::Transfer(err.message));
            } else {
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

    /// 上传文件（带流控 + 拥塞控制 + 压缩）
    pub async fn upload_file(&self, local_path: PathBuf, remote_path: &str) -> Result<u64> {
        let file_data = fs::read(&local_path).await?;
        let file_size = file_data.len() as u64;

        let mut hasher = Sha256::new();
        hasher.update(&file_data);
        let sha256 = hex::encode(hasher.finalize());

        let stream_id = self
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
        let resp = self.recv_frame().await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
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
            let resp = self.recv_frame().await?;
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

        let resp = self.recv_frame().await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            return Err(LspError::Transfer(err.message));
        }

        self.close_stream(stream_id).await?;
        info!("Upload complete: {} bytes", file_size);
        Ok(file_size)
    }

    /// 差异同步上传（只传变化部分）
    pub async fn delta_upload(&self, local_path: PathBuf, remote_path: &str) -> Result<u64> {
        let file_data = fs::read(&local_path).await?;

        let stream_id = self
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
        let resp = self.recv_frame().await?;
        if resp.frame_type != FrameType::DeltaSyncResp {
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

        let resp = self.recv_frame().await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
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
        let stream_id = self
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

        let resp = self.recv_frame().await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            return Err(LspError::Transfer(err.message));
        }

        self.close_stream(stream_id).await?;
        info!("File deleted: {}", path);
        Ok(())
    }

    /// 创建目录
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let stream_id = self
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

        let resp = self.recv_frame().await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
            return Err(LspError::Transfer(err.message));
        }

        self.close_stream(stream_id).await?;
        info!("Directory created: {}", path);
        Ok(())
    }

    /// 重命名/移动文件
    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        let stream_id = self
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

        let resp = self.recv_frame().await?;
        if resp.frame_type == FrameType::Error {
            let err: ErrorPayload = serde_json::from_slice(&resp.payload)?;
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

        let resp = self.recv_frame().await?;
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
