//! LSP v3.0 UDP 传输层
//!
//! 替代 TCP，在 UDP 上实现完整的可靠传输协议栈：
//! - 帧编解码（每个 UDP 数据报 = 一个 LSP 帧）
//! - 端到端加密（ChaCha20-Poly1305）
//! - 透明压缩（LZ4 / Zstd）
//! - 可靠传输（序列号 + ACK + 超时重传 + 快速重传 + SACK）
//! - 流量控制（滑动窗口 + 背压 + 零窗口探测）
//! - 拥塞控制（慢启动 + 拥塞避免 + 快速恢复）
//!
//! ## 架构
//!
//! ```text
//!  应用层 (client.rs / server.rs)
//!       │  send_frame / recv_frame
//!       ▼
//!  传输层 (transport.rs)  ← 本模块
//!       │  加密 + 压缩 + 编解码 + 重传 + 流控 + 拥塞控制
//!       ▼
//!  UDP Socket (tokio::net::UdpSocket)
//! ```
//!
//! ## 数据流
//!
//! **发送**：Frame → 压缩 → 加密 → 编码 → UDP send_to
//! **接收**：UDP recv → 解码 → 解密 → 解压 → Frame
//!
//! ## 多客户端支持
//!
//! 使用 mpsc channel 解耦 UDP 收发：
//! - 客户端：后台 task recv_from → 过滤 peer → channel
//! - 服务端：主循环 recv_from → 按 src_addr 分发 → 各 channel

use crate::compression::{Compressor, CompressionAlgo, CompressionConfig};
use crate::congestion::CongestionManager;
use crate::crypto::{aead, KeyPair, SessionKeys};
use crate::error::{LspError, Result};
use crate::flow_control::{FlowControlManager, DEFAULT_INITIAL_WINDOW};
use crate::protocol::*;
use crate::retransmission::{RetransmissionManager, RetransmitEvent};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, info, warn};

/// 接收通道容量
const RECV_CHANNEL_CAPACITY: usize = 512;
/// UDP 接收缓冲区大小
const UDP_RECV_BUF_SIZE: usize = 65535;
/// UDP socket 发送/接收缓冲区（Windows 默认仅 8KB，大文件分片需要更大）
const UDP_SOCKET_BUF_SIZE: usize = 512 * 1024;

/// 创建带大缓冲区的 UDP socket（socket2 → tokio）
pub async fn bind_udp_socket(addr: &str) -> Result<UdpSocket> {
    let sock_addr: SocketAddr = addr.parse()
        .map_err(|e| LspError::Protocol(format!("Invalid address: {}", e)))?;
    let sock = socket2::Socket::new(
        if sock_addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    let _ = sock.set_send_buffer_size(UDP_SOCKET_BUF_SIZE);
    let _ = sock.set_recv_buffer_size(UDP_SOCKET_BUF_SIZE);
    sock.set_nonblocking(true)?;
    sock.bind(&sock_addr.into())?;
    Ok(UdpSocket::from_std(sock.into())?)
}

// 自由函数：帧编解码（无状态，每次 new codec）

/// 将帧编码为字节
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(frame.frame_length());
    let mut codec = LspCodec::new();
    codec
        .encode(frame.clone(), &mut buf)
        .map_err(LspError::Io)?;
    Ok(buf.to_vec())
}

/// 从字节解码帧
pub fn decode_frame(data: &[u8]) -> Result<Frame> {
    let mut buf = BytesMut::from(data);
    let mut codec = LspCodec::new();
    codec
        .decode(&mut buf)
        .map_err(LspError::Io)?
        .ok_or_else(|| LspError::Protocol("Incomplete frame in UDP datagram".into()))
}

// UDP 连接

/// UDP 传输连接
///
/// 封装了 UDP socket + 编解码 + 加密 + 压缩 + 可靠传输 + 流控 + 拥塞控制。
/// client 和 server 共用此结构。
pub struct UdpConnection {
    /// UDP socket（客户端持有，用于发送；服务端通过 Arc 共享）
    socket: Arc<UdpSocket>,
    /// 对端地址
    peer_addr: SocketAddr,
    /// 接收通道（从后台 recv task 或 server 主循环接收原始 UDP 数据）
    recv_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// 加密会话密钥（握手后设置，RwLock 允许 Arc 共享时修改）
    pub session_keys: RwLock<Option<SessionKeys>>,
    /// 本端密钥对
    pub key_pair: KeyPair,
    /// 压缩器
    compressor: Compressor,
    /// 重传管理器
    pub retransmit_mgr: Arc<Mutex<RetransmissionManager>>,
    /// 流控管理器
    pub flow_ctrl_mgr: Arc<Mutex<FlowControlManager>>,
    /// 拥塞控制管理器
    pub congestion_mgr: Arc<Mutex<CongestionManager>>,
    /// 是否启用加密
    pub use_encryption: bool,
    /// 是否启用压缩
    pub use_compression: bool,
    /// 是否是客户端（决定加密方向）
    is_client: bool,
}

impl UdpConnection {
    // 构造

    /// 客户端：创建 UDP 连接
    ///
    /// 绑定本地随机端口，启动后台 recv task 过滤来自 peer 的数据报。
    /// 注意：不调用 socket.connect()，避免 Windows 上 connected UDP 的兼容性问题。
    pub async fn connect_client(
        server_addr: &str,
        use_encryption: bool,
        use_compression: bool,
    ) -> Result<Self> {
        let peer_addr: SocketAddr = server_addr
            .parse()
            .map_err(|e| LspError::Protocol(format!("Invalid server address: {}", e)))?;

        // 绑定到与 server 同族的地址（IPv4/IPv6）
        let bind_addr = if peer_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = bind_udp_socket(bind_addr).await?;
        let socket = Arc::new(socket);

        // 后台 recv task：只接收来自 peer 的数据报
        let (tx, rx) = mpsc::channel(RECV_CHANNEL_CAPACITY);
        let sock = socket.clone();
        let peer = peer_addr;
        tokio::spawn(async move {
            let mut buf = [0u8; UDP_RECV_BUF_SIZE];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((len, src)) if src == peer => {
                        if tx.send(buf[..len].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => { /* 忽略非 peer 来源 */ }
                    Err(e) => {
                        warn!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
        });

        info!("UDP client ready, target {}", peer_addr);

        Ok(Self {
            socket,
            peer_addr,
            recv_rx: Mutex::new(rx),
            session_keys: RwLock::new(None),
            key_pair: KeyPair::generate(),
            compressor: Compressor::new(CompressionConfig::default()),
            retransmit_mgr: Arc::new(Mutex::new(RetransmissionManager::new())),
            flow_ctrl_mgr: Arc::new(Mutex::new(FlowControlManager::new(
                DEFAULT_INITIAL_WINDOW,
            ))),
            congestion_mgr: Arc::new(Mutex::new(CongestionManager::new(
                DEFAULT_CHUNK_SIZE as u32,
            ))),
            use_encryption,
            use_compression,
            is_client: true,
        })
    }

    /// 服务端：为指定 peer 创建连接
    ///
    /// `recv_rx` 由 server 主循环通过 `recv_tx` 分发数据。
    pub fn from_peer(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        recv_rx: mpsc::Receiver<Vec<u8>>,
        use_encryption: bool,
        use_compression: bool,
    ) -> Self {
        Self {
            socket,
            peer_addr,
            recv_rx: Mutex::new(recv_rx),
            session_keys: RwLock::new(None),
            key_pair: KeyPair::generate(),
            compressor: Compressor::new(CompressionConfig::default()),
            retransmit_mgr: Arc::new(Mutex::new(RetransmissionManager::new())),
            flow_ctrl_mgr: Arc::new(Mutex::new(FlowControlManager::new(
                DEFAULT_INITIAL_WINDOW,
            ))),
            congestion_mgr: Arc::new(Mutex::new(CongestionManager::new(
                DEFAULT_CHUNK_SIZE as u32,
            ))),
            use_encryption,
            use_compression,
            is_client: false,
        }
    }

    // 发送

    /// 发送帧（压缩 → 加密 → 编码 → UDP send_to）
    pub async fn send_frame(&self, mut frame: Frame) -> Result<()> {
        // 压缩
        if self.use_compression && frame.payload.len() > 256 {
            let compressed = self.compressor.compress(&frame.payload, None);
            if compressed.compressed {
                frame.payload = Bytes::from(compressed.data);
                frame = frame.with_compression(
                    compressed.algo as u8,
                    compressed.original_size as u32,
                );
            }
        }

        // 加密
        if self.use_encryption {
            let keys_guard = self.session_keys.read().await;
            if let Some(ref keys) = *keys_guard {
                let nonce = aead::generate_nonce();
                let aad = build_aad(&frame);
                let write_key = if self.is_client {
                    &keys.client_write_key
                } else {
                    &keys.server_write_key
                };
                let (ciphertext, tag) = aead::encrypt(write_key, &nonce, &aad, &frame.payload);
                frame.payload = Bytes::from(ciphertext);
                frame = frame.with_encryption(nonce, tag);
            }
        }

        // 编码 + 发送
        let data = encode_frame(&frame)?;
        self.socket.send_to(&data, self.peer_addr).await?;

        Ok(())
    }

    /// 发送可靠帧（注册到重传管理器后发送）
    pub async fn send_reliable(&self, frame: Frame) -> Result<()> {
        self.send_frame_internal(frame, true).await
    }

    /// 内部发送（可选注册重传）
    async fn send_frame_internal(&self, mut frame: Frame, reliable: bool) -> Result<()> {
        let stream_id = frame.stream_id;
        let seq_num = frame.seq_num;
        let payload_len = frame.payload.len();

        // 压缩
        if self.use_compression && frame.payload.len() > 256 {
            let compressed = self.compressor.compress(&frame.payload, None);
            if compressed.compressed {
                frame.payload = Bytes::from(compressed.data);
                frame = frame.with_compression(
                    compressed.algo as u8,
                    compressed.original_size as u32,
                );
            }
        }

        // 加密
        if self.use_encryption {
            let keys_guard = self.session_keys.read().await;
            if let Some(ref keys) = *keys_guard {
                let nonce = aead::generate_nonce();
                let aad = build_aad(&frame);
                let write_key = if self.is_client {
                    &keys.client_write_key
                } else {
                    &keys.server_write_key
                };
                let (ciphertext, tag) = aead::encrypt(write_key, &nonce, &aad, &frame.payload);
                frame.payload = Bytes::from(ciphertext);
                frame = frame.with_encryption(nonce, tag);
            }
        }

        // 编码
        let data = encode_frame(&frame)?;

        // 注册重传
        if reliable {
            {
                let mut mgr = self.retransmit_mgr.lock().await;
                mgr.on_frame_sent(stream_id, seq_num, data.clone());
            }
            {
                let mut mgr = self.flow_ctrl_mgr.lock().await;
                mgr.on_data_sent(stream_id, payload_len as u32);
            }
        }

        // UDP 发送
        self.socket.send_to(&data, self.peer_addr).await?;

        Ok(())
    }

    // 接收

    /// 接收帧（从 channel 读原始数据 → 解码 → 解密 → 解压）
    pub async fn recv_frame(&self) -> Result<Frame> {
        let data = {
            let mut rx = self.recv_rx.lock().await;
            rx.recv()
                .await
                .ok_or(LspError::ConnectionClosed)?
        };

        let mut frame = decode_frame(&data)?;

        // 解密
        if frame.flags.has(Flags::ENCRYPTED) {
            let keys_guard = self.session_keys.read().await;
            if let Some(ref keys) = *keys_guard {
                if let (Some(nonce), Some(tag)) = (frame.nonce, frame.tag) {
                    let aad = build_aad(&frame);
                    let read_key = if self.is_client {
                        &keys.server_write_key
                    } else {
                        &keys.client_write_key
                    };
                    let plaintext =
                        aead::decrypt(read_key, &nonce, &aad, &frame.payload, &tag)
                            .map_err(|e| LspError::Decryption(e.to_string()))?;
                    frame.payload = Bytes::from(plaintext);
                }
            }
        }

        // 解压
        if frame.flags.has(Flags::COMPRESSED) {
            if let (Some(algo), Some(orig_size)) =
                (frame.compression_algo, frame.original_size)
            {
                let algo = CompressionAlgo::from_u8(algo)
                    .ok_or_else(|| LspError::Decompression("Unknown algo".into()))?;
                let decompressed = self
                    .compressor
                    .decompress(&frame.payload, algo, orig_size as usize)
                    .map_err(|e| LspError::Decompression(e.to_string()))?;
                frame.payload = Bytes::from(decompressed);
            }
        }

        Ok(frame)
    }

    // 可靠传输集成

    /// 处理收到的 ACK（更新重传/流控/拥塞状态）
    pub async fn handle_ack(&self, ack_seq: u32, stream_id: u32, bytes_acked: u32) {
        // 重传管理器
        let events = {
            let mut mgr = self.retransmit_mgr.lock().await;
            mgr.on_ack_received(stream_id, ack_seq, None)
        };

        for event in events {
            match event {
                RetransmitEvent::Retransmit {
                    stream_id: sid,
                    seq_num,
                    data,
                } => {
                    warn!("Fast retransmit: frame {} on stream {}", seq_num, sid);
                    if let Err(e) = self.socket.send_to(&data, self.peer_addr).await {
                        warn!("Retransmit send failed: {}", e);
                    }
                }
                RetransmitEvent::Dropped {
                    stream_id: sid,
                    seq_num,
                } => {
                    warn!("Frame dropped: {} on stream {} (max retransmits)", seq_num, sid);
                }
            }
        }

        // 流控
        {
            let mut mgr = self.flow_ctrl_mgr.lock().await;
            mgr.on_ack(stream_id, bytes_acked);
        }

        // 拥塞控制
        {
            let mut mgr = self.congestion_mgr.lock().await;
            mgr.on_ack(stream_id, bytes_acked, false, ack_seq);
        }
    }

    /// 检查超时重传（应由后台定时器定期调用）
    pub async fn check_retransmissions(&self) {
        let events = {
            let mut mgr = self.retransmit_mgr.lock().await;
            mgr.check_timeouts()
        };

        for event in events {
            match event {
                RetransmitEvent::Retransmit {
                    stream_id,
                    seq_num,
                    data,
                } => {
                    debug!(
                        "Timeout retransmit: frame {} on stream {}",
                        seq_num, stream_id
                    );
                    if let Err(e) = self.socket.send_to(&data, self.peer_addr).await {
                        warn!("Retransmit send failed: {}", e);
                    }
                    // 超时 → 拥塞控制
                    let mut mgr = self.congestion_mgr.lock().await;
                    mgr.on_timeout(stream_id);
                }
                RetransmitEvent::Dropped {
                    stream_id,
                    seq_num,
                } => {
                    warn!(
                        "Frame dropped after max retransmits: {} on stream {}",
                        seq_num, stream_id
                    );
                }
            }
        }
    }

    /// 启动后台重传检查定时器
    ///
    /// 每 50ms 检查一次超时重传。返回 JoinHandle，drop 时自动停止。
    pub fn spawn_retransmit_timer(self_arc: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(50));
            loop {
                interval.tick().await;
                self_arc.check_retransmissions().await;
            }
        })
    }

    // 流控查询

    /// 检查指定流是否可以发送数据（流控 + 拥塞窗口）
    pub async fn can_send(&self, stream_id: u32) -> bool {
        let flow_ok = {
            let mgr = self.flow_ctrl_mgr.lock().await;
            mgr.can_send(stream_id)
        };
        if !flow_ok {
            return false;
        }
        // 拥塞窗口检查：cwnd > 0 才允许发送
        let cwnd = {
            let mgr = self.congestion_mgr.lock().await;
            mgr.cwnd(stream_id)
        };
        cwnd > 0
    }

    /// 注册流到所有管理器
    pub async fn register_stream(&self, stream_id: u32) {
        {
            let mut mgr = self.retransmit_mgr.lock().await;
            mgr.register_stream(stream_id, 64);
        }
        {
            let mut mgr = self.flow_ctrl_mgr.lock().await;
            mgr.register_stream(stream_id, INITIAL_WINDOW_SIZE);
        }
        {
            let mut mgr = self.congestion_mgr.lock().await;
            mgr.register_stream(stream_id);
        }
    }

    /// 注销流
    pub async fn unregister_stream(&self, stream_id: u32) {
        {
            let mut mgr = self.retransmit_mgr.lock().await;
            mgr.unregister_stream(stream_id);
        }
        {
            let mut mgr = self.flow_ctrl_mgr.lock().await;
            mgr.unregister_stream(stream_id);
        }
        {
            let mut mgr = self.congestion_mgr.lock().await;
            mgr.unregister_stream(stream_id);
        }
    }

    // 访问器

    /// 设置会话密钥（握手完成后调用）
    pub async fn set_session_keys(&self, keys: SessionKeys) {
        let mut guard = self.session_keys.write().await;
        *guard = Some(keys);
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

/// 构建 AAD（附加认证数据）
fn build_aad(frame: &Frame) -> Vec<u8> {
    let mut aad = Vec::with_capacity(14);
    aad.extend_from_slice(&MAGIC.to_be_bytes());
    aad.push(frame.version);
    aad.push(frame.frame_type as u8);
    aad.extend_from_slice(&frame.stream_id.to_be_bytes());
    aad.extend_from_slice(&frame.seq_num.to_be_bytes());
    aad
}
