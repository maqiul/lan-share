//! # LSP Protocol v3.0 - 局域网文件传输协议
//!
//! LSP (LanShare Protocol) 是一个轻量级的二进制协议，专为局域网文件传输设计。
//!
//! ## v3.0 特性
//!
//! - **端到端加密** — X25519 密钥交换 + ChaCha20-Poly1305 AEAD
//! - **可靠传输** — 序列号 + ACK + 超时重传 + 快速重传 + SACK
//! - **流量控制** — 滑动窗口 + 背压传导 + 零窗口探测
//! - **拥塞控制** — 慢启动 + 拥塞避免 + 快速恢复（RFC 5681）
//! - **差异传输** — rsync 风格增量同步（Adler-32 + SHA-256）
//! - **透明压缩** — LZ4（默认）/ Zstd，自动跳过不可压缩文件
//! - **多路复用** — 单连接上并行多个操作（Stream）
//! - **完整文件操作** — 列表/上传/下载/删除/重命名/创建目录/文件锁/元数据/变更通知
//! - **断点续传** — 支持 offset 读取
//! - **写入事务** — write_req → write_data → write_commit / write_rollback
//!
//! ## 帧格式
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |             Magic = 0x4C535033 ("LSP3")                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Version      |  FrameType    |          Flags                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Frame Length                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Stream ID                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! ## 模块结构
//!
//! - [`protocol`] — 帧格式、消息类型、编解码
//! - [`crypto`] — X25519 密钥交换 + AEAD 加密
//! - [`retransmission`] — 超时重传 + RTT 估算 + SACK
//! - [`flow_control`] — 滑动窗口流控
//! - [`congestion`] — TCP 风格拥塞控制
//! - [`diff_transfer`] — rsync 差异传输
//! - [`compression`] — LZ4/Zstd 透明压缩
//! - [`client`] — 客户端实现
//! - [`server`] — 服务端实现
//! - [`error`] — 错误类型

pub mod codec;
pub mod protocol;
pub mod client;
pub mod server;
pub mod error;
pub mod crypto;
pub mod retransmission;
pub mod flow_control;
pub mod congestion;
pub mod diff_transfer;
pub mod compression;
pub mod transport;

pub use codec::LspCodec;
pub use protocol::*;
pub use client::LspClient;
pub use server::{LspServer, ServerConfig, Session};
pub use error::LspError;
pub use crypto::{KeyPair, SessionKeys};
pub use retransmission::RetransmissionManager;
pub use flow_control::FlowControlManager;
pub use congestion::CongestionManager;
pub use diff_transfer::{DeltaComputer, FileSignature};
pub use compression::{Compressor, CompressionConfig, CompressionAlgo};
pub use transport::UdpConnection;
