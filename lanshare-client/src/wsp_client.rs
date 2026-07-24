//! WSP 协议客户端 — 通过 WebSocket 连接 LanShare 服务端
//!
//! 提供同步接口（内部用 tokio runtime 桥接），供 WinFsp 回调使用。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

// ── WSP 帧常量（与服务端 wsp.rs 保持一致）──

const WSP_MAGIC: [u8; 2] = [0x57, 0x53]; // "WS"
const WSP_VERSION: u8 = 0x01;
const WSP_HEADER_LEN: usize = 16;
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

const MSG_HELLO: u8 = 0x01;
#[allow(dead_code)]
const MSG_HELLO_ACK: u8 = 0x02;
const MSG_AUTH: u8 = 0x03;
#[allow(dead_code)]
const MSG_AUTH_ACK: u8 = 0x04;

const MSG_LIST_DIR: u8 = 0x10;
#[allow(dead_code)]
const MSG_LIST_DIR_RESP: u8 = 0x11;
const MSG_STAT: u8 = 0x12;
#[allow(dead_code)]
const MSG_STAT_RESP: u8 = 0x13;

const MSG_DOWNLOAD_REQ: u8 = 0x30;
const MSG_DOWNLOAD_DATA: u8 = 0x31;
const MSG_DOWNLOAD_END: u8 = 0x32;

const MSG_ERROR: u8 = 0xF0;

// ── 消息结构体 ──

#[derive(Serialize, Deserialize)]
struct HelloMsg {
    client_name: String,
    version: u8,
}

#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
struct HelloAckMsg {
    #[allow(dead_code)]
    server_name: String,
    #[allow(dead_code)]
    version: u8,
    ok: bool,
}

#[derive(Serialize, Deserialize)]
struct AuthMsg {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct AuthAckMsg {
    ok: bool,
    #[allow(dead_code)]
    user: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ListDirMsg {
    path: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: String,
}

#[derive(Serialize, Deserialize)]
struct ListDirRespMsg {
    #[allow(dead_code)]
    path: String,
    entries: Vec<DirEntry>,
}

#[derive(Serialize, Deserialize)]
struct StatMsg {
    path: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StatResp {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: String,
    pub exists: bool,
}

#[derive(Serialize, Deserialize)]
struct DownloadReqMsg {
    path: String,
    offset: u64,
}

#[derive(Serialize, Deserialize)]
struct ErrorMsg {
    #[allow(dead_code)]
    code: u32,
    message: String,
}

// ── WSP 帧编解码 ──

#[derive(Debug, Clone)]
struct WspFrame {
    msg_type: u8,
    stream_id: u32,
    seq_num: u32,
    payload: Vec<u8>,
}

impl WspFrame {
    fn json<T: Serialize>(msg_type: u8, stream_id: u32, seq_num: u32, body: &T) -> Self {
        let payload = serde_json::to_vec(body).unwrap_or_default();
        Self { msg_type, stream_id, seq_num, payload }
    }

    fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(WSP_HEADER_LEN + self.payload.len());
        buf.extend_from_slice(&WSP_MAGIC);
        buf.push(WSP_VERSION);
        buf.push(self.msg_type);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&self.seq_num.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < WSP_HEADER_LEN {
            return Err(format!("帧太短: {}", data.len()));
        }
        if data[0] != WSP_MAGIC[0] || data[1] != WSP_MAGIC[1] {
            return Err("magic 不匹配".into());
        }
        let msg_type = data[3];
        let stream_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let seq_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let payload_len = u32::from_be_bytes([data[12], data[13], data[14], data[15]]) as usize;
        if payload_len > MAX_PAYLOAD {
            return Err(format!("payload 超限: {}", payload_len));
        }
        if data.len() < WSP_HEADER_LEN + payload_len {
            return Err("payload 不完整".into());
        }
        let payload = data[WSP_HEADER_LEN..WSP_HEADER_LEN + payload_len].to_vec();
        Ok(Self { msg_type, stream_id, seq_num, payload })
    }

    fn json_body<T: for<'de> Deserialize<'de>>(&self) -> Result<T, String> {
        serde_json::from_slice(&self.payload).map_err(|e| format!("JSON 解析失败: {}", e))
    }
}

// ── 连接管理 ──

type WsSink = futures_util::stream::SplitSink<
    WebSocketStream<MaybeTlsStream<TcpStream>>,
    Message,
>;
type WsStream = futures_util::stream::SplitStream<
    WebSocketStream<MaybeTlsStream<TcpStream>>,
>;

/// WSP 客户端 — 同步接口，内部桥接 tokio
pub struct WspClient {
    rt: Runtime,
    inner: Arc<Mutex<InnerClient>>,
    server_addr: String,
    token: String,
}

struct InnerClient {
    sink: Option<WsSink>,
    stream: Option<WsStream>,
    next_seq: AtomicU32,
    next_stream: AtomicU32,
}

impl WspClient {
    /// 创建客户端并连接 + 认证
    pub fn connect(server_addr: &str, token: &str) -> Result<Self, String> {
        let rt = Runtime::new().map_err(|e| format!("创建 runtime 失败: {}", e))?;
        let client = Self {
            rt,
            inner: Arc::new(Mutex::new(InnerClient {
                sink: None,
                stream: None,
                next_seq: AtomicU32::new(1),
                next_stream: AtomicU32::new(1),
            })),
            server_addr: server_addr.to_string(),
            token: token.to_string(),
        };
        client.rt.block_on(client.ensure_connected())?;
        Ok(client)
    }

    /// 确保 WebSocket 已连接（断线重连）
    async fn ensure_connected(&self) -> Result<(), String> {
        let need_connect = {
            let inner = self.inner.lock();
            inner.sink.is_none()
        };
        if !need_connect {
            return Ok(());
        }

        let url = format!("ws://{}/wsp", self.server_addr);
        let (ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| format!("WebSocket 连接失败: {}", e))?;
        let (sink, stream) = ws.split();

        {
            let mut inner = self.inner.lock();
            inner.sink = Some(sink);
            inner.stream = Some(stream);
        }

        // Hello 握手
        self.send_and_recv(MSG_HELLO, 0, &HelloMsg {
            client_name: "LanShareClient".into(),
            version: WSP_VERSION,
        }).await?;

        // 认证
        let auth_resp = self.send_and_recv(MSG_AUTH, 0, &AuthMsg {
            token: self.token.clone(),
        }).await?;
        let ack: AuthAckMsg = auth_resp.json_body()
            .map_err(|e| format!("认证响应解析失败: {}", e))?;
        if !ack.ok {
            return Err(format!("认证失败: {}", ack.error.unwrap_or_default()));
        }

        Ok(())
    }

    /// 发送帧并等待指定类型的响应
    async fn send_and_recv<T: Serialize>(
        &self,
        msg_type: u8,
        stream_id: u32,
        body: &T,
    ) -> Result<WspFrame, String> {
        let seq = {
            let inner = self.inner.lock();
            inner.next_seq.fetch_add(1, Ordering::Relaxed)
        };

        let frame = WspFrame::json(msg_type, stream_id, seq, body);
        let encoded = frame.encode();

        // 发送
        {
            let mut inner = self.inner.lock();
            if let Some(sink) = inner.sink.as_mut() {
                sink.send(Message::Binary(encoded.into()))
                    .await
                    .map_err(|e| format!("发送失败: {}", e))?;
            } else {
                return Err("未连接".into());
            }
        }

        // 接收响应（匹配 stream_id）
        let expected_resp = msg_type + 1; // 约定：响应 = 请求 + 1
        loop {
            let msg = {
                let mut inner = self.inner.lock();
                if let Some(stream) = inner.stream.as_mut() {
                    stream.next().await
                } else {
                    return Err("连接已断开".into());
                }
            };
            match msg {
                Some(Ok(Message::Binary(data))) => {
                    let resp = WspFrame::decode(&data)?;
                    if resp.msg_type == MSG_ERROR {
                        let err: ErrorMsg = resp.json_body().unwrap_or(ErrorMsg { code: 0, message: "未知错误".into() });
                        return Err(format!("服务端错误: {}", err.message));
                    }
                    if resp.stream_id == stream_id && resp.msg_type == expected_resp {
                        return Ok(resp);
                    }
                    // 不是我们要的响应，继续等
                }
                Some(Ok(Message::Close(_))) => {
                    // 连接关闭，重置
                    let mut inner = self.inner.lock();
                    inner.sink = None;
                    inner.stream = None;
                    return Err("连接已关闭".into());
                }
                Some(Err(e)) => {
                    let mut inner = self.inner.lock();
                    inner.sink = None;
                    inner.stream = None;
                    return Err(format!("接收错误: {}", e));
                }
                None => {
                    let mut inner = self.inner.lock();
                    inner.sink = None;
                    inner.stream = None;
                    return Err("连接已断开".into());
                }
                _ => {} // Ping/Pong 等忽略
            }
        }
    }

    /// 发送下载请求并收集所有数据帧
    async fn download_raw(&self, path: &str, offset: u64) -> Result<Vec<u8>, String> {
        self.ensure_connected().await?;

        let stream_id = {
            let inner = self.inner.lock();
            inner.next_stream.fetch_add(1, Ordering::Relaxed)
        };
        let seq = {
            let inner = self.inner.lock();
            inner.next_seq.fetch_add(1, Ordering::Relaxed)
        };

        let frame = WspFrame::json(MSG_DOWNLOAD_REQ, stream_id, seq, &DownloadReqMsg {
            path: path.to_string(),
            offset,
        });

        {
            let mut inner = self.inner.lock();
            if let Some(sink) = inner.sink.as_mut() {
                sink.send(Message::Binary(frame.encode().into()))
                    .await
                    .map_err(|e| format!("发送下载请求失败: {}", e))?;
            } else {
                return Err("未连接".into());
            }
        }

        let mut data = Vec::new();
        loop {
            let msg = {
                let mut inner = self.inner.lock();
                if let Some(stream) = inner.stream.as_mut() {
                    stream.next().await
                } else {
                    return Err("连接已断开".into());
                }
            };
            match msg {
                Some(Ok(Message::Binary(raw))) => {
                    let resp = WspFrame::decode(&raw)?;
                    if resp.stream_id != stream_id {
                        continue;
                    }
                    match resp.msg_type {
                        MSG_DOWNLOAD_DATA => {
                            // payload: [offset:8][is_last:1][data:N]
                            if resp.payload.len() > 9 {
                                data.extend_from_slice(&resp.payload[9..]);
                            }
                        }
                        MSG_DOWNLOAD_END => break,
                        MSG_ERROR => {
                            let err: ErrorMsg = resp.json_body().unwrap_or(ErrorMsg { code: 0, message: "下载错误".into() });
                            return Err(err.message);
                        }
                        _ => {}
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    let mut inner = self.inner.lock();
                    inner.sink = None;
                    inner.stream = None;
                    return Err("下载时连接断开".into());
                }
                Some(Err(e)) => {
                    let mut inner = self.inner.lock();
                    inner.sink = None;
                    inner.stream = None;
                    return Err(format!("下载接收错误: {}", e));
                }
                _ => {}
            }
        }
        Ok(data)
    }

    // ── 公开同步接口 ──

    /// 列出目录
    pub fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>, String> {
        self.rt.block_on(async {
            self.ensure_connected().await?;
            let resp = self.send_and_recv(MSG_LIST_DIR, 0, &ListDirMsg {
                path: path.to_string(),
            }).await?;
            let body: ListDirRespMsg = resp.json_body()
                .map_err(|e| format!("列目录响应解析失败: {}", e))?;
            Ok(body.entries)
        })
    }

    /// 获取文件/目录元信息
    pub fn stat(&self, path: &str) -> Result<StatResp, String> {
        self.rt.block_on(async {
            self.ensure_connected().await?;
            let resp = self.send_and_recv(MSG_STAT, 0, &StatMsg {
                path: path.to_string(),
            }).await?;
            resp.json_body().map_err(|e| format!("STAT 响应解析失败: {}", e))
        })
    }

    /// 下载文件（从 offset 开始）
    pub fn download(&self, path: &str, offset: u64) -> Result<Vec<u8>, String> {
        self.rt.block_on(self.download_raw(path, offset))
    }
}
