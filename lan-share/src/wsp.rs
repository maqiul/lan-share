//! WSP (WebSocket Share Protocol) — 自研 WebSocket 二进制协议
//!
//! 帧格式（16 字节头 + 变长 payload）:
//!   [0..2]   magic       0x57 0x53 ("WS")
//!   [2]      version     0x01
//!   [3]      msg_type    消息类型
//!   [4..8]   stream_id   u32 BE（多路复用）
//!   [8..12]  seq_num     u32 BE
//!   [12..16] payload_len u32 BE
//!   [16..]   payload     控制消息=JSON / 数据消息=二进制
//!
//! 并发安全设计:
//!   - mpsc 通道发帧：下载流式推送，不整文件加载
//!   - 连接计数器：全局上限 200，防资源耗尽
//!   - payload 上限 4MB：防伪造帧头撑爆内存
//!   - 上传大小上限 10GB：防写满磁盘
//!   - 锁粒度最小化：只在读写 ConnState 时持锁，I/O 在锁外

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};

use crate::webdav::WebDavState;

// 常量

pub const WSP_MAGIC: [u8; 2] = [0x57, 0x53]; // "WS"
pub const WSP_VERSION: u8 = 0x01;
pub const WSP_HEADER_LEN: usize = 16;

/// 单帧 payload 上限（防伪造帧头）
const MAX_PAYLOAD: usize = 4 * 1024 * 1024; // 4 MB
/// 全局最大并发连接数
const MAX_CONNECTIONS: usize = 200;
/// 单文件上传上限
const MAX_UPLOAD_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10 GB
/// 下载分块大小
const DOWNLOAD_CHUNK: usize = 64 * 1024; // 64 KB
/// 全局连接计数
static WSP_CONN_COUNT: AtomicUsize = AtomicUsize::new(0);

// 消息类型
pub const MSG_HELLO: u8 = 0x01;
pub const MSG_HELLO_ACK: u8 = 0x02;
pub const MSG_AUTH: u8 = 0x03;
pub const MSG_AUTH_ACK: u8 = 0x04;

pub const MSG_LIST_DIR: u8 = 0x10;
pub const MSG_LIST_DIR_RESP: u8 = 0x11;
pub const MSG_MKDIR: u8 = 0x14;
pub const MSG_RENAME: u8 = 0x15;
pub const MSG_DELETE: u8 = 0x16;
pub const MSG_OP_ACK: u8 = 0x17;

pub const MSG_UPLOAD_START: u8 = 0x20;
pub const MSG_UPLOAD_DATA: u8 = 0x21;
pub const MSG_UPLOAD_END: u8 = 0x22;
pub const MSG_UPLOAD_ACK: u8 = 0x23;

pub const MSG_DOWNLOAD_REQ: u8 = 0x30;
pub const MSG_DOWNLOAD_DATA: u8 = 0x31;
pub const MSG_DOWNLOAD_END: u8 = 0x32;

// 回收站操作
pub const MSG_TRASH_LIST: u8 = 0x40;
pub const MSG_TRASH_LIST_RESP: u8 = 0x41;
pub const MSG_TRASH_RESTORE: u8 = 0x42;
pub const MSG_TRASH_DELETE: u8 = 0x43; // 永久删除
pub const MSG_TRASH_EMPTY: u8 = 0x44; // 清空回收站

pub const MSG_ERROR: u8 = 0xF0;
pub const MSG_KEEPALIVE: u8 = 0xF1;

// 帧编解码

/// WSP 帧
#[derive(Debug, Clone)]
pub struct WspFrame {
    pub msg_type: u8,
    pub stream_id: u32,
    pub seq_num: u32,
    pub payload: Vec<u8>,
}

impl WspFrame {
    pub fn new(msg_type: u8, stream_id: u32, seq_num: u32, payload: Vec<u8>) -> Self {
        Self { msg_type, stream_id, seq_num, payload }
    }

    /// JSON 控制帧
    pub fn json<T: Serialize>(msg_type: u8, stream_id: u32, seq_num: u32, body: &T) -> Self {
        let payload = serde_json::to_vec(body).unwrap_or_default();
        Self::new(msg_type, stream_id, seq_num, payload)
    }

    /// 编码为字节
    pub fn encode(&self) -> Vec<u8> {
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

    /// 从字节解码（含 payload 大小校验）
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < WSP_HEADER_LEN {
            return Err(format!("帧太短: {} < {}", data.len(), WSP_HEADER_LEN));
        }
        if data[0] != WSP_MAGIC[0] || data[1] != WSP_MAGIC[1] {
            return Err("magic 不匹配".into());
        }
        if data[2] != WSP_VERSION {
            return Err(format!("版本不支持: {}", data[2]));
        }
        let msg_type = data[3];
        let stream_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let seq_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let payload_len = u32::from_be_bytes([data[12], data[13], data[14], data[15]]) as usize;
        // 防伪造帧头：payload 不得超过上限
        if payload_len > MAX_PAYLOAD {
            return Err(format!("payload 超限: {} > {}", payload_len, MAX_PAYLOAD));
        }
        if data.len() < WSP_HEADER_LEN + payload_len {
            return Err(format!("payload 不完整: {} < {}", data.len(), WSP_HEADER_LEN + payload_len));
        }
        let payload = data[WSP_HEADER_LEN..WSP_HEADER_LEN + payload_len].to_vec();
        Ok(Self { msg_type, stream_id, seq_num, payload })
    }

    /// 解析 JSON payload
    pub fn json_body<T: for<'de> Deserialize<'de>>(&self) -> Result<T, String> {
        serde_json::from_slice(&self.payload)
            .map_err(|e| format!("JSON 解析失败: {}", e))
    }
}

// 消息体定义

#[derive(Serialize, Deserialize)]
pub struct HelloMsg {
    pub client_name: String,
    pub version: u8,
}

#[derive(Serialize, Deserialize)]
pub struct HelloAckMsg {
    pub server_name: String,
    pub version: u8,
    pub ok: bool,
}

#[derive(Serialize, Deserialize)]
pub struct AuthMsg {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthAckMsg {
    pub ok: bool,
    pub user: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ListDirMsg {
    pub path: String,
}

#[derive(Serialize, Deserialize)]
pub struct DirEntryMsg {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListDirRespMsg {
    pub path: String,
    pub entries: Vec<DirEntryMsg>,
}

#[derive(Serialize, Deserialize)]
pub struct MkdirMsg {
    pub path: String,
}

#[derive(Serialize, Deserialize)]
pub struct RenameMsg {
    pub old_path: String,
    pub new_path: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeleteMsg {
    pub path: String,
}

#[derive(Serialize, Deserialize)]
pub struct OpAckMsg {
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UploadStartMsg {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
pub struct UploadEndMsg {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize)]
pub struct UploadAckMsg {
    pub ok: bool,
    pub offset: u64,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DownloadReqMsg {
    pub path: String,
    pub offset: u64,
}

#[derive(Serialize, Deserialize)]
pub struct DownloadEndMsg {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorMsg {
    pub code: u32,
    pub message: String,
}

// 连接状态

struct UploadState {
    path: PathBuf,
    file: tokio::fs::File,
    size: u64,
    received: u64,
}

struct ConnState {
    authenticated: bool,
    username: Option<String>,
    user_home: Option<PathBuf>,
    permissions: String,
    quota_mb: i64,
    seq: u32,
    uploads: HashMap<u32, UploadState>, // stream_id → upload
}

impl ConnState {
    fn new() -> Self {
        Self {
            authenticated: false,
            username: None,
            user_home: None,
            permissions: String::new(),
            quota_mb: 0,
            seq: 0,
            uploads: HashMap::new(),
        }
    }

    fn next_seq(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    fn can(&self, perm: &str) -> bool {
        self.permissions.split(',').any(|p| p.trim() == perm)
    }
}

// WebSocket 路由

/// GET /wsp → WebSocket 升级
pub async fn wsp_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebDavState>>,
) -> impl IntoResponse {
    // 连接数限流
    let count = WSP_CONN_COUNT.load(Ordering::Relaxed);
    if count >= MAX_CONNECTIONS {
        tracing::warn!("[WSP] 连接数已达上限 {}/{}", count, MAX_CONNECTIONS);
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "WSP 连接数已达上限").into_response();
    }

    ws.max_message_size(MAX_PAYLOAD + WSP_HEADER_LEN) // 限制单条消息大小
      .max_frame_size(MAX_PAYLOAD + WSP_HEADER_LEN)
      .on_upgrade(move |socket| wsp_connection(socket, state))
}

async fn wsp_connection(socket: WebSocket, state: Arc<WebDavState>) {
    use futures_util::{SinkExt, StreamExt};

    // 连接计数 +1，断开时 -1
    WSP_CONN_COUNT.fetch_add(1, Ordering::Relaxed);
    let _guard = scopeguard::guard((), |_| {
        WSP_CONN_COUNT.fetch_sub(1, Ordering::Relaxed);
    });

    let (mut tx, mut rx) = socket.split();
    let conn = Arc::new(Mutex::new(ConnState::new()));

    // mpsc 通道：handle_frame 通过通道发帧，sender task 统一写 WebSocket
    //   好处：下载可以流式逐块推送，不必整文件加载到内存
    let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(64);

    // sender task：从通道取帧，写入 WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(data) = frame_rx.recv().await {
            if tx.send(Message::Binary(data.into())).await.is_err() {
                break;
            }
        }
    });

    // 发送 Hello
    {
        let mut c = conn.lock().await;
        let hello = WspFrame::json(MSG_HELLO, 0, c.next_seq(), &HelloMsg {
            client_name: "LanShare-Server".into(),
            version: WSP_VERSION,
        });
        let _ = frame_tx.send(hello.encode()).await;
    }

    // 主循环：收帧 → 处理 → 通过通道发帧
    while let Some(Ok(msg)) = rx.next().await {
        let data = match msg {
            Message::Binary(b) => b.to_vec(),
            Message::Text(t) => t.as_bytes().to_vec(),
            Message::Close(_) => break,
            _ => continue,
        };

        let frame = match WspFrame::decode(&data) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("[WSP] 帧解码失败: {}", e);
                continue;
            }
        };

        // 处理帧，通过 frame_tx 流式发帧（下载不再整文件加载）
        handle_frame(&state, &conn, frame, &frame_tx).await;
    }

    // 清理：关闭通道 → sender task 退出 → 清理上传
    drop(frame_tx);
    let _ = send_task.await;
    let mut c = conn.lock().await;
    c.uploads.clear();
}

/// 计算目录总大小（字节）
async fn dir_size(path: &std::path::Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(meta) = tokio::fs::metadata(&path).await {
                total += meta.len();
            }
        }
    }
    total
}

/// 获取回收站目录（在用户共享目录下）
fn get_trash_dir(user_home: &std::path::Path) -> std::path::PathBuf {
    user_home.join(".trash")
}

/// 移动文件到回收站
async fn move_to_trash(user_home: &std::path::Path, target: &std::path::Path) -> Result<(), String> {
    let trash_dir = get_trash_dir(user_home);
    tokio::fs::create_dir_all(&trash_dir).await.map_err(|e| e.to_string())?;

    // 生成唯一文件名：原名_时间戳
    let file_name = target.file_name().unwrap_or_default().to_string_lossy();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let trash_name = format!("{}_{}", file_name, timestamp);
    let trash_path = trash_dir.join(&trash_name);

    // 保存原始路径信息（用于恢复）
    let relative_path = target.strip_prefix(user_home).unwrap_or(target);
    let meta_path = trash_dir.join(format!("{}.meta", trash_name));
    tokio::fs::write(&meta_path, relative_path.to_string_lossy().as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    // 移动文件
    tokio::fs::rename(target, &trash_path).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// 从回收站恢复文件
async fn restore_from_trash(user_home: &std::path::Path, trash_name: &str) -> Result<(), String> {
    let trash_dir = get_trash_dir(user_home);
    let trash_path = trash_dir.join(trash_name);
    let meta_path = trash_dir.join(format!("{}.meta", trash_name));

    // 读取原始路径
    let original_relative = tokio::fs::read_to_string(&meta_path)
        .await
        .map_err(|e| format!("读取元数据失败: {}", e))?;
    let original_path = user_home.join(&original_relative);

    // 确保父目录存在
    if let Some(parent) = original_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| e.to_string())?;
    }

    // 移动回去
    tokio::fs::rename(&trash_path, &original_path).await.map_err(|e| e.to_string())?;
    // 删除元数据
    let _ = tokio::fs::remove_file(&meta_path).await;
    Ok(())
}

/// 永久删除回收站中的文件
async fn permanent_delete_from_trash(user_home: &std::path::Path, trash_name: &str) -> Result<(), String> {
    let trash_dir = get_trash_dir(user_home);
    let trash_path = trash_dir.join(trash_name);
    let meta_path = trash_dir.join(format!("{}.meta", trash_name));

    if trash_path.is_dir() {
        tokio::fs::remove_dir_all(&trash_path).await.map_err(|e| e.to_string())?;
    } else {
        tokio::fs::remove_file(&trash_path).await.map_err(|e| e.to_string())?;
    }
    let _ = tokio::fs::remove_file(&meta_path).await;
    Ok(())
}

/// 清空回收站
async fn empty_trash(user_home: &std::path::Path) -> Result<u64, String> {
    let trash_dir = get_trash_dir(user_home);
    if !trash_dir.exists() {
        return Ok(0);
    }

    let mut count = 0;
    let mut entries = tokio::fs::read_dir(&trash_dir).await.map_err(|e| e.to_string())?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        // 跳过 .meta 文件
        if path.extension().map(|e| e == "meta").unwrap_or(false) {
            let _ = tokio::fs::remove_file(&path).await;
            continue;
        }
        if path.is_dir() {
            let _ = tokio::fs::remove_dir_all(&path).await;
        } else {
            let _ = tokio::fs::remove_file(&path).await;
        }
        count += 1;
    }
    Ok(count)
}

async fn handle_frame(
    state: &Arc<WebDavState>,
    conn: &Arc<Mutex<ConnState>>,
    frame: WspFrame,
    frame_tx: &mpsc::Sender<Vec<u8>>,
) {
    let sid = frame.stream_id;

    // 锁粒度最小化：只在读写 ConnState 时持锁，I/O 在锁外
    //   Phase 1: 读状态
    let (authenticated, user_home, seq) = {
        let mut c = conn.lock().await;
        (c.authenticated, c.user_home.clone(), c.next_seq())
    };

    match frame.msg_type {
        // 握手
        MSG_HELLO => {
            let ack = WspFrame::json(MSG_HELLO_ACK, sid, seq, &HelloAckMsg {
                server_name: "LanShare".into(),
                version: WSP_VERSION,
                ok: true,
            });
            let _ = frame_tx.send(ack.encode()).await;
        }

        // 认证
        MSG_AUTH => {
            let msg: AuthMsg = match frame.json_body() {
                Ok(m) => m,
                Err(e) => { let _ = frame_tx.send(error_frame(sid, seq, 400, &e).encode()).await; return; }
            };
            let simple_mode = state.db.get_admin_setting("simple_mode")
                .map(|v| v != "false")
                .unwrap_or(true);
            // 简易模式和账号模式互斥
            let user = if simple_mode {
                // 简易模式: 只允许 PIN
                if msg.token == state.pin {
                    Some(crate::db::User {
                        id: 0,
                        username: "share".to_string(),
                        role: "user".to_string(),
                        shared_dir: None,
                        must_change_password: false,
                        permissions: "read,write,delete,rename,share,mkdir".to_string(),
                        quota_mb: 0,
                    })
                } else {
                    None
                }
            } else {
                // 账号模式: 只允许 session token
                state.db.verify_session(&msg.token)
            };

            let mut c = conn.lock().await;
            if let Some(user) = user {
                let home = resolve_user_dir(state, &user);
                c.authenticated = true;
                c.username = Some(user.username.clone());
                c.user_home = Some(home);
                c.permissions = user.permissions.clone();
                c.quota_mb = user.quota_mb;
                let _ = frame_tx.send(WspFrame::json(MSG_AUTH_ACK, sid, c.next_seq(), &AuthAckMsg {
                    ok: true, user: Some(user.username), error: None,
                }).encode()).await;
            } else {
                let _ = frame_tx.send(WspFrame::json(MSG_AUTH_ACK, sid, c.next_seq(), &AuthAckMsg {
                    ok: false, user: None, error: Some("token 无效或已过期".into()),
                }).encode()).await;
            }
        }

        // 以下需要认证
        _ if !authenticated => {
            let _ = frame_tx.send(error_frame(sid, seq, 401, "未认证").encode()).await;
        }

        // 列目录
        MSG_LIST_DIR => {
            let msg: ListDirMsg = match frame.json_body() {
                Ok(m) => m,
                Err(e) => { let _ = frame_tx.send(error_frame(sid, seq, 400, &e).encode()).await; return; }
            };
            let home = user_home.unwrap();
            let Some(dir) = safe_join(&home, &msg.path) else {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(error_frame(sid, c.next_seq(), 403, "路径非法").encode()).await;
                return;
            };
            // I/O 在锁外
            let result = list_dir_entries(&dir).await;
            let mut c = conn.lock().await;
            match result {
                Ok(entries) => { let _ = frame_tx.send(WspFrame::json(MSG_LIST_DIR_RESP, sid, c.next_seq(), &ListDirRespMsg {
                    path: msg.path, entries,
                }).encode()).await; }
                Err(e) => { let _ = frame_tx.send(error_frame(sid, c.next_seq(), 500, &e).encode()).await; }
            }
        }

        // 建目录
        MSG_MKDIR => {
            let msg: MkdirMsg = match frame.json_body() {
                Ok(m) => m,
                Err(e) => { let _ = frame_tx.send(error_frame(sid, seq, 400, &e).encode()).await; return; }
            };
            // 权限检查
            {
                let c = conn.lock().await;
                if !c.can("mkdir") {
                    let _ = frame_tx.send(error_frame(sid, c.seq, 403, "无创建目录权限").encode()).await;
                    return;
                }
            }
            let home = user_home.unwrap();
            let Some(dir) = safe_join(&home, &msg.path) else {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(error_frame(sid, c.next_seq(), 403, "路径非法").encode()).await;
                return;
            };
            let result = tokio::fs::create_dir_all(&dir).await;
            let mut c = conn.lock().await;
            match result {
                Ok(()) => {
                    state.db.audit_log(None, c.username.as_deref().unwrap_or("?"), "mkdir", Some(&msg.path), None, None);
                    let _ = frame_tx.send(op_ack(sid, c.next_seq(), true, None).encode()).await;
                }
                Err(e) => { let _ = frame_tx.send(op_ack(sid, c.next_seq(), false, Some(e.to_string())).encode()).await; }
            }
        }

        // 重命名
        MSG_RENAME => {
            let msg: RenameMsg = match frame.json_body() {
                Ok(m) => m,
                Err(e) => { let _ = frame_tx.send(error_frame(sid, seq, 400, &e).encode()).await; return; }
            };
            // 权限检查
            {
                let c = conn.lock().await;
                if !c.can("rename") {
                    let _ = frame_tx.send(error_frame(sid, c.seq, 403, "无重命名权限").encode()).await;
                    return;
                }
            }
            let home = user_home.unwrap();
            let Some(old) = safe_join(&home, &msg.old_path) else {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(error_frame(sid, c.next_seq(), 403, "路径非法").encode()).await;
                return;
            };
            let Some(new) = safe_join(&home, &msg.new_path) else {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(error_frame(sid, c.next_seq(), 403, "路径非法").encode()).await;
                return;
            };
            let result = tokio::fs::rename(&old, &new).await;
            let mut c = conn.lock().await;
            match result {
                Ok(()) => {
                    state.db.audit_log(None, c.username.as_deref().unwrap_or("?"), "rename", Some(&msg.old_path), Some(&format!("→ {}", msg.new_path)), None);
                    let _ = frame_tx.send(op_ack(sid, c.next_seq(), true, None).encode()).await;
                }
                Err(e) => { let _ = frame_tx.send(op_ack(sid, c.next_seq(), false, Some(e.to_string())).encode()).await; }
            }
        }

        // 删除（移到回收站）
        MSG_DELETE => {
            let msg: DeleteMsg = match frame.json_body() {
                Ok(m) => m,
                Err(e) => { let _ = frame_tx.send(error_frame(sid, seq, 400, &e).encode()).await; return; }
            };
            // 权限检查
            {
                let c = conn.lock().await;
                if !c.can("delete") {
                    let _ = frame_tx.send(error_frame(sid, c.seq, 403, "无删除权限").encode()).await;
                    return;
                }
            }
            let home = user_home.unwrap();
            let Some(target) = safe_join(&home, &msg.path) else {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(error_frame(sid, c.next_seq(), 403, "路径非法").encode()).await;
                return;
            };
            // 移到回收站
            let result = move_to_trash(&home, &target).await;
            let mut c = conn.lock().await;
            match result {
                Ok(()) => {
                    state.db.audit_log(None, c.username.as_deref().unwrap_or("?"), "delete", Some(&msg.path), Some("移到回收站"), None);
                    let _ = frame_tx.send(op_ack(sid, c.next_seq(), true, None).encode()).await;
                }
                Err(e) => { let _ = frame_tx.send(op_ack(sid, c.next_seq(), false, Some(e)).encode()).await; }
            }
        }

        // 上传开始（支持断点续传）
        MSG_UPLOAD_START => {
            let msg: UploadStartMsg = match frame.json_body() {
                Ok(m) => m,
                Err(e) => { let _ = frame_tx.send(error_frame(sid, seq, 400, &e).encode()).await; return; }
            };
            // 权限检查
            {
                let c = conn.lock().await;
                if !c.can("write") {
                    let _ = frame_tx.send(WspFrame::json(MSG_UPLOAD_ACK, sid, c.seq, &UploadAckMsg {
                        ok: false, offset: 0, error: Some("无上传权限".into()),
                    }).encode()).await;
                    return;
                }
            }
            // 上传大小限制
            if msg.size > MAX_UPLOAD_SIZE {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(WspFrame::json(MSG_UPLOAD_ACK, sid, c.next_seq(), &UploadAckMsg {
                    ok: false, offset: 0, error: Some(format!("文件超过上限 {}GB", MAX_UPLOAD_SIZE / 1024 / 1024 / 1024)),
                }).encode()).await;
                return;
            }
            // 配额检查
            {
                let mut c = conn.lock().await;
                if c.quota_mb > 0 {
                    let quota_bytes = (c.quota_mb as u64) * 1024 * 1024;
                    let home = user_home.as_ref().unwrap();
                    let current_usage = dir_size(home).await;
                    // 如果是续传，减去已有文件大小
                    let existing_size = tokio::fs::metadata(home.join(&msg.path)).await.map(|m| m.len()).unwrap_or(0);
                    let net_add = msg.size.saturating_sub(existing_size);
                    if current_usage + net_add > quota_bytes {
                        let _ = frame_tx.send(WspFrame::json(MSG_UPLOAD_ACK, sid, c.next_seq(), &UploadAckMsg {
                            ok: false, offset: 0, error: Some(format!(
                                "超出配额限制 ({} MB / {} MB)",
                                current_usage / 1024 / 1024,
                                c.quota_mb
                            )),
                        }).encode()).await;
                        return;
                    }
                }
            }
            let home = user_home.unwrap();
            let Some(path) = safe_join(&home, &msg.path) else {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(WspFrame::json(MSG_UPLOAD_ACK, sid, c.next_seq(), &UploadAckMsg {
                    ok: false, offset: 0, error: Some("路径非法".into()),
                }).encode()).await;
                return;
            };
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            // 断点续传：检查已有文件大小
            let existing_size = tokio::fs::metadata(&path).await.map(|m| m.len()).unwrap_or(0);
            let resume_offset = if existing_size > 0 && existing_size < msg.size {
                existing_size // 部分上传，从已有大小处续传
            } else if existing_size == msg.size {
                msg.size // 已完整上传
            } else {
                0 // 新文件或已有文件比声明大（损坏），从头开始
            };

            // 打开文件：续传时不截断，新上传时截断
            let result = if resume_offset > 0 {
                tokio::fs::OpenOptions::new().write(true).open(&path).await
            } else {
                tokio::fs::File::create(&path).await
            };

            let mut c = conn.lock().await;
            match result {
                Ok(file) => {
                    c.uploads.insert(sid, UploadState {
                        path, file, size: msg.size, received: resume_offset,
                    });
                    let _ = frame_tx.send(WspFrame::json(MSG_UPLOAD_ACK, sid, c.next_seq(), &UploadAckMsg {
                        ok: true, offset: resume_offset, error: None,
                    }).encode()).await;
                }
                Err(e) => { let _ = frame_tx.send(WspFrame::json(MSG_UPLOAD_ACK, sid, c.next_seq(), &UploadAckMsg {
                    ok: false, offset: 0, error: Some(e.to_string()),
                }).encode()).await; }
            }
        }

        // 上传数据
        MSG_UPLOAD_DATA => {
            use tokio::io::{AsyncSeekExt, AsyncWriteExt};
            if frame.payload.len() < 8 {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(error_frame(sid, c.next_seq(), 400, "UploadData 太短").encode()).await;
                return;
            }
            let offset = u64::from_be_bytes(frame.payload[0..8].try_into().unwrap());
            let data = &frame.payload[8..];

            // 锁内只做 seek+write，结果在锁外发帧
            let result = {
                let mut c = conn.lock().await;
                if let Some(up) = c.uploads.get_mut(&sid) {
                    // 校验写入偏移不超过声明大小
                    if offset + data.len() as u64 > up.size {
                        Err(format!("写入越界: offset={} + len={} > size={}", offset, data.len(), up.size))
                    } else {
                        let _ = up.file.seek(std::io::SeekFrom::Start(offset)).await;
                        match up.file.write_all(data).await {
                            Ok(()) => {
                                up.received = offset + data.len() as u64;
                                Ok(up.received)
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    }
                } else {
                    Err("未找到上传会话".to_string())
                }
            };

            let mut c = conn.lock().await;
            match result {
                Ok(received) => { let _ = frame_tx.send(WspFrame::json(MSG_UPLOAD_ACK, sid, c.next_seq(), &UploadAckMsg {
                    ok: true, offset: received, error: None,
                }).encode()).await; }
                Err(e) => { let _ = frame_tx.send(WspFrame::json(MSG_UPLOAD_ACK, sid, c.next_seq(), &UploadAckMsg {
                    ok: false, offset, error: Some(e),
                }).encode()).await; }
            }
        }

        // 上传结束
        MSG_UPLOAD_END => {
            use tokio::io::AsyncWriteExt;
            let up = {
                let mut c = conn.lock().await;
                c.uploads.remove(&sid)
            };
            if let Some(mut up) = up {
                let _ = up.file.flush().await;
                drop(up.file);
                // 校验接收字节数 == 声明大小
                if up.received != up.size {
                    tracing::warn!("[WSP] 上传大小不匹配: {:?} 声明={} 实际={}", up.path, up.size, up.received);
                    let _ = tokio::fs::remove_file(&up.path).await;
                    let mut c = conn.lock().await;
                    let _ = frame_tx.send(op_ack(sid, c.next_seq(), false, Some(format!(
                        "大小不匹配: 声明 {} 实际 {}", up.size, up.received
                    ))).encode()).await;
                } else {
                    tracing::info!("[WSP] 上传完成: {:?} ({} bytes)", up.path, up.received);
                    let mut c = conn.lock().await;
                    state.db.audit_log(None, c.username.as_deref().unwrap_or("?"), "upload", Some(&up.path.to_string_lossy()), Some(&format!("{} bytes", up.received)), None);
                    let _ = frame_tx.send(op_ack(sid, c.next_seq(), true, None).encode()).await;
                }
            } else {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(error_frame(sid, c.next_seq(), 400, "未找到上传会话").encode()).await;
            }
        }

        // 下载请求（流式，不整文件加载）
        MSG_DOWNLOAD_REQ => {
            let msg: DownloadReqMsg = match frame.json_body() {
                Ok(m) => m,
                Err(e) => { let _ = frame_tx.send(error_frame(sid, seq, 400, &e).encode()).await; return; }
            };
            let home = user_home.unwrap();
            let Some(path) = safe_join(&home, &msg.path) else {
                let mut c = conn.lock().await;
                let _ = frame_tx.send(error_frame(sid, c.next_seq(), 403, "路径非法").encode()).await;
                return;
            };

            // 流式读取：每次只读 DOWNLOAD_CHUNK，逐帧推送
            let file_result = tokio::fs::File::open(&path).await;
            match file_result {
                Ok(file) => {
                    use tokio::io::{AsyncReadExt, AsyncSeekExt};
                    let meta = file.metadata().await;
                    let total = meta.map(|m| m.len()).unwrap_or(0);
                    let mut reader = tokio::io::BufReader::new(file);
                    let _ = reader.seek(std::io::SeekFrom::Start(msg.offset)).await;

                    // 锁外流式推送：本地 seq 计数器，不持锁读文件
                    let mut local_seq = {
                        let mut c = conn.lock().await;
                        c.next_seq()
                    };
                    let mut buf = vec![0u8; DOWNLOAD_CHUNK];
                    let mut offset = msg.offset;
                    loop {
                        let n = match reader.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(e) => {
                                let mut c = conn.lock().await;
                                let _ = frame_tx.send(error_frame(sid, c.next_seq(), 500, &e.to_string()).encode()).await;
                                return;
                            }
                        };
                        let is_last = offset + n as u64 >= total;
                        let mut payload = Vec::with_capacity(9 + n);
                        payload.extend_from_slice(&offset.to_be_bytes());
                        payload.push(if is_last { 1 } else { 0 });
                        payload.extend_from_slice(&buf[..n]);
                        let f = WspFrame::new(MSG_DOWNLOAD_DATA, sid, local_seq, payload);
                        if frame_tx.send(f.encode()).await.is_err() {
                            return; // 客户端断开
                        }
                        local_seq += 1;
                        offset += n as u64;
                    }
                    let mut c = conn.lock().await;
                    // 同步 seq 计数器
                    c.seq = local_seq;
                    state.db.audit_log(None, c.username.as_deref().unwrap_or("?"), "download", Some(&msg.path), Some(&format!("{} bytes", total)), None);
                    let _ = frame_tx.send(WspFrame::json(MSG_DOWNLOAD_END, sid, c.next_seq(), &DownloadEndMsg {
                        path: msg.path, size: total,
                    }).encode()).await;
                }
                Err(e) => {
                    let mut c = conn.lock().await;
                    let _ = frame_tx.send(error_frame(sid, c.next_seq(), 404, &e.to_string()).encode()).await;
                }
            }
        }

        // 回收站：列出
        MSG_TRASH_LIST => {
            let home = user_home.unwrap();
            let trash_dir = get_trash_dir(&home);
            let mut entries = Vec::new();
            if trash_dir.exists() {
                if let Ok(mut rd) = tokio::fs::read_dir(&trash_dir).await {
                    while let Ok(Some(entry)) = rd.next_entry().await {
                        let name = entry.file_name().to_string_lossy().to_string();
                        // 跳过 .meta 文件
                        if name.ends_with(".meta") { continue; }
                        let meta_path = trash_dir.join(format!("{}.meta", name));
                        let original_path = tokio::fs::read_to_string(&meta_path).await.unwrap_or_default();
                        let is_dir = entry.path().is_dir();
                        let size = if is_dir {
                            dir_size(&entry.path()).await
                        } else {
                            entry.metadata().await.map(|m| m.len()).unwrap_or(0)
                        };
                        entries.push(serde_json::json!({
                            "name": name,
                            "original_path": original_path,
                            "is_dir": is_dir,
                            "size": size,
                        }));
                    }
                }
            }
            let mut c = conn.lock().await;
            let resp = serde_json::json!({ "entries": entries });
            let _ = frame_tx.send(WspFrame::json(MSG_TRASH_LIST_RESP, sid, c.next_seq(), &resp).encode()).await;
        }

        // 回收站：恢复
        MSG_TRASH_RESTORE => {
            let msg: serde_json::Value = match frame.json_body() {
                Ok(m) => m,
                Err(e) => { let _ = frame_tx.send(error_frame(sid, seq, 400, &e).encode()).await; return; }
            };
            let trash_name = msg.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let home = user_home.unwrap();
            let result = restore_from_trash(&home, trash_name).await;
            let mut c = conn.lock().await;
            match result {
                Ok(()) => {
                    state.db.audit_log(None, c.username.as_deref().unwrap_or("?"), "trash_restore", Some(trash_name), None, None);
                    let _ = frame_tx.send(op_ack(sid, c.next_seq(), true, None).encode()).await;
                }
                Err(e) => { let _ = frame_tx.send(op_ack(sid, c.next_seq(), false, Some(e)).encode()).await; }
            }
        }

        // 回收站：永久删除
        MSG_TRASH_DELETE => {
            let msg: serde_json::Value = match frame.json_body() {
                Ok(m) => m,
                Err(e) => { let _ = frame_tx.send(error_frame(sid, seq, 400, &e).encode()).await; return; }
            };
            let trash_name = msg.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let home = user_home.unwrap();
            let result = permanent_delete_from_trash(&home, trash_name).await;
            let mut c = conn.lock().await;
            match result {
                Ok(()) => {
                    state.db.audit_log(None, c.username.as_deref().unwrap_or("?"), "trash_delete", Some(trash_name), Some("永久删除"), None);
                    let _ = frame_tx.send(op_ack(sid, c.next_seq(), true, None).encode()).await;
                }
                Err(e) => { let _ = frame_tx.send(op_ack(sid, c.next_seq(), false, Some(e)).encode()).await; }
            }
        }

        // 回收站：清空
        MSG_TRASH_EMPTY => {
            let home = user_home.unwrap();
            let result = empty_trash(&home).await;
            let mut c = conn.lock().await;
            match result {
                Ok(count) => {
                    state.db.audit_log(None, c.username.as_deref().unwrap_or("?"), "trash_empty", None, Some(&format!("删除 {} 项", count)), None);
                    let resp = serde_json::json!({ "ok": true, "deleted": count });
                    let _ = frame_tx.send(WspFrame::json(MSG_OP_ACK, sid, c.next_seq(), &resp).encode()).await;
                }
                Err(e) => { let _ = frame_tx.send(op_ack(sid, c.next_seq(), false, Some(e)).encode()).await; }
            }
        }

        // 心跳
        MSG_KEEPALIVE => {
            let mut c = conn.lock().await;
            let _ = frame_tx.send(WspFrame::new(MSG_KEEPALIVE, sid, c.next_seq(), vec![]).encode()).await;
        }

        _ => {
            let mut c = conn.lock().await;
            let _ = frame_tx.send(error_frame(sid, c.next_seq(), 400, &format!("未知消息类型: 0x{:02X}", frame.msg_type)).encode()).await;
        }
    }
}

// 辅助函数

fn error_frame(sid: u32, seq: u32, code: u32, msg: &str) -> WspFrame {
    WspFrame::json(MSG_ERROR, sid, seq, &ErrorMsg {
        code,
        message: msg.to_string(),
    })
}

fn op_ack(sid: u32, seq: u32, ok: bool, error: Option<String>) -> WspFrame {
    WspFrame::json(MSG_OP_ACK, sid, seq, &OpAckMsg { ok, error })
}

/// 解析用户可访问的共享目录（与 webdav.rs 逻辑一致）
fn resolve_user_dir(state: &WebDavState, user: &crate::db::User) -> PathBuf {
    let dir = if user.role == "admin" || user.id == 0 {
        state.shared_dir.clone()
    } else if let Some(dir) = &user.shared_dir {
        let p = PathBuf::from(dir);
        if p.is_absolute() { p } else { state.shared_dir.join(p) }
    } else {
        state.shared_dir.clone()
    };
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 安全路径拼接（防路径穿越）
/// 返回 None 表示路径非法（含 .. 或逃逸出 home）
fn safe_join(home: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim_start_matches('/').trim_start_matches('\\');
    // 空路径 = 根目录
    if rel.is_empty() {
        return home.canonicalize().ok();
    }
    // 拒绝含 .. 的路径组件（防穿越）
    if rel.split(['/', '\\']).any(|c| c == "..") {
        return None;
    }
    let joined = home.join(rel);
    // 文件已存在：canonicalize 后验证前缀
    if let Ok(p) = joined.canonicalize() {
        if let Ok(h) = home.canonicalize() {
            if p.starts_with(&h) { return Some(p); }
        }
        return None;
    }
    // 文件不存在（上传/建目录）：验证父目录在 home 内
    if let Some(parent) = joined.parent() {
        if let Ok(cp) = parent.canonicalize() {
            if let Ok(h) = home.canonicalize() {
                if cp.starts_with(&h) { return Some(joined); }
            }
        }
    }
    // 兜底：只允许简单文件名（不含任何路径分隔符）
    if !rel.contains('/') && !rel.contains('\\') {
        return Some(home.join(rel));
    }
    None
}

async fn list_dir_entries(dir: &Path) -> Result<Vec<DirEntryMsg>, String> {
    let mut entries = Vec::new();
    let mut rd = tokio::fs::read_dir(dir).await
        .map_err(|e| format!("无法读取目录: {}", e))?;
    while let Some(entry) = rd.next_entry().await.map_err(|e| e.to_string())? {
        let name = entry.file_name().to_string_lossy().to_string();
        // 隐藏系统目录
        if name == ".trash" { continue; }
        let meta = entry.metadata().await.map_err(|e| e.to_string())?;
        let mtime = chrono::DateTime::<chrono::Local>::from(meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH))
            .format("%Y-%m-%d %H:%M:%S").to_string();
        entries.push(DirEntryMsg {
            name,
            is_dir: meta.is_dir(),
            size: meta.len(),
            mtime,
        });
    }
    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}
