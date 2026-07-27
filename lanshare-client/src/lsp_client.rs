//! LSP3 协议客户端 — 通过自研 UDP 协议连接 LanShare 服务端
//!
//! 提供同步接口（内部用 tokio runtime 桥接），供 WinFsp 回调使用。
//!
//! 并发模型：底层 [`LspClient`] 内置后台分发器，按 `stream_id` 将响应分发到各请求通道，
//! 多个请求可同时 in-flight。本封装通过 `Mutex<Arc<LspClient>>` 持有客户端——
//! 操作时克隆 `Arc` 后立即释放锁（不串行化），重连时持锁重建并交换。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lsp_protocol::{LspClient, LspError};
use tokio::runtime::Runtime;

// ── 数据结构（供 fs.rs 使用，mtime 为 Unix 秒时间戳字符串）──

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: String,
}

#[derive(Clone, Debug)]
pub struct StatResp {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: String,
    pub exists: bool,
}

// ── 连接管理 ──

/// LSP3 认证凭据：PIN 码或账号密码
#[derive(Clone, Debug)]
pub enum LspAuth {
    /// PIN 码认证
    Pin(String),
    /// 账号密码认证
    Account { username: String, password: String },
}

/// LSP3 客户端 — 同步接口，内部桥接 tokio
pub struct LspShareClient {
    rt: Runtime,
    inner: Arc<InnerLsp>,
    server_addr: String,
    auth: LspAuth,
    /// 连接健康状态：最近一次操作/探测成功为 true，连接类失败为 false。供托盘显示连接状态。
    healthy: Arc<AtomicBool>,
    /// 认证后服务端授予的权限列表（逗号分隔，如 "read,write,delete,rename,mkdir"）。
    /// 决定挂载卷是否可写：无任何写类权限时 WinFsp 以只读卷挂载。
    permission: String,
}

struct InnerLsp {
    /// 当前客户端；操作时克隆 Arc 后释放锁，重连时持锁重建交换
    client: tokio::sync::Mutex<Arc<LspClient>>,
}

/// 建立一个新的 LSP3 客户端（UDP 连接 + 握手 + 认证），返回客户端与服务端授予的权限字符串
async fn build_client(addr: &str, auth: &LspAuth) -> Result<(LspClient, String), LspError> {
    let device_id = format!("lanshare-mount-{}", std::process::id());
    let mut client = LspClient::connect(addr, device_id, "LanShare Mount Client".to_string()).await?;
    client.handshake().await?;
    let permission = match auth {
        LspAuth::Pin(pin) => client.authenticate(pin).await?,
        LspAuth::Account { username, password } => {
            client.authenticate_account(username, password).await?
        }
    };
    Ok((client, permission))
}

/// 判断是否为连接类错误（值得重连重试）
///
/// UDP 会话一旦断开，加密密钥/会话状态即失效，必须完整重新握手+认证。
fn is_transient(e: &LspError) -> bool {
    matches!(
        e,
        LspError::ConnectionClosed
            | LspError::Timeout(_)
            | LspError::RetransmitLimitExceeded(_)
            | LspError::Io(_)
    )
}

impl LspShareClient {
    /// 创建客户端并连接 + 认证
    pub fn connect(server_addr: &str, auth: LspAuth) -> Result<Self, String> {
        let rt = Runtime::new().map_err(|e| format!("创建 runtime 失败: {}", e))?;
        let (client, permission) = rt
            .block_on(build_client(server_addr, &auth))
            .map_err(|e| format!("LSP3 连接失败: {}", e))?;
        Ok(Self {
            rt,
            inner: Arc::new(InnerLsp {
                client: tokio::sync::Mutex::new(Arc::new(client)),
            }),
            server_addr: server_addr.to_string(),
            auth,
            healthy: Arc::new(AtomicBool::new(true)),
            permission,
        })
    }

    /// 重建连接。仅当当前客户端仍是触发失败的那个（Arc 相同）时才重建，
    /// 避免并发请求重复重连。
    ///
    /// 不依赖 `is_connected()` 判断：服务端重启后，旧连接的分发器仍在空转
    /// （UDP recv 不会报错），`is_connected()` 会误判为已连接而跳过重连，
    /// 导致客户端永远无法恢复。改用 Arc 身份比较准确判断是否已被重连。
    async fn reconnect(&self, failed: &Arc<LspClient>) -> Result<(), String> {
        let mut guard = self.inner.client.lock().await;
        // 已被其他任务重连（Arc 已更换）则跳过
        if !Arc::ptr_eq(&guard, failed) {
            return Ok(());
        }
        let new_client = build_client(&self.server_addr, &self.auth)
            .await
            .map_err(|e| format!("LSP3 重连失败: {}", e))?;
        *guard = Arc::new(new_client.0);
        Ok(())
    }

    /// 包裹一个操作：连接类错误时自动重连并重试一次
    async fn with_retry<F, Fut, T>(&self, mut op: F) -> Result<T, String>
    where
        F: FnMut(Arc<LspClient>) -> Fut,
        Fut: std::future::Future<Output = Result<T, LspError>>,
    {
        let client = self.inner.client.lock().await.clone();
        match op(client.clone()).await {
            Ok(v) => {
                self.healthy.store(true, Ordering::Release);
                Ok(v)
            }
            Err(e) if is_transient(&e) => {
                self.healthy.store(false, Ordering::Release);
                self.reconnect(&client).await?;
                let client = self.inner.client.lock().await.clone();
                match op(client).await {
                    Ok(v) => {
                        self.healthy.store(true, Ordering::Release);
                        Ok(v)
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// 连接是否健康（最近一次操作/探测是否成功）。供托盘显示连接状态。
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// 是否具备写类权限（write/delete/rename/mkdir 任一）。决定挂载卷是否可写。
    /// 兼容旧格式 "readwrite"（视为全部权限）。
    pub fn is_writable(&self) -> bool {
        if self.permission == "readwrite" {
            return true;
        }
        self.permission
            .split(',')
            .any(|p| matches!(p.trim(), "write" | "delete" | "rename" | "mkdir"))
    }

    /// 检查是否具备指定权限项（如 "write"/"delete"/"rename"/"mkdir"）。
    /// 兼容旧格式 "readwrite"（视为全部权限）。
    pub fn can(&self, perm: &str) -> bool {
        if self.permission == "readwrite" {
            return true;
        }
        self.permission.split(',').any(|p| p.trim() == perm)
    }

    /// 强制重新连接（同步）。无论当前状态如何，都完整重新握手+认证，
    /// 成功后将健康状态置为 true。供托盘「重新连接」按钮调用。
    pub fn force_reconnect(&self) -> Result<(), String> {
        self.rt.block_on(async {
            let mut guard = self.inner.client.lock().await;
            let new_client = build_client(&self.server_addr, &self.auth)
                .await
                .map_err(|e| format!("LSP3 重连失败: {}", e))?;
            *guard = Arc::new(new_client.0);
            self.healthy.store(true, Ordering::Release);
            Ok(())
        })
    }

    /// 轻量健康探测：对根目录做一次 stat 以刷新健康状态。
    /// 服务端异常时会经由 with_retry 触发自动重连。供后台健康线程周期调用。
    pub fn probe(&self) -> bool {
        // stat 经由 with_retry 维护 healthy；探测仅触发一次往返以刷新状态
        let _ = self.stat("/");
        self.is_healthy()
    }

    // ── 公开同步接口 ──

    /// 列出目录
    pub fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>, String> {
        self.rt.block_on(self.with_retry(|c| async move {
            let entries = c.list_files(path, false).await?;
            Ok(entries
                .into_iter()
                .map(|e| DirEntry {
                    name: e.name,
                    is_dir: e.is_dir,
                    size: e.size,
                    mtime: e.modified.to_string(),
                })
                .collect())
        }))
    }

    /// 获取文件/目录元信息（不存在时返回 `exists == false`）
    pub fn stat(&self, path: &str) -> Result<StatResp, String> {
        self.rt.block_on(self.with_retry(|c| async move {
            match c.stat_file(path).await {
                Ok(e) => Ok(StatResp {
                    name: e.name,
                    is_dir: e.is_dir,
                    size: e.size,
                    mtime: e.modified.to_string(),
                    exists: true,
                }),
                Err(LspError::FileNotFound(_)) => Ok(StatResp {
                    name: basename(path),
                    is_dir: false,
                    size: 0,
                    mtime: "0".to_string(),
                    exists: false,
                }),
                Err(e) => Err(e),
            }
        }))
    }

    /// 下载文件（从 offset 开始读到末尾）
    pub fn download(&self, path: &str, offset: u64) -> Result<Vec<u8>, String> {
        self.rt.block_on(self.with_retry(|c| async move { c.read_range(path, offset, 0).await }))
    }

    /// 上传内存数据到远端文件（整文件替换）。供 WinFsp 写回缓存使用。
    pub fn upload_data(&self, path: &str, data: &[u8]) -> Result<u64, String> {
        let data = data.to_vec();
        self.rt.block_on(self.with_retry(|c| {
            let data = data.clone();
            async move { c.upload_data(&data, path).await }
        }))
    }

    /// 创建目录（含中间路径）
    pub fn mkdir(&self, path: &str) -> Result<(), String> {
        self.rt.block_on(self.with_retry(|c| async move { c.mkdir(path).await }))
    }

    /// 删除文件或目录（目录需 recursive=true）
    pub fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        self.rt.block_on(self.with_retry(|c| async move { c.delete_file(path, recursive).await }))
    }

    /// 重命名/移动
    pub fn rename(&self, old_path: &str, new_path: &str) -> Result<(), String> {
        self.rt.block_on(self.with_retry(|c| async move { c.rename(old_path, new_path).await }))
    }

    /// 请求文件锁（exclusive / shared），TTL 秒后自动过期。
    /// 服务端拒绝时返回 Err（文件已被其他客户端锁定）。
    pub fn lock_file(&self, path: &str, mode: &str, ttl_secs: u32) -> Result<(), String> {
        self.rt.block_on(self.with_retry(|c| async move {
            c.lock_file(path, mode, ttl_secs).await
        }))
    }

    /// 释放文件锁
    pub fn unlock_file(&self, path: &str) -> Result<(), String> {
        self.rt.block_on(self.with_retry(|c| async move {
            c.unlock_file(path).await
        }))
    }
}

/// 提取路径的最后一段作为文件名
fn basename(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string()
}
