//! LanShare HTTP 服务器（Web UI + REST API + WSP WebSocket）

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;

/// 内嵌 Web UI
const UI_HTML: &str = include_str!("../assets/index.html");

/// 全局服务状态
#[derive(Clone)]
pub struct AppState {
    pub shared_dir: PathBuf,
    pub pin: String,
    pub device_name: String,
    pub local_ip: String,
    pub lsp_port: u16,
    pub web_port: u16,
    pub start_ts: i64,
    /// 配置文件路径（用于 Web UI 设置面板读写）
    #[allow(dead_code)]
    pub config_path: Option<PathBuf>,
    /// SQLite 数据库（多用户系统）
    pub db: Arc<crate::db::Database>,
}

/// 启动 HTTP 服务器
pub async fn start_web_server(
    port: u16,
    shared_dir: PathBuf,
    pin: String,
    device_name: String,
    local_ip: String,
    lsp_port: u16,
    config_path: Option<PathBuf>,
    db: Arc<crate::db::Database>,
) -> Result<(), Box<dyn std::error::Error>> {
    let start_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let state = Arc::new(AppState {
        shared_dir,
        pin,
        device_name,
        local_ip,
        lsp_port,
        web_port: port,
        start_ts,
        config_path,
        db,
    });

    let app = Router::new()
        // REST API
        .route("/api/mode", get(crate::api::get_mode))
        .route("/api/login", post(crate::api::login))
        .route("/api/logout", post(crate::api::logout))
        .route("/api/me", get(crate::api::me))
        .route("/api/change-password", post(crate::api::change_password))
        .route("/api/admin/users", get(crate::api::list_users).post(crate::api::create_user))
        .route("/api/admin/users/{id}", delete(crate::api::delete_user).put(crate::api::update_user))
        .route("/api/admin/users/{id}/password", put(crate::api::reset_user_password))
        .route("/api/admin/settings", get(crate::api::get_admin_settings).put(crate::api::set_admin_settings))
        .route("/api/admin/restart", post(crate::api::restart_server))
        .route("/api/user/settings", get(crate::api::get_user_settings).put(crate::api::set_user_settings))
        .route("/api/zip", get(crate::api::download_zip))
        .route("/api/share", post(crate::api::create_share))
        .route("/api/shares", get(crate::api::list_shares))
        .route("/api/share/{token}", delete(crate::api::delete_share))
        .route("/s/{token}", get(crate::api::access_share))
        .route("/api/discover", get(crate::api::discover_servers))
        .route("/api/admin/audit-logs", get(crate::api::get_audit_logs))
        // Web UI + WSP
        .route("/", get(serve_ui))
        .route("/ui", get(serve_ui))
        .route("/wsp", get(crate::wsp::wsp_upgrade))
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .layer(DefaultBodyLimit::disable())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    info!("Web server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// 渲染并返回 Web UI（无需认证，数据操作才需要登录）
async fn serve_ui(State(state): State<Arc<AppState>>) -> Response {
    let html = UI_HTML
        .replace("{{DEVICE_NAME}}", &state.device_name)
        .replace("{{LOCAL_IP}}", &state.local_ip)
        .replace("{{WEB_PORT}}", &state.web_port.to_string())
        .replace("{{LSP_PORT}}", &state.lsp_port.to_string())
        .replace("{{SHARED_DIR}}", &state.shared_dir.display().to_string())
        .replace("{{START_TS}}", &state.start_ts.to_string());
    let mut resp = Html(html).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    resp
}

/// 根据用户解析其可访问的共享目录
/// - admin → 全局 shared_dir（可访问所有用户文件）
/// - 简易模式用户 (id=0) → 全局 shared_dir
/// - 普通用户 → 自己的 shared_dir（绝对路径直接用，相对路径相对全局 shared_dir）
/// 目录不存在时自动创建
pub(crate) fn resolve_shared_dir(state: &AppState, user: &crate::db::User) -> PathBuf {
    let dir = if user.role == "admin" || user.id == 0 {
        state.shared_dir.clone()
    } else if let Some(dir) = &user.shared_dir {
        let p = PathBuf::from(dir);
        if p.is_absolute() {
            p
        } else {
            state.shared_dir.join(p)
        }
    } else {
        state.shared_dir.clone()
    };

    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 确保路径不会逃逸出 shared_dir
pub(crate) fn safe_path(base: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim_start_matches('/').replace('\\', "/");
    let full = base.join(&rel);
    let canonical_base = base.canonicalize().ok()?;
    let canonical_full = full.canonicalize().ok().or_else(|| {
        full.parent()?.canonicalize().ok().map(|p| {
            p.join(full.file_name().unwrap_or_default())
        })
    })?;

    if canonical_full.starts_with(&canonical_base) {
        Some(canonical_full)
    } else {
        None
    }
}
