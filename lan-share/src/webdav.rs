//! WebDAV server for LanShare
//! 让 Windows/Mac/Linux 可以把共享目录映射为网络驱动器

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, HeaderName, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{any, delete, get, post, put},
    Router,
};
use http_body_util::BodyExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::info;

/// 内嵌 Web UI
const UI_HTML: &str = include_str!("../assets/index.html");

/// WebDAV 服务状态
#[derive(Clone)]
pub struct WebDavState {
    pub shared_dir: PathBuf,
    /// canonicalize 后的共享目录（用于计算相对路径）
    pub canonical_dir: PathBuf,
    pub pin: String,
    pub device_name: String,
    pub local_ip: String,
    pub lsp_port: u16,
    pub webdav_port: u16,
    pub start_ts: i64,
    /// 配置文件路径（用于 Web UI 设置面板读写）
    #[allow(dead_code)]
    pub config_path: Option<PathBuf>,
    /// SQLite 数据库（多用户系统）
    pub db: Arc<crate::db::Database>,
}

/// 启动 WebDAV 服务器
pub async fn start_webdav_server(
    port: u16,
    shared_dir: PathBuf,
    pin: String,
    device_name: String,
    local_ip: String,
    lsp_port: u16,
    config_path: Option<PathBuf>,
    db: Arc<crate::db::Database>,
) -> Result<(), Box<dyn std::error::Error>> {
    let canonical_dir = shared_dir.canonicalize().unwrap_or_else(|_| shared_dir.clone());
    let start_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let state = Arc::new(WebDavState {
        shared_dir,
        canonical_dir,
        pin,
        device_name,
        local_ip,
        lsp_port,
        webdav_port: port,
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
        // Web UI + WebDAV + WSP
        .route("/", any(root_handler))
        .route("/ui", get(serve_ui))
        .route("/wsp", get(crate::wsp::wsp_upgrade))
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .fallback(any(handle_request))
        .layer(DefaultBodyLimit::disable())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    info!("WebDAV server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// 渲染并返回 Web UI（无需认证，数据操作才需要 PIN）
async fn serve_ui(State(state): State<Arc<WebDavState>>) -> Response {
    let html = UI_HTML
        .replace("{{DEVICE_NAME}}", &state.device_name)
        .replace("{{LOCAL_IP}}", &state.local_ip)
        .replace("{{WEBDAV_PORT}}", &state.webdav_port.to_string())
        .replace("{{LSP_PORT}}", &state.lsp_port.to_string())
        .replace("{{SHARED_DIR}}", &state.shared_dir.display().to_string())
        .replace("{{START_TS}}", &state.start_ts.to_string());
    Html(html).into_response()
}

/// 根路径统一入口：GET 返回 Web UI，其余方法走 WebDAV 协议
async fn root_handler(
    state: State<Arc<WebDavState>>,
    req: Request,
) -> Response {
    if req.method() == Method::GET {
        return serve_ui(state).await;
    }
    handle_request(state, req).await
}

/// 统一请求处理入口
async fn handle_request(
    State(state): State<Arc<WebDavState>>,
    req: Request,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // 认证：返回当前用户（支持 Bearer token / Basic auth / 简易 PIN）
    let user = match authenticate(&state, &headers, &uri) {
        Some(u) => u,
        None => return unauthorized(),
    };

    // 根据用户解析共享目录（admin 和简易模式用全局，普通用户用自己的）
    let shared_dir = resolve_shared_dir(&state, &user);

    let path = decode_path(uri.path());
    let fs_path = match safe_path(&shared_dir, &path) {
        Some(p) => p,
        None => return status_response(StatusCode::FORBIDDEN, "Path traversal denied"),
    };

    match method {
        Method::OPTIONS => handle_options(),
        Method::GET => handle_get(&fs_path).await,
        Method::HEAD => handle_head(&fs_path).await,
        Method::PUT => handle_put_stream(&fs_path, req.into_body()).await,
        Method::DELETE => handle_delete(&fs_path).await,
        _ if method.as_str() == "MKCOL" => handle_mkcol(&fs_path).await,
        _ if method.as_str() == "MOVE" => handle_move(&shared_dir, &fs_path, &headers).await,
        _ if method.as_str() == "COPY" => handle_copy(&shared_dir, &fs_path, &headers).await,
        _ if method.as_str() == "PROPFIND" => handle_propfind(&state, &fs_path, &headers).await,
        _ if method.as_str() == "PROPPATCH" => handle_proppatch(&state, &fs_path).await,
        _ if method.as_str() == "LOCK" => handle_lock(&fs_path).await,
        _ if method.as_str() == "UNLOCK" => status_response(StatusCode::NO_CONTENT, ""),
        _ => status_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed"),
    }
}

// 认证

/// 统一认证：返回当前用户
/// 支持三种方式：
/// 1. Bearer token（Web UI 会话）
/// 2. Basic auth username:password（账号模式，WebDAV 客户端）
/// 3. Basic auth share:PIN 或 ?token=PIN（简易模式，需 admin 开启 simple_mode）
/// 注意：简易模式和账号模式互斥
fn authenticate(state: &WebDavState, headers: &HeaderMap, uri: &Uri) -> Option<crate::db::User> {
    // 检查简易模式是否启用（默认 true，保持兼容）
    let simple_mode = state.db.get_admin_setting("simple_mode")
        .map(|v| v != "false")
        .unwrap_or(true);

    // 1. Authorization header
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        // Bearer token
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if simple_mode {
                // 简易模式：Bearer token = PIN 也放行
                if token == state.pin {
                    return Some(crate::db::User {
                        id: 0,
                        username: "share".to_string(),
                        role: "user".to_string(),
                        shared_dir: None,
                        must_change_password: false,
                        permissions: "read,write,delete,rename,share,mkdir".to_string(),
                        quota_mb: 0,
                    });
                }
                // 简易模式下管理员的 session token 也放行
                return state.db.verify_session(token);
            }
            return state.db.verify_session(token);
        }
        // Basic auth
        if let Some(b64) = auth.strip_prefix("Basic ") {
            use base64::Engine;
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                if let Ok(creds) = String::from_utf8(decoded) {
                    if let Some((username, password)) = creds.split_once(':') {
                        if simple_mode {
                            // 简易模式: 只允许 share:PIN
                            if username == "share" && password == state.pin {
                                return Some(crate::db::User {
                                    id: 0,
                                    username: "share".to_string(),
                                    role: "user".to_string(),
                                    shared_dir: None,
                                    must_change_password: false,
                                    permissions: "read,write,delete,rename,share,mkdir".to_string(),
                                    quota_mb: 0,
                                });
                            }
                            return None;
                        } else {
                            // 账号模式: 只允许 username:password
                            return state.db.verify_login(username, password);
                        }
                    }
                }
            }
        }
    }

    // 2. URL query token（?token=xxx）— 用于浏览器原生下载（<a> 标签无法带 header）
    if let Some(token) = query_token(uri) {
        if simple_mode {
            // 简易模式: PIN 或管理员 session token
            if token == state.pin {
                return Some(crate::db::User {
                    id: 0,
                    username: "share".to_string(),
                    role: "user".to_string(),
                    shared_dir: None,
                    must_change_password: false,
                    permissions: "read,write,delete,rename,share,mkdir".to_string(),
                    quota_mb: 0,
                });
            }
            // 管理员的 session token 也放行（下载用）
            return state.db.verify_session(&token);
        } else {
            // 账号模式: 只允许 session token
            return state.db.verify_session(&token);
        }
    }

    None
}

/// 根据用户解析其可访问的共享目录
/// - admin → 全局 shared_dir（可访问所有用户文件）
/// - 简易模式用户 (id=0) → 全局 shared_dir
/// - 普通用户 → 自己的 shared_dir（绝对路径直接用，相对路径相对全局 shared_dir）
/// 目录不存在时自动创建
pub(crate) fn resolve_shared_dir(state: &WebDavState, user: &crate::db::User) -> PathBuf {
    let dir = if user.role == "admin" || user.id == 0 {
        state.shared_dir.clone()
    } else if let Some(dir) = &user.shared_dir {
        let p = PathBuf::from(dir);
        if p.is_absolute() {
            p
        } else {
            // 相对路径：相对全局 shared_dir
            state.shared_dir.join(p)
        }
    } else {
        state.shared_dir.clone()
    };

    // 自动创建目录（首次访问时）
    let _ = std::fs::create_dir_all(&dir);

    dir
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"LanShare\"")],
        "Unauthorized",
    )
        .into_response()
}

// 路径安全

fn decode_path(raw: &str) -> String {
    percent_encoding::percent_decode_str(raw)
        .decode_utf8_lossy()
        .to_string()
}

/// 确保路径不会逃逸出 shared_dir
pub(crate) fn safe_path(base: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim_start_matches('/').replace('\\', "/");
    let full = base.join(&rel);
    let canonical_base = base.canonicalize().ok()?;
    let canonical_full = full.canonicalize().ok().or_else(|| {
        // 文件可能不存在（PUT/MKCOL），检查父目录
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

// OPTIONS

fn handle_options() -> Response {
    (
        StatusCode::OK,
        [
            (header::ALLOW, "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, LOCK, UNLOCK, PROPPATCH"),
            (HeaderName::from_static("dav"), "1, 2"),
            (HeaderName::from_static("ms-author-via"), "DAV"),
            (header::CONTENT_LENGTH, "0"),
        ],
        "",
    )
        .into_response()
}

// PROPFIND

async fn handle_propfind(state: &WebDavState, fs_path: &Path, headers: &HeaderMap) -> Response {
    let depth = headers
        .get("Depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("1");

    let mut responses = Vec::new();

    if fs_path.is_dir() {
        // 目录自身 — href 用 URL 路径
        let href = fs_path_to_url(&state.canonical_dir, fs_path);
        responses.push(propfind_entry(&href, fs_path, true).await);

        // Depth: 1 时列出子项
        if depth != "0" {
            if let Ok(mut entries) = fs::read_dir(fs_path).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    let is_dir = path.is_dir();
                    let child_href = fs_path_to_url(&state.canonical_dir, &path);
                    responses.push(propfind_entry(&child_href, &path, is_dir).await);
                }
            }
        }
    } else if fs_path.is_file() {
        let href = fs_path_to_url(&state.canonical_dir, fs_path);
        responses.push(propfind_entry(&href, fs_path, false).await);
    } else {
        return status_response(StatusCode::NOT_FOUND, "Not found");
    }

    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
{}
</D:multistatus>"#,
        responses.join("\n")
    );

    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml,
    )
        .into_response()
}

/// 把文件系统路径转成 URL 路径（相对于 shared_dir）
fn fs_path_to_url(canonical_dir: &Path, path: &Path) -> String {
    match path.strip_prefix(canonical_dir) {
        Ok(rel) => {
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if rel_str.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", rel_str)
            }
        }
        Err(_) => {
            // fallback: 用文件名
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            format!("/{}", name)
        }
    }
}

async fn propfind_entry(href: &str, fs_path: &Path, is_dir: bool) -> String {
    let name = fs_path
        .file_name()
        .map(|n| xml_escape(&n.to_string_lossy()))
        .unwrap_or_else(|| "share".to_string());

    // 异步 metadata，不阻塞 tokio 线程
    let (size, modified) = match tokio::fs::metadata(fs_path).await {
        Ok(meta) => {
            let size = meta.len();
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs())
                })
                .unwrap_or(0);
            (size, modified)
        }
        Err(_) => (0, 0),
    };

    let modified_str = http_date(modified);

    let resourcetype = if is_dir {
        "<D:resourcetype><D:collection/></D:resourcetype>"
    } else {
        "<D:resourcetype/>"
    };

    let content_length = if is_dir {
        String::new()
    } else {
        format!("<D:getcontentlength>{}</D:getcontentlength>", size)
    };

    format!(
        r#"<D:response>
  <D:href>{}</D:href>
  <D:propstat>
    <D:prop>
      <D:displayname>{}</D:displayname>
      {}
      <D:getlastmodified>{}</D:getlastmodified>
      {}
    </D:prop>
    <D:status>HTTP/1.1 200 OK</D:status>
  </D:propstat>
</D:response>"#,
        href, name, resourcetype, modified_str, content_length
    )
}

/// 从 URL query 解析 token 参数（?token=xxx 或 ?pin=xxx），供浏览器原生下载携带认证
fn query_token(uri: &Uri) -> Option<String> {
    let q = uri.query()?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "token" || k == "pin" {
                return Some(percent_encoding::percent_decode_str(v).decode_utf8_lossy().to_string());
            }
        }
    }
    None
}

// GET / HEAD

async fn handle_get(fs_path: &Path) -> Response {
    if fs_path.is_dir() {
        // 返回目录列表的简单 HTML
        return dir_listing(fs_path).await;
    }

    // 流式读取：边读边发，避免大文件整体载入内存
    let file = match tokio::fs::File::open(fs_path).await {
        Ok(f) => f,
        Err(_) => return status_response(StatusCode::NOT_FOUND, "File not found"),
    };
    let len = match file.metadata().await {
        Ok(m) => m.len(),
        Err(_) => return status_response(StatusCode::NOT_FOUND, "File not found"),
    };
    let mime = guess_mime(fs_path);
    // Content-Disposition: attachment 触发浏览器下载；filename* 支持中文文件名（RFC 5987）
    let file_name = fs_path.file_name().and_then(|n| n.to_str()).unwrap_or("download");
    let disposition = format!(
        "attachment; filename*=UTF-8''{}",
        percent_encoding::utf8_percent_encode(file_name, percent_encoding::NON_ALPHANUMERIC)
    );
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = Body::from_stream(stream);

    match Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, len.to_string())
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(body)
    {
        Ok(resp) => resp,
        Err(_) => status_response(StatusCode::INTERNAL_SERVER_ERROR, "Stream build error"),
    }
}

async fn handle_head(fs_path: &Path) -> Response {
    match tokio::fs::metadata(fs_path).await {
        Ok(meta) => {
            let mime = if meta.is_dir() {
                "httpd/unix-directory".to_string()
            } else {
                guess_mime(fs_path)
            };
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, mime.as_str()),
                    (header::CONTENT_LENGTH, &meta.len().to_string()),
                ],
                "",
            )
                .into_response()
        }
        Err(_) => status_response(StatusCode::NOT_FOUND, "Not found"),
    }
}

async fn dir_listing(fs_path: &Path) -> Response {
    let mut html = String::from("<html><head><meta charset='utf-8'><title>LanShare</title></head><body><h2>LanShare WebDAV</h2><ul>");

    if let Ok(mut entries) = fs::read_dir(fs_path).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_dir = entry.path().is_dir();
            let icon = if is_dir { "📁" } else { "📄" };
            html.push_str(&format!(
                "<li>{} <a href=\"{}\">{}</a></li>",
                icon,
                percent_encoding::utf8_percent_encode(&name, percent_encoding::NON_ALPHANUMERIC),
                xml_escape(&name)
            ));
        }
    }

    html.push_str("</ul></body></html>");

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

// PUT

async fn handle_put_stream(fs_path: &Path, mut body: Body) -> Response {
    // 确保父目录存在
    if let Some(parent) = fs_path.parent() {
        if let Err(_) = fs::create_dir_all(parent).await {
            return status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cannot create parent directory",
            );
        }
    }

    let existed = fs_path.exists();

    // 流式写盘：边收边写，内存恒定，支持任意大文件（不再受 2MB 限制，也不会爆内存）
    let write_result = async {
        let mut file = fs::File::create(fs_path).await?;
        while let Some(frame) = body.frame().await {
            let frame =
                frame.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            if let Ok(data) = frame.into_data() {
                file.write_all(&data).await?;
            }
        }
        file.flush().await?;
        Ok::<_, std::io::Error>(())
    }
    .await;

    match write_result {
        Ok(_) => {
            if existed {
                status_response(StatusCode::NO_CONTENT, "")
            } else {
                status_response(StatusCode::CREATED, "Created")
            }
        }
        Err(e) => {
            // 写失败清理半成品文件
            let _ = fs::remove_file(fs_path).await;
            status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Write failed: {}", e),
            )
        }
    }
}

// DELETE

async fn handle_delete(fs_path: &Path) -> Response {
    if fs_path.is_dir() {
        match fs::remove_dir_all(fs_path).await {
            Ok(_) => status_response(StatusCode::NO_CONTENT, ""),
            Err(e) => status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Delete failed: {}", e),
            ),
        }
    } else if fs_path.is_file() {
        match fs::remove_file(fs_path).await {
            Ok(_) => status_response(StatusCode::NO_CONTENT, ""),
            Err(e) => status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Delete failed: {}", e),
            ),
        }
    } else {
        status_response(StatusCode::NOT_FOUND, "Not found")
    }
}

// MKCOL

async fn handle_mkcol(fs_path: &Path) -> Response {
    if fs_path.exists() {
        return status_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Already exists",
        );
    }

    match fs::create_dir(fs_path).await {
        Ok(_) => status_response(StatusCode::CREATED, "Created"),
        Err(e) => status_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("MKCOL failed: {}", e),
        ),
    }
}

// MOVE / COPY

async fn handle_move(
    base: &Path,
    fs_path: &Path,
    headers: &HeaderMap,
) -> Response {
    let dest = match get_destination(base, headers) {
        Some(d) => d,
        None => return status_response(StatusCode::BAD_REQUEST, "Missing Destination header"),
    };

    if !fs_path.exists() {
        return status_response(StatusCode::NOT_FOUND, "Source not found");
    }

    // 如果目标已存在且 Overwrite: F，返回 412
    let overwrite = headers
        .get("Overwrite")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("T")
        != "F";

    if dest.exists() && !overwrite {
        return status_response(StatusCode::PRECONDITION_FAILED, "Destination exists");
    }

    if dest.exists() {
        if dest.is_dir() {
            let _ = fs::remove_dir_all(&dest).await;
        } else {
            let _ = fs::remove_file(&dest).await;
        }
    }

    match fs::rename(fs_path, &dest).await {
        Ok(_) => status_response(StatusCode::CREATED, "Moved"),
        Err(e) => status_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Move failed: {}", e),
        ),
    }
}

async fn handle_copy(
    base: &Path,
    fs_path: &Path,
    headers: &HeaderMap,
) -> Response {
    let dest = match get_destination(base, headers) {
        Some(d) => d,
        None => return status_response(StatusCode::BAD_REQUEST, "Missing Destination header"),
    };

    if !fs_path.exists() {
        return status_response(StatusCode::NOT_FOUND, "Source not found");
    }

    let overwrite = headers
        .get("Overwrite")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("T")
        != "F";

    if dest.exists() && !overwrite {
        return status_response(StatusCode::PRECONDITION_FAILED, "Destination exists");
    }

    let result = if fs_path.is_dir() {
        copy_dir_recursive(fs_path, &dest).await
    } else {
        fs::copy(fs_path, &dest).await.map(|_| ())
    };

    match result {
        Ok(_) => status_response(StatusCode::CREATED, "Copied"),
        Err(e) => status_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Copy failed: {}", e),
        ),
    }
}

async fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst).await?;
    let mut entries = fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            Box::pin(copy_dir_recursive(&src_path, &dst_path)).await?;
        } else {
            fs::copy(&src_path, &dst_path).await?;
        }
    }
    Ok(())
}

fn get_destination(base: &Path, headers: &HeaderMap) -> Option<PathBuf> {
    let dest_header = headers.get("Destination")?.to_str().ok()?;

    // Destination 可能是完整 URL 或路径
    let path = if dest_header.starts_with("http://") || dest_header.starts_with("https://") {
        // 提取路径部分
        let uri: Uri = dest_header.parse().ok()?;
        decode_path(uri.path())
    } else {
        decode_path(dest_header)
    };

    safe_path(base, &path)
}

// LOCK / PROPPATCH

async fn handle_lock(_fs_path: &Path) -> Response {
    let token = uuid::Uuid::new_v4().to_string();

    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>infinity</D:depth>
      <D:timeout>Second-3600</D:timeout>
      <D:locktoken>
        <D:href>opaquelocktoken:{}</D:href>
      </D:locktoken>
      <D:owner>LanShare</D:owner>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>"#,
        token
    );

    let mut resp = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml,
    )
        .into_response();

    resp.headers_mut().insert(
        HeaderName::from_static("lock-token"),
        format!("<opaquelocktoken:{}>", token).parse().unwrap(),
    );

    resp
}

async fn handle_proppatch(state: &WebDavState, fs_path: &Path) -> Response {
    let href = fs_path_to_url(&state.canonical_dir, fs_path);
    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>{}</D:href>
    <D:propstat>
      <D:prop/>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#,
        href
    );

    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml,
    )
        .into_response()
}

// 工具函数

fn status_response(code: StatusCode, msg: &str) -> Response {
    (code, msg.to_string()).into_response()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn http_date(timestamp: u64) -> String {
    if timestamp == 0 {
        return "Thu, 01 Jan 1970 00:00:00 GMT".to_string();
    }
    chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

fn guess_mime(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html",
        Some("txt") | Some("md") | Some("log") => "text/plain",
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("mp4") => "video/mp4",
        Some("mp3") => "audio/mpeg",
        _ => "application/octet-stream",
    }
    .to_string()
}