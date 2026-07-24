//! REST API 模块
//! 登录/登出 / 用户管理（admin）/ 全局设置 / 用户设置

use crate::db::User;
use crate::server::AppState;
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

// 请求/响应结构

#[derive(Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResp {
    pub token: String,
    pub user: UserResp,
    pub must_change_password: bool,
}

#[derive(Serialize, Clone)]
pub struct UserResp {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub shared_dir: Option<String>,
    pub permissions: String,
    pub quota_mb: i64,
}

impl From<User> for UserResp {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            role: u.role,
            shared_dir: u.shared_dir,
            permissions: u.permissions,
            quota_mb: u.quota_mb,
        }
    }
}

#[derive(Deserialize)]
pub struct CreateUserReq {
    pub username: String,
    pub password: String,
    pub role: String,
    pub shared_dir: Option<String>,
    /// 权限列表（逗号分隔），默认全部权限
    #[serde(default = "default_permissions")]
    pub permissions: String,
    /// 配额（MB），0 表示不限，默认 0
    #[serde(default)]
    pub quota_mb: i64,
}

fn default_permissions() -> String {
    "read,write,delete,rename,share,mkdir".to_string()
}

#[derive(Deserialize)]
pub struct UpdateUserReq {
    pub role: Option<String>,
    pub shared_dir: Option<Option<String>>,
    pub permissions: Option<String>,
    pub quota_mb: Option<i64>,
}

#[derive(Deserialize)]
pub struct ChangePasswordReq {
    pub new_password: String,
}

// 认证辅助

/// 从 Authorization header 提取 Bearer token
pub fn extract_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|s| s.to_string())
}

/// 验证 Bearer token，返回 User（简易模式下 PIN 也放行）
pub fn auth_user(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let token = extract_token(headers)?;
    let simple_mode = state.db.get_admin_setting("simple_mode")
        .map(|v| v != "false")
        .unwrap_or(true);
    if simple_mode && token == state.pin {
        return Some(User {
            id: 0,
            username: "share".to_string(),
            role: "user".to_string(),
            shared_dir: None,
            must_change_password: false,
            permissions: "read,write,delete,rename,share,mkdir".to_string(),
            quota_mb: 0,
        });
    }
    state.db.verify_session(&token)
}

/// 要求登录，否则 401
macro_rules! require_auth {
    ($state:expr, $headers:expr) => {
        match auth_user($state, $headers) {
            Some(u) => u,
            None => return unauthorized_json("未登录或会话已"),
        }
    };
}

/// 要求 admin 权限
macro_rules! require_admin {
    ($user:expr) => {
        if $user.role != "admin" {
            return forbidden_json("需要管理员权限");
        }
    };
}

fn unauthorized_json(msg: &str) -> Response {
    json_resp(StatusCode::UNAUTHORIZED, &format!(r#"{{"error":"{msg}"}}"#))
}

fn forbidden_json(msg: &str) -> Response {
    json_resp(StatusCode::FORBIDDEN, &format!(r#"{{"error":"{msg}"}}"#))
}

fn bad_request_json(msg: &str) -> Response {
    json_resp(StatusCode::BAD_REQUEST, &format!(r#"{{"error":"{msg}"}}"#))
}

fn json_resp(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn ok_json<T: Serialize>(data: &T) -> Response {
    json_resp(StatusCode::OK, &serde_json::to_string(data).unwrap_or_default())
}

/// 密码复杂性验证：至少 8 位，包含大写、小写、数字中的至少 2 种
fn validate_password(pwd: &str) -> Result<(), String> {
    if pwd.len() < 8 {
        return Err("密码至少 8 位".to_string());
    }
    let has_upper = pwd.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = pwd.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = pwd.chars().any(|c| c.is_ascii_digit());
    let kinds = [has_upper, has_lower, has_digit].iter().filter(|&&x| x).count();
    if kinds < 2 {
        return Err("密码须包含大写字母、小写字母、数字中的至少 2 种".to_string());
    }
    Ok(())
}

// 登录 / 登出

/// GET /api/mode — 获取当前认证模式（无需登录）
pub async fn get_mode(State(state): State<Arc<AppState>>) -> Response {
    let simple_mode = state.db.get_admin_setting("simple_mode")
        .map(|v| v != "false")
        .unwrap_or(true);
    ok_json(&serde_json::json!({
        "simple_mode": simple_mode,
        "device_name": state.device_name,
    }))
}

/// POST /api/login
pub async fn login(State(state): State<Arc<AppState>>, Json(req): Json<LoginReq>) -> Response {
    // 简易模式下只允许管理员登录（用于进入设置界面）
    let simple_mode = state.db.get_admin_setting("simple_mode")
        .map(|v| v != "false")
        .unwrap_or(true);

    // 暴力破解防护：检查是否被锁定（数据库持久化）
    let (locked, remain_secs) = state.db.is_account_locked(&req.username);
    if locked {
        return json_resp(StatusCode::TOO_MANY_REQUESTS,
            &format!(r#"{{"error":"登录失败次数过多，请 {} 秒后重试"}}"#, remain_secs));
    }

    match state.db.verify_login(&req.username, &req.password) {
        Some(user) => {
            // 简易模式下只允许管理员登录
            if simple_mode && user.role != "admin" {
                return json_resp(StatusCode::FORBIDDEN, r#"{"error":"简易模式下请使用 PIN 码连接"}"#);
            }
            state.db.clear_failed_attempts(&req.username);
            state.db.record_login_attempt(&req.username, None, true);
            let token = match state.db.create_session(user.id) {
                Ok(t) => t,
                Err(e) => return json_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!(r#"{{"error":"{e}"}}"#)),
            };
            // 审计日志：登录成功
            state.db.audit_log(Some(user.id), &req.username, "login", None, Some("登录成功"), None);
            let resp = LoginResp {
                token,
                must_change_password: user.must_change_password,
                user: UserResp::from(user),
            };
            ok_json(&resp)
        }
        None => {
            state.db.record_login_attempt(&req.username, None, false);
            // 审计日志：登录失败
            state.db.audit_log(None, &req.username, "login_failed", None, Some("用户名或密码错误"), None);
            unauthorized_json("用户名或密码错误")
        }
    }
}

/// POST /api/logout
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = extract_token(&headers) {
        state.db.logout(&token);
    }
    json_resp(StatusCode::OK, r#"{"ok":true}"#)
}

/// GET /api/me — 当前登录用户信息
pub async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = require_auth!(&state, &headers);
    ok_json(&UserResp::from(user))
}

/// POST /api/change-password — 修改自己的密码
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordReq>,
) -> Response {
    let user = require_auth!(&state, &headers);
    if let Err(msg) = validate_password(&req.new_password) {
        return bad_request_json(&msg);
    }
    match state.db.change_password(user.id, &req.new_password) {
        Ok(()) => {
            state.db.audit_log(Some(user.id), &user.username, "change_password", None, Some("修改自己的密码"), None);
            json_resp(StatusCode::OK, r#"{"ok":true}"#)
        }
        Err(e) => json_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!(r#"{{"error":"{e}"}}"#)),
    }
}

// 用户管理（admin）

/// GET /api/admin/users
pub async fn list_users(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = require_auth!(&state, &headers);
    require_admin!(user);
    let users: Vec<UserResp> = state.db.list_users().into_iter().map(UserResp::from).collect();
    ok_json(&users)
}

/// POST /api/admin/users
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateUserReq>,
) -> Response {
    let user = require_auth!(&state, &headers);
    require_admin!(user);
    if req.username.is_empty() {
        return bad_request_json("用户名不能为空");
    }
    if let Err(msg) = validate_password(&req.password) {
        return bad_request_json(&msg);
    }
    if req.role != "admin" && req.role != "user" {
        return bad_request_json("role 必须是 admin 或 user");
    }

    // 共享目录：未指定时自动在全局根目录下创建用户名子文件夹
    let shared_dir = match req.shared_dir.as_deref() {
        Some(d) if !d.trim().is_empty() => Some(d.trim().to_string()),
        _ => {
            let user_dir = state.shared_dir.join(&req.username);
            if let Err(e) = tokio::fs::create_dir_all(&user_dir).await {
                return bad_request_json(&format!("创建用户目录失败: {}", e));
            }
            // 存相对路径（相对全局 shared_dir），方便移植
            Some(req.username.clone())
        }
    };

    match state.db.create_user(&req.username, &req.password, &req.role, shared_dir.as_deref(), &req.permissions, req.quota_mb) {
        Ok(id) => {
            state.db.audit_log(Some(user.id), &user.username, "create_user", None, Some(&format!("用户: {}", req.username)), None);
            json_resp(StatusCode::CREATED, &format!(r#"{{"ok":true,"id":{id}}}"#))
        }
        Err(e) => bad_request_json(&e),
    }
}

/// DELETE /api/admin/users/:id
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
) -> Response {
    let user = require_auth!(&state, &headers);
    require_admin!(user);
    match state.db.delete_user(user_id) {
        Ok(()) => {
            state.db.audit_log(Some(user.id), &user.username, "delete_user", None, Some(&format!("用户ID: {}", user_id)), None);
            json_resp(StatusCode::OK, r#"{"ok":true}"#)
        }
        Err(e) => bad_request_json(&e),
    }
}

/// PUT /api/admin/users/:id
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
    Json(req): Json<UpdateUserReq>,
) -> Response {
    let user = require_auth!(&state, &headers);
    require_admin!(user);
    match state.db.update_user(user_id, req.role.as_deref(), req.shared_dir.as_ref().map(|d| d.as_deref()), req.permissions.as_deref(), req.quota_mb) {
        Ok(()) => {
            state.db.audit_log(Some(user.id), &user.username, "update_user", None, Some(&format!("用户ID: {}", user_id)), None);
            json_resp(StatusCode::OK, r#"{"ok":true}"#)
        }
        Err(e) => bad_request_json(&e),
    }
}

/// PUT /api/admin/users/:id/password — admin 重置用户密码
pub async fn reset_user_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
    Json(req): Json<ChangePasswordReq>,
) -> Response {
    let user = require_auth!(&state, &headers);
    require_admin!(user);
    if let Err(msg) = validate_password(&req.new_password) {
        return bad_request_json(&msg);
    }
    match state.db.change_password(user_id, &req.new_password) {
        Ok(()) => {
            state.db.audit_log(Some(user.id), &user.username, "reset_password", None, Some(&format!("用户ID: {}", user_id)), None);
            json_resp(StatusCode::OK, r#"{"ok":true}"#)
        }
        Err(e) => json_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!(r#"{{"error":"{e}"}}"#)),
    }
}

// 全局设置（admin）

/// GET /api/admin/settings
pub async fn get_admin_settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = require_auth!(&state, &headers);
    require_admin!(user);
    let settings = state.db.get_all_admin_settings();
    ok_json(&settings)
}

/// PUT /api/admin/settings
pub async fn set_admin_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let user = require_auth!(&state, &headers);
    require_admin!(user);
    if let Some(obj) = req.as_object() {
        for (k, v) in obj {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            state.db.set_admin_setting(k, &val);
        }
    }

    // 同步写入 TOML 配置文件（重启后生效）
    if let Some(ref cfg_path) = state.config_path {
        if let Ok(text) = std::fs::read_to_string(cfg_path) {
            if let Ok(mut toml_val) = text.parse::<toml::Value>() {
                if let Some(obj) = req.as_object() {
                    // 只同步 TOML 中已有的字段
                    let toml_keys = ["shared_dir", "lsp_port", "web_port", "device_name", "auto_browser", "pin"];
                    for key in &toml_keys {
                        if let Some(v) = obj.get(*key) {
                            let toml_v = match v {
                                serde_json::Value::String(s) => toml::Value::String(s.clone()),
                                serde_json::Value::Number(n) => {
                                    if let Some(i) = n.as_i64() { toml::Value::Integer(i) }
                                    else if let Some(f) = n.as_f64() { toml::Value::Float(f) }
                                    else { continue; }
                                }
                                serde_json::Value::Bool(b) => toml::Value::Boolean(*b),
                                _ => continue,
                            };
                            toml_val[*key] = toml_v;
                        }
                    }
                }
                if let Ok(new_text) = toml::to_string_pretty(&toml_val) {
                    let _ = std::fs::write(cfg_path, new_text);
                }
            }
        }
    }

    state.db.audit_log(Some(user.id), &user.username, "update_settings", None, Some("修改系统设置"), None);
    json_resp(StatusCode::OK, r#"{"ok":true}"#)
}

// 用户设置（每人一份）

/// GET /api/user/settings
pub async fn get_user_settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = require_auth!(&state, &headers);
    let settings = state.db.get_all_user_settings(user.id);
    ok_json(&settings)
}

/// PUT /api/user/settings
pub async fn set_user_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let user = require_auth!(&state, &headers);
    if let Some(obj) = req.as_object() {
        for (k, v) in obj {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            state.db.set_user_setting(user.id, k, &val);
        }
    }
    json_resp(StatusCode::OK, r#"{"ok":true}"#)
}

// 服务重启

/// POST /api/admin/restart
/// 保存设置后自动重启服务：先回响应，500ms 后起子进程拉起新实例再退出自身
pub async fn restart_server(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = require_auth!(&state, &headers);
    require_admin!(user);

    tokio::spawn(async {
        // 等响应发完
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        if let Ok(exe) = std::env::current_exe() {
            let exe_str = exe.display().to_string();

            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                // DETACHED_PROCESS(0x08) | CREATE_NEW_PROCESS_GROUP(0x200)
                // 等 2 秒让旧进程释放端口，再 start 新实例
                let _ = std::process::Command::new("cmd")
                    .raw_arg(format!(
                        "/c timeout /t 2 /nobreak >nul & start \"\" \"{exe_str}\""
                    ))
                    .creation_flags(0x0000_0008 | 0x0000_0200)
                    .spawn();
            }

            #[cfg(not(target_os = "windows"))]
            {
                // Unix：直接 fork 新进程
                let _ = std::process::Command::new(&exe).spawn();
            }
        }

        tracing::info!("Restarting server...");
        std::process::exit(0);
    });

    json_resp(StatusCode::OK, r#"{"ok":true,"restarting":true}"#)
}

// 文件夹打包下载

#[derive(Deserialize)]
pub struct ZipQuery {
    /// 要打包的目录路径（相对共享根）
    path: String,
    /// 会话 token（浏览器 <a> 标签无法设 header，走 query param）
    token: String,
}

/// GET /api/zip?path=/some/dir&token=SESSION_TOKEN
/// 将目录打包为 zip 流式下载
pub async fn download_zip(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ZipQuery>,
) -> Response {
    // 认证：query param token
    let user = match state.db.verify_session(&q.token) {
        Some(u) => u,
        None => return unauthorized_json("未登录或会话已"),
    };

    // 解析用户共享目录 + 安全路径
    let home = crate::server::resolve_shared_dir(&state, &user);
    let dir = match crate::server::safe_path(&home, &q.path) {
        Some(p) => p,
        None => return json_resp(StatusCode::FORBIDDEN, r#"{"error":"路径非法"}"#),
    };

    if !dir.is_dir() {
        return json_resp(StatusCode::BAD_REQUEST, r#"{"error":"不是目录"}"#);
    }

    // 目录名作为 zip 文件名
    let dir_name = dir.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string());
    let zip_name = format!("{}.zip", dir_name);

    // 在临时目录创建 zip
    let temp_dir = std::env::temp_dir();
    let zip_path = temp_dir.join(format!("lanshare_{}_{}.zip",
        uuid::Uuid::new_v4().simple(),
        std::process::id(),
    ));

    // 同步创建 zip（walkdir + zip 都是同步 API，放 spawn_blocking 里）
    let dir_clone = dir.clone();
    let zip_path_clone = zip_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        create_zip(&dir_clone, &zip_path_clone)
    }).await;

    match result {
        Ok(Ok(())) => {
            // 流式发送 zip 文件
            let file = match tokio::fs::File::open(&zip_path).await {
                Ok(f) => f,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&zip_path).await;
                    return json_resp(StatusCode::INTERNAL_SERVER_ERROR,
                        &format!(r#"{{"error":"打开 zip 失败: {e}"}}"#));
                }
            };
            let meta = file.metadata().await.ok();
            let size = meta.map(|m| m.len()).unwrap_or(0);

            let stream = tokio_util::io::ReaderStream::new(file);
            let body = Body::from_stream(stream);

            // 发送完毕后删除临时文件
            let zip_path_cleanup = zip_path.clone();
            tokio::spawn(async move {
                // 等流式发送完成（通过 drop 检测）
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                let _ = tokio::fs::remove_file(&zip_path_cleanup).await;
            });

            let encoded_name = percent_encoding::utf8_percent_encode(
                &zip_name, percent_encoding::NON_ALPHANUMERIC
            ).to_string();

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/zip")
                .header(header::CONTENT_LENGTH, size.to_string())
                .header(header::CONTENT_DISPOSITION,
                    format!("attachment; filename*=UTF-8''{}", encoded_name))
                .body(body)
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Ok(Err(e)) => {
            let _ = tokio::fs::remove_file(&zip_path).await;
            json_resp(StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"打包失败: {e}"}}"#))
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&zip_path).await;
            json_resp(StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"打包任务异常: {e}"}}"#))
        }
    }
}

/// 同步创建 zip 文件（在 spawn_blocking 中调用）
fn create_zip(dir: &Path, zip_path: &Path) -> Result<(), String> {
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    let file = std::fs::File::create(zip_path)
        .map_err(|e| format!("创建 zip 文件失败: {e}"))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated);

    let base = dir.parent().unwrap_or(dir);

    for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        // zip 内路径：相对 base（包含顶层目录名）
        let rel = path.strip_prefix(base).unwrap_or(path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        if path.is_dir() {
            // 目录条目（以 / 结尾）
            let _ = zip.add_directory(format!("{}/", rel_str), options);
        } else {
            zip.start_file(rel_str, options)
                .map_err(|e| format!("写入 zip 条目失败: {e}"))?;
            let mut f = std::fs::File::open(path)
                .map_err(|e| format!("打开文件失败 {:?}: {e}", path))?;
            std::io::copy(&mut f, &mut zip)
                .map_err(|e| format!("写入文件数据失败: {e}"))?;
        }
    }

    zip.finish().map_err(|e| format!("完成 zip 失败: {e}"))?;
    Ok(())
}

// 分享链接

#[derive(Deserialize)]
pub struct CreateShareReq {
    /// 要分享的路径（相对共享根）
    path: String,
    /// 过期时间（小时），null 表示永不过期
    expires_hours: Option<i64>,
    /// 最大下载次数，null 表示不限
    max_downloads: Option<i64>,
}

/// POST /api/share — 创建分享链接
pub async fn create_share(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateShareReq>,
) -> Response {
    let user = require_auth!(&state, &headers);

    // 权限检查
    if !user.can_share() {
        return forbidden_json("无分享权限");
    }

    // 验证路径合法性
    let home = crate::server::resolve_shared_dir(&state, &user);
    if crate::server::safe_path(&home, &req.path).is_none() {
        return json_resp(StatusCode::FORBIDDEN, r#"{"error":"路径非法"}"#);
    }

    let token = state.db.create_share(user.id, &req.path, req.expires_hours, req.max_downloads);
    let url = format!("/s/{}", token);

    state.db.audit_log(Some(user.id), &user.username, "create_share", Some(&req.path), Some(&format!("token: {}", token)), None);

    json_resp(StatusCode::OK, &format!(
        r#"{{"ok":true,"token":"{}","url":"{}"}}"#,
        token, url
    ))
}

/// GET /api/shares — 列出当前用户的分享链接
pub async fn list_shares(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let user = require_auth!(&state, &headers);
    let shares = state.db.list_shares(user.id);

    let items: Vec<String> = shares.iter().map(|(token, path, expires, count)| {
        let exp = expires.as_ref().map(|e| format!(r#","expires_at":"{}""#, e)).unwrap_or_default();
        format!(r#"{{"token":"{}","path":"{}","url":"/s/{}"{},"download_count":{}}}"#,
            token, path, token, exp, count)
    }).collect();

    json_resp(StatusCode::OK, &format!(r#"{{"shares":[{}]}}"#, items.join(",")))
}

/// DELETE /api/share/:token — 删除分享链接
pub async fn delete_share(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Response {
    let user = require_auth!(&state, &headers);

    // 验证分享链接属于当前用户（admin 可删任何人的）
    if user.role != "admin" {
        if let Some((uid, _)) = state.db.verify_share(&token) {
            if uid != user.id {
                return forbidden_json("无权删除此分享链接");
            }
        }
    }

    state.db.delete_share(&token);
    json_resp(StatusCode::OK, r#"{"ok":true}"#)
}

/// GET /s/:token — 访问分享链接（无需登录）
pub async fn access_share(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Response {
    let Some((user_id, path)) = state.db.verify_share(&token) else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>链接无效</title>
<style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0a1120;color:#e8eef9}
.box{text-align:center}.big{font-size:64px}h2{margin:16px 0 8px}p{color:#7e91ad}</style></head>
<body><div class="box"><div class="big">🔗</div><h2>链接无效或已过期</h2><p>请联系分享者重新生成链接</p></div></body></html>"#))
            .unwrap();
    };

    // 获取用户信息以解析共享目录
    let Some(user) = state.db.get_user_by_id(user_id) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let home = crate::server::resolve_shared_dir(&state, &user);
    let Some(full_path) = crate::server::safe_path(&home, &path) else {
        return StatusCode::FORBIDDEN.into_response();
    };

    // 增加下载次数
    state.db.increment_share_download(&token);

    // 审计日志：分享链接访问
    state.db.audit_log(Some(user_id), &user.username, "share_access", Some(&path), Some(&format!("token: {}", token)), None);

    // 如果是目录，打包 zip 下载
    if full_path.is_dir() {
        let dir_name = full_path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "share".to_string());
        let zip_name = format!("{}.zip", dir_name);

        let temp_dir = std::env::temp_dir();
        let zip_path = temp_dir.join(format!("lanshare_share_{}.zip", uuid::Uuid::new_v4().simple()));

        let result = tokio::task::spawn_blocking({
            let full_path = full_path.clone();
            let zip_path = zip_path.clone();
            move || create_zip(&full_path, &zip_path)
        }).await;

        match result {
            Ok(Ok(())) => {
                let file = match tokio::fs::File::open(&zip_path).await {
                    Ok(f) => f,
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
                let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
                let stream = tokio_util::io::ReaderStream::new(file);
                let body = Body::from_stream(stream);

                let zip_path_cleanup = zip_path.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                    let _ = tokio::fs::remove_file(&zip_path_cleanup).await;
                });

                let encoded_name = percent_encoding::utf8_percent_encode(
                    &zip_name, percent_encoding::NON_ALPHANUMERIC
                ).to_string();

                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/zip")
                    .header(header::CONTENT_LENGTH, size.to_string())
                    .header(header::CONTENT_DISPOSITION, format!("attachment; filename*=UTF-8''{}", encoded_name))
                    .body(body)
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    } else if full_path.is_file() {
        // 单文件下载
        let file = match tokio::fs::File::open(&full_path).await {
            Ok(f) => f,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        let file_name = full_path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "download".to_string());

        let stream = tokio_util::io::ReaderStream::new(file);
        let body = Body::from_stream(stream);

        let encoded_name = percent_encoding::utf8_percent_encode(
            &file_name, percent_encoding::NON_ALPHANUMERIC
        ).to_string();

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, size.to_string())
            .header(header::CONTENT_DISPOSITION, format!("attachment; filename*=UTF-8''{}", encoded_name))
            .body(body)
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// GET /api/discover — 发现局域网内的其他 LanShare 服务器
pub async fn discover_servers(
    State(_state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let _user = require_auth!(&_state, &headers);

    let servers = crate::discovery::discover_servers(2000).await;
    let items: Vec<String> = servers.iter().map(|s| {
        format!(r#"{{"name":"{}","ip":"{}","web_port":{},"lsp_port":{},"version":"{}","url":"{}"}}"#,
            s.name, s.ip, s.web_port, s.lsp_port, s.version, s.url)
    }).collect();

    json_resp(StatusCode::OK, &format!(r#"{{"servers":[{}]}}"#, items.join(",")))
}

/// GET /api/admin/audit-logs — 获取审计日志（admin 专用）
pub async fn get_audit_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let user = require_auth!(&state, &headers);
    require_admin!(user);

    let limit = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(100);
    let logs = state.db.get_audit_logs(limit);

    let items: Vec<String> = logs.iter().map(|l| {
        let path = l.path.as_ref().map(|p| format!(r#","path":"{}""#, p.replace('"', "\\\""))).unwrap_or_default();
        let detail = l.detail.as_ref().map(|d| format!(r#","detail":"{}""#, d.replace('"', "\\\""))).unwrap_or_default();
        let ip = l.ip.as_ref().map(|i| format!(r#","ip":"{}""#, i)).unwrap_or_default();
        let username = l.username.as_ref().map(|u| format!(r#""{}""#, u.replace('"', "\\\""))).unwrap_or_else(|| "null".to_string());
        format!(r#"{{"id":{},"user_id":{:?},"username":{},"action":"{}"{}{}{},"created_at":"{}"}}"#,
            l.id, l.user_id, username, l.action, path, detail, ip, l.created_at)
    }).collect();

    json_resp(StatusCode::OK, &format!(r#"{{"logs":[{}]}}"#, items.join(",")))
}
