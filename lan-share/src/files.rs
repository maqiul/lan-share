//! Web 文件浏览器 REST API
//!
//! GET    /api/files?path=          → 列目录 JSON
//! GET    /api/files/download?path= → 文件下载（流式）
//! GET    /api/files/preview?path=  → 文件预览（文本/图片/视频/PDF）
//! POST   /api/files/upload         → multipart 上传（支持分片）
//! POST   /api/files/mkdir          → 创建目录
//! PUT    /api/files/rename         → 重命名
//! DELETE /api/files?path=          → 删除（移到回收站）

use crate::server::AppState;
use axum::{
    body::Body,
    extract::{Multipart, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// 回收站目录名（位于用户共享目录根部）
const TRASH_DIR: &str = ".lanshare-trash";

/// 分片上传临时目录名
const UPLOAD_TMP_DIR: &str = ".lanshare-uploads";

/// 单文件上传大小上限（非分片模式）：200 MB
const MAX_SINGLE_UPLOAD: u64 = 200 * 1024 * 1024;

/// 分片上传总大小上限：2 GB
const MAX_CHUNKED_UPLOAD: u64 = 2 * 1024 * 1024 * 1024;

// ── 请求/响应结构 ──

#[derive(Deserialize)]
pub struct PathQuery {
    #[serde(default = "default_path")]
    path: String,
    /// 可选 token 认证（供 <img>/<video> 标签等无法自定义 header 的场景）
    token: Option<String>,
}

fn default_path() -> String {
    "/".to_string()
}

#[derive(Serialize)]
struct FileEntry {
    name: String,
    is_dir: bool,
    size: u64,
    /// 最后修改时间（Unix 秒）
    mtime: i64,
}

#[derive(Deserialize)]
pub struct MkdirReq {
    path: String,
}

#[derive(Deserialize)]
pub struct RenameReq {
    path: String,
    new_name: String,
}

// ── 认证辅助 ──

/// 认证：优先 Bearer header，其次 query token
fn auth(state: &AppState, headers: &HeaderMap, query_token: Option<&str>) -> Option<crate::db::User> {
    if let Some(u) = crate::api::auth_user(state, headers) {
        return Some(u);
    }
    if let Some(token) = query_token {
        // 简易模式 PIN
        let simple_mode = state
            .db
            .get_admin_setting("simple_mode")
            .map(|v| v != "false")
            .unwrap_or(true);
        if simple_mode && token == state.pin {
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
        return state.db.verify_session(token);
    }
    None
}

fn err_json(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(format!(r#"{{"error":"{msg}"}}"#)))
        .unwrap()
}

fn ok_json<T: Serialize>(data: &T) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(serde_json::to_string(data).unwrap_or_default()))
        .unwrap()
}

/// MIME 类型推断（按扩展名）
fn mime_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        // 文本
        "txt" | "log" | "md" | "csv" | "json" | "xml" | "yml" | "yaml" | "ini" | "conf"
        | "cfg" | "toml" | "properties" => "text/plain; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "ts" => "text/typescript; charset=utf-8",
        // 代码（当文本预览）
        "rs" | "py" | "java" | "c" | "h" | "cpp" | "hpp" | "cs" | "go" | "rb" | "php"
        | "sh" | "bat" | "ps1" | "sql" | "r" | "swift" | "kt" | "scala" | "lua" | "pl" => {
            "text/plain; charset=utf-8"
        }
        // 图片
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "avif" => "image/avif",
        // 视频
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "ogg" => "video/ogg",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "avi" => "video/x-msvideo",
        // 音频
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "m4a" => "audio/mp4",
        // 文档
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        _ => "application/octet-stream",
    }
}

/// 是否为可文本预览的扩展名
fn is_text_preview(path: &Path) -> bool {
    let mime = mime_type(path);
    mime.starts_with("text/")
}

// ══════════════════════════════════════════════════════════
//  GET /api/files — 列目录
// ══════════════════════════════════════════════════════════

pub async fn list_files(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    let user = match auth(&state, &headers, q.token.as_deref()) {
        Some(u) => u,
        None => return err_json(StatusCode::UNAUTHORIZED, "未登录或会话过期"),
    };
    if !user.can_read() {
        return err_json(StatusCode::FORBIDDEN, "无读取权限");
    }

    let home = crate::server::resolve_shared_dir(&state, &user);
    let dir = match crate::server::safe_path(&home, &q.path) {
        Some(p) => p,
        None => return err_json(StatusCode::FORBIDDEN, "路径非法"),
    };

    if !dir.is_dir() {
        return err_json(StatusCode::BAD_REQUEST, "不是目录");
    }

    let entries = match tokio::fs::read_dir(&dir).await {
        Ok(rd) => rd,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("读取目录失败: {e}")),
    };

    let mut files: Vec<FileEntry> = Vec::new();
    let mut stream = entries;
    while let Ok(Some(entry)) = stream.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        // 隐藏内部目录（回收站/上传临时目录/点文件）
        if name.starts_with('.') {
            continue;
        }
        if let Ok(meta) = entry.metadata().await {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            files.push(FileEntry {
                name,
                is_dir: meta.is_dir(),
                size: meta.len(),
                mtime,
            });
        }
    }

    // 目录在前，文件在后，各自按名称排序
    files.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    ok_json(&serde_json::json!({
        "path": q.path,
        "entries": files,
        "permissions": user.permissions,
    }))
}

// ══════════════════════════════════════════════════════════
//  GET /api/files/download — 文件下载（流式）
// ══════════════════════════════════════════════════════════

pub async fn download_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    let user = match auth(&state, &headers, q.token.as_deref()) {
        Some(u) => u,
        None => return err_json(StatusCode::UNAUTHORIZED, "未登录或会话过期"),
    };
    if !user.can_read() {
        return err_json(StatusCode::FORBIDDEN, "无读取权限");
    }

    let home = crate::server::resolve_shared_dir(&state, &user);
    let file = match crate::server::safe_path(&home, &q.path) {
        Some(p) => p,
        None => return err_json(StatusCode::FORBIDDEN, "路径非法"),
    };

    if !file.is_file() {
        return err_json(StatusCode::BAD_REQUEST, "不是文件");
    }

    serve_file(file, true).await
}

// ══════════════════════════════════════════════════════════
//  GET /api/files/preview — 文件预览（inline）
// ══════════════════════════════════════════════════════════

pub async fn preview_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    let user = match auth(&state, &headers, q.token.as_deref()) {
        Some(u) => u,
        None => return err_json(StatusCode::UNAUTHORIZED, "未登录或会话过期"),
    };
    if !user.can_read() {
        return err_json(StatusCode::FORBIDDEN, "无读取权限");
    }

    let home = crate::server::resolve_shared_dir(&state, &user);
    let file = match crate::server::safe_path(&home, &q.path) {
        Some(p) => p,
        None => return err_json(StatusCode::FORBIDDEN, "路径非法"),
    };

    if !file.is_file() {
        return err_json(StatusCode::BAD_REQUEST, "不是文件");
    }

    // 文本预览限制大小（1MB）
    if is_text_preview(&file) {
        if let Ok(meta) = tokio::fs::metadata(&file).await {
            if meta.len() > 1024 * 1024 {
                return err_json(StatusCode::UNSUPPORTED_MEDIA_TYPE, "文件过大，请下载查看");
            }
        }
    }

    serve_file(file, false).await
}

/// 流式发送文件（attachment 或 inline）
async fn serve_file(path: PathBuf, attachment: bool) -> Response {
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("打开文件失败: {e}")),
    };
    let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);

    let mime = mime_type(&path);
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let encoded_name =
        percent_encoding::utf8_percent_encode(&filename, percent_encoding::NON_ALPHANUMERIC)
            .to_string();

    let disposition = if attachment {
        format!("attachment; filename*=UTF-8''{}", encoded_name)
    } else {
        format!("inline; filename*=UTF-8''{}", encoded_name)
    };

    let stream = tokio_util::io::ReaderStream::new(file);
    let body = Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, size.to_string())
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CACHE_CONTROL, "private, max-age=60")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ══════════════════════════════════════════════════════════
//  POST /api/files/upload — multipart 上传（单次 + 分片）
// ══════════════════════════════════════════════════════════

/// multipart 字段：
/// - path: 目标目录（必需）
/// - file: 文件内容（单次上传）
/// - filename: 文件名（分片模式必需）
/// - upload_id: 分片上传 ID（有则为分片模式）
/// - chunk_index: 当前分片序号（0-based）
/// - total_chunks: 总分片数
pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let user = match crate::api::auth_user(&state, &headers) {
        Some(u) => u,
        None => return err_json(StatusCode::UNAUTHORIZED, "未登录或会话过期"),
    };
    if !user.can_write() {
        return err_json(StatusCode::FORBIDDEN, "无写入权限");
    }

    let home = crate::server::resolve_shared_dir(&state, &user);

    let mut target_dir: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut upload_id: Option<String> = None;
    let mut chunk_index: Option<u32> = None;
    let mut total_chunks: Option<u32> = None;
    let mut file_data: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "path" => {
                if let Ok(v) = field.text().await {
                    target_dir = Some(v);
                }
            }
            "filename" => {
                if let Ok(v) = field.text().await {
                    filename = Some(v);
                }
            }
            "upload_id" => {
                if let Ok(v) = field.text().await {
                    upload_id = Some(v);
                }
            }
            "chunk_index" => {
                if let Ok(v) = field.text().await {
                    chunk_index = v.parse().ok();
                }
            }
            "total_chunks" => {
                if let Ok(v) = field.text().await {
                    total_chunks = v.parse().ok();
                }
            }
            "file" => {
                let fname = field.file_name().map(|s| s.to_string());
                if filename.is_none() {
                    filename = fname;
                }
                match field.bytes().await {
                    Ok(data) => {
                        if upload_id.is_none() && data.len() as u64 > MAX_SINGLE_UPLOAD {
                            return err_json(StatusCode::PAYLOAD_TOO_LARGE, "文件过大，请使用分片上传");
                        }
                        file_data = Some(data.to_vec());
                    }
                    Err(e) => return err_json(StatusCode::BAD_REQUEST, &format!("读取上传数据失败: {e}")),
                }
            }
            _ => {}
        }
    }

    let dir_rel = match target_dir {
        Some(d) => d,
        None => return err_json(StatusCode::BAD_REQUEST, "缺少 path 参数"),
    };
    let dir = match crate::server::safe_path(&home, &dir_rel) {
        Some(p) => p,
        None => return err_json(StatusCode::FORBIDDEN, "路径非法"),
    };
    if !dir.is_dir() {
        return err_json(StatusCode::BAD_REQUEST, "目标目录不存在");
    }

    if let Some(uid) = upload_id {
        // ── 分片模式 ──
        let (Some(fname), Some(idx), Some(total), Some(data)) =
            (filename, chunk_index, total_chunks, file_data)
        else {
            return err_json(StatusCode::BAD_REQUEST, "分片上传缺少必要参数");
        };
        if total == 0 || idx >= total {
            return err_json(StatusCode::BAD_REQUEST, "分片参数无效");
        }
        // upload_id 安全校验（仅字母数字和连字符）
        if !uid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') || uid.len() > 64 {
            return err_json(StatusCode::BAD_REQUEST, "upload_id 非法");
        }

        let tmp_dir = home.join(UPLOAD_TMP_DIR).join(&uid);
        if let Err(e) = tokio::fs::create_dir_all(&tmp_dir).await {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("创建临时目录失败: {e}"));
        }

        // 写入分片文件
        let chunk_path = tmp_dir.join(format!("part_{:06}", idx));
        if let Err(e) = tokio::fs::write(&chunk_path, &data).await {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("写入分片失败: {e}"));
        }

        // 记录元信息
        let meta_path = tmp_dir.join("meta.json");
        if !meta_path.exists() {
            let meta = serde_json::json!({
                "filename": fname,
                "total_chunks": total,
                "dir": dir_rel,
            });
            let _ = tokio::fs::write(&meta_path, meta.to_string()).await;
        }

        // 检查是否所有分片已到齐
        let mut received = 0u32;
        if let Ok(mut rd) = tokio::fs::read_dir(&tmp_dir).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                if e.file_name().to_string_lossy().starts_with("part_") {
                    received += 1;
                }
            }
        }

        if received < total {
            return ok_json(&serde_json::json!({
                "status": "partial",
                "received": received,
                "total": total,
            }));
        }

        // ── 合并分片 ──
        let final_path = match unique_path(&dir, &fname) {
            Some(p) => p,
            None => return err_json(StatusCode::FORBIDDEN, "文件名非法"),
        };

        // 检查总大小
        let mut total_size: u64 = 0;
        for i in 0..total {
            let cp = tmp_dir.join(format!("part_{:06}", i));
            match tokio::fs::metadata(&cp).await {
                Ok(m) => total_size += m.len(),
                Err(_) => return err_json(StatusCode::BAD_REQUEST, "分片缺失"),
            }
        }
        if total_size > MAX_CHUNKED_UPLOAD {
            let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
            return err_json(StatusCode::PAYLOAD_TOO_LARGE, "文件超过 2GB 上限");
        }

        // 合并到临时文件 → 原子 rename
        let tmp_file = tmp_dir.join("merged");
        {
            let mut out = match tokio::fs::File::create(&tmp_file).await {
                Ok(f) => f,
                Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("创建合并文件失败: {e}")),
            };
            use tokio::io::AsyncWriteExt;
            for i in 0..total {
                let cp = tmp_dir.join(format!("part_{:06}", i));
                let data = match tokio::fs::read(&cp).await {
                    Ok(d) => d,
                    Err(_) => return err_json(StatusCode::BAD_REQUEST, "分片读取失败"),
                };
                if let Err(e) = out.write_all(&data).await {
                    return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("合并写入失败: {e}"));
                }
            }
            let _ = out.flush().await;
        }

        if let Err(e) = tokio::fs::rename(&tmp_file, &final_path).await {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("移动文件失败: {e}"));
        }
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;

        let size = tokio::fs::metadata(&final_path).await.map(|m| m.len()).unwrap_or(0);
        ok_json(&serde_json::json!({
            "status": "complete",
            "name": final_path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
            "size": size,
        }))
    } else {
        // ── 单次上传模式 ──
        let (Some(fname), Some(data)) = (filename, file_data) else {
            return err_json(StatusCode::BAD_REQUEST, "缺少文件或文件名");
        };

        let final_path = match unique_path(&dir, &fname) {
            Some(p) => p,
            None => return err_json(StatusCode::FORBIDDEN, "文件名非法"),
        };

        // 写入临时文件 → 原子 rename
        let tmp_name = format!(".upload_{}", uuid::Uuid::new_v4().simple());
        let tmp_path = dir.join(&tmp_name);
        if let Err(e) = tokio::fs::write(&tmp_path, &data).await {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("写入文件失败: {e}"));
        }
        if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("移动文件失败: {e}"));
        }

        ok_json(&serde_json::json!({
            "status": "complete",
            "name": final_path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
            "size": data.len(),
        }))
    }
}

/// 生成不冲突的目标路径：同名文件自动加序号 (1), (2)...
/// 同时校验文件名安全性（不含路径分隔符）
fn unique_path(dir: &Path, filename: &str) -> Option<PathBuf> {
    let name = filename.replace('\\', "/");
    let name = name.rsplit('/').next().unwrap_or("");
    if name.is_empty() || name == "." || name == ".." || name.starts_with('.') {
        return None;
    }

    let candidate = dir.join(name);
    if !candidate.exists() {
        return Some(candidate);
    }

    // 加序号
    let stem = candidate
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let ext = candidate
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();

    for i in 1..1000 {
        let new_name = format!("{} ({}){}", stem, i, ext);
        let p = dir.join(&new_name);
        if !p.exists() {
            return Some(p);
        }
    }
    None
}

// ══════════════════════════════════════════════════════════
//  POST /api/files/mkdir — 创建目录
// ══════════════════════════════════════════════════════════

pub async fn mkdir(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<MkdirReq>,
) -> Response {
    let user = match crate::api::auth_user(&state, &headers) {
        Some(u) => u,
        None => return err_json(StatusCode::UNAUTHORIZED, "未登录或会话过期"),
    };
    if !user.can_mkdir() {
        return err_json(StatusCode::FORBIDDEN, "无创建目录权限");
    }

    let home = crate::server::resolve_shared_dir(&state, &user);
    let dir = match crate::server::safe_path(&home, &req.path) {
        Some(p) => p,
        None => return err_json(StatusCode::FORBIDDEN, "路径非法"),
    };

    if dir.exists() {
        return err_json(StatusCode::CONFLICT, "目录已存在");
    }

    match tokio::fs::create_dir_all(&dir).await {
        Ok(()) => ok_json(&serde_json::json!({"ok": true})),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("创建目录失败: {e}")),
    }
}

// ══════════════════════════════════════════════════════════
//  PUT /api/files/rename — 重命名
// ══════════════════════════════════════════════════════════

pub async fn rename_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RenameReq>,
) -> Response {
    let user = match crate::api::auth_user(&state, &headers) {
        Some(u) => u,
        None => return err_json(StatusCode::UNAUTHORIZED, "未登录或会话过期"),
    };
    if !user.can_rename() {
        return err_json(StatusCode::FORBIDDEN, "无重命名权限");
    }

    // 新名称安全校验
    if req.new_name.is_empty()
        || req.new_name.contains('/')
        || req.new_name.contains('\\')
        || req.new_name == "."
        || req.new_name == ".."
    {
        return err_json(StatusCode::BAD_REQUEST, "新名称非法");
    }

    let home = crate::server::resolve_shared_dir(&state, &user);
    let src = match crate::server::safe_path(&home, &req.path) {
        Some(p) => p,
        None => return err_json(StatusCode::FORBIDDEN, "路径非法"),
    };

    if !src.exists() {
        return err_json(StatusCode::NOT_FOUND, "文件不存在");
    }

    let dst = src.with_file_name(&req.new_name);
    // 确保目标仍在共享目录内
    let canonical_base = home.canonicalize().ok();
    let dst_parent = dst.parent().and_then(|p| p.canonicalize().ok());
    if canonical_base.is_none() || dst_parent != canonical_base {
        return err_json(StatusCode::FORBIDDEN, "路径非法");
    }

    if dst.exists() {
        return err_json(StatusCode::CONFLICT, "目标名称已存在");
    }

    match tokio::fs::rename(&src, &dst).await {
        Ok(()) => ok_json(&serde_json::json!({"ok": true, "new_name": req.new_name})),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("重命名失败: {e}")),
    }
}

// ══════════════════════════════════════════════════════════
//  DELETE /api/files?path= — 删除（移到回收站）
// ══════════════════════════════════════════════════════════

pub async fn delete_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Response {
    let user = match auth(&state, &headers, q.token.as_deref()) {
        Some(u) => u,
        None => return err_json(StatusCode::UNAUTHORIZED, "未登录或会话过期"),
    };
    if !user.can_delete() {
        return err_json(StatusCode::FORBIDDEN, "无删除权限");
    }

    let home = crate::server::resolve_shared_dir(&state, &user);
    let target = match crate::server::safe_path(&home, &q.path) {
        Some(p) => p,
        None => return err_json(StatusCode::FORBIDDEN, "路径非法"),
    };

    if !target.exists() {
        return err_json(StatusCode::NOT_FOUND, "文件不存在");
    }

    // 不允许删除共享目录本身
    if let (Ok(canon_home), Ok(canon_target)) = (home.canonicalize(), target.canonicalize()) {
        if canon_home == canon_target {
            return err_json(StatusCode::FORBIDDEN, "不能删除共享根目录");
        }
    }

    // 移到回收站
    let trash = home.join(TRASH_DIR);
    if let Err(e) = tokio::fs::create_dir_all(&trash).await {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, &format!("创建回收站失败: {e}"));
    }

    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "deleted".to_string());
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let trash_name = format!("{}_{}", ts, name);
    let trash_path = trash.join(&trash_name);

    match tokio::fs::rename(&target, &trash_path).await {
        Ok(()) => ok_json(&serde_json::json!({"ok": true, "trashed": trash_name})),
        Err(e) => {
            // rename 失败（跨设备等）时回退为直接删除
            let result = if target.is_dir() {
                tokio::fs::remove_dir_all(&target).await
            } else {
                tokio::fs::remove_file(&target).await
            };
            match result {
                Ok(()) => ok_json(&serde_json::json!({"ok": true, "trashed": null})),
                Err(e2) => err_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("删除失败: {} / {}", e, e2),
                ),
            }
        }
    }
}
