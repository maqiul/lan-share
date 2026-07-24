//! LanShare Client — 将远程 LanShare 共享挂载为本地盘符（只读）
//!
//! 用法：
//!   双击启动：自动读取同目录 lanshare-client.toml 配置
//!   简易模式：lanshare-client --server 192.168.1.100:8080 --pin 123456 --mount L:
//!   账号模式：lanshare-client --server 192.168.1.100:8080 -u admin -p 123456 --mount L:
//!   Token：  lanshare-client --server 192.168.1.100:8080 --token <session_token> --mount *
//!
//! 依赖：WinFsp 2.x（https://winfsp.dev）

mod fs;
mod wsp_client;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use serde::{Deserialize, Serialize};
use winfsp::host::{DebugMode, FileSystemHost, FileSystemParams, VolumeParams};
use winfsp::service::FileSystemServiceBuilder;
use winfsp::winfsp_init_or_die;
use winfsp::FspError;

use fs::LanShareFs;
use wsp_client::WspClient;

// ── 配置文件 ──────────────────────────────────────────────

/// 客户端配置文件（与 exe 同目录）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientConfig {
    /// 服务端地址（IP:端口）
    #[serde(default = "default_server")]
    server: String,
    /// 简易模式 PIN 码
    #[serde(default)]
    pin: Option<String>,
    /// 账号模式用户名
    #[serde(default)]
    username: Option<String>,
    /// 账号模式密码
    #[serde(default)]
    password: Option<String>,
    /// Session token（优先级最高）
    #[serde(default)]
    token: Option<String>,
    /// 挂载盘符（如 "L:" 或 "*" 自动分配）
    #[serde(default = "default_mount")]
    mount: String,
    /// 卷标名称
    #[serde(default = "default_label")]
    label: String,
}

fn default_server() -> String { "127.0.0.1:8080".to_string() }
fn default_mount() -> String { "*".to_string() }
fn default_label() -> String { "LanShare".to_string() }

const CLIENT_CONFIG_TEMPLATE: &str = r#"# LanShare 客户端配置文件
# 双击启动时自动读取此配置进行挂载
# 修改后保存，重新双击即可生效

# 服务端地址（IP:端口）
server = "192.168.0.248:8080"

# ── 认证方式（三选一，取消注释并填写）──

# 方式1：简易模式 PIN 码
pin = "123456"

# 方式2：账号模式
# username = "admin"
# password = "your_password"

# 方式3：Session Token（优先级最高，一般不用手动填）
# token = ""

# 挂载盘符（如 "L:" 指定盘符，"*" 自动分配）
mount = "*"

# 卷标名称（资源管理器里显示的名字）
label = "LanShare"
"#;

/// 配置文件路径（与 exe 同级）
fn client_config_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("lanshare-client.toml")))
}

/// 加载配置文件
fn load_client_config() -> Option<ClientConfig> {
    let path = client_config_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    match toml::from_str(&content) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!("配置文件解析失败 ({}): {}", path.display(), e);
            None
        }
    }
}

/// 生成默认配置模板
fn generate_client_config() -> Option<PathBuf> {
    let path = client_config_path()?;
    if std::fs::write(&path, CLIENT_CONFIG_TEMPLATE).is_ok() {
        Some(path)
    } else {
        None
    }
}

/// 弹出 Windows 消息框
#[cfg(windows)]
fn show_message_box(text: &str, title: &str, flags: u32) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::core::PCWSTR;
    let text_w: Vec<u16> = OsStr::new(text).encode_wide().chain(std::iter::once(0)).collect();
    let title_w: Vec<u16> = OsStr::new(title).encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(None, PCWSTR::from_raw(text_w.as_ptr()), PCWSTR::from_raw(title_w.as_ptr()), MESSAGEBOX_STYLE(flags));
    }
}

#[cfg(not(windows))]
fn show_message_box(text: &str, title: &str, _flags: u32) {
    eprintln!("[{}] {}", title, text);
}

// ── CLI 参数 ──────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "lanshare-client", about = "LanShare 网络驱动器挂载（只读）")]
struct Args {
    /// LanShare 服务端地址（IP:端口）
    #[arg(short, long)]
    server: Option<String>,

    /// 简易模式 PIN 码
    #[arg(short, long)]
    pin: Option<String>,

    /// 账号模式用户名
    #[arg(short = 'u', long)]
    username: Option<String>,

    /// 账号模式密码
    #[arg(short = 'p', long)]
    password: Option<String>,

    /// 账号模式 session token（直接传入，跳过登录）
    #[arg(short, long)]
    token: Option<String>,

    /// 挂载盘符（如 "L:" 或 "*" 自动分配）
    #[arg(short, long)]
    mount: Option<String>,

    /// 卷标名称
    #[arg(short, long)]
    label: Option<String>,
}

/// 合并 CLI 参数和配置文件（CLI 优先）
struct ResolvedConfig {
    server: String,
    pin: Option<String>,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    mount: String,
    label: String,
}

impl ResolvedConfig {
    fn resolve(args: Args) -> Result<Self, String> {
        // 如果 CLI 提供了认证信息，直接用 CLI 参数
        let has_cli_auth = args.pin.is_some() || args.username.is_some() || args.token.is_some();

        if has_cli_auth {
            return Ok(ResolvedConfig {
                server: args.server.unwrap_or_else(default_server),
                pin: args.pin,
                username: args.username,
                password: args.password,
                token: args.token,
                mount: args.mount.unwrap_or_else(default_mount),
                label: args.label.unwrap_or_else(default_label),
            });
        }

        // CLI 没有认证信息 → 尝试读配置文件
        if let Some(cfg) = load_client_config() {
            // 验证配置文件里至少有认证信息
            if cfg.pin.is_none() && cfg.username.is_none() && cfg.token.is_none() {
                return Err("配置文件中没有设置认证信息（pin / username+password / token）。\n请编辑配置文件后重试。".to_string());
            }
            return Ok(ResolvedConfig {
                server: args.server.unwrap_or(cfg.server),
                pin: cfg.pin,
                username: cfg.username,
                password: cfg.password,
                token: cfg.token,
                mount: args.mount.unwrap_or(cfg.mount),
                label: args.label.unwrap_or(cfg.label),
            });
        }

        // 配置文件也不存在 → 生成模板
        if let Some(path) = generate_client_config() {
            return Err(format!(
                "首次运行，已生成配置文件：\n{}\n\n请编辑此文件，填入服务端地址和认证信息后重新双击启动。",
                path.display()
            ));
        }

        Err("无法生成配置文件，请手动创建 lanshare-client.toml。".to_string())
    }

    fn has_auth(&self) -> bool {
        self.pin.is_some() || (self.username.is_some() && self.password.is_some()) || self.token.is_some()
    }
}

// ── WinFsp 入口 ──────────────────────────────────────────

fn main() {
    // ── 预检查：无命令行认证参数时，先检查配置文件 ──
    // 避免 WinFsp 初始化失败时用户看不到任何提示
    let cli_args: Vec<String> = std::env::args().collect();
    let has_cli_auth = cli_args.iter().any(|a| a == "--pin" || a == "-p" || a == "--token" || a == "-u" || a == "--username");
    if !has_cli_auth {
        // 没有命令行认证参数，检查配置文件
        if load_client_config().is_none() {
            // 配置文件不存在或解析失败 → 生成模板
            if let Some(path) = generate_client_config() {
                let msg = format!(
                    "首次运行，已生成配置文件：\n\n{}\n\n请编辑此文件，填入服务端地址和认证信息后重新双击启动。\n\n配置文件说明：\n• server = 服务端 IP:端口\n• pin = 简易模式 PIN 码\n• username + password = 账号模式\n• mount = 挂载盘符（* 自动分配）",
                    path.display()
                );
                eprintln!("{}", msg);
                show_message_box(&msg, "LanShare 客户端 - 首次运行", 0x40); // MB_ICONINFORMATION
            } else {
                let msg = "无法生成配置文件，请手动在程序同目录创建 lanshare-client.toml。";
                eprintln!("{}", msg);
                show_message_box(msg, "LanShare 客户端", 0x10);
            }
            return;
        }
    }

    let init = winfsp_init_or_die();

    let mut fsp = FileSystemServiceBuilder::new()
        .with_start(move || {
            let args = Args::parse();
            svc_start(args)
        })
        .with_stop(|fs| {
            svc_stop(fs);
            Ok(())
        })
        .build("LanShareClient", init)
        .expect("构建 WinFsp 服务失败");

    fsp.start().expect("启动 WinFsp 服务失败");
    let _ = fsp.join();
}

/// 通过 HTTP API 登录，获取 session token
fn http_login(server: &str, username: &str, password: &str) -> Result<String, String> {
    let body = serde_json::json!({
        "username": username,
        "password": password,
    });
    let body_str = body.to_string();

    let request = format!(
        "POST /api/login HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        server,
        body_str.len(),
        body_str
    );

    let mut stream = TcpStream::connect(server)
        .map_err(|e| format!("连接 {} 失败: {}", server, e))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("发送登录请求失败: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("读取登录响应失败: {}", e))?;

    let body_part = response.split("\r\n\r\n").nth(1).unwrap_or("");

    let status_ok = response
        .lines()
        .next()
        .map(|l| l.contains("200"))
        .unwrap_or(false);

    if !status_ok {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_part) {
            if let Some(err) = json.get("error").and_then(|e| e.as_str()) {
                return Err(format!("登录失败: {}", err));
            }
        }
        return Err("登录失败: HTTP 响应异常".to_string());
    }

    let json: serde_json::Value =
        serde_json::from_str(body_part).map_err(|e| format!("解析登录响应失败: {}", e))?;
    json.get("token")
        .and_then(|t| t.as_str())
        .map(|t| t.to_string())
        .ok_or_else(|| "登录响应中无 token".to_string())
}

fn svc_start(args: Args) -> Result<LanShareFsHost, FspError> {
    // 合并 CLI + 配置文件
    let cfg = ResolvedConfig::resolve(args).map_err(|msg| {
        eprintln!("{}", msg);
        show_message_box(&msg, "LanShare 客户端", 0x10); // MB_ICONERROR
        FspError::NTSTATUS(windows::Win32::Foundation::STATUS_INVALID_PARAMETER.0)
    })?;

    if !cfg.has_auth() {
        let msg = "错误：需要认证信息。\n\n请在配置文件中设置 pin 或 username+password，\n或使用命令行参数 --pin / -u -p / --token。";
        eprintln!("{}", msg);
        show_message_box(msg, "LanShare 客户端", 0x10);
        return Err(FspError::NTSTATUS(
            windows::Win32::Foundation::STATUS_INVALID_PARAMETER.0,
        ));
    }

    // 确定认证 token
    let token = if let Some(pin) = &cfg.pin {
        println!("使用 PIN 码认证（简易模式）");
        pin.clone()
    } else if let (Some(username), Some(password)) = (&cfg.username, &cfg.password) {
        println!("使用账号 {} 登录（账号模式）...", username);
        http_login(&cfg.server, username, password).map_err(|e| {
            eprintln!("{}", e);
            show_message_box(&e, "LanShare 客户端 - 登录失败", 0x10);
            FspError::NTSTATUS(0xC000_006Du32 as i32) // STATUS_LOGON_FAILURE
        })?
    } else if let Some(token) = &cfg.token {
        println!("使用 session token 认证");
        token.clone()
    } else {
        unreachable!()
    };

    println!("连接 LanShare 服务端 {} ...", cfg.server);
    let client = WspClient::connect(&cfg.server, &token).map_err(|e| {
        let msg = format!("WSP 连接失败: {}", e);
        eprintln!("{}", msg);
        show_message_box(&msg, "LanShare 客户端 - 连接失败", 0x10);
        FspError::NTSTATUS(windows::Win32::Foundation::STATUS_CONNECTION_REFUSED.0)
    })?;
    println!("认证成功，挂载为 {} ...", cfg.mount);

    let context = LanShareFs::new(Arc::new(client));

    // 配置卷参数
    let mut volume_params = VolumeParams::new();
    volume_params
        .sector_size(512)
        .sectors_per_allocation_unit(1)
        .volume_creation_time(now_filetime())
        .volume_serial_number(0x4C53_4852) // "LSHR"
        .file_info_timeout(5000) // 5 秒缓存
        .case_sensitive_search(false)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(true)
        .read_only_volume(true)
        .allow_open_in_kernel_mode(true);

    if cfg.mount != "*" && !cfg.mount.is_empty() {
        volume_params.prefix(&cfg.mount);
    }
    volume_params.filesystem_name(&cfg.label);

    let fs_params = FileSystemParams {
        use_dir_info_by_name: false,
        volume_params,
        debug_mode: DebugMode::none(),
    };

    let mut host =
        FileSystemHost::<LanShareFs>::new_with_options(fs_params, context).map_err(|_| {
            FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0)
        })?;

    if cfg.mount != "*" && !cfg.mount.is_empty() {
        host.mount(&cfg.mount).map_err(|_| {
            FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0)
        })?;
    }

    host.start()
        .map_err(|_| FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0))?;

    println!("✅ 已挂载！在资源管理器中查看盘符 {}", cfg.mount);

    Ok(LanShareFsHost { host })
}

fn svc_stop(fs: Option<&mut LanShareFsHost>) {
    if let Some(host) = fs {
        host.host.stop();
        println!("已卸载");
    }
}

struct LanShareFsHost {
    host: FileSystemHost<LanShareFs>,
}

fn now_filetime() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs * 10_000_000 + 116_444_736_000_000_000
}
