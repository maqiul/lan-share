//! LanShare Client — 将远程 LanShare 共享挂载为本地盘符（只读）
//!
//! 双击启动：自动扫描局域网 → 选择服务器 → 输入密码 → 挂载
//! 命令行：  lanshare-client --server IP:PORT --pin 123456 --mount L:
//! 配置文件：同目录 lanshare-client.toml（交互后自动保存，下次免输）
//!
//! 依赖：WinFsp 2.x（https://winfsp.dev）

mod fs;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use serde::{Deserialize, Serialize};
use winfsp::host::{DebugMode, FileSystemHost, FileSystemParams, MountPoint, VolumeParams};
use winfsp::service::FileSystemServiceBuilder;
use winfsp::winfsp_init_or_die;
use winfsp::FspError;

use fs::LanShareFs;
use lanshare_client::WspClient;

// ══════════════════════════════════════════════════════════
//  发现协议（同步 UDP，与服务端 discovery.rs 对应）
// ══════════════════════════════════════════════════════════

const DISCOVERY_PORT: u16 = 9999;
const DISCOVER_MAGIC: &[u8] = b"LANSHARE_DISCOVER";

#[derive(Debug, Clone, Deserialize)]
struct DiscoveredServer {
    name: String,
    ip: String,
    #[serde(alias = "webdav_port")]
    web_port: u16,
    #[allow(dead_code)]
    lsp_port: u16,
    #[allow(dead_code)]
    version: String,
    /// 是否简易模式（true=PIN，false=账号密码）
    #[serde(default)]
    simple_mode: bool,
}

impl DiscoveredServer {
    fn addr(&self) -> String {
        format!("{}:{}", self.ip, self.web_port)
    }
}

/// 同步 UDP 广播扫描局域网 LanShare 服务器
fn scan_lan(timeout_ms: u64) -> Vec<DiscoveredServer> {
    let mut results = Vec::new();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  ⚠ UDP 绑定失败: {}", e);
            return results;
        }
    };

    if socket.set_broadcast(true).is_err() {
        eprintln!("  ⚠ 无法启用广播");
        return results;
    }

    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();

    let broadcast: SocketAddr = format!("255.255.255.255:{}", DISCOVERY_PORT)
        .parse()
        .unwrap();

    if socket.send_to(DISCOVER_MAGIC, broadcast).is_err() {
        eprintln!("  ⚠ 广播发送失败");
        return results;
    }

    let mut buf = [0u8; 512];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let Ok(info) = serde_json::from_slice::<DiscoveredServer>(&buf[..len]) {
                    // 用响应来源 IP 覆盖（更准确）
                    let mut info = info;
                    info.ip = src.ip().to_string();
                    // 去重
                    if !results.iter().any(|r: &DiscoveredServer| r.addr() == info.addr()) {
                        results.push(info);
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }

    results
}

// ══════════════════════════════════════════════════════════
//  控制台交互
// ══════════════════════════════════════════════════════════

/// 读取一行输入（不回显，用于密码）
fn read_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().ok();

    #[cfg(windows)]
    {
        use windows::Win32::System::Console::*;
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE).unwrap_or_default();
            let mut mode = CONSOLE_MODE::default();
            let _ = GetConsoleMode(handle, &mut mode);
            let _ = SetConsoleMode(handle, mode & !CONSOLE_MODE(0x0004)); // ENABLE_ECHO_INPUT = 0x0004
            let mut line = String::new();
            io::stdin().read_line(&mut line).ok();
            let _ = SetConsoleMode(handle, mode);
            println!(); // 换行（因为密码输入时没有回显换行）
            return line.trim().to_string();
        }
    }

    #[cfg(not(windows))]
    {
        let mut line = String::new();
        io::stdin().read_line(&mut line).ok();
        line.trim().to_string()
    }
}

/// 读取一行普通输入
fn read_line(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line).ok();
    line.trim().to_string()
}

/// 交互发现模式：扫描 → 选择 → 认证 → 返回配置
fn interactive_discover() -> Option<ResolvedConfig> {
    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║   LanShare 客户端 - 自动发现模式        ║");
    println!("  ╚══════════════════════════════════════════╝");
    println!();

    // ── 扫描 ──
    print!("  🔍 正在扫描局域网...");
    io::stdout().flush().ok();
    let servers = scan_lan(2000);
    println!(" 完成");
    println!();

    if servers.is_empty() {
        println!("  ❌ 未发现 LanShare 服务器");
        println!();
        println!("  请确认：");
        println!("    • 服务端已启动");
        println!("    • 在同一局域网内");
        println!("    • 防火墙未阻止 UDP 9999 端口");
        println!();

        // 允许手动输入
        let addr = read_line("  手动输入服务端地址 (IP:端口，回车取消): ");
        if addr.is_empty() {
            return None;
        }
        return interactive_auth(addr, None);
    }

    // ── 显示列表 ──
    println!("  发现 {} 台 LanShare 服务器：", servers.len());
    println!();
    for (i, s) in servers.iter().enumerate() {
        println!("    [{}] {} ({})", i + 1, s.name, s.addr());
    }
    println!();

    // ── 选择 ──
    let choice = if servers.len() == 1 {
        println!("  自动选择唯一服务器: {}", servers[0].name);
        0
    } else {
        loop {
            let input = read_line(&format!("  请选择 [1-{}]: ", servers.len()));
            if let Ok(n) = input.parse::<usize>() {
                if n >= 1 && n <= servers.len() {
                    break n - 1;
                }
            }
            println!("  无效选择，请重新输入");
        }
    };

    let server = servers[choice].addr();
    let simple_mode = servers[choice].simple_mode;
    println!();
    println!("  已选择: {} ({})", servers[choice].name, server);
    println!("  模式: {}", if simple_mode { "简易模式（PIN 码）" } else { "账号模式（用户名+密码）" });
    println!();

    interactive_auth(server, Some(simple_mode))
}

/// 交互认证：根据服务器模式自动选择认证方式 → 输入凭据
/// known_mode: Some(true)=简易模式, Some(false)=账号模式, None=未知需用户选
fn interactive_auth(server: String, known_mode: Option<bool>) -> Option<ResolvedConfig> {
    let auth_mode = match known_mode {
        Some(true) => {
            println!("  🔑 该服务器为简易模式，请输入 PIN 码");
            println!();
            "pin"
        }
        Some(false) => {
            println!("  🔑 该服务器为账号模式，请输入用户名和密码");
            println!();
            "account"
        }
        None => {
            println!("  认证方式：");
            println!("    [1] PIN 码（简易模式）");
            println!("    [2] 账号密码");
            println!();
            loop {
                let input = read_line("  请选择 [1/2]: ");
                match input.as_str() {
                    "1" => break "pin",
                    "2" => break "account",
                    _ => println!("  请输入 1 或 2"),
                }
            }
        }
    };

    let (pin, username, password) = match auth_mode {
        "pin" => {
            let pin = read_password("  请输入 PIN 码: ");
            if pin.is_empty() {
                println!("  PIN 不能为空");
                return None;
            }
            (Some(pin), None, None)
        }
        "account" => {
            let username = read_line("  用户名: ");
            if username.is_empty() {
                println!("  用户名不能为空");
                return None;
            }
            let password = read_password("  密码: ");
            if password.is_empty() {
                println!("  密码不能为空");
                return None;
            }
            (None, Some(username), Some(password))
        }
        _ => unreachable!(),
    };

    let mount = {
        let input = read_line("  挂载盘符 (如 L: 或 * 自动分配，直接回车=*): ");
        if input.is_empty() {
            "*".to_string()
        } else {
            input
        }
    };

    let label = {
        let input = read_line("  卷标名称 (直接回车=LanShare): ");
        if input.is_empty() {
            "LanShare".to_string()
        } else {
            input
        }
    };

    println!();

    // 询问是否保存配置
    let save = read_line("  保存配置到文件？下次双击免输 [Y/n]: ");
    let save_config = !save.eq_ignore_ascii_case("n");

    let cfg = ResolvedConfig {
        server,
        pin,
        username,
        password,
        token: None,
        mount,
        label,
    };

    if save_config {
        if let Err(e) = save_client_config(&cfg) {
            eprintln!("  ⚠ 配置保存失败: {}", e);
        } else {
            println!("  💾 配置已保存（下次双击直接挂载）");
        }
    }

    println!();
    Some(cfg)
}

// ══════════════════════════════════════════════════════════
//  配置文件
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientConfig {
    #[serde(default = "default_server")]
    server: String,
    #[serde(default)]
    pin: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default = "default_mount")]
    mount: String,
    #[serde(default = "default_label")]
    label: String,
}

fn default_server() -> String {
    "127.0.0.1:8080".to_string()
}
fn default_mount() -> String {
    "*".to_string()
}
fn default_label() -> String {
    "LanShare".to_string()
}

fn client_config_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("lanshare-client.toml")))
}

fn load_client_config() -> Option<ClientConfig> {
    let path = client_config_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    match toml::from_str(&content) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!("  ⚠ 配置文件解析失败 ({}): {}", path.display(), e);
            None
        }
    }
}

fn save_client_config(cfg: &ResolvedConfig) -> Result<(), String> {
    let path = client_config_path().ok_or("无法获取配置文件路径")?;

    let toml_cfg = ClientConfig {
        server: cfg.server.clone(),
        pin: cfg.pin.clone(),
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        token: cfg.token.clone(),
        mount: cfg.mount.clone(),
        label: cfg.label.clone(),
    };

    let content = format!(
        r#"# LanShare 客户端配置（自动生成，可手动编辑）
# 双击启动时自动读取此配置进行挂载

server = "{}"
{}{}{}{}mount = "{}"
label = "{}"
"#,
        toml_cfg.server,
        toml_cfg
            .pin
            .as_ref()
            .map(|p| format!("pin = \"{}\"\n", p))
            .unwrap_or_default(),
        toml_cfg
            .username
            .as_ref()
            .map(|u| format!("username = \"{}\"\n", u))
            .unwrap_or_default(),
        toml_cfg
            .password
            .as_ref()
            .map(|p| format!("password = \"{}\"\n", p))
            .unwrap_or_default(),
        toml_cfg
            .token
            .as_ref()
            .map(|t| format!("token = \"{}\"\n", t))
            .unwrap_or_default(),
        toml_cfg.mount,
        toml_cfg.label,
    );

    std::fs::write(&path, content).map_err(|e| format!("{}", e))?;
    Ok(())
}

// ══════════════════════════════════════════════════════════
//  弹窗
// ══════════════════════════════════════════════════════════

#[cfg(windows)]
fn show_message_box(text: &str, title: &str, flags: u32) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::core::PCWSTR;
    let text_w: Vec<u16> = OsStr::new(text).encode_wide().chain(std::iter::once(0)).collect();
    let title_w: Vec<u16> = OsStr::new(title).encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            None,
            PCWSTR::from_raw(text_w.as_ptr()),
            PCWSTR::from_raw(title_w.as_ptr()),
            MESSAGEBOX_STYLE(flags),
        );
    }
}

#[cfg(not(windows))]
fn show_message_box(text: &str, title: &str, _flags: u32) {
    eprintln!("[{}] {}", title, text);
}

/// 隐藏控制台窗口，让程序在后台运行
#[cfg(windows)]
fn hide_console() {
    use windows::Win32::System::Console::GetConsoleWindow;
    use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
    unsafe {
        let hwnd = GetConsoleWindow();
        if !hwnd.is_invalid() {
            let _ = ShowWindow(hwnd, SW_HIDE);
        }
    }
}

// ══════════════════════════════════════════════════════════
//  CLI 参数
// ══════════════════════════════════════════════════════════

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

    /// 账号模式密码（命令行传入，注意安全风险）
    #[arg(short = 'p', long)]
    password: Option<String>,

    /// Session token
    #[arg(short, long)]
    token: Option<String>,

    /// 挂载盘符（如 "L:" 或 "*" 自动分配）
    #[arg(short, long)]
    mount: Option<String>,

    /// 卷标名称
    #[arg(short, long)]
    label: Option<String>,

    /// 跳过交互发现，即使没有配置也直接报错
    #[arg(long)]
    no_interactive: bool,
}

// ══════════════════════════════════════════════════════════
//  配置合并
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
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
    fn has_auth(&self) -> bool {
        self.pin.is_some()
            || (self.username.is_some() && self.password.is_some())
            || self.token.is_some()
    }

    /// 解析配置：CLI > 配置文件 > 交互发现
    fn resolve(args: Args) -> Result<Self, String> {
        let has_cli_auth =
            args.pin.is_some() || args.username.is_some() || args.token.is_some();

        // 1. CLI 有认证参数 → 直接用
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

        // 2. 读配置文件
        if let Some(cfg) = load_client_config() {
            if cfg.pin.is_some() || cfg.username.is_some() || cfg.token.is_some() {
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
        }

        // 3. 交互发现模式
        if args.no_interactive {
            return Err("没有配置且 --no-interactive 已设置".to_string());
        }

        interactive_discover().ok_or_else(|| "用户取消了操作".to_string())
    }
}

// ══════════════════════════════════════════════════════════
//  HTTP 登录
// ══════════════════════════════════════════════════════════

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

    let mut stream =
        TcpStream::connect(server).map_err(|e| format!("连接 {} 失败: {}", server, e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
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

// ══════════════════════════════════════════════════════════
//  主入口
// ══════════════════════════════════════════════════════════

fn main() {
    // 设置控制台 UTF-8 输出
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::*;
        unsafe {
            let _ = SetConsoleOutputCP(65001);
            let _ = SetConsoleCP(65001);
        }
    }

    // 确保 WinFsp DLL 可被 delayload 找到
    #[cfg(windows)]
    {
        use windows::Win32::System::LibraryLoader::SetDllDirectoryW;
        use windows::core::w;
        unsafe {
            let _ = SetDllDirectoryW(w!("C:\\Program Files (x86)\\WinFsp\\bin"));
        }
    }

    let args = Args::parse();

    // 解析配置（CLI > 配置文件 > 交互发现）
    let cfg = match ResolvedConfig::resolve(args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("\n  ❌ {}", msg);
            show_message_box(&msg, "LanShare 客户端", 0x10);
            pause_exit();
            return;
        }
    };

    if !cfg.has_auth() {
        let msg = "错误：没有认证信息（PIN / 账号密码 / Token）";
        eprintln!("\n  ❌ {}", msg);
        show_message_box(msg, "LanShare 客户端", 0x10);
        pause_exit();
        return;
    }

    // 确定认证 token
    let token = if let Some(ref pin) = cfg.pin {
        println!("  🔑 使用 PIN 码认证（简易模式）");
        pin.clone()
    } else if let (Some(ref username), Some(ref password)) = (&cfg.username, &cfg.password) {
        println!("  🔑 使用账号 {} 登录...", username);
        match http_login(&cfg.server, username, password) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("\n  ❌ {}", e);
                show_message_box(&e, "LanShare 客户端 - 登录失败", 0x10);
                pause_exit();
                return;
            }
        }
    } else if let Some(ref token) = cfg.token {
        println!("  🔑 使用 session token 认证");
        token.clone()
    } else {
        unreachable!()
    };

    // 把配置通过 Arc 传给 WinFsp 回调
    let mount = cfg.mount.clone();
    let label = cfg.label.clone();
    let server = cfg.server.clone();

    let shared = Arc::new(Mutex::new(Some((server, token, mount, label))));

    let init = winfsp_init_or_die();

    let mut fsp = FileSystemServiceBuilder::new()
        .with_start(move || {
            let (server, token, mount, label) = shared
                .lock()
                .unwrap()
                .take()
                .expect("配置已被消费");
            svc_start(&server, &token, &mount, &label)
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

fn svc_start(
    server: &str,
    token: &str,
    mount: &str,
    label: &str,
) -> Result<LanShareFsHost, FspError> {
    println!("  🌐 连接 {} ...", server);
    let client = WspClient::connect(server, token).map_err(|e| {
        let msg = format!("WSP 连接失败: {}", e);
        eprintln!("\n  ❌ {}", msg);
        show_message_box(&msg, "LanShare 客户端 - 连接失败", 0x10);
        FspError::NTSTATUS(windows::Win32::Foundation::STATUS_CONNECTION_REFUSED.0)
    })?;

    println!("  ✅ 认证成功，挂载中...");

    let context = LanShareFs::new(Arc::new(client));

    let mut volume_params = VolumeParams::new();
    volume_params
        .sector_size(512)
        .sectors_per_allocation_unit(1)
        .volume_creation_time(now_filetime())
        .volume_serial_number(0x4C53_4852) // "LSHR"
        .file_info_timeout(5000)
        .case_sensitive_search(false)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(true)
        .read_only_volume(true)
        .allow_open_in_kernel_mode(true);

    volume_params.filesystem_name(label);

    let fs_params = FileSystemParams {
        use_dir_info_by_name: false,
        volume_params,
        debug_mode: DebugMode::none(),
    };

    let mut host =
        FileSystemHost::<LanShareFs>::new_with_options(fs_params, context).map_err(|_| {
            FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0)
        })?;

    // 规范化盘符："L" → "L:"，"*" → NextFreeDrive 自动分配
    if mount == "*" || mount.is_empty() {
        host.mount(MountPoint::NextFreeDrive).map_err(|_| {
            FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0)
        })?;
    } else {
        let drive = if mount.len() == 1 && mount.chars().next().unwrap().is_ascii_alphabetic() {
            format!("{}:", mount)
        } else {
            mount.to_string()
        };
        host.mount(drive.as_str()).map_err(|_| {
            FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0)
        })?;
    }

    host.start()
        .map_err(|_| FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0))?;

    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║  ✅ 挂载成功！                           ║");
    println!("  ║  在资源管理器中查看盘符                  ║");
    println!("  ║  窗口即将隐藏，程序在后台运行            ║");
    println!("  ║  结束进程即可卸载                        ║");
    println!("  ╚══════════════════════════════════════════╝");
    println!();

    // 挂载成功后隐藏控制台，后台运行
    #[cfg(windows)]
    hide_console();

    Ok(LanShareFsHost { host })
}

fn svc_stop(fs: Option<&mut LanShareFsHost>) {
    if let Some(host) = fs {
        host.host.stop();
        println!("  🔌 已卸载");
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

/// 暂停等待用户按键后退出
fn pause_exit() {
    println!();
    print!("  按回车键退出...");
    io::stdout().flush().ok();
    let _ = io::stdin().read_line(&mut String::new());
}
