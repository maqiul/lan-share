//! LanShare Client — 将远程 LanShare 共享挂载为本地盘符（权限允许时可读写）
//!
//! 双击启动：自动扫描局域网 → 选择服务器 → 输入密码 → 挂载
//! 命令行：  lanshare-client --server IP:PORT --pin 123456 --mount L:
//! 配置文件：同目录 lanshare-client.toml（交互后自动保存，下次免输）
//!
//! 依赖：WinFsp 2.x（https://winfsp.dev）

mod fs;
mod tray;

use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use serde::{Deserialize, Serialize};
use winfsp::host::{DebugMode, FileSystemHost, FileSystemParams, VolumeParams};
use winfsp::service::FileSystemServiceBuilder;
use winfsp::winfsp_init_or_die;
use winfsp::FspError;

use fs::LanShareFs;
use lanshare_client::{LspShareClient, LspAuth};

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
        return interactive_auth(addr, None, default_lsp_port());
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
    let lsp_port = servers[choice].lsp_port;
    println!();
    println!("  已选择: {} ({})", servers[choice].name, server);
    println!("  模式: {}", if simple_mode { "简易模式（PIN 码）" } else { "账号模式（用户名+密码）" });
    println!();

    interactive_auth(server, Some(simple_mode), lsp_port)
}

/// 交互认证：根据服务器模式自动选择认证方式 → 输入凭据
/// known_mode: Some(true)=简易模式, Some(false)=账号模式, None=未知需用户选
fn interactive_auth(server: String, known_mode: Option<bool>, lsp_port: u16) -> Option<ResolvedConfig> {
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
        lsp_port,
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
    #[serde(default = "default_lsp_port")]
    lsp_port: u16,
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
fn default_lsp_port() -> u16 {
    9820
}
fn default_mount() -> String {
    "*".to_string()
}
fn default_label() -> String {
    "LanShare".to_string()
}

// ══════════════════════════════════════════════════════════
//  敏感信息保护（DPAPI 加密，仅当前 Windows 用户可解密）
// ══════════════════════════════════════════════════════════

/// 密文前缀，用于区分明文与加密值
const ENC_PREFIX: &str = "enc:";

/// 使用 DPAPI 加密敏感字符串，返回 "enc:<base64>"；加密失败时回退明文
#[cfg(windows)]
fn protect_secret(plain: &str) -> String {
    use base64::Engine as _;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

    let bytes = plain.as_bytes();
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut out_blob: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };

    let res = unsafe {
        CryptProtectData(
            &in_blob,
            windows::core::PCWSTR::null(),
            None,
            None,
            None,
            Default::default(),
            &mut out_blob,
        )
    };

    if res.is_ok() && !out_blob.pbData.is_null() {
        let cipher = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
        let enc = base64::engine::general_purpose::STANDARD.encode(cipher);
        unsafe {
            let _ = LocalFree(Some(HLOCAL(out_blob.pbData as _)));
        }
        format!("{}{}", ENC_PREFIX, enc)
    } else {
        plain.to_string()
    }
}

/// 解密 "enc:<base64>" 形式的密文；非加密值原样返回（兼容旧明文配置）
#[cfg(windows)]
fn unprotect_secret(value: &str) -> String {
    use base64::Engine as _;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    let Some(b64) = value.strip_prefix(ENC_PREFIX) else {
        return value.to_string();
    };
    let Ok(cipher) = base64::engine::general_purpose::STANDARD.decode(b64) else {
        return value.to_string();
    };

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: cipher.len() as u32,
        pbData: cipher.as_ptr() as *mut u8,
    };
    let mut out_blob: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };

    let res = unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            Default::default(),
            &mut out_blob,
        )
    };

    if res.is_ok() && !out_blob.pbData.is_null() {
        let plain_bytes = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
        let plain = String::from_utf8_lossy(plain_bytes).into_owned();
        unsafe {
            let _ = LocalFree(Some(HLOCAL(out_blob.pbData as _)));
        }
        plain
    } else {
        value.to_string()
    }
}

#[cfg(not(windows))]
fn protect_secret(plain: &str) -> String {
    plain.to_string()
}
#[cfg(not(windows))]
fn unprotect_secret(value: &str) -> String {
    value.to_string()
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
    .map(|mut cfg: ClientConfig| {
        // 解密敏感字段（兼容旧明文配置）
        cfg.pin = cfg.pin.map(|v| unprotect_secret(&v));
        cfg.password = cfg.password.map(|v| unprotect_secret(&v));
        cfg.token = cfg.token.map(|v| unprotect_secret(&v));
        cfg
    })
}

fn save_client_config(cfg: &ResolvedConfig) -> Result<(), String> {
    let path = client_config_path().ok_or("无法获取配置文件路径")?;

    let toml_cfg = ClientConfig {
        server: cfg.server.clone(),
        lsp_port: cfg.lsp_port,
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
lsp_port = {}
{}{}{}{}mount = "{}"
label = "{}"
"#,
        toml_cfg.server,
        toml_cfg.lsp_port,
        toml_cfg
            .pin
            .as_ref()
            .map(|p| format!("pin = \"{}\"\n", protect_secret(p)))
            .unwrap_or_default(),
        toml_cfg
            .username
            .as_ref()
            .map(|u| format!("username = \"{}\"\n", u))
            .unwrap_or_default(),
        toml_cfg
            .password
            .as_ref()
            .map(|p| format!("password = \"{}\"\n", protect_secret(p)))
            .unwrap_or_default(),
        toml_cfg
            .token
            .as_ref()
            .map(|t| format!("token = \"{}\"\n", protect_secret(t)))
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

/// 释放控制台，让程序完全在后台运行（窗口消失）
#[cfg(windows)]
fn hide_console() {
    use windows::Win32::System::Console::FreeConsole;
    unsafe {
        let _ = FreeConsole();
    }
}

// ══════════════════════════════════════════════
//  开机自启动（注册表 Run 键）
// ══════════════════════════════════════════════

const AUTOSTART_REG_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const AUTOSTART_VALUE_NAME: &str = "LanShareClient";

/// 检查是否已启用开机自启动
pub(crate) fn is_autostart_enabled() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey(AUTOSTART_REG_KEY) {
        Ok(run) => run.get_value::<String, _>(AUTOSTART_VALUE_NAME).is_ok(),
        Err(_) => false,
    }
}

/// 设置/取消开机自启动
pub(crate) fn set_autostart(enable: bool) {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if enable {
        if let Ok(exe) = std::env::current_exe() {
            if let Ok(run) = hkcu.create_subkey(AUTOSTART_REG_KEY) {
                let cmd = format!("\"{}\"", exe.display());
                let _ = run.0.set_value(AUTOSTART_VALUE_NAME, &cmd);
                log(&format!("开机自启动已开启: {}", cmd));
            }
        }
    } else {
        if let Ok(run) = hkcu.open_subkey_with_flags(AUTOSTART_REG_KEY, KEY_SET_VALUE) {
            let _ = run.delete_value(AUTOSTART_VALUE_NAME);
            log("开机自启动已关闭");
        }
    }
}

/// 获取本机主要 IP 地址（用于网络变化检测）
fn get_local_ip() -> String {
    use std::net::UdpSocket;
    // 连接外部地址（不实际发包）获取本机出口 IP
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("223.5.5.5:53")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

// ══════════════════════════════════════════════
//  日志（写入 exe 同目录 lanshare-client.log，FreeConsole 后仍可排查）
// ══════════════════════════════════════════════

fn log_file_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("lanshare-client.log")))
}

/// 将 UNIX 秒格式化为 "YYYY-MM-DD HH:MM:SS"（UTC）
fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days（Howard Hinnant 算法）
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let mut y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, h, mi, s)
}

/// 追加一条日志（带时间戳）
pub(crate) fn log(msg: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Some(path) = log_file_path() {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            use std::io::Write;
            let _ = writeln!(f, "[{}] {}", format_unix_utc(ts), msg);
        }
    }
}

// ══════════════════════════════════════════════════════════
//  CLI 参数
// ══════════════════════════════════════════════════════════

#[derive(Parser, Debug)]
#[command(name = "lanshare-client", about = "LanShare 网络驱动器挂载")]
struct Args {
    /// LanShare 服务端地址（IP:端口）
    #[arg(short, long)]
    server: Option<String>,

    /// LSP3 协议端口（默认 9820；扫描发现时自动获取，仅手动指定服务端且端口非默认时需要）
    #[arg(long)]
    lsp_port: Option<u16>,

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
    lsp_port: u16,
    pin: Option<String>,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    mount: String,
    label: String,
}

impl ResolvedConfig {
    /// LSP3 连接地址（ip:lsp_port）：从 server（ip:web_port）提取 IP 拼接 lsp_port
    fn lsp_addr(&self) -> String {
        let ip = self.server.split(':').next().unwrap_or(&self.server);
        format!("{}:{}", ip, self.lsp_port)
    }

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
                lsp_port: args.lsp_port.unwrap_or_else(default_lsp_port),
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
                    lsp_port: args.lsp_port.unwrap_or(cfg.lsp_port),
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

    // 单实例保护：只允许运行一个客户端
    #[cfg(windows)]
    {
        use windows::Win32::System::Threading::CreateMutexW;
        use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
        use windows::core::w;
        unsafe {
            let _ = CreateMutexW(None, true, w!("Global\\LanShareClient_Mutex"));
            if windows::Win32::Foundation::GetLastError() == ERROR_ALREADY_EXISTS {
                show_message_box(
                    "LanShare 客户端已在运行中。",
                    "LanShare 客户端",
                    0x40, // MB_ICONINFORMATION
                );
                return;
            }
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

        // 检测 WinFsp 是否已安装
        let winfsp_dll = std::path::Path::new(r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll");
        if !winfsp_dll.exists() {
            let msg = "未检测到 WinFsp，请先安装 WinFsp 2.x：\n\nhttps://winfsp.dev\n\n安装完成后重新运行本程序。";
            eprintln!("\n  ❌ {}", msg);
            show_message_box(msg, "LanShare 客户端 - 缺少 WinFsp", 0x10);
            return;
        }
    }

    let args = Args::parse();

    log("═══ LanShare 客户端启动 ═══");

    // 解析配置（CLI > 配置文件 > 交互发现）
    let cfg = match ResolvedConfig::resolve(args) {
        Ok(c) => c,
        Err(msg) => {
            log(&format!("配置解析失败: {}", msg));
            eprintln!("\n  ❌ {}", msg);
            show_message_box(&msg, "LanShare 客户端", 0x10);
            pause_exit();
            return;
        }
    };

    log(&format!("目标服务器: {}", cfg.lsp_addr()));

    if !cfg.has_auth() {
        let msg = "错误：没有认证信息（PIN / 账号密码 / Token）";
        eprintln!("\n  ❌ {}", msg);
        show_message_box(msg, "LanShare 客户端", 0x10);
        pause_exit();
        return;
    }

    // LSP3 认证：优先 PIN，其次账号密码
    let auth = if let Some(ref pin) = cfg.pin {
        println!("  🔑 使用 PIN 码认证（LSP3）");
        LspAuth::Pin(pin.clone())
    } else if let (Some(ref username), Some(ref password)) = (&cfg.username, &cfg.password) {
        println!("  👤 使用账号认证（LSP3）: {}", username);
        LspAuth::Account {
            username: username.clone(),
            password: password.clone(),
        }
    } else {
        let msg = "错误：未配置认证信息，请配置 PIN 或账号密码";
        log(msg);
        eprintln!("\n  ❌ {}", msg);
        show_message_box(msg, "LanShare 客户端", 0x10);
        pause_exit();
        return;
    };

    // 把配置通过 Arc 传给 WinFsp 回调；drive_tx 用于回传实际盘符
    let mount = cfg.mount.clone();
    let label = cfg.label.clone();
    let server = cfg.lsp_addr();

    let (drive_tx, drive_rx) = std::sync::mpsc::channel::<String>();
    // client_tx 回传 LSP 客户端句柄，供托盘显示连接状态与手动重连
    let (client_tx, client_rx) = std::sync::mpsc::channel::<Arc<LspShareClient>>();
    // pending_tx 回传写回计数器句柄，供托盘显示同步状态与优雅退出
    let (pending_tx, pending_rx) =
        std::sync::mpsc::channel::<Arc<std::sync::atomic::AtomicUsize>>();
    let shared = Arc::new(Mutex::new(Some((server, auth, mount, label, drive_tx, client_tx, pending_tx))));

    let init = winfsp_init_or_die();

    // stop 回调（在工作线程中执行卸载）完成后通过此通道通知主线程，
    // 主线程据此限时等待优雅卸载，超时则强制退出进程。
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

    let mut fsp = FileSystemServiceBuilder::new()
        .with_start(move || {
            let (server, auth, mount, label, drive_tx, client_tx, pending_tx) = shared
                .lock()
                .unwrap()
                .take()
                .expect("配置已被消费");
            svc_start(&server, &auth, &mount, &label, drive_tx, client_tx, pending_tx)
        })
        .with_stop(move |fs| {
            svc_stop(fs);
            let _ = stop_tx.send(());
            Ok(())
        })
        .build("LanShareClient", init)
        .expect("构建 WinFsp 服务失败");

    fsp.start().expect("启动 WinFsp 服务失败");

    // 等待挂载完成并获取实际盘符（挂载在工作线程中进行）
    match drive_rx.recv() {
        Ok(drive) => {
            // 接收 LSP 客户端句柄（用于托盘状态显示与手动重连）
            let client_handle = client_rx.recv().ok();
            // 获取 pending_writes 句柄（供托盘显示同步状态 + 优雅退出）
            let pending_writes_handle = pending_rx.recv().ok();
            // 后台健康探测 + 网络变化检测：
            // - 周期探测连接状态（服务端异常时经由 with_retry 自动重连）
            // - 检测本机 IP 变化（网络切换/重连）时立即强制重连
            if let Some(ref c) = client_handle {
                let probe_client = c.clone();
                std::thread::spawn(move || {
                    let mut last_ip = get_local_ip();
                    let mut was_healthy = true;
                    loop {
                        // 健康时 5s 探测，不健康时 2s 加速重试
                        let interval = if probe_client.is_healthy() { 5 } else { 2 };
                        std::thread::sleep(Duration::from_secs(interval));

                        // 网络变化检测：本机 IP 变了则立即重连
                        let cur_ip = get_local_ip();
                        if cur_ip != last_ip {
                            log(&format!("网络变化: {} -> {}，触发重连", last_ip, cur_ip));
                            last_ip = cur_ip.clone();
                            let _ = probe_client.force_reconnect();
                            tray::show_balloon("LanShare", "网络变化，已重新连接", false);
                            continue;
                        }

                        // 常规探测
                        let healthy = probe_client.probe();
                        if healthy && !was_healthy {
                            log("连接已恢复");
                            tray::show_balloon("LanShare", "连接已恢复", false);
                        } else if !healthy && was_healthy {
                            log("连接断开，尝试重连...");
                            tray::show_balloon("LanShare", "连接断开，正在重连...", true);
                        }
                        was_healthy = healthy;
                    }
                });
            }
            // 让用户看到挂载成功提示，随后隐藏控制台
            std::thread::sleep(Duration::from_secs(2));
            #[cfg(windows)]
            hide_console();
            // 主线程运行托盘（阻塞，直到用户选择退出）
            tray::run_tray(drive, client_handle, pending_writes_handle);
            // 优雅停止 WinFsp 服务（触发 svc_stop 卸载盘符）。
            log("用户退出，发送停止信号");
            fsp.stop();
        }
        Err(_) => {
            // 挂载失败，服务已自行停止
            log("挂载失败，服务退出");
        }
    }

    // 等待 stop 回调（卸载盘符）完成：正常会很快返回；
    // 若存在挂起的 I/O 或后台 runtime 导致卸载卡住，则限时等待后强制结束进程——
    // WinFsp 驱动会在进程退出时兜底卸载盘符，确保「卸载并退出」一定生效。
    match stop_rx.recv_timeout(Duration::from_secs(3)) {
        Ok(_) => log("服务已优雅停止"),
        Err(_) => log("服务停止超时，强制退出进程"),
    }
    std::process::exit(0);
}

/// 查找空闲盘符（从 Z: 往下，与 WinFsp NextFreeDrive 行为一致）
#[cfg(windows)]
fn find_free_drive() -> String {
    use windows::Win32::Storage::FileSystem::GetLogicalDrives;
    let mask = unsafe { GetLogicalDrives() };
    for i in (0..26u32).rev() {
        if mask & (1 << i) == 0 {
            return format!("{}:", (b'A' + i as u8) as char);
        }
    }
    "L:".to_string()
}

#[cfg(not(windows))]
fn find_free_drive() -> String {
    "L:".to_string()
}

fn svc_start(
    server: &str,
    auth: &LspAuth,
    mount: &str,
    label: &str,
    drive_tx: std::sync::mpsc::Sender<String>,
    client_tx: std::sync::mpsc::Sender<Arc<LspShareClient>>,
    pending_tx: std::sync::mpsc::Sender<Arc<std::sync::atomic::AtomicUsize>>,
) -> Result<LanShareFsHost, FspError> {
    println!("  🌐 连接 {} ...", server);
    let client = LspShareClient::connect(server, auth.clone()).map_err(|e| {
        let msg = format!("LSP3 连接失败: {}", e);
        log(&msg);
        eprintln!("\n  ❌ {}", msg);
        show_message_box(&msg, "LanShare 客户端 - 连接失败", 0x10);
        FspError::NTSTATUS(windows::Win32::Foundation::STATUS_CONNECTION_REFUSED.0)
    })?;

    log(&format!("连接成功: {}", server));
    println!("  ✅ 认证成功，挂载中...");

    let client = Arc::new(client);
    // 服务端授予的权限决定卷是否可写：只读权限时以只读卷挂载
    let writable = client.is_writable();
    // 回传客户端句柄供托盘使用（状态显示 + 手动重连）
    let _ = client_tx.send(client.clone());
    let context = LanShareFs::new(client);
    // 回传写回计数器句柄供托盘使用（同步状态 + 优雅退出）
    let _ = pending_tx.send(context.pending_writes_handle());

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
        .read_only_volume(!writable)
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

    // 确定盘符："*"/空 → 自动找空闲盘符；"L" → "L:"；其他照旧
    let drive = if mount == "*" || mount.is_empty() {
        find_free_drive()
    } else if mount.len() == 1 && mount.chars().next().unwrap().is_ascii_alphabetic() {
        format!("{}:", mount)
    } else {
        mount.to_string()
    };

    host.mount(drive.as_str()).map_err(|_| {
        FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0)
    })?;

    host.start()
        .map_err(|_| FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0))?;

    // 通知主线程实际挂载的盘符（用于托盘显示）
    let _ = drive_tx.send(drive.clone());

    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║  ✅ 挂载成功！盘符 {}                      ║", drive);
    println!("  ║  在资源管理器中查看盘符                  ║");
    println!("  ║  托盘图标可卸载退出                      ║");
    println!("  ╚══════════════════════════════════════════╝");
    println!();

    println!("  权限模式：{}", if writable { "可读写" } else { "只读" });
    println!();

    log(&format!("挂载成功，盘符 {}（{}）", drive, if writable { "可读写" } else { "只读" }));

    Ok(LanShareFsHost { host })
}

fn svc_stop(fs: Option<&mut LanShareFsHost>) {
    if let Some(host) = fs {
        host.host.stop();
        log("已卸载盘符，服务停止");
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
