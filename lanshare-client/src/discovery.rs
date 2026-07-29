//! 跨平台共享：UDP 发现协议 + 配置读写 + CLI 参数 + 日志
//!
//! 从 main.rs 提取，供 Windows (WinFsp) 与 Unix (FUSE) 入口复用。

use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use serde::{Deserialize, Serialize};

// ══════════════════════════════════════════════════════════
//  发现协议（同步 UDP，与服务端 discovery.rs 对应）
// ══════════════════════════════════════════════════════════

pub const DISCOVERY_PORT: u16 = 9999;
pub const DISCOVER_MAGIC: &[u8] = b"LANSHARE_DISCOVER";

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveredServer {
    pub name: String,
    pub ip: String,
    #[serde(alias = "webdav_port")]
    pub web_port: u16,
    pub lsp_port: u16,
    #[allow(dead_code)]
    pub version: String,
    /// 是否简易模式（true=PIN，false=账号密码）
    #[serde(default)]
    pub simple_mode: bool,
}

impl DiscoveredServer {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.ip, self.web_port)
    }
}

/// 同步 UDP 广播扫描局域网 LanShare 服务器
pub fn scan_lan(timeout_ms: u64) -> Vec<DiscoveredServer> {
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
                    let mut info = info;
                    info.ip = src.ip().to_string();
                    if !results
                        .iter()
                        .any(|r: &DiscoveredServer| r.addr() == info.addr())
                    {
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
pub fn read_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().ok();

    #[cfg(windows)]
    {
        use windows::Win32::System::Console::*;
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE).unwrap_or_default();
            let mut mode = CONSOLE_MODE::default();
            let _ = GetConsoleMode(handle, &mut mode);
            let _ = SetConsoleMode(handle, mode & !CONSOLE_MODE(0x0004));
            let mut line = String::new();
            io::stdin().read_line(&mut line).ok();
            let _ = SetConsoleMode(handle, mode);
            println!();
            line.trim().to_string()
        }
    }

    #[cfg(unix)]
    {
        // Unix: 关闭终端回显读取密码
        unsafe {
            let mut termios: libc::termios = std::mem::zeroed();
            let fd = 0; // stdin
            if libc::tcgetattr(fd, &mut termios) == 0 {
                let orig = termios;
                termios.c_lflag &= !libc::ECHO;
                libc::tcsetattr(fd, libc::TCSANOW, &termios);
                let mut line = String::new();
                io::stdin().read_line(&mut line).ok();
                libc::tcsetattr(fd, libc::TCSANOW, &orig);
                println!();
                return line.trim().to_string();
            }
        }
        let mut line = String::new();
        io::stdin().read_line(&mut line).ok();
        line.trim().to_string()
    }

    #[cfg(not(any(windows, unix)))]
    {
        let mut line = String::new();
        io::stdin().read_line(&mut line).ok();
        line.trim().to_string()
    }
}

/// 读取一行普通输入
pub fn read_line(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line).ok();
    line.trim().to_string()
}

/// 交互发现模式：扫描 → 选择 → 认证 → 返回配置
pub fn interactive_discover() -> Option<ResolvedConfig> {
    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║   LanShare 客户端 - 自动发现模式        ║");
    println!("  ╚══════════════════════════════════════════╝");
    println!();

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

        let addr = read_line("  手动输入服务端地址 (IP:端口，回车取消): ");
        if addr.is_empty() {
            return None;
        }
        return interactive_auth(addr, None, default_lsp_port());
    }

    println!("  发现 {} 台 LanShare 服务器：", servers.len());
    println!();
    for (i, s) in servers.iter().enumerate() {
        println!("    [{}] {} ({})", i + 1, s.name, s.addr());
    }
    println!();

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
    println!(
        "  模式: {}",
        if simple_mode {
            "简易模式（PIN 码）"
        } else {
            "账号模式（用户名+密码）"
        }
    );
    println!();

    interactive_auth(server, Some(simple_mode), lsp_port)
}

/// 交互认证：根据服务器模式自动选择认证方式 → 输入凭据
pub fn interactive_auth(
    server: String,
    known_mode: Option<bool>,
    lsp_port: u16,
) -> Option<ResolvedConfig> {
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

    let mount = { read_line("  挂载点 (直接回车=默认): ") };

    let label = {
        let input = read_line("  卷标名称 (直接回车=LanShare): ");
        if input.is_empty() {
            "LanShare".to_string()
        } else {
            input
        }
    };

    println!();

    let save = read_line("  保存配置到文件？下次免输 [Y/n]: ");
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
            println!("  💾 配置已保存（下次直接挂载）");
        }
    }

    println!();
    Some(cfg)
}

// ══════════════════════════════════════════════════════════
//  配置文件
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default = "default_server")]
    pub server: String,
    #[serde(default = "default_lsp_port")]
    pub lsp_port: u16,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub mount: String,
    #[serde(default = "default_label")]
    pub label: String,
}

pub fn default_server() -> String {
    "127.0.0.1:8080".to_string()
}
pub fn default_lsp_port() -> u16 {
    9820
}
pub fn default_label() -> String {
    "LanShare".to_string()
}

/// 平台默认挂载点
pub fn default_mount() -> String {
    #[cfg(windows)]
    {
        "*".to_string()
    }
    #[cfg(unix)]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/LanShare", home)
    }
    #[cfg(not(any(windows, unix)))]
    {
        "LanShare".to_string()
    }
}

// ══════════════════════════════════════════════════════════
//  敏感信息保护（Windows: DPAPI；Unix: 明文 600 权限文件）
// ══════════════════════════════════════════════════════════

#[cfg(windows)]
const ENC_PREFIX: &str = "enc:";

#[cfg(windows)]
pub fn protect_secret(plain: &str) -> String {
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
        let cipher =
            unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
        let enc = base64::engine::general_purpose::STANDARD.encode(cipher);
        unsafe {
            let _ = LocalFree(Some(HLOCAL(out_blob.pbData as _)));
        }
        format!("{}{}", ENC_PREFIX, enc)
    } else {
        plain.to_string()
    }
}

#[cfg(windows)]
pub fn unprotect_secret(value: &str) -> String {
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
        let plain_bytes =
            unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
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
pub fn protect_secret(plain: &str) -> String {
    plain.to_string()
}
#[cfg(not(windows))]
pub fn unprotect_secret(value: &str) -> String {
    value.to_string()
}

pub fn client_config_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("lanshare-client.toml")))
}

pub fn load_client_config() -> Option<ClientConfig> {
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
        cfg.pin = cfg.pin.map(|v| unprotect_secret(&v));
        cfg.password = cfg.password.map(|v| unprotect_secret(&v));
        cfg.token = cfg.token.map(|v| unprotect_secret(&v));
        cfg
    })
}

pub fn save_client_config(cfg: &ResolvedConfig) -> Result<(), String> {
    let path = client_config_path().ok_or("无法获取配置文件路径")?;

    let content = format!(
        r#"# LanShare 客户端配置（自动生成，可手动编辑）

server = "{}"
lsp_port = {}
{}{}{}{}mount = "{}"
label = "{}"
"#,
        cfg.server,
        cfg.lsp_port,
        cfg.pin
            .as_ref()
            .map(|p| format!("pin = \"{}\"\n", protect_secret(p)))
            .unwrap_or_default(),
        cfg.username
            .as_ref()
            .map(|u| format!("username = \"{}\"\n", u))
            .unwrap_or_default(),
        cfg.password
            .as_ref()
            .map(|p| format!("password = \"{}\"\n", protect_secret(p)))
            .unwrap_or_default(),
        cfg.token
            .as_ref()
            .map(|t| format!("token = \"{}\"\n", protect_secret(t)))
            .unwrap_or_default(),
        cfg.mount,
        cfg.label,
    );

    std::fs::write(&path, content).map_err(|e| format!("{}", e))?;

    // Unix: 配置文件含密码，收紧权限为 600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════
//  日志（写入 exe 同目录 lanshare-client.log）
// ══════════════════════════════════════════════════════════

pub fn log_file_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("lanshare-client.log")))
}

/// 将 UNIX 秒格式化为 "YYYY-MM-DD HH:MM:SS"（UTC）
fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
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
pub fn log(msg: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Some(path) = log_file_path() {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "[{}] {}", format_unix_utc(ts), msg);
        }
    }
}

// ══════════════════════════════════════════════════════════
//  CLI 参数
// ══════════════════════════════════════════════════════════

#[derive(Parser, Debug)]
#[command(name = "lanshare-client", about = "LanShare 网络驱动器挂载（跨平台）")]
pub struct Args {
    /// LanShare 服务端地址（IP:端口）
    #[arg(short, long)]
    pub server: Option<String>,

    /// LSP3 协议端口（默认 9820）
    #[arg(long)]
    pub lsp_port: Option<u16>,

    /// 简易模式 PIN 码
    #[arg(long)]
    pub pin: Option<String>,

    /// 账号模式用户名
    #[arg(short = 'u', long)]
    pub username: Option<String>,

    /// 账号模式密码
    #[arg(short = 'p', long)]
    pub password: Option<String>,

    /// Session token
    #[arg(short, long)]
    pub token: Option<String>,

    /// 挂载点（Windows: 盘符如 "L:" 或 "*"；Unix: 目录路径）
    #[arg(short, long)]
    pub mount: Option<String>,

    /// 卷标名称
    #[arg(short, long)]
    pub label: Option<String>,

    /// 跳过交互发现
    #[arg(long)]
    pub no_interactive: bool,

    /// 前台运行（Unix，不 fork 守护进程）
    #[cfg(unix)]
    #[arg(short, long)]
    pub foreground: bool,
}

// ══════════════════════════════════════════════════════════
//  配置合并
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub server: String,
    pub lsp_port: u16,
    pub pin: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub mount: String,
    pub label: String,
}

impl ResolvedConfig {
    /// LSP3 连接地址（ip:lsp_port）
    pub fn lsp_addr(&self) -> String {
        let ip = self.server.split(':').next().unwrap_or(&self.server);
        format!("{}:{}", ip, self.lsp_port)
    }

    pub fn has_auth(&self) -> bool {
        self.pin.is_some()
            || (self.username.is_some() && self.password.is_some())
            || self.token.is_some()
    }

    /// 解析配置：CLI > 配置文件 > 交互发现
    pub fn resolve(args: Args) -> Result<Self, String> {
        let has_cli_auth = args.pin.is_some() || args.username.is_some() || args.token.is_some();

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

        if let Some(cfg) = load_client_config() {
            if cfg.pin.is_some() || cfg.username.is_some() || cfg.token.is_some() {
                return Ok(ResolvedConfig {
                    server: args.server.unwrap_or(cfg.server),
                    lsp_port: args.lsp_port.unwrap_or(cfg.lsp_port),
                    pin: cfg.pin,
                    username: cfg.username,
                    password: cfg.password,
                    token: cfg.token,
                    mount: if let Some(m) = args.mount {
                        m
                    } else if cfg.mount.is_empty() {
                        default_mount()
                    } else {
                        cfg.mount
                    },
                    label: args.label.unwrap_or(cfg.label),
                });
            }
        }

        if args.no_interactive {
            return Err("没有配置且 --no-interactive 已设置".to_string());
        }

        interactive_discover().ok_or_else(|| "用户取消了操作".to_string())
    }
}
