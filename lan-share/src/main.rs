use clap::{Parser, Subcommand};
use lsp_protocol::{LspClient, LspServer, ServerConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, error};

mod api;
mod db;
mod discovery;
mod webdav;
mod wsp;

// 配置文件

/// GUI 模式配置（存于 exe 同目录的 lanshare.toml）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    /// 共享目录（相对路径相对 exe 所在目录）
    #[serde(default = "default_shared_dir")]
    shared_dir: String,
    /// LSP 协议端口
    #[serde(default = "default_lsp_port")]
    lsp_port: u16,
    /// WebDAV / Web UI 端口（0 = 禁用）
    #[serde(default = "default_webdav_port")]
    webdav_port: u16,
    /// 访问 PIN
    #[serde(default = "default_pin")]
    pin: String,
    /// 设备名（空 = 用计算机名）
    #[serde(default)]
    device_name: String,
    /// 启动后自动打开浏览器
    #[serde(default = "default_true")]
    auto_browser: bool,
}

fn default_shared_dir() -> String { "./shared".to_string() }
fn default_lsp_port() -> u16 { 9820 }
fn default_webdav_port() -> u16 { 8080 }
fn default_pin() -> String { "123456".to_string() }
fn default_true() -> bool { true }

impl Default for Config {
    fn default() -> Self {
        Config {
            shared_dir: default_shared_dir(),
            lsp_port: default_lsp_port(),
            webdav_port: default_webdav_port(),
            pin: default_pin(),
            device_name: String::new(),
            auto_browser: true,
        }
    }
}

/// 默认配置模板（首次运行写入，含中文注释供用户编辑）
const CONFIG_TEMPLATE: &str = r#"# LanShare 配置文件
# 修改后重启程序生效

# 共享目录（相对路径相对本文件所在目录；也可用绝对路径如 D:\share）
shared_dir = "./shared"

# LSP 协议端口（lan-share CLI 客户端连接用）
lsp_port = 9820

# WebDAV / Web 界面端口（0 = 禁用 WebDAV 和网页界面）
webdav_port = 8080

# 访问 PIN（简易模式用，Web UI 登录请用账号密码）
pin = "123456"

# 设备名（留空 = 使用计算机名）
device_name = ""

# 启动后自动打开浏览器
auto_browser = true
"#;

/// 配置文件路径（与 exe 同级）
fn config_path() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.join("lanshare.toml"))
}

/// 加载配置：文件不存在则生成默认配置；解析失败则用默认值
fn load_config() -> Config {
    let Some(path) = config_path() else {
        return Config::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(content) => match toml::from_str(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("  配置文件解析失败（{}），使用默认配置: {}", path.display(), e);
                Config::default()
            }
        },
        Err(_) => {
            // 首次运行：生成默认配置供用户编辑
            if let Err(e) = std::fs::write(&path, CONFIG_TEMPLATE) {
                eprintln!("  生成默认配置失败: {}", e);
            } else {
                println!("  已生成默认配置: {}（可编辑后重启生效）", path.display());
            }
            Config::default()
        }
    }
}

/// 解析共享目录：相对路径相对 exe 所在目录（并规范化，去掉 ./ 等）
fn resolve_shared_dir(raw: &str) -> PathBuf {
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        p
    } else if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.to_path_buf())) {
        dir.join(p).components().as_path().to_path_buf()
    } else {
        p
    }
}

/// 预检测 TCP 端口是否可用（bind 成功立即 drop）
async fn check_tcp_port(port: u16) -> Result<(), String> {
    let addr = format!("0.0.0.0:{}", port);
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("TCP 端口 {} 已被占用，无法启动服务。\n请关闭占用该端口的程序，或在 lanshare.toml 中更换端口。\n\n详细错误: {}", port, e)),
    }
}

/// 预检测 UDP 端口是否可用
async fn check_udp_port(port: u16) -> Result<(), String> {
    let addr = format!("0.0.0.0:{}", port);
    match tokio::net::UdpSocket::bind(&addr).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("UDP 端口 {} 已被占用，无法启动 LSP 服务。\n请关闭占用该端口的程序，或在 lanshare.toml 中更换端口。\n\n详细错误: {}", port, e)),
    }
}

/// 弹出错误对话框（Windows）或打印到 stderr
fn show_fatal_error(msg: &str) {
    eprintln!("\n❌ LanShare 启动失败\n{}\n", msg);
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::*;
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        let msg_w: Vec<u16> = OsStr::new(msg).encode_wide().chain(std::iter::once(0)).collect();
        let title_w: Vec<u16> = OsStr::new("LanShare 启动失败").encode_wide().chain(std::iter::once(0)).collect();
        unsafe {
            MessageBoxW(0, msg_w.as_ptr(), title_w.as_ptr(), MB_OK | MB_ICONERROR);
        }
    }
}

#[derive(Parser)]
#[command(name = "lan-share", about = "LanShare v3.0 - 基于 LSP3 协议的局域网文件共享", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 启动服务端
    Serve {
        #[arg(short, long, default_value = "9820")]
        port: u16,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long, default_value = "./shared")]
        dir: PathBuf,
        #[arg(long, default_value = "123456")]
        pin: String,
        /// WebDAV 端口（用于映射网络驱动器），0 表示禁用
        #[arg(long, default_value = "8080")]
        webdav_port: u16,
        /// 启动后不自动打开浏览器
        #[arg(long)]
        no_browser: bool,
    },
    /// 列出文件
    List {
        #[arg(default_value = "127.0.0.1:9820")]
        addr: String,
        #[arg(default_value = "/")]
        path: String,
        #[arg(short, long)]
        recursive: bool,
        #[arg(short, long, default_value = "123456")]
        pin: String,
    },
    /// 下载文件
    Download {
        #[arg(default_value = "127.0.0.1:9820")]
        addr: String,
        file: String,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long, default_value = "123456")]
        pin: String,
    },
    /// 上传文件
    Upload {
        #[arg(default_value = "127.0.0.1:9820")]
        addr: String,
        file: PathBuf,
        #[arg(short, long)]
        remote: Option<String>,
        #[arg(short, long, default_value = "123456")]
        pin: String,
    },
    /// 删除文件
    Delete {
        #[arg(default_value = "127.0.0.1:9820")]
        addr: String,
        file: String,
        #[arg(short, long)]
        recursive: bool,
        #[arg(short, long, default_value = "123456")]
        pin: String,
    },
    /// 创建目录
    Mkdir {
        #[arg(default_value = "127.0.0.1:9820")]
        addr: String,
        path: String,
        #[arg(short, long, default_value = "123456")]
        pin: String,
    },
    /// 重命名/移动
    Rename {
        #[arg(default_value = "127.0.0.1:9820")]
        addr: String,
        old: String,
        new: String,
        #[arg(short, long, default_value = "123456")]
        pin: String,
    },
    /// 查看文件信息
    Stat {
        #[arg(default_value = "127.0.0.1:9820")]
        addr: String,
        file: String,
        #[arg(short, long, default_value = "123456")]
        pin: String,
    },
    /// 差异同步上传（只传变化部分）
    DeltaUpload {
        #[arg(default_value = "127.0.0.1:9820")]
        addr: String,
        file: PathBuf,
        #[arg(short, long)]
        remote: Option<String>,
        #[arg(short, long, default_value = "123456")]
        pin: String,
    },
    /// 发现局域网内的 LanShare 服务器
    Discover {
        /// 等待响应的时间（毫秒）
        #[arg(short, long, default_value = "2000")]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lan_share=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Serve { port, name, dir, pin, webdav_port, no_browser }) => {
            run_server(port, name, dir, pin, webdav_port, !no_browser, false).await?
        }
        Some(Commands::List { addr, path, recursive, pin }) => run_list(&addr, &path, recursive, &pin).await?,
        Some(Commands::Download { addr, file, output, pin }) => run_download(&addr, &file, output, &pin).await?,
        Some(Commands::Upload { addr, file, remote, pin }) => run_upload(&addr, file, remote, &pin).await?,
        Some(Commands::Delete { addr, file, recursive, pin }) => run_delete(&addr, &file, recursive, &pin).await?,
        Some(Commands::Mkdir { addr, path, pin }) => run_mkdir(&addr, &path, &pin).await?,
        Some(Commands::Rename { addr, old, new, pin }) => run_rename(&addr, &old, &new, &pin).await?,
        Some(Commands::Stat { addr, file, pin }) => run_stat(&addr, &file, &pin).await?,
        Some(Commands::DeltaUpload { addr, file, remote, pin }) => run_delta_upload(&addr, file, remote, &pin).await?,
        Some(Commands::Discover { timeout }) => run_discover(timeout).await?,
        // 无参数：图形模式（双击启动）——默认配置 + 自动开浏览器 + 托盘常驻
        None => run_gui().await?,
    }

    Ok(())
}

async fn connect_and_auth(addr: &str, pin: &str) -> Result<LspClient, Box<dyn std::error::Error>> {
    let device_id = uuid::Uuid::new_v4().to_string();
    let mut client = LspClient::connect(addr, device_id, "lan-share-cli".to_string()).await?;
    client.handshake().await?;
    let perm = client.authenticate(pin).await?;
    info!("Permission: {}", perm);
    Ok(client)
}

async fn run_server(port: u16, name: Option<String>, dir: PathBuf, pin: String, webdav_port: u16, auto_browser: bool, with_tray: bool) -> Result<(), Box<dyn std::error::Error>> {
    let device_name = name.unwrap_or_else(|| {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "LSP-Server".to_string())
    });

    // 初始化 SQLite 数据库（与 exe 同目录）
    let db_path = config_path()
        .map(|p| p.with_file_name("lanshare.db"))
        .unwrap_or_else(|| PathBuf::from("lanshare.db"));
    let db = Arc::new(db::Database::open(&db_path).map_err(|e| format!("数据库打开失败: {e}"))?);
    info!("Database: {}", db_path.display());

    tokio::fs::create_dir_all(&dir).await?;

    let config = ServerConfig {
        device_id: uuid::Uuid::new_v4().to_string(),
        device_name: device_name.clone(),
        shared_dir: dir.clone(),
        pin: pin.clone(),
        ..Default::default()
    };

    let server = Arc::new(LspServer::new(config));

    let local_ip = local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    info!("=== LanShare LSP v3.0 Server ===");
    info!("Device: {}", device_name);
    info!("Shared dir: {}", dir.display());
    info!("LSP protocol: {}:{}", local_ip, port);
    if webdav_port > 0 {
        info!("WebDAV / Web UI: http://{}:{}", local_ip, webdav_port);
        let simple_mode = db.get_admin_setting("simple_mode")
            .map(|v| v != "false")
            .unwrap_or(true);
        if simple_mode {
            info!("PIN: {} (简易模式已开启)", pin);
            info!("--- 映射网络驱动器 ---");
            info!("  账号方式: net use Z: \\\\{}@{}\\DavWWWRoot /user:用户名 密码", local_ip, webdav_port);
            info!("  PIN 方式: net use Z: \\\\{}@{}\\DavWWWRoot /user:share {}", local_ip, webdav_port, pin);
        } else {
            info!("简易模式已关闭，请使用账号密码登录");
            info!("--- 映射网络驱动器 ---");
            info!("  net use Z: \\\\{}@{}\\DavWWWRoot /user:用户名 密码", local_ip, webdav_port);
        }
    }

    // ── 端口预检测：失败则弹窗提示，不闪退 ──
    if let Err(msg) = check_udp_port(port).await {
        show_fatal_error(&msg);
        return Err(msg.into());
    }
    if webdav_port > 0 {
        if let Err(msg) = check_tcp_port(webdav_port).await {
            show_fatal_error(&msg);
            return Err(msg.into());
        }
    }

    // LSP 二进制协议服务（UDP）
    let lsp_server = server.clone();
    let lsp_handle = tokio::spawn(async move {
        let addr = format!("0.0.0.0:{}", port);
        if let Err(e) = lsp_server.serve(&addr).await {
            error!("LSP UDP server error: {}", e);
        }
    });

    // WebDAV 服务
    if webdav_port > 0 {
        let webdav_dir = dir.clone();
        let webdav_pin = pin.clone();
        let webdav_name = device_name.clone();
        let webdav_ip = local_ip.clone();
        let webdav_cfg = config_path();
        let webdav_db = db.clone();
        let webdav_handle = tokio::spawn(async move {
            if let Err(e) = webdav::start_webdav_server(
                webdav_port, webdav_dir, webdav_pin, webdav_name, webdav_ip, port, webdav_cfg, webdav_db,
            ).await {
                error!("WebDAV server error: {}", e);
            }
        });

        // 局域网发现服务（UDP 广播）
        let discovery_info = Arc::new(discovery::ServerInfo {
            name: device_name.clone(),
            ip: local_ip.clone(),
            webdav_port,
            lsp_port: port,
            version: env!("CARGO_PKG_VERSION").to_string(),
        });
        tokio::spawn(async move {
            if let Err(e) = discovery::start_discovery_server(discovery_info).await {
                error!("Discovery server error: {}", e);
            }
        });

        // 自动打开浏览器（延迟 800ms 等服务就绪）
        if auto_browser {
            let url = format!("http://127.0.0.1:{}", webdav_port);
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                open_browser(&url);
            });
        }

        // 系统托盘常驻（_tray 持有到函数结束，避免图标被销毁）
        let _tray = if with_tray {
            let url = format!("http://127.0.0.1:{}", webdav_port);
            match setup_tray(&url) {
                Ok(t) => {
                    info!("托盘图标就绪（右键可打开界面 / 退出）");
                    Some(t)
                }
                Err(e) => {
                    error!("托盘图标创建失败: {}", e);
                    None
                }
            }
        } else {
            None
        };

        tokio::select! {
            _ = lsp_handle => {},
            _ = webdav_handle => {},
        }
    } else {
        lsp_handle.await?;
    }

    Ok(())
}

/// 图形模式（双击启动）：读取配置 + 自动开浏览器 + 托盘常驻
async fn run_gui() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = load_config();
    let shared_dir = resolve_shared_dir(&cfg.shared_dir);
    let name = if cfg.device_name.is_empty() { None } else { Some(cfg.device_name.clone()) };

    println!("╔════════════════════════════════════════════╗");
    println!("║     LanShare - 局域网文件共享              ║");
    println!("╚════════════════════════════════════════════╝");
    println!();
    println!("  图形模式启动中...");
    println!("  共享目录: {}", shared_dir.display());
    println!("  访问 PIN: {}", cfg.pin);
    println!("  LSP 端口: {}", cfg.lsp_port);
    if cfg.webdav_port > 0 {
        println!("  WebDAV / 界面端口: {}", cfg.webdav_port);
    } else {
        println!("  WebDAV / 界面: 已禁用");
    }
    println!();
    println!("  提示: 浏览器将自动打开；服务在托盘后台常驻");
    println!("        右键托盘图标可打开界面 / 退出");
    println!("        关闭本窗口将停止服务");
    println!();
    run_server(cfg.lsp_port, name, shared_dir, cfg.pin.clone(), cfg.webdav_port, cfg.auto_browser, true).await
}

/// 打开默认浏览器（各平台原生实现，零依赖）
fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    { let _ = std::process::Command::new("cmd").args(["/c", "start", "", url]).spawn(); }
    #[cfg(target_os = "macos")]
    { let _ = std::process::Command::new("open").arg(url).spawn(); }
    #[cfg(all(unix, not(target_os = "macos")))]
    { let _ = std::process::Command::new("xdg-open").arg(url).spawn(); }
}

/// 创建系统托盘图标（含「打开界面」「退出」菜单）
#[cfg(target_os = "windows")]
fn setup_tray(url: &str) -> Result<tray_item::TrayItem, Box<dyn std::error::Error>> {
    use tray_item::{IconSource, TrayItem};

    // 运行时生成图标字节 → CreateIconFromResourceEx 得到 HICON（无需外部 ico 文件）
    // 注意：该 API 需要图标「资源数据」（BITMAPINFOHEADER 起），须跳过 ICO 文件的 22 字节头（ICONDIR+ICONDIRENTRY）
    let icon_bytes = generate_icon_bytes();
    let res_data = &icon_bytes[22..];
    let hicon = unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::CreateIconFromResourceEx(
            res_data.as_ptr(),
            res_data.len() as u32,
            1,          // fIcon = TRUE
            0x00030000, // 图标版本
            16, 16,     // 期望尺寸
            0,          // LR_DEFAULTCOLOR
        )
    };
    if hicon == 0 {
        return Err("创建图标失败".into());
    }

    let mut tray = TrayItem::new("LanShare", IconSource::RawIcon(hicon))?;
    let _ = tray.add_label("LanShare - 局域网文件共享");

    let url_open = url.to_string();
    tray.add_menu_item("打开 LanShare 界面", move || open_browser(&url_open))?;
    tray.add_menu_item("退出", || std::process::exit(0))?;

    Ok(tray)
}

#[cfg(not(target_os = "windows"))]
fn setup_tray(_url: &str) -> Result<tray_item::TrayItem, Box<dyn std::error::Error>> {
    Err("当前平台暂不支持托盘图标".into())
}

/// 生成 16×16 32 位图标（.ico 字节流）：蓝色圆角背景 + 白色向上箭头（传输/分享）
fn generate_icon_bytes() -> Vec<u8> {
    const W: usize = 16;
    let blue: [u8; 4] = [0xE9, 0x7D, 0x2B, 0xFF]; // #2B7DE9（BGRA 序）
    let white: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
    let transparent: [u8; 4] = [0, 0, 0, 0];

    // 构建像素矩阵（逻辑坐标，y=0 为顶部）
    let mut px = [[0u8; 4]; W * W];
    for y in 0..W {
        for x in 0..W {
            let idx = y * W + x;
            // 四角 1px 透明 → 圆角效果
            if (x == 0 && y == 0) || (x == W - 1 && y == 0)
                || (x == 0 && y == W - 1) || (x == W - 1 && y == W - 1)
            {
                px[idx] = transparent;
            } else if is_arrow_pixel(x, y) {
                px[idx] = white;
            } else {
                px[idx] = blue;
            }
        }
    }

    let mut v = Vec::with_capacity(1150);
    // ICONDIR: reserved=0, type=1(图标), count=1
    v.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
    // ICONDIRENTRY: 16×16, 32bit, 数据长 1128, 偏移 22
    v.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0]);
    v.extend_from_slice(&1128u32.to_le_bytes());
    v.extend_from_slice(&22u32.to_le_bytes());
    // BITMAPINFOHEADER (40 字节): height=32（XOR+AND 双倍高度）
    v.extend_from_slice(&40u32.to_le_bytes());
    v.extend_from_slice(&16i32.to_le_bytes());
    v.extend_from_slice(&32i32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&32u16.to_le_bytes());
    v.extend_from_slice(&[0u8; 24]); // 压缩/大小/分辨率/色表
    // XOR 像素：DIB 扫描序为自下而上（从最后一行往第一行写，否则箭头会颠倒）
    for y in (0..W).rev() {
        for x in 0..W {
            v.extend_from_slice(&px[y * W + x]);
        }
    }
    // AND 掩码：16 行 × 4 字节，全 0（完全不透明）
    v.extend_from_slice(&[0u8; 64]);
    v
}

/// 判断像素 (x,y) 是否属于白色向上箭头（16×16 逻辑坐标，y=0 为顶部）
fn is_arrow_pixel(x: usize, y: usize) -> bool {
    // 箭头三角：第 3-7 行，自中心向外展开
    if (3..=7).contains(&y) {
        let spread = y - 2; // 行3:1 … 行7:5
        return x >= 8 - spread && x <= 7 + spread;
    }
    // 箭杆：第 8-12 行，列 6-9
    if (8..=12).contains(&y) {
        return (6..=9).contains(&x);
    }
    false
}

async fn run_list(addr: &str, path: &str, recursive: bool, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = connect_and_auth(addr, pin).await?;
    let files = client.list_files(path, recursive).await?;

    println!("\n📁 Files:");
    println!("{:-<70}", "");
    for f in &files {
        let icon = if f.is_dir { "📁" } else { "📄" };
        let size = if f.is_dir { "<DIR>".to_string() } else { format_size(f.size) };
        let ro = if f.readonly { " [RO]" } else { "" };
        let time = chrono::DateTime::from_timestamp(f.modified, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();
        println!("{} {:<30} {:>10}  {}{}", icon, f.name, size, time, ro);
    }
    println!("{:-<70}", "");
    println!("Total: {} items", files.len());
    Ok(())
}

async fn run_download(addr: &str, file: &str, output: PathBuf, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = connect_and_auth(addr, pin).await?;
    info!("Downloading {} -> {}", file, output.display());
    let size = client.download_file(file, output, 0).await?;
    println!("✅ Downloaded {} bytes", size);
    Ok(())
}

async fn run_upload(addr: &str, file: PathBuf, remote: Option<String>, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = connect_and_auth(addr, pin).await?;
    let remote_name = remote.unwrap_or_else(|| {
        file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".to_string())
    });
    info!("Uploading {} -> {}", file.display(), remote_name);
    let size = client.upload_file(file, &remote_name).await?;
    println!("✅ Uploaded {} bytes", size);
    Ok(())
}

async fn run_delete(addr: &str, file: &str, recursive: bool, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = connect_and_auth(addr, pin).await?;
    client.delete_file(file, recursive).await?;
    println!("✅ Deleted: {}", file);
    Ok(())
}

async fn run_mkdir(addr: &str, path: &str, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = connect_and_auth(addr, pin).await?;
    client.mkdir(path).await?;
    println!("✅ Directory created: {}", path);
    Ok(())
}

async fn run_rename(addr: &str, old: &str, new: &str, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = connect_and_auth(addr, pin).await?;
    client.rename(old, new).await?;
    println!("✅ Renamed: {} -> {}", old, new);
    Ok(())
}

async fn run_stat(addr: &str, file: &str, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = connect_and_auth(addr, pin).await?;
    let entry = client.stat_file(file).await?;

    println!("\n📄 File Info:");
    println!("{:-<50}", "");
    println!("Name:     {}", entry.name);
    println!("Path:     {}", entry.path);
    println!("Size:     {} ({})", format_size(entry.size), entry.size);
    println!("Type:     {}", if entry.is_dir { "Directory" } else { "File" });
    println!("Readonly: {}", entry.readonly);
    println!("Modified: {}", chrono::DateTime::from_timestamp(entry.modified, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default());
    if let Some(sha) = &entry.sha256 {
        println!("SHA-256:  {}", sha);
    }
    Ok(())
}

async fn run_delta_upload(addr: &str, file: PathBuf, remote: Option<String>, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = connect_and_auth(addr, pin).await?;
    let remote_name = remote.unwrap_or_else(|| {
        file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".to_string())
    });
    info!("Delta uploading {} -> {}", file.display(), remote_name);
    let size = client.delta_upload(file, &remote_name).await?;
    println!("✅ Delta uploaded {} bytes (only changes)", size);
    Ok(())
}

async fn run_discover(timeout: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 正在发现局域网内的 LanShare 服务器...");
    let servers = discovery::discover_servers(timeout).await;

    if servers.is_empty() {
        println!("❌ 未发现任何服务器");
        println!("   请确认：");
        println!("   1. 服务端已启动（lan-share serve）");
        println!("   2. 防火墙允许 UDP {} 端口", discovery::DISCOVERY_PORT);
        println!("   3. 本机与服务端在同一局域网");
    } else {
        println!("✅ 发现 {} 台服务器：\n", servers.len());
        for (i, s) in servers.iter().enumerate() {
            println!("  {}. {} ({})", i + 1, s.name, s.ip);
            println!("     Web UI:  {}", s.url);
            println!("     LSP:     {}:{}", s.ip, s.lsp_port);
            println!("     版本:    v{}", s.version);
            println!();
        }
    }

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes == 0 { return "0 B".to_string(); }
    let k = 1024;
    let sizes = ["B", "KB", "MB", "GB", "TB"];
    let i = (bytes as f64).log(k as f64) as usize;
    let i = i.min(sizes.len() - 1);
    format!("{:.1} {}", bytes as f64 / (k as f64).powi(i as i32), sizes[i])
}
