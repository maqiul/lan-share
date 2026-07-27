//! Windows 平台入口 — WinFsp 挂载 + 系统托盘 + 开机自启

pub(crate) mod fs;
pub(crate) mod tray;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use winfsp::host::{DebugMode, FileSystemHost, FileSystemParams, VolumeParams};
use winfsp::service::FileSystemServiceBuilder;
use winfsp::winfsp_init_or_die;
use winfsp::FspError;

use crate::discovery::{self, Args, ResolvedConfig};
use fs::LanShareFs;
use lanshare_client::{LspAuth, LspShareClient};

// ══════════════════════════════════════════════════════════
//  开机自启动（注册表 Run 键）
// ══════════════════════════════════════════════════════════

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
                discovery::log(&format!("开机自启动已开启: {}", cmd));
            }
        }
    } else if let Ok(run) = hkcu.open_subkey_with_flags(AUTOSTART_REG_KEY, KEY_SET_VALUE) {
        let _ = run.delete_value(AUTOSTART_VALUE_NAME);
        discovery::log("开机自启动已关闭");
    }
}

/// 获取本机主要 IP 地址（用于网络变化检测）
fn get_local_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("223.5.5.5:53")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

// ══════════════════════════════════════════════════════════
//  弹窗 / 控制台
// ══════════════════════════════════════════════════════════

fn show_message_box(text: &str, title: &str, flags: u32) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::*;
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

/// 释放控制台，让程序完全在后台运行
fn hide_console() {
    use windows::Win32::System::Console::FreeConsole;
    unsafe {
        let _ = FreeConsole();
    }
}

// ══════════════════════════════════════════════════════════
//  Windows 主入口
// ══════════════════════════════════════════════════════════

pub fn run() {
    // 设置控制台 UTF-8 输出
    unsafe {
        use windows::Win32::System::Console::*;
        let _ = SetConsoleOutputCP(65001);
        let _ = SetConsoleCP(65001);
    }

    // 单实例保护
    unsafe {
        use windows::core::w;
        use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
        use windows::Win32::System::Threading::CreateMutexW;
        let _ = CreateMutexW(None, true, w!("Global\\LanShareClient_Mutex"));
        if windows::Win32::Foundation::GetLastError() == ERROR_ALREADY_EXISTS {
            show_message_box(
                "LanShare 客户端已在运行中。",
                "LanShare 客户端",
                0x40,
            );
            return;
        }
    }

    // 确保 WinFsp DLL 可被 delayload 找到
    unsafe {
        use windows::core::w;
        use windows::Win32::System::LibraryLoader::SetDllDirectoryW;
        let _ = SetDllDirectoryW(w!("C:\\Program Files (x86)\\WinFsp\\bin"));
    }

    let winfsp_dll = std::path::Path::new(r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll");
    if !winfsp_dll.exists() {
        let msg = "未检测到 WinFsp，请先安装 WinFsp 2.x：\n\nhttps://winfsp.dev\n\n安装完成后重新运行本程序。";
        eprintln!("\n  ❌ {}", msg);
        show_message_box(msg, "LanShare 客户端 - 缺少 WinFsp", 0x10);
        return;
    }

    let args = Args::parse();

    discovery::log("═══ LanShare 客户端启动 (Windows) ═══");

    let cfg = match ResolvedConfig::resolve(args) {
        Ok(c) => c,
        Err(msg) => {
            discovery::log(&format!("配置解析失败: {}", msg));
            eprintln!("\n  ❌ {}", msg);
            show_message_box(&msg, "LanShare 客户端", 0x10);
            pause_exit();
            return;
        }
    };

    discovery::log(&format!("目标服务器: {}", cfg.lsp_addr()));

    if !cfg.has_auth() {
        let msg = "错误：没有认证信息（PIN / 账号密码 / Token）";
        eprintln!("\n  ❌ {}", msg);
        show_message_box(msg, "LanShare 客户端", 0x10);
        pause_exit();
        return;
    }

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
        discovery::log(msg);
        eprintln!("\n  ❌ {}", msg);
        show_message_box(msg, "LanShare 客户端", 0x10);
        pause_exit();
        return;
    };

    let mount = cfg.mount.clone();
    let label = cfg.label.clone();
    let server = cfg.lsp_addr();

    let (drive_tx, drive_rx) = std::sync::mpsc::channel::<String>();
    let (client_tx, client_rx) = std::sync::mpsc::channel::<Arc<LspShareClient>>();
    let (pending_tx, pending_rx) =
        std::sync::mpsc::channel::<Arc<std::sync::atomic::AtomicUsize>>();
    let shared = Arc::new(Mutex::new(Some((server, auth, mount, label, drive_tx, client_tx, pending_tx))));

    let init = winfsp_init_or_die();

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

    match drive_rx.recv() {
        Ok(drive) => {
            let client_handle = client_rx.recv().ok();
            let pending_writes_handle = pending_rx.recv().ok();
            // 后台健康探测 + 网络变化检测
            if let Some(ref c) = client_handle {
                let probe_client = c.clone();
                std::thread::spawn(move || {
                    let mut last_ip = get_local_ip();
                    let mut was_healthy = true;
                    loop {
                        let interval = if probe_client.is_healthy() { 5 } else { 2 };
                        std::thread::sleep(Duration::from_secs(interval));

                        let cur_ip = get_local_ip();
                        if cur_ip != last_ip {
                            discovery::log(&format!("网络变化: {} -> {}，触发重连", last_ip, cur_ip));
                            last_ip = cur_ip.clone();
                            let _ = probe_client.force_reconnect();
                            tray::show_balloon("LanShare", "网络变化，已重新连接", false);
                            continue;
                        }

                        let healthy = probe_client.probe();
                        if healthy && !was_healthy {
                            discovery::log("连接已恢复");
                            tray::show_balloon("LanShare", "连接已恢复", false);
                        } else if !healthy && was_healthy {
                            discovery::log("连接断开，尝试重连...");
                            tray::show_balloon("LanShare", "连接断开，正在重连...", true);
                        }
                        was_healthy = healthy;
                    }
                });
            }
            std::thread::sleep(Duration::from_secs(2));
            hide_console();
            tray::run_tray(drive, client_handle, pending_writes_handle);
            discovery::log("用户退出，发送停止信号");
            fsp.stop();
        }
        Err(_) => {
            discovery::log("挂载失败，服务退出");
        }
    }

    match stop_rx.recv_timeout(Duration::from_secs(3)) {
        Ok(_) => discovery::log("服务已优雅停止"),
        Err(_) => discovery::log("服务停止超时，强制退出进程"),
    }
    std::process::exit(0);
}

// ══════════════════════════════════════════════════════════
//  WinFsp 服务
// ══════════════════════════════════════════════════════════

/// 查找空闲盘符（从 Z: 往下）
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
        discovery::log(&msg);
        eprintln!("\n  ❌ {}", msg);
        show_message_box(&msg, "LanShare 客户端 - 连接失败", 0x10);
        FspError::NTSTATUS(windows::Win32::Foundation::STATUS_CONNECTION_REFUSED.0)
    })?;

    discovery::log(&format!("连接成功: {}", server));
    println!("  ✅ 认证成功，挂载中...");

    let client = Arc::new(client);
    let writable = client.is_writable();
    let _ = client_tx.send(client.clone());
    let context = LanShareFs::new(client);
    let _ = pending_tx.send(context.pending_writes_handle());

    let mut volume_params = VolumeParams::new();
    volume_params
        .sector_size(512)
        .sectors_per_allocation_unit(1)
        .volume_creation_time(now_filetime())
        .volume_serial_number(0x4C53_4852)
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

    discovery::log(&format!("挂载成功，盘符 {}（{}）", drive, if writable { "可读写" } else { "只读" }));

    Ok(LanShareFsHost { host })
}

fn svc_stop(fs: Option<&mut LanShareFsHost>) {
    if let Some(host) = fs {
        host.host.stop();
        discovery::log("已卸载盘符，服务停止");
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
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let _ = std::io::stdin().read_line(&mut String::new());
}
