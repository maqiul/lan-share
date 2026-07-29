//! Unix 平台入口 — FUSE 挂载 + 前台/守护进程 + 信号优雅退出

pub(crate) mod fuse_fs;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use fuser::MountOption;

use crate::discovery::{self, Args, ResolvedConfig};
use lanshare_client::{LspAuth, LspShareClient};

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

/// Unix 主入口
pub fn run() {
    let args = Args::parse();
    let foreground = args.foreground;

    discovery::log("═══ LanShare 客户端启动 (Unix/FUSE) ═══");

    let cfg = match ResolvedConfig::resolve(args) {
        Ok(c) => c,
        Err(msg) => {
            discovery::log(&format!("配置解析失败: {}", msg));
            eprintln!("\n  ❌ {}", msg);
            std::process::exit(1);
        }
    };

    discovery::log(&format!("目标服务器: {}", cfg.lsp_addr()));

    if !cfg.has_auth() {
        eprintln!("\n  ❌ 错误：没有认证信息（PIN / 账号密码 / Token）");
        std::process::exit(1);
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
        eprintln!("\n  ❌ 错误：未配置认证信息");
        std::process::exit(1);
    };

    let server = cfg.lsp_addr();
    let mountpoint = cfg.mount.clone();

    // 尽早阻塞 SIGINT/SIGTERM（fork 与子线程均继承此掩码），
    // 确保信号只由主线程 sigwait 接收，不会被投递到后台探测线程。
    block_signals();

    // 连接 LSP3
    println!("  🌐 连接 {} ...", server);
    let client = match LspShareClient::connect(&server, auth) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("LSP3 连接失败: {}", e);
            discovery::log(&msg);
            eprintln!("\n  ❌ {}", msg);
            std::process::exit(1);
        }
    };

    discovery::log(&format!("连接成功: {}", server));
    println!("  ✅ 认证成功");

    let client = Arc::new(client);
    let writable = client.is_writable();
    println!("  权限模式：{}", if writable { "可读写" } else { "只读" });

    // 守护进程化（非前台模式）
    if !foreground {
        daemonize();
    }

    // 确保挂载点存在
    let mount_path = std::path::PathBuf::from(&mountpoint);
    if !mount_path.exists() {
        if let Err(e) = std::fs::create_dir_all(&mount_path) {
            discovery::log(&format!("创建挂载点失败: {}", e));
            eprintln!("  ❌ 创建挂载点失败 ({}): {}", mountpoint, e);
            std::process::exit(1);
        }
    }

    // FUSE 挂载选项
    let mut options = vec![
        MountOption::FSName("lanshare".to_string()),
        MountOption::AutoUnmount,
        MountOption::NoDev,
        MountOption::NoSuid,
    ];
    if !writable {
        options.push(MountOption::RO);
    }
    // macOS 需要 volname
    #[cfg(target_os = "macos")]
    options.push(MountOption::CUSTOM(format!("volname={}", cfg.label)));

    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║  挂载中: {} ...", mountpoint);
    println!("  ╚══════════════════════════════════════════╝");

    let session = match fuse_fs::mount_fuse(client.clone(), &mount_path, options) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("FUSE 挂载失败: {}", e);
            discovery::log(&msg);
            eprintln!("\n  ❌ {}", msg);
            eprintln!();
            eprintln!("  请确认：");
            #[cfg(target_os = "linux")]
            eprintln!("    • 已安装 fuse3 (apt install fuse3 / yum install fuse)");
            #[cfg(target_os = "macos")]
            eprintln!("    • 已安装 macFUSE (https://osxfuse.github.io)");
            eprintln!("    • 当前用户有权限挂载 (user_allow_other 或 root)");
            std::process::exit(1);
        }
    };

    println!("  ✅ 挂载成功: {}", mountpoint);
    println!("  Ctrl+C 卸载退出");
    println!();
    discovery::log(&format!(
        "挂载成功: {}（{}）",
        mountpoint,
        if writable { "可读写" } else { "只读" }
    ));

    // 后台健康探测 + 网络变化检测
    {
        let probe_client = client.clone();
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
                    continue;
                }

                let healthy = probe_client.probe();
                if healthy && !was_healthy {
                    discovery::log("连接已恢复");
                } else if !healthy && was_healthy {
                    discovery::log("连接断开，尝试重连...");
                }
                was_healthy = healthy;
            }
        });
    }

    // 等待 SIGINT / SIGTERM → 优雅退出
    wait_for_signal();

    discovery::log("收到退出信号，卸载中...");
    println!("\n  🔌 卸载中...");

    // 卸载（BackgroundSession drop 时自动 unmount）
    drop(session);

    discovery::log("已卸载，退出");
    println!("  ✅ 已安全卸载");
}

/// 守护进程化：fork → setsid → 关闭标准流
fn daemonize() {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("  ❌ fork 失败");
            std::process::exit(1);
        }
        if pid > 0 {
            // 父进程退出
            std::process::exit(0);
        }
        // 子进程：新会话
        if libc::setsid() < 0 {
            std::process::exit(1);
        }
        // 忽略 SIGHUP（终端断开）
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        // 第二次 fork 防止重新获取终端
        let pid2 = libc::fork();
        if pid2 < 0 {
            std::process::exit(1);
        }
        if pid2 > 0 {
            std::process::exit(0);
        }
        // 重定向标准流到 /dev/null
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
}

/// 阻塞 SIGINT / SIGTERM（在派生任何线程之前调用，子线程继承此掩码）
fn block_signals() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

/// 阻塞等待 SIGINT 或 SIGTERM（需先调用 block_signals）
fn wait_for_signal() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        let mut sig: libc::c_int = 0;
        libc::sigwait(&set, &mut sig);
    }
}
