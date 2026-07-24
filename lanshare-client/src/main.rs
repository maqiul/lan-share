//! LanShare Client — 将远程 LanShare 共享挂载为本地盘符（只读）
//!
//! 用法：
//!   lanshare-client --server 192.168.1.100:8080 --pin 123456 --mount L:
//!   lanshare-client --server 192.168.1.100:8080 --token <session_token> --mount *
//!
//! 依赖：WinFsp 2.x（https://winfsp.dev）

mod fs;
mod wsp_client;

use std::sync::Arc;

use clap::Parser;
use winfsp::host::{DebugMode, FileSystemHost, FileSystemParams, VolumeParams};
use winfsp::service::FileSystemServiceBuilder;
use winfsp::winfsp_init_or_die;
use winfsp::FspError;

use fs::LanShareFs;
use wsp_client::WspClient;

#[derive(Parser, Debug)]
#[command(name = "lanshare-client", about = "LanShare 网络驱动器挂载（只读）")]
struct Args {
    /// LanShare 服务端地址（IP:端口）
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    server: String,

    /// 简易模式 PIN 码
    #[arg(short, long)]
    pin: Option<String>,

    /// 账号模式 session token
    #[arg(short, long)]
    token: Option<String>,

    /// 挂载盘符（如 "L:" 或 "*" 自动分配）
    #[arg(short, long, default_value = "*")]
    mount: String,

    /// 卷标名称
    #[arg(short, long, default_value = "LanShare")]
    label: String,
}

fn main() {
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

fn svc_start(args: Args) -> Result<LanShareFsHost, FspError> {
    // 确定认证 token
    let token = if let Some(pin) = &args.pin {
        pin.clone()
    } else if let Some(token) = &args.token {
        token.clone()
    } else {
        eprintln!("错误：需要 --pin 或 --token 参数");
        return Err(FspError::NTSTATUS(
            windows::Win32::Foundation::STATUS_INVALID_PARAMETER.0,
        ));
    };

    println!("连接 LanShare 服务端 {} ...", args.server);
    let client = WspClient::connect(&args.server, &token).map_err(|e| {
        eprintln!("连接失败: {}", e);
        FspError::NTSTATUS(windows::Win32::Foundation::STATUS_CONNECTION_REFUSED.0)
    })?;
    println!("认证成功，挂载为 {} ...", args.mount);

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

    if args.mount != "*" && !args.mount.is_empty() {
        volume_params.prefix(&args.mount);
    }
    volume_params.filesystem_name("LanShare");

    let fs_params = FileSystemParams {
        use_dir_info_by_name: false,
        volume_params,
        debug_mode: DebugMode::none(),
    };

    let mut host = FileSystemHost::<LanShareFs>::new_with_options(fs_params, context)
        .map_err(|_| FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0))?;

    if args.mount != "*" && !args.mount.is_empty() {
        host.mount(&args.mount)
            .map_err(|_| FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0))?;
    }

    host.start()
        .map_err(|_| FspError::NTSTATUS(windows::Win32::Foundation::STATUS_UNSUCCESSFUL.0))?;

    println!("已挂载！在资源管理器中查看盘符 {}", args.mount);

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
