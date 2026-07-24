//! LanShare Client — 将远程 LanShare 共享挂载为本地盘符（只读）
//!
//! 用法：
//!   简易模式：lanshare-client --server 192.168.1.100:8080 --pin 123456 --mount L:
//!   账号模式：lanshare-client --server 192.168.1.100:8080 -u admin -p 123456 --mount L:
//!   Token：  lanshare-client --server 192.168.1.100:8080 --token <session_token> --mount *
//!
//! 依赖：WinFsp 2.x（https://winfsp.dev）

mod fs;
mod wsp_client;

use std::io::{Read, Write};
use std::net::TcpStream;
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
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    stream.write_all(request.as_bytes())
        .map_err(|e| format!("发送登录请求失败: {}", e))?;

    let mut response = String::new();
    stream.read_to_string(&mut response)
        .map_err(|e| format!("读取登录响应失败: {}", e))?;

    // 解析 HTTP 响应：跳过 headers，取 body
    let body_part = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("");

    // 检查 HTTP 状态码
    let status_ok = response
        .lines()
        .next()
        .map(|l| l.contains("200"))
        .unwrap_or(false);

    if !status_ok {
        // 尝试从 body 提取错误信息
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_part) {
            if let Some(err) = json.get("error").and_then(|e| e.as_str()) {
                return Err(format!("登录失败: {}", err));
            }
        }
        return Err(format!("登录失败: HTTP 响应异常"));
    }

    // 解析 token
    let json: serde_json::Value = serde_json::from_str(body_part)
        .map_err(|e| format!("解析登录响应失败: {}", e))?;
    json.get("token")
        .and_then(|t| t.as_str())
        .map(|t| t.to_string())
        .ok_or_else(|| "登录响应中无 token".to_string())
}

fn svc_start(args: Args) -> Result<LanShareFsHost, FspError> {
    // 确定认证 token：PIN > 用户名密码登录 > 直接 token
    let token = if let Some(pin) = &args.pin {
        println!("使用 PIN 码认证（简易模式）");
        pin.clone()
    } else if let (Some(username), Some(password)) = (&args.username, &args.password) {
        println!("使用账号 {} 登录（账号模式）...", username);
        http_login(&args.server, username, password).map_err(|e| {
            eprintln!("{}", e);
            FspError::NTSTATUS(0xC000_006Du32 as i32) // STATUS_LOGON_FAILURE
        })?
    } else if let Some(token) = &args.token {
        println!("使用 session token 认证");
        token.clone()
    } else {
        eprintln!("错误：需要 --pin、--username + --password、或 --token 参数");
        eprintln!("  简易模式：--pin <PIN码>");
        eprintln!("  账号模式：-u <用户名> -p <密码>");
        eprintln!("  Token：  --token <session_token>");
        return Err(FspError::NTSTATUS(
            windows::Win32::Foundation::STATUS_INVALID_PARAMETER.0,
        ));
    };

    println!("连接 LanShare 服务端 {} ...", args.server);
    let client = WspClient::connect(&args.server, &token).map_err(|e| {
        eprintln!("WSP 连接失败: {}", e);
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
    volume_params.filesystem_name(&args.label);

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
