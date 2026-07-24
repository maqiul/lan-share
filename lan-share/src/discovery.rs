//! 局域网自动发现模块
//! UDP 广播协议：客户端发送 "LANSHARE_DISCOVER"，服务端回复 JSON 信息

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// 默认发现端口
pub const DISCOVERY_PORT: u16 = 9999;

/// 发现请求魔数
const DISCOVER_MAGIC: &[u8] = b"LANSHARE_DISCOVER";

/// 服务端信息（回复给发现请求）
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ServerInfo {
    /// 设备名称
    pub name: String,
    /// 本机 IP
    pub ip: String,
    /// Web UI 端口
    pub web_port: u16,
    /// LSP 协议端口
    pub lsp_port: u16,
    /// 协议版本
    pub version: String,
    /// 是否简易模式（true=PIN，false=账号密码）
    #[serde(default)]
    pub simple_mode: bool,
}

/// 启动发现服务（UDP 监听）
pub async fn start_discovery_server(
    info: Arc<ServerInfo>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 绑定 0.0.0.0 以接收广播
    let bind_addr = format!("0.0.0.0:{}", DISCOVERY_PORT);
    let socket = UdpSocket::bind(&bind_addr).await?;

    // 允许广播
    socket.set_broadcast(true)?;

    info!("Discovery server listening on UDP {}", bind_addr);

    let mut buf = [0u8; 64];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Discovery recv error: {}", e);
                continue;
            }
        };

        // 验证魔数
        if len < DISCOVER_MAGIC.len() || &buf[..DISCOVER_MAGIC.len()] != DISCOVER_MAGIC {
            debug!("Ignoring non-discovery packet from {}", src);
            continue;
        }

        // 回复 JSON
        let response = serde_json::to_vec(&*info).unwrap_or_default();
        if let Err(e) = socket.send_to(&response, src).await {
            warn!("Discovery reply to {} failed: {}", src, e);
        } else {
            debug!("Replied to discovery request from {}", src);
        }
    }
}

/// 客户端：广播发现请求，收集响应
pub async fn discover_servers(timeout_ms: u64) -> Vec<DiscoveredServer> {
    let mut results = Vec::new();

    // 创建 UDP socket
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!("Discovery bind failed: {}", e);
            return results;
        }
    };

    if let Err(e) = socket.set_broadcast(true) {
        warn!("Discovery set_broadcast failed: {}", e);
        return results;
    }

    // 广播到 255.255.255.255
    let broadcast_addr: SocketAddr = "255.255.255.255:9999".parse().unwrap();
    if let Err(e) = socket.send_to(DISCOVER_MAGIC, broadcast_addr).await {
        warn!("Discovery broadcast failed: {}", e);
        return results;
    }

    info!("Sent discovery broadcast, waiting {}ms for responses...", timeout_ms);

    // 收集响应（带超时）
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 512];

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                if let Ok(info) = serde_json::from_slice::<ServerInfo>(&buf[..len]) {
                    // 用响应来源 IP 覆盖（更准确）
                    let ip = src.ip().to_string();
                    results.push(DiscoveredServer {
                        name: info.name,
                        ip: ip.clone(),
                        web_port: info.web_port,
                        lsp_port: info.lsp_port,
                        version: info.version,
                        url: format!("http://{}:{}", ip, info.web_port),
                    });
                }
            }
            Ok(Err(e)) => {
                debug!("Discovery recv error: {}", e);
                break;
            }
            Err(_) => break, // 超时
        }
    }

    info!("Discovered {} server(s)", results.len());
    results
}

/// 发现的服务器信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredServer {
    pub name: String,
    pub ip: String,
    pub web_port: u16,
    pub lsp_port: u16,
    pub version: String,
    pub url: String,
}
