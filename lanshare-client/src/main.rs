//! LanShare Client — 跨平台客户端入口
//!
//! Windows: WinFsp 挂载为盘符 + 系统托盘
//! Linux/macOS: FUSE 挂载为目录 + 前台/守护进程
//!
//! 双击启动：自动扫描局域网 → 选择服务器 → 输入密码 → 挂载
//! 命令行：  lanshare-client --server IP:PORT --pin 123456 --mount L:
//! 配置文件：同目录 lanshare-client.toml（交互后自动保存，下次免输）

mod discovery;

#[cfg(windows)]
mod win;

#[cfg(unix)]
mod unix;

fn main() {
    #[cfg(windows)]
    win::run();

    #[cfg(unix)]
    unix::run();
}
