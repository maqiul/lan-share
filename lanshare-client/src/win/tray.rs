//! 系统托盘图标 — 后台运行时提供状态显示与操作入口
//!
//! 挂载成功后在主线程运行托盘消息循环：
//! - 左键双击：在资源管理器中打开挂载盘符
//! - 右键：弹出菜单（打开盘符 / 连接状态 / 重新连接 / 开机自启 / 卸载并退出）
//! - 悬停提示与菜单实时反映连接状态（定时器周期刷新）
//! - 气泡通知：连接成功/断开/写回完成等事件
//!
//! 退出时通过 PostQuitMessage 结束消息循环，由主线程优雅停止 WinFsp 服务。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use lanshare_client::LspShareClient;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::UI::Shell::{
    ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, NIIF_INFO, NIIF_WARNING,
};
use windows::Win32::UI::WindowsAndMessaging::*;

/// 托盘回调消息（WM_APP + 1）
const WM_TRAYICON: u32 = 0x8000 + 1;
/// 托盘图标 ID
const TRAY_ICON_ID: u32 = 1;
/// 菜单项：打开盘符
const IDM_OPEN_DRIVE: u32 = 40001;
/// 菜单项：卸载并退出
const IDM_EXIT: u32 = 40002;
/// 菜单项：重新连接
const IDM_RECONNECT: u32 = 40003;
/// 菜单项：开机自启动开关
const IDM_AUTOSTART: u32 = 40004;
/// 状态刷新定时器 ID
const TIMER_ID: usize = 1;
/// 状态刷新间隔（毫秒）
const TIMER_INTERVAL_MS: u32 = 2000;

/// 已挂载的盘符（如 "L:"），供窗口过程读取
static DRIVE: OnceLock<String> = OnceLock::new();
/// LSP 客户端句柄（用于查询连接状态与手动重连）
static CLIENT: OnceLock<Option<Arc<LspShareClient>>> = OnceLock::new();
/// 待写回计数（优雅退出时等待归零）
static PENDING_WRITES: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
/// 托盘窗口句柄（供全局气泡通知使用）
/// HWND 内部是 *mut c_void，但 Windows 允许跨线程发送消息，故手动实现 Send+Sync
#[derive(Clone, Copy)]
struct SafeHwnd(HWND);
unsafe impl Send for SafeHwnd {}
unsafe impl Sync for SafeHwnd {}
static TRAY_HWND: OnceLock<SafeHwnd> = OnceLock::new();

/// 将 &str 转为以 NUL 结尾的宽字符串
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// 当前连接状态文本（依据客户端健康标志）
fn status_text() -> &'static str {
    match CLIENT.get() {
        Some(Some(c)) if c.is_healthy() => "已连接",
        _ => "已断开",
    }
}

/// 是否有待完成的写回上传
fn is_syncing() -> bool {
    PENDING_WRITES
        .get()
        .map(|p| p.load(Ordering::Acquire) > 0)
        .unwrap_or(false)
}

/// 更新托盘悬停提示（NIM_MODIFY 仅刷新提示文本）
unsafe fn update_tooltip(hwnd: HWND) {
    let drive = DRIVE.get().map(|s| s.as_str()).unwrap_or("");
    let status = if is_syncing() {
        "正在同步..."
    } else {
        status_text()
    };
    let tip = to_wide(&format!("LanShare - {} ({})", status, drive));
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    nid.uFlags = NIF_TIP;
    let n = tip.len().min(nid.szTip.len()) - 1;
    nid.szTip[..n].copy_from_slice(&tip[..n]);
    let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
}

/// 运行托盘（阻塞，直到用户选择退出）
///
/// 必须在主线程调用（消息循环所在线程）。
pub fn run_tray(
    drive: String,
    client: Option<Arc<LspShareClient>>,
    pending_writes: Option<Arc<AtomicUsize>>,
) {
    let _ = DRIVE.set(drive);
    let _ = CLIENT.set(client);
    if let Some(pw) = pending_writes {
        let _ = PENDING_WRITES.set(pw);
    }

    unsafe {
        let hinstance = windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
            .unwrap_or_default();

        // 注册隐藏窗口类
        let class_name = w!("LanShareTrayWnd");
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinstance.into();
        wc.lpszClassName = PCWSTR(class_name.as_ptr());
        RegisterClassW(&wc);

        // 创建消息窗口（不可见）
        let hwnd = match CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name.as_ptr()),
            PCWSTR::null(),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(hinstance.into()),
            None,
        ) {
            Ok(h) => h,
            Err(_) => return,
        };

        add_tray_icon(hwnd);
        let _ = TRAY_HWND.set(SafeHwnd(hwnd));
        // 启动状态刷新定时器：周期更新托盘提示以反映连接状态
        let _ = SetTimer(Some(hwnd), TIMER_ID, TIMER_INTERVAL_MS, None);

        // 消息循环（PostQuitMessage 后 GetMessage 返回 false 退出）
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        remove_tray_icon(hwnd);
    }
}

/// 加载内嵌于模块资源的应用图标（build.rs 经 winres 以序号 1 内嵌）；
/// 加载失败时回退到系统默认图标。
unsafe fn load_app_icon() -> HICON {
    let hinstance = windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
        .unwrap_or_default();
    // MAKEINTRESOURCEW(1)：低 16 位直接作为资源序号
    match LoadImageW(
        Some(hinstance.into()),
        PCWSTR(1 as *mut u16),
        IMAGE_ICON,
        0,
        0,
        LR_DEFAULTSIZE | LR_SHARED,
    ) {
        Ok(h) => HICON(h.0),
        Err(_) => LoadIconW(None, IDI_APPLICATION).unwrap_or_default(),
    }
}

/// 添加托盘图标
unsafe fn add_tray_icon(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = load_app_icon();

    // 悬停提示：LanShare - 已连接 (L:)
    let drive = DRIVE.get().map(|s| s.as_str()).unwrap_or("");
    let tip = to_wide(&format!("LanShare - {} ({})", status_text(), drive));
    let n = tip.len().min(nid.szTip.len()) - 1;
    nid.szTip[..n].copy_from_slice(&tip[..n]);

    let _ = Shell_NotifyIconW(NIM_ADD, &nid);
}

/// 移除托盘图标
unsafe fn remove_tray_icon(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
}

/// 在资源管理器中打开挂载盘符
unsafe fn open_drive() {
    if let Some(drive) = DRIVE.get() {
        let op = to_wide("open");
        let path = to_wide(&format!("{}\\", drive));
        ShellExecuteW(
            None,
            PCWSTR(op.as_ptr()),
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// 弹出右键菜单
unsafe fn show_context_menu(hwnd: HWND) {
    let menu = match CreatePopupMenu() {
        Ok(m) => m,
        Err(_) => return,
    };

    let drive = DRIVE.get().map(|s| s.as_str()).unwrap_or("");
    let open_text = to_wide(&format!("打开盘符 ({})", drive));
    let status_item = to_wide(&format!("连接状态：{}", status_text()));
    let reconnect_text = to_wide("重新连接");
    let autostart_text = if crate::win::is_autostart_enabled() {
        to_wide("✓ 开机自启动")
    } else {
        to_wide("开机自启动")
    };
    let exit_text = if is_syncing() {
        to_wide("卸载并退出（正在同步...）")
    } else {
        to_wide("卸载并退出")
    };

    let _ = AppendMenuW(menu, MF_STRING, IDM_OPEN_DRIVE as usize, PCWSTR(open_text.as_ptr()));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    // 连接状态（灰显，仅作信息展示）
    let _ = AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, PCWSTR(status_item.as_ptr()));
    let _ = AppendMenuW(menu, MF_STRING, IDM_RECONNECT as usize, PCWSTR(reconnect_text.as_ptr()));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, IDM_AUTOSTART as usize, PCWSTR(autostart_text.as_ptr()));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, IDM_EXIT as usize, PCWSTR(exit_text.as_ptr()));

    let mut pt: POINT = std::mem::zeroed();
    let _ = GetCursorPos(&mut pt);

    // 必须先置前台，否则菜单不会随点击消失
    let _ = SetForegroundWindow(hwnd);
    let _ = TrackPopupMenu(menu, TPM_RIGHTALIGN, pt.x, pt.y, None, hwnd, None);
    let _ = DestroyMenu(menu);
}

/// 发送托盘气泡通知（可从任意线程调用）
pub fn show_balloon(title: &str, msg: &str, warning: bool) {
    let hwnd = match TRAY_HWND.get() {
        Some(h) => h.0,
        None => return,
    };
    unsafe {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ICON_ID;
        nid.uFlags = NIF_INFO;
        nid.dwInfoFlags = if warning { NIIF_WARNING } else { NIIF_INFO };

        let title_w = to_wide(title);
        let n = title_w.len().min(nid.szInfoTitle.len()) - 1;
        nid.szInfoTitle[..n].copy_from_slice(&title_w[..n]);

        let msg_w = to_wide(msg);
        let n = msg_w.len().min(nid.szInfo.len()) - 1;
        nid.szInfo[..n].copy_from_slice(&msg_w[..n]);

        let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

/// 托盘隐藏窗口的窗口过程
unsafe extern "system" fn wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TRAYICON => {
            let event = (lparam.0 & 0xFFFF) as u32;
            match event {
                WM_LBUTTONDBLCLK => {
                    open_drive();
                    return LRESULT(0);
                }
                WM_RBUTTONUP => {
                    show_context_menu(hwnd);
                    return LRESULT(0);
                }
                _ => {}
            }
        }
        WM_TIMER => {
            update_tooltip(hwnd);
            return LRESULT(0);
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as u32;
            match id {
                IDM_OPEN_DRIVE => {
                    open_drive();
                    return LRESULT(0);
                }
                IDM_RECONNECT => {
                    crate::discovery::log("用户点击「重新连接」");
                    if let Some(Some(client)) = CLIENT.get() {
                        let client = client.clone();
                        // 在独立线程重连，避免阻塞托盘消息循环（重连可能耗时数秒）
                        std::thread::spawn(move || match client.force_reconnect() {
                            Ok(_) => {
                                crate::discovery::log("手动重连成功");
                                show_balloon("LanShare", "重新连接成功", false);
                            }
                            Err(e) => {
                                crate::discovery::log(&format!("手动重连失败: {}", e));
                                show_balloon("LanShare", &format!("重连失败: {}", e), true);
                            }
                        });
                    }
                    return LRESULT(0);
                }
                IDM_AUTOSTART => {
                    let current = crate::win::is_autostart_enabled();
                    crate::win::set_autostart(!current);
                    crate::discovery::log(&format!("开机自启动: {}", if !current { "已开启" } else { "已关闭" }));
                    return LRESULT(0);
                }
                IDM_EXIT => {
                    crate::discovery::log("用户点击「卸载并退出」");
                    // 优雅退出：等待写回完成（最多 10 秒）
                    if is_syncing() {
                        crate::discovery::log("有待完成的写回，等待同步完成...");
                        show_balloon("LanShare", "正在等待同步完成...", false);
                        let pw = PENDING_WRITES.get().cloned();
                        std::thread::spawn(move || {
                            // 等待写回完成（最多 10 秒）
                            let deadline = std::time::Instant::now()
                                + std::time::Duration::from_secs(10);
                            while std::time::Instant::now() < deadline {
                                let done = pw.as_ref()
                                    .map(|p| p.load(Ordering::Acquire) == 0)
                                    .unwrap_or(true);
                                if done {
                                    break;
                                }
                                std::thread::sleep(std::time::Duration::from_millis(200));
                            }
                            crate::discovery::log("同步完成或超时，执行退出");
                            unsafe { PostQuitMessage(0); }
                        });
                    } else {
                        remove_tray_icon(hwnd);
                        // 看门狗：若消息循环或卸载流程卡住，超时后强制结束进程
                        std::thread::spawn(|| {
                            std::thread::sleep(std::time::Duration::from_secs(5));
                            crate::discovery::log("退出看门狗超时，强制结束进程");
                            std::process::exit(0);
                        });
                        PostQuitMessage(0);
                    }
                    return LRESULT(0);
                }
                _ => {}
            }
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}
