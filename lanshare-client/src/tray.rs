//! 系统托盘图标 — 后台运行时提供状态显示与操作入口
//!
//! 挂载成功后在主线程运行托盘消息循环：
//! - 左键双击：在资源管理器中打开挂载盘符
//! - 右键：弹出菜单（打开盘符 / 卸载并退出）
//!
//! 退出时通过 PostQuitMessage 结束消息循环，由主线程优雅停止 WinFsp 服务。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::UI::Shell::{
    ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
    NOTIFYICONDATAW,
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

/// 已挂载的盘符（如 "L:"），供窗口过程读取
static DRIVE: OnceLock<String> = OnceLock::new();

/// 将 &str 转为以 NUL 结尾的宽字符串
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// 运行托盘（阻塞，直到用户选择退出）
///
/// 必须在主线程调用（消息循环所在线程）。
pub fn run_tray(drive: String) {
    let _ = DRIVE.set(drive);

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

        // 消息循环（PostQuitMessage 后 GetMessage 返回 false 退出）
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        remove_tray_icon(hwnd);
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
    nid.hIcon = LoadIconW(None, IDI_APPLICATION).unwrap_or_default();

    // 悬停提示：LanShare - 已挂载 (L:)
    let drive = DRIVE.get().map(|s| s.as_str()).unwrap_or("");
    let tip = to_wide(&format!("LanShare - 已挂载 ({})", drive));
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
    let exit_text = to_wide("卸载并退出");

    let _ = AppendMenuW(menu, MF_STRING, IDM_OPEN_DRIVE as usize, PCWSTR(open_text.as_ptr()));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, IDM_EXIT as usize, PCWSTR(exit_text.as_ptr()));

    let mut pt: POINT = std::mem::zeroed();
    let _ = GetCursorPos(&mut pt);

    // 必须先置前台，否则菜单不会随点击消失
    let _ = SetForegroundWindow(hwnd);
    let _ = TrackPopupMenu(menu, TPM_RIGHTALIGN, pt.x, pt.y, None, hwnd, None);
    let _ = DestroyMenu(menu);
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
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as u32;
            match id {
                IDM_OPEN_DRIVE => {
                    open_drive();
                    return LRESULT(0);
                }
                IDM_EXIT => {
                    crate::log("用户点击「卸载并退出」");
                    remove_tray_icon(hwnd);
                    PostQuitMessage(0);
                    return LRESULT(0);
                }
                _ => {}
            }
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}
