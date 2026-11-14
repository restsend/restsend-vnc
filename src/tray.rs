//! Windows tray icon + native Win32 settings window.
//!
//! Menu: Settings…, Disconnect all sessions, open the configured URL, About,
//! Exit. Settings are persisted to `%APPDATA%\rvnc\settings.ini` and applied
//! live (port/loopback changes rebind the listener).

#![cfg(target_os = "windows")]

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering};
use std::time::Instant;

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontW, GetSysColorBrush, InvalidateRect, RedrawWindow, SetBkMode, CLEARTYPE_QUALITY,
    CLIP_DEFAULT_PRECIS, COLOR_WINDOW, DEFAULT_CHARSET, DEFAULT_PITCH, FF_DONTCARE, FW_NORMAL,
    HBRUSH, HDC, HFONT, OUT_DEFAULT_PRECIS, RDW_ALLCHILDREN, RDW_ERASE, RDW_INVALIDATE,
    RDW_UPDATENOW, TRANSPARENT,
};
use windows::Win32::System::Com::{CoInitializeEx, CoTaskMemFree, COINIT_APARTMENTTHREADED};
use windows::Win32::System::Diagnostics::Debug::MessageBeep;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    CheckDlgButton, InitCommonControlsEx, IsDlgButtonChecked, DLG_BUTTON_CHECK_STATE,
    EM_SETPASSWORDCHAR, ICC_STANDARD_CLASSES, ICC_TAB_CLASSES, ICC_WIN95_CLASSES,
    INITCOMMONCONTROLSEX, NMHDR, TCIF_TEXT, TCITEMW, TCM_GETCURSEL, TCM_INSERTITEMW, TCM_SETCURSEL,
    TCN_SELCHANGE, WC_TABCONTROLW,
};
use windows::Win32::UI::HiDpi::GetDpiForSystem;
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::Shell::{
    SHBrowseForFolderW, SHGetPathFromIDListW, ShellExecuteW, Shell_NotifyIconW, BIF_NEWDIALOGSTYLE,
    BIF_RETURNONLYFSDIRS, BROWSEINFOW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
    NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::*;

const WM_TRAY: u32 = WM_APP + 1;
const TIMER_APPROVAL: usize = 1;
const ID_SETTINGS: usize = 1;
const ID_KILL: usize = 2;
const ID_OPEN: usize = 3;
const ID_ABOUT: usize = 4;
const ID_EXIT: usize = 5;

const C_PORT: i32 = 1001;
const C_COLOR: i32 = 1002;
const C_LOOPBACK: i32 = 1003;
const C_KEEP: i32 = 1004;
const C_DEBUG: i32 = 1005;
const C_PASS: i32 = 1007;
const C_TITLE: i32 = 1008;
const C_AUTOSTART: i32 = 1009;
const C_ELEVATE: i32 = 1010;
const C_SHARE: i32 = 1011;
const C_SHARE_DIR: i32 = 1012;
// Keep control IDs unique: combo-box notifications also arrive as WM_COMMAND.
const C_BROWSE: i32 = 1013;
const C_TLS: i32 = 1014;
const C_CONFIRM: i32 = 1015;
const C_ALLOW: i32 = 1016;
const C_VIEWONLY: i32 = 1017;
const C_PASS_SHOW: i32 = 1018;
const C_TABS: i32 = 1020;

const C_CC_COUNT: i32 = 1031;
const C_CC_ACCEPT: i32 = 1032;
const C_CC_REJECT: i32 = 1033;

static UI_FONT: AtomicIsize = AtomicIsize::new(0);
/// Non-zero while the settings window is open (prevents nested duplicates).
static SETTINGS_HWND: AtomicIsize = AtomicIsize::new(0);
/// Non-zero while the confirmation window is on screen.
static CONFIRM_ID: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Control handles per settings tab, stored as `isize` because `HWND`
    /// itself is not `Send`/`Sync`.
    static SETTINGS_PAGES: RefCell<Vec<Vec<isize>>> = const { RefCell::new(Vec::new()) };
}

pub fn spawn() {
    // Common Controls v6 (themed buttons/edits) — paired with the embedded
    // manifest that requests Microsoft.Windows.Common-Controls 6.
    unsafe {
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES | ICC_TAB_CLASSES,
        };
        let _ = InitCommonControlsEx(&icc);
    }
    std::thread::Builder::new()
        .name("restsend-vnc-tray".into())
        .spawn(|| unsafe { run() })
        .ok();
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn run() {
    // Shell dialogs (the shared-folder picker) need an apartment-threaded COM
    // initialisation on the thread that owns the windows.
    let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    let hinst = GetModuleHandleW(None).unwrap();
    let class = w!("restsend_vnc_tray_wnd");
    let wc = WNDCLASSW {
        lpfnWndProc: Some(tray_proc),
        hInstance: hinst.into(),
        lpszClassName: class,
        ..Default::default()
    };
    RegisterClassW(&wc);
    let hwnd = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        class,
        w!("restsend-vnc"),
        WINDOW_STYLE(0),
        0,
        0,
        0,
        0,
        None,
        None,
        Some(hinst.into()),
        None,
    )
    .unwrap();

    let mut nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: WM_TRAY,
        hIcon: LoadIconW(Some(hinst.into()), PCWSTR(std::ptr::without_provenance(1)))
            .or_else(|_| LoadIconW(None, IDI_APPLICATION))
            .unwrap_or_default(),
        ..Default::default()
    };
    let tip = wide("restsend-vnc - VNC server");
    let n = tip.len().min(128); // szTip is [u16; 128]; NOTIFYICONDATAW is packed
    unsafe {
        let dst = std::ptr::addr_of_mut!(nid.szTip) as *mut u16;
        std::ptr::copy_nonoverlapping(tip.as_ptr(), dst, n);
    }
    let _ = Shell_NotifyIconW(NIM_ADD, &nid);
    // Poll the approval queue; a timer keeps the tray window responsive while
    // the modal settings window runs its own message loop.
    let _ = SetTimer(Some(hwnd), TIMER_APPROVAL, 200, None);

    let mut msg = MSG::default();
    loop {
        if crate::settings::EXIT.load(Ordering::Relaxed) {
            break;
        }
        if !GetMessageW(&mut msg, None, 0, 0).as_bool() {
            break;
        }
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    let _ = KillTimer(Some(hwnd), TIMER_APPROVAL);
    crate::approval::reject_all();
    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
    if crate::settings::EXIT.load(Ordering::Relaxed) {
        std::process::exit(0);
    }
}

unsafe extern "system" fn tray_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TRAY => {
            let ev = lparam.0 as u32;
            if ev == WM_RBUTTONUP || ev == WM_CONTEXTMENU {
                let menu = CreatePopupMenu().unwrap();
                let _ = AppendMenuW(menu, MF_STRING, ID_SETTINGS, w!("Settings..."));
                let _ = AppendMenuW(menu, MF_STRING, ID_KILL, w!("Disconnect all sessions"));
                let url = wide(&crate::settings::url());
                let _ = AppendMenuW(menu, MF_STRING, ID_OPEN, PCWSTR(url.as_ptr()));
                let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
                let _ = AppendMenuW(menu, MF_STRING, ID_ABOUT, w!("About restsend-vnc"));
                let _ = AppendMenuW(menu, MF_STRING, ID_EXIT, w!("Exit"));
                let mut pt = POINT::default();
                let _ = GetCursorPos(&mut pt);
                let _ = SetForegroundWindow(hwnd);
                let _ = TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, Some(0), hwnd, None);
                let _ = DestroyMenu(menu);
            }
        }
        WM_COMMAND => {
            let id = wparam.0 & 0xffff;
            match id {
                ID_SETTINGS => {
                    let existing = SETTINGS_HWND.load(Ordering::Relaxed);
                    if existing != 0 {
                        let _ = SetForegroundWindow(HWND(existing as *mut core::ffi::c_void));
                    } else {
                        open_settings();
                    }
                }
                ID_KILL => {
                    let n = crate::server::kill_all_sessions();
                    tracing::info!("tray: disconnected {n} session(s)");
                }
                ID_OPEN => {
                    let url = wide(&crate::settings::url());
                    ShellExecuteW(
                        None,
                        w!("open"),
                        PCWSTR(url.as_ptr()),
                        PCWSTR::null(),
                        PCWSTR::null(),
                        SW_SHOWNORMAL,
                    );
                }
                ID_ABOUT => {
                    let body = format!(
                        "restsend-vnc {}\nbuild {}\n\nRFB 3.8 / Apple 3.889 VNC server\n{}",
                        env!("CARGO_PKG_VERSION"),
                        env!("BUILD_TIME"),
                        crate::settings::url()
                    );
                    let text = wide(&body);
                    MessageBoxW(
                        Some(hwnd),
                        PCWSTR(text.as_ptr()),
                        w!("About restsend-vnc"),
                        MB_OK | MB_ICONINFORMATION,
                    );
                }
                ID_EXIT => {
                    crate::approval::reject_all();
                    crate::settings::EXIT.store(true, Ordering::Relaxed);
                    PostQuitMessage(0);
                }
                _ => {}
            }
        }
        WM_TIMER => {
            if wparam.0 == TIMER_APPROVAL {
                poll_approval();
            }
        }
        WM_DESTROY => {
            crate::approval::reject_all();
            PostQuitMessage(0);
        }
        _ => return DefWindowProcW(hwnd, msg, wparam, lparam),
    }
    LRESULT(0)
}

#[allow(clippy::too_many_arguments)]
unsafe fn ctrl(
    parent: HWND,
    class: PCWSTR,
    text: PCWSTR,
    style: WINDOW_STYLE,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    hinst: isize,
) -> HWND {
    let hwnd = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        class,
        text,
        style,
        x,
        y,
        w,
        h,
        Some(parent),
        Some(HMENU(id as isize as *mut core::ffi::c_void)),
        Some(windows::Win32::Foundation::HINSTANCE(
            hinst as *mut core::ffi::c_void,
        )),
        None,
    )
    .unwrap_or_default();
    let f = UI_FONT.load(AtomicOrdering::Relaxed);
    if f != 0 {
        SendMessageW(hwnd, WM_SETFONT, Some(WPARAM(f as usize)), Some(LPARAM(1)));
    }
    hwnd
}

unsafe fn ensure_ui_font(scale: f32) -> HFONT {
    let existing = UI_FONT.load(AtomicOrdering::Relaxed);
    if existing != 0 {
        return HFONT(existing as *mut core::ffi::c_void);
    }
    let px = ((15.0 * scale).round() as i32).max(9);
    let font = CreateFontW(
        -px,
        0,
        0,
        0,
        FW_NORMAL.0 as i32,
        0,
        0,
        0,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        (DEFAULT_PITCH.0 | FF_DONTCARE.0) as u32,
        w!("Segoe UI"),
    );
    UI_FONT.store(font.0 as isize, AtomicOrdering::Relaxed);
    font
}

unsafe fn show_settings_page(hwnd: HWND, index: usize) {
    SETTINGS_PAGES.with(|pages| {
        let pages = pages.borrow();
        for (i, group) in pages.iter().enumerate() {
            let cmd = if i == index { SW_SHOW } else { SW_HIDE };
            for &h in group {
                let _ = ShowWindow(HWND(h as *mut core::ffi::c_void), cmd);
            }
        }
    });
    // The page controls are siblings of the tab control. Repaint the whole
    // window and every child immediately so STATIC labels are not left blank
    // until the next tab switch (the tab body can otherwise paint after them).
    let _ = RedrawWindow(
        Some(hwnd),
        None,
        None,
        RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE | RDW_UPDATENOW,
    );
}

/// Called by the tray timer: show the next pending connection request.
unsafe fn poll_approval() {
    if CONFIRM_ID.load(Ordering::Relaxed) != 0 {
        return;
    }
    let Some(pending) = crate::approval::front_pending() else {
        return;
    };
    if !crate::approval::is_pending(pending.id) {
        return;
    }
    show_confirm(&pending);
}

unsafe fn show_confirm(pending: &crate::approval::PendingView) {
    let hinst = GetModuleHandleW(None).unwrap();
    let class = w!("restsend_vnc_confirm_wnd");
    let wc = WNDCLASSW {
        lpfnWndProc: Some(confirm_proc),
        hInstance: hinst.into(),
        lpszClassName: class,
        hbrBackground: HBRUSH((COLOR_WINDOW.0 as isize + 1) as *mut core::ffi::c_void),
        ..Default::default()
    };
    RegisterClassW(&wc);

    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
    let dpi = GetDpiForSystem() as f32;
    let scale = (dpi / 96.0).max(1.0);
    let f = |v: i32| ((v as f32) * scale).round() as i32;
    ensure_ui_font(scale);

    let mut wr = RECT {
        left: 0,
        top: 0,
        right: f(460),
        bottom: f(240),
    };
    let _ = AdjustWindowRectEx(&mut wr, style, false, WS_EX_TOPMOST);
    let screen_w = GetSystemMetrics(SM_CXSCREEN);
    let screen_h = GetSystemMetrics(SM_CYSCREEN);
    let width = wr.right - wr.left;
    let height = wr.bottom - wr.top;
    let x = ((screen_w - width) / 2).max(0);
    let y = ((screen_h - height) / 2).max(0);

    let hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        class,
        w!("restsend-vnc - connection request"),
        style,
        x,
        y,
        width,
        height,
        None,
        None,
        Some(hinst.into()),
        None,
    )
    .unwrap_or_default();
    if hwnd.0.is_null() {
        tracing::warn!("could not create the connection confirmation window");
        return;
    }

    CONFIRM_ID.store(pending.id, Ordering::Relaxed);
    let hi = hinst.0 as isize;
    let label: WINDOW_STYLE = WS_CHILD | WS_VISIBLE;
    let body = format!(
        "Accept this connection?\n\n{}\n{}\n\nNo screen data is sent until you accept.",
        pending.peer, pending.info
    );
    let body_w = wide(&body);
    ctrl(
        hwnd,
        w!("STATIC"),
        PCWSTR(body_w.as_ptr()),
        label,
        f(18),
        f(16),
        f(424),
        f(130),
        0,
        hi,
    );
    ctrl(
        hwnd,
        w!("STATIC"),
        w!(""),
        label,
        f(18),
        f(150),
        f(424),
        f(20),
        C_CC_COUNT,
        hi,
    );
    ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Accept"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        f(230),
        f(178),
        f(100),
        f(30),
        C_CC_ACCEPT,
        hi,
    );
    ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Reject"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
        f(340),
        f(178),
        f(100),
        f(30),
        C_CC_REJECT,
        hi,
    );
    let reject = GetDlgItem(Some(hwnd), C_CC_REJECT).unwrap_or_default();
    let _ = SetForegroundWindow(hwnd);
    let _ = SetFocus(Some(reject));
    let _ = SetTimer(Some(hwnd), 1, 200, None);

    let flash = FLASHWINFO {
        cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
        hwnd,
        dwFlags: FLASHWINFO_FLAGS(FLASHW_ALL.0 | FLASHW_TIMERNOFG.0),
        uCount: 3,
        dwTimeout: 0,
    };
    let _ = FlashWindowEx(&flash);
    let _ = MessageBeep(MB_ICONQUESTION);
    update_confirm_countdown(hwnd, pending.deadline);
}

unsafe fn update_confirm_countdown(hwnd: HWND, deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let text = if remaining.is_zero() {
        "Rejecting now...".to_string()
    } else {
        format!("Auto-reject in {} second(s)", remaining.as_secs().max(1))
    };
    let text = wide(&text);
    let _ = SetDlgItemTextW(hwnd, C_CC_COUNT, PCWSTR(text.as_ptr()));
}

unsafe fn finish_confirm(hwnd: HWND, accept: bool) {
    let id = CONFIRM_ID.load(Ordering::Relaxed);
    if id != 0 {
        crate::approval::resolve(id, accept);
    }
    let _ = DestroyWindow(hwnd);
}

unsafe extern "system" fn confirm_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        // Keep label backgrounds equal to the window background.
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => return control_color(wparam),
        WM_COMMAND => {
            if clicked(wparam, C_CC_ACCEPT) {
                finish_confirm(hwnd, true);
            } else if clicked(wparam, C_CC_REJECT) {
                finish_confirm(hwnd, false);
            }
        }
        WM_TIMER => {
            let id = CONFIRM_ID.load(Ordering::Relaxed);
            if id == 0 || !crate::approval::is_pending(id) {
                let _ = DestroyWindow(hwnd);
            } else if let Some(pending) = crate::approval::front_pending() {
                if pending.id == id {
                    update_confirm_countdown(hwnd, pending.deadline);
                    if Instant::now() >= pending.deadline {
                        finish_confirm(hwnd, false);
                    }
                } else {
                    finish_confirm(hwnd, false);
                }
            }
        }
        WM_CLOSE => finish_confirm(hwnd, false),
        WM_DESTROY => {
            let _ = KillTimer(Some(hwnd), 1);
            CONFIRM_ID.store(0, Ordering::Relaxed);
        }
        _ => return DefWindowProcW(hwnd, msg, wparam, lparam),
    }
    LRESULT(0)
}

unsafe fn open_settings() {
    let hinst = GetModuleHandleW(None).unwrap();
    let class = w!("restsend_vnc_settings_wnd");
    let wc = WNDCLASSW {
        lpfnWndProc: Some(settings_proc),
        hInstance: hinst.into(),
        lpszClassName: class,
        hbrBackground: HBRUSH((COLOR_WINDOW.0 as isize + 1) as *mut core::ffi::c_void),
        ..Default::default()
    };
    RegisterClassW(&wc);

    // Per-Monitor V2: scale coordinates/fonts by the system DPI, and derive
    // the OUTER window size from the desired CLIENT area so bottom controls
    // are never clipped by the caption/borders.
    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
    let dpi = GetDpiForSystem() as f32;
    let scale = (dpi / 96.0).max(1.0);
    let f = |v: i32| ((v as f32) * scale).round() as i32;

    let mut wr = RECT {
        left: 0,
        top: 0,
        right: f(480),
        bottom: f(452),
    };
    let _ = AdjustWindowRectEx(&mut wr, style, false, WINDOW_EX_STYLE(0));

    let hwnd = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        class,
        w!("restsend-vnc settings"),
        style | WS_CLIPCHILDREN,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        wr.right - wr.left,
        wr.bottom - wr.top,
        None,
        None,
        Some(hinst.into()),
        None,
    )
    .unwrap();
    SETTINGS_HWND.store(hwnd.0 as isize, Ordering::Relaxed);

    let s = crate::settings::load();
    let hi = hinst.0 as isize;
    let label: WINDOW_STYLE = WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS;
    let edit: WINDOW_STYLE = WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_BORDER | WS_TABSTOP;
    let check: WINDOW_STYLE =
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP | WINDOW_STYLE(BS_AUTOCHECKBOX as u32);

    let font = ensure_ui_font(scale);
    SendMessageW(
        hwnd,
        WM_SETFONT,
        Some(WPARAM(font.0 as usize)),
        Some(LPARAM(1)),
    );

    // --- tab strip ---------------------------------------------------------
    let tab = ctrl(
        hwnd,
        WC_TABCONTROLW,
        w!(""),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS,
        f(12),
        f(12),
        f(456),
        f(380),
        C_TABS,
        hi,
    );
    for (i, name) in ["General", "Security", "Files"].iter().enumerate() {
        let mut text = wide(name);
        let item = TCITEMW {
            mask: TCIF_TEXT,
            pszText: PWSTR(text.as_mut_ptr()),
            cchTextMax: text.len() as i32,
            ..Default::default()
        };
        let _ = SendMessageW(
            tab,
            TCM_INSERTITEMW,
            Some(WPARAM(i)),
            Some(LPARAM(&item as *const _ as isize)),
        );
    }
    let _ = SendMessageW(tab, TCM_SETCURSEL, Some(WPARAM(0)), Some(LPARAM(0)));
    SendMessageW(
        tab,
        WM_SETFONT,
        Some(WPARAM(font.0 as usize)),
        Some(LPARAM(1)),
    );

    // --- General page ------------------------------------------------------
    let mut general: Vec<HWND> = Vec::new();
    general.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Port:"),
        label,
        f(24),
        f(58),
        f(70),
        f(20),
        0,
        hi,
    ));
    let port = ctrl(
        hwnd,
        w!("EDIT"),
        w!(""),
        edit,
        f(100),
        f(56),
        f(90),
        f(24),
        C_PORT,
        hi,
    );
    let ptxt = wide(&s.port.to_string());
    let _ = SetWindowTextW(port, PCWSTR(ptxt.as_ptr()));
    general.push(port);

    general.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Colour:"),
        label,
        f(212),
        f(58),
        f(60),
        f(20),
        0,
        hi,
    ));
    let combo = ctrl(
        hwnd,
        w!("COMBOBOX"),
        w!(""),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(CBS_DROPDOWNLIST as u32),
        f(276),
        f(56),
        f(150),
        f(160),
        C_COLOR,
        hi,
    );
    for t in [
        "High quality (24-bit)",
        "Balanced (16-bit)",
        "Fastest (8-bit)",
    ]
    .iter()
    {
        let wv = wide(t);
        SendMessageW(
            combo,
            CB_ADDSTRING,
            Some(WPARAM(0)),
            Some(LPARAM(wv.as_ptr() as isize)),
        );
    }
    let sel = match s.color_level {
        8 => 2,
        16 => 1,
        _ => 0,
    };
    let _ = SendMessageW(combo, CB_SETCURSEL, Some(WPARAM(sel)), Some(LPARAM(0)));
    general.push(combo);

    general.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Title:"),
        label,
        f(24),
        f(98),
        f(70),
        f(20),
        0,
        hi,
    ));
    let title = ctrl(
        hwnd,
        w!("EDIT"),
        w!(""),
        edit,
        f(100),
        f(96),
        f(320),
        f(24),
        C_TITLE,
        hi,
    );
    let ttxt = wide(&s.title);
    let _ = SetWindowTextW(title, PCWSTR(ttxt.as_ptr()));
    general.push(title);

    general.push(ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Keep the machine awake"),
        check,
        f(24),
        f(134),
        f(400),
        f(24),
        C_KEEP,
        hi,
    ));
    let _ = CheckDlgButton(
        hwnd,
        C_KEEP,
        DLG_BUTTON_CHECK_STATE(if s.keep_awake { 1 } else { 0 }),
    );

    general.push(ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Allow debug panel (Ctrl + 3 clicks)"),
        check,
        f(24),
        f(166),
        f(400),
        f(24),
        C_DEBUG,
        hi,
    ));
    let _ = CheckDlgButton(
        hwnd,
        C_DEBUG,
        DLG_BUTTON_CHECK_STATE(if s.allow_debug { 1 } else { 0 }),
    );

    general.push(ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Start with Windows (current user)"),
        check,
        f(24),
        f(198),
        f(400),
        f(24),
        C_AUTOSTART,
        hi,
    ));
    let _ = CheckDlgButton(
        hwnd,
        C_AUTOSTART,
        DLG_BUTTON_CHECK_STATE(if s.autostart { 1 } else { 0 }),
    );

    general.push(ctrl(
        hwnd,
        w!("BUTTON"),
        w!("View only (clients cannot control this PC)"),
        check,
        f(24),
        f(230),
        f(400),
        f(24),
        C_VIEWONLY,
        hi,
    ));
    let _ = CheckDlgButton(
        hwnd,
        C_VIEWONLY,
        DLG_BUTTON_CHECK_STATE(if s.view_only { 1 } else { 0 }),
    );
    general.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Keyboard, mouse, clipboard and file uploads are disabled.\nApplies to new connections."),
        WS_CHILD | WS_VISIBLE,
        f(24),
        f(258),
        f(400),
        f(44),
        0,
        hi,
    ));

    // --- Security page -----------------------------------------------------
    let mut security: Vec<HWND> = Vec::new();
    security.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Password:"),
        label,
        f(24),
        f(58),
        f(70),
        f(20),
        0,
        hi,
    ));
    let pass = ctrl(
        hwnd,
        w!("EDIT"),
        w!(""),
        edit, // stored in plain text by design
        f(100),
        f(56),
        f(250),
        f(24),
        C_PASS,
        hi,
    );
    let ptxt = wide(s.password.as_deref().unwrap_or(""));
    let _ = SetWindowTextW(pass, PCWSTR(ptxt.as_ptr()));
    // Mask by default; the Show checkbox clears the password character.
    let _ = SendMessageW(
        pass,
        EM_SETPASSWORDCHAR,
        Some(WPARAM('*' as usize)),
        Some(LPARAM(0)),
    );
    security.push(pass);
    security.push(ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Show"),
        check,
        f(360),
        f(56),
        f(100),
        f(24),
        C_PASS_SHOW,
        hi,
    ));

    security.push(ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Only accept loopback connections"),
        check,
        f(24),
        f(94),
        f(400),
        f(24),
        C_LOOPBACK,
        hi,
    ));
    let _ = CheckDlgButton(
        hwnd,
        C_LOOPBACK,
        DLG_BUTTON_CHECK_STATE(if s.loopback_only { 1 } else { 0 }),
    );

    security.push(ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Ask before accepting incoming connections"),
        check,
        f(24),
        f(124),
        f(400),
        f(24),
        C_CONFIRM,
        hi,
    ));
    let _ = CheckDlgButton(
        hwnd,
        C_CONFIRM,
        DLG_BUTTON_CHECK_STATE(if s.confirm_connections { 1 } else { 0 }),
    );

    security.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Each new connection must be accepted locally.\nNo screen data is sent before you accept.\nRequests are rejected after 30 seconds."),
        WS_CHILD | WS_VISIBLE,
        f(24),
        f(150),
        f(400),
        f(66),
        0,
        hi,
    ));

    security.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Encryption:"),
        label,
        f(24),
        f(220),
        f(80),
        f(20),
        0,
        hi,
    ));
    let tls = ctrl(
        hwnd,
        w!("COMBOBOX"),
        w!(""),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(CBS_DROPDOWNLIST as u32),
        f(110),
        f(218),
        f(300),
        f(160),
        C_TLS,
        hi,
    );
    for t in ["Prefer TLS (recommended)", "Require TLS", "Off (plaintext)"] {
        let wv = wide(t);
        SendMessageW(
            tls,
            CB_ADDSTRING,
            Some(WPARAM(0)),
            Some(LPARAM(wv.as_ptr() as isize)),
        );
    }
    let tls_sel = match s.tls {
        crate::tls::Mode::Auto => 0,
        crate::tls::Mode::Required => 1,
        crate::tls::Mode::Off => 2,
    };
    let _ = SendMessageW(tls, CB_SETCURSEL, Some(WPARAM(tls_sel)), Some(LPARAM(0)));
    security.push(tls);

    security.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Allowed networks (CIDR, empty = all):"),
        label,
        f(24),
        f(250),
        f(400),
        f(20),
        0,
        hi,
    ));
    let allow = ctrl(
        hwnd,
        w!("EDIT"),
        w!(""),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
        f(24),
        f(274),
        f(400),
        f(24),
        C_ALLOW,
        hi,
    );
    let atxt = wide(&s.allow_cidrs);
    let _ = SetWindowTextW(allow, PCWSTR(atxt.as_ptr()));
    security.push(allow);
    security.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Loopback is not implicit: add 127.0.0.1/32.\nExample: 192.168.1.0/24, 10.0.0.0/8"),
        WS_CHILD | WS_VISIBLE,
        f(24),
        f(302),
        f(400),
        f(44),
        0,
        hi,
    ));

    let elevate = ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Install elevated autostart (admin)"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        f(24),
        f(354),
        f(300),
        f(30),
        C_ELEVATE,
        hi,
    );
    // UAC shield on the button (Common Controls v6).
    SendMessageW(elevate, 0x160C, Some(WPARAM(0)), Some(LPARAM(1)));
    security.push(elevate);

    // --- Files page --------------------------------------------------------
    let mut files: Vec<HWND> = Vec::new();
    files.push(ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Share files with connected clients"),
        check,
        f(24),
        f(58),
        f(400),
        f(24),
        C_SHARE,
        hi,
    ));
    let _ = CheckDlgButton(
        hwnd,
        C_SHARE,
        DLG_BUTTON_CHECK_STATE(if s.share_files { 1 } else { 0 }),
    );

    files.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Shared folder:"),
        label,
        f(24),
        f(98),
        f(90),
        f(20),
        0,
        hi,
    ));
    let share_dir = ctrl(
        hwnd,
        w!("EDIT"),
        w!(""),
        edit,
        f(120),
        f(96),
        f(260),
        f(24),
        C_SHARE_DIR,
        hi,
    );
    let dtxt = wide(&s.share_dir.display().to_string());
    let _ = SetWindowTextW(share_dir, PCWSTR(dtxt.as_ptr()));
    files.push(share_dir);
    files.push(ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Browse..."),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        f(388),
        f(95),
        f(80),
        f(26),
        C_BROWSE,
        hi,
    ));
    files.push(ctrl(
        hwnd,
        w!("STATIC"),
        w!("Clients can only browse this folder.\nThe Tight file-transfer extension is used by\nTightVNC/UltraVNC-compatible viewers."),
        WS_CHILD | WS_VISIBLE,
        f(24),
        f(136),
        f(400),
        f(66),
        0,
        hi,
    ));

    SETTINGS_PAGES.with(|pages| {
        let to_isize = |v: Vec<HWND>| v.into_iter().map(|h| h.0 as isize).collect::<Vec<_>>();
        *pages.borrow_mut() = vec![to_isize(general), to_isize(security), to_isize(files)];
    });

    ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Save"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
        f(250),
        f(408),
        f(90),
        f(30),
        1,
        hi,
    );
    ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Cancel"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        f(350),
        f(408),
        f(90),
        f(30),
        2,
        hi,
    );

    // All page controls (and Save/Cancel) exist now. Only now move the tab
    // strip to the bottom of the sibling z-order: child windows created later
    // are inserted below it, so moving it earlier would leave it above the
    // page controls and hide them.
    let _ = SetWindowPos(
        tab,
        Some(HWND_BOTTOM),
        0,
        0,
        0,
        0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
    );
    show_settings_page(hwnd, 0);
    let _ = RedrawWindow(
        Some(hwnd),
        None,
        None,
        RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE | RDW_UPDATENOW,
    );

    let mut msg = MSG::default();
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
        if crate::settings::EXIT.load(Ordering::Relaxed) {
            break;
        }
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

fn read_text(hwnd: HWND, id: i32) -> String {
    unsafe {
        let control = GetDlgItem(Some(hwnd), id).unwrap_or_default();
        let mut buf = [0u16; 260];
        let n = GetWindowTextW(control, &mut buf);
        String::from_utf16_lossy(&buf[..n.max(0) as usize])
    }
}

/// True for a button's `BN_CLICKED` notification. Combo boxes and check boxes
/// also send `WM_COMMAND`, so checking the notification code as well as the
/// control ID prevents a combo selection from activating a neighbouring
/// button (for example opening the shared-folder picker when the Encryption
/// drop-down changes).
fn clicked(wparam: WPARAM, id: i32) -> bool {
    (wparam.0 & 0xffff) as i32 == id && ((wparam.0 >> 16) & 0xffff) == 0
}

/// Background brush for STATIC labels and check boxes.
///
/// `DefWindowProcW` answers `WM_CTLCOLORSTATIC`/`WM_CTLCOLORBTN` with the
/// system button face because the STATIC/BUTTON classes have no background
/// brush of their own. That gray does not match this window's white client
/// area (`COLOR_WINDOW`), so labels would appear as gray boxes. Return the
/// window brush and draw text transparently so both stay the same colour.
unsafe fn control_color(wparam: WPARAM) -> LRESULT {
    let hdc = HDC(wparam.0 as *mut core::ffi::c_void);
    let _ = SetBkMode(hdc, TRANSPARENT);
    LRESULT(GetSysColorBrush(COLOR_WINDOW).0 as isize)
}

/// Native "select folder" dialog for the shared-directory field.
unsafe fn pick_folder(owner: HWND) -> Option<PathBuf> {
    let mut display = [0u16; 260];
    let title = wide("Select the folder shared with VNC clients");
    let bi = BROWSEINFOW {
        hwndOwner: owner,
        pszDisplayName: PWSTR(display.as_mut_ptr()),
        lpszTitle: PCWSTR(title.as_ptr()),
        ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
        ..Default::default()
    };
    let pidl = SHBrowseForFolderW(&bi);
    if pidl.is_null() {
        return None;
    }
    let mut buf = [0u16; 260];
    let ok = SHGetPathFromIDListW(pidl, &mut buf).as_bool();
    CoTaskMemFree(Some(pidl as *const core::ffi::c_void));
    if !ok {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..len])))
}

unsafe extern "system" fn settings_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        // Labels and check boxes must share the window's white background.
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => return control_color(wparam),
        WM_COMMAND => {
            if clicked(wparam, C_PASS_SHOW) {
                let show = IsDlgButtonChecked(hwnd, C_PASS_SHOW) == 1;
                let pass = GetDlgItem(Some(hwnd), C_PASS).unwrap_or_default();
                let _ = SendMessageW(
                    pass,
                    EM_SETPASSWORDCHAR,
                    Some(WPARAM(if show { 0 } else { '*' as usize })),
                    Some(LPARAM(0)),
                );
                let _ = InvalidateRect(Some(pass), None, true);
                return LRESULT(0);
            }
            if clicked(wparam, 1) {
                let port = read_text(hwnd, C_PORT).parse::<u16>().unwrap_or(5900);
                let sel = SendMessageW(
                    GetDlgItem(Some(hwnd), C_COLOR).unwrap_or_default(),
                    CB_GETCURSEL,
                    Some(WPARAM(0)),
                    Some(LPARAM(0)),
                )
                .0;
                let color = match sel {
                    2 => 8,
                    1 => 16,
                    _ => 24,
                };
                let tls_sel = SendMessageW(
                    GetDlgItem(Some(hwnd), C_TLS).unwrap_or_default(),
                    CB_GETCURSEL,
                    Some(WPARAM(0)),
                    Some(LPARAM(0)),
                )
                .0;
                let tls = match tls_sel {
                    1 => crate::tls::Mode::Required,
                    2 => crate::tls::Mode::Off,
                    _ => crate::tls::Mode::Auto,
                };
                let allow_cidrs = read_text(hwnd, C_ALLOW);
                if let Err(e) = crate::acl::check(&allow_cidrs) {
                    let msg = wide(&format!("Allowed networks are invalid:\n\n{e}"));
                    MessageBoxW(
                        Some(hwnd),
                        PCWSTR(msg.as_ptr()),
                        w!("restsend-vnc"),
                        MB_OK | MB_ICONWARNING,
                    );
                    return LRESULT(0);
                }
                let s = crate::settings::Settings {
                    port,
                    color_level: color,
                    loopback_only: IsDlgButtonChecked(hwnd, C_LOOPBACK) == 1,
                    confirm_connections: IsDlgButtonChecked(hwnd, C_CONFIRM) == 1,
                    allow_cidrs,
                    view_only: IsDlgButtonChecked(hwnd, C_VIEWONLY) == 1,
                    keep_awake: IsDlgButtonChecked(hwnd, C_KEEP) == 1,
                    allow_debug: IsDlgButtonChecked(hwnd, C_DEBUG) == 1,
                    autostart: IsDlgButtonChecked(hwnd, C_AUTOSTART) == 1,
                    password: {
                        let p = read_text(hwnd, C_PASS);
                        if p.is_empty() {
                            None
                        } else {
                            Some(p)
                        }
                    },
                    title: {
                        let t = read_text(hwnd, C_TITLE);
                        if t.trim().is_empty() {
                            "restsend-vnc".to_string()
                        } else {
                            t
                        }
                    },
                    // Site URL is not edited here; keep the configured/default one.
                    url: crate::settings::url(),
                    logon_task: crate::settings::current().logon_task,
                    share_files: IsDlgButtonChecked(hwnd, C_SHARE) == 1,
                    share_dir: {
                        let d = read_text(hwnd, C_SHARE_DIR);
                        if d.trim().is_empty() {
                            crate::settings::default_share_dir()
                        } else {
                            PathBuf::from(d)
                        }
                    },
                    // TLS certificate/key paths are configured outside this
                    // dialog; keep the persisted/CLI values.
                    tls,
                    tls_cert: crate::settings::load().tls_cert,
                    tls_key: crate::settings::load().tls_key,
                };
                crate::settings::save(&s);
                crate::settings::apply_live(&s);
                crate::autostart::set(s.autostart);
                tracing::info!("tray: settings saved ({s:?})");
                let _ = DestroyWindow(hwnd);
            } else if clicked(wparam, 2) {
                let _ = DestroyWindow(hwnd);
            } else if clicked(wparam, C_BROWSE) {
                if let Some(dir) = pick_folder(hwnd) {
                    let text = wide(&dir.display().to_string());
                    let edit = GetDlgItem(Some(hwnd), C_SHARE_DIR).unwrap_or_default();
                    let _ = SetWindowTextW(edit, PCWSTR(text.as_ptr()));
                }
            } else if clicked(wparam, C_ELEVATE) {
                let exe = std::env::current_exe().unwrap_or_default();
                let exe_w = wide(&exe.display().to_string());
                ShellExecuteW(
                    Some(hwnd),
                    w!("runas"),
                    PCWSTR(exe_w.as_ptr()),
                    w!("--install-task"),
                    PCWSTR::null(),
                    SW_SHOWNORMAL,
                );
            }
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
        }
        WM_NOTIFY => {
            let hdr = lparam.0 as *const NMHDR;
            if !hdr.is_null() && (*hdr).code == TCN_SELCHANGE {
                let tab = GetDlgItem(Some(hwnd), C_TABS).unwrap_or_default();
                let index =
                    SendMessageW(tab, TCM_GETCURSEL, Some(WPARAM(0)), Some(LPARAM(0))).0 as usize;
                show_settings_page(hwnd, index);
            }
        }
        WM_DESTROY => {
            SETTINGS_PAGES.with(|pages| pages.borrow_mut().clear());
            SETTINGS_HWND.store(0, Ordering::Relaxed);
            PostQuitMessage(0);
        }
        _ => return DefWindowProcW(hwnd, msg, wparam, lparam),
    }
    LRESULT(0)
}

#[cfg(test)]
mod tests {
    use super::{clicked, C_BROWSE, C_TLS};
    use windows::Win32::Foundation::WPARAM;

    #[test]
    fn combo_notifications_do_not_trigger_buttons() {
        let button_click = WPARAM(C_TLS as usize); // BN_CLICKED == 0
        let combo_change = WPARAM(C_TLS as usize | (1 << 16)); // CBN_SELCHANGE
        assert!(clicked(button_click, C_TLS));
        assert!(!clicked(combo_change, C_TLS));
        assert!(!clicked(combo_change, C_BROWSE));
    }
}
