//! Windows tray icon + native Win32 settings window.
//!
//! Menu: Settings…, Disconnect all sessions, open the configured URL, About,
//! Exit. Settings are persisted to `%APPDATA%\rvnc\settings.ini` and applied
//! live (port/loopback changes rebind the listener).

#![cfg(target_os = "windows")]

use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::atomic::Ordering as AtomicOrdering;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, ShellExecuteW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
    NOTIFYICONDATAW,
};
use windows::Win32::Graphics::Gdi::{
    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, COLOR_WINDOW, CreateFontW, DEFAULT_CHARSET,
    DEFAULT_PITCH, FF_DONTCARE, FW_NORMAL, HBRUSH, OUT_DEFAULT_PRECIS,
};
use windows::Win32::UI::Controls::{
    CheckDlgButton, DLG_BUTTON_CHECK_STATE, ICC_STANDARD_CLASSES, ICC_WIN95_CLASSES,
    INITCOMMONCONTROLSEX, InitCommonControlsEx, IsDlgButtonChecked,
};
use windows::Win32::UI::HiDpi::GetDpiForSystem;
use windows::Win32::UI::WindowsAndMessaging::*;

const WM_TRAY: u32 = WM_APP + 1;
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

static UI_FONT: AtomicIsize = AtomicIsize::new(0);

pub fn spawn() {
    // Common Controls v6 (themed buttons/edits) — paired with the embedded
    // manifest that requests Microsoft.Windows.Common-Controls 6.
    unsafe {
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES,
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
        hIcon: LoadIconW(
            Some(hinst.into()),
            PCWSTR(1 as *const u16),
        )
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

    let mut msg = MSG::default();
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
    if crate::settings::EXIT.load(Ordering::Relaxed) {
        std::process::exit(0);
    }
}

unsafe extern "system" fn tray_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAY => {
            let ev = lparam.0 as u32;
            if ev == WM_RBUTTONUP || ev == WM_CONTEXTMENU {
                let menu = CreatePopupMenu().unwrap();
                let _ = AppendMenuW(menu, MF_STRING, ID_SETTINGS, w!("Settings..."));
                let _ = AppendMenuW(menu, MF_STRING, ID_KILL, w!("Disconnect all sessions"));
                let url = wide(&crate::settings::url());
                let _ = AppendMenuW(
                    menu,
                    MF_STRING,
                    ID_OPEN,
                    PCWSTR(url.as_ptr()),
                );
                let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
                let _ = AppendMenuW(menu, MF_STRING, ID_ABOUT, w!("About restsend-vnc"));
                let _ = AppendMenuW(menu, MF_STRING, ID_EXIT, w!("Exit"));
                let mut pt = POINT::default();
                let _ = GetCursorPos(&mut pt);
                let _ = SetForegroundWindow(hwnd);
                let _ = TrackPopupMenu(
                    menu,
                    TPM_RIGHTBUTTON,
                    pt.x,
                    pt.y,
                    Some(0),
                    hwnd,
                    None,
                );
                let _ = DestroyMenu(menu);
            }
        }
        WM_COMMAND => {
            let id = wparam.0 & 0xffff;
            match id {
                ID_SETTINGS => open_settings(),
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
                    crate::settings::EXIT.store(true, Ordering::Relaxed);
                    let _ = PostQuitMessage(0);
                }
                _ => {}
            }
        }
        WM_DESTROY => PostQuitMessage(0),
        _ => return DefWindowProcW(hwnd, msg, wparam, lparam),
    }
    LRESULT(0)
}

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
        Some(windows::Win32::Foundation::HINSTANCE(hinst as *mut core::ffi::c_void)),
        None,
    )
    .unwrap_or_default();
    let f = UI_FONT.load(AtomicOrdering::Relaxed);
    if f != 0 {
        SendMessageW(hwnd, WM_SETFONT, Some(WPARAM(f as usize)), Some(LPARAM(1)));
    }
    hwnd
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
        bottom: f(400),
    };
    let _ = AdjustWindowRectEx(&mut wr, style, false, WINDOW_EX_STYLE(0));

    let hwnd = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        class,
        w!("restsend-vnc settings"),
        style,
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

    let s = crate::settings::load();
    let hi = hinst.0 as isize;
    let label: WINDOW_STYLE = WS_CHILD | WS_VISIBLE;
    let edit: WINDOW_STYLE = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP;
    let check: WINDOW_STYLE =
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_AUTOCHECKBOX as u32);

    let font = CreateFontW(
        -f(15),
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
    SendMessageW(hwnd, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));

    ctrl(hwnd, w!("STATIC"), w!("Port:"), label, f(18), f(20), f(80), f(20), 0, hi);
    let port = ctrl(hwnd, w!("EDIT"), w!(""), edit, f(110), f(18), f(90), f(24), C_PORT, hi);
    let ptxt = wide(&s.port.to_string());
    SetWindowTextW(port, PCWSTR(ptxt.as_ptr()));

    ctrl(hwnd, w!("STATIC"), w!("Colour:"), label, f(220), f(20), f(70), f(20), 0, hi);
    let combo = ctrl(
        hwnd,
        w!("COMBOBOX"),
        w!(""),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(CBS_DROPDOWNLIST as u32),
        f(292),
        f(18),
        f(120),
        f(160),
        C_COLOR,
        hi,
    );
    for t in ["High quality (24-bit)", "Balanced (16-bit)", "Fastest (8-bit)"]
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

    ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Only accept loopback connections"),
        check,
        f(18),
        f(60),
        f(420),
        f(24),
        C_LOOPBACK,
        hi,
    );
    let _ = CheckDlgButton(
        hwnd,
        C_LOOPBACK,
        DLG_BUTTON_CHECK_STATE(if s.loopback_only { 1 } else { 0 }),
    );
    ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Keep the machine awake"),
        check,
        f(18),
        f(92),
        f(420),
        f(24),
        C_KEEP,
        hi,
    );
    let _ = CheckDlgButton(hwnd, C_KEEP, DLG_BUTTON_CHECK_STATE(if s.keep_awake { 1 } else { 0 }));
    ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Allow debug panel (Ctrl + 3 clicks)"),
        check,
        f(18),
        f(124),
        f(420),
        f(24),
        C_DEBUG,
        hi,
    );
    let _ = CheckDlgButton(hwnd, C_DEBUG, DLG_BUTTON_CHECK_STATE(if s.allow_debug { 1 } else { 0 }));

    ctrl(hwnd, w!("STATIC"), w!("Title:"), label, f(18), f(166), f(80), f(20), 0, hi);
    let title = ctrl(hwnd, w!("EDIT"), w!(""), edit, f(110), f(164), f(320), f(24), C_TITLE, hi);
    let ttxt = wide(&s.title);
    SetWindowTextW(title, PCWSTR(ttxt.as_ptr()));

    ctrl(hwnd, w!("STATIC"), w!("Password:"), label, f(18), f(206), f(80), f(20), 0, hi);
    let pass = ctrl(
        hwnd,
        w!("EDIT"),
        w!(""),
        edit, // plain text by default (no ES_PASSWORD masking)
        f(110),
        f(204),
        f(320),
        f(24),
        C_PASS,
        hi,
    );
    let ptxt = wide(s.password.as_deref().unwrap_or(""));
    SetWindowTextW(pass, PCWSTR(ptxt.as_ptr()));

    ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Start with Windows (current user)"),
        check,
        f(18),
        f(246),
        f(420),
        f(24),
        C_AUTOSTART,
        hi,
    );
    let _ = CheckDlgButton(hwnd, C_AUTOSTART, DLG_BUTTON_CHECK_STATE(if s.autostart { 1 } else { 0 }));

    let elevate = ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Install elevated autostart (admin)"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        f(18),
        f(280),
        f(300),
        f(30),
        C_ELEVATE,
        hi,
    );
    // UAC shield on the button (Common Controls v6).
    SendMessageW(elevate, 0x160C, Some(WPARAM(0)), Some(LPARAM(1)));

    ctrl(
        hwnd,
        w!("BUTTON"),
        w!("Save"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
        f(250),
        f(340),
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
        f(340),
        f(90),
        f(30),
        2,
        hi,
    );

    let mut msg = MSG::default();
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
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

unsafe extern "system" fn settings_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_COMMAND => {
            let id = wparam.0 & 0xffff;
            if id == 1 {
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
                let s = crate::settings::Settings {
                    port,
                    color_level: color,
                    loopback_only: IsDlgButtonChecked(hwnd, C_LOOPBACK) == 1,
                    keep_awake: IsDlgButtonChecked(hwnd, C_KEEP) == 1,
                    allow_debug: IsDlgButtonChecked(hwnd, C_DEBUG) == 1,
                    autostart: IsDlgButtonChecked(hwnd, C_AUTOSTART) == 1,
                    password: {
                        let p = read_text(hwnd, C_PASS);
                        if p.is_empty() { None } else { Some(p) }
                    },
                    title: {
                        let t = read_text(hwnd, C_TITLE);
                        if t.trim().is_empty() { "restsend-vnc".to_string() } else { t }
                    },
                    // Site URL is not edited here; keep the configured/default one.
                    url: crate::settings::url(),
                    logon_task: crate::settings::current().logon_task,
                };
                crate::settings::save(&s);
                crate::settings::apply_live(&s);
                crate::autostart::set(s.autostart);
                tracing::info!("tray: settings saved ({s:?})");
                let _ = DestroyWindow(hwnd);
            } else if id == 2 {
                let _ = DestroyWindow(hwnd);
            } else if id == C_ELEVATE as usize {
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
        WM_DESTROY => PostQuitMessage(0),
        _ => return DefWindowProcW(hwnd, msg, wparam, lparam),
    }
    LRESULT(0)
}
