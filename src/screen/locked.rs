//! Renders a "session locked" notice for viewers while the interactive
//! Windows session is locked (or a secure/UAC desktop is active).
//!
//! Windows.Graphics.Capture stops producing frames once the workstation is
//! locked, which would otherwise leave viewers staring at a frozen image with
//! no explanation. A small watchdog publishes a rendered notice instead.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::framebuffer::{Frame, ScreenState};

/// Fallback geometry when no real frame has been captured yet (locked at
/// startup): the ServerInit would otherwise advertise a 0x0 framebuffer.
const FALLBACK_W: u32 = 1280;
const FALLBACK_H: u32 = 720;

/// Set by the power callback when the system resumes from sleep/hibernate.
static RESUMED: AtomicBool = AtomicBool::new(false);

pub fn spawn(state: Arc<ScreenState>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("restsend-vnc-lock-watch".into())
        .spawn(move || run(state))
        .expect("spawn lock watchdog")
}

fn run(state: Arc<ScreenState>) {
    let mut announced = false;
    // Debounce: Windows briefly reports LOCK during screensaver/desktop
    // transitions. Require two consecutive readings before changing state.
    let mut locked_streak = 0u32;
    let mut unlocked_streak = 0u32;
    let mut last_capture_gen = state.capture_generation();
    let mut last_capture_change = Instant::now();
    register_resume_notification();
    loop {
        if state.is_stopped() {
            return;
        }
        let gen = state.capture_generation();
        if gen != last_capture_gen {
            last_capture_gen = gen;
            last_capture_change = Instant::now();
        }
        if RESUMED.swap(false, Ordering::Relaxed) {
            // Sleep / hibernate cycle: Windows.Graphics.Capture resumes
            // without its yellow capture border, so the session must be
            // recreated once the desktop is back.
            tracing::info!("system resumed from sleep — recreating the capture session");
            state.request_capture_restart();
            // The first lock reading after a resume is not trustworthy.
            locked_streak = 0;
            unlocked_streak = 0;
        }
        if is_locked() {
            locked_streak += 1;
            unlocked_streak = 0;
        } else {
            unlocked_streak += 1;
            locked_streak = 0;
        }
        // Only show the notice when the session is really locked AND the
        // capture backend has genuinely stalled (not just a static desktop).
        let capture_stalled = last_capture_change.elapsed() > Duration::from_millis(1500);
        let show = locked_streak >= 2 && capture_stalled;
        if show {
            if !announced {
                tracing::warn!(
                    "Windows session is locked (or a secure desktop is active) — \
                     viewers get a lock notice instead of the desktop"
                );
                announced = true;
            }
            let (w, h) = {
                let snap = state.snapshot();
                let (w, h) = snap.dims();
                if w == 0 || h == 0 {
                    (FALLBACK_W, FALLBACK_H)
                } else {
                    (w, h)
                }
            };
            state.publish(render(w, h));
        } else if unlocked_streak >= 2 && announced {
            // The capture usually resumes after an unlock but without its
            // yellow border; drop and recreate the session so it comes back.
            tracing::info!("Windows session unlocked — recreating the capture session");
            announced = false;
            state.request_capture_restart();
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Subscribes to suspend/resume notifications so [`RESUMED`] is set when the
/// system wakes up (covers sleep/hibernate with and without a lock screen).
#[cfg(target_os = "windows")]
fn register_resume_notification() {
    use std::ptr;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Power::{
        PowerRegisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
    };
    use windows::Win32::UI::WindowsAndMessaging::DEVICE_NOTIFY_CALLBACK;

    // PBT_APMXSUSPEND == 4, PBT_APMXRESUME == 18.
    extern "system" fn power_callback(
        _ctx: *const std::ffi::c_void,
        ptype: u32,
        _s: *const std::ffi::c_void,
    ) -> u32 {
        if ptype == 18 {
            RESUMED.store(true, Ordering::Relaxed);
        }
        0
    }

    // The parameters must outlive the registration; the raw pointer inside
    // makes the struct !Sync, hence the wrapper.
    struct Params(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS);
    unsafe impl Sync for Params {}
    static PARAMS: Params = Params(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
        Callback: Some(power_callback),
        Context: ptr::null_mut(),
    });

    let mut handle: *mut std::ffi::c_void = ptr::null_mut();
    let rc = unsafe {
        PowerRegisterSuspendResumeNotification(
            DEVICE_NOTIFY_CALLBACK,
            HANDLE(&PARAMS.0 as *const _ as *mut _),
            &mut handle,
        )
    };
    if rc.is_err() {
        tracing::warn!("cannot register suspend/resume notifications: {rc:?}");
        return;
    }
    // The registration is never unregistered: the watchdog thread runs until
    // process shutdown, which invalidates it anyway.
    tracing::debug!("suspend/resume notifications registered");
}

#[cfg(not(target_os = "windows"))]
fn register_resume_notification() {}

/// WTS_SESSIONSTATE_UNLOCK = 0, WTS_SESSIONSTATE_LOCK = 1. Getting this
/// backwards shows the lock notice on an idle but unlocked desktop (the
/// capture is legitimately stalled while nothing on screen changes).
const WTS_SESSIONSTATE_LOCK: i32 = 1;

fn flags_locked(flags: i32) -> bool {
    flags == WTS_SESSIONSTATE_LOCK
}

/// True when the interactive session is locked / a secure desktop is up.
#[cfg(target_os = "windows")]
fn is_locked() -> bool {
    use windows::Win32::System::RemoteDesktop::{
        WTSFreeMemory, WTSQuerySessionInformationW, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
        WTS_INFO_CLASS,
    };

    // WTSSessionInfoEx == 25; Level1.SessionFlags sits at buffer offset 12.
    const WTS_SESSION_INFO_EX: i32 = 25;

    let mut buf = windows::core::PWSTR::null();
    let mut bytes = 0u32;
    let ok = unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            WTS_CURRENT_SESSION,
            WTS_INFO_CLASS(WTS_SESSION_INFO_EX),
            &mut buf,
            &mut bytes,
        )
    };
    if ok.is_err() || buf.is_null() || bytes < 16 {
        // Unknown: treat as locked=False so we never hide a working desktop.
        return false;
    }
    let mut locked = false;
    unsafe {
        let base = buf.0 as *const u8;
        let level = std::ptr::read_unaligned(base as *const u32);
        if level == 1 {
            let flags = std::ptr::read_unaligned(base.add(12) as *const i32);
            locked = flags_locked(flags);
        }
        WTSFreeMemory(buf.0 as _);
    }
    locked
}

#[cfg(not(target_os = "windows"))]
fn is_locked() -> bool {
    false
}

// --- rendering --------------------------------------------------------------

use super::font;

const BG: [u8; 4] = [24, 20, 16, 255]; // BGRA dark slate
const PANEL: [u8; 4] = [40, 34, 28, 255];
const ACCENT: [u8; 4] = [80, 170, 255, 255];
const TEXT: [u8; 4] = [240, 240, 240, 255];
const MUTED: [u8; 4] = [170, 170, 170, 255];

fn render(w: u32, h: u32) -> Frame {
    let mut f = Frame::new(w.max(64), h.max(64));
    font::fill(&mut f, BG);

    let w = f.width;
    let h = f.height;
    let panel_w = (w * 3 / 4).clamp(420, 1100);
    let panel_h = (h / 3).clamp(180, 300);
    let px = (w - panel_w) / 2;
    let py = (h - panel_h) / 2;
    font::fill_rect(&mut f, px, py, panel_w, panel_h, PANEL);
    font::fill_rect(&mut f, px, py, panel_w, (panel_h / 24).max(3), ACCENT);

    // Lock icon: body + shackle (drawn with rects).
    let icon = (panel_h / 5).max(28);
    let ix = px + panel_w / 2 - icon / 2;
    let iy = py + panel_h / 6;
    let body_h = icon * 3 / 5;
    font::fill_rect(&mut f, ix, iy + icon - body_h, icon, body_h, ACCENT);
    let shackle_w = icon * 3 / 4;
    let sx = ix + (icon - shackle_w) / 2;
    let sy = iy + icon / 6;
    let sh = icon * 2 / 5;
    font::fill_rect(&mut f, sx, sy, shackle_w, sh, ACCENT);
    let inner = (shackle_w / 4).max(2);
    font::fill_rect(&mut f, sx + inner, sy, shackle_w - inner * 2, sh / 2, PANEL);

    let title = "WINDOWS SESSION LOCKED";
    let sub = "PLEASE UNLOCK TO CONTINUE";
    let hint = "RVNC IS WAITING";

    let ts = (panel_w / (title.len() as u32 * 6)).clamp(2, 6);
    let text_y = iy + icon + (panel_h / 14);
    draw_centered(&mut f, px, panel_w, text_y, title, ts, TEXT);

    let ss = (ts * 2 / 3).max(1);
    draw_centered(&mut f, px, panel_w, text_y + 8 * ts + 6, sub, ss, MUTED);
    draw_centered(
        &mut f,
        px,
        panel_w,
        text_y + 8 * ts + 6 + 8 * ss + 6,
        hint,
        ss,
        ACCENT,
    );
    f
}

fn draw_centered(
    f: &mut Frame,
    panel_x: u32,
    panel_w: u32,
    y: u32,
    text: &str,
    scale: u32,
    color: [u8; 4],
) {
    let total = font::text_width(text, scale);
    let x = panel_x + panel_w.saturating_sub(total) / 2;
    font::draw_text(f, x, y, text, scale, color);
}

#[cfg(test)]
mod tests {
    use super::flags_locked;

    #[test]
    fn wts_lock_flag_is_one() {
        assert!(!flags_locked(0), "WTS_SESSIONSTATE_UNLOCK");
        assert!(flags_locked(1), "WTS_SESSIONSTATE_LOCK");
    }
}
