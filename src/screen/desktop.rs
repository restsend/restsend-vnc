//! Real-desktop capture via `windows-capture` (Windows.Graphics.Capture).
//!
//! This replaces the `scap` wrapper with a small direct adapter: monitor
//! selection, a capture handler that publishes BGRA frames into
//! [`ScreenState`], and a supervisor that restarts the capture thread when it
//! dies and gives up when no frame ever arrives (for example when rvnc runs in
//! a service/SSH session without an interactive desktop).
//!
//! The pointer is handled separately (cursor pseudo-encoding or a
//! server-composited overlay), so cursor capture is disabled when the OS
//! supports that setting. The OS capture border is kept as the visual
//! "screen is being shared" reminder.

use std::ffi::c_void;
use std::io;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Graphics::Gdi::{GetMonitorInfoW, HMONITOR, MONITORINFO};
use windows::Win32::UI::WindowsAndMessaging::{
    SystemParametersInfoW, SPI_GETMOUSETRAILS, SPI_SETMOUSETRAILS,
};
use windows_capture::capture::{Context, GraphicsCaptureApiHandler};
use windows_capture::frame::Frame as CaptureFrame;
use windows_capture::graphics_capture_api::{GraphicsCaptureApi, InternalCaptureControl};
use windows_capture::monitor::Monitor;
use windows_capture::settings::{
    ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
    MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
};

use crate::framebuffer::{Frame, ScreenState};

/// Give a fresh capture session this long to produce its first frame before
/// declaring it stale and starting over.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(15);
/// Consecutive stale starts before giving up entirely.
const MAX_STALE_STARTS: u32 = 5;

pub fn spawn(
    display_index: usize,
    fps: u32,
    state: Arc<ScreenState>,
) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("restsend-vnc-capture".into())
        .spawn(move || run(display_index, fps, state))
        .map_err(io::Error::other)
}

fn pick_monitor(display_index: usize) -> io::Result<Monitor> {
    let monitors = Monitor::enumerate()
        .map_err(|e| io::Error::other(format!("monitor enumeration failed: {e}")))?;
    monitors.get(display_index).copied().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "display index {display_index} not found ({} display(s) available)",
                monitors.len()
            ),
        )
    })
}

/// Records the captured monitor's physical rect so the cursor poller can map
/// `GetCursorPos` into framebuffer coordinates (including `--scale`).
fn remember_display_rect(monitor: &Monitor, state: &ScreenState) {
    let mut info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    let handle = HMONITOR(monitor.as_raw_hmonitor());
    if unsafe { GetMonitorInfoW(handle, &mut info) }.as_bool() {
        let r = info.rcMonitor;
        state.set_cursor_map(
            r.left,
            r.top,
            (r.right - r.left).max(1) as u32,
            (r.bottom - r.top).max(1) as u32,
        );
    }
}

/// The capture handler owns a copy of the monitor so it can refresh the cursor
/// mapping when the desktop geometry changes.
struct CaptureHandler {
    state: Arc<ScreenState>,
    monitor: Monitor,
    dims: Option<(u32, u32)>,
}

impl GraphicsCaptureApiHandler for CaptureHandler {
    type Flags = (Arc<ScreenState>, Monitor);
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn new(ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
        let (state, monitor) = ctx.flags;
        Ok(Self {
            state,
            monitor,
            dims: None,
        })
    }

    fn on_frame_arrived(
        &mut self,
        frame: &mut CaptureFrame,
        _capture_control: InternalCaptureControl,
    ) -> Result<(), Self::Error> {
        if self.state.is_stopped() {
            return Ok(());
        }
        let (w, h) = (frame.width(), frame.height());
        if w == 0 || h == 0 {
            return Ok(());
        }
        let stride = (w as usize).checked_mul(4).ok_or("frame width overflow")?;
        let size = stride
            .checked_mul(h as usize)
            .ok_or("frame size overflow")?;

        let mut buf = frame
            .buffer()
            .map_err(|e| format!("cannot map capture frame: {e}"))?;
        let mut bgra = Vec::with_capacity(size);
        if buf.has_padding() {
            let row_pitch = buf.row_pitch() as usize;
            let raw = buf.as_raw_buffer();
            if row_pitch < stride {
                return Err("capture row pitch is smaller than the frame width".into());
            }
            for y in 0..h as usize {
                let start = y
                    .checked_mul(row_pitch)
                    .ok_or("capture row offset overflow")?;
                let end = start + stride;
                if end > raw.len() {
                    return Err("capture frame buffer is shorter than expected".into());
                }
                bgra.extend_from_slice(&raw[start..end]);
            }
        } else {
            let raw = buf.as_raw_buffer();
            if raw.len() < size {
                return Err("capture frame buffer is shorter than expected".into());
            }
            bgra.extend_from_slice(&raw[..size]);
        }
        if bgra.len() != size {
            return Err("capture frame size mismatch".into());
        }

        if self.dims != Some((w, h)) {
            match self.dims {
                None => tracing::info!("first frame captured ({}x{})", w, h),
                Some((old_w, old_h)) => tracing::info!(
                    "display size changed from {}x{} to {}x{}",
                    old_w,
                    old_h,
                    w,
                    h
                ),
            }
            self.dims = Some((w, h));
            remember_display_rect(&self.monitor, &self.state);
        }
        self.state.publish_capture(Frame {
            width: w,
            height: h,
            bgra,
        });
        Ok(())
    }
}

/// Why a [`capture_session`] call returned.
#[derive(Debug)]
enum CaptureExit {
    /// Global shutdown requested; the supervisor should return.
    Stopped,
    /// Planned restart (lock/unlock or sleep/resume): recreate the session.
    Restarted,
}

fn run(display_index: usize, fps: u32, state: Arc<ScreenState>) {
    let mut stale_starts = 0u32;
    loop {
        if state.is_stopped() {
            return;
        }
        let generation_before = state.generation();
        match capture_session(display_index, fps, &state) {
            Ok(CaptureExit::Stopped) => return, // stopped
            Ok(CaptureExit::Restarted) => {
                // Planned restart (lock/unlock or sleep/resume transition):
                // not a failure, so it neither counts as stale nor waits.
                stale_starts = 0;
                continue;
            }
            Err(e) => {
                if state.generation() == generation_before {
                    stale_starts += 1;
                } else {
                    stale_starts = 0;
                }
                if stale_starts >= MAX_STALE_STARTS {
                    tracing::error!(
                        "capture keeps failing without ever producing a frame; giving up: {e}"
                    );
                    std::process::exit(1);
                }
                tracing::error!("capture failed: {e}; retrying in 2s");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// Temporarily disables Windows pointer trails while sharing. WGC is asked
/// to exclude the cursor, but some builds still composite trail ghosts from
/// the cursor layer; those show up as small dark dots behind fast movement.
/// The original setting is restored when the capture session stops.
struct PointerTrailsGuard {
    previous: Option<u32>,
}

impl PointerTrailsGuard {
    fn new() -> Self {
        Self {
            previous: disable_pointer_trails(),
        }
    }
}

impl Drop for PointerTrailsGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            unsafe {
                let _ =
                    SystemParametersInfoW(SPI_SETMOUSETRAILS, previous, None, Default::default());
            }
        }
    }
}

fn disable_pointer_trails() -> Option<u32> {
    let mut trails = 0u32;
    let got = unsafe {
        SystemParametersInfoW(
            SPI_GETMOUSETRAILS,
            0,
            Some(&mut trails as *mut u32 as *mut c_void),
            Default::default(),
        )
    };
    if got.is_err() || trails == 0 {
        return None;
    }
    let set = unsafe { SystemParametersInfoW(SPI_SETMOUSETRAILS, 0, None, Default::default()) };
    if set.is_err() {
        return None;
    }
    tracing::info!("pointer trails were enabled ({trails}); disabled them while sharing");
    Some(trails)
}

fn capture_session(
    display_index: usize,
    fps: u32,
    state: &Arc<ScreenState>,
) -> Result<CaptureExit, io::Error> {
    let monitor = pick_monitor(display_index)?;
    remember_display_rect(&monitor, state);
    if let (Ok(w), Ok(h)) = (monitor.width(), monitor.height()) {
        tracing::info!("capturing display {display_index} ({w}x{h})");
    }

    // Always try to exclude the OS cursor from the captured frame. The server
    // composites the pointer itself; a captured cursor would leave a second
    // pointer and visible trails behind fast mouse movement.
    // `is_cursor_settings_supported` is only a hint: some builds report false
    // but accept the setting, so try it and fall back on the explicit error.
    let cursor_supported = GraphicsCaptureApi::is_cursor_settings_supported().unwrap_or(false);
    let preferred = match std::env::var("RESTSEND_VNC_CAPTURE_CURSOR").as_deref() {
        Ok("on") | Ok("1") => CursorCaptureSettings::WithCursor,
        _ => CursorCaptureSettings::WithoutCursor,
    };
    tracing::info!(
        "capture cursor: {:?} (settings supported: {cursor_supported})",
        preferred
    );
    // Keep the OS capture border: it is the visible reminder that the screen
    // is being shared, and it matches the previous scap behaviour. On old
    // Windows builds, requesting "no border" would fail the whole session.
    let border = DrawBorderSettings::Default;
    let interval = if GraphicsCaptureApi::is_minimum_update_interval_supported().unwrap_or(false) {
        MinimumUpdateIntervalSettings::Custom(Duration::from_nanos(
            1_000_000_000 / u64::from(fps.max(1)),
        ))
    } else {
        MinimumUpdateIntervalSettings::Default
    };

    let make_settings = |cursor_setting| {
        Settings::new(
            monitor,
            cursor_setting,
            border,
            SecondaryWindowSettings::Default,
            interval,
            DirtyRegionSettings::Default,
            ColorFormat::Bgra8,
            (Arc::clone(state), monitor),
        )
    };

    let control = match CaptureHandler::start_free_threaded(make_settings(preferred)) {
        Ok(control) => control,
        Err(windows_capture::capture::GraphicsCaptureApiError::GraphicsCaptureApiError(
            windows_capture::graphics_capture_api::Error::CursorConfigUnsupported,
        )) => {
            tracing::warn!(
                "this Windows build cannot exclude the cursor from the capture; viewers may see a second pointer or trails"
            );
            CaptureHandler::start_free_threaded(make_settings(CursorCaptureSettings::Default))
                .map_err(|e| io::Error::other(format!("capture start failed: {e}")))?
        }
        Err(e) => {
            return Err(io::Error::other(format!("capture start failed: {e}")));
        }
    };

    let _pointer_trails = PointerTrailsGuard::new();
    let started = Instant::now();
    let mut generation_before = state.generation();
    let mut stale_warned = false;
    loop {
        if state.is_stopped() {
            let _ = control.stop();
            return Ok(CaptureExit::Stopped);
        }
        if state.take_capture_restart() {
            // Windows.Graphics.Capture keeps delivering frames after a
            // lock/unlock or sleep/resume but stops drawing its yellow
            // capture border; only a fresh session restores it.
            tracing::info!("recreating the capture session to restore the capture border");
            let _ = control.stop();
            return Ok(CaptureExit::Restarted);
        }
        if control.is_finished() {
            return match control.wait() {
                Ok(()) if state.is_stopped() => Ok(CaptureExit::Stopped),
                Ok(()) => Err(io::Error::other("capture session ended unexpectedly")),
                Err(e) => Err(io::Error::other(format!("capture session ended: {e}"))),
            };
        }
        if state.generation() != generation_before {
            // Frames are flowing; reset the stale clock.
            generation_before = state.generation();
        } else if started.elapsed() > FIRST_FRAME_TIMEOUT && !stale_warned {
            stale_warned = true;
            tracing::error!(
                "no frames {}s after capture start; hints: rvnc must run in an \
                 interactive desktop session (not a service/SSH session), \
                 Windows 10 1903+ is required, and the --display index must exist",
                FIRST_FRAME_TIMEOUT.as_secs()
            );
            // Keep waiting a while longer in case frames come late; the outer
            // loop counts consecutive stale starts and gives up after
            // MAX_STALE_STARTS.
            if started.elapsed() > FIRST_FRAME_TIMEOUT * 4 {
                let _ = control.stop();
                return Err(io::Error::other("no frames ever captured (stale)"));
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
