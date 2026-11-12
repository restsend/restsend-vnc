//! Real-desktop capture via the `scap` crate (Windows.Graphics.Capture on
//! Windows). Recreates the capturer automatically when the display
//! resolution changes, and self-heals when no frames are produced at all
//! (e.g. rvnc running in a service/SSH session without an interactive
//! desktop).

use std::io;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use scap::capturer::{Capturer, Options, Resolution};
use scap::frame::{Frame as ScapFrame, FrameType};
use scap::{Target, get_all_targets};

use crate::framebuffer::{Frame, ScreenState};

/// Give a fresh capturer this long to produce its first frame before
/// declaring the capture session stale and rebuilding.
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

fn pick_target(display_index: usize) -> io::Result<Target> {
    let displays: Vec<Target> = get_all_targets()
        .into_iter()
        .filter(|t| matches!(t, Target::Display(_)))
        .collect();
    displays.get(display_index).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "display index {display_index} not found ({} display(s) available)",
                displays.len()
            ),
        )
    })
}

fn build_capturer(
    display_index: usize,
    fps: u32,
    state: &ScreenState,
) -> io::Result<Capturer> {
    let target = pick_target(display_index)?;
    remember_display_rect(&target, state);
    let options = Options {
        fps: fps.max(1),
        // The pointer is handled separately (cursor pseudo-encoding or a
        // server-composited overlay). Burning it into the frame would make
        // every mouse move trigger a full 4K capture + diff + encode pass.
        show_cursor: false,
        show_highlight: false,
        output_type: FrameType::BGRAFrame,
        output_resolution: Resolution::Captured, // native pixels * scale factor
        target: Some(target),
        crop_area: None,
        excluded_targets: None,
    };
    let capturer = Capturer::build(options)
        .map_err(|e| io::Error::other(format!("capturer build failed: {e:?}")))?;
    Ok(capturer)
}

/// Records the captured monitor's physical rect so the cursor poller can map
/// `GetCursorPos` into framebuffer coordinates (including `--scale`).
fn remember_display_rect(target: &Target, state: &ScreenState) {
    use windows::Win32::Graphics::Gdi::{GetMonitorInfoW, MONITORINFO};
    use windows::Win32::Foundation::RECT;
    if let Target::Display(display) = target {
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            rcMonitor: RECT::default(),
            rcWork: RECT::default(),
            dwFlags: 0,
        };
        // scap links a different windows-rs version; rebuild the handle in
        // our own type space (both are raw HMONITOR pointers).
        let monitor = windows::Win32::Graphics::Gdi::HMONITOR(display.raw_handle.0);
        if unsafe { GetMonitorInfoW(monitor, &mut info) }.as_bool() {
            let r = info.rcMonitor;
            state.set_cursor_map(
                r.left,
                r.top,
                (r.right - r.left).max(1) as u32,
                (r.bottom - r.top).max(1) as u32,
            );
        }
    }
}

fn run(display_index: usize, fps: u32, state: Arc<ScreenState>) {
    let mut stale_starts = 0u32;
    loop {
        if state.is_stopped() {
            return;
        }
        let generation_before = state.generation();
        match capture_session(display_index, fps, &state) {
            Ok(()) => return, // stopped
            Err(CaptureError::ResolutionChange) => {
                tracing::info!("display size changed, rebuilding capturer");
                std::thread::sleep(Duration::from_millis(300));
            }
            Err(CaptureError::Engine(e)) => {
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

enum CaptureError {
    ResolutionChange,
    Engine(io::Error),
}

enum PumpMsg {
    Started(u32, u32),
    Exit(io::Result<()>),
}

fn capture_session(
    display_index: usize,
    fps: u32,
    state: &Arc<ScreenState>,
) -> Result<(), CaptureError> {
    // The pump owns the capturer exclusively: `get_next_frame` blocks, the
    // capturer itself is not `Send` across the boundary, and no one else may
    // hold a reference to it while it blocks.
    let pump_state = Arc::clone(state);
    let (msg_tx, msg_rx) = std::sync::mpsc::channel::<PumpMsg>();
    let pump = std::thread::Builder::new()
        .name("restsend-vnc-capture-pump".into())
        .spawn(move || {
            let mut capturer = match build_capturer(display_index, fps, &pump_state) {
                Ok(c) => c,
                Err(e) => {
                    let _ = msg_tx.send(PumpMsg::Exit(Err(e)));
                    return;
                }
            };
            let [w, h] = capturer.get_output_frame_size();
            if msg_tx.send(PumpMsg::Started(w, h)).is_err() {
                return;
            }
            capturer.start_capture();
            let _ = msg_tx.send(PumpMsg::Exit(pump_loop(&mut capturer, &pump_state)));
        })
        .map_err(CaptureError::Engine)?;

    // Wait for the engine to come up.
    let dims = match msg_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(PumpMsg::Started(w, h)) => (w, h),
        Ok(PumpMsg::Exit(Err(e))) => {
            let _ = pump.join();
            return Err(CaptureError::Engine(e));
        }
        Ok(PumpMsg::Exit(Ok(()))) => {
            let _ = pump.join();
            return Ok(());
        }
        Err(_) => {
            let _ = pump.join();
            return Err(CaptureError::Engine(io::Error::other(
                "capture pump thread panicked",
            )));
        }
    };
    tracing::info!("capturing display {display_index} ({}x{})", dims.0, dims.1);

    // Parent: supervises the pump — detects a dead engine and a capturer that
    // never produces its first frame (the pump would otherwise block in
    // `get_next_frame` forever, and viewers would stare at a blank screen).
    let started = Instant::now();
    let mut generation_before = state.generation();
    let mut stale_warned = false;
    let result = loop {
        if state.is_stopped() {
            break Ok(());
        }
        match msg_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(PumpMsg::Exit(Ok(()))) => break Ok(()), // pump stopped cleanly
            Ok(PumpMsg::Exit(Err(e))) if e.kind() == io::ErrorKind::WouldBlock => {
                break Err(CaptureError::ResolutionChange);
            }
            Ok(PumpMsg::Exit(Err(e))) => break Err(CaptureError::Engine(e)),
            Ok(PumpMsg::Started(..)) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break Err(CaptureError::Engine(io::Error::other(
                    "capture pump thread panicked",
                )));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if state.generation() != generation_before {
                    // frames are flowing; reset the stale clock
                    generation_before = state.generation();
                    continue;
                }
                if started.elapsed() > FIRST_FRAME_TIMEOUT && !stale_warned {
                    stale_warned = true;
                    tracing::error!(
                        "no frames {}s after capture start; hints: rvnc must run in an \
                         interactive desktop session (not a service/SSH session), \
                         Windows 10 1903+ is required, and the --display index must exist",
                        FIRST_FRAME_TIMEOUT.as_secs()
                    );
                    // Keep waiting a while longer in case frames come late;
                    // the outer loop counts consecutive stale starts and
                    // gives up after {MAX_STALE_STARTS}.
                    if started.elapsed() > FIRST_FRAME_TIMEOUT * 4 {
                        break Err(CaptureError::Engine(io::Error::other(
                            "no frames ever captured (stale)",
                        )));
                    }
                }
            }
        }
    };

    let _ = pump.join();
    result
}

/// Owns the capturer; publishes frames until stop / engine death / size change.
fn pump_loop(capturer: &mut Capturer, state: &Arc<ScreenState>) -> io::Result<()> {
    let mut expected_dims: Option<(u32, u32)> = None;
    loop {
        if state.is_stopped() {
            capturer.stop_capture();
            return Ok(());
        }

        let frame = capturer.get_next_frame().map_err(io::Error::other)?;

        let ScapFrame::BGRA(bgra) = frame else {
            continue;
        };
        let (w, h) = (bgra.width.max(0) as u32, bgra.height.max(0) as u32);
        if w == 0 || h == 0 {
            continue; // Idle frame placeholder from the engine
        }
        if Some((w, h)) != expected_dims && expected_dims.is_some() {
            // Display resolution changed -> let the supervisor rebuild us.
            tracing::info!(
                "display resolution changed to {}x{}, rebuilding capturer",
                w,
                h
            );
            capturer.stop_capture();
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "resolution change"));
        }
        let want = w as usize * h as usize * 4;
        if bgra.data.len() == want {
            // Take the capture buffer directly: `Frame::new` would zero a
            // fresh 4K buffer (33 MB) just before it is overwritten.
            let out = Frame {
                width: w,
                height: h,
                bgra: bgra.data,
            };
            state.publish_capture(out);
            if expected_dims.is_none() {
                tracing::info!("first frame captured ({}x{})", w, h);
            }
            expected_dims = Some((w, h));
        } else {
            tracing::debug!(
                "skipping malformed frame {}x{} ({} bytes, want {})",
                w,
                h,
                bgra.data.len(),
                want
            );
        }
    }
}
