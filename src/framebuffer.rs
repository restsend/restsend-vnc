//! Shared screen state: the latest BGRA8 frame published by the capture
//! thread, plus an optional cached cursor shape (Windows).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

/// One framebuffer frame in BGRA8 layout (bytes per pixel: B, G, R, X),
/// tightly packed (stride == width * 4).
#[derive(Clone)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub bgra: Vec<u8>,
}

impl Frame {
    pub fn new(width: u32, height: u32) -> Self {
        Frame {
            width,
            height,
            bgra: vec![0u8; width as usize * height as usize * 4],
        }
    }

    pub fn stride(&self) -> usize {
        self.width as usize * 4
    }

    /// Area-averaging downscale (keeps text legible at 0.5x/0.75x).
    pub fn resized(&self, scale: f32) -> Frame {
        let nw = ((self.width as f32 * scale).round() as u32).max(2);
        let nh = ((self.height as f32 * scale).round() as u32).max(2);
        if nw >= self.width || nh >= self.height {
            return self.clone();
        }
        let sw = self.width as usize;
        let sh = self.height as usize;
        let mut out = Frame::new(nw, nh);
        let ostride = out.stride();
        let istride = self.stride();
        for dy in 0..nh as usize {
            let y0 = dy * sh / nh as usize;
            let y1 = (((dy + 1) * sh + nh as usize - 1) / nh as usize).clamp(y0 + 1, sh);
            for dx in 0..nw as usize {
                let x0 = dx * sw / nw as usize;
                let x1 = (((dx + 1) * sw + nw as usize - 1) / nw as usize).clamp(x0 + 1, sw);
                let (mut b, mut g, mut r) = (0u32, 0u32, 0u32);
                let mut n = 0u32;
                for y in y0..y1 {
                    let row = &self.bgra[y * istride..];
                    for x in x0..x1 {
                        let px = &row[x * 4..x * 4 + 4];
                        b += px[0] as u32;
                        g += px[1] as u32;
                        r += px[2] as u32;
                        n += 1;
                    }
                }
                let o = dy * ostride + dx * 4;
                out.bgra[o] = (b / n) as u8;
                out.bgra[o + 1] = (g / n) as u8;
                out.bgra[o + 2] = (r / n) as u8;
                out.bgra[o + 3] = 255;
            }
        }
        out
    }

    pub fn dims(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Copies `rect` from `src` into `self` (used to keep unsent regions
    /// "pending" in a session's cached frame).
    pub fn copy_region(&mut self, src: &Frame, x: u32, y: u32, w: u32, h: u32) {
        if self.dims() != src.dims() {
            return;
        }
        let w = w.min(self.width.saturating_sub(x));
        let h = h.min(self.height.saturating_sub(y));
        if w == 0 || h == 0 {
            return;
        }
        let (sw, dw) = (src.stride(), self.stride());
        for row in 0..h as usize {
            let s = ((y as usize + row) * sw) + x as usize * 4;
            let d = ((y as usize + row) * dw) + x as usize * 4;
            self.bgra[d..d + w as usize * 4].copy_from_slice(&src.bgra[s..s + w as usize * 4]);
        }
    }
}

/// State shared between the capture thread and all client sessions.
pub struct ScreenState {
    frame: RwLock<Arc<Frame>>,
    generation: AtomicU64,
    /// Frames published by the real capture backend (not the lock notice).
    capture_generation: AtomicU64,
    pub stop: Arc<AtomicBool>,
    last_publish_ms: AtomicU64,
    /// Maximum publish rate (frames per second).
    pub max_fps: u32,
    /// Colour level (8/16/24) applied to every published frame.
    color_level: u8,
    /// Downscale factor applied before publishing (1.0 = native).
    scale: f32,
    /// Draw the statistics overlay (`--debug`).
    debug: AtomicBool,
    stats: Mutex<DebugStats>,
    /// Client address shown in the overlay.
    peer: Mutex<String>,
    client_info: Mutex<String>,
    /// Process CPU percent (x10) and resident memory (KB), sampled once/s.
    cpu_x10: AtomicU64,
    rss_kb: AtomicU64,
    /// Server process start and current session start (overlay uptime).
    started: Instant,
    session_start: Mutex<Option<Instant>>,
    /// Visual input feedback for the test-pattern demo: last pointer/button
    /// state seen from a client and a keypress counter.
    pub echo: Mutex<EchoState>,
}

fn fmt_hms(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Masks colour channels to the requested depth. BGRA byte order.
fn quantize(frame: &mut Frame, level: u8) {
    match level {
        8 => {
            for px in frame.bgra.chunks_exact_mut(4) {
                px[0] &= 0xC0; // B: 2 bits
                px[1] &= 0xE0; // G: 3 bits
                px[2] &= 0xE0; // R: 3 bits
            }
        }
        16 => {
            for px in frame.bgra.chunks_exact_mut(4) {
                px[0] &= 0xF8; // B: 5 bits
                px[1] &= 0xFC; // G: 6 bits
                px[2] &= 0xF8; // R: 5 bits
            }
        }
        _ => {}
    }
}

/// Statistics shown by the `--debug` overlay.
#[derive(Clone, Default)]
pub struct DebugStats {
    pub cap_fps: f32,
    pub push_fps: f32,
    pub kb_s: f32,
    pub enc_ms: f32,
    pub drops: u64,
    pub last_capture: Option<Instant>,
}

/// Demo-mode input echo (rendered by the test-pattern source).
#[derive(Clone, Default)]
pub struct EchoState {
    pub pointer: (u32, u32),
    pub buttons: u8,
    pub key_tick: u64,
    #[allow(dead_code)]
    pub last_keysym: u32,
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl ScreenState {
    pub fn new(max_fps: u32) -> Self {
        Self::with_color_level(max_fps, 24)
    }

    /// `color_level` is 8 (3-3-2), 16 (5-6-5) or 24 (full colour).
    pub fn with_color_level(max_fps: u32, color_level: u8) -> Self {
        Self::with_options(max_fps, color_level, 1.0)
    }

    pub fn with_options(max_fps: u32, color_level: u8, scale: f32) -> Self {
        ScreenState {
            frame: RwLock::new(Arc::new(Frame::new(0, 0))),
            generation: AtomicU64::new(0),
            capture_generation: AtomicU64::new(0),
            stop: Arc::new(AtomicBool::new(false)),
            last_publish_ms: AtomicU64::new(0),
            max_fps: max_fps.max(1),
            color_level,
            scale: scale.clamp(0.25, 1.0),
            debug: AtomicBool::new(false),
            stats: Mutex::new(DebugStats::default()),
            peer: Mutex::new(String::from("-")),
            client_info: Mutex::new(String::from("-")),
            cpu_x10: AtomicU64::new(0),
            rss_kb: AtomicU64::new(0),
            started: Instant::now(),
            session_start: Mutex::new(None),
            echo: Mutex::new(EchoState::default()),
        }
    }

    /// Records a client pointer event for the test-pattern echo display.
    pub fn echo_pointer(&self, x: u16, y: u16, buttons: u8) {
        let mut echo = self.echo.lock().unwrap();
        echo.pointer = (x as u32, y as u32);
        echo.buttons = buttons;
    }

    /// Records a client key event for the test-pattern echo display.
    pub fn echo_key(&self, keysym: u32, down: bool) {
        let mut echo = self.echo.lock().unwrap();
        echo.last_keysym = keysym;
        if down {
            echo.key_tick = echo.key_tick.wrapping_add(1);
        }
    }

    /// Minimum interval between published frames (ms) — derived from `--fps`.
    #[allow(dead_code)]
    pub fn min_frame_interval_ms(&self) -> u64 {
        (1000 / self.max_fps.max(1)) as u64
    }

    /// True when the fps throttle window allows a publish right now.
    #[allow(dead_code)]
    pub fn throttle_open(&self) -> bool {
        let last = self.last_publish_ms.load(Ordering::Relaxed);
        last == 0 || now_millis() >= last + (1000 / self.max_fps.max(1)) as u64
    }

    pub fn publish(&self, mut frame: Frame) {
        self.last_publish_ms.store(now_millis(), Ordering::Relaxed);
        if self.scale < 0.999 {
            frame = frame.resized(self.scale);
        }
        quantize(&mut frame, self.color_level);
        if self.debug.load(Ordering::Relaxed) {
            let st = self.stats.lock().unwrap().clone();
            let peer = self.peer.lock().unwrap().clone();
            let cpu = self.cpu_x10.load(Ordering::Relaxed) as f32 / 10.0;
            let rss = self.rss_kb.load(Ordering::Relaxed) as f32 / 1024.0;
            let now = chrono::Local::now().format("%H:%M:%S");
            let lines = vec![
                format!("{now}  {peer}"),
                format!("CAP {:.1} PUSH {:.1}", st.cap_fps, st.push_fps),
                format!("TX {:.0}KB/S ENC {:.1}MS", st.kb_s, st.enc_ms),
                format!("DROP {} CPU {:.0}% MEM {:.0}MB", st.drops, cpu, rss),
                format!(
                    "SRV {} {}",
                    env!("CARGO_PKG_VERSION"),
                    &env!("BUILD_TIME").chars().take(16).collect::<String>()
                ),
                format!("CLI {}", self.client_info.lock().unwrap()),
                format!(
                    "UP {}  SES {}",
                    fmt_hms(self.started.elapsed().as_secs()),
                    fmt_hms(
                        self.session_start
                            .lock()
                            .unwrap()
                            .map(|t| t.elapsed().as_secs())
                            .unwrap_or(0)
                    )
                ),
            ];
            crate::screen::overlay::draw(&mut frame, &lines);
        }
        *self.frame.write().unwrap() = Arc::new(frame);
        self.generation.fetch_add(1, Ordering::Relaxed);
    }
    pub fn set_debug(&self, on: bool) {
        self.debug.store(on, Ordering::Relaxed);
    }

    /// Toggles the stats overlay and returns the new state.
    pub fn toggle_debug(&self) -> bool {
        let on = !self.debug.load(Ordering::Relaxed);
        self.debug.store(on, Ordering::Relaxed);
        on
    }

    pub fn set_peer(&self, peer: String) {
        *self.peer.lock().unwrap() = peer;
        *self.session_start.lock().unwrap() = Some(Instant::now());
    }

    pub fn set_client_info(&self, info: String) {
        *self.client_info.lock().unwrap() = info;
    }

    pub fn clear_session(&self) {
        *self.session_start.lock().unwrap() = None;
    }

    pub fn set_sys_stats(&self, cpu_pct: f32, rss_mb: f32) {
        self.cpu_x10
            .store((cpu_pct.max(0.0) * 10.0) as u64, Ordering::Relaxed);
        self.rss_kb
            .store((rss_mb.max(0.0) * 1024.0) as u64, Ordering::Relaxed);
    }

    /// Called by the pusher roughly once per second.
    pub fn set_push_stats(&self, push_fps: f32, kb_s: f32, enc_ms: f32, drops: u64) {
        let mut st = self.stats.lock().unwrap();
        st.push_fps = push_fps;
        st.kb_s = kb_s;
        st.enc_ms = enc_ms;
        st.drops = drops;
    }

    /// Publishes a frame coming from the real capture backend. The lock
    /// watchdog checks this counter to tell "capture is alive" from "capture
    /// stalled because the desktop is locked".
    pub fn publish_capture(&self, frame: Frame) {
        self.capture_generation.fetch_add(1, Ordering::Relaxed);
        {
            let mut st = self.stats.lock().unwrap();
            let now = Instant::now();
            if let Some(last) = st.last_capture {
                let dt = now.duration_since(last).as_secs_f32();
                if dt > 1e-4 {
                    let inst = 1.0 / dt;
                    st.cap_fps = if st.cap_fps <= 0.0 {
                        inst
                    } else {
                        st.cap_fps * 0.9 + inst * 0.1
                    };
                }
            }
            st.last_capture = Some(now);
        }
        self.publish(frame);
    }

    /// Number of real capture frames published so far.
    pub fn capture_generation(&self) -> u64 {
        self.capture_generation.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> Arc<Frame> {
        self.frame.read().unwrap().clone()
    }

    /// Monotonic counter of published frames (used by the capture watchdog).
    #[allow(dead_code)]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_region() {
        let mut dst = Frame::new(4, 2);
        let mut src = Frame::new(4, 2);
        // paint a red pixel at (1,1) in src
        let idx = (4 + 1) * 4; // pixel (1,1) on a 4-wide frame
        src.bgra[idx..idx + 4].copy_from_slice(&[0, 0, 255, 255]);
        dst.copy_region(&src, 0, 0, 4, 2);
        assert_eq!(&dst.bgra[idx..idx + 4], &[0, 0, 255, 255]);
        // partial region copy
        let mut dst2 = Frame::new(4, 2);
        dst2.copy_region(&src, 1, 1, 2, 1);
        assert_eq!(&dst2.bgra[idx..idx + 4], &[0, 0, 255, 255]);
        let other = idx + 4;
        assert_eq!(&dst2.bgra[other..other + 4], &[0, 0, 0, 0]);
    }
}
