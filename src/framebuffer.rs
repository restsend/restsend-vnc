//! Shared screen state: the latest BGRA8 frame published by the capture
//! thread, plus an optional cached cursor shape (Windows).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use rayon::prelude::*;

use crate::cursor::{CursorShape, CursorSnapshot, CursorStore};

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
        let nwu = nw as usize;
        let nhu = nh as usize;
        let fill_row = |dy: usize, dst: &mut [u8]| {
            let y0 = dy * sh / nhu;
            let y1 = (((dy + 1) * sh + nhu - 1) / nhu).clamp(y0 + 1, sh);
            for dx in 0..nwu {
                let x0 = dx * sw / nwu;
                let x1 = (((dx + 1) * sw + nwu - 1) / nwu).clamp(x0 + 1, sw);
                let (mut b, mut g, mut r) = (0u32, 0u32, 0u32);
                let mut n = 0u32;
                for y in y0..y1 {
                    let src = &self.bgra[y * istride..];
                    for x in x0..x1 {
                        let px = &src[x * 4..x * 4 + 4];
                        b += px[0] as u32;
                        g += px[1] as u32;
                        r += px[2] as u32;
                        n += 1;
                    }
                }
                let o = dx * 4;
                dst[o] = (b / n) as u8;
                dst[o + 1] = (g / n) as u8;
                dst[o + 2] = (r / n) as u8;
                dst[o + 3] = 255;
            }
        };
        if nhu >= 64 && nwu * nhu >= 256 * 1024 {
            out.bgra
                .par_chunks_mut(ostride)
                .enumerate()
                .for_each(|(dy, dst)| fill_row(dy, dst));
        } else {
            for (dy, dst) in out.bgra.chunks_mut(ostride).enumerate() {
                fill_row(dy, dst);
            }
        }
        out
    }

    pub fn dims(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Copies `rect` from `src` into `self` (used to keep unsent regions
    /// "pending" in a session's cached frame).
    /// Copies an axis-aligned sub-rectangle into a new tightly packed frame.
    /// Coordinates are clamped; the result may therefore be smaller than
    /// requested (but is never empty for a non-empty intersection).
    pub fn subframe(&self, x: u32, y: u32, w: u32, h: u32) -> Frame {
        let x = x.min(self.width);
        let y = y.min(self.height);
        let w = w.min(self.width.saturating_sub(x));
        let h = h.min(self.height.saturating_sub(y));
        let mut out = Frame::new(w, h);
        if w == 0 || h == 0 {
            return out;
        }
        let (sw, dw) = (self.stride(), out.stride());
        for row in 0..h as usize {
            let s = (y as usize + row) * sw + x as usize * 4;
            let d = row * dw;
            out.bgra[d..d + w as usize * 4].copy_from_slice(&self.bgra[s..s + w as usize * 4]);
        }
        out
    }

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
    /// Startup colour level (live value comes from `settings::COLOR_LEVEL`).
    #[allow(dead_code)]
    color_level: u8,
    /// Downscale factor applied before publishing (1.0 = native).
    scale: f32,
    /// Draw the statistics overlay (`--debug`).
    debug: AtomicBool,
    stats: Mutex<DebugStats>,
    /// Client address shown in the overlay.
    peer: Mutex<String>,
    client_info: Mutex<String>,
    cursor_mode: Mutex<String>,
    /// Process CPU percent (x10) and resident memory (KB), sampled once/s.
    cpu_x10: AtomicU64,
    rss_kb: AtomicU64,
    /// Server process start and current session start (overlay uptime).
    started: Instant,
    session_start: Mutex<Option<Instant>>,
    /// Visual input feedback for the test-pattern demo: last pointer/button
    /// state seen from a client and a keypress counter.
    pub echo: Mutex<EchoState>,
    /// Current system cursor (shape, position, visibility), shared by all
    /// sessions. WGC no longer burns the pointer into the captured frame.
    cursor: Mutex<CursorStore>,
    cursor_generation: AtomicU64,
    /// Physical screen rect of the captured display, used to map
    /// `GetCursorPos` coordinates into framebuffer coordinates.
    cursor_map: Mutex<Option<(i32, i32, u32, u32)>>,
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
    // BGRA little-endian: 0xAARRGGBB. One AND per pixel (vectorises well).
    let mask: u32 = match level {
        8 => 0xFFE0_E0C0,  // R 3 bits, G 3 bits, B 2 bits
        16 => 0xFFF8_FCF8, // R 5 bits, G 6 bits, B 5 bits
        _ => return,
    };
    let pass = |row: &mut [u8]| {
        for px in row.chunks_exact_mut(4) {
            let v = u32::from_ne_bytes([px[0], px[1], px[2], px[3]]) & mask;
            px.copy_from_slice(&v.to_ne_bytes());
        }
    };
    if frame.bgra.len() >= 1 << 20 {
        let stride = frame.stride();
        frame.bgra.par_chunks_mut(stride).for_each(|row| pass(row));
    } else {
        pass(&mut frame.bgra);
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
            cursor_mode: Mutex::new(String::from("-")),
            cpu_x10: AtomicU64::new(0),
            rss_kb: AtomicU64::new(0),
            started: Instant::now(),
            session_start: Mutex::new(None),
            echo: Mutex::new(EchoState::default()),
            cursor: Mutex::new(CursorStore::default()),
            cursor_generation: AtomicU64::new(0),
            cursor_map: Mutex::new(None),
        }
    }

    /// Latest cursor state. Cheap: the shape is behind an `Arc`.
    pub fn cursor_snapshot(&self) -> CursorSnapshot {
        self.cursor.lock().unwrap().snapshot()
    }

    pub fn cursor_generation(&self) -> u64 {
        self.cursor_generation.load(Ordering::Relaxed)
    }

    pub fn set_cursor_shape(&self, shape: Option<Arc<CursorShape>>) {
        if self.cursor.lock().unwrap().set_shape(shape) {
            // The pusher also waits on this counter, so a shape change wakes
            // it even when the desktop itself is static.
            self.cursor_generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn set_cursor_pos(&self, x: u16, y: u16) {
        if self.cursor.lock().unwrap().set_pos(x, y) {
            self.cursor_generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn set_cursor_visible(&self, visible: bool) {
        if self.cursor.lock().unwrap().set_visible(visible) {
            self.cursor_generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Physical rect of the captured monitor (virtual-screen coordinates).
    pub fn set_cursor_map(&self, x: i32, y: i32, w: u32, h: u32) {
        if w > 0 && h > 0 {
            *self.cursor_map.lock().unwrap() = Some((x, y, w, h));
        }
    }

    /// Maps a physical screen point to framebuffer coordinates (accounting
    /// for `--scale` and multi-monitor origins). Returns None until the first
    /// frame and monitor rect are known.
    pub fn map_screen_point(&self, sx: i32, sy: i32) -> Option<(u16, u16)> {
        let (ox, oy, mw, mh) = (*self.cursor_map.lock().unwrap())?;
        let (fw, fh) = {
            let frame = self.frame.read().unwrap();
            (frame.width, frame.height)
        };
        if fw == 0 || fh == 0 {
            return None;
        }
        let x = (sx as i64 - ox as i64) * fw as i64 / mw as i64;
        let y = (sy as i64 - oy as i64) * fh as i64 / mh as i64;
        if x < 0 || y < 0 || x >= fw as i64 || y >= fh as i64 {
            return None;
        }
        Some((x as u16, y as u16))
    }

    /// Downscale factor applied to the framebuffer (1.0 = native).
    pub fn scale(&self) -> f32 {
        self.scale
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
        // Colour level is read live from settings so changes in the tray take
        // effect immediately (and survive reconnects).
        let level = crate::settings::COLOR_LEVEL.load(Ordering::Relaxed);
        quantize(&mut frame, level);
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
                format!(
                    "CLI {}  CUR {}",
                    self.client_info.lock().unwrap(),
                    self.cursor_mode.lock().unwrap()
                ),
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

    /// Shows how the pointer is delivered (`client` pseudo-encoding or
    /// `composited` by the server) in the debug overlay.
    pub fn set_cursor_mode(&self, mode: &str) {
        *self.cursor_mode.lock().unwrap() = mode.to_string();
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
        // Throttle the capture side to --fps. Windows.Graphics.Capture emits
        // frames on every screen change and can exceed the requested rate
        // (e.g. 50-120 fps while dragging); dropping the excess here keeps
        // CAP <= --fps and avoids quantise/lock/wakeup work for frames the
        // pusher would never send anyway.
        if !self.throttle_open() {
            return;
        }
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

    #[test]
    fn subframe_matches_copy_region() {
        let mut src = Frame::new(8, 6);
        for (i, px) in src.bgra.chunks_exact_mut(4).enumerate() {
            px.copy_from_slice(&[(i % 251) as u8, (i / 3 % 241) as u8, 7, 255]);
        }
        let sub = src.subframe(2, 1, 4, 3);
        assert_eq!((sub.width, sub.height), (4, 3));
        for y in 0..3usize {
            for x in 0..4usize {
                let s = ((y + 1) * 8 + x + 2) * 4;
                let d = (y * 4 + x) * 4;
                assert_eq!(&sub.bgra[d..d + 4], &src.bgra[s..s + 4]);
            }
        }
        // Clamping never panics and never produces an oversized frame.
        let clamped = src.subframe(6, 5, 100, 100);
        assert_eq!((clamped.width, clamped.height), (2, 1));
    }

    #[test]
    fn quantize_parallel_path_is_idempotent() {
        // 512x512x4 == 1 MiB, which selects the rayon path.
        let mut frame = Frame::new(512, 512);
        for (i, px) in frame.bgra.chunks_exact_mut(4).enumerate() {
            px.copy_from_slice(&[
                (i % 256) as u8,
                (i * 7 % 256) as u8,
                (i * 13 % 256) as u8,
                255,
            ]);
        }
        quantize(&mut frame, 16);
        let mask: u32 = 0xFFF8_FCF8;
        for px in frame.bgra.chunks_exact(4) {
            let v = u32::from_ne_bytes([px[0], px[1], px[2], px[3]]);
            assert_eq!(v & !mask, 0);
        }
        // A second pass must not change anything (mask is idempotent).
        let before = frame.bgra.clone();
        quantize(&mut frame, 16);
        assert_eq!(frame.bgra, before);
    }

    fn resize_reference(src: &Frame, scale: f32) -> Frame {
        let nw = ((src.width as f32 * scale).round() as u32).max(2);
        let nh = ((src.height as f32 * scale).round() as u32).max(2);
        let (sw, sh) = (src.width as usize, src.height as usize);
        let mut out = Frame::new(nw, nh);
        let istride = src.stride();
        let ostride = out.stride();
        for dy in 0..nh as usize {
            let y0 = dy * sh / nh as usize;
            let y1 = (((dy + 1) * sh + nh as usize - 1) / nh as usize).clamp(y0 + 1, sh);
            for dx in 0..nw as usize {
                let x0 = dx * sw / nw as usize;
                let x1 = (((dx + 1) * sw + nw as usize - 1) / nw as usize).clamp(x0 + 1, sw);
                let (mut b, mut g, mut r) = (0u32, 0u32, 0u32);
                let mut n = 0u32;
                for y in y0..y1 {
                    for x in x0..x1 {
                        let o = y * istride + x * 4;
                        b += src.bgra[o] as u32;
                        g += src.bgra[o + 1] as u32;
                        r += src.bgra[o + 2] as u32;
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

    #[test]
    fn resized_parallel_matches_reference() {
        let mut src = Frame::new(1024, 1024);
        for y in 0..1024usize {
            for x in 0..1024usize {
                let o = y * src.stride() + x * 4;
                src.bgra[o..o + 4].copy_from_slice(&[x as u8, y as u8, (x ^ y) as u8, 255]);
            }
        }
        let expected = resize_reference(&src, 0.5);
        let got = src.resized(0.5);
        assert_eq!(got.dims(), expected.dims());
        assert_eq!(got.bgra, expected.bgra);
    }
}
