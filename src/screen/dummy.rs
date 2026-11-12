//! Synthetic animated test pattern — no permissions required, used for
//! protocol debugging (`--test-pattern`) and CI.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::framebuffer::{Frame, ScreenState};

const WIDTH: u32 = 1280;
const HEIGHT: u32 = 720;

pub fn spawn(fps: u32, state: Arc<ScreenState>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("restsend-vnc-dummy-capture".into())
        .spawn(move || run(fps, state))
        .expect("spawn dummy capture thread")
}

fn run(fps: u32, state: Arc<ScreenState>) {
    let mut frame = Frame::new(WIDTH, HEIGHT);
    let frame_period = Duration::from_millis(1000 / fps.max(1) as u64);
    let start = Instant::now();
    let mut frame_no: u64 = 0;

    state.publish_capture(frame.clone());
    while !state.is_stopped() {
        let now = Instant::now();
        let echo = state.echo.lock().unwrap().clone();
        render(
            &mut frame,
            now.duration_since(start).as_secs_f64(),
            frame_no,
            &echo,
        );
        state.publish_capture(frame.clone());
        frame_no += 1;
        let elapsed = now.elapsed();
        if elapsed < frame_period {
            std::thread::sleep(frame_period - elapsed);
        }
    }
}

fn render(frame: &mut Frame, t: f64, frame_no: u64, echo: &crate::framebuffer::EchoState) {
    let (w, h) = (frame.width as usize, frame.height as usize);
    let stride = frame.stride();
    let t = t as f32;

    // Moving color wash + checkerboard grid + bouncing box.
    let phase = (t * 0.5) as usize;
    let bx = ((t * 220.0) as usize) % (w - 160).max(1);
    let by = ((t * 140.0) as usize) % (h - 120).max(1);

    for y in 0..h {
        let row = &mut frame.bgra[y * stride..y * stride + w * 4];
        for x in 0..w {
            let px = &mut row[x * 4..x * 4 + 4];
            let r = ((x / 4 + phase).rotate_right(1) % 256) as u8;
            let g = ((y / 4 + phase) % 256) as u8;
            let b = (((x ^ y) + phase) % 256) as u8;
            let mut color = [b, g, r, 255];
            if (x % 128 == 0) || (y % 128 == 0) {
                color = [255, 255, 255, 255];
            }
            if x >= bx && x < bx + 160 && y >= by && y < by + 120 {
                color = [40, 200, 40, 255];
            }
            px.copy_from_slice(&color);
        }
    }

    // Input echo: crosshair at the last pointer position, a red square while a
    // button is held, and a key-tick indicator strip in the top-left corner.
    let (px, py) = (echo.pointer.0 as usize, echo.pointer.1 as usize);
    if px < w && py < h {
        for x in 0..w {
            let off = py * stride + x * 4;
            frame.bgra[off..off + 4].copy_from_slice(&[255, 255, 0, 255]);
        }
        for y in 0..h {
            let off = y * stride + px * 4;
            frame.bgra[off..off + 4].copy_from_slice(&[255, 255, 0, 255]);
        }
        if echo.buttons & 0x7 != 0 {
            for dy in -10i32..=10 {
                for dx in -10i32..=10 {
                    let x = px as i32 + dx;
                    let y = py as i32 + dy;
                    if (0..w as i32).contains(&x) && (0..h as i32).contains(&y) {
                        let off = (y as usize) * stride + (x as usize) * 4;
                        frame.bgra[off..off + 4].copy_from_slice(&[0, 0, 220, 255]);
                    }
                }
            }
        }
    }
    // Key-tick strip: one 24px cell per keypress (wraps every 8 presses).
    let cells = (echo.key_tick % 8) as usize;
    for i in 0..cells {
        for dy in 0..24 {
            for dx in 0..24 {
                let off = (dy * stride) + (i * 24 + dx) * 4;
                if off + 4 <= frame.bgra.len() {
                    frame.bgra[off..off + 4].copy_from_slice(&[250, 120, 20, 255]);
                }
            }
        }
    }
    let _ = frame_no;
}
