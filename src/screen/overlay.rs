//! `--debug` statistics overlay, composited into the framebuffer's
//! bottom-right corner with a frosted-glass panel (blurred backdrop + tint).

use super::font;
use crate::framebuffer::Frame;

const TINT: [u8; 4] = [34, 28, 24, 255]; // BGRA dark slate
const FG: [u8; 4] = [238, 238, 238, 255];
const ACCENT: [u8; 4] = [120, 255, 140, 255];
const BORDER: [u8; 4] = [90, 96, 92, 255];

pub fn draw(frame: &mut Frame, lines: &[String]) {
    if lines.is_empty() || frame.width < 200 || frame.height < 80 {
        return;
    }
    let scale = (frame.height / 360).clamp(1, 3);
    let line_h = 9 * scale;
    let pad = 8 * scale;
    let text_w = lines
        .iter()
        .map(|l| font::text_width(l, scale))
        .max()
        .unwrap_or(0);
    let w = text_w + pad * 2;
    let h = lines.len() as u32 * line_h + pad * 2 - 2 * scale;
    let x = frame.width.saturating_sub(w + pad);
    let y = frame.height.saturating_sub(h + pad);

    frost(frame, x, y, w, h);
    // Thin border.
    font::fill_rect(frame, x, y, w, scale, BORDER);
    font::fill_rect(frame, x, y + h - scale, w, scale, BORDER);
    font::fill_rect(frame, x, y, scale, h, BORDER);
    font::fill_rect(frame, x + w - scale, y, scale, h, BORDER);

    for (i, line) in lines.iter().enumerate() {
        let color = if i == 0 { ACCENT } else { FG };
        font::draw_text(
            frame,
            x + pad,
            y + pad + i as u32 * line_h,
            line,
            scale,
            color,
        );
    }
}

/// Blurs the backdrop under the panel and blends a dark translucent tint.
fn frost(frame: &mut Frame, x: u32, y: u32, w: u32, h: u32) {
    let stride = frame.stride();
    let x0 = x.min(frame.width) as usize;
    let x1 = (x + w).min(frame.width) as usize;
    let y0 = y.min(frame.height) as usize;
    let y1 = (y + h).min(frame.height) as usize;
    let rw = x1.saturating_sub(x0);
    let rh = y1.saturating_sub(y0);
    if rw < 2 || rh < 2 {
        return;
    }

    let mut buf = vec![0u8; rw * rh * 4];
    for yy in 0..rh {
        let src = &frame.bgra[(y0 + yy) * stride + x0 * 4..][..rw * 4];
        buf[yy * rw * 4..(yy + 1) * rw * 4].copy_from_slice(src);
    }

    // Two separable box-blur passes (radius 2) approximate frosted glass.
    let r = 2isize;
    let mut tmp = vec![0u8; buf.len()];
    for _ in 0..2 {
        // horizontal: buf -> tmp
        for yy in 0..rh {
            for xx in 0..rw {
                let lo = (xx as isize - r).max(0) as usize;
                let hi = ((xx as isize + r) as usize).min(rw - 1);
                let (mut b, mut g, mut rr) = (0u32, 0u32, 0u32);
                for k in lo..=hi {
                    let p = (yy * rw + k) * 4;
                    b += buf[p] as u32;
                    g += buf[p + 1] as u32;
                    rr += buf[p + 2] as u32;
                }
                let n = (hi - lo + 1) as u32;
                let p = (yy * rw + xx) * 4;
                tmp[p] = (b / n) as u8;
                tmp[p + 1] = (g / n) as u8;
                tmp[p + 2] = (rr / n) as u8;
                tmp[p + 3] = 255;
            }
        }
        // vertical: tmp -> buf
        for yy in 0..rh {
            let lo = (yy as isize - r).max(0) as usize;
            let hi = ((yy as isize + r) as usize).min(rh - 1);
            for xx in 0..rw {
                let (mut b, mut g, mut rr) = (0u32, 0u32, 0u32);
                for k in lo..=hi {
                    let p = (k * rw + xx) * 4;
                    b += tmp[p] as u32;
                    g += tmp[p + 1] as u32;
                    rr += tmp[p + 2] as u32;
                }
                let n = (hi - lo + 1) as u32;
                let p = (yy * rw + xx) * 4;
                buf[p] = (b / n) as u8;
                buf[p + 1] = (g / n) as u8;
                buf[p + 2] = (rr / n) as u8;
                buf[p + 3] = 255;
            }
        }
    }

    // Blend: 40% blurred backdrop + 60% dark tint.
    for p in (0..buf.len()).step_by(4) {
        for c in 0..3 {
            buf[p + c] = ((buf[p + c] as u32 * 2 + TINT[c] as u32 * 3) / 5) as u8;
        }
        buf[p + 3] = 255;
    }

    for yy in 0..rh {
        let dst = &mut frame.bgra[(y0 + yy) * stride + x0 * 4..][..rw * 4];
        dst.copy_from_slice(&buf[yy * rw * 4..(yy + 1) * rw * 4]);
    }
}
