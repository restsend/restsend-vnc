//! Cursor capture, local composition and RFB cursor pseudo-encodings.
//!
//! Windows.Graphics.Capture can either burn the pointer into the frame (the
//! old behaviour) or exclude it. The latter is what we want on a 4K desktop:
//! moving the pointer no longer forces a full-resolution capture, diff and
//! encode pass just to move a 32x32 sprite.
//!
//! The cursor is handled in one of two ways per session:
//! - the server composites a software cursor into a tiny overlay rectangle and
//!   pushes it at up to 60 Hz. Screen Sharing always uses this path, because
//!   its client leaves trails when it draws a local cursor under rapid full
//!   frame updates;
//! - other viewers can use the Rich Cursor pseudo-encoding (-239): the shape is
//!   sent once and the viewer draws it locally (zero traffic while moving);
//! - Apple's CursorAlpha (1104) is available behind an opt-in test flag.

use std::sync::Arc;

use crate::diff::Rect;
use crate::framebuffer::Frame;
use crate::rfb::messages::{framebuffer_update_header, pseudo, rect_header};
use crate::rfb::pixel::PixelEncoder;

/// A cursor bitmap in straight-alpha BGRA8 (bytes in memory: B, G, R, A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    pub width: u16,
    pub height: u16,
    pub hot_x: u16,
    pub hot_y: u16,
    pub bgra: Vec<u8>,
}

impl CursorShape {
    #[allow(dead_code)]
    pub fn new(width: u16, height: u16, hot_x: u16, hot_y: u16, bgra: Vec<u8>) -> Self {
        debug_assert_eq!(bgra.len(), width as usize * height as usize * 4);
        CursorShape {
            width,
            height,
            hot_x,
            hot_y,
            bgra,
        }
    }

    /// Nearest-neighbour scale used when the framebuffer is downscaled
    /// (`--scale`). Cursor bitmaps are tiny, so this stays cheap.
    pub fn scaled(&self, scale: f32) -> CursorShape {
        if scale >= 0.999 || self.width == 0 || self.height == 0 {
            return self.clone();
        }
        let nw = ((self.width as f32 * scale).round() as u16).max(1);
        let nh = ((self.height as f32 * scale).round() as u16).max(1);
        let mut out = vec![0u8; nw as usize * nh as usize * 4];
        for dy in 0..nh as usize {
            let sy = dy * self.height as usize / nh as usize;
            for dx in 0..nw as usize {
                let sx = dx * self.width as usize / nw as usize;
                let s = (sy * self.width as usize + sx) * 4;
                let d = (dy * nw as usize + dx) * 4;
                out[d..d + 4].copy_from_slice(&self.bgra[s..s + 4]);
            }
        }
        let hot_x = ((self.hot_x as f32 * scale).round() as u16).min(nw.saturating_sub(1));
        let hot_y = ((self.hot_y as f32 * scale).round() as u16).min(nh.saturating_sub(1));
        CursorShape {
            width: nw,
            height: nh,
            hot_x,
            hot_y,
            bgra: out,
        }
    }
}

/// Immutable-ish view of the current cursor handed to sessions.
#[derive(Clone, Default)]
pub struct CursorSnapshot {
    pub shape: Option<Arc<CursorShape>>,
    /// Incremented whenever the shape changes.
    pub shape_serial: u64,
    /// Pointer position in framebuffer coordinates.
    pub x: u16,
    pub y: u16,
    /// Incremented whenever the position changes.
    pub pos_serial: u64,
    pub visible: bool,
    /// Monotonic store generation (shape, position or visibility change).
    pub generation: u64,
}

/// Small mutable store behind `ScreenState`'s cursor mutex.
#[derive(Default)]
pub struct CursorStore {
    snapshot: CursorSnapshot,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    next_shape_serial: u64,
}

impl CursorStore {
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn set_shape(&mut self, shape: Option<Arc<CursorShape>>) -> bool {
        let changed = match (&self.snapshot.shape, &shape) {
            (Some(a), Some(b)) => !Arc::ptr_eq(a, b) && **a != **b,
            (None, None) => false,
            _ => true,
        };
        if changed {
            self.next_shape_serial += 1;
            self.snapshot.shape_serial = self.next_shape_serial;
            self.snapshot.shape = shape;
            self.snapshot.generation += 1;
        }
        changed
    }

    pub fn set_pos(&mut self, x: u16, y: u16) -> bool {
        if self.snapshot.x == x && self.snapshot.y == y {
            return false;
        }
        self.snapshot.x = x;
        self.snapshot.y = y;
        self.snapshot.pos_serial += 1;
        self.snapshot.generation += 1;
        true
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn set_visible(&mut self, visible: bool) -> bool {
        if self.snapshot.visible == visible {
            return false;
        }
        self.snapshot.visible = visible;
        self.snapshot.generation += 1;
        true
    }

    pub fn snapshot(&self) -> CursorSnapshot {
        self.snapshot.clone()
    }
}

/// Rectangle covered by the cursor (hotspot included), clamped to the frame.
pub fn cursor_rect(
    shape: &CursorShape,
    x: u16,
    y: u16,
    scale: f32,
    frame_w: u32,
    frame_h: u32,
) -> Option<Rect> {
    if frame_w == 0 || frame_h == 0 {
        return None;
    }
    let shape = shape.scaled(scale);
    let left = x as i32 - shape.hot_x as i32;
    let top = y as i32 - shape.hot_y as i32;
    let right = left + shape.width as i32;
    let bottom = top + shape.height as i32;
    let cx0 = left.max(0);
    let cy0 = top.max(0);
    let cx1 = right.min(frame_w as i32);
    let cy1 = bottom.min(frame_h as i32);
    if cx1 <= cx0 || cy1 <= cy0 {
        return None;
    }
    Some(Rect::new(
        cx0 as u16,
        cy0 as u16,
        (cx1 - cx0) as u16,
        (cy1 - cy0) as u16,
    ))
}

/// Copies `rect` out of `base` and alpha-blends the cursor into it.
pub fn overlay_frame(base: &Frame, rect: Rect, snapshot: &CursorSnapshot, scale: f32) -> Frame {
    let mut out = base.subframe(rect.x as u32, rect.y as u32, rect.w as u32, rect.h as u32);
    if !snapshot.visible {
        return out;
    }
    let Some(shape) = snapshot.shape.as_ref() else {
        return out;
    };
    let shape = shape.scaled(scale);
    let left = snapshot.x as i32 - shape.hot_x as i32;
    let top = snapshot.y as i32 - shape.hot_y as i32;
    let dst_stride = out.stride();

    let x0 = (rect.x as i32).max(left).max(0);
    let y0 = (rect.y as i32).max(top).max(0);
    let x1 = (rect.x as i32 + rect.w as i32)
        .min(left + shape.width as i32)
        .min(base.width as i32);
    let y1 = (rect.y as i32 + rect.h as i32)
        .min(top + shape.height as i32)
        .min(base.height as i32);
    if x1 <= x0 || y1 <= y0 {
        return out;
    }

    let src_w = shape.width as usize;
    for y in y0..y1 {
        let sy = (y - top) as usize;
        for x in x0..x1 {
            let sx = (x - left) as usize;
            let s = (sy * src_w + sx) * 4;
            let a = shape.bgra[s + 3] as u32;
            if a == 0 {
                continue;
            }
            let d = (y - rect.y as i32) as usize * dst_stride + (x - rect.x as i32) as usize * 4;
            if a == 255 {
                out.bgra[d..d + 4].copy_from_slice(&shape.bgra[s..s + 4]);
                continue;
            }
            let ia = 255 - a;
            for c in 0..3 {
                out.bgra[d + c] =
                    ((shape.bgra[s + c] as u32 * a + out.bgra[d + c] as u32 * ia + 127) / 255)
                        as u8;
            }
            out.bgra[d + 3] = 255;
        }
    }
    out
}

/// A FramebufferUpdate carrying the Rich Cursor pseudo-rectangle.
pub fn rich_cursor_message(shape: &CursorShape, enc: &PixelEncoder) -> Vec<u8> {
    let mut out = framebuffer_update_header(1);
    out.extend_from_slice(&rect_header(
        shape.hot_x,
        shape.hot_y,
        shape.width,
        shape.height,
        pseudo::RICH_CURSOR,
    ));
    for px in shape.bgra.as_chunks::<4>().0 {
        enc.push_pixel(&mut out, [px[0], px[1], px[2], px[3]]);
    }
    let mask_stride = (shape.width as usize).div_ceil(8);
    let mut mask = vec![0u8; mask_stride * shape.height as usize];
    for y in 0..shape.height as usize {
        for x in 0..shape.width as usize {
            if shape.bgra[(y * shape.width as usize + x) * 4 + 3] != 0 {
                mask[y * mask_stride + x / 8] |= 0x80 >> (x % 8);
            }
        }
    }
    out.extend_from_slice(&mask);
    out
}

/// Apple CursorAlpha (encoding 1104): a cached BGRA image plus a separate
/// alpha plane, zlib-compressed. Screen Sharing draws this at its local
/// pointer, which avoids the Rich Cursor artifacts some macOS builds show.
pub fn cursor_alpha_message(shape: &CursorShape, cache_id: u32) -> Vec<u8> {
    let w = shape.width as usize;
    let h = shape.height as usize;
    let mut raw = Vec::with_capacity(w * h * 5);
    raw.extend_from_slice(&shape.bgra);
    for px in shape.bgra.as_chunks::<4>().0 {
        raw.push(px[3]);
    }
    // Apple frames this stream with Z_SYNC_FLUSH (no final block), like the
    // pasteboard codec. A complete zlib stream makes Screen Sharing close the
    // session when it inflates the cursor.
    let mut encoder = flate2::Compress::new(flate2::Compression::best(), true);
    let mut compressed = Vec::with_capacity(raw.len() + 128);
    encoder
        .compress_vec(&raw, &mut compressed, flate2::FlushCompress::Sync)
        .expect("in-memory cursor compression");

    let mut out = crate::rfb::messages::framebuffer_update_header(1);
    out.extend_from_slice(&crate::rfb::messages::rect_header(
        shape.hot_x,
        shape.hot_y,
        shape.width,
        shape.height,
        1104,
    ));
    out.extend_from_slice(&cache_id.to_be_bytes());
    out.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    out.extend_from_slice(&compressed);
    out
}

/// A zero-sized Cursor pseudo-rectangle hides the locally drawn cursor.
pub fn hidden_cursor_message() -> Vec<u8> {
    let mut out = framebuffer_update_header(1);
    out.extend_from_slice(&rect_header(0, 0, 0, 0, pseudo::RICH_CURSOR));
    out
}

/// TightVNC PointerPos pseudo-rectangle (position of the local cursor).
pub fn pointer_pos_message(x: u16, y: u16) -> Vec<u8> {
    let mut out = framebuffer_update_header(1);
    out.extend_from_slice(&rect_header(x, y, 0, 0, pseudo::POINTER_POS));
    out
}

// --- Windows cursor polling -------------------------------------------------

/// Polls the system cursor 60 times per second and publishes shape/position.
/// Windows-only; other platforms simply don't call this.
#[cfg(target_os = "windows")]
pub fn spawn_poller(
    state: Arc<crate::framebuffer::ScreenState>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("restsend-vnc-cursor".into())
        .spawn(move || poll_loop(state))
        .map_err(std::io::Error::other)
}

#[cfg(target_os = "windows")]
fn poll_loop(state: Arc<crate::framebuffer::ScreenState>) {
    use windows::Win32::UI::WindowsAndMessaging::{GetCursorInfo, CURSORINFO, CURSOR_SHOWING};

    crate::input::windows::enable_dpi_awareness();

    let mut last_handle = 0isize;
    loop {
        if state.is_stopped() {
            return;
        }
        let mut ci = CURSORINFO {
            cbSize: std::mem::size_of::<CURSORINFO>() as u32,
            ..Default::default()
        };
        if unsafe { GetCursorInfo(&mut ci) }.is_ok() {
            let handle = ci.hCursor.0 as isize;
            if handle != last_handle {
                last_handle = handle;
                let shape = if handle == 0 {
                    None
                } else {
                    unsafe { extract_shape(ci.hCursor) }
                };
                state.set_cursor_shape(shape);
            }
            let showing = ci.flags.0 & CURSOR_SHOWING.0 != 0;
            let mapped = state.map_screen_point(ci.ptScreenPos.x, ci.ptScreenPos.y);
            // A pointer on another monitor is not part of this capture.
            state.set_cursor_visible(showing && mapped.is_some());
            if let Some((x, y)) = mapped {
                state.set_cursor_pos(x, y);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(16));
    }
}

#[cfg(target_os = "windows")]
unsafe fn extract_shape(
    hcursor: windows::Win32::UI::WindowsAndMessaging::HCURSOR,
) -> Option<Arc<CursorShape>> {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::Graphics::Gdi::{
        DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO,
        BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HGDIOBJ,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetIconInfo, ICONINFO};

    let _ = POINT::default;
    let mut ii = ICONINFO::default();
    if GetIconInfo(
        windows::Win32::UI::WindowsAndMessaging::HICON(hcursor.0),
        &mut ii,
    )
    .is_err()
    {
        return None;
    }
    let color = if ii.hbmColor.is_invalid() {
        None
    } else {
        Some(ii.hbmColor)
    };
    let mask = if ii.hbmMask.is_invalid() {
        None
    } else {
        Some(ii.hbmMask)
    };

    let result = (|| {
        let bmp = color.or(mask)?;
        let mut b = BITMAP::default();
        if GetObjectW(
            HGDIOBJ(bmp.0),
            std::mem::size_of::<BITMAP>() as i32,
            Some((&mut b as *mut BITMAP).cast()),
        ) == 0
        {
            return None;
        }
        let mut w = b.bmWidth;
        let mut h = b.bmHeight;
        if color.is_none() {
            // Monochrome cursors store the AND and XOR masks stacked.
            h /= 2;
        }
        if w <= 0 || h <= 0 {
            return None;
        }
        // Ignore absurd sizes; Windows cursors are at most 256x256 today.
        if w > 512 || h > 512 {
            w = w.min(512);
            h = h.min(512);
        }

        let hdc = GetDC(None);
        if hdc.is_invalid() {
            return None;
        }
        let mut bmi = BITMAPINFO::default();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = -h; // top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB.0;
        let mut pixels = vec![0u8; w as usize * h as usize * 4];
        let got = if let Some(c) = color {
            GetDIBits(
                hdc,
                c,
                0,
                h as u32,
                Some(pixels.as_mut_ptr().cast()),
                &mut bmi,
                DIB_RGB_COLORS,
            )
        } else {
            0
        };

        let mut mask_pixels = vec![0u8; w as usize * h as usize * 4];
        let mut got_mask = 0;
        if let Some(m) = mask {
            got_mask = GetDIBits(
                hdc,
                m,
                0,
                h as u32,
                Some(mask_pixels.as_mut_ptr().cast()),
                &mut bmi,
                DIB_RGB_COLORS,
            );
        }
        ReleaseDC(None, hdc);

        if got == 0 && got_mask == 0 {
            return None;
        }

        let has_alpha = got != 0 && pixels.as_chunks::<4>().0.iter().any(|p| p[3] != 0);
        if !has_alpha {
            // Legacy 1-bit cursor: the AND mask says which pixels are opaque.
            for i in 0..(w as usize * h as usize) {
                let transparent = if got_mask != 0 {
                    mask_pixels[i * 4] != 0
                } else {
                    false
                };
                pixels[i * 4 + 3] = if transparent { 0 } else { 255 };
                if got == 0 {
                    // Monochrome: GetDIBits gave us the colour bitmap above;
                    // without one fall back to black.
                    pixels[i * 4..i * 4 + 3].fill(0);
                }
            }
        }
        Some(Arc::new(CursorShape::new(
            w as u16,
            h as u16,
            ii.xHotspot as u16,
            ii.yHotspot as u16,
            pixels,
        )))
    })();

    if let Some(c) = color {
        let _ = DeleteObject(HGDIOBJ(c.0));
    }
    if let Some(m) = mask {
        let _ = DeleteObject(HGDIOBJ(m.0));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::Frame;

    fn shape_2x2() -> CursorShape {
        #[rustfmt::skip]
        let bgra = vec![
            0, 0, 255, 255,   0, 255, 0, 128,
            255, 0, 0, 255,   0, 0, 0, 0,
        ];
        CursorShape::new(2, 2, 0, 0, bgra)
    }

    #[test]
    fn alpha_cursor_payload_shape() {
        let shape = shape_2x2();
        let msg = cursor_alpha_message(&shape, 1234);
        assert_eq!(&msg[0..4], &[0, 0, 0, 1]);
        assert_eq!(i32::from_be_bytes(msg[12..16].try_into().unwrap()), 1104);
        assert_eq!(u32::from_be_bytes(msg[16..20].try_into().unwrap()), 1234);
        let compressed = u32::from_be_bytes(msg[20..24].try_into().unwrap()) as usize;
        assert_eq!(msg.len(), 24 + compressed);
        let mut decoder = flate2::Decompress::new(true);
        let mut raw = Vec::with_capacity(2 * 2 * 5);
        decoder
            .decompress_vec(&msg[24..], &mut raw, flate2::FlushDecompress::None)
            .unwrap();
        assert_eq!(raw.len(), 2 * 2 * 5, "BGRA + alpha plane");
        assert_eq!(&raw[..16], shape.bgra.as_slice());
        assert_eq!(&raw[16..], &[255, 128, 255, 0]);
    }

    #[test]
    fn cursor_rect_clips_at_edges() {
        let shape = shape_2x2();
        assert_eq!(
            cursor_rect(&shape, 5, 5, 1.0, 10, 10),
            Some(Rect::new(5, 5, 2, 2))
        );
        assert_eq!(
            cursor_rect(&shape, 9, 9, 1.0, 10, 10),
            Some(Rect::new(9, 9, 1, 1))
        );
        assert_eq!(cursor_rect(&shape, 0, 0, 1.0, 0, 0), None);
    }

    #[test]
    fn overlay_blends_and_preserves_base_elsewhere() {
        let mut base = Frame::new(4, 4);
        for px in base.bgra.as_chunks_mut::<4>().0 {
            px.copy_from_slice(&[10, 20, 30, 255]);
        }
        let snap = CursorSnapshot {
            shape: Some(Arc::new(shape_2x2())),
            visible: true,
            x: 2,
            y: 2,
            ..Default::default()
        };
        let out = overlay_frame(&base, Rect::new(0, 0, 4, 4), &snap, 1.0);
        // (2,2) is opaque red.
        assert_eq!(
            &out.bgra[(2 * 4 + 2) * 4..(2 * 4 + 2) * 4 + 4],
            &[0, 0, 255, 255]
        );
        // (3,2) is 50% green over the base.
        let g = &out.bgra[(2 * 4 + 3) * 4..(2 * 4 + 3) * 4 + 4];
        assert_eq!(g[0], 5);
        assert!((g[1] as i32 - 138).abs() <= 1);
        assert_eq!(g[2], 15);
        // (0,0) untouched.
        assert_eq!(&out.bgra[0..4], &[10, 20, 30, 255]);
    }

    #[test]
    fn overlay_rect_is_subframe() {
        let mut base = Frame::new(8, 8);
        for (i, px) in base.bgra.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            px.copy_from_slice(&[i as u8, 0, 0, 255]);
        }
        let out = overlay_frame(
            &base,
            Rect::new(2, 3, 2, 2),
            &CursorSnapshot::default(),
            1.0,
        );
        assert_eq!((out.width, out.height), (2, 2));
        assert_eq!(out.bgra[0], (3 * 8 + 2) as u8);
    }

    #[test]
    fn scaled_cursor_keeps_hotspot_in_range() {
        let s = shape_2x2().scaled(0.5);
        assert_eq!((s.width, s.height), (1, 1));
        assert_eq!((s.hot_x, s.hot_y), (0, 0));
    }

    #[test]
    fn rich_cursor_message_has_mask_and_pixels() {
        let enc = PixelEncoder::new(crate::rfb::pixel::PixelFormat::native());
        let msg = rich_cursor_message(&shape_2x2(), &enc);
        assert_eq!(&msg[0..4], &[0, 0, 0, 1]); // FramebufferUpdate, 1 rect
        assert_eq!(&msg[4..8], &[0, 0, 0, 0]); // hotspot x/y
        assert_eq!(&msg[8..12], &[0, 2, 0, 2]); // width/height
        assert_eq!(i32::from_be_bytes(msg[12..16].try_into().unwrap()), -239);
        // 4 pixels * 4 bytes + 1 byte mask row * 2.
        assert_eq!(msg.len(), 16 + 16 + 2);
        // Mask: top-left visible, top-right visible, bottom-left visible,
        // bottom-right transparent -> 1100_0000, 1000_0000.
        assert_eq!(&msg[32..34], &[0b1100_0000, 0b1000_0000]);
    }

    #[test]
    fn rich_cursor_uses_client_pixel_format() {
        let fmt = crate::rfb::pixel::PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            big_endian: false,
            true_colour: true,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
        };
        let enc = PixelEncoder::new(fmt);
        let mut shape = shape_2x2();
        shape.bgra[0..4].copy_from_slice(&[0, 0, 255, 255]); // red
        let msg = rich_cursor_message(&shape, &enc);
        assert_eq!(msg.len(), 16 + 2 * 2 * 2 + 2);
        // First cursor pixel is pure red in RGB565 little-endian.
        assert_eq!(&msg[16..18], &[0x00, 0xF8]);
    }

    #[test]
    fn hidden_and_pointer_pos_layouts() {
        let h = hidden_cursor_message();
        assert_eq!(h.len(), 16);
        assert_eq!(i32::from_be_bytes(h[12..16].try_into().unwrap()), -239);

        let p = pointer_pos_message(7, 9);
        assert_eq!(p.len(), 16);
        assert_eq!(&p[4..8], &[0, 7, 0, 9]);
        assert_eq!(&p[8..12], &[0, 0, 0, 0]);
        assert_eq!(i32::from_be_bytes(p[12..16].try_into().unwrap()), -232);
    }
}
