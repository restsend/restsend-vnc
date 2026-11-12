//! Raw encoding: pixels row by row, in the client pixel format.

use crate::diff::Rect;
use crate::framebuffer::Frame;
use crate::rfb::pixel::PixelEncoder;

pub fn encode(out: &mut Vec<u8>, frame: &Frame, rect: Rect, enc: &PixelEncoder) {
    let stride = frame.stride();
    let x0 = rect.x as usize;
    let w = rect.w as usize;
    for y in rect.y as usize..rect.y as usize + rect.h as usize {
        let off = y * stride + x0 * 4;
        enc.push_row(out, &frame.bgra[off..off + w * 4], w);
    }
}
