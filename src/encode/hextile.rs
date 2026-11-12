//! Hextile encoding (RFC 6143 §7.7.3): 16x16 tiles with a subencoding byte.
//!
//! Simple strategy: uniform tiles emit only a background-specified header;
//! everything else is sent as a raw tile. Valid for all viewers, albeit not
//! the most bandwidth-optimal (ZRLE covers that when available).

#![allow(clippy::too_many_arguments)]
#![allow(clippy::chunks_exact_to_as_chunks)]

use crate::diff::Rect;
use crate::framebuffer::Frame;
use crate::rfb::pixel::PixelEncoder;

pub const TILE: usize = 16;

pub fn encode(out: &mut Vec<u8>, frame: &Frame, rect: Rect, enc: &PixelEncoder) {
    let stride = frame.stride();
    let x0 = rect.x as usize;
    let y0 = rect.y as usize;
    let x1 = x0 + rect.w as usize;
    let y1 = y0 + rect.h as usize;

    let mut ty = y0;
    while ty < y1 {
        let mut tx = x0;
        while tx < x1 {
            let tw = TILE.min(x1 - tx);
            let th = TILE.min(y1 - ty);
            encode_tile(out, frame, tx, ty, tw, th, stride, enc);
            tx += TILE;
        }
        ty += TILE;
    }
}

fn encode_tile(
    out: &mut Vec<u8>,
    frame: &Frame,
    tx: usize,
    ty: usize,
    tw: usize,
    th: usize,
    stride: usize,
    enc: &PixelEncoder,
) {
    let base = ty * stride + tx * 4;
    let first: [u8; 4] = frame.bgra[base..base + 4].try_into().unwrap();

    // Uniformity check: every pixel must equal the first one.
    let mut uniform = true;
    'rows: for dy in 0..th {
        let off = (ty + dy) * stride + tx * 4;
        let row = &frame.bgra[off..off + tw * 4];
        for px in row.chunks_exact(4) {
            if px != first {
                uniform = false;
                break 'rows;
            }
        }
    }

    if uniform {
        // subencoding 0x02: background specified, no subrects
        out.push(0x02);
        enc.push_pixel(out, first);
    } else {
        // subencoding 0x01: raw tile (tw*th pixels, no row padding)
        out.push(0x01);
        for dy in 0..th {
            let off = (ty + dy) * stride + tx * 4;
            enc.push_row(out, &frame.bgra[off..off + tw * 4], tw);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfb::pixel::PixelFormat;

    /// Minimal decoder used by tests to validate wire shape.
    fn decode_hextile(data: &[u8], tiles_expected: usize) -> (usize, Vec<Vec<u8>>) {
        let mut pos = 0usize;
        let mut tiles = Vec::new();
        for _ in 0..tiles_expected {
            let sub = data[pos];
            pos += 1;
            if sub & 0x02 != 0 {
                pos += 4; // bg pixel (32bpp)
            }
            if sub & 0x01 != 0 {
                let raw = &data[pos..pos + TILE * TILE * 4];
                pos += TILE * TILE * 4;
                tiles.push(raw.to_vec());
            } else if sub == 0x02 {
                tiles.push(Vec::new());
            }
        }
        (tiles.len(), tiles)
    }

    #[test]
    fn uniform_and_raw_tiles() {
        // 32x32 frame: left tile column uniform black, right column noisy
        let mut frame = Frame::new(32, 32);
        for y in 0..32usize {
            for x in 0..32usize {
                let off = (y * frame.stride()) + x * 4;
                let color = if x < 16 {
                    [0u8; 4]
                } else {
                    [x as u8, y as u8, 7, 255]
                };
                frame.bgra[off..off + 4].copy_from_slice(&color);
            }
        }
        let enc = PixelEncoder::new(PixelFormat::native());
        let mut out = Vec::new();
        encode(&mut out, &frame, Rect::new(0, 0, 32, 32), &enc);
        let (n, tiles) = decode_hextile(&out, 4);
        assert_eq!(n, 4);
        assert_eq!(tiles[0].len(), 0); // uniform tile
        assert_eq!(tiles[1].len(), 16 * 16 * 4); // raw tile
        assert_eq!(tiles[2].len(), 0); // uniform tile
        assert_eq!(tiles[3].len(), 16 * 16 * 4); // raw tile
        assert_eq!(out.len(), 2 * 5 + 2 * (1 + 16 * 16 * 4));
    }
}
