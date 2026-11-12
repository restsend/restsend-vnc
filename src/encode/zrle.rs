//! ZRLE encoding (RFC 6143 §7.7.4): 64x64 tiles inside one per-connection
//! zlib stream with a sync flush after every rect.
//!
//! Tile subencodings used: 0 = raw tile, 1 = solid tile. The zlib layer does
//! the actual compression; palette/RLE modes can be added later.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::chunks_exact_to_as_chunks)]

use std::io;

use flate2::{Compress, FlushCompress};

use crate::diff::Rect;
use crate::framebuffer::Frame;
use crate::rfb::pixel::PixelEncoder;

pub const TILE: usize = 64;

pub fn encode(
    z: &mut Compress,
    out: &mut Vec<u8>,
    frame: &Frame,
    rect: Rect,
    enc: &PixelEncoder,
) -> io::Result<()> {
    let stride = frame.stride();
    let x0 = rect.x as usize;
    let y0 = rect.y as usize;
    let x1 = x0 + rect.w as usize;
    let y1 = y0 + rect.h as usize;

    let mut tile_data: Vec<u8> = Vec::with_capacity(TILE * TILE * 4);

    let mut ty = y0;
    while ty < y1 {
        let mut tx = x0;
        while tx < x1 {
            let tw = TILE.min(x1 - tx);
            let th = TILE.min(y1 - ty);
            encode_tile(&mut tile_data, frame, tx, ty, tw, th, stride, enc);
            tx += TILE;
        }
        ty += TILE;
    }

    // Compress the whole rect with a sync flush so the client can decode it
    // independently while keeping one continuous zlib stream.
    // NB: compress_vec writes into spare capacity and stops when it runs out,
    // so loop until all input is consumed, growing as needed.
    let mut compressed = Vec::with_capacity(tile_data.len() + tile_data.len() / 16 + 256);
    let mut consumed = 0usize;
    loop {
        z.compress_vec(&tile_data[consumed..], &mut compressed, FlushCompress::Sync)
            .map_err(io::Error::other)?;
        consumed = z.total_in() as usize;
        if consumed >= tile_data.len() {
            break;
        }
        compressed.reserve(tile_data.len() - consumed + 1024);
    }
    out.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    out.extend_from_slice(&compressed);
    Ok(())
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

    let mut uniform = true;
    let first_u32 = u32::from_ne_bytes(first);
    'rows: for dy in 0..th {
        let off = (ty + dy) * stride + tx * 4;
        let row = &frame.bgra[off..off + tw * 4];
        for px in row.chunks_exact(4) {
            if u32::from_ne_bytes([px[0], px[1], px[2], px[3]]) != first_u32 {
                uniform = false;
                break 'rows;
            }
        }
    }

    if uniform {
        out.push(1); // solid
        enc.push_cpixel(out, first);
    } else if !try_palette(out, frame, tx, ty, tw, th, stride, enc) {
        out.push(0); // raw tile: tw*th CPIXELs, no row padding
        for dy in 0..th {
            let off = (ty + dy) * stride + tx * 4;
            enc.push_cpixel_row(out, &frame.bgra[off..off + tw * 4], tw);
        }
    }
}

/// ZRLE packed-palette subencoding (2..=16 colours). Returns false (and
/// writes nothing) when the tile has more than 16 colours, so noisy/video
/// tiles fall back to raw without extra cost beyond the early bail-out.
fn try_palette(
    out: &mut Vec<u8>,
    frame: &Frame,
    tx: usize,
    ty: usize,
    tw: usize,
    th: usize,
    stride: usize,
    enc: &PixelEncoder,
) -> bool {
    const MAX: usize = 16;
    const SLOTS: usize = 32;
    let mut used = [false; SLOTS];
    let mut table = [0u32; SLOTS];
    let mut n = 0usize;

    let mut insert = |v: u32| -> bool {
        let mut h = (v.wrapping_mul(2654435761) >> 27) as usize & (SLOTS - 1);
        loop {
            if !used[h] {
                used[h] = true;
                table[h] = v;
                n += 1;
                return n <= MAX;
            }
            if table[h] == v {
                return true;
            }
            h = (h + 1) & (SLOTS - 1);
        }
    };

    for dy in 0..th {
        let off = (ty + dy) * stride + tx * 4;
        let row = &frame.bgra[off..off + tw * 4];
        for px in row.chunks_exact(4) {
            if !insert(u32::from_ne_bytes([px[0], px[1], px[2], px[3]])) {
                return false;
            }
        }
    }
    if n < 2 {
        return false; // covered by the solid case
    }

    // Compact palette in table order.
    let mut pal = [0u32; MAX];
    let mut pn = 0;
    for h in 0..SLOTS {
        if used[h] {
            pal[pn] = table[h];
            pn += 1;
        }
    }
    // Rebuild the hash to map colour -> palette index.
    let mut idx_used = [false; SLOTS];
    let mut idx_table = [0u8; SLOTS];
    for (i, color) in pal[..pn].iter().enumerate() {
        let mut h = (color.wrapping_mul(2654435761) >> 27) as usize & (SLOTS - 1);
        while idx_used[h] {
            h = (h + 1) & (SLOTS - 1);
        }
        idx_used[h] = true;
        idx_table[h] = i as u8;
    }

    out.push(pn as u8); // subencoding = palette size
    for color in &pal[..pn] {
        enc.push_cpixel(out, color.to_ne_bytes());
    }

    let bits = if pn <= 2 {
        1
    } else if pn <= 4 {
        2
    } else {
        4
    };
    let mut bitbuf: u32 = 0;
    let mut nbits = 0u32;
    for dy in 0..th {
        let off = (ty + dy) * stride + tx * 4;
        let row = &frame.bgra[off..off + tw * 4];
        for px in row.chunks_exact(4) {
            let v = u32::from_ne_bytes([px[0], px[1], px[2], px[3]]);
            let mut h = (v.wrapping_mul(2654435761) >> 27) as usize & (SLOTS - 1);
            while idx_used[h] && pal[idx_table[h] as usize] != v {
                h = (h + 1) & (SLOTS - 1);
            }
            let idx = idx_table[h] as u32;
            bitbuf = (bitbuf << bits) | idx;
            nbits += bits;
            while nbits >= 8 {
                nbits -= 8;
                out.push((bitbuf >> nbits) as u8);
            }
        }
    }
    if nbits > 0 {
        out.push((bitbuf << (8 - nbits)) as u8);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfb::pixel::PixelFormat;
    use flate2::{Decompress, FlushDecompress};

    /// Client-side view: inflate the whole rect payload, then walk tiles.
    fn decode(data: &[u8], tile_count: usize, cpix: usize) -> Vec<u8> {
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut inflated: Vec<u8> = Vec::with_capacity(TILE * TILE * cpix * tile_count + 1024);
        let mut d = Decompress::new(true);
        d.decompress_vec(&data[4..4 + len], &mut inflated, FlushDecompress::Finish)
            .unwrap();
        inflated.truncate(d.total_out() as usize);
        let mut pos = 0usize;
        let mut pixels = Vec::new();
        for _ in 0..tile_count {
            let sub = inflated[pos];
            pos += 1;
            match sub {
                1 => {
                    pixels.extend_from_slice(&inflated[pos..pos + cpix]);
                    pos += cpix;
                }
                0 => {
                    pixels.extend_from_slice(&inflated[pos..pos + TILE * TILE * cpix]);
                    pos += TILE * TILE * cpix;
                }
                n @ 2..=16 => {
                    let mut pal = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        pal.push(inflated[pos..pos + cpix].to_vec());
                        pos += cpix;
                    }
                    let bits = if n <= 2 { 1 } else if n <= 4 { 2 } else { 4 };
                    let mut bitbuf: u32 = 0;
                    let mut nbits: u32 = 0;
                    for _ in 0..TILE * TILE {
                        while nbits < bits {
                            bitbuf = (bitbuf << 8) | inflated[pos] as u32;
                            pos += 1;
                            nbits += 8;
                        }
                        let idx = (bitbuf >> (nbits - bits)) & ((1 << bits) - 1);
                        nbits -= bits;
                        pixels.extend_from_slice(&pal[idx as usize]);
                    }
                }
                other => panic!("unexpected subencoding {other}"),
            }
        }
        assert_eq!(pos, inflated.len());
        pixels
    }

    #[test]
    fn zrle_roundtrip_solid_and_raw() {
        // 128x64 frame: tile 0 solid, tile 1 noisy
        let mut frame = Frame::new(128, 64);
        for y in 0..64usize {
            for x in 0..128usize {
                let off = (y * frame.stride()) + x * 4;
                let color: [u8; 4] = if x < 64 {
                    [10, 20, 30, 255]
                } else {
                    [(x * y % 251) as u8, x as u8, y as u8, 255]
                };
                frame.bgra[off..off + 4].copy_from_slice(&color);
            }
        }
        let enc = PixelEncoder::new(PixelFormat::native());
        let cpix = enc.cpixel_bytes();
        // ServerInit advertises 32bpp/depth 24, so ZRLE uses 3-byte CPIXELs.
        assert_eq!(cpix, 3);
        let mut z = Compress::new(flate2::Compression::new(6), true);
        let mut out = Vec::new();
        encode(&mut z, &mut out, &frame, Rect::new(0, 0, 128, 64), &enc).unwrap();

        let pixels = decode(&out, 2, cpix);
        // tile 0: one solid CPIXEL (b,g,r) = 10,20,30
        assert_eq!(&pixels[..cpix], &[10, 20, 30]);
        // tile 1: raw CPIXELs
        let tile2 = &pixels[cpix..];
        for y in 0..64usize {
            for x in 64..128usize {
                let i = ((y * 64) + (x - 64)) * cpix;
                let expected = [(x * y % 251) as u8, x as u8, y as u8];
                assert_eq!(&tile2[i..i + cpix], &expected, "mismatch at {x},{y}");
            }
        }
        // compression actually helps on the solid part
        assert!(out.len() < 64 * 64 * 4);
    }

    #[test]
    fn zrle_roundtrip_palette() {
        // One 64x64 tile with 4 colours: should use the packed-palette mode.
        let mut frame = Frame::new(64, 64);
        for y in 0..64usize {
            for x in 0..64usize {
                let off = y * frame.stride() + x * 4;
                let c: [u8; 4] = match (x / 16 + y / 16) % 4 {
                    0 => [0, 0, 0, 255],
                    1 => [255, 0, 0, 255],
                    2 => [0, 255, 0, 255],
                    _ => [0, 0, 255, 255],
                };
                frame.bgra[off..off + 4].copy_from_slice(&c);
            }
        }
        let enc = PixelEncoder::new(PixelFormat::native());
        let cpix = enc.cpixel_bytes();
        let mut z = Compress::new(flate2::Compression::new(6), true);
        let mut out = Vec::new();
        encode(&mut z, &mut out, &frame, Rect::new(0, 0, 64, 64), &enc).unwrap();
        let pixels = decode(&out, 1, cpix);
        for y in 0..64usize {
            for x in 0..64usize {
                let i = (y * 64 + x) * cpix;
                // CPIXEL3 = B,G,R (the frame stores BGRA).
                let expected: [u8; 3] = match (x / 16 + y / 16) % 4 {
                    0 => [0, 0, 0],
                    1 => [255, 0, 0],
                    2 => [0, 255, 0],
                    _ => [0, 0, 255],
                };
                assert_eq!(&pixels[i..i + cpix], &expected, "at {x},{y}");
            }
        }
    }

    #[test]
    fn cpixel_3byte_when_masks_fit_24bit() {
        // Apple's Screen Sharing asks for 32bpp/depth 32 yet decodes 3-byte
        // CPIXELs, so the compact form is chosen from the colour masks.
        let mut fmt = PixelFormat::native();
        fmt.depth = 32;
        let enc = PixelEncoder::new(fmt);
        assert_eq!(enc.cpixel_bytes(), 3);
        let mut out = Vec::new();
        enc.push_cpixel(&mut out, [1, 2, 3, 4]);
        assert_eq!(out, [1, 2, 3]);
    }

    #[test]
    fn cpixel_4byte_when_masks_need_32bit() {
        // Colour maxima that do not fit in 24 bits require the full-width
        // CPIXEL.
        let mut fmt = PixelFormat::native();
        fmt.red_max = 1023;
        fmt.red_shift = 20;
        let enc = PixelEncoder::new(fmt);
        assert_eq!(enc.cpixel_bytes(), 4);
        let mut out = Vec::new();
        enc.push_cpixel(&mut out, [1, 2, 3, 4]);
        assert_eq!(out.len(), 4);
    }
}
