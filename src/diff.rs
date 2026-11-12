//! Tile-based framebuffer diffing with horizontal run merging.

use rayon::prelude::*;

use crate::framebuffer::Frame;

/// A rectangle in framebuffer coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Rect { x, y, w, h }
    }

    /// Clamps to (0,0,width,height); returns None when empty.
    pub fn clamp(&self, width: u32, height: u32) -> Option<Rect> {
        let x = (self.x as u32).min(width);
        let y = (self.y as u32).min(height);
        let w = (self.w as u32).min(width.saturating_sub(x));
        let h = (self.h as u32).min(height.saturating_sub(y));
        if w == 0 || h == 0 {
            None
        } else {
            Some(Rect {
                x: x as u16,
                y: y as u16,
                w: w as u16,
                h: h as u16,
            })
        }
    }
}

pub const DIFF_TILE: u16 = 16;

/// Compares `cached` and `current` inside `region` on a tile grid and returns
/// merged dirty rectangles (horizontal runs per tile row).
/// When dimensions differ, the whole (clamped) region is reported.
pub fn diff_tiles(cached: &Frame, current: &Frame, region: Rect) -> Vec<Rect> {
    let Some(region) = region.clamp(current.width, current.height) else {
        return Vec::new();
    };
    if cached.dims() != current.dims() {
        return vec![region];
    }

    let tile = DIFF_TILE as usize;
    let stride = current.stride();
    let tile_x0 = region.x as usize / tile;
    let tile_y0 = region.y as usize / tile;
    let tile_x1 = (region.x as usize + region.w as usize).div_ceil(tile);
    let tile_y1 = (region.y as usize + region.h as usize).div_ceil(tile);

    // One job per tile row. 4K has 135 rows of 240 tiles, which is plenty
    // of parallelism and keeps enough work per task to amortise rayon.
    let rows: Vec<usize> = (tile_y0..tile_y1).collect();
    let scan = |ty: &usize| -> Vec<Rect> {
        let ty = *ty;
        let mut row_rects = Vec::new();
        let mut run_start: Option<usize> = None; // tile x where the dirty run began
        for tx in tile_x0..tile_x1 {
            let x0 = (tx * tile).max(region.x as usize);
            let y0 = (ty * tile).max(region.y as usize);
            let x1 = ((tx + 1) * tile).min(region.x as usize + region.w as usize);
            let y1 = ((ty + 1) * tile).min(region.y as usize + region.h as usize);
            if x1 <= x0 || y1 <= y0 {
                continue;
            }
            let mut dirty = false;
            'rows: for y in y0..y1 {
                let off = y * stride;
                let a = &cached.bgra[off + x0 * 4..off + x1 * 4];
                let b = &current.bgra[off + x0 * 4..off + x1 * 4];
                if a != b {
                    dirty = true;
                    break 'rows;
                }
            }
            if dirty {
                if run_start.is_none() {
                    run_start = Some(tx);
                }
            } else if let Some(start_tx) = run_start.take() {
                row_rects.push(tile_run_rect(start_tx, tx, ty, &region, tile));
            }
        }
        if let Some(start_tx) = run_start {
            row_rects.push(tile_run_rect(start_tx, tile_x1, ty, &region, tile));
        }
        row_rects
    };

    let pixels = current.width as usize * current.height as usize;
    let per_row: Vec<Vec<Rect>> = if rows.len() < 8 || pixels < 512 * 512 {
        rows.iter().map(scan).collect()
    } else {
        rows.par_iter().map(scan).collect()
    };
    merge_rects(merge_vertical(per_row))
}

fn rect_area(r: &Rect) -> u64 {
    r.w as u64 * r.h as u64
}

fn union_rect(a: Rect, b: Rect) -> Rect {
    let x0 = a.x.min(b.x);
    let y0 = a.y.min(b.y);
    let x1 = (a.x as u32 + a.w as u32).max(b.x as u32 + b.w as u32);
    let y1 = (a.y as u32 + a.h as u32).max(b.y as u32 + b.h as u32);
    Rect::new(x0, y0, (x1 - x0 as u32) as u16, (y1 - y0 as u32) as u16)
}

/// Merges overlapping/nearby rectangles into their bounding box when doing so
/// grows the repainted area by at most ~40%.
///
/// A moving window leaves an L-shaped dirty region (top sliver, left/right
/// strips, bottom sliver). Painting that as four rectangles looks like a
/// broken image; one bounding box is visually atomic, compresses better
/// (64x64 ZRLE tiles again) and usually touches fewer extra pixels than the
/// sum of the fragments. Far-apart changes are left alone.
fn merge_rects(mut rects: Vec<Rect>) -> Vec<Rect> {
    if rects.len() < 2 || rects.len() > 128 {
        return rects;
    }
    let total_dirty: u64 = rects.iter().map(rect_area).sum();
    // Never let bounding-box merging turn a few scattered pixels into a
    // much larger repaint than the dirty area itself.
    let max_merged_area = total_dirty.saturating_mul(2);
    let mut merges = 0usize;
    loop {
        let mut merged = false;
        'outer: for i in 0..rects.len() {
            for j in i + 1..rects.len() {
                let u = union_rect(rects[i], rects[j]);
                let sum = rect_area(&rects[i]) + rect_area(&rects[j]);
                if rect_area(&u) <= max_merged_area && rect_area(&u) as f64 <= sum as f64 * 1.5 {
                    rects[i] = u;
                    rects.remove(j);
                    merged = true;
                    merges += 1;
                    break 'outer;
                }
            }
        }
        if !merged || merges >= 32 {
            break;
        }
    }
    rects
}

/// Merges runs with identical x/width that continue on the next tile row.
///
/// Without this, moving a window produces one 16-pixel-high rectangle per
/// tile row: the viewer paints those as thin bands (and ZRLE gets 16-row
/// tiles), which looks like a shattered image while dragging.
fn merge_vertical(rows: Vec<Vec<Rect>>) -> Vec<Rect> {
    use std::collections::HashMap;

    let mut out: Vec<Rect> = Vec::new();
    // (x, w) -> index into `out` for the rect that ends on the previous row.
    let mut open: HashMap<(u16, u16), usize> = HashMap::new();
    for row in rows {
        let mut next: HashMap<(u16, u16), usize> = HashMap::new();
        for rect in row {
            let key = (rect.x, rect.w);
            if let Some(&idx) = open.get(&key) {
                let prev = &mut out[idx];
                if prev.y as u32 + prev.h as u32 == rect.y as u32 {
                    prev.h = prev.h.saturating_add(rect.h);
                    next.insert(key, idx);
                    continue;
                }
            }
            let idx = out.len();
            out.push(rect);
            next.insert(key, idx);
        }
        open = next;
    }
    out
}

/// Rect covering tile columns [start_tx, end_tx) of tile row `ty`, clamped to
/// the requested region.
fn tile_run_rect(start_tx: usize, end_tx: usize, ty: usize, region: &Rect, tile: usize) -> Rect {
    let x = (start_tx * tile).max(region.x as usize);
    let y = (ty * tile).max(region.y as usize);
    let x1 = (end_tx * tile).min(region.x as usize + region.w as usize);
    let y1 = ((ty + 1) * tile).min(region.y as usize + region.h as usize);
    Rect {
        x: x as u16,
        y: y as u16,
        w: (x1 - x) as u16,
        h: (y1 - y) as u16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_with_dirty(width: u32, height: u32, dirty_tiles: &[(usize, usize)]) -> (Frame, Frame) {
        let cached = Frame::new(width, height);
        let mut current = Frame::new(width, height);
        for (tx, ty) in dirty_tiles {
            let off = (ty * 16 * width as usize + tx * 16) * 4;
            current.bgra[off] = 255;
        }
        (cached, current)
    }

    #[test]
    fn no_changes_no_rects() {
        let (cached, current) = frame_with_dirty(64, 64, &[]);
        assert_eq!(
            diff_tiles(&cached, &current, Rect::new(0, 0, 64, 64)),
            vec![]
        );
    }

    #[test]
    fn single_dirty_tile() {
        let (cached, current) = frame_with_dirty(64, 64, &[(1, 2)]);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 64, 64));
        assert_eq!(rects, vec![Rect::new(16, 32, 16, 16)]);
    }

    #[test]
    fn adjacent_tiles_merge() {
        let (cached, current) = frame_with_dirty(64, 64, &[(0, 0), (1, 0), (2, 0)]);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 64, 64));
        assert_eq!(rects, vec![Rect::new(0, 0, 48, 16)]);
    }

    #[test]
    fn vertical_runs_merge_into_one_rect() {
        // Same tile column on three consecutive tile rows -> one 16x48 rect.
        let (cached, current) = frame_with_dirty(64, 64, &[(1, 0), (1, 1), (1, 2)]);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 64, 64));
        assert_eq!(rects, vec![Rect::new(16, 0, 16, 48)]);
    }

    #[test]
    fn small_vertical_gaps_are_bridged() {
        // Tile rows 0 and 2 are dirty, row 1 is not. Bridging the 16-pixel
        // gap costs 256 pixels and gives the client one rectangle instead of
        // two bands.
        let (cached, current) = frame_with_dirty(64, 64, &[(1, 0), (1, 2)]);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 64, 64));
        assert_eq!(rects, vec![Rect::new(16, 0, 16, 48)]);
    }

    #[test]
    fn full_width_rows_merge_to_full_screen() {
        let cached = Frame::new(160, 64);
        let mut current = Frame::new(160, 64);
        for y in [0usize, 16, 32, 48] {
            for tx in 0..10 {
                let off = y * 160 * 4 + tx * 16 * 4;
                current.bgra[off] = 1;
            }
        }
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 160, 64));
        assert_eq!(rects, vec![Rect::new(0, 0, 160, 64)]);
    }

    #[test]
    fn moving_window_yields_two_large_rects_not_bands() {
        let mut cached = Frame::new(256, 256);
        let mut current = Frame::new(256, 256);
        let draw = |frame: &mut Frame, ox: usize, oy: usize| {
            for y in oy..oy + 64 {
                for x in ox..ox + 64 {
                    let off = y * frame.stride() + x * 4;
                    frame.bgra[off..off + 4].copy_from_slice(&[255, 255, 255, 255]);
                }
            }
        };
        draw(&mut cached, 32, 32);
        draw(&mut current, 64, 48);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 256, 256));
        // One bounding box around the old and new window positions instead of
        // dozens of 16-pixel bands.
        assert_eq!(rects.len(), 1, "unexpected fragmentation: {rects:?}");
        assert_eq!(rects[0], Rect::new(32, 32, 96, 80));
    }

    #[test]
    fn far_apart_changes_are_not_merged() {
        let cached = Frame::new(512, 128);
        let mut current = Frame::new(512, 128);
        for y in 0..16 {
            for x in [0usize, 400] {
                let off = y * current.stride() + x * 4;
                current.bgra[off] = 9;
            }
        }
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 512, 128));
        assert_eq!(rects.len(), 2, "far-apart rects must stay separate");
        assert!(rects[0].x < 64 && rects[1].x > 300);
    }

    #[test]
    fn separated_tiles_stay_split() {
        let (cached, current) = frame_with_dirty(64, 64, &[(0, 0), (3, 0)]);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 64, 64));
        assert_eq!(
            rects,
            vec![Rect::new(0, 0, 16, 16), Rect::new(48, 0, 16, 16)]
        );
    }

    #[test]
    fn region_limit() {
        let (cached, current) = frame_with_dirty(64, 64, &[(3, 0)]);
        assert_eq!(
            diff_tiles(&cached, &current, Rect::new(0, 0, 32, 64)),
            vec![]
        );
    }

    #[test]
    fn dims_change_reports_everything() {
        let cached = Frame::new(32, 32);
        let current = Frame::new(64, 64);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 500, 500));
        assert_eq!(rects, vec![Rect::new(0, 0, 64, 64)]);
    }

    #[test]
    fn parallel_path_preserves_row_major_order() {
        // 1024x1024 = 64 tile rows, enough to take the rayon path.
        let cached = Frame::new(1024, 1024);
        let mut current = Frame::new(1024, 1024);
        let mark = |frame: &mut Frame, tx: usize, ty: usize| {
            let off = (ty * 16 * 1024 + tx * 16) * 4;
            frame.bgra[off] = 255;
        };
        // Out of order on purpose.
        mark(&mut current, 7, 3);
        mark(&mut current, 1, 1);
        mark(&mut current, 2, 7);
        mark(&mut current, 0, 7);
        mark(&mut current, 1, 7);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 1024, 1024));
        assert_eq!(
            rects,
            vec![
                Rect::new(16, 16, 16, 16),
                Rect::new(112, 48, 16, 16),
                Rect::new(0, 112, 48, 16),
            ]
        );
    }

    #[test]
    fn odd_sizes() {
        // 50x30: tiles 4x2 (last tiles partially clamped by region)
        let (cached, current) = frame_with_dirty(50, 30, &[(3, 1)]);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 50, 30));
        // tile (3,1) covers x 48..50 (clamped), y 16..30
        assert_eq!(rects, vec![Rect::new(48, 16, 2, 14)]);
    }
}
