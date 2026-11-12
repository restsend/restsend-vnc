//! Tile-based framebuffer diffing with horizontal run merging.

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

    let mut rects = Vec::new();

    for ty in tile_y0..tile_y1 {
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
                rects.push(tile_run_rect(start_tx, tx, ty, &region, tile));
            }
        }
        if let Some(start_tx) = run_start {
            rects.push(tile_run_rect(start_tx, tile_x1, ty, &region, tile));
        }
    }

    rects
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
        assert_eq!(diff_tiles(&cached, &current, Rect::new(0, 0, 64, 64)), vec![]);
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
    fn separated_tiles_stay_split() {
        let (cached, current) = frame_with_dirty(64, 64, &[(0, 0), (3, 0)]);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 64, 64));
        assert_eq!(rects, vec![Rect::new(0, 0, 16, 16), Rect::new(48, 0, 16, 16)]);
    }

    #[test]
    fn region_limit() {
        let (cached, current) = frame_with_dirty(64, 64, &[(3, 0)]);
        assert_eq!(diff_tiles(&cached, &current, Rect::new(0, 0, 32, 64)), vec![]);
    }

    #[test]
    fn dims_change_reports_everything() {
        let cached = Frame::new(32, 32);
        let current = Frame::new(64, 64);
        let rects = diff_tiles(&cached, &current, Rect::new(0, 0, 500, 500));
        assert_eq!(rects, vec![Rect::new(0, 0, 64, 64)]);
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
