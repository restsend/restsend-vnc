//! Rect encoders: Raw, Hextile and ZRLE.

pub mod hextile;
pub mod raw;
pub mod zrle;

use std::io;

use crate::diff::Rect;
use crate::framebuffer::Frame;
use crate::rfb::pixel::PixelEncoder;

/// Encoding choices we can serve, in preference order (best first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Zrle,
    Hextile,
    Raw,
}
impl Encoding {
    pub fn code(self) -> i32 {
        match self {
            Encoding::Zrle => 16,
            Encoding::Hextile => 5,
            Encoding::Raw => 0,
        }
    }

    /// Picks the best encoding from the client's requested list.
    pub fn pick(client_encodings: &[i32]) -> Encoding {
        for enc in client_encodings {
            match *enc {
                16 => return Encoding::Zrle,
                5 => return Encoding::Hextile,
                0 => return Encoding::Raw,
                _ => {}
            }
        }
        Encoding::Raw // mandatory fallback
    }
}

/// Encodes one rect into `out` in the requested encoding.
/// For ZRLE, `z` compresses with a per-connection zlib stream (sync flush).
pub fn encode_rect(
    out: &mut Vec<u8>,
    frame: &Frame,
    rect: Rect,
    encoding: Encoding,
    enc: &PixelEncoder,
    z: &mut Option<flate2::Compress>,
) -> io::Result<()> {
    match encoding {
        Encoding::Raw => {
            raw::encode(out, frame, rect, enc);
            Ok(())
        }
        Encoding::Hextile => {
            hextile::encode(out, frame, rect, enc);
            Ok(())
        }
        Encoding::Zrle => {
            let z = z.get_or_insert_with(|| {
                // Real-time trade-off: level 6 compresses best but costs CPU.
                // RESTSEND_VNC_ZRLE_LEVEL lets slow links/CPU pick 1..9.
                let level = std::env::var("RESTSEND_VNC_ZRLE_LEVEL")
                    .ok()
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(6)
                    .clamp(1, 9);
                flate2::Compress::new(flate2::Compression::new(level), true)
            });
            zrle::encode(z, out, frame, rect, enc)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_preference() {
        assert_eq!(Encoding::pick(&[5, 0]), Encoding::Hextile);
        assert_eq!(Encoding::pick(&[16, 5]), Encoding::Zrle);
        assert_eq!(Encoding::pick(&[1011, 1002, 6, 16, -239, -223]), Encoding::Zrle);
        assert_eq!(Encoding::pick(&[-223, 5]), Encoding::Hextile);
        assert_eq!(Encoding::pick(&[-239]), Encoding::Raw);
        assert_eq!(Encoding::pick(&[]), Encoding::Raw);
    }
}
