//! RFB pixel format representation and BGRA framebuffer -> client format conversion.
//!
//! The server keeps its framebuffer in BGRA8 (bytes in memory: B, G, R, X).
//! The server-native wire format is 32bpp little-endian with shifts
//! R=16/G=8/B=0, which is a byte-identical copy of that layout, so the hot
//! path is a plain memcpy.

#![allow(clippy::chunks_exact_to_as_chunks)]

/// Client pixel format as negotiated via `SetPixelFormat` / `ServerInit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    pub const SIZE: usize = 16;

    /// Server-native wire format; byte-identical to our BGRA8 framebuffer.
    pub fn native() -> Self {
        PixelFormat {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }

    /// Parse from the wire (16 bytes). Returns an error message on unsupported values.
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < Self::SIZE {
            return Err("pixel format too short".into());
        }
        let bpp = buf[0];
        if !matches!(bpp, 16 | 24 | 32) {
            return Err(format!("unsupported bits-per-pixel: {bpp}"));
        }
        Ok(PixelFormat {
            bits_per_pixel: bpp,
            depth: buf[1],
            big_endian: buf[2] != 0,
            true_colour: buf[3] != 0,
            red_max: u16::from_be_bytes([buf[4], buf[5]]),
            green_max: u16::from_be_bytes([buf[6], buf[7]]),
            blue_max: u16::from_be_bytes([buf[8], buf[9]]),
            red_shift: buf[10],
            green_shift: buf[11],
            blue_shift: buf[12],
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.bits_per_pixel);
        out.push(self.depth);
        out.push(u8::from(self.big_endian));
        out.push(u8::from(self.true_colour));
        out.extend_from_slice(&self.red_max.to_be_bytes());
        out.extend_from_slice(&self.green_max.to_be_bytes());
        out.extend_from_slice(&self.blue_max.to_be_bytes());
        out.push(self.red_shift);
        out.push(self.green_shift);
        out.push(self.blue_shift);
        out.extend_from_slice(&[0u8; 3]);
    }

    /// Bytes per pixel as packed in framebuffer updates (24bpp = 3, no padding).
    pub fn bytes_per_pixel(&self) -> usize {
        match self.bits_per_pixel {
            24 => 3,
            b => (b / 8) as usize,
        }
    }

    /// True when a pixel in this format is a byte-identical copy of the
    /// BGRA8 framebuffer memory layout (32bpp little-endian, B,G,R,X).
    pub fn is_native_bgra(&self) -> bool {
        !self.big_endian
            && self.bits_per_pixel == 32
            && self.red_max == 255
            && self.green_max == 255
            && self.blue_max == 255
            && self.red_shift == 16
            && self.green_shift == 8
            && self.blue_shift == 0
    }
}

/// Converts BGRA8 samples into the negotiated client pixel format.
#[derive(Debug, Clone)]
pub struct PixelEncoder {
    fmt: PixelFormat,
    bytes_pp: usize,
    native: bool,
}

impl PixelEncoder {
    pub fn new(fmt: PixelFormat) -> Self {
        PixelEncoder {
            bytes_pp: fmt.bytes_per_pixel(),
            native: fmt.is_native_bgra(),
            fmt,
        }
    }

    #[allow(dead_code)]
    pub fn format(&self) -> &PixelFormat {
        &self.fmt
    }

    pub fn bytes_per_pixel(&self) -> usize {
        self.bytes_pp
    }

    /// Pack an 8-bit RGB triple into a pixel value in the client format.
    pub fn pack(&self, r: u8, g: u8, b: u8) -> u32 {
        let rm = self.fmt.red_max as u32;
        let gm = self.fmt.green_max as u32;
        let bm = self.fmt.blue_max as u32;
        let r = ((r as u32 * rm + 127) / 255) << self.fmt.red_shift;
        let g = ((g as u32 * gm + 127) / 255) << self.fmt.green_shift;
        let b = ((b as u32 * bm + 127) / 255) << self.fmt.blue_shift;
        r | g | b
    }

    /// Serialize a packed pixel value to wire bytes.
    pub fn write_packed(&self, out: &mut Vec<u8>, value: u32) {
        match (self.fmt.bits_per_pixel, self.fmt.big_endian) {
            (32, false) => out.extend_from_slice(&value.to_le_bytes()),
            (32, true) => out.extend_from_slice(&value.to_be_bytes()),
            (16, false) => out.extend_from_slice(&(value as u16).to_le_bytes()),
            (16, true) => out.extend_from_slice(&(value as u16).to_be_bytes()),
            // 24bpp: three bytes, most significant byte first.
            _ => out.extend_from_slice(&value.to_be_bytes()[1..4]),
        }
    }

    /// Append a single pixel from a BGRA (b,g,r,x) sample.
    pub fn push_pixel(&self, out: &mut Vec<u8>, bgra: [u8; 4]) {
        if self.native {
            out.extend_from_slice(&bgra);
            return;
        }
        let v = self.pack(bgra[2], bgra[1], bgra[0]);
        self.write_packed(out, v);
    }

    /// Number of bytes in a ZRLE/TRLE CPIXEL (RFC 6143 §7.7.5): 3 bytes when
    /// true-colour 32bpp with depth <= 24 and the colour bits fit in the
    /// least-significant 3 bytes, otherwise the full pixel size.
    pub fn cpixel_bytes(&self) -> usize {
        if self.cpixel3() {
            3
        } else {
            self.bytes_pp
        }
    }

    fn cpixel3(&self) -> bool {
        // RFC 6143 §7.7.5 allows the compact 3-byte CPIXEL when the colour
        // bits fit in 24 bits. Some clients (Apple's Screen Sharing) request
        // 32bpp/depth 32 yet still decode 3-byte CPIXELs, so decide from the
        // colour masks rather than the depth field.
        self.fmt.true_colour
            && self.fmt.bits_per_pixel == 32
            && self.fmt.red_max <= 255
            && self.fmt.green_max <= 255
            && self.fmt.blue_max <= 255
            && self.fmt.red_shift < 24
            && self.fmt.green_shift < 24
            && self.fmt.blue_shift < 24
    }

    /// Append a CPIXEL (ZRLE/TRLE compact pixel) from a BGRA sample.
    pub fn push_cpixel(&self, out: &mut Vec<u8>, bgra: [u8; 4]) {
        if self.cpixel3() {
            if self.native {
                out.extend_from_slice(&bgra[..3]);
            } else {
                let v = self.pack(bgra[2], bgra[1], bgra[0]);
                if self.fmt.big_endian {
                    out.extend_from_slice(&v.to_be_bytes()[1..]);
                } else {
                    out.extend_from_slice(&v.to_le_bytes()[..3]);
                }
            }
            return;
        }
        self.push_pixel(out, bgra);
    }

    /// Append a row of CPIXELs.
    pub fn push_cpixel_row(&self, out: &mut Vec<u8>, row_bgra: &[u8], width: usize) {
        if self.cpixel3() && self.native {
            for px in row_bgra[..width * 4].chunks_exact(4) {
                out.extend_from_slice(&px[..3]);
            }
            return;
        }
        for px in row_bgra[..width * 4].chunks_exact(4) {
            self.push_cpixel(out, [px[0], px[1], px[2], px[3]]);
        }
    }

    /// Append `width` pixels from the start of a BGRA8 row slice.
    /// Falls back to a plain copy on the native fast path.
    pub fn push_row(&self, out: &mut Vec<u8>, row_bgra: &[u8], width: usize) {
        if self.native {
            out.extend_from_slice(&row_bgra[..width * 4]);
            return;
        }
        for px in row_bgra[..width * 4].chunks_exact(4) {
            self.push_pixel(out, [px[0], px[1], px[2], px[3]]);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_is_identity() {
        let enc = PixelEncoder::new(PixelFormat::native());
        let mut out = Vec::new();
        enc.push_pixel(&mut out, [0x11, 0x22, 0x33, 0xFF]); // b g r a
        assert_eq!(out, vec![0x11, 0x22, 0x33, 0xFF]);
    }

    #[test]
    fn rgb565_conversion() {
        let fmt = PixelFormat {
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
        let mut out = Vec::new();
        enc.push_pixel(&mut out, [0, 0, 0xFF, 0]); // pure red
        assert_eq!(out, [0x00, 0xF8]); // 0b11111_000000_00000 as LE u16
        out.clear();
        enc.push_pixel(&mut out, [0, 0xFF, 0, 0]); // pure green
        assert_eq!(out, [0xE0, 0x07]); // 0b00000_111111_00000 as LE u16
    }

    #[test]
    fn parse_rejects_bad_bpp() {
        let mut buf = [0u8; 16];
        buf[0] = 8;
        assert!(PixelFormat::parse(&buf).is_err());
        buf[0] = 32;
        assert!(PixelFormat::parse(&buf).is_ok());
    }

    #[test]
    fn roundtrip_write_parse() {
        let fmt = PixelFormat::native();
        let mut buf = Vec::new();
        fmt.write(&mut buf);
        assert_eq!(PixelFormat::parse(&buf).unwrap(), fmt);
    }
}
