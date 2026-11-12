//! Client->server message parsing and server->client message helpers,
//! including the TightVNC file-transfer extension messages (types 130-136).

use std::io::{self, Read};

use crate::rfb::pixel::PixelFormat;

pub mod ft {
    // client -> server
    pub const FILE_LIST_REQUEST: u8 = 130;
    pub const FILE_DOWNLOAD_REQUEST: u8 = 131;
    pub const FILE_UPLOAD_REQUEST: u8 = 132;
    pub const FILE_UPLOAD_DATA: u8 = 133;
    pub const FILE_DOWNLOAD_CANCEL: u8 = 134;
    pub const FILE_UPLOAD_FAILED: u8 = 135;
    pub const FILE_CREATE_DIR: u8 = 136;

    // server -> client
    pub const FILE_LIST_DATA: u8 = 130;
    pub const FILE_DOWNLOAD_DATA: u8 = 131;
    pub const FILE_UPLOAD_CANCEL: u8 = 132;
    pub const FILE_DOWNLOAD_FAILED: u8 = 133;
}

/// Pseudo-encoding numbers we care about.
#[allow(dead_code)]
pub mod pseudo {
    pub const RICH_CURSOR: i32 = -239;
    pub const X_CURSOR: i32 = -240;
    pub const POINTER_POS: i32 = -232;
    pub const LAST_RECT: i32 = -224;
    pub const NEW_FB_SIZE: i32 = -223;
}

#[derive(Debug)]
pub enum UploadPayload {
    /// File chunk. `real_size` is the uncompressed length (used to detect
    /// zlib-compressed chunks: compressedSize < realSize means compressed).
    Chunk { real_size: u16, data: Vec<u8> },
    /// End-of-file marker carrying the client-side mtime (unix seconds).
    Eof { mtime: u32 },
}

#[derive(Debug)]
pub enum ClientMessage {
    SetPixelFormat(PixelFormat),
    SetEncodings(Vec<i32>),
    FramebufferUpdateRequest {
        // Pusher-driven update model: FBURs are accepted but ignored.
        #[allow(dead_code)]
        incremental: bool,
        #[allow(dead_code)]
        x: u16,
        #[allow(dead_code)]
        y: u16,
        #[allow(dead_code)]
        width: u16,
        #[allow(dead_code)]
        height: u16,
    },
    KeyEvent {
        down: bool,
        keysym: u32,
    },
    PointerEvent {
        mask: u8,
        x: u16,
        y: u16,
    },
    ClientCutText(String),
    /// Apple 3.889 session-start (type 10); informational, ignored.
    AppleSession,
    /// Apple 3.889 encrypted client message: `[0x10][subtype][16-byte
    /// AES-128-ECB block]` (session key from Apple DH auth).
    AppleEncrypted {
        subtype: u8,
        block: [u8; 16],
    },
    /// Apple 3.889 auto-pasteboard command (`RFBAutoPasteboardMessage`,
    /// client message type 30): 8 raw bytes, BE16 command at offset 2.
    AppleAutoPasteboard([u8; 8]),
    /// Apple 3.889 viewer-info message sent after the extended ServerInit.
    AppleViewerInfo(Vec<u8>),
    // --- TightVNC file transfer extensions ---
    FileListRequest {
        flags: u8,
        dir_name: String,
    },
    FileDownloadRequest {
        compressed_level: u8,
        position: u32,
        file_name: String,
    },
    FileUploadRequest {
        compressed_level: u8,
        position: u32,
        file_name: String,
    },
    FileUploadData {
        compressed_level: u8,
        payload: UploadPayload,
    },
    FileDownloadCancel(String),
    FileUploadFailed(String),
    FileCreateDir(String),
}

fn read_u8(r: &mut impl Read) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn read_string(r: &mut impl Read, len: usize) -> io::Result<String> {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

const MAX_STRING_LEN: usize = 1 << 20; // 1 MiB sanity cap

/// Reads one client message. `ft_enabled` gates the TightVNC extension types.
pub fn read_client_message(r: &mut impl Read, ft_enabled: bool) -> io::Result<ClientMessage> {
    let msg_type = read_u8(r)?;
    Ok(match msg_type {
        0 => {
            let mut pad = [0u8; 3];
            r.read_exact(&mut pad)?;
            let mut fmt = [0u8; 16];
            r.read_exact(&mut fmt)?;
            ClientMessage::SetPixelFormat(PixelFormat::parse(&fmt).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("bad pixel format: {e}"))
            })?)
        }
        2 => {
            let mut pad = [0u8; 1];
            r.read_exact(&mut pad)?;
            let n = read_u16(r)? as usize;
            if n > 512 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many encodings",
                ));
            }
            let mut encodings = Vec::with_capacity(n);
            for _ in 0..n {
                encodings.push(i32::from_be_bytes([
                    read_u8(r)?,
                    read_u8(r)?,
                    read_u8(r)?,
                    read_u8(r)?,
                ]));
            }
            ClientMessage::SetEncodings(encodings)
        }
        3 => {
            let incremental = read_u8(r)? != 0;
            let x = read_u16(r)?;
            let y = read_u16(r)?;
            let width = read_u16(r)?;
            let height = read_u16(r)?;
            ClientMessage::FramebufferUpdateRequest {
                incremental,
                x,
                y,
                width,
                height,
            }
        }
        4 => {
            let down = read_u8(r)? != 0;
            let mut pad = [0u8; 2];
            r.read_exact(&mut pad)?;
            let keysym = read_u32(r)?;
            ClientMessage::KeyEvent { down, keysym }
        }
        5 => {
            let mask = read_u8(r)?;
            let x = read_u16(r)?;
            let y = read_u16(r)?;
            ClientMessage::PointerEvent { mask, x, y }
        }
        6 => {
            let mut pad = [0u8; 3];
            r.read_exact(&mut pad)?;
            let len = read_u32(r)? as usize;
            if len > MAX_STRING_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cut text too large",
                ));
            }
            ClientMessage::ClientCutText(read_string(r, len)?)
        }
        10 => {
            // Apple 3.889 dialect: session-start message, fixed 4 bytes
            // (type + u32 big-endian value 1). No response required.
            let mut payload = [0u8; 3];
            r.read_exact(&mut payload)?;
            ClientMessage::AppleSession
        }
        9 => {
            // Apple 3.889 dialect: framebuffer hint — 15 bytes containing the
            // client's expected framebuffer geometry (w/h packed LE-style).
            // Informational; the session keeps the server-decided size.
            let mut payload = [0u8; 15];
            r.read_exact(&mut payload)?;
            ClientMessage::AppleSession
        }
        16 => {
            // Apple 3.889: encrypted client message. Fixed frame:
            // [type=16][subtype u8][16-byte AES-128-ECB block].
            let subtype = read_u8(r)?;
            let mut block = [0u8; 16];
            r.read_exact(&mut block)?;
            ClientMessage::AppleEncrypted { subtype, block }
        }
        30 => {
            // Apple 3.889: RFBAutoPasteboardMessage (8-byte body).
            let mut payload = [0u8; 8];
            r.read_exact(&mut payload)?;
            ClientMessage::AppleAutoPasteboard(payload)
        }
        33 => {
            // Apple 3.889 viewer-info message (fixed 77-byte body).
            let mut payload = vec![0u8; 77];
            r.read_exact(&mut payload)?;
            ClientMessage::AppleViewerInfo(payload)
        }
        ft::FILE_LIST_REQUEST if ft_enabled => {
            let flags = read_u8(r)?;
            let len = read_u16(r)? as usize;
            if len > MAX_STRING_LEN {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "path too long"));
            }
            ClientMessage::FileListRequest {
                flags,
                dir_name: read_string(r, len)?,
            }
        }
        ft::FILE_DOWNLOAD_REQUEST | ft::FILE_UPLOAD_REQUEST if ft_enabled => {
            let compressed_level = read_u8(r)?;
            let name_len = read_u16(r)? as usize;
            let position = read_u32(r)?;
            if name_len > MAX_STRING_LEN {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "path too long"));
            }
            let file_name = read_string(r, name_len)?;
            if msg_type == ft::FILE_DOWNLOAD_REQUEST {
                ClientMessage::FileDownloadRequest {
                    compressed_level,
                    position,
                    file_name,
                }
            } else {
                ClientMessage::FileUploadRequest {
                    compressed_level,
                    position,
                    file_name,
                }
            }
        }
        ft::FILE_UPLOAD_DATA if ft_enabled => {
            let compressed_level = read_u8(r)?;
            let real_size = read_u16(r)?;
            let compressed_size = read_u16(r)?;
            let payload = if real_size == 0 && compressed_size == 0 {
                // EOF marker carrying the client-side mtime (unix seconds)
                UploadPayload::Eof {
                    mtime: read_u32(r)?,
                }
            } else {
                let mut buf = vec![0u8; compressed_size as usize];
                r.read_exact(&mut buf)?;
                UploadPayload::Chunk {
                    real_size,
                    data: buf,
                }
            };
            ClientMessage::FileUploadData {
                compressed_level,
                payload,
            }
        }
        ft::FILE_DOWNLOAD_CANCEL | ft::FILE_UPLOAD_FAILED if ft_enabled => {
            let mut pad = [0u8; 1];
            r.read_exact(&mut pad)?;
            let len = read_u16(r)? as usize;
            if len > MAX_STRING_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reason too long",
                ));
            }
            let reason = read_string(r, len)?;
            if msg_type == ft::FILE_DOWNLOAD_CANCEL {
                ClientMessage::FileDownloadCancel(reason)
            } else {
                ClientMessage::FileUploadFailed(reason)
            }
        }
        ft::FILE_CREATE_DIR if ft_enabled => {
            let mut pad = [0u8; 1];
            r.read_exact(&mut pad)?;
            let len = read_u16(r)? as usize;
            if len > MAX_STRING_LEN {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "path too long"));
            }
            ClientMessage::FileCreateDir(read_string(r, len)?)
        }
        _ => {
            // Diagnose proprietary client extensions: drain everything the
            // client sent after the unknown type byte and hex-dump it, so the
            // message format can be reconstructed from logs.
            let mut extra: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                match r.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        extra.extend_from_slice(&chunk[..n]);
                        if extra.len() > 4096 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let hex: String = extra.iter().take(64).map(|b| format!("{b:02x}")).collect();
            tracing::warn!(
                "unknown client message type {msg_type}: {} payload bytes, head [{}]; \
                 closing session (client reconnects automatically)",
                extra.len(),
                hex
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown client message type {msg_type}"),
            ));
        }
    })
}

// ---------------------------------------------------------------------------
// Server -> client helpers
// ---------------------------------------------------------------------------

pub fn framebuffer_update_header(nrects: u16) -> Vec<u8> {
    let mut out = vec![0u8, 0];
    out.extend_from_slice(&nrects.to_be_bytes());
    out
}

pub fn rect_header(x: u16, y: u16, w: u16, h: u16, encoding: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&x.to_be_bytes());
    out.extend_from_slice(&y.to_be_bytes());
    out.extend_from_slice(&w.to_be_bytes());
    out.extend_from_slice(&h.to_be_bytes());
    out.extend_from_slice(&encoding.to_be_bytes());
    out
}

pub fn server_cut_text(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = vec![3u8, 0, 0, 0];
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parse_key_event() {
        // type 4, down=1, pad, keysym 0x00FF1B
        let data = [4u8, 1, 0, 0, 0x00, 0x00, 0xFF, 0x1B].to_vec();
        let mut c = Cursor::new(data);
        let msg = read_client_message(&mut c, false).unwrap();
        let ClientMessage::KeyEvent { down, keysym } = msg else {
            panic!("wrong variant");
        };
        assert!(down);
        assert_eq!(keysym, 0xFF1B);
    }

    #[test]
    fn parse_set_encodings_with_pseudo() {
        let mut data = vec![2u8, 0, 0, 3];
        data.extend_from_slice(&0i32.to_be_bytes());
        data.extend_from_slice(&(-223i32).to_be_bytes());
        data.extend_from_slice(&7i32.to_be_bytes());
        let mut c = Cursor::new(data);
        let ClientMessage::SetEncodings(enc) = read_client_message(&mut c, false).unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(enc, vec![0, -223, 7]);
    }

    #[test]
    fn parse_pointer_event() {
        let data = [5u8, 0b101, 0x01, 0x02, 0x00, 0x10].to_vec();
        let mut c = Cursor::new(data);
        let ClientMessage::PointerEvent { mask, x, y } =
            read_client_message(&mut c, false).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!((mask, x, y), (0b101, 0x0102, 0x0010));
    }

    #[test]
    fn parse_ft_list_request() {
        let mut data = vec![130u8, 0x10, 0, 2];
        data.extend_from_slice(b"/d");
        let mut c = Cursor::new(data);
        let ClientMessage::FileListRequest { flags, dir_name } =
            read_client_message(&mut c, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(flags, 0x10);
        assert_eq!(dir_name, "/d");
    }

    #[test]
    fn ft_disabled_rejects_ft_types() {
        let data = [130u8, 0, 0, 0].to_vec();
        let mut c = Cursor::new(data);
        assert!(read_client_message(&mut c, false).is_err());
    }

    #[test]
    fn parse_upload_eof_marker() {
        let data = [133u8, 0, 0, 0, 0, 0, 0x5F, 0x5A, 0xE9, 0xC0].to_vec();
        let mut c = Cursor::new(data);
        let ClientMessage::FileUploadData { payload, .. } =
            read_client_message(&mut c, true).unwrap()
        else {
            panic!("wrong variant");
        };
        let UploadPayload::Eof { mtime } = payload else {
            panic!("expected EOF marker");
        };
        assert_eq!(mtime, 0x5F5AE9C0);
    }

    #[test]
    fn parse_upload_chunk() {
        let mut data = vec![133u8, 0, 0x00, 0x10, 0x00, 0x08]; // realSize=16, compressedSize=8
        data.extend_from_slice(&[0xAAu8; 8]);
        let mut c = Cursor::new(data);
        let ClientMessage::FileUploadData { payload, .. } =
            read_client_message(&mut c, true).unwrap()
        else {
            panic!("wrong variant");
        };
        let UploadPayload::Chunk { real_size, data } = payload else {
            panic!("expected chunk");
        };
        assert_eq!(real_size, 16);
        assert_eq!(data, vec![0xAAu8; 8]);
    }
}
