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

/// Apple 3.889 private client message types and ServerInit capability bits.
#[allow(dead_code)]
pub mod apple {
    pub const CLIPBOARD_FETCH: u8 = 0x0b;
    pub const SET_ENCRYPTION: u8 = 0x12;
    pub const AUTO_PASTEBOARD: u8 = 0x15;
    pub const CLIPBOARD_SEND: u8 = 0x1f;
    pub const DRAG_AND_DROP: u8 = 0x20;
    pub const VIEWER_INFO: u8 = 0x21;
    pub const FILE_COPY: u8 = 0x22;

    /// True when the extended ServerInit capability bitmap accepts `command`.
    pub fn has(caps: &[u8; 16], command: u8) -> bool {
        caps[command as usize / 8] & (0x80 >> (command % 8)) != 0
    }

    pub fn set(caps: &mut [u8; 16], command: u8) {
        caps[command as usize / 8] |= 0x80 >> (command % 8);
    }

    pub fn clear(caps: &mut [u8; 16], command: u8) {
        caps[command as usize / 8] &= !(0x80 >> (command % 8));
    }
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
    /// client message type 0x15): selector 1 = start monitoring, 2 = stop.
    AppleAutoPasteboard(u16),
    /// Apple 3.889 ViewerInfo (type 0x21, length-prefixed body).
    AppleViewerInfo(Vec<u8>),
    /// Apple 3.889 SetEncryption (type 0x12): command 1 starts the record
    /// layer, command 2 switches the client->server stream to records.
    AppleSetEncryption {
        command: u16,
    },
    /// Apple 3.889 viewer scale request (type 0x08): 0.0 or >1 means native.
    AppleScaleFactor(f64),
    /// Apple 3.889 clipboard fetch (type 0x0b): `echo` is returned in the
    /// 0x1f reply so the client can suppress its own echo. `promise` asks for
    /// flavour metadata only; the viewer fetches the bytes when pasting.
    AppleClipboardFetch {
        echo: u32,
        promise: bool,
    },
    /// Apple 3.889 rich pasteboard send (type 0x1f).
    AppleClipboardSend {
        promise: bool,
        echo: u32,
        uncompressed: u32,
        compressed: u32,
        data: Vec<u8>,
    },
    /// Apple 3.889 drag (type 0x20): compressed pasteboard archive.
    AppleDrag {
        id: u32,
        uncompressed: u32,
        compressed: u32,
        data: Vec<u8>,
    },
    /// Apple 3.889 file copy (type 0x22).
    AppleFileCopy {
        version: u16,
        command: u16,
        session: u32,
        body: Vec<u8>,
    },
    /// A known Apple message we deliberately ignore (gesture, media, display).
    AppleIgnored(u8),
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
/// Upper bound for one Apple pasteboard/drag payload (compressed).
const MAX_APPLE_PASTEBOARD: usize = 16 << 20;
/// Upper bound for one Apple 0x22 file-copy message (client -> server).
const MAX_APPLE_FILE_MESSAGE: usize = 4 << 20;

/// Reads exactly `len` bytes but keeps at most `cap` of them; the remainder is
/// drained from the stream so an oversized Apple message cannot desync the
/// session. Callers compare `out.len()` with the declared length.
fn read_capped(r: &mut impl Read, len: usize, cap: usize) -> io::Result<Vec<u8>> {
    let keep = len.min(cap);
    let mut out = vec![0u8; keep];
    r.read_exact(&mut out)?;
    let mut remaining = len - keep;
    let mut scratch = [0u8; 4096];
    while remaining > 0 {
        let n = remaining.min(scratch.len());
        r.read_exact(&mut scratch[..n])?;
        remaining -= n;
    }
    Ok(out)
}

/// Reads one client message. `ft_enabled` gates the TightVNC extension types;
/// `apple` enables the RFB 003.889 private message set.
pub fn read_client_message(
    r: &mut impl Read,
    ft_enabled: bool,
    apple: bool,
) -> io::Result<ClientMessage> {
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
            let bytes = read_capped(r, len, MAX_STRING_LEN)?;
            ClientMessage::ClientCutText(latin1_to_string(&bytes))
        }
        10 => {
            // Apple 3.889 dialect: session-start message, fixed 4 bytes
            // (type + u32 big-endian value 1). No response required.
            let mut payload = [0u8; 3];
            r.read_exact(&mut payload)?;
            ClientMessage::AppleSession
        }
        9 => {
            // Apple 3.889 dialect: AutoFrameBufferUpdate — 16 bytes total.
            // Informational; the pusher free-runs for Apple clients.
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
        8 if apple => {
            // ScaleFactor: type + pad + f64 BE (10 bytes total).
            let mut payload = [0u8; 9];
            r.read_exact(&mut payload)?;
            let scale = f64::from_be_bytes(payload[1..9].try_into().unwrap());
            ClientMessage::AppleScaleFactor(scale)
        }
        11 if apple => {
            // ClipboardFetch: type + pad + pad2 + u32 echo = 8 bytes.
            let mut payload = [0u8; 7];
            r.read_exact(&mut payload)?;
            let promise = payload[0] & 1 != 0;
            let echo = u32::from_be_bytes([payload[3], payload[4], payload[5], payload[6]]);
            ClientMessage::AppleClipboardFetch { echo, promise }
        }
        12 if apple => {
            // SetCurtain: `[0x0c][pad][pad2][u16 size][body]`.
            let mut header = [0u8; 5];
            r.read_exact(&mut header)?;
            let size = u16::from_be_bytes([header[3], header[4]]) as usize;
            let _ = read_capped(r, size, 1 << 20)?;
            ClientMessage::AppleIgnored(12)
        }
        13 if apple => {
            // SetDisplay: fixed 8 bytes.
            let mut payload = [0u8; 7];
            r.read_exact(&mut payload)?;
            ClientMessage::AppleIgnored(13)
        }
        18 if apple => {
            // SetEncryption: 8-byte header, then 4 bytes per count word.
            let mut header = [0u8; 7];
            r.read_exact(&mut header)?;
            let command = u16::from_be_bytes([header[1], header[2]]);
            let count = u16::from_be_bytes([header[5], header[6]]);
            let extra = 4usize * count as usize;
            if extra > 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SetEncryption payload too large",
                ));
            }
            let mut tail = vec![0u8; extra];
            r.read_exact(&mut tail)?;
            ClientMessage::AppleSetEncryption { command }
        }
        12 | 13 => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Apple message 0x{msg_type:02x} outside an ARD session"),
            ))
        }
        21 if apple => {
            // AutoPasteboard: type + pad + u16 selector + 4 reserved = 8 bytes.
            let mut payload = [0u8; 7];
            r.read_exact(&mut payload)?;
            ClientMessage::AppleAutoPasteboard(u16::from_be_bytes([payload[1], payload[2]]))
        }
        22 | 23 | 26 | 28 | 29 if apple => {
            // Counted body after a 4-byte header (`[type][pad][u16 size]`).
            let mut header = [0u8; 3];
            r.read_exact(&mut header)?;
            let size = u16::from_be_bytes([header[1], header[2]]) as usize;
            let _ = read_capped(r, size, 1 << 20)?;
            ClientMessage::AppleIgnored(msg_type)
        }
        31 if apple => {
            // ClipboardSend: 16-byte header + zlib payload.
            let mut header = [0u8; 15];
            r.read_exact(&mut header)?;
            let promise = header[1] != 0;
            let echo = u32::from_be_bytes([header[3], header[4], header[5], header[6]]);
            let uncompressed = u32::from_be_bytes([header[7], header[8], header[9], header[10]]);
            let compressed = u32::from_be_bytes([header[11], header[12], header[13], header[14]]);
            let data = read_capped(r, compressed as usize, MAX_APPLE_PASTEBOARD)?;
            ClientMessage::AppleClipboardSend {
                promise,
                echo,
                uncompressed,
                compressed,
                data,
            }
        }
        32 if apple => {
            // Drag: same 16-byte header shape, `id` instead of `echo`.
            let mut header = [0u8; 15];
            r.read_exact(&mut header)?;
            let id = u32::from_be_bytes([header[3], header[4], header[5], header[6]]);
            let uncompressed = u32::from_be_bytes([header[7], header[8], header[9], header[10]]);
            let compressed = u32::from_be_bytes([header[11], header[12], header[13], header[14]]);
            let data = read_capped(r, compressed as usize, MAX_APPLE_PASTEBOARD)?;
            ClientMessage::AppleDrag {
                id,
                uncompressed,
                compressed,
                data,
            }
        }
        34 if apple => {
            // FileCopy: `[0x22][sub][u32 size]` then `size` bytes starting at
            // the u16 version.
            let mut header = [0u8; 5];
            r.read_exact(&mut header)?;
            let size = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            if !(8..=MAX_APPLE_FILE_MESSAGE).contains(&size) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Apple file-copy message of {size} bytes"),
                ));
            }
            let body = read_capped(r, size, MAX_APPLE_FILE_MESSAGE)?;
            let version = u16::from_be_bytes([body[0], body[1]]);
            let command = u16::from_be_bytes([body[2], body[3]]);
            let session = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            ClientMessage::AppleFileCopy {
                version,
                command,
                session,
                body: body[8..].to_vec(),
            }
        }
        33 if apple => {
            // ViewerInfo: `[0x21][pad][u16 size][body]`.
            let mut header = [0u8; 3];
            r.read_exact(&mut header)?;
            let size = u16::from_be_bytes([header[1], header[2]]) as usize;
            let body = read_capped(r, size, 1 << 20)?;
            ClientMessage::AppleViewerInfo(body)
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

/// RFC 6143 cut text is Latin-1; keep one byte per character rather than
/// mangling high bytes through UTF-8 replacement.
fn latin1_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
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
        let msg = read_client_message(&mut c, false, false).unwrap();
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
        let ClientMessage::SetEncodings(enc) = read_client_message(&mut c, false, false).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(enc, vec![0, -223, 7]);
    }

    #[test]
    fn parse_pointer_event() {
        let data = [5u8, 0b101, 0x01, 0x02, 0x00, 0x10].to_vec();
        let mut c = Cursor::new(data);
        let ClientMessage::PointerEvent { mask, x, y } =
            read_client_message(&mut c, false, false).unwrap()
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
            read_client_message(&mut c, true, false).unwrap()
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
        assert!(read_client_message(&mut c, false, false).is_err());
    }

    #[test]
    fn parse_upload_eof_marker() {
        let data = [133u8, 0, 0, 0, 0, 0, 0x5F, 0x5A, 0xE9, 0xC0].to_vec();
        let mut c = Cursor::new(data);
        let ClientMessage::FileUploadData { payload, .. } =
            read_client_message(&mut c, true, false).unwrap()
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
            read_client_message(&mut c, true, false).unwrap()
        else {
            panic!("wrong variant");
        };
        let UploadPayload::Chunk { real_size, data } = payload else {
            panic!("expected chunk");
        };
        assert_eq!(real_size, 16);
        assert_eq!(data, vec![0xAAu8; 8]);
    }

    #[test]
    fn parse_apple_set_encryption_cmd1_and_cmd2() {
        // 12-byte cmd=1 form: 8-byte header, count word = 1 -> 4 more bytes.
        let cmd1 = [
            0x12u8, 0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        let mut c = Cursor::new(cmd1.to_vec());
        let ClientMessage::AppleSetEncryption { command } =
            read_client_message(&mut c, false, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(command, 1);

        // 8-byte cmd=2 form.
        let cmd2 = [0x12u8, 0, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00];
        let mut c = Cursor::new(cmd2.to_vec());
        let ClientMessage::AppleSetEncryption { command } =
            read_client_message(&mut c, false, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(command, 2);
    }

    #[test]
    fn parse_apple_auto_pasteboard_is_eight_bytes() {
        let data = [0x15u8, 0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let mut c = Cursor::new(data.to_vec());
        let ClientMessage::AppleAutoPasteboard(cmd) =
            read_client_message(&mut c, false, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(cmd, 1);
    }

    #[test]
    fn parse_apple_clipboard_fetch() {
        let data = [0x0bu8, 0, 0, 0, 0, 0, 0, 7];
        let mut c = Cursor::new(data.to_vec());
        let ClientMessage::AppleClipboardFetch { echo, promise } =
            read_client_message(&mut c, false, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(echo, 7);
        assert!(!promise);
    }

    #[test]
    fn parse_apple_clipboard_fetch_promise() {
        let data = [0x0bu8, 1, 0, 0, 0, 0, 0, 9];
        let mut c = Cursor::new(data.to_vec());
        let ClientMessage::AppleClipboardFetch { echo, promise } =
            read_client_message(&mut c, false, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(echo, 9);
        assert!(promise);
    }

    #[test]
    fn parse_apple_scale_factor() {
        let mut data = vec![0x08u8, 0];
        data.extend_from_slice(&0.75f64.to_be_bytes());
        let mut c = Cursor::new(data);
        let ClientMessage::AppleScaleFactor(scale) =
            read_client_message(&mut c, false, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert!((scale - 0.75).abs() < 1e-9);
    }

    #[test]
    fn parse_apple_clipboard_send_header() {
        let mut data = vec![0x1fu8, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 5, 0, 0, 0, 3];
        data.extend_from_slice(&[1, 2, 3]);
        let mut c = Cursor::new(data);
        let ClientMessage::AppleClipboardSend {
            promise,
            echo,
            uncompressed,
            compressed,
            data,
        } = read_client_message(&mut c, false, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert!(!promise);
        assert_eq!(echo, 9);
        assert_eq!(uncompressed, 5);
        assert_eq!(compressed, 3);
        assert_eq!(data, vec![1, 2, 3]);
    }

    #[test]
    fn parse_apple_viewer_info_is_counted() {
        let mut data = vec![0x21u8, 0, 0x00, 0x62];
        data.extend_from_slice(&[0xAA; 0x62]);
        let mut c = Cursor::new(data);
        let ClientMessage::AppleViewerInfo(body) =
            read_client_message(&mut c, false, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(body.len(), 0x62);
    }

    #[test]
    fn parse_apple_file_copy_header() {
        // version 1, command 2 (start receive), session 3, body [1,2,3,4].
        let mut data = vec![0x22u8, 0, 0, 0, 0, 12];
        data.extend_from_slice(&[0, 1, 0, 2, 0, 0, 0, 3, 1, 2, 3, 4]);
        let mut c = Cursor::new(data);
        let ClientMessage::AppleFileCopy {
            version,
            command,
            session,
            body,
        } = read_client_message(&mut c, false, true).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!((version, command, session), (1, 2, 3));
        assert_eq!(body, vec![1, 2, 3, 4]);
    }
}
