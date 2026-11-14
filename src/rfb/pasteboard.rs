//! Apple ARD rich pasteboard (`0x1f`) archive codec.
//!
//! Wire layout (after the 16-byte `0x1f` header):
//!
//! ```text
//! repeat until end of archive:
//!   u32 flavor_count
//!   per flavor:
//!     u32 uti_len,  u8 uti[uti_len]
//!     u32 reserved
//!     u32 tag_count
//!     per tag: u32 key_len, key, u32 value_len, value
//!     u32 data_len, u8 data[data_len]
//! ```
//!
//! Apple's producer uses zlib streams framed with `Z_SYNC_FLUSH`, so decoding
//! must accept streams that never emit the final block. We emit ordinary
//! complete zlib streams, which every peer (including Apple's own client)
//! accepts. Text is carried as `public.utf8-plain-text`, with UTF-16 and the
//! legacy Mac text flavor as fallbacks.

use std::io::{self, Write};

use flate2::write::ZlibEncoder;
use flate2::{Compression, Decompress, FlushDecompress, Status};

/// Cap on one compressed pasteboard payload.
pub const MAX_COMPRESSED: usize = 16 << 20;
/// Cap on one decompressed pasteboard archive.
pub const MAX_ARCHIVE: usize = 64 << 20;

pub const UTF8_TEXT: &str = "public.utf8-plain-text";
pub const UTF16_TEXT: &str = "public.utf16-plain-text";
pub const LEGACY_TEXT: &str = "com.apple.traditional-mac-plain-text";
#[allow(dead_code)]
pub const FILE_URL: &str = "public.file-url";

#[derive(Debug, Default, Clone)]
pub struct PasteboardItem {
    pub uti: String,
    #[allow(dead_code)]
    pub tags: Vec<(String, String)>,
    pub data: Vec<u8>,
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_blob(out: &mut Vec<u8>, data: &[u8]) {
    put_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

fn push_flavor(out: &mut Vec<u8>, uti: &str, tags: &[(&str, &str)], data: &[u8]) {
    put_blob(out, uti.as_bytes());
    put_u32(out, 0); // reserved
    put_u32(out, tags.len() as u32);
    for (key, value) in tags {
        put_blob(out, key.as_bytes());
        put_blob(out, value.as_bytes());
    }
    put_blob(out, data);
}

/// A one-flavor text archive, the shape produced by Screen Sharing itself.
#[allow(dead_code)]
pub fn text_archive(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + text.len());
    put_u32(&mut out, 1); // one flavor in the first "item"
    push_flavor(&mut out, UTF8_TEXT, &[], text.as_bytes());
    out
}

#[allow(dead_code)]
/// A one-flavor file URL archive (used for Mac -> Windows clipboard files).
pub fn file_archive(url: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + url.len());
    put_u32(&mut out, 1);
    push_flavor(
        &mut out,
        FILE_URL,
        &[("com.apple.ostype", "furl")],
        url.as_bytes(),
    );
    out
}

/// Percent-encodes a local path into the `file:///C:/...` form used in the
/// pasteboard. The Mac client treats the URL opaquely and echoes it back in
/// the `0x22` download request.
pub fn file_url(path: &std::path::Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut url = String::from("file:///");
    let text = text.strip_prefix('/').unwrap_or(&text);
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b':' | b'-' | b'_' | b'.' | b'~' => {
                url.push(byte as char)
            }
            _ => url.push_str(&format!("%{byte:02X}")),
        }
    }
    url
}

/// Builds an archive carrying text and/or file URLs. Each file is its own
/// "item" (one flavor), matching what Screen Sharing expects from a file
/// pasteboard.
pub fn content_archive(text: Option<&str>, files: &[std::path::PathBuf]) -> Vec<u8> {
    if files.is_empty() && text.map(str::is_empty).unwrap_or(true) {
        return empty_archive().to_vec();
    }
    let mut out = Vec::new();
    if let Some(text) = text.filter(|t| !t.is_empty()) {
        put_u32(&mut out, 1);
        push_flavor(&mut out, UTF8_TEXT, &[], text.as_bytes());
    }
    for file in files {
        put_u32(&mut out, 1);
        push_flavor(
            &mut out,
            FILE_URL,
            &[("com.apple.ostype", "furl")],
            file_url(file).as_bytes(),
        );
    }
    out
}

/// The "no items" archive: a single zero flavor count.
pub fn empty_archive() -> [u8; 4] {
    [0, 0, 0, 0]
}

fn compress(archive: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(archive)?;
    encoder.finish()
}

/// Builds one `0x1f` ClipboardSend message. `echo` is copied from the `0x0b`
/// fetch request; `None`/empty text sends an empty archive.
#[allow(dead_code)]
pub fn message(text: Option<&str>, echo: u32) -> io::Result<Vec<u8>> {
    let archive = match text {
        Some(t) if !t.is_empty() => text_archive(t),
        _ => empty_archive().to_vec(),
    };
    message_for_archive(&archive, echo)
}

/// Builds one `0x1f` ClipboardSend from a pre-built archive.
pub fn message_for_archive(archive: &[u8], echo: u32) -> io::Result<Vec<u8>> {
    if archive.len() > MAX_ARCHIVE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pasteboard archive is too large",
        ));
    }
    let compressed = compress(archive)?;
    let mut out = Vec::with_capacity(16 + compressed.len());
    out.push(0x1f);
    out.push(0);
    out.push(0); // promise: full data
    out.push(0);
    out.extend_from_slice(&echo.to_be_bytes());
    out.extend_from_slice(&(archive.len() as u32).to_be_bytes());
    out.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    out.extend_from_slice(&compressed);
    Ok(out)
}

/// Inflates a `Z_SYNC_FLUSH`-framed or complete zlib payload, capped at the
/// declared uncompressed size. Truncated output is still returned: text
/// extraction can use whatever arrived.
pub fn inflate(payload: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    if expected == 0 {
        return Ok(Vec::new());
    }
    let cap = expected.min(MAX_ARCHIVE);
    let mut out = Vec::with_capacity(cap);
    let mut decoder = Decompress::new(true);
    let mut consumed = 0usize;
    loop {
        let before_in = decoder.total_in() as usize;
        let before_out = decoder.total_out() as usize;
        let input = &payload[consumed.min(payload.len())..];
        let status = decoder
            .decompress_vec(input, &mut out, FlushDecompress::None)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        consumed += decoder.total_in() as usize - before_in;
        let produced = decoder.total_out() as usize - before_out;
        match status {
            Status::StreamEnd => break,
            Status::Ok => {
                if consumed >= payload.len() || produced == 0 {
                    // Z_SYNC_FLUSH has no final block; all input is consumed.
                    break;
                }
            }
            Status::BufError => {
                if out.len() >= cap {
                    break;
                }
                out.reserve((cap - out.len()).clamp(1, 64 << 10));
                if produced == 0 && consumed >= payload.len() {
                    break;
                }
            }
        }
    }
    out.truncate(out.len().min(cap));
    Ok(out)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let bytes = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    fn blob(&mut self, limit: usize) -> Option<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > limit {
            return None;
        }
        let bytes = self.data.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(bytes.to_vec())
    }
}

/// Parses an archive into its flavors. Malformed input yields `None`; a
/// zero-length archive yields an empty list.
pub fn parse_archive(archive: &[u8]) -> Option<Vec<PasteboardItem>> {
    if archive.is_empty() {
        return Some(Vec::new());
    }
    let mut reader = Reader {
        data: archive,
        pos: 0,
    };
    let mut items = Vec::new();
    while reader.pos < archive.len() {
        let flavors = reader.u32()? as usize;
        if flavors > 1024 {
            return None;
        }
        for _ in 0..flavors {
            let uti = String::from_utf8_lossy(&reader.blob(4096)?).into_owned();
            let _reserved = reader.u32()?;
            let tag_count = reader.u32()? as usize;
            if tag_count > 256 {
                return None;
            }
            let mut tags = Vec::with_capacity(tag_count);
            for _ in 0..tag_count {
                let key = String::from_utf8_lossy(&reader.blob(4096)?).into_owned();
                let value = String::from_utf8_lossy(&reader.blob(4096)?).into_owned();
                tags.push((key, value));
            }
            let data = reader.blob(MAX_ARCHIVE)?;
            items.push(PasteboardItem { uti, tags, data });
        }
    }
    Some(items)
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

fn utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }
    let pairs: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect();
    if let Ok(text) = String::from_utf16(&pairs) {
        return Some(text);
    }
    let pairs: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16(&pairs).ok()
}

/// Extracts the best text flavor from a parsed archive. UTF-8 wins, then
/// UTF-16, then the legacy Mac text flavor, then any `public.*text*` flavor.
pub fn text_from_items(items: &[PasteboardItem]) -> Option<String> {
    let mut best: Option<(u8, String)> = None;
    for item in items {
        let text = match item.uti.as_str() {
            UTF8_TEXT => Some((0u8, String::from_utf8_lossy(&item.data).into_owned())),
            UTF16_TEXT => utf16(&item.data).map(|t| (1, t)),
            LEGACY_TEXT => Some((2, latin1(&item.data))),
            uti if uti.starts_with("public.") && uti.contains("text") => {
                Some((3, String::from_utf8_lossy(&item.data).into_owned()))
            }
            _ => None,
        };
        if let Some((rank, text)) = text {
            if !text.is_empty() && best.as_ref().map(|(r, _)| rank < *r).unwrap_or(true) {
                best = Some((rank, text));
            }
        }
    }
    best.map(|(_, text)| text)
}

pub fn text_from_archive(archive: &[u8]) -> Option<String> {
    text_from_items(&parse_archive(archive)?)
}

/// Decompresses a `0x1f` payload and extracts text.
pub fn text_from_message(payload: &[u8], uncompressed: u32) -> Option<String> {
    if uncompressed as usize > MAX_ARCHIVE || payload.len() > MAX_COMPRESSED {
        return None;
    }
    let archive = inflate(payload, uncompressed as usize).ok()?;
    text_from_archive(&archive)
}

#[allow(dead_code)]
/// Extracts the `public.file-url` entries (UTF-8 URLs) from an archive.
pub fn files_from_archive(archive: &[u8]) -> Vec<String> {
    parse_archive(archive)
        .unwrap_or_default()
        .into_iter()
        .filter(|item| item.uti == FILE_URL && !item.data.is_empty())
        .map(|item| String::from_utf8_lossy(&item.data).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_archive_roundtrip() {
        let archive = text_archive("héllo ✓");
        assert_eq!(text_from_archive(&archive).as_deref(), Some("héllo ✓"));
    }

    #[test]
    fn empty_archive_has_no_text() {
        assert_eq!(text_from_archive(&empty_archive()), None);
    }

    #[test]
    fn message_header_and_payload() {
        let msg = message(Some("hello"), 0x1234).unwrap();
        assert_eq!(msg[0], 0x1f);
        assert_eq!(msg[2], 0);
        assert_eq!(u32::from_be_bytes(msg[4..8].try_into().unwrap()), 0x1234);
        let uncompressed = u32::from_be_bytes(msg[8..12].try_into().unwrap()) as usize;
        let compressed = u32::from_be_bytes(msg[12..16].try_into().unwrap()) as usize;
        assert_eq!(msg.len(), 16 + compressed);
        let archive = inflate(&msg[16..], uncompressed).unwrap();
        assert_eq!(text_from_archive(&archive).as_deref(), Some("hello"));
    }

    #[test]
    fn accepts_z_sync_flush_streams() {
        // zlib.compressobj(..., 15).compress("hello sync-flushed pasteboard")
        // + flush(Z_SYNC_FLUSH) — no final block.
        let hex = "78daca48cdc9c95728aecc4bd64dcb292dce484d5128482c2e494dca4f2c4a01000000ffff";
        let compressed = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        let archive = inflate(&compressed, 29).unwrap();
        assert_eq!(&archive, b"hello sync-flushed pasteboard");
    }

    #[test]
    fn prefers_utf8_over_legacy_flavors() {
        let mut archive = Vec::new();
        put_u32(&mut archive, 2);
        push_flavor(&mut archive, LEGACY_TEXT, &[], b"legacy");
        push_flavor(&mut archive, UTF8_TEXT, &[], "utf8 ✓".as_bytes());
        assert_eq!(text_from_archive(&archive).as_deref(), Some("utf8 ✓"));
    }

    #[test]
    fn decodes_utf16_be() {
        let text = "hello utf16";
        let bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        let mut archive = Vec::new();
        put_u32(&mut archive, 1);
        push_flavor(&mut archive, UTF16_TEXT, &[], &bytes);
        assert_eq!(text_from_archive(&archive).as_deref(), Some(text));
    }

    #[test]
    fn rejects_malformed_archives() {
        assert_eq!(text_from_archive(&[0, 0, 0, 9]), None);
        assert_eq!(text_from_archive(&[0, 0, 0, 1, 0, 0]), None);
    }

    #[test]
    fn finds_file_urls() {
        let archive = file_archive("file:///C:/Users/pi/file.txt");
        assert_eq!(
            files_from_archive(&archive),
            vec!["file:///C:/Users/pi/file.txt".to_string()]
        );
    }

    #[test]
    fn content_archive_carries_text_and_files() {
        let files = vec![std::path::PathBuf::from(r"C:\Users\pi\a b.txt")];
        let archive = content_archive(Some("clip text"), &files);
        assert_eq!(text_from_archive(&archive).as_deref(), Some("clip text"));
        assert_eq!(
            files_from_archive(&archive),
            vec!["file:///C:/Users/pi/a%20b.txt".to_string()]
        );
    }
}
