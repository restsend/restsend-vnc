//! Apple ARD file copy (message type `0x22`) and drag/drop destination
//! (`0x1e`).
//!
//! Frame: `[0x22][0][u32 size][u16 version=1][u16 command][u32 session][body]`
//! where `size` counts everything after it (version onward).
//!
//! Commands used by Screen Sharing:
//! 1 start send (remote -> viewer), 2 start receive (viewer -> remote),
//! 3 pause, 4 continue, 5 stop, 100 item info, 101 new item, 102 data,
//! 103 compressed data, 104 end (LE status), 200 receiver done.
//!
//! This module implements the *receiver* side (uploads from the Mac) and the
//! message builders needed by the sender side (downloads to the Mac).

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use flate2::{Decompress, FlushDecompress};

use crate::rfb::filetransfer::ShareRoot;

pub const MESSAGE_TYPE: u8 = 0x22;
pub const DROP_DESTINATION_TYPE: u8 = 0x1e;

const HEADER_SIZE: usize = 14;
const PROTOCOL_VERSION: u16 = 1;
const MAX_SERVER_MESSAGE: usize = 4 << 20;
const MAX_CLIENT_MESSAGE: usize = 4 << 20;
pub const CHUNK_SIZE: usize = 64 << 10;

pub const CMD_START_SEND: u16 = 1;
pub const CMD_START_RECEIVE: u16 = 2;
pub const CMD_PAUSE: u16 = 3;
pub const CMD_CONTINUE: u16 = 4;
pub const CMD_STOP: u16 = 5;
pub const CMD_ITEM_INFO: u16 = 100;
pub const CMD_NEW_ITEM: u16 = 101;
pub const CMD_DATA: u16 = 102;
pub const CMD_COMPRESSED_DATA: u16 = 103;
pub const CMD_END: u16 = 104;
pub const CMD_RECEIVER_DONE: u16 = 200;

const ITEM_TYPE_FILE: u8 = 1;
const ITEM_TYPE_FOLDER: u8 = 2;
const ITEM_TYPE_LINK: u8 = 3;

/// Carbon `fnfErr`: the client maps this to "not found".
pub const STATUS_NOT_FOUND: i32 = -43;
/// Carbon `permErr`: the client maps this to "permission denied".
pub const STATUS_PERMISSION: i32 = -54;
pub const STATUS_CANNOT_WRITE: i16 = 3;
pub const STATUS_NOT_AVAILABLE: i16 = 2;

const MAX_UPLOAD_BYTES: u64 = 8 << 30;
const MAX_UPLOAD_ITEMS: usize = 10_000;

fn append_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn append_header(out: &mut Vec<u8>, command: u16, session: u32, body_size: usize) {
    out.push(MESSAGE_TYPE);
    out.push(0);
    append_u32(out, (HEADER_SIZE - 6 + body_size) as u32);
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(&command.to_be_bytes());
    append_u32(out, session);
}

/// `[0x22][0][size][ver][cmd=2][session][flags][0][pathLen][path][NUL]`
pub fn start_message(command: u16, session: u32, flags: u32, path: &str) -> Vec<u8> {
    let body_size = 10 + path.len() + 1;
    let mut out = Vec::with_capacity(HEADER_SIZE + body_size);
    append_header(&mut out, command, session, body_size);
    append_u32(&mut out, flags);
    append_u32(&mut out, 0);
    out.extend_from_slice(&(path.len() as u16).to_be_bytes());
    out.extend_from_slice(path.as_bytes());
    out.push(0);
    out
}

/// 52-byte modern item summary.
pub fn item_info_message(
    session: u32,
    single_file: bool,
    logical: u64,
    physical: u64,
    files: u64,
    folders: u64,
) -> Vec<u8> {
    let body_size = 52;
    let mut out = Vec::with_capacity(HEADER_SIZE + body_size);
    append_header(&mut out, CMD_ITEM_INFO, session, body_size);
    append_u32(&mut out, if single_file { 1 } else { 0 });
    append_u32(&mut out, 0);
    append_u64(&mut out, logical);
    append_u64(&mut out, physical);
    append_u64(&mut out, files);
    append_u64(&mut out, 0);
    append_u64(&mut out, folders);
    append_u32(&mut out, 0);
    out
}

pub struct NewItem<'a> {
    pub name: &'a str,
    pub size: u64,
    pub mode: u16,
    pub level: u16,
    pub item_type: u8,
    pub link_target: &'a str,
}

/// 104-byte modern item record plus name/NUL/link target.
pub fn new_item_message(session: u32, item: &NewItem<'_>) -> Vec<u8> {
    let link_len = if item.item_type == ITEM_TYPE_LINK {
        item.link_target.len().saturating_sub(1)
    } else {
        0
    };
    let body_size = 104 + item.name.len() + 1 + item.link_target.len();
    let mut out = Vec::with_capacity(HEADER_SIZE + body_size);
    append_header(&mut out, CMD_NEW_ITEM, session, body_size);

    out.push(item.item_type);
    out.push(0); // user access
    out.extend_from_slice(&[0u8; 16]); // finder info
    out.extend_from_slice(&[0u8; 16]); // extended finder info
    append_u64(&mut out, 0); // resource fork size
    append_u64(&mut out, item.size);
    out.extend_from_slice(&[0u8; 40]); // five Carbon dates
    out.extend_from_slice(&0u16.to_be_bytes()); // node flags
    out.extend_from_slice(&item.level.to_be_bytes());
    out.extend_from_slice(&item.mode.to_be_bytes());
    append_u32(&mut out, 0); // text encoding
    out.extend_from_slice(&(item.name.len() as u16).to_be_bytes());
    out.extend_from_slice(&(link_len as u16).to_be_bytes());
    out.extend_from_slice(item.name.as_bytes());
    out.push(0);
    out.extend_from_slice(item.link_target.as_bytes());
    out
}

pub fn data_message(session: u32, chunk: &[u8]) -> Vec<u8> {
    let body_size = 4 + chunk.len();
    let mut out = Vec::with_capacity(HEADER_SIZE + body_size);
    append_header(&mut out, CMD_DATA, session, body_size);
    append_u32(&mut out, chunk.len() as u32);
    out.extend_from_slice(chunk);
    out
}

/// Command 104. Apple writes the status little-endian even though the rest of
/// the message is big-endian.
pub fn end_message(session: u32, status: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + 4);
    append_header(&mut out, CMD_END, session, 4);
    out.extend_from_slice(&status.to_le_bytes());
    out
}

/// Command 200: `status i16 BE || nameLen u16 BE || name`.
pub fn receiver_done_message(session: u32, status: i16, name: &str) -> Vec<u8> {
    let body_size = 4 + name.len();
    let mut out = Vec::with_capacity(HEADER_SIZE + body_size);
    append_header(&mut out, CMD_RECEIVER_DONE, session, body_size);
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out
}

/// `0x1e` drop destination: `[0x1e][pad3][id u32][pathLen u32][path]`.
pub fn drop_destination_message(id: u32, path: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + path.len());
    out.push(DROP_DESTINATION_TYPE);
    out.extend_from_slice(&[0, 0, 0]);
    append_u32(&mut out, id);
    append_u32(&mut out, path.len() as u32);
    out.extend_from_slice(path.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    pub flags: u32,
    pub path: String,
}

pub fn parse_start(body: &[u8]) -> Option<Start> {
    if body.len() < 10 {
        return None;
    }
    let flags = u32_at(body, 0)?;
    let len = u16_at(body, 8)? as usize;
    let bytes = body.get(10..10 + len)?;
    Some(Start {
        flags,
        path: String::from_utf8_lossy(bytes).into_owned(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct ItemInfo {
    pub single_file: bool,
    pub logical: u64,
    pub files: u64,
    pub folders: u64,
}

pub fn parse_item_info(body: &[u8]) -> Option<ItemInfo> {
    if body.len() >= 52 {
        return Some(ItemInfo {
            single_file: u32_at(body, 0)? & 1 != 0,
            logical: u64_at(body, 8)?,
            files: u64_at(body, 24)?,
            folders: u64_at(body, 40)?,
        });
    }
    // Older 48-byte form: u32 sizes at +8/+16, count at +24.
    let logical = u32_at(body, 8)? as u64;
    Some(ItemInfo {
        single_file: u32_at(body, 0)? & 1 != 0,
        logical,
        files: u32_at(body, 24)? as u64,
        folders: 0,
    })
}

#[derive(Debug, Clone)]
pub struct NewItemInfo {
    pub item_type: u8,
    pub data_size: u64,
    pub resource_size: u64,
    pub level: u16,
    pub mode: u16,
    pub name: String,
    pub link_target: String,
}

pub fn parse_new_item(body: &[u8]) -> Option<NewItemInfo> {
    // Modern layout: 104-byte header, name at +104; older: 100-byte header,
    // name at +100. Detect by checking the NUL terminator at the modern spot.
    let (header, data_size, resource_size, level, mode) = if body.len() >= 104 {
        let name_len = u16_at(body, 100)? as usize;
        let modern_nul = body.get(104 + name_len).copied() == Some(0);
        if modern_nul {
            (
                104,
                u64_at(body, 42)?,
                u64_at(body, 34)?,
                u16_at(body, 92)?,
                u16_at(body, 94)?,
            )
        } else if body.len() >= 100 {
            let name_len = u16_at(body, 96)? as usize;
            if body.get(100 + name_len).copied() != Some(0) {
                return None;
            }
            (
                100,
                u32_at(body, 42)? as u64,
                0,
                u16_at(body, 88)?,
                u16_at(body, 90)?,
            )
        } else {
            return None;
        }
    } else if body.len() >= 100 {
        let name_len = u16_at(body, 96)? as usize;
        if body.get(100 + name_len).copied() != Some(0) {
            return None;
        }
        (
            100,
            u32_at(body, 42)? as u64,
            0,
            u16_at(body, 88)?,
            u16_at(body, 90)?,
        )
    } else {
        return None;
    };

    let item_type = *body.first()?;
    let name_len = u16_at(body, header - 4)? as usize;
    let rest = body.get(header..)?;
    if name_len == 0 || name_len >= rest.len() || rest[name_len] != 0 {
        return None;
    }
    let name = String::from_utf8_lossy(&rest[..name_len]).into_owned();
    let mut link_target = String::new();
    let after_name = &rest[name_len + 1..];
    if item_type == ITEM_TYPE_LINK {
        let link_len = data_size as usize;
        if link_len == 0 || link_len > after_name.len() {
            return None;
        }
        link_target = String::from_utf8_lossy(&after_name[..link_len]).into_owned();
    }
    Some(NewItemInfo {
        item_type,
        data_size,
        resource_size,
        level,
        mode,
        name,
        link_target,
    })
}

pub fn parse_data(body: &[u8]) -> Option<&[u8]> {
    let len = u32_at(body, 0)? as usize;
    body.get(4..4 + len)
}

#[derive(Debug, Clone, Copy)]
pub struct CompressedChunk<'a> {
    pub uncompressed: u32,
    pub data: &'a [u8],
}

pub fn parse_compressed_data(body: &[u8]) -> Option<CompressedChunk<'_>> {
    // u16 compression(=1 zlib) || u32 uncompressed || u32 length || data
    if u16_at(body, 0)? != 1 {
        return None;
    }
    let uncompressed = u32_at(body, 2)?;
    let len = u32_at(body, 6)? as usize;
    Some(CompressedChunk {
        uncompressed,
        data: body.get(10..10 + len)?,
    })
}

pub fn parse_end(body: &[u8]) -> i32 {
    if body.len() < 4 {
        return 0;
    }
    i32::from_le_bytes(body[..4].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Upload receiver
// ---------------------------------------------------------------------------

struct OpenFile {
    file: fs::File,
    path: PathBuf,
    data_remaining: u64,
    resource_remaining: u64,
}

pub struct UploadReceiver {
    session: u32,
    root: Arc<ShareRoot>,
    top_rel: Option<String>,
    top_name: String,
    folders: Vec<String>,
    info: Option<ItemInfo>,
    current: Option<OpenFile>,
    total: u64,
    items: usize,
    inflater: Option<Decompress>,
    failed: bool,
}

impl UploadReceiver {
    pub fn new(session: u32, root: Arc<ShareRoot>) -> Self {
        UploadReceiver {
            session,
            root,
            top_rel: None,
            top_name: String::new(),
            folders: Vec::new(),
            info: None,
            current: None,
            total: 0,
            items: 0,
            inflater: None,
            failed: false,
        }
    }

    pub fn session(&self) -> u32 {
        self.session
    }

    /// Handles one command. Returns a message to write back (currently only
    /// the final `receiver done`).
    pub fn handle(&mut self, command: u16, body: &[u8]) -> Option<Vec<u8>> {
        if self.failed && command != CMD_START_RECEIVE && command != CMD_STOP {
            return None;
        }
        match command {
            CMD_START_RECEIVE => {
                self.reset();
                if let Some(start) = parse_start(body) {
                    tracing::info!(
                        "ARD file upload start: destination {:?}, flags {:#x}",
                        start.path,
                        start.flags
                    );
                }
                None
            }
            CMD_ITEM_INFO => {
                let Some(info) = parse_item_info(body) else {
                    self.abort();
                    return Some(self.done(STATUS_CANNOT_WRITE));
                };
                if info.logical > MAX_UPLOAD_BYTES || info.files as usize > MAX_UPLOAD_ITEMS {
                    self.abort();
                    return Some(self.done(STATUS_CANNOT_WRITE));
                }
                self.info = Some(info);
                None
            }
            CMD_NEW_ITEM => {
                let Some(item) = parse_new_item(body) else {
                    self.abort();
                    return Some(self.done(STATUS_CANNOT_WRITE));
                };
                if let Err(reason) = self.begin_item(&item) {
                    tracing::warn!("ARD upload item rejected: {reason}");
                    self.abort();
                    return Some(self.done(STATUS_CANNOT_WRITE));
                }
                None
            }
            CMD_DATA => {
                let Some(data) = parse_data(body) else {
                    self.abort();
                    return Some(self.done(STATUS_CANNOT_WRITE));
                };
                if let Err(reason) = self.write(data) {
                    tracing::warn!("ARD upload data rejected: {reason}");
                    self.abort();
                    return Some(self.done(STATUS_CANNOT_WRITE));
                }
                None
            }
            CMD_COMPRESSED_DATA => {
                let Some(chunk) = parse_compressed_data(body) else {
                    self.abort();
                    return Some(self.done(STATUS_CANNOT_WRITE));
                };
                let limit = self
                    .current
                    .as_ref()
                    .map(|c| c.data_remaining + c.resource_remaining)
                    .unwrap_or(0)
                    .min(16 << 20);
                if chunk.uncompressed as u64 > limit.saturating_add(4096) {
                    self.abort();
                    return Some(self.done(STATUS_CANNOT_WRITE));
                }
                let inflater = self.inflater.get_or_insert_with(|| Decompress::new(true));
                let mut out = Vec::with_capacity(chunk.uncompressed as usize);
                let _ = inflater.decompress_vec(chunk.data, &mut out, FlushDecompress::None);
                if let Err(reason) = self.write(&out) {
                    tracing::warn!("ARD upload data rejected: {reason}");
                    self.abort();
                    return Some(self.done(STATUS_CANNOT_WRITE));
                }
                None
            }
            CMD_END => {
                let status = parse_end(body);
                if status != 0 {
                    tracing::warn!("ARD upload ended with status {status}");
                    self.abort();
                    return None;
                }
                match self.finish() {
                    Ok(()) => Some(self.done(0)),
                    Err(reason) => {
                        tracing::warn!("ARD upload incomplete: {reason}");
                        self.abort();
                        Some(self.done(STATUS_CANNOT_WRITE))
                    }
                }
            }
            CMD_STOP | CMD_PAUSE | CMD_CONTINUE => {
                if command == CMD_STOP {
                    tracing::info!("ARD upload stopped by the viewer");
                    self.abort();
                }
                None
            }
            _ => None,
        }
    }

    fn reset(&mut self) {
        self.abort();
        self.failed = false;
        self.top_rel = None;
        self.top_name.clear();
        self.folders.clear();
        self.info = None;
        self.total = 0;
        self.items = 0;
        self.inflater = None;
    }

    fn begin_item(&mut self, item: &NewItemInfo) -> Result<(), String> {
        self.finish_current()?;
        self.items += 1;
        if self.items > MAX_UPLOAD_ITEMS {
            return Err("too many items".into());
        }
        if item.item_type == ITEM_TYPE_LINK {
            return Err("symbolic links are not accepted".into());
        }
        let name = safe_name(&item.name).ok_or_else(|| "invalid item name".to_string())?;
        let level = item.level as usize;
        if level == 0 && self.top_rel.is_some() {
            return Err("a second top-level item".into());
        }
        let parent = if level == 0 {
            None
        } else {
            Some(
                self.folders
                    .get(level - 1)
                    .ok_or_else(|| "item outside its folder".to_string())?
                    .clone(),
            )
        };
        let rel = match parent {
            Some(parent) => format!("{parent}/{name}"),
            None => self.free_top_name(&name),
        };
        if level == 0 {
            self.top_name = rel.clone();
            self.top_rel = Some(rel.clone());
        }
        self.folders.truncate(level);
        if item.item_type == ITEM_TYPE_FOLDER {
            let path = self.root.resolve(&rel).map_err(|e| e.to_string())?;
            fs::create_dir(&path).map_err(|e| e.to_string())?;
            self.folders.push(rel);
            return Ok(());
        }
        let path = self.root.resolve(&rel).map_err(|e| e.to_string())?;
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        self.total = self.total.saturating_add(item.data_size);
        if self.total > MAX_UPLOAD_BYTES {
            return Err("transfer is too large".into());
        }
        self.current = Some(OpenFile {
            file,
            path,
            data_remaining: item.data_size,
            resource_remaining: item.resource_size,
        });
        if item.data_size == 0 {
            self.finish_current()?;
        }
        Ok(())
    }

    fn free_top_name(&self, name: &str) -> String {
        for number in 1..1000 {
            let candidate = if number == 1 {
                name.to_string()
            } else if let Some((stem, ext)) = name.rsplit_once('.') {
                format!("{stem} {number}.{ext}")
            } else {
                format!("{name} {number}")
            };
            if !self.path_exists(&candidate) {
                return candidate;
            }
        }
        format!("{name} 999")
    }

    fn path_exists(&self, rel: &str) -> bool {
        self.root
            .resolve(rel)
            .map(|path| path.exists())
            .unwrap_or(false)
    }

    fn write(&mut self, mut data: &[u8]) -> Result<(), String> {
        let Some(current) = self.current.as_mut() else {
            if data.is_empty() {
                return Ok(());
            }
            return Err("data without an open file".into());
        };
        while !data.is_empty() {
            if current.data_remaining > 0 {
                let n = (data.len() as u64).min(current.data_remaining) as usize;
                current
                    .file
                    .write_all(&data[..n])
                    .map_err(|e| e.to_string())?;
                current.data_remaining -= n as u64;
                data = &data[n..];
            } else if current.resource_remaining > 0 {
                let n = (data.len() as u64).min(current.resource_remaining) as usize;
                current.resource_remaining -= n as u64;
                data = &data[n..];
            } else {
                return Err("more data than the item holds".into());
            }
        }
        Ok(())
    }

    fn finish_current(&mut self) -> Result<(), String> {
        if let Some(mut current) = self.current.take() {
            current.file.flush().map_err(|e| e.to_string())?;
            let _ = current.file.sync_all();
            if current.data_remaining != 0 || current.resource_remaining != 0 {
                return Err(format!(
                    "{} is short {} bytes",
                    current.path.display(),
                    current.data_remaining + current.resource_remaining
                ));
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), String> {
        self.finish_current()?;
        if self.top_rel.is_none() {
            return Err("no item was received".into());
        }
        Ok(())
    }

    fn abort(&mut self) {
        self.current = None;
        self.inflater = None;
        if let Some(rel) = self.top_rel.take() {
            if let Ok(path) = self.root.resolve(&rel) {
                let _ = fs::remove_dir_all(&path);
                let _ = fs::remove_file(&path);
            }
        }
    }

    fn done(&mut self, status: i16) -> Vec<u8> {
        let name = if status == 0 {
            self.top_name.clone()
        } else {
            String::new()
        };
        receiver_done_message(self.session, status, &name)
    }
}

/// Windows-safe file name filter. `:` comes from Carbon's `/` escaping and is
/// invalid on Windows, so it is folded to `-`.
fn safe_name(name: &str) -> Option<String> {
    let name = name.replace(':', "-");
    let name = name.trim_end_matches([' ', '.']);
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    if name
        .chars()
        .any(|c| matches!(c, '/' | '\\' | '\0') || (c as u32) < 0x20)
    {
        return None;
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem.as_str()) {
        return None;
    }
    Some(name.to_string())
}

// ---------------------------------------------------------------------------
// Download helpers
// ---------------------------------------------------------------------------

/// Builds the metadata messages for a download and returns the file size.
pub fn download_meta(session: u32, path: &Path) -> Result<(Vec<u8>, Vec<u8>, u64), i32> {
    let meta = fs::metadata(path).map_err(|_| STATUS_NOT_FOUND)?;
    if !meta.is_file() {
        return Err(STATUS_NOT_FOUND);
    }
    let size = meta.len();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let info = item_info_message(session, true, size, size.div_ceil(4096) * 4096, 1, 0);
    let item = new_item_message(
        session,
        &NewItem {
            name: &name,
            size,
            mode: 0o100644,
            level: 0,
            item_type: ITEM_TYPE_FILE,
            link_target: "",
        },
    );
    Ok((info, item, size))
}

/// Reads a local file into ARD messages using the sender side of the protocol.
/// Returns the sequence of messages to write, in order. Kept for tests and
/// small files; the session streams large files with `download_meta`.
#[allow(dead_code)]
pub fn download_messages(session: u32, path: &Path) -> Result<Vec<Vec<u8>>, i32> {
    let (info, item, _size) = download_meta(session, path)?;
    let mut messages = vec![info, item];
    let mut file = fs::File::open(path).map_err(|_| STATUS_PERMISSION)?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buffer).map_err(|_| STATUS_PERMISSION)?;
        if n == 0 {
            break;
        }
        messages.push(data_message(session, &buffer[..n]));
    }
    messages.push(end_message(session, 0));
    Ok(messages)
}

/// Maximum file-copy message accepted from the peer.
pub fn max_message_size() -> usize {
    MAX_SERVER_MESSAGE.max(MAX_CLIENT_MESSAGE)
}

/// Parses a raw `0x22` frame. Returns `(command, session, body)`.
pub fn parse_frame(frame: &[u8]) -> Option<(u16, u32, &[u8])> {
    if frame.len() < HEADER_SIZE || frame[0] != MESSAGE_TYPE {
        return None;
    }
    let size = u32_at(frame, 2)? as usize;
    if !(8..=MAX_SERVER_MESSAGE).contains(&size) || frame.len() < 6 + size {
        return None;
    }
    let version = u16_at(frame, 6)?;
    if version != PROTOCOL_VERSION {
        return None;
    }
    let command = u16_at(frame, 8)?;
    let session = u32_at(frame, 10)?;
    Some((command, session, &frame[HEADER_SIZE..6 + size]))
}

/// Normalizes a client-supplied remote path for a download request.
///
/// Screen Sharing echoes the `public.file-url` path it was given, which may be
/// `C:/...`, `/C:/...` or a percent-encoded `file:///C:/...` URL. Returns the
/// decoded local path when it can be mapped.
#[allow(dead_code)]
pub fn local_path_from_request(request: &str) -> Option<PathBuf> {
    let mut text = request.trim().to_string();
    if let Some(rest) = text.strip_prefix("file://") {
        text = rest.to_string();
        if let Some(pos) = text.find('/') {
            text = text[pos..].to_string();
        }
    }
    let text = percent_decode(&text);
    let text = text.strip_prefix('/').unwrap_or(&text).replace('/', "\\");
    let drive_absolute =
        text.len() >= 3 && text.as_bytes()[1] == b':' && text.as_bytes()[0].is_ascii_alphabetic();
    let path = PathBuf::from(text);
    if path.is_absolute() || drive_absolute {
        Some(path)
    } else {
        None
    }
}

#[allow(dead_code)]
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[allow(dead_code)]
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let msg = start_message(CMD_START_RECEIVE, 3, 0, "/drop");
        let (command, session, body) = parse_frame(&msg).unwrap();
        assert_eq!((command, session), (CMD_START_RECEIVE, 3));
        assert_eq!(parse_start(body).unwrap().path, "/drop");
    }

    #[test]
    fn item_info_and_new_item_shape() {
        let info = item_info_message(2, true, 10, 4096, 1, 0);
        let (_, _, body) = parse_frame(&info).unwrap();
        assert_eq!(body.len(), 52);
        assert_eq!(parse_item_info(body).unwrap().logical, 10);

        let item = new_item_message(
            2,
            &NewItem {
                name: "a.txt",
                size: 10,
                mode: 0o100644,
                level: 0,
                item_type: ITEM_TYPE_FILE,
                link_target: "",
            },
        );
        let (_, _, body) = parse_frame(&item).unwrap();
        let parsed = parse_new_item(body).unwrap();
        assert_eq!(parsed.name, "a.txt");
        assert_eq!(parsed.data_size, 10);
    }

    #[test]
    fn end_status_is_little_endian() {
        let msg = end_message(2, -43);
        assert_eq!(&msg[14..18], &(-43i32).to_le_bytes());
    }

    #[test]
    fn receiver_done_shape() {
        let msg = receiver_done_message(2, 0, "a.txt");
        let (command, _, body) = parse_frame(&msg).unwrap();
        assert_eq!(command, CMD_RECEIVER_DONE);
        assert_eq!(&body[..2], &0i16.to_be_bytes());
        assert_eq!(&body[2..4], &5u16.to_be_bytes());
        assert_eq!(&body[4..], b"a.txt");
    }

    #[test]
    fn rejects_path_traversal_names() {
        assert!(safe_name("../evil").is_none());
        assert!(safe_name("a/b").is_none());
        assert!(safe_name("CON").is_none());
        assert_eq!(safe_name("ok name.txt").as_deref(), Some("ok name.txt"));
        assert_eq!(safe_name("a:b").as_deref(), Some("a-b"));
    }

    #[test]
    fn download_messages_for_a_temp_file() {
        let dir = std::env::temp_dir().join(format!(
            "restsend-ard-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hello.txt");
        fs::write(&path, b"hello file").unwrap();
        let messages = download_messages(7, &path).unwrap();
        assert_eq!(messages[0][0], MESSAGE_TYPE);
        let (command, session, body) = parse_frame(&messages[0]).unwrap();
        assert_eq!((command, session), (CMD_ITEM_INFO, 7));
        assert_eq!(parse_item_info(body).unwrap().logical, 10);
        let (command, _, _) = parse_frame(messages.last().unwrap()).unwrap();
        assert_eq!(command, CMD_END);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_path_from_url() {
        assert_eq!(
            local_path_from_request("file:///C:/Users/pi/a%20b.txt"),
            Some(PathBuf::from("C:\\Users\\pi\\a b.txt"))
        );
        assert_eq!(
            local_path_from_request("/C:/Users/pi/a.txt"),
            Some(PathBuf::from("C:\\Users\\pi\\a.txt"))
        );
    }
}
