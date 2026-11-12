//! TightVNC-compatible file transfer server (RFB message types 130-136).
//!
//! Wire format reverse-engineered from TightVNC 1.3.10 (rfbproto.h and
//! winvnc/vncClient.cpp), compatible with TightVNC 1.3 and UltraVNC viewers.
//! All paths are sandboxed inside the configured share root.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use flate2::{Decompress, FlushDecompress};

use crate::rfb::messages::ft;

/// The sandbox root for all file operations.
#[derive(Debug, Clone)]
pub struct ShareRoot {
    pub canonical: PathBuf,
}

impl ShareRoot {
    pub fn new(path: &Path) -> io::Result<Self> {
        let canonical = path.canonicalize()?;
        if !canonical.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("share dir is not a directory: {}", canonical.display()),
            ));
        }
        Ok(ShareRoot { canonical })
    }

    /// Resolves a client-supplied path inside the sandbox.
    /// Empty string = the root itself. Rejects traversal outside the root.
    /// Non-existing paths (e.g. new uploads) are validated against their
    /// longest existing ancestor, so uploads into fresh directories work.
    pub fn resolve(&self, name: &str) -> io::Result<PathBuf> {
        let name = name.replace('\\', "/");
        let trimmed = name.trim_start_matches('/');
        let joined = if trimmed.is_empty() {
            self.canonical.clone()
        } else {
            self.canonical.join(trimmed)
        };
        // Lexical normalization first (rejects explicit .. climbs without
        // touching the filesystem).
        let mut norm = PathBuf::new();
        for comp in joined.components() {
            match comp {
                Component::ParentDir => {
                    if !norm.pop() {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "path escapes the share root",
                        ));
                    }
                }
                Component::CurDir => {}
                comp => norm.push(comp),
            }
        }
        if norm.exists() {
            let resolved = norm.canonicalize()?;
            if !resolved.starts_with(&self.canonical) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "path {:?} escapes the share root {:?}",
                        resolved.display(),
                        self.canonical.display()
                    ),
                ));
            }
            return Ok(resolved);
        }
        // Not on disk: canonicalize the longest existing ancestor and
        // re-append the remainder lexically.
        let mut anc = norm.clone();
        let mut remainder = PathBuf::new();
        while !anc.exists() {
            match (anc.parent(), remainder.parent().map(|_| ())) {
                (Some(p), _) if p != anc => {
                    remainder = anc
                        .file_name()
                        .map(|f| remainder.join(f))
                        .unwrap_or(remainder);
                    anc = p.to_path_buf();
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "path escapes the share root",
                    ));
                }
            }
        }
        let canon_anc = anc.canonicalize()?;
        if !canon_anc.starts_with(&self.canonical) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "path {:?} escapes the share root {:?}",
                    norm.display(),
                    self.canonical.display()
                ),
            ));
        }
        Ok(canon_anc.join(remainder))
    }

    /// Builds a `FileListData` (type 130) response for `dir`.
    /// `dirs_only` mirrors the client's flags&0x10 request.
    pub fn list_message(&self, flags: u8, dir: &Path) -> Vec<u8> {
        let mut entries: Vec<(String, u64, bool, u32)> = Vec::new(); // (name, size, is_dir, mtime)
        let result = fs::read_dir(dir).and_then(|rd| {
            for entry in rd {
                let entry = entry?;
                let meta = entry.metadata()?;
                let is_dir = meta.is_dir();
                if is_dir || (flags & 0x10) == 0 {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as u32)
                        .unwrap_or(0);
                    entries.push((name, meta.len(), is_dir, mtime));
                }
            }
            Ok(())
        });
        if result.is_err() {
            return empty_list_data(flags);
        }
        // dirs first, then files; each alphabetical
        entries.sort_by(|a, b| (b.2, &a.0).cmp(&(a.2, &b.0)));
        // wire limits: names blob and entry count are u16
        let mut names: Vec<u8> = Vec::new();
        let mut sized: Vec<u8> = Vec::new();
        let mut num_files: u16 = 0;
        for (name, size, is_dir, mtime) in entries {
            let blob_len = names.len() + name.len() + 1;
            if blob_len > 60000 || num_files == u16::MAX {
                break; // listing truncated
            }
            names.extend_from_slice(name.as_bytes());
            names.push(0);
            let (wire_size, wire_data): (u32, u32) = if is_dir {
                (u32::MAX, 0)
            } else {
                (size.min(u32::MAX as u64) as u32, mtime)
            };
            sized.extend_from_slice(&wire_size.to_be_bytes());
            sized.extend_from_slice(&wire_data.to_be_bytes());
            num_files += 1;
        }
        let mut out = Vec::with_capacity(8 + sized.len() + names.len());
        out.push(ft::FILE_LIST_DATA);
        out.push(flags & 0xF0);
        out.extend_from_slice(&num_files.to_be_bytes());
        out.extend_from_slice(&(names.len() as u16).to_be_bytes()); // dataSize
        out.extend_from_slice(&(names.len() as u16).to_be_bytes()); // compressedSize
        out.extend_from_slice(&sized);
        out.extend_from_slice(&names);
        out
    }
}

/// Builds an empty (error) `FileListData` response; flags bit 0x80 set.
pub fn empty_list_data(flags: u8) -> Vec<u8> {
    vec![ft::FILE_LIST_DATA, flags | 0x80, 0, 0, 0, 0, 0, 0]
}

/// Builds `FileDownloadData` (type 131) carrying one raw chunk.
pub fn download_chunk_message(chunk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + chunk.len());
    out.push(ft::FILE_DOWNLOAD_DATA);
    out.push(0); // compressLevel 0 = raw
    out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
    out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
    out.extend_from_slice(chunk);
    out
}

/// Builds the end-of-download `FileDownloadData` marker (zero sizes + mtime).
pub fn download_eof_message(mtime: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.push(ft::FILE_DOWNLOAD_DATA);
    out.push(0);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&mtime.to_be_bytes());
    out
}

pub fn download_failed_message(reason: &str) -> Vec<u8> {
    let bytes = reason.as_bytes();
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.push(ft::FILE_DOWNLOAD_FAILED);
    out.push(0);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

pub fn upload_cancel_message(reason: &str) -> Vec<u8> {
    let bytes = reason.as_bytes();
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.push(ft::FILE_UPLOAD_CANCEL);
    out.push(0);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// File mtime as unix seconds (u32, saturating).
pub fn mtime_of(path: &Path) -> u32 {
    fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

/// State of an in-progress upload (opened by FileUploadRequest).
#[derive(Debug)]
pub struct UploadState {
    pub file: fs::File,
    pub path: PathBuf,
    pub bytes_written: u64,
}

impl UploadState {
    pub fn open(root: &ShareRoot, name: &str, position: u32) -> io::Result<UploadState> {
        let path = root.resolve(name)?;
        let mut file = if position > 0 {
            // resume: write at the given offset in the existing file
            fs::OpenOptions::new().write(true).open(&path)?
        } else {
            fs::File::create(&path)?
        };
        if position > 0 {
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(position as u64))?;
        }
        Ok(UploadState {
            file,
            path,
            bytes_written: position as u64,
        })
    }

    /// Writes one chunk. `compressed_level > 0` with `data.len() < real_size`
    /// means the chunk is a fresh zlib stream (UltraVNC viewer behavior);
    /// raw otherwise.
    pub fn write_chunk(
        &mut self,
        compressed_level: u8,
        real_size: u16,
        data: &[u8],
    ) -> io::Result<()> {
        use std::io::Write;
        if compressed_level == 0 || data.len() >= real_size as usize {
            self.file.write_all(data)?;
            self.bytes_written += data.len() as u64;
            return Ok(());
        }
        // zlib-compressed chunk: inflate with headroom, write the result.
        let mut d = Decompress::new(true);
        let mut out = vec![0u8; real_size as usize * 4 + 1024];
        d.decompress(data, &mut out, FlushDecompress::Finish)?;
        let n = d.total_out() as usize;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upload chunk decompressed to nothing",
            ));
        }
        self.file.write_all(&out[..n])?;
        self.bytes_written += n as u64;
        Ok(())
    }

    pub fn finish(&mut self, _mtime: u32) {
        // Note: setting the file mtime portably would need the `filetime`
        // crate; skipped for now — the file keeps the transfer time.
        self.file.sync_all().ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_root() -> (tempdir::TempDirGuard, ShareRoot) {
        let dir = tempdir::make();
        let root = ShareRoot::new(&dir.path).unwrap();
        (dir, root)
    }

    // Minimal temp-dir helpers (no external crate)
    mod tempdir {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        pub struct TempDirGuard {
            pub path: PathBuf,
        }
        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.path).ok();
            }
        }
        pub fn make() -> TempDirGuard {
            let base =
                std::env::temp_dir().join(format!("restsend-vnc-test-{}", std::process::id()));
            // Nanosecond timestamps can collide when tests run in parallel.
            let path = base.join(format!(
                "t-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempDirGuard { path }
        }
    }

    #[test]
    fn sandbox_rejects_escapes() {
        let (_guard, root) = make_root();
        assert!(root.resolve("docs/a.txt").is_ok());
        assert!(root.resolve("").is_ok());
        assert!(root.resolve("docs/../../..").is_err());
        assert!(root.resolve("../outside").is_err());
        assert!(root.resolve("a/../../b").is_err());
    }

    #[test]
    fn list_message_shape() {
        let guard = tempdir::make();
        std::fs::create_dir_all(guard.path.join("sub")).unwrap();
        std::fs::write(guard.path.join("file.bin"), vec![0u8; 100]).unwrap();
        let root = ShareRoot::new(&guard.path).unwrap();
        let msg = root.list_message(0, &root.canonical);
        assert_eq!(msg[0], 130);
        assert_eq!(&msg[2..4], &2u16.to_be_bytes()); // numFiles
        let num = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        // 2 entries * (4+4) + names
        let ds = u16::from_be_bytes([msg[4], msg[5]]) as usize;
        let cs = u16::from_be_bytes([msg[6], msg[7]]) as usize;
        assert_eq!(ds, cs);
        let entries = &msg[8..8 + num * 8];
        // first entry is the dir: size = 0xFFFFFFFF
        assert_eq!(&entries[0..4], &u32::MAX.to_be_bytes());
        let names = &msg[8 + num * 8..];
        let text = String::from_utf8_lossy(names).to_string();
        assert!(text.contains("sub"));
        assert!(text.contains("file.bin"));
        // dirs-only flag skips files
        let msg = root.list_message(0x10, &root.canonical);
        assert_eq!(&msg[2..4], &1u16.to_be_bytes());
    }

    #[test]
    fn download_messages() {
        let chunk = download_chunk_message(&[1, 2, 3]);
        assert_eq!(chunk[0], 131);
        assert_eq!(chunk[1], 0);
        assert_eq!(&chunk[2..4], &3u16.to_be_bytes());
        let eof = download_eof_message(1234);
        assert_eq!(eof.len(), 10);
        assert_eq!(&eof[6..10], &1234u32.to_be_bytes());
    }
}
