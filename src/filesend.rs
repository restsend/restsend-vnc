//! Server-initiated file offers for Apple (Screen Sharing) clients.
//!
//! The Mac viewer cannot be told to save a file outright — Screen Sharing
//! only consumes files through its pasteboard: the server advertises
//! `public.file-url` items, the viewer places file promises on the Mac
//! pasteboard, and pressing ⌘V in Finder resolves each promise through the
//! ARD `0x22` file channel. This module is the "send file" backend behind
//! the tray panel: it holds the file list picked by the local user and
//! notifies Apple sessions, so the next pasteboard fetch serves the offered
//! files instead of the host clipboard.
//!
//! The offer stays active until the user sends a different list, or the
//! host clipboard changes, or it expires. Transfer progress (the `0x22`
//! downloads it triggers) is recorded in a small log the panel displays.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::clipboard::ClipboardHub;

/// How long an offer stays authoritative for pasteboard fetches.
const OFFER_TTL: Duration = Duration::from_secs(15 * 60);
/// Number of log lines kept for the panel.
const LOG_CAP: usize = 120;

struct Offer {
    files: Vec<PathBuf>,
    created: Instant,
}

static OFFER: Mutex<Option<Offer>> = Mutex::new(None);
static HUB: OnceLock<Arc<ClipboardHub>> = OnceLock::new();
static LOG: Mutex<Vec<(Instant, String)>> = Mutex::new(Vec::new());
/// Bumped every time the offer list changes (panel refresh aid).
static OFFER_SEQ: AtomicU64 = AtomicU64::new(0);

/// Registers the clipboard hub used to notify Apple sessions. Called once
/// at startup; a no-op afterwards.
pub fn init(hub: Arc<ClipboardHub>) {
    let _ = HUB.set(hub);
}

fn log_line(line: impl Into<String>) {
    let mut log = LOG.lock().unwrap();
    log.push((Instant::now(), line.into()));
    let excess = log.len().saturating_sub(LOG_CAP);
    log.drain(..excess);
}

/// The currently offered files, or `None` when no fresh offer exists.
pub fn offer() -> Option<Vec<PathBuf>> {
    let mut guard = OFFER.lock().unwrap();
    let offer = guard.as_ref()?;
    if offer.created.elapsed() > OFFER_TTL {
        *guard = None;
        return None;
    }
    Some(offer.files.clone())
}

/// True when `canonical` is in the current offer: the only paths a viewer
/// may download outside the share root and clipboard.
pub fn is_offered(canonical: &std::path::Path) -> bool {
    offer()
        .map(|files| files.iter().any(|f| f == canonical))
        .unwrap_or(false)
}

/// Publishes a new offer and notifies every Apple session. Returns the
/// number of Apple sessions that were notified.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn offer_files(files: Vec<PathBuf>) -> usize {
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|f| f.is_file())
        .collect::<Vec<_>>();
    OFFER_SEQ.fetch_add(1, Ordering::Relaxed);
    let notified = HUB
        .get()
        .map(|hub| hub.apple_session_count())
        .unwrap_or(0);
    *OFFER.lock().unwrap() = Some(Offer {
        files: files.clone(),
        created: Instant::now(),
    });
    if notified > 0 {
        if let Some(hub) = HUB.get() {
            hub.broadcast_apple_pasteboard();
        }
    }
    let names: Vec<String> = files
        .iter()
        .map(|f| f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
        .collect();
    log_line(format!(
        "offered {} file(s) to {notified} Apple client(s): {}",
        files.len(),
        names.join(", ")
    ));
    notified
}

/// Drops the offer. Called when the host clipboard changes so the real
/// clipboard wins again.
pub fn clear() {
    OFFER_SEQ.fetch_add(1, Ordering::Relaxed);
    if OFFER.lock().unwrap().take().is_some() {
        log_line("offer cleared (host clipboard changed or expired)");
    }
}

/// Drops the offer explicitly (the panel's Clear button).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn clear_manual() {
    OFFER_SEQ.fetch_add(1, Ordering::Relaxed);
    if OFFER.lock().unwrap().take().is_some() {
        log_line("offer cleared manually");
    }
}

/// Records one line of transfer progress for the panel.
pub fn record_transfer(line: impl Into<String>) {
    log_line(line);
}

/// Snapshot of the panel log (oldest first).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn log_snapshot() -> Vec<(Instant, String)> {
    LOG.lock().unwrap().clone()
}

/// Number of Apple clients currently registered for pasteboard pushes.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn apple_session_count() -> usize {
    HUB.get().map(|hub| hub.apple_session_count()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offer lives in globals shared by the whole process; serialize the
    /// tests that mutate it.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn write_file(name: &str, body: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "restsend-filesend-{}-{}-{}",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn offer_roundtrip_and_clear() {
        let _guard = TEST_LOCK.lock().unwrap();
        let path = write_file("a.txt", b"abc");
        offer_files(vec![path.clone()]);
        let files = offer().expect("offer active");
        assert_eq!(files, vec![path.clone()]);
        assert!(is_offered(&path));
        assert!(!is_offered(std::path::Path::new("/nonexistent")));

        clear();
        assert!(offer().is_none());
        assert!(!is_offered(&path));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn nonexistent_files_are_filtered() {
        let _guard = TEST_LOCK.lock().unwrap();
        let path = write_file("b.txt", b"zz");
        let ghost = path.parent().unwrap().join("ghost.txt");
        offer_files(vec![path.clone(), ghost]);
        let files = offer().unwrap();
        assert_eq!(files, vec![path.clone()]);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn offer_replaces_previous() {
        let _guard = TEST_LOCK.lock().unwrap();
        let a = write_file("one.txt", b"1");
        let b = write_file("two.txt", b"2");
        offer_files(vec![a.clone()]);
        offer_files(vec![b.clone()]);
        let files = offer().unwrap();
        assert_eq!(files, vec![b]);
        std::fs::remove_dir_all(a.parent().unwrap()).ok();
    }
}
