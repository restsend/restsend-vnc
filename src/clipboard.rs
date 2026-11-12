//! Bidirectional clipboard sync between the host and VNC sessions.
//!
//! - Client -> host: ClientCutText sets the system clipboard (arboard).
//! - Host -> clients: a watcher thread polls the system clipboard and
//!   broadcasts ServerCutText to every registered session.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Registry of session writer channels + echo suppression state.
pub struct ClipboardHub {
    sessions: Mutex<HashMap<u64, std::sync::mpsc::SyncSender<Vec<u8>>>>,
    /// Apple 3.889 sessions: they don't understand standard ServerCutText, so
    /// they only get an AutoPasteboardInfo notification (message type 20).
    apple_sessions: Mutex<HashMap<u64, std::sync::mpsc::SyncSender<Vec<u8>>>>,
    next_id: AtomicU64,
    /// Text most recently set locally from ClientCutText (suppresses echo).
    last_local: Mutex<Option<String>>,
    /// Last text seen by the watcher (dedup).
    last_seen: Mutex<Option<String>>,
}

impl ClipboardHub {
    pub fn new() -> Self {
        ClipboardHub {
            sessions: Mutex::new(HashMap::new()),
            apple_sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            last_local: Mutex::new(None),
            last_seen: Mutex::new(None),
        }
    }

    pub fn register(&self, tx: std::sync::mpsc::SyncSender<Vec<u8>>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.sessions.lock().unwrap().insert(id, tx);
        id
    }

    /// Registers an Apple 3.889 session for pasteboard notifications.
    pub fn register_apple(&self, tx: std::sync::mpsc::SyncSender<Vec<u8>>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.apple_sessions.lock().unwrap().insert(id, tx);
        id
    }

    pub fn unregister(&self, id: u64) {
        self.sessions.lock().unwrap().remove(&id);
        self.apple_sessions.lock().unwrap().remove(&id);
    }

    /// Best-effort delivery: busy channels are skipped, dead ones removed.
    pub fn broadcast(&self, bytes: Vec<u8>) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, tx| match tx.try_send(bytes.clone()) {
            Ok(()) => true,
            // Full: session is busy (e.g. mid-update); keep it registered.
            Err(std::sync::mpsc::TrySendError::Full(_)) => true,
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
        });
    }

    /// Tells Apple viewers that the host pasteboard changed. They then fetch
    /// it via their own clipboard request. `cmd = 2` is the "pasteboard is
    /// available" notification used by AppleVNCServer.
    pub fn broadcast_apple_pasteboard(&self) {
        let bytes = crate::rfb::apple_auth::auto_pasteboard_info(2).to_vec();
        let mut sessions = self.apple_sessions.lock().unwrap();
        sessions.retain(|_, tx| match tx.try_send(bytes.clone()) {
            Ok(()) => true,
            Err(std::sync::mpsc::TrySendError::Full(_)) => true,
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
        });
    }

    /// Marks `text` as locally-set so the watcher won't echo it back.
    pub fn mark_local(&self, text: &str) {
        *self.last_local.lock().unwrap() = Some(text.to_string());
    }

    /// Returns true (and clears the marker) when `text` is our own echo.
    fn take_local_if_matches(&self, text: &str) -> bool {
        let mut last_local = self.last_local.lock().unwrap();
        if last_local.as_deref() == Some(text) {
            last_local.take();
            true
        } else {
            false
        }
    }

    /// Spawns the system clipboard watcher thread.
    pub fn spawn_watcher(self: &Arc<Self>, enabled: bool) {
        if !enabled {
            return;
        }
        let hub = Arc::clone(self);
        std::thread::Builder::new()
            .name("rvnc-clipboard".into())
            .spawn(move || watcher(hub))
            .expect("spawn clipboard watcher");
    }
}

fn watcher(hub: Arc<ClipboardHub>) {
    let Ok(mut clipboard) = arboard::Clipboard::new() else {
        tracing::warn!("clipboard unavailable, ServerCutText disabled");
        return;
    };
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let Ok(text) = clipboard.get_text() else {
            continue; // non-text content on clipboard
        };
        if text.is_empty() {
            continue;
        }
        {
            let last_seen = hub.last_seen.lock().unwrap();
            if last_seen.as_deref() == Some(text.as_str()) {
                continue;
            }
        }
        if hub.take_local_if_matches(&text) {
            *hub.last_seen.lock().unwrap() = Some(text);
            continue;
        }
        *hub.last_seen.lock().unwrap() = Some(text.clone());
        tracing::debug!(len = text.len(), "host clipboard changed, broadcasting");
        hub.broadcast(crate::rfb::messages::server_cut_text(&text));
        hub.broadcast_apple_pasteboard();
    }
}

/// Sets the host clipboard (used on ClientCutText). Errors are logged.
pub fn set_clipboard(text: &str) {
    match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(text.to_string())) {
        Ok(()) => {}
        Err(e) => tracing::warn!("failed to set host clipboard: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_echo_suppression() {
        let hub = ClipboardHub::new();
        hub.mark_local("hello");
        assert!(hub.take_local_if_matches("hello"));
        assert!(!hub.take_local_if_matches("hello")); // consumed once
        assert!(!hub.take_local_if_matches("other"));
    }

    #[test]
    fn broadcast_removes_dead_sessions() {
        let hub = ClipboardHub::new();
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        let id = hub.register(tx);
        drop(rx);
        hub.broadcast(vec![1, 2, 3]);
        assert!(!hub.sessions.lock().unwrap().contains_key(&id));
    }

    #[test]
    fn broadcast_delivers() {
        let hub = ClipboardHub::new();
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        hub.register(tx);
        hub.broadcast(vec![7]);
        assert_eq!(rx.try_recv().unwrap(), vec![7]);
    }
}
