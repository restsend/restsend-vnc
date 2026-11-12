//! TCP listener: accepts connections and spawns a session per client.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::clipboard::ClipboardHub;
use crate::framebuffer::ScreenState;
use crate::session::{self, SessionConfig};

/// Live client sockets, so the tray can disconnect everyone.
static SESSIONS: Mutex<Vec<(u64, TcpStream)>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub fn register_session(stream: &TcpStream) -> u64 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(clone) = stream.try_clone() {
        SESSIONS.lock().unwrap().push((id, clone));
    }
    id
}

pub fn unregister_session(id: u64) {
    SESSIONS.lock().unwrap().retain(|(sid, _)| *sid != id);
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn kill_all_sessions() -> usize {
    let sessions = SESSIONS.lock().unwrap();
    for (_, s) in sessions.iter() {
        let _ = s.shutdown(Shutdown::Both);
    }
    sessions.len()
}

/// Accepts until `start_reload` changes (tray changed the port) or exit.
pub fn serve(
    listener: TcpListener,
    state: Arc<ScreenState>,
    hub: Arc<ClipboardHub>,
    _cli_password: Option<String>,
    cfg: SessionConfig,
    start_reload: usize,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    loop {
        if crate::settings::EXIT.load(Ordering::Relaxed)
            || crate::settings::RELOAD.load(Ordering::Relaxed) != start_reload
        {
            return Ok(());
        }
        let conn = match listener.accept() {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };
        let (stream, peer) = conn;
        if crate::settings::LOOPBACK_ONLY.load(Ordering::Relaxed) && !peer.ip().is_loopback() {
            tracing::warn!("rejecting non-loopback client {peer} (loopback-only)");
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }
        if !crate::settings::allows(peer.ip()) {
            tracing::warn!("rejecting {peer}: not in allow_cidrs");
            crate::audit::log("acl_reject", &peer, "not in allow_cidrs", None);
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }
        let peer: SocketAddr = peer;
        let Ok(stream) = configure_stream(stream) else {
            continue;
        };
        tracing::info!("connection from {peer}");
        let session_id = register_session(&stream);
        let state = Arc::clone(&state);
        let hub = Arc::clone(&hub);
        // `--share-dir` overrides the tray setting for this run; otherwise the
        // live setting is evaluated per connection so toggling it in the tray
        // applies without restarting.
        let share_root = cfg.share_root.clone().or_else(crate::settings::share_root);
        let cfg = SessionConfig {
            name: crate::settings::title(),
            view_only: cfg.view_only,
            test_pattern: cfg.test_pattern,
            input_enabled: cfg.input_enabled,
            share_root,
            clipboard_enabled: cfg.clipboard_enabled,
        };
        let password = crate::settings::password();
        std::thread::Builder::new()
            .name("restsend-vnc-session".into())
            .spawn(move || {
                if let Err(e) = session::handle_client(stream, peer, state, password, cfg, hub) {
                    tracing::debug!("session setup failed for {peer}: {e}");
                }
                unregister_session(session_id);
            })
            .ok();
    }
}

fn configure_stream(stream: TcpStream) -> io::Result<TcpStream> {
    // The listener is non-blocking; accepted sockets must be switched back to
    // blocking mode or every session read/write fails with WouldBlock.
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    Ok(stream)
}
