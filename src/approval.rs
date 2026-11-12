//! Manual approval for incoming connections.
//!
//! A session thread calls [`request`] after a successful RFB handshake and
//! before `ServerInit`, so a rejected client never receives any screen data.
//! On Windows GUI builds the tray polls the queue, shows a modeless
//! Accept/Reject window and calls [`resolve`]. Console builds prompt on stdin;
//! when no terminal exists the request fails closed.
//!
//! `RESTSEND_VNC_APPROVAL=accept|reject|timeout` is an internal test hook that
//! bypasses the UI. It only takes effect while confirmation is enabled.
//! `RESTSEND_VNC_APPROVAL_TIMEOUT_MS` shortens the timeout for tests.

use std::collections::VecDeque;
use std::io::IsTerminal;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long the local user has to accept a connection before it is rejected.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound the number of sessions parked waiting for a decision.
const MAX_PENDING: usize = 4;
/// How often the waiting session re-checks the timeout and client liveness.
const POLL: Duration = Duration::from_millis(100);

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
struct Pending {
    id: u64,
    peer: SocketAddr,
    info: String,
    created: Instant,
    timeout: Duration,
    tx: SyncSender<bool>,
}

/// A request as seen by the tray UI.
#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub struct PendingView {
    pub id: u64,
    pub peer: SocketAddr,
    pub info: String,
    pub deadline: Instant,
}

#[derive(Default)]
struct State {
    next_id: u64,
    queue: VecDeque<Pending>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(State::default()))
}

fn timeout_from_env() -> Duration {
    std::env::var("RESTSEND_VNC_APPROVAL_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|ms| Duration::from_millis(ms.clamp(50, 600_000)))
        .unwrap_or(DEFAULT_TIMEOUT)
}

/// Enqueues a request and returns the id plus the decision channel.
fn enqueue(peer: SocketAddr, info: &str, timeout: Duration) -> Result<(u64, Receiver<bool>), ()> {
    let mut st = state().lock().unwrap();
    if st.queue.len() >= MAX_PENDING {
        return Err(());
    }
    st.next_id = st.next_id.wrapping_add(1).max(1);
    let id = st.next_id;
    let (tx, rx) = mpsc::sync_channel(1);
    st.queue.push_back(Pending {
        id,
        peer,
        info: info.to_string(),
        created: Instant::now(),
        timeout,
        tx,
    });
    Ok((id, rx))
}

fn remove(id: u64) -> Option<Pending> {
    let mut st = state().lock().unwrap();
    let pos = st.queue.iter().position(|p| p.id == id)?;
    st.queue.remove(pos)
}

/// Session side: ask for approval. Returns true when the connection may
/// continue. When confirmation is disabled this is a cheap true.
pub fn request(stream: &TcpStream, peer: SocketAddr, info: &str) -> bool {
    if !crate::settings::confirm_connections() {
        return true;
    }

    let timeout = timeout_from_env();
    if let Some(decision) = env_decision(timeout, &peer, info) {
        return decision;
    }

    if !cfg!(all(target_os = "windows", feature = "gui")) {
        return console_request(&peer, info);
    }

    let (id, rx) = match enqueue(peer, info, timeout) {
        Ok(v) => v,
        Err(()) => {
            crate::audit::log("queue_full", &peer, info, None);
            tracing::warn!("{peer}: too many pending connection requests; rejected");
            return false;
        }
    };
    crate::audit::log("pending", &peer, info, None);
    tracing::info!("{peer}: waiting for local approval ({info})");

    let created = Instant::now();
    loop {
        match rx.try_recv() {
            Ok(accept) => {
                let event = if accept { "accept" } else { "reject" };
                crate::audit::log(event, &peer, info, None);
                return accept;
            }
            Err(TryRecvError::Disconnected) => {
                remove(id);
                return false;
            }
            Err(TryRecvError::Empty) => {}
        }

        if created.elapsed() >= timeout {
            remove(id);
            crate::audit::log("timeout", &peer, info, None);
            tracing::info!("{peer}: approval timed out");
            return false;
        }
        if !peer_alive(stream) {
            remove(id);
            crate::audit::log("abandoned", &peer, info, None);
            tracing::info!("{peer}: client disconnected while waiting for approval");
            return false;
        }
        std::thread::sleep(POLL);
    }
}

fn env_decision(timeout: Duration, peer: &SocketAddr, info: &str) -> Option<bool> {
    let value = std::env::var("RESTSEND_VNC_APPROVAL").ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "accept" | "yes" => {
            crate::audit::log("accept", peer, info, None);
            Some(true)
        }
        "reject" | "no" => {
            crate::audit::log("reject", peer, info, None);
            Some(false)
        }
        "timeout" => {
            std::thread::sleep(timeout);
            crate::audit::log("timeout", peer, info, None);
            Some(false)
        }
        _ => None,
    }
}

/// Console/headless fallback: ask on stdin, or fail closed.
fn console_request(peer: &SocketAddr, info: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        crate::audit::log("no_ui", peer, info, None);
        tracing::warn!(
            "{peer}: confirmation is required but no UI or terminal is available; rejected"
        );
        return false;
    }
    use std::io::Write;
    print!("\nConnection request from {peer}\n  {info}\nAccept? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let accepted = std::io::stdin().read_line(&mut line).is_ok()
        && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    crate::audit::log(if accepted { "accept" } else { "reject" }, peer, info, None);
    accepted
}

/// True unless the peer has definitely closed the connection. Used to dismiss
/// a stale prompt when a viewer gives up while the user is deciding.
fn peer_alive(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return true;
    }
    let mut byte = [0u8; 1];
    let res = stream.peek(&mut byte);
    let _ = stream.set_nonblocking(false);
    match res {
        Ok(0) => false,
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

// --- tray UI API -----------------------------------------------------------

/// Front of the queue, for the tray to display.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn front_pending() -> Option<PendingView> {
    let st = state().lock().unwrap();
    st.queue.front().map(|p| PendingView {
        id: p.id,
        peer: p.peer,
        info: p.info.clone(),
        deadline: p.created + p.timeout,
    })
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn is_pending(id: u64) -> bool {
    let st = state().lock().unwrap();
    st.queue.iter().any(|p| p.id == id)
}

/// Resolves a request. Safe to call after the waiter timed out (no-op).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn resolve(id: u64, accept: bool) {
    if let Some(p) = remove(id) {
        let _ = p.tx.try_send(accept);
    }
}

/// Rejects everything still queued (tray exit / shutdown).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn reject_all() {
    let drained: Vec<Pending> = {
        let mut st = state().lock().unwrap();
        st.queue.drain(..).collect()
    };
    for p in drained {
        let _ = p.tx.try_send(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    fn test_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap()
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:5901".parse().unwrap()
    }

    #[test]
    fn queue_is_fifo_and_capped() {
        let _guard = test_lock();
        reject_all();
        for i in 0..MAX_PENDING {
            enqueue(peer(), &format!("client {i}"), DEFAULT_TIMEOUT).expect("enqueue");
        }
        assert!(enqueue(peer(), "too many", DEFAULT_TIMEOUT).is_err());

        let first = front_pending().expect("front request");
        assert_eq!(first.info, "client 0");
        resolve(first.id, true);
        assert_eq!(front_pending().unwrap().info, "client 1");
        reject_all();
        assert!(front_pending().is_none());
    }

    #[test]
    fn resolve_delivers_decision_and_unknown_is_noop() {
        let _guard = test_lock();
        reject_all();
        let (id, rx) = enqueue(peer(), "client", DEFAULT_TIMEOUT).unwrap();
        resolve(id, true);
        assert_eq!(rx.recv_timeout(Duration::from_millis(100)), Ok(true));
        // Late/unknown ids must not panic or affect other requests.
        resolve(id, false);
        resolve(9999, false);
        assert!(!is_pending(id));
    }

    #[test]
    fn reject_all_delivers_false() {
        let _guard = test_lock();
        reject_all();
        let (id_a, rx_a) = enqueue(peer(), "a", DEFAULT_TIMEOUT).unwrap();
        let (_id_b, rx_b) = enqueue(peer(), "b", DEFAULT_TIMEOUT).unwrap();
        assert!(is_pending(id_a));
        reject_all();
        assert_eq!(rx_a.recv_timeout(Duration::from_millis(100)), Ok(false));
        assert_eq!(rx_b.recv_timeout(Duration::from_millis(100)), Ok(false));
        assert!(front_pending().is_none());
    }
}
