//! Per-connection session: handshake, message loop, framebuffer updates,
//! input injection, clipboard and file transfer.
//!
//! Threading model per session:
//! - reader thread (this module's main flow): reads client messages, injects
//!   input, handles clipboard/file-transfer, mutates the shared encoder state;
//! - pusher thread: owns the framebuffer-update machinery and pushes
//!   incremental updates at the configured fps (Apple 3.889 clients never send
//!   FramebufferUpdateRequests — they expect server-push — so updates are
//!   driven here for every client uniformly);
//! - writer thread: serialises all socket writes from a bounded channel.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flate2::Compress;

use crate::clipboard::ClipboardHub;
use crate::diff::{diff_tiles, Rect};
use crate::encode::{encode_rect, Encoding};
use crate::framebuffer::{Frame, ScreenState};
use crate::input::InputBackend;
use crate::rfb::filetransfer::{self, ShareRoot, UploadState};
use crate::rfb::handshake::{self, HandshakeError};
use crate::rfb::messages::{self, pseudo, rect_header, ClientMessage, UploadPayload};
use crate::rfb::pixel::{PixelEncoder, PixelFormat};

/// Maximum bytes of pixel data queued per framebuffer update. Large
/// full-screen changes (video) are split across several ticks so one update
/// can never stall the stream for long (latency > throughput).
const MAX_UPDATE_BYTES: usize = 1 << 20;
/// Cap on the raw bytes of a single rect. Large dirty areas (window drag,
/// video) are encoded as horizontal strips so one encode never blocks the
/// stream for hundreds of milliseconds.
const MAX_RECT_RAW: usize = 512 << 10;
const DOWNLOAD_CHUNK: usize = 8192;
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a session waits for the first captured frame (viewer connect
/// timeouts are typically ~30s; keep well below).
const FIRST_FRAME_WAIT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct SessionConfig {
    pub name: String,
    pub view_only: bool,
    /// Test-pattern mode has no meaningful screen to control; injection is off.
    pub input_enabled: bool,
    /// Test-pattern mode visualizes received input in the pattern instead.
    pub test_pattern: bool,
    pub share_root: Option<Arc<ShareRoot>>,
    pub clipboard_enabled: bool,
}

/// Session writer channel message.
enum OutMsg {
    /// Pre-serialized wire bytes (plaintext or encrypted, depending on state).
    Data(Vec<u8>),
    /// Switch the Apple 3.889 writer to the encrypted frame channel.
    Activate(crate::rfb::apple_auth::AppleStreamCipher),
}

pub fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<ScreenState>,
    password: Option<String>,
    cfg: SessionConfig,
    hub: Arc<ClipboardHub>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    // Larger send buffer: helps keep throughput up on Wi-Fi / higher RTT
    // links where the default (64K) throttles the window.
    let sock = socket2::SockRef::from(&stream);
    let _ = sock.set_send_buffer_size(1 << 20);
    let trace_path = std::env::var("RESTSEND_VNC_TRACE_INBOUND").ok();

    // --- handshake (needs both directions) ---
    let mut reader_stream = stream.try_clone()?;
    let session_reader_stream = reader_stream.try_clone()?;
    let mut reader = std::io::BufReader::new(&mut reader_stream);
    let mut writer_stream = stream;

    let hs = match handshake::perform(
        &mut reader,
        &mut writer_stream,
        password.as_deref(),
        cfg.share_root.is_some() && !cfg.view_only,
    ) {
        Ok(hs) => hs,
        // Port scans / Bonjour probes open and close without speaking RFB.
        Err(HandshakeError::Protocol(msg)) if msg.contains("during version exchange") => {
            tracing::debug!("{peer}: connection closed before handshake ({msg})");
            return Ok(());
        }
        Err(e) => {
            tracing::warn!("{peer}: handshake failed: {e}");
            return Ok(());
        }
    };
    state.set_peer(peer.to_string());
    let client_info = format!(
        "RFB3.{:02} {}{}",
        hs.minor,
        match hs.auth {
            crate::rfb::handshake::AuthMethod::None => "NONE",
            crate::rfb::handshake::AuthMethod::VncAuth => "VNC-AUTH",
            crate::rfb::handshake::AuthMethod::AppleDh => "APPLE-DH",
        },
        if hs.tight { " TIGHT" } else { "" }
    );
    state.set_client_info(client_info.clone());
    crate::audit::log("connect", &peer, &client_info, None);
    let session_started = Instant::now();
    tracing::info!(
        "handshake from {peer}: rfb 3.{:02}, security type {}, auth={:?}, tight={}",
        hs.minor,
        hs.security_type,
        hs.auth,
        hs.tight
    );

    // --- wait for the first captured frame so ServerInit carries real dims ---
    let deadline = Instant::now() + FIRST_FRAME_WAIT;
    let mut current = state.snapshot();
    while current.dims() == (0, 0) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        current = state.snapshot();
    }
    if current.dims() == (0, 0) {
        tracing::warn!(
            "no frame captured yet after {:?}; check capture logs above \
             (rvnc needs an interactive desktop session on Windows)",
            FIRST_FRAME_WAIT
        );
    }
    let (w, h) = if current.dims() == (0, 0) {
        (0u16, 0u16)
    } else {
        (current.width as u16, current.height as u16)
    };

    // --- server init ---
    let pf = PixelFormat::native();
    let mut init = Vec::with_capacity(46 + cfg.name.len());
    init.extend_from_slice(&w.to_be_bytes());
    init.extend_from_slice(&h.to_be_bytes());
    pf.write(&mut init);
    // Apple 3.889 clients set the high bit in ClientInit and expect the
    // extended ARD ServerInit ("RFBServerInfo2"): a u32 extra length, then
    // 22 bytes of server information followed by the machine name.
    let extended = std::env::var_os("RESTSEND_VNC_APPLE_EXTINIT").is_some()
        && (hs.minor == 889 || hs.client_init & 0x80 != 0);
    if extended {
        let extralen = 22 + cfg.name.len();
        init.extend_from_slice(&(extralen as u32).to_be_bytes());
        init.extend_from_slice(&[0u8, 0u8]); // u16 reserved
        let flags: u32 = std::env::var("RESTSEND_VNC_APPLE_FLAGS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        init.extend_from_slice(&flags.to_be_bytes()); // flags (bit0/bit1)
        // Server info block (AppleVNCServer's gServerInfo: magic + feature
        // flags; the default table advertises commands 34..39).
        // Capability bitmask. Byte 2 bit 5 (command 18) advertises stream
        // encryption; clearing it keeps frames plaintext while the clipboard
        // bits (commands 25/35, byte 3 bit 6 / byte 4 bit 4) stay set.
        let no_enc = std::env::var_os("RESTSEND_VNC_APPLE_NO_ENC").is_some();
        let mut caps = [
            0xbf, 0xf6, 0xe7, 0xe3, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        if no_enc {
            caps[2] &= !0x20;
        }
        init.extend_from_slice(&caps);
        init.extend_from_slice(cfg.name.as_bytes());
    } else {
        init.extend_from_slice(&(cfg.name.len() as u32).to_be_bytes());
        init.extend_from_slice(cfg.name.as_bytes());
    }
    writer_stream.write_all(&init)?;
    writer_stream.flush()?;

    // --- Tight interaction caps (advertises file-transfer extensions) ---
    if hs.tight {
        send_interaction_caps(&mut writer_stream, cfg.share_root.is_some() && !cfg.view_only)?;
    }

    // --- ARD encrypted frame channel (experimental, extended-init clients) ---
    // First send the plaintext key/IV setup pseudo-rect, then seal every
    // subsequent server->client message with AES-128-CBC.
    let mut pending_setup: Option<Vec<u8>> = None;
    let mut pending_cipher: Option<crate::rfb::apple_auth::AppleStreamCipher> = None;
    let apple_no_enc = std::env::var_os("RESTSEND_VNC_APPLE_NO_ENC").is_some();
    if extended && !apple_no_enc {
        if let Some(dh) = hs.apple_key {
            let mut key = [0u8; 16];
            let mut iv = [0u8; 16];
            let _ = getrandom::fill(&mut key);
            let _ = getrandom::fill(&mut iv);
            pending_setup = Some(crate::rfb::apple_auth::encryption_setup_message(
                &dh, &key, &iv,
            ));
            let seq0: u32 = std::env::var("RESTSEND_VNC_APPLE_SEQ0")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let reset = std::env::var_os("RESTSEND_VNC_APPLE_CBC_RESET").is_some();
            pending_cipher = Some(
                crate::rfb::apple_auth::AppleStreamCipher::new(key, iv, seq0)
                    .with_iv_reset(reset),
            );
        }
    }

    // --- writer thread ---
    let (tx, rx) = std::sync::mpsc::sync_channel::<OutMsg>(256);
    let queue_depth = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let writer_thread = std::thread::Builder::new()
        .name("restsend-vnc-session-writer".into())
        .spawn({
            let depth = Arc::clone(&queue_depth);
            move || writer_loop(writer_stream, rx, depth)
        })
        .expect("spawn session writer");

    // --- shared encoder state + update pusher thread ---
    // ServerCutText is harmful to Apple clients (corrupts their protocol
    // state), so Apple sessions never receive clipboard broadcasts — they
    // sync their clipboard via type-16 pushes instead.
    let apple_client = hs.minor == 889;
    let client_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let enc: Arc<Mutex<EncState>> = Arc::new(Mutex::new(EncState {
        encodings: Vec::new(),
        encoder: PixelEncoder::new(pf),
    }));
    // Every client is server-push fed: the pusher thread publishes
    // incremental updates at the configured fps. (Apple 3.889 clients send
    // only an initial full FBUR and then expect continuous server-push.)
    let mut updater = Updater {
        tx: tx.clone(),
        state: Arc::clone(&state),
        enc: Arc::clone(&enc),
        client_ready: Arc::clone(&client_ready),
        cached: Arc::new(Frame::new(0, 0)),
        client_dims: (w as u32, h as u32),
        zrle: None,
        stats_at: Instant::now(),
        stats_updates: 0,
        stats_bytes: 0,
        dbg_at: Instant::now(),
        dbg_updates: 0,
        dbg_bytes: 0,
        dbg_encode_ns: 0,
        stats_encode_ns: 0,
        dropped: 0,
        queue_depth: Arc::clone(&queue_depth),
        frame_interval: Duration::from_millis(1000 / state.max_fps.max(1) as u64),
        force_next: false,
        pending: Vec::new(),
        fbur_seen: 0,
    };
    std::thread::Builder::new()
        .name("restsend-vnc-session-pusher".into())
        .spawn(move || updater.run())
        .expect("spawn session pusher");

    // View-only sessions must not receive the host clipboard (privacy), and
    // Apple 3.889 clients don't handle standard ServerCutText (it corrupts
    // their protocol state) — they sync their clipboard via type-16 pushes.
    let clipboard_receive = cfg.clipboard_enabled && !cfg.view_only;
    let session_id = if clipboard_receive {
        // The hub speaks raw bytes; forward them into the writer channel.
        let (clip_tx, clip_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(64);
        let fwd = tx.clone();
        std::thread::Builder::new()
            .name("restsend-vnc-clip-fwd".into())
            .spawn(move || {
                while let Ok(v) = clip_rx.recv() {
                    if fwd.send(OutMsg::Data(v)).is_err() {
                        break;
                    }
                }
            })
            .ok();
        if apple_client {
            hub.register_apple(clip_tx)
        } else {
            hub.register(clip_tx)
        }
    } else {
        0
    };

    let mut session = Session {
        state,
        cfg,
        hub,
        tx,
        queue_depth: Arc::clone(&queue_depth),
        session_id,
        reader_stream: session_reader_stream,
        apple_key: hs.apple_key,
        apple_seq: Arc::new(std::sync::atomic::AtomicU32::new(
            std::env::var("RESTSEND_VNC_APPLE_SEQ")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        )),
        apple_info_sent: false,
        apple_auto_cmd: None,
        pending_setup,
        pending_cipher,
        enc: Arc::clone(&enc),
        client_ready: Arc::clone(&client_ready),
        screen_dims: (w as u32, h as u32),
        input: None,
        upload: None,
        ctrl_held: false,
        last_mask: 0,
        cheat_clicks: 0,
        cheat_at: None,
    };

    // Tell Apple 3.889 viewers about the pasteboard so they enable the
    // shared-clipboard UI. AppleVNCServer sends this when the pasteboard
    // changes (well after startup), so delay it until the client finished
    // its initial handshake.
    // Apple 3.889 viewers need an AutoPasteboardInfo notification before the
    // shared-clipboard menu items become usable. AppleVNCServer emits it as a
    // plaintext control message (message type 20, cmd 2) while the session is
    // still unencrypted; we do the same shortly after startup.
    if session.apple_key.is_some() && std::env::var_os("RESTSEND_VNC_APPLE_NO_INFO").is_none() {
        let tx = session.tx.clone();
        std::thread::Builder::new()
            .name("restsend-vnc-apple-info".into())
            .spawn(move || {
                std::thread::sleep(Duration::from_secs(1));
                let payload = crate::rfb::apple_auth::auto_pasteboard_info(2);
                let _ = tx.try_send(OutMsg::Data(payload.to_vec()));
            })
            .ok();
    }
    session.apple_info_sent = true;

    let result = match trace_path
        .as_ref()
        .and_then(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).ok())
    {
        Some(mut file) => {
            let mut tee = TeeReader {
                inner: &mut reader,
                out: &mut file,
            };
            session.run(&mut tee, peer)
        }
        None => session.run(&mut reader, peer),
    };
    let duration = session_started.elapsed();
    let reason = match &result {
        Ok(()) => "closed".to_string(),
        Err(e) => e.to_string(),
    };
    crate::audit::log(
        "disconnect",
        &peer,
        &format!("{client_info} reason={reason}"),
        Some(duration),
    );
    session.hub.unregister(session.session_id);
    session.state.clear_session();
    drop(session.tx); // closes channel -> writer exits
    let _ = writer_thread.join();

    match result {
        Ok(()) => tracing::info!("session ended: {peer}"),
        Err(e) => tracing::info!("session ended: {peer} ({e})"),
    }
    Ok(())
}

/// macOS Screen Sharing maps Command to Alt_L and Option to Meta_L on the
/// wire. Windows users expect Command -> Ctrl and Option -> Alt, so remap the
/// modifier keysyms for Apple clients only.
fn apple_keysym_target(keysym: u32) -> u32 {
    use crate::rfb::keysym as ks;
    match keysym {
        ks::ALT_L => ks::CONTROL_L,
        ks::ALT_R => ks::CONTROL_R,
        ks::META_L => ks::ALT_L,
        ks::META_R => ks::ALT_R,
        k => k,
    }
}

fn writer_loop(
    mut stream: TcpStream,
    rx: std::sync::mpsc::Receiver<OutMsg>,
    depth: Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut cipher: Option<crate::rfb::apple_auth::AppleStreamCipher> = None;
    while let Ok(msg) = rx.recv() {
        let ok = match msg {
            OutMsg::Activate(c) => {
                cipher = Some(c);
                true
            }
            OutMsg::Data(data) => {
                let _ = depth.fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
                match cipher.as_mut() {
                None => stream.write_all(&data).is_ok(),
                    Some(c) => data
                        .chunks(0x8000)
                        .all(|chunk| stream.write_all(&c.seal(chunk)).is_ok()),
                }
            }
        };
        if !ok {
            return;
        }
        let _ = stream.flush();
    }
}

/// Tight protocol interaction capabilities sent right after ServerInit.
/// Without these, Tight-family viewers keep the file-transfer UI disabled.
fn send_interaction_caps(stream: &mut TcpStream, ft_enabled: bool) -> std::io::Result<()> {
    const TGHT: &[u8; 4] = b"TGHT";
    const STDV: &[u8; 4] = b"STDV";
    fn cap(code: i32, vendor: &[u8; 4], name: &[u8; 8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&(code as u32).to_be_bytes());
        v.extend_from_slice(vendor);
        v.extend_from_slice(name);
        v
    }

    let mut smsg = Vec::new();
    let mut cmsg = Vec::new();
    if ft_enabled {
        smsg.extend(cap(130, TGHT, b"FTS_LSDT"));
        smsg.extend(cap(131, TGHT, b"FTS_DNDT"));
        smsg.extend(cap(132, TGHT, b"FTS_UPCN"));
        smsg.extend(cap(133, TGHT, b"FTS_DNFL"));
        cmsg.extend(cap(130, TGHT, b"FTC_LSRQ"));
        cmsg.extend(cap(131, TGHT, b"FTC_DNRQ"));
        cmsg.extend(cap(132, TGHT, b"FTC_UPRQ"));
        cmsg.extend(cap(133, TGHT, b"FTC_UPDT"));
        cmsg.extend(cap(134, TGHT, b"FTC_DNCN"));
        cmsg.extend(cap(135, TGHT, b"FTC_UPFL"));
        cmsg.extend(cap(136, TGHT, b"FTC_FCDR"));
    }

    let mut enc = Vec::new();
    enc.extend(cap(0, STDV, b"RAW_____"));
    enc.extend(cap(5, STDV, b"HEXTILE_"));
    enc.extend(cap(16, STDV, b"ZRLE____"));
    enc.extend(cap(-223, TGHT, b"NEWFBSIZ"));

    let mut out = Vec::new();
    out.extend_from_slice(&((smsg.len() / 16) as u16).to_be_bytes());
    out.extend_from_slice(&((cmsg.len() / 16) as u16).to_be_bytes());
    out.extend_from_slice(&((enc.len() / 16) as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // reserved
    out.extend_from_slice(&smsg);
    out.extend_from_slice(&cmsg);
    out.extend_from_slice(&enc);
    stream.write_all(&out)?;
    stream.flush()
}

/// Debug aid: force a specific encoding regardless of the client's list.
/// `RESTSEND_VNC_FORCE_ENCODING=raw|hextile|zrle`.
fn encoding_override() -> Option<Encoding> {
    match std::env::var("RESTSEND_VNC_FORCE_ENCODING").ok()?.as_str() {
        "raw" => Some(Encoding::Raw),
        "hextile" => Some(Encoding::Hextile),
        "zrle" => Some(Encoding::Zrle),
        _ => None,
    }
}

/// Reader wrapper that dumps every client->server byte to a file
/// (`RESTSEND_VNC_TRACE_INBOUND=<path>`) for protocol analysis.
struct TeeReader<'a, R> {
    inner: R,
    out: &'a mut std::fs::File,
}

impl<R: std::io::Read> std::io::Read for TeeReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            let _ = self.out.write_all(&buf[..n]);
            let _ = self.out.flush();
        }
        Ok(n)
    }
}

/// Encoder/pixel-format state shared between reader and pusher threads.
struct EncState {
    encodings: Vec<i32>,
    encoder: PixelEncoder,
}

/// Pusher thread state: owns the framebuffer-update machinery.
struct Updater {
    tx: SyncSender<OutMsg>,
    state: Arc<ScreenState>,
    enc: Arc<Mutex<EncState>>,
    /// Set once the client sends its first post-init message; pushing before
    /// that would interleave framebuffer data with the client's own init.
    client_ready: Arc<std::sync::atomic::AtomicBool>,
    cached: Arc<Frame>,
    client_dims: (u32, u32),
    zrle: Option<Compress>,
    stats_at: Instant,
    stats_updates: u64,
    stats_bytes: u64,
    /// 1s window for the debug overlay.
    dbg_at: Instant,
    dbg_updates: u64,
    dbg_bytes: u64,
    dbg_encode_ns: u64,
    stats_encode_ns: u64,
    dropped: u64,
    queue_depth: Arc<std::sync::atomic::AtomicUsize>,
    frame_interval: Duration,
    /// True when the previous update had to defer rects (byte cap).
    force_next: bool,
    /// Rects deferred by the byte cap, sent first on the next tick.
    pending: Vec<Rect>,
    /// FBUR counter (diagnostics for the Apple FBUR-driven path).
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fbur_seen: u64,
}

fn contains_rect(outer: &Rect, inner: &Rect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && inner.x as u32 + inner.w as u32 <= outer.x as u32 + outer.w as u32
        && inner.y as u32 + inner.h as u32 <= outer.y as u32 + outer.h as u32
}

/// Splits `rect` into horizontal strips whose raw BGRA size is <= `max_raw`.
fn split_rect(out: &mut Vec<Rect>, rect: Rect, bpp: usize, max_raw: usize) {
    if rect.w == 0 || rect.h == 0 {
        return;
    }
    let raw = rect.w as usize * rect.h as usize * bpp;
    if raw <= max_raw {
        out.push(rect);
        return;
    }
    let row_bytes = (rect.w as usize * bpp).max(1);
    let rows = (max_raw / row_bytes).max(1) as u16;
    let mut y = 0u16;
    while y < rect.h {
        let h = rows.min(rect.h - y);
        out.push(Rect {
            x: rect.x,
            y: rect.y + y,
            w: rect.w,
            h,
        });
        y += h;
    }
}

impl Updater {
    /// Pusher main loop: publish incremental updates at the configured fps.
    fn run(&mut self) {
        use std::sync::atomic::Ordering;
        // Wait (bounded) until the client starts talking post-init AND has
        // negotiated encodings (pushing before that would race its init).
        let ready_at = Instant::now();
        loop {
            let encodings_known = !self.enc.lock().unwrap().encodings.is_empty();
            if (self.client_ready.load(Ordering::Relaxed) && encodings_known)
                || ready_at.elapsed() > FIRST_FRAME_WAIT * 2
                || self.state.is_stopped()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        if !self.enc.lock().unwrap().encodings.is_empty() {
            tracing::debug!("pusher: starting, encodings negotiated");
        }
        let mut first = true;
        let mut last_pushed_gen = u64::MAX;
        loop {
            if self.state.is_stopped() {
                return;
            }
            let last_generation = self.state.generation();
            let started = Instant::now();
            // Skip the whole diff/encode pass when the capture thread has not
            // produced a new frame (the common case for a static desktop).
            let behind = self.queue_depth.load(Ordering::Relaxed) > 8;
            if !first && behind {
                // Client/link is behind: skip this encode, but do NOT mark the
                // generation as pushed — the dirty frame is retried next tick.
            } else if first || self.force_next || last_generation != last_pushed_gen {
                let incremental = !first && self.cached.dims() == {
                    let snap = self.state.snapshot();
                    snap.dims()
                };
                let t0 = Instant::now();
                if std::env::var_os("RESTSEND_VNC_NO_FRAMES").is_some() {
                    // Experiment: keep the session alive without frames.
                    first = false;
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                let complete =
                    self.send_update(incremental, Rect::new(0, 0, u16::MAX, u16::MAX))
                        .unwrap_or(false);
                let enc_ns = t0.elapsed().as_nanos() as u64;
                self.dbg_encode_ns += enc_ns;
                self.stats_encode_ns += enc_ns;
                self.force_next = !complete;
                self.force_next |= !self.pending.is_empty();
                last_pushed_gen = last_generation;
            }
            first = false;

            if self.dbg_at.elapsed() >= Duration::from_secs(1) {
                let secs = self.dbg_at.elapsed().as_secs_f32().max(1e-3);
                let fps = self.dbg_updates as f32 / secs;
                let kb_s = self.dbg_bytes as f32 / 1024.0 / secs;
                let enc_ms = if self.dbg_updates > 0 {
                    self.dbg_encode_ns as f32 / 1e6 / self.dbg_updates as f32
                } else {
                    0.0
                };
                self.state.set_push_stats(fps, kb_s, enc_ms, self.dropped);
                self.dbg_at = Instant::now();
                self.dbg_updates = 0;
                self.dbg_bytes = 0;
                self.dbg_encode_ns = 0;
            }

            if self.stats_at.elapsed() >= Duration::from_secs(10) {
                let (updates, bytes) = (self.stats_updates, self.stats_bytes);
                let enc_ms = if updates > 0 {
                    self.stats_encode_ns as f32 / 1e6 / updates as f32
                } else {
                    0.0
                };
                self.stats_encode_ns = 0;
                tracing::info!(
                    "pusher: {updates} framebuffer updates, {bytes} bytes in the last 10s, \
                     enc {enc_ms:.1} ms/update"
                );
                self.stats_updates = 0;
                self.stats_bytes = 0;
                self.stats_at = Instant::now();
            }

            let elapsed = started.elapsed();
            if elapsed < self.frame_interval {
                // Responsiveness: wake up as soon as the capture thread has a
                // newer frame instead of sleeping the whole frame interval.
                // The --fps value still caps the update rate.
                let wait = self.frame_interval - elapsed;
                let mut waited = Duration::ZERO;
                while waited < wait {
                    let step = Duration::from_millis(2).min(wait - waited);
                    std::thread::sleep(step);
                    waited += step;
                    if self.state.generation() != last_generation {
                        break;
                    }
                }
            }
        }
    }

    /// Queues wire bytes for the writer thread. Blocks (up to SEND_TIMEOUT)
    /// while the client is not consuming, then gives up.
    fn send(&self, msg: Vec<u8>) -> std::io::Result<()> {
        let mut slot = Some(OutMsg::Data(msg));
        let deadline = Instant::now() + SEND_TIMEOUT;
        loop {
            match self.tx.try_send(slot.take().expect("send slot occupied")) {
                Ok(()) => {
                    self.queue_depth.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(TrySendError::Full(m)) => {
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "client is not consuming updates",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                    slot = Some(m);
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "writer closed",
                    ))
                }
            }
        }
    }

    /// Non-blocking send used by the frame pusher: a full queue means the
    /// client is behind, so the frame is dropped rather than blocking.
    fn send_drop(&mut self, msg: Vec<u8>) -> std::io::Result<()> {
        match self.tx.try_send(OutMsg::Data(msg)) {
            Ok(()) => {
                self.queue_depth.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                self.dropped += 1;
                Ok(())
            }
            Err(TrySendError::Disconnected(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "writer closed",
            )),
        }
    }

    fn send_update(&mut self, incremental: bool, region: Rect) -> std::io::Result<bool> {
        let current = self.state.snapshot();
        if current.dims() == (0, 0) {
            let _ = self.send(messages::framebuffer_update_header(0));
            return Ok(true);
        }

        // Resolution changed since the client last saw the framebuffer?
        if current.dims() != self.client_dims {
            let (encodings, _) = self.enc_state();
            if encodings.contains(&pseudo::NEW_FB_SIZE) {
                let mut msg = messages::framebuffer_update_header(1);
                msg.extend(rect_header(
                    0,
                    0,
                    current.width as u16,
                    current.height as u16,
                    pseudo::NEW_FB_SIZE,
                ));
                self.client_dims = current.dims();
                self.cached = Arc::clone(&current);
                tracing::debug!("sent NewFBSize {}x{}", current.width, current.height);
                let _ = self.send(msg);
                return Ok(true);
            }
            // Clients without resize support just get the new-size pixels.
        }

        let (encodings, encoder) = self.enc_state();
        let encoding = encoding_override().unwrap_or_else(|| Encoding::pick(&encodings));
        // Deferred rects from the previous tick take priority: otherwise a
        // continuously changing screen would always re-send the top and never
        // reach the bottom.
        // Always diff the whole frame: deferred (pending) rects are sent
        // first for fairness, but skipping the diff here would leave every
        // other region that changed during the drain permanently stale
        // (visible as torn/undeleted blocks while dragging).
        let mut rects = if incremental && self.cached.dims() == current.dims() {
            diff_tiles(&self.cached, &current, region)
        } else {
            region
                .clamp(current.width, current.height)
                .into_iter()
                .collect::<Vec<_>>()
        };
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            // Drop diff rects fully covered by a pending rect to avoid
            // sending the same pixels twice in one tick.
            rects.retain(|r| !pending.iter().any(|q| contains_rect(q, r)));
            let mut merged = pending;
            merged.extend(rects);
            rects = merged;
        }

        // Split oversized rects into strips to bound per-rect encode time.
        let mut expanded: Vec<Rect> = Vec::new();
        for r in rects.drain(..) {
            split_rect(&mut expanded, r, encoder.bytes_per_pixel().max(1), MAX_RECT_RAW);
        }
        rects = expanded;

        // Encode rects under a per-update byte cap; leftovers are restored
        // into the cached frame so the next push re-diffs them.
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut total: usize = 0;
        let mut unsent: Vec<Rect> = Vec::new();
        for rect in rects.drain(..) {
            let estimate = rect.w as usize * rect.h as usize * encoder.bytes_per_pixel();
            if !payloads.is_empty() && total + estimate > MAX_UPDATE_BYTES {
                unsent.push(rect);
                continue;
            }
            let mut payload = rect_header(rect.x, rect.y, rect.w, rect.h, encoding.code());
            encode_rect(
                &mut payload,
                &current,
                rect,
                encoding,
                &encoder,
                &mut self.zrle,
            )?;
            total += payload.len();
            payloads.push(payload);
        }

        let nrects = payloads.len();
        if nrects == 0 {
            // Nothing changed: don't burn a wakeup on an empty update.
            return Ok(true);
        }
        let mut msg = messages::framebuffer_update_header(nrects as u16);
        for p in payloads {
            msg.extend_from_slice(&p);
        }
        let msg_bytes = msg.len();
        // Real-time path: drop the frame if the writer is still busy instead
        // of stalling the capture/push loop (stutter).
        self.send_drop(msg)?;

        // The shared cached frame is always the latest capture; deferred rects
        // are tracked explicitly in `pending`, so no full-frame clone is
        // needed here.
        self.pending = unsent;
        self.cached = Arc::clone(&current);
        self.stats_updates += 1;
        self.stats_bytes += msg_bytes as u64;
        self.dbg_updates += 1;
        self.dbg_bytes += msg_bytes as u64;
        Ok(self.pending.is_empty())
    }

    fn enc_state(&self) -> (Vec<i32>, PixelEncoder) {
        let st = self.enc.lock().unwrap();
        (st.encodings.clone(), st.encoder.clone())
    }
}

/// Session reader state (thread-local to the reader thread).
struct Session {
    state: Arc<ScreenState>,
    cfg: SessionConfig,
    hub: Arc<ClipboardHub>,
    tx: SyncSender<OutMsg>,
    queue_depth: Arc<std::sync::atomic::AtomicUsize>,
    #[allow(dead_code)]
    session_id: u64,
    /// Socket clone used to tweak read timeouts during Apple clipboard drains.
    #[allow(dead_code)]
    reader_stream: TcpStream,
    apple_key: Option<[u8; 16]>,
    /// Server->client control-message sequence counter (Apple 3.889 only).
    #[allow(dead_code)]
    apple_seq: Arc<std::sync::atomic::AtomicU32>,
    /// Whether the initial AutoPasteboardInfo was already pushed.
    apple_info_sent: bool,
    /// Last auto-pasteboard command from the viewer (1 = enabled).
    apple_auto_cmd: Option<u16>,
    /// Plaintext ARD encryption-setup rect (sent on first SetEncodings).
    pending_setup: Option<Vec<u8>>,
    /// Cipher activated right after the setup rect has been queued.
    pending_cipher: Option<crate::rfb::apple_auth::AppleStreamCipher>,
    enc: Arc<Mutex<EncState>>,
    client_ready: Arc<std::sync::atomic::AtomicBool>,
    screen_dims: (u32, u32),
    input: Option<InputBackend>,
    upload: Option<UploadState>,
    /// Ctrl state as seen from the client (for the debug-panel shortcut).
    ctrl_held: bool,
    /// Last pointer button mask (edge detection).
    last_mask: u8,
    /// Ctrl+click shortcut state: clicks counted and when the window started.
    cheat_clicks: u8,
    cheat_at: Option<Instant>,
}

impl Session {
    fn run(&mut self, reader: &mut impl std::io::Read, peer: SocketAddr) -> std::io::Result<()> {
        let ft_enabled = self.cfg.share_root.is_some() && !self.cfg.view_only;
        loop {
            let msg = messages::read_client_message(reader, ft_enabled)?;
            self.dispatch(msg, peer, reader)?;
        }
    }

    /// Sends one encrypted ARD control message (AutoPasteboardInfo) to an
    /// Apple 3.889 viewer, bumping the server->client sequence counter.
    #[allow(dead_code)]
    fn send_apple_control(&mut self, cmd: u8) {
        let Some(key) = self.apple_key else { return };
        let payload = crate::rfb::apple_auth::auto_pasteboard_info(cmd);
        use std::sync::atomic::Ordering;
        let seq = self.apple_seq.fetch_add(1, Ordering::Relaxed);
        let msg = crate::rfb::apple_auth::encrypt_server_message(&key, seq, &payload);
        if let Err(e) = self.tx.try_send(OutMsg::Data(msg)) {
            tracing::debug!("apple control send failed: {e}");
        }
    }

    fn dispatch(
        &mut self,
        msg: ClientMessage,
        peer: SocketAddr,
        _reader: &mut impl std::io::Read,
    ) -> std::io::Result<()> {
        match msg {
            ClientMessage::SetPixelFormat(fmt) => {
                tracing::debug!("{peer}: pixel format -> {fmt:?}");
                self.enc.lock().unwrap().encoder = PixelEncoder::new(fmt);
            }
            ClientMessage::SetEncodings(encodings) => {
                tracing::debug!("{peer}: encodings -> {:?}", encodings);
                self.enc.lock().unwrap().encodings = encodings;
                // ARD encrypted frame channel: the setup rect must follow the
                // client's first SetEncodings; encryption starts right after.
                if let Some(setup) = self.pending_setup.take() {
                    let _ = self.tx.try_send(OutMsg::Data(setup));
                }
                if let Some(cipher) = self.pending_cipher.take() {
                    let _ = self.tx.try_send(OutMsg::Activate(cipher));
                }
                // Client finished negotiating encodings: the pusher may now
                // start sending frames (Apple clients wait for server-push).
                use std::sync::atomic::Ordering;
                self.client_ready.store(true, Ordering::Relaxed);
            }
            ClientMessage::FramebufferUpdateRequest { .. } => {
                // Server-push model: the pusher thread publishes updates at
                // the configured fps; FBURs need no action.
            }
            ClientMessage::KeyEvent { down, keysym } => {
                tracing::debug!("{peer}: key {keysym:#06x} {}", if down { "down" } else { "up" });
                self.apply_key(keysym, down);
            }
            ClientMessage::PointerEvent { mask, x, y } => {
                tracing::debug!("{peer}: pointer {x},{y} mask {mask:#04x}");
                self.apply_pointer(x, y, mask);
            }
            ClientMessage::ClientCutText(text) => {
                if self.cfg.clipboard_enabled && !self.cfg.view_only {
                    tracing::debug!("{peer}: clipboard set ({} bytes)", text.len());
                    self.hub.mark_local(&text);
                    crate::clipboard::set_clipboard(&text);
                }
            }
            ClientMessage::AppleSession => {
                tracing::debug!("{peer}: Apple session-start message (ignored)");
            }
            ClientMessage::AppleViewerInfo(p) => {
                let hex: String = p.iter().take(16).map(|b| format!("{b:02x}")).collect();
                tracing::debug!("{peer}: Apple viewer info ({} bytes) head=[{hex}]", p.len());
            }
            ClientMessage::AppleAutoPasteboard(p) => {
                let cmd = u16::from_be_bytes([p[2], p[3]]);
                tracing::info!(
                    "{peer}: Apple auto-pasteboard command cmd={cmd} raw=[{}]",
                    p.iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
                self.apple_auto_cmd = Some(cmd);
            }
            ClientMessage::AppleEncrypted { subtype, block } => {
                let mut plain = block;
                if let Some(key) = self.apple_key {
                    crate::rfb::apple_auth::SessionCipher::new(&key).decrypt_block(&mut plain);
                }
                self.apple_input(subtype, &plain);
            }
            // --- file transfer ---
            ClientMessage::FileListRequest { flags, dir_name } => {
                self.ft_list(flags, &dir_name);
            }
            ClientMessage::FileDownloadRequest {
                compressed_level,
                position,
                file_name,
            } => {
                tracing::debug!("{peer}: download request level={compressed_level}");
                self.ft_download(&file_name, position)?;
            }
            ClientMessage::FileUploadRequest {
                compressed_level,
                position,
                file_name,
            } => {
                tracing::debug!("{peer}: upload request level={compressed_level}");
                self.ft_upload(&file_name, position);
            }
            ClientMessage::FileUploadData {
                compressed_level,
                payload,
            } => {
                self.ft_upload_data(compressed_level, payload);
            }
            ClientMessage::FileDownloadCancel(reason) => {
                tracing::info!("{peer}: download canceled by client: {reason}");
            }
            ClientMessage::FileUploadFailed(reason) => {
                tracing::info!("{peer}: upload failed on client: {reason}");
                self.upload = None;
            }
            ClientMessage::FileCreateDir(dir) => {
                self.ft_mkdir(&dir);
            }
        }
        Ok(())
    }

    fn ensure_input(&mut self) {
        if self.input.is_none()
            && self.screen_dims != (0, 0) {
                self.input = Some(InputBackend::for_platform(
                    self.screen_dims.0,
                    self.screen_dims.1,
                ));
            }
    }

    /// Applies a key event (shared by standard RFB and Apple clients).
    fn apply_key(&mut self, keysym: u32, down: bool) {
        if keysym == crate::rfb::keysym::CONTROL_L || keysym == crate::rfb::keysym::CONTROL_R {
            self.ctrl_held = down;
        }
        if self.cfg.test_pattern {
            // Demo mode: visualize received input in the pattern
            // (injecting into the local desktop would feed back into the
            // viewer on the same machine).
            self.state.echo_key(keysym, down);
        } else if !self.cfg.view_only && self.cfg.input_enabled {
            self.ensure_input();
            if let Some(input) = self.input.as_mut() {
                input.key(keysym, down);
            }
        }
    }

    /// Applies a pointer position/button update (shared by standard RFB and
    /// Apple clients). `mask` follows RFB bit order.
    fn apply_pointer(&mut self, x: u16, y: u16, mask: u8) {
        // Hidden shortcut: hold Ctrl and left-click 3 times (within 2s) to
        // toggle the debug overlay.
        let left_pressed = mask & 1 != 0 && self.last_mask & 1 == 0;
        self.last_mask = mask;
        if left_pressed
            && self.ctrl_held
            && crate::settings::ALLOW_DEBUG.load(Ordering::Relaxed)
        {
            let fresh = self
                .cheat_at
                .map(|t| t.elapsed() <= Duration::from_secs(2))
                .unwrap_or(false);
            if !fresh {
                self.cheat_clicks = 0;
                self.cheat_at = Some(Instant::now());
            }
            self.cheat_clicks += 1;
            if self.cheat_clicks >= 3 {
                self.cheat_clicks = 0;
                self.cheat_at = None;
                let on = self.state.toggle_debug();
                tracing::info!("debug overlay {}", if on { "ON" } else { "OFF" });
            }
        }
        if self.cfg.test_pattern {
            self.state.echo_pointer(x, y, mask);
        } else if !self.cfg.view_only && self.cfg.input_enabled {
            self.ensure_input();
            if let Some(input) = self.input.as_mut() {
                input.pointer(x, y, mask);
            }
        }
    }

    /// Decodes an Apple 3.889 encrypted client message (16-byte plaintext).
    ///
    /// The client uses two layouts inside the encrypted block:
    /// * key event: `[0]=0xff, [1]=down, [2..6]=keysym (BE u32)`
    /// * pointer:   `[10]=0xff, [11]=button mask, [12..14]=x, [14..16]=y`
    ///
    /// Anything else is logged (trace) so new Apple dialects can be captured.
    fn apple_input(&mut self, subtype: u8, p: &[u8; 16]) {
        if p[0] == 0xff {
            let down = p[1] != 0;
            let keysym = u32::from_be_bytes([p[2], p[3], p[4], p[5]]);
            if keysym != 0 {
                // macOS Screen Sharing sends Command as Alt_L (0xffe9) and
                // Option as Meta_L (0xffe7). On a Windows target the expected
                // mapping is Command -> Ctrl and Option -> Alt.
                let mapped = apple_keysym_target(keysym);
                tracing::trace!(
                    "apple key {keysym:#06x} -> {mapped:#06x} down={down} (subtype {subtype})"
                );
                self.apply_key(mapped, down);
            }
        } else if p[10] == 0xff {
            let x = u16::from_be_bytes([p[12], p[13]]);
            let y = u16::from_be_bytes([p[14], p[15]]);
            let mask = apple_button_mask(p[11]);
            tracing::trace!("apple pointer {x},{y} buttons={:#04x} (subtype {subtype})", p[11]);
            self.apply_pointer(x, y, mask);
        } else {
            let hex: String = p.iter().map(|b| format!("{b:02x}")).collect();
            tracing::trace!(
                "apple other subtype={subtype} plain=[{hex}] ascii={:?}",
                String::from_utf8_lossy(p)
            );
        }
    }

    /// Queues wire bytes for the writer thread. Blocks (up to SEND_TIMEOUT)
    /// while the client is not consuming, then gives up.
    fn send(&self, msg: Vec<u8>) -> std::io::Result<()> {
        let mut slot = Some(OutMsg::Data(msg));
        let deadline = Instant::now() + SEND_TIMEOUT;
        loop {
            match self.tx.try_send(slot.take().expect("send slot occupied")) {
                Ok(()) => {
                    self.queue_depth.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(TrySendError::Full(m)) => {
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "client is not consuming updates",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                    slot = Some(m);
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "writer closed",
                    ))
                }
            }
        }
    }

    // --- file transfer -------------------------------------------------------

    fn ft_list(&mut self, flags: u8, dir_name: &str) {
        let Some(root) = self.cfg.share_root.clone() else {
            return;
        };
        let msg = match root.resolve(dir_name) {
            Ok(path) => root.list_message(flags, &path),
            Err(e) => {
                tracing::debug!("list {dir_name:?} rejected: {e}");
                filetransfer::empty_list_data(flags)
            }
        };
        let _ = self.send(msg);
    }

    fn ft_download(&mut self, file_name: &str, position: u32) -> std::io::Result<()> {
        let Some(root) = self.cfg.share_root.clone() else {
            return Ok(());
        };
        let path = match root.resolve(file_name) {
            Ok(p) => p,
            Err(e) => {
                return self.send(filetransfer::download_failed_message(&format!(
                    "invalid path: {e}"
                )))
            }
        };
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                return self.send(filetransfer::download_failed_message(
                    "cannot open file: does not exist",
                ))
            }
        };
        if !meta.is_file() {
            return self.send(filetransfer::download_failed_message("not a regular file"));
        }
        let mtime = filetransfer::mtime_of(&path);
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                return self
                    .send(filetransfer::download_failed_message(&format!("open failed: {e}")))
            }
        };
        if position > 0 {
            use std::io::Seek;
            if file.seek(std::io::SeekFrom::Start(position as u64)).is_err() {
                return self.send(filetransfer::download_failed_message("invalid resume position"));
            }
        }
        tracing::info!("FT download: {} (resume at {position})", path.display());

        let mut buf = vec![0u8; DOWNLOAD_CHUNK];
        loop {
            use std::io::Read;
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let msg = filetransfer::download_chunk_message(&buf[..n]);
                    if self.send(msg).is_err() {
                        tracing::info!("FT download aborted (client stalled)");
                        return Ok(());
                    }
                }
                Err(e) => {
                    return self
                        .send(filetransfer::download_failed_message(&format!("read error: {e}")))
                }
            }
        }
        self.send(filetransfer::download_eof_message(mtime))?;
        tracing::info!("FT download complete: {}", path.display());
        Ok(())
    }

    fn ft_upload(&mut self, file_name: &str, position: u32) {
        let Some(root) = self.cfg.share_root.clone() else {
            return;
        };
        match UploadState::open(&root, file_name, position) {
            Ok(state) => {
                tracing::info!("FT upload: {} (resume at {position})", state.path.display());
                self.upload = Some(state);
            }
            Err(e) => {
                tracing::warn!("FT upload rejected: {e}");
                let _ = self.send(filetransfer::upload_cancel_message(&format!("{e}")));
            }
        }
    }

    fn ft_upload_data(&mut self, compressed_level: u8, payload: UploadPayload) {
        let Some(upload) = self.upload.as_mut() else {
            return; // stray data without a request
        };
        match payload {
            UploadPayload::Eof { mtime } => {
                tracing::info!(
                    "FT upload complete: {} ({} bytes)",
                    upload.path.display(),
                    upload.bytes_written
                );
                upload.finish(mtime);
                self.upload = None;
            }
            UploadPayload::Chunk { real_size, data } => {
                if let Err(e) = upload.write_chunk(compressed_level, real_size, &data) {
                    tracing::warn!("FT upload failed: {e}");
                    let _ = self.send(filetransfer::upload_cancel_message(&format!("{e}")));
                    self.upload = None;
                }
            }
        }
    }

    fn ft_mkdir(&mut self, dir: &str) {
        let Some(root) = self.cfg.share_root.clone() else {
            return;
        };
        match root.resolve(dir) {
            Ok(path) => {
                if let Err(e) = std::fs::create_dir_all(&path) {
                    tracing::warn!("FT mkdir {}: {e}", path.display());
                } else {
                    tracing::info!("FT mkdir {}", path.display());
                }
            }
            Err(e) => tracing::warn!("FT mkdir rejected: {e}"),
        }
    }

}

/// Converts an Apple Screen Sharing button mask to RFB/X11 order.
///
/// Apple's client uses `1 = left, 2 = right, 4 = other`, while RFB expects
/// `1 = left, 2 = middle, 4 = right` (RFC 6143 §7.5.6).
fn apple_button_mask(mask: u8) -> u8 {
    let mut out = 0u8;
    if mask & 1 != 0 {
        out |= 1; // left
    }
    if mask & 2 != 0 {
        out |= 4; // right
    }
    if mask & 4 != 0 {
        out |= 2; // middle
    }
    // Wheel: Apple uses the RFB button-4/5 bits directly.
    if mask & 0x08 != 0 {
        out |= 0x08; // wheel up
    }
    if mask & 0x10 != 0 {
        out |= 0x10; // wheel down
    }
    out
}



#[cfg(test)]
mod apple_key_tests {
    use super::apple_keysym_target;
    use crate::rfb::keysym as ks;

    #[test]
    fn apple_modifier_mapping() {
        assert_eq!(apple_keysym_target(ks::ALT_L), ks::CONTROL_L); // Command
        assert_eq!(apple_keysym_target(ks::META_L), ks::ALT_L); // Option
        assert_eq!(apple_keysym_target(ks::CONTROL_L), ks::CONTROL_L);
        assert_eq!(apple_keysym_target(0x63), 0x63);
    }
}
