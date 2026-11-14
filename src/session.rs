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

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flate2::Compress;

use crate::clipboard::ClipboardHub;
use crate::cursor::{
    cursor_rect, hidden_cursor_message, overlay_frame, pointer_pos_message, rich_cursor_message,
    CursorSnapshot,
};
use crate::diff::{diff_tiles, Rect};
use crate::encode::{encode_rect, Encoding};
use crate::framebuffer::{Frame, ScreenState};
use crate::input::InputBackend;
use crate::rfb::filetransfer::{self, ShareRoot, UploadState};
use crate::rfb::handshake::{self, HandshakeError};
use crate::rfb::messages::{self, pseudo, rect_header, ClientMessage, UploadPayload};
use crate::rfb::pixel::{PixelEncoder, PixelFormat};
use crate::throttle::{cursor_interval, ByteBudget};

/// Hard cap on the wire bytes of one framebuffer update. The time budget
/// below is the primary limiter; this only prevents pathological messages.
const MAX_UPDATE_BYTES: usize = 2 << 20;
/// Apple Screen Sharing treats each ARD record body as one RFB message, so an
/// encrypted framebuffer update must fit in a single record (<= 65498 bytes).
/// Keep a margin for the FBU and rectangle headers.
const APPLE_UPDATE_BYTES: usize = 60 << 10;
const APPLE_RECT_RAW: usize = APPLE_UPDATE_BYTES - 1024;
/// Bytes allowed to be queued/in flight before the pusher stops encoding.
/// Keeping roughly one 4K update in flight bounds latency without starving
/// the link. Larger than one max update so a burst can drain.
const FRAME_QUEUE_LIMIT: usize = (MAX_UPDATE_BYTES / 4) * 5;
/// Upper bound on the wall-clock budget for encoding one incremental update.
/// The actual value follows the frame interval (see `send_update`).
const MAX_UPDATE_BUDGET: Duration = Duration::from_millis(25);
/// Cap on the raw bytes of a single rect. Large dirty areas (window drag,
/// video) are encoded as horizontal strips so one encode never blocks the
/// stream for hundreds of milliseconds.
const MAX_RECT_RAW: usize = 2 << 20;
const DOWNLOAD_CHUNK: usize = 8192;
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound the RFB/TLS handshake so a slow or silent client cannot pin a
/// session thread forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
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
    /// Pre-serialized control bytes (clipboard, file transfer, pseudo-rects).
    Data(Vec<u8>),
    /// A framebuffer update, counted against the byte budget until written.
    Frame(Vec<u8>),
    /// Write the plaintext ARD 1103 setup rect, then switch the writer to the
    /// encrypted record layer. Kept as one message so the pusher cannot
    /// interleave a plaintext frame between the two steps.
    StartEncryption {
        setup: Vec<u8>,
        cipher: crate::rfb::apple_auth::AppleStreamCipher,
    },
}

pub fn handle_client(
    mut stream: TcpStream,
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
    // Kept until the session ends so a writer blocked in write_all() (or a
    // TLS pump blocked in poll) can be woken up; otherwise the threads and
    // the cached framebuffer leak after every disconnect.
    let shutdown_sock = stream.try_clone().ok();
    let trace_path = std::env::var("RESTSEND_VNC_TRACE_INBOUND").ok();

    // --- handshake (single duplex stream; VeNCrypt upgrades it to TLS) ---
    // No BufReader here: a client may pipeline its TLS ClientHello right
    // behind the VeNCrypt sub-type choice, and buffered bytes must not be
    // lost when the transport is replaced.
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let tls_mode = crate::settings::tls_mode();
    let tls_config = if tls_mode == crate::tls::Mode::Off {
        None
    } else {
        crate::tls::server_config()
    };
    let mut hs = match handshake::perform(
        &mut stream,
        password.as_deref(),
        cfg.share_root.is_some() && !cfg.view_only,
        tls_mode,
        tls_config,
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
    let _ = stream.set_read_timeout(None);
    let client_info = describe_client(&hs);

    // A local user can require manual approval for every new connection. This
    // runs after authentication (wrong passwords never prompt) and before
    // ServerInit, so a rejected client never receives any screen data.
    if !crate::approval::request(&stream, peer, &client_info) {
        tracing::info!("{peer}: connection not approved; closing");
        return Ok(());
    }

    // --- transport: plain socket halves or TLS pump ---
    let crate::transport::Io {
        reader,
        writer: mut writer_stream,
        pump,
    } = if let Some(conn) = hs.tls.take() {
        crate::transport::tls(conn, stream)?
    } else {
        crate::transport::plain(stream)?
    };
    let mut reader = reader;

    state.set_peer(peer.to_string());
    state.set_client_info(client_info.clone());
    crate::audit::log("connect", &peer, &client_info, None);
    let session_started = Instant::now();
    tracing::info!(
        "handshake from {peer}: rfb 3.{:02}, security type {}, auth={:?} ({}), tight={}",
        hs.minor,
        hs.security_type,
        hs.auth,
        if hs.encrypted {
            "encrypted"
        } else {
            "plaintext"
        },
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
    let extended = (hs.minor == 889 || hs.client_init & 0x80 != 0)
        && std::env::var_os("RESTSEND_VNC_APPLE_NO_EXT").is_none();
    if extended {
        let extralen = 22 + cfg.name.len();
        init.extend_from_slice(&(extralen as u32).to_be_bytes());
        init.extend_from_slice(&[0u8, 0u8]); // u16 reserved
                                             // bit 4 = extended info, bit 1 = control privilege, bits 5..7 = max
                                             // virtual displays (1). View-only sessions advertise observe-only and
                                             // drop the control privilege.
        let mut flags: u32 = 0x10 | 0x02 | (1 << 5);
        if cfg.view_only {
            flags = (flags & !0x02) | 0x01;
        }
        if let Ok(v) = std::env::var("RESTSEND_VNC_APPLE_FLAGS") {
            if let Ok(v) = v.parse() {
                flags = v;
            }
        }
        init.extend_from_slice(&flags.to_be_bytes());
        let clipboard = cfg.clipboard_enabled && !cfg.view_only;
        let files = cfg.share_root.is_some() && !cfg.view_only;
        let mut caps = apple_server_caps(clipboard, files);
        if std::env::var_os("RESTSEND_VNC_APPLE_NO_ENC").is_some() {
            messages::apple::clear(&mut caps, messages::apple::SET_ENCRYPTION);
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
        send_interaction_caps(
            writer_stream.as_mut(),
            cfg.share_root.is_some() && !cfg.view_only,
        )?;
    }

    // --- writer thread ---
    let (tx, rx) = std::sync::mpsc::sync_channel::<OutMsg>(64);
    let queue_depth = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let frame_budget = Arc::new(ByteBudget::new(FRAME_QUEUE_LIMIT));
    let session_stop = Arc::new(AtomicBool::new(false));
    let writer_thread = std::thread::Builder::new()
        .name("restsend-vnc-session-writer".into())
        .spawn({
            let depth = Arc::clone(&queue_depth);
            let budget = Arc::clone(&frame_budget);
            move || writer_loop(writer_stream, rx, depth, budget)
        })
        .expect("spawn session writer");

    // --- shared encoder state + update pusher thread ---
    // ServerCutText is harmful to Apple clients (corrupts their protocol
    // state), so Apple sessions never receive clipboard broadcasts — they
    // sync their clipboard through the encrypted ARD control channel.
    let apple_client = hs.minor == 889 || hs.client_init & 0x80 != 0;
    let apple_ready = Arc::new(AtomicBool::new(false));
    let apple_pasteboard = Arc::new(AtomicBool::new(false));
    let client_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let enc: Arc<Mutex<EncState>> = Arc::new(Mutex::new(EncState {
        encodings: Vec::new(),
        encoder: PixelEncoder::new(pf),
        cursor_rich: false,
        cursor_pos: false,
    }));
    // Every client is server-push fed: the pusher thread publishes
    // incremental updates at the configured fps. (Apple 3.889 clients send
    // only an initial full FBUR and then expect continuous server-push.)
    let mut updater = Updater {
        tx: tx.clone(),
        state: Arc::clone(&state),
        enc: Arc::clone(&enc),
        frame_budget: Arc::clone(&frame_budget),
        stop: Arc::clone(&session_stop),
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
        max_update_bytes: if apple_client {
            APPLE_UPDATE_BYTES
        } else {
            MAX_UPDATE_BYTES
        },
        max_rect_raw: if apple_client {
            APPLE_RECT_RAW
        } else {
            MAX_RECT_RAW
        },
        last_frame_gen: u64::MAX,
        cursor_shape_serial_sent: 0,
        cursor_pos_sent: (u16::MAX, u16::MAX),
        cursor_visible_sent: false,
        cursor_gen_sent: u64::MAX,
        cursor_bbox_sent: None,
        cursor_need_repaint: false,
        fbur_seen: 0,
    };
    let updater_thread = std::thread::Builder::new()
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
        let ready = Arc::clone(&apple_ready);
        let enabled = Arc::clone(&apple_pasteboard);
        std::thread::Builder::new()
            .name("restsend-vnc-clip-fwd".into())
            .spawn(move || {
                while let Ok(v) = clip_rx.recv() {
                    // ARD notifications are only meaningful once the client
                    // switched its stream to the record layer and enabled
                    // its shared pasteboard.
                    if apple_client
                        && !(ready.load(Ordering::Acquire) && enabled.load(Ordering::Acquire))
                    {
                        continue;
                    }
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
        apple_client,
        apple_key: hs.apple_key,
        apple_record_key: None,
        apple_record_iv: None,
        apple_started: false,
        apple_ready: Arc::clone(&apple_ready),
        apple_display_sent: false,
        apple_pasteboard,
        apple_auto_cmd: None,
        ard_upload: None,
        pending_drag: None,
        ard_offered_files: Vec::new(),
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

    let result = match trace_path.as_ref().and_then(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .ok()
    }) {
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
    // Tear the session down deterministically. Without this the pusher keeps
    // its 4K `cached` frame and the writer blocks in recv() forever after a
    // static-screen disconnect (one leaked thread set + ~33 MB per viewer).
    session_stop.store(true, Ordering::Relaxed);
    if let Some(sock) = &shutdown_sock {
        let _ = sock.shutdown(Shutdown::Both);
    }
    session.hub.unregister(session.session_id);
    session.state.clear_session();
    drop(session.tx);
    let _ = updater_thread.join();
    let _ = writer_thread.join();
    if let Some(pump) = pump {
        let _ = pump.join();
    }

    match result {
        Ok(()) => tracing::info!("session ended: {peer}"),
        Err(e) => tracing::info!("session ended: {peer} ({e})"),
    }
    Ok(())
}

/// One-line client description used by the audit log and the debug overlay's
/// `CLI` line. Always ends in `[TLS]` or `[PLAIN]` so the link encryption is
/// visible at a glance.
fn describe_client(hs: &handshake::HandshakeResult) -> String {
    let mut info = format!("RFB3.{:02} {}", hs.minor, hs.auth.label());
    if hs.tight {
        info.push_str(" TIGHT");
    }
    info.push_str(if hs.encrypted { " [TLS]" } else { " [PLAIN]" });
    info
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

/// Chooses between the client-side (Rich Cursor) and server-composited
/// cursor.
///
/// Apple's Screen Sharing advertises the Rich Cursor pseudo-encoding but does
/// not reliably draw the shape it receives, and macOS hides the local pointer
/// while typing — both leave the viewer with no visible pointer. Apple/ARD
/// sessions therefore always get the server-composited cursor, which is part
/// of the framebuffer and cannot be hidden by the client. `force_server`
/// (`RESTSEND_VNC_CURSOR_SERVER`) overrides the choice for other clients.
fn use_client_cursor(composited_apple: bool, force_server: bool, encodings: &[i32]) -> bool {
    !composited_apple && !force_server && encodings.contains(&pseudo::RICH_CURSOR)
}

fn writer_loop(
    mut stream: Box<dyn Write + Send>,
    rx: std::sync::mpsc::Receiver<OutMsg>,
    depth: Arc<std::sync::atomic::AtomicUsize>,
    budget: Arc<ByteBudget>,
) {
    let mut cipher: Option<crate::rfb::apple_auth::AppleStreamCipher> = None;
    while let Ok(msg) = rx.recv() {
        let ok = match msg {
            OutMsg::StartEncryption { setup, cipher: c } => {
                // The 1103 rect itself travels plaintext; every following
                // message on this channel is sealed.
                let ok = stream.write_all(&setup).is_ok();
                cipher = Some(c);
                ok
            }
            OutMsg::Frame(data) => {
                tracing::trace!(
                    "writer: frame {} bytes head={:02x?}",
                    data.len(),
                    &data[..data.len().min(16)]
                );
                let _ = depth.fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
                let len = data.len();
                let ok = match cipher.as_mut() {
                    None => stream.write_all(&data).is_ok(),
                    Some(c) => data
                        .chunks(crate::rfb::apple_auth::MAX_RECORD_BODY)
                        .all(|chunk| stream.write_all(&c.seal(chunk)).is_ok()),
                };
                // The bytes are out of our hands (or the connection died);
                // either way the pusher may encode again.
                budget.release(len);
                ok
            }
            OutMsg::Data(data) => {
                tracing::trace!(
                    "writer: data {} bytes head={:02x?}",
                    data.len(),
                    &data[..data.len().min(16)]
                );
                let _ = depth.fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
                match cipher.as_mut() {
                    None => stream.write_all(&data).is_ok(),
                    Some(c) => data
                        .chunks(crate::rfb::apple_auth::MAX_RECORD_BODY)
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

/// ARD AppleDisplayLayout pseudo-rect (encoding 1105). Screen Sharing uses
/// this to size its framebuffer/decoder before the first pixel update; without
/// it the codecs reject the first frame ("unexpected frame update").
fn apple_display_layout_message(width: u16, height: u16) -> Vec<u8> {
    let mut body = Vec::with_capacity(0x14 + 0x38 + 2);
    body.extend_from_slice(&5u16.to_be_bytes()); // version
    body.extend_from_slice(&width.to_be_bytes()); // desktop (points)
    body.extend_from_slice(&height.to_be_bytes());
    body.extend_from_slice(&width.to_be_bytes()); // framebuffer (pixels)
    body.extend_from_slice(&height.to_be_bytes());
    body.extend_from_slice(&0xffff_ffffu32.to_be_bytes()); // all displays
    body.extend_from_slice(&4u32.to_be_bytes()); // session state: on console
    body.extend_from_slice(&1u16.to_be_bytes()); // display count
    body.extend_from_slice(&1.0f64.to_be_bytes()); // density
    body.extend_from_slice(&1.0f64.to_be_bytes()); // scale
    body.extend_from_slice(&1u32.to_be_bytes()); // display id
    for _ in 0..2 {
        // logical rect (top, left, bottom, right), then backing rect
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&height.to_be_bytes());
        body.extend_from_slice(&width.to_be_bytes());
    }
    body.extend_from_slice(&1u32.to_be_bytes()); // main display
    PixelFormat::native().write(&mut body);

    let mut out = messages::framebuffer_update_header(1);
    out.extend_from_slice(&messages::rect_header(0, 0, 0, 0, 1105));
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Capability bitmap for the extended ARD ServerInit: bit N (MSB-first)
/// advertises that the server accepts client message N. Keep this to messages
/// the session parser actually understands so a 003.889 client never sends a
/// type we would have to abort on.
fn apple_server_caps(clipboard: bool, files: bool) -> [u8; 16] {
    use crate::rfb::messages::apple;
    let mut caps = [0u8; 16];
    for command in [
        0x00, 0x02, 0x03, 0x04, 0x05, 0x06, //
        0x09, 0x0a, // AutoFrameBufferUpdate, SetMode
        0x10, // encrypted input event
        0x12, // SetEncryption
        0x21, // ViewerInfo
    ] {
        apple::set(&mut caps, command);
    }
    if clipboard {
        for command in [0x0b, 0x15, 0x1f] {
            apple::set(&mut caps, command);
        }
    }
    if files {
        for command in [0x20, 0x22] {
            apple::set(&mut caps, command);
        }
    }
    caps
}

/// Tight protocol interaction capabilities sent right after ServerInit.
/// Without these, Tight-family viewers keep the file-transfer UI disabled.
fn send_interaction_caps(stream: &mut dyn Write, ft_enabled: bool) -> std::io::Result<()> {
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
    /// Client advertised the Rich Cursor pseudo-encoding (-239).
    cursor_rich: bool,
    /// Client advertised the PointerPos pseudo-encoding (-232).
    cursor_pos: bool,
}

/// Pusher thread state: owns the framebuffer-update machinery.
struct Updater {
    tx: SyncSender<OutMsg>,
    state: Arc<ScreenState>,
    enc: Arc<Mutex<EncState>>,
    frame_budget: Arc<ByteBudget>,
    /// Set by `handle_client` when the reader is done, so the pusher does not
    /// keep a 4K `cached` frame alive forever after a static-screen
    /// disconnect.
    stop: Arc<AtomicBool>,
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
    /// Base frame interval (from --fps). Updates never run faster than this;
    /// when encoding takes longer the loop naturally slows down instead of
    /// adding an artificial backoff (which made 4K drags paint in bands).
    frame_interval: Duration,
    /// True when the previous update had to defer rects (time/byte cap).
    force_next: bool,
    /// Rects deferred by the time budget, sent first on the next tick.
    pending: Vec<Rect>,
    /// Per-update wire cap. Apple clients get one RFB message per record, so a
    /// framebuffer update must fit in a single record (~64 KiB).
    max_update_bytes: usize,
    /// Largest raw rect to encode before splitting into strips (keeps one
    /// rectangle's payload inside `max_update_bytes`).
    max_rect_raw: usize,
    /// Last frame generation we pushed.
    last_frame_gen: u64,
    /// Cursor state last acknowledged by the client.
    cursor_shape_serial_sent: u64,
    cursor_pos_sent: (u16, u16),
    cursor_visible_sent: bool,
    cursor_gen_sent: u64,
    /// Cursor bbox currently drawn by a compositing (non-pseudo) client.
    cursor_bbox_sent: Option<Rect>,
    /// A frame update overlapped the cursor; repaint it.
    cursor_need_repaint: bool,
    /// FBUR counter (diagnostics for the Apple FBUR-driven path).
    #[allow(dead_code)]
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
                || self.stop.load(Ordering::Relaxed)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        if !self.enc.lock().unwrap().encodings.is_empty() {
            tracing::debug!("pusher: starting, encodings negotiated");
        }
        let mut first = true;
        loop {
            if self.state.is_stopped() || self.stop.load(Ordering::Relaxed) {
                return;
            }
            let frame_gen = self.state.generation();
            let cursor_gen = self.state.cursor_generation();
            let started = Instant::now();
            let frame_dirty = first || self.force_next || frame_gen != self.last_frame_gen;
            let cursor_snapshot = self.state.cursor_snapshot();
            let cursor_dirty = cursor_snapshot.generation != self.cursor_gen_sent;
            let cursor_only = !frame_dirty && (cursor_dirty || self.cursor_need_repaint);

            if frame_dirty && self.frame_budget.has_capacity() {
                let incremental = !first
                    && self.cached.dims() == {
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
                match self.send_update(incremental, Rect::new(0, 0, u16::MAX, u16::MAX)) {
                    Ok(status) => {
                        let cost = t0.elapsed();
                        let enc_ns = cost.as_nanos() as u64;
                        self.dbg_encode_ns += enc_ns;
                        self.stats_encode_ns += enc_ns;
                        self.force_next = !self.pending.is_empty();
                        match status {
                            UpdateStatus::Sent => {
                                self.last_frame_gen = frame_gen;
                                // Any new pixels may have painted over the
                                // software cursor; repaint it right after.
                                self.cursor_need_repaint = true;
                            }
                            UpdateStatus::Empty => self.last_frame_gen = frame_gen,
                            UpdateStatus::Skipped => self.dropped += 1,
                        }
                    }
                    Err(e) => {
                        tracing::info!("pusher ended: {e}");
                        return;
                    }
                }
            }
            first = false;

            if (cursor_dirty || self.cursor_need_repaint) && self.frame_budget.has_capacity() {
                match self.send_cursor(&cursor_snapshot) {
                    Ok(true) => {
                        self.cursor_gen_sent = cursor_snapshot.generation;
                        self.cursor_need_repaint = false;
                    }
                    Ok(false) => {} // out of budget: retry next tick
                    Err(e) => {
                        tracing::info!("pusher ended: {e}");
                        return;
                    }
                }
            }

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

            let interval = if cursor_only {
                // Pointer updates carry a few hundred bytes; let them run at
                // up to 60 Hz even when the configured capture rate is 30.
                cursor_interval(self.frame_interval)
            } else {
                self.frame_interval
            };
            let elapsed = started.elapsed();
            if elapsed < interval {
                // Responsiveness: wake up as soon as the capture thread or the
                // cursor poller has a newer state instead of sleeping the
                // whole interval.
                let wait = interval - elapsed;
                let mut waited = Duration::ZERO;
                while waited < wait {
                    let step = Duration::from_millis(2).min(wait - waited);
                    std::thread::sleep(step);
                    waited += step;
                    if self.stop.load(Ordering::Relaxed)
                        || self.state.generation() != frame_gen
                        || self.state.cursor_generation() != cursor_gen
                    {
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

    /// Queues an already-encoded update. `reserved` bytes were taken from the
    /// budget *before* encoding: ZRLE uses one continuous zlib stream, so an
    /// encoded update can never be dropped without corrupting every following
    /// rect. If the channel is momentarily full we wait for the writer.
    fn queue_reserved(&mut self, msg: Vec<u8>, reserved: usize) -> std::io::Result<()> {
        let len = msg.len();
        let deadline = Instant::now() + SEND_TIMEOUT;
        let mut slot = Some(OutMsg::Frame(msg));
        loop {
            if self.stop.load(Ordering::Relaxed) {
                self.frame_budget.release(reserved);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "session ended",
                ));
            }
            match self.tx.try_send(slot.take().expect("send slot occupied")) {
                Ok(()) => {
                    self.queue_depth.fetch_add(1, Ordering::Relaxed);
                    self.frame_budget.release(reserved.saturating_sub(len));
                    return Ok(());
                }
                Err(TrySendError::Full(m)) => {
                    if Instant::now() >= deadline {
                        self.frame_budget.release(reserved);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "client is not consuming updates",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                    slot = Some(m);
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.frame_budget.release(reserved);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "writer closed",
                    ));
                }
            }
        }
    }

    fn send_update(&mut self, incremental: bool, region: Rect) -> std::io::Result<UpdateStatus> {
        // Reserve the worst-case update size before touching the zlib stream.
        let reserved = self.max_update_bytes + (64 << 10);
        if !self.frame_budget.try_reserve(reserved) {
            return Ok(UpdateStatus::Skipped);
        }
        let current = self.state.snapshot();
        if current.dims() == (0, 0) {
            let _ = self.send(messages::framebuffer_update_header(0));
            self.frame_budget.release(reserved);
            return Ok(UpdateStatus::Empty);
        }

        // Resolution changed since the client last saw the framebuffer?
        if current.dims() != self.client_dims {
            let (encodings, _, _, _) = self.enc_state();
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
                // Rects and the cursor overlay belong to the old geometry.
                self.pending.clear();
                self.cursor_bbox_sent = None;
                self.cursor_gen_sent = u64::MAX;
                self.frame_budget.release(reserved);
                return Ok(UpdateStatus::Empty);
            }
            // Clients without resize support just get the new-size pixels.
        }

        let (encodings, encoder, _, _) = self.enc_state();
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
            split_rect(
                &mut expanded,
                r,
                encoder.bytes_per_pixel().max(1),
                self.max_rect_raw,
            );
        }
        rects = expanded;

        // Encode rects under a wall-clock budget. This bounds the latency of
        // one update even when a full-screen change compresses very well (the
        // old 1 MB cap could take a second to drain 4K top-to-bottom).
        // The very first paint (and a resolution change) has no interactive
        // latency to protect, so allow it to finish in fewer ticks.
        let budget = if incremental {
            // Leave headroom for the cursor overlay and the next tick, but
            // let a 30 fps session spend ~23 ms encoding so window drags
            // complete in one or two updates instead of many thin bands.
            self.frame_interval
                .mul_f32(0.7)
                .clamp(Duration::from_millis(8), MAX_UPDATE_BUDGET)
        } else {
            Duration::from_millis(150)
        };
        let encode_started = Instant::now();
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut total: usize = 0;
        let mut unsent: Vec<Rect> = Vec::new();
        for rect in rects.drain(..) {
            let estimate = rect.w as usize * rect.h as usize * encoder.bytes_per_pixel();
            if !payloads.is_empty()
                && (encode_started.elapsed() >= budget || total + estimate > self.max_update_bytes)
            {
                unsent.push(rect);
                continue;
            }
            let mut payload = rect_header(rect.x, rect.y, rect.w, rect.h, encoding.code());
            if let Err(e) = encode_rect(
                &mut payload,
                &current,
                rect,
                encoding,
                &encoder,
                &mut self.zrle,
            ) {
                self.frame_budget.release(reserved);
                return Err(e);
            }
            total += payload.len();
            payloads.push(payload);
        }

        let nrects = payloads.len();
        if nrects == 0 {
            // Nothing changed: don't burn a wakeup on an empty update.
            self.frame_budget.release(reserved);
            return Ok(UpdateStatus::Empty);
        }
        let mut msg = messages::framebuffer_update_header(nrects as u16);
        for p in payloads {
            msg.extend_from_slice(&p);
        }
        let msg_bytes = msg.len();
        self.queue_reserved(msg, reserved)?;

        self.pending = unsent;
        self.cached = Arc::clone(&current);
        if !self.pending.is_empty() {
            tracing::trace!("deferred {} rect(s) to the next update", self.pending.len());
        }
        self.stats_updates += 1;
        self.stats_bytes += msg_bytes as u64;
        self.dbg_updates += 1;
        self.dbg_bytes += msg_bytes as u64;
        Ok(UpdateStatus::Sent)
    }

    fn enc_state(&self) -> (Vec<i32>, PixelEncoder, bool, bool) {
        let st = self.enc.lock().unwrap();
        (
            st.encodings.clone(),
            st.encoder.clone(),
            st.cursor_rich,
            st.cursor_pos,
        )
    }

    /// Sends cursor shape/position pseudo-rects (client-side cursor) or a
    /// tiny composited overlay rectangle (all other clients). Returns false
    /// when the send budget is exhausted and the update should be retried.
    fn send_cursor(&mut self, snap: &CursorSnapshot) -> std::io::Result<bool> {
        let (encodings, encoder, rich, pos_supported) = self.enc_state();
        if encodings.is_empty() {
            return Ok(true);
        }
        let scale = self.state.scale();

        if rich {
            let mut queued = false;
            let hidden = !snap.visible || snap.shape.is_none();
            if hidden != !self.cursor_visible_sent
                || snap.shape_serial != self.cursor_shape_serial_sent
            {
                let (msg, estimate) = match (snap.visible, snap.shape.as_ref()) {
                    (true, Some(shape)) => {
                        let scaled = shape.scaled(scale);
                        let w = scaled.width as usize;
                        let h = scaled.height as usize;
                        let estimate = 16 + w * h * encoder.bytes_per_pixel() + w.div_ceil(8) * h;
                        (rich_cursor_message(&scaled, &encoder), estimate)
                    }
                    _ => (hidden_cursor_message(), 16),
                };
                if !self.frame_budget.try_reserve(estimate) {
                    return Ok(false);
                }
                self.queue_reserved(msg, estimate)?;
                self.cursor_shape_serial_sent = snap.shape_serial;
                self.cursor_visible_sent = snap.visible;
                self.stats_updates += 1;
                self.dbg_updates += 1;
                self.dbg_bytes += estimate as u64;
                queued = true;
            }
            if pos_supported && (snap.x, snap.y) != self.cursor_pos_sent {
                if !self.frame_budget.try_reserve(16) {
                    return Ok(false);
                }
                self.queue_reserved(pointer_pos_message(snap.x, snap.y), 16)?;
                self.cursor_pos_sent = (snap.x, snap.y);
                self.stats_updates += 1;
                self.dbg_updates += 1;
                self.dbg_bytes += 16;
                queued = true;
            }
            if !queued {
                // Nothing to send; still count the state as acknowledged.
                self.cursor_pos_sent = (snap.x, snap.y);
            }
            return Ok(true);
        }

        // Composited cursor: paint the sprite into a tiny rectangle. Use the
        // last frame the client actually has (not a newer capture) so the
        // overlay never leaks pixels the viewer has not received yet.
        let frame = Arc::clone(&self.cached);
        if frame.dims() == (0, 0) {
            // Retry after the first frame arrives; do not acknowledge the
            // cursor generation yet or the pointer would never be drawn.
            return Ok(false);
        }
        let cur_rect = if snap.visible {
            snap.shape.as_ref().and_then(|shape| {
                cursor_rect(shape, snap.x, snap.y, scale, frame.width, frame.height)
            })
        } else {
            None
        };
        if cur_rect == self.cursor_bbox_sent
            && snap.generation == self.cursor_gen_sent
            && !self.cursor_need_repaint
        {
            return Ok(true);
        }

        let mut paint: Vec<(Rect, bool)> = Vec::new();
        if let Some(old) = self.cursor_bbox_sent {
            if Some(old) != cur_rect {
                paint.push((old, false));
            }
        }
        if let Some(cur) = cur_rect {
            paint.push((cur, true));
        }
        if paint.is_empty() {
            self.cursor_bbox_sent = None;
            return Ok(true);
        }

        let encoding = encoding_override().unwrap_or_else(|| Encoding::pick(&encodings));
        // Upper bound for the ZRLE/Raw payloads, reserved before encoding so
        // the shared zlib stream can never be left ahead of the wire.
        let estimate: usize = paint
            .iter()
            .map(|(r, _)| 12 + r.w as usize * r.h as usize * encoder.bytes_per_pixel() + 256)
            .sum();
        if !self.frame_budget.try_reserve(estimate) {
            return Ok(false);
        }
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(paint.len());
        for (rect, draw_cursor) in paint {
            let rect = match rect.clamp(frame.width, frame.height) {
                Some(r) => r,
                None => continue,
            };
            let tile = if draw_cursor {
                overlay_frame(&frame, rect, snap, scale)
            } else {
                frame.subframe(rect.x as u32, rect.y as u32, rect.w as u32, rect.h as u32)
            };
            let mut payload = rect_header(rect.x, rect.y, rect.w, rect.h, encoding.code());
            if let Err(e) = encode_rect(
                &mut payload,
                &tile,
                Rect::new(0, 0, rect.w, rect.h),
                encoding,
                &encoder,
                &mut self.zrle,
            ) {
                self.frame_budget.release(estimate);
                return Err(e);
            }
            payloads.push(payload);
        }
        if payloads.is_empty() {
            self.frame_budget.release(estimate);
            self.cursor_bbox_sent = cur_rect;
            return Ok(true);
        }
        let mut msg = messages::framebuffer_update_header(payloads.len() as u16);
        for p in payloads {
            msg.extend_from_slice(&p);
        }
        let bytes = msg.len();
        self.queue_reserved(msg, estimate)?;
        self.cursor_bbox_sent = cur_rect;
        self.stats_updates += 1;
        self.stats_bytes += bytes as u64;
        self.dbg_updates += 1;
        self.dbg_bytes += bytes as u64;
        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateStatus {
    /// A framebuffer update was queued.
    Sent,
    /// There was nothing to send.
    Empty,
    /// The writer is at its byte budget; retry next tick.
    Skipped,
}

/// Reader adapter that can switch from the plaintext RFB stream to the ARD
/// record layer mid-session (`0x12 cmd=2`). The decoder owns no reference to
/// the underlying reader, so the borrow stays simple.
struct ClientStream<'a, R: Read> {
    inner: &'a mut R,
    decoder: Option<crate::rfb::apple_auth::RecordDecoder>,
}

impl<'a, R: Read> ClientStream<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        ClientStream {
            inner,
            decoder: None,
        }
    }

    fn enable_records(&mut self, key: [u8; 16], iv: [u8; 16]) {
        self.decoder = Some(crate::rfb::apple_auth::RecordDecoder::new(key, iv));
    }
}

impl<R: Read> Read for ClientStream<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.decoder.as_mut() {
            None => self.inner.read(buf),
            Some(decoder) => decoder.read(self.inner, buf),
        }
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
    /// True for RFB 003.889 (or ClientInit 0x80) sessions.
    apple_client: bool,
    /// Apple 3.889: DH session key (ECB input decrypt) until the record layer
    /// is active, then the record-layer key (the client swaps its cryptor too).
    apple_key: Option<[u8; 16]>,
    /// Record-layer key/IV distributed by the plaintext 1103 setup rect.
    apple_record_key: Option<[u8; 16]>,
    apple_record_iv: Option<[u8; 16]>,
    /// True once the plaintext 1103 setup rect has been queued.
    apple_started: bool,
    /// Set when the client switches its own stream to records (`0x12 cmd=2`).
    apple_ready: Arc<AtomicBool>,
    /// Whether the ARD DisplayInfo pseudo-rect was queued.
    apple_display_sent: bool,
    /// Set by `0x15` selector 1: the viewer enabled shared pasteboard.
    apple_pasteboard: Arc<AtomicBool>,
    /// Last auto-pasteboard command from the viewer (1 = enabled).
    apple_auto_cmd: Option<u16>,
    /// In-progress Apple 0x22 upload from the viewer.
    ard_upload: Option<crate::rfb::ard_file::UploadReceiver>,
    /// Drag id from `0x20`; answered with `0x1e` when the pointer is released.
    pending_drag: Option<u32>,
    /// Files advertised to the viewer via the pasteboard; the only absolute
    /// paths outside the share root that a download may read.
    ard_offered_files: Vec<std::path::PathBuf>,
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
    fn run(&mut self, reader: &mut impl Read, peer: SocketAddr) -> std::io::Result<()> {
        let ft_enabled = self.cfg.share_root.is_some() && !self.cfg.view_only;
        let mut stream = ClientStream::new(reader);
        loop {
            let msg =
                match messages::read_client_message(&mut stream, ft_enabled, self.apple_client) {
                    Ok(msg) => msg,
                    // Normal client disconnect (plain TCP reset or TLS EOF).
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        return Ok(())
                    }
                    Err(e) => return Err(e),
                };
            if let ClientMessage::AppleSetEncryption { command, .. } = msg {
                self.handle_set_encryption(command, &mut stream, peer)?;
                continue;
            }
            // Once the ARD record layer is active, the viewer's first
            // encrypted message is its post-encryption preface (usually a
            // second SetEncodings). Only then may the pusher send frames:
            // Screen Sharing rejects an unsolicited framebuffer update with
            // "unexpected frame update".
            if self.apple_client && self.apple_ready.load(Ordering::Acquire) {
                self.client_ready.store(true, Ordering::Release);
            }
            self.dispatch(msg, peer, &mut stream)?;
        }
    }

    /// Sends one ARD MiscStatus notification (type 0x14). The writer seals it
    /// once the record layer is active.
    fn send_apple_status(&self, cmd: u8) {
        if let Err(e) = self.send(crate::rfb::apple_auth::auto_pasteboard_info(cmd).to_vec()) {
            tracing::warn!("ARD status {cmd} send failed: {e}");
        }
    }

    /// True when the session may exchange files with the viewer.
    fn files_enabled(&self) -> bool {
        self.cfg.share_root.is_some() && !self.cfg.view_only
    }

    fn handle_apple_file(
        &mut self,
        peer: SocketAddr,
        command: u16,
        session: u32,
        body: &[u8],
    ) -> std::io::Result<()> {
        use crate::rfb::ard_file as af;
        if command == af::CMD_START_RECEIVE {
            let Some(root) = self.cfg.share_root.clone() else {
                return Ok(());
            };
            let mut upload = af::UploadReceiver::new(session, root);
            if let Some(reply) = upload.handle(command, body) {
                self.send(reply)?;
            }
            tracing::info!("{peer}: ARD file upload started (session {session})");
            self.ard_upload = Some(upload);
            return Ok(());
        }
        if command == af::CMD_START_SEND {
            return self.apple_download(peer, session, body);
        }
        let Some(upload) = self.ard_upload.as_mut() else {
            tracing::debug!("{peer}: ARD file-copy command {command} without a transfer");
            return Ok(());
        };
        if upload.session() != session {
            tracing::debug!(
                "{peer}: ARD file-copy session {session} does not match {}",
                upload.session()
            );
            return Ok(());
        }
        if let Some(reply) = upload.handle(command, body) {
            self.send(reply)?;
        }
        if matches!(command, af::CMD_END | af::CMD_STOP) {
            self.ard_upload = None;
        }
        Ok(())
    }

    fn apple_download(
        &mut self,
        peer: SocketAddr,
        session: u32,
        body: &[u8],
    ) -> std::io::Result<()> {
        use crate::rfb::ard_file as af;
        let Some(start) = af::parse_start(body) else {
            return Ok(());
        };
        let Some(root) = self.cfg.share_root.clone() else {
            return Ok(());
        };
        let Some(path) = self.resolve_download(&root, &start.path) else {
            tracing::info!("{peer}: ARD download {:?} denied", start.path);
            self.send(af::end_message(session, af::STATUS_NOT_FOUND))?;
            return Ok(());
        };
        let (info, item, size) = match af::download_meta(session, &path) {
            Ok(meta) => meta,
            Err(status) => {
                self.send(af::end_message(session, status))?;
                return Ok(());
            }
        };
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(e) => {
                tracing::warn!("{peer}: cannot open {}: {e}", path.display());
                self.send(af::end_message(session, af::STATUS_PERMISSION))?;
                return Ok(());
            }
        };
        tracing::info!("{peer}: ARD download {} ({size} bytes)", path.display());
        self.send(info)?;
        self.send(item)?;
        let mut buffer = vec![0u8; af::CHUNK_SIZE];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            self.send(af::data_message(session, &buffer[..n]))?;
        }
        self.send(af::end_message(session, 0))?;
        Ok(())
    }

    fn resolve_download(&self, root: &ShareRoot, request: &str) -> Option<std::path::PathBuf> {
        // Share-relative request (the destination path we returned via 0x1e).
        if request.starts_with('/') {
            if let Ok(path) = root.resolve(request) {
                if path.is_file() {
                    return Some(path);
                }
            }
        }
        // Absolute path echoed from a file URL: only under the share root or
        // explicitly present in the current host clipboard file list.
        let requested = crate::rfb::ard_file::local_path_from_request(request)?;
        let canonical = requested.canonicalize().ok()?;
        if canonical.starts_with(&root.canonical) && canonical.is_file() {
            return Some(canonical);
        }
        if let Some(content) = crate::clipboard::get_clipboard_content() {
            for file in content.files {
                if let Ok(file) = file.canonicalize() {
                    if file == canonical {
                        return Some(canonical);
                    }
                }
            }
        }
        for file in &self.ard_offered_files {
            if let Ok(file) = file.canonicalize() {
                if file == canonical {
                    return Some(canonical);
                }
            }
        }
        None
    }

    /// Handles Apple's `0x12 SetEncryption`: command 1 requests the record
    /// layer (server replies with the plaintext 1103 setup rect and switches
    /// its writer); command 2 is the client's "streams are switching now"
    /// marker, so the reader switches as well.
    fn handle_set_encryption<R: Read>(
        &mut self,
        command: u16,
        stream: &mut ClientStream<'_, R>,
        peer: SocketAddr,
    ) -> std::io::Result<()> {
        tracing::info!("{peer}: Apple SetEncryption cmd={command}");
        match command {
            1 => self.start_apple_encryption(peer)?,
            2 => {
                self.start_apple_encryption(peer)?;
                if let (Some(key), Some(iv)) = (self.apple_record_key, self.apple_record_iv) {
                    stream.enable_records(key, iv);
                    // The client replaces its ECB input cryptor with the
                    // record-layer key when it sends this marker.
                    self.apple_key = Some(key);
                    self.apple_ready.store(true, Ordering::Release);
                    if !self.apple_display_sent {
                        self.apple_display_sent = true;
                        let (w, h) = self.screen_dims;
                        let msg = apple_display_layout_message(w as u16, h as u16);
                        self.queue(OutMsg::Data(msg))?;
                    }
                    // Fallback: if the viewer sends no encrypted preface,
                    // start pushing after a short grace period.
                    let ready = Arc::clone(&self.client_ready);
                    std::thread::Builder::new()
                        .name("restsend-vnc-ard-push".into())
                        .spawn(move || {
                            std::thread::sleep(Duration::from_millis(300));
                            ready.store(true, Ordering::Relaxed);
                        })
                        .ok();
                    tracing::info!("{peer}: ARD record layer active (client -> server)");
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Sends the plaintext 1103 key/IV setup and switches the writer to the
    /// ARD record layer. Idempotent; called on cmd=1 and as a fallback on cmd=2.
    fn start_apple_encryption(&mut self, peer: SocketAddr) -> std::io::Result<()> {
        if self.apple_started || !self.apple_client {
            return Ok(());
        }
        let Some(dh_key) = self.apple_key else {
            return Ok(());
        };
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        getrandom::fill(&mut key).map_err(|e| std::io::Error::other(e.to_string()))?;
        getrandom::fill(&mut iv).map_err(|e| std::io::Error::other(e.to_string()))?;
        let setup = crate::rfb::apple_auth::encryption_setup_message(&dh_key, &key, &iv);
        let reset = std::env::var_os("RESTSEND_VNC_APPLE_CBC_RESET").is_some();
        self.queue(OutMsg::StartEncryption {
            setup,
            cipher: crate::rfb::apple_auth::AppleStreamCipher::new(key, iv, 0)
                .with_iv_reset(reset),
        })?;
        self.apple_record_key = Some(key);
        self.apple_record_iv = Some(iv);
        self.apple_started = true;
        tracing::info!("{peer}: ARD 1103 rekey sent; server -> client records active");
        Ok(())
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
                {
                    let mut st = self.enc.lock().unwrap();
                    let force_server = std::env::var_os("RESTSEND_VNC_CURSOR_SERVER").is_some();
                    st.cursor_rich =
                        use_client_cursor(self.apple_client && self.apple_started, force_server, &encodings);
                    // The viewer already knows where its own pointer is.
                    // Echoing PointerPos at 60 Hz is redundant and some
                    // clients repaint badly when it interleaves with frame
                    // updates, so it is opt-in.
                    st.cursor_pos = encodings.contains(&pseudo::POINTER_POS)
                        && std::env::var_os("RESTSEND_VNC_POINTER_POS").is_some();
                    st.encodings = encodings;
                }
                let (rich, pos) = {
                    let st = self.enc.lock().unwrap();
                    (st.cursor_rich, st.cursor_pos)
                };
                let mode = if rich { "client" } else { "composited" };
                self.state.set_cursor_mode(mode);
                tracing::info!(
                    "{peer}: cursor mode = {} (rich={} pointer-pos={} apple={})",
                    mode,
                    rich,
                    pos,
                    self.apple_client
                );
                // Client finished negotiating encodings: the pusher may now
                // start sending frames (Apple clients wait for server-push).
                // When the ARD record layer is requested, wait for the
                // viewer's encrypted preface instead (see Session::run).
                use std::sync::atomic::Ordering;
                if !(self.apple_client && self.apple_started) {
                    self.client_ready.store(true, Ordering::Relaxed);
                }
            }
            ClientMessage::FramebufferUpdateRequest { .. } => {
                // Server-push model: the pusher thread publishes updates at
                // the configured fps; FBURs need no action.
            }
            ClientMessage::KeyEvent { down, keysym } => {
                tracing::debug!(
                    "{peer}: key {keysym:#06x} {}",
                    if down { "down" } else { "up" }
                );
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
                tracing::trace!("{peer}: Apple session/auto-update message (ignored)");
            }
            ClientMessage::AppleViewerInfo(p) => {
                let hex: String = p.iter().take(16).map(|b| format!("{b:02x}")).collect();
                tracing::debug!("{peer}: Apple viewer info ({} bytes) head=[{hex}]", p.len());
            }
            ClientMessage::AppleAutoPasteboard(cmd) => {
                tracing::info!("{peer}: Apple auto-pasteboard cmd={cmd} (1=enable 2=disable)");
                self.apple_auto_cmd = Some(cmd);
                self.apple_pasteboard.store(cmd == 1, Ordering::Release);
            }
            ClientMessage::AppleClipboardFetch { echo } => {
                if !self.cfg.clipboard_enabled || self.cfg.view_only {
                    return Ok(());
                }
                let content = crate::clipboard::get_clipboard_content().unwrap_or_default();
                tracing::debug!(
                    "{peer}: Apple pasteboard fetch echo={echo} ({} text bytes, {} files)",
                    content.text.as_deref().map(str::len).unwrap_or(0),
                    content.files.len()
                );
                let archive = crate::rfb::pasteboard::content_archive(
                    content.text.as_deref(),
                    &content.files,
                );
                if !content.files.is_empty() {
                    self.ard_offered_files = content.files.clone();
                }
                match crate::rfb::pasteboard::message_for_archive(&archive, echo) {
                    Ok(msg) => {
                        self.send(msg)?;
                    }
                    Err(e) => tracing::warn!("{peer}: cannot build pasteboard reply: {e}"),
                }
            }
            ClientMessage::AppleClipboardSend {
                promise,
                echo,
                uncompressed,
                compressed,
                data,
            } => {
                if !self.cfg.clipboard_enabled || self.cfg.view_only {
                    return Ok(());
                }
                if data.len() != compressed as usize {
                    tracing::warn!(
                        "{peer}: Apple pasteboard truncated ({} of {compressed} bytes); ignored",
                        data.len()
                    );
                    return Ok(());
                }
                if promise {
                    tracing::debug!("{peer}: Apple pasteboard is a promise; requesting data");
                    self.send_apple_status(3);
                    return Ok(());
                }
                match crate::rfb::pasteboard::text_from_message(&data, uncompressed) {
                    Some(text) if !text.is_empty() => {
                        tracing::debug!(
                            "{peer}: Apple pasteboard set host clipboard ({} bytes)",
                            text.len()
                        );
                        self.hub.mark_local(&text);
                        crate::clipboard::set_clipboard(&text);
                    }
                    Some(_) => {}
                    None => tracing::debug!(
                        "{peer}: Apple pasteboard has no text flavor (echo={echo}, {uncompressed} bytes)"
                    ),
                }
            }
            ClientMessage::AppleDrag {
                id,
                uncompressed,
                compressed,
                data,
            } => {
                if !self.files_enabled() {
                    return Ok(());
                }
                if data.len() != compressed as usize {
                    tracing::warn!(
                        "{peer}: Apple drag truncated ({} of {compressed} bytes); ignored",
                        data.len()
                    );
                    return Ok(());
                }
                if data.is_empty() || id == 0 {
                    self.pending_drag = None;
                    return Ok(());
                }
                let archive = crate::rfb::pasteboard::inflate(&data, uncompressed as usize)
                    .unwrap_or_default();
                let files = crate::rfb::pasteboard::files_from_archive(&archive);
                tracing::info!(
                    "{peer}: Apple drag id={id} with {} file URL(s)",
                    files.len()
                );
                self.pending_drag = Some(id);
            }
            ClientMessage::AppleFileCopy {
                version,
                command,
                session,
                body,
            } => {
                if !self.files_enabled() {
                    tracing::debug!("{peer}: Apple file copy refused (file sharing off)");
                    return Ok(());
                }
                if version != 1 {
                    tracing::debug!("{peer}: Apple file copy version {version} ignored");
                    return Ok(());
                }
                self.handle_apple_file(peer, command, session, &body)?;
            }
            ClientMessage::AppleIgnored(kind) => {
                tracing::trace!("{peer}: Apple message 0x{kind:02x} ignored");
            }
            ClientMessage::AppleSetEncryption { command, .. } => {
                // Normally handled before dispatch so the reader can switch
                // to the record layer; keep this arm for exhaustiveness.
                tracing::trace!("{peer}: Apple SetEncryption cmd={command} (already handled)");
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
        if self.input.is_none() && self.screen_dims != (0, 0) {
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
        // Track the pointer in framebuffer coordinates for the composited
        // cursor. (The WGC frame no longer contains the pointer.)
        if !self.cfg.test_pattern {
            self.state.set_cursor_pos(x, y);
        }
        // Hidden shortcut: hold Ctrl and left-click 3 times (within 2s) to
        // toggle the debug overlay.
        let left_pressed = mask & 1 != 0 && self.last_mask & 1 == 0;
        let left_released = mask & 1 == 0 && self.last_mask & 1 != 0;
        self.last_mask = mask;
        if left_released {
            if let Some(id) = self.pending_drag.take() {
                if self.files_enabled() {
                    // Tell the viewer where the drop landed; it then uploads
                    // through 0x22. `/` maps to the configured share root.
                    let reply = crate::rfb::ard_file::drop_destination_message(id, "/");
                    if let Err(e) = self.send(reply) {
                        tracing::debug!("ARD drop destination send failed: {e}");
                    }
                }
            }
        }
        if left_pressed && self.ctrl_held && crate::settings::ALLOW_DEBUG.load(Ordering::Relaxed) {
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
            tracing::trace!(
                "apple pointer {x},{y} buttons={:#04x} (subtype {subtype})",
                p[11]
            );
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
        self.queue(OutMsg::Data(msg))
    }

    /// Queues any writer message, blocking (up to SEND_TIMEOUT) while the
    /// channel is full so ordering is preserved.
    fn queue(&self, msg: OutMsg) -> std::io::Result<()> {
        let mut slot = Some(msg);
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
                return self.send(filetransfer::download_failed_message(&format!(
                    "open failed: {e}"
                )))
            }
        };
        if position > 0 {
            use std::io::Seek;
            if file
                .seek(std::io::SeekFrom::Start(position as u64))
                .is_err()
            {
                return self.send(filetransfer::download_failed_message(
                    "invalid resume position",
                ));
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
                    return self.send(filetransfer::download_failed_message(&format!(
                        "read error: {e}"
                    )))
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
mod throttle_tests {
    use super::*;

    fn area(r: &Rect) -> u64 {
        r.w as u64 * r.h as u64
    }

    #[test]
    fn split_rect_respects_cap_and_covers_input() {
        let mut out = Vec::new();
        split_rect(&mut out, Rect::new(0, 0, 3840, 2160), 3, MAX_RECT_RAW);
        assert!(out.len() > 1);
        assert_eq!(out.iter().map(area).sum::<u64>(), 3840 * 2160);
        for r in &out {
            assert_eq!(r.x, 0);
            assert_eq!(r.w, 3840);
            assert!(r.w as usize * r.h as usize * 3 <= MAX_RECT_RAW || r.h == 1);
            assert!(r.h > 0);
        }
        // Contiguous, non-overlapping strips.
        let mut y = 0u16;
        for r in &out {
            assert_eq!(r.y, y);
            y += r.h;
        }
        assert_eq!(y, 2160);
    }

    #[test]
    fn split_rect_keeps_small_rect_whole() {
        let mut out = Vec::new();
        split_rect(&mut out, Rect::new(10, 20, 100, 50), 4, MAX_RECT_RAW);
        assert_eq!(out, vec![Rect::new(10, 20, 100, 50)]);
        out.clear();
        split_rect(&mut out, Rect::new(0, 0, 0, 10), 4, MAX_RECT_RAW);
        assert!(out.is_empty());
    }

    #[test]
    fn contains_rect_is_nesting_not_intersection() {
        let outer = Rect::new(0, 0, 100, 100);
        assert!(contains_rect(&outer, &Rect::new(10, 10, 20, 20)));
        assert!(contains_rect(&outer, &outer));
        assert!(!contains_rect(&outer, &Rect::new(90, 90, 20, 20)));
        assert!(!contains_rect(&Rect::new(10, 10, 20, 20), &outer));
    }
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

#[cfg(test)]
mod cursor_mode_tests {
    use super::use_client_cursor;
    use crate::rfb::messages::pseudo;

    #[test]
    fn apple_clients_always_get_the_composited_cursor() {
        // Screen Sharing advertises -239 but does not draw it reliably.
        let encodings = [16, 0, pseudo::RICH_CURSOR, pseudo::POINTER_POS];
        assert!(!use_client_cursor(true, false, &encodings));
        // Even an explicit opt-out request is irrelevant for Apple clients.
        assert!(!use_client_cursor(true, true, &encodings));
    }

    #[test]
    fn other_clients_use_the_rich_cursor_when_negotiated() {
        let encodings = [16, 0, pseudo::RICH_CURSOR];
        assert!(use_client_cursor(false, false, &encodings));
        // No Rich Cursor: composite server-side.
        assert!(!use_client_cursor(false, false, &[16, 0]));
        // Escape hatch for clients that advertise -239 but ignore it.
        assert!(!use_client_cursor(false, true, &encodings));
    }
}

#[cfg(test)]
mod client_info_tests {
    use super::describe_client;
    use crate::rfb::handshake::{AuthMethod, HandshakeResult};

    fn result(auth: AuthMethod, encrypted: bool) -> HandshakeResult {
        HandshakeResult {
            minor: 8,
            security_type: if encrypted { 19 } else { 2 },
            tight: false,
            auth,
            apple_key: None,
            client_init: 1,
            encrypted,
            tls: None,
        }
    }

    #[test]
    fn debug_overlay_marks_encryption() {
        assert_eq!(
            describe_client(&result(AuthMethod::VeNCryptTlsVnc, true)),
            "RFB3.08 TLS-VNC [TLS]"
        );
        assert_eq!(
            describe_client(&result(AuthMethod::VeNCryptTlsNone, true)),
            "RFB3.08 TLS-NONE [TLS]"
        );
        assert_eq!(
            describe_client(&result(AuthMethod::VncAuth, false)),
            "RFB3.08 VNC-AUTH [PLAIN]"
        );
        assert_eq!(
            describe_client(&result(AuthMethod::AppleDh, false)),
            "RFB3.08 APPLE-DH [PLAIN]"
        );
    }
}
