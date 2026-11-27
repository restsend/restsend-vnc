//! System-audio streaming (Windows): WASAPI loopback capture -> Media
//! Foundation AAC encode (raw-WAV fallback) -> built-in HTTP server.
//!
//! The VNC/ARD protocol has no audio channel, so viewers cannot hear this
//! machine. A side HTTP port fills that gap: opening
//! `http://<host>:<port>/<token>/` in any browser (Safari/Chrome/VLC) plays
//! a live stream of everything the PC plays — no client install needed.
//! The random per-run token keeps the URL unguessable; the loopback-only
//! and CIDR settings apply to it as well.
//!
//! Threading:
//! - supervisor thread: watches AUDIO_ENABLED / AUDIO_PORT / AUDIO_RELOAD,
//!   starts and stops server instances;
//! - server thread: accepts HTTP connections, spawns the capture thread;
//! - capture thread: WASAPI loopback -> encoder -> broadcast hub;
//! - one thread per HTTP connection, fed from the hub.

#![cfg(target_os = "windows")]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Broadcast hub: capture thread -> HTTP connections
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// ADTS AAC frames (encoded mode).
    Aac,
    /// Raw s16le PCM (WAV fallback mode).
    Wav,
}

struct Chunk {
    kind: Kind,
    data: Vec<u8>,
}

struct Listener {
    id: u64,
    tx: SyncSender<Chunk>,
}

static LISTENERS: Mutex<Vec<Listener>> = Mutex::new(Vec::new());
static NEXT_LISTENER: AtomicU64 = AtomicU64::new(1);
/// Format of the active capture session, set before the first chunk.
static ACTIVE_FORMAT: Mutex<Option<(u32, u16)>> = Mutex::new(None);

fn publish(chunk: Chunk) {
    let mut listeners = LISTENERS.lock().unwrap();
    if listeners.is_empty() {
        return;
    }
    listeners.retain(|l| l.tx.try_send(clone_chunk(&chunk)).is_ok());
}

fn clone_chunk(chunk: &Chunk) -> Chunk {
    Chunk {
        kind: chunk.kind,
        data: chunk.data.clone(),
    }
}

fn subscribe() -> (u64, Receiver<Chunk>) {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Chunk>(128);
    let id = NEXT_LISTENER.fetch_add(1, Ordering::Relaxed);
    LISTENERS.lock().unwrap().push(Listener { id, tx });
    (id, rx)
}

fn unsubscribe(id: u64) {
    LISTENERS.lock().unwrap().retain(|l| l.id != id);
}

fn listener_count() -> usize {
    LISTENERS.lock().unwrap().len()
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

struct ServerHandle {
    stop: Arc<AtomicBool>,
    generation: usize,
    reload_seen: usize,
}

static SERVER: Mutex<Option<ServerHandle>> = Mutex::new(None);

/// Spawns the supervisor that follows the live settings. Call once.
pub fn spawn_supervisor() {
    std::thread::Builder::new()
        .name("restsend-vnc-audio-supervisor".into())
        .spawn(|| loop {
            if crate::settings::EXIT.load(Ordering::Relaxed) {
                stop_server();
                return;
            }
            let enabled = crate::settings::AUDIO_ENABLED.load(Ordering::Relaxed);
            let reload = crate::settings::AUDIO_RELOAD.load(Ordering::Relaxed);
            let mut guard = SERVER.lock().unwrap();
            let running = guard.is_some();
            let stale = guard
                .as_ref()
                .map(|s| s.reload_seen != reload)
                .unwrap_or(false);
            if enabled && (stale || !running) {
                if let Some(handle) = guard.take() {
                    handle.stop.store(true, Ordering::Relaxed);
                }
                let stop = Arc::new(AtomicBool::new(false));
                let generation = guard.as_ref().map(|s| s.generation).unwrap_or(0) + 1;
                std::thread::Builder::new()
                    .name("restsend-vnc-audio-server".into())
                    .spawn({
                        let stop = Arc::clone(&stop);
                        move || run_server(stop, generation)
                    })
                    .ok();
                *guard = Some(ServerHandle {
                    stop,
                    generation,
                    reload_seen: reload,
                });
            } else if !enabled && running {
                if let Some(handle) = guard.take() {
                    handle.stop.store(true, Ordering::Relaxed);
                }
            }
            drop(guard);
            std::thread::sleep(Duration::from_millis(400));
        })
        .ok();
}

/// True when a server instance is running (used by the tray menu).
#[allow(dead_code)]
pub fn running() -> bool {
    SERVER.lock().unwrap().is_some()
}

fn stop_server() {
    if let Some(handle) = SERVER.lock().unwrap().take() {
        handle.stop.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

fn run_server(stop: Arc<AtomicBool>, generation: usize) {
    let port = crate::settings::AUDIO_PORT.load(Ordering::Relaxed);
    let host = if crate::settings::LOOPBACK_ONLY.load(Ordering::Relaxed) {
        "127.0.0.1"
    } else {
        "0.0.0.0"
    };
    let listener = match TcpListener::bind((host, port)) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("audio[gen {generation}]: cannot bind {host}:{port}: {e}");
            // Back off so a broken port does not spin the supervisor.
            std::thread::sleep(Duration::from_secs(3));
            return;
        }
    };
    let _ = listener.set_nonblocking(true);
    tracing::info!("audio[gen {generation}]: streaming on {host}:{port} (token-protected)");

    let capture_stop = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("restsend-vnc-audio-capture".into())
        .spawn(move || capture_loop(capture_stop))
        .ok();

    while !stop.load(Ordering::Relaxed) && !crate::settings::EXIT.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !crate::settings::allows(peer.ip()) {
                    tracing::debug!("audio: rejecting {peer} (not in allow_cidrs)");
                    continue;
                }
                let stop = Arc::clone(&stop);
                std::thread::Builder::new()
                    .name("restsend-vnc-audio-http".into())
                    .spawn(move || {
                        let _ = stream.set_nodelay(true);
                        handle_conn(stream, peer.to_string(), stop);
                    })
                    .ok();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(80));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(150)),
        }
    }
    tracing::debug!("audio[gen {generation}]: server stopped");
}

fn http_response(code: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {code}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn index_page() -> Vec<u8> {
    let body = "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>restsend-vnc audio</title>\
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px;color:#222}\
h1{font-size:20px}code{background:#f2f2f2;padding:2px 6px;border-radius:4px}</style></head><body>\
<h1>&#128266; restsend-vnc audio</h1>\
<p>Live system audio from the Windows PC. Press play to listen.</p>\
<p><audio controls autoplay src=\"stream\" style=\"width:100%\"></audio></p>\
<p style=\"color:#888\">Keep this tab open — audio continues in the background.<br>\
Tip: the stream also works in VLC: <code>Media &gt; Open Network Stream</code>.</p>\
</body></html>";
    http_response("200 OK", "text/html; charset=utf-8", body.as_bytes())
}

/// Reads the request head (capped) and returns the request path.
fn read_request_path(stream: &mut TcpStream) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if Instant::now() > deadline || buf.len() > 16 * 1024 {
            return None;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]);
            let first = head.lines().next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");
            if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
                return None;
            }
            let path = target.split('?').next().unwrap_or(target);
            return Some(path.to_string());
        }
    }
}

fn handle_conn(mut stream: TcpStream, peer: String, stop: Arc<AtomicBool>) {
    let Some(path) = read_request_path(&mut stream) else {
        return;
    };
    let token = crate::settings::audio_token();
    let rel = path
        .trim_start_matches('/')
        .strip_prefix(&token)
        .map(|rest| rest.trim_start_matches('/'))
        .unwrap_or("\u{0}denied");
    let rel = rel.trim_end_matches('/');
    match rel {
        "" => {
            let _ = stream.write_all(&index_page());
        }
        "stream" => stream_endpoint(&mut stream, peer, stop),
        "favicon.ico" => {}
        _ => {
            let body = b"<h1>403</h1><p>Wrong token.</p>";
            let _ = stream.write_all(&http_response("403 Forbidden", "text/html", body));
        }
    }
}

/// Streams the live audio until the client or the server goes away. The
/// first chunk decides the content type (AAC frames or raw PCM).
fn stream_endpoint(stream: &mut TcpStream, peer: String, stop: Arc<AtomicBool>) {
    let (id, rx) = subscribe();
    // Wait (bounded) for the first chunk so a dead capture thread yields a
    // clean 503 instead of an empty 200.
    let first = match rx.recv_timeout(Duration::from_secs(8)) {
        Ok(chunk) => chunk,
        Err(_) => {
            tracing::warn!("audio: no capture data for {peer}; capture may have failed");
            let body = b"<h1>503</h1><p>Audio capture is not producing data (check the server log).</p>";
            let _ = stream.write_all(&http_response(
                "503 Service Unavailable",
                "text/html",
                body,
            ));
            unsubscribe(id);
            return;
        }
    };
    let (content_type, first_data) = match first.kind {
        Kind::Aac => ("audio/aac", first.data),
        // Raw-WAV fallback: emit a fresh header for this listener.
        Kind::Wav => {
            let fmt = ACTIVE_FORMAT
                .lock()
                .unwrap()
                .unwrap_or((48000, 2));
            let mut head = wav_header(fmt.0, fmt.1);
            head.extend_from_slice(&first.data);
            ("audio/wav", head)
        }
    };
    tracing::info!(
        "audio: {peer} listening ({content_type}, {} listener(s))",
        listener_count()
    );
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(&first_data);
    if stream.write_all(&out).is_err() {
        unsubscribe(id);
        return;
    }
    let kind = first.kind;
    loop {
        if stop.load(Ordering::Relaxed) || crate::settings::EXIT.load(Ordering::Relaxed) {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(chunk) => {
                if chunk.kind != kind {
                    // Encoder mode changed (capture restart); the stream is
                    // no longer decodable — end it, browsers will reload.
                    break;
                }
                if stream.write_all(&chunk.data).is_err() {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    unsubscribe(id);
    tracing::info!("audio: {peer} left ({} listener(s))", listener_count());
}

// ---------------------------------------------------------------------------
// Capture + encode
// ---------------------------------------------------------------------------

fn capture_loop(stop: Arc<AtomicBool>) {
    let mut backoff = Duration::from_millis(500);
    while !stop.load(Ordering::Relaxed) && !crate::settings::EXIT.load(Ordering::Relaxed) {
        match run_capture_session(&stop) {
            Ok(()) => break, // stop requested
            Err(e) => {
                tracing::warn!("audio capture failed: {e}; retrying in {backoff:?}");
                *ACTIVE_FORMAT.lock().unwrap() = None;
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        }
    }
}

/// WASAPI loopback session: opens the default render endpoint, encodes and
/// publishes until `stop`. Returns Err on device/encoder failure.
fn run_capture_session(stop: &Arc<AtomicBool>) -> Result<(), String> {
    use windows::Win32::Media::Audio::{
        self as wasapi, eConsole, eRender, IAudioCaptureClient, IAudioClient,
        IMMDeviceEnumerator, MMDeviceEnumerator, AUDCLNT_SHAREMODE_SHARED,
        AUDCLNT_STREAMFLAGS_LOOPBACK,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_ALL, COINIT_MULTITHREADED,
    };
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

        let enumerator: IMMDeviceEnumerator =
            CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL).map_err(|e| e.to_string())?;
        let device = enumerator
            .GetDefaultAudioEndpoint(eRender, eConsole)
            .map_err(|e| format!("no default audio endpoint: {e}"))?;
        let client: IAudioClient = device
            .Activate::<IAudioClient>(CLSCTX_ALL, None)
            .map_err(|e| e.to_string())?;
        let fmt = client.GetMixFormat().map_err(|e| e.to_string())?;
        let (rate, channels, sample_fmt, src_block_align) = parse_format(fmt);
        if rate == 0 || channels == 0 || channels > 8 {
            CoTaskMemFree(Some(fmt as *const core::ffi::c_void));
            return Err(format!(
                "unsupported mix format (rate={rate} ch={channels} fmt={sample_fmt:?})"
            ));
        }
        client
            .Initialize(
                AUDCLNT_SHAREMODE_SHARED,
                AUDCLNT_STREAMFLAGS_LOOPBACK,
                1_000_000, // 100 ms buffer
                0,
                fmt,
                None,
            )
            .map_err(|e| format!("audio client init: {e}"))?;
        CoTaskMemFree(Some(fmt as *const core::ffi::c_void));
        let capture: IAudioCaptureClient = client
            .GetService()
            .map_err(|e| format!("capture service: {e}"))?;
        client.Start().map_err(|e| format!("audio start: {e}"))?;

        *ACTIVE_FORMAT.lock().unwrap() = Some((rate, channels));
        let mut encoder = match AacEncoder::new(rate, channels) {
            Some(enc) => {
                tracing::info!("audio: MF AAC encoder active ({rate} Hz, {channels} ch)");
                Encoder::Aac(enc)
            }
            None => {
                tracing::warn!("audio: MF AAC encoder unavailable; serving raw WAV");
                Encoder::Passthrough
            }
        };
        let bytes_per_frame = channels as usize * 2;
        let silence_packet = (rate as usize / 100).max(1) * bytes_per_frame;
        let mut silence_timer = Instant::now();

        let result = (|| -> Result<(), String> {
            loop {
                if stop.load(Ordering::Relaxed) || crate::settings::EXIT.load(Ordering::Relaxed) {
                    return Ok(());
                }
                let Ok(packets) = capture.GetNextPacketSize() else {
                    return Err("GetNextPacketSize failed".into());
                };
                if packets == 0 {
                    // WASAPI loopback emits nothing while nothing plays.
                    // Publish silence so listeners keep a continuous stream.
                    if listener_count() > 0 && silence_timer.elapsed() >= Duration::from_millis(10)
                    {
                        let pcm = vec![0u8; silence_packet];
                        for chunk in encoder.push(&pcm) {
                            publish(chunk);
                        }
                        silence_timer = Instant::now();
                    }
                    std::thread::sleep(Duration::from_millis(8));
                    continue;
                }
                let mut data = std::ptr::null_mut::<u8>();
                let mut frames = 0u32;
                let mut flags = 0u32;
                capture
                    .GetBuffer(&mut data, &mut frames, &mut flags, None, None)
                    .map_err(|e| e.to_string())?;
                if frames > 0 {
                    // WASAPI hands us `frames` frames in the device's own
                    // stride; never read more than that (a 24-bit or 32-bit
                    // device has a wider stride than our 16-bit output).
                    let src_len = frames as usize * src_block_align;
                    let pcm_len = frames as usize * bytes_per_frame;
                    let mut pcm = vec![0u8; pcm_len];
                    if !data.is_null() {
                        if flags & wasapi::AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0 {
                            // pcm stays zeroed
                        } else {
                            let src = std::slice::from_raw_parts(data, src_len);
                            convert_samples(src, &mut pcm, channels as usize, sample_fmt);
                        }
                    }
                    for chunk in encoder.push(&pcm) {
                        publish(chunk);
                    }
                    silence_timer = Instant::now();
                }
                let _ = capture.ReleaseBuffer(frames);
            }
        })();

        let _ = client.Stop();
        *ACTIVE_FORMAT.lock().unwrap() = None;
        result
    }
}

/// Sample encodings a WASAPI mix format can realistically use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SampleFmt {
    /// 32-bit IEEE float (the usual shared-mode mix format).
    F32,
    /// 16-bit signed PCM.
    I16,
    /// 24-bit signed PCM (3 bytes per sample, little-endian).
    I24,
    /// 32-bit signed PCM.
    I32,
}

/// Reads rate/channels/sample-format/source stride from a WAVEFORMATEX (or
/// EXTENSIBLE). Returns zero rate when the format is not one we can convert,
/// which disables capture gracefully instead of reading out of bounds.
unsafe fn parse_format(
    fmt: *mut windows::Win32::Media::Audio::WAVEFORMATEX,
) -> (u32, u16, SampleFmt, usize) {
    use windows::core::GUID;
    const UNSUPPORTED: (u32, u16, SampleFmt, usize) = (0, 0, SampleFmt::F32, 0);
    if fmt.is_null() {
        return UNSUPPORTED;
    }
    let base = &*fmt;
    let (sample_fmt, src_block_align) = match base.wFormatTag {
        0xFFFE => {
            // WAVE_FORMAT_EXTENSIBLE: inspect the SubFormat GUID and the
            // declared valid bit depth.
            const FLOAT_GUID: u128 = 0x0000_0003_0000_0010_8000_00aa_0038_9b71;
            const PCM_GUID: u128 = 0x0000_0001_0000_0010_8000_00aa_0038_9b71;
            let ext = fmt as *const windows::Win32::Media::Audio::WAVEFORMATEXTENSIBLE;
            if ext.is_null() {
                return UNSUPPORTED;
            }
            let sub = (*ext).SubFormat;
            let bits = (*ext).Samples.wValidBitsPerSample;
            let kind = if sub == GUID::from_u128(FLOAT_GUID) {
                Some(SampleFmt::F32)
            } else if sub == GUID::from_u128(PCM_GUID) {
                match bits {
                    16 => Some(SampleFmt::I16),
                    24 => Some(SampleFmt::I24),
                    32 => Some(SampleFmt::I32),
                    _ => None,
                }
            } else {
                None
            };
            match kind {
                Some(k) => (k, base.nBlockAlign as usize),
                None => return UNSUPPORTED,
            }
        }
        3 => (SampleFmt::F32, base.nBlockAlign as usize),
        1 => match base.wBitsPerSample {
            16 => (SampleFmt::I16, base.nBlockAlign as usize),
            24 => (SampleFmt::I24, base.nBlockAlign as usize),
            32 => (SampleFmt::I32, base.nBlockAlign as usize),
            _ => return UNSUPPORTED,
        },
        _ => return UNSUPPORTED,
    };
    (base.nSamplesPerSec, base.nChannels, sample_fmt, src_block_align)
}

/// Converts one WASAPI capture packet into interleaved 16-bit LE PCM.
///
/// `src` holds exactly `frames * src_block_align` bytes in `sample_fmt`;
/// `dst` is `frames * channels * 2` bytes of output.
fn convert_samples(src: &[u8], dst: &mut [u8], channels: usize, sample_fmt: SampleFmt) {
    let frames = dst.len() / (channels * 2);
    let mut write_sample = |i: usize, s: i16| {
        if i * 2 + 2 <= dst.len() {
            dst[i * 2..i * 2 + 2].copy_from_slice(&s.to_le_bytes());
        }
    };
    match sample_fmt {
        SampleFmt::F32 => {
            for (i, sample) in src.chunks_exact(4).take(frames * channels).enumerate() {
                let v = f32::from_le_bytes(sample.try_into().unwrap());
                write_sample(i, (v.clamp(-1.0, 1.0) * 32767.0) as i16);
            }
        }
        SampleFmt::I16 => {
            // 16-bit source is already our output format: plain copy.
            let copy_len = (frames * channels * 2).min(src.len());
            dst[..copy_len].copy_from_slice(&src[..copy_len]);
        }
        SampleFmt::I24 => {
            for (i, sample) in src.chunks_exact(3).take(frames * channels).enumerate() {
                // 24-bit little-endian sample; sign-extend via shifts and
                // scale down to 16 bits.
                let v = (sample[0] as i32) | ((sample[1] as i32) << 8) | ((sample[2] as i32) << 16);
                write_sample(i, ((v << 8) >> 16) as i16);
            }
        }
        SampleFmt::I32 => {
            for (i, sample) in src.chunks_exact(4).take(frames * channels).enumerate() {
                let v = i32::from_le_bytes(sample.try_into().unwrap());
                write_sample(i, (v >> 16) as i16);
            }
        }
    }
    let _ = frames;
}

/// Minimal 44-byte streaming WAV header (unknown data size).
fn wav_header(rate: u32, channels: u16) -> Vec<u8> {
    let bits: u16 = 16;
    let block_align = channels * (bits / 8);
    let byte_rate = rate * block_align as u32;
    let mut out = Vec::with_capacity(44);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk size
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&channels.to_le_bytes());
    out.extend_from_slice(&rate.to_le_bytes());
    out.extend_from_slice(&byte_rate.to_le_bytes());
    out.extend_from_slice(&block_align.to_le_bytes());
    out.extend_from_slice(&bits.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    debug_assert_eq!(out.len(), 44);
    out
}

enum Encoder {
    Aac(AacEncoder),
    /// Raw s16 PCM passthrough (WAV fallback).
    Passthrough,
}

impl Encoder {
    fn push(&mut self, pcm: &[u8]) -> Vec<Chunk> {
        match self {
            Encoder::Aac(enc) => enc
                .push(pcm)
                .into_iter()
                .map(|data| Chunk {
                    kind: Kind::Aac,
                    data,
                })
                .collect(),
            Encoder::Passthrough => vec![Chunk {
                kind: Kind::Wav,
                data: pcm.to_vec(),
            }],
        }
    }
}

// ---------------------------------------------------------------------------
// Media Foundation AAC encoder
// ---------------------------------------------------------------------------

static MF_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

struct AacEncoder {
    transform: windows::Win32::Media::MediaFoundation::IMFTransform,
    sample_rate: u32,
    channels: u16,
    /// Cumulative sample time in 100 ns units for SetSampleTime.
    time_100ns: i64,
}

impl AacEncoder {
    fn new(sample_rate: u32, channels: u16) -> Option<AacEncoder> {
        use windows::Win32::Media::MediaFoundation as mf;
        use windows::Win32::Media::MediaFoundation::{
            MFMediaType_Audio, MF_MT_AUDIO_AVG_BYTES_PER_SECOND, MF_MT_AUDIO_BITS_PER_SAMPLE,
            MF_MT_AUDIO_NUM_CHANNELS, MF_MT_AUDIO_SAMPLES_PER_SECOND, MF_MT_MAJOR_TYPE,
            MF_MT_SUBTYPE, MFAudioFormat_AAC, MFAudioFormat_PCM, MFT_CATEGORY_AUDIO_ENCODER,
            MFT_ENUM_FLAG_SORTANDFILTER, MFT_ENUM_FLAG_SYNCMFT, MFT_REGISTER_TYPE_INFO,
        };
        unsafe {
            MF_INIT.get_or_init(|| {
                // MF_VERSION = SDK 2, API 7.
                if let Err(e) = mf::MFStartup((2u32 << 16) | 7u32, mf::MFSTARTUP_LITE) {
                    tracing::warn!("audio: MFStartup failed: {e}");
                }
            });

            let input = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Audio,
                guidSubtype: MFAudioFormat_PCM,
            };
            let output = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Audio,
                guidSubtype: MFAudioFormat_AAC,
            };
            // MFTEnumEx returns a heap array of IMFActivate pointers; the
            // caller owns both the interfaces (Release via drop) and the
            // array itself (CoTaskMemFree).
            let mut array: *mut Option<mf::IMFActivate> = std::ptr::null_mut();
            let mut count = 0u32;
            if mf::MFTEnumEx(
                MFT_CATEGORY_AUDIO_ENCODER,
                MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER,
                Some(&input),
                Some(&output),
                &mut array as *mut _,
                &mut count,
            )
            .is_err()
                || array.is_null()
                || count == 0
            {
                if !array.is_null() {
                    windows::Win32::System::Com::CoTaskMemFree(Some(
                        array as *const core::ffi::c_void,
                    ));
                }
                return None;
            }

            let activations = std::slice::from_raw_parts_mut(array, count as usize);
            // Activate the first matching transform, then release every
            // activation and free the array (the transform is an independent
            // reference and stays valid).
            let transform: Option<mf::IMFTransform> = activations[0]
                .as_ref()
                .and_then(|a| a.ActivateObject().ok());
            for activation in activations {
                std::ptr::drop_in_place(activation);
            }
            windows::Win32::System::Com::CoTaskMemFree(Some(array as *const core::ffi::c_void));
            let transform = transform?;

            let mt = mf::MFCreateMediaType().ok()?;
            mt.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio).ok()?;
            mt.SetGUID(&MF_MT_SUBTYPE, &MFAudioFormat_PCM).ok()?;
            mt.SetUINT32(&MF_MT_AUDIO_BITS_PER_SAMPLE, 16).ok()?;
            mt.SetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND, sample_rate).ok()?;
            mt.SetUINT32(&MF_MT_AUDIO_NUM_CHANNELS, channels as u32).ok()?;
            transform.SetInputType(0, &mt, 0).ok()?;

            // Pick the matching AAC output preset (smallest bitrate listed).
            let mut chosen: Option<mf::IMFMediaType> = None;
            let mut best_bytes_per_sec = u32::MAX;
            for i in 0..64u32 {
                let Ok(t) = transform.GetOutputAvailableType(0, i) else {
                    break;
                };
                let sr = t.GetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND).unwrap_or(0);
                let ch = t.GetUINT32(&MF_MT_AUDIO_NUM_CHANNELS).unwrap_or(0);
                let bps = t.GetUINT32(&MF_MT_AUDIO_AVG_BYTES_PER_SECOND).unwrap_or(0);
                if sr == sample_rate && ch == channels as u32 && bps > 0 && bps < best_bytes_per_sec
                {
                    chosen = Some(t);
                    best_bytes_per_sec = bps;
                }
            }
            let out = chosen?;
            transform.SetOutputType(0, &out, 0).ok()?;
            transform
                .ProcessMessage(mf::MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .ok()?;
            transform
                .ProcessMessage(mf::MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .ok()?;
            Some(AacEncoder {
                transform,
                sample_rate,
                channels,
                time_100ns: 0,
            })
        }
    }

    /// Feeds one PCM packet and drains every ready AAC frame as ADTS.
    fn push(&mut self, pcm: &[u8]) -> Vec<Vec<u8>> {
        use windows::Win32::Media::MediaFoundation::{
            self as mf, MF_E_TRANSFORM_NEED_MORE_INPUT,
        };
        let mut out = Vec::new();
        unsafe {
            let Ok(sample) = mf::MFCreateSample() else {
                return out;
            };
            let Ok(buffer) = mf::MFCreateMemoryBuffer(pcm.len().max(1) as u32) else {
                return out;
            };
            let mut ptr = std::ptr::null_mut::<u8>();
            let mut max = 0u32;
            let mut cur = 0u32;
            if buffer
                .Lock(&mut ptr, Some(&mut max), Some(&mut cur))
                .is_err()
            {
                return out;
            }
            std::ptr::copy_nonoverlapping(pcm.as_ptr(), ptr, pcm.len());
            let _ = buffer.Unlock();
            let _ = buffer.SetCurrentLength(pcm.len() as u32);
            if sample.AddBuffer(&buffer).is_err() {
                return out;
            }
            let frames = pcm.len() as i64 / (self.channels as i64 * 2);
            let duration = frames * 10_000_000 / self.sample_rate.max(1) as i64;
            let _ = sample.SetSampleTime(self.time_100ns);
            let _ = sample.SetSampleDuration(duration.max(1));
            self.time_100ns += duration;
            if self.transform.ProcessInput(0, &sample, 0).is_err() {
                return out;
            }
            let Ok(info) = self.transform.GetOutputStreamInfo(0) else {
                return out;
            };
            let provides =
                info.dwFlags & (mf::MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32) != 0;
            loop {
                let mut buffers = [mf::MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: core::mem::ManuallyDrop::new(None),
                    dwStatus: 0,
                    pEvents: core::mem::ManuallyDrop::new(None),
                }];
                if !provides {
                    let Ok(frame_sample) = mf::MFCreateSample() else {
                        break;
                    };
                    let Ok(frame_buffer) = mf::MFCreateMemoryBuffer(info.cbSize.max(4096))
                    else {
                        break;
                    };
                    if frame_sample.AddBuffer(&frame_buffer).is_err() {
                        break;
                    }
                    buffers[0].pSample = core::mem::ManuallyDrop::new(Some(frame_sample));
                }
                let mut status = 0u32;
                match self.transform.ProcessOutput(0, &mut buffers, &mut status) {
                    Ok(()) => {
                        let Some(out_sample) = buffers[0].pSample.as_ref() else {
                            break;
                        };
                        let Ok(contiguous) = out_sample.ConvertToContiguousBuffer() else {
                            break;
                        };
                        let mut ptr = std::ptr::null_mut::<u8>();
                        let mut max = 0u32;
                        let mut cur = 0u32;
                        if contiguous
                            .Lock(&mut ptr, Some(&mut max), Some(&mut cur))
                            .is_err()
                        {
                            break;
                        }
                        let bytes = std::slice::from_raw_parts(ptr, cur as usize).to_vec();
                        let _ = contiguous.Unlock();
                        // Release the sample we allocated; the MFT-owned one
                        // stays untouched (ManuallyDrop).
                        if !provides {
                            core::mem::ManuallyDrop::drop(&mut buffers[0].pSample);
                        }
                        if !bytes.is_empty() {
                            let header =
                                adts_header(bytes.len() as u32, self.sample_rate, self.channels);
                            let mut frame = Vec::with_capacity(7 + bytes.len());
                            frame.extend_from_slice(&header);
                            frame.extend_from_slice(&bytes);
                            out.push(frame);
                        }
                    }
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => {
                        if !provides && buffers[0].pSample.is_some() {
                            core::mem::ManuallyDrop::drop(&mut buffers[0].pSample);
                        }
                        break;
                    }
                    Err(e) => {
                        if !provides && buffers[0].pSample.is_some() {
                            core::mem::ManuallyDrop::drop(&mut buffers[0].pSample);
                        }
                        tracing::warn!("audio: encoder output failed: {e}");
                        break;
                    }
                }
            }
        }
        out
    }
}

impl Drop for AacEncoder {
    fn drop(&mut self) {
        use windows::Win32::Media::MediaFoundation::{
            MFT_MESSAGE_COMMAND_DRAIN, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
        };
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0);
        }
    }
}

/// 7-byte ADTS header for one AAC-LC frame (no CRC).
fn adts_header(frame_len: u32, sample_rate: u32, channels: u16) -> [u8; 7] {
    let rate_index = match sample_rate {
        96000 => 0,
        88200 => 1,
        64000 => 2,
        48000 => 3,
        44100 => 4,
        32000 => 5,
        24000 => 6,
        22050 => 7,
        16000 => 8,
        12000 => 9,
        11025 => 10,
        8000 => 11,
        7350 => 12,
        _ => 3, // 48 kHz: the encoder refuses unusual rates anyway
    };
    let channels = channels.clamp(1, 7) as u32;
    let profile = 1u32; // AAC-LC (object type 2 - 1)
    let full_len = frame_len + 7;
    let mut h = [0u8; 7];
    h[0] = 0xFF; // syncword
    h[1] = 0xF1; // MPEG-4, layer 0, protection absent
    // profile(2) | rate_index(4) | private(1) | channel_config MSB
    h[2] = ((profile << 6) | (rate_index << 2) | (1 << 1) | (channels >> 2)) as u8;
    // channel_config LSBs | original(1) | home(1) | copyright id(1) |
    // copyright start(1) | frame length bits 11..10
    h[3] = (((channels & 0x3) << 6) | ((full_len >> 11) & 0x3)) as u8;
    h[4] = ((full_len >> 3) & 0xFF) as u8;
    // frame length LSBs | buffer fullness 0x7FF high bits
    h[5] = (((full_len & 0x7) << 5) | 0x1F) as u8;
    // buffer fullness LSBs | frames-per-buffer - 1
    h[6] = 0xFC;
    h
}

// ---------------------------------------------------------------------------
// URL helper (used by the tray)
// ---------------------------------------------------------------------------

/// Best-effort LAN IPv4 of this machine (no packets are sent).
fn lan_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Clickable stream URL for the tray menu, or `None` when audio is off.
pub fn stream_url() -> Option<String> {
    if !crate::settings::AUDIO_ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let ip = if crate::settings::LOOPBACK_ONLY.load(Ordering::Relaxed) {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        lan_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    };
    Some(format!(
        "http://{ip}:{}/{}",
        crate::settings::AUDIO_PORT.load(Ordering::Relaxed),
        crate::settings::audio_token()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adts_header_shape() {
        let h = adts_header(371, 48000, 2);
        assert_eq!(h[0], 0xFF);
        assert_eq!(h[1], 0xF1);
        // profile=1 (AAC-LC) | rate index 3 (48 kHz) | private=1 | ch MSB=0
        assert_eq!(h[2], (1 << 6) | (3 << 2) | (1 << 1));
        let full = 371 + 7;
        let length = ((h[3] as u32 & 0x3) << 11) | ((h[4] as u32) << 3) | ((h[5] as u32) >> 5);
        assert_eq!(length, full);
        assert_eq!(h[6], 0xFC);
    }

    #[test]
    fn wav_header_shape() {
        let h = wav_header(48000, 2);
        assert_eq!(&h[0..4], b"RIFF");
        assert_eq!(&h[8..12], b"WAVE");
        assert_eq!(h.len(), 44);
        let channels = u16::from_le_bytes(h[22..24].try_into().unwrap());
        let rate = u32::from_le_bytes(h[24..28].try_into().unwrap());
        assert_eq!((channels, rate), (2, 48000));
    }

    #[test]
    fn hub_subscribe_publish_unsubscribe() {
        let (id, rx) = subscribe();
        publish(Chunk {
            kind: Kind::Wav,
            data: vec![1, 2, 3],
        });
        let got = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(got.data, vec![1, 2, 3]);
        unsubscribe(id);
        assert!(!LISTENERS.lock().unwrap().iter().any(|l| l.id == id));
    }
}
