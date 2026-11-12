//! Session transport abstraction.
//!
//! Plain sessions keep the original design: the socket is cloned and the
//! reader/writer threads own one half each. TLS cannot be cloned, so a pump
//! thread owns the `rustls::ServerConnection` and the socket, and exchanges
//! plaintext with the session through channels:
//!
//! ```text
//! writer thread -> bounded outbound channel -> TLS pump -> socket
//! session reader <- inbound channel <- TLS pump <- socket
//! ```

use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread::JoinHandle;

use polling::{Event, Events, Poller};
use rustls::ServerConnection;

/// Poller key identifying the TCP socket (the notify key is `usize::MAX`).
const SOCKET_KEY: usize = 0;
/// Maximum plaintext bytes queued for the TLS pump before the writer thread
/// is throttled. The session writer already has its own (larger) queue, so a
/// small queue here keeps buffered frame data bounded on slow links.
const OUTBOUND_QUEUE: usize = 4;
/// Inbound plaintext chunks buffered ahead of the session reader. Bounds
/// memory if a client floods input while the reader is busy.
const INBOUND_QUEUE: usize = 256;

pub struct Io {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    /// Joined after the writer thread exits (TLS only).
    pub pump: Option<JoinHandle<()>>,
}

/// Splits a plain TCP connection into independent read/write halves.
pub fn plain(stream: TcpStream) -> io::Result<Io> {
    let read_half = stream.try_clone()?;
    Ok(Io {
        reader: Box::new(BufReader::new(read_half)),
        writer: Box::new(stream),
        pump: None,
    })
}

/// Starts the TLS pump for an established `rustls` connection.
pub fn tls(conn: ServerConnection, stream: TcpStream) -> io::Result<Io> {
    stream.set_nonblocking(false)?;
    let poller = Arc::new(Poller::new()?);
    // SAFETY: the socket stays open until the pump thread exits; the poller
    // registration is removed when the poller is dropped.
    unsafe {
        poller.add(&stream, Event::readable(SOCKET_KEY))?;
    }

    let (out_tx, out_rx) = mpsc::sync_channel::<Vec<u8>>(OUTBOUND_QUEUE);
    let (in_tx, in_rx) = mpsc::sync_channel::<Vec<u8>>(INBOUND_QUEUE);

    let pump_poller = Arc::clone(&poller);
    let pump = std::thread::Builder::new()
        .name("restsend-vnc-tls".into())
        .spawn(move || pump_loop(conn, stream, out_rx, in_tx, pump_poller))?;

    Ok(Io {
        reader: Box::new(ChannelReader {
            rx: in_rx,
            buf: Vec::new(),
            pos: 0,
        }),
        writer: Box::new(TlsWriter { tx: out_tx, poller }),
        pump: Some(pump),
    })
}

/// Writer half handed to the session writer thread. Plaintext bytes are
/// queued to the TLS pump, which encrypts and writes them.
struct TlsWriter {
    tx: SyncSender<Vec<u8>>,
    poller: Arc<Poller>,
}

impl Write for TlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TLS pump closed"))?;
        let _ = self.poller.notify();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _ = self.poller.notify();
        Ok(())
    }
}

impl Drop for TlsWriter {
    fn drop(&mut self) {
        // Wake the pump so it notices the disconnected channel and sends a
        // TLS close_notify before exiting.
        let _ = self.poller.notify();
    }
}

/// Reader half handed to the session reader thread.
struct ChannelReader {
    rx: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                // Pump exited (peer closed or transport error): EOF.
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn pump_loop(
    mut conn: ServerConnection,
    mut sock: TcpStream,
    outbound: Receiver<Vec<u8>>,
    inbound: SyncSender<Vec<u8>>,
    poller: Arc<Poller>,
) {
    let mut events = Events::new();
    let mut plain = vec![0u8; 64 * 1024];

    loop {
        if flush_tls(&mut conn, &mut sock).is_err() {
            tracing::debug!("tls pump: write/flush failed");
            break;
        }

        // Queue everything the session writer produced since the last wakeup.
        let mut disconnected = false;
        loop {
            match outbound.try_recv() {
                Ok(data) => {
                    if let Err(e) = write_plain(&mut conn, &mut sock, &data) {
                        tracing::debug!("tls pump: TLS writer error: {e}");
                        disconnected = true;
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    tracing::debug!("tls pump: outbound channel closed");
                    disconnected = true;
                    break;
                }
            }
        }
        if disconnected {
            conn.send_close_notify();
            let _ = flush_tls(&mut conn, &mut sock);
            break;
        }
        if flush_tls(&mut conn, &mut sock).is_err() {
            tracing::debug!("tls pump: write/flush failed");
            break;
        }

        // rustls may already hold decrypted plaintext that was pipelined right
        // behind the TLS handshake (for example ClientInit followed by the
        // client's first SetEncodings). Deliver it before blocking on poll.
        loop {
            match conn.reader().read(&mut plain) {
                Ok(0) => break,
                Ok(n) => {
                    if inbound.send(plain[..n].to_vec()).is_err() {
                        return;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }

        events.clear();
        if let Err(e) = poller.wait(&mut events, None) {
            tracing::debug!("tls pump: poll failed: {e}");
            break;
        }
        let readable = events.iter().any(|ev| ev.key == SOCKET_KEY && ev.readable);
        if !readable {
            continue; // spurious/notify wakeup: loop to drain outbound
        }

        // The socket is blocking, so a single read_tls() after a readiness
        // event returns promptly. It may still see a partial TLS record; the
        // remaining bytes arrive in the next wakeup.
        match conn.read_tls(&mut sock) {
            Ok(0) => {
                tracing::debug!("tls pump: socket EOF");
                break;
            }
            Ok(_) => {
                if let Err(e) = conn.process_new_packets() {
                    tracing::debug!("tls pump: process_new_packets failed: {e}");
                    break;
                }
                loop {
                    match conn.reader().read(&mut plain) {
                        Ok(0) => break,
                        Ok(n) => {
                            if inbound.send(plain[..n].to_vec()).is_err() {
                                tracing::debug!("tls pump: inbound channel closed");
                                return; // session reader went away
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            tracing::debug!("tls pump: reader failed: {e}");
                            return;
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                tracing::debug!("tls pump: read failed: {e}");
                break;
            }
        }

        // polling is in oneshot mode: re-arm the socket for the next event.
        if let Err(e) = poller.modify(&sock, Event::readable(SOCKET_KEY)) {
            tracing::debug!("tls pump: re-arm failed: {e}");
            break;
        }
    }

    // Dropping `inbound` closes the reader side.
}

fn flush_tls(conn: &mut ServerConnection, sock: &mut TcpStream) -> io::Result<()> {
    while conn.wants_write() {
        conn.write_tls(sock)?;
    }
    sock.flush()
}

/// Writes application plaintext into rustls, flushing TLS records whenever the
/// plaintext buffer fills up.
///
/// rustls buffers plaintext up to a small internal limit (64 KiB by default)
/// and `Writer::write` returns `Ok(0)` when it is full. A plain `write_all`
/// would turn that into a fatal `WriteZero` error, which is exactly what
/// happens with a multi-hundred-kilobyte framebuffer update.
fn write_plain(
    conn: &mut ServerConnection,
    sock: &mut TcpStream,
    mut data: &[u8],
) -> io::Result<()> {
    let mut stalled = 0;
    while !data.is_empty() {
        match conn.writer().write(data) {
            Ok(0) => {
                flush_tls(conn, sock)?;
                stalled += 1;
                if stalled > 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS plaintext buffer made no progress",
                    ));
                }
            }
            Ok(n) => {
                stalled = 0;
                data = &data[n..];
                // Keep the unencrypted buffer bounded while a large frame is
                // handed over; this also applies TCP backpressure promptly.
                flush_tls(conn, sock)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn tls_pump_roundtrip() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key)
                .unwrap(),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            while tls.conn.is_handshaking() {
                tls.conn.complete_io(&mut tls.sock).unwrap();
            }
            let rustls::StreamOwned { conn, sock } = tls;
            let mut io = super::tls(conn, sock).unwrap();
            // Echo a payload larger than rustls's 64 KiB plaintext buffer to
            // exercise write_plain()'s flush/retry path.
            const N: usize = 200_000;
            let mut buf = vec![0u8; N];
            io.reader.read_exact(&mut buf).unwrap();
            io.writer.write_all(&buf).unwrap();
            io.writer.flush().unwrap();
            std::thread::sleep(Duration::from_millis(500));
        });

        let sock = TcpStream::connect(addr).unwrap();
        let conn =
            rustls::ClientConnection::new(client_cfg, "localhost".try_into().unwrap()).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).unwrap();
        }
        const N: usize = 200_000;
        let payload: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
        tls.write_all(&payload).unwrap();
        tls.flush().unwrap();
        let mut buf = vec![0u8; N];
        tls.read_exact(&mut buf).unwrap();
        assert_eq!(buf, payload);
        server.join().unwrap();
    }
}
