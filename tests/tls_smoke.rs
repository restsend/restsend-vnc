//! End-to-end VeNCrypt/TLS smoke test.
//!
//! Starts the real binary with `--tls required` and a test certificate, then
//! performs the VeNCrypt negotiation and a rustls handshake exactly like a
//! TigerVNC/RealVNC client would, and finally reads the encrypted ServerInit
//! and a framebuffer update.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::CertificateDer;

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

fn connect_retry(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => return s,
            Err(e) => {
                if Instant::now() > deadline {
                    panic!("server did not start listening on {port}: {e}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn read_exact<R: Read>(r: &mut R, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).expect("read from server");
    buf
}

fn read_u8<R: Read>(r: &mut R) -> u8 {
    read_exact(r, 1)[0]
}

fn read_u16<R: Read>(r: &mut R) -> u16 {
    u16::from_be_bytes(read_exact(r, 2).try_into().unwrap())
}

fn read_u32<R: Read>(r: &mut R) -> u32 {
    u32::from_be_bytes(read_exact(r, 4).try_into().unwrap())
}

#[test]
fn vencrypt_tls_session_reaches_framebuffer_update() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // A dedicated certificate so the client can trust it without touching the
    // user's settings directory.
    let dir = std::env::temp_dir().join(format!(
        "restsend-vnc-tls-smoke-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_restsend-vnc"))
        .args([
            "--test-pattern",
            "--no-auth",
            "--tls",
            "required",
            "--tls-cert",
            cert_path.to_str().unwrap(),
            "--tls-key",
            key_path.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env("APPDATA", &dir)
        .env("HOME", &dir)
        .spawn()
        .expect("spawn restsend-vnc");
    let _guard = KillOnDrop(child);

    let mut s = connect_retry(port);
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(15))).unwrap();

    let version = read_exact(&mut s, 12);
    assert_eq!(&version[..4], b"RFB ");
    s.write_all(b"RFB 003.008\n").unwrap();

    let count = read_u8(&mut s) as usize;
    let types = read_exact(&mut s, count);
    assert_eq!(
        types,
        vec![19],
        "required TLS must offer only VeNCrypt: {types:?}"
    );
    s.write_all(&[19]).unwrap();

    // VeNCrypt 0.2.
    assert_eq!(read_exact(&mut s, 2), vec![0, 2]);
    s.write_all(&[0, 2]).unwrap();
    assert_eq!(read_u8(&mut s), 0, "VeNCrypt version accepted");
    let n = read_u8(&mut s) as usize;
    let subtypes = read_exact(&mut s, n * 4);
    let subtypes: Vec<u32> = subtypes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
        .collect();
    assert_eq!(subtypes, vec![257], "no password => TLSNone");
    s.write_all(&257u32.to_be_bytes()).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(client_cfg), "localhost".try_into().unwrap())
        .unwrap();
    let mut tls = rustls::StreamOwned::new(conn, s);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).unwrap();
    }

    assert_eq!(read_u32(&mut tls), 0, "SecurityResult must be success");

    // ClientInit + ServerInit.
    tls.write_all(&[1]).unwrap();
    tls.flush().unwrap();
    let width = read_u16(&mut tls);
    let height = read_u16(&mut tls);
    assert_eq!((width, height), (1280, 720), "test-pattern geometry");
    let _pf = read_exact(&mut tls, 16);
    let name_len = read_u32(&mut tls) as usize;
    let _name = read_exact(&mut tls, name_len.min(4096));

    // SetEncodings (Raw + ZRLE) inside TLS.
    let encodings: [i32; 2] = [0, 16];
    let mut msg = vec![2u8, 0];
    msg.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for e in encodings {
        msg.extend_from_slice(&e.to_be_bytes());
    }
    tls.write_all(&msg).unwrap();
    tls.flush().unwrap();

    // The pusher sends updates through the TLS pump.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_update = false;
    while Instant::now() < deadline {
        match read_u8(&mut tls) {
            0 => {
                let _pad = read_u8(&mut tls);
                let nrects = read_u16(&mut tls) as usize;
                if nrects > 0 {
                    saw_update = true;
                    break;
                }
            }
            3 => {
                // ServerCutText (clipboard): skip it.
                let _pad = read_exact(&mut tls, 3);
                let len = read_u32(&mut tls) as usize;
                let _text = read_exact(&mut tls, len);
            }
            other => panic!("unexpected server message type {other}"),
        }
    }
    assert!(saw_update, "no encrypted framebuffer update within 10s");

    drop(_guard);
    let _ = std::fs::remove_dir_all(dir);
}
