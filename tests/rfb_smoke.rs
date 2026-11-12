//! End-to-end wire smoke test.
//!
//! Starts the real binary in `--test-pattern` mode and walks a plain RFB 3.8
//! session far enough to receive a framebuffer update. This catches protocol
//! regressions in the handshake, ServerInit, encoding negotiation and the
//! server-push loop without needing a real desktop.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().unwrap().port()
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

fn read_u8(s: &mut TcpStream) -> u8 {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).expect("read from server");
    b[0]
}

fn read_u16(s: &mut TcpStream) -> u16 {
    let mut b = [0u8; 2];
    s.read_exact(&mut b).expect("read from server");
    u16::from_be_bytes(b)
}

fn read_u32(s: &mut TcpStream) -> u32 {
    let mut b = [0u8; 4];
    s.read_exact(&mut b).expect("read from server");
    u32::from_be_bytes(b)
}

#[test]
fn test_pattern_session_reaches_framebuffer_update() {
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_restsend-vnc"))
        .args([
            "--test-pattern",
            "--no-auth",
            "--no-confirm",
            "--allow-cidrs",
            "127.0.0.1/32",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn restsend-vnc");
    let _guard = KillOnDrop(child);

    let mut s = connect_retry(port);
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();

    // Version exchange: the server announces 3.889 (Apple-compatible), a
    // standard client answers 3.8.
    let mut server_version = [0u8; 12];
    s.read_exact(&mut server_version).expect("server version");
    assert_eq!(&server_version[..4], b"RFB ");
    s.write_all(b"RFB 003.008\n").unwrap();

    // Security types: choose None (1).
    let count = read_u8(&mut s) as usize;
    assert!(count > 0, "server offered no security types");
    let mut types = vec![0u8; count];
    s.read_exact(&mut types).unwrap();
    let chosen = if types.contains(&1) {
        1
    } else {
        panic!("test pattern without --no-auth should offer None, got {types:?}");
    };
    s.write_all(&[chosen]).unwrap();
    let result = read_u32(&mut s);
    assert_eq!(result, 0, "SecurityResult must be success");

    // ClientInit (shared) + ServerInit.
    s.write_all(&[1]).unwrap();
    let width = read_u16(&mut s);
    let height = read_u16(&mut s);
    assert_eq!((width, height), (1280, 720), "test-pattern geometry");

    let mut pf = [0u8; 16];
    s.read_exact(&mut pf).unwrap();
    let name_len = read_u32(&mut s) as usize;
    let mut name = vec![0u8; name_len.min(4096)];
    s.read_exact(&mut name).unwrap();

    // SetPixelFormat (native 32bpp) and SetEncodings (ZRLE + Raw + cursor).
    let mut msg = vec![0u8, 0, 0, 0];
    msg.extend_from_slice(&pf);
    s.write_all(&msg).unwrap();
    let encodings: [i32; 4] = [16, 0, -239, -232];
    let mut msg = vec![2u8, 0];
    msg.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for e in encodings {
        msg.extend_from_slice(&e.to_be_bytes());
    }
    s.write_all(&msg).unwrap();

    // A normal incremental request; the server pushes regardless, but this
    // also exercises the client-message parser.
    let mut fbur = vec![3u8, 1];
    fbur.extend_from_slice(&0u16.to_be_bytes());
    fbur.extend_from_slice(&0u16.to_be_bytes());
    fbur.extend_from_slice(&width.to_be_bytes());
    fbur.extend_from_slice(&height.to_be_bytes());
    s.write_all(&fbur).unwrap();

    // Read messages until a non-empty FramebufferUpdate arrives. Cursor
    // pseudo-rects (-239/-232) are fine too; we only assert layout sanity.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_update = false;
    while Instant::now() < deadline {
        let msg_type = read_u8(&mut s);
        match msg_type {
            0 => {
                let _pad = read_u8(&mut s);
                let nrects = read_u16(&mut s) as usize;
                assert!(nrects > 0, "framebuffer update carried no rects");
                {
                    let x = read_u16(&mut s);
                    let y = read_u16(&mut s);
                    let w = read_u16(&mut s);
                    let h = read_u16(&mut s);
                    let enc = read_u32(&mut s) as i32;
                    assert!(x as u32 + w as u32 <= width as u32 + 1);
                    assert!(y as u32 + h as u32 <= height as u32 + 1);
                    assert!(matches!(enc, 0 | 5 | 16 | -239 | -232 | -223));
                    // We cannot skip the payload without decoding it, and
                    // this test only needs the first header. Close instead.
                    let _ = (x, y, w, h);
                    saw_update = true;
                }
                if saw_update {
                    break;
                }
            }
            1 | 2 => panic!("unexpected server message type {msg_type}"),
            other => panic!("unexpected message type {other}"),
        }
    }
    assert!(saw_update, "no framebuffer update within 10s");
}
