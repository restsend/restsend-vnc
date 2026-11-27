//! Audio side-channel smoke test (Windows only).
//!
//! The audio HTTP endpoint must serve the token-gated index page on plain
//! HTTP, reject wrong tokens, and stream (or cleanly 503 when the runner has
//! no audio capture device). Playback itself is the browser's job; this test
//! only exercises the server side.

#![cfg(target_os = "windows")]

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
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn connect_retry(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => return s,
            Err(e) => {
                if Instant::now() > deadline {
                    panic!("audio server did not start on {port}: {e}");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Performs one HTTP/1.1 GET and returns (status_code, headers, body_head).
fn http_get(port: u16, path: &str, read_for: Duration) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let deadline = Instant::now() + read_for;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while Instant::now() < deadline {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
        if buf.len() > 512 * 1024 {
            break;
        }
    }
    let text_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..text_end]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, head, buf[buf.len().min(text_end + 4)..].to_vec())
}

#[test]
fn audio_http_endpoint_serves_page_and_gates_tokens() {
    let vnc_port = free_port();
    let audio_port = free_port();
    let share_dir = std::env::temp_dir().join(format!(
        "restsend-vnc-audio-share-{}-{}",
        std::process::id(),
        vnc_port
    ));
    std::fs::create_dir_all(&share_dir).unwrap();
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
            &vnc_port.to_string(),
            "--share-dir",
            &share_dir.to_string_lossy(),
            "--audio",
            "--audio-port",
            &audio_port.to_string(),
        ])
        .env("RESTSEND_VNC_ALLOW_MULTIPLE", "1")
        .env("RESTSEND_VNC_AUDIO_TOKEN", "tokentokentoken")
        .env("RUST_LOG", "restsend_vnc=info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn restsend-vnc");
    let _guard = KillOnDrop(child);

    connect_retry(audio_port);

    // Wrong token: 403, never the page.
    let (status, _, body) = http_get(audio_port, "/wrong-token/", Duration::from_secs(3));
    assert_eq!(status, 403, "wrong token must be rejected");
    assert!(!body.windows(6).any(|w| w == b"<audio"), "no player markup");

    // Index page: 200 with the audio element.
    let (status, _, body) = http_get(audio_port, "/tokentokentoken/", Duration::from_secs(3));
    assert_eq!(status, 200, "index page status");
    assert!(
        body.windows(6).any(|w| w == b"<audio"),
        "index page carries the audio element"
    );

    // Stream endpoint: either a live stream (Content-Type: audio/*) or a
    // clean 503 when the machine has no capture device.
    let (status, head, body) =
        http_get(audio_port, "/tokentokentoken/stream", Duration::from_secs(6));
    let content_type = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
        .map(|l| l.trim().to_string())
        .unwrap_or_default();
    if status == 200 {
        assert!(
            content_type.to_ascii_lowercase().contains("audio/"),
            "stream content type: {content_type}"
        );
        assert!(
            !body.is_empty(),
            "live stream must deliver data immediately after the header"
        );
    } else {
        assert_eq!(status, 503, "stream status must be 200 or 503, got {status}");
    }

    let _ = std::fs::remove_dir_all(&share_dir);
}
