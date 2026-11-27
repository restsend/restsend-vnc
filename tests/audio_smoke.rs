//! Audio side-channel smoke test (Windows only).
//!
//! The audio HTTP endpoint must serve the token-gated index page on plain
//! HTTP, reject wrong tokens, and stream (or cleanly 503 when the runner has
//! no audio capture device / its Media Foundation stack cannot encode).
//! Playback itself is the browser's job; this test only exercises the server
//! side. The server's stderr is captured and reported on failure so a
//! capture/encoder crash is visible in CI.

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
    let mut s = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(s) => s,
        Err(_) => return (0, String::new(), Vec::new()),
    };
    s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    if write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .is_err()
    {
        return (0, String::new(), Vec::new());
    }
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
    let Some(text_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return (0, String::new(), buf);
    };
    let head = String::from_utf8_lossy(&buf[..text_end]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, head, buf[buf.len().min(text_end + 4)..].to_vec())
}

fn server_alive() -> bool {
    // The spawned binary is restsend-vnc.exe (console build).
    !std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq restsend-vnc.exe", "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("restsend-vnc"))
        .unwrap_or(true)
}

/// Non-panicking variant used from the panic hook.
fn server_alive_probe() -> bool {
    server_alive()
}

fn dump_server_log(path: &std::path::Path) {
    if let Ok(text) = std::fs::read_to_string(path) {
        let tail: Vec<&str> = text.lines().rev().take(12).collect();
        println!("--- server stderr tail ---");
        for line in tail.iter().rev() {
            println!("{line}");
        }
    }
}

#[test]
fn audio_http_endpoint_serves_page_and_gates_tokens() {
    let vnc_port = free_port();
    let audio_port = free_port();
    let work = std::env::temp_dir().join(format!(
        "restsend-vnc-audio-test-{}-{}",
        std::process::id(),
        vnc_port
    ));
    std::fs::create_dir_all(&work).unwrap();
    let share_dir = work.join("share");
    std::fs::create_dir_all(&share_dir).unwrap();
    let stderr_log = work.join("server.err.log");
    // Dump the server's stderr on ANY test failure: the audio capture or
    // encoder can take the process down natively (no Rust panic), and the
    // stderr is the only way to see how far startup got.
    let hook_log = stderr_log.clone();
    std::panic::set_hook(Box::new(move |info| {
        println!("panic: {info}");
        println!("server process alive: {}", server_alive_probe());
        if let Ok(text) = std::fs::read_to_string(&hook_log) {
            println!("--- server stderr ({} bytes) ---", text.len());
            println!("{text}");
        } else {
            println!("--- server stderr: <unavailable> ---");
        }
    }));
    let mut child = Command::new(env!("CARGO_BIN_EXE_restsend-vnc"))
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
        .stderr(Stdio::from(std::fs::File::create(&stderr_log).unwrap()))
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
    // clean 503 when the machine has no capture device. A dead server is
    // reported with its stderr tail: on runner SKUs without a usable Media
    // Foundation stack the capture thread can take the process down, which
    // this test records instead of masking.
    // The server answers 503 after its own 8 s first-chunk deadline when no
    // capture device is present; read longer than that so the 503 is seen.
    let (status, head, body) = http_get(
        audio_port,
        "/tokentokentoken/stream",
        Duration::from_secs(12),
    );
    if status == 0 && !server_alive() {
        // Report everything useful before panicking: the process exit code,
        // the last Application-log crash event, and the server's stderr.
        if let Ok(Some(status_info)) = child.try_wait() {
            println!("server exit status: {status_info}");
        } else {
            println!("server still running per handle (tasklist disagreed)");
        }
        if let Ok(out) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1001} -MaxEvents 2 -ErrorAction SilentlyContinue | ForEach-Object { $_.TimeCreated.ToString() + ' :: ' + $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) }",
            ])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            println!("--- last Application error events ---\n{text}");
        }
        dump_server_log(&stderr_log);
        panic!(
            "server process died before the stream request (capture/encoder crash on this SKU)"
        );
    }
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
        assert!(
            status == 503,
            "stream status must be 200 or 503, got {status} (server alive: {})",
            server_alive()
        );
    }

    let _ = std::fs::remove_dir_all(&work);
}
