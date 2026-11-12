//! Connection-confirmation smoke tests.
//!
//! The decision is supplied through `RESTSEND_VNC_APPROVAL`, so these tests
//! exercise the real session gate without needing a Windows desktop. The GUI
//! dialog itself is verified manually (see the checklist in the PR/README).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
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

/// Completes version/security/ClientInit and returns the stream right before
/// the server would send ServerInit (or reject the connection).
fn start_session(port: u16) -> TcpStream {
    let mut s = connect_retry(port);
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut server_version = [0u8; 12];
    s.read_exact(&mut server_version).expect("server version");
    assert_eq!(&server_version[..4], b"RFB ");
    s.write_all(b"RFB 003.008\n").unwrap();

    let count = read_u8(&mut s) as usize;
    let mut types = vec![0u8; count];
    s.read_exact(&mut types).unwrap();
    assert!(
        types.contains(&1),
        "expected security type None, got {types:?}"
    );
    s.write_all(&[1]).unwrap();
    assert_eq!(read_u32(&mut s), 0, "SecurityResult must be success");

    s.write_all(&[1]).unwrap(); // ClientInit (shared)
    s
}

fn expect_eof(s: &mut TcpStream) {
    let mut byte = [0u8; 1];
    match s.read(&mut byte) {
        Ok(0) => {}
        Ok(n) => panic!("expected EOF before ServerInit, got {n} byte(s)"),
        Err(e) => panic!("expected EOF before ServerInit, got error: {e}"),
    }
}

fn spawn(port: u16, extra: &[&str], envs: &[(&str, &str)]) -> KillOnDrop {
    let port_text = port.to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_restsend-vnc"));
    cmd.args([
        "--test-pattern",
        "--no-auth",
        "--allow-cidrs",
        "127.0.0.1/32",
        "--host",
        "127.0.0.1",
        "--port",
        &port_text,
    ])
    .args(extra)
    .env("RESTSEND_VNC_ALLOW_MULTIPLE", "1")
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    KillOnDrop(cmd.spawn().expect("spawn restsend-vnc"))
}

#[test]
fn accepted_connection_reaches_server_init() {
    let port = free_port();
    let _guard = spawn(port, &["--confirm"], &[("RESTSEND_VNC_APPROVAL", "accept")]);
    let mut s = start_session(port);
    assert_eq!(read_u16(&mut s), 1280, "test-pattern width");
    assert_eq!(read_u16(&mut s), 720, "test-pattern height");
}

#[test]
fn rejected_connection_closes_before_server_init() {
    let port = free_port();
    let _guard = spawn(port, &["--confirm"], &[("RESTSEND_VNC_APPROVAL", "reject")]);
    let mut s = start_session(port);
    expect_eof(&mut s);
}

#[test]
fn timeout_closes_before_server_init() {
    let port = free_port();
    let _guard = spawn(
        port,
        &["--confirm"],
        &[
            ("RESTSEND_VNC_APPROVAL", "timeout"),
            ("RESTSEND_VNC_APPROVAL_TIMEOUT_MS", "300"),
        ],
    );
    let mut s = start_session(port);
    let started = Instant::now();
    expect_eof(&mut s);
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "timeout fired too early"
    );
}

#[test]
fn disabled_confirmation_ignores_override() {
    let port = free_port();
    let _guard = spawn(
        port,
        &["--no-confirm"],
        &[("RESTSEND_VNC_APPROVAL", "reject")],
    );
    let mut s = start_session(port);
    assert_eq!(read_u16(&mut s), 1280);
    assert_eq!(read_u16(&mut s), 720);
}

#[test]
fn rejection_is_written_to_the_audit_log() {
    let port = free_port();
    let temp = std::env::temp_dir().join(format!(
        "rvnc-approval-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();
    let appdata = temp.display().to_string();
    let _guard = spawn(
        port,
        &["--confirm"],
        &[
            ("RESTSEND_VNC_APPROVAL", "reject"),
            ("APPDATA", appdata.as_str()),
        ],
    );
    let mut s = start_session(port);
    expect_eof(&mut s);

    let log: PathBuf = temp.join("restsend-vnc").join("sessions.log");
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut body = String::new();
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&log) {
            body = text;
            if body.contains("reject") {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(&temp);
    assert!(
        body.contains("reject"),
        "expected a reject event in {}, got: {body:?}",
        log.display()
    );
}
