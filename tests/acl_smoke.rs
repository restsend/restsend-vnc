//! CIDR allow-list integration tests.
//!
//! The ACL is enforced after `accept()` and before the RFB handshake, so a
//! rejected peer sees an immediate EOF and an allowed peer receives the
//! protocol version string.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TempAppData(PathBuf);

impl TempAppData {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rvnc-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempAppData(dir)
    }
}

impl Drop for TempAppData {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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

fn spawn(port: u16, appdata: &TempAppData, extra: &[&str]) -> ChildGuard {
    let port_text = port.to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_restsend-vnc"));
    cmd.args([
        "--test-pattern",
        "--no-auth",
        "--no-confirm",
        "--host",
        "127.0.0.1",
        "--port",
        &port_text,
    ])
    .args(extra)
    .env("APPDATA", &appdata.0)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    ChildGuard(cmd.spawn().expect("spawn restsend-vnc"))
}

fn expect_protocol_version(port: u16) {
    let mut s = connect_retry(port);
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut version = [0u8; 12];
    s.read_exact(&mut version).expect("server version");
    assert_eq!(&version[..4], b"RFB ", "expected an RFB greeting");
}

fn expect_closed(port: u16) {
    let mut s = connect_retry(port);
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut byte = [0u8; 1];
    match s.read(&mut byte) {
        Ok(0) => {}
        Ok(n) => panic!("ACL rejection leaked {n} byte(s) to the peer"),
        // Windows reports an aborted connection rather than a clean EOF.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        Err(e) => panic!("unexpected error while waiting for ACL rejection: {e}"),
    }
}

#[test]
fn acl_rejects_unlisted_loopback() {
    let appdata = TempAppData::new();
    let port = free_port();
    let _guard = spawn(port, &appdata, &["--allow-cidrs", "10.0.0.0/8"]);
    expect_closed(port);
}

#[test]
fn acl_allows_listed_loopback() {
    let appdata = TempAppData::new();
    let port = free_port();
    let _guard = spawn(
        port,
        &appdata,
        &["--allow-cidrs", "127.0.0.1/32, 10.0.0.0/8"],
    );
    expect_protocol_version(port);
}

#[test]
fn acl_empty_allows_loopback() {
    let appdata = TempAppData::new();
    let port = free_port();
    let _guard = spawn(port, &appdata, &[]);
    expect_protocol_version(port);
}

#[test]
fn invalid_acl_refuses_to_start() {
    let appdata = TempAppData::new();
    let port = free_port();
    let port_text = port.to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_restsend-vnc"))
        .args([
            "--test-pattern",
            "--no-auth",
            "--no-confirm",
            "--host",
            "127.0.0.1",
            "--port",
            &port_text,
            "--allow-cidrs",
            "10.0.0.0/33",
        ])
        .env("APPDATA", &appdata.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn restsend-vnc");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            assert!(!status.success(), "invalid --allow-cidrs must fail startup");
            return;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("invalid --allow-cidrs did not fail startup");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
