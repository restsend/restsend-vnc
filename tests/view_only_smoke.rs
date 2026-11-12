//! View-only configuration smoke tests.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
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

fn spawn(port: u16, extra: &[&str]) -> ChildGuard {
    let port_text = port.to_string();
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_restsend-vnc"))
            .args([
                "--test-pattern",
                "--no-auth",
                "--no-confirm",
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
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn restsend-vnc"),
    )
}

#[test]
fn view_only_starts_and_serves_the_protocol() {
    let port = free_port();
    let _guard = spawn(port, &["--view-only"]);
    let mut s = connect_retry(port);
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut version = [0u8; 12];
    s.read_exact(&mut version).expect("server version");
    assert_eq!(&version[..4], b"RFB ");
}

#[test]
fn conflicting_view_only_flags_fail_startup() {
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
            "--view-only",
            "--no-view-only",
        ])
        .env("RESTSEND_VNC_ALLOW_MULTIPLE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn restsend-vnc");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            assert!(
                !status.success(),
                "--view-only and --no-view-only must be rejected"
            );
            return;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("conflicting view-only flags did not fail startup");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
