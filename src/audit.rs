//! Session audit log: client address, protocol/auth version, connect time and
//! session duration (append-only `sessions.log` next to settings.ini).

use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;

pub fn log(event: &str, peer: &SocketAddr, info: &str, duration: Option<Duration>) {
    let path = crate::settings::settings_path().with_file_name("sessions.log");
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let dur = duration
        .map(|d| {
            format!(
                " duration={:02}:{:02}:{:02}",
                d.as_secs() / 3600,
                (d.as_secs() % 3600) / 60,
                d.as_secs() % 60
            )
        })
        .unwrap_or_default();
    let line = format!("{ts} {event} {peer} {info}{dur}\n");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
    tracing::info!("session {event}: {peer} {info}{dur}");
}
