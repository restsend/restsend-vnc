use std::time::{SystemTime, UNIX_EPOCH};

/// Formats a Unix timestamp as UTC, e.g. `2026-11-11 14:03:00 UTC`.
fn utc_string(secs: u64) -> String {
    // Civil-from-days algorithm (Howard Hinnant) — no external crates needed.
    let days = secs / 86400;
    let tod = secs % 86400;
    let (h, m, sec) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_full = if mo <= 2 { y + 1 } else { y };
    format!("{y_full:04}-{mo:02}-{d:02} {h:02}:{m:02}:{sec:02} UTC")
}

/// Local wall-clock time of the build host, so a freshly built exe is easy to
/// identify (`rvnc --version`). Falls back to UTC when `date` is unavailable.
fn local_string() -> Option<String> {
    let out = std::process::Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S %Z")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    // Windows icon + manifest resource. `embed-resource` locates the right
    // compiler for the target (windres for *-windows-gnu, rc.exe/llvm-rc for
    // *-windows-msvc) instead of relying on it being on PATH. This matters on
    // GitHub Actions, where rc.exe is present in the Windows SDK but not on
    // PATH; the old manual code silently produced an exe without the icon or
    // the Common Controls v6 manifest.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rerun-if-changed=assets/rvnc.rc");
        println!("cargo:rerun-if-changed=assets/rvnc.ico");
        println!("cargo:rerun-if-changed=assets/rvnc.manifest");
        let _ = embed_resource::compile("assets/rvnc.rc", embed_resource::NONE).manifest_optional();
    }

    // Build timestamp embedded into the binary; `rvnc --version` shows it so
    // locally-built and downloaded exes can be told apart.
    let stamp = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(v) => v
            .parse::<u64>()
            .map(utc_string)
            .unwrap_or_else(|_| utc_string(now_secs())),
        Err(_) => local_string().unwrap_or_else(|| utc_string(now_secs())),
    };

    println!("cargo:rustc-env=BUILD_TIME={stamp}");
    // Re-run on any source change so the timestamp tracks the build (a no-op
    // rebuild intentionally keeps the previous stamp).
    println!("cargo:rerun-if-changed=build.rs");
    // Refresh the stamp whenever the program sources change.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
