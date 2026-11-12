//! rvnc — a headless VNC server CLI for Windows.
#![cfg_attr(all(target_os = "windows", feature = "gui"), windows_subsystem = "windows")]
//!
//! See README.md for usage notes.

mod awake;
mod clipboard;
mod config;
mod cursor;
mod diff;
mod encode;
mod framebuffer;
mod input;
mod rfb;
mod screen;
mod server;
mod settings;
mod autostart;
mod audit;
mod tls;
mod transport;
#[cfg(target_os = "windows")]
mod tray;
mod session;
mod throttle;

use std::io::IsTerminal;
use std::net::TcpListener;
use std::sync::Arc;

use config::{Config, Cli};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    if cli.install_task {
        install_logon_task(true);
        return;
    }
    if cli.remove_task {
        install_logon_task(false);
        return;
    }

    // Logging: RUST_LOG wins; otherwise warn (debug with -v).
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        if cli.verbose {
            "restsend_vnc=debug".into()
        } else {
            "warn".into()
        }
    });
    #[cfg(all(target_os = "windows", feature = "gui"))]
    {
        let path = settings::settings_path().with_file_name("restsend-vnc.log");
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let writer = LogFile(std::sync::Arc::new(std::sync::Mutex::new(file)));
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new(filter.clone()))
                .with_writer(writer)
                .with_ansi(false)
                .init();
        }
    }
    #[cfg(not(all(target_os = "windows", feature = "gui")))]
    {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_writer(std::io::stderr)
            .init();
    }

    tracing::info!(
        "starting {} build {} (settings: {})",
        if cfg!(feature = "gui") { "GUI" } else { "console" },
        env!("BUILD_TIME"),
        settings::settings_path().display()
    );

    #[cfg(target_os = "windows")]
    if !single_instance_ok() {
        fatal_dialog(
            "restsend-vnc is already running.\n\nOnly one instance is allowed.\n\
             Look for the tray icon, or stop the other rvnc process first.",
        );
        std::process::exit(0);
    }

    let cfg = match Config::resolve(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    // Persisted settings (settings.ini) are the base; CLI flags override them
    // for THIS run only and are never written back to the file.
    let file_settings = settings::load();
    if !settings::settings_path().exists() {
        settings::save(&file_settings);
        tracing::info!("created default settings at {}", settings::settings_path().display());
    }
    let mut effective = file_settings.clone();
    if cfg.port != 5900 {
        effective.port = cfg.port;
    }
    if cfg.color_level != 24 {
        effective.color_level = cfg.color_level;
    }
    if cfg.keep_awake {
        effective.keep_awake = true;
    }
    if cfg.debug {
        effective.allow_debug = true;
    }
    if cfg.name != "restsend-vnc" {
        effective.title = cfg.name.clone();
    }
    if let Some(mode) = cfg.tls {
        effective.tls = mode;
    }
    if let Some(path) = &cfg.tls_cert {
        effective.tls_cert = Some(path.display().to_string());
    }
    if let Some(path) = &cfg.tls_key {
        effective.tls_key = Some(path.display().to_string());
    }
    settings::apply_live(&effective);
    tracing::info!(
        "settings: port={} color={} loopback_only={} keep_awake={} allow_debug={} tls={} url={}",
        effective.port,
        effective.color_level,
        effective.loopback_only,
        effective.keep_awake,
        effective.allow_debug,
        effective.tls,
        effective.url
    );

    // Load/generate the TLS certificate before accepting connections so a
    // required-TLS configuration fails closed instead of silently downgrading.
    if effective.tls != tls::Mode::Off {
        let available = tls::server_config().is_some();
        if !available && effective.tls == tls::Mode::Required {
            fatal_dialog(
                "TLS is required but no usable certificate could be loaded.\n\n\
                 Check the log, or provide --tls-cert and --tls-key.",
            );
            std::process::exit(1);
        }
    }
    if cfg.password.is_some() {
        settings::set_password(cfg.password.clone());
    }

    // Tray icon + native settings window (Windows GUI build).
    #[cfg(target_os = "windows")]
    tray::spawn();

    if cfg.keep_awake || settings::KEEP_AWAKE.load(std::sync::atomic::Ordering::Relaxed) {
        awake::enable();
    }

    #[cfg(target_os = "windows")]
    if !cfg.test_pattern && !is_elevated() {
        tracing::warn!(
            "restsend-vnc is not running as administrator: Task Manager, UAC prompts and \
             other elevated windows cannot receive mouse/keyboard input (UIPI). \
             Restart from an elevated terminal to control them."
        );
    }

    // DPI awareness must be set before WGC/monitor/cursor queries so all of
    // them report physical pixels.
    #[cfg(target_os = "windows")]
    input::windows::enable_dpi_awareness();

    // --- screen capture thread ---
    let state = Arc::new(framebuffer::ScreenState::with_options(
        cfg.fps,
        cfg.color_level,
        cfg.scale,
    ));
    state.set_debug(cfg.debug);
    spawn_sys_sampler(Arc::clone(&state));
    // Encoder reads this when it creates its per-session zlib stream.
    std::env::set_var("RESTSEND_VNC_ZRLE_LEVEL", cfg.zrle_level.to_string());
    // windows-capture reads this to coalesce frames before the GPU->CPU copy.
    std::env::set_var("RESTSEND_VNC_CAPTURE_FPS", cfg.fps.max(1).to_string());
    let kind = if cfg.test_pattern {
        screen::ScreenKind::Dummy
    } else {
        screen::ScreenKind::Desktop
    };
    if let Err(e) = screen::spawn(kind, cfg.display, cfg.fps, Arc::clone(&state)) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    #[cfg(target_os = "windows")]
    if !cfg.test_pattern {
        // Watches the system cursor independently of WGC: pointer movement
        // must not force a full-resolution capture pass.
        let _ = cursor::spawn_poller(Arc::clone(&state));
    }
    if cfg.test_pattern {
        tracing::info!("serving a synthetic test pattern (--test-pattern)");
        if !cfg.view_only {
            tracing::warn!("input is disabled in test-pattern mode");
        }
    }
    // --- clipboard watcher ---
    let hub = Arc::new(clipboard::ClipboardHub::new());
    hub.spawn_watcher(cfg.clipboard_enabled && !cfg.view_only);

    let auth_desc = if cfg.password.is_some() {
        "vnc auth"
    } else {
        "no auth"
    };
    let tls_desc = match effective.tls {
        tls::Mode::Off => "TLS off",
        tls::Mode::Auto => "TLS preferred",
        tls::Mode::Required => "TLS required",
    };
    let session_cfg = session::SessionConfig {
        name: cfg.name.clone(),
        view_only: cfg.view_only,
        input_enabled: !cfg.test_pattern,
        test_pattern: cfg.test_pattern,
        share_root: cfg.share_root.clone(),
        clipboard_enabled: cfg.clipboard_enabled,
    };

    let mut printed = false;
    loop {
        if settings::EXIT.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let port = settings::PORT.load(std::sync::atomic::Ordering::Relaxed);
        let loopback = settings::LOOPBACK_ONLY.load(std::sync::atomic::Ordering::Relaxed);
        let host = if loopback {
            "127.0.0.1".to_string()
        } else {
            cfg.host.clone().unwrap_or_else(|| "0.0.0.0".to_string())
        };
        let addr = format!("{host}:{port}");
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("cannot bind {addr}: {e}");
                if !printed {
                    fatal_dialog(&format!(
                        "Cannot listen on {addr}:\n{e}\n\n\
                         The port may be in use by another program."
                    ));
                    printed = true;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
        };
        printed = false;
        let flags = [
            ("view-only", cfg.view_only),
            ("clipboard", cfg.clipboard_enabled && !cfg.view_only),
            ("file-transfer", !cfg.view_only && (cfg.share_root.is_some() || settings::share_files())),
            ("keep-awake", settings::KEEP_AWAKE.load(std::sync::atomic::Ordering::Relaxed)),
        ]
        .into_iter()
        .filter_map(|(k, on)| on.then_some(k.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
        tracing::info!(
            "listening on {addr} (auth: {auth_desc}; {tls_desc}{})",
            if flags.is_empty() {
                String::new()
            } else {
                format!("; {flags}")
            }
        );
        if std::io::stdin().is_terminal() && !printed {
            println!("Connect with: vnc://{}:{port}", display_host(&host));
            println!("Press Ctrl+C to stop.");
        }
        printed = true;
        let generation = settings::RELOAD.load(std::sync::atomic::Ordering::Relaxed);
        if let Err(e) = server::serve(
            listener,
            Arc::clone(&state),
            Arc::clone(&hub),
            cfg.password.clone(),
            session_cfg.clone(),
            generation,
        ) {
            tracing::error!("listener error: {e}");
        }
    }
}

fn display_host(host: &str) -> &str {
    match host {
        "0.0.0.0" | "::" => "127.0.0.1",
        other => other,
    }
}


/// True when the process token is elevated (running "as administrator").
#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}


/// Samples process CPU/RSS once per second for the debug overlay.
fn spawn_sys_sampler(state: Arc<framebuffer::ScreenState>) {
    std::thread::Builder::new()
        .name("restsend-vnc-sys-sampler".into())
        .spawn(move || {
            let mut sys = sysinfo::System::new();
            let pid = sysinfo::get_current_pid().ok();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
                if let Some(proc_) = pid.and_then(|p| sys.process(p)) {
                    let rss_mb = proc_.memory() as f32 / 1_048_576.0;
                    state.set_sys_stats(proc_.cpu_usage(), rss_mb);
                }
            }
        })
        .ok();
}


/// Windows named mutex: only one rvnc process per machine/session.
#[cfg(target_os = "windows")]
fn single_instance_ok() -> bool {
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;
    let name: Vec<u16> = "Global\\restsend_vnc_single_instance\0".encode_utf16().collect();
    match unsafe { CreateMutexW(None, true, windows::core::PCWSTR(name.as_ptr())) } {
        Ok(_) => unsafe { GetLastError() != ERROR_ALREADY_EXISTS },
        Err(_) => true,
    }
}

/// Log writer for the GUI build (no console): appends to `%APPDATA%\rvnc\rvnc.log`.
#[cfg(all(target_os = "windows", feature = "gui"))]
#[derive(Clone)]
struct LogFile(std::sync::Arc<std::sync::Mutex<std::fs::File>>);

#[cfg(all(target_os = "windows", feature = "gui"))]
impl std::io::Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut f = self.0.lock().unwrap();
        f.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

#[cfg(all(target_os = "windows", feature = "gui"))]
impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for LogFile {
    type Writer = LogFile;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}


/// Shows a message box in GUI builds and prints to stderr otherwise.
fn fatal_dialog(msg: &str) {
    tracing::error!("{msg}");
    #[cfg(all(target_os = "windows", feature = "gui"))]
    {
        let text: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
                None,
                windows::core::PCWSTR(text.as_ptr()),
                windows::core::w!("restsend-vnc"),
                windows::Win32::UI::WindowsAndMessaging::MB_OK
                    | windows::Win32::UI::WindowsAndMessaging::MB_ICONWARNING,
            );
        }
    }
    #[cfg(not(all(target_os = "windows", feature = "gui")))]
    {
        eprintln!("error: {msg}");
    }
}


/// Creates/removes a logon scheduled task with highest privileges (the
/// practical equivalent of a service for screen capture, which cannot run in
/// session 0). The tray button launches this elevated via `--install-task`.
fn install_logon_task(install: bool) {
    let exe = std::env::current_exe().unwrap_or_default();
    let mut cmd = std::process::Command::new("schtasks");
    if install {
        cmd.args([
            "/Create",
            "/F",
            "/SC",
            "ONLOGON",
            "/RL",
            "HIGHEST",
            "/TN",
            "restsend-vnc",
            "/TR",
            &format!("\"{}\"", exe.display()),
        ]);
    } else {
        cmd.args(["/Delete", "/F", "/TN", "restsend-vnc"]);
    }
    let ok = cmd.status().map(|s| s.success()).unwrap_or(false);
    crate::settings::set_autostart_task(install);
    let msg = if install {
        "Elevated logon task installed (runs at sign-in as administrator)."
    } else {
        "Elevated logon task removed."
    };
    let text: Vec<u16> = format!("{}\n\n{}", msg, if ok { "OK" } else { "Failed" })
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    #[cfg(target_os = "windows")]
    unsafe {
        windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
            None,
            windows::core::PCWSTR(text.as_ptr()),
            windows::core::w!("restsend-vnc"),
            windows::Win32::UI::WindowsAndMessaging::MB_OK,
        );
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = text;
        eprintln!("{msg}");
    }
}
