//! CLI definition and config resolution.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use crate::rfb::filetransfer::ShareRoot;

#[derive(Parser, Debug)]
#[command(
    name = "restsend-vnc",
    version = concat!(env!("CARGO_PKG_VERSION"), " (build ", env!("BUILD_TIME"), ")"),
    about = "A headless VNC server CLI for Windows",
    after_help = "Examples:\n  restsend-vnc --password secret\n  restsend-vnc --host 0.0.0.0 --port 5900 --password s3cret --share-dir C:\\Public --keep-awake\n  restsend-vnc --test-pattern --port 5901 --no-auth\n\nConnect with any VNC viewer (TightVNC, UltraVNC, TigerVNC, RealVNC...)."
)]
pub struct Cli {
    /// Listen address (default 0.0.0.0 = all interfaces; use 127.0.0.1 to
    /// restrict to this machine). The tray "only loopback" setting wins.
    #[arg(long)]
    pub host: Option<String>,

    /// Listen port (default VNC port 5900)
    #[arg(long, default_value_t = 5900)]
    pub port: u16,

    /// VNC authentication password (protocol uses the first 8 bytes).
    /// Falls back to the RESTSEND_VNC_PASSWORD environment variable, then to an
    /// interactive prompt.
    #[arg(long)]
    pub password: Option<String>,

    /// Allow unauthenticated connections (or omit --password deliberately)
    #[arg(long)]
    pub no_auth: bool,

    /// Ignore all client input (keyboard, mouse, clipboard, files)
    #[arg(long)]
    pub view_only: bool,

    /// Display/output index to share (default: 0)
    #[arg(long, default_value_t = 0)]
    pub display: usize,

    /// Maximum capture/push frame rate
    #[arg(long, default_value_t = 30)]
    pub fps: u32,

    /// zlib compression level for ZRLE (1 = fastest, 9 = smallest).
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..=9))]
    pub zrle_level: u32,

    /// Internal: install an elevated logon task (used by the tray button).
    #[arg(long, hide = true)]
    pub install_task: bool,

    /// Internal: remove the elevated logon task.
    #[arg(long, hide = true)]
    pub remove_task: bool,

    /// Draw a live stats overlay (capture/push fps, throughput, encode ms,
    /// dropped frames) in the bottom-right corner.
    #[arg(long)]
    pub debug: bool,

    /// Downscale the framebuffer before sending (0.25..1.0). 0.5 quarters
    /// the pixel count — the biggest lever for video/slow links.
    #[arg(long, default_value_t = 1.0)]
    pub scale: f32,

    /// Colour depth sent to viewers: 8 (3-3-2), 16 (5-6-5) or 24 (full).
    /// Lower values compress better and cut CPU/bandwidth.
    #[arg(long, default_value_t = 24, value_parser = clap::value_parser!(u8).range(8..=24))]
    pub color_level: u8,

    /// Session name shown by viewers
    #[arg(long, default_value = "restsend-vnc")]
    pub name: String,

    /// Serve a synthetic animated test pattern instead of the real screen
    /// (no permissions needed; useful for debugging viewers)
    #[arg(long)]
    pub test_pattern: bool,

    /// Enable TightVNC/UltraVNC-compatible file transfer, sandboxed to this
    /// directory (client needs the Tight security type; recommended viewers:
    /// TightVNC, UltraVNC)
    #[arg(long, value_name = "DIR")]
    pub share_dir: Option<PathBuf>,

    /// Encryption policy: auto (prefer TLS/VeNCrypt, fall back for old
    /// viewers), required (reject clients without VeNCrypt), or off.
    /// Defaults to the persisted setting (auto).
    #[arg(long, value_enum)]
    pub tls: Option<crate::tls::Mode>,

    /// TLS certificate chain in PEM format (with --tls-key). When omitted a
    /// self-signed certificate is generated in the settings directory.
    #[arg(long, value_name = "PEM")]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key in PEM format (with --tls-cert).
    #[arg(long, value_name = "PEM")]
    pub tls_key: Option<PathBuf>,

    /// Prevent Windows from sleeping while rvnc runs (disabled by default)
    #[arg(long)]
    pub keep_awake: bool,

    /// Disable clipboard sync in both directions
    #[arg(long)]
    pub no_clipboard: bool,

    /// Verbose logging (or set RUST_LOG)
    #[arg(short, long)]
    pub verbose: bool,
}

pub struct Config {
    /// Explicit --host (None => 0.0.0.0 unless the tray says loopback-only).
    pub host: Option<String>,
    pub port: u16,
    pub password: Option<String>,
    pub view_only: bool,
    pub display: usize,
    pub fps: u32,
    /// Requested colour level (8/16/24); 24 means no quantization.
    pub color_level: u8,
    /// Framebuffer downscale factor (0.25..=1.0).
    pub scale: f32,
    /// Show the debug stats overlay.
    pub debug: bool,
    /// ZRLE zlib level (1..=9).
    pub zrle_level: u32,
    pub name: String,
    pub test_pattern: bool,
    /// Explicit `--share-dir` override; when unset, the live tray setting is
    /// used for each connection.
    pub share_root: Option<Arc<ShareRoot>>,
    pub clipboard_enabled: bool,
    pub keep_awake: bool,
    /// CLI override for the persisted encryption policy.
    pub tls: Option<crate::tls::Mode>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

impl Config {
    /// Resolves the effective configuration, including the password fallback
    /// chain (flag -> env -> interactive prompt) and the share root.
    pub fn resolve(cli: Cli) -> Result<Config, String> {
        let password = if let Some(p) = cli.password {
            if p.is_empty() {
                return Err("--password is empty; pass a real password or use --no-auth".into());
            }
            if p.len() > 8 {
                tracing::warn!("VNC auth only uses the first 8 bytes of the password");
            }
            Some(p)
        } else if cli.no_auth {
            None
        } else if let Ok(p) = std::env::var("RESTSEND_VNC_PASSWORD") {
            if p.is_empty() {
                return Err(
                    "RESTSEND_VNC_PASSWORD is empty; set a real password or use --no-auth".into(),
                );
            }
            if p.len() > 8 {
                tracing::warn!("VNC auth only uses the first 8 bytes of the password");
            }
            Some(p)
        } else if let Some(p) = crate::settings::load().password {
            Some(p)
        } else if std::io::stdin().is_terminal() {
            Some(rpassword::prompt_password("Set VNC password (max 8 chars used): ")
                .map_err(|e| format!("failed to read password: {e}"))?)
        } else if cfg!(feature = "gui") {
            // GUI build has no terminal to prompt on; run without auth rather
            // than exiting silently (the tray/log will warn).
            tracing::warn!(
                "no password configured; GUI build runs WITHOUT authentication \
                 (set RESTSEND_VNC_PASSWORD or pass --password)"
            );
            None
        } else {
            return Err(
                "no password configured: pass --password, set RESTSEND_VNC_PASSWORD, or pass --no-auth"
                    .into(),
            );
        };

        if password.is_none() {
            tracing::warn!("running WITHOUT authentication; anyone who can reach the port can view and (unless --view-only) control this machine");
        }

        let share_root = match &cli.share_dir {
            Some(dir) => Some(Arc::new(
                ShareRoot::new(dir).map_err(|e| {
                    format!("--share-dir {} is not usable: {e}", dir.display())
                })?),
            ),
            None => None,
        };
        if cli.share_dir.is_none() {
            tracing::debug!(
                "no --share-dir: file transfer follows the tray setting (off by default)"
            );
        }

        if cli.tls_cert.is_some() != cli.tls_key.is_some() {
            return Err("--tls-cert and --tls-key must be provided together".into());
        }

        Ok(Config {
            host: cli.host,
            port: cli.port,
            password,
            view_only: cli.view_only,
            display: cli.display,
            fps: cli.fps,
            debug: cli.debug,
            zrle_level: cli.zrle_level,
            scale: if (0.25..=1.0).contains(&cli.scale) {
                cli.scale
            } else {
                return Err(format!("--scale must be between 0.25 and 1.0 (got {})", cli.scale));
            },
            color_level: match cli.color_level {
                8 | 16 | 24 => cli.color_level,
                other => return Err(format!("--color-level must be 8, 16 or 24 (got {other})")),
            },
            name: cli.name,
            test_pattern: cli.test_pattern,
            share_root,
            clipboard_enabled: !cli.no_clipboard,
            keep_awake: cli.keep_awake,
            tls: cli.tls,
            tls_cert: cli.tls_cert,
            tls_key: cli.tls_key,
        })
    }
}
