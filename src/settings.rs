//! Persisted tray settings + live global switches shared by the server,
//! the tray UI and the debug overlay.

use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::acl::Acl;
use crate::rfb::filetransfer::ShareRoot;
use crate::tls::Mode;

pub const DEFAULT_URL: &str = "https://restsend.com";

/// Default folder offered for file sharing: the current user's home directory.
pub fn default_share_dir() -> PathBuf {
    for var in ["USERPROFILE", "HOME"] {
        if let Some(p) = std::env::var_os(var) {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub port: u16,
    pub color_level: u8,
    pub loopback_only: bool,
    /// Ask the local user to accept every new connection before ServerInit.
    pub confirm_connections: bool,
    /// Optional CIDR allow-list for incoming peers (empty = allow all).
    pub allow_cidrs: String,
    pub keep_awake: bool,
    pub allow_debug: bool,
    pub url: String,
    pub password: Option<String>,
    pub title: String,
    pub autostart: bool,
    pub logon_task: bool,
    /// File transfer is opt-in; clients can only browse `share_dir`.
    pub share_files: bool,
    /// Sandbox root for uploads/downloads (defaults to the user's home).
    pub share_dir: PathBuf,
    /// Encryption policy: off / auto (prefer TLS) / required.
    pub tls: Mode,
    /// Optional user-provided certificate / key (PEM).
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            port: 5900,
            color_level: 16,
            loopback_only: false,
            confirm_connections: false,
            allow_cidrs: String::new(),
            keep_awake: true,
            allow_debug: true,
            url: DEFAULT_URL.to_string(),
            password: None,
            title: "restsend-vnc".to_string(),
            autostart: false,
            logon_task: false,
            share_files: false,
            share_dir: default_share_dir(),
            tls: Mode::Auto,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// Live values readable from any thread.
pub static PORT: AtomicU16 = AtomicU16::new(5900);
pub static COLOR_LEVEL: AtomicU8 = AtomicU8::new(16);
pub static LOOPBACK_ONLY: AtomicBool = AtomicBool::new(false);
/// Ask the local user to accept each new connection (live, applies at once).
pub static CONFIRM_CONNECTIONS: AtomicBool = AtomicBool::new(false);
/// CIDR allow-list for incoming peers (live, applies to new connections).
static ACL: OnceLock<Mutex<Arc<Acl>>> = OnceLock::new();
pub static KEEP_AWAKE: AtomicBool = AtomicBool::new(true);
pub static ALLOW_DEBUG: AtomicBool = AtomicBool::new(true);
/// Encryption policy (0 = off, 1 = auto/prefer TLS, 2 = required).
pub static TLS_MODE: AtomicU8 = AtomicU8::new(Mode::Auto as u8);
/// File transfer is off unless the user opts in via the tray settings.
pub static SHARE_FILES: AtomicBool = AtomicBool::new(false);
/// Incremented when the listener needs to rebind (port/loopback changed).
pub static RELOAD: AtomicUsize = AtomicUsize::new(0);
/// Set by the tray "Exit" item.
pub static EXIT: AtomicBool = AtomicBool::new(false);

static URL: OnceLock<Mutex<String>> = OnceLock::new();
static PASSWORD: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static TITLE: OnceLock<Mutex<String>> = OnceLock::new();
static SHARE_DIR: OnceLock<Mutex<PathBuf>> = OnceLock::new();
static TLS_CERT: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static TLS_KEY: OnceLock<Mutex<Option<String>>> = OnceLock::new();

pub fn tls_mode() -> Mode {
    Mode::from_u8(TLS_MODE.load(Ordering::Relaxed))
}

pub fn set_tls_mode(mode: Mode) {
    TLS_MODE.store(mode as u8, Ordering::Relaxed);
}

pub fn tls_cert() -> Option<String> {
    TLS_CERT
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .clone()
}

pub fn set_tls_cert(path: Option<String>) {
    *TLS_CERT.get_or_init(|| Mutex::new(None)).lock().unwrap() = path;
}

pub fn tls_key() -> Option<String> {
    TLS_KEY
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .clone()
}

pub fn set_tls_key(path: Option<String>) {
    *TLS_KEY.get_or_init(|| Mutex::new(None)).lock().unwrap() = path;
}

fn share_dir_cell() -> &'static Mutex<PathBuf> {
    SHARE_DIR.get_or_init(|| Mutex::new(default_share_dir()))
}

pub fn share_dir() -> PathBuf {
    share_dir_cell().lock().unwrap().clone()
}

pub fn set_share_dir(dir: &std::path::Path) {
    let dir = if dir.as_os_str().is_empty() {
        default_share_dir()
    } else {
        dir.to_path_buf()
    };
    *share_dir_cell().lock().unwrap() = dir;
}

pub fn share_files() -> bool {
    SHARE_FILES.load(Ordering::Relaxed)
}

/// True when each new connection must be accepted by the local user.
pub fn confirm_connections() -> bool {
    CONFIRM_CONNECTIONS.load(Ordering::Relaxed)
}

fn acl_cell() -> &'static Mutex<Arc<Acl>> {
    ACL.get_or_init(|| Mutex::new(Arc::new(Acl::default())))
}

/// Snapshot of the live allow-list. Cheap (Arc clone) and safe to keep for
/// the duration of one accept() decision.
pub fn acl() -> Arc<Acl> {
    acl_cell().lock().unwrap().clone()
}

/// True when `ip` may connect. Empty list = allow all; malformed list denies.
pub fn allows(ip: IpAddr) -> bool {
    acl().allows(ip)
}

/// Replaces the live allow-list and logs whether it is active.
pub fn set_allow_cidrs(raw: &str) {
    let acl = Acl::parse(raw);
    if !acl.invalid_entries().is_empty() {
        tracing::error!(
            "allow_cidrs contains invalid entries {:?}; all connections will be refused",
            acl.invalid_entries()
        );
    } else if acl.is_empty() {
        tracing::debug!("allow_cidrs is empty (all peers allowed)");
    } else {
        tracing::info!("allow_cidrs active: {}", acl.raw());
    }
    *acl_cell().lock().unwrap() = Arc::new(acl);
}

/// Raw allow-list as persisted (used by the tray Settings snapshot).
pub fn allow_cidrs_raw() -> String {
    acl().raw().to_string()
}

/// Resolves the live share root for new connections. `None` means the
/// TightVNC file-transfer extension stays disabled.
pub fn share_root() -> Option<Arc<ShareRoot>> {
    if !share_files() {
        return None;
    }
    let dir = share_dir();
    match ShareRoot::new(&dir) {
        Ok(root) => Some(Arc::new(root)),
        Err(e) => {
            tracing::warn!(
                "shared folder {} is not usable ({e}); file transfer is disabled",
                dir.display()
            );
            None
        }
    }
}

pub fn title() -> String {
    TITLE
        .get_or_init(|| Mutex::new("restsend-vnc".to_string()))
        .lock()
        .unwrap()
        .clone()
}

pub fn set_title(t: &str) {
    *TITLE
        .get_or_init(|| Mutex::new("restsend-vnc".to_string()))
        .lock()
        .unwrap() = if t.trim().is_empty() {
        "restsend-vnc".to_string()
    } else {
        t.to_string()
    };
}

fn password_cell() -> &'static Mutex<Option<String>> {
    PASSWORD.get_or_init(|| Mutex::new(None))
}

pub fn password() -> Option<String> {
    password_cell().lock().unwrap().clone()
}

pub fn set_password(p: Option<String>) {
    *password_cell().lock().unwrap() = p;
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn url() -> String {
    URL.get_or_init(|| Mutex::new(DEFAULT_URL.to_string()))
        .lock()
        .unwrap()
        .clone()
}

pub fn set_url(u: &str) {
    *URL.get_or_init(|| Mutex::new(DEFAULT_URL.to_string()))
        .lock()
        .unwrap() = u.to_string();
}

pub fn settings_path() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        PathBuf::from(appdata)
            .join("restsend-vnc")
            .join("settings.ini")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
            .join(".config")
            .join("restsend-vnc")
            .join("settings.ini")
    } else {
        PathBuf::from("restsend-vnc-settings.ini")
    }
}

pub fn load() -> Settings {
    let mut s = Settings::default();
    let Ok(text) = std::fs::read_to_string(settings_path()) else {
        return s;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "port" => {
                if let Ok(p) = v.parse() {
                    s.port = p;
                }
            }
            "color_level" => {
                if let Ok(c) = v.parse() {
                    s.color_level = c;
                }
            }
            "loopback_only" => s.loopback_only = v == "1" || v.eq_ignore_ascii_case("true"),
            "confirm_connections" => {
                s.confirm_connections = v == "1" || v.eq_ignore_ascii_case("true")
            }
            "allow_cidrs" => s.allow_cidrs = v.to_string(),
            "keep_awake" => s.keep_awake = v == "1" || v.eq_ignore_ascii_case("true"),
            "allow_debug" => s.allow_debug = v == "1" || v.eq_ignore_ascii_case("true"),
            "title" => s.title = v.to_string(),
            "autostart" => s.autostart = v == "1" || v.eq_ignore_ascii_case("true"),
            "logon_task" => s.logon_task = v == "1" || v.eq_ignore_ascii_case("true"),
            "share_files" => s.share_files = v == "1" || v.eq_ignore_ascii_case("true"),
            "share_dir" => {
                if !v.is_empty() {
                    s.share_dir = PathBuf::from(v);
                }
            }
            "tls" => {
                if let Some(mode) = Mode::parse(v) {
                    s.tls = mode;
                }
            }
            "tls_cert" => {
                s.tls_cert = if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                }
            }
            "tls_key" => {
                s.tls_key = if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                }
            }
            "password" => {
                s.password = if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                };
            }
            "url" if !v.is_empty() => {
                s.url = v.to_string();
            }
            _ => {}
        }
    }
    s
}

pub fn save(s: &Settings) {
    let path = settings_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let body = format!(
        "# rvnc settings\nport={}\ncolor_level={}\nloopback_only={}\nconfirm_connections={}\nallow_cidrs={}\nkeep_awake={}\nallow_debug={}\npassword={}\ntitle={}\nautostart={}\nlogon_task={}\nshare_files={}\nshare_dir={}\ntls={}\ntls_cert={}\ntls_key={}\nurl={}\n",
        s.port,
        s.color_level,
        s.loopback_only as u8,
        s.confirm_connections as u8,
        s.allow_cidrs,
        s.keep_awake as u8,
        s.allow_debug as u8,
        s.password.clone().unwrap_or_default(),
        s.title,
        s.autostart as u8,
        s.logon_task as u8,
        s.share_files as u8,
        s.share_dir.display(),
        s.tls,
        s.tls_cert.clone().unwrap_or_default(),
        s.tls_key.clone().unwrap_or_default(),
        s.url
    );
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = f.write_all(body.as_bytes());
    }
}

/// Publishes the values read by the running server / tray / overlay.
pub fn apply_live(s: &Settings) {
    COLOR_LEVEL.store(s.color_level, Ordering::Relaxed);
    let old_loop = LOOPBACK_ONLY.swap(s.loopback_only, Ordering::Relaxed);
    CONFIRM_CONNECTIONS.store(s.confirm_connections, Ordering::Relaxed);
    set_allow_cidrs(&s.allow_cidrs);
    KEEP_AWAKE.store(s.keep_awake, Ordering::Relaxed);
    ALLOW_DEBUG.store(s.allow_debug, Ordering::Relaxed);
    SHARE_FILES.store(s.share_files, Ordering::Relaxed);
    set_share_dir(&s.share_dir);
    set_tls_mode(s.tls);
    set_tls_cert(s.tls_cert.clone());
    set_tls_key(s.tls_key.clone());
    set_url(&s.url);
    set_password(s.password.clone());
    set_title(&s.title);
    let old_port = PORT.swap(s.port, Ordering::Relaxed);
    if old_port != s.port || old_loop != s.loopback_only {
        RELOAD.fetch_add(1, Ordering::Relaxed);
    }
}

static LOGON_TASK: AtomicBool = AtomicBool::new(false);
pub fn set_autostart_task(on: bool) {
    LOGON_TASK.store(on, Ordering::Relaxed);
}
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn logon_task_flag() -> bool {
    LOGON_TASK.load(Ordering::Relaxed)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn current() -> Settings {
    Settings {
        port: PORT.load(Ordering::Relaxed),
        color_level: COLOR_LEVEL.load(Ordering::Relaxed),
        loopback_only: LOOPBACK_ONLY.load(Ordering::Relaxed),
        confirm_connections: confirm_connections(),
        allow_cidrs: allow_cidrs_raw(),
        keep_awake: KEEP_AWAKE.load(Ordering::Relaxed),
        allow_debug: ALLOW_DEBUG.load(Ordering::Relaxed),
        url: url(),
        password: password(),
        title: title(),
        autostart: crate::autostart::enabled(),
        logon_task: logon_task_flag(),
        share_files: share_files(),
        share_dir: share_dir(),
        tls: tls_mode(),
        tls_cert: tls_cert(),
        tls_key: tls_key(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_sharing_is_opt_in() {
        let s = Settings::default();
        assert!(!s.share_files);
        assert!(!s.share_dir.as_os_str().is_empty());
    }
}
