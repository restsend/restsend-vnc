//! Persisted tray settings + live global switches shared by the server,
//! the tray UI and the debug overlay.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

pub const DEFAULT_URL: &str = "https://restsend.com";

#[derive(Debug, Clone)]
pub struct Settings {
    pub port: u16,
    pub color_level: u8,
    pub loopback_only: bool,
    pub keep_awake: bool,
    pub allow_debug: bool,
    pub url: String,
    pub password: Option<String>,
    pub title: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            port: 5900,
            color_level: 16,
            loopback_only: false,
            keep_awake: true,
            allow_debug: true,
            url: DEFAULT_URL.to_string(),
            password: None,
            title: "restsend-vnc".to_string(),
        }
    }
}

/// Live values readable from any thread.
pub static PORT: AtomicU16 = AtomicU16::new(5900);
pub static COLOR_LEVEL: AtomicU8 = AtomicU8::new(16);
pub static LOOPBACK_ONLY: AtomicBool = AtomicBool::new(false);
pub static KEEP_AWAKE: AtomicBool = AtomicBool::new(true);
pub static ALLOW_DEBUG: AtomicBool = AtomicBool::new(true);
/// Incremented when the listener needs to rebind (port/loopback changed).
pub static RELOAD: AtomicUsize = AtomicUsize::new(0);
/// Set by the tray "Exit" item.
pub static EXIT: AtomicBool = AtomicBool::new(false);

static URL: OnceLock<Mutex<String>> = OnceLock::new();
static PASSWORD: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static TITLE: OnceLock<Mutex<String>> = OnceLock::new();

pub fn title() -> String {
    TITLE
        .get_or_init(|| Mutex::new("restsend-vnc".to_string()))
        .lock()
        .unwrap()
        .clone()
}

pub fn set_title(t: &str) {
    *TITLE.get_or_init(|| Mutex::new("restsend-vnc".to_string())).lock().unwrap() =
        if t.trim().is_empty() { "restsend-vnc".to_string() } else { t.to_string() };
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
        PathBuf::from(appdata).join("restsend-vnc").join("settings.ini")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config").join("restsend-vnc").join("settings.ini")
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
            "keep_awake" => s.keep_awake = v == "1" || v.eq_ignore_ascii_case("true"),
            "allow_debug" => s.allow_debug = v == "1" || v.eq_ignore_ascii_case("true"),
            "title" => s.title = v.to_string(),
            "password" => {
                s.password = if v.is_empty() { None } else { Some(v.to_string()) };
            }
            "url" => {
                if !v.is_empty() {
                    s.url = v.to_string();
                }
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
        "# rvnc settings\nport={}\ncolor_level={}\nloopback_only={}\nkeep_awake={}\nallow_debug={}\npassword={}\ntitle={}\nurl={}\n",
        s.port,
        s.color_level,
        s.loopback_only as u8,
        s.keep_awake as u8,
        s.allow_debug as u8,
        s.password.clone().unwrap_or_default(),
        s.title,
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
    KEEP_AWAKE.store(s.keep_awake, Ordering::Relaxed);
    ALLOW_DEBUG.store(s.allow_debug, Ordering::Relaxed);
    set_url(&s.url);
    set_password(s.password.clone());
    set_title(&s.title);
    let old_port = PORT.swap(s.port, Ordering::Relaxed);
    if old_port != s.port || old_loop != s.loopback_only {
        RELOAD.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn current() -> Settings {
    Settings {
        port: PORT.load(Ordering::Relaxed),
        color_level: COLOR_LEVEL.load(Ordering::Relaxed),
        loopback_only: LOOPBACK_ONLY.load(Ordering::Relaxed),
        keep_awake: KEEP_AWAKE.load(Ordering::Relaxed),
        allow_debug: ALLOW_DEBUG.load(Ordering::Relaxed),
        url: url(),
        password: password(),
        title: title(),
    }
}
