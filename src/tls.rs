//! TLS support for the VeNCrypt security type (RFB type 19).
//!
//! Certificates are generated on first use (self-signed ECDSA P-256) and
//! persisted next to the settings file. `--tls-cert` / `--tls-key` (or the
//! matching settings.ini keys) override them with a real certificate.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};

/// Encryption policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[repr(u8)]
pub enum Mode {
    /// No TLS; legacy RFB security types only.
    Off = 0,
    /// Offer VeNCrypt (TLS) when the client supports it, fall back to legacy
    /// security types otherwise. This is the default.
    Auto = 1,
    /// Only accept TLS (VeNCrypt). Clients without VeNCrypt are rejected.
    Required = 2,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Auto => "auto",
            Mode::Required => "required",
        }
    }

    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "none" | "0" => Some(Mode::Off),
            "auto" | "prefer" | "1" => Some(Mode::Auto),
            "required" | "require" | "on" | "2" => Some(Mode::Required),
            _ => None,
        }
    }

    pub fn from_u8(v: u8) -> Mode {
        match v {
            2 => Mode::Required,
            0 => Mode::Off,
            _ => Mode::Auto,
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cached server configuration; built lazily so a tray change from off to
/// auto/required starts working without a restart.
static CONFIG: Mutex<Option<Arc<ServerConfig>>> = Mutex::new(None);
/// Serializes first-time certificate generation (several clients may connect
/// at once right after TLS is enabled from the tray).
static BUILD_LOCK: Mutex<()> = Mutex::new(());
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// Directory holding the auto-generated certificate.
pub fn default_dir() -> PathBuf {
    crate::settings::settings_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tls")
}

fn configured_paths() -> (PathBuf, PathBuf) {
    let cert = crate::settings::tls_cert().filter(|s| !s.trim().is_empty());
    let key = crate::settings::tls_key().filter(|s| !s.trim().is_empty());
    match (cert, key) {
        (Some(c), Some(k)) => (PathBuf::from(c), PathBuf::from(k)),
        (Some(_), None) | (None, Some(_)) => {
            tracing::warn!(
                "TLS: both --tls-cert and --tls-key are required; using the generated certificate"
            );
            default_paths()
        }
        (None, None) => default_paths(),
    }
}

fn default_paths() -> (PathBuf, PathBuf) {
    let dir = default_dir();
    (dir.join("server.crt"), dir.join("server.key"))
}

/// Returns the rustls server config, generating/loading the certificate on
/// first use. `None` means TLS is unavailable (a warning is logged once per
/// distinct error).
pub fn server_config() -> Option<Arc<ServerConfig>> {
    if let Some(cfg) = CONFIG.lock().unwrap().clone() {
        return Some(cfg);
    }
    let _build = BUILD_LOCK.lock().unwrap();
    // Another thread may have finished the build while we waited.
    if let Some(cfg) = CONFIG.lock().unwrap().clone() {
        return Some(cfg);
    }
    match build() {
        Ok((cfg, cert_path, fingerprint)) => {
            *LAST_ERROR.lock().unwrap() = None;
            tracing::warn!(
                "TLS enabled: certificate SHA-256 fingerprint {} ({})",
                fingerprint,
                cert_path.display()
            );
            let cfg = Arc::new(cfg);
            *CONFIG.lock().unwrap() = Some(Arc::clone(&cfg));
            Some(cfg)
        }
        Err(e) => {
            let mut last = LAST_ERROR.lock().unwrap();
            if last.as_deref() != Some(e.as_str()) {
                tracing::warn!("TLS unavailable: {e}");
                *last = Some(e);
            }
            None
        }
    }
}

/// Fingerprint of the configured certificate (for the tray/log), if available.
#[allow(dead_code)]
pub fn fingerprint() -> Option<String> {
    let (cert, _) = configured_paths();
    let certs = load_certs(&cert).ok()?;
    Some(fingerprint_of(certs.last()?))
}

fn build() -> Result<(ServerConfig, PathBuf, String), String> {
    install_crypto_provider();
    let (cert_path, key_path) = configured_paths();
    ensure_cert(&cert_path, &key_path)?;
    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;
    let fingerprint = fingerprint_of(
        certs
            .last()
            .ok_or_else(|| format!("{} contains no certificate", cert_path.display()))?,
    );
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            format!(
                "invalid certificate/key pair: {e} \
                 (use a PKCS#8 RSA/ECDSA key with a named curve; \
                 LibreSSL explicit-parameter EC keys are not supported)"
            )
        })?;
    Ok((cfg, cert_path, fingerprint))
}

fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // If another provider was already installed this fails harmlessly;
        // rustls uses whichever provider is the process default.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("cannot read certificate {}: {e}", path.display()))?;
    rustls_pemfile::certs(&mut &data[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse certificate {}: {e}", path.display()))
}

fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("cannot read private key {}: {e}", path.display()))?;
    rustls_pemfile::private_key(&mut &data[..])
        .map_err(|e| format!("cannot parse private key {}: {e}", path.display()))?
        .ok_or_else(|| format!("{} contains no private key", path.display()))
}

fn fingerprint_of(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn ensure_cert(cert: &Path, key: &Path) -> Result<(), String> {
    if cert.is_file() && key.is_file() {
        return Ok(());
    }
    if cert.exists() != key.exists() {
        return Err(format!(
            "only one of {} / {} exists; remove both to regenerate",
            cert.display(),
            key.display()
        ));
    }
    for path in [cert, key] {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
    }
    let (cert_pem, key_pem) = generate_self_signed()?;
    std::fs::write(cert, cert_pem).map_err(|e| format!("cannot write {}: {e}", cert.display()))?;
    std::fs::write(key, key_pem).map_err(|e| format!("cannot write {}: {e}", key.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(
        "TLS: generated a self-signed certificate at {} (verify its SHA-256 fingerprint on the client)",
        cert.display()
    );
    Ok(())
}

fn generate_self_signed() -> Result<(String, String), String> {
    use rcgen::{CertificateParams, DnType, KeyPair};

    let hostname = hostname();
    let mut names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(h) = &hostname {
        names.push(h.clone());
    }
    if let Some(ip) = local_ip() {
        names.push(ip.to_string());
    }
    names.sort();
    names.dedup();

    let mut params = CertificateParams::new(names)
        .map_err(|e| format!("invalid certificate subject names: {e}"))?;
    params.distinguished_name.push(
        DnType::CommonName,
        hostname.unwrap_or_else(|| "restsend-vnc".into()),
    );
    params
        .distinguished_name
        .push(DnType::OrganizationName, "restsend-vnc");
    // Self-signed certificates are commonly rejected if they claim to live
    // forever; 10 years is plenty for a LAN screen-sharing server.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd((1970 + now / 31_556_952 + 10) as i32, 1, 1);

    let key_pair = KeyPair::generate().map_err(|e| format!("key generation failed: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("certificate generation failed: {e}"))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        })
}

/// Best-effort local IPv4 address (no packets are sent by `connect` on UDP).
fn local_ip() -> Option<IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parsing_and_display() {
        assert_eq!(Mode::parse("off"), Some(Mode::Off));
        assert_eq!(Mode::parse("AUTO"), Some(Mode::Auto));
        assert_eq!(Mode::parse("required"), Some(Mode::Required));
        assert_eq!(Mode::parse("require"), Some(Mode::Required));
        assert_eq!(Mode::parse("bogus"), None);
        assert_eq!(Mode::from_u8(2), Mode::Required);
        assert_eq!(Mode::Required.to_string(), "required");
    }

    #[test]
    fn generated_certificate_is_usable_by_rustls() {
        install_crypto_provider();
        let dir = std::env::temp_dir().join(format!(
            "restsend-vnc-tls-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cert = dir.join("server.crt");
        let key = dir.join("server.key");
        ensure_cert(&cert, &key).unwrap();
        assert!(cert.is_file() && key.is_file());

        let certs = load_certs(&cert).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(fingerprint_of(&certs[0]).split(':').count(), 32);
        let private_key = load_key(&key).unwrap();
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .expect("generated certificate must be accepted by rustls");

        // Existing files are reused, not regenerated.
        let before = std::fs::read(&cert).unwrap();
        ensure_cert(&cert, &key_path(&cert)).unwrap();
        assert_eq!(before, std::fs::read(&cert).unwrap());

        let _ = std::fs::remove_dir_all(dir);
    }

    fn key_path(cert: &Path) -> PathBuf {
        cert.with_file_name("server.key")
    }
}
