//! RFB handshake: version exchange, security negotiation (None / VNC auth /
//! Tight with capability exchange / VeNCrypt TLS) and ClientInit.

use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::rfb::security;
use crate::rfb::vencrypt;
use crate::tls;

/// Apple's own servers announce this version, which makes Apple's Screen
/// Sharing client use its native protocol path: Apple DH auth (type 30,
/// password dialog that actually works on modern macOS) and then standard
/// RFB messages (session-start, encodings, pixel format) with server-push
/// updates. Non-Apple viewers downgrade 889 → 003.008/003.007/003.003
/// safely (standard clients have handled 889 servers for decades — every
/// macOS machine with Screen Sharing announces it).
pub const PROTOCOL_STRING: &[u8; 12] = b"RFB 003.889\n";

pub const SEC_NONE: u8 = 1;
pub const SEC_VNC_AUTH: u8 = 2;
pub const SEC_TIGHT: u8 = 16;
pub const SEC_APPLE_DH: u8 = 30;

const STDV_VENDOR: &[u8; 4] = b"STDV";
const NAME_VNC_AUTH: &[u8; 8] = b"VNCAUTH_";

/// Auth methods, for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    None,
    VncAuth,
    AppleDh,
    VeNCryptTlsNone,
    VeNCryptTlsVnc,
}

impl AuthMethod {
    /// Short label used by the audit log / debug overlay.
    pub fn label(self) -> &'static str {
        match self {
            AuthMethod::None => "NONE",
            AuthMethod::VncAuth => "VNC-AUTH",
            AuthMethod::AppleDh => "APPLE-DH",
            AuthMethod::VeNCryptTlsNone => "TLS-NONE",
            AuthMethod::VeNCryptTlsVnc => "TLS-VNC",
        }
    }

    /// True when the RFB transport itself is encrypted (VeNCrypt TLS).
    pub fn encrypted(self) -> bool {
        matches!(
            self,
            AuthMethod::VeNCryptTlsNone | AuthMethod::VeNCryptTlsVnc
        )
    }
}

pub struct HandshakeResult {
    /// Protocol minor version the client chose (3, 7 or 8).
    pub minor: u16,
    /// The security type the client picked (1 = None, 2 = VNC auth, 16 = Tight,
    /// 19 = VeNCrypt).
    pub security_type: u8,
    /// True when the Tight security type was negotiated; the server must send
    /// interaction capabilities right after ServerInit to enable extensions
    /// such as file transfer.
    pub tight: bool,
    pub auth: AuthMethod,
    /// AES-128 session key derived from the Apple DH exchange (type 30 only);
    /// used to decrypt Apple client clipboard pushes.
    pub apple_key: Option<[u8; 16]>,
    /// Raw ClientInit byte. Apple 3.889 clients set the high bit (0x80) to
    /// request the extended ARD ServerInit.
    pub client_init: u8,
    /// True when every subsequent byte travels through rustls TLS.
    pub encrypted: bool,
    /// TLS connection to hand over to the session I/O pump (VeNCrypt only).
    pub tls: Option<rustls::ServerConnection>,
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
}

type HsResult<T> = Result<T, HandshakeError>;

/// Reads the client's version string, e.g. `RFB 003.008\n`.
fn parse_version(buf: &[u8; 12]) -> HsResult<(u16, u16)> {
    if &buf[0..4] != b"RFB " || buf[11] != b'\n' {
        return Err(HandshakeError::Protocol(format!(
            "malformed version string: {:?}",
            String::from_utf8_lossy(buf)
        )));
    }
    let major = std::str::from_utf8(&buf[4..7])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let minor = std::str::from_utf8(&buf[8..11])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if major != 3 {
        return Err(HandshakeError::Protocol(format!(
            "unsupported RFB major version: {major}"
        )));
    }
    Ok((3, minor))
}

fn write_cap(out: &mut Vec<u8>, code: u32, vendor: &[u8; 4], name: &[u8; 8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(vendor);
    out.extend_from_slice(name);
}

/// Annotates an i/o error with the handshake stage it happened in, so logs
/// show exactly where a client gave up.
fn stage_err(stage: &str, e: HandshakeError) -> HandshakeError {
    match &e {
        HandshakeError::Io(io_err) if io_err.kind() == io::ErrorKind::UnexpectedEof => {
            HandshakeError::Protocol(format!("client disconnected during {stage}"))
        }
        _ => e,
    }
}

/// VNC-auth challenge/response over the wire.
fn vnc_auth_exchange<S: Read + Write>(
    stream: &mut S,
    password: &str,
    send_result_on_failure: bool,
) -> HsResult<()> {
    let challenge = security::random_challenge();
    stream.write_all(&challenge)?;
    stream.flush()?;
    let mut response = [0u8; 16];
    stream
        .read_exact(&mut response)
        .map_err(|e| stage_err("VNC auth challenge/response", e.into()))?;
    if !security::verify_response(password, &challenge, &response) {
        // RFB 3.8 requires a SecurityResult(1) + reason before closing.
        if send_result_on_failure {
            let reason = "VNC authentication failed: wrong password";
            let _ = stream.write_all(&1u32.to_be_bytes());
            let _ = stream.write_all(&(reason.len() as u32).to_be_bytes());
            let _ = stream.write_all(reason.as_bytes());
            let _ = stream.flush();
        }
        return Err(HandshakeError::Protocol(
            "VNC authentication failed: wrong password".into(),
        ));
    }
    Ok(())
}

/// Apple Remote Desktop authentication (security type 30): the scheme the
/// macOS built-in Screen Sharing client uses instead of legacy VNC auth.
fn apple_dh_exchange<S: Read + Write>(
    stream: &mut S,
    password: Option<&str>,
    send_result_on_failure: bool,
) -> HsResult<[u8; 16]> {
    use crate::rfb::apple_auth;

    let (server_public, secret) = apple_auth::generate_server_keys()
        .map_err(|e| HandshakeError::Protocol(format!("DH keygen failed: {e}")))?;
    stream
        .write_all(&apple_auth::server_message(&server_public))
        .map_err(|e| stage_err("Apple DH server message", e.into()))?;
    stream.flush()?;

    // Client replies: encrypted_credentials[128] ++ public_key[256].
    let mut response = [0u8; 128 + 256];
    stream
        .read_exact(&mut response)
        .map_err(|e| stage_err("Apple DH credentials", e.into()))?;
    let (encrypted, client_public) = response.split_at(128);

    match apple_auth::verify_client_response(
        password,
        &secret,
        encrypted.try_into().unwrap(),
        client_public.try_into().unwrap(),
    ) {
        Ok(username) => {
            stream.write_all(&0u32.to_be_bytes())?;
            stream.flush()?;
            let session_key = apple_auth::session_key(&secret, client_public.try_into().unwrap());
            tracing::info!(
                "Apple DH auth: user \"{username}\" authenticated (session key {})",
                hex::encode(session_key)
            );
            Ok(session_key)
        }
        Err(reason) => {
            if send_result_on_failure {
                let _ = stream.write_all(&1u32.to_be_bytes());
                let _ = stream.write_all(&(reason.len() as u32).to_be_bytes());
                let _ = stream.write_all(reason.as_bytes());
                let _ = stream.flush();
            }
            Err(HandshakeError::Protocol(format!(
                "Apple DH authentication failed: {reason}"
            )))
        }
    }
}

/// Runs the full handshake up to and including ClientInit.
///
/// `stream` is a single duplex stream so the connection can be upgraded to
/// TLS mid-handshake. For VeNCrypt the returned `HandshakeResult::tls`
/// contains the established rustls connection; all bytes after ClientInit
/// must go through it.
pub fn perform<S: Read + Write>(
    stream: &mut S,
    password: Option<&str>,
    allow_tight: bool,
    tls_mode: tls::Mode,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> HsResult<HandshakeResult> {
    // Experiment: announce 3.3 / 3.8 to see if Screen Sharing.app accepts a
    // standard RFB session (which would give us the standard clipboard).
    let version: &[u8; 12] = match std::env::var("RESTSEND_VNC_RFB_VER").as_deref() {
        Ok("33") => b"RFB 003.003\n",
        Ok("37") => b"RFB 003.007\n",
        Ok("38") => b"RFB 003.008\n",
        _ => PROTOCOL_STRING,
    };
    stream.write_all(version)?;
    stream.flush()?;

    let mut version = [0u8; 12];
    stream
        .read_exact(&mut version)
        .map_err(|e| stage_err("version exchange", e.into()))?;
    let (_major, minor) = parse_version(&version)?;
    // Apple's Screen Sharing client announces itself with a non-standard
    // minor version (003.889) and cannot complete legacy VNC auth (type 2) —
    // when we detect it, only offer the Apple DH scheme.
    let apple_client = minor == 889;
    tracing::debug!(
        "handshake: client version {}{}",
        String::from_utf8_lossy(&version).trim(),
        if apple_client { " (Apple client)" } else { "" }
    );
    let legacy = minor <= 3; // 3.3: server picks the security type unilaterally
    let has_result = minor >= 8 && !legacy;

    // VeNCrypt needs the RFB 3.7+ security-type list and (for the
    // SecurityResult inside TLS) a 3.8 handshake. Apple clients never speak
    // it; keep their dedicated type-30 path unchanged.
    let tls_available =
        tls_config.is_some() && tls_mode != tls::Mode::Off && has_result && !apple_client;

    // Build the offer. VeNCrypt is listed first so clients that honour the
    // server's order pick encryption.
    let mut offered: Vec<u8> = Vec::new();
    if tls_available {
        offered.push(vencrypt::SEC_VENCRYPT);
    }
    if apple_client {
        if tls_mode == tls::Mode::Required {
            // macOS Screen Sharing does not implement VeNCrypt; refusing is
            // the only honest behaviour in required mode.
        } else if password.is_none() && std::env::var_os("RESTSEND_VNC_APPLE_NONE").is_some() {
            // No password: try the standard no-auth type first (no login
            // prompt). With a password, Apple DH is required (the client
            // aborts type 2).
            offered.push(SEC_NONE);
        } else {
            offered.push(SEC_APPLE_DH);
        }
    } else if tls_mode == tls::Mode::Required {
        // Strictly VeNCrypt: no plaintext fallback.
    } else if password.is_some() {
        // Apple DH (30) is Apple-only: standard viewers such as TigerVNC
        // also implement type 30 and would pick it over plain VNC auth,
        // then fail the Apple-specific credential exchange.
        offered.push(SEC_VNC_AUTH);
    } else {
        offered.push(SEC_NONE);
    }
    if allow_tight && !apple_client && tls_mode != tls::Mode::Required {
        offered.push(SEC_TIGHT);
    }

    let chosen = if legacy {
        if tls_mode == tls::Mode::Required {
            // RFB 3.3 cannot express a security-type list; refuse safely.
            stream.write_all(&0u32.to_be_bytes())?;
            stream.flush()?;
            return Err(HandshakeError::Protocol(
                "TLS is required but the client speaks RFB 3.3".into(),
            ));
        }
        let pick = if password.is_some() {
            SEC_VNC_AUTH
        } else {
            SEC_NONE
        };
        stream.write_all(&(pick as u32).to_be_bytes())?;
        stream.flush()?;
        pick
    } else {
        if offered.is_empty() {
            let reason = if tls_mode == tls::Mode::Required {
                "TLS is required but this client does not support VeNCrypt"
            } else {
                "no supported security types"
            };
            stream.write_all(&[0u8])?;
            stream.write_all(&(reason.len() as u32).to_be_bytes())?;
            stream.write_all(reason.as_bytes())?;
            stream.flush()?;
            return Err(HandshakeError::Protocol(reason.into()));
        }
        stream.write_all(&[offered.len() as u8])?;
        stream.write_all(&offered)?;
        stream.flush()?;
        let mut pick = [0u8; 1];
        stream
            .read_exact(&mut pick)
            .map_err(|e| stage_err("security type choice", e.into()))?;
        let pick = pick[0];
        tracing::debug!("handshake: offered {:?}, client picked {}", offered, pick);
        if !offered.contains(&pick) {
            return Err(HandshakeError::Protocol(format!(
                "client picked unsupported security type {pick}"
            )));
        }
        pick
    };

    let mut apple_key: Option<[u8; 16]> = None;
    let (tight, auth) = match chosen {
        vencrypt::SEC_VENCRYPT => {
            let config = tls_config.ok_or_else(|| {
                HandshakeError::Protocol("client picked VeNCrypt but TLS is unavailable".into())
            })?;
            let subtype = vencrypt::negotiate(stream, password.is_some())
                .map_err(|e| stage_err("VeNCrypt negotiation", e.into()))?;
            let mut tls_stream = vencrypt::start_tls(stream, config)
                .map_err(|e| stage_err("TLS handshake", e.into()))?;
            match subtype {
                vencrypt::SUBTYPE_X509VNC => {
                    let pw = password.ok_or_else(|| {
                        HandshakeError::Protocol(
                            "client chose X509Vnc with no password configured".into(),
                        )
                    })?;
                    vnc_auth_exchange(&mut tls_stream, pw, true)?;
                }
                vencrypt::SUBTYPE_X509NONE => {}
                other => {
                    return Err(HandshakeError::Protocol(format!(
                        "unsupported VeNCrypt sub-type {other}"
                    )))
                }
            }
            // VeNCrypt's inner security phase always ends with a
            // SecurityResult, regardless of the RFB version.
            tls_stream.write_all(&0u32.to_be_bytes())?;
            tls_stream.flush()?;

            let mut shared = [0u8; 1];
            tls_stream
                .read_exact(&mut shared)
                .map_err(|e| stage_err("ClientInit", e.into()))?;
            let rustls::StreamOwned { conn, .. } = tls_stream;
            tracing::debug!("handshake: complete (TLS encrypted)");
            return Ok(HandshakeResult {
                minor,
                security_type: vencrypt::SEC_VENCRYPT,
                tight: false,
                auth: if subtype == vencrypt::SUBTYPE_X509VNC {
                    AuthMethod::VeNCryptTlsVnc
                } else {
                    AuthMethod::VeNCryptTlsNone
                },
                apple_key: None,
                client_init: shared[0],
                encrypted: true,
                tls: Some(conn),
            });
        }
        SEC_TIGHT => {
            // 1) tunneling caps: none.
            stream.write_all(&0u32.to_be_bytes())?;
            stream.flush()?;
            // 2) auth caps. Empty list = no auth needed, client sends nothing.
            match password {
                Some(pw) => {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&1u32.to_be_bytes());
                    write_cap(&mut buf, SEC_VNC_AUTH as u32, STDV_VENDOR, NAME_VNC_AUTH);
                    stream.write_all(&buf)?;
                    stream.flush()?;
                    let mut code = [0u8; 4];
                    stream
                        .read_exact(&mut code)
                        .map_err(|e| stage_err("Tight auth scheme choice", e.into()))?;
                    if u32::from_be_bytes(code) != SEC_VNC_AUTH as u32 {
                        return Err(HandshakeError::Protocol(format!(
                            "client picked unsupported Tight auth scheme {}",
                            u32::from_be_bytes(code)
                        )));
                    }
                    // The Tight flow has no SecurityResult message.
                    vnc_auth_exchange(stream, pw, false)?;
                    (true, AuthMethod::VncAuth)
                }
                None => {
                    stream.write_all(&0u32.to_be_bytes())?;
                    stream.flush()?;
                    (true, AuthMethod::None)
                }
            }
        }
        SEC_APPLE_DH => {
            // Apple clients get type 30 even without a configured password;
            // in that case whatever they type is accepted.
            apple_key = Some(apple_dh_exchange(stream, password, has_result)?);
            (false, AuthMethod::AppleDh)
        }
        SEC_VNC_AUTH => {
            let pw = password.ok_or_else(|| {
                HandshakeError::Protocol("client chose VNC auth with no password configured".into())
            })?;
            vnc_auth_exchange(stream, pw, has_result)?;
            (false, AuthMethod::VncAuth)
        }
        _ => (false, AuthMethod::None),
    };

    // RFB 3.8 sends a SecurityResult after the security handshake (including
    // for None). The Tight flow and the Apple DH flow already wrote their own
    // result, and 3.3/3.7 have none at all.
    if has_result && !tight && auth != AuthMethod::AppleDh {
        stream.write_all(&0u32.to_be_bytes())?;
        stream.flush()?;
    }

    // ClientInit
    let mut shared = [0u8; 1];
    stream
        .read_exact(&mut shared)
        .map_err(|e| stage_err("ClientInit", e.into()))?;

    tracing::debug!("handshake: complete");
    Ok(HandshakeResult {
        minor,
        security_type: chosen,
        tight,
        auth,
        apple_key,
        client_init: shared[0],
        encrypted: auth.encrypted(),
        tls: None,
    })
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version(b"RFB 003.008\n").unwrap(), (3, 8));
        assert_eq!(parse_version(b"RFB 003.003\n").unwrap(), (3, 3));
        assert_eq!(parse_version(b"RFB 003.007\n").unwrap(), (3, 7));
        assert!(parse_version(b"HTTP/1.1 200").is_err());
    }

    #[test]
    fn handshake_38_tight_none() {
        let (mut server, mut client) = duplex_pair();
        let cli = std::thread::spawn(move || {
            let (mut client, mut client_w) = client.split();
            let mut expect = [0u8; 12];
            client.read_exact(&mut expect).unwrap();
            client_w.write_all(b"RFB 003.008\n").unwrap();
            let mut hdr = [0u8; 1];
            client.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[0], 2); // two security types
            let mut types = [0u8; 2];
            client.read_exact(&mut types).unwrap();
            assert_eq!(types, [SEC_NONE, SEC_TIGHT]);
            client_w.write_all(&[SEC_TIGHT]).unwrap();
            let mut u32buf = [0u8; 4];
            client.read_exact(&mut u32buf).unwrap(); // tunnel caps = 0
            assert_eq!(u32buf, [0; 4]);
            client.read_exact(&mut u32buf).unwrap(); // auth caps = empty
            assert_eq!(u32buf, [0; 4]);
            client_w.write_all(&[0x01]).unwrap(); // ClientInit
        });
        let res = perform(&mut server, None, true, tls::Mode::Off, None).unwrap();
        assert!(res.tight);
        assert_eq!(res.auth, AuthMethod::None);
        assert!(!res.encrypted);
        cli.join().unwrap();
    }

    #[test]
    fn handshake_38_vnc_auth_wrong_password() {
        let (mut server, mut client) = duplex_pair();
        let cli = std::thread::spawn(move || {
            let (mut client, mut client_w) = client.split();
            let mut buf = [0u8; 12];
            client.read_exact(&mut buf).unwrap();
            client_w.write_all(b"RFB 003.008\n").unwrap();
            let mut one = [0u8; 1];
            client.read_exact(&mut one).unwrap();
            // Non-Apple client: only VNC auth is offered.
            assert_eq!(one[0], 1);
            let mut types = [0u8; 1];
            client.read_exact(&mut types).unwrap();
            assert_eq!(types, [SEC_VNC_AUTH]);
            client_w.write_all(&[SEC_VNC_AUTH]).unwrap();
            let mut ch = [0u8; 16];
            client.read_exact(&mut ch).unwrap();
            let mut resp = ch;
            security::des_encrypt(&security::vnc_key("WRONG"), &mut resp);
            client_w.write_all(&resp).unwrap();
            // 3.8 failure: SecurityResult(1) + reason string
            let mut res = [0u8; 4];
            client.read_exact(&mut res).unwrap();
            assert_eq!(res, [0, 0, 0, 1]);
            let mut len = [0u8; 4];
            client.read_exact(&mut len).unwrap();
            let n = u32::from_be_bytes(len) as usize;
            let mut reason = vec![0u8; n];
            client.read_exact(&mut reason).unwrap();
        });
        let err = match perform(&mut server, Some("rightpw"), false, tls::Mode::Off, None) {
            Ok(_) => panic!("expected authentication failure"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("authentication failed"));
        cli.join().unwrap();
    }

    #[test]
    fn handshake_38_vnc_auth_ok() {
        let (mut server, mut client) = duplex_pair();
        let pw = "secret";
        let cli = std::thread::spawn(move || {
            let (mut client, mut client_w) = client.split();
            let mut buf = [0u8; 12];
            client.read_exact(&mut buf).unwrap();
            client_w.write_all(b"RFB 003.008\n").unwrap();
            let mut one = [0u8; 1];
            client.read_exact(&mut one).unwrap();
            // A standard (non-Apple) client is only offered VNC auth: Apple
            // DH (type 30) is reserved for RFB 003.889 clients.
            assert_eq!(one, [1]);
            let mut types = [0u8; 1];
            client.read_exact(&mut types).unwrap();
            assert_eq!(types, [SEC_VNC_AUTH]);
            client_w.write_all(&[SEC_VNC_AUTH]).unwrap();
            let mut ch = [0u8; 16];
            client.read_exact(&mut ch).unwrap();
            let mut resp = ch;
            security::des_encrypt(&security::vnc_key(pw), &mut resp);
            client_w.write_all(&resp).unwrap();
            let mut res = [0u8; 4];
            client.read_exact(&mut res).unwrap();
            assert_eq!(res, [0, 0, 0, 0]);
            client_w.write_all(&[0x01]).unwrap();
        });
        let res = perform(&mut server, Some(pw), false, tls::Mode::Off, None).unwrap();
        assert_eq!(res.auth, AuthMethod::VncAuth);
        assert!(!res.tight);
        cli.join().unwrap();
    }

    #[test]
    fn handshake_38_apple_dh_ok() {
        use cipher::{generic_array::GenericArray, KeyInit};
        use md5::{Digest, Md5};
        use num_bigint::BigUint;

        let (mut server, mut client) = duplex_pair();
        let pw = "secret".to_string();
        let pw_server = pw.clone();
        let cli = std::thread::spawn(move || {
            let (mut client, mut client_w) = client.split();
            let mut buf = [0u8; 12];
            client.read_exact(&mut buf).unwrap();
            // Apple clients announce themselves with a non-standard version
            client_w.write_all(b"RFB 003.889\n").unwrap();
            let mut one = [0u8; 1];
            client.read_exact(&mut one).unwrap();
            assert_eq!(one[0], 1); // Apple clients only get the Apple DH scheme
            let mut types = [0u8; 1];
            client.read_exact(&mut types).unwrap();
            assert_eq!(types, [SEC_APPLE_DH]);
            client_w.write_all(&[SEC_APPLE_DH]).unwrap();

            // server -> client: generator, key size, prime, server public key
            let mut msg = [0u8; 4 + 256 + 256];
            client.read_exact(&mut msg).unwrap();
            let g = u16::from_be_bytes([msg[0], msg[1]]) as u32;
            let key_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
            assert_eq!((g, key_len), (2, 256));
            let prime = BigUint::from_bytes_be(&msg[4..4 + key_len]);
            let server_pub = BigUint::from_bytes_be(&msg[4 + key_len..]);

            // client side: own secret, shared key, encrypt credentials
            let mut secret_bytes = [0u8; 256];
            getrandom::fill(&mut secret_bytes).unwrap();
            let secret = BigUint::from_bytes_be(&secret_bytes);
            let client_pub = BigUint::from(g).modpow(&secret, &prime);
            let shared = server_pub.modpow(&secret, &prime);
            let key = Md5::digest(shared.to_bytes_be());
            let cipher = aes::Aes128::new(GenericArray::from_slice(&key));

            let mut creds = vec![0u8; 128];
            creds[..3].copy_from_slice(b"mac");
            creds[64..64 + pw.len()].copy_from_slice(pw.as_bytes());
            for block in creds.as_chunks_mut::<16>().0 {
                use cipher::BlockEncrypt;
                cipher.encrypt_block(block.into());
            }

            // wire order: encrypted credentials, then public key (256B BE)
            let mut pubkey = client_pub.to_bytes_be();
            let mut out = vec![0u8; 256 - pubkey.len()];
            out.append(&mut pubkey);
            let mut wire = creds;
            wire.append(&mut out);
            assert_eq!(wire.len(), 128 + 256);
            client_w.write_all(&wire).unwrap();

            let mut res = [0u8; 4];
            client.read_exact(&mut res).unwrap();
            assert_eq!(res, [0, 0, 0, 0]);
            client_w.write_all(&[0x01]).unwrap();
        });
        let res = perform(&mut server, Some(&pw_server), false, tls::Mode::Auto, None).unwrap();
        assert_eq!(res.auth, AuthMethod::AppleDh);
        assert_eq!(res.security_type, SEC_APPLE_DH);
        assert!(!res.encrypted);
        cli.join().unwrap();
    }

    #[test]
    fn handshake_37_none_no_security_result() {
        let (mut server, mut client) = duplex_pair();
        let cli = std::thread::spawn(move || {
            let (mut client, mut client_w) = client.split();
            let mut buf = [0u8; 12];
            client.read_exact(&mut buf).unwrap();
            client_w.write_all(b"RFB 003.007\n").unwrap();
            let mut one = [0u8; 1];
            client.read_exact(&mut one).unwrap(); // count
            client.read_exact(&mut one).unwrap(); // None
            client_w.write_all(&[SEC_NONE]).unwrap();
            // no SecurityResult expected under 3.7 — straight to ClientInit
            client_w.write_all(&[0x01]).unwrap();
            // If the server (wrongly) sent a SecurityResult, ClientInit would
            // be consumed by it and perform() would block forever; the test
            // completing proves the absence.
        });
        let res = perform(&mut server, None, true, tls::Mode::Off, None).unwrap();
        assert_eq!(res.minor, 7);
        cli.join().unwrap();
    }

    #[test]
    fn handshake_38_vencrypt_tlsvnc_ok() {
        let (server_cfg, client_cfg) = test_tls_configs();
        let (mut server, client) = duplex_pair();
        let cli = std::thread::spawn(move || {
            let mut client = client;
            let mut buf = [0u8; 12];
            client.read_exact(&mut buf).unwrap();
            client.write_all(b"RFB 003.008\n").unwrap();
            let mut count = [0u8; 1];
            client.read_exact(&mut count).unwrap();
            let mut types = vec![0u8; count[0] as usize];
            client.read_exact(&mut types).unwrap();
            assert!(types.contains(&vencrypt::SEC_VENCRYPT));
            client.write_all(&[vencrypt::SEC_VENCRYPT]).unwrap();

            // VeNCrypt version 0.2 + sub-type list
            let mut ver = [0u8; 2];
            client.read_exact(&mut ver).unwrap();
            assert_eq!(ver, [0, 2]);
            client.write_all(&[0, 2]).unwrap();
            let mut ok = [0u8; 1];
            client.read_exact(&mut ok).unwrap();
            assert_eq!(ok, [0]);
            let mut n = [0u8; 1];
            client.read_exact(&mut n).unwrap();
            let mut subtypes = vec![0u8; n[0] as usize * 4];
            client.read_exact(&mut subtypes).unwrap();
            assert!(subtypes
                .chunks(4)
                .any(|c| u32::from_be_bytes(c.try_into().unwrap()) == vencrypt::SUBTYPE_X509VNC));
            client
                .write_all(&vencrypt::SUBTYPE_X509VNC.to_be_bytes())
                .unwrap();
            let mut ack = [0u8; 1];
            client.read_exact(&mut ack).unwrap();
            assert_eq!(ack, [1], "VeNCrypt TLS ACK");

            // TLS handshake, then VNC auth inside TLS.
            let conn =
                rustls::ClientConnection::new(client_cfg, "localhost".try_into().unwrap()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, &mut client);
            while tls.conn.is_handshaking() {
                tls.conn.complete_io(&mut tls.sock).unwrap();
            }
            let mut challenge = [0u8; 16];
            tls.read_exact(&mut challenge).unwrap();
            let mut response = challenge;
            security::des_encrypt(&security::vnc_key("secret"), &mut response);
            tls.write_all(&response).unwrap();
            tls.flush().unwrap();
            let mut result = [0u8; 4];
            tls.read_exact(&mut result).unwrap();
            assert_eq!(result, [0, 0, 0, 0]);
            tls.write_all(&[1]).unwrap();
            tls.flush().unwrap();
        });
        let res = perform(
            &mut server,
            Some("secret"),
            false,
            tls::Mode::Auto,
            Some(server_cfg),
        )
        .unwrap();
        assert!(res.encrypted);
        assert_eq!(res.auth, AuthMethod::VeNCryptTlsVnc);
        assert_eq!(res.security_type, vencrypt::SEC_VENCRYPT);
        assert!(res.tls.is_some());
        cli.join().unwrap();
    }

    #[test]
    fn handshake_38_required_rejects_plain_client() {
        let (server_cfg, _) = test_tls_configs();
        let (mut server, mut client) = duplex_pair();
        let cli = std::thread::spawn(move || {
            let (mut client, mut client_w) = client.split();
            let mut buf = [0u8; 12];
            client.read_exact(&mut buf).unwrap();
            client_w.write_all(b"RFB 003.008\n").unwrap();
            // Required mode: only VeNCrypt is offered.
            let mut n = [0u8; 1];
            client.read_exact(&mut n).unwrap();
            assert_eq!(n[0], 1);
            let mut types = [0u8; 1];
            client.read_exact(&mut types).unwrap();
            assert_eq!(types, [vencrypt::SEC_VENCRYPT]);
        });
        let res = perform(
            &mut server,
            None,
            false,
            tls::Mode::Required,
            Some(server_cfg),
        );
        // The test client closes without completing the handshake.
        assert!(res.is_err());
        cli.join().unwrap();
    }

    #[test]
    fn apple_client_never_gets_vencrypt() {
        let (server_cfg, _) = test_tls_configs();
        let (mut server, mut client) = duplex_pair();
        let cli = std::thread::spawn(move || {
            let (mut client, mut client_w) = client.split();
            let mut buf = [0u8; 12];
            client.read_exact(&mut buf).unwrap();
            client_w.write_all(b"RFB 003.889\n").unwrap();
            let mut n = [0u8; 1];
            client.read_exact(&mut n).unwrap();
            assert_eq!(n[0], 1);
            let mut types = [0u8; 1];
            client.read_exact(&mut types).unwrap();
            assert_eq!(types, [SEC_APPLE_DH]);
        });
        // Auto mode + a usable TLS config: Apple still gets only type 30.
        let res = perform(
            &mut server,
            Some("pw"),
            false,
            tls::Mode::Auto,
            Some(server_cfg),
        );
        assert!(res.is_err()); // client closed without choosing
        cli.join().unwrap();
    }

    #[test]
    fn handshake_37_does_not_offer_vencrypt() {
        let (server_cfg, _) = test_tls_configs();
        let (mut server, mut client) = duplex_pair();
        let cli = std::thread::spawn(move || {
            let (mut client, mut client_w) = client.split();
            let mut buf = [0u8; 12];
            client.read_exact(&mut buf).unwrap();
            client_w.write_all(b"RFB 003.007\n").unwrap();
            let mut n = [0u8; 1];
            client.read_exact(&mut n).unwrap();
            assert_eq!(n[0], 2);
            let mut types = [0u8; 2];
            client.read_exact(&mut types).unwrap();
            assert_eq!(types, [SEC_NONE, SEC_TIGHT]); // no VeNCrypt under RFB 3.7
            client_w.write_all(&[SEC_NONE]).unwrap();
            client_w.write_all(&[0x01]).unwrap();
        });
        let res = perform(&mut server, None, true, tls::Mode::Auto, Some(server_cfg)).unwrap();
        assert_eq!(res.minor, 7);
        assert!(!res.encrypted);
        cli.join().unwrap();
    }

    fn test_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (Arc::new(server), Arc::new(client))
    }

    /// Simple in-memory bidirectional pipe pair.
    fn duplex_pair() -> (DuplexEnd, DuplexEnd) {
        let (a_tx, a_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (b_tx, b_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        (
            DuplexEnd {
                inbox: b_rx,
                outbox: a_tx,
                pending: Vec::new(),
            },
            DuplexEnd {
                inbox: a_rx,
                outbox: b_tx,
                pending: Vec::new(),
            },
        )
    }

    struct DuplexEnd {
        inbox: std::sync::mpsc::Receiver<Vec<u8>>,
        outbox: std::sync::mpsc::Sender<Vec<u8>>,
        pending: Vec<u8>,
    }

    impl DuplexEnd {
        /// Splits into separate Read/Write halves so the peer side can borrow
        /// both directions at once.
        fn split(&mut self) -> (impl std::io::Read + '_, impl std::io::Write + '_) {
            let inbox = &mut self.inbox;
            let pending = &mut self.pending;
            let outbox = &mut self.outbox;
            (DuplexReader { inbox, pending }, DuplexWriter { outbox })
        }
    }

    impl std::io::Read for DuplexEnd {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            while self.pending.is_empty() {
                match self.inbox.recv() {
                    Ok(chunk) => self.pending = chunk,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "peer closed",
                        ))
                    }
                }
            }
            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Ok(n)
        }
    }

    impl std::io::Write for DuplexEnd {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbox
                .send(buf.to_vec())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer closed"))?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct DuplexReader<'a> {
        inbox: &'a mut std::sync::mpsc::Receiver<Vec<u8>>,
        pending: &'a mut Vec<u8>,
    }

    impl std::io::Read for DuplexReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            while self.pending.is_empty() {
                match self.inbox.recv() {
                    Ok(chunk) => *self.pending = chunk,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "peer closed",
                        ))
                    }
                }
            }
            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Ok(n)
        }
    }

    struct DuplexWriter<'a> {
        outbox: &'a mut std::sync::mpsc::Sender<Vec<u8>>,
    }

    impl std::io::Write for DuplexWriter<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbox
                .send(buf.to_vec())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer closed"))?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
