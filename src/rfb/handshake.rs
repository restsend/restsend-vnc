//! RFB handshake: version exchange, security negotiation (None / VNC auth /
//! Tight with capability exchange) and ClientInit.

use std::io::{self, Read, Write};

use crate::rfb::security;

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
}

#[derive(Debug, Clone, Copy)]
pub struct HandshakeResult {
    /// Protocol minor version the client chose (3, 7 or 8).
    pub minor: u16,
    /// The security type the client picked (1 = None, 2 = VNC auth, 16 = Tight).
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
fn vnc_auth_exchange(
    reader: &mut impl Read,
    writer: &mut impl Write,
    password: &str,
    send_result_on_failure: bool,
) -> HsResult<()> {
    let challenge = security::random_challenge();
    writer.write_all(&challenge)?;
    writer.flush()?;
    let mut response = [0u8; 16];
    reader
        .read_exact(&mut response)
        .map_err(|e| stage_err("VNC auth challenge/response", e.into()))?;
    if !security::verify_response(password, &challenge, &response) {
        // RFB 3.8 requires a SecurityResult(1) + reason before closing.
        if send_result_on_failure {
            let reason = "VNC authentication failed: wrong password";
            let _ = writer.write_all(&1u32.to_be_bytes());
            let _ = writer.write_all(&(reason.len() as u32).to_be_bytes());
            let _ = writer.write_all(reason.as_bytes());
            let _ = writer.flush();
        }
        return Err(HandshakeError::Protocol(
            "VNC authentication failed: wrong password".into(),
        ));
    }
    Ok(())
}

/// Apple Remote Desktop authentication (security type 30): the scheme the
/// macOS built-in Screen Sharing client uses instead of legacy VNC auth.
fn apple_dh_exchange(
    reader: &mut impl Read,
    writer: &mut impl Write,
    password: Option<&str>,
    send_result_on_failure: bool,
) -> HsResult<[u8; 16]> {
    use crate::rfb::apple_auth;

    let (server_public, secret) = apple_auth::generate_server_keys()
        .map_err(|e| HandshakeError::Protocol(format!("DH keygen failed: {e}")))?;
    writer
        .write_all(&apple_auth::server_message(&server_public))
        .map_err(|e| stage_err("Apple DH server message", e.into()))?;
    writer.flush()?;

    // Client replies: encrypted_credentials[128] ++ public_key[256].
    let mut response = [0u8; 128 + 256];
    reader
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
            writer.write_all(&0u32.to_be_bytes())?;
            writer.flush()?;
            let session_key = apple_auth::session_key(
                &secret,
                client_public.try_into().unwrap(),
            );
            tracing::info!(
                "Apple DH auth: user \"{username}\" authenticated (session key {})",
                hex::encode(session_key)
            );
            Ok(session_key)
        }
        Err(reason) => {
            if send_result_on_failure {
                let _ = writer.write_all(&1u32.to_be_bytes());
                let _ = writer.write_all(&(reason.len() as u32).to_be_bytes());
                let _ = writer.write_all(reason.as_bytes());
                let _ = writer.flush();
            }
            Err(HandshakeError::Protocol(format!(
                "Apple DH authentication failed: {reason}"
            )))
        }
    }
}

/// Runs the full handshake up to and including ClientInit.
pub fn perform(
    reader: &mut impl Read,
    writer: &mut impl Write,
    password: Option<&str>,
    allow_tight: bool,
) -> HsResult<HandshakeResult> {
    // Experiment: announce 3.3 / 3.8 to see if Screen Sharing.app accepts a
    // standard RFB session (which would give us the standard clipboard).
    let version: &[u8; 12] = match std::env::var("RVNC_RFB_VER").as_deref() {
        Ok("33") => b"RFB 003.003\n",
        Ok("37") => b"RFB 003.007\n",
        Ok("38") => b"RFB 003.008\n",
        _ => PROTOCOL_STRING,
    };
    writer.write_all(version)?;
    writer.flush()?;

    let mut version = [0u8; 12];
    reader
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

    // Build the offer: Apple clients (RFB 003.889) get ONLY the Apple DH
    // scheme — they pick legacy VNC auth (type 2) when it's on the list but
    // then abort the challenge, so type 2 must not be offered to them.
    let mut offered: Vec<u8> = Vec::new();
    if apple_client {
        // No password: try the standard no-auth type first (no login prompt).
        // With a password, Apple DH is required (the client aborts type 2).
        if password.is_none() && std::env::var_os("RVNC_APPLE_NONE").is_some() {
            offered.push(SEC_NONE);
        } else {
            offered.push(SEC_APPLE_DH);
        }
    } else if password.is_some() {
        // Apple DH (30) is Apple-only: standard viewers such as TigerVNC
        // also implement type 30 and would pick it over plain VNC auth,
        // then fail the Apple-specific credential exchange.
        offered.push(SEC_VNC_AUTH);
    } else {
        offered.push(SEC_NONE);
    }
    if allow_tight && !apple_client {
        offered.push(SEC_TIGHT);
    }

    let chosen = if legacy {
        let pick = if password.is_some() {
            SEC_VNC_AUTH
        } else {
            SEC_NONE
        };
        writer.write_all(&(pick as u32).to_be_bytes())?;
        writer.flush()?;
        pick
    } else {
        writer.write_all(&[offered.len() as u8])?;
        writer.write_all(&offered)?;
        writer.flush()?;
        let mut pick = [0u8; 1];
        reader
            .read_exact(&mut pick)
            .map_err(|e| stage_err("security type choice", e.into()))?;
        let pick = pick[0];
        tracing::debug!(
            "handshake: offered {:?}, client picked {}",
            offered,
            pick
        );
        if !offered.contains(&pick) {
            return Err(HandshakeError::Protocol(format!(
                "client picked unsupported security type {pick}"
            )));
        }
        pick
    };

    let mut apple_key: Option<[u8; 16]> = None;
    let (tight, auth) = match chosen {
        SEC_TIGHT => {
            // 1) tunneling caps: none.
            writer.write_all(&0u32.to_be_bytes())?;
            writer.flush()?;
            // 2) auth caps. Empty list = no auth needed, client sends nothing.
            match password {
                Some(pw) => {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&1u32.to_be_bytes());
                    write_cap(&mut buf, SEC_VNC_AUTH as u32, STDV_VENDOR, NAME_VNC_AUTH);
                    writer.write_all(&buf)?;
                    writer.flush()?;
                    let mut code = [0u8; 4];
                    reader
                        .read_exact(&mut code)
                        .map_err(|e| stage_err("Tight auth scheme choice", e.into()))?;
                    if u32::from_be_bytes(code) != SEC_VNC_AUTH as u32 {
                        return Err(HandshakeError::Protocol(format!(
                            "client picked unsupported Tight auth scheme {}",
                            u32::from_be_bytes(code)
                        )));
                    }
                    // The Tight flow has no SecurityResult message.
                    vnc_auth_exchange(reader, writer, pw, false)?;
                    (true, AuthMethod::VncAuth)
                }
                None => {
                    writer.write_all(&0u32.to_be_bytes())?;
                    writer.flush()?;
                    (true, AuthMethod::None)
                }
            }
        }
        SEC_APPLE_DH => {
            // Apple clients get type 30 even without a configured password;
            // in that case whatever they type is accepted.
            apple_key = Some(apple_dh_exchange(reader, writer, password, has_result)?);
            (false, AuthMethod::AppleDh)
        }
        SEC_VNC_AUTH => {
            let pw = password.ok_or_else(|| {
                HandshakeError::Protocol("client chose VNC auth with no password configured".into())
            })?;
            vnc_auth_exchange(reader, writer, pw, has_result)?;
            (false, AuthMethod::VncAuth)
        }
        _ => (false, AuthMethod::None),
    };

    // RFB 3.8 sends a SecurityResult after the security handshake (including
    // for None). The Tight flow and the Apple DH flow already wrote their own
    // result, and 3.3/3.7 have none at all.
    if has_result && !tight && auth != AuthMethod::AppleDh {
        writer.write_all(&0u32.to_be_bytes())?;
        writer.flush()?;
    }

    // ClientInit
    let mut shared = [0u8; 1];
    reader
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
    })
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        let (mut r, mut w) = server.split();
        let res = perform(&mut r, &mut w, None, true).unwrap();
        assert!(res.tight);
        assert_eq!(res.auth, AuthMethod::None);
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
        let (mut r, mut w) = server.split();
        let err = perform(&mut r, &mut w, Some("rightpw"), false).unwrap_err();
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
        let (mut r, mut w) = server.split();
        let res = perform(&mut r, &mut w, Some(pw), false).unwrap();
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
        let (mut r, mut w) = server.split();
        let res = perform(&mut r, &mut w, Some(&pw_server), false).unwrap();
        assert_eq!(res.auth, AuthMethod::AppleDh);
        assert_eq!(res.security_type, SEC_APPLE_DH);
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
        let (mut r, mut w) = server.split();
        let res = perform(&mut r, &mut w, None, true).unwrap();
        assert_eq!(res.minor, 7);
        cli.join().unwrap();
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
        /// Splits into separate Read/Write halves so `perform(&mut r, &mut w)`
        /// can borrow disjoint fields.
        fn split(
            &mut self,
        ) -> (
            impl std::io::Read + '_,
            impl std::io::Write + '_,
        ) {
            let inbox = &mut self.inbox;
            let pending = &mut self.pending;
            let outbox = &mut self.outbox;
            (
                DuplexReader { inbox, pending },
                DuplexWriter { outbox },
            )
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
