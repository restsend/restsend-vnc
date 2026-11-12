//! VeNCrypt (RFB security type 19) version/sub-type negotiation and the
//! upgrade to a rustls TLS stream.
//!
//! Only the X.509 sub-types are implemented:
//! * 260 X509None — TLS with a server certificate, no authentication
//! * 261 X509Vnc  — TLS with a server certificate + VNC DES authentication
//!
//! The anonymous TLS sub-types (257 TLSNone / 258 TLSVnc) are deliberately
//! not offered: they use anonymous cipher suites, which rustls does not
//! implement, and TigerVNC/RealVNC both support the X.509 variants. After the
//! TLS handshake all further RFB traffic (including the inner authentication
//! and ClientInit) is encrypted.

use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::{ServerConfig, ServerConnection};

pub const SEC_VENCRYPT: u8 = 19;

pub const VERSION_MAJOR: u8 = 0;
pub const VERSION_MINOR: u8 = 2;

pub const SUBTYPE_X509NONE: u32 = 260;
pub const SUBTYPE_X509VNC: u32 = 261;

/// Runs the VeNCrypt version and sub-type handshake.
///
/// `offer_vnc_auth` selects X509Vnc (password configured) instead of X509None.
pub fn negotiate<S: Read + Write>(stream: &mut S, offer_vnc_auth: bool) -> io::Result<u32> {
    stream.write_all(&[VERSION_MAJOR, VERSION_MINOR])?;
    stream.flush()?;

    let mut version = [0u8; 2];
    stream.read_exact(&mut version)?;
    let (major, minor) = (version[0], version[1]);
    if major == 0 && minor == 0 {
        return Err(protocol_err("client refused VeNCrypt"));
    }
    // 0.1 is obsolete (and uses U8 sub-types); only 0.2 is supported.
    if major != 0 || minor < 2 {
        let _ = stream.write_all(&[255]);
        let _ = stream.flush();
        return Err(protocol_err(&format!(
            "client chose unsupported VeNCrypt version {major}.{minor}"
        )));
    }

    // Version accepted.
    stream.write_all(&[0])?;

    let subtypes: &[u32] = if offer_vnc_auth {
        &[SUBTYPE_X509VNC]
    } else {
        &[SUBTYPE_X509NONE]
    };
    stream.write_all(&[subtypes.len() as u8])?;
    for subtype in subtypes {
        stream.write_all(&subtype.to_be_bytes())?;
    }
    stream.flush()?;

    let mut choice = [0u8; 4];
    stream.read_exact(&mut choice)?;
    let choice = u32::from_be_bytes(choice);
    if !subtypes.contains(&choice) {
        return Err(protocol_err(&format!(
            "client chose unsupported VeNCrypt sub-type {choice}"
        )));
    }
    tracing::debug!("VeNCrypt: version 0.2, sub-type {choice}");
    // The TLS/X509 sub-types require an explicit success ACK before the TLS
    // handshake starts. TigerVNC (and other GnuTLS clients) wait for this
    // byte; omitting it stalls both sides until the connection times out.
    // 0 = failure, 1 = success.
    stream.write_all(&[1])?;
    stream.flush()?;
    Ok(choice)
}

/// Performs the TLS handshake over `stream`, returning a `StreamOwned` that
/// transparently encrypts/decrypts the rest of the RFB session.
pub fn start_tls<S: Read + Write>(
    stream: &mut S,
    config: Arc<ServerConfig>,
) -> io::Result<rustls::StreamOwned<ServerConnection, &mut S>> {
    let connection = ServerConnection::new(config)
        .map_err(|e| protocol_err(&format!("cannot create TLS server connection: {e}")))?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    tracing::debug!("VeNCrypt: TLS handshake complete");
    Ok(tls)
}

fn protocol_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}
