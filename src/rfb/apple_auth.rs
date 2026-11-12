//! Apple Remote Desktop authentication (RFB security type 30) — lets the
//! macOS built-in "Screen Sharing.app" client authenticate with a password.
//!
//! Wire format (reverse-engineered from Apple's client, cross-checked against
//! neatvnc's `src/auth/apple-dh.c`):
//!
//! ```text
//! server -> client: u16 generator (=2), u16 key_size (=256),
//!                   [key_size] prime (RFC 3526 group 14),
//!                   [key_size] server public key = 2^secret mod p
//! client -> server: [128] AES-128-ECB(username[64] ++ password[64]),
//!                   [key_size] client public key = 2^client_secret mod p
//! server -> client: u32 security result (0 = ok, 1 = failed)
//! ```
//!
//! key = MD5(DH shared secret, 256 bytes big-endian).
//! The stream continues unencrypted after authentication (same as neatvnc),
//! so this alone is not MITM-proof — fine on a trusted LAN.

use aes::Aes128;
use cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use md5::{Digest, Md5};
use num_bigint::BigUint;

/// RFC 3526 §3, 2048-bit MODP group prime.
const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF";

const KEY_LEN: usize = 256;
const GENERATOR: u32 = 2;
const CREDENTIALS_LEN: usize = 128;

fn prime() -> BigUint {
    BigUint::from_bytes_be(&hex_decode(PRIME_HEX))
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Left-pads a big-endian representation to `len` bytes.
fn pad_be(n: &BigUint, len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

/// One half of the handshake: generates the server's DH secret and returns
/// `(server_public_key[256], secret)`.
pub fn generate_server_keys() -> io::Result<([u8; KEY_LEN], BigUint)> {
    let mut secret_bytes = [0u8; KEY_LEN];
    getrandom::fill(&mut secret_bytes).map_err(|e| io::Error::other(e.to_string()))?;
    let secret = BigUint::from_bytes_be(&secret_bytes);

    let public = BigUint::from(GENERATOR).modpow(&secret, &prime());
    let mut public_padded = [0u8; KEY_LEN];
    public_padded.copy_from_slice(&pad_be(&public, KEY_LEN));
    Ok((public_padded, secret))
}

/// Builds the `apple-dh` server message: generator, key size, prime, public key.
pub fn server_message(public_key: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + KEY_LEN * 2);
    out.extend_from_slice(&(GENERATOR as u16).to_be_bytes());
    out.extend_from_slice(&(KEY_LEN as u16).to_be_bytes());
    out.extend_from_slice(&pad_be(&prime(), KEY_LEN));
    out.extend_from_slice(public_key);
    out
}

/// Derives the AES-128 session key (MD5 of the 256-byte DH shared secret)
/// used for Apple client clipboard pushes after authentication.
pub fn session_key(secret: &BigUint, client_public_key: &[u8; KEY_LEN]) -> [u8; 16] {
    let client_public = BigUint::from_bytes_be(client_public_key);
    let shared = client_public.modpow(secret, &prime());
    let shared_padded = pad_be(&shared, KEY_LEN);
    Md5::digest(&shared_padded).into()
}

/// Streaming AES-128 session cipher for Apple 3.889 post-auth messages
/// (clipboard pushes are block-aligned on the wire).
pub struct SessionCipher {
    cipher: Aes128,
}

impl SessionCipher {
    pub fn new(key: &[u8; 16]) -> Self {
        SessionCipher {
            cipher: Aes128::new(GenericArray::from_slice(key)),
        }
    }

    /// Decrypts one 16-byte wire block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockDecrypt;
        self.cipher
            .decrypt_block(GenericArray::from_mut_slice(block));
    }
}

/// Builds one ARD server->client control message (AppleVNCServer's
/// `EncryptOneMessage`):
///
/// ```text
/// total = (payload.len() + 0x25) & !0xF
/// plain[0..2]  = BE16(payload.len())
/// plain[2..2+n] = payload
/// plain[..total-20] zero padded
/// plain[total-20..] = SHA1(BE32(seq) || plain[..total-20])
/// wire = AES-128-ECB(plain)
/// ```
///
/// `seq` is a per-session, per-direction counter starting at 0 and bumped for
/// every message. The client uses it to reject replayed/reordered messages.
#[allow(dead_code)]
pub fn encrypt_server_message(key: &[u8; 16], seq: u32, payload: &[u8]) -> Vec<u8> {
    use aes::cipher::BlockEncrypt;
    use sha1::{Digest as _, Sha1};

    let total = (payload.len() + 0x25) & !0xF;
    let mut out = vec![0u8; total];
    out[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[2..2 + payload.len()].copy_from_slice(payload);

    let body = total - 20;
    let mut sha = Sha1::new();
    sha.update(seq.to_be_bytes());
    sha.update(&out[..body]);
    out[body..].copy_from_slice(&sha.finalize());

    let cipher = Aes128::new(GenericArray::from_slice(key));
    for block in out.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(block.into());
    }
    out
}

/// Payload of an ARD `AutoPasteboardInfo` control message (type `0x14`).
///
/// `cmd` observed in AppleVNCServer: `2` after the server pasteboard changed,
/// `3` for the initial state pushed when a viewer starts.
pub fn auto_pasteboard_info(cmd: u8) -> [u8; 8] {
    [0x14, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, cmd]
}

/// AES-128-CBC stream cipher for the ARD server->client encrypted channel.
///
/// AppleVNCServer keeps one `CCCryptorRef` per session and calls
/// `CCCryptorUpdate` for every record, so the CBC chaining state (and thus
/// the effective IV) carries over from one record to the next.
pub struct AppleStreamCipher {
    key: [u8; 16],
    iv: [u8; 16],
    initial_iv: [u8; 16],
    /// Reset the CBC IV for every record (some clients do not chain).
    reset_iv: bool,
    /// Per-record SHA1 prefix counter (`viewer->0x914`, starts at 0).
    pub seq: u32,
}

impl AppleStreamCipher {
    pub fn new(key: [u8; 16], iv: [u8; 16], seq: u32) -> Self {
        AppleStreamCipher {
            key,
            iv,
            initial_iv: iv,
            reset_iv: false,
            seq,
        }
    }

    fn cbc_encrypt(&mut self, data: &mut [u8]) {
        use aes::cipher::BlockEncrypt;
        let cipher = Aes128::new(GenericArray::from_slice(&self.key));
        for block in data.as_chunks_mut::<16>().0 {
            for (b, iv) in block.iter_mut().zip(self.iv.iter()) {
                *b ^= *iv;
            }
            cipher.encrypt_block(block.into());
            self.iv.copy_from_slice(block);
        }
    }

    /// Seals one record: `BE16(len) || payload || 0..0 || SHA1(BE32(seq)||body)`
    /// padded to `(len + 0x25) & !0xF`, then CBC-encrypted.
    pub fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        use sha1::{Digest as _, Sha1};
        debug_assert!(payload.len() <= 0xFFFF);
        let total = (payload.len() + 0x25) & !0xF;
        let mut out = vec![0u8; total];
        out[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        out[2..2 + payload.len()].copy_from_slice(payload);

        let body = total - 20;
        let mut sha = Sha1::new();
        sha.update(self.seq.to_be_bytes());
        sha.update(&out[..body]);
        out[body..].copy_from_slice(&sha.finalize());
        self.seq = self.seq.wrapping_add(1);
        if self.reset_iv {
            self.iv = self.initial_iv;
        }

        self.cbc_encrypt(&mut out);
        out
    }
}

impl AppleStreamCipher {
    pub fn with_iv_reset(mut self, reset: bool) -> Self {
        self.reset_iv = reset;
        self
    }
}

/// Encrypts one 16-byte block with AES-128-ECB (DH session key).
#[allow(dead_code)]
pub fn encrypt_ecb_block(key: &[u8; 16], block: &mut [u8; 16]) {
    use aes::cipher::BlockEncrypt;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

/// Builds the ARD "encryption setup" message that AppleVNCServer sends as a
/// plaintext FramebufferUpdate carrying one pseudo-rect (encoding 1103):
///
/// ```text
/// 00 00 00 01   FramebufferUpdate, 1 rect
/// 00 00 00 00 00 00 00 00   x=0 y=0 w=0 h=0
/// 00 00 04 4f   encoding 1103 (encryption info)
/// 00 00 00 01   initial server->client sequence number
/// AES-ECB(dh_key, enc_key)   16 bytes
/// AES-ECB(dh_key, iv)        16 bytes
/// ```
///
/// After this message both directions switch to AES-128-CBC for the encrypted
/// control channel (`EncryptOneMessage`).
#[allow(dead_code)]
pub fn encryption_setup_message(
    dh_key: &[u8; 16],
    enc_key: &[u8; 16],
    iv: &[u8; 16],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&[0x00, 0x00, 0x04, 0x4f]);
    out.extend_from_slice(&1u32.to_be_bytes());

    let mut k = *enc_key;
    encrypt_ecb_block(dh_key, &mut k);
    out.extend_from_slice(&k);

    let mut v = *iv;
    encrypt_ecb_block(dh_key, &mut v);
    out.extend_from_slice(&v);
    out
}

/// Verifies the client's response: decrypts the credentials with the shared
/// secret and checks the password. Returns the (ignored) username on success.
pub fn verify_client_response(
    password: Option<&str>,
    secret: &BigUint,
    encrypted_credentials: &[u8; CREDENTIALS_LEN],
    client_public_key: &[u8; KEY_LEN],
) -> Result<String, String> {
    let client_public = BigUint::from_bytes_be(client_public_key);
    let shared = client_public.modpow(secret, &prime());
    let shared_padded = pad_be(&shared, KEY_LEN);

    let key = Md5::digest(&shared_padded);
    let cipher = Aes128::new(GenericArray::from_slice(&key));

    let mut plain = encrypted_credentials.to_vec();
    for block in plain.as_chunks_mut::<16>().0 {
        cipher.decrypt_block(block.into());
    }

    let username = zero_trim(&plain[..64]);
    let got_password = zero_trim(&plain[64..]);

    match password {
        // No password configured: accept whatever the client typed.
        None => Ok(String::from_utf8_lossy(username).into_owned()),
        Some(want) if got_password == want.as_bytes() => {
            Ok(String::from_utf8_lossy(username).into_owned())
        }
        Some(_) => Err("wrong password".into()),
    }
}

fn zero_trim(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

use std::io;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_is_2048_bit_rfc3526() {
        let p = prime();
        assert_eq!(p.bits(), 2048);
        assert_eq!(pad_be(&p, KEY_LEN).len(), KEY_LEN);
        // last byte 0xFF, first byte 0xFF per the RFC string
        let bytes = p.to_bytes_be();
        assert_eq!(bytes[0], 0xFF);
        assert_eq!(*bytes.last().unwrap(), 0xFF);
    }

    #[test]
    fn dh_roundtrip_and_password_check() {
        // Server side
        let (server_pub, secret) = generate_server_keys().unwrap();

        // Client side (what Screen Sharing.app does): own secret, derive pub,
        // shared, key, encrypt credentials.
        let mut client_secret_bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut client_secret_bytes).unwrap();
        let client_secret = BigUint::from_bytes_be(&client_secret_bytes);
        let client_pub_big = BigUint::from(GENERATOR).modpow(&client_secret, &prime());
        let mut client_pub = [0u8; KEY_LEN];
        client_pub.copy_from_slice(&pad_be(&client_pub_big, KEY_LEN));

        let shared = BigUint::from_bytes_be(&server_pub).modpow(&client_secret, &prime());
        let key = Md5::digest(pad_be(&shared, KEY_LEN).as_slice());
        let client_cipher = Aes128::new(GenericArray::from_slice(&key));

        let mut creds = vec![0u8; CREDENTIALS_LEN];
        creds[..4].copy_from_slice(b"user");
        creds[64..70].copy_from_slice(b"secret");
        for block in creds.as_chunks_mut::<16>().0 {
            use cipher::BlockEncrypt;
            client_cipher.encrypt_block(block.into());
        }

        let username = verify_client_response(
            Some("secret"),
            &secret,
            creds.as_slice().try_into().unwrap(),
            &client_pub,
        )
        .unwrap();
        assert_eq!(username, "user");

        let wrong = verify_client_response(
            Some("WRONG"),
            &secret,
            creds.as_slice().try_into().unwrap(),
            &client_pub,
        );
        assert!(wrong.is_err());
    }

    #[test]
    fn server_message_shape() {
        let (server_pub, _secret) = generate_server_keys().unwrap();
        let msg = server_message(&server_pub);
        assert_eq!(msg.len(), 4 + KEY_LEN * 2);
        assert_eq!(&msg[0..2], &2u16.to_be_bytes()); // generator
        assert_eq!(&msg[2..4], &256u16.to_be_bytes()); // key size
    }
}
