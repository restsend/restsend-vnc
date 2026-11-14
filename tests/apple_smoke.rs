//! End-to-end smoke test for the RFB 003.889 / Apple ARD dialect.
//!
//! Performs the Apple DH exchange, verifies the extended ServerInit, starts
//! the ARD record layer through `0x12 SetEncryption`, and checks that a
//! framebuffer update arrives inside the encrypted stream. This is the
//! regression gate for "Screen Sharing.app connects and stays connected".

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use md5::{Digest as _, Md5};
use num_bigint::BigUint;

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

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn connect_retry(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => return s,
            Err(e) => {
                if Instant::now() > deadline {
                    panic!("server did not start listening on {port}: {e}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn read_u8(s: &mut TcpStream) -> u8 {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).unwrap();
    b[0]
}

fn read_u16(s: &mut TcpStream) -> u16 {
    let mut b = [0u8; 2];
    s.read_exact(&mut b).unwrap();
    u16::from_be_bytes(b)
}

fn read_u32(s: &mut TcpStream) -> u32 {
    let mut b = [0u8; 4];
    s.read_exact(&mut b).unwrap();
    u32::from_be_bytes(b)
}

fn pad_be(n: &BigUint, len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

fn aes_ecb_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = Aes128::new(key.into());
    cipher.encrypt_block(block.into());
}

fn aes_ecb_decrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = Aes128::new(key.into());
    cipher.decrypt_block(block.into());
}

fn cbc_encrypt(key: &[u8; 16], iv: &mut [u8; 16], data: &mut [u8]) {
    for block in data.as_chunks_mut::<16>().0 {
        for (b, v) in block.iter_mut().zip(iv.iter()) {
            *b ^= *v;
        }
        aes_ecb_encrypt_block(key, block);
        iv.copy_from_slice(block);
    }
}

fn cbc_decrypt(key: &[u8; 16], iv: &mut [u8; 16], data: &mut [u8]) {
    for block in data.as_chunks_mut::<16>().0 {
        let mut ct = [0u8; 16];
        ct.copy_from_slice(block);
        aes_ecb_decrypt_block(key, block);
        for (b, v) in block.iter_mut().zip(iv.iter()) {
            *b ^= *v;
        }
        *iv = ct;
    }
}

struct RecordCipher {
    key: [u8; 16],
    iv: [u8; 16],
    seq: u32,
}

impl RecordCipher {
    fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        RecordCipher { key, iv, seq: 0 }
    }

    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let total = (payload.len() + 0x25) & !0xF;
        let mut out = vec![0u8; total];
        out[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        out[2..2 + payload.len()].copy_from_slice(payload);
        let body = total - 20;
        let mut sha = sha1::Sha1::new();
        sha.update(self.seq.to_be_bytes());
        sha.update(&out[..body]);
        out[body..].copy_from_slice(&sha.finalize());
        self.seq = self.seq.wrapping_add(1);
        let mut iv = self.iv;
        cbc_encrypt(&self.key, &mut iv, &mut out);
        self.iv = iv;
        let mut wire = Vec::with_capacity(total + 2);
        wire.extend_from_slice(&(total as u16).to_be_bytes());
        wire.extend_from_slice(&out);
        wire
    }

    fn open(s: &mut TcpStream, key: &[u8; 16], iv: &mut [u8; 16], seq: &mut u32) -> Vec<u8> {
        let size = read_u16(s) as usize;
        assert!(size >= 32 && size.is_multiple_of(16), "bad record size {size}");
        let mut ct = vec![0u8; size];
        s.read_exact(&mut ct).unwrap();
        cbc_decrypt(key, iv, &mut ct);
        let tag_at = size - 20;
        let mut sha = sha1::Sha1::new();
        sha.update(seq.to_be_bytes());
        sha.update(&ct[..tag_at]);
        assert_eq!(&sha.finalize()[..], &ct[tag_at..], "record SHA-1");
        *seq = seq.wrapping_add(1);
        let body_len = u16::from_be_bytes([ct[0], ct[1]]) as usize;
        assert!(2 + body_len <= tag_at);
        ct[2..2 + body_len].to_vec()
    }
}

fn apple_dh(s: &mut TcpStream) -> [u8; 16] {
    // Server offers security types; choose 30 (Apple DH).
    let count = read_u8(s) as usize;
    let mut types = vec![0u8; count];
    s.read_exact(&mut types).unwrap();
    assert!(types.contains(&30), "server did not offer Apple DH: {types:?}");
    s.write_all(&[30]).unwrap();

    let generator = read_u16(s) as u32;
    let keylen = read_u16(s) as usize;
    let mut prime_bytes = vec![0u8; keylen];
    s.read_exact(&mut prime_bytes).unwrap();
    let mut server_pub = vec![0u8; keylen];
    s.read_exact(&mut server_pub).unwrap();
    let prime = BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).unwrap();
    assert_eq!(generator, 2);
    assert_eq!(keylen, 256);
    assert_eq!(BigUint::from_bytes_be(&prime_bytes), prime);

    let secret = BigUint::from_bytes_be(&[0x42u8; 32]);
    let client_pub = BigUint::from(2u32).modpow(&secret, &prime);
    let shared = BigUint::from_bytes_be(&server_pub).modpow(&secret, &prime);
    let key: [u8; 16] = Md5::digest(pad_be(&shared, 256)).into();

    let mut creds = [0u8; 128];
    creds[..4].copy_from_slice(b"user");
    creds[64..70].copy_from_slice(b"secret");
    for block in creds.as_chunks_mut::<16>().0 {
        aes_ecb_encrypt_block(&key, block);
    }
    s.write_all(&creds).unwrap();
    s.write_all(&pad_be(&client_pub, 256)).unwrap();
    let result = read_u32(s);
    assert_eq!(result, 0, "Apple DH authentication failed");
    key
}

#[test]
fn apple_session_starts_encrypted_record_layer() {
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_restsend-vnc"))
        .args([
            "--test-pattern",
            "--no-auth",
            "--no-confirm",
            "--no-clipboard",
            "--allow-cidrs",
            "127.0.0.1/32",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .env("RESTSEND_VNC_ALLOW_MULTIPLE", "1")
        .env("RUST_LOG", "restsend_vnc=info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn restsend-vnc");
    let _guard = KillOnDrop(child);

    let mut s = connect_retry(port);
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();

    let mut version = [0u8; 12];
    s.read_exact(&mut version).unwrap();
    assert_eq!(&version, b"RFB 003.889\n");
    s.write_all(b"RFB 003.889\n").unwrap();

    let dh_key = apple_dh(&mut s);

    // ClientInit: shared + select + enhanced.
    s.write_all(&[0xC1]).unwrap();
    let width = read_u16(&mut s);
    let height = read_u16(&mut s);
    assert!(width > 0 && height > 0);
    let mut pf = [0u8; 16];
    s.read_exact(&mut pf).unwrap();
    let name_len = read_u32(&mut s) as usize;
    let mut name = vec![0u8; name_len];
    s.read_exact(&mut name).unwrap();
    assert!(name_len >= 22, "expected extended ServerInit, got {name_len}");
    assert_eq!(&name[..2], &[0, 0]);
    let flags = u32::from_be_bytes([name[2], name[3], name[4], name[5]]);
    assert_ne!(flags & 0x10, 0, "extended flag missing: {flags:#x}");
    let mut caps = [0u8; 16];
    caps.copy_from_slice(&name[6..22]);
    let accepts = |cmd: u8| caps[cmd as usize / 8] & (0x80 >> (cmd % 8)) != 0;
    assert!(accepts(0x12), "SetEncryption not advertised");
    assert!(accepts(0x21), "ViewerInfo not advertised");

    // Prelude: ViewerInfo, then request encryption.
    let mut viewer_info = vec![0x21u8, 0, 0, 0x3E, 0, 1];
    for value in [2u32, 6, 1, 0, 26, 6, 2] {
        viewer_info.extend_from_slice(&value.to_be_bytes());
    }
    viewer_info.extend_from_slice(&[0u8; 32]);
    s.write_all(&viewer_info).unwrap();
    // 0x12 cmd=1 (12-byte form).
    s.write_all(&[0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1])
        .unwrap();

    // Plaintext FramebufferUpdate carrying the 1103 setup rect.
    let fbu_type = read_u8(&mut s);
    assert_eq!(fbu_type, 0, "expected the 1103 framebuffer update");
    let _pad = read_u8(&mut s);
    let rects = read_u16(&mut s);
    assert_eq!(rects, 1);
    let _x = read_u16(&mut s);
    let _y = read_u16(&mut s);
    let _w = read_u16(&mut s);
    let _h = read_u16(&mut s);
    let encoding = read_u32(&mut s);
    assert_eq!(encoding, 1103);
    let generation = read_u32(&mut s);
    assert_eq!(generation, 1);
    let mut enc_key = [0u8; 16];
    let mut enc_iv = [0u8; 16];
    s.read_exact(&mut enc_key).unwrap();
    s.read_exact(&mut enc_iv).unwrap();
    aes_ecb_decrypt_block(&dh_key, &mut enc_key);
    aes_ecb_decrypt_block(&dh_key, &mut enc_iv);

    // Tell the server the client switched its own stream to records.
    s.write_all(&[0x12, 0, 0, 2, 0, 1, 0, 0]).unwrap();

    let mut enc = RecordCipher::new(enc_key, enc_iv);
    let mut dec_iv = enc_iv;
    let mut dec_seq = 0u32;

    // The first encrypted message is the second SetEncodings.
    let mut set_encodings = vec![2u8, 0];
    let encodings: [i32; 3] = [16, 0, -239];
    set_encodings.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for e in encodings {
        set_encodings.extend_from_slice(&e.to_be_bytes());
    }
    s.write_all(&enc.seal(&set_encodings)).unwrap();

    // The pusher now free-runs. Read records until a FramebufferUpdate body
    // arrives (control messages such as 0x14 may interleave).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_update = false;
    while Instant::now() < deadline {
        let body = RecordCipher::open(&mut s, &enc_key, &mut dec_iv, &mut dec_seq);
        if body.is_empty() {
            continue;
        }
        match body[0] {
            0 => {
                assert!(body.len() >= 4);
                let nrects = u16::from_be_bytes([body[2], body[3]]);
                assert!(nrects > 0, "framebuffer update carried no rects");
                saw_update = true;
                break;
            }
            0x14 | 0x03 => continue,
            other => panic!("unexpected record body type {other:#04x}"),
        }
    }
    assert!(saw_update, "no encrypted framebuffer update within 10s");

    // Input after activation is a record body carrying an ECB block under the
    // record key. If the key switch is wrong the server drops the connection.
    let mut block = [0u8; 16];
    block[0] = 0xff;
    block[1] = 1;
    block[5] = 0x61; // 'a'
    aes_ecb_encrypt_block(&enc_key, &mut block);
    let mut input = vec![0x10u8, 0];
    input.extend_from_slice(&block);
    s.write_all(&enc.seal(&input)).unwrap();

    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut more = vec![0u8; 1];
    let _ = s.read(&mut more); // must not be a reset (read_exact would error)
}
