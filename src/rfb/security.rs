//! VNC authentication (RFC 6143 "DES challenge-response").
//!
//! The shared key is the password truncated/padded to 8 bytes, with the bits
//! of every byte reversed (a quirk of the original RFB implementation).
//! Each 8-byte block of the 16-byte challenge is DES-ECB encrypted.

#![allow(clippy::chunks_exact_to_as_chunks)]

use cipher::{generic_array::GenericArray, BlockEncrypt, BlockSizeUser, KeyInit};
use des::Des;

/// Derives the DES key from a password per the VNC auth spec.
pub fn vnc_key(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    let bytes = password.as_bytes();
    for (i, b) in bytes.iter().take(8).enumerate() {
        key[i] = b.reverse_bits();
    }
    key
}

/// DES-ECB encrypts `data` in place (len must be a multiple of 8).
pub fn des_encrypt(key: &[u8; 8], data: &mut [u8]) {
    let Ok(cipher) = Des::new_from_slice(key) else {
        return;
    };
    for chunk in data.chunks_exact_mut(8) {
        let mut block = GenericArray::<u8, <Des as BlockSizeUser>::BlockSize>::default();
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
}

/// Generates a random 16-byte challenge.
pub fn random_challenge() -> [u8; 16] {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("system RNG unavailable");
    buf
}

/// Verifies a client's response to a challenge. Constant enough.
pub fn verify_response(password: &str, challenge: &[u8; 16], response: &[u8; 16]) -> bool {
    let key = vnc_key(password);
    let mut expected = *challenge;
    des_encrypt(&key, &mut expected);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(response.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_bit_reversal() {
        // 'ö' (U+00F0) encodes as UTF-8 [0xC3, 0xB0]; 0xC3 is a bit-palindrome,
        // 0xB0 reversed is 0x0D; the rest is zero padding.
        let key = vnc_key("\u{F0}");
        assert_eq!(key[0], 0xC3);
        assert_eq!(key[1], 0x0D);
        assert_eq!(&key[2..], &[0u8; 6]);
        // "abc"
        let key = vnc_key("abc");
        assert_eq!(key[0], 0x86); // 'a' = 0x61 -> 0x86
        assert_eq!(key[1], 0x46); // 'b' = 0x62 -> 0x46
        assert_eq!(key[2], 0xC6); // 'c' = 0x63 -> 0xC6
        assert_eq!(&key[3..], &[0u8; 5]);
    }

    #[test]
    fn challenge_response_roundtrip() {
        let password = "secret1";
        let challenge = random_challenge();
        let key = vnc_key(password);
        let mut response = challenge;
        des_encrypt(&key, &mut response);
        assert!(verify_response(password, &challenge, &response));
        assert!(!verify_response("wrongpw", &challenge, &response));
    }

    #[test]
    fn encrypt_is_blockwise_ecb() {
        let key = vnc_key("pw");
        let mut data = [0x11u8; 16];
        let plain = data[0..8].to_vec();
        des_encrypt(&key, &mut data);
        // identical plaintext blocks -> identical ciphertext blocks
        assert_eq!(data[0..8], data[8..16]);
        // ...and different from the plaintext
        assert_ne!(data[0..8].to_vec(), plain);
    }
}
