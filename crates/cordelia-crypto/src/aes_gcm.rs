//! AES-256-GCM item encryption using channel PSK.
//!
//! Binary format: iv[12] || ciphertext[N] || auth_tag[16]
//! Total overhead: 28 bytes per item.
//!
//! Spec: seed-drill/specs/ecies-envelope-encryption.md §5

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

use crate::CryptoError;

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Encrypt plaintext with a 32-byte channel PSK.
///
/// Returns binary: iv[12] || ciphertext[N] || auth_tag[16]
pub fn item_encrypt(psk: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let rng = SystemRandom::new();
    let mut iv = [0u8; IV_LEN];
    rng.fill(&mut iv)
        .map_err(|_| CryptoError::EncryptionFailed("RNG failure".into()))?;

    let unbound = UnboundKey::new(&AES_256_GCM, psk)
        .map_err(|_| CryptoError::EncryptionFailed("invalid PSK".into()))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&iv)
        .map_err(|_| CryptoError::EncryptionFailed("nonce error".into()))?;

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::EncryptionFailed("AES-GCM seal failed".into()))?;

    // Output: iv || ciphertext || tag (tag is already appended by ring)
    let mut output = Vec::with_capacity(IV_LEN + in_out.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&in_out);
    Ok(output)
}

/// Decrypt binary blob encrypted with item_encrypt.
///
/// Input format: iv[12] || ciphertext[N] || auth_tag[16]
pub fn item_decrypt(psk: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < IV_LEN + TAG_LEN {
        return Err(CryptoError::DecryptionFailed);
    }

    let iv = &encrypted[..IV_LEN];
    let ct_and_tag = &encrypted[IV_LEN..];

    let unbound =
        UnboundKey::new(&AES_256_GCM, psk).map_err(|_| CryptoError::DecryptionFailed)?;
    let key = LessSafeKey::new(unbound);
    let nonce =
        Nonce::try_assume_unique_for_key(iv).map_err(|_| CryptoError::DecryptionFailed)?;

    let mut in_out = ct_and_tag.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_item_round_trip() {
        let psk = [0x42u8; 32];
        let plaintext = b"hello cordelia";

        let encrypted = item_encrypt(&psk, plaintext).unwrap();
        assert_eq!(encrypted.len(), IV_LEN + plaintext.len() + TAG_LEN);

        let decrypted = item_decrypt(&psk, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_unique_iv_per_encryption() {
        let psk = [0x42u8; 32];
        let e1 = item_encrypt(&psk, b"same data").unwrap();
        let e2 = item_encrypt(&psk, b"same data").unwrap();

        // IVs (first 12 bytes) should differ
        assert_ne!(&e1[..IV_LEN], &e2[..IV_LEN]);
    }

    #[test]
    fn test_wrong_psk_fails() {
        let psk1 = [0x01u8; 32];
        let psk2 = [0x02u8; 32];

        let encrypted = item_encrypt(&psk1, b"secret").unwrap();
        assert!(item_decrypt(&psk2, &encrypted).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let psk = [0x42u8; 32];
        let mut encrypted = item_encrypt(&psk, b"data").unwrap();
        encrypted[IV_LEN] ^= 0xff; // tamper first byte of ciphertext
        assert!(item_decrypt(&psk, &encrypted).is_err());
    }

    #[test]
    fn test_too_short_input_fails() {
        let psk = [0x42u8; 32];
        assert!(item_decrypt(&psk, &[0u8; 10]).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let psk = [0x42u8; 32];
        let encrypted = item_encrypt(&psk, b"").unwrap();
        assert_eq!(encrypted.len(), IV_LEN + TAG_LEN); // 28 bytes, no ciphertext
        let decrypted = item_decrypt(&psk, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_json_payload() {
        let psk = [0x42u8; 32];
        let data = serde_json::json!({
            "content": "hello world",
            "metadata": { "type": "message" }
        });
        let plaintext = serde_json::to_vec(&data).unwrap();

        let encrypted = item_encrypt(&psk, &plaintext).unwrap();
        let decrypted = item_decrypt(&psk, &encrypted).unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(data, recovered);
    }
}
