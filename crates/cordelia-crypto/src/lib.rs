//! Cordelia Crypto -- Ed25519/X25519 identity, ECIES envelope encryption,
//! AES-256-GCM item encryption, Bech32 encoding, CBOR signing.
//!
//! Spec: seed-drill/specs/ecies-envelope-encryption.md
//! Port source: cordelia-core/crates/cordelia-crypto (adapted for new spec)

pub mod aes_gcm;
pub mod bech32;
pub mod ecies;
pub mod identity;
pub mod signing;

pub use aes_gcm::{item_decrypt, item_encrypt};
pub use bech32::{bech32_decode, bech32_encode};
pub use ecies::{ecies_decrypt, ecies_encrypt, hkdf_sha256, EciesEnvelope};
pub use identity::{x25519_from_ed25519_seed, NodeIdentity};

use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("identity error: {0}")]
    IdentityError(String),

    #[error("signing error: {0}")]
    SigningError(String),

    #[error("bech32 error: {0}")]
    Bech32Error(String),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

/// SHA-256 hash, returned as raw bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// SHA-256 hash, returned as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_raw() {
        let hash = sha256(b"hello");
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
