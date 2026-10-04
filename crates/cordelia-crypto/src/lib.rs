//! Cordelia Crypto -- Ed25519/X25519 identity, ECIES envelope encryption,
//! AES-256-GCM item encryption, Bech32 encoding, CBOR signing.
//!
//! Spec: seed-drill/specs/ecies-envelope-encryption.md
//! Port source: cordelia-core/crates/cordelia-crypto (adapted for new spec)
//!
//! Also here, and not yet used by the node, is a channel from its secret
//! (decision 2026-10-04): what is derived from a channel's secret and where
//! each kind's secret comes from ([`derive`]), the recovery phrase
//! ([`phrase`]), the statement of a person's devices ([`statement`]), and
//! the entry that carries a statement to a device ([`change_entry`]). Each
//! is pure functions, with vectors in
//! `docs/reference/step4-test-vectors.json`. Beside them are an entry in
//! the form such a channel has, with its seal, its two signatures and its
//! chain ([`entry`]), the one place that builds a chain ([`chain`]), and
//! how a slot's current version is read ([`version`]); and, for a device that is added, the record of its
//! addition ([`addition`]) and what it is handed ([`hand_over`]).

pub mod addition;
pub mod aes_gcm;
pub mod bech32;
pub mod chain;
pub mod change_entry;
pub mod channel_state;
pub mod derive;
pub mod ecies;
pub mod entry;
pub mod hand_over;
pub mod identity;
pub mod phrase;
pub mod psk_envelope;
pub mod signing;
pub mod slots;
pub mod statement;
pub mod version;

#[cfg(test)]
mod vectors;

pub use aes_gcm::{item_decrypt, item_encrypt};
pub use bech32::{bech32_decode, bech32_encode};
pub use ecies::{EciesEnvelope, ecies_decrypt, ecies_encrypt, hkdf_sha256, hkdf_sha256_of};
pub use identity::{NodeIdentity, verify_swarm_child, x25519_from_ed25519_seed};

use ring::rand::{SecureRandom, SystemRandom};
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

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Generate a random 32-byte PSK using CSPRNG.
pub fn generate_psk() -> Result<[u8; 32], CryptoError> {
    let rng = SystemRandom::new();
    let mut psk = [0u8; 32];
    rng.fill(&mut psk)
        .map_err(|_| CryptoError::EncryptionFailed("RNG failure".into()))?;
    Ok(psk)
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

    // T4-1 (HIGH): Full PSK distribution flow -- identity -> ECIES -> item encrypt/decrypt
    #[test]
    fn test_full_psk_distribution_flow() {
        // Sender creates a channel with a PSK
        let _sender = NodeIdentity::generate().unwrap();
        let recipient = NodeIdentity::generate().unwrap();
        let psk = generate_psk().unwrap();

        // Sender encrypts PSK for recipient using ECIES
        let recipient_xpk = recipient.x25519_public_key();
        let envelope = ecies_encrypt(&recipient_xpk, &psk).unwrap();

        // Simulate wire transfer: serialize to bytes and back
        let wire_bytes = envelope.to_bytes();
        let received = EciesEnvelope::from_bytes(&wire_bytes, 32).unwrap();

        // Recipient decrypts PSK
        let recipient_xsk = recipient.x25519_private_key();
        let recovered_psk_vec = ecies_decrypt(&recipient_xsk, &received).unwrap();
        let recovered_psk: [u8; 32] = recovered_psk_vec.try_into().unwrap();
        assert_eq!(recovered_psk, psk);

        // Both sides can now encrypt/decrypt items with the shared PSK
        let plaintext = b"hello from sender";
        let aad = b"test_channel_abc";
        let ciphertext = item_encrypt(&psk, plaintext, aad).unwrap();
        let decrypted = item_decrypt(&recovered_psk, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
