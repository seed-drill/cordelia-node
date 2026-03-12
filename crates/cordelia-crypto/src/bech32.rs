//! Bech32 encoding/decoding for Cordelia key types.
//!
//! HRP prefixes:
//!   cordelia_pk1   -- Ed25519 public key (32 bytes)
//!   cordelia_sk1   -- Ed25519 seed/private key (32 bytes)
//!   cordelia_xpk1  -- X25519 public key (32 bytes)
//!   cordelia_sig1  -- Ed25519 signature (64 bytes)
//!   cordelia_psk1  -- Pre-Shared Key (32 bytes)
//!
//! Spec: seed-drill/specs/identity.md §10

use crate::CryptoError;

/// Known HRP prefixes.
pub const HRP_PUBLIC_KEY: &str = "cordelia_pk";
pub const HRP_SECRET_KEY: &str = "cordelia_sk";
pub const HRP_X25519_PK: &str = "cordelia_xpk";
pub const HRP_SIGNATURE: &str = "cordelia_sig";
pub const HRP_PSK: &str = "cordelia_psk";

/// Encode bytes to Bech32m with the given HRP.
pub fn bech32_encode(hrp: &str, data: &[u8]) -> Result<String, CryptoError> {
    let hrp = bech32::Hrp::parse(hrp).map_err(|e| CryptoError::Bech32Error(e.to_string()))?;
    let encoded =
        bech32::encode::<bech32::Bech32m>(hrp, data).map_err(|e| CryptoError::Bech32Error(e.to_string()))?;
    Ok(encoded)
}

/// Decode Bech32m string, returning (hrp, data).
pub fn bech32_decode(encoded: &str) -> Result<(String, Vec<u8>), CryptoError> {
    let (hrp, data) =
        bech32::decode(encoded).map_err(|e| CryptoError::Bech32Error(e.to_string()))?;
    Ok((hrp.to_string(), data))
}

/// Encode an Ed25519 public key to cordelia_pk1...
pub fn encode_public_key(pk: &[u8; 32]) -> Result<String, CryptoError> {
    bech32_encode(HRP_PUBLIC_KEY, pk)
}

/// Decode a cordelia_pk1... string to raw bytes.
pub fn decode_public_key(encoded: &str) -> Result<[u8; 32], CryptoError> {
    let (hrp, data) = bech32_decode(encoded)?;
    if hrp != HRP_PUBLIC_KEY {
        return Err(CryptoError::Bech32Error(format!(
            "expected HRP '{HRP_PUBLIC_KEY}', got '{hrp}'"
        )));
    }
    if data.len() != 32 {
        return Err(CryptoError::Bech32Error(format!(
            "expected 32 bytes, got {}",
            data.len()
        )));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&data);
    Ok(pk)
}

/// Encode a PSK to cordelia_psk1...
pub fn encode_psk(psk: &[u8; 32]) -> Result<String, CryptoError> {
    bech32_encode(HRP_PSK, psk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_round_trip() {
        let pk = [0x42u8; 32];
        let encoded = encode_public_key(&pk).unwrap();
        assert!(encoded.starts_with("cordelia_pk1"));
        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    fn test_wrong_hrp_rejected() {
        let psk = [0x42u8; 32];
        let encoded = encode_psk(&psk).unwrap();
        assert!(decode_public_key(&encoded).is_err());
    }

    #[test]
    fn test_signature_encoding() {
        let sig = [0xABu8; 64];
        let encoded = bech32_encode(HRP_SIGNATURE, &sig).unwrap();
        assert!(encoded.starts_with("cordelia_sig1"));
        let (hrp, data) = bech32_decode(&encoded).unwrap();
        assert_eq!(hrp, HRP_SIGNATURE);
        assert_eq!(data, sig);
    }

    #[test]
    fn test_all_hrp_prefixes() {
        let data32 = [0x01u8; 32];
        let data64 = [0x01u8; 64];

        assert!(bech32_encode(HRP_PUBLIC_KEY, &data32).unwrap().starts_with("cordelia_pk1"));
        assert!(bech32_encode(HRP_SECRET_KEY, &data32).unwrap().starts_with("cordelia_sk1"));
        assert!(bech32_encode(HRP_X25519_PK, &data32).unwrap().starts_with("cordelia_xpk1"));
        assert!(bech32_encode(HRP_PSK, &data32).unwrap().starts_with("cordelia_psk1"));
        assert!(bech32_encode(HRP_SIGNATURE, &data64).unwrap().starts_with("cordelia_sig1"));
    }
}
