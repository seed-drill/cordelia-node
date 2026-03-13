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

/// Encode bytes to Bech32 (BIP-173) with the given HRP.
/// Per spec §3.5: use Bech32, NOT Bech32m (BIP-350). Aligned with Cardano CIP-19.
pub fn bech32_encode(hrp: &str, data: &[u8]) -> Result<String, CryptoError> {
    let hrp = bech32::Hrp::parse(hrp).map_err(|e| CryptoError::Bech32Error(e.to_string()))?;
    let encoded =
        bech32::encode::<bech32::Bech32>(hrp, data).map_err(|e| CryptoError::Bech32Error(e.to_string()))?;
    Ok(encoded)
}

/// Known valid HRPs for validation.
const VALID_HRPS: &[&str] = &[
    HRP_PUBLIC_KEY, HRP_SECRET_KEY, HRP_X25519_PK, HRP_SIGNATURE, HRP_PSK,
];

/// Decode Bech32 (BIP-173) string, returning (hrp, data).
/// Rejects unknown HRPs per spec §3.6.
pub fn bech32_decode(encoded: &str) -> Result<(String, Vec<u8>), CryptoError> {
    let (hrp, data) =
        bech32::decode(encoded).map_err(|e| CryptoError::Bech32Error(e.to_string()))?;
    let hrp_str = hrp.to_string();
    if !VALID_HRPS.contains(&hrp_str.as_str()) {
        return Err(CryptoError::Bech32Error(format!("unknown HRP: {hrp_str}")));
    }
    Ok((hrp_str, data))
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

    // ── Spec test vectors (ecies-envelope-encryption.md §3.6, §8.5) ──

    /// TV-B1: Ed25519 public key. Cross-language: TS (bech32 npm) must match.
    #[test]
    fn test_tv_b1_public_key() {
        let pk = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        let encoded = bech32_encode(HRP_PUBLIC_KEY, &pk).unwrap();
        assert_eq!(encoded, "cordelia_pk16adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdx3ac82ydqlx0asz");
        assert_eq!(encoded.len(), 70);
        let (hrp, decoded) = bech32_decode(&encoded).unwrap();
        assert_eq!(hrp, HRP_PUBLIC_KEY);
        assert_eq!(decoded, pk);
    }

    /// TV-B2: Ed25519 seed.
    #[test]
    fn test_tv_b2_secret_key() {
        let sk = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let encoded = bech32_encode(HRP_SECRET_KEY, &sk).unwrap();
        assert_eq!(encoded, "cordelia_sk1n4smr800l4dxpw5yft6f9mpvc3zyn3tf0vexjxts8wkqx89w0asqcef9k6");
        assert_eq!(encoded.len(), 70);
    }

    /// TV-B3: X25519 public key.
    #[test]
    fn test_tv_b3_x25519_key() {
        let xpk = hex::decode("d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e").unwrap();
        let encoded = bech32_encode(HRP_X25519_PK, &xpk).unwrap();
        assert_eq!(encoded, "cordelia_xpk1mp0q0mpzkzkcs9fhct6y6e3drg2re7psc4av5sc9mpw84y8kkchqsefgnd");
        assert_eq!(encoded.len(), 71);
    }

    /// TV-B4: Ed25519 signature (122 chars, exceeds BIP-173 90-char limit).
    #[test]
    fn test_tv_b4_signature() {
        let sig = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
        let encoded = bech32_encode(HRP_SIGNATURE, &sig).unwrap();
        assert_eq!(encoded, "cordelia_sig1u4tyxqxrvzk89yyxutxgqm5z32zgwlc7hrjajaxcw0sx2gjfq924lwyzzkg2xwavcc0rjuqulx6xh5jm7hc9jka7y3j4zs2r3eapqzcjyfx4e");
        assert_eq!(encoded.len(), 122);
    }

    /// TV-B5: Channel PSK.
    #[test]
    fn test_tv_b5_psk() {
        let psk = hex::decode("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2").unwrap();
        let encoded = bech32_encode(HRP_PSK, &psk).unwrap();
        assert_eq!(encoded, "cordelia_psk15xev848976nm3jwsu8e28dx96mnl32dsc8fw8a99kmra360s5xeq6lzazn");
        assert_eq!(encoded.len(), 71);
    }

    /// TV-B6: Invalid checksum must be rejected.
    #[test]
    fn test_tv_b6_invalid_checksum() {
        let result = bech32_decode("cordelia_pk16adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdx3ac82ydqlx0asq");
        assert!(result.is_err());
    }

    /// TV-B7: Unknown HRP must be rejected.
    #[test]
    fn test_tv_b7_unknown_hrp() {
        let result = bech32_decode("cordelia_foo16adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdx3ac82ydqpdgfjj");
        assert!(result.is_err());
    }
}
