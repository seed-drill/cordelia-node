//! CBOR PSK envelope wrapper per data-formats.md §4.2.
//!
//! PSK envelope items use `key_version = 0` to signal that `encrypted_blob`
//! is NOT AES-encrypted with the channel PSK. Instead, the blob is a CBOR
//! structure containing the ECIES envelope, the PSK version being distributed,
//! and the recipient's X25519 public key.
//!
//! Format:
//! ```cbor
//! {
//!   "envelope":      h'<92 bytes>',   -- ECIES binary envelope
//!   "key_version":   <integer>,       -- PSK version (>= 1)
//!   "recipient_xpk": h'<32 bytes>'   -- recipient X25519 public key
//! }
//! ```

use crate::CryptoError;

/// Encode a PSK envelope blob as CBOR per data-formats.md §4.2.
///
/// - `ecies_envelope`: raw ECIES envelope bytes (92 bytes for 32-byte PSK)
/// - `key_version`: the PSK version being distributed (>= 1)
/// - `recipient_xpk`: recipient's X25519 public key (32 bytes)
pub fn encode_psk_envelope(
    ecies_envelope: &[u8],
    key_version: i64,
    recipient_xpk: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    use ciborium::Value;

    // Deterministic CBOR: keys sorted lexicographically (RFC 8949 §4.2.1)
    // "envelope" < "key_version" < "recipient_xpk"
    let map = Value::Map(vec![
        (
            Value::Text("envelope".into()),
            Value::Bytes(ecies_envelope.to_vec()),
        ),
        (
            Value::Text("key_version".into()),
            Value::Integer(key_version.into()),
        ),
        (
            Value::Text("recipient_xpk".into()),
            Value::Bytes(recipient_xpk.to_vec()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf)
        .map_err(|e| CryptoError::EncryptionFailed(format!("CBOR encoding failed: {e}")))?;
    Ok(buf)
}

/// Decoded PSK envelope fields.
pub struct PskEnvelopeFields {
    /// Raw ECIES envelope bytes (92 bytes for 32-byte PSK).
    pub envelope: Vec<u8>,
    /// PSK version being distributed.
    pub key_version: i64,
    /// Recipient's X25519 public key (32 bytes).
    pub recipient_xpk: [u8; 32],
}

/// Decode a CBOR PSK envelope blob per data-formats.md §4.2.
pub fn decode_psk_envelope(cbor_bytes: &[u8]) -> Result<PskEnvelopeFields, CryptoError> {
    use ciborium::Value;

    let value: Value =
        ciborium::from_reader(cbor_bytes).map_err(|_e| CryptoError::DecryptionFailed)?;

    let map = match value {
        Value::Map(m) => m,
        _ => return Err(CryptoError::DecryptionFailed),
    };

    let mut envelope = None;
    let mut key_version = None;
    let mut recipient_xpk = None;

    for (k, v) in &map {
        match k {
            Value::Text(s) if s == "envelope" => {
                if let Value::Bytes(b) = v {
                    envelope = Some(b.clone());
                }
            }
            Value::Text(s) if s == "key_version" => {
                if let Value::Integer(i) = v {
                    key_version = Some(i128::from(*i) as i64);
                }
            }
            Value::Text(s) if s == "recipient_xpk" => {
                if let Value::Bytes(b) = v
                    && b.len() == 32
                {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    recipient_xpk = Some(arr);
                }
            }
            _ => {}
        }
    }

    Ok(PskEnvelopeFields {
        envelope: envelope.ok_or(CryptoError::DecryptionFailed)?,
        key_version: key_version.ok_or(CryptoError::DecryptionFailed)?,
        recipient_xpk: recipient_xpk.ok_or(CryptoError::DecryptionFailed)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let envelope_bytes = [0xAAu8; 92]; // mock ECIES envelope
        let recipient = [0xBBu8; 32];

        let cbor = encode_psk_envelope(&envelope_bytes, 3, &recipient).unwrap();

        let decoded = decode_psk_envelope(&cbor).unwrap();
        assert_eq!(decoded.envelope, envelope_bytes);
        assert_eq!(decoded.key_version, 3);
        assert_eq!(decoded.recipient_xpk, recipient);
    }

    #[test]
    fn test_key_version_1() {
        let envelope_bytes = [0x42u8; 92];
        let recipient = [0x01u8; 32];

        let cbor = encode_psk_envelope(&envelope_bytes, 1, &recipient).unwrap();
        let decoded = decode_psk_envelope(&cbor).unwrap();
        assert_eq!(decoded.key_version, 1);
    }

    #[test]
    fn test_deterministic_encoding() {
        let envelope_bytes = [0x42u8; 92];
        let recipient = [0x01u8; 32];

        let cbor1 = encode_psk_envelope(&envelope_bytes, 1, &recipient).unwrap();
        let cbor2 = encode_psk_envelope(&envelope_bytes, 1, &recipient).unwrap();
        assert_eq!(cbor1, cbor2);
    }

    #[test]
    fn test_invalid_cbor_fails() {
        assert!(decode_psk_envelope(&[0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_missing_field_fails() {
        use ciborium::Value;
        // Only envelope + key_version, missing recipient_xpk
        let map = Value::Map(vec![
            (Value::Text("envelope".into()), Value::Bytes(vec![0u8; 92])),
            (Value::Text("key_version".into()), Value::Integer(1.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        assert!(decode_psk_envelope(&buf).is_err());
    }
}
