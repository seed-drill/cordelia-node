//! CBOR deterministic signing for item metadata envelopes.
//!
//! Signs a CBOR-encoded metadata map with Ed25519. The signature covers
//! all fields except the signature itself. Map keys are sorted per
//! RFC 8949 §4.2.1 (encoded byte length first, then lexicographic).
//!
//! Spec: seed-drill/specs/ecies-envelope-encryption.md §11

use crate::identity::NodeIdentity;
use crate::CryptoError;

/// Sign a CBOR-encoded payload with the node's Ed25519 key.
///
/// The caller is responsible for producing deterministic CBOR encoding
/// (sorted map keys per RFC 8949 §4.2.1). This function signs the
/// raw bytes as provided.
pub fn sign_cbor(identity: &NodeIdentity, cbor_payload: &[u8]) -> [u8; 64] {
    identity.sign(cbor_payload)
}

/// Verify a CBOR payload signature against a public key.
pub fn verify_cbor(
    public_key: &[u8; 32],
    cbor_payload: &[u8],
    signature: &[u8; 64],
) -> bool {
    crate::identity::verify_signature(public_key, cbor_payload, signature)
}

/// Encode a metadata map to deterministic CBOR bytes.
///
/// Keys are sorted by encoded byte length first, then lexicographic
/// (RFC 8949 §4.2.1). This matches ciborium's default map encoding
/// when keys are pre-sorted.
///
/// Fields for item metadata envelope (ECIES spec §11.7):
///   author_id, channel_id, content_hash, is_tombstone,
///   item_id, key_version, published_at
pub fn encode_metadata_envelope(fields: &[(&str, ciborium::Value)]) -> Result<Vec<u8>, CryptoError> {
    // Sort keys per RFC 8949 §4.2.1: by encoded byte length, then lexicographic
    let mut sorted: Vec<_> = fields.iter().collect();
    sorted.sort_by(|a, b| {
        let a_len = a.0.len();
        let b_len = b.0.len();
        a_len.cmp(&b_len).then_with(|| a.0.cmp(b.0))
    });

    let map: Vec<(ciborium::Value, ciborium::Value)> = sorted
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Text(k.to_string()), v.clone()))
        .collect();

    let value = ciborium::Value::Map(map);
    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf)
        .map_err(|e| CryptoError::SigningError(format!("CBOR encoding failed: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_cbor() {
        let id = NodeIdentity::generate().unwrap();

        let fields = [
            ("item_id", ciborium::Value::Text("ci_test123".into())),
            ("channel_id", ciborium::Value::Text("abc123".into())),
            ("key_version", ciborium::Value::Integer(1.into())),
        ];

        let cbor = encode_metadata_envelope(&fields).unwrap();
        let sig = sign_cbor(&id, &cbor);
        assert!(verify_cbor(&id.public_key(), &cbor, &sig));

        // Tampered payload fails
        let mut tampered = cbor.clone();
        tampered[0] ^= 0xff;
        assert!(!verify_cbor(&id.public_key(), &tampered, &sig));
    }

    #[test]
    fn test_deterministic_encoding() {
        // Same fields in different order should produce same CBOR
        let fields_a = [
            ("channel_id", ciborium::Value::Text("ch1".into())),
            ("item_id", ciborium::Value::Text("it1".into())),
            ("key_version", ciborium::Value::Integer(1.into())),
        ];

        let fields_b = [
            ("key_version", ciborium::Value::Integer(1.into())),
            ("item_id", ciborium::Value::Text("it1".into())),
            ("channel_id", ciborium::Value::Text("ch1".into())),
        ];

        let cbor_a = encode_metadata_envelope(&fields_a).unwrap();
        let cbor_b = encode_metadata_envelope(&fields_b).unwrap();
        assert_eq!(cbor_a, cbor_b);
    }

    #[test]
    fn test_key_sort_order() {
        // RFC 8949 §4.2.1: shorter keys first, then lexicographic
        let fields = [
            ("published_at", ciborium::Value::Text("2026-03-12T00:00:00Z".into())),
            ("item_id", ciborium::Value::Text("ci_test".into())),
            ("author_id", ciborium::Value::Bytes(vec![0u8; 32])),
            ("channel_id", ciborium::Value::Text("abc".into())),
            ("content_hash", ciborium::Value::Bytes(vec![0u8; 32])),
            ("is_tombstone", ciborium::Value::Bool(false)),
            ("key_version", ciborium::Value::Integer(1.into())),
        ];

        let cbor = encode_metadata_envelope(&fields).unwrap();

        // Decode and verify key order
        let decoded: ciborium::Value =
            ciborium::from_reader(cbor.as_slice()).unwrap();
        if let ciborium::Value::Map(entries) = decoded {
            let keys: Vec<String> = entries
                .iter()
                .map(|(k, _)| {
                    if let ciborium::Value::Text(s) = k {
                        s.clone()
                    } else {
                        panic!("expected text key")
                    }
                })
                .collect();

            // Sorted by length then alpha:
            // 7: item_id
            // 9: author_id
            // 10: channel_id
            // 11: key_version
            // 12: content_hash, is_tombstone, published_at
            assert_eq!(
                keys,
                vec![
                    "item_id",
                    "author_id",
                    "channel_id",
                    "key_version",
                    "content_hash",
                    "is_tombstone",
                    "published_at",
                ]
            );
        } else {
            panic!("expected CBOR map");
        }
    }
}
