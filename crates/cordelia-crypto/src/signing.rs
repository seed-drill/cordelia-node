//! CBOR deterministic signing for item metadata envelopes.
//!
//! Signs a CBOR-encoded metadata map with Ed25519. The signature covers
//! all fields except the signature itself. Map keys are sorted per
//! RFC 8949 §4.2.1 (encoded byte length first, then lexicographic).
//!
//! Spec: seed-drill/specs/ecies-envelope-encryption.md §11

use crate::CryptoError;
use crate::identity::NodeIdentity;

/// Sign a CBOR-encoded payload with the node's Ed25519 key.
///
/// The caller is responsible for producing deterministic CBOR encoding
/// (sorted map keys per RFC 8949 §4.2.1). This function signs the
/// raw bytes as provided.
pub fn sign_cbor(identity: &NodeIdentity, cbor_payload: &[u8]) -> [u8; 64] {
    identity.sign(cbor_payload)
}

/// Verify a CBOR payload signature against a public key.
pub fn verify_cbor(public_key: &[u8; 32], cbor_payload: &[u8], signature: &[u8; 64]) -> bool {
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
pub fn encode_metadata_envelope(
    fields: &[(&str, ciborium::Value)],
) -> Result<Vec<u8>, CryptoError> {
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

/// The signed fields of an item (ECIES spec §11.7), plus the slot and
/// revision of a replaceable item (decision 2026-09-30-agent-memory-sync
/// §4.3). Slot and revision are signed only when present, so the encoding
/// of ordinary items, and test vector TV-C1, are unchanged.
pub struct ItemMetadata<'a> {
    pub author_id: &'a [u8; 32],
    pub channel_id: &'a str,
    pub content_hash: &'a [u8; 32],
    pub is_tombstone: bool,
    pub item_id: &'a str,
    pub key_version: i64,
    pub published_at: &'a str,
    pub slot: Option<&'a [u8; 32]>,
    pub rev: Option<u64>,
}

impl ItemMetadata<'_> {
    /// Deterministic CBOR bytes ready for Ed25519 signing.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let mut fields = vec![
            ("author_id", ciborium::Value::Bytes(self.author_id.to_vec())),
            ("channel_id", ciborium::Value::Text(self.channel_id.into())),
            (
                "content_hash",
                ciborium::Value::Bytes(self.content_hash.to_vec()),
            ),
            ("is_tombstone", ciborium::Value::Bool(self.is_tombstone)),
            ("item_id", ciborium::Value::Text(self.item_id.into())),
            (
                "key_version",
                ciborium::Value::Integer(self.key_version.into()),
            ),
            (
                "published_at",
                ciborium::Value::Text(self.published_at.into()),
            ),
        ];
        if let Some(slot) = self.slot {
            fields.push(("slot", ciborium::Value::Bytes(slot.to_vec())));
        }
        if let Some(rev) = self.rev {
            fields.push(("rev", ciborium::Value::Integer(rev.into())));
        }
        encode_metadata_envelope(&fields)
    }
}

/// Build and encode the item metadata envelope for an ordinary (unslotted)
/// item (ECIES spec §11.7).
///
/// Returns deterministic CBOR bytes ready for Ed25519 signing.
pub fn build_item_metadata_envelope(
    author_id: &[u8; 32],
    channel_id: &str,
    content_hash: &[u8; 32],
    is_tombstone: bool,
    item_id: &str,
    key_version: i64,
    published_at: &str,
) -> Result<Vec<u8>, CryptoError> {
    ItemMetadata {
        author_id,
        channel_id,
        content_hash,
        is_tombstone,
        item_id,
        key_version,
        published_at,
        slot: None,
        rev: None,
    }
    .encode()
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
            (
                "published_at",
                ciborium::Value::Text("2026-03-12T00:00:00Z".into()),
            ),
            ("item_id", ciborium::Value::Text("ci_test".into())),
            ("author_id", ciborium::Value::Bytes(vec![0u8; 32])),
            ("channel_id", ciborium::Value::Text("abc".into())),
            ("content_hash", ciborium::Value::Bytes(vec![0u8; 32])),
            ("is_tombstone", ciborium::Value::Bool(false)),
            ("key_version", ciborium::Value::Integer(1.into())),
        ];

        let cbor = encode_metadata_envelope(&fields).unwrap();

        // Decode and verify key order
        let decoded: ciborium::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
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

    #[test]
    fn test_slot_and_rev_are_signed() {
        let id = NodeIdentity::generate().unwrap();
        let pk = id.public_key();
        let meta = |slot: Option<&'static [u8; 32]>, rev: Option<u64>| ItemMetadata {
            author_id: &pk,
            channel_id: "grp_x",
            content_hash: &[0x01; 32],
            is_tombstone: false,
            item_id: "ci_1",
            key_version: 1,
            published_at: "2026-09-30T00:00:00Z",
            slot,
            rev,
        };
        static SLOT: [u8; 32] = [0x5A; 32];
        static OTHER: [u8; 32] = [0x5B; 32];

        let signed = meta(Some(&SLOT), Some(2)).encode().unwrap();
        let sig = sign_cbor(&id, &signed);

        // Moving the item to another slot, or replaying it as another
        // revision, breaks the signature.
        let moved = meta(Some(&OTHER), Some(2)).encode().unwrap();
        let bumped = meta(Some(&SLOT), Some(3)).encode().unwrap();
        let unslotted = meta(None, None).encode().unwrap();
        assert!(verify_cbor(&pk, &signed, &sig));
        assert!(!verify_cbor(&pk, &moved, &sig));
        assert!(!verify_cbor(&pk, &bumped, &sig));
        assert!(!verify_cbor(&pk, &unslotted, &sig));

        // Without a slot, the encoding is exactly the original envelope.
        assert_eq!(
            unslotted,
            build_item_metadata_envelope(
                &pk,
                "grp_x",
                &[0x01; 32],
                false,
                "ci_1",
                1,
                "2026-09-30T00:00:00Z"
            )
            .unwrap()
        );
    }

    /// TV-C1 from ecies-envelope-encryption.md §8.6.
    /// Cross-language: TypeScript (cbor-x) must produce identical bytes.
    #[test]
    fn test_tv_c1_item_metadata_envelope() {
        let author_id =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let content_hash =
            hex::decode("355e3caf62b8121affe7a3ae801b20d586968a64e231cde1c0ed7714d4c31184")
                .unwrap();

        let cbor = build_item_metadata_envelope(
            &author_id.try_into().unwrap(),
            "fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6",
            &content_hash.try_into().unwrap(),
            false,
            "ci_a1b2c3d4e5f6",
            1,
            "2026-03-10T19:36:00Z",
        )
        .unwrap();

        let expected = concat!(
            "a7676974656d5f69646f63695f613162326333643465356636",
            "69617574686f725f69645820d75a980182b10ab7d54bfed3c9",
            "64073a0ee172f3daa62325af021a68f707511a6a6368616e6e",
            "656c5f6964784066653032386664616639343363313665633861",
            "31666334393638313832373463653765383665393231616439",
            "3236663937313238383666613236643330396436",
            "6b6b65795f76657273696f6e016c636f6e74656e745f686173",
            "685820355e3caf62b8121affe7a3ae801b20d586968a64e231",
            "cde1c0ed7714d4c311846c69735f746f6d6273746f6e65f4",
            "6c7075626c69736865645f617474323032362d30332d313054",
            "31393a33363a30305a",
        );

        assert_eq!(hex::encode(&cbor), expected);
    }
}
