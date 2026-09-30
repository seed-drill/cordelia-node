//! Replaceable-item slots (decision 2026-09-30-agent-memory-sync §4.3).
//!
//! A slot names "the current version of this key" without revealing the
//! key: `slot = HMAC-SHA256(slot_key, "cordelia:slot:v1:" || key)`. Relays
//! can match revisions of the same slot but learn nothing about the key.
//! The channel's slot key is random, shared with members in channel
//! states, and never rotated.

use ring::hmac;

const SLOT_DOMAIN: &[u8] = b"cordelia:slot:v1:";

/// Derive the slot for `logical_key` in a channel with `slot_key`.
pub fn slot_id(slot_key: &[u8; 32], logical_key: &str) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, slot_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(SLOT_DOMAIN);
    ctx.update(logical_key.as_bytes());
    let tag = ctx.sign();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// AES-GCM associated data for an item: the channel ID, plus the slot and
/// big-endian revision for a replaceable item. Binding them means an item
/// cannot be moved to another channel or slot, or presented as another
/// revision, without failing to decrypt.
pub fn item_aad(channel_id: &str, slot: Option<&[u8]>, rev: Option<u64>) -> Vec<u8> {
    let mut aad = channel_id.as_bytes().to_vec();
    if let (Some(slot), Some(rev)) = (slot, rev) {
        aad.extend_from_slice(slot);
        aad.extend_from_slice(&rev.to_be_bytes());
    }
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_id_is_keyed_and_deterministic() {
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        assert_eq!(slot_id(&k1, "notes.md"), slot_id(&k1, "notes.md"));
        assert_ne!(slot_id(&k1, "notes.md"), slot_id(&k1, "notes2.md"));
        assert_ne!(
            slot_id(&k1, "notes.md"),
            slot_id(&k2, "notes.md"),
            "without the slot key, slots reveal nothing about keys"
        );
    }

    #[test]
    fn test_slot_id_vector() {
        // HMAC-SHA256(key = 0x00 * 32, "cordelia:slot:v1:MEMORY.md"), computed
        // independently (Python hmac), so other implementations can check
        // themselves against it.
        assert_eq!(
            hex::encode(slot_id(&[0u8; 32], "MEMORY.md")),
            "3c00145946c6dbac2bc3b99a5990c91966f2bf24c6fabeca42bd46362d90e168"
        );
    }

    #[test]
    fn test_aad_binds_slot_and_rev() {
        let psk = [0x33u8; 32];
        let slot = [0x44u8; 32];
        let aad = item_aad("grp_x", Some(&slot), Some(2));
        let blob = crate::item_encrypt(&psk, b"hello", &aad).unwrap();

        assert!(crate::item_decrypt(&psk, &blob, &aad).is_ok());
        for wrong in [
            item_aad("grp_x", Some(&slot), Some(3)),
            item_aad("grp_x", Some(&[0x45; 32]), Some(2)),
            item_aad("grp_y", Some(&slot), Some(2)),
            item_aad("grp_x", None, None),
        ] {
            assert!(crate::item_decrypt(&psk, &blob, &wrong).is_err());
        }
        // Ordinary items keep the original associated data.
        assert_eq!(item_aad("grp_x", None, None), b"grp_x".to_vec());
    }
}
