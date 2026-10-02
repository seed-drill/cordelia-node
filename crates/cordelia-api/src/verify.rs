//! Item signature verification, shared by the listen/search handlers and
//! invite processing.

use cordelia_crypto::signing;
use cordelia_storage::items::StoredItem;

/// Verify an item's Ed25519 signature over its CBOR metadata envelope
/// (ecies-envelope-encryption.md §11.7). The envelope commits to the
/// author, channel, content hash, tombstone flag, item ID, key version,
/// publication time, and a replaceable item's slot and revision, so none of
/// them can be altered without detection. A revision over the limit is not
/// valid whoever signed it.
pub fn verify_item_signature(item: &StoredItem) -> bool {
    let (Ok(author), Ok(content_hash), Ok(sig)) = (
        <[u8; 32]>::try_from(item.author_id.as_slice()),
        <[u8; 32]>::try_from(item.content_hash.as_slice()),
        <[u8; 64]>::try_from(item.signature.as_slice()),
    ) else {
        return false;
    };

    let slot: Option<[u8; 32]> = match &item.slot {
        None => None,
        Some(s) => match <[u8; 32]>::try_from(s.as_slice()) {
            Ok(s) => Some(s),
            Err(_) => return false,
        },
    };
    if slot.is_some() != item.rev.is_some() {
        return false;
    }
    if item
        .rev
        .is_some_and(|rev| rev > cordelia_core::protocol::MAX_REV)
    {
        return false;
    }
    let Ok(cbor) = signing::ItemMetadata {
        author_id: &author,
        channel_id: &item.channel_id,
        content_hash: &content_hash,
        is_tombstone: item.is_tombstone,
        item_id: &item.item_id,
        key_version: item.key_version,
        published_at: &item.published_at,
        slot: slot.as_ref(),
        rev: item.rev,
    }
    .encode() else {
        return false;
    };

    cordelia_crypto::identity::verify_signature(&author, &cbor, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(id: &cordelia_crypto::NodeIdentity, rev: u64) -> StoredItem {
        let (author, slot, hash) = (id.public_key(), [0x5A; 32], [0x07; 32]);
        let cbor = signing::ItemMetadata {
            author_id: &author,
            channel_id: "grp_x",
            content_hash: &hash,
            is_tombstone: false,
            item_id: "ci_sig",
            key_version: 1,
            published_at: "2026-10-02T00:00:00Z",
            slot: Some(&slot),
            rev: Some(rev),
        }
        .encode()
        .unwrap();
        StoredItem {
            item_id: "ci_sig".into(),
            channel_id: "grp_x".into(),
            author_id: author.to_vec(),
            item_type: "memory".into(),
            published_at: "2026-10-02T00:00:00Z".into(),
            is_tombstone: false,
            parent_id: None,
            key_version: 1,
            content_hash: hash.to_vec(),
            signature: id.sign(&cbor).to_vec(),
            encrypted_blob: Vec::new(),
            seq: 0,
            slot: Some(slot.to_vec()),
            rev: Some(rev),
        }
    }

    /// T2. A revision over the limit does not verify, even with a good
    /// signature, so it is never read as a channel's current value.
    #[test]
    fn a_revision_over_the_limit_does_not_verify() {
        use cordelia_core::protocol::MAX_REV;
        let id = cordelia_crypto::NodeIdentity::generate().unwrap();

        assert!(verify_item_signature(&signed(&id, MAX_REV)));
        for rev in [MAX_REV + 1, i64::MAX as u64, u64::MAX] {
            assert!(!verify_item_signature(&signed(&id, rev)), "{rev}");
        }
    }
}
