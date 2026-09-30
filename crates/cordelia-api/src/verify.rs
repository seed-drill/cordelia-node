//! Item signature verification, shared by the listen/search handlers and
//! invite processing.

use cordelia_crypto::signing;
use cordelia_storage::items::StoredItem;

/// Verify an item's Ed25519 signature over its CBOR metadata envelope
/// (ecies-envelope-encryption.md §11.7). The envelope commits to the
/// author, channel, content hash, tombstone flag, item ID, key version,
/// publication time, and a replaceable item's slot and revision, so none of
/// them can be altered without detection.
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
