//! Item signature verification, shared by the listen/search handlers and
//! invite processing.

use cordelia_crypto::signing;
use cordelia_storage::items::StoredItem;

/// Verify an item's Ed25519 signature over its CBOR metadata envelope
/// (ecies-envelope-encryption.md §11.7). The envelope commits to the
/// author, channel, content hash, tombstone flag, item ID, key version and
/// publication time, so none of them can be altered without detection.
pub fn verify_item_signature(item: &StoredItem) -> bool {
    let (Ok(author), Ok(content_hash), Ok(sig)) = (
        <[u8; 32]>::try_from(item.author_id.as_slice()),
        <[u8; 32]>::try_from(item.content_hash.as_slice()),
        <[u8; 64]>::try_from(item.signature.as_slice()),
    ) else {
        return false;
    };

    let Ok(cbor) = signing::build_item_metadata_envelope(
        &author,
        &item.channel_id,
        &content_hash,
        item.is_tombstone,
        &item.item_id,
        item.key_version,
        &item.published_at,
    ) else {
        return false;
    };

    cordelia_crypto::identity::verify_signature(&author, &cbor, &sig)
}
