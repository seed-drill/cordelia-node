//! Keyed (replaceable) items: publishing revisions and resolving each key's
//! current value (decision 2026-09-30-agent-memory-sync §4.3).
//!
//! A keyed item lives in a slot derived from its key with the channel's slot
//! key, so relays see slots, never keys. Each author has at most one stored
//! revision per slot. A reader resolves a slot by considering only items
//! that are signed, authored by an active member of the channel, decrypt
//! under the key version they claim, and name a key that maps back to the
//! slot; the highest revision wins, ties going to the higher content hash.
//! Other items at the winning revision are concurrent edits, returned as
//! conflicts so no one's change is silently lost.

use chrono::Utc;
use rusqlite::Connection;
use serde_json::Value;

use cordelia_core::CordeliaError;
use cordelia_crypto::signing::ItemMetadata;
use cordelia_crypto::slots::{item_aad, slot_id};
use cordelia_storage::items::{self, NewItem, StoredItem};
use cordelia_storage::{channels, psk};

use crate::state::{AppState, PushItem};
use crate::verify::verify_item_signature;

/// Longest key accepted, in bytes. Keys are file paths in v1.
pub const MAX_KEY_BYTES: usize = 1024;

/// A new revision of a key to publish.
pub struct Write<'a> {
    pub key: &'a str,
    pub content: &'a Value,
    pub metadata: Option<&'a Value>,
    pub item_type: &'a str,
    /// Publish a tombstone revision: the key was deleted (§4.4).
    pub deleted: bool,
}

/// A revision just published.
#[derive(Debug, Clone)]
pub struct Published {
    pub item_id: String,
    pub rev: u64,
    pub published_at: String,
}

/// One version of a key, decrypted.
#[derive(Debug, Clone)]
pub struct Version {
    pub item_id: String,
    pub author: [u8; 32],
    pub rev: u64,
    pub published_at: String,
    pub deleted: bool,
    pub content: Value,
    pub metadata: Option<Value>,
    content_hash: Vec<u8>,
}

/// A key's current value, plus any concurrent versions at the same revision.
#[derive(Debug, Clone)]
pub struct Entry {
    pub key: String,
    pub current: Version,
    pub conflicts: Vec<Version>,
}

fn crypto_err(e: cordelia_crypto::CryptoError) -> CordeliaError {
    CordeliaError::Crypto(e.to_string())
}

fn validate_key(key: &str) -> Result<(), CordeliaError> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES || key.contains('\0') {
        return Err(CordeliaError::Validation(format!(
            "key must be 1-{MAX_KEY_BYTES} bytes with no NUL characters"
        )));
    }
    Ok(())
}

/// Read the channel's slot key.
fn slot_key(state: &AppState, channel_id: &str) -> Result<[u8; 32], CordeliaError> {
    psk::read_slot_key(&state.home_dir, channel_id).map_err(|_| {
        CordeliaError::Validation(format!(
            "channel {channel_id} has no slot key; keyed items need a group channel"
        ))
    })
}

/// Publish a new revision of `key` in `channel_id`: the next revision after
/// the highest this node holds for the slot, from any author. A tombstone
/// revision (`deleted`) records that the key was deleted (§4.4).
pub fn publish(
    state: &AppState,
    db: &Connection,
    channel_id: &str,
    write: &Write,
) -> Result<Published, CordeliaError> {
    let Write {
        key,
        content,
        metadata,
        item_type,
        deleted,
    } = *write;
    validate_key(key)?;
    let pk = state.identity.public_key();
    if !channels::is_member(db, channel_id, &pk)? {
        return Err(CordeliaError::NotAuthorised {
            context: "not a member of this channel".into(),
        });
    }

    let slot = slot_id(&slot_key(state, channel_id)?, key);
    let rev = items::max_rev(db, channel_id, &slot)?.unwrap_or(0) + 1;
    let channel = channels::get_by_id(db, channel_id)?;

    let plaintext = serde_json::to_vec(&serde_json::json!({
        "key": key,
        "content": if deleted { Value::Null } else { content.clone() },
        "metadata": if deleted { None } else { metadata.cloned() },
    }))
    .map_err(|e| CordeliaError::Internal(e.to_string()))?;
    if plaintext.len() > cordelia_core::protocol::MAX_ITEM_BYTES {
        return Err(CordeliaError::Validation(format!(
            "item is {} bytes; the limit is {}",
            plaintext.len(),
            cordelia_core::protocol::MAX_ITEM_BYTES
        )));
    }

    let channel_key = psk::read_psk(&state.home_dir, channel_id)?;
    let blob = cordelia_crypto::item_encrypt(
        &channel_key,
        &plaintext,
        &item_aad(channel_id, Some(&slot), Some(rev)),
    )
    .map_err(crypto_err)?;

    let item_id = items::generate_item_id();
    let published_at = Utc::now().to_rfc3339();
    let content_hash = cordelia_crypto::sha256(&blob);
    let cbor = ItemMetadata {
        author_id: &pk,
        channel_id,
        content_hash: &content_hash,
        is_tombstone: deleted,
        item_id: &item_id,
        key_version: channel.key_version,
        published_at: &published_at,
        slot: Some(&slot),
        rev: Some(rev),
    }
    .encode()
    .map_err(crypto_err)?;
    let signature = state.identity.sign(&cbor);

    let stored = items::insert_item(
        db,
        &NewItem {
            item_id: &item_id,
            channel_id,
            author_id: &pk,
            item_type,
            published_at: &published_at,
            parent_id: None,
            key_version: channel.key_version,
            content_hash: &content_hash,
            signature: &signature,
            encrypted_blob: &blob,
            is_tombstone: deleted,
            slot: Some(&slot),
            rev: Some(rev),
        },
    )?;
    if !stored {
        return Err(CordeliaError::Internal(
            "revision was not newer than the one stored".into(),
        ));
    }

    if let Some(tx) = &state.push_tx {
        let _ = tx.send(PushItem {
            channel_id: channel_id.to_string(),
            item_id: item_id.clone(),
            encrypted_blob: blob,
            content_hash: content_hash.to_vec(),
            author_id: pk.to_vec(),
            signature: signature.to_vec(),
            key_version: channel.key_version as u32,
            published_at: published_at.clone(),
            item_type: item_type.to_string(),
            is_tombstone: deleted,
            parent_id: None,
            slot: Some(slot.to_vec()),
            rev: Some(rev),
            exclude_peer: None,
        });
    }

    Ok(Published {
        item_id,
        rev,
        published_at,
    })
}

/// Decrypt a stored item with the key version it claims and the associated
/// data it must have been sealed with. Returns the plaintext JSON envelope.
pub fn decrypt(state: &AppState, channel_key_version: i64, item: &StoredItem) -> Option<Value> {
    let key = psk::read_psk_for_version(
        &state.home_dir,
        &item.channel_id,
        item.key_version,
        channel_key_version,
    )
    .ok()?;
    let aad = item_aad(&item.channel_id, item.slot.as_deref(), item.rev);
    let plaintext = cordelia_crypto::item_decrypt(&key, &item.encrypted_blob, &aad).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

/// Each key's current value in `channel_id` (§4.3 resolution), sorted by key.
pub fn current(
    state: &AppState,
    db: &Connection,
    channel_id: &str,
) -> Result<Vec<Entry>, CordeliaError> {
    let pk = state.identity.public_key();
    if !channels::is_member(db, channel_id, &pk)? {
        return Err(CordeliaError::NotAuthorised {
            context: "not a member of this channel".into(),
        });
    }
    let channel = channels::get_by_id(db, channel_id)?;
    let slot_key = slot_key(state, channel_id)?;
    let members = channels::list_active_member_keys(db, channel_id)?;

    // slot -> (key, versions)
    let mut slots: std::collections::BTreeMap<Vec<u8>, (String, Vec<Version>)> =
        std::collections::BTreeMap::new();
    for item in items::slotted_items(db, channel_id)? {
        let (Some(slot), Some(rev)) = (&item.slot, item.rev) else {
            continue;
        };
        let Ok(author) = <[u8; 32]>::try_from(item.author_id.as_slice()) else {
            continue;
        };
        if !members.contains(&author) || !verify_item_signature(&item) {
            continue;
        }
        let Some(envelope) = decrypt(state, channel.key_version, &item) else {
            continue;
        };
        let Some(key) = envelope.get("key").and_then(Value::as_str) else {
            continue;
        };
        // The key inside must map back to the slot it was stored under.
        if slot_id(&slot_key, key).as_slice() != slot.as_slice() {
            continue;
        }
        let version = Version {
            item_id: item.item_id.clone(),
            author,
            rev,
            published_at: item.published_at.clone(),
            deleted: item.is_tombstone,
            content: envelope.get("content").cloned().unwrap_or(Value::Null),
            metadata: envelope.get("metadata").cloned().filter(|m| !m.is_null()),
            content_hash: item.content_hash.clone(),
        };
        slots
            .entry(slot.clone())
            .or_insert_with(|| (key.to_string(), Vec::new()))
            .1
            .push(version);
    }

    let mut entries: Vec<Entry> = slots
        .into_values()
        .map(|(key, mut versions)| {
            // Highest revision first; ties to the higher content hash.
            versions.sort_by(|a, b| (b.rev, &b.content_hash).cmp(&(a.rev, &a.content_hash)));
            let current = versions.remove(0);
            let conflicts = versions
                .into_iter()
                .filter(|v| v.rev == current.rev)
                .collect();
            Entry {
                key,
                current,
                conflicts,
            }
        })
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(entries)
}
