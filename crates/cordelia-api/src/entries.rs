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
//! conflicts. An item at a lower revision is not returned, though it too
//! may have been written without sight of the winner. A reader that
//! minds says so itself: the sync adapter has each of its entries say
//! what it was written after (`Write::after`, decision 2026-09-30 §4.5).

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
    /// What the writer says this revision was written after, carried
    /// beside the content and sealed with it, for a delete as for a
    /// text. `None` puts no such member in the entry. Only the sync
    /// adapter sets it, and only its readers take anything from it
    /// (decision 2026-09-30 §4.5).
    pub after: Option<&'a Value>,
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
    /// The `after` member the writer put beside the content, as it was
    /// written. `None` where there is none, or it is `null`.
    pub after: Option<Value>,
    pub item_type: String,
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
/// the highest this node holds for the slot from the channel's members. A
/// tombstone revision (`deleted`) records that the key was deleted (§4.4).
pub fn publish(
    state: &AppState,
    db: &Connection,
    channel_id: &str,
    write: &Write,
) -> Result<Published, CordeliaError> {
    publish_at(state, db, channel_id, write, None)
}

/// [`publish`], at a given revision when `at` is set.
fn publish_at(
    state: &AppState,
    db: &Connection,
    channel_id: &str,
    write: &Write,
    at: Option<u64>,
) -> Result<Published, CordeliaError> {
    let Write {
        key,
        content,
        metadata,
        item_type,
        deleted,
        after,
    } = *write;
    validate_key(key)?;
    let pk = state.identity.public_key();
    if !channels::is_member(db, channel_id, &pk)? {
        return Err(CordeliaError::NotAuthorised {
            context: "not a member of this channel".into(),
        });
    }

    let slot = slot_id(&slot_key(state, channel_id)?, key);
    let rev = match at {
        Some(rev) => rev,
        None => items::max_rev(db, channel_id, &slot)?.unwrap_or(0) + 1,
    };
    if rev > cordelia_core::protocol::MAX_REV {
        return Err(CordeliaError::Validation(format!(
            "{key} has reached the revision limit and cannot be written again in this channel"
        )));
    }
    let channel = channels::get_by_id(db, channel_id)?;

    let mut envelope = serde_json::json!({
        "key": key,
        "content": if deleted { Value::Null } else { content.clone() },
        "metadata": if deleted { None } else { metadata.cloned() },
    });
    if let Some(after) = after {
        envelope["after"] = after.clone();
    }
    let plaintext =
        serde_json::to_vec(&envelope).map_err(|e| CordeliaError::Internal(e.to_string()))?;
    // Checked here as well as by every node that carries it: the entry as
    // it travels is its content plus what sealing adds.
    let sealed_len = plaintext.len() + cordelia_core::protocol::ITEM_SEAL_OVERHEAD_BYTES;
    if sealed_len > cordelia_core::protocol::MAX_ITEM_BYTES {
        return Err(CordeliaError::TooLarge {
            bytes: sealed_len,
            limit: cordelia_core::protocol::MAX_ITEM_BYTES,
        });
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

/// What a reader needs to tell which stored items of a channel count.
struct Reading<'a> {
    state: &'a AppState,
    key_version: i64,
    slot_key: [u8; 32],
    members: Vec<[u8; 32]>,
}

impl<'a> Reading<'a> {
    fn of(state: &'a AppState, db: &Connection, channel_id: &str) -> Result<Self, CordeliaError> {
        let pk = state.identity.public_key();
        if !channels::is_member(db, channel_id, &pk)? {
            return Err(CordeliaError::NotAuthorised {
                context: "not a member of this channel".into(),
            });
        }
        Ok(Self {
            state,
            key_version: channels::get_by_id(db, channel_id)?.key_version,
            slot_key: slot_key(state, channel_id)?,
            members: channels::list_active_member_keys(db, channel_id)?,
        })
    }

    /// `item` as a version of the key it names, if it counts: it is signed
    /// by an active member, decrypts under the key version it claims, and
    /// names a key that maps back to the slot it is stored under.
    fn version(&self, item: &StoredItem) -> Option<(Vec<u8>, String, Version)> {
        let (slot, rev) = (item.slot.as_ref()?, item.rev?);
        let author = <[u8; 32]>::try_from(item.author_id.as_slice()).ok()?;
        if !self.members.contains(&author) || !verify_item_signature(item) {
            return None;
        }
        let envelope = decrypt(self.state, self.key_version, item)?;
        let key = envelope.get("key").and_then(Value::as_str)?;
        // The key inside must map back to the slot it was stored under.
        if slot_id(&self.slot_key, key).as_slice() != slot.as_slice() {
            return None;
        }
        let version = Version {
            item_id: item.item_id.clone(),
            author,
            rev,
            published_at: item.published_at.clone(),
            deleted: item.is_tombstone,
            content: envelope.get("content").cloned().unwrap_or(Value::Null),
            metadata: envelope.get("metadata").cloned().filter(|m| !m.is_null()),
            after: envelope.get("after").cloned().filter(|a| !a.is_null()),
            item_type: item.item_type.clone(),
            content_hash: item.content_hash.clone(),
        };
        Some((slot.clone(), key.to_string(), version))
    }
}

/// The current value among the versions of one key, with any concurrent
/// ones: highest revision first, ties to the higher content hash.
/// `versions` is not empty.
fn resolve(key: String, mut versions: Vec<Version>) -> Entry {
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
}

/// Each key's current value in `channel_id` (§4.3 resolution), sorted by key.
pub fn current(
    state: &AppState,
    db: &Connection,
    channel_id: &str,
) -> Result<Vec<Entry>, CordeliaError> {
    let reading = Reading::of(state, db, channel_id)?;

    // slot -> (key, versions)
    let mut slots: std::collections::BTreeMap<Vec<u8>, (String, Vec<Version>)> =
        std::collections::BTreeMap::new();
    for item in items::slotted_items(db, channel_id)? {
        let Some((slot, key, version)) = reading.version(&item) else {
            continue;
        };
        slots
            .entry(slot)
            .or_insert_with(|| (key, Vec::new()))
            .1
            .push(version);
    }

    let mut entries: Vec<Entry> = slots
        .into_values()
        .map(|(key, versions)| resolve(key, versions))
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(entries)
}

/// The current value of one key in `channel_id`, resolved as [`current`]
/// resolves every key, reading that key's slot and no other. `None` when
/// nothing that counts is stored for it.
pub fn current_of(
    state: &AppState,
    db: &Connection,
    channel_id: &str,
    key: &str,
) -> Result<Option<Entry>, CordeliaError> {
    let reading = Reading::of(state, db, channel_id)?;
    let slot = slot_id(&reading.slot_key, key);
    let versions: Vec<Version> = items::slot_items(db, channel_id, &slot)?
        .iter()
        .filter_map(|item| reading.version(item))
        .map(|(_, _, version)| version)
        .collect();
    Ok((!versions.is_empty()).then(|| resolve(key.to_string(), versions)))
}

/// Publish again, under this device's name, every key in `channel_id` whose
/// current value was written by `leaving`: its content, or its delete.
/// Returns how many were published.
///
/// Called by the device that removes `leaving` from the channel, just
/// before it does, while `leaving`'s entries still count. Once it is
/// removed they count for nothing, so without this the channel would go
/// back to whatever the others last wrote: a file it edited would revert
/// for a new device, and a file it deleted would come back.
///
/// Each entry is published at the revision `leaving` gave it, so it takes
/// that entry's place exactly: a device that already holds the entry has
/// the same text at the same revision, and changes no file for it; one
/// that is behind sees a newer revision. Two cases differ:
///
/// - This device already has a revision that high for the key (it lost a
///   tie to `leaving`): the next one up is used.
/// - `leaving`'s revision is in the upper half of the range, which editing
///   never reaches. That is an attempt to use the numbers up. The entry is
///   published at the next revision after the remaining members' instead,
///   which keeps its content and gives the name its revisions back.
///
/// A key that cannot be published again (it has grown past a limit, say)
/// is skipped with a warning; the removal goes ahead.
pub fn take_over(
    state: &AppState,
    db: &Connection,
    channel_id: &str,
    leaving: &[u8; 32],
) -> Result<usize, CordeliaError> {
    let pk = state.identity.public_key();
    let slot_key = slot_key(state, channel_id)?;
    let mut taken = 0;
    for entry in current(state, db, channel_id)? {
        if &entry.current.author != leaving {
            continue;
        }
        let slot = slot_id(&slot_key, &entry.key);
        let own = items::author_rev(db, channel_id, &slot, &pk)?;
        let at = if entry.current.rev > cordelia_core::protocol::MAX_REV / 2 {
            let others = items::max_rev_except(db, channel_id, &slot, leaving)?;
            others.unwrap_or(0) + 1
        } else {
            entry.current.rev.max(own.map_or(0, |rev| rev + 1))
        };
        let write = Write {
            key: &entry.key,
            content: &entry.current.content,
            metadata: entry.current.metadata.as_ref(),
            item_type: &entry.current.item_type,
            deleted: entry.current.deleted,
            // Not carried over from the entry this takes the place of:
            // this device did not write the text over anything. A reader
            // takes an entry without it by its revision alone, as before.
            after: None,
        };
        match publish_at(state, db, channel_id, &write, Some(at)) {
            Ok(_) => taken += 1,
            Err(e) => tracing::warn!(
                channel = %channel_id,
                error = %e,
                "could not publish again an entry that a removed device last wrote"
            ),
        }
    }
    Ok(taken)
}
