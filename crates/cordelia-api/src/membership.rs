//! Devices, invites, and channel membership (decision
//! 2026-09-30-agent-memory-sync §4.1).
//!
//! Channel keys and member lists travel only as sealed channel states
//! ([`ChannelState`]) published into each member's inbox channel. A node
//! applies a state only if it is newer than the last one it applied (higher
//! epoch, then higher author key) and comes from an owner of the channel;
//! a state for a channel it has never seen is applied only if the sender is
//! trusted, and otherwise waits as a pending invite.
//!
//! Trust is explicit (`add-device`, `accept`) or comes from membership of
//! this node's personal channel, whose members are the person's devices.

use chrono::Utc;
use rusqlite::Connection;

use cordelia_core::CordeliaError;
use cordelia_crypto::channel_state::{ChannelState, MemberRole, StateMember};
use cordelia_crypto::signing;
use cordelia_storage::invites::{self, InviteStatus};
use cordelia_storage::items::{self, StoredItem};
use cordelia_storage::trust::{self, TrustKind};
use cordelia_storage::{channels, meta, naming, psk};

use crate::state::{AppState, PushItem};
use crate::verify::verify_item_signature;

/// Name given to a node's personal channel (local, and inside sealed states).
const PERSONAL_CHANNEL_NAME: &str = "personal";

/// Result of `add_device`.
#[derive(Debug, Clone)]
pub struct AddDeviceOutcome {
    pub personal_channel_id: String,
    /// Channels the device was added to (or re-sent, if already a member).
    pub channels: Vec<String>,
}

/// Result of `remove_device`.
#[derive(Debug, Clone)]
pub struct RemoveDeviceOutcome {
    /// Channels the device was removed from, each with a rotated key.
    pub channels_rotated: Vec<String>,
}

/// Result of processing the inbox.
#[derive(Debug, Clone, Default)]
pub struct InboxSummary {
    /// Channels joined or updated.
    pub applied: Vec<String>,
    pub pending: usize,
    pub superseded: usize,
    pub invalid: usize,
}

/// A device of this person, for display.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub key: [u8; 32],
    pub label: Option<String>,
    pub this_device: bool,
    /// Member of the personal channel.
    pub in_personal_channel: bool,
    /// Explicitly trusted via `add-device` or `accept`.
    pub explicitly_trusted: bool,
}

fn lock(state: &AppState) -> Result<std::sync::MutexGuard<'_, Connection>, CordeliaError> {
    state
        .db
        .lock()
        .map_err(|e| CordeliaError::Internal(format!("db lock: {e}")))
}

fn crypto_err(e: cordelia_crypto::CryptoError) -> CordeliaError {
    CordeliaError::Crypto(e.to_string())
}

/// Create this node's inbox channel if needed, and return its ID. Only
/// personal nodes have inboxes.
pub fn ensure_own_inbox(state: &AppState) -> Result<String, CordeliaError> {
    let db = lock(state)?;
    ensure_own_inbox_locked(state, &db)
}

fn ensure_own_inbox_locked(state: &AppState, db: &Connection) -> Result<String, CordeliaError> {
    let pk = state.identity.public_key();
    let inbox = naming::inbox_channel_id(&pk);
    channels::ensure_inbox(db, &inbox, &pk, true)?;
    Ok(inbox)
}

/// This node's personal channel, if it has one.
fn personal_channel(db: &Connection, pk: &[u8; 32]) -> Result<Option<String>, CordeliaError> {
    let Some(id) = meta::get(db, meta::PERSONAL_CHANNEL_ID)? else {
        return Ok(None);
    };
    Ok(channels::is_member(db, &id, pk)?.then_some(id))
}

/// Return the personal channel, creating it (with this node as its only
/// owner) on first use.
fn ensure_personal_channel(state: &AppState, db: &Connection) -> Result<String, CordeliaError> {
    let pk = state.identity.public_key();
    if let Some(id) = personal_channel(db, &pk)? {
        return Ok(id);
    }

    let key = cordelia_crypto::generate_psk().map_err(crypto_err)?;
    let slot_key = cordelia_crypto::generate_psk().map_err(crypto_err)?;
    let ch = channels::create_group(db, &pk, "realtime", Some(PERSONAL_CHANNEL_NAME), Some(&key))?;
    psk::write_psk(&state.home_dir, &ch.channel_id, &key)?;
    psk::write_slot_key(&state.home_dir, &ch.channel_id, &slot_key)?;
    channels::set_state(
        db,
        &ch.channel_id,
        1,
        &pk,
        1,
        &cordelia_crypto::sha256(&key),
    )?;
    meta::set(db, meta::PERSONAL_CHANNEL_ID, &ch.channel_id)?;
    announce(state, &ch.channel_id);
    tracing::info!(channel = %ch.channel_id, "created personal channel");
    Ok(ch.channel_id)
}

/// Whether invites from `sender` are applied without asking.
fn is_trusted_sender(
    db: &Connection,
    pk: &[u8; 32],
    sender: &[u8; 32],
) -> Result<bool, CordeliaError> {
    if trust::is_trusted(db, sender)? {
        return Ok(true);
    }
    match personal_channel(db, pk)? {
        Some(personal) => channels::is_member(db, &personal, sender),
        None => Ok(false),
    }
}

/// Read a channel's slot key, creating one for channels made before slot
/// keys existed.
fn slot_key(state: &AppState, channel_id: &str) -> Result<[u8; 32], CordeliaError> {
    match psk::read_slot_key(&state.home_dir, channel_id) {
        Ok(k) => Ok(k),
        Err(_) => {
            let k = cordelia_crypto::generate_psk().map_err(crypto_err)?;
            psk::write_slot_key(&state.home_dir, channel_id, &k)?;
            Ok(k)
        }
    }
}

/// Build this node's current view of a channel as a state to send.
fn build_state(
    state: &AppState,
    db: &Connection,
    channel_id: &str,
) -> Result<ChannelState, CordeliaError> {
    let pk = state.identity.public_key();
    let ch = channels::get_by_id(db, channel_id)?;
    let (epoch, _) = channels::epoch(db, channel_id)?;
    let members = channels::list_active_members(db, channel_id)?
        .into_iter()
        .map(|(key, role)| {
            Ok(StateMember {
                key,
                role: MemberRole::parse(&role).map_err(crypto_err)?,
            })
        })
        .collect::<Result<Vec<_>, CordeliaError>>()?;
    let key_version = u32::try_from(ch.key_version)
        .map_err(|_| CordeliaError::Internal("key version out of range".into()))?;

    Ok(ChannelState {
        channel_id: channel_id.to_string(),
        name: ch.channel_name,
        mode: ch.mode,
        creator: ch.creator_id,
        sender: pk,
        epoch,
        key_version,
        keys: psk::export_key_ring(&state.home_dir, channel_id, ch.key_version)?,
        slot_key: slot_key(state, channel_id)?,
        members,
        personal: personal_channel(db, &pk)?.as_deref() == Some(channel_id),
    })
}

/// Seal `cs` to `recipient` and publish it into the recipient's inbox:
/// stored locally (so relays can also pull it) and pushed to hot relays.
fn send_state(
    state: &AppState,
    db: &Connection,
    recipient: &[u8; 32],
    cs: &ChannelState,
) -> Result<(), CordeliaError> {
    let pk = state.identity.public_key();
    let inbox = naming::inbox_channel_id(recipient);
    channels::ensure_inbox(db, &inbox, recipient, false)?;

    let sealed = cs.seal(recipient).map_err(crypto_err)?;
    let item_id = items::generate_item_id();
    let published_at = Utc::now().to_rfc3339();
    let content_hash = cordelia_crypto::sha256(&sealed);
    let cbor = signing::build_item_metadata_envelope(
        &pk,
        &inbox,
        &content_hash,
        false,
        &item_id,
        0,
        &published_at,
    )
    .map_err(crypto_err)?;
    let signature = state.identity.sign(&cbor);

    items::insert_item(
        db,
        &items::NewItem {
            item_id: &item_id,
            channel_id: &inbox,
            author_id: &pk,
            item_type: invites::INVITE_ITEM_TYPE,
            published_at: &published_at,
            parent_id: None,
            key_version: 0,
            content_hash: &content_hash,
            signature: &signature,
            encrypted_blob: &sealed,
            is_tombstone: false,
            slot: None,
            rev: None,
        },
    )?;

    if let Some(tx) = &state.push_tx {
        let _ = tx.send(PushItem {
            channel_id: inbox,
            item_id,
            encrypted_blob: sealed,
            content_hash: content_hash.to_vec(),
            author_id: pk.to_vec(),
            signature: signature.to_vec(),
            key_version: 0,
            published_at,
            item_type: invites::INVITE_ITEM_TYPE.to_string(),
            is_tombstone: false,
            parent_id: None,
            slot: None,
            rev: None,
            exclude_peer: None,
        });
    }
    Ok(())
}

/// Send this node's current state of a channel to every other member.
fn publish_state(
    state: &AppState,
    db: &Connection,
    channel_id: &str,
) -> Result<usize, CordeliaError> {
    let pk = state.identity.public_key();
    let cs = build_state(state, db, channel_id)?;
    let mut sent = 0;
    for member in cs.members.iter().filter(|m| m.key != pk) {
        send_state(state, db, &member.key, &cs)?;
        sent += 1;
    }
    Ok(sent)
}

/// Advance a channel's epoch after a local change, keeping its key state.
fn bump_epoch(state: &AppState, db: &Connection, channel_id: &str) -> Result<u64, CordeliaError> {
    let pk = state.identity.public_key();
    let ch = channels::get_by_id(db, channel_id)?;
    let (epoch, _) = channels::epoch(db, channel_id)?;
    let next = epoch + 1;
    let psk_hash = ch.psk_hash.unwrap_or_else(|| {
        psk::read_psk(&state.home_dir, channel_id)
            .map(|k| cordelia_crypto::sha256(&k).to_vec())
            .unwrap_or_default()
    });
    channels::set_state(db, channel_id, next, &pk, ch.key_version as u32, &psk_hash)?;
    Ok(next)
}

/// Replace a channel's key with a fresh one (new version), keeping the old
/// versions in the ring, and advance the epoch.
fn rotate_key(state: &AppState, db: &Connection, channel_id: &str) -> Result<(), CordeliaError> {
    let pk = state.identity.public_key();
    let ch = channels::get_by_id(db, channel_id)?;
    let (epoch, _) = channels::epoch(db, channel_id)?;
    let new_version = u32::try_from(ch.key_version + 1)
        .map_err(|_| CordeliaError::Internal("key version out of range".into()))?;
    let new_key = cordelia_crypto::generate_psk().map_err(crypto_err)?;

    let mut keys = psk::export_key_ring(&state.home_dir, channel_id, ch.key_version)?;
    keys.push((new_version, new_key));
    psk::install_key_ring(&state.home_dir, channel_id, &keys, new_version)?;
    channels::set_state(
        db,
        channel_id,
        epoch + 1,
        &pk,
        new_version,
        &cordelia_crypto::sha256(&new_key),
    )
}

fn announce(state: &AppState, channel_id: &str) {
    if let Some(tx) = &state.announce_tx {
        let _ = tx.send(channel_id.to_string());
    }
}

/// This node's personal channel, created on first use.
pub fn personal_channel_id(state: &AppState) -> Result<String, CordeliaError> {
    let db = lock(state)?;
    ensure_personal_channel(state, &db)
}

/// Create a group channel owned by this device alone, e.g. for a project's
/// memory. Other devices of the person join only when they have the project
/// themselves, by [`request_join`]; a device that never works on the
/// project never holds its key.
pub fn create_project_group(state: &AppState, name: &str) -> Result<String, CordeliaError> {
    let pk = state.identity.public_key();
    let db = lock(state)?;
    ensure_personal_channel(state, &db)?;

    let key = cordelia_crypto::generate_psk().map_err(crypto_err)?;
    let slot_key = cordelia_crypto::generate_psk().map_err(crypto_err)?;
    let ch = channels::create_group(&db, &pk, "realtime", Some(name), Some(&key))?;
    psk::write_psk(&state.home_dir, &ch.channel_id, &key)?;
    psk::write_slot_key(&state.home_dir, &ch.channel_id, &slot_key)?;
    channels::set_state(
        &db,
        &ch.channel_id,
        1,
        &pk,
        1,
        &cordelia_crypto::sha256(&key),
    )?;
    announce(state, &ch.channel_id);
    tracing::info!(channel = %ch.channel_id, %name, "created channel");
    Ok(ch.channel_id)
}

/// Key prefix of join requests in the personal channel.
const JOIN_PREFIX: &str = "join/";

/// How long after a request was granted this device waits for the
/// invitation before asking again.
const JOIN_RETRY_SECS: i64 = 120;

fn join_key(channel_id: &str, device: &[u8; 32]) -> Result<String, CordeliaError> {
    let device = cordelia_crypto::bech32::encode_public_key(device).map_err(crypto_err)?;
    Ok(format!("{JOIN_PREFIX}{channel_id}/{device}"))
}

/// Ask this person's other devices to add this device to `channel_id` (a
/// project it has found locally). The request is a keyed item in the
/// personal channel, so any owner of the channel can grant it the next time
/// it runs. Returns true if a new request was published: not while one is
/// pending, nor within [`JOIN_RETRY_SECS`] of one being granted.
pub fn request_join(state: &AppState, channel_id: &str) -> Result<bool, CordeliaError> {
    let pk = state.identity.public_key();
    let db = lock(state)?;
    let personal = ensure_personal_channel(state, &db)?;
    let key = join_key(channel_id, &pk)?;

    if let Some(existing) = crate::entries::current(state, &db, &personal)?
        .into_iter()
        .find(|e| e.key == key)
    {
        if !existing.current.deleted {
            return Ok(false); // still pending
        }
        let granted = chrono::DateTime::parse_from_rfc3339(&existing.current.published_at)
            .map(|t| chrono::Utc::now().signed_duration_since(t).num_seconds())
            .unwrap_or(i64::MAX);
        if granted < JOIN_RETRY_SECS {
            return Ok(false); // granted recently; the invitation is on its way
        }
    }

    crate::entries::publish(
        state,
        &db,
        &personal,
        &crate::entries::Write {
            key: &key,
            content: &serde_json::json!({ "channel_id": channel_id }),
            metadata: None,
            item_type: "membership",
            deleted: false,
        },
    )?;
    tracing::info!(channel = %channel_id, "asked this person's other devices to join");
    Ok(true)
}

/// Grant the join requests this device can: for each request in the
/// personal channel made by one of this person's devices, for a channel this
/// device owns, add the requester as an owner and send the new state; then
/// clear the request. A request is honoured only from the device it names
/// (its author), so no device can ask on another's behalf. Returns the
/// number of devices added.
pub fn process_join_requests(state: &AppState) -> Result<usize, CordeliaError> {
    let pk = state.identity.public_key();
    let db = lock(state)?;
    let Some(personal) = personal_channel(&db, &pk)? else {
        return Ok(0);
    };

    let mut added = 0;
    for entry in crate::entries::current(state, &db, &personal)? {
        let Some(rest) = entry.key.strip_prefix(JOIN_PREFIX) else {
            continue;
        };
        if entry.current.deleted {
            continue;
        }
        let requester = entry.current.author;
        let Some((channel_id, _)) = rest.split_once('/') else {
            continue;
        };
        // Honour a request only from the device it names, and only if that
        // device is one of this person's.
        if entry.key != join_key(channel_id, &requester)?
            || requester == pk
            || !channels::is_member(&db, &personal, &requester)?
        {
            continue;
        }
        if channels::get_member_role(&db, channel_id, &pk)?.as_deref() != Some("owner") {
            continue; // another device owns it and will answer
        }
        if !channels::is_member(&db, channel_id, &requester)? {
            channels::add_member(&db, channel_id, &requester, "owner")?;
            bump_epoch(state, &db, channel_id)?;
            publish_state(state, &db, channel_id)?;
            added += 1;
            tracing::info!(channel = %channel_id, "added one of this person's devices to a channel");
        }
        crate::entries::publish(
            state,
            &db,
            &personal,
            &crate::entries::Write {
                key: &entry.key,
                content: &serde_json::Value::Null,
                metadata: None,
                item_type: "membership",
                deleted: true,
            },
        )?;
    }
    Ok(added)
}

/// Add another of this person's devices: trust it, and make it an owner of
/// the personal channel (created if needed), whose new epoch goes to every
/// member. It joins project channels on its own, as it finds those projects
/// locally ([`request_join`]). Re-adding a current member re-sends it the
/// current state.
pub fn add_device(
    state: &AppState,
    device: &[u8; 32],
    label: Option<&str>,
) -> Result<AddDeviceOutcome, CordeliaError> {
    let pk = state.identity.public_key();
    if *device == pk {
        return Err(CordeliaError::Validation(
            "that is this device's own key".into(),
        ));
    }

    let db = lock(state)?;
    ensure_own_inbox_locked(state, &db)?;
    trust::trust(&db, device, TrustKind::Device, label)?;
    let personal_channel_id = ensure_personal_channel(state, &db)?;

    if channels::get_member_role(&db, &personal_channel_id, device)?.as_deref() == Some("owner") {
        let cs = build_state(state, &db, &personal_channel_id)?;
        send_state(state, &db, device, &cs)?;
    } else {
        channels::add_member(&db, &personal_channel_id, device, "owner")?;
        bump_epoch(state, &db, &personal_channel_id)?;
        publish_state(state, &db, &personal_channel_id)?;
    }
    let updated = vec![personal_channel_id.clone()];
    tracing::info!("device added");

    Ok(AddDeviceOutcome {
        personal_channel_id,
        channels: updated,
    })
}

/// Trust another of this person's devices (the one that ran `add-device`
/// for this node), then apply any invites from it that were waiting.
pub fn accept(
    state: &AppState,
    key: &[u8; 32],
    label: Option<&str>,
) -> Result<InboxSummary, CordeliaError> {
    if *key == state.identity.public_key() {
        return Err(CordeliaError::Validation(
            "that is this device's own key".into(),
        ));
    }
    {
        let db = lock(state)?;
        ensure_own_inbox_locked(state, &db)?;
        trust::trust(&db, key, TrustKind::Device, label)?;
    }
    process_inbox(state)
}

/// Remove one of this person's devices: revoke trust, remove it from every
/// group channel this node owns, and rotate each of those channels' keys so
/// it cannot read anything written afterwards.
pub fn remove_device(
    state: &AppState,
    device: &[u8; 32],
) -> Result<RemoveDeviceOutcome, CordeliaError> {
    let pk = state.identity.public_key();
    if *device == pk {
        return Err(CordeliaError::Validation(
            "cannot remove this device from itself".into(),
        ));
    }

    let db = lock(state)?;
    trust::revoke(&db, device)?;

    let mut rotated = Vec::new();
    for ch in channels::list_owned_groups(&db, &pk)? {
        if !channels::is_member(&db, &ch.channel_id, device)? {
            continue;
        }
        channels::remove_member(&db, &ch.channel_id, device)?;
        rotate_key(state, &db, &ch.channel_id)?;
        publish_state(state, &db, &ch.channel_id)?;
        rotated.push(ch.channel_id);
    }
    tracing::info!(channels = rotated.len(), "device removed, keys rotated");
    Ok(RemoveDeviceOutcome {
        channels_rotated: rotated,
    })
}

/// This person's devices: this node, members of the personal channel, and
/// explicitly trusted devices.
pub fn list_devices(state: &AppState) -> Result<Vec<DeviceInfo>, CordeliaError> {
    let pk = state.identity.public_key();
    let db = lock(state)?;

    let personal_members: Vec<[u8; 32]> = match personal_channel(&db, &pk)? {
        Some(id) => channels::list_active_member_keys(&db, &id)?,
        None => Vec::new(),
    };
    let explicit: Vec<trust::TrustedKey> = trust::list(&db)?
        .into_iter()
        .filter(|t| t.kind == TrustKind::Device.as_str() && t.revoked_at.is_none())
        .collect();

    let mut keys: Vec<[u8; 32]> = vec![pk];
    for k in personal_members
        .iter()
        .chain(explicit.iter().map(|t| &t.key))
    {
        if !keys.contains(k) {
            keys.push(*k);
        }
    }

    keys.into_iter()
        .map(|key| {
            Ok(DeviceInfo {
                key,
                label: trust::label(&db, &key)?,
                this_device: key == pk,
                in_personal_channel: personal_members.contains(&key),
                explicitly_trusted: explicit.iter().any(|t| t.key == key),
            })
        })
        .collect()
}

/// Invites waiting for `accept`.
pub fn list_pending(state: &AppState) -> Result<Vec<invites::PendingInvite>, CordeliaError> {
    let db = lock(state)?;
    invites::pending(&db)
}

/// Process new and pending invites in this node's inbox.
pub fn process_inbox(state: &AppState) -> Result<InboxSummary, CordeliaError> {
    let db = lock(state)?;
    let inbox = ensure_own_inbox_locked(state, &db)?;
    let mut summary = InboxSummary::default();

    for item in invites::unprocessed(&db, &inbox)? {
        let (status, channel_id) = match process_one(state, &db, &item) {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::warn!(item = %item.item_id, error = %e, "invite processing failed");
                (InviteStatus::Invalid, String::new())
            }
        };
        match status {
            InviteStatus::Accepted => summary.applied.push(channel_id.clone()),
            InviteStatus::Pending => summary.pending += 1,
            InviteStatus::Superseded => summary.superseded += 1,
            InviteStatus::Invalid | InviteStatus::Rejected => summary.invalid += 1,
        }
        invites::record(&db, &item.item_id, &item.author_id, &channel_id, status)?;
    }
    invites::enforce_pending_cap(&db)?;

    if !summary.applied.is_empty() || summary.pending > 0 {
        tracing::info!(
            applied = summary.applied.len(),
            pending = summary.pending,
            superseded = summary.superseded,
            invalid = summary.invalid,
            "inbox processed"
        );
    }
    Ok(summary)
}

/// Decide one invite. Returns the decision and the channel it concerns.
fn process_one(
    state: &AppState,
    db: &Connection,
    item: &StoredItem,
) -> Result<(InviteStatus, String), CordeliaError> {
    let pk = state.identity.public_key();
    let invalid = |why: &str| {
        tracing::warn!(item = %item.item_id, reason = why, "invalid invite");
        Ok((InviteStatus::Invalid, String::new()))
    };

    let Ok(author) = <[u8; 32]>::try_from(item.author_id.as_slice()) else {
        return invalid("malformed author");
    };
    if author == pk {
        return invalid("sent by this node");
    }
    if !verify_item_signature(item) {
        return invalid("bad signature");
    }
    let Ok(cs) = ChannelState::open(&state.identity, &item.encrypted_blob) else {
        return invalid("cannot open or validate channel state");
    };
    if cs.sender != author {
        return invalid("sealed sender does not match item author");
    }
    let channel_id = cs.channel_id.clone();

    match channels::get_by_id(db, &channel_id) {
        Ok(existing) => {
            if existing.channel_type != "group" {
                return invalid("state names a non-group channel");
            }
            if channels::get_member_role(db, &channel_id, &author)?.as_deref() != Some("owner") {
                return invalid("sender is not an owner of the channel");
            }
            let (epoch, epoch_author) = channels::epoch(db, &channel_id)?;
            if (cs.epoch, &cs.sender[..]) <= (epoch, epoch_author.as_slice()) {
                return Ok((InviteStatus::Superseded, channel_id));
            }
            apply(state, db, &cs, false)?;
            Ok((InviteStatus::Accepted, channel_id))
        }
        Err(CordeliaError::ChannelNotFound { .. }) => {
            if cs.role_of(&pk).is_none() {
                return invalid("state for an unknown channel does not include this node");
            }
            if !is_trusted_sender(db, &pk, &author)? {
                return Ok((InviteStatus::Pending, channel_id));
            }
            apply(state, db, &cs, true)?;
            Ok((InviteStatus::Accepted, channel_id))
        }
        Err(e) => Err(e),
    }
}

/// Apply a verified, newer channel state.
fn apply(
    state: &AppState,
    db: &Connection,
    cs: &ChannelState,
    joining: bool,
) -> Result<(), CordeliaError> {
    let pk = state.identity.public_key();
    let channel_id = &cs.channel_id;
    let current_key = cs
        .current_key()
        .ok_or_else(|| CordeliaError::Crypto("state lacks current key".into()))?;

    channels::ensure_group(db, channel_id, cs.name.as_deref(), &cs.mode, &cs.creator)?;
    psk::install_key_ring(&state.home_dir, channel_id, &cs.keys, cs.key_version)?;
    psk::write_slot_key(&state.home_dir, channel_id, &cs.slot_key)?;
    let members: Vec<([u8; 32], &str)> = cs
        .members
        .iter()
        .map(|m| (m.key, m.role.as_str()))
        .collect();
    channels::replace_members(db, channel_id, &members)?;
    channels::set_state(
        db,
        channel_id,
        cs.epoch,
        &cs.sender,
        cs.key_version,
        &cordelia_crypto::sha256(current_key),
    )?;

    let personal = personal_channel(db, &pk)?;
    if cs.personal
        && cs.role_of(&pk) == Some(MemberRole::Owner)
        && trust::is_trusted(db, &cs.sender)?
    {
        // A device invite: adopt the inviter's personal channel, unless this
        // node's own personal channel already has other devices in it.
        let keep_own = match &personal {
            Some(own) if own != channel_id => channels::member_count(db, own)? > 1,
            _ => false,
        };
        if !keep_own && personal.as_deref() != Some(channel_id.as_str()) {
            meta::set(db, meta::PERSONAL_CHANNEL_ID, channel_id)?;
            tracing::info!(channel = %channel_id, "adopted personal channel");
        }
    }

    // A device dropped from the personal channel is no longer trusted here.
    if personal.as_deref() == Some(channel_id.as_str()) {
        for t in trust::list(db)? {
            if t.revoked_at.is_none()
                && t.kind == TrustKind::Device.as_str()
                && cs.role_of(&t.key).is_none()
            {
                trust::revoke(db, &t.key)?;
            }
        }
    }

    if cs.role_of(&pk).is_none() {
        tracing::info!(channel = %channel_id, "removed from channel");
    } else if joining {
        tracing::info!(channel = %channel_id, epoch = cs.epoch, "joined channel");
        announce(state, channel_id);
    } else {
        tracing::info!(channel = %channel_id, epoch = cs.epoch, "channel state updated");
    }
    Ok(())
}
