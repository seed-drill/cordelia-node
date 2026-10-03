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
use cordelia_storage::{channels, meta, naming, offers, psk};

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
    /// States from this person's devices that name a key this device does
    /// not know as one of them, kept until it does.
    pub held: usize,
    /// What the person should know: why something they asked for did not
    /// happen.
    pub notes: Vec<String>,
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
    /// When this device sent the oldest change to a channel's members or
    /// keys that the other device has not yet been seen to hold (Unix
    /// seconds). `None` when it holds everything this device sent it.
    pub unconfirmed_since: Option<i64>,
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

/// Whether invites from `sender` are applied without asking: it is trusted
/// as one of this person's devices, by `add-device` or `accept`, or it is
/// in the personal channel. Trust of any other kind does not count.
fn is_trusted_sender(
    db: &Connection,
    pk: &[u8; 32],
    sender: &[u8; 32],
) -> Result<bool, CordeliaError> {
    if trust::is_trusted_as(db, sender, TrustKind::Device)? {
        return Ok(true);
    }
    match personal_channel(db, pk)? {
        Some(personal) => channels::is_member(db, &personal, sender),
        None => Ok(false),
    }
}

/// Whether `key` is one of this person's devices: this device, or a member
/// of the personal channel.
fn is_own_device(db: &Connection, pk: &[u8; 32], key: &[u8; 32]) -> Result<bool, CordeliaError> {
    if key == pk {
        return Ok(true);
    }
    match personal_channel(db, pk)? {
        Some(personal) => channels::is_member(db, &personal, key),
        None => Ok(false),
    }
}

/// Why this device keeps the personal channel it has, if it does: it is in
/// use. A device with other devices in its personal channel, or one that is
/// syncing, is never moved into another personal channel by anything it is
/// sent, whoever sent it. Moving it would put its memory in someone else's
/// channel.
fn why_personal_channel_stays(
    db: &Connection,
    pk: &[u8; 32],
) -> Result<Option<&'static str>, CordeliaError> {
    if let Some(own) = personal_channel(db, pk)?
        && channels::member_count(db, &own)? > 1
    {
        return Ok(Some("it already has other devices in its personal channel"));
    }
    let set = |key: &str| -> Result<bool, CordeliaError> {
        Ok(meta::get(db, key)?.is_some_and(|v| !v.is_empty() && v != "[]"))
    };
    if set(meta::SYNC_CLAUDE_DIR)? || set(meta::SYNC_CLAUDE_MAPPINGS)? {
        return Ok(Some("it is syncing memory under its own personal channel"));
    }
    Ok(None)
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
    let is_personal = personal_channel(db, &pk)?.as_deref() == Some(channel_id);
    let mut members = Vec::new();
    for (key, role) in channels::list_active_members(db, channel_id)? {
        // One of this person's own channels lists only their devices. A key
        // that got into the list some other way is left out of what this
        // node sends, so it is neither handed the keys nor vouched for.
        if !is_personal && !is_own_device(db, &pk, &key)? {
            tracing::warn!(
                channel = %channel_id,
                "leaving a key that is not one of this person's devices out of the channel's state"
            );
            continue;
        }
        members.push(StateMember {
            key,
            role: MemberRole::parse(&role).map_err(crypto_err)?,
        });
    }
    let key_version = u32::try_from(ch.key_version)
        .map_err(|_| CordeliaError::Internal("key version out of range".into()))?;
    // A state holds only so many keys. Past that the oldest are left out of
    // what is sent: otherwise a ring that has been filled could not be
    // sent at all, and no device could be removed from the channel. Devices
    // that already hold the older keys keep them. A device added later
    // cannot read what was written under the ones left out.
    let mut keys = psk::export_key_ring(&state.home_dir, channel_id, ch.key_version)?;
    let most = cordelia_core::protocol::MAX_STATE_KEYS;
    if keys.len() > most {
        tracing::warn!(
            channel = %channel_id,
            left_out = keys.len() - most,
            "this channel has had more keys than a state holds; the oldest are not sent"
        );
        keys.drain(..keys.len() - most);
    }

    Ok(ChannelState {
        channel_id: channel_id.to_string(),
        name: ch.channel_name,
        mode: ch.mode,
        creator: ch.creator_id,
        sender: pk,
        epoch,
        key_version,
        keys,
        slot_key: slot_key(state, channel_id)?,
        members,
        personal: personal_channel(db, &pk)?.as_deref() == Some(channel_id),
    })
}

/// Hand `cs` to `recipient`, and remember that it was sent until the
/// recipient is seen to hold it (see [`offer_again`]).
fn send_state(
    state: &AppState,
    db: &Connection,
    recipient: &[u8; 32],
    cs: &ChannelState,
) -> Result<(), CordeliaError> {
    let item_id = seal_and_send(state, db, recipient, cs)?;
    offers::record(
        db,
        &cs.channel_id,
        recipient,
        cs.epoch,
        &item_id,
        Utc::now().timestamp(),
    )
}

/// Seal `cs` to `recipient` and publish it into the recipient's inbox:
/// stored locally (so relays can also pull it) and pushed to hot relays.
/// Returns the item that carries it.
fn seal_and_send(
    state: &AppState,
    db: &Connection,
    recipient: &[u8; 32],
    cs: &ChannelState,
) -> Result<String, CordeliaError> {
    let pk = state.identity.public_key();
    // Every channel in v1 is this person's own. Sealing a state hands over
    // every key the channel has had, and with them everything written so
    // far, so the check is here, where the keys leave: only to one of this
    // person's devices (decision 2026-09-30 §4.7).
    if !is_own_device(db, &pk, recipient)? {
        return Err(CordeliaError::Validation(
            "that key is not one of your devices, and a channel of your own is only ever \
             handed to your own devices"
                .into(),
        ));
    }
    let inbox = naming::inbox_channel_id(recipient);
    channels::ensure_inbox(db, &inbox, recipient, false)?;

    let sealed = cs.seal(recipient).map_err(crypto_err)?;
    if sealed.len() > cordelia_core::protocol::MAX_ITEM_BYTES {
        return Err(CordeliaError::TooLarge {
            bytes: sealed.len(),
            limit: cordelia_core::protocol::MAX_ITEM_BYTES,
        });
    }
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
            item_id: item_id.clone(),
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
    Ok(item_id)
}

/// Tell `sender` that this device now holds the state it sent: send back
/// this device's own view of the channel, which carries the epoch it holds.
/// The sender takes that as confirmation and stops offering.
///
/// It is this device's state like any other, so nothing new travels. It is
/// not remembered as something to confirm in turn, or two devices would
/// answer each other for ever. A failure is only logged: the sender offers
/// again, and this device answers again.
fn answer(state: &AppState, db: &Connection, channel_id: &str, sender: &[u8; 32]) {
    let sent =
        build_state(state, db, channel_id).and_then(|cs| seal_and_send(state, db, sender, &cs));
    if let Err(e) = sent {
        tracing::warn!(channel = %channel_id, error = %e, "could not confirm a channel state to its sender");
    }
}

/// How long after its `offers`-th offer a state that is still not
/// confirmed is offered again.
fn offer_wait(offers: u32) -> i64 {
    use cordelia_core::protocol::{STATE_OFFER_RETRY_BASE_SECS, STATE_OFFER_RETRY_MAX_SECS};
    STATE_OFFER_RETRY_BASE_SECS
        .saturating_mul(1u64 << offers.saturating_sub(1).min(32))
        .min(STATE_OFFER_RETRY_MAX_SECS) as i64
}

/// Offer again every channel state that was sent to a member and that the
/// member has not been seen to hold, once its wait has passed. Returns how
/// many were offered. `now` is Unix seconds.
///
/// The item that carries the state goes back into the outbox, so it is
/// pushed to a relay again. A relay that still has it says so; one that
/// lost it, or refused it the first time, stores it. Nothing new is
/// written, so a member that is away for a month costs a handful of small
/// pushes a day and nothing on the relays.
///
/// This is what makes a removal reach every remaining device: until each
/// of them answers, the device that removed keeps offering it, and
/// `cordelia devices` says which have not answered.
pub fn offer_again(state: &AppState, now: i64) -> Result<usize, CordeliaError> {
    let pk = state.identity.public_key();
    let db = lock(state)?;
    let mut offered = 0;
    for offer in offers::unconfirmed(&db)? {
        // Only while both are still in the channel.
        let both_members = channels::is_member(&db, &offer.channel_id, &offer.member)
            .unwrap_or(false)
            && channels::is_member(&db, &offer.channel_id, &pk).unwrap_or(false);
        if !both_members {
            offers::forget(&db, &offer.channel_id, &offer.member)?;
            continue;
        }
        if now - offer.last_offered_at < offer_wait(offer.offers) {
            continue;
        }
        if items::mark_unrelayed(&db, &offer.item_id)? {
            offers::offered_again(&db, &offer.channel_id, &offer.member, now)?;
        } else {
            // The item is no longer stored here: send the channel as it is.
            let cs = build_state(state, &db, &offer.channel_id)?;
            let item_id = seal_and_send(state, &db, &offer.member, &cs)?;
            offers::forget(&db, &offer.channel_id, &offer.member)?;
            offers::record(
                &db,
                &offer.channel_id,
                &offer.member,
                cs.epoch,
                &item_id,
                now,
            )?;
        }
        tracing::info!(
            channel = %offer.channel_id,
            offers = offer.offers + 1,
            "a member has not confirmed a channel state; offering it again"
        );
        offered += 1;
    }
    Ok(offered)
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
        if !is_own_device(db, &pk, &member.key)? {
            tracing::warn!(
                channel = %channel_id,
                "a member of this channel is not one of this person's devices; not sending it the channel's keys"
            );
            continue;
        }
        send_state(state, db, &member.key, &cs)?;
        sent += 1;
    }
    Ok(sent)
}

/// The epoch of a channel's next change.
fn next_epoch(db: &Connection, channel_id: &str) -> Result<u64, CordeliaError> {
    let (epoch, _) = channels::epoch(db, channel_id)?;
    if epoch >= cordelia_core::protocol::MAX_EPOCH {
        return Err(CordeliaError::Validation(
            "this channel's members can no longer be changed: it has reached the limit on changes"
                .into(),
        ));
    }
    Ok(epoch + 1)
}

/// Advance a channel's epoch after a local change, keeping its key state.
fn bump_epoch(state: &AppState, db: &Connection, channel_id: &str) -> Result<u64, CordeliaError> {
    let pk = state.identity.public_key();
    let ch = channels::get_by_id(db, channel_id)?;
    let next = next_epoch(db, channel_id)?;
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
    let next = next_epoch(db, channel_id)?;
    let new_version = u32::try_from(ch.key_version + 1)
        .map_err(|_| CordeliaError::Internal("key version out of range".into()))?;
    let new_key = cordelia_crypto::generate_psk().map_err(crypto_err)?;

    let mut keys = psk::export_key_ring(&state.home_dir, channel_id, ch.key_version)?;
    keys.push((new_version, new_key));
    psk::install_key_ring(&state.home_dir, channel_id, &keys, new_version)?;
    channels::set_state(
        db,
        channel_id,
        next,
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

/// Refuse bytes that cannot be a device's key: not a point on the curve,
/// or a point of small order. Nothing can be sealed to such a key except
/// under a secret that anyone can work out, so it is never made a device,
/// never trusted, and never sealed to.
fn not_a_device_key(key: &[u8; 32]) -> Result<(), CordeliaError> {
    if cordelia_crypto::identity::is_usable_public_key(key) {
        return Ok(());
    }
    Err(CordeliaError::Validation(
        "that is not a device's key: check it against `cordelia id` on the other device".into(),
    ))
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
    not_a_device_key(device)?;

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
    not_a_device_key(key)?;
    let stays = {
        let db = lock(state)?;
        ensure_own_inbox_locked(state, &db)?;
        trust::trust(&db, key, TrustKind::Device, label)?;
        // Which personal channel this device belongs to is decided here, by
        // the person's act on this device, and by nothing it is sent. A
        // device that is in use stays where it is.
        let pk = state.identity.public_key();
        let stays = why_personal_channel_stays(&db, &pk)?;
        if stays.is_none() {
            meta::set(
                &db,
                meta::ACCEPTED_PERSONAL_FROM,
                &format!("{} {}", hex::encode(key), Utc::now().timestamp()),
            )?;
        }
        stays
    };
    let mut summary = process_inbox(state)?;
    if let Some(why) = stays {
        let note = staying_note(why);
        if !summary.notes.contains(&note) {
            summary.notes.push(note);
        }
    }
    Ok(summary)
}

/// How long after `cordelia accept` the accepted device's offer of its
/// personal channel is still taken. The offer travels through a relay and
/// normally arrives within a minute; an hour covers a device that was
/// added a little later, without leaving the decision open for good.
const ACCEPTED_PERSONAL_SECS: i64 = 3600;

/// Whether this device has decided, recently, to take the personal channel
/// offered by `sender`.
fn accepted_personal_from(db: &Connection, sender: &[u8; 32]) -> Result<bool, CordeliaError> {
    let Some(value) = meta::get(db, meta::ACCEPTED_PERSONAL_FROM)? else {
        return Ok(false);
    };
    let Some((key, at)) = value.split_once(' ') else {
        return Ok(false);
    };
    let recent = at
        .parse::<i64>()
        .is_ok_and(|at| Utc::now().timestamp() - at <= ACCEPTED_PERSONAL_SECS);
    Ok(recent && key == hex::encode(sender))
}

fn staying_note(why: &str) -> String {
    format!(
        "This device keeps its own personal channel, because {why}. To move it into \
         another one, turn sync off here first (`cordelia sync off`), then accept again."
    )
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
        keep_what_it_wrote(state, &db, &ch.channel_id, device);
        channels::remove_member(&db, &ch.channel_id, device)?;
        offers::forget(&db, &ch.channel_id, device)?;
        rotate_key(state, &db, &ch.channel_id)?;
        publish_state(state, &db, &ch.channel_id)?;
        rotated.push(ch.channel_id);
    }
    tracing::info!(channels = rotated.len(), "device removed, keys rotated");
    Ok(RemoveDeviceOutcome {
        channels_rotated: rotated,
    })
}

/// Publish again, as this device, what `leaving` last wrote in a channel,
/// just before this device removes it there (see
/// [`crate::entries::take_over`]). A failure is logged and does not stop
/// the removal: taking a device out matters more than keeping what it
/// wrote.
///
/// Only the device that removes does this, with what it holds at that
/// moment. A device that learns of the removal later does not: it cannot
/// tell what the removed device wrote before its removal from what it
/// wrote afterwards. Anything it holds that the remover did not is kept on
/// that device as a conflict file (cordelia-sync, `plan`).
fn keep_what_it_wrote(state: &AppState, db: &Connection, channel_id: &str, leaving: &[u8; 32]) {
    match crate::entries::take_over(state, db, channel_id, leaving) {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            channel = %channel_id,
            entries = n,
            "published again what a removed device last wrote"
        ),
        Err(e) => tracing::warn!(
            channel = %channel_id,
            error = %e,
            "could not publish again what a removed device last wrote"
        ),
    }
}

/// Finish removing `gone` from this person's channels after `remover`
/// dropped it from the personal channel. The remover already rotated every
/// channel it owns; since devices join only the projects they have, a
/// project channel the remover is not in still lists `gone`. Of that
/// channel's remaining owners that are still this person's `devices`, the
/// one with the lowest key removes it and rotates the key, so two devices
/// never rotate the same channel at once. Returns the channels rotated.
fn remove_where_remover_absent(
    state: &AppState,
    db: &Connection,
    gone: &[u8; 32],
    remover: &[u8; 32],
    personal: &str,
    devices: &[[u8; 32]],
) -> Result<Vec<String>, CordeliaError> {
    let pk = state.identity.public_key();
    let mut rotated = Vec::new();
    for ch in channels::list_owned_groups(db, &pk)? {
        let id = ch.channel_id;
        if id == personal
            || !channels::is_member(db, &id, gone)?
            || channels::is_member(db, &id, remover)?
        {
            continue;
        }
        let acting = channels::list_active_members(db, &id)?
            .into_iter()
            .filter(|(key, role)| role == "owner" && key != gone && devices.contains(key))
            .map(|(key, _)| key)
            .min();
        if acting != Some(pk) {
            continue; // another remaining owner acts
        }
        keep_what_it_wrote(state, db, &id, gone);
        channels::remove_member(db, &id, gone)?;
        offers::forget(db, &id, gone)?;
        rotate_key(state, db, &id)?;
        publish_state(state, db, &id)?;
        tracing::info!(channel = %id, "removed a device the remover could not reach, keys rotated");
        rotated.push(id);
    }
    Ok(rotated)
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

    let waiting = offers::unconfirmed(&db)?;
    keys.into_iter()
        .map(|key| {
            Ok(DeviceInfo {
                key,
                label: trust::label(&db, &key)?,
                this_device: key == pk,
                in_personal_channel: personal_members.contains(&key),
                explicitly_trusted: explicit.iter().any(|t| t.key == key),
                unconfirmed_since: waiting
                    .iter()
                    .filter(|offer| offer.member == key)
                    .map(|offer| offer.sent_at)
                    .min(),
            })
        })
        .collect()
}

/// Invites waiting for `accept`.
pub fn list_pending(state: &AppState) -> Result<Vec<invites::PendingInvite>, CordeliaError> {
    let db = lock(state)?;
    let pk = state.identity.public_key();
    waiting_for_accept(&db, &pk)
}

/// The invitations that wait for `accept`, oldest first: those from a key
/// this device has not accepted. Anything else that waits is from one of
/// this person's own devices and waits for another reason (see
/// `process_one`).
fn waiting_for_accept(
    db: &Connection,
    pk: &[u8; 32],
) -> Result<Vec<invites::PendingInvite>, CordeliaError> {
    let mut waiting = Vec::new();
    for invite in invites::pending(db)? {
        if !is_trusted_sender(db, pk, &invite.inviter)? {
            waiting.push(invite);
        }
    }
    Ok(waiting)
}

/// Keep at most [`invites::MAX_PENDING_INVITES`] invitations waiting for
/// `accept`, rejecting the oldest beyond that, so a stranger who knows this
/// device's key cannot grow the list without limit.
///
/// Only what waits for `accept` is counted or rejected. A state that one of
/// this person's own devices sent, and that is held, is left alone: what
/// strangers send must not push it out.
fn cap_waiting_invites(db: &Connection, pk: &[u8; 32]) -> Result<usize, CordeliaError> {
    let waiting = waiting_for_accept(db, pk)?;
    let over = waiting.len().saturating_sub(invites::MAX_PENDING_INVITES);
    for invite in &waiting[..over] {
        invites::record(
            db,
            &invite.item_id,
            &invite.inviter,
            &invite.channel_id,
            InviteStatus::Rejected,
        )?;
    }
    Ok(over)
}

/// Process new and pending invites in this node's inbox.
pub fn process_inbox(state: &AppState) -> Result<InboxSummary, CordeliaError> {
    let db = lock(state)?;
    let inbox = ensure_own_inbox_locked(state, &db)?;
    let mut summary = InboxSummary::default();

    // A state that is held may apply once another one has (it names a
    // device this one had not heard of yet), so look again for as long as
    // that keeps happening.
    loop {
        let applied_before = summary.applied.len();
        summary.pending = 0;
        summary.held = 0;
        for item in invites::unprocessed(&db, &inbox)? {
            let mut note = None;
            let (status, channel_id) = match process_one(state, &db, &item, &mut note) {
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
                InviteStatus::Held => summary.held += 1,
            }
            if let Some(note) = note
                && !summary.notes.contains(&note)
            {
                summary.notes.push(note);
            }
            invites::record(&db, &item.item_id, &item.author_id, &channel_id, status)?;
        }
        if summary.held == 0 || summary.applied.len() == applied_before {
            break;
        }
    }
    cap_waiting_invites(&db, &state.identity.public_key())?;

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
    note: &mut Option<String>,
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
            // A state from a member shows which epoch it holds. That
            // confirms what this device sent it, if it was waiting to hear.
            offers::confirm(db, &channel_id, &author, cs.epoch, Utc::now().timestamp())?;
            let (epoch, epoch_author) = channels::epoch(db, &channel_id)?;
            if (cs.epoch, &cs.sender[..]) <= (epoch, epoch_author.as_slice()) {
                return Ok((InviteStatus::Superseded, channel_id));
            }
            // One change moves the epoch by one, and a device that was away
            // may skip some. A state that moves it further than that is an
            // attempt to use the numbers up, so that the members could
            // never be changed again.
            if cs.epoch - epoch > cordelia_core::protocol::MAX_EPOCH_STEP {
                return invalid("state moves the epoch further than one change may");
            }
            // A removal moves the key version by one, with the epoch. So
            // the version never goes back, never moves further than the
            // epoch did, and never further than a state has room for keys.
            // Otherwise a member could send the largest version there is,
            // and no device could be removed afterwards.
            let moved = i64::from(cs.key_version) - existing.key_version;
            let room = (cs.epoch - epoch).min(cordelia_core::protocol::MAX_STATE_KEYS as u64);
            if moved < 0 || moved as u64 > room {
                return invalid("state moves the key version further than its changes can");
            }
            let is_personal = personal_channel(db, &pk)?.as_deref() == Some(channel_id.as_str());
            if !is_personal && names_a_stranger(db, &pk, &cs)? {
                return Ok((InviteStatus::Held, channel_id));
            }
            apply(state, db, &cs, false, false)?;
            // A change, not only a tie between two devices at one epoch:
            // tell its sender that this device holds it.
            if cs.epoch > epoch && cs.role_of(&pk).is_some() {
                answer(state, db, &channel_id, &author);
            }
            Ok((InviteStatus::Accepted, channel_id))
        }
        Err(CordeliaError::ChannelNotFound { .. }) => {
            if cs.role_of(&pk).is_none() {
                return invalid("state for an unknown channel does not include this node");
            }
            if !is_trusted_sender(db, &pk, &author)? {
                return Ok((InviteStatus::Pending, channel_id));
            }
            if cs.personal {
                // An offer to join another personal channel. It is taken
                // only if the person has just accepted this sender on this
                // device, which they can do only while the device is not in
                // use (see `accept`). Otherwise it waits.
                if !accepted_personal_from(db, &author)? {
                    tracing::warn!(
                        "offered another personal channel without a recent accept of its sender; this device keeps its own"
                    );
                    if let Some(why) = why_personal_channel_stays(db, &pk)? {
                        *note = Some(staying_note(why));
                    }
                    return Ok((InviteStatus::Pending, channel_id));
                }
                apply(state, db, &cs, true, true)?;
                meta::set(db, meta::ACCEPTED_PERSONAL_FROM, "")?;
                answer(state, db, &channel_id, &author);
                return Ok((InviteStatus::Accepted, channel_id));
            }
            if names_a_stranger(db, &pk, &cs)? {
                return Ok((InviteStatus::Held, channel_id));
            }
            apply(state, db, &cs, true, false)?;
            answer(state, db, &channel_id, &author);
            Ok((InviteStatus::Accepted, channel_id))
        }
        Err(e) => Err(e),
    }
}

/// Whether a state for one of this person's own channels (not the personal
/// channel) names a key that is not one of this person's devices. Such a
/// state is not applied: a channel of your own holds only your own devices,
/// whatever one of them says (decision 2026-09-30 §4.7). The key may be a
/// device this one has not heard of yet, so the state is kept and looked at
/// again, not thrown away.
fn names_a_stranger(
    db: &Connection,
    pk: &[u8; 32],
    cs: &ChannelState,
) -> Result<bool, CordeliaError> {
    for member in &cs.members {
        if !is_own_device(db, pk, &member.key)? {
            tracing::warn!(
                channel = %cs.channel_id,
                "a state for one of this person's channels names a key that is not one of their devices; not applying it"
            );
            return Ok(true);
        }
    }
    Ok(false)
}

/// Apply a verified, newer channel state. `adopt` makes it this device's
/// personal channel: only for an offer this device has decided to take
/// (see `process_one`), never because the state says so.
fn apply(
    state: &AppState,
    db: &Connection,
    cs: &ChannelState,
    joining: bool,
    adopt: bool,
) -> Result<(), CordeliaError> {
    let pk = state.identity.public_key();
    let channel_id = &cs.channel_id;
    let current_key = cs
        .current_key()
        .ok_or_else(|| CordeliaError::Crypto("state lacks current key".into()))?;

    let personal = personal_channel(db, &pk)?;
    let is_personal = personal.as_deref() == Some(channel_id.as_str());
    // Devices this state drops from the personal channel, i.e. removed.
    let dropped: Vec<[u8; 32]> = if is_personal {
        channels::list_active_members(db, channel_id)?
            .into_iter()
            .map(|(key, _)| key)
            .filter(|key| cs.role_of(key).is_none())
            .collect()
    } else {
        Vec::new()
    };

    channels::ensure_group(db, channel_id, cs.name.as_deref(), &cs.mode, &cs.creator)?;
    psk::install_key_ring(&state.home_dir, channel_id, &cs.keys, cs.key_version)?;
    psk::write_slot_key(&state.home_dir, channel_id, &cs.slot_key)?;
    let members: Vec<([u8; 32], &str)> = cs
        .members
        .iter()
        .map(|m| (m.key, m.role.as_str()))
        .collect();
    // A member this device had not heard of may already have written to
    // the channel, and this device refused those entries: it stores only
    // what members wrote. Have the channel listed again.
    let mut joined = false;
    for (key, _) in &members {
        joined |= !channels::is_member(db, channel_id, key)?;
    }
    channels::replace_members(db, channel_id, &members)?;
    if joined && let Ok(mut relist) = state.relist.lock() {
        relist.insert(channel_id.clone());
    }
    channels::set_state(
        db,
        channel_id,
        cs.epoch,
        &cs.sender,
        cs.key_version,
        &cordelia_crypto::sha256(current_key),
    )?;

    if adopt
        && cs.personal
        && cs.role_of(&pk) == Some(MemberRole::Owner)
        && trust::is_trusted_as(db, &cs.sender, TrustKind::Device)?
        && personal.as_deref() != Some(channel_id.as_str())
    {
        // A device invite, taken by a device that is not in use: the
        // inviter's personal channel becomes this device's.
        meta::set(db, meta::PERSONAL_CHANNEL_ID, channel_id)?;
        tracing::info!(channel = %channel_id, "adopted personal channel");
    }

    // A device dropped from the personal channel is no longer trusted here,
    // and leaves the channels the remover could not reach.
    if is_personal {
        for t in trust::list(db)? {
            if t.revoked_at.is_none()
                && t.kind == TrustKind::Device.as_str()
                && cs.role_of(&t.key).is_none()
            {
                trust::revoke(db, &t.key)?;
            }
        }
        let devices: Vec<[u8; 32]> = cs.members.iter().map(|m| m.key).collect();
        for gone in &dropped {
            remove_where_remover_absent(state, db, gone, &cs.sender, channel_id, &devices)?;
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
