//! Channel CRUD operations.
//!
//! Spec: seed-drill/specs/channels-api.md, seed-drill/specs/data-formats.md §3.1

use chrono::Utc;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use cordelia_core::{ChannelId, CordeliaError};

use crate::naming::{self, ChannelType};

/// Channel record (matches channels table).
#[derive(Debug, Clone)]
pub struct Channel {
    pub channel_id: String,
    pub channel_name: Option<String>,
    pub channel_type: String,
    pub mode: String,
    pub access: String,
    pub scope: String,
    pub creator_id: [u8; 32],
    pub key_version: i64,
    pub psk_hash: Option<Vec<u8>>,
    pub created_at: String,
    pub updated_at: String,
}

/// Create a named channel.
///
/// Canonicalizes the name, derives the channel ID, inserts into channels table,
/// and adds the creator as owner in channel_members.
pub fn create_named(
    conn: &Connection,
    name: &str,
    mode: &str,
    access: &str,
    creator_id: &[u8; 32],
    psk: Option<&[u8; 32]>,
) -> Result<Channel, CordeliaError> {
    let canonical = naming::canonicalize(name)?;
    let channel_id = naming::named_channel_id(&canonical);
    let now = Utc::now().to_rfc3339();
    let psk_hash = psk.map(|k| Sha256::digest(k).to_vec());

    conn.execute(
        "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id, psk_hash, created_at, updated_at)
         VALUES (?1, ?2, 'named', ?3, ?4, ?5, ?6, ?7, ?8)",
        params![channel_id, canonical, mode, access, creator_id.as_slice(), psk_hash, now, now],
    )
    .map_err(|e| {
        if is_unique_violation(&e) {
            CordeliaError::ChannelAlreadyExists {
                channel: canonical.clone(),
            }
        } else {
            CordeliaError::Storage(e.to_string())
        }
    })?;

    // Add creator as owner
    conn.execute(
        "INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
         VALUES (?1, ?2, 'owner', ?3)",
        params![channel_id, creator_id.as_slice(), now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    Ok(Channel {
        channel_id,
        channel_name: Some(canonical),
        channel_type: "named".into(),
        mode: mode.into(),
        access: access.into(),
        scope: "network".into(),
        creator_id: *creator_id,
        key_version: 1,
        psk_hash,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Create a DM channel between two Ed25519 public keys.
///
/// Derives the deterministic channel ID from sorted keys.
/// Also inserts a dm_peers row for the remote peer.
pub fn create_dm(
    conn: &Connection,
    local_pk: &[u8; 32],
    peer_pk: &[u8; 32],
    psk: Option<&[u8; 32]>,
) -> Result<Channel, CordeliaError> {
    let channel_id = naming::dm_channel_id(local_pk, peer_pk);
    let now = Utc::now().to_rfc3339();
    let psk_hash = psk.map(|k| Sha256::digest(k).to_vec());

    conn.execute(
        "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, psk_hash, created_at, updated_at)
         VALUES (?1, 'dm', 'realtime', 'invite_only', ?2, ?3, ?4, ?5)",
        params![channel_id, local_pk.as_slice(), psk_hash, now, now],
    )
    .map_err(|e| {
        if is_unique_violation(&e) {
            CordeliaError::ChannelAlreadyExists {
                channel: channel_id.clone(),
            }
        } else {
            CordeliaError::Storage(e.to_string())
        }
    })?;

    // Add both parties as members
    conn.execute(
        "INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
         VALUES (?1, ?2, 'owner', ?3)",
        params![channel_id, local_pk.as_slice(), now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    conn.execute(
        "INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
         VALUES (?1, ?2, 'member', ?3)",
        params![channel_id, peer_pk.as_slice(), now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    // Record peer for fast DM lookups
    conn.execute(
        "INSERT INTO dm_peers (channel_id, peer_key) VALUES (?1, ?2)",
        params![channel_id, peer_pk.as_slice()],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    Ok(Channel {
        channel_id,
        channel_name: None,
        channel_type: "dm".into(),
        mode: "realtime".into(),
        access: "invite_only".into(),
        scope: "network".into(),
        creator_id: *local_pk,
        key_version: 1,
        psk_hash,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Create a group conversation.
///
/// Uses random UUID for the channel ID. Creator is added as owner.
pub fn create_group(
    conn: &Connection,
    creator_id: &[u8; 32],
    mode: &str,
    name: Option<&str>,
    psk: Option<&[u8; 32]>,
) -> Result<Channel, CordeliaError> {
    let channel_id = naming::group_channel_id();
    let now = Utc::now().to_rfc3339();
    let psk_hash = psk.map(|k| Sha256::digest(k).to_vec());

    conn.execute(
        "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id, psk_hash, created_at, updated_at)
         VALUES (?1, ?2, 'group', ?3, 'invite_only', ?4, ?5, ?6, ?7)",
        params![channel_id, name, mode, creator_id.as_slice(), psk_hash, now, now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    conn.execute(
        "INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
         VALUES (?1, ?2, 'owner', ?3)",
        params![channel_id, creator_id.as_slice(), now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    Ok(Channel {
        channel_id,
        channel_name: name.map(String::from),
        channel_type: "group".into(),
        mode: mode.into(),
        access: "invite_only".into(),
        scope: "network".into(),
        creator_id: *creator_id,
        key_version: 1,
        psk_hash,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Create an inbox channel row (decision 2026-09-30 §4.1).
///
/// `owner` is the key whose inbox this is. A node creates its own inbox
/// with `owner_is_self` (and becomes its member, so pull-sync fetches it),
/// and creates other nodes' inbox rows without membership, only so that
/// invites it sends can be stored and served to relays. Idempotent.
pub fn ensure_inbox(
    conn: &Connection,
    channel_id: &str,
    owner: &[u8; 32],
    owner_is_self: bool,
) -> Result<(), CordeliaError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
         VALUES (?1, 'inbox', 'realtime', 'invite_only', ?2, ?3, ?3)",
        params![channel_id, owner.as_slice(), now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    if owner_is_self {
        conn.execute(
            "INSERT OR IGNORE INTO channel_members (channel_id, entity_key, role, joined_at)
             VALUES (?1, ?2, 'owner', ?3)",
            params![channel_id, owner.as_slice(), now],
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    }
    Ok(())
}

/// Create the row for a group channel this node is joining, with the ID
/// and attributes from a channel state. Membership and key state are set
/// separately. Idempotent: an existing row is left as it is.
pub fn ensure_group(
    conn: &Connection,
    channel_id: &str,
    name: Option<&str>,
    mode: &str,
    creator_id: &[u8; 32],
) -> Result<(), CordeliaError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id, created_at, updated_at)
         VALUES (?1, ?2, 'group', ?3, 'invite_only', ?4, ?5, ?5)",
        params![channel_id, name, mode, creator_id.as_slice(), now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// A channel's membership epoch and the author of the state that set it.
///
/// A stored value outside 0..=MAX_EPOCH can only have been written before
/// the limit existed. It reads as zero, so that the channel's members can
/// put it right with their next change.
pub fn epoch(conn: &Connection, channel_id: &str) -> Result<(u64, Vec<u8>), CordeliaError> {
    conn.query_row(
        "SELECT epoch, epoch_author FROM channels WHERE channel_id = ?1",
        params![channel_id],
        |row| {
            let epoch: i64 = row.get(0)?;
            let author: Option<Vec<u8>> = row.get(1)?;
            let epoch = u64::try_from(epoch)
                .ok()
                .filter(|e| *e <= cordelia_core::protocol::MAX_EPOCH)
                .unwrap_or(0);
            Ok((epoch, author.unwrap_or_default()))
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => CordeliaError::ChannelNotFound {
            channel: channel_id.to_string(),
        },
        other => CordeliaError::Storage(other.to_string()),
    })
}

/// Record the channel state applied to a channel: epoch, its author, the
/// current key version, and the current key's hash. An epoch over
/// MAX_EPOCH is refused.
pub fn set_state(
    conn: &Connection,
    channel_id: &str,
    epoch: u64,
    epoch_author: &[u8; 32],
    key_version: u32,
    psk_hash: &[u8],
) -> Result<(), CordeliaError> {
    if epoch > cordelia_core::protocol::MAX_EPOCH {
        return Err(CordeliaError::Validation(
            "membership epoch is over the limit".into(),
        ));
    }
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE channels SET epoch = ?1, epoch_author = ?2, key_version = ?3, psk_hash = ?4,
                             updated_at = ?5
         WHERE channel_id = ?6",
        params![
            epoch as i64,
            epoch_author.as_slice(),
            key_version,
            psk_hash,
            now,
            channel_id
        ],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Make the channel's active members exactly `members` (key, role):
/// listed keys are added or updated, anyone else is soft-removed.
pub fn replace_members(
    conn: &Connection,
    channel_id: &str,
    members: &[([u8; 32], &str)],
) -> Result<(), CordeliaError> {
    for (key, role) in members {
        add_member(conn, channel_id, key, role)?;
    }
    for existing in list_active_member_keys(conn, channel_id)? {
        if !members.iter().any(|(k, _)| *k == existing) {
            remove_member(conn, channel_id, &existing)?;
        }
    }
    Ok(())
}

/// Active members of a channel with their roles.
pub fn list_active_members(
    conn: &Connection,
    channel_id: &str,
) -> Result<Vec<([u8; 32], String)>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT entity_key, role FROM channel_members
             WHERE channel_id = ?1 AND posture = 'active'
             ORDER BY joined_at ASC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(params![channel_id], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok((blob, row.get::<_, String>(1)?))
        })
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        let (blob, role) = row.map_err(|e| CordeliaError::Storage(e.to_string()))?;
        if let Ok(key) = <[u8; 32]>::try_from(blob.as_slice()) {
            out.push((key, role));
        }
    }
    Ok(out)
}

/// When `entity_key` joined the channel (RFC 3339), if it is a member.
pub fn member_joined_at(
    conn: &Connection,
    channel_id: &str,
    entity_key: &[u8; 32],
) -> Result<Option<String>, CordeliaError> {
    match conn.query_row(
        "SELECT joined_at FROM channel_members
         WHERE channel_id = ?1 AND entity_key = ?2 AND posture = 'active'",
        params![channel_id, entity_key.as_slice()],
        |row| row.get(0),
    ) {
        Ok(at) => Ok(Some(at)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(CordeliaError::Storage(e.to_string())),
    }
}

/// Group channels (network scope) in which `entity_key` is an active owner.
pub fn list_owned_groups(
    conn: &Connection,
    entity_key: &[u8; 32],
) -> Result<Vec<Channel>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT c.channel_id, c.channel_name, c.channel_type, c.mode, c.access,
                    c.creator_id, c.key_version, c.psk_hash, c.created_at, c.updated_at, c.scope
             FROM channels c
             INNER JOIN channel_members m ON c.channel_id = m.channel_id
             WHERE m.entity_key = ?1 AND m.posture = 'active' AND m.role = 'owner'
               AND c.channel_type = 'group' AND c.scope = 'network'
             ORDER BY c.created_at ASC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(params![entity_key.as_slice()], channel_from_row)
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }
    Ok(out)
}

/// Look up a channel by name (canonicalizes first) or by raw channel ID.
pub fn get(conn: &Connection, name_or_id: &str) -> Result<Channel, CordeliaError> {
    let channel_type = ChannelType::from_id(name_or_id);

    let channel_id = match channel_type {
        ChannelType::Named => {
            // Could be a name or a hex ID. Try canonicalize first.
            if let Ok(canonical) = naming::canonicalize(name_or_id) {
                naming::named_channel_id(&canonical)
            } else {
                // Assume it's already a hex channel ID
                name_or_id.to_string()
            }
        }
        _ => name_or_id.to_string(),
    };

    get_by_id(conn, &channel_id)
}

/// Look up a channel by its exact channel_id.
pub fn get_by_id(conn: &Connection, channel_id: &str) -> Result<Channel, CordeliaError> {
    conn.query_row(
        "SELECT channel_id, channel_name, channel_type, mode, access, creator_id,
                key_version, psk_hash, created_at, updated_at, scope
         FROM channels WHERE channel_id = ?1",
        params![channel_id],
        |row| {
            let creator_blob: Vec<u8> = row.get(5)?;
            let mut creator_id = [0u8; 32];
            if creator_blob.len() == 32 {
                creator_id.copy_from_slice(&creator_blob);
            }
            Ok(Channel {
                channel_id: row.get(0)?,
                channel_name: row.get(1)?,
                channel_type: row.get(2)?,
                mode: row.get(3)?,
                access: row.get(4)?,
                scope: row.get(10)?,
                creator_id,
                key_version: row.get(6)?,
                psk_hash: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => CordeliaError::ChannelNotFound {
            channel: channel_id.to_string(),
        },
        other => CordeliaError::Storage(other.to_string()),
    })
}

/// Resolve a user-facing channel reference to a ChannelId.
///
/// Handles the full prefix disambiguation logic from channel-naming.md §5:
/// - Plain name → canonicalize + SHA-256
/// - `dm_...` → direct ID
/// - `grp_...` → direct ID
pub fn resolve(name_or_id: &str) -> Result<ChannelId, CordeliaError> {
    let channel_type = ChannelType::from_id(name_or_id);

    match channel_type {
        ChannelType::Named => {
            let canonical = naming::canonicalize(name_or_id)?;
            Ok(ChannelId(naming::named_channel_id(&canonical)))
        }
        ChannelType::Dm | ChannelType::Group | ChannelType::Inbox | ChannelType::Protocol => {
            Ok(ChannelId(name_or_id.to_string()))
        }
    }
}

/// Map a row (with 11 columns ending in scope) to a Channel struct.
fn channel_from_row(row: &rusqlite::Row) -> rusqlite::Result<Channel> {
    let creator_blob: Vec<u8> = row.get(5)?;
    let mut creator_id = [0u8; 32];
    if creator_blob.len() == 32 {
        creator_id.copy_from_slice(&creator_blob);
    }
    Ok(Channel {
        channel_id: row.get(0)?,
        channel_name: row.get(1)?,
        channel_type: row.get(2)?,
        mode: row.get(3)?,
        access: row.get(4)?,
        scope: row.get(10)?,
        creator_id,
        key_version: row.get(6)?,
        psk_hash: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

/// List channels the given entity is a member of.
pub fn list_for_entity(
    conn: &Connection,
    entity_key: &[u8; 32],
) -> Result<Vec<Channel>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT c.channel_id, c.channel_name, c.channel_type, c.mode, c.access,
                    c.creator_id, c.key_version, c.psk_hash, c.created_at, c.updated_at, c.scope
             FROM channels c
             INNER JOIN channel_members m ON c.channel_id = m.channel_id
             WHERE m.entity_key = ?1 AND m.posture = 'active'
             ORDER BY c.updated_at DESC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![entity_key.as_slice()], channel_from_row)
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut channels = Vec::new();
    for row in rows {
        channels.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }
    Ok(channels)
}

/// List distinct channel IDs that have stored items.
/// Used by relay nodes for pull-sync: relays aren't channel members
/// but need to sync channels they've received items for.
pub fn list_stored_channel_ids(conn: &Connection) -> Result<Vec<String>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT DISTINCT channel_id FROM items")
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }
    Ok(ids)
}

/// Whether this node has a row for the channel.
pub fn exists(conn: &Connection, channel_id: &str) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM channels WHERE channel_id = ?1)",
        params![channel_id],
        |row| row.get(0),
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))
}

/// The channel a relay came to hold most recently. When a relay is over
/// its cap it makes room by dropping this one, so that what was there
/// first is never pushed out by what came later.
pub fn newest_stored(conn: &Connection) -> Result<Option<String>, CordeliaError> {
    match conn.query_row(
        "SELECT channel_id FROM channels
         WHERE channel_id IN (SELECT DISTINCT channel_id FROM items)
         ORDER BY created_at DESC, rowid DESC LIMIT 1",
        [],
        |row| row.get(0),
    ) {
        Ok(id) => Ok(Some(id)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(CordeliaError::Storage(e.to_string())),
    }
}

/// Drop a channel that this node only stores: its items, and its row if
/// it has no members. Returns how many items went. For a relay, which holds
/// no keys or members for a channel; and for the inbox of another key,
/// which a device writes into without being a member of it.
pub fn drop_stored(conn: &Connection, channel_id: &str) -> Result<usize, CordeliaError> {
    let storage = |e: rusqlite::Error| CordeliaError::Storage(e.to_string());
    conn.execute(
        "DELETE FROM search_content WHERE channel_id = ?1",
        params![channel_id],
    )
    .map_err(storage)?;
    let items = conn
        .execute(
            "DELETE FROM items WHERE channel_id = ?1",
            params![channel_id],
        )
        .map_err(storage)?;
    conn.execute(
        "DELETE FROM channels WHERE channel_id = ?1
           AND NOT EXISTS (SELECT 1 FROM channel_members WHERE channel_id = ?1)",
        params![channel_id],
    )
    .map_err(storage)?;
    Ok(items)
}

/// The tables that refer to a channel by ID, other than `channels` itself
/// and the two that [`drop_stored`] empties (`items` and `search_content`).
/// A table that comes to refer to a channel by ID belongs here too: the
/// test of [`remove_swarm_channels`] reads the schema, and fails until it
/// is added.
const TABLES_OF_A_CHANNEL: [&str; 7] = [
    "channel_members",
    "channel_keys",
    "dm_peers",
    "invites",
    "state_offers",
    "sync_files",
    "index_lines",
];

/// Remove a channel from the database with everything held for it there:
/// its members, the rows of every table that refers to it by ID, its
/// items, and its own row. Returns how many items went. The caller makes
/// it one transaction.
fn remove(conn: &Connection, channel_id: &str) -> Result<usize, CordeliaError> {
    for table in TABLES_OF_A_CHANNEL {
        conn.execute(
            &format!("DELETE FROM {table} WHERE channel_id = ?1"),
            params![channel_id],
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    }
    // With no member left, this takes the channel's row with its items.
    drop_stored(conn, channel_id)
}

/// What [`remove_swarm_channels`] removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RemovedSwarmChannels {
    pub channels: usize,
    /// The items those channels held.
    pub items: usize,
    /// The key files kept for them.
    pub key_files: usize,
    /// The key files kept for them that could not be removed, and are
    /// still there.
    pub key_files_left: usize,
}

impl RemovedSwarmChannels {
    /// Whether anything was removed.
    pub fn any(&self) -> bool {
        self.channels > 0 || self.items > 0 || self.key_files > 0
    }
}

/// Remove every swarm channel this node holds (an ID that begins
/// [`naming::SWARM_CHANNEL_PREFIX`]), with its members, its items, every
/// row that refers to it, and its key files.
///
/// A node makes no channel that it does not use. Up to 0.2.0-alpha.7 a
/// personal node made a swarm channel for itself each time it started, and
/// v1 publishes nothing in one and reads nothing from one. Its ID holds the
/// node's entity ID, which holds a name, so it is not one a node should
/// keep: a node removes any it finds when it starts. What such a channel
/// holds goes with it, since nothing reads it.
///
/// The rows go in one transaction, and the key files after it. The files
/// are found by name, so a start that is cut short between the two leaves
/// nothing for good: the next start takes the files.
///
/// It fails only where the database does. A key file that cannot be
/// removed is counted and left, and tried again at the next start: it is
/// for the node to say so, and no reason for it not to start.
pub fn remove_swarm_channels(
    conn: &Connection,
    home_dir: &std::path::Path,
) -> Result<RemovedSwarmChannels, CordeliaError> {
    let storage = |e: rusqlite::Error| CordeliaError::Storage(e.to_string());
    let batch =
        rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
    let ids: Vec<String> = {
        let mut stmt = batch
            .prepare("SELECT channel_id FROM channels WHERE substr(channel_id, 1, ?1) = ?2")
            .map_err(storage)?;
        let rows = stmt
            .query_map(
                params![
                    naming::SWARM_CHANNEL_PREFIX.len() as i64,
                    naming::SWARM_CHANNEL_PREFIX
                ],
                |row| row.get(0),
            )
            .map_err(storage)?;
        rows.collect::<Result<_, _>>().map_err(storage)?
    };
    let mut items = 0;
    for id in &ids {
        items += remove(&batch, id)?;
    }
    batch.commit().map_err(storage)?;
    let (key_files, key_files_left) = crate::psk::delete_swarm_keys(home_dir);
    Ok(RemovedSwarmChannels {
        channels: ids.len(),
        items,
        key_files,
        key_files_left,
    })
}

/// Create a local-scope channel (ephemeral, never forwarded to relay mesh).
///
/// Uses a protocol-prefixed channel ID. The `channel_id` must be provided
/// (typically generated by the caller, e.g. `cordelia:local:<uuid>`).
pub fn create_local(
    conn: &Connection,
    channel_id: &str,
    creator_id: &[u8; 32],
    psk: Option<&[u8; 32]>,
) -> Result<Channel, CordeliaError> {
    let now = Utc::now().to_rfc3339();
    let psk_hash = psk.map(|k| Sha256::digest(k).to_vec());

    conn.execute(
        "INSERT INTO channels (channel_id, channel_type, mode, access, scope, creator_id, psk_hash, created_at, updated_at)
         VALUES (?1, 'named', 'realtime', 'invite_only', 'local', ?2, ?3, ?4, ?5)",
        params![channel_id, creator_id.as_slice(), psk_hash, now, now],
    )
    .map_err(|e| {
        if is_unique_violation(&e) {
            CordeliaError::ChannelAlreadyExists {
                channel: channel_id.to_string(),
            }
        } else {
            CordeliaError::Storage(e.to_string())
        }
    })?;

    conn.execute(
        "INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
         VALUES (?1, ?2, 'owner', ?3)",
        params![channel_id, creator_id.as_slice(), now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    Ok(Channel {
        channel_id: channel_id.to_string(),
        channel_name: None,
        channel_type: "named".into(),
        mode: "realtime".into(),
        access: "invite_only".into(),
        scope: "local".into(),
        creator_id: *creator_id,
        key_version: 1,
        psk_hash,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// List network-scope channels for an entity (excludes local channels).
pub fn list_network_channels(
    conn: &Connection,
    entity_key: &[u8; 32],
) -> Result<Vec<Channel>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT c.channel_id, c.channel_name, c.channel_type, c.mode, c.access,
                    c.creator_id, c.key_version, c.psk_hash, c.created_at, c.updated_at, c.scope
             FROM channels c
             INNER JOIN channel_members m ON c.channel_id = m.channel_id
             WHERE m.entity_key = ?1 AND m.posture = 'active' AND c.scope = 'network'
             ORDER BY c.updated_at DESC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![entity_key.as_slice()], channel_from_row)
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut channels = Vec::new();
    for row in rows {
        channels.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }
    Ok(channels)
}

/// List local-scope channels for an entity.
pub fn list_local_channels(
    conn: &Connection,
    entity_key: &[u8; 32],
) -> Result<Vec<Channel>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT c.channel_id, c.channel_name, c.channel_type, c.mode, c.access,
                    c.creator_id, c.key_version, c.psk_hash, c.created_at, c.updated_at, c.scope
             FROM channels c
             INNER JOIN channel_members m ON c.channel_id = m.channel_id
             WHERE m.entity_key = ?1 AND m.posture = 'active' AND c.scope = 'local'
             ORDER BY c.updated_at DESC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![entity_key.as_slice()], channel_from_row)
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut channels = Vec::new();
    for row in rows {
        channels.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }
    Ok(channels)
}

/// Check if a channel has local scope (should not be forwarded to relay mesh).
pub fn is_local_scope(conn: &Connection, channel_id: &str) -> Result<bool, CordeliaError> {
    let scope: String = conn
        .query_row(
            "SELECT scope FROM channels WHERE channel_id = ?1",
            params![channel_id],
            |row| row.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => CordeliaError::ChannelNotFound {
                channel: channel_id.to_string(),
            },
            other => CordeliaError::Storage(other.to_string()),
        })?;
    Ok(scope == "local")
}

/// Add a member to a channel.
pub fn add_member(
    conn: &Connection,
    channel_id: &str,
    entity_key: &[u8; 32],
    role: &str,
) -> Result<(), CordeliaError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(channel_id, entity_key) DO UPDATE SET
            role = excluded.role,
            posture = 'active',
            removed_at = NULL",
        params![channel_id, entity_key.as_slice(), role, now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Soft-remove a member from a channel.
pub fn remove_member(
    conn: &Connection,
    channel_id: &str,
    entity_key: &[u8; 32],
) -> Result<(), CordeliaError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE channel_members SET posture = 'removed', removed_at = ?1
         WHERE channel_id = ?2 AND entity_key = ?3",
        params![now, channel_id, entity_key.as_slice()],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Get a member's role in a channel, or None if not an active member.
pub fn get_member_role(
    conn: &Connection,
    channel_id: &str,
    entity_key: &[u8; 32],
) -> Result<Option<String>, CordeliaError> {
    conn.query_row(
        "SELECT role FROM channel_members
         WHERE channel_id = ?1 AND entity_key = ?2 AND posture = 'active'",
        params![channel_id, entity_key.as_slice()],
        |row| row.get(0),
    )
    .map_or_else(
        |e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(CordeliaError::Storage(other.to_string())),
        },
        |role| Ok(Some(role)),
    )
}

/// Check if an entity is an active member of a channel.
pub fn is_member(
    conn: &Connection,
    channel_id: &str,
    entity_key: &[u8; 32],
) -> Result<bool, CordeliaError> {
    Ok(get_member_role(conn, channel_id, entity_key)?.is_some())
}

/// Count active members in a channel.
pub fn member_count(conn: &Connection, channel_id: &str) -> Result<i64, CordeliaError> {
    conn.query_row(
        "SELECT COUNT(*) FROM channel_members WHERE channel_id = ?1 AND posture = 'active'",
        params![channel_id],
        |row| row.get(0),
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))
}

/// List DM channels for an entity.
pub fn list_dms_for_entity(
    conn: &Connection,
    entity_key: &[u8; 32],
) -> Result<Vec<Channel>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT c.channel_id, c.channel_name, c.channel_type, c.mode, c.access,
                    c.creator_id, c.key_version, c.psk_hash, c.created_at, c.updated_at, c.scope
             FROM channels c
             INNER JOIN channel_members m ON c.channel_id = m.channel_id
             WHERE m.entity_key = ?1 AND m.posture = 'active' AND c.channel_type = 'dm'
             ORDER BY c.updated_at DESC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![entity_key.as_slice()], channel_from_row)
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut channels = Vec::new();
    for row in rows {
        channels.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }
    Ok(channels)
}

/// List group channels for an entity.
pub fn list_groups_for_entity(
    conn: &Connection,
    entity_key: &[u8; 32],
) -> Result<Vec<Channel>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT c.channel_id, c.channel_name, c.channel_type, c.mode, c.access,
                    c.creator_id, c.key_version, c.psk_hash, c.created_at, c.updated_at, c.scope
             FROM channels c
             INNER JOIN channel_members m ON c.channel_id = m.channel_id
             WHERE m.entity_key = ?1 AND m.posture = 'active' AND c.channel_type = 'group'
             ORDER BY c.updated_at DESC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![entity_key.as_slice()], channel_from_row)
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut channels = Vec::new();
    for row in rows {
        channels.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }
    Ok(channels)
}

/// List all active member public keys for a channel.
pub fn list_active_member_keys(
    conn: &Connection,
    channel_id: &str,
) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT entity_key FROM channel_members
             WHERE channel_id = ?1 AND posture = 'active'",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![channel_id], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut keys = Vec::new();
    for row in rows {
        let blob = row.map_err(|e| CordeliaError::Storage(e.to_string()))?;
        if blob.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&blob);
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Every key that is an active member of any channel this node has a row
/// for, each once.
pub fn all_active_member_keys(conn: &Connection) -> Result<Vec<[u8; 32]>, CordeliaError> {
    let storage = |e: rusqlite::Error| CordeliaError::Storage(e.to_string());
    let mut stmt = conn
        .prepare("SELECT DISTINCT entity_key FROM channel_members WHERE posture = 'active'")
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(storage)?;
    let mut keys = Vec::new();
    for row in rows {
        if let Ok(key) = <[u8; 32]>::try_from(row.map_err(storage)?.as_slice()) {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Soft-remove a key from every channel it is an active member of. Returns
/// how many channels that was.
pub fn remove_member_everywhere(
    conn: &Connection,
    entity_key: &[u8; 32],
) -> Result<usize, CordeliaError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE channel_members SET posture = 'removed', removed_at = ?1
         WHERE entity_key = ?2 AND posture = 'active'",
        params![now, entity_key.as_slice()],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))
}

/// Increment key_version and update psk_hash after a PSK rotation.
pub fn increment_key_version(
    conn: &Connection,
    channel_id: &str,
    new_psk_hash: &[u8],
) -> Result<i64, CordeliaError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE channels SET key_version = key_version + 1, psk_hash = ?1, updated_at = ?2
         WHERE channel_id = ?3",
        params![new_psk_hash, now, channel_id],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    conn.query_row(
        "SELECT key_version FROM channels WHERE channel_id = ?1",
        params![channel_id],
        |row| row.get(0),
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))
}

/// Look up the peer key in a DM channel (the key that isn't the local key).
pub fn dm_peer_key(conn: &Connection, channel_id: &str) -> Result<[u8; 32], CordeliaError> {
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT peer_key FROM dm_peers WHERE channel_id = ?1",
            params![channel_id],
            |row| row.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => CordeliaError::ChannelNotFound {
                channel: channel_id.to_string(),
            },
            other => CordeliaError::Storage(other.to_string()),
        })?;

    if blob.len() != 32 {
        return Err(CordeliaError::Storage("dm_peers key not 32 bytes".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&blob);
    Ok(key)
}

fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(err, _)
        if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        || err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn test_creator() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn test_psk() -> [u8; 32] {
        [0xABu8; 32]
    }

    /// T20. An epoch over the limit is not stored, and one that an earlier
    /// version stored reads as zero and not as a huge or wrapped number.
    #[test]
    fn an_epoch_over_the_limit_is_neither_stored_nor_read() {
        use cordelia_core::protocol::MAX_EPOCH;
        let conn = db::open_in_memory().unwrap();
        let ch = "grp_550e8400-e29b-41d4-a716-446655440000";
        ensure_group(&conn, ch, None, "realtime", &test_creator()).unwrap();
        let author = [0x07u8; 32];

        set_state(&conn, ch, MAX_EPOCH, &author, 1, &[0x01; 32]).unwrap();
        assert_eq!(epoch(&conn, ch).unwrap().0, MAX_EPOCH);
        for over in [MAX_EPOCH + 1, i64::MAX as u64, u64::MAX] {
            assert!(set_state(&conn, ch, over, &author, 1, &[0x01; 32]).is_err());
            assert_eq!(epoch(&conn, ch).unwrap().0, MAX_EPOCH, "{over}");
        }

        for stored in [-1i64, i64::MIN, i64::MAX, MAX_EPOCH as i64 + 1] {
            conn.execute(
                "UPDATE channels SET epoch = ?1 WHERE channel_id = ?2",
                params![stored, ch],
            )
            .unwrap();
            assert_eq!(epoch(&conn, ch).unwrap().0, 0, "{stored}");
        }
    }

    /// The channel that a personal node made for itself each time it
    /// started, up to 0.2.0-alpha.7, made as that version made it: its
    /// row, the node as its owner, and its key file.
    fn swarm_channel_as_it_was_made(
        conn: &Connection,
        home: &std::path::Path,
        entity_id: &str,
        pk: &[u8; 32],
    ) -> String {
        let id = naming::swarm_channel_id(entity_id);
        let now = Utc::now().to_rfc3339();
        let psk = [0x5Cu8; 32];
        conn.execute(
            "INSERT OR IGNORE INTO channels (channel_id, channel_type, mode, access, scope, creator_id, psk_hash, created_at, updated_at)
             VALUES (?1, 'named', 'realtime', 'invite_only', 'network', ?2, ?3, ?4, ?5)",
            params![id, pk.as_slice(), Sha256::digest(psk).as_slice(), now, now],
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO channel_members (channel_id, entity_key, role, joined_at)
             VALUES (?1, ?2, 'owner', ?3)",
            params![id, pk.as_slice(), now],
        )
        .unwrap();
        crate::psk::write_psk(home, &id, &psk).unwrap();
        id
    }

    /// A row for `channel_id` in every table that refers to a channel by
    /// ID, beyond the channel's own row and its first member: an item with
    /// what search keeps of it, and one row in each other table. `n` keeps
    /// one channel's rows apart from another's.
    fn a_row_in_every_table(conn: &Connection, channel_id: &str, n: u8) {
        let item_id = format!("ci_{n}");
        assert!(
            crate::items::insert_item(
                conn,
                &crate::items::NewItem::plain(
                    &item_id,
                    channel_id,
                    &test_creator(),
                    "message",
                    "2026-01-01T00:00:00Z",
                    1,
                    &[n; 32],
                    &[0x02; 64],
                    &[0x03; 100],
                ),
            )
            .unwrap()
        );
        conn.execute(
            "INSERT INTO search_content (item_id, channel_id, item_type, published_at, content_text)
             VALUES (?1, ?2, 'message', '2026-01-01T00:00:00Z', 'kept for search')",
            params![item_id, channel_id],
        )
        .unwrap();
        add_member(conn, channel_id, &[0x99; 32], "member").unwrap();
        for sql in [
            "INSERT INTO channel_keys (channel_id, encrypted_psk) VALUES (?1, X'01')",
            "INSERT INTO dm_peers (channel_id, peer_key) VALUES (?1, X'02')",
            "INSERT INTO invites (item_id, inviter, channel_id, status, received_at)
             VALUES ('ci_invite_' || ?1, X'03', ?1, 'pending', '2026-01-01')",
            "INSERT INTO state_offers (channel_id, member, epoch, item_id, sent_at, last_offered_at)
             VALUES (?1, X'04', 1, 'ci_state', 0, 0)",
            "INSERT INTO sync_files (folder, channel_id, key, rev) VALUES ('/m', ?1, 'notes.md', 1)",
            "INSERT INTO index_lines (folder, channel_id, file) VALUES ('/m', ?1, 'notes.md')",
        ] {
            conn.execute(sql, params![channel_id]).unwrap();
        }
    }

    /// The tables that refer to a channel by an ID that is text, as the
    /// schema has them, and how many rows each holds for `channel_id`. An
    /// ID that is text can hold a name. A channel from its secret is
    /// known by 32 bytes, which hold none: the tables of those are not
    /// among these.
    fn rows_by_table(conn: &Connection, channel_id: &str) -> Vec<(String, i64)> {
        let tables: Vec<String> = conn
            .prepare(
                "SELECT m.name FROM sqlite_master m, pragma_table_info(m.name) c
                 WHERE m.type = 'table' AND c.name = 'channel_id' AND c.type = 'TEXT'
                 ORDER BY m.name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        tables
            .into_iter()
            .map(|table| {
                let rows = conn
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE channel_id = ?1"),
                        params![channel_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                (table, rows)
            })
            .collect()
    }

    /// A node makes no channel that it does not use, and removes the one
    /// an earlier version made when it starts: its row, its members, its
    /// items, every row that refers to it, and its key files. Every other
    /// channel is left as it was, with its keys. A second start finds
    /// nothing to remove.
    #[test]
    fn a_swarm_channel_is_removed_with_everything_held_for_it() {
        let conn = db::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let me = test_creator();
        let key_files = |home: &std::path::Path| -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(home.join("channel-keys"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        };

        // The node's own, as an earlier version made it, which has come to
        // hold an item and a row in every table; and one with a ring and a
        // slot key besides its key, as a channel whose key changed has.
        let own = swarm_channel_as_it_was_made(&conn, home, "lead_a1b2", &me);
        a_row_in_every_table(&conn, &own, 1);
        let other = swarm_channel_as_it_was_made(&conn, home, "other_c3d4", &me);
        crate::psk::rotate_psk(home, &other, &[0x5D; 32], "2026-01-01T00:00:00Z").unwrap();
        crate::psk::write_slot_key(home, &other, &[0x5E; 32]).unwrap();

        // What the node does use: a group, its inbox, and a local channel,
        // whose ID begins as a swarm channel's does up to the second word.
        let group = create_group(&conn, &me, "realtime", None, Some(&test_psk())).unwrap();
        let group = group.channel_id;
        a_row_in_every_table(&conn, &group, 2);
        let inbox = naming::inbox_channel_id(&me);
        ensure_inbox(&conn, &inbox, &me, true).unwrap();
        let local = "cordelia:local:550e8400";
        create_local(&conn, local, &me, Some(&test_psk())).unwrap();
        for kept in [group.as_str(), local] {
            crate::psk::write_psk(home, kept, &test_psk()).unwrap();
        }
        crate::psk::write_slot_key(home, &group, &[0x5F; 32]).unwrap();
        let kept_keys = vec![
            format!("{local}.key"),
            format!("{group}.key"),
            format!("{group}.slot"),
        ];

        // Every table that refers to a channel by ID is one the removal
        // knows of, and each holds something for the node's own.
        let before = rows_by_table(&conn, &own);
        let mut known: Vec<&str> = TABLES_OF_A_CHANNEL.to_vec();
        known.extend(["channels", "items", "search_content"]);
        known.sort();
        assert_eq!(
            before.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
            known,
            "a table refers to a channel by ID and is not removed from"
        );
        assert!(before.iter().all(|(_, rows)| *rows > 0), "{before:?}");
        let of_group = rows_by_table(&conn, &group);
        assert_eq!(key_files(home).len(), kept_keys.len() + 4);

        let removed = remove_swarm_channels(&conn, home).unwrap();
        assert_eq!(
            removed,
            RemovedSwarmChannels {
                channels: 2,
                items: 1,
                key_files: 4,
                key_files_left: 0,
            }
        );
        assert!(removed.any());
        for gone in [&own, &other] {
            let rows = rows_by_table(&conn, gone);
            assert!(rows.iter().all(|(_, rows)| *rows == 0), "{gone}: {rows:?}");
            assert!(!exists(&conn, gone).unwrap());
        }
        assert_eq!(key_files(home), kept_keys);
        // Nothing of the item is left for search to find.
        let indexed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM search_fts WHERE search_fts MATCH 'kept'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexed, 1, "the group's item, and not the swarm channel's");

        // The channels the node uses are as they were.
        assert_eq!(rows_by_table(&conn, &group), of_group);
        let mut left: Vec<String> = list_for_entity(&conn, &me)
            .unwrap()
            .into_iter()
            .map(|c| c.channel_id)
            .collect();
        left.sort();
        let mut expected = vec![group.clone(), inbox, local.to_string()];
        expected.sort();
        assert_eq!(left, expected);
        assert_eq!(crate::psk::read_psk(home, &group).unwrap(), test_psk());

        // A second start has nothing to remove, and says nothing.
        let again = remove_swarm_channels(&conn, home).unwrap();
        assert!(!again.any(), "{again:?}");
        assert_eq!(key_files(home), kept_keys);
    }

    /// The rows of a swarm channel go together or not at all, and its key
    /// files only once they have gone. A removal that fails part of the
    /// way leaves the channel whole, and the next one takes all of it. A
    /// key file whose channel has no row is taken too.
    #[test]
    fn a_swarm_channel_is_removed_whole_or_not_at_all() {
        let conn = db::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let own = swarm_channel_as_it_was_made(&conn, home, "lead_a1b2", &test_creator());
        a_row_in_every_table(&conn, &own, 1);
        let before = rows_by_table(&conn, &own);

        // The last statement of the removal fails: the channel's own row
        // cannot be deleted.
        conn.execute_batch(
            "CREATE TRIGGER refuse BEFORE DELETE ON channels
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .unwrap();
        assert!(remove_swarm_channels(&conn, home).is_err());
        assert_eq!(rows_by_table(&conn, &own), before);
        assert!(crate::psk::has_psk(home, &own));

        conn.execute_batch("DROP TRIGGER refuse;").unwrap();
        let removed = remove_swarm_channels(&conn, home).unwrap();
        assert_eq!(
            (removed.channels, removed.items, removed.key_files),
            (1, 1, 1)
        );
        assert!(!crate::psk::has_psk(home, &own));

        // A key file left behind by a removal that was cut short after its
        // rows had gone.
        crate::psk::write_psk(home, &own, &[0x5C; 32]).unwrap();
        let removed = remove_swarm_channels(&conn, home).unwrap();
        assert_eq!(
            (removed.channels, removed.items, removed.key_files),
            (0, 0, 1)
        );
        assert!(!crate::psk::has_psk(home, &own));

        // A node with no key directory at all has nothing to remove.
        let empty = tempfile::tempdir().unwrap();
        assert!(!remove_swarm_channels(&conn, empty.path()).unwrap().any());
    }

    /// A key file that cannot be removed does not fail the removal. It is
    /// counted, and all that can go goes: the channel's rows, and its
    /// other key files. The next removal tries it again, and takes it once
    /// it can be removed. (Here it is a directory where a slot key would
    /// be, which cannot be removed as a file is.)
    #[test]
    fn a_key_file_that_cannot_be_removed_is_counted_and_fails_nothing() {
        let conn = db::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let own = swarm_channel_as_it_was_made(&conn, home, "lead_a1b2", &test_creator());
        let stuck = crate::psk::slot_key_path(home, &own);
        std::fs::create_dir(&stuck).unwrap();

        let removed = remove_swarm_channels(&conn, home).unwrap();
        assert_eq!(
            removed,
            RemovedSwarmChannels {
                channels: 1,
                items: 0,
                key_files: 1,
                key_files_left: 1,
            }
        );
        assert!(!exists(&conn, &own).unwrap());
        assert!(!crate::psk::has_psk(home, &own));
        assert!(stuck.exists());

        // Nothing more to remove, and the one that is left is counted
        // again: there was nothing to say was removed.
        let again = remove_swarm_channels(&conn, home).unwrap();
        assert!(!again.any(), "{again:?}");
        assert_eq!(again.key_files_left, 1);

        // Once it can be removed, it is.
        std::fs::remove_dir(&stuck).unwrap();
        crate::psk::write_slot_key(home, &own, &[0x5E; 32]).unwrap();
        let last = remove_swarm_channels(&conn, home).unwrap();
        assert_eq!((last.key_files, last.key_files_left), (1, 0));
        assert!(!stuck.exists());
    }

    #[test]
    fn test_create_named_channel() {
        let conn = db::open_in_memory().unwrap();
        let ch = create_named(
            &conn,
            "research-findings",
            "realtime",
            "open",
            &test_creator(),
            Some(&test_psk()),
        )
        .unwrap();

        assert_eq!(ch.channel_name.as_deref(), Some("research-findings"));
        assert_eq!(ch.channel_type, "named");
        assert_eq!(
            ch.channel_id,
            "fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6"
        );
    }

    #[test]
    fn test_create_named_canonicalizes() {
        let conn = db::open_in_memory().unwrap();
        let ch = create_named(
            &conn,
            "  Research-Findings  ",
            "realtime",
            "open",
            &test_creator(),
            None,
        )
        .unwrap();
        assert_eq!(ch.channel_name.as_deref(), Some("research-findings"));
    }

    #[test]
    fn test_create_named_duplicate_fails() {
        let conn = db::open_in_memory().unwrap();
        create_named(&conn, "engineering", "batch", "open", &test_creator(), None).unwrap();
        let result = create_named(&conn, "engineering", "batch", "open", &test_creator(), None);
        assert!(matches!(
            result,
            Err(CordeliaError::ChannelAlreadyExists { .. })
        ));
    }

    #[test]
    fn test_create_named_invalid_name() {
        let conn = db::open_in_memory().unwrap();
        let result = create_named(&conn, "ab", "realtime", "open", &test_creator(), None);
        assert!(matches!(
            result,
            Err(CordeliaError::InvalidChannelName { .. })
        ));
    }

    #[test]
    fn test_create_dm() {
        let conn = db::open_in_memory().unwrap();
        let pk_a = [0x01u8; 32];
        let pk_b = [0x02u8; 32];

        let ch = create_dm(&conn, &pk_a, &pk_b, Some(&test_psk())).unwrap();
        assert!(ch.channel_id.starts_with("dm_"));
        assert_eq!(ch.channel_type, "dm");
        assert_eq!(ch.access, "invite_only");

        // Verify dm_peers row
        let peer: Vec<u8> = conn
            .query_row(
                "SELECT peer_key FROM dm_peers WHERE channel_id = ?1",
                params![ch.channel_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(peer, pk_b.to_vec());
    }

    #[test]
    fn test_create_dm_symmetric() {
        // dm(a,b) and dm(b,a) should produce the same channel_id
        let pk_a = [0x01u8; 32];
        let pk_b = [0x02u8; 32];
        let id_ab = naming::dm_channel_id(&pk_a, &pk_b);
        let id_ba = naming::dm_channel_id(&pk_b, &pk_a);
        assert_eq!(id_ab, id_ba);
    }

    #[test]
    fn test_create_group() {
        let conn = db::open_in_memory().unwrap();
        let ch = create_group(&conn, &test_creator(), "realtime", None, None).unwrap();
        assert!(ch.channel_id.starts_with("grp_"));
        assert_eq!(ch.channel_type, "group");
    }

    #[test]
    fn test_get_by_name() {
        let conn = db::open_in_memory().unwrap();
        create_named(&conn, "engineering", "batch", "open", &test_creator(), None).unwrap();

        let ch = get(&conn, "engineering").unwrap();
        assert_eq!(ch.channel_name.as_deref(), Some("engineering"));
    }

    #[test]
    fn test_get_not_found() {
        let conn = db::open_in_memory().unwrap();
        let result = get(&conn, "nonexistent");
        assert!(matches!(result, Err(CordeliaError::ChannelNotFound { .. })));
    }

    #[test]
    fn test_resolve_named() {
        let id = resolve("research-findings").unwrap();
        assert_eq!(
            id.0,
            "fe028fdaf943c16ec8a1fc496818274ce7e86e921ad926f9712886fa26d309d6"
        );
    }

    #[test]
    fn test_resolve_dm_passthrough() {
        let id = resolve("dm_abc123").unwrap();
        assert_eq!(id.0, "dm_abc123");
    }

    #[test]
    fn test_resolve_group_passthrough() {
        let id = resolve("grp_550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(id.0, "grp_550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_list_for_entity() {
        let conn = db::open_in_memory().unwrap();
        let creator = test_creator();

        create_named(&conn, "alpha", "realtime", "open", &creator, None).unwrap();
        create_named(&conn, "beta", "batch", "open", &creator, None).unwrap();

        let channels = list_for_entity(&conn, &creator).unwrap();
        assert_eq!(channels.len(), 2);
    }

    #[test]
    fn test_add_and_remove_member() {
        let conn = db::open_in_memory().unwrap();
        let creator = test_creator();
        let member = [0x99u8; 32];

        let ch = create_named(&conn, "team-chat", "realtime", "open", &creator, None).unwrap();
        add_member(&conn, &ch.channel_id, &member, "member").unwrap();

        let channels = list_for_entity(&conn, &member).unwrap();
        assert_eq!(channels.len(), 1);

        remove_member(&conn, &ch.channel_id, &member).unwrap();
        let channels = list_for_entity(&conn, &member).unwrap();
        assert_eq!(channels.len(), 0);
    }

    #[test]
    fn test_create_local_channel() {
        let conn = db::open_in_memory().unwrap();
        let creator = test_creator();
        let ch = create_local(
            &conn,
            "cordelia:local:test-session",
            &creator,
            Some(&test_psk()),
        )
        .unwrap();
        assert_eq!(ch.scope, "local");
        assert_eq!(ch.access, "invite_only");
        assert_eq!(ch.channel_id, "cordelia:local:test-session");
    }

    #[test]
    fn test_list_network_excludes_local() {
        let conn = db::open_in_memory().unwrap();
        let creator = test_creator();
        create_named(&conn, "network-chan", "realtime", "open", &creator, None).unwrap();
        create_local(&conn, "cordelia:local:ephemeral", &creator, None).unwrap();

        let network = list_network_channels(&conn, &creator).unwrap();
        assert_eq!(network.len(), 1);
        assert_eq!(network[0].channel_name.as_deref(), Some("network-chan"));

        let local = list_local_channels(&conn, &creator).unwrap();
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].channel_id, "cordelia:local:ephemeral");
    }

    #[test]
    fn test_is_local_scope() {
        let conn = db::open_in_memory().unwrap();
        let creator = test_creator();
        create_named(&conn, "net-chan", "realtime", "open", &creator, None).unwrap();
        create_local(&conn, "cordelia:local:scratch", &creator, None).unwrap();

        let net_id = naming::named_channel_id("net-chan");
        assert!(!is_local_scope(&conn, &net_id).unwrap());
        assert!(is_local_scope(&conn, "cordelia:local:scratch").unwrap());
    }

    #[test]
    fn test_default_scope_is_network() {
        let conn = db::open_in_memory().unwrap();
        let creator = test_creator();
        let ch = create_named(&conn, "default-scope", "realtime", "open", &creator, None).unwrap();
        assert_eq!(ch.scope, "network");
    }

    #[test]
    fn test_readd_removed_member() {
        let conn = db::open_in_memory().unwrap();
        let creator = test_creator();
        let member = [0x99u8; 32];

        let ch = create_named(&conn, "team-chat", "realtime", "open", &creator, None).unwrap();
        add_member(&conn, &ch.channel_id, &member, "member").unwrap();
        remove_member(&conn, &ch.channel_id, &member).unwrap();

        // Re-add should work (upsert)
        add_member(&conn, &ch.channel_id, &member, "admin").unwrap();
        let channels = list_for_entity(&conn, &member).unwrap();
        assert_eq!(channels.len(), 1);
    }
}
