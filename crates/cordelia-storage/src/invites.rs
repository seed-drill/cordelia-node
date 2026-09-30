//! Processing state for invites (channel-state items) in this node's inbox.
//!
//! The invite itself stays in `items`, still sealed; this table records only
//! what the node decided about it, so nothing secret is copied here.
//!
//! Spec: decision 2026-09-30-agent-memory-sync §4.1

use chrono::Utc;
use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;

use crate::items::StoredItem;

/// Item type of a sealed channel state in an inbox.
pub const INVITE_ITEM_TYPE: &str = "invite";

/// Most pending invites kept; beyond this the oldest are rejected, so a
/// stranger who knows this node's key cannot grow the list without limit.
pub const MAX_PENDING_INVITES: i64 = 100;

/// Decision recorded for an invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteStatus {
    /// Valid, but the sender is not trusted: waits for `accept`.
    Pending,
    /// Applied.
    Accepted,
    /// Dropped (pending list overflow).
    Rejected,
    /// Failed verification: bad signature, wrong recipient, malformed.
    Invalid,
    /// Valid, but not newer than the state this node already applied.
    Superseded,
}

impl InviteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Invalid => "invalid",
            Self::Superseded => "superseded",
        }
    }
}

/// A pending invite, for display.
#[derive(Debug, Clone)]
pub struct PendingInvite {
    pub item_id: String,
    pub inviter: [u8; 32],
    pub channel_id: String,
    pub received_at: String,
}

/// Record (or update) the decision for an invite item.
pub fn record(
    conn: &Connection,
    item_id: &str,
    inviter: &[u8],
    channel_id: &str,
    status: InviteStatus,
) -> Result<(), CordeliaError> {
    let now = Utc::now().to_rfc3339();
    let decided_at = (status != InviteStatus::Pending).then(|| now.clone());
    conn.execute(
        "INSERT INTO invites (item_id, inviter, channel_id, status, received_at, decided_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(item_id) DO UPDATE SET
            status = excluded.status,
            channel_id = excluded.channel_id,
            decided_at = excluded.decided_at",
        params![
            item_id,
            inviter,
            channel_id,
            status.as_str(),
            now,
            decided_at
        ],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Invite items in `inbox_channel_id` that still need processing: never
/// seen, or pending (a pending invite is reconsidered once its sender is
/// trusted). Oldest first.
pub fn unprocessed(
    conn: &Connection,
    inbox_channel_id: &str,
) -> Result<Vec<StoredItem>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT i.item_id, i.channel_id, i.author_id, i.item_type, i.published_at,
                    i.is_tombstone, i.parent_id, i.key_version, i.content_hash, i.signature,
                    i.encrypted_blob
             FROM items i
             LEFT JOIN invites v ON v.item_id = i.item_id
             WHERE i.channel_id = ?1
               AND i.item_type = ?2
               AND i.is_tombstone = 0
               AND (v.item_id IS NULL OR v.status = 'pending')
             ORDER BY i.published_at ASC, i.item_id ASC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(params![inbox_channel_id, INVITE_ITEM_TYPE], |row| {
            Ok(StoredItem {
                item_id: row.get(0)?,
                channel_id: row.get(1)?,
                author_id: row.get(2)?,
                item_type: row.get(3)?,
                published_at: row.get(4)?,
                is_tombstone: row.get::<_, i64>(5)? != 0,
                parent_id: row.get(6)?,
                key_version: row.get(7)?,
                content_hash: row.get(8)?,
                signature: row.get(9)?,
                encrypted_blob: row.get(10)?,
            })
        })
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }
    Ok(out)
}

/// Pending invites, oldest first.
pub fn pending(conn: &Connection) -> Result<Vec<PendingInvite>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT item_id, inviter, channel_id, received_at FROM invites
             WHERE status = 'pending' ORDER BY received_at ASC, item_id ASC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            let blob: Vec<u8> = row.get(1)?;
            Ok((row.get(0)?, blob, row.get(2)?, row.get(3)?))
        })
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        let (item_id, blob, channel_id, received_at) =
            row.map_err(|e| CordeliaError::Storage(e.to_string()))?;
        if let Ok(inviter) = <[u8; 32]>::try_from(blob.as_slice()) {
            out.push(PendingInvite {
                item_id,
                inviter,
                channel_id,
                received_at,
            });
        }
    }
    Ok(out)
}

/// Reject the oldest pending invites beyond [`MAX_PENDING_INVITES`].
/// Returns how many were rejected.
pub fn enforce_pending_cap(conn: &Connection) -> Result<usize, CordeliaError> {
    let now = Utc::now().to_rfc3339();
    let rejected = conn
        .execute(
            "UPDATE invites SET status = 'rejected', decided_at = ?1
             WHERE item_id IN (
                 SELECT item_id FROM invites WHERE status = 'pending'
                 ORDER BY received_at DESC, item_id DESC
                 LIMIT -1 OFFSET ?2
             )",
            params![now, MAX_PENDING_INVITES],
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db, items};

    fn inbox(conn: &Connection) {
        conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('inbox_x', 'inbox', 'realtime', 'invite_only', X'00', '2026-01-01', '2026-01-01')",
            [],
        )
        .unwrap();
    }

    fn invite_item(conn: &Connection, id: &str, hash: u8, ts: &str) {
        items::insert_item(
            conn,
            &items::NewItem {
                item_id: id,
                channel_id: "inbox_x",
                author_id: &[0x0A; 32],
                item_type: INVITE_ITEM_TYPE,
                published_at: ts,
                parent_id: None,
                key_version: 0,
                content_hash: &[hash; 32],
                signature: &[0; 64],
                encrypted_blob: &[1, 2, 3],
            },
        )
        .unwrap();
    }

    #[test]
    fn test_unprocessed_excludes_decided_keeps_pending() {
        let conn = db::open_in_memory().unwrap();
        inbox(&conn);
        invite_item(&conn, "ci_1", 1, "2026-01-01T00:01:00Z");
        invite_item(&conn, "ci_2", 2, "2026-01-01T00:02:00Z");
        invite_item(&conn, "ci_3", 3, "2026-01-01T00:03:00Z");

        record(&conn, "ci_1", &[0x0A; 32], "grp_a", InviteStatus::Accepted).unwrap();
        record(&conn, "ci_2", &[0x0A; 32], "grp_b", InviteStatus::Pending).unwrap();

        let ids: Vec<_> = unprocessed(&conn, "inbox_x")
            .unwrap()
            .into_iter()
            .map(|i| i.item_id)
            .collect();
        assert_eq!(ids, vec!["ci_2", "ci_3"]);

        let pend = pending(&conn).unwrap();
        assert_eq!(pend.len(), 1);
        assert_eq!(pend[0].channel_id, "grp_b");
    }

    #[test]
    fn test_pending_cap_rejects_oldest() {
        let conn = db::open_in_memory().unwrap();
        for i in 0..(MAX_PENDING_INVITES + 3) {
            let id = format!("ci_{i:04}");
            record(&conn, &id, &[0x0B; 32], "grp_x", InviteStatus::Pending).unwrap();
        }
        assert_eq!(enforce_pending_cap(&conn).unwrap(), 3);
        assert_eq!(pending(&conn).unwrap().len() as i64, MAX_PENDING_INVITES);
    }
}
