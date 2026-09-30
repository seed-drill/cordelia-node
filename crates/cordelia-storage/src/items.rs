//! Item CRUD operations (insert, query, tombstone).
//!
//! Spec: seed-drill/specs/data-formats.md §3.4, seed-drill/specs/channels-api.md §3.2-§3.3

use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;

/// Node-internal item types filtered from listen/search responses.
/// Keep in sync with the `NOT IN` lists in the SQL below (a test checks).
const INTERNAL_TYPES: &[&str] = &[
    "psk_envelope",
    "kv",
    "attestation",
    "descriptor",
    "probe",
    "invite",
];

/// Check if an item_type is node-internal (not publishable via API).
pub fn is_internal_type(item_type: &str) -> bool {
    INTERNAL_TYPES.contains(&item_type)
}

/// Generate a new item ID: "ci_" + ULID.
pub fn generate_item_id() -> String {
    format!("ci_{}", ulid::Ulid::new())
}

/// Fields for inserting a new item.
pub struct NewItem<'a> {
    pub item_id: &'a str,
    pub channel_id: &'a str,
    pub author_id: &'a [u8; 32],
    pub item_type: &'a str,
    pub published_at: &'a str,
    pub parent_id: Option<&'a str>,
    pub key_version: i64,
    pub content_hash: &'a [u8],
    pub signature: &'a [u8],
    pub encrypted_blob: &'a [u8],
    pub is_tombstone: bool,
    /// Replaceable-item slot and revision (decision 2026-09-30 §4.3).
    /// Both set, or both `None` for an ordinary append-only item.
    pub slot: Option<&'a [u8; 32]>,
    pub rev: Option<u64>,
}

impl<'a> NewItem<'a> {
    /// An ordinary (append-only, live) item: no slot, not a tombstone.
    #[allow(clippy::too_many_arguments)]
    pub fn plain(
        item_id: &'a str,
        channel_id: &'a str,
        author_id: &'a [u8; 32],
        item_type: &'a str,
        published_at: &'a str,
        key_version: i64,
        content_hash: &'a [u8],
        signature: &'a [u8],
        encrypted_blob: &'a [u8],
    ) -> Self {
        Self {
            item_id,
            channel_id,
            author_id,
            item_type,
            published_at,
            parent_id: None,
            key_version,
            content_hash,
            signature,
            encrypted_blob,
            is_tombstone: false,
            slot: None,
            rev: None,
        }
    }
}

/// Insert an item.
///
/// Returns false, storing nothing, if the channel already holds an item
/// with the same content hash, or, for a slotted item, if the same author
/// already has an equal or newer revision in that slot. Storing a slotted
/// item deletes that author's older revisions of the slot: storage keeps
/// the newest revision per (channel, slot, author), never per slot alone,
/// so no one can overwrite another author's item (§4.3).
///
/// Every stored item gets the next value of this node's arrival sequence,
/// which item-sync pages by.
pub fn insert_item(conn: &Connection, item: &NewItem) -> Result<bool, CordeliaError> {
    let storage = |e: rusqlite::Error| CordeliaError::Storage(e.to_string());
    if item.slot.is_some() != item.rev.is_some() {
        return Err(CordeliaError::Validation(
            "slot and rev must be set together".into(),
        ));
    }

    conn.execute_batch("SAVEPOINT insert_item")
        .map_err(storage)?;
    let result = (|| -> Result<bool, CordeliaError> {
        let duplicate: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM items WHERE channel_id = ?1 AND content_hash = ?2)",
                params![item.channel_id, item.content_hash],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if duplicate {
            return Ok(false);
        }

        if let (Some(slot), Some(rev)) = (item.slot, item.rev) {
            let newest: Option<i64> = conn
                .query_row(
                    "SELECT MAX(rev) FROM items
                     WHERE channel_id = ?1 AND slot = ?2 AND author_id = ?3",
                    params![item.channel_id, slot.as_slice(), item.author_id.as_slice()],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if newest.is_some_and(|n| n >= rev_to_sql(rev)) {
                return Ok(false);
            }
        }

        let seq: i64 = conn
            .query_row(
                "UPDATE counters SET value = value + 1 WHERE name = 'item_seq' RETURNING value",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;

        conn.execute(
            "INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                is_tombstone, parent_id, key_version, content_hash, signature,
                                encrypted_blob, content_length, seq, slot, rev)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                item.item_id,
                item.channel_id,
                item.author_id.as_slice(),
                item.item_type,
                item.published_at,
                item.is_tombstone,
                item.parent_id,
                item.key_version,
                item.content_hash,
                item.signature,
                item.encrypted_blob,
                item.encrypted_blob.len() as i64,
                seq,
                item.slot.map(|s| s.as_slice()),
                item.rev.map(rev_to_sql),
            ],
        )
        .map_err(storage)?;

        if let (Some(slot), Some(rev)) = (item.slot, item.rev) {
            let args = params![
                item.channel_id,
                slot.as_slice(),
                item.author_id.as_slice(),
                rev_to_sql(rev)
            ];
            conn.execute(
                "DELETE FROM search_content WHERE item_id IN (
                     SELECT item_id FROM items
                     WHERE channel_id = ?1 AND slot = ?2 AND author_id = ?3 AND rev < ?4)",
                args,
            )
            .map_err(storage)?;
            conn.execute(
                "DELETE FROM items
                 WHERE channel_id = ?1 AND slot = ?2 AND author_id = ?3 AND rev < ?4",
                args,
            )
            .map_err(storage)?;
        }
        Ok(true)
    })();

    match &result {
        Ok(_) => conn.execute_batch("RELEASE insert_item").map_err(storage)?,
        Err(_) => {
            let _ = conn.execute_batch("ROLLBACK TO insert_item; RELEASE insert_item");
        }
    }
    result
}

/// Revisions are u64 on the wire and i64 in SQLite; clamp rather than wrap.
fn rev_to_sql(rev: u64) -> i64 {
    i64::try_from(rev).unwrap_or(i64::MAX)
}

/// A stored item row.
#[derive(Debug, Clone)]
pub struct StoredItem {
    pub item_id: String,
    pub channel_id: String,
    pub author_id: Vec<u8>,
    pub item_type: String,
    pub published_at: String,
    pub is_tombstone: bool,
    pub parent_id: Option<String>,
    pub key_version: i64,
    pub content_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub encrypted_blob: Vec<u8>,
    /// This node's arrival sequence number for the item.
    pub seq: i64,
    pub slot: Option<Vec<u8>>,
    pub rev: Option<u64>,
}

/// Column list matching [`stored_item_from_row`]; other modules select
/// items with it so the mapping lives in one place.
pub const ITEM_COLUMNS: &str = "item_id, channel_id, author_id, item_type, published_at,
    is_tombstone, parent_id, key_version, content_hash, signature, encrypted_blob,
    seq, slot, rev";

/// Query items for the listen endpoint.
///
/// Filters out internal types and tombstones. Orders by published_at ASC, item_id ASC.
/// Returns up to `limit` items with `published_at > since`.
pub fn query_listen(
    conn: &Connection,
    channel_id: &str,
    since: Option<&str>,
    limit: u32,
) -> Result<Vec<StoredItem>, CordeliaError> {
    const VISIBLE: &str =
        "item_type NOT IN ('psk_envelope', 'kv', 'attestation', 'descriptor', 'probe', 'invite')
               AND is_tombstone = 0";
    let storage = |e: rusqlite::Error| CordeliaError::Storage(e.to_string());

    let mut items = Vec::new();
    match since {
        Some(since) => {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {ITEM_COLUMNS} FROM items
                     WHERE channel_id = ?1 AND published_at > ?2 AND {VISIBLE}
                     ORDER BY published_at ASC, item_id ASC
                     LIMIT ?3"
                ))
                .map_err(storage)?;
            let rows = stmt
                .query_map(params![channel_id, since, limit], stored_item_from_row)
                .map_err(storage)?;
            for row in rows {
                items.push(row.map_err(storage)?);
            }
        }
        None => {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {ITEM_COLUMNS} FROM items
                     WHERE channel_id = ?1 AND {VISIBLE}
                     ORDER BY published_at DESC, item_id DESC
                     LIMIT ?2"
                ))
                .map_err(storage)?;
            let rows = stmt
                .query_map(params![channel_id, limit], stored_item_from_row)
                .map_err(storage)?;
            for row in rows {
                items.push(row.map_err(storage)?);
            }
            // Fetched newest first; respond oldest first.
            items.reverse();
        }
    }
    Ok(items)
}

/// Query items for item-sync (network replication, §4.5).
///
/// Unlike [`query_listen`], this returns every item stored for the channel,
/// including node-internal types (key envelopes, invites, membership events)
/// and tombstones: replication must carry them, while the listen API hides
/// them. Ordering and the `since`/`limit` semantics match `query_listen`.
pub fn query_sync(
    conn: &Connection,
    channel_id: &str,
    since: Option<&str>,
    limit: u32,
) -> Result<Vec<StoredItem>, CordeliaError> {
    let mut items = Vec::new();
    match since {
        Some(since) => {
            let sql = format!(
                "SELECT {ITEM_COLUMNS} FROM items
                 WHERE channel_id = ?1 AND published_at > ?2
                 ORDER BY published_at ASC, item_id ASC
                 LIMIT ?3"
            );
            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| CordeliaError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(params![channel_id, since, limit], stored_item_from_row)
                .map_err(|e| CordeliaError::Storage(e.to_string()))?;
            for row in rows {
                items.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
            }
        }
        None => {
            let sql = format!(
                "SELECT {ITEM_COLUMNS} FROM items
                 WHERE channel_id = ?1
                 ORDER BY published_at DESC, item_id DESC
                 LIMIT ?2"
            );
            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| CordeliaError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(params![channel_id, limit], stored_item_from_row)
                .map_err(|e| CordeliaError::Storage(e.to_string()))?;
            for row in rows {
                items.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
            }
        }
    }

    // Without `since` we fetched the newest first; return oldest first.
    if since.is_none() {
        items.reverse();
    }
    Ok(items)
}

/// Items of a channel that arrived on this node after `after_seq`, in
/// arrival order: the item-sync paging query. Includes internal types and
/// tombstones, like [`query_sync`]. Arrival order is this node's own, so a
/// peer paging with it never skips an item whatever the author's clock said.
pub fn query_sync_after(
    conn: &Connection,
    channel_id: &str,
    after_seq: i64,
    limit: u32,
) -> Result<Vec<StoredItem>, CordeliaError> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {ITEM_COLUMNS} FROM items
             WHERE channel_id = ?1 AND seq > ?2
             ORDER BY seq ASC
             LIMIT ?3"
        ))
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(params![channel_id, after_seq, limit], stored_item_from_row)
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }
    Ok(items)
}

/// Fetch specific items of a channel by ID, for item-sync fetch requests.
///
/// Includes internal types and tombstones, like [`query_sync`]. Unknown IDs
/// and IDs belonging to other channels are skipped.
pub fn get_items_by_ids(
    conn: &Connection,
    channel_id: &str,
    item_ids: &[String],
) -> Result<Vec<StoredItem>, CordeliaError> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {ITEM_COLUMNS} FROM items WHERE channel_id = ?1 AND item_id = ?2"
        ))
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut items = Vec::with_capacity(item_ids.len());
    for item_id in item_ids {
        match stmt.query_row(params![channel_id, item_id], stored_item_from_row) {
            Ok(item) => items.push(item),
            Err(rusqlite::Error::QueryReturnedNoRows) => {}
            Err(e) => return Err(CordeliaError::Storage(e.to_string())),
        }
    }
    Ok(items)
}

/// Look up which of the given item IDs are already stored.
///
/// Returns item_id -> (content_hash, published_at), the shape
/// `compute_fetch_list` expects. Checking only the IDs a peer offered keeps
/// the cost independent of channel size.
pub fn known_items(
    conn: &Connection,
    item_ids: &[String],
) -> Result<std::collections::HashMap<String, (Vec<u8>, String)>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT content_hash, published_at FROM items WHERE item_id = ?1")
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut known = std::collections::HashMap::new();
    for item_id in item_ids {
        match stmt.query_row(params![item_id], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        }) {
            Ok(entry) => {
                known.insert(item_id.clone(), entry);
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {}
            Err(e) => return Err(CordeliaError::Storage(e.to_string())),
        }
    }
    Ok(known)
}

/// Map a row selected with [`ITEM_COLUMNS`] to a [`StoredItem`].
pub fn stored_item_from_row(row: &rusqlite::Row) -> rusqlite::Result<StoredItem> {
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
        seq: row.get::<_, Option<i64>>(11)?.unwrap_or(0),
        slot: row.get(12)?,
        rev: row.get::<_, Option<i64>>(13)?.map(|r| r.max(0) as u64),
    })
}

/// Tombstone an item (soft delete).
pub fn tombstone_item(conn: &Connection, item_id: &str) -> Result<bool, CordeliaError> {
    let updated = conn
        .execute(
            "UPDATE items SET is_tombstone = 1 WHERE item_id = ?1 AND is_tombstone = 0",
            params![item_id],
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(updated > 0)
}

/// Count items in a channel (excludes internal types and tombstones).
pub fn count_for_channel(conn: &Connection, channel_id: &str) -> Result<i64, CordeliaError> {
    conn.query_row(
        "SELECT COUNT(*) FROM items
         WHERE channel_id = ?1
           AND item_type NOT IN ('psk_envelope', 'kv', 'attestation', 'descriptor', 'probe', 'invite')
           AND is_tombstone = 0",
        params![channel_id],
        |row| row.get(0),
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))
}

/// Get the most recent published_at for a channel (for last_activity in list).
pub fn last_activity(conn: &Connection, channel_id: &str) -> Result<Option<String>, CordeliaError> {
    conn.query_row(
        "SELECT MAX(published_at) FROM items WHERE channel_id = ?1 AND is_tombstone = 0",
        params![channel_id],
        |row| row.get(0),
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn setup() -> Connection {
        let conn = db::open_in_memory().unwrap();
        // Create a test channel
        conn.execute(
            "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('ch1', 'test', 'named', 'realtime', 'open', X'0000000000000000000000000000000000000000000000000000000000000042', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        ).unwrap();
        conn
    }

    fn test_item(id: &str, published_at: &str) -> NewItem<'static> {
        // Leak strings for test convenience (test-only)
        let id = Box::leak(id.to_string().into_boxed_str());
        let published_at = Box::leak(published_at.to_string().into_boxed_str());
        NewItem {
            item_id: id,
            channel_id: "ch1",
            author_id: &[0x42u8; 32],
            item_type: "message",
            published_at,
            parent_id: None,
            key_version: 1,
            content_hash: &[0x01u8; 32],
            signature: &[0x02u8; 64],
            encrypted_blob: &[0x03u8; 100],
            is_tombstone: false,
            slot: None,
            rev: None,
        }
    }

    #[test]
    fn test_generate_item_id() {
        let id = generate_item_id();
        assert!(id.starts_with("ci_"));
        assert_eq!(id.len(), 3 + 26); // "ci_" + ULID
    }

    #[test]
    fn test_insert_and_query() {
        let conn = setup();
        let item = test_item("ci_test001", "2026-01-01T00:01:00Z");
        assert!(insert_item(&conn, &item).unwrap());

        let items = query_listen(&conn, "ch1", None, 50).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item_id, "ci_test001");
    }

    #[test]
    fn test_dedup_by_content_hash() {
        let conn = setup();
        let item1 = test_item("ci_test001", "2026-01-01T00:01:00Z");
        assert!(insert_item(&conn, &item1).unwrap()); // inserted

        let item2 = NewItem {
            item_id: "ci_test002",
            ..test_item("ci_test002", "2026-01-01T00:02:00Z")
        };
        assert!(!insert_item(&conn, &item2).unwrap()); // duplicate content_hash
    }

    #[test]
    fn test_listen_since() {
        let conn = setup();
        // Insert items with different content hashes
        let mut i1 = test_item("ci_001", "2026-01-01T00:01:00Z");
        let hash1 = [0x10u8; 32];
        i1.content_hash = &hash1;
        insert_item(&conn, &i1).unwrap();

        let mut i2 = test_item("ci_002", "2026-01-01T00:02:00Z");
        let hash2 = [0x20u8; 32];
        i2.content_hash = &hash2;
        i2.item_id = "ci_002";
        insert_item(&conn, &i2).unwrap();

        let items = query_listen(&conn, "ch1", Some("2026-01-01T00:01:00Z"), 50).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item_id, "ci_002");
    }

    #[test]
    fn test_internal_types_filtered() {
        let conn = setup();
        let mut item = test_item("ci_psk", "2026-01-01T00:01:00Z");
        item.item_type = "psk_envelope";
        let hash = [0x99u8; 32];
        item.content_hash = &hash;
        insert_item(&conn, &item).unwrap();

        let items = query_listen(&conn, "ch1", None, 50).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_tombstone() {
        let conn = setup();
        let item = test_item("ci_del", "2026-01-01T00:01:00Z");
        insert_item(&conn, &item).unwrap();

        assert!(tombstone_item(&conn, "ci_del").unwrap());
        let items = query_listen(&conn, "ch1", None, 50).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_count_and_last_activity() {
        let conn = setup();
        let mut i1 = test_item("ci_c1", "2026-01-01T00:01:00Z");
        let h1 = [0x10u8; 32];
        i1.content_hash = &h1;
        insert_item(&conn, &i1).unwrap();

        let mut i2 = test_item("ci_c2", "2026-01-01T00:02:00Z");
        let h2 = [0x20u8; 32];
        i2.content_hash = &h2;
        i2.item_id = "ci_c2";
        insert_item(&conn, &i2).unwrap();

        assert_eq!(count_for_channel(&conn, "ch1").unwrap(), 2);
        assert_eq!(
            last_activity(&conn, "ch1").unwrap().as_deref(),
            Some("2026-01-01T00:02:00Z")
        );
    }

    #[test]
    fn test_is_internal_type() {
        assert!(is_internal_type("psk_envelope"));
        assert!(is_internal_type("kv"));
        assert!(!is_internal_type("message"));
        assert!(!is_internal_type("event"));
        assert!(!is_internal_type("memory:entity"));
    }

    #[test]
    fn test_query_sync_includes_internal_types_and_tombstones() {
        let conn = setup();
        let mut envelope = test_item("ci_env", "2026-01-01T00:01:00Z");
        envelope.item_type = "psk_envelope";
        envelope.content_hash = &[0x11; 32];
        insert_item(&conn, &envelope).unwrap();

        let mut deleted = test_item("ci_gone", "2026-01-01T00:02:00Z");
        deleted.content_hash = &[0x22; 32];
        insert_item(&conn, &deleted).unwrap();
        tombstone_item(&conn, "ci_gone").unwrap();

        let mut live = test_item("ci_live", "2026-01-01T00:03:00Z");
        live.content_hash = &[0x33; 32];
        insert_item(&conn, &live).unwrap();

        // The listen API hides both...
        let listened: Vec<_> = query_listen(&conn, "ch1", None, 50)
            .unwrap()
            .into_iter()
            .map(|i| i.item_id)
            .collect();
        assert_eq!(listened, vec!["ci_live"]);

        // ...but replication must carry all three, oldest first.
        let synced = query_sync(&conn, "ch1", None, 50).unwrap();
        let ids: Vec<_> = synced.iter().map(|i| i.item_id.as_str()).collect();
        assert_eq!(ids, vec!["ci_env", "ci_gone", "ci_live"]);
        assert!(synced[1].is_tombstone);
    }

    #[test]
    fn test_query_sync_since_and_limit() {
        let conn = setup();
        for (i, hash) in [0x41u8, 0x42, 0x43].iter().enumerate() {
            let id = format!("ci_s{i}");
            let ts = format!("2026-01-01T00:0{}:00Z", i + 1);
            let mut item = test_item(&id, &ts);
            let h = Box::leak(Box::new([*hash; 32]));
            item.content_hash = h;
            insert_item(&conn, &item).unwrap();
        }

        // No cursor: newest `limit` items, returned oldest first.
        let latest: Vec<_> = query_sync(&conn, "ch1", None, 2)
            .unwrap()
            .into_iter()
            .map(|i| i.item_id)
            .collect();
        assert_eq!(latest, vec!["ci_s1", "ci_s2"]);

        // Cursor: strictly after `since`, oldest first.
        let after: Vec<_> = query_sync(&conn, "ch1", Some("2026-01-01T00:01:00Z"), 10)
            .unwrap()
            .into_iter()
            .map(|i| i.item_id)
            .collect();
        assert_eq!(after, vec!["ci_s1", "ci_s2"]);
    }

    #[test]
    fn test_get_items_by_ids_scoped_to_channel() {
        let conn = setup();
        conn.execute(
            "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('ch2', 'other', 'named', 'realtime', 'open', X'00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        let mut a = test_item("ci_a", "2026-01-01T00:01:00Z");
        a.item_type = "invite";
        a.content_hash = &[0x51; 32];
        insert_item(&conn, &a).unwrap();
        let mut b = test_item("ci_b", "2026-01-01T00:02:00Z");
        b.channel_id = "ch2";
        b.content_hash = &[0x52; 32];
        insert_item(&conn, &b).unwrap();

        let ids = vec![
            "ci_a".to_string(),
            "ci_b".to_string(),
            "ci_none".to_string(),
        ];
        let got: Vec<_> = get_items_by_ids(&conn, "ch1", &ids)
            .unwrap()
            .into_iter()
            .map(|i| i.item_id)
            .collect();
        // Internal type is served; other channel's item and unknown ID are not.
        assert_eq!(got, vec!["ci_a"]);
    }

    #[test]
    fn test_known_items() {
        let conn = setup();
        let mut a = test_item("ci_k1", "2026-01-01T00:01:00Z");
        a.content_hash = &[0x61; 32];
        insert_item(&conn, &a).unwrap();

        let known = known_items(&conn, &["ci_k1".to_string(), "ci_k2".to_string()]).unwrap();
        assert_eq!(known.len(), 1);
        let (hash, published_at) = &known["ci_k1"];
        assert_eq!(hash.as_slice(), &[0x61; 32]);
        assert_eq!(published_at, "2026-01-01T00:01:00Z");
    }

    #[test]
    fn test_every_internal_type_hidden_from_listen_and_count() {
        let conn = setup();
        for (i, t) in INTERNAL_TYPES.iter().enumerate() {
            let id = Box::leak(format!("ci_int{i}").into_boxed_str());
            let mut item = test_item(id, "2026-01-01T00:01:00Z");
            item.item_type = t;
            let hash = Box::leak(Box::new([0x70 + i as u8; 32]));
            item.content_hash = hash;
            insert_item(&conn, &item).unwrap();
        }
        assert!(query_listen(&conn, "ch1", None, 50).unwrap().is_empty());
        assert_eq!(count_for_channel(&conn, "ch1").unwrap(), 0);
        assert_eq!(
            query_sync(&conn, "ch1", None, 50).unwrap().len(),
            INTERNAL_TYPES.len()
        );
    }

    fn slotted<'a>(
        id: &'a str,
        author: &'a [u8; 32],
        slot: &'a [u8; 32],
        rev: u64,
        hash: &'a [u8; 32],
    ) -> NewItem<'a> {
        NewItem {
            item_id: id,
            channel_id: "ch1",
            author_id: author,
            item_type: "memory",
            published_at: "2026-01-01T00:00:00Z",
            parent_id: None,
            key_version: 1,
            content_hash: hash,
            signature: &[0x02; 64],
            encrypted_blob: &[0x03; 10],
            is_tombstone: false,
            slot: Some(slot),
            rev: Some(rev),
        }
    }

    fn ids(conn: &Connection) -> Vec<String> {
        query_sync(conn, "ch1", None, 100)
            .unwrap()
            .into_iter()
            .map(|i| i.item_id)
            .collect()
    }

    #[test]
    fn test_newer_revision_replaces_older_from_same_author() {
        let conn = setup();
        let (me, slot) = ([0xA1; 32], [0x51; 32]);
        assert!(insert_item(&conn, &slotted("ci_r1", &me, &slot, 1, &[0x01; 32])).unwrap());
        assert!(insert_item(&conn, &slotted("ci_r2", &me, &slot, 2, &[0x02; 32])).unwrap());
        assert_eq!(ids(&conn), vec!["ci_r2"]);

        // Stale and equal revisions are refused and change nothing.
        assert!(!insert_item(&conn, &slotted("ci_r1b", &me, &slot, 1, &[0x03; 32])).unwrap());
        assert!(!insert_item(&conn, &slotted("ci_r2b", &me, &slot, 2, &[0x04; 32])).unwrap());
        assert_eq!(ids(&conn), vec!["ci_r2"]);

        let kept = &query_sync(&conn, "ch1", None, 10).unwrap()[0];
        assert_eq!(kept.slot.as_deref(), Some(&slot[..]));
        assert_eq!(kept.rev, Some(2));
    }

    #[test]
    fn test_other_authors_cannot_evict_an_item() {
        let conn = setup();
        let (me, stranger, slot) = ([0xA1; 32], [0xEE; 32], [0x51; 32]);
        insert_item(&conn, &slotted("ci_mine", &me, &slot, 1, &[0x01; 32])).unwrap();

        // A higher revision from someone else lands in their own cell.
        insert_item(
            &conn,
            &slotted("ci_junk", &stranger, &slot, 999, &[0x02; 32]),
        )
        .unwrap();
        let mut got = ids(&conn);
        got.sort();
        assert_eq!(got, vec!["ci_junk", "ci_mine"]);

        // And replacing their own cell never touches mine.
        insert_item(
            &conn,
            &slotted("ci_junk2", &stranger, &slot, 1000, &[0x03; 32]),
        )
        .unwrap();
        let mut got = ids(&conn);
        got.sort();
        assert_eq!(got, vec!["ci_junk2", "ci_mine"]);
    }

    #[test]
    fn test_slot_and_rev_must_come_together() {
        let conn = setup();
        let (me, slot) = ([0xA1; 32], [0x51; 32]);
        let mut item = slotted("ci_x", &me, &slot, 1, &[0x01; 32]);
        item.rev = None;
        assert!(insert_item(&conn, &item).is_err());
        assert!(ids(&conn).is_empty(), "failed insert leaves nothing behind");
    }

    #[test]
    fn test_arrival_sequence_is_monotonic_and_never_reused() {
        let conn = setup();
        let (me, slot) = ([0xA1; 32], [0x51; 32]);
        insert_item(&conn, &slotted("ci_s1", &me, &slot, 1, &[0x01; 32])).unwrap();
        let first = query_sync(&conn, "ch1", None, 10).unwrap()[0].seq;

        // Replacing deletes the row holding the current maximum...
        insert_item(&conn, &slotted("ci_s2", &me, &slot, 2, &[0x02; 32])).unwrap();
        let second = query_sync(&conn, "ch1", None, 10).unwrap()[0].seq;
        assert!(second > first);

        // ...and a later item still gets a fresh, larger number.
        let mut plain = test_item("ci_p", "2026-01-01T00:00:00Z");
        plain.content_hash = &[0x09; 32];
        insert_item(&conn, &plain).unwrap();
        let all = query_sync(&conn, "ch1", None, 10).unwrap();
        let plain_seq = all.iter().find(|i| i.item_id == "ci_p").unwrap().seq;
        assert!(plain_seq > second);
    }

    #[test]
    fn test_query_sync_after_pages_in_arrival_order() {
        let conn = setup();
        // Authors' clocks disagree: the second arrival claims to be oldest.
        for (i, ts) in [
            "2026-01-02T00:00:00Z",
            "2020-01-01T00:00:00Z",
            "2026-01-03T00:00:00Z",
        ]
        .iter()
        .enumerate()
        {
            let id = Box::leak(format!("ci_a{i}").into_boxed_str());
            let mut item = test_item(id, ts);
            let hash = Box::leak(Box::new([0x20 + i as u8; 32]));
            item.content_hash = hash;
            insert_item(&conn, &item).unwrap();
        }

        let page1 = query_sync_after(&conn, "ch1", 0, 2).unwrap();
        assert_eq!(
            page1.iter().map(|i| i.item_id.as_str()).collect::<Vec<_>>(),
            vec!["ci_a0", "ci_a1"]
        );
        let page2 = query_sync_after(&conn, "ch1", page1[1].seq, 2).unwrap();
        assert_eq!(
            page2.iter().map(|i| i.item_id.as_str()).collect::<Vec<_>>(),
            vec!["ci_a2"]
        );
        assert!(
            query_sync_after(&conn, "ch1", page2[0].seq, 2)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_tombstone_flag_is_stored() {
        let conn = setup();
        let mut item = test_item("ci_t", "2026-01-01T00:00:00Z");
        item.is_tombstone = true;
        insert_item(&conn, &item).unwrap();
        assert!(query_sync(&conn, "ch1", None, 10).unwrap()[0].is_tombstone);
    }

    // T3-3 (MEDIUM): Tombstone nonexistent item
    #[test]
    fn test_tombstone_nonexistent_item() {
        let conn = setup();
        let result = tombstone_item(&conn, "ci_doesnotexist");
        assert!(matches!(result, Ok(false)));
    }

    // T3-4 (MEDIUM): Double tombstone
    #[test]
    fn test_double_tombstone() {
        let conn = setup();
        let item = test_item("ci_double_del", "2026-01-01T00:01:00Z");
        insert_item(&conn, &item).unwrap();
        assert!(matches!(tombstone_item(&conn, "ci_double_del"), Ok(true)));
        assert!(matches!(tombstone_item(&conn, "ci_double_del"), Ok(false)));
    }

    // T5-2 (MEDIUM): Empty blob
    #[test]
    fn test_insert_empty_blob() {
        let conn = setup();
        let mut item = test_item("ci_empty", "2026-01-01T00:01:00Z");
        item.encrypted_blob = &[];
        item.content_hash = &[0; 32]; // Different hash to avoid dedup
        // Should succeed -- storage layer doesn't enforce min size
        assert!(insert_item(&conn, &item).is_ok());
    }

    // T5-3 (MEDIUM): Listen with limit=1
    #[test]
    fn test_listen_limit_one() {
        let conn = setup();
        let mut i1 = test_item("ci_lim1", "2026-01-01T00:01:00Z");
        i1.content_hash = &[0x10; 32];
        insert_item(&conn, &i1).unwrap();
        let mut i2 = test_item("ci_lim2", "2026-01-01T00:02:00Z");
        i2.content_hash = &[0x20; 32];
        insert_item(&conn, &i2).unwrap();

        let items = query_listen(&conn, "ch1", None, 1).unwrap();
        assert_eq!(items.len(), 1);
    }

    // T9-1: Relay auto-creation of channel rows (BV-21 regression)
    #[test]
    fn test_insert_item_fails_without_channel_row() {
        let conn = db::open_in_memory().unwrap();
        // Do NOT create a channel row -- simulate relay scenario before BV-21 fix
        let mut item = test_item("ci_relay_01", "2026-01-01T00:01:00Z");
        item.channel_id = "unknown_channel";
        let result = insert_item(&conn, &item);
        // Should fail with FK constraint (no channel row)
        assert!(
            result.is_err(),
            "insert_item without channel row should fail with FK constraint"
        );
    }

    #[test]
    fn test_insert_item_succeeds_with_relay_auto_created_channel() {
        let conn = db::open_in_memory().unwrap();
        // Simulate relay auto-creation (BV-21 fix: INSERT OR IGNORE)
        conn.execute(
            "INSERT OR IGNORE INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at) VALUES (?1, 'named', 'realtime', 'open', X'00', datetime('now'), datetime('now'))",
            rusqlite::params!["relay_channel"],
        )
        .unwrap();

        let mut item = test_item("ci_relay_02", "2026-01-01T00:01:00Z");
        item.channel_id = "relay_channel";
        let result = insert_item(&conn, &item);
        assert!(
            result.is_ok(),
            "insert after relay auto-creation should succeed"
        );
        assert!(result.unwrap(), "item should be newly inserted");
    }
}
