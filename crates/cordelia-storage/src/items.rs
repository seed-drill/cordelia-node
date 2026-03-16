//! Item CRUD operations (insert, query, tombstone).
//!
//! Spec: seed-drill/specs/data-formats.md §3.4, seed-drill/specs/channels-api.md §3.2-§3.3

use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;

/// Node-internal item types filtered from listen/search responses.
const INTERNAL_TYPES: &[&str] = &["psk_envelope", "kv", "attestation", "descriptor", "probe"];

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
}

/// Insert an item with deduplication by content_hash.
///
/// Returns true if inserted, false if duplicate (content_hash already exists for this channel).
pub fn insert_item(conn: &Connection, item: &NewItem) -> Result<bool, CordeliaError> {
    // Check for duplicate content_hash in same channel
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM items WHERE channel_id = ?1 AND content_hash = ?2)",
            params![item.channel_id, item.content_hash],
            |row| row.get(0),
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    if exists {
        return Ok(false);
    }

    conn.execute(
        "INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                            is_tombstone, parent_id, key_version, content_hash, signature,
                            encrypted_blob, content_length)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            item.item_id,
            item.channel_id,
            item.author_id.as_slice(),
            item.item_type,
            item.published_at,
            item.parent_id,
            item.key_version,
            item.content_hash,
            item.signature,
            item.encrypted_blob,
            item.encrypted_blob.len() as i64,
        ],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    Ok(true)
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
}

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
    let sql = if since.is_some() {
        "SELECT item_id, channel_id, author_id, item_type, published_at,
                is_tombstone, parent_id, key_version, content_hash, signature, encrypted_blob
         FROM items
         WHERE channel_id = ?1
           AND published_at > ?2
           AND item_type NOT IN ('psk_envelope', 'kv', 'attestation', 'descriptor', 'probe')
           AND is_tombstone = 0
         ORDER BY published_at ASC, item_id ASC
         LIMIT ?3"
    } else {
        "SELECT item_id, channel_id, author_id, item_type, published_at,
                is_tombstone, parent_id, key_version, content_hash, signature, encrypted_blob
         FROM items
         WHERE channel_id = ?1
           AND item_type NOT IN ('psk_envelope', 'kv', 'attestation', 'descriptor', 'probe')
           AND is_tombstone = 0
         ORDER BY published_at DESC, item_id DESC
         LIMIT ?3"
    };

    let since_val = since.unwrap_or("");
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![channel_id, since_val, limit], |row| {
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

    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }

    // If no `since`, we fetched DESC (latest first) -- reverse to ASC for response
    if since.is_none() {
        items.reverse();
    }

    Ok(items)
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
           AND item_type NOT IN ('psk_envelope', 'kv', 'attestation', 'descriptor', 'probe')
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
