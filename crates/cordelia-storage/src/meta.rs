//! Node-level key/value metadata (`node_meta`).

use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;

/// Key under which the ID of this node's personal channel is stored.
pub const PERSONAL_CHANNEL_ID: &str = "personal_channel_id";

/// Claude Code directory to sync; sync is off when absent.
pub const SYNC_CLAUDE_DIR: &str = "sync.claude.dir";

/// The directory sync last ran with, kept while sync is off so that
/// turning it on again does not fall back to the default.
pub const SYNC_CLAUDE_LAST_DIR: &str = "sync.claude.last_dir";

/// JSON report of the last sync cycle.
pub const SYNC_CLAUDE_REPORT: &str = "sync.claude.report";

/// JSON array of project remotes this device never syncs.
pub const SYNC_CLAUDE_EXCLUDE: &str = "sync.claude.exclude";

/// `"off"` when this device does not sync home-folder memory.
pub const SYNC_CLAUDE_HOME: &str = "sync.claude.home";

/// `"on"` when everything found syncs (home and git projects, now and
/// later); `"off"` when only declared mappings sync.
pub const SYNC_CLAUDE_ALL: &str = "sync.claude.all";

/// JSON array of declared mappings, `[{"folder": "/abs/path", "name": "..."}]`:
/// Claude's memory for sessions started in `folder` syncs under `name`.
pub const SYNC_CLAUDE_MAPPINGS: &str = "sync.claude.mappings";

/// Hex secret this node hashes peer keys with for its usage counts
/// (`crate::usage`). Never leaves the node.
pub const USAGE_SIGHTING_SECRET: &str = "usage.sighting_secret";

/// RFC 3339 time of the last sync cycle that sent or received a memory.
pub const SYNC_CLAUDE_LAST_CHANGE: &str = "sync.claude.last_change";

/// JSON object, per synced name, of when this device last received and
/// last sent a memory under it: `{"<name>": {"pulled": "...", "published": "..."}}`.
pub const SYNC_CLAUDE_ACTIVITY: &str = "sync.claude.activity";

/// Delete a metadata value.
pub fn remove(conn: &Connection, key: &str) -> Result<(), CordeliaError> {
    conn.execute("DELETE FROM node_meta WHERE key = ?1", params![key])
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Read a metadata value.
pub fn get(conn: &Connection, key: &str) -> Result<Option<String>, CordeliaError> {
    match conn.query_row(
        "SELECT value FROM node_meta WHERE key = ?1",
        params![key],
        |row| row.get(0),
    ) {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(CordeliaError::Storage(e.to_string())),
    }
}

/// Write a metadata value.
pub fn set(conn: &Connection, key: &str, value: &str) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO node_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn test_get_set() {
        let conn = db::open_in_memory().unwrap();
        assert_eq!(get(&conn, PERSONAL_CHANNEL_ID).unwrap(), None);
        set(&conn, PERSONAL_CHANNEL_ID, "grp_a").unwrap();
        set(&conn, PERSONAL_CHANNEL_ID, "grp_b").unwrap();
        assert_eq!(
            get(&conn, PERSONAL_CHANNEL_ID).unwrap().as_deref(),
            Some("grp_b")
        );
    }
}
