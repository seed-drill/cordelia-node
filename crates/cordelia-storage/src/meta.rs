//! Node-level key/value metadata (`node_meta`).

use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;

/// Key under which the ID of this node's personal channel is stored.
pub const PERSONAL_CHANNEL_ID: &str = "personal_channel_id";

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
