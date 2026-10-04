//! Sync adapter state: what each local folder last agreed with its channel,
//! per key (decision 2026-09-30-agent-memory-sync §4.5).

use std::collections::HashMap;

use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;

/// Agreed state of one key: content hash (`None` = deleted) and revision.
pub type Agreed = (Option<[u8; 32]>, u64);

/// Everything `folder` agreed with `channel_id`, by key.
pub fn load(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
) -> Result<HashMap<String, Agreed>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT key, hash, rev FROM sync_files WHERE folder = ?1 AND channel_id = ?2")
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(params![folder, channel_id], |row| {
            let hash: Option<Vec<u8>> = row.get(1)?;
            Ok((row.get::<_, String>(0)?, hash, row.get::<_, i64>(2)?))
        })
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let mut out = HashMap::new();
    for row in rows {
        let (key, hash, rev) = row.map_err(|e| CordeliaError::Storage(e.to_string()))?;
        let hash = hash.and_then(|h| <[u8; 32]>::try_from(h.as_slice()).ok());
        out.insert(key, (hash, rev.max(0) as u64));
    }
    Ok(out)
}

/// Record what `folder` and `channel_id` now agree on for `key`.
pub fn save(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    key: &str,
    agreed: Agreed,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO sync_files (folder, channel_id, key, hash, rev) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(folder, channel_id, key) DO UPDATE SET hash = excluded.hash, rev = excluded.rev",
        params![
            folder,
            channel_id,
            key,
            agreed.0.map(|h| h.to_vec()),
            i64::try_from(agreed.1).unwrap_or(i64::MAX)
        ],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Forget what every folder agreed, except the (folder, channel) pairs in
/// `keep`. A folder that stops syncing and later syncs again then starts
/// afresh: its files merge with the channel's, and nothing it lost in
/// between is taken as a delete. Returns the number of keys forgotten.
pub fn forget_except(conn: &Connection, keep: &[(String, String)]) -> Result<usize, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT DISTINCT folder, channel_id FROM sync_files")
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let pairs: Vec<(String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| CordeliaError::Storage(e.to_string()))?
        .collect::<Result<_, _>>()
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let mut forgotten = 0;
    for (folder, channel_id) in pairs {
        if keep.iter().any(|(f, c)| *f == folder && *c == channel_id) {
            continue;
        }
        forgotten += conn
            .execute(
                "DELETE FROM sync_files WHERE folder = ?1 AND channel_id = ?2",
                params![folder, channel_id],
            )
            .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    }
    Ok(forgotten)
}

/// Forget what one folder agreed, with every channel. Returns the number
/// of keys forgotten.
pub fn forget_folder(conn: &Connection, folder: &str) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM sync_files WHERE folder = ?1", params![folder])
        .map_err(|e| CordeliaError::Storage(e.to_string()))
}

/// Forget what every folder agreed, with every channel, except the folders
/// in `keep`. Returns the number of keys forgotten.
pub fn forget_folders_except(conn: &Connection, keep: &[String]) -> Result<usize, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT DISTINCT folder FROM sync_files")
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let folders: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| CordeliaError::Storage(e.to_string()))?
        .collect::<Result<_, _>>()
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let mut forgotten = 0;
    for folder in folders.iter().filter(|f| !keep.contains(f)) {
        forgotten += forget_folder(conn, folder)?;
    }
    Ok(forgotten)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn test_forget_by_folder() {
        let conn = db::open_in_memory().unwrap();
        save(&conn, "/m", "grp_a", "notes.md", (Some([7; 32]), 2)).unwrap();
        save(&conn, "/m", "grp_b", "notes.md", (Some([7; 32]), 1)).unwrap();
        save(&conn, "/other", "grp_a", "x.md", (None, 4)).unwrap();
        save(&conn, "/third", "grp_c", "y.md", (None, 1)).unwrap();

        // One folder, whatever channels it agreed with.
        assert_eq!(forget_folder(&conn, "/m").unwrap(), 2);
        assert!(load(&conn, "/m", "grp_a").unwrap().is_empty());
        assert!(load(&conn, "/m", "grp_b").unwrap().is_empty());
        assert_eq!(load(&conn, "/other", "grp_a").unwrap().len(), 1);
        assert_eq!(forget_folder(&conn, "/m").unwrap(), 0);

        // Every folder but those named.
        let keep = ["/other".to_string()];
        assert_eq!(forget_folders_except(&conn, &keep).unwrap(), 1);
        assert_eq!(load(&conn, "/other", "grp_a").unwrap().len(), 1);
        assert!(load(&conn, "/third", "grp_c").unwrap().is_empty());
        assert_eq!(forget_folders_except(&conn, &[]).unwrap(), 1);
    }

    #[test]
    fn test_forget_except() {
        let conn = db::open_in_memory().unwrap();
        save(&conn, "/m", "grp_a", "notes.md", (Some([7; 32]), 2)).unwrap();
        save(&conn, "/m", "grp_b", "notes.md", (Some([7; 32]), 1)).unwrap();
        save(&conn, "/other", "grp_a", "x.md", (None, 4)).unwrap();

        let keep = [("/m".to_string(), "grp_a".to_string())];
        assert_eq!(forget_except(&conn, &keep).unwrap(), 2);
        assert_eq!(load(&conn, "/m", "grp_a").unwrap().len(), 1);
        assert!(load(&conn, "/m", "grp_b").unwrap().is_empty());
        assert!(load(&conn, "/other", "grp_a").unwrap().is_empty());
        assert_eq!(forget_except(&conn, &keep).unwrap(), 0);
        assert_eq!(forget_except(&conn, &[]).unwrap(), 1);
    }

    #[test]
    fn test_save_and_load() {
        let conn = db::open_in_memory().unwrap();
        save(&conn, "/m", "grp_a", "notes.md", (Some([7; 32]), 2)).unwrap();
        save(&conn, "/m", "grp_a", "gone.md", (None, 5)).unwrap();
        save(&conn, "/m", "grp_a", "notes.md", (Some([8; 32]), 3)).unwrap();
        save(&conn, "/other", "grp_a", "notes.md", (Some([9; 32]), 1)).unwrap();

        let state = load(&conn, "/m", "grp_a").unwrap();
        assert_eq!(state.len(), 2);
        assert_eq!(state["notes.md"], (Some([8; 32]), 3));
        assert_eq!(state["gone.md"], (None, 5));
    }
}
