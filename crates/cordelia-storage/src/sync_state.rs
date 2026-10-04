//! Sync adapter state: what each local folder last agreed with its channel,
//! per key, and the texts it has kept beside files that are still to take
//! the channel's version (decision 2026-09-30-agent-memory-sync §4.5).

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

/// A text that a folder has kept beside a file, until the file and the
/// channel next agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The channel's version that the file was about to take: its item ID.
    pub version: String,
    /// The name of the conflict file the text was kept in.
    pub copy: String,
    /// The hash of the text.
    pub hash: [u8; 32],
    /// The channel's entry under the conflict file's name (its item ID),
    /// if there is one, as far as this folder knows of it: the entry that
    /// was there when the copy was written, and then the entry that the
    /// folder published the copy as ([`kept_published`]).
    pub under: Option<String>,
}

/// What `folder` has kept beside `key`, if anything.
pub fn kept(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    key: &str,
) -> Result<Option<Kept>, CordeliaError> {
    use rusqlite::OptionalExtension;
    let row = conn
        .query_row(
            "SELECT version, copy, hash, under FROM sync_kept
             WHERE folder = ?1 AND channel_id = ?2 AND key = ?3",
            params![folder, channel_id, key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    // A hash that is not one is no record of a text.
    Ok(row.and_then(|(version, copy, hash, under)| {
        let hash = <[u8; 32]>::try_from(hash.as_slice()).ok()?;
        Some(Kept {
            version,
            copy,
            hash,
            under,
        })
    }))
}

/// Record what `folder` has kept beside `key`, in place of whatever it
/// had recorded for that file.
pub fn keep(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    key: &str,
    kept: &Kept,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO sync_kept (folder, channel_id, key, version, copy, hash, under)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(folder, channel_id, key) DO UPDATE
         SET version = excluded.version, copy = excluded.copy, hash = excluded.hash,
             under = excluded.under",
        params![
            folder,
            channel_id,
            key,
            kept.version,
            kept.copy,
            kept.hash.to_vec(),
            kept.under
        ],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Record that `folder` has published the conflict file `copy` itself,
/// with the text of `hash`, as the entry `under`: a text it has kept in
/// that file is under that entry now.
pub fn kept_published(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    copy: &str,
    hash: &[u8; 32],
    under: &str,
) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE sync_kept SET under = ?5
         WHERE folder = ?1 AND channel_id = ?2 AND copy = ?3 AND hash = ?4",
        params![folder, channel_id, copy, hash.to_vec(), under],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Forget what `folder` has kept beside `key`: the file and the channel
/// agree again, or the file has been replaced.
pub fn unkeep(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    key: &str,
) -> Result<(), CordeliaError> {
    conn.execute(
        "DELETE FROM sync_kept WHERE folder = ?1 AND channel_id = ?2 AND key = ?3",
        params![folder, channel_id, key],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Forget what every folder agreed, and what it has kept, except the
/// (folder, channel) pairs in `keep`. A folder that stops syncing and later
/// syncs again then starts afresh: its files merge with the channel's, and
/// nothing it lost in between is taken as a delete. Returns the number of
/// keys whose agreement was forgotten.
pub fn forget_except(conn: &Connection, keep: &[(String, String)]) -> Result<usize, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT folder, channel_id FROM sync_files
             UNION SELECT folder, channel_id FROM sync_kept",
        )
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
        conn.execute(
            "DELETE FROM sync_kept WHERE folder = ?1 AND channel_id = ?2",
            params![folder, channel_id],
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
        forgotten += conn
            .execute(
                "DELETE FROM sync_files WHERE folder = ?1 AND channel_id = ?2",
                params![folder, channel_id],
            )
            .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    }
    Ok(forgotten)
}

/// Forget what one folder agreed, and what it has kept, with every
/// channel. Returns the number of keys whose agreement was forgotten.
pub fn forget_folder(conn: &Connection, folder: &str) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM sync_kept WHERE folder = ?1", params![folder])
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    conn.execute("DELETE FROM sync_files WHERE folder = ?1", params![folder])
        .map_err(|e| CordeliaError::Storage(e.to_string()))
}

/// Forget what every folder agreed, and what it has kept, with every
/// channel, except the folders in `keep`. Returns the number of keys whose
/// agreement was forgotten.
pub fn forget_folders_except(conn: &Connection, keep: &[String]) -> Result<usize, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT folder FROM sync_files UNION SELECT folder FROM sync_kept")
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

    /// What a folder has kept beside a file is stored for that file,
    /// replaced by the next thing kept beside it, brought up to date when
    /// the copy is published, and gone when asked.
    #[test]
    fn test_what_is_kept_beside_a_file() {
        let conn = db::open_in_memory().unwrap();
        let first = Kept {
            version: "ci_one".into(),
            copy: "notes.conflict-0a1b2c3d.md".into(),
            hash: [7; 32],
            under: None,
        };
        assert_eq!(kept(&conn, "/m", "grp_a", "notes.md").unwrap(), None);
        keep(&conn, "/m", "grp_a", "notes.md", &first).unwrap();
        assert_eq!(
            kept(&conn, "/m", "grp_a", "notes.md").unwrap(),
            Some(first.clone())
        );
        // For that file, in that folder and channel, and no other.
        assert_eq!(kept(&conn, "/m", "grp_a", "other.md").unwrap(), None);
        assert_eq!(kept(&conn, "/m", "grp_b", "notes.md").unwrap(), None);
        assert_eq!(kept(&conn, "/n", "grp_a", "notes.md").unwrap(), None);

        let second = Kept {
            version: "ci_two".into(),
            copy: "notes.conflict-0a1b2c3d-2.md".into(),
            hash: [8; 32],
            under: Some("ci_delete".into()),
        };
        keep(&conn, "/m", "grp_a", "notes.md", &second).unwrap();
        assert_eq!(
            kept(&conn, "/m", "grp_a", "notes.md").unwrap(),
            Some(second.clone())
        );

        // A copy that its folder publishes is under the entry it was
        // published as: that copy, with that text, in that folder and
        // channel, and no other.
        let under = |folder: &str, channel: &str| {
            let kept = kept(&conn, folder, channel, "notes.md").unwrap();
            kept.and_then(|kept| kept.under)
        };
        keep(&conn, "/n", "grp_a", "notes.md", &second).unwrap();
        keep(&conn, "/m", "grp_b", "notes.md", &second).unwrap();
        let published = |copy: &str, hash: [u8; 32]| {
            kept_published(&conn, "/m", "grp_a", copy, &hash, "ci_published").unwrap();
            under("/m", "grp_a")
        };
        let before = Some("ci_delete".to_string());
        assert_eq!(published(&first.copy, [8; 32]), before);
        assert_eq!(published(&second.copy, [7; 32]), before);
        assert_eq!(published("notes.md", [8; 32]), before);
        assert_eq!(
            published(&second.copy, [8; 32]).as_deref(),
            Some("ci_published")
        );
        assert_eq!(under("/n", "grp_a"), before);
        assert_eq!(under("/m", "grp_b"), before);

        unkeep(&conn, "/m", "grp_a", "notes.md").unwrap();
        assert_eq!(kept(&conn, "/m", "grp_a", "notes.md").unwrap(), None);
        // Nothing to forget is no error.
        unkeep(&conn, "/m", "grp_a", "notes.md").unwrap();
    }

    /// What a folder has kept is forgotten with what it agreed, by each of
    /// the three ways of forgetting, and for a folder that has agreed
    /// nothing yet.
    #[test]
    fn test_what_is_kept_is_forgotten_with_what_is_agreed() {
        let conn = db::open_in_memory().unwrap();
        let one = |copy: &str| Kept {
            version: "ci_one".into(),
            copy: copy.into(),
            hash: [7; 32],
            under: None,
        };
        let fill = || {
            save(&conn, "/m", "grp_a", "notes.md", (Some([7; 32]), 2)).unwrap();
            keep(&conn, "/m", "grp_a", "notes.md", &one("a")).unwrap();
            // A folder that has agreed nothing, and kept a text.
            keep(&conn, "/new", "grp_b", "notes.md", &one("b")).unwrap();
            save(&conn, "/stays", "grp_c", "x.md", (None, 1)).unwrap();
            keep(&conn, "/stays", "grp_c", "x.md", &one("c")).unwrap();
        };
        let left = || -> Vec<bool> {
            [
                ("/m", "grp_a", "notes.md"),
                ("/new", "grp_b", "notes.md"),
                ("/stays", "grp_c", "x.md"),
            ]
            .iter()
            .map(|(folder, channel, key)| kept(&conn, folder, channel, key).unwrap().is_some())
            .collect()
        };

        fill();
        assert_eq!(forget_folder(&conn, "/m").unwrap(), 1);
        assert_eq!(forget_folder(&conn, "/new").unwrap(), 0);
        assert_eq!(left(), [false, false, true]);

        fill();
        let keep_pairs = [("/stays".to_string(), "grp_c".to_string())];
        assert_eq!(forget_except(&conn, &keep_pairs).unwrap(), 1);
        assert_eq!(left(), [false, false, true]);

        fill();
        assert_eq!(
            forget_folders_except(&conn, &["/stays".to_string()]).unwrap(),
            1
        );
        assert_eq!(left(), [false, false, true]);
    }

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
