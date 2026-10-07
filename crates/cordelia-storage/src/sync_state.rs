//! Sync adapter state: what each local folder last agreed with its channel,
//! per key (decision 2026-09-30-agent-memory-sync §4.5; decision 2026-10-04
//! §2.3, §7.3).
//!
//! A folder's record of a file is of one entry of the channel's: the hash
//! of its text, its revision, the key that signed it and its chain. Where a
//! version is held in several entries, it is the one that a device writes
//! over: its own where it holds one, and otherwise the one whose signer
//! has the lowest key. A channel is known here by its ID as it is written.
//!
//! When a device applies a statement, each folder's records go with the
//! name to the name's new channel ([`move_channel`]), with its records of
//! index lines, and each revision in them is renumbered as every device
//! renumbers it.

use std::collections::HashMap;

use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{ENTRY_LINK_HASH_BYTES, ENTRY_LINK_SIGNER_BYTES, MAX_ENTRY_LINKS};
use cordelia_crypto::entry::Link;

/// What a folder and its channel agreed for one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agreed {
    /// The hash of the agreed text; `None` where what was agreed is that
    /// the file is deleted.
    pub hash: Option<[u8; 32]>,
    pub rev: u64,
    /// The key that signed the entry the folder agreed. `None` in a row
    /// that does not say: one from before it was kept.
    pub signer: Option<[u8; 32]>,
    /// That entry's chain. `None` where the entry lacked what it should
    /// say, and in a row that does not say.
    pub chain: Option<Vec<Link>>,
}

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// How many bytes a link takes in a row.
const LINK_BYTES: usize = ENTRY_LINK_HASH_BYTES + ENTRY_LINK_SIGNER_BYTES;

/// A chain as a row holds it: its links one after another, each the start
/// of a hash and then the start of a key.
fn chain_to_row(chain: &[Link]) -> Vec<u8> {
    let mut row = Vec::with_capacity(chain.len() * LINK_BYTES);
    for link in chain {
        row.extend_from_slice(&link.hash);
        row.extend_from_slice(&link.signer);
    }
    row
}

/// The chain that a row holds. `None` for what is no chain: bytes that are
/// not whole links, and more links than an entry may have.
fn chain_from_row(row: &[u8]) -> Option<Vec<Link>> {
    let (links, rest) = row.as_chunks::<LINK_BYTES>();
    if !rest.is_empty() || links.len() > MAX_ENTRY_LINKS {
        return None;
    }
    links
        .iter()
        .map(|link| {
            let (hash, signer) = link.split_at(ENTRY_LINK_HASH_BYTES);
            Some(Link {
                hash: hash.try_into().ok()?,
                signer: signer.try_into().ok()?,
            })
        })
        .collect()
}

/// A column that should hold a blob, as it is read: whatever is there
/// that is no blob is read as an empty one, so that a value which a row
/// should never hold does not end the folder's cycle.
fn blob(row: &rusqlite::Row, column: usize) -> rusqlite::Result<Option<Vec<u8>>> {
    Ok(match row.get_ref(column)? {
        rusqlite::types::ValueRef::Null => None,
        rusqlite::types::ValueRef::Blob(bytes) => Some(bytes.to_vec()),
        _ => Some(Vec::new()),
    })
}

/// Whether a folder's record names a text of the file `key` in
/// `channel_id`: some folder agreed a text there, and has not agreed
/// since that the file is deleted.
pub fn names_a_text(conn: &Connection, channel_id: &str, key: &str) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sync_files
                       WHERE channel_id = ?1 AND key = ?2 AND hash IS NOT NULL)",
        params![channel_id, key],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// Forget each folder's record that the file `key` is deleted in
/// `channel_id`: the delete that it was agreed with is held no more.
/// A record of a text is left as it is. Returns how many went.
pub fn forget_deleted(
    conn: &Connection,
    channel_id: &str,
    key: &str,
) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM sync_files WHERE channel_id = ?1 AND key = ?2 AND hash IS NULL",
        params![channel_id, key],
    )
    .map_err(storage)
}

/// Everything `folder` agreed with `channel_id`, by key.
pub fn load(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
) -> Result<HashMap<String, Agreed>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT key, hash, rev, author, chain FROM sync_files
             WHERE folder = ?1 AND channel_id = ?2",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map(params![folder, channel_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, i64>(2)?,
                blob(row, 3)?,
                blob(row, 4)?,
            ))
        })
        .map_err(storage)?;
    let as_key = |bytes: Option<Vec<u8>>| bytes.and_then(|b| <[u8; 32]>::try_from(b).ok());
    let mut out = HashMap::new();
    for row in rows {
        let (key, hash, rev, signer, chain) = row.map_err(storage)?;
        out.insert(
            key,
            Agreed {
                hash: as_key(hash),
                rev: rev.max(0) as u64,
                signer: as_key(signer),
                chain: chain.and_then(|row| chain_from_row(&row)),
            },
        );
    }
    Ok(out)
}

/// Whether `folder` has a record of any key in `channel_id`: whether it
/// has had a cycle there that agreed anything (decision 2026-10-04 §6).
pub fn any(conn: &Connection, folder: &str, channel_id: &str) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sync_files WHERE folder = ?1 AND channel_id = ?2)",
        params![folder, channel_id],
        |row| row.get(0),
    )
    .map_err(storage)
}

/// Record what `folder` and `channel_id` now agree on for `key`.
pub fn save(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    key: &str,
    agreed: &Agreed,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO sync_files (folder, channel_id, key, hash, rev, author, chain)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(folder, channel_id, key) DO UPDATE
         SET hash = excluded.hash, rev = excluded.rev, author = excluded.author,
             chain = excluded.chain",
        params![
            folder,
            channel_id,
            key,
            agreed.hash.map(|h| h.to_vec()),
            i64::try_from(agreed.rev).unwrap_or(i64::MAX),
            agreed.signer.map(|key| key.to_vec()),
            agreed.chain.as_deref().map(chain_to_row),
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Every folder's records in `channel_id`: each folder with a key it has a
/// record of there, in order.
pub fn files(conn: &Connection, channel_id: &str) -> Result<Vec<(String, String)>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT folder, key FROM sync_files WHERE channel_id = ?1 ORDER BY folder, key")
        .map_err(storage)?;
    let rows = stmt
        .query_map(params![channel_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Forget what `folder` agreed with `channel_id` for `key`, and nothing
/// else. Returns whether there was a record.
pub fn forget_file(
    conn: &Connection,
    folder: &str,
    channel_id: &str,
    key: &str,
) -> Result<bool, CordeliaError> {
    conn.execute(
        "DELETE FROM sync_files WHERE folder = ?1 AND channel_id = ?2 AND key = ?3",
        params![folder, channel_id, key],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// Every folder's records in the channel `from` are records in the channel
/// `to` from now on, with its records of index lines
/// ([`crate::index_lines`]): the name's channel in the generation that a
/// device has come to (decision 2026-10-04 §4.2). Each revision in them
/// becomes what `renumbered` gives it. Returns how many records moved.
///
/// It is whole inside the caller's transaction. Whatever `to` held of a
/// folder that has a record in `from` is replaced by it.
pub fn move_channel(
    conn: &Connection,
    from: &str,
    to: &str,
    renumbered: impl Fn(u64) -> u64,
) -> Result<usize, CordeliaError> {
    if from == to {
        return Ok(0);
    }
    let rows: Vec<(String, String, i64)> = {
        let mut stmt = conn
            .prepare("SELECT folder, key, rev FROM sync_files WHERE channel_id = ?1")
            .map_err(storage)?;
        stmt.query_map(params![from], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?
    };
    for table in ["sync_files", "index_lines"] {
        conn.execute(
            &format!(
                "DELETE FROM {table} WHERE channel_id = ?2
                 AND folder IN (SELECT folder FROM {table} WHERE channel_id = ?1)"
            ),
            params![from, to],
        )
        .map_err(storage)?;
    }
    for (folder, key, rev) in &rows {
        let rev = renumbered((*rev).max(0) as u64);
        conn.execute(
            "UPDATE sync_files SET channel_id = ?4, rev = ?5
             WHERE folder = ?1 AND channel_id = ?2 AND key = ?3",
            params![
                folder,
                from,
                key,
                to,
                i64::try_from(rev).unwrap_or(i64::MAX)
            ],
        )
        .map_err(storage)?;
    }
    conn.execute(
        "UPDATE index_lines SET channel_id = ?2 WHERE channel_id = ?1",
        params![from, to],
    )
    .map_err(storage)?;
    Ok(rows.len())
}

/// Forget what every folder agreed, except the (folder, channel) pairs in
/// `keep`. A folder that stops syncing and later syncs again then starts
/// afresh: its files merge with the channel's, and nothing it lost in
/// between is taken as a delete. Returns the number of keys forgotten.
///
/// What a folder wrote down of the memories it deleted
/// ([`crate::index_lines`]) is forgotten with what it agreed, here and in
/// the two ways below: for a folder that has no agreed key too.
pub fn forget_except(conn: &Connection, keep: &[(String, String)]) -> Result<usize, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT folder, channel_id FROM sync_files
             UNION SELECT DISTINCT folder, channel_id FROM index_lines",
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
        forgotten += conn
            .execute(
                "DELETE FROM sync_files WHERE folder = ?1 AND channel_id = ?2",
                params![folder, channel_id],
            )
            .map_err(|e| CordeliaError::Storage(e.to_string()))?;
        conn.execute(
            "DELETE FROM index_lines WHERE folder = ?1 AND channel_id = ?2",
            params![folder, channel_id],
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    }
    Ok(forgotten)
}

/// Forget what one folder agreed, with every channel. Returns the number
/// of keys forgotten.
pub fn forget_folder(conn: &Connection, folder: &str) -> Result<usize, CordeliaError> {
    conn.execute("DELETE FROM index_lines WHERE folder = ?1", params![folder])
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    conn.execute("DELETE FROM sync_files WHERE folder = ?1", params![folder])
        .map_err(|e| CordeliaError::Storage(e.to_string()))
}

/// Forget what every folder agreed with `channel_id`, with its records of
/// index lines there ([`crate::index_lines`]). Returns the number of keys
/// forgotten.
///
/// A device that holds a name no more keeps nothing of the name's channel:
/// a folder that comes to sync the name again meets the channel as on any
/// first sync, and what it lost in between is not taken for deletes.
pub fn forget_channel(conn: &Connection, channel_id: &str) -> Result<usize, CordeliaError> {
    conn.execute(
        "DELETE FROM index_lines WHERE channel_id = ?1",
        params![channel_id],
    )
    .map_err(storage)?;
    conn.execute(
        "DELETE FROM sync_files WHERE channel_id = ?1",
        params![channel_id],
    )
    .map_err(storage)
}

/// Forget what every folder agreed, with every channel, except the folders
/// in `keep`. Returns the number of keys forgotten.
pub fn forget_folders_except(conn: &Connection, keep: &[String]) -> Result<usize, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT folder FROM sync_files UNION SELECT DISTINCT folder FROM index_lines",
        )
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

    /// A record of the text whose hash is `hash`, at `rev`, by the key
    /// `signer`, with a chain of one link.
    fn agreed(hash: Option<[u8; 32]>, rev: u64, signer: u8) -> Agreed {
        Agreed {
            hash,
            rev,
            signer: Some([signer; 32]),
            chain: Some(vec![Link {
                hash: [signer; 16],
                signer: [rev as u8; 16],
            }]),
        }
    }

    /// Whether a folder's record names a text of a file is asked of every
    /// folder's record of that file in that channel: a record that the
    /// file is deleted names none. And the records that a file is deleted
    /// are forgotten alone: a record of a text stays, and so does every
    /// record of another file or another channel.
    #[test]
    fn test_a_record_of_a_delete_names_no_text_and_is_forgotten_alone() {
        let conn = db::open_in_memory().unwrap();
        let (text, deleted) = (agreed(Some([7; 32]), 2, 1), agreed(None, 3, 1));
        save(&conn, "/one", "ch_a", "gone.md", &deleted).unwrap();
        save(&conn, "/two", "ch_a", "gone.md", &text).unwrap();
        save(&conn, "/one", "ch_a", "other.md", &deleted).unwrap();
        save(&conn, "/one", "ch_b", "gone.md", &deleted).unwrap();

        assert!(names_a_text(&conn, "ch_a", "gone.md").unwrap());
        // A record of a delete alone names no text: in another channel,
        // and for another file.
        assert!(!names_a_text(&conn, "ch_b", "gone.md").unwrap());
        assert!(!names_a_text(&conn, "ch_a", "other.md").unwrap());
        assert!(!names_a_text(&conn, "ch_a", "no-such.md").unwrap());

        // The record of the delete goes, and the record of the text
        // stays, with every other record.
        assert_eq!(forget_deleted(&conn, "ch_a", "gone.md").unwrap(), 1);
        assert_eq!(forget_deleted(&conn, "ch_a", "gone.md").unwrap(), 0);
        assert_eq!(
            files(&conn, "ch_a").unwrap(),
            [
                ("/one".to_string(), "other.md".to_string()),
                ("/two".to_string(), "gone.md".to_string())
            ]
        );
        assert_eq!(load(&conn, "/two", "ch_a").unwrap()["gone.md"], text);
        assert_eq!(files(&conn, "ch_b").unwrap().len(), 1);
        assert!(names_a_text(&conn, "ch_a", "gone.md").unwrap());
    }

    #[test]
    fn test_forget_by_folder() {
        let conn = db::open_in_memory().unwrap();
        save(
            &conn,
            "/m",
            "ch_a",
            "notes.md",
            &agreed(Some([7; 32]), 2, 1),
        )
        .unwrap();
        save(
            &conn,
            "/m",
            "ch_b",
            "notes.md",
            &agreed(Some([7; 32]), 1, 1),
        )
        .unwrap();
        save(&conn, "/other", "ch_a", "x.md", &agreed(None, 4, 1)).unwrap();
        save(&conn, "/third", "ch_c", "y.md", &agreed(None, 1, 1)).unwrap();

        // One folder, whatever channels it agreed with.
        assert_eq!(forget_folder(&conn, "/m").unwrap(), 2);
        assert!(load(&conn, "/m", "ch_a").unwrap().is_empty());
        assert!(load(&conn, "/m", "ch_b").unwrap().is_empty());
        assert_eq!(load(&conn, "/other", "ch_a").unwrap().len(), 1);
        assert_eq!(forget_folder(&conn, "/m").unwrap(), 0);

        // Every folder but those named.
        let keep = ["/other".to_string()];
        assert_eq!(forget_folders_except(&conn, &keep).unwrap(), 1);
        assert_eq!(load(&conn, "/other", "ch_a").unwrap().len(), 1);
        assert!(load(&conn, "/third", "ch_c").unwrap().is_empty());
        assert_eq!(forget_folders_except(&conn, &[]).unwrap(), 1);
    }

    #[test]
    fn test_forget_except() {
        let conn = db::open_in_memory().unwrap();
        save(
            &conn,
            "/m",
            "ch_a",
            "notes.md",
            &agreed(Some([7; 32]), 2, 1),
        )
        .unwrap();
        save(
            &conn,
            "/m",
            "ch_b",
            "notes.md",
            &agreed(Some([7; 32]), 1, 1),
        )
        .unwrap();
        save(&conn, "/other", "ch_a", "x.md", &agreed(None, 4, 1)).unwrap();

        let keep = [("/m".to_string(), "ch_a".to_string())];
        assert_eq!(forget_except(&conn, &keep).unwrap(), 2);
        assert_eq!(load(&conn, "/m", "ch_a").unwrap().len(), 1);
        assert!(load(&conn, "/m", "ch_b").unwrap().is_empty());
        assert!(load(&conn, "/other", "ch_a").unwrap().is_empty());
        assert_eq!(forget_except(&conn, &keep).unwrap(), 0);
        assert_eq!(forget_except(&conn, &[]).unwrap(), 1);
    }

    /// Every folder forgets what it agreed with one channel, with its
    /// records of index lines there, and nothing of another channel goes.
    #[test]
    fn test_forget_by_channel() {
        let conn = db::open_in_memory().unwrap();
        for (folder, channel, key) in [
            ("/m", "ch_a", "notes.md"),
            ("/m", "ch_a", "gone.md"),
            ("/other", "ch_a", "x.md"),
            ("/m", "ch_b", "notes.md"),
        ] {
            save(&conn, folder, channel, key, &agreed(Some([7; 32]), 2, 1)).unwrap();
        }
        crate::index_lines::line_removed(&conn, "/m", "ch_a", "notes.md", "- a line", 7).unwrap();
        crate::index_lines::line_removed(&conn, "/lines-only", "ch_a", "y.md", "- a line", 7)
            .unwrap();
        crate::index_lines::line_removed(&conn, "/m", "ch_b", "notes.md", "- other", 7).unwrap();
        let lines = |channel: &str| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM index_lines WHERE channel_id = ?1",
                [channel],
                |row| row.get(0),
            )
            .unwrap()
        };

        assert_eq!(forget_channel(&conn, "ch_a").unwrap(), 3);
        assert!(!any(&conn, "/m", "ch_a").unwrap());
        assert!(!any(&conn, "/other", "ch_a").unwrap());
        assert_eq!((lines("ch_a"), lines("ch_b")), (0, 1));
        assert_eq!(load(&conn, "/m", "ch_b").unwrap().len(), 1);
        assert_eq!(forget_channel(&conn, "ch_a").unwrap(), 0);
    }

    /// A record keeps the hash, the revision, the signer and the chain of
    /// the entry a folder agreed, and each is replaced with the rest. A
    /// chain of no links is not the same as no chain.
    #[test]
    fn test_a_record_keeps_the_signer_and_the_chain_of_the_entry_agreed() {
        let conn = db::open_in_memory().unwrap();
        save(
            &conn,
            "/m",
            "ch_a",
            "notes.md",
            &agreed(Some([7; 32]), 2, 1),
        )
        .unwrap();
        save(&conn, "/m", "ch_a", "gone.md", &agreed(None, 5, 2)).unwrap();
        save(
            &conn,
            "/m",
            "ch_a",
            "notes.md",
            &agreed(Some([8; 32]), 3, 2),
        )
        .unwrap();
        save(
            &conn,
            "/other",
            "ch_a",
            "notes.md",
            &agreed(Some([9; 32]), 1, 1),
        )
        .unwrap();

        let state = load(&conn, "/m", "ch_a").unwrap();
        assert_eq!(state.len(), 2);
        assert_eq!(state["notes.md"], agreed(Some([8; 32]), 3, 2));
        assert_eq!(state["gone.md"], agreed(None, 5, 2));
        assert!(any(&conn, "/m", "ch_a").unwrap());
        assert!(!any(&conn, "/m", "ch_b").unwrap());
        assert!(!any(&conn, "/nowhere", "ch_a").unwrap());

        // No links, no chain, and a hundred links.
        let long: Vec<Link> = (0..MAX_ENTRY_LINKS)
            .map(|n| Link {
                hash: [n as u8; 16],
                signer: [n as u8 + 1; 16],
            })
            .collect();
        for chain in [Some(Vec::new()), None, Some(long)] {
            let record = Agreed {
                chain,
                ..agreed(None, 6, 3)
            };
            save(&conn, "/m", "ch_a", "gone.md", &record).unwrap();
            let state = load(&conn, "/m", "ch_a").unwrap();
            assert_eq!(state["gone.md"], record);
            assert_eq!(state["notes.md"], agreed(Some([8; 32]), 3, 2));
        }
    }

    /// What is in a row and is no key, or no chain, is read as none:
    /// a blob of another length, a text, a number, links that are not
    /// whole, and more links than an entry may have. The rest of the row
    /// is read as it is.
    #[test]
    fn test_a_row_that_holds_no_key_or_no_chain_says_none() {
        let conn = db::open_in_memory().unwrap();
        save(&conn, "/m", "ch_a", "gone.md", &agreed(None, 6, 3)).unwrap();
        let text_of_a_keys_length = format!("'{}'", "k".repeat(32));
        for odd in [
            "NULL",
            "x'0102'",
            "'a text'",
            text_of_a_keys_length.as_str(),
            "17",
            "1.5",
        ] {
            let set = format!("UPDATE sync_files SET author = {odd} WHERE key = 'gone.md'");
            conn.execute(&set, []).unwrap();
            let state = load(&conn, "/m", "ch_a").unwrap();
            assert_eq!(state["gone.md"].signer, None, "{odd}");
            assert_eq!(state["gone.md"].rev, 6, "{odd}");
            assert_eq!(state["gone.md"].chain, agreed(None, 6, 3).chain, "{odd}");
        }
        let too_long = format!("zeroblob({})", (MAX_ENTRY_LINKS + 1) * LINK_BYTES);
        for odd in [
            "NULL",
            "x'0102'",
            "zeroblob(33)",
            "'a text'",
            "17",
            &too_long,
        ] {
            let set = format!("UPDATE sync_files SET chain = {odd} WHERE key = 'gone.md'");
            conn.execute(&set, []).unwrap();
            let state = load(&conn, "/m", "ch_a").unwrap();
            // A text and a number are read as an empty blob: no links.
            let expected = match odd {
                "'a text'" | "17" => Some(Vec::new()),
                _ => None,
            };
            assert_eq!(state["gone.md"].chain, expected, "{odd}");
        }
    }

    /// When a device applies a statement, each folder's records go with
    /// the name to its new channel: every record of the channel that is
    /// left, with its records of index lines, and each revision as the
    /// renumbering gives it. Another channel's records stay.
    #[test]
    fn test_a_folders_records_move_to_the_names_new_channel_renumbered() {
        let conn = db::open_in_memory().unwrap();
        save(
            &conn,
            "/m",
            "ch_old",
            "notes.md",
            &agreed(Some([7; 32]), 2, 1),
        )
        .unwrap();
        save(&conn, "/m", "ch_old", "gone.md", &agreed(None, 900, 2)).unwrap();
        save(
            &conn,
            "/n",
            "ch_old",
            "notes.md",
            &agreed(Some([8; 32]), 3, 1),
        )
        .unwrap();
        save(
            &conn,
            "/m",
            "ch_other",
            "notes.md",
            &agreed(Some([9; 32]), 4, 1),
        )
        .unwrap();
        crate::index_lines::line_removed(&conn, "/m", "ch_old", "notes.md", "- a line", 7).unwrap();
        crate::index_lines::line_removed(&conn, "/m", "ch_other", "notes.md", "- other", 7)
            .unwrap();
        assert_eq!(
            files(&conn, "ch_old").unwrap(),
            [
                ("/m".to_string(), "gone.md".to_string()),
                ("/m".to_string(), "notes.md".to_string()),
                ("/n".to_string(), "notes.md".to_string()),
            ]
        );

        // One record is dropped by itself, and the rest move.
        assert!(forget_file(&conn, "/n", "ch_old", "notes.md").unwrap());
        assert!(!forget_file(&conn, "/n", "ch_old", "notes.md").unwrap());
        let lift = |rev: u64| if rev >= 100 { rev + 1000 } else { rev };
        assert_eq!(move_channel(&conn, "ch_old", "ch_new", lift).unwrap(), 2);
        assert!(load(&conn, "/m", "ch_old").unwrap().is_empty());
        let moved = load(&conn, "/m", "ch_new").unwrap();
        assert_eq!(moved["notes.md"], agreed(Some([7; 32]), 2, 1));
        assert_eq!(
            moved["gone.md"],
            Agreed {
                rev: 1900,
                ..agreed(None, 900, 2)
            }
        );
        assert_eq!(
            load(&conn, "/m", "ch_other").unwrap()["notes.md"],
            agreed(Some([9; 32]), 4, 1)
        );
        let lines = |channel: &str| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM index_lines WHERE channel_id = ?1",
                [channel],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(
            (lines("ch_old"), lines("ch_new"), lines("ch_other")),
            (0, 1, 1)
        );
        // Moved again, nothing is there to move, and a channel is not
        // moved to itself.
        assert_eq!(move_channel(&conn, "ch_old", "ch_new", lift).unwrap(), 0);
        assert_eq!(move_channel(&conn, "ch_new", "ch_new", lift).unwrap(), 0);
        assert_eq!(load(&conn, "/m", "ch_new").unwrap().len(), 2);
    }
}
