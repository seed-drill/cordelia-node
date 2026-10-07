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

/// The name home memory syncs under on this device, or last did: the name
/// the home directory is or was mapped under, or `~` where it was found
/// and not mapped. It is written when home starts to sync under a name,
/// and kept when home memory is turned off or unmapped, so that turning it
/// on again maps it under the same name, into the same channel.
pub const SYNC_CLAUDE_HOME_NAME: &str = "sync.claude.home_name";

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

/// The files whose record in a folder could not be carried when this
/// device applied the statement it has applied (decision 2026-10-04
/// §4.2), as JSON: each as the name it syncs under and the file. Replaced
/// at each statement applied.
pub const PERSON_NOT_CARRIED: &str = "person.not_carried";

/// Present where the statement that this device has applied removes a key
/// that the statement it held before did not (decision 2026-10-04
/// §10.1), as the device found it at the moment it applied the
/// statement: a renewal removes nobody, though its list of removed keys
/// names every key removed so far. Written at each statement applied.
pub const PERSON_REMOVED_A_KEY: &str = "person.removed_a_key";

/// JSON array of the names that this device holds by a carry that a
/// person asked for, or by a recovery, with no folder of its own mapped
/// to them (decision 2026-10-04 §7.3, §9): it holds each, and lists it
/// in the personal channel, whether or not sync is on here. A name goes
/// from the list when the device stops it, and the list goes when the
/// device leaves its phrase.
pub const PERSON_NAMES_CARRIED: &str = "person.names_carried";

/// Whether the look of a recovery that was made on this machine has not
/// ended (decision 2026-10-04 §8, §9): it is set where the recovery's
/// statement is applied, and goes when the look has carried what it
/// takes. While it is set the machine does not write that it has sent
/// what it carried: a recovery whose look was interrupted was cut short,
/// and the next recovery says so.
pub const PERSON_LOOK_PENDING: &str = "person.look_pending";

/// JSON object of what this device called each key that a statement it
/// applied removed, by the key in hex (decision 2026-10-04 §7.3): a
/// statement lists removed keys bare, and a person names one by its
/// label at `cordelia sync carry --from`. A key that the device never
/// knew by a label is not in it.
pub const PERSON_REMOVED_LABELS: &str = "person.removed_labels";

/// The mark that the first start on a version that carries no channel of
/// the older kind is done, with whether the step was made and the version
/// that wrote it (`crate::first_start`, decision 2026-10-04 §10.1).
pub const FIRST_START: &str = "first_start.done";

/// JSON array of what a device whose stored scope was on has been told:
/// one record for each time, with the date, the Claude Code directory and
/// the folders that stopped syncing (`crate::first_start::Notice`,
/// decision 2026-10-04 §10.1).
pub const SYNC_CLAUDE_NOTICE: &str = "sync.claude.notice";

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
