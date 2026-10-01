//! Explicit trust: keys this node accepts invites from without asking.
//!
//! Set by `add-device` (the device being added) and `accept` (the device
//! that added this one). A person's other devices are also trusted through
//! membership of the personal channel, which is not stored here.
//!
//! Spec: decision 2026-09-30-agent-memory-sync §4.1

use chrono::Utc;
use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;

/// Kind of a trusted key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustKind {
    /// Another device of the same person.
    Device,
    /// Another person, for channels shared between people (not built;
    /// memory is never shared, decision 2026-09-30 §4.7).
    Person,
}

impl TrustKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Person => "person",
        }
    }
}

/// A row of `trusted_keys`.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub key: [u8; 32],
    pub kind: String,
    pub label: Option<String>,
    pub added_at: String,
    pub revoked_at: Option<String>,
}

/// Trust `key`, or re-trust it if previously revoked. Updates the label
/// only when one is given.
pub fn trust(
    conn: &Connection,
    key: &[u8; 32],
    kind: TrustKind,
    label: Option<&str>,
) -> Result<(), CordeliaError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO trusted_keys (entity_key, kind, label, added_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(entity_key) DO UPDATE SET
            kind = excluded.kind,
            label = COALESCE(excluded.label, trusted_keys.label),
            revoked_at = NULL",
        params![key.as_slice(), kind.as_str(), label, now],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// Revoke explicit trust in `key`. Returns false if it was not trusted.
pub fn revoke(conn: &Connection, key: &[u8; 32]) -> Result<bool, CordeliaError> {
    let now = Utc::now().to_rfc3339();
    let updated = conn
        .execute(
            "UPDATE trusted_keys SET revoked_at = ?1
             WHERE entity_key = ?2 AND revoked_at IS NULL",
            params![now, key.as_slice()],
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(updated > 0)
}

/// Whether `key` is explicitly trusted and not revoked.
pub fn is_trusted(conn: &Connection, key: &[u8; 32]) -> Result<bool, CordeliaError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM trusted_keys
                       WHERE entity_key = ?1 AND revoked_at IS NULL)",
        params![key.as_slice()],
        |row| row.get(0),
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))
}

/// The label recorded for `key`, if any.
pub fn label(conn: &Connection, key: &[u8; 32]) -> Result<Option<String>, CordeliaError> {
    match conn.query_row(
        "SELECT label FROM trusted_keys WHERE entity_key = ?1",
        params![key.as_slice()],
        |row| row.get::<_, Option<String>>(0),
    ) {
        Ok(label) => Ok(label),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(CordeliaError::Storage(e.to_string())),
    }
}

/// All trusted keys, including revoked ones, oldest first.
pub fn list(conn: &Connection) -> Result<Vec<TrustedKey>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT entity_key, kind, label, added_at, revoked_at
             FROM trusted_keys ORDER BY added_at ASC",
        )
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok((blob, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        let (blob, kind, label, added_at, revoked_at) =
            row.map_err(|e| CordeliaError::Storage(e.to_string()))?;
        if let Ok(key) = <[u8; 32]>::try_from(blob.as_slice()) {
            out.push(TrustedKey {
                key,
                kind,
                label,
                added_at,
                revoked_at,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn test_trust_revoke_retrust() {
        let conn = db::open_in_memory().unwrap();
        let key = [0x07u8; 32];

        assert!(!is_trusted(&conn, &key).unwrap());
        trust(&conn, &key, TrustKind::Device, Some("imac")).unwrap();
        assert!(is_trusted(&conn, &key).unwrap());
        assert_eq!(label(&conn, &key).unwrap().as_deref(), Some("imac"));

        assert!(revoke(&conn, &key).unwrap());
        assert!(!is_trusted(&conn, &key).unwrap());
        assert!(!revoke(&conn, &key).unwrap(), "second revoke is a no-op");

        // Re-trusting clears the revocation and keeps the old label.
        trust(&conn, &key, TrustKind::Device, None).unwrap();
        assert!(is_trusted(&conn, &key).unwrap());
        assert_eq!(label(&conn, &key).unwrap().as_deref(), Some("imac"));

        let all = list(&conn).unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].revoked_at.is_none());
    }
}
