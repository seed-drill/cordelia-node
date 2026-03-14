//! Database connection management.

use rusqlite::Connection;
use std::path::Path;

use crate::StorageError;
use crate::schema;

/// Open (or create) the Cordelia database and run migrations.
pub fn open(path: &Path) -> Result<Connection, StorageError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    schema::init_db(&conn)?;
    Ok(conn)
}

/// Open an in-memory database with schema initialised. For testing.
pub fn open_in_memory() -> Result<Connection, StorageError> {
    let conn = Connection::open_in_memory()?;
    schema::init_db(&conn)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_file_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let conn = open(&path).unwrap();

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, schema::SCHEMA_VERSION);
    }

    #[test]
    fn test_open_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("cordelia.db");
        let _conn = open(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_open_in_memory() {
        let _conn = open_in_memory().unwrap();
    }
}
