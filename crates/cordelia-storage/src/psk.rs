//! PSK file I/O and key ring management for channel key lifecycle.
//!
//! Current PSK: `~/.cordelia/channel-keys/<channel_id>.key` (32 bytes raw, mode 0600).
//! Key ring: `~/.cordelia/channel-keys/<channel_id>.ring.json` (historical PSKs).
//! Spec: seed-drill/specs/ecies-envelope-encryption.md §6.3-§6.4

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use cordelia_core::CordeliaError;

/// Key ring entry for a historical PSK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRingEntry {
    pub version: i64,
    pub psk_hex: String,
    pub rotated_at: String,
}

/// Key ring: historical PSKs for a channel, enabling decryption of old items after rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRing {
    pub channel_id: String,
    pub current_version: i64,
    pub keys: Vec<KeyRingEntry>,
}

/// Path to a channel's PSK file.
pub fn psk_path(home_dir: &Path, channel_id: &str) -> PathBuf {
    home_dir.join("channel-keys").join(format!("{channel_id}.key"))
}

/// Read a 32-byte PSK from the filesystem.
pub fn read_psk(home_dir: &Path, channel_id: &str) -> Result<[u8; 32], CordeliaError> {
    let path = psk_path(home_dir, channel_id);
    let bytes =
        std::fs::read(&path).map_err(|e| CordeliaError::Storage(format!("read PSK: {e}")))?;
    if bytes.len() != 32 {
        return Err(CordeliaError::Crypto(format!(
            "PSK file must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&bytes);
    Ok(psk)
}

/// Write a 32-byte PSK to the filesystem (mode 0600).
pub fn write_psk(home_dir: &Path, channel_id: &str, psk: &[u8; 32]) -> Result<(), CordeliaError> {
    let path = psk_path(home_dir, channel_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CordeliaError::Storage(format!("create PSK dir: {e}")))?;
    }
    std::fs::write(&path, psk)
        .map_err(|e| CordeliaError::Storage(format!("write PSK: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CordeliaError::Storage(format!("set PSK permissions: {e}")))?;
    }

    Ok(())
}

/// Delete a channel's PSK file.
pub fn delete_psk(home_dir: &Path, channel_id: &str) -> Result<(), CordeliaError> {
    let path = psk_path(home_dir, channel_id);
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| CordeliaError::Storage(format!("delete PSK: {e}")))?;
    }
    Ok(())
}

/// Check if a PSK file exists for a channel.
pub fn has_psk(home_dir: &Path, channel_id: &str) -> bool {
    psk_path(home_dir, channel_id).exists()
}

/// Path to a channel's key ring file.
pub fn ring_path(home_dir: &Path, channel_id: &str) -> PathBuf {
    home_dir.join("channel-keys").join(format!("{channel_id}.ring.json"))
}

/// Read the key ring for a channel, or return an empty ring if none exists.
pub fn read_ring(home_dir: &Path, channel_id: &str) -> Result<KeyRing, CordeliaError> {
    let path = ring_path(home_dir, channel_id);
    if !path.exists() {
        return Ok(KeyRing {
            channel_id: channel_id.to_string(),
            current_version: 1,
            keys: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| CordeliaError::Storage(format!("read key ring: {e}")))?;
    serde_json::from_str(&content)
        .map_err(|e| CordeliaError::Storage(format!("parse key ring: {e}")))
}

/// Write the key ring to disk (mode 0600).
pub fn write_ring(home_dir: &Path, ring: &KeyRing) -> Result<(), CordeliaError> {
    let path = ring_path(home_dir, &ring.channel_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CordeliaError::Storage(format!("create ring dir: {e}")))?;
    }
    let content = serde_json::to_string_pretty(ring)
        .map_err(|e| CordeliaError::Storage(format!("serialize key ring: {e}")))?;
    std::fs::write(&path, content)
        .map_err(|e| CordeliaError::Storage(format!("write key ring: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CordeliaError::Storage(format!("set ring permissions: {e}")))?;
    }

    Ok(())
}

/// Rotate the PSK for a channel: archive old PSK to ring, write new PSK.
///
/// Returns the new key_version.
pub fn rotate_psk(
    home_dir: &Path,
    channel_id: &str,
    new_psk: &[u8; 32],
    rotated_at: &str,
) -> Result<i64, CordeliaError> {
    // Read current PSK (the one being replaced)
    let old_psk = read_psk(home_dir, channel_id)?;
    let mut ring = read_ring(home_dir, channel_id)?;

    // Archive the old PSK
    ring.keys.push(KeyRingEntry {
        version: ring.current_version,
        psk_hex: hex::encode(old_psk),
        rotated_at: rotated_at.to_string(),
    });
    ring.current_version += 1;

    // Write new ring, then new PSK
    write_ring(home_dir, &ring)?;
    write_psk(home_dir, channel_id, new_psk)?;

    Ok(ring.current_version)
}

/// Look up a historical PSK by key_version. Falls back to current PSK if version matches.
pub fn read_psk_for_version(
    home_dir: &Path,
    channel_id: &str,
    version: i64,
    current_version: i64,
) -> Result<[u8; 32], CordeliaError> {
    if version == current_version {
        return read_psk(home_dir, channel_id);
    }

    let ring = read_ring(home_dir, channel_id)?;
    for entry in &ring.keys {
        if entry.version == version {
            let bytes = hex::decode(&entry.psk_hex)
                .map_err(|e| CordeliaError::Crypto(format!("decode ring PSK: {e}")))?;
            if bytes.len() != 32 {
                return Err(CordeliaError::Crypto(format!(
                    "ring PSK must be 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut psk = [0u8; 32];
            psk.copy_from_slice(&bytes);
            return Ok(psk);
        }
    }

    Err(CordeliaError::Crypto(format!(
        "key version {version} not found in ring for {channel_id}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psk_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let psk = [0x42u8; 32];
        write_psk(dir.path(), "test-channel", &psk).unwrap();
        let loaded = read_psk(dir.path(), "test-channel").unwrap();
        assert_eq!(loaded, psk);
    }

    #[test]
    fn test_psk_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_psk(dir.path(), "nonexistent").is_err());
    }

    #[test]
    fn test_delete_psk() {
        let dir = tempfile::tempdir().unwrap();
        let psk = [0x42u8; 32];
        write_psk(dir.path(), "test-channel", &psk).unwrap();
        assert!(has_psk(dir.path(), "test-channel"));
        delete_psk(dir.path(), "test-channel").unwrap();
        assert!(!has_psk(dir.path(), "test-channel"));
    }

    #[test]
    fn test_has_psk() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!has_psk(dir.path(), "test-channel"));
        write_psk(dir.path(), "test-channel", &[0u8; 32]).unwrap();
        assert!(has_psk(dir.path(), "test-channel"));
    }

    #[test]
    fn test_key_ring_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ring = read_ring(dir.path(), "test-channel").unwrap();
        assert_eq!(ring.current_version, 1);
        assert!(ring.keys.is_empty());
    }

    #[test]
    fn test_rotate_psk() {
        let dir = tempfile::tempdir().unwrap();
        let psk_v1 = [0x11u8; 32];
        let psk_v2 = [0x22u8; 32];
        let psk_v3 = [0x33u8; 32];

        // Write initial PSK
        write_psk(dir.path(), "ch1", &psk_v1).unwrap();

        // Rotate to v2
        let v2 = rotate_psk(dir.path(), "ch1", &psk_v2, "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(v2, 2);
        assert_eq!(read_psk(dir.path(), "ch1").unwrap(), psk_v2);

        // Rotate to v3
        let v3 = rotate_psk(dir.path(), "ch1", &psk_v3, "2026-01-02T00:00:00Z").unwrap();
        assert_eq!(v3, 3);
        assert_eq!(read_psk(dir.path(), "ch1").unwrap(), psk_v3);

        // Read historical versions
        let recovered_v1 = read_psk_for_version(dir.path(), "ch1", 1, 3).unwrap();
        assert_eq!(recovered_v1, psk_v1);
        let recovered_v2 = read_psk_for_version(dir.path(), "ch1", 2, 3).unwrap();
        assert_eq!(recovered_v2, psk_v2);
        let recovered_v3 = read_psk_for_version(dir.path(), "ch1", 3, 3).unwrap();
        assert_eq!(recovered_v3, psk_v3);
    }

    #[test]
    fn test_read_psk_for_version_missing() {
        let dir = tempfile::tempdir().unwrap();
        write_psk(dir.path(), "ch1", &[0x42u8; 32]).unwrap();
        let result = read_psk_for_version(dir.path(), "ch1", 99, 1);
        assert!(result.is_err());
    }
}
