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

/// Channel IDs become file names. Refuse anything that could escape the
/// channel-keys directory: channel IDs now arrive from other nodes in
/// channel states, and legitimate IDs never contain these characters.
fn check_file_component(channel_id: &str) -> Result<(), CordeliaError> {
    if channel_id.is_empty()
        || channel_id.contains(['/', '\\', '\0'])
        || channel_id.starts_with('.')
    {
        return Err(CordeliaError::Storage(format!(
            "invalid channel id for key file: {channel_id:?}"
        )));
    }
    Ok(())
}

/// Write a 32-byte secret to `path` with mode 0600.
fn write_secret(path: &Path, secret: &[u8; 32]) -> Result<(), CordeliaError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CordeliaError::Storage(format!("create key dir: {e}")))?;
    }
    std::fs::write(path, secret).map_err(|e| CordeliaError::Storage(format!("write key: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CordeliaError::Storage(format!("set key permissions: {e}")))?;
    }
    Ok(())
}

/// Read a 32-byte secret from `path`.
fn read_secret(path: &Path) -> Result<[u8; 32], CordeliaError> {
    let bytes =
        std::fs::read(path).map_err(|e| CordeliaError::Storage(format!("read key: {e}")))?;
    bytes.as_slice().try_into().map_err(|_| {
        CordeliaError::Crypto(format!("key file must be 32 bytes, got {}", bytes.len()))
    })
}

/// Path to a channel's PSK file.
pub fn psk_path(home_dir: &Path, channel_id: &str) -> PathBuf {
    home_dir
        .join("channel-keys")
        .join(format!("{channel_id}.key"))
}

/// Read a 32-byte PSK from the filesystem.
pub fn read_psk(home_dir: &Path, channel_id: &str) -> Result<[u8; 32], CordeliaError> {
    check_file_component(channel_id)?;
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
    check_file_component(channel_id)?;
    let path = psk_path(home_dir, channel_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CordeliaError::Storage(format!("create PSK dir: {e}")))?;
    }
    std::fs::write(&path, psk).map_err(|e| CordeliaError::Storage(format!("write PSK: {e}")))?;

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
    check_file_component(channel_id)?;
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

/// Delete every key file kept for a swarm channel: its key, and its ring
/// and its slot key if it has them. A key file is named for its channel,
/// so these are found by how their names begin
/// ([`crate::naming::SWARM_CHANNEL_PREFIX`]), whether or not the database
/// still has the channel.
///
/// Returns how many files went, and how many are left: those that could
/// not be deleted. Nothing here fails. A node does this when it starts,
/// and a file it cannot delete is no reason for it not to start: it is
/// counted, for the node to say, and tried again at the next start. (Where
/// the directory itself, or an entry of it, cannot be read, that counts as
/// one left: whatever it is could not be deleted either.)
pub fn delete_swarm_keys(home_dir: &Path) -> (usize, usize) {
    let (mut deleted, mut left) = (0, 0);
    let entries = match std::fs::read_dir(home_dir.join("channel-keys")) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, 0),
        Err(_) => return (0, 1),
    };
    for entry in entries {
        let Ok(entry) = entry else {
            left += 1;
            continue;
        };
        let of_a_swarm_channel = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(crate::naming::SWARM_CHANNEL_PREFIX));
        if of_a_swarm_channel {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => deleted += 1,
                Err(_) => left += 1,
            }
        }
    }
    (deleted, left)
}

/// Path to a channel's key ring file.
pub fn ring_path(home_dir: &Path, channel_id: &str) -> PathBuf {
    home_dir
        .join("channel-keys")
        .join(format!("{channel_id}.ring.json"))
}

/// Read the key ring for a channel, or return an empty ring if none exists.
pub fn read_ring(home_dir: &Path, channel_id: &str) -> Result<KeyRing, CordeliaError> {
    check_file_component(channel_id)?;
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
    check_file_component(&ring.channel_id)?;
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

/// Drop from a ring what is not part of the channel's history as this
/// device records it: entries at or above the version the ring says this
/// device holds. Every earlier version it used is below that. An entry at
/// or above it was put there by something other than a change this device
/// made or applied, and, left in the ring, would stand as that version's
/// key once the channel had passed the version.
fn drop_what_is_not_history(ring: &mut KeyRing) {
    let held = ring.current_version;
    ring.keys.retain(|e| e.version < held);
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
    drop_what_is_not_history(&mut ring);

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

/// Path to a channel's slot key file (decision 2026-09-30 §4.3).
pub fn slot_key_path(home_dir: &Path, channel_id: &str) -> PathBuf {
    home_dir
        .join("channel-keys")
        .join(format!("{channel_id}.slot"))
}

/// Write a channel's slot key (mode 0600). The slot key is never rotated.
pub fn write_slot_key(
    home_dir: &Path,
    channel_id: &str,
    slot_key: &[u8; 32],
) -> Result<(), CordeliaError> {
    check_file_component(channel_id)?;
    write_secret(&slot_key_path(home_dir, channel_id), slot_key)
}

/// Read a channel's slot key.
pub fn read_slot_key(home_dir: &Path, channel_id: &str) -> Result<[u8; 32], CordeliaError> {
    check_file_component(channel_id)?;
    read_secret(&slot_key_path(home_dir, channel_id))
}

/// Install a channel's full key ring, as received in a channel state.
///
/// The key for `current_version` becomes the channel PSK. Every earlier
/// version given goes into the ring, unless the ring already holds that
/// version, in which case the key it holds stays.
///
/// A key for a version the channel has not reached is never kept. One
/// given above `current_version` is dropped. One already in the ring at
/// or above the version this device held is dropped before the merge
/// (see [`drop_what_is_not_history`]), so that the real key for that
/// version is taken from the state when the channel has passed it.
pub fn install_key_ring(
    home_dir: &Path,
    channel_id: &str,
    keys: &[(u32, [u8; 32])],
    current_version: u32,
) -> Result<(), CordeliaError> {
    let current = keys
        .iter()
        .find(|(v, _)| *v == current_version)
        .map(|(_, k)| *k)
        .ok_or_else(|| {
            CordeliaError::Crypto(format!(
                "key ring for {channel_id} lacks current version {current_version}"
            ))
        })?;

    let mut ring = read_ring(home_dir, channel_id)?;
    drop_what_is_not_history(&mut ring);
    let now = chrono::Utc::now().to_rfc3339();
    for (version, key) in keys {
        let version = *version as i64;
        if version == current_version as i64 || ring.keys.iter().any(|e| e.version == version) {
            continue;
        }
        ring.keys.push(KeyRingEntry {
            version,
            psk_hex: hex::encode(key),
            rotated_at: now.clone(),
        });
    }
    ring.keys.retain(|e| e.version < current_version as i64);
    ring.keys.sort_by_key(|e| e.version);
    ring.current_version = current_version as i64;

    write_ring(home_dir, &ring)?;
    write_psk(home_dir, channel_id, &current)
}

/// The full key ring held for a channel: every earlier version plus the
/// current PSK, ordered by version. Used to build channel states, and to
/// make the next version. Nothing in the ring above the current version is
/// part of it.
pub fn export_key_ring(
    home_dir: &Path,
    channel_id: &str,
    current_version: i64,
) -> Result<Vec<(u32, [u8; 32])>, CordeliaError> {
    let mut keys = Vec::new();
    for entry in read_ring(home_dir, channel_id)?.keys {
        if entry.version >= current_version {
            continue;
        }
        let bytes = hex::decode(&entry.psk_hex)
            .map_err(|e| CordeliaError::Crypto(format!("decode ring PSK: {e}")))?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CordeliaError::Crypto("ring PSK must be 32 bytes".into()))?;
        let version = u32::try_from(entry.version)
            .map_err(|_| CordeliaError::Crypto("ring version out of range".into()))?;
        keys.push((version, key));
    }
    let current = u32::try_from(current_version)
        .map_err(|_| CordeliaError::Crypto("key version out of range".into()))?;
    keys.push((current, read_psk(home_dir, channel_id)?));
    keys.sort_by_key(|(v, _)| *v);
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_path_escaping_channel_ids() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "",
            "../x",
            "grp_../../etc/passwd",
            ".hidden",
            "a\\b",
            "a\0b",
        ] {
            assert!(write_psk(dir.path(), bad, &[0; 32]).is_err(), "{bad:?}");
            assert!(
                write_slot_key(dir.path(), bad, &[0; 32]).is_err(),
                "{bad:?}"
            );
            assert!(read_psk(dir.path(), bad).is_err(), "{bad:?}");
        }
        // Real IDs are fine.
        write_psk(
            dir.path(),
            "grp_550e8400-e29b-41d4-a716-446655440000",
            &[1; 32],
        )
        .unwrap();
        write_psk(dir.path(), "inbox_ab12", &[1; 32]).unwrap();
    }

    #[test]
    fn test_slot_key_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        write_slot_key(dir.path(), "grp_a", &[0x5A; 32]).unwrap();
        assert_eq!(read_slot_key(dir.path(), "grp_a").unwrap(), [0x5A; 32]);
    }

    #[test]
    fn test_install_and_export_key_ring() {
        let dir = tempfile::tempdir().unwrap();
        let keys = [(1u32, [0x11u8; 32]), (2, [0x22; 32]), (3, [0x33; 32])];
        install_key_ring(dir.path(), "grp_r", &keys, 3).unwrap();

        assert_eq!(read_psk(dir.path(), "grp_r").unwrap(), [0x33; 32]);
        assert_eq!(
            read_psk_for_version(dir.path(), "grp_r", 1, 3).unwrap(),
            [0x11; 32]
        );
        assert_eq!(
            export_key_ring(dir.path(), "grp_r", 3).unwrap(),
            keys.to_vec()
        );

        // A later state with a new current key keeps every old version.
        install_key_ring(dir.path(), "grp_r", &[(3, [0x33; 32]), (4, [0x44; 32])], 4).unwrap();
        let exported = export_key_ring(dir.path(), "grp_r", 4).unwrap();
        assert_eq!(
            exported.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(read_psk(dir.path(), "grp_r").unwrap(), [0x44; 32]);

        // The current version must be in the ring being installed.
        assert!(install_key_ring(dir.path(), "grp_r", &[(5, [0x55; 32])], 6).is_err());
    }

    /// T16. A key for a version the channel has not reached is never kept
    /// and never handed on. Otherwise it would wait for the removal that
    /// makes that version, and take the place of the key made then.
    #[test]
    fn a_key_above_the_current_version_is_never_kept() {
        let dir = tempfile::tempdir().unwrap();
        let versions = |dir: &Path| -> Vec<i64> {
            let ring = read_ring(dir, "grp_r").unwrap();
            ring.keys.iter().map(|e| e.version).collect()
        };

        // Given in a state: not kept.
        let given = [(1u32, [0x11u8; 32]), (2, [0x22; 32]), (3, [0x4a; 32])];
        install_key_ring(dir.path(), "grp_r", &given, 2).unwrap();
        assert_eq!(versions(dir.path()), vec![1]);
        assert_eq!(read_psk(dir.path(), "grp_r").unwrap(), [0x22; 32]);

        // Already in the file: not handed on, and gone at the next install.
        let mut ring = read_ring(dir.path(), "grp_r").unwrap();
        ring.keys.push(KeyRingEntry {
            version: 3,
            psk_hex: hex::encode([0x4a; 32]),
            rotated_at: "2026-10-03T00:00:00Z".into(),
        });
        write_ring(dir.path(), &ring).unwrap();
        assert_eq!(
            export_key_ring(dir.path(), "grp_r", 2).unwrap(),
            vec![(1, [0x11; 32]), (2, [0x22; 32])]
        );
        install_key_ring(dir.path(), "grp_r", &[(2, [0x22; 32])], 2).unwrap();
        assert_eq!(versions(dir.path()), vec![1]);

        // An entry at the current version itself is no part of the ring
        // either: the key in place is the current one.
        let mut ring = read_ring(dir.path(), "grp_r").unwrap();
        ring.keys.push(KeyRingEntry {
            version: 2,
            psk_hex: hex::encode([0x4a; 32]),
            rotated_at: "2026-10-03T00:00:00Z".into(),
        });
        write_ring(dir.path(), &ring).unwrap();
        assert_eq!(
            export_key_ring(dir.path(), "grp_r", 2).unwrap(),
            vec![(1, [0x11; 32]), (2, [0x22; 32])]
        );
        install_key_ring(dir.path(), "grp_r", &[(2, [0x22; 32])], 2).unwrap();
        assert_eq!(versions(dir.path()), vec![1]);
    }

    /// T16. A key that was waiting in the ring for a later version does
    /// not become that version's key when the channel passes it: a device
    /// that was away for two changes takes the real key for the version it
    /// missed, and can read what was written under it.
    #[test]
    fn a_key_that_was_waiting_is_not_kept_when_its_version_is_passed() {
        let dir = tempfile::tempdir().unwrap();
        install_key_ring(dir.path(), "grp_r", &[(1, [0x11; 32]), (2, [0x22; 32])], 2).unwrap();
        let mut ring = read_ring(dir.path(), "grp_r").unwrap();
        ring.keys.push(KeyRingEntry {
            version: 3,
            psk_hex: hex::encode([0x4a; 32]),
            rotated_at: "2026-10-03T00:00:00Z".into(),
        });
        write_ring(dir.path(), &ring).unwrap();

        let later = [
            (1u32, [0x11u8; 32]),
            (2, [0x22; 32]),
            (3, [0x33; 32]),
            (4, [0x44; 32]),
        ];
        install_key_ring(dir.path(), "grp_r", &later, 4).unwrap();
        assert_eq!(
            read_psk_for_version(dir.path(), "grp_r", 3, 4).unwrap(),
            [0x33; 32]
        );
        assert_eq!(export_key_ring(dir.path(), "grp_r", 4).unwrap(), later);

        // The same for an entry at the very version this device holds: the
        // key in use is the one in the key file, and when the channel
        // moves on, that version's key is the one the state gives.
        let mut ring = read_ring(dir.path(), "grp_r").unwrap();
        ring.keys.push(KeyRingEntry {
            version: 4,
            psk_hex: hex::encode([0x4a; 32]),
            rotated_at: "2026-10-03T00:00:00Z".into(),
        });
        write_ring(dir.path(), &ring).unwrap();
        let next = [
            (1u32, [0x11u8; 32]),
            (2, [0x22; 32]),
            (3, [0x33; 32]),
            (4, [0x44; 32]),
            (5, [0x55; 32]),
        ];
        install_key_ring(dir.path(), "grp_r", &next, 5).unwrap();
        assert_eq!(
            read_psk_for_version(dir.path(), "grp_r", 4, 5).unwrap(),
            [0x44; 32]
        );
        assert_eq!(export_key_ring(dir.path(), "grp_r", 5).unwrap(), next);
    }

    /// T16. The older way of making a new key (`rotate_psk`) drops a
    /// waiting key as well. Kept, it would sit beside the real key for its
    /// version after two rotations, and be the one that is read.
    #[test]
    fn a_key_that_was_waiting_does_not_survive_the_older_rotation() {
        let dir = tempfile::tempdir().unwrap();
        write_psk(dir.path(), "ch1", &[0x11; 32]).unwrap();
        let mut ring = read_ring(dir.path(), "ch1").unwrap();
        ring.keys.push(KeyRingEntry {
            version: 2,
            psk_hex: hex::encode([0x4a; 32]),
            rotated_at: "2026-10-03T00:00:00Z".into(),
        });
        write_ring(dir.path(), &ring).unwrap();

        rotate_psk(dir.path(), "ch1", &[0x22; 32], "2026-10-03T00:00:00Z").unwrap();
        rotate_psk(dir.path(), "ch1", &[0x33; 32], "2026-10-03T00:00:01Z").unwrap();
        assert_eq!(
            read_psk_for_version(dir.path(), "ch1", 2, 3).unwrap(),
            [0x22; 32]
        );
        assert_eq!(
            export_key_ring(dir.path(), "ch1", 3).unwrap(),
            vec![(1, [0x11; 32]), (2, [0x22; 32]), (3, [0x33; 32])]
        );
    }

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
