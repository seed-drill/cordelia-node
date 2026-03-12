//! PSK file I/O for channel key management.
//!
//! PSK files live at `~/.cordelia/channel-keys/<channel_id>.key` (mode 0600).
//! Spec: seed-drill/specs/ecies-envelope-encryption.md §6.3

use std::path::{Path, PathBuf};

use cordelia_core::CordeliaError;

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
}
