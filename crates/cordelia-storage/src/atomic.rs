//! Writing a memory file so that a reader sees the old text or the new
//! one, whole (decision 2026-09-30-agent-memory-sync §4.5). The sync
//! adapter writes every file through this, and so does a restore from
//! local history.

use std::path::Path;

/// Write `text` to `dir/name` atomically: temporary file, then rename. The
/// rename replaces a symlink at `name` rather than writing through it.
/// Returns `false`, with nothing written under `name`, if `unchanged` says
/// that what is there is no longer what the caller saw.
///
/// The text is flushed to the disk before the file gets its name. A copy
/// of this device's version is written just before a file is replaced:
/// if the power went between the two, the copy must not be the one that
/// is empty. A flush takes long enough for an agent to write to the file
/// meanwhile, so `unchanged` is asked after it, as the last thing before
/// the rename. The name is flushed after the rename, as far as the volume
/// can: the record of a write is on the disk as soon as it is made, and a
/// name that was not would leave the old text under a record of the new.
///
/// `flushed` is run between the flush and that last look. Nothing is done
/// there but by a test, which does what an agent may do while a text is
/// flushed.
///
/// The folder is never made here. A sync cycle makes it once, before any
/// file, where it was not there when it was listed and a file is to
/// arrive. A folder that is not there for a write has gone since: made
/// again by the write, it would hold only what is written from then on,
/// and the next cycle would read that as every other file deleted.
pub fn write_atomic(
    dir: &Path,
    name: &str,
    text: &str,
    flushed: &dyn Fn(),
    unchanged: &dyn Fn() -> bool,
) -> std::io::Result<bool> {
    let tmp = dir.join(temporary_name(name));
    // Made anew each time, so that it is never written through a link
    // that something has left under its name.
    let _ = std::fs::remove_file(&tmp);
    let mut made = std::fs::OpenOptions::new();
    made.write(true).create_new(true);
    let written = made
        .open(&tmp)
        .and_then(|mut file| {
            std::io::Write::write_all(&mut file, text.as_bytes())?;
            flush(&file)
        })
        .and_then(|()| {
            flushed();
            match unchanged() {
                true => std::fs::rename(&tmp, dir.join(name)).map(|()| true),
                false => Ok(false),
            }
        });
    match written {
        Ok(true) => flush_names(dir),
        // Not left behind where it could not be written whole, or did not
        // take the file's place.
        _ => {
            let _ = std::fs::remove_file(&tmp);
        }
    }
    written
}

/// Flush the names in a folder to the disk. The file is already in place,
/// so where this cannot be done there is nothing more to do.
fn flush_names(dir: &Path) {
    if let Err(error) = std::fs::File::open(dir).and_then(|dir| dir.sync_all()) {
        tracing::debug!(folder = %dir.display(), %error, "could not flush a folder's names");
    }
}

/// Flush a file's contents to the disk. A volume that has no flush (some
/// network volumes and some removable ones) is written as it was before a
/// flush was asked for.
pub(crate) fn flush(file: &std::fs::File) -> std::io::Result<()> {
    match file.sync_all() {
        Err(e) if has_no_flush(&e) => Ok(()),
        done => done,
    }
}

/// Whether a flush failed because the volume has none, as against a flush
/// that was tried and failed (a full disk, a fault of the disk).
fn has_no_flush(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{InvalidInput, Unsupported};
    // On a Mac a flush is a request of its own, which a volume without it
    // answers with one of two codes that have no kind of their own there:
    // ENOTSUP (45) and ENOTTY (25).
    let on_a_mac = cfg!(target_vendor = "apple") && matches!(e.raw_os_error(), Some(45 | 25));
    on_a_mac || matches!(e.kind(), InvalidInput | Unsupported)
}

/// The name of the temporary file that `name` is written through: hidden,
/// so that it is never read as a memory file, and short whatever the
/// length of `name`. A name may be as long as a file name can be, and a
/// temporary name made by adding to it would then be too long to create.
pub fn temporary_name(name: &str) -> String {
    let hash = cordelia_crypto::sha256(name.as_bytes());
    format!(".cordelia-tmp-{}", hex::encode(&hash[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flush that fails because the volume has none is no failure, and
    /// one that was tried and failed is.
    #[test]
    fn test_a_volume_with_no_flush_is_told_from_a_flush_that_failed() {
        let failed = std::io::Error::from_raw_os_error;
        // EINVAL, and whatever the system calls unsupported: no flush
        // here.
        assert!(has_no_flush(&failed(22)));
        assert!(has_no_flush(&std::io::Error::from(
            std::io::ErrorKind::Unsupported
        )));
        if cfg!(target_os = "linux") {
            // ENOSYS and EOPNOTSUPP.
            assert!(has_no_flush(&failed(38)));
            assert!(has_no_flush(&failed(95)));
        }
        // EIO, ENOSPC and EACCES: a flush that failed.
        assert!(!has_no_flush(&failed(5)));
        assert!(!has_no_flush(&failed(28)));
        assert!(!has_no_flush(&failed(13)));
        // ENOTSUP and ENOTTY as a Mac numbers them.
        if cfg!(target_vendor = "apple") {
            assert!(has_no_flush(&failed(45)));
            assert!(has_no_flush(&failed(25)));
        }
    }
}
