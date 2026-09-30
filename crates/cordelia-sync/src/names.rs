//! Which keys may become file names, and how conflict files are named.
//!
//! Keys arrive from other devices and become file names inside an agent's
//! memory folder, so only plain file names are accepted: anything that
//! could name a path elsewhere, or a hidden file, is refused.

/// Longest file name accepted (common filesystem limit).
const MAX_NAME_BYTES: usize = 255;

/// Whether `name` is a plain file name that is safe to create in a memory
/// folder: no separators, no parent references, not hidden, no NUL.
pub fn is_safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && !name.starts_with('.')
        && !name.contains(['/', '\\', '\0'])
        && name != ".."
}

/// Name of the file holding this device's version of `name` after a
/// conflict: `notes.md` -> `notes.conflict-<tag>.md`.
pub fn conflict_name(name: &str, tag: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}.conflict-{tag}.{ext}"),
        _ => format!("{name}.conflict-{tag}"),
    }
}

/// Whether `name` is a conflict file made by [`conflict_name`]: the stem
/// ends in `.conflict-<tag>`, where the tag is 8 hex digits, optionally
/// followed by `-<n>` when an earlier conflict file was already taken.
pub fn is_conflict_name(name: &str) -> bool {
    let Some((_, rest)) = name.rsplit_once(".conflict-") else {
        return false;
    };
    let tag = rest.split_once('.').map_or(rest, |(tag, _ext)| tag);
    let (hex, n) = tag.split_once('-').unwrap_or((tag, ""));
    hex.len() == 8
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
        && (n.is_empty() || n.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_names_are_recognised() {
        for name in [
            conflict_name("notes.md", "3f9a0b1c"),
            conflict_name("a.b.md", "3f9a0b1c"),
            conflict_name("README", "3f9a0b1c"),
            conflict_name("notes.md", "3f9a0b1c-2"),
        ] {
            assert!(is_conflict_name(&name), "{name}");
        }
        for name in [
            "notes.md",
            "notes.conflict-.md",
            "notes.conflict-3f9a.md",
            "notes.conflict-3f9a0b1z.md",
            "notes.conflict-3f9a0b1c-x.md",
            "conflict-resolution.md",
        ] {
            assert!(!is_conflict_name(name), "{name}");
        }
    }

    #[test]
    fn test_safe_file_names() {
        for ok in [
            "MEMORY.md",
            "cordelia-seeddrill.md",
            "notes",
            "a.b.c",
            "émoji-🙂.md",
        ] {
            assert!(is_safe_file_name(ok), "{ok}");
        }
        for bad in [
            "",
            "..",
            ".hidden.md",
            "../escape.md",
            "sub/dir.md",
            "c:\\evil.md",
            "nul\0.md",
            &"x".repeat(256),
        ] {
            assert!(!is_safe_file_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn test_conflict_name() {
        assert_eq!(conflict_name("notes.md", "3f9a"), "notes.conflict-3f9a.md");
        assert_eq!(conflict_name("a.b.md", "3f9a"), "a.b.conflict-3f9a.md");
        assert_eq!(conflict_name("README", "3f9a"), "README.conflict-3f9a");
        assert!(is_safe_file_name(&conflict_name("notes.md", "3f9a")));
    }
}
