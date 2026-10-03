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
///
/// It is never longer than 255 bytes, which is as long as a file name can
/// usually be. Where the name is so long that the conflict name would be
/// longer, the name is cut short and marked with the start of its hash,
/// so that two long names that begin alike do not get one conflict name:
/// `<start of the name>-<8 hex digits>.conflict-<tag>.md`. Without this a
/// file with such a name could never have a version kept beside it, and
/// would be left out of sync from its first conflict on.
pub fn conflict_name(name: &str, tag: &str) -> String {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (name, None),
    };
    let ending = |ext: Option<&str>| match ext {
        Some(ext) => format!(".conflict-{tag}.{ext}"),
        None => format!(".conflict-{tag}"),
    };
    let end = ending(ext);
    if stem.len() + end.len() <= MAX_NAME_BYTES {
        return format!("{stem}{end}");
    }
    let hash = cordelia_crypto::sha256(name.as_bytes());
    let mark = format!("-{}", hex::encode(&hash[..4]));
    // The extension is kept where there is room for it. One that is itself
    // most of the name is not: the whole name is then cut.
    let (stem, end) = if end.len() + mark.len() < MAX_NAME_BYTES {
        (stem, end)
    } else {
        (name, ending(None))
    };
    let room = MAX_NAME_BYTES.saturating_sub(end.len() + mark.len());
    let mut cut = room.min(stem.len());
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{mark}{end}", &stem[..cut])
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

    /// A conflict name is a name a file can have, whatever the length of
    /// the name it is for.
    #[test]
    fn test_a_conflict_name_always_fits() {
        const TAG: &str = "3f9a0b1c";
        // The longest name whose conflict name fits as it is.
        let fits = format!("{}.md", "n".repeat(MAX_NAME_BYTES - 3 - 18));
        let whole = conflict_name(&fits, TAG);
        assert_eq!(whole.len(), MAX_NAME_BYTES);
        assert_eq!(
            whole,
            format!("{}.conflict-{TAG}.md", &fits[..fits.len() - 3])
        );

        // One byte longer: cut, and marked with the start of its hash.
        let long = format!("{}.md", "n".repeat(MAX_NAME_BYTES - 3 - 17));
        let cut = conflict_name(&long, TAG);
        assert_eq!(cut.len(), MAX_NAME_BYTES);
        let mark = format!(
            "-{}",
            hex::encode(&cordelia_crypto::sha256(long.as_bytes())[..4])
        );
        assert!(cut.ends_with(&format!("{mark}.conflict-{TAG}.md")), "{cut}");
        assert!(cut.starts_with("nnnn") && is_conflict_name(&cut) && is_safe_file_name(&cut));

        // The longest names there are, and the numbered conflict names
        // that are tried after the first.
        for ext in [".md", ""] {
            let name = format!("{}{ext}", "n".repeat(MAX_NAME_BYTES - ext.len()));
            for tag in [TAG.to_string(), format!("{TAG}-2"), format!("{TAG}-1000")] {
                let conflict = conflict_name(&name, &tag);
                assert!(conflict.len() <= MAX_NAME_BYTES, "{conflict}");
                assert!(is_conflict_name(&conflict), "{conflict}");
                assert!(is_safe_file_name(&conflict), "{conflict}");
                assert!(conflict.ends_with(&format!(".conflict-{tag}{ext}")));
            }
        }

        // Two long names that begin alike get two conflict names.
        let a = format!("{}a.md", "n".repeat(250));
        let b = format!("{}b.md", "n".repeat(250));
        assert_ne!(conflict_name(&a, TAG), conflict_name(&b, TAG));

        // The cut falls between characters, not inside one.
        let wide = format!("{}.md", "é".repeat(126));
        assert_eq!(wide.len(), MAX_NAME_BYTES);
        let conflict = conflict_name(&wide, TAG);
        assert!(conflict.len() <= MAX_NAME_BYTES && conflict.starts_with('é'));
        assert!(is_conflict_name(&conflict), "{conflict}");

        // An extension that is most of the name is cut with the rest.
        let all_ext = format!("a.{}", "x".repeat(MAX_NAME_BYTES - 2));
        let conflict = conflict_name(&all_ext, TAG);
        assert!(conflict.len() <= MAX_NAME_BYTES, "{conflict}");
        assert!(
            conflict.ends_with(&format!(".conflict-{TAG}")),
            "{conflict}"
        );
        assert!(conflict.starts_with("a.xxxx"), "{conflict}");
        assert!(is_conflict_name(&conflict) && is_safe_file_name(&conflict));
    }
}
