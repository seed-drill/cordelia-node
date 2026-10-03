//! Merging `MEMORY.md`, the index Claude Code keeps of its memory files.
//!
//! The index is a list of one-line pointers (`- [Title](file.md) — hook`),
//! so two devices' concurrent edits merge by taking the union of lines
//! rather than one side winning: the current version's lines in order, then
//! any lines only this device had, minus lines pointing at deleted files
//! (decision 2026-09-30-agent-memory-sync §4.5).

use std::collections::HashSet;

/// File name MEMORY.md merging applies to.
pub const INDEX_FILE: &str = "MEMORY.md";

/// The file a line links to (`...](file.md)...`), if any.
fn linked_file(line: &str) -> Option<&str> {
    let start = line.find("](")? + 2;
    let end = start + line[start..].find(')')?;
    let target = line[start..end].trim();
    (!target.is_empty() && !target.contains("://")).then_some(target)
}

/// Merge `ours` into `current`: every line of `current` in order, then each
/// line of `ours` not already present, dropping lines that link to a file
/// in `deleted`. Blank lines only survive from `current`.
pub fn merge(current: &str, ours: &str, deleted: &HashSet<String>) -> String {
    let keep = |line: &str| linked_file(line).is_none_or(|f| !deleted.contains(f));

    let mut out: Vec<&str> = current.lines().filter(|l| keep(l)).collect();
    let present: HashSet<&str> = current.lines().map(str::trim_end).collect();
    for line in ours.lines() {
        if !line.trim().is_empty() && !present.contains(line.trim_end()) && keep(line) {
            out.push(line);
        }
    }

    let mut merged = out.join("\n");
    if current.ends_with('\n') || ours.ends_with('\n') {
        merged.push('\n');
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn test_union_keeps_both_devices_pointers() {
        let current = "- [A](a.md) — from laptop\n- [B](b.md) — shared\n";
        let ours = "- [B](b.md) — shared\n- [C](c.md) — from desktop\n";
        assert_eq!(
            merge(current, ours, &none()),
            "- [A](a.md) — from laptop\n- [B](b.md) — shared\n- [C](c.md) — from desktop\n"
        );
    }

    #[test]
    fn test_drops_pointers_to_deleted_files() {
        let current = "- [A](a.md) — keep\n- [Gone](gone.md) — deleted\n";
        let ours = "- [Also gone](gone.md) — deleted too\n- [C](c.md) — new\n";
        let deleted: HashSet<String> = ["gone.md".to_string()].into();
        assert_eq!(
            merge(current, ours, &deleted),
            "- [A](a.md) — keep\n- [C](c.md) — new\n"
        );
    }

    #[test]
    fn test_merge_is_idempotent_and_ignores_trailing_space() {
        let current = "- [A](a.md) — x\n";
        let ours = "- [A](a.md) — x   \n";
        let once = merge(current, ours, &none());
        assert_eq!(once, current);
        assert_eq!(merge(&once, ours, &none()), once);
    }

    #[test]
    fn test_links_to_urls_are_not_files() {
        assert_eq!(linked_file("- [Site](https://seeddrill.ai) x"), None);
        assert_eq!(linked_file("- [Note](note.md) — hook"), Some("note.md"));
        assert_eq!(linked_file("plain line"), None);
    }
}
