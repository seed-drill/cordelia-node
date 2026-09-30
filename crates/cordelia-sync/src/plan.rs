//! Deciding what to do with one file: a pure function of the local file,
//! the channel's current value, and what this folder last agreed with the
//! channel (decision 2026-09-30-agent-memory-sync §4.5).
//!
//! Rules, in order:
//!
//! - Only one side changed since the last agreement: take that side.
//! - Both changed to the same thing: just record it.
//! - Both changed differently: the channel's version (which other devices
//!   already have) goes in the file, and this device's version is kept
//!   beside it as a conflict file, which syncs like any other file. An edit
//!   beats a delete, whichever side made it. `MEMORY.md` is merged instead.
//! - This device lost a same-revision race (another device published the
//!   same revision concurrently and won): as above, our version becomes a
//!   conflict file, or is merged into `MEMORY.md`.
//!
//! Nothing is ever dropped silently: every losing edit ends up in a file.

use std::collections::HashSet;

use crate::memory_md;

/// A file's content and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub text: String,
    pub hash: [u8; 32],
}

impl Content {
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        let hash = cordelia_crypto::sha256(text.as_bytes());
        Self { text, hash }
    }
}

/// The channel's current value for a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub rev: u64,
    /// `None` when the key's current revision is a delete.
    pub content: Option<Content>,
}

/// What this folder and the channel last agreed on for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Agreed {
    /// Hash of the agreed content; `None` if the agreement was "deleted".
    pub hash: Option<[u8; 32]>,
    pub rev: u64,
}

/// What to do for one key. Applied in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Publish the local content as a new revision, then record it.
    Publish(String),
    /// Publish a delete, then record the key as deleted.
    PublishDelete,
    /// Write the channel's content to the file and record it at `rev`.
    Pull { text: String, rev: u64 },
    /// Remove the file and record the key as deleted at `rev`.
    RemoveFile { rev: u64 },
    /// Keep this device's version in a conflict file beside the original.
    SaveConflict(String),
    /// Write merged content to the file, publish it, and record it.
    Merge(String),
    /// Nothing to move; record that both sides agree on this state.
    Record(Agreed),
}

/// Plan one key. `deleted_files` lists keys deleted in the channel (used to
/// drop their pointers when merging `MEMORY.md`).
pub fn plan(
    key: &str,
    local: Option<&Content>,
    remote: Option<&Remote>,
    agreed: Option<&Agreed>,
    deleted_files: &HashSet<String>,
) -> Vec<Action> {
    let local_hash = local.map(|c| c.hash);
    let remote_hash = remote.and_then(|r| r.content.as_ref().map(|c| c.hash));

    let local_changed = match agreed {
        None => local.is_some(),
        Some(a) => local_hash != a.hash,
    };
    let remote_changed = match (remote, agreed) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(r), Some(a)) => r.rev > a.rev || (r.rev == a.rev && remote_hash != a.hash),
    };
    let is_index = key == memory_md::INDEX_FILE;

    match (local_changed, remote_changed) {
        (false, false) => vec![],

        (true, false) => match local {
            Some(c) => vec![Action::Publish(c.text.clone())],
            // Deleted here; tell the channel unless it has nothing live.
            None => match remote {
                Some(r) if r.content.is_some() => vec![Action::PublishDelete],
                Some(r) => vec![Action::Record(Agreed {
                    hash: None,
                    rev: r.rev,
                })],
                None => vec![],
            },
        },

        (false, true) => {
            let r = remote.expect("remote_changed implies remote");
            // Same revision as ours but different content: another device
            // won a concurrent publish. Keep our version before pulling.
            let lost_race = agreed.is_some_and(|a| a.rev == r.rev) && local.is_some();
            match &r.content {
                None => {
                    if local.is_some() {
                        vec![Action::RemoveFile { rev: r.rev }]
                    } else {
                        vec![Action::Record(Agreed {
                            hash: None,
                            rev: r.rev,
                        })]
                    }
                }
                Some(c) if lost_race && is_index => {
                    let ours = &local.expect("lost_race implies local").text;
                    vec![Action::Merge(memory_md::merge(
                        &c.text,
                        ours,
                        deleted_files,
                    ))]
                }
                Some(c) if lost_race => vec![
                    Action::SaveConflict(local.expect("lost_race implies local").text.clone()),
                    Action::Pull {
                        text: c.text.clone(),
                        rev: r.rev,
                    },
                ],
                Some(c) => vec![Action::Pull {
                    text: c.text.clone(),
                    rev: r.rev,
                }],
            }
        }

        (true, true) => {
            let r = remote.expect("remote_changed implies remote");
            match (local, &r.content) {
                // Converged independently.
                (l, rc) if l.map(|c| c.hash) == rc.as_ref().map(|c| c.hash) => {
                    vec![Action::Record(Agreed {
                        hash: local_hash,
                        rev: r.rev,
                    })]
                }
                // Deleted here, edited there: the edit wins.
                (None, Some(c)) => vec![Action::Pull {
                    text: c.text.clone(),
                    rev: r.rev,
                }],
                // Edited here, deleted there: the edit wins (revives the key).
                (Some(l), None) => vec![Action::Publish(l.text.clone())],
                (Some(l), Some(c)) if is_index => {
                    vec![Action::Merge(memory_md::merge(
                        &c.text,
                        &l.text,
                        deleted_files,
                    ))]
                }
                (Some(l), Some(c)) => vec![
                    Action::SaveConflict(l.text.clone()),
                    Action::Pull {
                        text: c.text.clone(),
                        rev: r.rev,
                    },
                ],
                (None, None) => vec![Action::Record(Agreed {
                    hash: None,
                    rev: r.rev,
                })],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(t: &str) -> Content {
        Content::new(t)
    }
    fn live(rev: u64, t: &str) -> Remote {
        Remote {
            rev,
            content: Some(c(t)),
        }
    }
    fn gone(rev: u64) -> Remote {
        Remote { rev, content: None }
    }
    fn agreed(rev: u64, t: &str) -> Agreed {
        Agreed {
            hash: Some(c(t).hash),
            rev,
        }
    }
    fn none() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn nothing_changed() {
        let a = agreed(2, "x");
        assert!(
            plan(
                "n.md",
                Some(&c("x")),
                Some(&live(2, "x")),
                Some(&a),
                &none()
            )
            .is_empty()
        );
        assert!(plan("n.md", None, None, None, &none()).is_empty());
    }

    #[test]
    fn new_local_file_is_published() {
        assert_eq!(
            plan("n.md", Some(&c("hello")), None, None, &none()),
            vec![Action::Publish("hello".into())]
        );
    }

    #[test]
    fn local_edit_is_published() {
        let a = agreed(1, "v1");
        assert_eq!(
            plan(
                "n.md",
                Some(&c("v2")),
                Some(&live(1, "v1")),
                Some(&a),
                &none()
            ),
            vec![Action::Publish("v2".into())]
        );
    }

    #[test]
    fn local_delete_is_published() {
        let a = agreed(1, "v1");
        assert_eq!(
            plan("n.md", None, Some(&live(1, "v1")), Some(&a), &none()),
            vec![Action::PublishDelete]
        );
    }

    #[test]
    fn new_remote_file_is_pulled() {
        assert_eq!(
            plan("n.md", None, Some(&live(1, "from mac")), None, &none()),
            vec![Action::Pull {
                text: "from mac".into(),
                rev: 1
            }]
        );
    }

    #[test]
    fn remote_edit_is_pulled() {
        let a = agreed(1, "v1");
        assert_eq!(
            plan(
                "n.md",
                Some(&c("v1")),
                Some(&live(2, "v2")),
                Some(&a),
                &none()
            ),
            vec![Action::Pull {
                text: "v2".into(),
                rev: 2
            }]
        );
    }

    #[test]
    fn remote_delete_removes_the_file() {
        let a = agreed(1, "v1");
        assert_eq!(
            plan("n.md", Some(&c("v1")), Some(&gone(2)), Some(&a), &none()),
            vec![Action::RemoveFile { rev: 2 }]
        );
    }

    #[test]
    fn same_file_created_on_both_sides_just_records() {
        assert_eq!(
            plan(
                "n.md",
                Some(&c("same")),
                Some(&live(1, "same")),
                None,
                &none()
            ),
            vec![Action::Record(Agreed {
                hash: Some(c("same").hash),
                rev: 1
            })]
        );
    }

    #[test]
    fn concurrent_edits_keep_both() {
        let a = agreed(1, "base");
        assert_eq!(
            plan(
                "n.md",
                Some(&c("mine")),
                Some(&live(2, "theirs")),
                Some(&a),
                &none()
            ),
            vec![
                Action::SaveConflict("mine".into()),
                Action::Pull {
                    text: "theirs".into(),
                    rev: 2
                },
            ]
        );
    }

    #[test]
    fn edit_beats_delete_either_way() {
        let a = agreed(1, "base");
        // Deleted here, edited there.
        assert_eq!(
            plan("n.md", None, Some(&live(2, "edited")), Some(&a), &none()),
            vec![Action::Pull {
                text: "edited".into(),
                rev: 2
            }]
        );
        // Edited here, deleted there.
        assert_eq!(
            plan(
                "n.md",
                Some(&c("edited")),
                Some(&gone(2)),
                Some(&a),
                &none()
            ),
            vec![Action::Publish("edited".into())]
        );
    }

    #[test]
    fn losing_a_same_revision_race_keeps_our_version() {
        // We published "mine" at rev 2; another device published "theirs"
        // at rev 2 too, and won the tie.
        let a = agreed(2, "mine");
        assert_eq!(
            plan(
                "n.md",
                Some(&c("mine")),
                Some(&live(2, "theirs")),
                Some(&a),
                &none()
            ),
            vec![
                Action::SaveConflict("mine".into()),
                Action::Pull {
                    text: "theirs".into(),
                    rev: 2
                },
            ]
        );
    }

    #[test]
    fn index_is_merged_not_conflicted() {
        let a = agreed(1, "- [A](a.md) x\n");
        let merged = plan(
            memory_md::INDEX_FILE,
            Some(&c("- [A](a.md) x\n- [B](b.md) mine\n")),
            Some(&live(2, "- [A](a.md) x\n- [C](c.md) theirs\n")),
            Some(&a),
            &none(),
        );
        assert_eq!(
            merged,
            vec![Action::Merge(
                "- [A](a.md) x\n- [C](c.md) theirs\n- [B](b.md) mine\n".into()
            )]
        );

        // Same for a lost same-revision race on the index.
        let raced = agreed(2, "- [B](b.md) mine\n");
        assert_eq!(
            plan(
                memory_md::INDEX_FILE,
                Some(&c("- [B](b.md) mine\n")),
                Some(&live(2, "- [C](c.md) theirs\n")),
                Some(&raced),
                &none(),
            ),
            vec![Action::Merge(
                "- [C](c.md) theirs\n- [B](b.md) mine\n".into()
            )]
        );
    }

    #[test]
    fn deleted_on_both_sides_records() {
        let a = agreed(1, "v1");
        assert_eq!(
            plan("n.md", None, Some(&gone(2)), Some(&a), &none()),
            vec![Action::Record(Agreed { hash: None, rev: 2 })]
        );
    }
}
