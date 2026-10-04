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
//!   beats a delete, whichever side made it. `MEMORY.md` is merged instead;
//!   where the merge is the channel's version as it stands, the file takes
//!   that and nothing is published.
//! - The channel's version does not follow from what this folder agreed:
//!   treated as both having changed, so this device's version is kept as
//!   above. That is so when
//!   - another device published the same revision concurrently and won; or
//!   - the channel has gone back to an earlier entry, at a lower revision
//!     or the same one, because the entry that was agreed no longer
//!     counts: the device that wrote it was removed, and nothing replaced
//!     what it wrote; or its writer has written again, in an entry this
//!     device cannot read yet (decision 2026-09-30 §9).
//! - The channel's version is at a higher revision, and is not known to
//!   have been written after the entry this folder agreed
//!   ([`known_to_follow`]): the file takes it, or goes if it is a delete,
//!   exactly as it would if it were known, and what the file held is kept
//!   first as a conflict file. That is all the difference it makes, for
//!   every file, `MEMORY.md` included: nothing is merged or published that
//!   would not be otherwise.
//! - Only the channel's revision moved, not its content (an entry is
//!   published again when the device that wrote it is removed), or only
//!   what a record says of its writer: note it, and touch nothing.
//!
//! Every losing edit is meant to end up in a file. Where it does not is in
//! decision 2026-09-30 §9: a version that says nothing of what it was
//! written after is taken by its revision, whoever wrote it and whatever
//! they had seen.

use std::collections::HashSet;

pub use cordelia_storage::sync_state::Writer;

use crate::after::After;
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
    /// The device that wrote it.
    pub author: [u8; 32],
    /// What it says it was written after; `None` if it says nothing.
    pub after: Option<After>,
}

impl Remote {
    /// What a record of this version says of its writer: the device that
    /// wrote it, where it says what it was written after, and nobody where
    /// it says nothing. Only a sync adapter writes an entry that says
    /// something, for a file of its folder. One that says nothing need
    /// never have been in its writer's folder (it is published again by
    /// the node when a device is removed, or written through the API), so
    /// nothing is rested on who wrote it.
    pub fn writer(&self) -> Writer {
        match self.after {
            Some(_) => Writer::Device(self.author),
            None => Writer::Nobody,
        }
    }
}

/// What this folder and the channel last agreed on for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Agreed {
    /// Hash of the agreed content; `None` if the agreement was "deleted".
    pub hash: Option<[u8; 32]>,
    pub rev: u64,
    /// Who wrote the agreed entry, as far as anything is rested on it
    /// ([`Remote::writer`]). Not recorded in a row from before this was
    /// kept.
    pub writer: Writer,
}

/// What to do for one key. Applied in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Publish the local content as a new revision, then record it.
    Publish(String),
    /// Publish a delete, then record the key as deleted.
    PublishDelete,
    /// Write the channel's content to the file and record it at `rev`, as
    /// written by `writer`.
    Pull {
        text: String,
        rev: u64,
        writer: Writer,
    },
    /// Remove the file and record the key as deleted at `rev`, by `writer`.
    RemoveFile { rev: u64, writer: Writer },
    /// Keep this device's version in a conflict file beside the original.
    SaveConflict(String),
    /// Write merged content to the file, publish it, and record it.
    Merge(String),
    /// Nothing to move; record that both sides agree on this state.
    Record(Agreed),
}

/// Whether the channel's version `r`, at a higher revision than the one
/// this folder agreed (`a`), is known to have been written after the
/// agreed entry: by a device that had that entry, or one written after it,
/// in front of it.
///
/// A higher revision alone does not show that (see [`crate::after`]). It
/// is known where
///
/// 1. `r` says nothing of what it was written after: nothing can be
///    known, and the revision decides as it did before entries said
///    anything;
/// 2. the record is from before the writer was kept: the same;
/// 3. the record names a device, and that device wrote `r`;
/// 4. the record names a device, and `r` names it at the agreed revision
///    or a higher one;
/// 5. the agreed revision is below the one under which `r` leaves
///    everything to its revision, or is that revision and the record
///    names nobody; or
/// 6. `r` was published over an entry with the agreed text at the agreed
///    revision (the agreed entry, or one that tied with it): the hash is
///    the agreed text's, and the agreed revision is the highest `r` names.
///
/// 3 and 4 rest on a device's later entries descending from its earlier
/// ones. So they are used only where the record names a device: where the
/// agreed entry said what it was written after ([`Remote::writer`]).
///
/// 5: `below` is the revision of an entry in the history of `r` that said
/// nothing. An agreed entry at that revision that said nothing is that
/// entry, or one that tied with it, and between entries that say nothing
/// the revision decides. One that said something is another entry than
/// the one in the history of `r`, which has one entry at a revision.
///
/// A wrong "not known" costs a conflict file that was not needed, and
/// nothing else: the file takes the channel's version either way.
pub fn known_to_follow(r: &Remote, a: &Agreed) -> bool {
    let Some(after) = &r.after else {
        return true;
    };
    let named = match a.writer {
        Writer::NotRecorded => return true,
        Writer::Nobody => None,
        Writer::Device(writer) => Some(writer),
    };
    named.is_some_and(|writer| {
        r.author == writer || after.of.get(&writer).is_some_and(|at| *at >= a.rev)
    }) || after
        .below
        .is_some_and(|below| a.rev < below || (a.rev == below && named.is_none()))
        || (a.hash.is_some() && after.over == a.hash && after.of.values().max() == Some(&a.rev))
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
    // The channel has changed when its content differs from what was
    // agreed, at whatever revision.
    let remote_changed = match (remote, agreed) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(_), Some(a)) => remote_hash != a.hash,
    };
    // Its version follows from what was agreed only at a higher revision.
    let follows = match (remote, agreed) {
        (Some(r), Some(a)) => r.rev > a.rev,
        _ => true,
    };
    // And it is taken without keeping what the file holds only where it
    // is also known to have been written after the agreed entry.
    let known = match (remote, agreed) {
        (Some(r), Some(a)) => known_to_follow(r, a),
        _ => true,
    };
    let is_index = key == memory_md::INDEX_FILE;
    // The record of the channel's version `r`, with `hash` in the file.
    let agreed_with = |r: &Remote, hash: Option<[u8; 32]>| Agreed {
        hash,
        rev: r.rev,
        writer: r.writer(),
    };
    let pull = |r: &Remote, c: &Content| Action::Pull {
        text: c.text.clone(),
        rev: r.rev,
        writer: r.writer(),
    };
    // The index: the channel's version `c`, with this device's lines.
    // Where the channel's version already has them all, the merge is that
    // version, and the file takes it as any file would: there is nothing
    // to publish. (Published all the same, a merge that could not then be
    // written to the file would be published again every cycle.)
    let merged = |r: &Remote, c: &Content, l: &Content| {
        let text = memory_md::merge(&c.text, &l.text, deleted_files);
        if text == c.text {
            pull(r, c)
        } else {
            Action::Merge(text)
        }
    };

    match (local_changed, remote_changed) {
        // Nothing to move. If the channel's revision moved all the same,
        // note where it is now; and if the record does not say of the
        // writer what the channel's version gives (two devices published
        // one text at one revision, or the entry was published again
        // saying nothing, or nothing was recorded), note that.
        (false, false) => match (remote, agreed) {
            (Some(r), Some(a)) if r.rev != a.rev || a.writer != r.writer() => {
                vec![Action::Record(agreed_with(r, a.hash))]
            }
            _ => vec![],
        },

        (true, false) => match local {
            Some(c) => vec![Action::Publish(c.text.clone())],
            // Deleted here; tell the channel unless it has nothing live.
            None => match remote {
                Some(r) if r.content.is_some() => vec![Action::PublishDelete],
                Some(r) => vec![Action::Record(agreed_with(r, None))],
                None => vec![],
            },
        },

        (false, true) => {
            let r = remote.expect("remote_changed implies remote");
            let remove = Action::RemoveFile {
                rev: r.rev,
                writer: r.writer(),
            };
            match (&r.content, local) {
                (None, None) => vec![Action::Record(agreed_with(r, None))],
                (None, Some(_)) if follows && known => vec![remove],
                // A delete at a higher revision, not known to have been
                // made with this version in sight: the file goes, as it
                // would anyway, and what it held is kept first.
                (None, Some(l)) if follows => vec![Action::SaveConflict(l.text.clone()), remove],
                // A delete that does not follow from this device's version
                // was made without seeing it: the edit wins.
                (None, Some(l)) => vec![Action::Publish(l.text.clone())],
                (Some(c), None) => vec![pull(r, c)],
                (Some(c), Some(_)) if follows && known => vec![pull(r, c)],
                // Content that does not follow from this device's version:
                // keep ours before taking the channel's.
                (Some(c), Some(l)) if is_index && !follows => vec![merged(r, c, l)],
                // The same for content at a higher revision that is not
                // known to follow, the index included: it is taken, as it
                // would be anyway, and what the file held is kept first.
                (Some(c), Some(l)) => vec![Action::SaveConflict(l.text.clone()), pull(r, c)],
            }
        }

        (true, true) => {
            let r = remote.expect("remote_changed implies remote");
            match (local, &r.content) {
                // Converged independently.
                (l, rc) if l.map(|c| c.hash) == rc.as_ref().map(|c| c.hash) => {
                    vec![Action::Record(agreed_with(r, local_hash))]
                }
                // Deleted here, edited there: the edit wins.
                (None, Some(c)) => vec![pull(r, c)],
                // Edited here, deleted there: the edit wins (revives the key).
                (Some(l), None) => vec![Action::Publish(l.text.clone())],
                (Some(l), Some(c)) if is_index => vec![merged(r, c, l)],
                (Some(l), Some(c)) => vec![Action::SaveConflict(l.text.clone()), pull(r, c)],
                (None, None) => vec![Action::Record(agreed_with(r, None))],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This device, another, and a third.
    const ME: [u8; 32] = [1; 32];
    const THEM: [u8; 32] = [9; 32];
    const THIRD: [u8; 32] = [5; 32];

    fn c(t: &str) -> Content {
        Content::new(t)
    }
    /// A version by `THEM` that says nothing of what it was written after.
    fn live(rev: u64, t: &str) -> Remote {
        Remote {
            rev,
            content: Some(c(t)),
            author: THEM,
            after: None,
        }
    }
    fn gone(rev: u64) -> Remote {
        Remote {
            rev,
            content: None,
            author: THEM,
            after: None,
        }
    }
    /// A record that says `by` of the agreed entry's writer.
    fn agreed_by(by: Writer, rev: u64, t: &str) -> Agreed {
        Agreed {
            hash: Some(c(t).hash),
            rev,
            writer: by,
        }
    }
    /// A record of an entry that said nothing of what it was written
    /// after, as [`live`] and [`gone`] do: nobody is its writer.
    fn agreed(rev: u64, t: &str) -> Agreed {
        agreed_by(Writer::Nobody, rev, t)
    }
    /// What is recorded of a version that says nothing.
    fn recorded(hash: Option<[u8; 32]>, rev: u64) -> Action {
        Action::Record(Agreed {
            hash,
            rev,
            writer: Writer::Nobody,
        })
    }
    /// The file takes a version that says nothing.
    fn pull(text: &str, rev: u64) -> Action {
        Action::Pull {
            text: text.into(),
            rev,
            writer: Writer::Nobody,
        }
    }
    /// The file takes a version that says something, written by `by`.
    fn pull_of(text: &str, rev: u64, by: [u8; 32]) -> Action {
        Action::Pull {
            text: text.into(),
            rev,
            writer: Writer::Device(by),
        }
    }
    fn remove(rev: u64) -> Action {
        Action::RemoveFile {
            rev,
            writer: Writer::Nobody,
        }
    }
    fn remove_of(rev: u64, by: [u8; 32]) -> Action {
        Action::RemoveFile {
            rev,
            writer: Writer::Device(by),
        }
    }
    fn keep(text: &str) -> Action {
        Action::SaveConflict(text.into())
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
            vec![pull("from mac", 1)]
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
            vec![pull("v2", 2)]
        );
    }

    #[test]
    fn remote_delete_removes_the_file() {
        let a = agreed(1, "v1");
        assert_eq!(
            plan("n.md", Some(&c("v1")), Some(&gone(2)), Some(&a), &none()),
            vec![remove(2)]
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
            vec![recorded(Some(c("same").hash), 1)]
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
            vec![keep("mine"), pull("theirs", 2)]
        );
    }

    #[test]
    fn edit_beats_delete_either_way() {
        let a = agreed(1, "base");
        // Deleted here, edited there.
        assert_eq!(
            plan("n.md", None, Some(&live(2, "edited")), Some(&a), &none()),
            vec![pull("edited", 2)]
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
        let a = agreed_by(Writer::Device(ME), 2, "mine");
        assert_eq!(
            plan(
                "n.md",
                Some(&c("mine")),
                Some(&live(2, "theirs")),
                Some(&a),
                &none()
            ),
            vec![keep("mine"), pull("theirs", 2)]
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
        let raced = agreed_by(Writer::Device(ME), 2, "- [B](b.md) mine\n");
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

    /// The merged index is the channel's version as it stands where that
    /// version has every line this device has. The file then takes it, and
    /// nothing is published: where both changed, and at a lost race.
    #[test]
    fn an_index_the_channel_already_has_whole_is_pulled() {
        let theirs = "- [A](a.md) x\n- [B](b.md) mine\n- [C](c.md) theirs\n";
        let taken = vec![pull(theirs, 2)];
        let a = agreed(1, "- [A](a.md) x\n");
        let mine = c("- [A](a.md) x\n- [B](b.md) mine\n");
        let index = memory_md::INDEX_FILE;
        assert_eq!(
            plan(
                index,
                Some(&mine),
                Some(&live(2, theirs)),
                Some(&a),
                &none()
            ),
            taken
        );
        let raced = agreed_by(Writer::Device(ME), 2, "- [B](b.md) mine\n");
        assert_eq!(
            plan(
                index,
                Some(&c("- [B](b.md) mine\n")),
                Some(&live(2, theirs)),
                Some(&raced),
                &none()
            ),
            taken
        );
        // A line of the channel's that points at a deleted file is dropped
        // by the merge. The merge is then not the channel's version, and
        // is published.
        let deleted: HashSet<String> = ["c.md".to_string()].into();
        assert_eq!(
            plan(
                index,
                Some(&mine),
                Some(&live(2, theirs)),
                Some(&a),
                &deleted
            ),
            vec![Action::Merge("- [A](a.md) x\n- [B](b.md) mine\n".into())]
        );
    }

    #[test]
    fn a_revision_that_moves_without_new_content_is_only_noted() {
        // An entry is published again, with the same content, when the
        // device that wrote it is removed. Nothing is written to the file.
        let a = agreed(2, "x");
        for rev in [5, 1] {
            assert_eq!(
                plan(
                    "n.md",
                    Some(&c("x")),
                    Some(&live(rev, "x")),
                    Some(&a),
                    &none()
                ),
                vec![recorded(Some(c("x").hash), rev)]
            );
        }
        // Deleted, and the delete published again.
        let deleted = Agreed {
            hash: None,
            rev: 2,
            writer: Writer::Nobody,
        };
        assert_eq!(
            plan("n.md", None, Some(&gone(5)), Some(&deleted), &none()),
            vec![recorded(None, 5)]
        );
        // An edit made here on top of that content is a plain edit.
        assert_eq!(
            plan(
                "n.md",
                Some(&c("y")),
                Some(&live(5, "x")),
                Some(&a),
                &none()
            ),
            vec![Action::Publish("y".into())]
        );
    }

    #[test]
    fn a_channel_that_has_gone_back_keeps_this_devices_version() {
        // This folder agreed revision 9, written by a device that has since
        // been removed. Its entry no longer counts, and nothing replaced
        // it, so the channel shows an older revision again.
        let a = agreed_by(Writer::Device(THIRD), 9, "last");
        assert_eq!(
            plan(
                "n.md",
                Some(&c("last")),
                Some(&live(4, "older")),
                Some(&a),
                &none()
            ),
            vec![keep("last"), pull("older", 4)]
        );
        // The index is merged.
        let a = agreed_by(
            Writer::Device(THIRD),
            9,
            "- [A](a.md) x\n- [B](b.md) last\n",
        );
        assert_eq!(
            plan(
                memory_md::INDEX_FILE,
                Some(&c("- [A](a.md) x\n- [B](b.md) last\n")),
                Some(&live(4, "- [A](a.md) x\n")),
                Some(&a),
                &none()
            ),
            vec![Action::Merge("- [A](a.md) x\n- [B](b.md) last\n".into())]
        );
        // The older revision is a delete: the file stays, and is published.
        let a = agreed_by(Writer::Device(THIRD), 9, "last");
        assert_eq!(
            plan("n.md", Some(&c("last")), Some(&gone(4)), Some(&a), &none()),
            vec![Action::Publish("last".into())]
        );
        // This folder agreed a delete, and the channel shows the file again:
        // an edit beats a delete, so it comes back.
        let deleted = Agreed {
            hash: None,
            rev: 9,
            writer: Writer::Device(THIRD),
        };
        assert_eq!(
            plan(
                "n.md",
                None,
                Some(&live(4, "older")),
                Some(&deleted),
                &none()
            ),
            vec![pull("older", 4)]
        );
    }

    #[test]
    fn losing_a_same_revision_race_to_a_delete_keeps_the_edit() {
        // We published "mine" at rev 2; another device published a delete
        // at rev 2 and won the tie. An edit beats a delete.
        let a = agreed_by(Writer::Device(ME), 2, "mine");
        assert_eq!(
            plan("n.md", Some(&c("mine")), Some(&gone(2)), Some(&a), &none()),
            vec![Action::Publish("mine".into())]
        );
    }

    #[test]
    fn deleted_on_both_sides_records() {
        let a = agreed(1, "v1");
        assert_eq!(
            plan("n.md", None, Some(&gone(2)), Some(&a), &none()),
            vec![recorded(None, 2)]
        );
    }

    /// A version by `THEM` that says what it was written after, and shows
    /// nothing about an entry `ME` wrote at revision 4 with the text
    /// "mine": it names another device, at another revision; it was
    /// published over another text; and it leaves to their revisions only
    /// entries below that one.
    fn says(rev: u64, content: Option<&str>) -> Remote {
        Remote {
            rev,
            content: content.map(c),
            author: THEM,
            after: Some(After {
                of: [(THIRD, 5)].into_iter().collect(),
                over: Some(c("another text").hash),
                below: Some(3),
            }),
        }
    }

    /// #79. A file that is unchanged here, and a version of it in the
    /// channel at a higher revision whose writer is not known to have had
    /// this folder's version in front of it. The file takes that version,
    /// or goes, exactly as it would if it were known. What the file held
    /// is kept first.
    #[test]
    fn a_higher_revision_not_known_to_follow_is_taken_and_what_was_held_is_kept() {
        let a = agreed_by(Writer::Device(ME), 4, "mine");
        let local = c("mine");
        let planned = |key: &str, r: &Remote| plan(key, Some(&local), Some(r), Some(&a), &none());

        // Another text.
        assert_eq!(
            planned("n.md", &says(6, Some("theirs"))),
            vec![keep("mine"), pull_of("theirs", 6, THEM)]
        );
        // A delete: the file goes, and its text is kept. It is not
        // published again, as it is at a tie.
        assert_eq!(
            planned("n.md", &says(6, None)),
            vec![keep("mine"), remove_of(6, THEM)]
        );
        // The index is a file like any other here: it is not merged.
        assert_eq!(
            planned(memory_md::INDEX_FILE, &says(6, Some("theirs"))),
            vec![keep("mine"), pull_of("theirs", 6, THEM)]
        );

        // A version that says nothing is taken by its revision, as it was
        // before any said anything.
        assert_eq!(planned("n.md", &live(6, "theirs")), vec![pull("theirs", 6)]);
        assert_eq!(planned("n.md", &gone(6)), vec![remove(6)]);
    }

    /// Each reason a version is known to follow, alone: the version of
    /// [`says`], which shows nothing, with one thing changed. And each
    /// reason against a record that names nobody, and one from before.
    #[test]
    fn each_reason_a_version_is_known_to_follow_by() {
        let mine = agreed_by(Writer::Device(ME), 4, "mine");
        let nobodys = agreed_by(Writer::Nobody, 4, "mine");
        let before = agreed_by(Writer::NotRecorded, 4, "mine");
        let local = c("mine");
        let kept = vec![keep("mine"), pull_of("theirs", 6, THEM)];
        let taken = vec![pull_of("theirs", 6, THEM)];
        let planned =
            |r: &Remote, a: &Agreed| plan("n.md", Some(&local), Some(r), Some(a), &none());
        let base = says(6, Some("theirs"));
        let with = |change: &dyn Fn(&mut After)| {
            let mut r = base.clone();
            change(r.after.as_mut().unwrap());
            r
        };
        assert_eq!(planned(&base, &mine), kept);

        // 1. It says nothing.
        let silent = Remote {
            after: None,
            ..base.clone()
        };
        for record in [&mine, &nobodys, &before] {
            assert_eq!(planned(&silent, record), vec![pull("theirs", 6)]);
        }

        // 2. The record is from before the writer was kept. One that names
        // nobody is not such a record.
        assert_eq!(planned(&base, &before), taken);
        assert_eq!(planned(&base, &nobodys), kept);

        // 3. The device that wrote it wrote the agreed entry too. (It does
        // not name itself, and need not.) Where the record names nobody,
        // the same device having written both shows nothing: the agreed
        // entry need never have been in its folder.
        let own = Remote {
            author: ME,
            ..base.clone()
        };
        assert_eq!(planned(&own, &mine), vec![pull_of("theirs", 6, ME)]);
        assert_eq!(
            planned(&own, &nobodys),
            vec![keep("mine"), pull_of("theirs", 6, ME)]
        );

        // 4. It names the writer of the agreed entry, at the agreed
        // revision or higher. One below is an earlier entry of that
        // writer's, and shows nothing about this one. A record that names
        // nobody has no writer to be named.
        let named = |at: u64| {
            with(&|after| {
                after.of.insert(ME, at);
            })
        };
        assert_eq!(planned(&named(3), &mine), kept);
        assert_eq!(planned(&named(4), &mine), taken);
        assert_eq!(planned(&named(5), &mine), taken);
        assert_eq!(planned(&named(4), &nobodys), kept);
        assert_eq!(planned(&named(5), &nobodys), kept);

        // 5. The agreed revision is below the one under which everything
        // is left to its revision. At that revision itself, only an agreed
        // entry that said nothing is the one in this version's history,
        // or one that tied with it: a record that names a device is of
        // another entry.
        let below = |at: u64| with(&|after| after.below = Some(at));
        assert_eq!(planned(&below(3), &mine), kept);
        assert_eq!(planned(&below(4), &mine), kept);
        assert_eq!(planned(&below(5), &mine), taken);
        assert_eq!(planned(&below(3), &nobodys), kept);
        assert_eq!(planned(&below(4), &nobodys), taken);
        assert_eq!(planned(&below(5), &nobodys), taken);

        // 6. It was published over an entry with the agreed text at the
        // agreed revision: the hash is the agreed text's, and the highest
        // revision it names is the agreed one. The same text at another
        // revision is another entry, written before or after the one that
        // was agreed. It holds whatever the record says of the writer.
        let over = |highest: u64| {
            with(&|after| {
                after.over = Some(c("mine").hash);
                after.of = [(THIRD, highest)].into_iter().collect();
            })
        };
        for record in [&mine, &nobodys] {
            assert_eq!(planned(&over(3), record), kept);
            assert_eq!(planned(&over(4), record), taken);
            assert_eq!(planned(&over(5), record), kept);
        }
        // The agreed revision named, over another text: nothing.
        let other_text = with(&|after| after.of = [(THIRD, 4)].into_iter().collect());
        assert_eq!(planned(&other_text, &mine), kept);

        // The same for a delete: known, the file goes and nothing is kept.
        let delete = Remote {
            content: None,
            ..named(4)
        };
        assert_eq!(planned(&delete, &mine), vec![remove_of(6, THEM)]);

        // An agreed delete has no text for a version to have been
        // published over. A version over a delete names no text either,
        // and the two are not taken for the same.
        let deleted = Agreed {
            hash: None,
            rev: 4,
            writer: Writer::Device(ME),
        };
        let over_a_delete = with(&|after| {
            after.over = None;
            after.of = [(THIRD, 4)].into_iter().collect();
        });
        assert!(!known_to_follow(&over_a_delete, &deleted));
        assert!(known_to_follow(&over(4), &mine));
    }

    /// An entry published again when its writer is removed is written by
    /// the node, from what it holds, under the key of the device that
    /// removes, and says nothing. A folder that holds its text as agreed
    /// then records nobody as its writer. So what that device writes
    /// later, from a folder that need never have held the text, is not
    /// taken to follow it for having the same writer: the text is kept.
    #[test]
    fn what_the_publisher_of_an_entry_published_again_writes_later_does_not_follow_it() {
        let mine = agreed_by(Writer::Device(ME), 4, "mine");
        let local = c("mine");
        // The same text at the same revision, by another device, saying
        // nothing: nothing moves, and the record names nobody.
        let again = Remote {
            rev: 4,
            content: Some(c("mine")),
            author: THEM,
            after: None,
        };
        let noted = agreed_by(Writer::Nobody, 4, "mine");
        assert_eq!(
            plan("n.md", Some(&local), Some(&again), Some(&mine), &none()),
            vec![Action::Record(noted)]
        );
        // A later entry by that device, which names itself and not the
        // first writer.
        let later = Remote {
            rev: 6,
            content: Some(c("theirs")),
            author: THEM,
            after: Some(After {
                of: [(THEM, 5)].into_iter().collect(),
                over: Some(c("another text").hash),
                below: None,
            }),
        };
        assert_eq!(
            plan("n.md", Some(&local), Some(&later), Some(&noted), &none()),
            vec![keep("mine"), pull_of("theirs", 6, THEM)]
        );
        // Had the record named that device, as it would for an entry that
        // said something, the same entry would have been taken.
        let named = agreed_by(Writer::Device(THEM), 4, "mine");
        assert_eq!(
            plan("n.md", Some(&local), Some(&later), Some(&named), &none()),
            vec![pull_of("theirs", 6, THEM)]
        );
    }

    /// What a version says can only make this device keep more. At the
    /// agreed revision, or below it, a version does not follow whatever
    /// it says and whoever wrote it, and is handled as it was before:
    /// both kept, the index merged, an edit over a delete.
    #[test]
    fn at_an_equal_or_a_lower_revision_nothing_a_version_says_is_used() {
        let mine = agreed_by(Writer::Device(ME), 4, "mine");
        let local = c("mine");
        // It says everything that would make a higher revision known, and
        // is by the device that wrote the agreed entry besides.
        let says_all = |rev: u64, content: Option<&str>, by: [u8; 32]| Remote {
            rev,
            content: content.map(c),
            author: by,
            after: Some(After {
                of: [(ME, 4)].into_iter().collect(),
                over: Some(c("mine").hash),
                below: Some(9),
            }),
        };
        let planned =
            |key: &str, r: &Remote| plan(key, Some(&local), Some(r), Some(&mine), &none());
        for by in [THEM, ME] {
            let taken = pull_of("theirs", 5, by);
            for rev in [4, 3] {
                let then = pull_of("theirs", rev, by);
                assert_eq!(
                    planned("n.md", &says_all(rev, Some("theirs"), by)),
                    vec![keep("mine"), then],
                    "{rev}"
                );
                assert_eq!(
                    planned("n.md", &says_all(rev, None, by)),
                    vec![Action::Publish("mine".into())],
                    "{rev}"
                );
                assert_eq!(
                    planned(memory_md::INDEX_FILE, &says_all(rev, Some("theirs"), by)),
                    vec![Action::Merge("theirs\nmine".into())],
                    "{rev}"
                );
            }
            // One above, the same version is taken.
            assert_eq!(
                planned("n.md", &says_all(5, Some("theirs"), by)),
                vec![taken]
            );
        }
    }

    /// What is recorded for a version of the channel's says who wrote it,
    /// in every place a record is made of one: the device that wrote it,
    /// where the version says what it was written after, and nobody where
    /// it says nothing.
    #[test]
    fn what_is_recorded_of_a_version_says_who_wrote_it() {
        // A record of an entry by THEM, and a version by THIRD that is
        // known to follow it: it says nothing, or it names THEM there.
        let a = agreed_by(Writer::Device(THEM), 2, "x");
        let x = c("x");
        for says in [false, true] {
            let by_third = |rev: u64, content: Option<&str>| Remote {
                rev,
                content: content.map(c),
                author: THIRD,
                after: says.then(|| After {
                    of: [(THEM, 2)].into_iter().collect(),
                    over: None,
                    below: None,
                }),
            };
            let writer = match says {
                true => Writer::Device(THIRD),
                false => Writer::Nobody,
            };
            let third = |hash: Option<[u8; 32]>, rev: u64| {
                vec![Action::Record(Agreed { hash, rev, writer })]
            };
            let pulled = |text: &str| {
                vec![Action::Pull {
                    text: text.into(),
                    rev: 3,
                    writer,
                }]
            };

            // The file takes it, or goes.
            assert_eq!(
                plan(
                    "n.md",
                    Some(&x),
                    Some(&by_third(3, Some("y"))),
                    Some(&a),
                    &none()
                ),
                pulled("y")
            );
            assert_eq!(
                plan(
                    "n.md",
                    Some(&x),
                    Some(&by_third(3, None)),
                    Some(&a),
                    &none()
                ),
                vec![Action::RemoveFile { rev: 3, writer }]
            );
            // The index, taken because the channel's has all of this
            // device's.
            let index = memory_md::INDEX_FILE;
            assert_eq!(
                plan(
                    index,
                    Some(&c("x\ny\n")),
                    Some(&by_third(3, Some("x\ny\nz\n"))),
                    Some(&a),
                    &none()
                ),
                pulled("x\ny\nz\n")
            );
            // Only its revision moved.
            assert_eq!(
                plan(
                    "n.md",
                    Some(&x),
                    Some(&by_third(3, Some("x"))),
                    Some(&a),
                    &none()
                ),
                third(Some(x.hash), 3)
            );
            // A delete in the channel, and no file here.
            assert_eq!(
                plan("n.md", None, Some(&by_third(3, None)), None, &none()),
                third(None, 3)
            );
            // Both sides changed to the same thing: a text, and a delete.
            let y = c("y");
            assert_eq!(
                plan(
                    "n.md",
                    Some(&y),
                    Some(&by_third(3, Some("y"))),
                    Some(&a),
                    &none()
                ),
                third(Some(y.hash), 3)
            );
            assert_eq!(
                plan("n.md", None, Some(&by_third(3, None)), Some(&a), &none()),
                third(None, 3)
            );
        }
    }

    /// Two devices can publish one text at one revision; an entry can be
    /// published again, saying nothing, when its writer is removed; and a
    /// record can be from before the writer was kept. Where the file, the
    /// record and the channel's version are the same text at the same
    /// revision, nothing moves, and the record takes what the channel's
    /// version gives of its writer, if it says anything else.
    #[test]
    fn a_record_takes_the_writer_of_the_version_it_agrees_with() {
        let x = c("x");
        // The channel's version says nothing: nobody.
        let planned = |a: &Agreed| plan("n.md", Some(&x), Some(&live(2, "x")), Some(a), &none());
        let nobodys = vec![recorded(Some(x.hash), 2)];
        assert_eq!(planned(&agreed_by(Writer::Device(ME), 2, "x")), nobodys);
        assert_eq!(planned(&agreed_by(Writer::Device(THEM), 2, "x")), nobodys);
        assert_eq!(planned(&agreed_by(Writer::NotRecorded, 2, "x")), nobodys);
        // Already so: nothing to do.
        assert_eq!(planned(&agreed_by(Writer::Nobody, 2, "x")), vec![]);

        // It says something: the device that wrote it.
        let said = Remote {
            after: Some(After::default()),
            ..live(2, "x")
        };
        let planned = |a: &Agreed| plan("n.md", Some(&x), Some(&said), Some(a), &none());
        let theirs = vec![Action::Record(agreed_by(Writer::Device(THEM), 2, "x"))];
        // This device's own entry lost the tie to the same text.
        assert_eq!(planned(&agreed_by(Writer::Device(ME), 2, "x")), theirs);
        assert_eq!(planned(&agreed_by(Writer::Nobody, 2, "x")), theirs);
        assert_eq!(planned(&agreed_by(Writer::NotRecorded, 2, "x")), theirs);
        assert_eq!(planned(&agreed_by(Writer::Device(THEM), 2, "x")), vec![]);
        // And a later version is then judged by that record. THEM's next
        // entry names nobody: it follows what THEM wrote, and not what
        // this device wrote at the same revision.
        let next = Remote {
            rev: 3,
            content: Some(c("y")),
            ..said.clone()
        };
        let judged = |a: &Agreed| plan("n.md", Some(&x), Some(&next), Some(a), &none());
        assert_eq!(
            judged(&agreed_by(Writer::Device(THEM), 2, "x")),
            vec![pull_of("y", 3, THEM)]
        );
        assert_eq!(
            judged(&agreed_by(Writer::Device(ME), 2, "x")),
            vec![keep("x"), pull_of("y", 3, THEM)]
        );

        // The same for a file that both have as deleted.
        let deleted = |by: Writer| Agreed {
            hash: None,
            rev: 2,
            writer: by,
        };
        let planned = |a: &Agreed| plan("n.md", None, Some(&gone(2)), Some(a), &none());
        assert_eq!(
            planned(&deleted(Writer::Device(ME))),
            vec![recorded(None, 2)]
        );
        assert_eq!(
            planned(&deleted(Writer::NotRecorded)),
            vec![recorded(None, 2)]
        );
        assert_eq!(planned(&deleted(Writer::Nobody)), vec![]);
    }
}
