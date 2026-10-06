//! Deciding what to do with one file: a pure function of the local file,
//! the channel's current version, what this folder last agreed with the
//! channel, and the keys that count (decision 2026-09-30-agent-memory-sync
//! §4.5, decision 2026-10-04 §7.3).
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
//!   - another device published the same revision concurrently and won the
//!     tie; or
//!   - the channel has gone back to an earlier version, at a lower revision
//!     or the same one, because the entry that was agreed no longer
//!     counts: the device that wrote it was removed, and nothing replaced
//!     what it wrote.
//! - The channel's version is at a higher revision, and is not known to
//!   have been written after the text this folder agreed
//!   ([`known_to_follow`]): the file takes it, or goes if it is a delete,
//!   exactly as it would if it were known, and what the file held is kept
//!   first as a conflict file. That is all the difference it makes, for
//!   every file, `MEMORY.md` included: nothing is merged or published that
//!   would not be otherwise.
//! - Only the channel's revision moved, not its content (a version is
//!   carried into a name's new channel when a statement is applied), or
//!   only the entry that the folder's record is of: note it, and touch
//!   nothing.
//!
//! Every losing edit is meant to end up in a file.

use std::collections::HashSet;

pub use cordelia_api::person::Counting;
pub use cordelia_storage::sync_state::Agreed;

use cordelia_api::publish;
use cordelia_crypto::entry::Link;
use cordelia_crypto::version::Version;

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

/// The channel's current version of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub rev: u64,
    /// `None` when the current version is a delete.
    pub content: Option<Content>,
    /// The key that signed the one entry of the version that a folder's
    /// record is of (decision 2026-10-04 §2.3): this device's own where it
    /// holds one, and otherwise the one whose signer has the lowest key.
    pub signer: [u8; 32],
    /// That entry's chain, or `None` where it lacks what it should say.
    pub chain: Option<Vec<Link>>,
    /// The version, with every entry that the device holds of it: what
    /// is asked whether it is known to follow a text.
    pub version: Version,
}

impl Remote {
    /// What a folder records where it agrees this version with `hash` in
    /// its file (`None` for no file): the version's revision, and the
    /// signer and the chain of its one entry.
    pub fn agreed_with(&self, hash: Option<[u8; 32]>) -> Agreed {
        Agreed {
            hash,
            rev: self.rev,
            signer: Some(self.signer),
            chain: self.chain.clone(),
        }
    }
}

/// What to do for one key. Applied in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Publish the local content as a new revision, then record it.
    Publish(String),
    /// Publish a delete, then record the key as deleted.
    PublishDelete,
    /// Write the channel's content to the file and record it as `agreed`.
    Pull { text: String, agreed: Agreed },
    /// Remove the file and record the key as deleted, as `agreed`.
    RemoveFile { agreed: Agreed },
    /// Keep this device's version in a conflict file beside the original.
    SaveConflict(String),
    /// Write merged content to the file, publish it, and record it.
    Merge(String),
    /// Nothing to move; record that both sides agree on this state.
    Record(Agreed),
}

/// Whether the channel's version `r` is known to have been written after
/// the text that this folder agreed (`a`), where `counting` says which
/// keys count (decision 2026-10-04 §7.3).
///
/// There is one way to know: the agreed text's hash is in the version's
/// chain, and every link that is newer than it was signed by a key that
/// counts ([`cordelia_crypto::entry::known_to_follow`]). An agreed delete
/// is named as a delete is, by zeros. A version of which the device holds
/// several entries is known to follow only if each of them shows it
/// ([`publish::follows`]).
///
/// Nothing else is asked: not who signed the version, not its revision,
/// and not what the record says of who signed the agreed entry. An entry
/// that lacks its chain, or whose chain cannot be read, is known to follow
/// nothing, and so is a new file's entry, whose chain is empty.
///
/// A wrong "not known" costs a conflict file that was not needed, and
/// nothing else: the file takes the channel's version either way.
pub fn known_to_follow(r: &Remote, a: &Agreed, counting: &Counting) -> bool {
    let agreed = a.hash.unwrap_or([0u8; 32]);
    publish::follows(&r.version, &agreed, counting)
}

/// Plan one key. `deleted_files` lists keys deleted in the channel (used to
/// drop their pointers when merging `MEMORY.md`), and `counting` says
/// which keys count.
pub fn plan(
    key: &str,
    local: Option<&Content>,
    remote: Option<&Remote>,
    agreed: Option<&Agreed>,
    deleted_files: &HashSet<String>,
    counting: &Counting,
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
    // is also known to have been written after the agreed text.
    let known = match (remote, agreed) {
        (Some(r), Some(a)) => known_to_follow(r, a, counting),
        _ => true,
    };
    let is_index = key == memory_md::INDEX_FILE;
    let pull = |r: &Remote, c: &Content| Action::Pull {
        text: c.text.clone(),
        agreed: r.agreed_with(Some(c.hash)),
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
        // note where it is now; and if the record is not of the entry that
        // a record of the channel's version is of now (two devices
        // published one text at one revision, or this device carried the
        // version, or the record says nothing of it), note that.
        (false, false) => match (remote, agreed) {
            (Some(r), Some(a)) if *a != r.agreed_with(a.hash) => {
                vec![Action::Record(r.agreed_with(a.hash))]
            }
            _ => vec![],
        },

        (true, false) => match local {
            Some(c) => vec![Action::Publish(c.text.clone())],
            // Deleted here; tell the channel unless it has nothing live.
            None => match remote {
                Some(r) if r.content.is_some() => vec![Action::PublishDelete],
                Some(r) => vec![Action::Record(r.agreed_with(None))],
                None => vec![],
            },
        },

        (false, true) => {
            let r = remote.expect("remote_changed implies remote");
            let remove = Action::RemoveFile {
                agreed: r.agreed_with(None),
            };
            match (&r.content, local) {
                (None, None) => vec![Action::Record(r.agreed_with(None))],
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
                    vec![Action::Record(r.agreed_with(local_hash))]
                }
                // Deleted here, edited there: the edit wins.
                (None, Some(c)) => vec![pull(r, c)],
                // Edited here, deleted there: the edit wins (revives the key).
                (Some(l), None) => vec![Action::Publish(l.text.clone())],
                (Some(l), Some(c)) if is_index => vec![merged(r, c, l)],
                (Some(l), Some(c)) => vec![Action::SaveConflict(l.text.clone()), pull(r, c)],
                (None, None) => vec![Action::Record(r.agreed_with(None))],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cordelia_crypto::entry::Value;
    use cordelia_crypto::version::VersionEntry;

    /// This device, another, and a third: the three that count. And a
    /// fourth key, which does not.
    const ME: [u8; 32] = [1; 32];
    const THEM: [u8; 32] = [9; 32];
    const THIRD: [u8; 32] = [5; 32];
    const GONE: [u8; 32] = [7; 32];

    fn counting() -> Counting {
        Counting::of_devices(&[ME, THEM, THIRD])
    }

    fn c(t: &str) -> Content {
        Content::new(t)
    }

    /// What a chain names the text `t` by, or a delete (`None`), signed by
    /// `signer`.
    fn link(t: Option<&str>, signer: [u8; 32]) -> Link {
        let whole = t.map_or([0u8; 32], |t| c(t).hash);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&whole[..16]);
        Link {
            hash,
            signer: Link::signer_of(&signer),
        }
    }

    /// A chain of texts, newest first, each signed by `THEM`.
    fn after(texts: &[&str]) -> Option<Vec<Link>> {
        Some(texts.iter().map(|t| link(Some(t), THEM)).collect())
    }

    /// An entry of a version: who signed it, and its chain.
    fn entry(author: [u8; 32], chain: Option<Vec<Link>>) -> VersionEntry {
        let mut named = author.to_vec();
        for link in chain.iter().flatten() {
            named.extend_from_slice(&link.hash);
            named.extend_from_slice(&link.signer);
        }
        VersionEntry {
            id: cordelia_crypto::sha256(&named),
            author,
            chain,
        }
    }

    /// The version `t` (a delete for `None`) at `rev`, held in `entries`:
    /// the first of them is the one a record is of.
    fn held_as(rev: u64, t: Option<&str>, entries: Vec<VersionEntry>) -> Remote {
        let one = entries[0].clone();
        Remote {
            rev,
            content: t.map(c),
            signer: one.author,
            chain: one.chain,
            version: Version {
                rev,
                name: "n.md".into(),
                value: t.map_or(Value::Delete, |t| Value::Text(t.into())),
                entries,
            },
        }
    }

    /// A text by `THEM` whose chain is `chain`.
    fn says(rev: u64, t: &str, chain: Option<Vec<Link>>) -> Remote {
        held_as(rev, Some(t), vec![entry(THEM, chain)])
    }
    /// A new file's version by `THEM`: its chain is empty.
    fn live(rev: u64, t: &str) -> Remote {
        says(rev, t, Some(Vec::new()))
    }
    /// A text by `THEM` written over the texts `over`, newest first.
    fn live_after(rev: u64, t: &str, over: &[&str]) -> Remote {
        says(rev, t, after(over))
    }
    /// A delete by `THEM` written over the texts `over`, newest first.
    fn gone_after(rev: u64, over: &[&str]) -> Remote {
        held_as(rev, None, vec![entry(THEM, after(over))])
    }
    /// A record of the version `r` with the text `t` in the file.
    fn agreed_as(r: &Remote, t: &str) -> Agreed {
        r.agreed_with(Some(c(t).hash))
    }
    /// A record of a new file's version by `THEM` at `rev`, with `t`.
    fn agreed(rev: u64, t: &str) -> Agreed {
        agreed_as(&live(rev, t), t)
    }
    fn pull(r: &Remote) -> Action {
        let content = r.content.as_ref().expect("a text");
        Action::Pull {
            text: content.text.clone(),
            agreed: r.agreed_with(Some(content.hash)),
        }
    }
    fn remove(r: &Remote) -> Action {
        Action::RemoveFile {
            agreed: r.agreed_with(None),
        }
    }
    fn keep(text: &str) -> Action {
        Action::SaveConflict(text.into())
    }
    fn none() -> HashSet<String> {
        HashSet::new()
    }
    fn planned(
        key: &str,
        local: Option<&str>,
        remote: Option<&Remote>,
        agreed: Option<&Agreed>,
    ) -> Vec<Action> {
        let local = local.map(c);
        plan(key, local.as_ref(), remote, agreed, &none(), &counting())
    }

    #[test]
    fn nothing_changed() {
        let r = live(2, "x");
        let a = agreed_as(&r, "x");
        assert!(planned("n.md", Some("x"), Some(&r), Some(&a)).is_empty());
        assert!(planned("n.md", None, None, None).is_empty());
    }

    #[test]
    fn new_local_file_is_published() {
        assert_eq!(
            planned("n.md", Some("hello"), None, None),
            vec![Action::Publish("hello".into())]
        );
    }

    #[test]
    fn local_edit_is_published() {
        let r = live(1, "v1");
        let a = agreed_as(&r, "v1");
        assert_eq!(
            planned("n.md", Some("v2"), Some(&r), Some(&a)),
            vec![Action::Publish("v2".into())]
        );
    }

    #[test]
    fn local_delete_is_published() {
        let r = live(1, "v1");
        let a = agreed_as(&r, "v1");
        assert_eq!(
            planned("n.md", None, Some(&r), Some(&a)),
            vec![Action::PublishDelete]
        );
    }

    #[test]
    fn new_remote_file_is_pulled() {
        let r = live(1, "from the other");
        assert_eq!(planned("n.md", None, Some(&r), None), vec![pull(&r)]);
    }

    #[test]
    fn remote_edit_is_pulled() {
        let a = agreed(1, "v1");
        let r = live_after(2, "v2", &["v1"]);
        assert_eq!(
            planned("n.md", Some("v1"), Some(&r), Some(&a)),
            vec![pull(&r)]
        );
    }

    #[test]
    fn remote_delete_removes_the_file() {
        let a = agreed(1, "v1");
        let r = gone_after(2, &["v1"]);
        assert_eq!(
            planned("n.md", Some("v1"), Some(&r), Some(&a)),
            vec![remove(&r)]
        );
    }

    #[test]
    fn same_file_created_on_both_sides_just_records() {
        let r = live(1, "same");
        assert_eq!(
            planned("n.md", Some("same"), Some(&r), None),
            vec![Action::Record(agreed_as(&r, "same"))]
        );
    }

    #[test]
    fn concurrent_edits_keep_both() {
        let a = agreed(1, "v1");
        let r = live_after(2, "theirs", &["v1"]);
        assert_eq!(
            planned("n.md", Some("mine"), Some(&r), Some(&a)),
            vec![keep("mine"), pull(&r)]
        );
    }

    #[test]
    fn edit_beats_delete_either_way() {
        let a = agreed(1, "v1");
        // Deleted here, edited there: the file comes back.
        let r = live_after(2, "theirs", &["v1"]);
        assert_eq!(planned("n.md", None, Some(&r), Some(&a)), vec![pull(&r)]);
        // Edited here, deleted there: the edit is published.
        let r = gone_after(2, &["v1"]);
        assert_eq!(
            planned("n.md", Some("mine"), Some(&r), Some(&a)),
            vec![Action::Publish("mine".into())]
        );
    }

    #[test]
    fn losing_a_same_revision_race_keeps_our_version() {
        // Both published revision 2. Ours is recorded; theirs won the tie.
        let ours = held_as(2, Some("mine"), vec![entry(ME, after(&["v1"]))]);
        let a = agreed_as(&ours, "mine");
        let r = live_after(2, "theirs", &["v1"]);
        assert_eq!(
            planned("n.md", Some("mine"), Some(&r), Some(&a)),
            vec![keep("mine"), pull(&r)]
        );
    }

    #[test]
    fn index_is_merged_not_conflicted() {
        let a = agreed(1, "- [a](a.md)\n");
        let r = live_after(2, "- [a](a.md)\n- [b](b.md)\n", &["- [a](a.md)\n"]);
        let actions = planned(
            memory_md::INDEX_FILE,
            Some("- [a](a.md)\n- [c](c.md)\n"),
            Some(&r),
            Some(&a),
        );
        let [Action::Merge(text)] = actions.as_slice() else {
            panic!("expected one merge, got {actions:?}");
        };
        assert!(text.contains("a.md") && text.contains("b.md") && text.contains("c.md"));

        // The same where the channel's index lost nothing and this
        // device's version does not follow from it: a tie at one revision.
        let ours = held_as(
            2,
            Some("- [a](a.md)\n- [c](c.md)\n"),
            vec![entry(ME, after(&["- [a](a.md)\n"]))],
        );
        let a = agreed_as(&ours, "- [a](a.md)\n- [c](c.md)\n");
        let actions = planned(
            memory_md::INDEX_FILE,
            Some("- [a](a.md)\n- [c](c.md)\n"),
            Some(&r),
            Some(&a),
        );
        assert!(
            matches!(actions.as_slice(), [Action::Merge(text)] if text.contains("b.md") && text.contains("c.md")),
            "{actions:?}"
        );
    }

    /// Where the channel's index already has every line of this device's,
    /// the merge is the channel's version: the file takes it, and nothing
    /// is published.
    #[test]
    fn an_index_the_channel_already_has_whole_is_pulled() {
        let a = agreed(1, "- [a](a.md)\n");
        let theirs = "- [a](a.md)\n- [b](b.md)\n- [c](c.md)\n";
        let r = live_after(2, theirs, &["- [a](a.md)\n"]);
        assert_eq!(
            planned(
                memory_md::INDEX_FILE,
                Some("- [a](a.md)\n- [c](c.md)\n"),
                Some(&r),
                Some(&a)
            ),
            vec![pull(&r)]
        );
    }

    /// The revision moved and the content did not: a version is carried
    /// into a name's new channel at the revision the renumbering gives it.
    /// The record follows, and nothing is done to the file.
    #[test]
    fn a_revision_that_moves_without_new_content_is_only_noted() {
        let a = agreed(3, "same");
        let r = live(7, "same");
        assert_eq!(
            planned("n.md", Some("same"), Some(&r), Some(&a)),
            vec![Action::Record(agreed_as(&r, "same"))]
        );
        // A delete, the same.
        let gone = held_as(3, None, vec![entry(THEM, after(&["x"]))]);
        let a = gone.agreed_with(None);
        let moved = held_as(7, None, vec![entry(THEM, after(&["x"]))]);
        assert_eq!(
            planned("n.md", None, Some(&moved), Some(&a)),
            vec![Action::Record(moved.agreed_with(None))]
        );
        // Deleted here against a delete there at another revision: noted.
        let a = agreed(1, "v1");
        let r = gone_after(2, &["v1"]);
        assert_eq!(
            planned("n.md", None, Some(&r), Some(&a)),
            vec![Action::Record(r.agreed_with(None))]
        );
    }

    /// The channel's version is at a lower revision than the one agreed,
    /// or at the same one with another text: the entry that was agreed
    /// counts no longer. This device's version is kept, never overwritten.
    #[test]
    fn a_channel_that_has_gone_back_keeps_this_devices_version() {
        let a = agreed(5, "newer");
        for rev in [3, 5] {
            let r = live(rev, "older");
            // The file is as agreed: kept beside, and the channel's taken.
            assert_eq!(
                planned("n.md", Some("newer"), Some(&r), Some(&a)),
                vec![keep("newer"), pull(&r)],
                "at revision {rev}"
            );
            // The file was edited too: the same.
            assert_eq!(
                planned("n.md", Some("edited"), Some(&r), Some(&a)),
                vec![keep("edited"), pull(&r)],
                "at revision {rev}"
            );
            // The index is merged with what the channel went back to.
            let actions = planned(
                memory_md::INDEX_FILE,
                Some("- [n](n.md)\n"),
                Some(&live(rev, "- [o](o.md)\n")),
                Some(&agreed(5, "- [n](n.md)\n")),
            );
            assert!(
                matches!(actions.as_slice(), [Action::Merge(text)] if text.contains("n.md") && text.contains("o.md")),
                "at revision {rev}: {actions:?}"
            );
            // A delete that the channel went back to does not remove the
            // file: the edit wins, and is published again.
            let back = held_as(rev, None, vec![entry(THEM, Some(Vec::new()))]);
            assert_eq!(
                planned("n.md", Some("newer"), Some(&back), Some(&a)),
                vec![Action::Publish("newer".into())],
                "at revision {rev}"
            );
        }
    }

    #[test]
    fn losing_a_same_revision_race_to_a_delete_keeps_the_edit() {
        let ours = held_as(2, Some("mine"), vec![entry(ME, after(&["v1"]))]);
        let a = agreed_as(&ours, "mine");
        let r = gone_after(2, &["v1"]);
        assert_eq!(
            planned("n.md", Some("mine"), Some(&r), Some(&a)),
            vec![Action::Publish("mine".into())]
        );
    }

    #[test]
    fn deleted_on_both_sides_records() {
        let a = agreed(1, "v1");
        let r = gone_after(2, &["v1"]);
        assert_eq!(
            planned("n.md", None, Some(&r), Some(&a)),
            vec![Action::Record(r.agreed_with(None))]
        );
    }

    /// A version at a higher revision that is not known to have been
    /// written after the text this folder agreed is taken as it would be
    /// anyway, and what the file held is kept first: for a text, for a
    /// delete, and for the index.
    #[test]
    fn a_higher_revision_not_known_to_follow_is_taken_and_what_was_held_is_kept() {
        let a = agreed(1, "v1");
        // Written over another text than the one agreed.
        let r = live_after(2, "v2", &["elsewhere"]);
        assert_eq!(
            planned("n.md", Some("v1"), Some(&r), Some(&a)),
            vec![keep("v1"), pull(&r)]
        );
        let r = gone_after(2, &["elsewhere"]);
        assert_eq!(
            planned("n.md", Some("v1"), Some(&r), Some(&a)),
            vec![keep("v1"), remove(&r)]
        );
        // The index is no exception: nothing is merged or published that
        // would not be otherwise.
        let a = agreed(1, "- [a](a.md)\n");
        let r = live_after(2, "- [b](b.md)\n", &["elsewhere"]);
        assert_eq!(
            planned(
                memory_md::INDEX_FILE,
                Some("- [a](a.md)\n"),
                Some(&r),
                Some(&a)
            ),
            vec![keep("- [a](a.md)\n"), pull(&r)]
        );
        // Where the file is not there, nothing was held: it is taken.
        let a = agreed(1, "v1");
        let r = live_after(2, "v2", &["elsewhere"]);
        assert_eq!(planned("n.md", None, Some(&r), Some(&a)), vec![pull(&r)]);
    }

    /// There is one way to know that a version follows a folder's text:
    /// the text's hash is in the version's chain, and every link newer
    /// than it was signed by a key that counts (decision 2026-10-04
    /// §7.3). Each of the others that there used to be says no.
    #[test]
    fn a_version_is_known_to_follow_by_its_chain_and_by_nothing_else() {
        let a = agreed(4, "agreed");
        let known = |r: &Remote, a: &Agreed| known_to_follow(r, a, &counting());
        let clean = |r: &Remote, a: &Agreed| {
            let actions = planned("n.md", Some("agreed"), Some(r), Some(a));
            assert_eq!(
                actions.last(),
                Some(&pull(r)),
                "the file takes it either way"
            );
            actions.len() == 1
        };

        // The agreed text is the version it was written over.
        let r = live_after(5, "next", &["agreed"]);
        assert!(known(&r, &a) && clean(&r, &a));
        // Or further back, with only keys that count between.
        let r = says(
            9,
            "next",
            Some(vec![
                link(Some("c"), THIRD),
                link(Some("b"), ME),
                link(Some("agreed"), THEM),
                link(Some("older"), GONE),
            ]),
        );
        assert!(known(&r, &a) && clean(&r, &a));

        // A key that does not count signed a version between the two.
        let r = says(
            9,
            "next",
            Some(vec![
                link(Some("c"), THIRD),
                link(Some("b"), GONE),
                link(Some("agreed"), THEM),
            ]),
        );
        assert!(!known(&r, &a) && !clean(&r, &a));
        // Who signed the agreed text itself is not asked: what was
        // written after it was written by a device that had that text.
        let r = says(
            9,
            "next",
            Some(vec![link(Some("b"), ME), link(Some("agreed"), GONE)]),
        );
        assert!(known(&r, &a) && clean(&r, &a));

        // The agreed text is not in the chain at all.
        let r = live_after(5, "next", &["another", "yet another"]);
        assert!(!known(&r, &a) && !clean(&r, &a));
        // A new file's entry has an empty chain, and follows nothing.
        let r = live(5, "next");
        assert!(!known(&r, &a) && !clean(&r, &a));

        // An entry that lacks its chain shows nothing, and is known to
        // follow nothing: it is no longer taken by its revision.
        let r = says(5, "next", None);
        assert!(!known(&r, &a) && !clean(&r, &a));
        // Nor does a record that says nothing of who signed what it
        // agreed make anything known: a row from before that was kept.
        let unsaid = Agreed {
            signer: None,
            chain: None,
            ..a.clone()
        };
        assert!(!known(&r, &unsaid) && !clean(&r, &unsaid));
        // With such a record the chain still decides, as with any.
        let r = live_after(5, "next", &["agreed"]);
        assert!(known(&r, &unsaid) && clean(&r, &unsaid));

        // That the version was signed by the key that signed the agreed
        // entry shows nothing: a device's later version need not descend
        // from its earlier one (a folder started afresh, or was restored).
        assert_eq!(a.signer, Some(THEM));
        let r = live_after(5, "next", &["another"]);
        assert_eq!(r.signer, THEM);
        assert!(!known(&r, &a) && !clean(&r, &a));

        // Where the hash stands twice, the newest link with it decides.
        let r = says(
            9,
            "next",
            Some(vec![
                link(Some("b"), ME),
                link(Some("agreed"), THEM),
                link(Some("x"), GONE),
                link(Some("agreed"), THEM),
            ]),
        );
        assert!(known(&r, &a) && clean(&r, &a));
    }

    /// What a folder agreed can be that the file is deleted: a delete is
    /// named as a delete is, by zeros.
    #[test]
    fn a_version_is_known_to_follow_an_agreed_delete_by_its_chain() {
        let deleted = gone_after(4, &["v1"]);
        let a = deleted.agreed_with(None);
        // Written over the delete: the file comes back, with nothing to
        // keep beside it either way.
        let r = says(
            5,
            "back",
            Some(vec![link(None, THEM), link(Some("v1"), THEM)]),
        );
        assert!(known_to_follow(&r, &a, &counting()));
        assert_eq!(planned("n.md", None, Some(&r), Some(&a)), vec![pull(&r)]);
        // Not written over it.
        let r = live(5, "back");
        assert!(!known_to_follow(&r, &a, &counting()));
        assert_eq!(planned("n.md", None, Some(&r), Some(&a)), vec![pull(&r)]);
    }

    /// A version of which a device holds several entries is known to
    /// follow a folder's text only if each of them shows it: two devices
    /// that made the same edit apart say two things of it, and the one
    /// that says less decides (decision 2026-10-04 §2.3).
    #[test]
    fn a_version_held_in_several_entries_is_known_only_if_each_shows_it() {
        let a = agreed(4, "agreed");
        let shows = || entry(ME, after(&["agreed"]));
        let both = held_as(
            5,
            Some("next"),
            vec![shows(), entry(THIRD, after(&["agreed"]))],
        );
        assert!(known_to_follow(&both, &a, &counting()));
        assert_eq!(
            planned("n.md", Some("agreed"), Some(&both), Some(&a)),
            vec![pull(&both)]
        );
        for says_less in [after(&["another"]), Some(Vec::new()), None] {
            let one = held_as(5, Some("next"), vec![shows(), entry(THIRD, says_less)]);
            assert!(!known_to_follow(&one, &a, &counting()));
            assert_eq!(
                planned("n.md", Some("agreed"), Some(&one), Some(&a)),
                vec![keep("agreed"), pull(&one)]
            );
        }
    }

    /// At the agreed revision, or below it, nothing that a chain says is
    /// used: the version does not follow from the one agreed, and this
    /// device's is kept, whatever the chain shows.
    #[test]
    fn at_an_equal_or_a_lower_revision_nothing_a_chain_says_is_used() {
        let ours = held_as(5, Some("mine"), vec![entry(ME, after(&["v1"]))]);
        let a = agreed_as(&ours, "mine");
        for rev in [5, 4] {
            // Its chain lists the agreed text, as a forged one could.
            let r = live_after(rev, "theirs", &["mine", "v1"]);
            assert!(known_to_follow(&r, &a, &counting()));
            assert_eq!(
                planned("n.md", Some("mine"), Some(&r), Some(&a)),
                vec![keep("mine"), pull(&r)],
                "at revision {rev}"
            );
            let r = held_as(rev, None, vec![entry(THEM, after(&["mine"]))]);
            assert_eq!(
                planned("n.md", Some("mine"), Some(&r), Some(&a)),
                vec![Action::Publish("mine".into())],
                "at revision {rev}"
            );
        }
    }

    /// What a folder records of a version is one entry of it: the
    /// version's revision, and that entry's signer and chain (decision
    /// 2026-10-04 §2.3).
    #[test]
    fn what_is_recorded_of_a_version_is_its_one_entry() {
        let chain = Some(vec![link(Some("v1"), THIRD), link(Some("v0"), THEM)]);
        let r = held_as(
            6,
            Some("v2"),
            vec![entry(ME, chain.clone()), entry(THEM, after(&["v1"]))],
        );
        let recorded = Agreed {
            hash: Some(c("v2").hash),
            rev: 6,
            signer: Some(ME),
            chain: chain.clone(),
        };
        // Taken into the file.
        assert_eq!(
            planned("n.md", None, Some(&r), None),
            vec![Action::Pull {
                text: "v2".into(),
                agreed: recorded.clone()
            }]
        );
        // Found the same on both sides.
        assert_eq!(
            planned("n.md", Some("v2"), Some(&r), None),
            vec![Action::Record(recorded.clone())]
        );
        // A delete that removes the file.
        let a = agreed(1, "v1");
        let gone = held_as(6, None, vec![entry(THIRD, after(&["v1"]))]);
        assert_eq!(
            planned("n.md", Some("v1"), Some(&gone), Some(&a)),
            vec![Action::RemoveFile {
                agreed: Agreed {
                    hash: None,
                    rev: 6,
                    signer: Some(THIRD),
                    chain: after(&["v1"]),
                }
            }]
        );
    }

    /// A record follows the entry that a record of the channel's version
    /// is of, where nothing else has changed: this device carried the
    /// version, so the entry is its own now and says one link more; or a
    /// row says nothing of the entry.
    #[test]
    fn a_record_takes_the_entry_of_the_version_it_agrees_with() {
        let before = held_as(6, Some("v2"), vec![entry(THEM, after(&["v1"]))]);
        let a = agreed_as(&before, "v2");
        // Carried by this device: its own entry, with a first link for
        // the key that signed the entry it was carried from.
        let carried_chain = Some(vec![link(Some("v2"), THEM), link(Some("v1"), THEM)]);
        let carried = held_as(6, Some("v2"), vec![entry(ME, carried_chain)]);
        assert_eq!(
            planned("n.md", Some("v2"), Some(&carried), Some(&a)),
            vec![Action::Record(agreed_as(&carried, "v2"))]
        );
        // Once recorded, nothing follows.
        let a = agreed_as(&carried, "v2");
        assert!(planned("n.md", Some("v2"), Some(&carried), Some(&a)).is_empty());
        // A row that says nothing of the entry is filled in.
        let unsaid = Agreed {
            signer: None,
            chain: None,
            ..a.clone()
        };
        assert_eq!(
            planned("n.md", Some("v2"), Some(&carried), Some(&unsaid)),
            vec![Action::Record(a)]
        );
    }

    /// What the plan does when a device has applied a statement and
    /// carried what it held (decision 2026-10-04 §7.3, "What the plan
    /// then does"): with nothing else changed in it.
    #[test]
    fn what_the_plan_does_after_a_carry() {
        // What the folder had agreed before the statement: `v2`, written
        // by the other device over `v1`, at revision 6.
        let before = held_as(6, Some("v2"), vec![entry(THEM, after(&["v1"]))]);
        let a = agreed_as(&before, "v2");
        let carried_by = |who: [u8; 32], t: &str, from: [u8; 32], over: &[&str]| {
            // A carried entry keeps the version's chain, with one link
            // first where another key signed the entry it is carried from.
            let mut chain = after(over).unwrap_or_default();
            if who != from {
                chain.insert(0, link(Some(t), from));
            }
            entry(who, Some(chain))
        };

        // 1. A file as its record, and the new channel has that version:
        //    nothing is done to the file. (The record follows the entry.)
        let mine = held_as(6, Some("v2"), vec![carried_by(ME, "v2", THEM, &["v1"])]);
        let actions = planned("n.md", Some("v2"), Some(&mine), Some(&a));
        assert_eq!(actions, vec![Action::Record(agreed_as(&mine, "v2"))]);
        let a_now = agreed_as(&mine, "v2");

        // 2. The new channel comes to be ahead: another device published
        //    a higher revision, over the version it carried. The file
        //    takes it, as it would have in the old channel.
        let ahead = held_as(
            7,
            Some("v3"),
            vec![entry(
                THEM,
                Some(vec![link(Some("v2"), THEM), link(Some("v1"), THEM)]),
            )],
        );
        assert_eq!(
            planned("n.md", Some("v2"), Some(&ahead), Some(&a_now)),
            vec![pull(&ahead)]
        );

        // 3. The file was edited here and not yet published: the edit is
        //    published, over the version this device carried.
        assert_eq!(
            planned("n.md", Some("edited here"), Some(&mine), Some(&a_now)),
            vec![Action::Publish("edited here".into())]
        );

        // 4. Two devices carry one version: the two entries are one
        //    version, and nothing follows.
        let both = held_as(
            6,
            Some("v2"),
            vec![
                carried_by(ME, "v2", THEM, &["v1"]),
                carried_by(THEM, "v2", THEM, &["v1"]),
            ],
        );
        assert!(planned("n.md", Some("v2"), Some(&both), Some(&a_now)).is_empty());

        // 5. Two devices carry two versions at one revision (each had
        //    edited before it heard): a tie, and the text that loses is
        //    kept beside the file.
        let ours = held_as(
            7,
            Some("mine"),
            vec![carried_by(ME, "mine", ME, &["v2", "v1"])],
        );
        let a_ours = agreed_as(&ours, "mine");
        let theirs = held_as(
            7,
            Some("theirs"),
            vec![carried_by(THEM, "theirs", THEM, &["v2", "v1"])],
        );
        assert_eq!(
            planned("n.md", Some("mine"), Some(&theirs), Some(&a_ours)),
            vec![keep("mine"), pull(&theirs)]
        );
    }

    /// A version by a key that no longer counts, between the folder's
    /// text and the version that arrives: the text is kept beside the
    /// file (decision 2026-10-04 §7.3).
    #[test]
    fn a_version_between_by_a_key_that_no_longer_counts_keeps_the_text() {
        let a = agreed(4, "agreed");
        // The other device wrote over what the removed key had written
        // over the agreed text.
        let r = says(
            6,
            "next",
            Some(vec![link(Some("theirs"), GONE), link(Some("agreed"), THEM)]),
        );
        assert_eq!(
            planned("n.md", Some("agreed"), Some(&r), Some(&a)),
            vec![keep("agreed"), pull(&r)]
        );
        // The same chain, read while that key still counts.
        let with_it = Counting::of_devices(&[ME, THEM, THIRD, GONE]);
        assert_eq!(
            plan(
                "n.md",
                Some(&c("agreed")),
                Some(&r),
                Some(&a),
                &none(),
                &with_it
            ),
            vec![pull(&r)]
        );
    }

    /// More than a hundred versions behind: the agreed text has fallen
    /// off the chain, and the text is kept beside the file, with no
    /// change of devices at all.
    #[test]
    fn more_than_a_chains_length_behind_keeps_the_text() {
        use cordelia_core::protocol::MAX_ENTRY_LINKS;
        let a = agreed(1, "agreed");
        let texts: Vec<String> = (0..MAX_ENTRY_LINKS).map(|n| format!("v{n}")).collect();
        let mut links: Vec<Link> = texts.iter().map(|t| link(Some(t), THEM)).collect();
        // The last link that fits is the agreed text: known.
        *links.last_mut().unwrap() = link(Some("agreed"), THEM);
        let within = says(200, "next", Some(links.clone()));
        assert_eq!(
            planned("n.md", Some("agreed"), Some(&within), Some(&a)),
            vec![pull(&within)]
        );
        // One version more, and it has fallen off.
        links.pop();
        links.insert(0, link(Some("one more"), THEM));
        let beyond = says(201, "next", Some(links));
        assert_eq!(
            planned("n.md", Some("agreed"), Some(&beyond), Some(&a)),
            vec![keep("agreed"), pull(&beyond)]
        );
    }
}
