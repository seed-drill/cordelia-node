//! Publishing in a name a device holds, and reading one (decision
//! 2026-10-04 §2.3, §7.3).
//!
//! Plain functions over the node's database and the device's own key, as
//! [`crate::person`] is. Nothing here sends or fetches anything, and no
//! command, handler or adapter calls it yet.
//!
//! ## Reading
//!
//! [`read`] reads the slot of a file in a name: its current version with
//! every entry that is it, the versions that lost a tie, and the next
//! revision. It is read under the statement the device has applied, with
//! its word on who counts, and that word is given back with the slot
//! ([`Read`]): both are of one moment.
//!
//! Whether a version is known to follow a text is asked of what was read
//! ([`Read::follows`], [`follows`]), and of nothing else: only if each
//! entry held of the version shows so. A caller that asks, and then
//! plans against the version it asked about, writes over that version or
//! not at all. There is no way here to ask of whatever the slot holds by
//! then.
//!
//! ## Publishing
//!
//! [`publish`] writes a value under a file's name, as this device's own
//! entry, and only over what the caller planned against:
//!
//! - It is made only where the slot's current version is still the one
//!   the caller read: the same kind of value, with the same bytes, at the
//!   same revision ([`PlannedAgainst`]). Otherwise nothing is written,
//!   and it says so.
//! - Its chain is that of an entry written over one entry of that version
//!   ([`chain::written_over`]): this device's own where it holds one, and
//!   otherwise the one whose signer has the lowest key. A merged index is
//!   written over the channel's version with its other source woven in
//!   ([`chain::merged`]). Over no version the chain is empty.
//! - Its revision is the slot's next. Where there is none until the next
//!   statement, the name is out of reach, and it says so.
//! - A name and a value over their bound are refused, and never cut.
//!
//! A device that follows no phrase has no secret, and publishes nothing.
//! Nor does one that has stopped, or is in a fork (§4.3, §4.5).

use rusqlite::Connection;

use cordelia_core::protocol::ENTRY_LINK_HASH_BYTES;
use cordelia_crypto::chain;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Link, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::version::{self, Slot, Version, VersionEntry};
use cordelia_storage::entries::{self, Outcome};
use cordelia_storage::person::{self as held_rows, State};

use crate::person::{Counting, Held, PersonError, applied_secret, held, in_one};

/// What a caller planned against: what it read in a slot before it wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannedAgainst {
    /// The slot held no version.
    NoVersion,
    /// The slot's current version was this one: a value at a revision.
    /// The value is said by which of the three it is, and by its hash
    /// ([`value_hash`]). Two entries that are one version are one here,
    /// whichever of them the caller read.
    Version {
        rev: u64,
        kind: Kind,
        hash: [u8; 32],
    },
}

/// Which of the three a value is. A text and bytes that are no text are
/// two values though their bytes are the same, and two versions at one
/// revision: where they tie, the text wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A text: what a file holds.
    Text,
    /// Nothing: the name was deleted.
    Delete,
    /// Bytes that are not a text.
    Other,
}

impl Kind {
    /// Which of the three `value` is.
    pub fn of(value: &Value) -> Self {
        match value {
            Value::Text(_) => Self::Text,
            Value::Delete => Self::Delete,
            Value::Other(_) => Self::Other,
        }
    }
}

impl PlannedAgainst {
    /// What a caller that read `slot` plans against.
    pub fn what_is_in(slot: &Slot) -> Self {
        match &slot.current {
            None => Self::NoVersion,
            Some(version) => Self::Version {
                rev: version.rev,
                kind: Kind::of(&version.value),
                hash: value_hash(&version.value),
            },
        }
    }

    /// Whether `current` is still what was planned against: the same
    /// kind of value, with the same bytes, at the same revision.
    fn is_still(&self, current: Option<&Version>) -> bool {
        match (self, current) {
            (Self::NoVersion, None) => true,
            (Self::Version { rev, kind, hash }, Some(version)) => {
                version.rev == *rev
                    && Kind::of(&version.value) == *kind
                    && value_hash(&version.value) == *hash
            }
            _ => false,
        }
    }
}

/// What a version's value is named by where versions are compared
/// (decision 2026-10-04 §7.3): SHA-256 of the text's bytes, or of the
/// bytes that are no text, and zeros for a delete. A chain names a value
/// by the first 16 bytes of this.
pub fn value_hash(value: &Value) -> [u8; 32] {
    value.hash().unwrap_or([0u8; 32])
}

/// The other source of a merged index (decision 2026-10-04 §7.3): the
/// version that the folder's own file held, as the folder's record keeps
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherSource {
    /// The hash of that version's value ([`value_hash`]).
    pub hash: [u8; 32],
    /// The key that signed the entry the folder agreed.
    pub signer: [u8; 32],
    /// That entry's chain, or `None` where it lacked what it should say.
    pub chain: Option<Vec<Link>>,
}

impl OtherSource {
    /// The other source as a chain names it.
    fn link(&self) -> Link {
        Link {
            hash: named(&self.hash),
            signer: Link::signer_of(&self.signer),
        }
    }
}

/// What a device is asked to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write<'a> {
    /// The name, which the device holds: its channel is where the entry
    /// goes.
    pub name: &'a str,
    /// The file's name, which is the entry's.
    pub file: &'a str,
    /// What the file holds: a text, a delete, or bytes that are no text.
    pub value: Value,
    /// What the caller read in the slot before it wrote.
    pub planned: PlannedAgainst,
    /// The other source of a merged index, and `None` for anything else.
    pub merge: Option<&'a OtherSource>,
}

/// What became of a value that a device was asked to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    /// It was made, as this device's own entry, and the store holds it.
    Made(Box<CheckedEntry>),
    /// The slot's current version is not what the caller planned against.
    /// Nothing was written.
    Changed,
    /// There is no next revision in the slot until the next statement
    /// (decision 2026-10-04 §2.3): the name is out of reach. Nothing was
    /// written.
    OutOfReach,
}

/// Publish a value under a file's name in a name that this device holds,
/// over what the caller planned against (see the module's documentation).
///
/// Refused, with nothing written: on a device that follows no phrase, or
/// has stopped; a name the device does not hold; a file's name of no
/// bytes; a name and a value over their bound together; and a merge where
/// the slot holds no version, since a merge is written over one.
pub fn publish(
    conn: &Connection,
    identity: &NodeIdentity,
    write: &Write,
    now: i64,
) -> Result<Published, PersonError> {
    in_one(conn, || {
        let standing = Standing::to_write(conn)?;
        let channel = standing.name_secret(conn, write.name)?;
        let slot = standing.slot(conn, &channel, write.file)?;
        if !write.planned.is_still(slot.current.as_ref()) {
            return Ok(Published::Changed);
        }
        let over = Over {
            channel: &channel,
            slot: &slot,
            merge: write.merge,
        };
        let written = written_over(conn, identity, &over, write.file, &write.value, now)?;
        Ok(written.map_or(Published::OutOfReach, |entry| {
            Published::Made(Box::new(entry))
        }))
    })
}

/// What a device read in a slot, at one moment: the slot, and who counted
/// for the device then. What a caller asks next, it asks of this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// The slot as it was read: its current version with every entry
    /// that is it, the versions that lost a tie, and the next revision.
    pub slot: Slot,
    /// Who counted, as the device knew them at that read: what the slot
    /// was read with.
    pub counting: Counting,
}

impl Read {
    /// Whether the current version that was read is known to follow the
    /// value whose hash is `agreed` ([`value_hash`]): what a folder agreed
    /// (decision 2026-10-04 §7.3).
    ///
    /// It is, where the hash is in the chain of every entry that the
    /// device held of the version, and in each every newer link was
    /// signed by a key that counted ([`follows`]). A slot that held no
    /// version follows nothing.
    pub fn follows(&self, agreed: &[u8; 32]) -> bool {
        self.slot
            .current
            .as_ref()
            .is_some_and(|version| follows(version, agreed, &self.counting))
    }
}

/// Read the slot of `file` in the name `name`, which this device holds:
/// under the statement it has applied, with its word on who counts. The
/// slot and that word are read in one transaction, and given together.
///
/// A device that has stopped reads what it holds as any device does: it
/// takes nothing by reading.
pub fn read(conn: &Connection, name: &str, file: &str) -> Result<Read, PersonError> {
    in_one(conn, || {
        let standing = Standing::of(conn)?;
        let channel = standing.name_secret(conn, name)?;
        let slot = standing.slot(conn, &channel, file)?;
        Ok(Read {
            slot,
            counting: standing.counting,
        })
    })
}

/// Whether `version` is known to follow the value whose hash is `agreed`,
/// where `counting` says who counts.
///
/// A version of which a device holds several entries is known to follow
/// only if each of them shows it (decision 2026-10-04 §2.3): two devices
/// that made the same edit apart say two things of it, and the one that
/// says less decides.
pub fn follows(version: &Version, agreed: &[u8; 32], counting: &Counting) -> bool {
    let agreed = named(agreed);
    !version.entries.is_empty()
        && version.entries.iter().all(|one| {
            cordelia_crypto::entry::known_to_follow(one.chain.as_deref(), &agreed, |signer| {
                counting.signer_counts(signer)
            })
        })
}

/// What a chain names a value by: the first 16 bytes of its hash.
fn named(hash: &[u8; 32]) -> [u8; ENTRY_LINK_HASH_BYTES] {
    let mut named = [0u8; ENTRY_LINK_HASH_BYTES];
    named.copy_from_slice(&hash[..ENTRY_LINK_HASH_BYTES]);
    named
}

/// Where a device stands in its own channels: the statement it has
/// applied, that statement's secret, and who counts under it.
pub(crate) struct Standing {
    pub(crate) held: Held,
    /// The person secret of the statement applied.
    pub(crate) secret: [u8; 32],
    pub(crate) counting: Counting,
}

impl Standing {
    /// Where this device stands, in whatever state it is. A device that
    /// follows no phrase has no secret, and stands nowhere.
    pub(crate) fn of(conn: &Connection) -> Result<Self, PersonError> {
        let held = held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
        let secret = applied_secret(conn, &held.statement.statement)?;
        let counting = Counting::of(&held.statement.statement, &held_rows::additions(conn)?);
        Ok(Self {
            held,
            secret,
            counting,
        })
    }

    /// Where this device stands, as one that may write in its own
    /// channels: it has applied a statement, and has not stopped since
    /// (decision 2026-10-04 §4.3, §4.5).
    pub(crate) fn to_write(conn: &Connection) -> Result<Self, PersonError> {
        let standing = Self::of(conn)?;
        if standing.held.state != State::Applied {
            return Err(PersonError::Stopped(standing.held.state));
        }
        Ok(standing)
    }

    /// The number of the statement applied.
    pub(crate) fn number(&self) -> u64 {
        self.held.statement.statement.number
    }

    /// The secret of the channel of `name`, in the generation applied. A
    /// name that the device does not hold is refused.
    pub(crate) fn name_secret(
        &self,
        conn: &Connection,
        name: &str,
    ) -> Result<[u8; 32], PersonError> {
        let held = held_rows::channel_of_name(conn, name)?
            .ok_or_else(|| PersonError::NameNotHeld(name.to_string()))?;
        let secret = derive::own_secret(&self.secret, name)?;
        if derive::channel_id(&secret)? != held {
            return Err(PersonError::Held(format!(
                "the channel kept for the name {name} is not its channel in the generation applied"
            )));
        }
        Ok(secret)
    }

    /// The slot of `file` in the channel whose secret is `channel`, as
    /// the device's store has it.
    pub(crate) fn slot(
        &self,
        conn: &Connection,
        channel: &[u8; 32],
        file: &str,
    ) -> Result<Slot, PersonError> {
        let id = derive::channel_id(channel)?;
        let slot = slot_id(&derive::slot_key(channel)?, file);
        let held = entries::slot_entries(conn, &id, &slot)?;
        Ok(version::current(&held, channel, self.number(), |key| {
            self.counting.counts(key)
        })?)
    }
}

/// What an entry is written over: a slot of a channel, as the device
/// reads it now, inside the caller's transaction.
pub(crate) struct Over<'a> {
    /// The channel's secret.
    pub(crate) channel: &'a [u8; 32],
    pub(crate) slot: &'a Slot,
    /// The other source, where the entry is a merged index.
    pub(crate) merge: Option<&'a OtherSource>,
}

/// Write `value` under `file` over what a slot holds, as this device's
/// own entry at the slot's next revision. `None`, with nothing written,
/// where the slot has no next revision.
pub(crate) fn written_over(
    conn: &Connection,
    identity: &NodeIdentity,
    over: &Over,
    file: &str,
    value: &Value,
    now: i64,
) -> Result<Option<CheckedEntry>, PersonError> {
    let current = over.slot.current.as_ref();
    let chain = chain_over(current, &identity.public_key(), over.merge)?;
    let Some(rev) = over.slot.next else {
        return Ok(None);
    };
    let inside = Inside {
        name: file.to_string(),
        value: value.clone(),
        chain: Some(chain),
    };
    let entry = Entry::seal(over.channel, identity, rev, &inside)?.check()?;
    if entries::store(conn, &entry, now)? != Outcome::Stored {
        return Err(PersonError::Held(
            "the store holds an entry of this device's at or above the slot's next revision".into(),
        ));
    }
    Ok(Some(entry))
}

/// The chain of an entry that the device whose key is `own` writes over
/// `current` (decision 2026-10-04 §7.3).
///
/// Over no version it is empty: a new file's entry. Over a version it is
/// built from one entry of that version ([`the_one_entry`]), with that
/// entry's signer and that entry's chain: one entry's chain is never put
/// behind another entry's signer.
fn chain_over(
    current: Option<&Version>,
    own: &[u8; 32],
    merge: Option<&OtherSource>,
) -> Result<Vec<Link>, PersonError> {
    let Some(version) = current else {
        return match merge {
            None => Ok(Vec::new()),
            Some(_) => Err(PersonError::MergeOverNoVersion),
        };
    };
    let from = the_one_entry(version, own)?;
    Ok(match merge {
        None => chain::written_over(&version.value, &from.author, from.chain.as_deref()),
        Some(other) => chain::merged(
            &version.value,
            &from.author,
            from.chain.as_deref(),
            &other.link(),
            other.chain.as_deref(),
        ),
    })
}

/// The one entry of a version that a device writes over (decision
/// 2026-10-04 §2.3): its own where it holds one, and otherwise the one
/// whose signer has the lowest key. A version's entries are in order of
/// their signers' keys.
fn the_one_entry<'a>(
    version: &'a Version,
    own: &[u8; 32],
) -> Result<&'a VersionEntry, PersonError> {
    version
        .entries
        .iter()
        .find(|entry| entry.author == *own)
        .or(version.entries.first())
        .ok_or_else(|| PersonError::Held("a version with no entry".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::several::{Machine, Several, entry_by, link, signed_in, text};
    use cordelia_core::protocol::{
        MAX_ENTRY_NAME_AND_VALUE_BYTES, REV_BAND_HALF, REV_BAND_SIZE, REV_COUNT_BITS,
    };
    use cordelia_crypto::entry::EntryError;

    /// The revision at `count` in `band`.
    fn at(band: u64, count: u64) -> u64 {
        (band << REV_COUNT_BITS) + count
    }

    fn hash(said: &str) -> [u8; 32] {
        value_hash(&text(said))
    }

    /// One device, alone under its phrase, which holds the name `notes`.
    fn alone() -> Several {
        let mut s = Several::new(1);
        s.make_phrase(0);
        s.hold(&[0], "notes");
        s
    }

    /// Device `n` publishes `value` under `file` in `notes`, over what it
    /// reads there.
    fn published(s: &mut Several, n: usize, file: &str, value: Value) -> Published {
        let now = s.tick();
        let on = &s[n];
        let write = Write {
            name: "notes",
            file,
            value,
            planned: PlannedAgainst::what_is_in(&on.slot("notes", file)),
            merge: None,
        };
        publish(&on.conn, &on.identity, &write, now).unwrap()
    }

    fn made(published: Published) -> CheckedEntry {
        match published {
            Published::Made(entry) => *entry,
            other => panic!("{other:?}"),
        }
    }

    /// The one entry of the current version of `file` in `notes`, as
    /// device `n` reads it: its chain.
    fn chain_of(s: &Several, n: usize, file: &str) -> Vec<Link> {
        let version = s[n].slot("notes", file).current.unwrap();
        let own = s.key(n);
        let one = version.entries.iter().find(|one| one.author == own);
        one.unwrap().chain.clone().unwrap()
    }

    /// The store of device `n` is given `entry`, past the door: what it
    /// holds is what it holds, however it came by it.
    fn holds(s: &Several, n: usize, entry: &CheckedEntry) {
        assert_eq!(
            entries::store(&s[n].conn, entry, s.now).unwrap(),
            Outcome::Stored
        );
    }

    /// A new file's entry is this device's own, at revision 1, with an
    /// empty chain, and the store holds it. What is written over it says
    /// what it was written over: a text, a delete, bytes that are no text.
    #[test]
    fn test_a_value_is_published_as_this_devices_own_entry_over_what_the_slot_holds() {
        let mut s = alone();
        let own = s.key(0);
        let channel = s[0].own("notes");

        let first = made(published(&mut s, 0, "a.md", text("one")));
        assert_eq!(first.channel, derive::channel_id(&channel).unwrap());
        assert_eq!((first.author, first.rev, first.delete), (own, 1, false));
        assert_eq!(
            first.open(&channel).unwrap(),
            Inside {
                name: "a.md".to_string(),
                value: text("one"),
                chain: Some(Vec::new()),
            }
        );
        // The store holds it, and it is what the slot is read as.
        let slot = read(&s[0].conn, "notes", "a.md").unwrap().slot;
        let version = slot.current.clone().unwrap();
        assert_eq!((version.value, version.rev), (text("one"), 1));
        assert_eq!(version.entries.len(), 1);
        assert_eq!(version.entries[0].id, first.id());
        assert_eq!((slot.lost.len(), slot.next), (0, Some(2)));

        // A delete over it, and a text over the delete, and bytes that are
        // no text over that: each at the slot's next revision, each with
        // the link of what it was written over put first.
        let delete = made(published(&mut s, 0, "a.md", Value::Delete));
        assert_eq!((delete.rev, delete.delete), (2, true));
        assert_eq!(chain_of(&s, 0, "a.md"), [link("one", own)]);
        let again = made(published(&mut s, 0, "a.md", text("two")));
        assert_eq!(again.rev, 3);
        assert_eq!(
            chain_of(&s, 0, "a.md"),
            [Link::of(&Value::Delete, own), link("one", own)]
        );
        let bytes = made(published(&mut s, 0, "a.md", Value::Other(vec![0, 0xff])));
        assert_eq!(bytes.rev, 4);
        assert_eq!(
            chain_of(&s, 0, "a.md"),
            [
                link("two", own),
                Link::of(&Value::Delete, own),
                link("one", own)
            ]
        );
        // Another file of the name is another slot.
        let other = made(published(&mut s, 0, "b.md", text("one")));
        assert_eq!(other.rev, 1);
        assert_ne!(other.slot, first.slot);
        assert_eq!(s[0].stored_in(&channel).len(), 2);
    }

    /// What a caller plans against is a value at a revision, or no
    /// version. A value is named by the hash of its text or of its bytes,
    /// and a delete by zeros.
    #[test]
    fn test_what_is_planned_against_is_a_value_at_a_revision() {
        assert_eq!(hash("one"), cordelia_crypto::sha256(b"one"));
        assert_eq!(
            value_hash(&Value::Other(vec![1, 2])),
            cordelia_crypto::sha256(&[1, 2])
        );
        assert_eq!(value_hash(&Value::Delete), [0u8; 32]);
        // A chain names a value by the start of that hash.
        assert_eq!(named(&hash("one")), text("one").chain_hash());
        assert_eq!(named(&[0u8; 32]), Value::Delete.chain_hash());

        let mut s = alone();
        let on = |s: &Several| PlannedAgainst::what_is_in(&s[0].slot("notes", "a.md"));
        assert_eq!(on(&s), PlannedAgainst::NoVersion);
        published(&mut s, 0, "a.md", text("one"));
        assert_eq!(
            on(&s),
            PlannedAgainst::Version {
                rev: 1,
                kind: Kind::Text,
                hash: hash("one")
            }
        );
        published(&mut s, 0, "a.md", Value::Delete);
        assert_eq!(
            on(&s),
            PlannedAgainst::Version {
                rev: 2,
                kind: Kind::Delete,
                hash: [0u8; 32]
            }
        );
        published(&mut s, 0, "a.md", Value::Other(b"one".to_vec()));
        assert_eq!(
            on(&s),
            PlannedAgainst::Version {
                rev: 3,
                kind: Kind::Other,
                hash: hash("one")
            }
        );
    }

    /// An entry is made only where the slot's current version is still
    /// the one that was planned against. Otherwise nothing is written.
    #[test]
    fn test_an_entry_is_made_only_over_the_version_that_was_planned_against() {
        let mut s = alone();
        let attempt = |s: &mut Several, file: &str, planned: PlannedAgainst| {
            let now = s.tick();
            let on = &s[0];
            let write = Write {
                name: "notes",
                file,
                value: text("an edit"),
                planned,
                merge: None,
            };
            let before = on.everything();
            let outcome = publish(&on.conn, &on.identity, &write, now).unwrap();
            if !matches!(outcome, Published::Made(_)) {
                assert_eq!(on.everything(), before);
            }
            outcome
        };
        let version = |rev: u64, said: &str| PlannedAgainst::Version {
            rev,
            kind: Kind::Text,
            hash: hash(said),
        };

        // The slot holds no version: a caller that read one finds it
        // changed.
        assert_eq!(
            attempt(&mut s, "a.md", version(1, "one")),
            Published::Changed
        );
        published(&mut s, 0, "a.md", text("one"));
        published(&mut s, 0, "a.md", text("two"));

        // It holds "two" at revision 2. A caller that read no version,
        // the version before, that text at another revision, or another
        // text at that revision, finds it changed.
        for planned in [
            PlannedAgainst::NoVersion,
            version(1, "one"),
            version(1, "two"),
            version(3, "two"),
            version(2, "one"),
            PlannedAgainst::Version {
                rev: 2,
                kind: Kind::Delete,
                hash: [0u8; 32],
            },
            // That text's bytes at that revision, as bytes that are no
            // text, and as a delete.
            PlannedAgainst::Version {
                rev: 2,
                kind: Kind::Other,
                hash: hash("two"),
            },
            PlannedAgainst::Version {
                rev: 2,
                kind: Kind::Delete,
                hash: hash("two"),
            },
        ] {
            assert_eq!(
                attempt(&mut s, "a.md", planned),
                Published::Changed,
                "{planned:?}"
            );
        }
        assert_eq!(s[0].text("notes", "a.md").as_deref(), Some("two"));

        // The version it holds: the edit is made.
        let entry = made(attempt(&mut s, "a.md", version(2, "two")));
        assert_eq!(entry.rev, 3);
        assert_eq!(s[0].text("notes", "a.md").as_deref(), Some("an edit"));
        // And over no version, in a slot that holds none.
        let entry = made(attempt(&mut s, "b.md", PlannedAgainst::NoVersion));
        assert_eq!(entry.rev, 1);
    }

    /// Two entries that are one version are one for the check, whichever
    /// of them the caller read: a second device's entry of the same text
    /// at the same revision changes nothing that was planned against.
    #[test]
    fn test_two_entries_that_are_one_version_are_one_for_what_was_planned_against() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        s.write(0, "notes", "a.md", "the same edit");
        let planned = PlannedAgainst::what_is_in(&s[0].slot("notes", "a.md"));

        // Device 1 made the same edit apart.
        let same = entry_by(
            &s[1].identity,
            &s[0].own("notes"),
            1,
            "a.md",
            text("the same edit"),
            &[],
        );
        holds(&s, 0, &same);
        assert_eq!(s[0].slot("notes", "a.md").current.unwrap().entries.len(), 2);
        let now = s.tick();
        let on = &s[0];
        let write = Write {
            name: "notes",
            file: "a.md",
            value: text("over both"),
            planned,
            merge: None,
        };
        assert!(matches!(
            publish(&on.conn, &on.identity, &write, now).unwrap(),
            Published::Made(_)
        ));

        // Another text at that revision is another version: where it wins
        // the tie, what was planned against is no longer current.
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        s.write(0, "notes", "b.md", "one text");
        let planned = PlannedAgainst::what_is_in(&s[0].slot("notes", "b.md"));
        let (mut n, mut other) = (0u8, String::new());
        while other.is_empty() || hash(&other) < hash("one text") {
            other = format!("another text {n}");
            n += 1;
        }
        let tie = entry_by(
            &s[1].identity,
            &s[0].own("notes"),
            1,
            "b.md",
            text(&other),
            &[],
        );
        holds(&s, 0, &tie);
        let slot = s[0].slot("notes", "b.md");
        assert_eq!(slot.current.unwrap().value, text(&other));
        assert_eq!(slot.lost.len(), 1);
        let now = s.tick();
        let on = &s[0];
        let write = Write {
            name: "notes",
            file: "b.md",
            value: text("over the loser"),
            planned,
            merge: None,
        };
        assert_eq!(
            publish(&on.conn, &on.identity, &write, now).unwrap(),
            Published::Changed
        );
    }

    /// A text and bytes that are no text are two versions though their
    /// bytes are the same. A caller read the bytes, and a text of those
    /// very bytes then wins the tie at that revision: what was planned
    /// against is no longer current, and nothing is written.
    #[test]
    fn test_a_text_and_other_bytes_with_the_same_bytes_are_two_versions() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let channel = s[0].own("notes");
        let bytes = Value::Other(b"the same bytes".to_vec());
        made(published(&mut s, 0, "a.md", bytes.clone()));
        let planned = PlannedAgainst::what_is_in(&s[0].slot("notes", "a.md"));
        let a_text = entry_by(
            &s[1].identity,
            &channel,
            1,
            "a.md",
            text("the same bytes"),
            &[],
        );
        holds(&s, 0, &a_text);
        let slot = s[0].slot("notes", "a.md");
        assert_eq!(slot.current.unwrap().value, text("the same bytes"));
        assert_eq!(slot.lost[0].value, bytes);

        let on = &s[0];
        let write = |planned: PlannedAgainst| Write {
            name: "notes",
            file: "a.md",
            value: text("over what was read"),
            planned,
            merge: None,
        };
        let before = on.everything();
        assert_eq!(
            publish(&on.conn, &on.identity, &write(planned), s.now).unwrap(),
            Published::Changed
        );
        assert_eq!(on.everything(), before);
        // The control: planned against the text, which is current.
        let planned = PlannedAgainst::what_is_in(&on.slot("notes", "a.md"));
        assert!(matches!(
            publish(&on.conn, &on.identity, &write(planned), s.now).unwrap(),
            Published::Made(_)
        ));
    }

    /// A device writes over a version from one of its entries: its own
    /// where it holds one, and otherwise the one whose signer has the
    /// lowest key. That entry's signer and that entry's chain are what
    /// the new chain is built from.
    #[test]
    fn test_an_entry_is_written_over_this_devices_own_entry_or_the_lowest_keys() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        // The device that writes is the one with the highest key, so that
        // its own entry is not the first of a version's entries.
        let mut by_key = [0, 1, 2];
        by_key.sort_by_key(|n| s.key(*n));
        let (lowest, between, writer) = (by_key[0], by_key[1], by_key[2]);
        let keys = [s.key(lowest), s.key(between), s.key(writer)];
        let channel = s[writer].own("notes");
        let of = |n: usize, file: &str, chain: &[Link]| {
            entry_by(&s[n].identity, &channel, 5, file, text("the same"), chain)
        };

        // One version in two entries, neither of them this device's.
        let chains = [
            vec![link("x", keys[0])],
            vec![link("y", keys[1]), link("z", keys[2])],
        ];
        holds(&s, writer, &of(lowest, "a.md", &chains[0]));
        holds(&s, writer, &of(between, "a.md", &chains[1]));
        // And in three, of which one is this device's own.
        let own_chain = [link("w", keys[2])];
        holds(&s, writer, &of(lowest, "b.md", &chains[0]));
        holds(&s, writer, &of(between, "b.md", &chains[1]));
        holds(&s, writer, &of(writer, "b.md", &own_chain));

        let over_anothers = made(published(&mut s, writer, "a.md", text("an edit")));
        assert_eq!(over_anothers.rev, 6);
        assert_eq!(
            chain_of(&s, writer, "a.md"),
            [link("the same", keys[0]), link("x", keys[0])]
        );
        let over_its_own = made(published(&mut s, writer, "b.md", text("an edit")));
        assert_eq!(over_its_own.rev, 6);
        assert_eq!(
            chain_of(&s, writer, "b.md"),
            [link("the same", keys[2]), link("w", keys[2])]
        );
    }

    /// A merge is written over a version: where the slot holds none there
    /// is nothing to merge with, and nothing is written.
    #[test]
    fn test_a_merge_over_no_version_is_refused() {
        let s = alone();
        let on = &s[0];
        let other = OtherSource {
            hash: hash("what the file held"),
            signer: on.key(),
            chain: Some(Vec::new()),
        };
        let write = Write {
            name: "notes",
            file: "MEMORY.md",
            value: text("merged"),
            planned: PlannedAgainst::NoVersion,
            merge: Some(&other),
        };
        let before = on.everything();
        assert!(matches!(
            publish(&on.conn, &on.identity, &write, s.now),
            Err(PersonError::MergeOverNoVersion)
        ));
        assert_eq!(on.everything(), before);
        // The other source as a chain names it: the start of its hash, and
        // of its signer's key.
        assert_eq!(other.link(), link("what the file held", on.key()));
    }

    /// An entry's revision is the slot's next: one above the highest that
    /// counts for it, an entry that is no version among them. Where there
    /// is none until the next statement, the name is out of reach, and
    /// nothing is written.
    #[test]
    fn test_the_revision_is_the_slots_next_and_a_name_out_of_reach_is_said_to_be() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let channel = s[0].own("notes");
        // Device 1, which counts: its key signs what device 0 comes to hold.
        let other = &Machine::new(1).identity;
        assert_eq!(other.public_key(), s.key(1));
        let top = at(1, REV_BAND_SIZE - 1);

        // At the top of the statement's band nothing can be written above.
        holds(
            &s,
            0,
            &entry_by(other, &channel, top, "a.md", text("at the top"), &[]),
        );
        let before = s[0].everything();
        assert_eq!(
            published(&mut s, 0, "a.md", text("above it")),
            Published::OutOfReach
        );
        assert_eq!(s[0].everything(), before);
        // One below the top, the last revision is still there to write.
        let below = entry_by(other, &channel, top - 1, "b.md", text("below the top"), &[]);
        holds(&s, 0, &below);
        assert_eq!(
            made(published(&mut s, 0, "b.md", text("the last"))).rev,
            top
        );

        // An entry that does not open is no version: the slot holds none,
        // and the next revision is above it all the same.
        let slot = slot_id(&derive::slot_key(&channel).unwrap(), "c.md");
        let elsewhere = entry_by(
            other,
            &[0xee; 32],
            40,
            "c.md",
            text("sealed elsewhere"),
            &[],
        );
        let unread = signed_in(&channel, other, slot, 40, elsewhere.content.clone());
        holds(&s, 0, &unread);
        assert_eq!(s[0].slot("notes", "c.md").current, None);
        let over = made(published(
            &mut s,
            0,
            "c.md",
            text("over what does not open"),
        ));
        assert_eq!(over.rev, 41);
        assert_eq!(chain_of(&s, 0, "c.md"), []);

        // An entry in the top half of a lower band is no version either,
        // and the next revision is moved as a move would move it.
        let jumped = at(0, REV_BAND_HALF + 5);
        holds(
            &s,
            0,
            &entry_by(other, &channel, jumped, "d.md", text("jumped"), &[]),
        );
        assert_eq!(
            made(published(&mut s, 0, "d.md", text("after a jump"))).rev,
            at(1, 6)
        );
        // One in a band above the statement's counts for nothing.
        holds(
            &s,
            0,
            &entry_by(other, &channel, at(2, 7), "e.md", text("above"), &[]),
        );
        assert_eq!(made(published(&mut s, 0, "e.md", text("the first"))).rev, 1);

        // Nor does this device's own entry up there. The store holds it
        // above the slot's next revision, and takes no entry of this
        // device's below it: nothing is written, and it is said so.
        let own = &Machine::new(0).identity;
        let above = entry_by(own, &channel, at(2, 7), "f.md", text("its own"), &[]);
        holds(&s, 0, &above);
        let on = &s[0];
        let write = Write {
            name: "notes",
            file: "f.md",
            value: text("below its own"),
            planned: PlannedAgainst::NoVersion,
            merge: None,
        };
        let before = on.everything();
        assert!(matches!(
            publish(&on.conn, &on.identity, &write, s.now),
            Err(PersonError::Held(_))
        ));
        assert_eq!(on.everything(), before);
    }

    #[test]
    fn test_a_name_and_a_value_over_their_bound_are_refused() {
        let mut s = alone();
        let room = MAX_ENTRY_NAME_AND_VALUE_BYTES - "a.md".len();
        let before = s[0].everything();
        let attempt = |s: &Several, file: &str, value: Value| {
            let on = &s[0];
            let write = Write {
                name: "notes",
                file,
                value,
                planned: PlannedAgainst::NoVersion,
                merge: None,
            };
            publish(&on.conn, &on.identity, &write, s.now)
        };
        for value in [text(&"x".repeat(room + 1)), Value::Other(vec![7; room + 1])] {
            assert!(matches!(
                attempt(&s, "a.md", value),
                Err(PersonError::Entry(EntryError::OverTheBound(61_441)))
            ));
        }
        // A file's name of no bytes.
        assert!(matches!(
            attempt(&s, "", text("a text")),
            Err(PersonError::Entry(EntryError::NameEmpty))
        ));
        assert_eq!(s[0].everything(), before);

        // The control: at the bound it is made, whole.
        let whole = made(published(&mut s, 0, "a.md", text(&"x".repeat(room))));
        let inside = whole.open(&s[0].own("notes")).unwrap();
        assert_eq!(inside.value.bytes().len(), room);
    }

    /// A device that follows no phrase has no secret, and publishes
    /// nothing. Nor does one that has stopped, or is in a fork, though it
    /// reads what it holds. And a name that the device does not hold has
    /// no channel here.
    #[test]
    fn test_a_device_with_no_phrase_or_that_has_stopped_publishes_nothing() {
        let new = Machine::new(7);
        let write = Write {
            name: "notes",
            file: "a.md",
            value: text("one"),
            planned: PlannedAgainst::NoVersion,
            merge: None,
        };
        assert!(matches!(
            publish(&new.conn, &new.identity, &write, 5),
            Err(PersonError::FollowsNoPhrase)
        ));
        assert!(matches!(
            read(&new.conn, "notes", "a.md"),
            Err(PersonError::FollowsNoPhrase)
        ));
        assert!(new.stored().is_empty());

        let mut s = alone();
        published(&mut s, 0, "a.md", text("one"));
        let on = &s[0];
        // A name it does not hold.
        let elsewhere = Write {
            name: "other",
            ..write.clone()
        };
        assert!(matches!(
            publish(&on.conn, &on.identity, &elsewhere, s.now),
            Err(PersonError::NameNotHeld(name)) if name == "other"
        ));
        assert!(matches!(
            read(&on.conn, "other", "a.md"),
            Err(PersonError::NameNotHeld(_))
        ));

        let over = Write {
            planned: PlannedAgainst::what_is_in(&on.slot("notes", "a.md")),
            ..write.clone()
        };
        for state in [
            State::Fork,
            State::Removed,
            State::NotListed,
            State::NotOpened,
        ] {
            held_rows::set_state(&on.conn, state).unwrap();
            let before = on.everything();
            assert!(matches!(
                publish(&on.conn, &on.identity, &over, s.now),
                Err(PersonError::Stopped(stopped)) if stopped == state
            ));
            assert_eq!(on.everything(), before);
            // It reads what it holds.
            assert_eq!(on.text("notes", "a.md").as_deref(), Some("one"));
        }
        // The control: it has not stopped, and the entry is made.
        held_rows::set_state(&on.conn, State::Applied).unwrap();
        assert!(matches!(
            publish(&on.conn, &on.identity, &over, s.now).unwrap(),
            Published::Made(_)
        ));

        // A name whose channel, as it is kept, is not the name's channel
        // in the generation applied: what is held does not hold together,
        // and nothing is read or written there.
        held_rows::move_name(&on.conn, "notes", &[0x44; 32]).unwrap();
        let before = on.everything();
        assert!(matches!(
            publish(&on.conn, &on.identity, &write, s.now),
            Err(PersonError::Held(_))
        ));
        assert!(matches!(
            read(&on.conn, "notes", "a.md"),
            Err(PersonError::Held(_))
        ));
        assert_eq!(on.everything(), before);
    }

    /// What is read is the slot and who counted, of one moment. A caller
    /// asks whether the version it was given follows a text, whatever has
    /// arrived since: and what it plans against that version is not made
    /// where another is current by then.
    #[test]
    fn test_what_is_read_is_the_slot_and_who_counted_at_one_moment() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        s.write(0, "notes", "a.md", "one");
        s.write(0, "notes", "a.md", "two");
        let was = read(&s[0].conn, "notes", "a.md").unwrap();
        assert_eq!(was.slot.current.as_ref().unwrap().value, text("two"));
        assert_eq!(was.counting, crate::person::who_counts(&s[0].conn).unwrap());
        assert!(was.follows(&hash("one")) && !was.follows(&hash("another")));

        // A version that was written apart arrives, and a key comes to
        // count.
        let channel = s[0].own("notes");
        let apart = entry_by(&s[1].identity, &channel, 3, "a.md", text("apart"), &[]);
        holds(&s, 0, &apart);
        let on = &s[0];
        let new = Machine::new(7);
        crate::adding::add_device(&on.conn, &on.identity, &new.key(), "device 7", s.now).unwrap();
        let is = read(&on.conn, "notes", "a.md").unwrap();
        assert_eq!(is.slot.current.as_ref().unwrap().value, text("apart"));
        assert!(!is.follows(&hash("one")));
        assert!(is.counting.counts(&new.key()));
        // What was read says what it said, of the version that was read
        // and of who counted then.
        assert_ne!(was.slot, is.slot);
        assert!(!was.counting.counts(&new.key()));
        assert!(was.follows(&hash("one")));
        assert_eq!(was.slot.current.as_ref().unwrap().value, text("two"));
        // An edit that is planned against it is not made.
        let write = Write {
            name: "notes",
            file: "a.md",
            value: text("over two"),
            planned: PlannedAgainst::what_is_in(&was.slot),
            merge: None,
        };
        assert_eq!(
            publish(&on.conn, &on.identity, &write, s.now).unwrap(),
            Published::Changed
        );
    }

    /// A slot is read under the statement applied, with the device's word
    /// on who counts: an entry of a key that does not count is nothing
    /// there, and a version that lost a tie is given as that.
    #[test]
    fn test_a_slot_is_read_under_the_statement_applied_with_who_counts() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let channel = s[0].own("notes");
        s.write(0, "notes", "a.md", "by a device that counts");
        let stranger = Machine::new(9);
        let late = entry_by(
            &stranger.identity,
            &channel,
            9,
            "a.md",
            text("a stranger's"),
            &[],
        );
        holds(&s, 0, &late);
        let slot = read(&s[0].conn, "notes", "a.md").unwrap().slot;
        assert_eq!(slot.current.unwrap().value, text("by a device that counts"));
        assert_eq!((slot.highest, slot.next), (Some(1), Some(2)));

        // A tie between two devices that count: the loser is given.
        let tie = entry_by(
            &s[1].identity,
            &channel,
            1,
            "a.md",
            text("at the same revision"),
            &[],
        );
        holds(&s, 0, &tie);
        let slot = read(&s[0].conn, "notes", "a.md").unwrap().slot;
        let (won, lost) = (slot.current.unwrap(), slot.lost);
        assert_eq!(lost.len(), 1);
        assert_eq!((won.rev, lost[0].rev), (1, 1));
        assert!(value_hash(&won.value) > value_hash(&lost[0].value));
        let authors = [won.entries[0].author, lost[0].entries[0].author];
        assert!(authors.contains(&s.key(0)) && authors.contains(&s.key(1)));
    }

    /// A version is known to follow a text where the text's hash is in
    /// the chain of every entry held of the version, and in each every
    /// newer link was signed by a key that counts.
    #[test]
    fn test_a_version_is_known_to_follow_only_if_each_entry_held_of_it_shows_it() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        let keys = [s.key(0), s.key(1), s.key(2)];
        let stranger = Machine::new(9).key();
        let channel = s[0].own("notes");
        let put = |n: usize, file: &str, chain: &[Link]| {
            let entry = entry_by(&s[n].identity, &channel, 5, file, text("the same"), chain);
            holds(&s, 0, &entry);
        };
        let agreed = link("agreed", keys[0]);
        let follows_agreed = |file: &str| {
            read(&s[0].conn, "notes", file)
                .unwrap()
                .follows(&hash("agreed"))
        };

        // One entry, which shows it.
        put(1, "one.md", &[agreed]);
        assert!(follows_agreed("one.md"));
        // Two entries, and each shows it: one through a newer link that a
        // key which counts signed.
        put(1, "both.md", &[agreed]);
        put(2, "both.md", &[link("between", keys[1]), agreed]);
        assert!(follows_agreed("both.md"));
        // Two entries, and one does not show it.
        put(1, "one of two.md", &[agreed]);
        put(2, "one of two.md", &[link("another", keys[0])]);
        assert!(!follows_agreed("one of two.md"));
        // One entry, where a key that does not count signed a version
        // between.
        put(1, "between.md", &[link("between", stranger), agreed]);
        assert!(!follows_agreed("between.md"));
        // An entry with an empty chain, and a slot with no version.
        put(1, "new.md", &[]);
        assert!(!follows_agreed("new.md"));
        assert!(!follows_agreed("none.md"));

        // What a folder agreed can be a delete, which a chain names by
        // zeros.
        put(1, "deleted.md", &[Link::of(&Value::Delete, keys[0])]);
        let deleted = read(&s[0].conn, "notes", "deleted.md").unwrap();
        assert!(deleted.follows(&[0u8; 32]));
        assert!(!follows_agreed("deleted.md"));

        // An entry that lacks its chain shows nothing, and a version with
        // one such entry is known to follow nothing.
        let counting = crate::person::who_counts(&s[0].conn).unwrap();
        let mut version = s[0].slot("notes", "both.md").current.unwrap();
        assert!(follows(&version, &hash("agreed"), &counting));
        version.entries[1].chain = None;
        assert!(!follows(&version, &hash("agreed"), &counting));
        version.entries.clear();
        assert!(!follows(&version, &hash("agreed"), &counting));
    }
}
