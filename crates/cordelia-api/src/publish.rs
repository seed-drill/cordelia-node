//! Publishing in a name a device holds, and reading one (decision
//! 2026-10-04 §2.3, §7.3).
//!
//! Plain functions over the node's database and the device's own key, as
//! [`crate::person`] is. Nothing here sends or fetches anything, and no
//! command, handler or adapter calls it yet.
//!
//! ## Reading
//!
//! [`current`] reads the slot of a file in a name: its current version
//! with every entry that is it, the versions that lost a tie, and the next
//! revision. It is read under the statement the device has applied, with
//! its word on who counts. [`known_to_follow`] says whether that version
//! is known to follow a text: only if each entry held of it shows so.
//!
//! ## Publishing
//!
//! [`publish`] writes a value under a file's name, as this device's own
//! entry, and only over what the caller planned against:
//!
//! - It is made only where the slot's current version is still the one
//!   the caller read: the same value at the same revision
//!   ([`PlannedAgainst`]). Otherwise nothing is written, and it says so.
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
    /// The slot's current version was this one: a value, named by its
    /// hash ([`value_hash`]), at a revision. Two entries that are one
    /// version are one here, whichever of them the caller read.
    Version { rev: u64, hash: [u8; 32] },
}

impl PlannedAgainst {
    /// What a caller that read `slot` plans against.
    pub fn what_is_in(slot: &Slot) -> Self {
        match &slot.current {
            None => Self::NoVersion,
            Some(version) => Self::Version {
                rev: version.rev,
                hash: value_hash(&version.value),
            },
        }
    }

    /// Whether `current` is still what was planned against.
    fn is_still(&self, current: Option<&Version>) -> bool {
        match (self, current) {
            (Self::NoVersion, None) => true,
            (Self::Version { rev, hash }, Some(version)) => {
                version.rev == *rev && value_hash(&version.value) == *hash
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

/// The slot of `file` in the name `name`, which this device holds, as it
/// reads it: under the statement it has applied, with its word on who
/// counts.
///
/// A device that has stopped reads what it holds as any device does: it
/// takes nothing by reading.
pub fn current(conn: &Connection, name: &str, file: &str) -> Result<Slot, PersonError> {
    let standing = Standing::of(conn)?;
    let channel = standing.name_secret(conn, name)?;
    standing.slot(conn, &channel, file)
}

/// Whether the current version of `file` in the name `name` is known to
/// follow the value whose hash is `agreed` ([`value_hash`]): what a
/// folder agreed (decision 2026-10-04 §7.3).
///
/// It is, where the hash is in the chain of every entry that the device
/// holds of the version, and in each every newer link was signed by a key
/// that counts ([`follows`]). A slot that holds no version follows
/// nothing.
pub fn known_to_follow(
    conn: &Connection,
    name: &str,
    file: &str,
    agreed: &[u8; 32],
) -> Result<bool, PersonError> {
    let standing = Standing::of(conn)?;
    let channel = standing.name_secret(conn, name)?;
    let slot = standing.slot(conn, &channel, file)?;
    Ok(slot
        .current
        .is_some_and(|version| follows(&version, agreed, &standing.counting)))
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
