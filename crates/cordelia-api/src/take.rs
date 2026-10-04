//! Taking an entry from outside (decision 2026-10-04 §4.4, §7.5).
//!
//! [`take`] is the one function that an entry from a relay, or from
//! another device, goes through. It is given an entry that passed the
//! check which needs no key, and decides by the entry's channel:
//!
//! - **The personal channel, or the channel of a name this device holds,
//!   in the generation it has applied.** The entry is stored only if its
//!   signer counts (§4.4), and by the store's own rule. A record of an
//!   addition in the personal channel is also taken as a record
//!   ([`crate::person::see_addition`]).
//! - **The phrase's channel.** The entry is shown to the device as a
//!   change entry ([`crate::person::shown`]).
//! - **A channel of a generation it has left, or any other channel.** The
//!   entry is refused, and nothing is stored (§7.5). A pair channel is
//!   among the others: its one entry is read where a person accepts
//!   ([`crate::adding::accept`]), and nowhere else.
//!
//! A device that has stopped, or is in a fork, takes nothing in its own
//! channels (§4.3, §4.5). It still looks at the phrase's channel: that is
//! how a device in a fork is shown the statement that settles it.
//!
//! Each outcome says what it was ([`Taken`]), so that a caller can count
//! and report. An error is this device's, and not the entry's: its
//! database could not be read or written, and nothing was changed.

use rusqlite::Connection;

use cordelia_core::protocol::PERSONAL_ADDED_PREFIX;
use cordelia_core::revision::band;
use cordelia_crypto::addition::{AdditionError, SignedAddition};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_storage::entries::{self, Outcome};
use cordelia_storage::person::{self as held_rows, State};

use crate::person::{
    AdditionSeen, PersonError, Shown, added_name, held, in_one, see_addition, shown, who_counts,
};
use crate::publish::Standing;

/// What became of an entry from outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// It is of a channel of this device's own, in the generation it has
    /// applied, and its signer counts: the store was given it.
    Own {
        /// What the store did with it, by its own rule.
        stored: Outcome,
        /// What it was as a record of an addition, where it is in the
        /// personal channel under a record's name and the store took it.
        record: Option<Record>,
        /// How many keys came to count by it: none for any entry but a
        /// record, and more than one where a record that was kept as not
        /// counted came to count with it.
        came_to_count: usize,
    },
    /// It is of the phrase's channel: it was shown to the device, which
    /// did what a change entry has it do.
    Shown(Shown),
    /// It was refused, and nothing was stored.
    Refused(NotTaken),
}

/// Why an entry from outside was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotTaken {
    /// This device follows no phrase: it has no channel of its own.
    FollowsNoPhrase,
    /// This device has stopped, or is in a fork: it takes nothing in its
    /// own channels.
    Stopped(State),
    /// The key that signed it does not count, as this device knows them
    /// (decision 2026-10-04 §4.4).
    SignerDoesNotCount,
    /// Its revision is in a band above the applied statement's: it counts
    /// for nothing (decision 2026-10-04 §2.3).
    BandAboveTheStatements,
    /// It is of a channel of a generation that this device has left: the
    /// personal channel, or the channel of a name it holds (decision
    /// 2026-10-04 §7.5).
    OldChannel,
    /// It is of no channel that this device takes from.
    AnotherChannel,
}

/// What an entry in the personal channel, under a record's name, was as a
/// record of an addition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// It was taken as a record, and this is what became of it.
    Seen(AdditionSeen),
    /// It was not read as a record. The entry is stored all the same: its
    /// signer counts.
    NotRead(NotRead),
}

/// Why an entry under a record's name was not read as a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotRead {
    /// What it holds is not a record's bytes.
    NotARecord(AdditionError),
    /// It holds a text, or a delete: a record is bytes that are no text.
    NoBytes,
    /// The record is another device's word than the entry's signer's, or
    /// is under another name than that of the key it adds.
    NotItsSigners,
    /// The record does not verify.
    DoesNotVerify(AdditionError),
    /// The record is made under another statement than the one applied.
    UnderAnotherStatement,
}

/// Take an entry from outside (see the module's documentation). `entry`
/// has passed the check that needs no key.
pub fn take(
    conn: &Connection,
    identity: &NodeIdentity,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Taken, PersonError> {
    in_one(conn, || {
        let Some(held) = held(conn)? else {
            return Ok(Taken::Refused(NotTaken::FollowsNoPhrase));
        };
        if entry.channel == held.following.phrase_channel {
            return shown(conn, identity, entry, now).map(Taken::Shown);
        }

        let standing = Standing::of(conn)?;
        let personal = derive::personal_secret(&standing.secret)?;
        let is_personal = entry.channel == derive::channel_id(&personal)?;
        if !is_personal && held_rows::name_of_channel(conn, &entry.channel)?.is_none() {
            return Ok(Taken::Refused(if is_of_a_generation_left(conn, entry)? {
                NotTaken::OldChannel
            } else {
                NotTaken::AnotherChannel
            }));
        }
        if held.state != State::Applied {
            return Ok(Taken::Refused(NotTaken::Stopped(held.state)));
        }
        if !standing.counting.counts(&entry.author) {
            return Ok(Taken::Refused(NotTaken::SignerDoesNotCount));
        }
        if band(entry.rev) > standing.number() {
            return Ok(Taken::Refused(NotTaken::BandAboveTheStatements));
        }

        let stored = entries::store(conn, entry, now)?;
        let mut taken = (None, 0);
        if is_personal && stored == Outcome::Stored {
            taken = record_in(conn, entry, &personal, now)?;
        }
        Ok(Taken::Own {
            stored,
            record: taken.0,
            came_to_count: taken.1,
        })
    })
}

/// Whether `entry` is of a channel of a generation that this device has
/// left and still holds the secret of: that generation's personal
/// channel, or its channel of a name the device holds.
fn is_of_a_generation_left(conn: &Connection, entry: &CheckedEntry) -> Result<bool, PersonError> {
    let names = held_rows::names(conn)?;
    for left in held_rows::secrets(conn)? {
        if left.left_at.is_none() {
            continue;
        }
        let personal = derive::personal_secret(&left.secret)?;
        if derive::channel_id(&personal)? == entry.channel {
            return Ok(true);
        }
        for name in &names {
            let own = derive::own_secret(&left.secret, &name.name)?;
            if derive::channel_id(&own)? == entry.channel {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// What an entry of the personal channel, which the store has just taken,
/// is as a record of an addition (decision 2026-10-04 §6), and how many
/// keys came to count by it. `None` where it is no record: it does not
/// open, or its name is not a record's.
///
/// A record is the word of the device that adds, and is read only from
/// that device's own entry, under the name of the key it adds: the
/// record's adder is the entry's signer, and the entry's name is
/// [`added_name`] of the record's key.
fn record_in(
    conn: &Connection,
    entry: &CheckedEntry,
    personal: &[u8; 32],
    now: i64,
) -> Result<(Option<Record>, usize), PersonError> {
    let Ok(inside) = entry.open(personal) else {
        return Ok((None, 0));
    };
    if !inside.name.starts_with(PERSONAL_ADDED_PREFIX) {
        return Ok((None, 0));
    }
    let not_read = |why: NotRead| Ok((Some(Record::NotRead(why)), 0));
    let Value::Other(bytes) = &inside.value else {
        return not_read(NotRead::NoBytes);
    };
    let record = match SignedAddition::from_bytes(bytes) {
        Ok(record) => record,
        Err(e) => return not_read(NotRead::NotARecord(e)),
    };
    let added = &record.addition;
    if added.adder != entry.author || inside.name != added_name(&added.device.key)? {
        return not_read(NotRead::NotItsSigners);
    }

    let before = who_counts(conn)?.devices();
    let seen = match see_addition(conn, &record, now) {
        Ok(seen) => seen,
        Err(PersonError::Addition(e)) => return not_read(NotRead::DoesNotVerify(e)),
        Err(PersonError::RecordUnderAnotherStatement) => {
            return not_read(NotRead::UnderAnotherStatement);
        }
        Err(e) => return Err(e),
    };
    let came_to_count = who_counts(conn)?.devices() - before;
    Ok((Some(Record::Seen(seen)), came_to_count))
}
