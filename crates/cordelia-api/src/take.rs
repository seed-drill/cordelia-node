//! Taking an entry from outside (decision 2026-10-04 §4.4, §7.5).
//!
//! [`take`] is the one function that an entry from a relay, or from
//! another device, goes through. It is given an entry that passed the
//! check which needs no key, and decides by the entry's channel:
//!
//! - **The personal channel, the channel of a name this device holds, or
//!   the messages channel, in the generation it has applied.** The entry
//!   is stored only if its signer counts (§4.4), and by the store's own
//!   rule. A record of an addition in the personal channel is also taken
//!   as a record ([`crate::person::see_addition`]). An entry of the
//!   messages channel is stored as an entry of any channel of the
//!   person's own is (decision 2026-10-09 §2.1), and what the store keeps
//!   of it the reader reads in the same write ([`crate::reader::taken`]),
//!   which refuses nothing.
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
//!
//! ## What a caller owes it
//!
//! An entry whose signer does not count is refused, and nothing of it is
//! kept. So what a device that is being added wrote is refused where it
//! arrives before the record of that device's addition, and so is a
//! record whose own signer does not count yet. Nothing here remembers
//! them.
//!
//! **Where [`take`] says that a key came to count, or came to may add**
//! (`came_to_count` or `came_to_add` above 0 in [`Taken::Own`]), **the
//! caller gives it again every entry of this device's own channels that
//! it gave before.** What the key that now counts had signed is then
//! taken, and a record among it may let a further key count, which is
//! said in its turn. A record that a key signed before it might add was
//! not counted, and where the device kept nothing of it, it is judged
//! when its entry is given again. A device that does so ends with the
//! same entries, and the same answers, as one that was given the records
//! first. A node does it by reading its channels at its relays again from
//! the start (§16), and does not stop at an entry that it holds already.
//!
//! A record that is not counted may go where the device keeps 256 of
//! them ([`crate::person::see_addition`]). It is then as one never seen,
//! and is judged when its entry is given again, though the store holds
//! the entry already. Nothing here asks for it: it is given again when
//! the caller next gives everything.

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
    AdditionSeen, Counting, PersonError, Shown, added_name, applied_secret, held, in_one,
    see_addition, shown, who_counts,
};

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
        /// And where the store held it already, and the device keeps
        /// nothing of the record in it: one that went at the bound of
        /// records not counted is judged when it is given again.
        record: Option<Record>,
        /// How many keys came to count by it: none for any entry but a
        /// record, and more than one where a record that was kept as not
        /// counted came to count with it.
        ///
        /// Above 0, the caller gives [`take`] again every entry of this
        /// device's own channels that it gave before: what a key that
        /// now counts had signed was refused when it arrived, and was
        /// not kept.
        came_to_count: usize,
        /// How many keys came to may add by it: keys that count, and that
        /// a device of the statement has now added (decision 2026-10-04
        /// §6). None for any entry but a record.
        ///
        /// Above 0, the caller gives everything again as well: a record
        /// that such a key signed before was not counted, and the device
        /// may keep nothing of it.
        came_to_add: usize,
    },
    /// It is of the phrase's channel: it was shown to the device, which
    /// did what a change entry has it do.
    Shown(Shown),
    /// It is of a shared channel this device holds, and passed the door's
    /// checks (decision 2026-10-10 §2.3): the store was given it, with no
    /// check that its signer counts.
    Shared {
        /// What the store did with it, by its own rule.
        stored: Outcome,
        /// What the reader made of it, where the store kept it.
        read: Option<crate::shared::Read>,
    },
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
    /// It is of a shared channel, and sync is off on this device: a shared
    /// channel is turned off as messages are (decision 2026-10-10 §2.3,
    /// rule 2; §6.1).
    SyncOff,
    /// It is of a shared channel, and no honest member writes it: a
    /// delete, an entry in none of the 65 slots named for its author, or
    /// one whose content is not its slot's size (§2.3, rule 3).
    NotAShared,
    /// It is of a shared channel, and its revision is not in the bottom
    /// half of band 0 (§2.3, rule 3).
    NotInBandZero,
    /// It is of a shared channel, and the device has no room for it: a new
    /// slot of a key the person does not know, past the room of all such
    /// keys; or an entry of a key the table let go, at or below what its
    /// row kept (§2.3, rule 4; §6.3).
    SharedFull,
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
///
/// **What the caller owes:** where this returns [`Taken::Own`] with
/// `came_to_count` or `came_to_add` above 0, it gives again every entry
/// of this device's own channels that it gave before. An entry that a key signed before
/// that key counted was refused here and not kept, whichever arrived
/// first: the entries of a device that is being added, and a record that
/// such a device signed.
pub fn take(
    conn: &Connection,
    identity: &NodeIdentity,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Taken, PersonError> {
    let taken = in_one(conn, || {
        let taken = match taken_as_its_own(conn, identity, entry, now)? {
            Some(taken) => Some(taken),
            // Of no channel of the person's own: perhaps of a shared
            // channel, in the same transaction (decision 2026-10-10 §2.3).
            None => crate::shared::taken_as_shared(conn, &identity.public_key(), entry, now)?,
        };
        // Who the person knows may have changed: a statement applied, or a
        // key that came to count. The shared channels follow it (§6.3).
        let knows_anew = matches!(
            &taken,
            Some(Taken::Shown(Shown::Applied(_)))
                | Some(Taken::Own {
                    came_to_count: 1..,
                    ..
                })
        );
        // The person's lists are worked out again, and the device's own
        // written where it changed (§3.4, "What a device writes"), in a
        // write of its own: an error there is logged, and takes back
        // nothing of what was taken, a statement applied among it.
        if knows_anew && let Err(e) = crate::lists::follow(conn, identity, now) {
            tracing::warn!(error = %e, "could not work out the person's lists again");
        }
        Ok(taken)
    })?;
    match taken {
        Some(taken) => Ok(taken),
        // Of no channel that this device takes from: it is refused, and
        // only then is the refusal given its name.
        None => Ok(Taken::Refused(not_its_own(conn, entry)?)),
    }
}

/// What becomes of `entry` where it is of the phrase's channel, or of a
/// channel of this device's own in the generation it has applied, in one
/// transaction. `None` where it is of neither: nothing was done with it,
/// and nothing was derived to say which other channel it is of.
fn taken_as_its_own(
    conn: &Connection,
    identity: &NodeIdentity,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Option<Taken>, PersonError> {
    let Some(held) = held(conn)? else {
        return Ok(Some(Taken::Refused(NotTaken::FollowsNoPhrase)));
    };
    if entry.channel == held.following.phrase_channel {
        let shown = shown(conn, identity, entry, now)?;
        return Ok(Some(Taken::Shown(shown)));
    }

    let statement = &held.statement.statement;
    let secret = applied_secret(conn, statement)?;
    let personal = derive::personal_secret(&secret)?;
    let is_personal = entry.channel == derive::channel_id(&personal)?;
    // The messages channel is a channel of the person's own, beside the
    // personal channel and the channels of names (decision 2026-10-09
    // §2.1): so it is refused where the device does not stand applied,
    // from a signer that does not count, and in a band above the
    // statement's, as they are.
    let is_messages = entry.channel == derive::channel_id(&derive::messages_secret(&secret)?)?;
    if !is_personal && !is_messages && held_rows::name_of_channel(conn, &entry.channel)?.is_none() {
        return Ok(None);
    }
    if held.state != State::Applied {
        return Ok(Some(Taken::Refused(NotTaken::Stopped(held.state))));
    }
    let counting = Counting::of(statement, &held_rows::additions(conn)?);
    if !counting.counts(&entry.author) {
        return Ok(Some(Taken::Refused(NotTaken::SignerDoesNotCount)));
    }
    if band(entry.rev) > statement.number {
        return Ok(Some(Taken::Refused(NotTaken::BandAboveTheStatements)));
    }

    let stored = entries::store(conn, entry, now)?;
    // What the store kept of the messages channel the reader reads in
    // this write (decision 2026-10-09 §7.1): an entry it held already, or
    // one below what it holds, is not read again.
    if is_messages && stored == Outcome::Stored {
        crate::reader::taken(conn, &identity.public_key(), &secret, statement, entry, now)?;
    }
    let mut taken = (None, 0);
    if is_personal && stored != Outcome::OlderThanHeld {
        let again = stored == Outcome::AlreadyHeld;
        taken = record_in(conn, entry, &personal, again, now)?;
    }
    // A device's list stored: this device keeps when it first held each
    // act the list brings (decision 2026-10-10 property 9). An error there
    // is logged, and takes back nothing of the entry.
    if is_personal && stored == Outcome::Stored {
        let own = identity.public_key();
        if let Err(e) = crate::lists::took(conn, &own, entry, &personal, now) {
            tracing::warn!(error = %e, "could not keep when this device took the acts of a list");
        }
    }
    // A record that was taken can let a key add: the one it adds, where
    // a device of the statement signed it. (A record that is not counted
    // can go where the device keeps too many, and with it what let a key
    // add: none came to, then.)
    let came_to_add = match taken.0 {
        Some(Record::Seen(_)) => {
            let may_add = who_counts(conn)?.adders();
            may_add.saturating_sub(counting.adders())
        }
        _ => 0,
    };
    Ok(Some(Taken::Own {
        stored,
        record: taken.0,
        came_to_count: taken.1,
        came_to_add,
    }))
}

/// Why an entry is refused that is of no channel this device takes from:
/// it is of a channel of a generation that was left, or of any other.
///
/// Telling the two apart takes a derivation for each secret the device
/// still holds and each name. It is made after the entry was refused, and
/// outside the transaction that takes an entry: it gives the refusal a
/// name, and decides nothing.
fn not_its_own(conn: &Connection, entry: &CheckedEntry) -> Result<NotTaken, PersonError> {
    Ok(if is_of_a_generation_left(conn, entry)? {
        NotTaken::OldChannel
    } else {
        NotTaken::AnotherChannel
    })
}

/// Whether `entry` is of a channel of a generation that this device has
/// left and still holds the secret of: that generation's personal
/// channel, its messages channel, or its channel of a name the device
/// holds.
fn is_of_a_generation_left(conn: &Connection, entry: &CheckedEntry) -> Result<bool, PersonError> {
    let names = held_rows::names(conn)?;
    for left in held_rows::secrets(conn)? {
        if left.left_at.is_none() {
            continue;
        }
        let personal = derive::personal_secret(&left.secret)?;
        let messages = derive::messages_secret(&left.secret)?;
        for secret in [personal, messages] {
            if derive::channel_id(&secret)? == entry.channel {
                return Ok(true);
            }
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

/// What an entry of the personal channel is as a record of an addition
/// (decision 2026-10-04 §6), and how many keys came to count by it.
/// `None` where it is no record: it does not open, or its name is not a
/// record's.
///
/// A record is the word of the device that adds, and is read only from
/// that device's own entry, under the name of the key it adds: the
/// record's adder is the entry's signer, and the entry's name is
/// [`added_name`] of the record's key.
///
/// `again` says that the store did not take the entry now, and holds one
/// from that signer there at that revision. An entry is read when the
/// store takes it, and a record that the device keeps from it says no
/// more when the entry is given again. But a record that is not counted
/// goes where the device keeps too many, and is then as one never seen:
/// the entry is read again where it is the very entry the store holds,
/// and the device keeps nothing of its record. Whatever else an entry
/// given again is, it was that when the store took it: `None`.
fn record_in(
    conn: &Connection,
    entry: &CheckedEntry,
    personal: &[u8; 32],
    again: bool,
    now: i64,
) -> Result<(Option<Record>, usize), PersonError> {
    let Ok(inside) = entry.open(personal) else {
        return Ok((None, 0));
    };
    if !inside.name.starts_with(PERSONAL_ADDED_PREFIX) {
        return Ok((None, 0));
    }
    let not_read = |why: NotRead| Ok(((!again).then_some(Record::NotRead(why)), 0));
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
    if again && (is_kept(conn, &record)? || !is_the_entry_held(conn, entry)?) {
        return Ok((None, 0));
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

/// Whether the device keeps `record`, counted or not.
fn is_kept(conn: &Connection, record: &SignedAddition) -> Result<bool, PersonError> {
    let bytes = record.to_bytes()?;
    let kept = held_rows::additions(conn)?;
    Ok(kept.iter().any(|one| one.record == bytes))
}

/// Whether `entry` is the very entry that the store holds from its signer
/// in its slot. The store answers that it holds one already for another
/// entry too, which that signer signed at the same revision: what such a
/// one says is not read.
fn is_the_entry_held(conn: &Connection, entry: &CheckedEntry) -> Result<bool, PersonError> {
    let held = entries::author_entry(conn, &entry.channel, &entry.slot, &entry.author)?;
    Ok(held.is_some_and(|held| held.entry == **entry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::person::{NotCounted, Refused};
    use crate::several::{Machine, Several, entry_by, identity_of, listed_as, signed_in, text};
    use cordelia_core::protocol::{
        HAND_OVER_NAME, MAX_NOT_COUNTED_RECORDS, REV_BAND_HALF, REV_BAND_SIZE, REV_COUNT_BITS,
    };
    use cordelia_crypto::addition::Addition;
    use cordelia_crypto::change_entry::{self, ChangeEntryError};
    use cordelia_crypto::statement::Link as StatementLink;

    /// An ordinary entry that the store took.
    const STORED: Taken = Taken::Own {
        stored: Outcome::Stored,
        record: None,
        came_to_count: 0,
        came_to_add: 0,
    };

    /// An entry that the store held already, and that says no more.
    const HELD: Taken = Taken::Own {
        stored: Outcome::AlreadyHeld,
        record: None,
        came_to_count: 0,
        came_to_add: 0,
    };

    /// The revision at `count` in `band`.
    fn at(band: u64, count: u64) -> u64 {
        (band << REV_COUNT_BITS) + count
    }

    /// Two devices of one person, each holding the name `notes`.
    fn two() -> Several {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        s
    }

    /// Device `n` is given `entry`.
    fn given(s: &Several, n: usize, entry: &CheckedEntry) -> Taken {
        let on = &s[n];
        take(&on.conn, &on.identity, entry, s.now).unwrap()
    }

    /// The record that `adder` adds `new`, under the statement that
    /// device `n` has applied, signed by the adder.
    fn record(s: &Several, n: usize, adder: &Machine, new: &Machine) -> SignedAddition {
        let statement = s[n].held().statement.statement;
        Addition::under(&statement, new.listed(), adder.key(), s.now as u64)
            .unwrap()
            .sign(&adder.identity)
            .unwrap()
    }

    /// The entry of `record` in the personal channel of device `n`, as
    /// the device that adds writes it.
    fn record_entry(
        s: &Several,
        n: usize,
        adder: &Machine,
        record: &SignedAddition,
    ) -> CheckedEntry {
        entry_by(
            &adder.identity,
            &s[n].personal(),
            1,
            &added_name(&record.addition.device.key).unwrap(),
            Value::Other(record.to_bytes().unwrap()),
            &[],
        )
    }

    /// An entry of a name that this device holds, in the generation it
    /// has applied, is stored only if its signer counts: and then by the
    /// store's own rule, whatever the entry says.
    #[test]
    fn test_an_entry_of_a_name_held_is_stored_only_if_its_signer_counts() {
        let s = two();
        let channel = s[0].own("notes");
        let by = |author: &NodeIdentity, rev: u64, file: &str, said: &str| {
            entry_by(author, &channel, rev, file, text(said), &[])
        };

        let first = by(&s[1].identity, 5, "a.md", "by a device that counts");
        assert_eq!(given(&s, 0, &first), STORED);
        assert_eq!(s[0].stored_in(&channel), std::slice::from_ref(&first));
        assert_eq!(
            s[0].text("notes", "a.md").as_deref(),
            Some("by a device that counts")
        );
        // What the store says of it is given back: the entry it holds, and
        // one below it.
        let held = |stored: Outcome| Taken::Own {
            stored,
            record: None,
            came_to_count: 0,
            came_to_add: 0,
        };
        assert_eq!(given(&s, 0, &first), held(Outcome::AlreadyHeld));
        let older = by(&s[1].identity, 4, "a.md", "older");
        assert_eq!(given(&s, 0, &older), held(Outcome::OlderThanHeld));
        assert_eq!(s[0].stored_in(&channel), std::slice::from_ref(&first));

        // A key that does not count: nothing is stored.
        let stranger = Machine::new(9);
        let before = s[0].everything();
        let late = by(&stranger.identity, 9, "a.md", "by a stranger");
        assert_eq!(
            given(&s, 0, &late),
            Taken::Refused(NotTaken::SignerDoesNotCount)
        );
        assert_eq!(s[0].everything(), before);

        // An entry that does not open is stored where its signer counts:
        // it is no version, and the next revision is above it.
        let slot = first.slot;
        let elsewhere = entry_by(&s[1].identity, &[0xee; 32], 8, "a.md", text("x"), &[]);
        let unread = signed_in(&channel, &s[1].identity, slot, 8, elsewhere.content.clone());
        assert_eq!(given(&s, 0, &unread), STORED);
        assert_eq!(s[0].slot("notes", "a.md").next, Some(9));

        // This device's own entry, come back to it: it counts for itself.
        let own = by(&s[0].identity, 3, "b.md", "its own");
        assert_eq!(given(&s, 0, &own), STORED);
    }

    /// A record of an addition in the personal channel is stored as any
    /// entry is, and is also taken as a record: the key it adds counts.
    #[test]
    fn test_a_record_in_the_personal_channel_is_also_taken_as_a_record() {
        let mut s = Several::of_one_person(2);
        let new = Machine::new(7);
        // Device 0 adds a device, and device 1 is given what it wrote.
        let now = s.tick();
        let added = add_device_on(&s, 0, &new, now);
        assert!(!s[1].counts(&new.key()));
        assert_eq!(
            given(&s, 1, &added),
            Taken::Own {
                stored: Outcome::Stored,
                record: Some(Record::Seen(AdditionSeen::Counted)),
                came_to_count: 1,
                came_to_add: 1,
            }
        );
        assert!(s[1].counts(&new.key()));
        assert_eq!(held_rows::additions(&s[1].conn).unwrap().len(), 2);
        // Given again, the store holds it, and nothing is seen again.
        assert_eq!(
            given(&s, 1, &added),
            Taken::Own {
                stored: Outcome::AlreadyHeld,
                record: None,
                came_to_count: 0,
                came_to_add: 0,
            }
        );

        // Any other entry of the personal channel is stored, and is no
        // record: under another name, and one that does not open.
        let personal = s[1].personal();
        let word = entry_by(&s[0].identity, &personal, 1, "syncing", text("notes"), &[]);
        assert_eq!(given(&s, 1, &word), STORED);
        let elsewhere = entry_by(&s[0].identity, &[0xee; 32], 3, "added/x", text("x"), &[]);
        let unread = signed_in(
            &personal,
            &s[0].identity,
            [7; 32],
            3,
            elsewhere.content.clone(),
        );
        assert_eq!(given(&s, 1, &unread), STORED);
        // What the new device signs is taken from now on.
        let theirs = entry_by(&new.identity, &personal, 1, "syncing", text("notes"), &[]);
        assert_eq!(given(&s, 1, &theirs), STORED);
    }

    /// The entry that device `n` writes in its personal channel when it
    /// adds `new`.
    fn add_device_on(s: &Several, n: usize, new: &Machine, now: i64) -> CheckedEntry {
        let on = &s[n];
        crate::adding::add_device(&on.conn, &on.identity, &new.key(), &new.label, now)
            .unwrap()
            .record
            .unwrap()
    }

    /// A record that is taken can let a record count that was kept as not
    /// counted: the outcome says how many keys came to count by it.
    #[test]
    fn test_a_record_says_how_many_keys_came_to_count_by_it() {
        let s = Several::of_one_person(2);
        let (a, b, c) = (Machine::new(7), Machine::new(8), Machine::new(9));
        let listed = Machine::new(0);
        let seen = |adder: &Machine, new: &Machine| {
            let record = record(&s, 1, adder, new);
            given(&s, 1, &record_entry(&s, 1, adder, &record))
        };
        let taken = |seen: AdditionSeen, came_to_count: usize, came_to_add: usize| Taken::Own {
            stored: Outcome::Stored,
            record: Some(Record::Seen(seen)),
            came_to_count,
            came_to_add,
        };

        // A device of the statement adds a: it counts, and may add.
        assert_eq!(seen(&listed, &a), taken(AdditionSeen::Counted, 1, 1));
        // Device a adds b: it counts, and may not add.
        assert_eq!(seen(&a, &b), taken(AdditionSeen::Counted, 1, 0));
        // Device b was added by a device added since: it may not add.
        let may_not = AdditionSeen::NotCounted(NotCounted::MayNotAdd);
        assert_eq!(seen(&b, &c), taken(may_not, 0, 0));
        assert!(!s[1].counts(&c.key()));
        // A device of the statement adds b too: b counts already, and
        // comes to may add. The record that b signed comes to count with
        // this one, and the key it adds may not add.
        let already = AdditionSeen::NotCounted(NotCounted::CountsAlready);
        assert_eq!(seen(&listed, &b), taken(already, 1, 1));
        assert!(s[1].counts(&c.key()));
        // The same record from another device of the statement's word
        // changes nothing more: no key comes to count, or to may add.
        assert_eq!(who_counts(&s[1].conn).unwrap().adders(), 4);
    }

    /// A record is the word of the device that adds: it is read only from
    /// that device's own entry, under the name of the key it adds, and
    /// only where it verifies and is under the statement applied. The
    /// entry is stored all the same, and no key comes to count.
    #[test]
    fn test_a_record_is_read_only_from_its_signers_own_entry_under_its_keys_name() {
        let s = Several::of_one_person(2);
        let personal = s[1].personal();
        let (listed, other, new) = (Machine::new(0), Machine::new(1), Machine::new(7));
        let good = record(&s, 1, &listed, &new);
        let name = added_name(&new.key()).unwrap();
        let not_read = |entry: &CheckedEntry| match given(&s, 1, entry) {
            Taken::Own {
                stored: Outcome::Stored,
                record: Some(Record::NotRead(why)),
                came_to_count: 0,
                came_to_add: 0,
            } => why,
            other => panic!("{other:?}"),
        };
        let holding = |author: &Machine, rev: u64, name: &str, value: Value| {
            entry_by(&author.identity, &personal, rev, name, value, &[])
        };
        let bytes = |record: &SignedAddition| Value::Other(record.to_bytes().unwrap());

        // Another device's entry that holds device 0's record.
        let relayed = holding(&other, 1, &name, bytes(&good));
        assert_eq!(not_read(&relayed), NotRead::NotItsSigners);
        // The adder's own entry, under the name of another key.
        let elsewhere = added_name(&Machine::new(8).key()).unwrap();
        let misnamed = holding(&listed, 1, &elsewhere, bytes(&good));
        assert_eq!(not_read(&misnamed), NotRead::NotItsSigners);
        // A text, and bytes that are no record.
        let a_text = holding(&listed, 1, "added/a text", text("a record"));
        assert_eq!(not_read(&a_text), NotRead::NoBytes);
        let no_record = holding(&listed, 1, "added/bytes", Value::Other(vec![1, 2, 3]));
        assert!(matches!(not_read(&no_record), NotRead::NotARecord(_)));
        // A record that does not verify.
        let mut forged = good.clone();
        forged.signature[0] ^= 1;
        let unverified = holding(&listed, 2, &name, bytes(&forged));
        assert_eq!(
            not_read(&unverified),
            NotRead::DoesNotVerify(AdditionError::Signature)
        );
        // A record under another statement than the one applied.
        let mut apart = good.addition.clone();
        apart.under = StatementLink {
            number: 1,
            hash: [9; 16],
        };
        let apart = apart.sign(&listed.identity).unwrap();
        let under_another = holding(&listed, 3, &name, bytes(&apart));
        assert_eq!(not_read(&under_another), NotRead::UnderAnotherStatement);

        assert!(!s[1].counts(&new.key()));
        assert_eq!(held_rows::additions(&s[1].conn).unwrap().len(), 1);

        // The control: the adder's own entry, under the key's name.
        let own = holding(&listed, 4, &name, bytes(&good));
        assert_eq!(
            given(&s, 1, &own),
            Taken::Own {
                stored: Outcome::Stored,
                record: Some(Record::Seen(AdditionSeen::Counted)),
                came_to_count: 1,
                came_to_add: 1,
            }
        );
        assert!(s[1].counts(&new.key()));
    }

    /// An entry that is given again is read as a record only where it is
    /// the very entry the store holds. The store answers that it holds
    /// one already for another entry that its signer signed at that
    /// revision: what that one says is not read.
    #[test]
    fn test_an_entry_given_again_is_read_only_where_it_is_the_one_the_store_holds() {
        let s = Several::of_one_person(2);
        let personal = s[1].personal();
        let (listed, new) = (Machine::new(0), Machine::new(7));
        let name = added_name(&new.key()).unwrap();
        let good = Value::Other(record(&s, 1, &listed, &new).to_bytes().unwrap());
        let holding =
            |rev: u64, value: Value| entry_by(&listed.identity, &personal, rev, &name, value, &[]);

        // Device 0 signs two entries at one revision, under the name of
        // the key: a text, which the store takes, and a record.
        let a_text = holding(1, text("no record"));
        assert_eq!(
            given(&s, 1, &a_text),
            Taken::Own {
                stored: Outcome::Stored,
                record: Some(Record::NotRead(NotRead::NoBytes)),
                came_to_count: 0,
                came_to_add: 0,
            }
        );
        // Given again, it is what it was when the store took it, and
        // says no more.
        assert_eq!(given(&s, 1, &a_text), HELD);
        // The record at that revision: the store holds one there, which
        // is not this entry. It is not read, though the device keeps
        // nothing of the record.
        assert_eq!(given(&s, 1, &holding(1, good.clone())), HELD);
        assert!(!s[1].counts(&new.key()));
        assert_eq!(held_rows::additions(&s[1].conn).unwrap().len(), 1);

        // The control: at the next revision the store takes it, and the
        // record is read.
        assert_eq!(
            given(&s, 1, &holding(2, good.clone())),
            Taken::Own {
                stored: Outcome::Stored,
                record: Some(Record::Seen(AdditionSeen::Counted)),
                came_to_count: 1,
                came_to_add: 1,
            }
        );
        // An entry below the one that the store holds is not read at all.
        assert_eq!(
            given(&s, 1, &holding(1, good)),
            Taken::Own {
                stored: Outcome::OlderThanHeld,
                record: None,
                came_to_count: 0,
                came_to_add: 0,
            }
        );
    }

    /// A device keeps at most 256 records that are not counted, and a
    /// device that counts can sign any number of them. The record by
    /// which a device of the statement lets a key add is not among those
    /// that go: no flood takes from a key that it may add. What goes goes
    /// by the order of keeping (decision 2026-10-17 §2.2): the flood's
    /// own last record, and not another adder's.
    ///
    /// A record that did go is as one never seen. It is judged when its
    /// entry is given again, though the store holds the entry already.
    #[test]
    fn test_a_flood_of_records_drops_none_that_lets_a_key_add() {
        const COUNTED: AdditionSeen = AdditionSeen::Counted;
        const ALREADY: AdditionSeen = AdditionSeen::NotCounted(NotCounted::CountsAlready);
        const MAY_NOT: AdditionSeen = AdditionSeen::NotCounted(NotCounted::MayNotAdd);

        // Device 1 is given everything. The statement lists device 0,
        // which added device 1.
        let s = Several::of_one_person(2);
        let on = &s[1];
        let statement = on.held().statement.statement;
        let personal = on.personal();
        // The entry in which device `adder` adds device `new`.
        let adds = |adder: u16, new: u16| {
            let by = identity_of(adder);
            let record = Addition::under(&statement, listed_as(new), by.public_key(), 1)
                .unwrap()
                .sign(&by)
                .unwrap();
            let name = added_name(&record.addition.device.key).unwrap();
            let value = Value::Other(record.to_bytes().unwrap());
            entry_by(&by, &personal, 1, &name, value, &[])
        };
        // What the store did with an entry that device 1 is given, what
        // the record in it was, and how many keys came to count by it,
        // and to may add.
        let taken = |entry: &CheckedEntry| match given(&s, 1, entry) {
            Taken::Own {
                stored,
                record,
                came_to_count,
                came_to_add,
            } => (stored, record, (came_to_count, came_to_add)),
            other => panic!("{other:?}"),
        };
        // `came` keys came to count, and none to may add.
        let stored = |seen: AdditionSeen, came: usize| {
            (Outcome::Stored, Some(Record::Seen(seen)), (came, 0))
        };
        // No key came to count, and one to may add.
        let lets_add = (Outcome::Stored, Some(Record::Seen(ALREADY)), (0, 1));
        let again = |seen: AdditionSeen, came: usize| {
            (Outcome::AlreadyHeld, Some(Record::Seen(seen)), (came, 0))
        };
        let says_no_more = (Outcome::AlreadyHeld, None, (0, 0));
        let keeps = |entry: &CheckedEntry| {
            let Value::Other(record) = entry.open(&personal).unwrap().value else {
                panic!("a record is bytes");
            };
            let kept = held_rows::additions(&on.conn).unwrap();
            kept.iter().any(|one| one.record == record)
        };
        let not_counted = || {
            let kept = held_rows::additions(&on.conn).unwrap();
            kept.iter().filter(|one| !one.counted).count()
        };
        let may_add = |n: u16| {
            let counting = who_counts(&on.conn).unwrap();
            counting.may_add(&identity_of(n).public_key())
        };

        // Device 1, which was added since the statement, adds device 8:
        // it counts, and may not add. Device 0 adds it too: now it may.
        assert_eq!(taken(&adds(1, 8)), stored(COUNTED, 1));
        assert!(!may_add(8));
        let lets_8_add = adds(0, 8);
        assert_eq!(taken(&lets_8_add), lets_add);
        assert!(may_add(8));
        // Device 8 adds devices 9 and 10, which count and may not add:
        // what they sign is kept as not counted.
        assert_eq!(taken(&adds(8, 9)), stored(COUNTED, 1));
        assert_eq!(taken(&adds(8, 10)), stored(COUNTED, 1));

        // A flood of 256 such records: one by device 9, and 255 by
        // device 10. With the one that lets device 8 add, that is one
        // more than the device keeps.
        let by_9 = adds(9, 11);
        assert_eq!(taken(&by_9), stored(MAY_NOT, 0));
        let by_10: Vec<CheckedEntry> = (0..255).map(|n| adds(10, 1000 + n)).collect();
        for entry in &by_10 {
            assert_eq!(taken(entry), stored(MAY_NOT, 0));
        }
        assert_eq!(not_counted(), MAX_NOT_COUNTED_RECORDS);
        // The two adders are dealt their keys in turn, so device 9's one
        // record is in the first turn. Each record says the same time, so
        // device 10's keys are in order of key, and the one that went is
        // its last. The record that lets device 8 add stays.
        let last = (0..255u16)
            .max_by_key(|n| identity_of(1000 + n).public_key())
            .unwrap() as usize;
        assert!(keeps(&lets_8_add) && keeps(&by_9) && !keeps(&by_10[last]));
        let others = by_10.iter().enumerate().filter(|(n, _)| *n != last);
        assert!(others.map(|(_, entry)| entry).all(keeps));
        assert!(may_add(8));
        // What device 8 signs next counts.
        assert_eq!(taken(&adds(8, 12)), stored(COUNTED, 1));

        // Device 0 adds device 9 too: it may add from now on. The record
        // by device 9 that is kept comes to count, which makes room for
        // this one, and nothing goes. That a key came to count, or to may
        // add, is what says the caller is to give everything again.
        assert_eq!(
            taken(&adds(0, 9)),
            (Outcome::Stored, Some(Record::Seen(ALREADY)), (1, 1))
        );
        assert!(may_add(9));
        assert!(
            who_counts(&on.conn)
                .unwrap()
                .counts(&identity_of(11).public_key())
        );
        assert_eq!(not_counted(), MAX_NOT_COUNTED_RECORDS);

        // The record by device 10 that went is given again. The store
        // holds its entry already, and it is judged as a record never
        // seen: it does not count, and is the last in the order again, so
        // it goes again, and the others stay.
        assert_eq!(taken(&by_10[last]), again(MAY_NOT, 0));
        assert!(!keeps(&by_10[last]) && keeps(&by_10[0]));
        assert_eq!(not_counted(), MAX_NOT_COUNTED_RECORDS);
        // A record that the device keeps says no more when its entry is
        // given again: one that counts, and two that do not.
        for kept in [&by_9, &lets_8_add, &by_10[2]] {
            assert_eq!(taken(kept), says_no_more);
        }
    }

    /// A record that went at the bound comes to count when its entry is
    /// given again through the door, where its adder has come to add since
    /// and there is room (decision 2026-10-17 §2.7). Twenty keys that may
    /// not add yet each sign 13 records: 260, four more than the device
    /// keeps, and the four that go are the last turn of the four adders
    /// last by key. The last of them then comes to add.
    #[test]
    fn test_a_record_that_went_at_the_bound_counts_when_its_entry_is_given_again() {
        const MAY_NOT: AdditionSeen = AdditionSeen::NotCounted(NotCounted::MayNotAdd);
        // Device 1 is given everything. The statement lists device 0,
        // which added device 1.
        let s = Several::of_one_person(2);
        let on = &s[1];
        let statement = on.held().statement.statement;
        let personal = on.personal();
        let adds = |adder: u16, new: u16| {
            let by = identity_of(adder);
            let record = Addition::under(&statement, listed_as(new), by.public_key(), 1)
                .unwrap()
                .sign(&by)
                .unwrap();
            let name = added_name(&record.addition.device.key).unwrap();
            let value = Value::Other(record.to_bytes().unwrap());
            entry_by(&by, &personal, 1, &name, value, &[])
        };
        let seen = |entry: &CheckedEntry| match given(&s, 1, entry) {
            Taken::Own {
                record: Some(Record::Seen(seen)),
                came_to_count,
                ..
            } => (seen, came_to_count),
            other => panic!("{other:?}"),
        };
        let keeps = |entry: &CheckedEntry| {
            let Value::Other(record) = entry.open(&personal).unwrap().value else {
                panic!("a record is bytes");
            };
            let kept = held_rows::additions(&on.conn).unwrap();
            kept.iter().any(|one| one.record == record)
        };
        let key_of = |n: u16| identity_of(n).public_key();

        // Device 1, added since, adds keys 10 to 29: they count, and may
        // not add. 22 count, and there is room for 42 more.
        let adders: Vec<u16> = (10..30).collect();
        for adder in &adders {
            assert_eq!(seen(&adds(1, *adder)).0, AdditionSeen::Counted);
        }
        // Each adder's entries, as they were given: an entry is sealed
        // anew each time it is made.
        let of: Vec<Vec<CheckedEntry>> = adders
            .iter()
            .map(|adder| {
                (0..13)
                    .map(|n| adds(*adder, 1000 + 13 * (adder - 10) + n))
                    .collect()
            })
            .collect();
        for entry in of.iter().flatten() {
            assert_eq!(seen(entry), (MAY_NOT, 0));
        }
        assert_eq!(
            held_rows::additions(&on.conn)
                .unwrap()
                .iter()
                .filter(|one| !one.counted)
                .count(),
            MAX_NOT_COUNTED_RECORDS
        );
        // The adder last by key, and its key last by key: the record that
        // went last.
        let last = *adders.iter().max_by_key(|n| key_of(**n)).unwrap();
        let mut its = of[(last - 10) as usize].clone();
        its.sort_by_key(|entry| {
            let Value::Other(record) = entry.open(&personal).unwrap().value else {
                panic!("a record is bytes");
            };
            SignedAddition::from_bytes(&record)
                .unwrap()
                .addition
                .device
                .key
        });
        let (went, stayed) = its.split_last().unwrap();
        assert!(!keeps(went) && stayed.iter().all(keeps));

        // Device 0 adds it too: it may add, and its twelve that were kept
        // come to count.
        assert_eq!(seen(&adds(0, last)).1, 12);
        // The record that went is given again: the store holds its entry
        // already, and it is judged as a record never seen. It counts.
        assert_eq!(
            given(&s, 1, went),
            Taken::Own {
                stored: Outcome::AlreadyHeld,
                record: Some(Record::Seen(AdditionSeen::Counted)),
                came_to_count: 1,
                came_to_add: 0,
            }
        );
        assert!(keeps(went));
        let counting = who_counts(&on.conn).unwrap();
        let went_adds = {
            let Value::Other(record) = went.open(&personal).unwrap().value else {
                panic!("a record is bytes");
            };
            SignedAddition::from_bytes(&record)
                .unwrap()
                .addition
                .device
                .key
        };
        assert!(counting.counts(&went_adds));
    }

    /// An entry of the phrase's channel is shown to the device, which
    /// does with it what a change entry has it do.
    #[test]
    fn test_an_entry_of_the_phrases_channel_is_shown() {
        let mut s = two();
        s.write(1, "notes", "a.md", "one");
        let change = s.change(0, &[0, 1], &[]);
        let before = s[1].latest();
        assert_eq!(given(&s, 1, &before), Taken::Shown(Shown::Held));

        // An entry of that channel that the phrase's key did not write.
        let channel = s.phrase.channel_secret().unwrap();
        let slot = change_entry::slot(&derive::channel_id(&channel).unwrap());
        let forged = signed_in(&channel, &s[0].identity, slot, 2, change.content.clone());
        let stood = s[1].everything();
        assert_eq!(
            given(&s, 1, &forged),
            Taken::Shown(Shown::Refused(Refused::NotAChangeEntry(
                ChangeEntryError::AnotherAuthor
            )))
        );
        assert_eq!(s[1].everything(), stood);

        // The change entry: it is applied, in the same step.
        assert!(matches!(
            given(&s, 1, &change),
            Taken::Shown(Shown::Applied(crate::person::Applied {
                number: 2,
                left: Some(1),
                carried: 1,
                ..
            }))
        ));
        assert_eq!(s[1].number(), 2);
        assert_eq!(given(&s, 1, &change), Taken::Shown(Shown::Held));
        assert_eq!(given(&s, 1, &before), Taken::Shown(Shown::Behind));
    }

    /// An entry of a channel of a generation that the device has left is
    /// refused, and so is one of any other channel. Nothing is stored.
    #[test]
    fn test_an_entry_of_a_generation_that_was_left_or_of_another_channel_is_refused() {
        let mut s = two();
        let old = (s[1].personal(), s[1].own("notes"), s[1].secret());
        let change = s.change(0, &[0, 1], &[]);
        assert!(matches!(
            given(&s, 1, &change),
            Taken::Shown(Shown::Applied(_))
        ));
        let new = (s[1].personal(), s[1].own("notes"));
        let by = |channel: &[u8; 32], name: &str| {
            entry_by(
                &s[0].identity,
                channel,
                7,
                name,
                text("by a device that counts"),
                &[],
            )
        };
        let before = s[1].everything();

        // The channels it left: the personal channel, and that of a name
        // it holds.
        for channel in [&old.0, &old.1] {
            assert_eq!(
                given(&s, 1, &by(channel, "a.md")),
                Taken::Refused(NotTaken::OldChannel)
            );
        }
        // A channel of a name it does not hold, in either generation; a
        // pair channel; and a channel that is nobody's.
        let other_name = [
            derive::own_secret(&old.2, "other").unwrap(),
            derive::own_secret(&s[1].secret(), "other").unwrap(),
        ];
        let pair = derive::pair_secret(&s[0].identity, &s.key(1)).unwrap();
        for channel in [&other_name[0], &other_name[1], &[0x33; 32]] {
            assert_eq!(
                given(&s, 1, &by(channel, "a.md")),
                Taken::Refused(NotTaken::AnotherChannel)
            );
        }
        assert_eq!(
            given(&s, 1, &by(&pair, HAND_OVER_NAME)),
            Taken::Refused(NotTaken::AnotherChannel)
        );
        assert_eq!(s[1].everything(), before);

        // The control: the same entries, in the channels of the
        // generation it has applied.
        for channel in [&new.0, &new.1] {
            assert_eq!(given(&s, 1, &by(channel, "a.md")), STORED);
        }

        // Once a secret that was left is forgotten, its channels are
        // channels like any other: refused all the same.
        let later = s.now + 91 * 24 * 60 * 60;
        assert_eq!(
            held_rows::forget_left_secrets(&s[1].conn, later).unwrap(),
            1
        );
        assert_eq!(
            given(&s, 1, &by(&old.1, "a.md")),
            Taken::Refused(NotTaken::AnotherChannel)
        );
    }

    /// The messages channel is a channel of the person's own (decision
    /// 2026-10-09 §2.1): an entry of it in the generation applied is
    /// stored where its signer counts, whatever it holds and whether or
    /// not sync is on. It is refused from a signer that does not count, in
    /// a band above the statement's, on a device that has stopped, and in
    /// a generation that was left.
    #[test]
    fn test_the_door_takes_the_messages_channel_as_a_channel_of_the_persons_own() {
        let mut s = two();
        let number = s[1].number();
        let messages = |on: &Machine| derive::messages_secret(&on.secret()).unwrap();
        let old = messages(&s[1]);
        // Message 1 of `author`, in its slot, at revision 2: the door does
        // not read what it holds.
        let message = |author: &NodeIdentity, channel: &[u8; 32], rev: u64| {
            let name = cordelia_crypto::message::message_name(&author.public_key(), 1).unwrap();
            let value = Value::Other(cordelia_crypto::message::clearing_value());
            entry_by(author, channel, rev, &name, value, &[])
        };

        let first = message(&s[0].identity, &old, 2);
        assert_eq!(given(&s, 1, &first), STORED);
        assert_eq!(s[1].stored_in(&old), std::slice::from_ref(&first));

        let before = s[1].everything();
        let stranger = Machine::new(9);
        assert_eq!(
            given(&s, 1, &message(&stranger.identity, &old, 2)),
            Taken::Refused(NotTaken::SignerDoesNotCount)
        );
        assert_eq!(
            given(&s, 1, &message(&s[0].identity, &old, at(number + 1, 4))),
            Taken::Refused(NotTaken::BandAboveTheStatements)
        );
        held_rows::set_state(&s[1].conn, State::Removed).unwrap();
        assert_eq!(
            given(&s, 1, &message(&s[0].identity, &old, 4)),
            Taken::Refused(NotTaken::Stopped(State::Removed))
        );
        held_rows::set_state(&s[1].conn, State::Applied).unwrap();
        assert_eq!(s[1].everything(), before);

        // A statement: the messages channel of the generation left is
        // refused as an old channel, and the new one is taken.
        let change = s.change(0, &[0, 1], &[]);
        assert!(matches!(
            given(&s, 1, &change),
            Taken::Shown(Shown::Applied(_))
        ));
        let new = messages(&s[1]);
        assert_ne!(new, old);
        assert_eq!(
            given(&s, 1, &message(&s[0].identity, &old, 4)),
            Taken::Refused(NotTaken::OldChannel)
        );
        assert_eq!(given(&s, 1, &message(&s[0].identity, &new, 2)), STORED);
    }

    /// A device that has stopped takes nothing in its own channels: it
    /// was removed, is in no list, could not open a change, or is in a
    /// fork. It still looks at the phrase's channel.
    #[test]
    fn test_a_device_that_has_stopped_takes_nothing_in_its_own_channels() {
        let mut s = two();
        s.write(0, "notes", "a.md", "one");
        let in_notes = entry_by(
            &s[0].identity,
            &s[1].own("notes"),
            2,
            "a.md",
            text("two"),
            &[],
        );
        let in_personal = entry_by(
            &s[0].identity,
            &s[1].personal(),
            1,
            "syncing",
            text("n"),
            &[],
        );
        let change = s.change(0, &[0, 1], &[]);

        for state in [
            State::Fork,
            State::Removed,
            State::NotListed,
            State::NotOpened,
        ] {
            held_rows::set_state(&s[1].conn, state).unwrap();
            let before = s[1].everything();
            for entry in [&in_notes, &in_personal] {
                assert_eq!(
                    given(&s, 1, entry),
                    Taken::Refused(NotTaken::Stopped(state)),
                    "{state:?}"
                );
            }
            // An entry of another channel is refused as that.
            let elsewhere = entry_by(&s[0].identity, &[0x33; 32], 1, "a.md", text("x"), &[]);
            assert_eq!(
                given(&s, 1, &elsewhere),
                Taken::Refused(NotTaken::AnotherChannel)
            );
            assert_eq!(s[1].everything(), before, "{state:?}");
        }
        // It still looks at the phrase's channel: there it is told that
        // the way on is a person's.
        held_rows::set_state(&s[1].conn, State::Removed).unwrap();
        assert_eq!(
            given(&s, 1, &change),
            Taken::Shown(Shown::Refused(Refused::Stopped))
        );

        // The control: it has not stopped, and takes each.
        held_rows::set_state(&s[1].conn, State::Applied).unwrap();
        for entry in [&in_notes, &in_personal] {
            assert_eq!(given(&s, 1, entry), STORED);
        }
    }

    #[test]
    fn test_a_device_that_follows_no_phrase_takes_nothing() {
        let mut s = two();
        let new = Machine::new(7);
        s.write(0, "notes", "a.md", "one");
        // An entry of each kind of channel: the personal channel, that of
        // a name, the phrase's, and the pair channel of the two.
        let mut given_it = s[0].stored();
        given_it.push(s[0].latest());
        let pair = derive::pair_secret(&s[0].identity, &new.key()).unwrap();
        given_it.push(entry_by(
            &s[0].identity,
            &pair,
            1,
            HAND_OVER_NAME,
            text("x"),
            &[],
        ));
        assert!(given_it.len() >= 5);
        for entry in &given_it {
            assert_eq!(
                take(&new.conn, &new.identity, entry, s.now).unwrap(),
                Taken::Refused(NotTaken::FollowsNoPhrase)
            );
        }
        assert!(new.stored().is_empty() && !new.follows_a_phrase());
    }

    /// The door takes a shared channel's entries only of a channel held in
    /// the table of shared channels, on a device that stands applied with
    /// sync on (decision 2026-10-10 §2.3, rules 1 and 2): of a channel not
    /// held, one dropped and one moved from, an entry is refused as of
    /// another channel; with sync off, as `SyncOff`; on a device that has
    /// stopped, as it is stopped. Nothing is stored. The control: applied,
    /// with sync on, it is stored, from a signer that does not count.
    #[test]
    fn the_door_takes_a_shared_channels_entries_only_where_the_device_stands_applied_with_sync_on()
    {
        use crate::lists::Do;
        use crate::shared::tests::{Shared, acts, bob, everything, holds, member, message};
        use cordelia_storage::meta;

        let s = bob(1);
        let now = s.now + 10;
        let alice = member(1);
        let channel = Shared::of(1);
        let entry = message(&alice, &channel, 1, "hello", now);
        let before = everything(&s, 0);
        assert_eq!(
            given(&s, 0, &entry),
            Taken::Refused(NotTaken::AnotherChannel)
        );
        assert_eq!(everything(&s, 0), before);

        holds(&s, 0, 1, "review", now);
        let before = everything(&s, 0);
        meta::remove(&s[0].conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(given(&s, 0, &entry), Taken::Refused(NotTaken::SyncOff));
        meta::set(&s[0].conn, meta::SYNC_CLAUDE_DIR, "/home/bob/.claude").unwrap();
        for state in [
            State::Fork,
            State::Removed,
            State::NotListed,
            State::NotOpened,
        ] {
            held_rows::set_state(&s[0].conn, state).unwrap();
            assert_eq!(
                given(&s, 0, &entry),
                Taken::Refused(NotTaken::Stopped(state))
            );
        }
        held_rows::set_state(&s[0].conn, State::Applied).unwrap();
        assert_eq!(everything(&s, 0), before);

        assert!(!s[0].counts(&alice.public_key()));
        assert_eq!(
            given(&s, 0, &entry),
            Taken::Shared {
                stored: Outcome::Stored,
                read: Some(crate::shared::Read::Message(
                    cordelia_storage::shared::Indexed::New
                )),
            }
        );
        assert_eq!(
            given(&s, 0, &entry),
            Taken::Shared {
                stored: Outcome::AlreadyHeld,
                read: None,
            }
        );

        // Dropped, and moved from: refused as of another channel.
        let moved = holds(&s, 0, 2, "design", now);
        acts(&s, 0, Do::Drop(channel.id), now + 1);
        let mut to = crate::lists::tests::filing(3, "design");
        to.came = cordelia_crypto::acts::Came::Moved(moved.id);
        acts(&s, 0, Do::Move { from: moved.id, to }, now + 2);
        let before = everything(&s, 0);
        for channel in [&channel, &moved] {
            let entry = message(&alice, channel, 2, "again", now);
            assert_eq!(
                given(&s, 0, &entry),
                Taken::Refused(NotTaken::AnotherChannel)
            );
        }
        assert_eq!(everything(&s, 0), before);
    }

    /// An entry outside its signer's slots or size is not stored (decision
    /// 2026-10-10 §1, property 22; §2.3, rule 3, T23): a delete, an entry in
    /// a slot of no name of its author's, one of another size than its
    /// slot's, and one at or above the half of band 0, each refused before
    /// anything is stored, and none leaves a row. A key that writes in all
    /// 65 of its slots, and then in a 66th, leaves 214,016 bytes as a relay
    /// counts them, and a slot written again changes nothing.
    #[test]
    fn an_entry_outside_its_signers_slots_or_size_is_not_stored() {
        use crate::shared::tests::{
            ANEW_COST, MESSAGE_COST, bob, everything, held_by, holds, key_row, member, message,
        };
        use cordelia_core::protocol::{AGENT_MESSAGE_VALUE_BYTES, SHARED_ANEW_VALUE_BYTES};
        use cordelia_crypto::message::message_name;
        use cordelia_crypto::shared::anew_name;

        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let alice = member(1);
        let key = alice.public_key();
        let by_alice = |name: &str, rev: u64, value: Value| {
            entry_by(&alice, &channel.secret, rev, name, value, &[])
        };
        let msg_0 = message_name(&key, 0).unwrap();
        let her_anew = anew_name(&key).unwrap();
        let (message_value, anew_value) = (
            Value::Other(vec![0; AGENT_MESSAGE_VALUE_BYTES]),
            Value::Other(vec![5; SHARED_ANEW_VALUE_BYTES]),
        );
        let before = everything(&s, 0);
        let refused = [
            (by_alice(&msg_0, 129, Value::Delete), NotTaken::NotAShared),
            (by_alice(&her_anew, 3, Value::Delete), NotTaken::NotAShared),
            (
                by_alice("notes.md", 2, message_value.clone()),
                NotTaken::NotAShared,
            ),
            (
                by_alice(&format!("{msg_0}4"), 2, message_value.clone()),
                NotTaken::NotAShared,
            ),
            (
                by_alice(
                    &message_name(&key, 64).unwrap().replace("/0", "/64"),
                    2,
                    message_value.clone(),
                ),
                NotTaken::NotAShared,
            ),
            (
                by_alice(
                    &message_name(&member(2).public_key(), 1).unwrap(),
                    2,
                    message_value.clone(),
                ),
                NotTaken::NotAShared,
            ),
            (
                by_alice(&msg_0, 128, Value::Other(vec![0; 3_000])),
                NotTaken::NotAShared,
            ),
            (
                by_alice(&her_anew, 1, message_value.clone()),
                NotTaken::NotAShared,
            ),
            (
                by_alice(&msg_0, REV_BAND_HALF, message_value.clone()),
                NotTaken::NotInBandZero,
            ),
            (
                by_alice(&her_anew, REV_BAND_HALF, anew_value.clone()),
                NotTaken::NotInBandZero,
            ),
            (
                by_alice(&her_anew, REV_BAND_SIZE + 1, anew_value.clone()),
                NotTaken::NotInBandZero,
            ),
        ];
        for (entry, why) in &refused {
            assert_eq!(given(&s, 0, entry), Taken::Refused(*why));
        }
        // A delete of a message's full size, in her slot, signed so: no
        // honest node writes one, and it is refused as a delete.
        let full_delete = {
            use cordelia_core::protocol::{LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL};
            let slot = cordelia_crypto::slots::slot_id(
                &derive::slot_key(&channel.secret).unwrap(),
                &message_name(&key, 1).unwrap(),
            );
            let channel_key = derive::signing_key(&channel.secret).unwrap();
            let mut entry = cordelia_crypto::entry::Entry {
                channel: channel_key.public_key(),
                slot,
                author: key,
                rev: 3,
                delete: true,
                content: vec![0; cordelia_core::protocol::AGENT_MESSAGE_CONTENT_BYTES],
                author_signature: [0; 64],
                channel_signature: [0; 64],
            };
            let form = entry.signed_bytes();
            entry.author_signature = alice.sign(&[LABEL_ENTRY_AUTHOR, &form[..]].concat());
            entry.channel_signature = channel_key.sign(&[LABEL_ENTRY_CHANNEL, &form[..]].concat());
            entry.check().unwrap()
        };
        assert_eq!(
            given(&s, 0, &full_delete),
            Taken::Refused(NotTaken::NotAShared)
        );
        assert_eq!(everything(&s, 0), before);
        assert!(key_row(&s, 0, &channel, &key).is_none());
        // The highest revision below the half of band 0 is taken.
        let highest = by_alice(&her_anew, REV_BAND_HALF - 1, anew_value);
        assert!(matches!(
            given(&s, 0, &highest),
            Taken::Shared {
                stored: Outcome::Stored,
                ..
            }
        ));

        // All 65 slots, and then a 66th that is none of them.
        for number in 1..=64 {
            let entry = message(&alice, &channel, number, "one of 64", now);
            assert!(matches!(
                given(&s, 0, &entry),
                Taken::Shared {
                    stored: Outcome::Stored,
                    ..
                }
            ));
        }
        let held = || held_by(&s, 0, &channel, &key);
        assert_eq!(held().len(), 65);
        let counted = |held: &[CheckedEntry]| -> u64 {
            held.iter()
                .map(|entry| cordelia_core::protocol::entry_cost(entry.content.len()))
                .sum()
        };
        assert_eq!(counted(&held()), 64 * MESSAGE_COST + ANEW_COST);
        assert_eq!(counted(&held()), 214_016);
        for (entry, why) in &refused {
            assert_eq!(given(&s, 0, entry), Taken::Refused(*why));
        }
        // A slot written again: the next number, in the slot of number 1.
        let over = message(&alice, &channel, 65, "over number 1", now);
        assert!(matches!(
            given(&s, 0, &over),
            Taken::Shared {
                stored: Outcome::Stored,
                ..
            }
        ));
        assert_eq!(held().len(), 65);
        assert_eq!(counted(&held()), 214_016);
        assert_eq!(
            key_row(&s, 0, &channel, &key).unwrap().bytes_stored,
            214_016
        );
    }

    /// An entry in a band above the applied statement's counts for
    /// nothing, and is refused: what the store holds from its author
    /// stays. One in the statement's own band is stored, to its last
    /// revision, and so is one in the top half of a lower band, which is
    /// no version and counts for the next revision.
    #[test]
    fn test_an_entry_in_a_band_above_the_applied_statements_is_refused() {
        let mut s = two();
        s.write(1, "notes", "a.md", "one");
        s.pass(1, 0);
        let channel = s[0].own("notes");
        let by = |rev: u64, file: &str| {
            entry_by(
                &s[1].identity,
                &channel,
                rev,
                file,
                text("at a revision"),
                &[],
            )
        };

        let before = s[0].everything();
        for rev in [at(2, 0), at(2, 5), at(3, REV_BAND_HALF), at(256, 1)] {
            assert_eq!(
                given(&s, 0, &by(rev, "a.md")),
                Taken::Refused(NotTaken::BandAboveTheStatements),
                "{rev}"
            );
        }
        assert_eq!(s[0].everything(), before);
        assert_eq!(s[0].text("notes", "a.md").as_deref(), Some("one"));

        assert_eq!(given(&s, 0, &by(at(1, REV_BAND_SIZE - 1), "b.md")), STORED);
        assert_eq!(given(&s, 0, &by(at(0, REV_BAND_HALF + 1), "c.md")), STORED);
        let slot = s[0].slot("notes", "c.md");
        assert_eq!((slot.current, slot.next), (None, Some(at(1, 2))));
    }

    /// A device of the version before this one beside one of this version
    /// (decision 2026-10-19 §7): an entry under `reached/` is taken by the
    /// one door where its signer counts, and stored; and the paths that
    /// version has, which this one keeps, read nothing of it. It is no
    /// record of an addition, counts no key, and leaves the word under
    /// `applied/` as it was.
    #[test]
    fn an_entry_under_reached_is_stored_and_read_as_nothing_by_the_older_paths() {
        let s = two();
        let key = s[0].key();
        let word = cordelia_crypto::reached::CarriedWord {
            number: s[1].number(),
            keys: vec![[0xa1; 32]],
            more: 0,
            not_yet: 1,
        };
        let entry = entry_by(
            &s[0].identity,
            &s[1].personal(),
            1,
            &crate::person::reached_name(&key).unwrap(),
            Value::Other(word.to_value().unwrap()),
            &[],
        );
        let applied_before = s[1].word_of(&key);
        let conn = &s[1].conn;
        let additions = held_rows::additions(conn).unwrap();
        let counting = who_counts(conn).unwrap();
        let other = identity_of(7).public_key();
        let counted = |counting: &Counting| {
            let keys = [key, s[1].key(), other];
            (counting.adders(), keys.map(|key| counting.counts(&key)))
        };
        // `record_in` reads no record in it, and counts no key by it.
        let personal = s[1].personal();
        assert_eq!(
            record_in(conn, &entry, &personal, false, s.now).unwrap(),
            (None, 0)
        );
        assert_eq!(given(&s, 1, &entry), STORED);
        assert!(s[1].stored().contains(&entry));
        assert_eq!(s[1].word_of(&key), applied_before);
        // No addition is kept by it, and the counting is as it was.
        assert_eq!(held_rows::additions(conn).unwrap(), additions);
        assert_eq!(counted(&who_counts(conn).unwrap()), counted(&counting));
        let applied = applied_before.map(|value| match value {
            Value::Text(word) => crate::person::read_applied_word(&word),
            _ => None,
        });
        assert_eq!(applied, Some(Some((s[1].number(), false))));
    }
}
