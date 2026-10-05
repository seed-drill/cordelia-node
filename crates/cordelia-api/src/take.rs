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
//!
//! ## What a caller owes it
//!
//! An entry whose signer does not count is refused, and nothing of it is
//! kept. So what a device that is being added wrote is refused where it
//! arrives before the record of that device's addition, and so is a
//! record whose own signer does not count yet. Nothing here remembers
//! them.
//!
//! **Where [`take`] says that a key came to count** (`came_to_count`
//! above 0 in [`Taken::Own`]), **the caller gives it again every entry of
//! this device's own channels that it gave before.** What the key that
//! now counts had signed is then taken, and a record among it may let a
//! further key count, which is said in its turn. A device that does so
//! ends with the same entries, and the same answers, as one that was
//! given the record first. A node does it by listing its channels to its
//! relays again from the start (§16).
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
///
/// **What the caller owes:** where this returns [`Taken::Own`] with
/// `came_to_count` above 0, it gives again every entry of this device's
/// own channels that it gave before. An entry that a key signed before
/// that key counted was refused here and not kept, whichever arrived
/// first: the entries of a device that is being added, and a record that
/// such a device signed.
pub fn take(
    conn: &Connection,
    identity: &NodeIdentity,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Taken, PersonError> {
    match in_one(conn, || taken_as_its_own(conn, identity, entry, now))? {
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
    let personal = derive::personal_secret(&applied_secret(conn, statement)?)?;
    let is_personal = entry.channel == derive::channel_id(&personal)?;
    if !is_personal && held_rows::name_of_channel(conn, &entry.channel)?.is_none() {
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
    let mut taken = (None, 0);
    if is_personal && stored != Outcome::OlderThanHeld {
        let again = stored == Outcome::AlreadyHeld;
        taken = record_in(conn, entry, &personal, again, now)?;
    }
    Ok(Some(Taken::Own {
        stored,
        record: taken.0,
        came_to_count: taken.1,
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
    };

    /// An entry that the store held already, and that says no more.
    const HELD: Taken = Taken::Own {
        stored: Outcome::AlreadyHeld,
        record: None,
        came_to_count: 0,
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
        let taken = |seen: AdditionSeen, came_to_count: usize| Taken::Own {
            stored: Outcome::Stored,
            record: Some(Record::Seen(seen)),
            came_to_count,
        };

        assert_eq!(seen(&listed, &a), taken(AdditionSeen::Counted, 1));
        assert_eq!(seen(&a, &b), taken(AdditionSeen::Counted, 1));
        // Device b was added by a device added since: it may not add.
        let may_not = AdditionSeen::NotCounted(NotCounted::MayNotAdd);
        assert_eq!(seen(&b, &c), taken(may_not, 0));
        assert!(!s[1].counts(&c.key()));
        // A device of the statement adds b too: b counts already, and the
        // record that b signed comes to count with this one.
        let already = AdditionSeen::NotCounted(NotCounted::CountsAlready);
        assert_eq!(seen(&listed, &b), taken(already, 1));
        assert!(s[1].counts(&c.key()));
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
            given(&s, 1, &holding(2, good)),
            Taken::Own {
                stored: Outcome::Stored,
                record: Some(Record::Seen(AdditionSeen::Counted)),
                came_to_count: 1,
            }
        );
    }

    /// A device keeps at most 256 records that are not counted, and a
    /// device that counts can sign any number of them. The record by
    /// which a device of the statement lets a key add is not among those
    /// that go: no flood takes from a key that it may add.
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
        // the record in it was, and how many keys came to count by it.
        let taken = |entry: &CheckedEntry| match given(&s, 1, entry) {
            Taken::Own {
                stored,
                record,
                came_to_count,
            } => (stored, record, came_to_count),
            other => panic!("{other:?}"),
        };
        let stored =
            |seen: AdditionSeen, came: usize| (Outcome::Stored, Some(Record::Seen(seen)), came);
        let again = |seen: AdditionSeen, came: usize| {
            (Outcome::AlreadyHeld, Some(Record::Seen(seen)), came)
        };
        let says_no_more = (Outcome::AlreadyHeld, None, 0);
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
        assert_eq!(taken(&lets_8_add), stored(ALREADY, 0));
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
        // The one that went is the oldest of the flood. The record that
        // lets device 8 add is older, and stays.
        assert!(keeps(&lets_8_add) && !keeps(&by_9));
        assert!(by_10.iter().all(keeps));
        assert!(may_add(8));
        // What device 8 signs next counts.
        assert_eq!(taken(&adds(8, 12)), stored(COUNTED, 1));

        // Device 0 adds device 9 too: it may add from now on. The device
        // keeps nothing that device 9 signed, so no key comes to count.
        // This record stays as the other does, and the oldest of the
        // others goes.
        assert_eq!(taken(&adds(0, 9)), stored(ALREADY, 0));
        assert!(may_add(9) && !keeps(&by_10[0]));
        assert_eq!(not_counted(), MAX_NOT_COUNTED_RECORDS);

        // The record by device 9 that went is given again. The store
        // holds its entry already, and it is judged as a record never
        // seen: the key it adds counts.
        assert_eq!(taken(&by_9), again(COUNTED, 1));
        assert!(
            who_counts(&on.conn)
                .unwrap()
                .counts(&identity_of(11).public_key())
        );
        // So is the one by device 10 that went: it does not count, is
        // kept again, and the oldest of the others goes in its turn.
        assert_eq!(taken(&by_10[0]), again(MAY_NOT, 0));
        assert!(keeps(&by_10[0]) && !keeps(&by_10[1]));
        assert_eq!(not_counted(), MAX_NOT_COUNTED_RECORDS);
        // A record that the device keeps says no more when its entry is
        // given again: one that counts, and two that do not.
        for kept in [&by_9, &lets_8_add, &by_10[2]] {
            assert_eq!(taken(kept), says_no_more);
        }
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
}
