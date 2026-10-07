//! Leaving a phrase by a person's own command (decision 2026-10-04 §5.2).
//!
//! Two commands have a device leave the phrase it follows: `cordelia
//! phrase`, which then makes a new one there, and `cordelia init
//! --new-key`, which gives the device a new key. Neither asks for the
//! phrase. What each does to what the device holds is here, as plain
//! functions over its database:
//!
//! - [`among`] says where the device stands: it follows no phrase, is
//!   alone under one, is one of several, or has stopped. The command asks
//!   its yes by that.
//! - [`begin`] is what a device owes the devices it leaves, written while
//!   it is still one of them: **its word that it has left**, in the
//!   personal channel it is leaving, under `left/` and its own key; and a
//!   delete over each hand-over that a relay was sent, as where a device
//!   that is alone leaves by `accept` ([`crate::adding::accept`]). Both
//!   wait in its store, and the node sends them.
//! - [`forget`] forgets everything else that a device holds of its
//!   person: the phrase it followed, the statement, every secret, the
//!   change entries, the records of additions, what its store holds of
//!   every channel it can name, and what a person typed and cleared
//!   there. It keeps the names it holds, which are its folders' names.
//!
//! **The word outlives the leaving** where the device goes on under its
//! key (`cordelia phrase`): it stays in the store, as the device's own
//! entry in a channel that is its own no longer, and is sent to each
//! relay as the delete over a hand-over is. Under a new key nothing can
//! be sent in the old one's name: `cordelia init --new-key` waits for the
//! relays to be sent what [`begin`] wrote, and forgets after.
//!
//! A device that has stopped says nothing: it was removed, or is in no
//! list, or in a fork, and publishes nothing (§4.3, §4.5). A device that
//! is taken over can be made to leave without a word. One that leaves by
//! its own command says so.

use rusqlite::Connection;

use cordelia_core::protocol::PERSONAL_LEFT_PREFIX;
use cordelia_core::revision::next_under;
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::slots::slot_id;
use cordelia_storage::acts;
use cordelia_storage::at_relays as kept_rows;
use cordelia_storage::entries;
use cordelia_storage::person::{self as held_rows, Kept, State};

use crate::adding::{is_alone, leave, write_over_dropped};
use crate::at_relays::{Kind, Own};
use crate::person::{
    Applied, PersonError, applied_secret, drop_hand_overs, follow_first, held, in_one,
};
use crate::publish::Standing;

/// Where a device stands among the devices of its person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Among {
    /// It follows no phrase.
    NoPhrase,
    /// It is alone under a phrase: its statement lists no other device,
    /// and it has added none.
    Alone,
    /// It is one of several: with so many others, by the statement it has
    /// applied and the records it keeps.
    Several(usize),
    /// It follows a phrase, and has stopped.
    Stopped(State),
}

/// Where this device stands among the devices of its person.
pub fn among(conn: &Connection, identity: &NodeIdentity) -> Result<Among, PersonError> {
    let Some(held) = held(conn)? else {
        return Ok(Among::NoPhrase);
    };
    if held.state != State::Applied {
        return Ok(Among::Stopped(held.state));
    }
    let own = identity.public_key();
    if is_alone(conn, &held, &own)? {
        return Ok(Among::Alone);
    }
    let mut others: Vec<[u8; 32]> = held
        .statement
        .statement
        .devices
        .iter()
        .map(|device| device.key)
        .chain(held_rows::additions(conn)?.iter().map(|record| record.key))
        .filter(|key| *key != own)
        .collect();
    others.sort_unstable();
    others.dedup();
    Ok(Among::Several(others.len()))
}

/// The name, in the personal channel, of the word of the device whose key
/// is `device` that it has left (decision 2026-10-04 §5.2): `left/` and
/// the device's key, as a device's key is written.
pub fn left_name(device: &[u8; 32]) -> Result<String, PersonError> {
    Ok(format!(
        "{PERSONAL_LEFT_PREFIX}{}",
        encode_public_key(device)?
    ))
}

/// What a device wrote for the devices it leaves.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Begun {
    /// Its word that it has left, where it is one of several: its own
    /// entry in the personal channel, which waits in its store to be sent.
    pub word: Option<CheckedEntry>,
    /// How many hand-overs went from its store.
    pub dropped: usize,
    /// How many deletes it wrote over hand-overs that a relay was sent.
    pub written_over: usize,
}

/// What a device owes the devices it leaves, written while it is still
/// one of them (see the module's documentation). `now` is this device's
/// clock, in seconds.
///
/// A device that is one of several writes that it has left: its own entry
/// under [`left_name`], one revision above the one it wrote there before,
/// which says when. Run twice, it says so twice, and the later word
/// stands. A device that is alone has nobody to tell, and one that has
/// stopped publishes nothing: neither writes a word.
///
/// Every hand-over that the device made goes from its store, and a delete
/// is written over each that a relay was sent
/// ([`write_over_dropped`]): a hand-over holds the secret of the phrase
/// that is being left.
///
/// A device that follows no phrase has nothing to begin.
pub fn begin(conn: &Connection, identity: &NodeIdentity, now: i64) -> Result<Begun, PersonError> {
    in_one(conn, || {
        let mut begun = Begun::default();
        if let Among::Several(_) = among(conn, identity)? {
            begun.word = Some(say_left(conn, identity, now)?);
        }
        if held(conn)?.is_some() {
            begun.dropped = drop_hand_overs(conn, |_| false)?;
            begun.written_over = write_over_dropped(conn, identity, now)?;
        }
        Ok(begun)
    })
}

/// Write this device's word that it has left, in the personal channel of
/// the generation it has applied.
fn say_left(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<CheckedEntry, PersonError> {
    write_word(conn, identity, Value::Text(now.to_string()), now)
}

/// Take back this device's word that it has left (decision 2026-10-04
/// §16): a delete over it, one revision above, in the personal channel of
/// the generation it has applied. It is for a device that said it would
/// leave and then did not: `cordelia init --new-key`, stopped at its
/// second yes. Where the word was not yet sent to a relay, the delete
/// takes its place in the store, and the word is sent nowhere. Where a
/// relay holds it, the delete goes after it, and each device that was
/// told shows it no more.
///
/// Returns the delete, or `None` where no word of this device's stands:
/// it wrote none, or took it back already. What it wrote over the
/// hand-overs it made stays written ([`begin`]).
pub fn take_back(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<Option<CheckedEntry>, PersonError> {
    in_one(conn, || match own_word(conn, identity)? {
        Some(word) if !word.delete => write_word(conn, identity, Value::Delete, now).map(Some),
        _ => Ok(None),
    })
}

/// Write `value` under this device's own name for its word that it has
/// left, one revision above what it wrote there before.
fn write_word(
    conn: &Connection,
    identity: &NodeIdentity,
    value: Value,
    now: i64,
) -> Result<CheckedEntry, PersonError> {
    let standing = Standing::to_write(conn)?;
    let own = identity.public_key();
    let personal = derive::personal_secret(&standing.secret)?;
    let name = left_name(&own)?;
    let channel = derive::channel_id(&personal)?;
    let slot = slot_id(&derive::slot_key(&personal)?, &name);
    let before = entries::author_entry(conn, &channel, &slot, &own)?.map(|held| held.entry.rev);
    let rev = next_under(before, standing.number()).ok_or_else(|| {
        PersonError::Held(
            "this device's own word in that slot is at the last revision under the statement"
                .into(),
        )
    })?;
    let inside = Inside {
        name,
        value,
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&personal, identity, rev, &inside)?.check()?;
    entries::store(conn, &entry, now)?;
    Ok(entry)
}

/// This device's own word that it has left, as its store holds it in the
/// personal channel of the generation it has applied.
fn own_word(
    conn: &Connection,
    identity: &NodeIdentity,
) -> Result<Option<CheckedEntry>, PersonError> {
    let Some(held) = held(conn)? else {
        return Ok(None);
    };
    let own = identity.public_key();
    let personal = derive::personal_secret(&applied_secret(conn, &held.statement.statement)?)?;
    let channel = derive::channel_id(&personal)?;
    let slot = slot_id(&derive::slot_key(&personal)?, &left_name(&own)?);
    entries::author_entry(conn, &channel, &slot, &own)?
        .map(|held| {
            held.entry
                .check()
                .map_err(|e| PersonError::Held(format!("this device's own word: {e}")))
        })
        .transpose()
}

/// Forget what this device holds of its person (decision 2026-10-04
/// §5.2), in one transaction: the phrase it followed, the statement,
/// every secret, the change entries it keeps, the records of additions,
/// what its store holds of every channel that it can name under those
/// secrets, what it keeps of the hand-overs it made, and what a person
/// typed, cleared and was to be told there. It then follows no phrase.
/// Returns whether it followed one.
///
/// It keeps the names it holds: they are its folders' names, and each
/// has its channel again under the statement it next applies. Its folders
/// forget what they had agreed ([`leave`]): each meets that channel as on
/// any first sync.
///
/// `keep_word` says that the device goes on under its key: its word that
/// it has left, where it wrote one ([`begin`]), then stays in the store,
/// alone in a channel that the device can read no longer, and is sent to
/// each relay as whatever else it wrote in a channel of another's is. A
/// device that is given a new key keeps none: nothing is sent in the old
/// key's name once the key is gone.
///
/// Whatever state the device is in, this is done: a device that was
/// removed, or is in a fork, forgets as one that is not.
pub fn forget(
    conn: &Connection,
    identity: &NodeIdentity,
    keep_word: bool,
    now: i64,
) -> Result<bool, PersonError> {
    in_one(conn, || {
        let Some(held) = held(conn)? else {
            return Ok(false);
        };
        let word = match keep_word {
            true => own_word(conn, identity)?,
            false => None,
        };
        // Every entry of every channel it can name, the hand-overs it
        // still holds, and every secret.
        leave(conn, &held)?;
        // What it handed a key under the phrase it leaves is written over
        // at each relay that was sent it, and it keeps nothing more of
        // any hand-over it made (§6).
        write_over_dropped(conn, identity, now)?;
        held_rows::forget_hand_overs(conn)?;
        held_rows::drop_change_entry(conn, Kept::Latest)?;
        held_rows::drop_change_entry(conn, Kept::Apart)?;
        held_rows::clear_additions(conn)?;
        held_rows::forget_person(conn)?;
        acts::forget_all(conn)?;
        if let Some(word) = word {
            entries::store(conn, &word, now)?;
        }
        Ok(true)
    })
}

/// The device starts again alone, under the phrase whose first statement
/// `entry` carries (decision 2026-10-04 §5.2): the node's half of
/// `cordelia phrase`, in one transaction. `statement_key` is that
/// phrase's statement key.
///
/// `shown` is where the device stood when the command asked its yes, and
/// the yes was for that: where it stands elsewhere now, nothing is done,
/// and the command asks again ([`PersonError::ChangedSincePrompt`]). A
/// device that was one of several and is one of several still is where
/// the yes was for, however many the others are now.
///
/// A device that follows no phrase follows this one. One that is alone
/// under a phrase, or one of several, first does what it owes the devices
/// it leaves ([`begin`]), forgets what it held ([`forget`], with its word
/// kept to be sent), and then follows this one. A device that has stopped
/// is refused: the way on is another ([`PersonError::Stopped`]).
pub fn start_again(
    conn: &Connection,
    identity: &NodeIdentity,
    shown: Among,
    entry: &CheckedEntry,
    statement_key: &[u8; 32],
    now: i64,
) -> Result<Applied, PersonError> {
    in_one(conn, || {
        let stands = among(conn, identity)?;
        match (shown, stands) {
            (_, Among::Stopped(state)) => return Err(PersonError::Stopped(state)),
            (Among::NoPhrase, Among::NoPhrase) | (Among::Alone, Among::Alone) => {}
            (Among::Several(_), Among::Several(_)) => {}
            _ => return Err(PersonError::ChangedSincePrompt),
        }
        if stands != Among::NoPhrase {
            begin(conn, identity, now)?;
            forget(conn, identity, true, now)?;
        }
        let applied = follow_first(conn, identity, entry, statement_key, now)?;
        // Whatever key was typed at `cordelia accept` before was typed
        // by a device that had made no phrase of its own: none of them
        // is spent under this one (§16).
        acts::forget_every_typed_key(conn)?;
        // It then publishes its folders (§5.2): it holds a name for each
        // folder it maps, and the next sync cycle publishes what is in
        // them. The change entry goes to each relay ahead of that, as it
        // goes ahead of everything a device sends.
        crate::names::hold_mapped(conn, identity, now)?;
        Ok(applied)
    })
}

/// How many of this device's channels have something that waits to be
/// sent to the relay whose node key is `relay`: of the personal channel,
/// the channel of each name it holds, and each channel in which it only
/// sends what it wrote (a hand-over and the delete over it, and its word
/// that it has left).
///
/// It is read from what the device keeps of the relay, and writes
/// nothing. A delete over a hand-over waits only for a relay that was
/// sent the hand-over ([`crate::at_relays::to_send`]). What the relay
/// had no room for waits too: it is kept, to be sent again.
pub fn waits_at(
    conn: &Connection,
    identity: &NodeIdentity,
    relay: &[u8; 32],
) -> Result<usize, PersonError> {
    let mut waiting = 0;
    for channel in crate::at_relays::channels(conn, identity)? {
        let waits = waits_in(conn, identity, relay, &channel)?;
        let refused = !kept_rows::waiting_refused(conn, relay, &channel.id)?.is_empty();
        waiting += usize::from(waits || refused);
    }
    Ok(waiting)
}

/// Whether something of `channel`, a channel of this device's own, waits
/// to be sent to the relay whose node key is `relay`, as the device keeps
/// of that relay how far it was sent the channel. What the relay had no
/// room for is not asked here.
fn waits_in(
    conn: &Connection,
    identity: &NodeIdentity,
    relay: &[u8; 32],
    channel: &Own,
) -> Result<bool, PersonError> {
    let own = identity.public_key();
    let carried_up_to = kept_rows::carried_up_to(conn)?;
    let kept = kept_rows::kept(conn, relay, &channel.id)?;
    // The place of the first entry that the store holds of the
    // channel after `place`, in the store's own order.
    let first_after = |place: i64| -> Result<Option<i64>, PersonError> {
        let next = entries::channel_entries_after(conn, &channel.id, place, 1)?;
        Ok(next.first().map(|held| held.seq))
    };
    Ok(match channel.kind {
        Kind::Personal => first_after(kept.sent_to)?.is_some(),
        // What came since the statement was applied, and what was
        // carried then, each from where it was sent to.
        Kind::Name(_) => {
            first_after(kept.sent_to.max(carried_up_to))?.is_some()
                || first_after(kept.carried_to)?.is_some_and(|seq| seq <= carried_up_to)
        }
        // Only what the device wrote itself, and a delete only for a
        // relay that was sent what it is written over.
        Kind::Pair => {
            let was_sent = kept_rows::keeps_any(conn, relay, &channel.id)?;
            entries::channel_entries_after(conn, &channel.id, kept.sent_to, 8)?
                .iter()
                .any(|held| held.entry.author == own && (was_sent || !held.entry.delete))
        }
    })
}

/// The names that this device holds, in order, each with whether
/// something of its channel still waits to be sent to any of `relays`,
/// by their node keys (decision 2026-10-04 §7.1, §8): what a device has
/// still to send, by name. What a relay had no room for waits too.
///
/// None on a device that follows no phrase, or has stopped: it sends
/// nothing in a channel of its own.
pub fn names_to_go(
    conn: &Connection,
    identity: &NodeIdentity,
    relays: &[[u8; 32]],
) -> Result<Vec<(String, bool)>, PersonError> {
    let mut names = Vec::new();
    for channel in crate::at_relays::channels(conn, identity)? {
        let Kind::Name(name) = &channel.kind else {
            continue;
        };
        let mut to_go = false;
        for relay in relays {
            to_go |= waits_in(conn, identity, relay, &channel)?
                || !kept_rows::waiting_refused(conn, relay, &channel.id)?.is_empty();
        }
        names.push((name.clone(), to_go));
    }
    Ok(names)
}

/// Since when something of a name's channel has waited to be sent to one
/// of `relays`, by their node keys: when this device stored the earliest
/// entry that is the first to wait at one of them, in seconds. `None`
/// where nothing of a name waits. What a relay had no room for waits
/// from when it was stored.
///
/// A status says that names are not yet sent only once they have waited
/// for some minutes (decision 2026-10-04 §10.1): what was written a
/// moment ago is being sent.
pub fn names_waiting_since(
    conn: &Connection,
    identity: &NodeIdentity,
    relays: &[[u8; 32]],
) -> Result<Option<i64>, PersonError> {
    let carried_up_to = kept_rows::carried_up_to(conn)?;
    let mut since: Option<i64> = None;
    for channel in crate::at_relays::channels(conn, identity)? {
        if !matches!(channel.kind, Kind::Name(_)) {
            continue;
        }
        let first_after = |place: i64| -> Result<Option<(i64, i64)>, PersonError> {
            let next = entries::channel_entries_after(conn, &channel.id, place, 1)?;
            Ok(next.first().map(|held| (held.seq, held.stored_at)))
        };
        for relay in relays {
            let kept = kept_rows::kept(conn, relay, &channel.id)?;
            // As [`waits_in`] finds what waits: what came since the
            // statement was applied, and what was carried then.
            let mut waits: Vec<i64> = Vec::new();
            if let Some((_, at)) = first_after(kept.sent_to.max(carried_up_to))? {
                waits.push(at);
            }
            if let Some((seq, at)) = first_after(kept.carried_to)?
                && seq <= carried_up_to
            {
                waits.push(at);
            }
            for refused in kept_rows::waiting_refused(conn, relay, &channel.id)? {
                if let Some((seq, at)) = first_after(refused - 1)?
                    && seq == refused
                {
                    waits.push(at);
                }
            }
            since = waits.into_iter().chain(since).min();
        }
    }
    Ok(since)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adding::Accepted;
    use crate::at_relays;
    use crate::person::{first_entry, first_statement, who_counts};
    use crate::several::{OTHER_WORDS, Several};
    use crate::take::{Taken, take};
    use cordelia_crypto::phrase::Phrase;

    /// Device `to` is given `entry`, through the one door.
    fn give(s: &mut Several, to: usize, entry: &CheckedEntry) -> Taken {
        let now = s.tick();
        take(&s[to].conn, &s[to].identity, entry, now).unwrap()
    }

    /// The word of device `of` that it has left, as device `on` holds it
    /// in its personal channel: that device's own entry under its own
    /// name there.
    fn word_on(s: &Several, on: usize, of: usize) -> Option<Value> {
        let reader = &s[on];
        let personal = reader.personal();
        let name = left_name(&s.key(of)).unwrap();
        let slot = slot_id(&derive::slot_key(&personal).unwrap(), &name);
        let id = derive::channel_id(&personal).unwrap();
        entries::author_entry(&reader.conn, &id, &slot, &s.key(of))
            .unwrap()
            .map(|held| held.entry.check().unwrap().open(&personal).unwrap().value)
    }

    /// A device stands in one of four places: it follows no phrase, is
    /// alone under one, is one of several, or has stopped.
    #[test]
    fn test_where_a_device_stands_among_the_devices_of_its_person() {
        let mut s = Several::new(3);
        assert_eq!(among(&s[0].conn, &s[0].identity).unwrap(), Among::NoPhrase);
        s.make_phrase(0);
        assert_eq!(among(&s[0].conn, &s[0].identity).unwrap(), Among::Alone);
        // A record that it keeps is a device added, counted or not.
        s.hand(0, 1);
        assert_eq!(
            among(&s[0].conn, &s[0].identity).unwrap(),
            Among::Several(1)
        );

        let mut s = Several::of_one_person(3);
        for n in 0..3 {
            assert_eq!(
                among(&s[n].conn, &s[n].identity).unwrap(),
                Among::Several(2),
                "{n}"
            );
        }
        // A device that was removed has stopped.
        let removal = s.change(0, &[0, 1], &[2]);
        give(&mut s, 2, &removal);
        assert_eq!(
            among(&s[2].conn, &s[2].identity).unwrap(),
            Among::Stopped(State::Removed)
        );
    }

    /// A device that is one of several writes that it has left, in the
    /// personal channel it is leaving, as its own entry under its own
    /// name: every other device that takes it holds the word.
    #[test]
    fn test_a_device_that_is_one_of_several_writes_that_it_has_left() {
        let mut s = Several::of_one_person(3);
        let now = s.tick();
        let begun = begin(&s[2].conn, &s[2].identity, now).unwrap();
        let word = begun.word.clone().expect("it is one of several");
        assert_eq!(word.author, s.key(2));
        assert_eq!(word.channel, derive::channel_id(&s[2].personal()).unwrap());
        let inside = word.open(&s[2].personal()).unwrap();
        assert_eq!(inside.name, left_name(&s.key(2)).unwrap());
        assert_eq!(inside.value, Value::Text(now.to_string()));
        assert!(inside.name.starts_with("left/cordelia_pk1"));

        // The others take it as any entry of the personal channel.
        for n in [0, 1] {
            assert_eq!(word_on(&s, n, 2), None);
            give(&mut s, n, &word);
            assert_eq!(word_on(&s, n, 2), Some(Value::Text(now.to_string())));
        }
        // Said again, the later word is above the earlier, and stands.
        let later = s.tick();
        let again = begin(&s[2].conn, &s[2].identity, later)
            .unwrap()
            .word
            .unwrap();
        assert!(again.rev > word.rev);
        give(&mut s, 0, &again);
        assert_eq!(word_on(&s, 0, 2), Some(Value::Text(later.to_string())));
    }

    /// A device that said it left, and then did not leave, takes its word
    /// back (decision 2026-10-04 §16): a delete over it, one revision
    /// above. The store holds the delete in the word's place, so a word
    /// that no relay was sent is sent to none; and a device that had read
    /// the word shows that it left no more. With no word standing,
    /// nothing is written.
    #[test]
    fn test_a_device_that_did_not_leave_takes_back_its_word() {
        let mut s = Several::of_one_person(2);
        s.change(0, &[0, 1], &[]);
        s.meet(&[0, 1]);
        let now = s.tick();
        let on = &s[1];
        // No word stands: nothing is taken back.
        assert_eq!(take_back(&on.conn, &on.identity, now).unwrap(), None);
        let word = begin(&on.conn, &on.identity, now).unwrap().word.unwrap();
        give(&mut s, 0, &word);
        assert_eq!(word_on(&s, 0, 1), Some(Value::Text(now.to_string())));

        let later = s.tick();
        let on = &s[1];
        let back = take_back(&on.conn, &on.identity, later).unwrap().unwrap();
        assert!(back.delete);
        assert_eq!((back.channel, back.slot), (word.channel, word.slot));
        assert_eq!(back.rev, word.rev + 1);
        // The store holds the delete in the word's place: the word itself
        // waits to be sent nowhere.
        let held = on.stored_in(&on.personal());
        assert!(held.iter().any(|entry| entry.id() == back.id()));
        assert!(held.iter().all(|entry| entry.id() != word.id()));
        // Taken back once: there is no word to take back again.
        assert_eq!(take_back(&on.conn, &on.identity, later).unwrap(), None);
        // The device that had read the word is given the delete, and
        // reads that it left no more.
        give(&mut s, 0, &back);
        assert_eq!(word_on(&s, 0, 1), Some(Value::Delete));
        // It may say so again, and that word stands.
        let now = s.tick();
        let on = &s[1];
        let again = begin(&on.conn, &on.identity, now).unwrap().word.unwrap();
        assert_eq!(again.rev, back.rev + 1);
        // A device that follows no phrase has no word.
        let alone = crate::several::Machine::new(7);
        assert_eq!(take_back(&alone.conn, &alone.identity, now).unwrap(), None);
    }

    /// A device that is alone has nobody to tell, one that has stopped
    /// publishes nothing, and one that follows no phrase has nothing to
    /// begin: none writes a word.
    #[test]
    fn test_a_device_that_is_alone_or_has_stopped_writes_no_word() {
        let mut s = Several::new(1);
        let none = begin(&s[0].conn, &s[0].identity, s.now).unwrap();
        assert_eq!(none, Begun::default());
        s.make_phrase(0);
        let before = s[0].stored().len();
        let alone = begin(&s[0].conn, &s[0].identity, s.now).unwrap();
        assert_eq!(alone.word, None);
        assert_eq!(s[0].stored().len(), before);

        let mut s = Several::of_one_person(3);
        let removal = s.change(0, &[0, 1], &[2]);
        give(&mut s, 2, &removal);
        let before = s[2].stored().len();
        let stopped = begin(&s[2].conn, &s[2].identity, s.now).unwrap();
        assert_eq!(stopped.word, None);
        assert_eq!(s[2].stored().len(), before);
    }

    /// Leaving drops every hand-over from the store, and writes a delete
    /// over each that a relay was sent: what `accept` does for a device
    /// that leaves alone.
    #[test]
    fn test_leaving_writes_over_what_it_handed_and_keeps_nothing_of_it() {
        let mut s = Several::of_one_person(2);
        let added = s.hand(0, 1);
        let pair = added.hand_over.channel;
        // A relay was sent the hand-over.
        let relay = [0x77; 32];
        kept_rows::sending(&s[0].conn, &relay, &pair).unwrap();
        assert_eq!(held_rows::hand_overs_held(&s[0].conn).unwrap().len(), 1);

        let now = s.tick();
        let begun = begin(&s[0].conn, &s[0].identity, now).unwrap();
        assert_eq!((begun.dropped, begun.written_over), (1, 1));
        assert!(held_rows::hand_overs_held(&s[0].conn).unwrap().is_empty());
        // What the store holds of the pair channel is the delete, one
        // revision above the hand-over.
        let held = entries::channel_entries_after(&s[0].conn, &pair, 0, 10).unwrap();
        assert_eq!(held.len(), 1);
        assert!(held[0].entry.delete);
        assert_eq!(held[0].entry.rev, added.hand_over.rev + 1);

        // And once it has forgotten, it keeps nothing of any hand-over.
        forget(&s[0].conn, &s[0].identity, true, now).unwrap();
        assert!(held_rows::hand_overs_gone(&s[0].conn).unwrap().is_empty());
        assert!(
            held_rows::handed_over(&s[0].conn, &s.key(1))
                .unwrap()
                .is_none()
        );
        // The delete still waits to be sent.
        let held = entries::channel_entries_after(&s[0].conn, &pair, 0, 10).unwrap();
        assert!(held.len() == 1 && held[0].entry.delete);
    }

    /// A device that forgets follows no phrase: it holds no statement, no
    /// secret, no change entry, no record and no entry of a channel of
    /// its own, and nothing of what a person typed or cleared. It keeps
    /// its names.
    #[test]
    fn test_a_device_that_forgets_keeps_its_names_and_nothing_else_of_its_person() {
        let mut s = Several::of_one_person(3);
        let now = s.tick();
        let on = &s[1];
        crate::person::hold_name(&on.conn, "notes", now).unwrap();
        acts::type_key(&on.conn, &[9; 32], "several", now).unwrap();
        acts::clear_notice(&on.conn, &[8; 32], now).unwrap();
        acts::note_left_out(&on.conn, &[7; 32], "laptop", 1, now).unwrap();
        assert!(!on.stored().is_empty());

        assert!(forget(&on.conn, &on.identity, false, now).unwrap());
        assert!(!on.follows_a_phrase());
        assert!(held_rows::secrets(&on.conn).unwrap().is_empty());
        assert_eq!(
            held_rows::change_entry(&on.conn, Kept::Latest).unwrap(),
            None
        );
        assert_eq!(
            held_rows::change_entry(&on.conn, Kept::Apart).unwrap(),
            None
        );
        assert!(held_rows::additions(&on.conn).unwrap().is_empty());
        assert!(on.stored().is_empty());
        assert!(acts::typed_keys(&on.conn).unwrap().is_empty());
        assert!(acts::left_out(&on.conn).unwrap().is_empty());
        assert!(!acts::is_cleared(&on.conn, &[8; 32]).unwrap());
        let names: Vec<String> = held_rows::names(&on.conn)
            .unwrap()
            .into_iter()
            .map(|name| name.name)
            .collect();
        assert_eq!(names, ["notes"]);
        // Forgotten twice, there is nothing more to forget.
        assert!(!forget(&on.conn, &on.identity, false, now).unwrap());
        assert_eq!(among(&on.conn, &on.identity).unwrap(), Among::NoPhrase);

        // A device in a fork keeps two change entries: it forgets both.
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        s.change(0, &[0, 1], &[2]);
        let apart = s.change(1, &[0, 1, 2], &[]);
        give(&mut s, 0, &apart);
        let on = &s[0];
        assert_eq!(on.state(), State::Fork);
        for kept in [Kept::Latest, Kept::Apart] {
            assert!(held_rows::change_entry(&on.conn, kept).unwrap().is_some());
        }
        assert!(forget(&on.conn, &on.identity, false, s.now).unwrap());
        for kept in [Kept::Latest, Kept::Apart] {
            assert_eq!(held_rows::change_entry(&on.conn, kept).unwrap(), None);
        }
    }

    /// `cordelia phrase`, the node's half: a device that follows no
    /// phrase follows the new one; one that is alone, or one of several,
    /// leaves first, in the same step; and where the device stands
    /// elsewhere than the yes was asked for, nothing is done.
    #[test]
    fn test_a_device_starts_again_only_from_where_the_yes_was_asked() {
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let made = |s: &Several, n: usize| first_entry(&other, &s.key(n), "desktop").unwrap();
        let again = |s: &Several, n: usize, shown: Among| {
            let made = made(s, n);
            let on = &s[n];
            start_again(
                &on.conn,
                &on.identity,
                shown,
                &made.entry,
                &made.statement_key,
                s.now + 1,
            )
        };

        // It follows no phrase.
        let s = Several::new(1);
        for shown in [Among::Alone, Among::Several(2)] {
            assert!(matches!(
                again(&s, 0, shown),
                Err(PersonError::ChangedSincePrompt)
            ));
            assert!(!s[0].follows_a_phrase());
        }
        let applied = again(&s, 0, Among::NoPhrase).unwrap();
        assert_eq!((applied.number, applied.left), (1, None));
        assert_eq!(
            s[0].held().statement.statement.phrase_key,
            other.public_key().unwrap()
        );
        assert_eq!(s[0].held().statement.statement.devices[0].label, "desktop");

        // It is alone under the fixture's phrase.
        let mut s = Several::new(1);
        s.make_phrase(0);
        let before = s[0].everything();
        for shown in [Among::NoPhrase, Among::Several(1)] {
            assert!(matches!(
                again(&s, 0, shown),
                Err(PersonError::ChangedSincePrompt)
            ));
            assert_eq!(s[0].everything(), before);
        }
        again(&s, 0, Among::Alone).unwrap();
        assert_eq!(
            s[0].held().statement.statement.phrase_key,
            other.public_key().unwrap()
        );
        assert_eq!(held_rows::secrets(&s[0].conn).unwrap().len(), 1);

        // It is one of several: it leaves them with its word, and the
        // word is all that its store keeps of the channels it left.
        let mut s = Several::of_one_person(3);
        let old_personal = derive::channel_id(&s[2].personal()).unwrap();
        let before = s[2].everything();
        for shown in [Among::NoPhrase, Among::Alone] {
            assert!(matches!(
                again(&s, 2, shown),
                Err(PersonError::ChangedSincePrompt)
            ));
            assert_eq!(s[2].everything(), before);
        }
        // The yes was asked when it was with one other, and it is with
        // two now: it is one of several still.
        again(&s, 2, Among::Several(1)).unwrap();
        assert_eq!(among(&s[2].conn, &s[2].identity).unwrap(), Among::Alone);
        let left: Vec<CheckedEntry> = s[2]
            .stored()
            .into_iter()
            .filter(|entry| entry.channel == old_personal)
            .collect();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].author, s.key(2));
        give(&mut s, 0, &left[0].clone());
        assert!(word_on(&s, 0, 2).is_some());

        // A device that has stopped is refused, whatever was shown.
        let mut s = Several::of_one_person(3);
        let removal = s.change(0, &[0, 1], &[2]);
        give(&mut s, 2, &removal);
        let before = s[2].everything();
        for shown in [Among::NoPhrase, Among::Alone, Among::Several(2)] {
            assert!(matches!(
                again(&s, 2, shown),
                Err(PersonError::Stopped(State::Removed))
            ));
        }
        assert_eq!(s[2].everything(), before);
    }

    /// What waits to be sent to a relay is counted by channel, from what
    /// the device keeps of the relay: its word that it has left waits
    /// until the relay was sent it, and a delete over a hand-over waits
    /// only for a relay that was sent the hand-over. What a relay had no
    /// room for waits there, although the relay was sent it.
    #[test]
    fn test_what_waits_to_be_sent_to_a_relay_is_counted_by_channel() {
        let mut s = Several::of_one_person(2);
        let (relay, other) = ([0x77; 32], [0x78; 32]);
        let on = &s[0];
        // Everything in the personal channel waits for a relay that was
        // sent nothing: one channel. And the hand-over, in the pair
        // channel: another.
        assert_eq!(waits_at(&on.conn, &on.identity, &relay).unwrap(), 2);
        let sent_all = |relay: &[u8; 32]| {
            for channel in at_relays::channels(&on.conn, &on.identity).unwrap() {
                let last = kept_rows::last_taken(&on.conn, &channel.id).unwrap();
                if channel.kind == Kind::Pair {
                    kept_rows::sending(&on.conn, relay, &channel.id).unwrap();
                }
                kept_rows::sent(&on.conn, relay, &channel.id, last).unwrap();
            }
        };
        sent_all(&relay);
        assert_eq!(waits_at(&on.conn, &on.identity, &relay).unwrap(), 0);
        assert_eq!(waits_at(&on.conn, &on.identity, &other).unwrap(), 2);
        // The relay had no room for one entry of the personal channel:
        // that channel waits there, until the relay holds the entry.
        let personal = derive::channel_id(&on.personal()).unwrap();
        let last = kept_rows::last_taken(&on.conn, &personal).unwrap();
        kept_rows::refused(&on.conn, &relay, &personal, last).unwrap();
        assert_eq!(waits_at(&on.conn, &on.identity, &relay).unwrap(), 1);
        kept_rows::not_refused(&on.conn, &relay, &personal, last).unwrap();
        assert_eq!(waits_at(&on.conn, &on.identity, &relay).unwrap(), 0);

        // It says that it leaves: its word waits, and the delete over
        // the hand-over waits for the relay that was sent the hand-over.
        let now = s.tick();
        let on = &s[0];
        let begun = begin(&on.conn, &on.identity, now).unwrap();
        assert!(begun.word.is_some());
        assert_eq!((begun.dropped, begun.written_over), (1, 1));
        assert_eq!(waits_at(&on.conn, &on.identity, &relay).unwrap(), 2);
        // The other relay was never sent the hand-over: the personal
        // channel waits for it, and no delete does.
        assert_eq!(waits_at(&on.conn, &on.identity, &other).unwrap(), 1);
    }

    /// A device that goes on under its key keeps its word that it has
    /// left, alone in its store, and sends it once it follows a phrase
    /// again: it is in what the pass goes through, as a channel in which
    /// the device only sends what it wrote. A device that is given a new
    /// key keeps none.
    #[test]
    fn test_the_word_outlives_the_leaving_where_the_device_keeps_its_key() {
        let mut s = Several::of_one_person(2);
        let now = s.tick();
        let old_personal = derive::channel_id(&s[1].personal()).unwrap();
        let word = begin(&s[1].conn, &s[1].identity, now)
            .unwrap()
            .word
            .unwrap();
        {
            let on = &s[1];
            forget(&on.conn, &on.identity, true, now).unwrap();
            assert_eq!(on.stored(), std::slice::from_ref(&word));
            // It starts again alone, under a phrase of its own.
            let phrase = Phrase::parse(OTHER_WORDS).unwrap();
            first_statement(&on.conn, &on.identity, &phrase, "device 1", now + 1).unwrap();
            let own = at_relays::channels(&on.conn, &on.identity).unwrap();
            let left: Vec<&at_relays::Own> = own
                .iter()
                .filter(|channel| channel.id == old_personal)
                .collect();
            assert_eq!(left.len(), 1);
            assert_eq!(left[0].kind, Kind::Pair);
            assert!(!left[0].is_pulled());
            let relay = [0x33; 32];
            let most = at_relays::Most {
                entries: 10,
                bytes: 1 << 20,
            };
            let batch = at_relays::to_send(
                &on.conn,
                &on.identity,
                &relay,
                left[0],
                at_relays::Which::Since,
                most,
                true,
            )
            .unwrap();
            assert_eq!(batch.entries, [word.clone().into_entry()]);
            assert_eq!(who_counts(&on.conn).unwrap().devices(), 1);
        }
        // The device it left takes the word, and still counts it: a
        // device that has left is still listed.
        give(&mut s, 0, &word);
        assert!(word_on(&s, 0, 1).is_some());
        assert!(s[0].counts(&s.key(1)));

        // Under a new key, nothing of the old one's is kept.
        let mut s = Several::of_one_person(2);
        let now = s.tick();
        begin(&s[1].conn, &s[1].identity, now)
            .unwrap()
            .word
            .unwrap();
        forget(&s[1].conn, &s[1].identity, false, now).unwrap();
        assert!(s[1].stored().is_empty());
        // And it can be added again as any new install is.
        assert!(matches!(s.add(0, 1), Accepted::Joined(_)));
        assert!(s[1].follows_a_phrase());
    }
}
