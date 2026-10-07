//! Adding a device (decision 2026-10-04 §5.1, §6), in two halves.
//!
//! A device is added by a device that is in, with no phrase: its key is
//! typed there, and that device's key is typed on it, within an hour. The
//! two meet in their pair channel, which each derives from the other's
//! key.
//!
//! ## The device that adds
//!
//! [`add_device`] makes the record of the addition, writes it in the
//! personal channel, where every other device sees it, and makes the
//! hand-over: one entry of the pair channel, under the name `hand-over`,
//! whose value is the statement applied, its secret, the statement key,
//! the change entry and the records. A key that the statement already
//! lists is handed the change again, with no record.
//!
//! Both wait in the device's store to be sent, and the hand-over goes
//! ahead of everything else (§6). The hand-over holds the person secret,
//! and does not stay there: it goes two hours after the time it says it
//! was made ([`drop_old_hand_overs`]), when the device applies a
//! statement, and when it leaves its phrase. What the device keeps of it
//! is its revision.
//!
//! A relay that was sent the hand-over still holds it then. So the
//! device that adds writes a delete over it in the pair channel, one
//! revision above it, which waits in its store to be sent to each relay
//! that was sent the hand-over ([`write_over_dropped`]): the relay's copy
//! is written over. The node does that as it goes, after it has dropped
//! what is old. A device that leaves its phrase does it as it leaves, and
//! then keeps nothing of any hand-over it made.
//!
//! A pair channel is one channel for as long as both keys exist, whatever
//! phrase either device follows, and a statement's number starts again
//! under each phrase. So the hand-over's revision is the time it was
//! made, by the clock of the device that adds, or one above the one it
//! made before for that key: what is handed later takes the place of what
//! was handed before. The revision only orders them. When a hand-over was
//! made, it says itself.
//!
//! ## The device that accepts
//!
//! [`accept`] is given the pair channel's entry, the key a person typed
//! and when it was typed. It takes the entry only if that key signed it,
//! it was typed within the last hour, and the hand-over says it was made
//! within the hour before or after the key was typed: an old hand-over is
//! not taken, whoever shows it. What it then does goes by the state the
//! device is in, as the table of §5.1 has it:
//!
//! | This device | What it does |
//! |---|---|
//! | Follows no phrase | Takes the statement, the secret and the phrase, keeps the change entry, and applies |
//! | Is alone under a phrase | Refused while sync is on. Otherwise it leaves that phrase and takes this one, and its names forget what they held |
//! | Is one of several | Takes only a hand-over under the phrase it already follows that brings a change it can apply. One whose statement was made apart shows as a fork. Any other moves nothing |
//! | Is in no list, or could not open a change | Takes only a hand-over under the phrase it already follows, and carries what it holds |
//! | Was removed | Refused |
//! | Is in a fork | Refused |
//!
//! A device applies a statement that does not list it only where a record
//! of its addition comes with it, and that record counts under the
//! statement (§4.2, rule 3). Once it has applied, it writes that it has
//! (§8).
//!
//! Nothing here asks a yes, sends or fetches: a command asks, and the
//! node sends what waits in its store.

use rusqlite::Connection;

use cordelia_core::protocol::{
    HAND_OVER_KEPT_SECS, HAND_OVER_NAME, MAX_COUNTED_DEVICES, MAX_TYPED_KEYS, PAIR_KEY_TYPED_SECS,
    TYPED_KEY_KEPT_SECS,
};
use cordelia_core::revision::next_under;
use cordelia_crypto::addition::{Addition, SignedAddition};
use cordelia_crypto::change_entry;
use cordelia_crypto::derive::{self, DeriveError};
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
use cordelia_crypto::hand_over::{HandOver, HandOverError};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::statement::{Device, Judgement, Statement, StatementError, judge};
use cordelia_storage::acts::{self, TypedKey};
use cordelia_storage::at_relays as kept_rows;
use cordelia_storage::entries;
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, Following, State};
use cordelia_storage::sync_state;

use crate::leaving::Among;
use crate::person::{
    AdditionSeen, Applied, Change, Held, NotCounted, PersonError, Shown, added_name,
    applied_secret, apply_added, apply_judged, drop_hand_overs, held, in_one, its_own_entry,
    latest_entry, see_addition, shown,
};
use crate::publish::Standing;

// ── The device that adds ─────────────────────────────────────────────

/// What a device that adds another has made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    /// The record of the addition, as this device's entry in the personal
    /// channel. `None` where the statement already lists the key: it is
    /// handed the change again, with no record.
    pub record: Option<CheckedEntry>,
    /// What the record was to this device itself, where one was made.
    pub seen: Option<AdditionSeen>,
    /// The hand-over: this device's entry under the name `hand-over` in
    /// the pair channel of the two keys, above the one it made before for
    /// that key. It is in this device's store for two hours, or until the
    /// device applies a statement or leaves its phrase.
    pub hand_over: CheckedEntry,
}

/// Add the device whose key is `new`, under `label`, from this device
/// (decision 2026-10-04 §6). Both entries are in this device's store, to
/// be sent, and are returned. `now` is this device's clock, in seconds.
///
/// Refused, with nothing written:
///
/// - on a device that follows no phrase, is in a fork, was removed, is in
///   no list, or could not open a change;
/// - a key that the statement lists as removed: it is not added again
///   without a new key;
/// - on a device that may not add: one that was itself added, since the
///   last statement, by a device added since;
/// - where the device already counts 64, and the key does not count yet;
/// - this device's own key, a key that is no usable public key, and a
///   label that a statement could not carry.
///
/// A key that the statement already lists is handed the change again,
/// with no record, and `label` is not used: the statement's own label
/// stands. A key that already counts by a record this device keeps is
/// handed the change again too, with a record of this device's own: it
/// takes no room, and the bound of 64 is not asked for it.
///
/// Before anything else, and whatever then comes of the adding, the
/// hand-overs this device made that are not within two hours of `now` go
/// from its store ([`drop_old_hand_overs`]).
///
/// **What the caller owes:** the record is taken here as any record is
/// ([`see_addition`]), and a key may come to count by it: the key that is
/// added, and any key that a record it had signed adds in its turn. What
/// such a key signed was refused when it arrived, and was not kept. So
/// wherever a record was made ([`Added::record`] is `Some`), the caller
/// gives [`crate::take::take`] again every entry of this device's own
/// channels that it gave before, as it does where `take` says that a key
/// came to count.
pub fn add_device(
    conn: &Connection,
    identity: &NodeIdentity,
    new: &[u8; 32],
    label: &str,
    now: i64,
) -> Result<Added, PersonError> {
    drop_old_hand_overs(conn, now)?;
    in_one(conn, || {
        let standing = Standing::to_write(conn)?;
        let own = identity.public_key();
        let statement = &standing.held.statement.statement;
        let pair = derive::pair_secret(identity, new)?;
        if statement.removes(new) {
            return Err(PersonError::KeyRemoved);
        }
        if !standing.counting.may_add(&own) {
            return Err(PersonError::MayNotAdd);
        }

        let mut hand_over = HandOver {
            made_at: at(now),
            statement: standing.held.statement.clone(),
            secret: standing.secret,
            statement_key: standing.held.following.statement_key,
            change_entry: latest_entry(conn)?.into_entry(),
            addition: None,
            adders_own: None,
        };
        let mut added = (None, None);
        if !statement.lists(new) {
            let counts_already = standing.counting.counts(new);
            if !counts_already && standing.counting.devices() >= MAX_COUNTED_DEVICES {
                return Err(PersonError::NoRoom);
            }
            let record = Addition::under(statement, Device::new(*new, label)?, own, at(now))?
                .sign(identity)?;
            let entry = record_written(conn, identity, &standing, &record, now)?;
            let seen = see_addition(conn, &record, now)?;
            added = (Some(entry), Some(seen));
            hand_over.adders_own = own_addition(conn, statement, &own)?;
            hand_over.addition = Some(record);
        }

        let hand_over = hand_over_written(conn, identity, new, &pair, &hand_over, now)?;
        Ok(Added {
            record: added.0,
            seen: added.1,
            hand_over,
        })
    })
}

/// What adding a key would do, asked before a person's yes (decision
/// 2026-10-04 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WouldAdd {
    /// The statement already lists the key, under this label: it is one
    /// of the person's devices, and is handed the last change again, with
    /// no record.
    HandsAgain { label: String },
    /// A record of the addition would be made, and the hand-over.
    Adds {
        /// The key counts already, by a record that the device keeps.
        counts_already: bool,
        /// The key was not in the last change: this device counted it
        /// before the statement it has applied, and that statement lists
        /// it in neither list (§8). `Some` with the label it was known by.
        left_out_as: Option<String>,
    },
}

/// What [`add_device`] would do with the key `new`, under `label`, with
/// nothing written: for a command that shows what it is about to do
/// before it asks its yes. Every refusal of [`add_device`] is a refusal
/// here, in the same order.
pub fn would_add(
    conn: &Connection,
    identity: &NodeIdentity,
    new: &[u8; 32],
    label: &str,
) -> Result<WouldAdd, PersonError> {
    let standing = Standing::to_write(conn)?;
    let own = identity.public_key();
    let statement = &standing.held.statement.statement;
    derive::pair_secret(identity, new)?;
    if statement.removes(new) {
        return Err(PersonError::KeyRemoved);
    }
    if !standing.counting.may_add(&own) {
        return Err(PersonError::MayNotAdd);
    }
    if let Some(listed) = statement.devices.iter().find(|device| device.key == *new) {
        return Ok(WouldAdd::HandsAgain {
            label: listed.label.clone(),
        });
    }
    let counts_already = standing.counting.counts(new);
    if !counts_already && standing.counting.devices() >= MAX_COUNTED_DEVICES {
        return Err(PersonError::NoRoom);
    }
    Device::new(*new, label)?;
    let left_out_as = acts::left_out(conn)?
        .into_iter()
        .find(|shown| shown.key == *new)
        .map(|shown| shown.label);
    Ok(WouldAdd::Adds {
        counts_already,
        left_out_as,
    })
}

/// The time `now`, as a record or a revision gives it: seconds, and none
/// before 1970.
fn at(now: i64) -> u64 {
    u64::try_from(now).unwrap_or(0)
}

/// Write the record of an addition in the personal channel, as this
/// device's own entry under the name of the key it adds: bytes that are
/// no text.
///
/// Its revision is one above this device's own entry in that slot, and 1
/// where it has none, whatever another key has written there. A record is
/// read only from its adder's own entry, and each author has an entry of
/// its own in a slot: no other key's entry there stops this one being
/// written, at whatever revision it stands.
fn record_written(
    conn: &Connection,
    identity: &NodeIdentity,
    standing: &Standing,
    record: &SignedAddition,
    now: i64,
) -> Result<CheckedEntry, PersonError> {
    let personal = derive::personal_secret(&standing.secret)?;
    let name = added_name(&record.addition.device.key)?;
    let channel = derive::channel_id(&personal)?;
    let slot = slot_id(&derive::slot_key(&personal)?, &name);
    let own = entries::author_entry(conn, &channel, &slot, &identity.public_key())?
        .map(|held| held.entry.rev);
    let rev = next_under(own, standing.number()).ok_or_else(|| {
        PersonError::Held(
            "this device's own record in that slot is at the last revision under the statement"
                .into(),
        )
    })?;
    let value = Value::Other(record.to_bytes()?);
    let inside = Inside {
        name,
        value,
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&personal, identity, rev, &inside)?.check()?;
    entries::store(conn, &entry, now)?;
    Ok(entry)
}

/// The record of this device's own addition, where the statement does not
/// list it: the one that a device of the statement signed, which is what
/// lets it add. It goes with what this device hands over.
fn own_addition(
    conn: &Connection,
    statement: &Statement,
    own: &[u8; 32],
) -> Result<Option<SignedAddition>, PersonError> {
    if statement.lists(own) {
        return Ok(None);
    }
    let kept = held_rows::additions(conn)?;
    let record = kept
        .iter()
        .find(|record| record.key == *own && statement.lists(&record.adder))
        .ok_or_else(|| {
            PersonError::Held("a device that may add keeps the record of its own addition".into())
        })?;
    Ok(Some(SignedAddition::from_bytes(&record.record)?))
}

/// Write the hand-over as this device's entry under the name `hand-over`
/// in the pair channel whose secret is `pair`, which is its channel with
/// the key `new`. A hand-over that the device it is for would refuse is
/// not written.
///
/// A pair channel is of no generation, and a revision in it is a plain
/// number (decision 2026-10-04 §2.3). It is one channel for as long as
/// both keys exist, whatever phrase either device follows, so nothing
/// that starts again under a phrase can number its entries. The entry's
/// revision is the time it is made, by this device's clock, in seconds:
/// what is handed later takes the place of what was handed before, in
/// this device's store and at a relay. Where the last hand-over this
/// device made for that key is already at that time or above it (two made
/// in one second, or a clock that was set back), it is one above that
/// one. The device keeps the revision of the last for each key, whether
/// or not its store still holds the hand-over.
///
/// The revision orders the hand-overs, and says nothing else: it can run
/// ahead of the clock for good. When the hand-over was made is in the
/// hand-over.
fn hand_over_written(
    conn: &Connection,
    identity: &NodeIdentity,
    new: &[u8; 32],
    pair: &[u8; 32],
    hand_over: &HandOver,
    now: i64,
) -> Result<CheckedEntry, PersonError> {
    let before = held_rows::handed_over(conn, new)?.map(|last| last.rev);
    // The delete that this device wrote over the last one is above it,
    // and is all there is where the device keeps nothing of the last: it
    // left the phrase that it handed that one under.
    let slot = slot_id(&derive::slot_key(pair)?, HAND_OVER_NAME);
    let channel = derive::channel_id(pair)?;
    let in_store = entries::author_entry(conn, &channel, &slot, &identity.public_key())?;
    let before = before.max(in_store.map(|held| held.entry.rev));
    let made_at = at(now);
    let rev = match before {
        Some(before) if before >= made_at => before + 1,
        _ => made_at,
    };
    let inside = Inside {
        name: HAND_OVER_NAME.to_string(),
        value: Value::Other(hand_over.to_bytes()?),
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(pair, identity, rev, &inside)?.check()?;
    entries::store(conn, &entry, now)?;
    let said = i64::try_from(hand_over.made_at).unwrap_or(i64::MAX);
    held_rows::note_hand_over(conn, new, &entry.channel, rev, said)?;
    Ok(entry)
}

/// Drop from this device's store each hand-over it made that is not
/// within two hours of now, by the time the hand-over says it was made
/// (decision 2026-10-04 §3, §6). `now` is this device's clock, in
/// seconds. Returns how many went.
///
/// A hand-over holds the person secret. No device takes one two hours
/// after it was made: a key opens the pair channel for an hour, and only
/// for a hand-over made within the hour of its typing. One that says a
/// time two hours or more ahead of the clock was made by a clock that has
/// since been set back, and no key typed by now takes it: it goes too,
/// and does not wait for a time that may be years away.
///
/// The node calls this as it goes. A device also does it first wherever
/// it adds or accepts, whatever then comes of that, and every hand-over
/// goes where the device applies a statement or leaves its phrase.
pub fn drop_old_hand_overs(conn: &Connection, now: i64) -> Result<usize, PersonError> {
    in_one(conn, || {
        drop_hand_overs(conn, |made_at| {
            now.checked_sub(made_at)
                .and_then(i64::checked_abs)
                .is_some_and(|apart| apart < HAND_OVER_KEPT_SECS)
        })
    })
}

/// Write a delete over each hand-over that this device made and that has
/// gone from its store (decision 2026-10-04 §6): its own entry under the
/// name `hand-over` in the pair channel, one revision above the
/// hand-over. It waits in the store to be sent, and a relay that takes it
/// holds the hand-over no longer. `now` is this device's clock, in
/// seconds. Returns how many were written.
///
/// A hand-over holds the person secret, and goes from the store of the
/// device that made it two hours after it was made, when that device
/// applies a statement, and when it leaves its phrase. A relay that was
/// sent it would hold it for as long as it holds the pair channel.
///
/// None is written:
///
/// - over a hand-over that the store still holds;
/// - where no relay was sent anything of the pair channel: there is
///   nothing to write over;
/// - where the store holds an entry of this device's in the pair channel:
///   that is the delete, written before.
///
/// The node calls this as it goes, after [`drop_old_hand_overs`].
pub fn write_over_dropped(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<usize, PersonError> {
    in_one(conn, || {
        let own = identity.public_key();
        let mut written = 0;
        for gone in held_rows::hand_overs_gone(conn)? {
            if !kept_rows::keeps_any_anywhere(conn, &gone.channel)?
                || kept_rows::holds_by(conn, &gone.channel, &own)?
            {
                continue;
            }
            // The pair channel of this device and that key: a row that
            // names another channel is not this device's, and is left.
            let Ok(pair) = derive::pair_secret(identity, &gone.key) else {
                continue;
            };
            if derive::channel_id(&pair)? != gone.channel {
                continue;
            }
            let inside = Inside {
                name: HAND_OVER_NAME.into(),
                value: Value::Delete,
                chain: Some(Vec::new()),
            };
            let entry = Entry::seal(&pair, identity, gone.rev.saturating_add(1), &inside)?;
            entries::store(conn, &entry.check()?, now)?;
            written += 1;
        }
        Ok(written)
    })
}

// ── The device that accepts ──────────────────────────────────────────

/// The rows of §5.1 in which `cordelia accept` takes a key: where a
/// device stands when a person types a key and says yes. The yes names
/// what will happen in that row, and in no other (decision 2026-10-04
/// §5.1, §16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row {
    /// It follows no phrase.
    NoPhrase,
    /// It is alone under a phrase.
    Alone,
    /// It is one of several.
    Several,
    /// It is in no list of a statement under the phrase it follows, or is
    /// listed in a change that it could not open.
    NotListed,
}

impl Row {
    /// The row's name, as a request names it and as it is kept.
    pub fn name(self) -> &'static str {
        match self {
            Self::NoPhrase => "no_phrase",
            Self::Alone => "alone",
            Self::Several => "several",
            Self::NotListed => "not_listed",
        }
    }

    /// The row that is named so.
    pub fn named(name: &str) -> Option<Self> {
        [Self::NoPhrase, Self::Alone, Self::Several, Self::NotListed]
            .into_iter()
            .find(|row| row.name() == name)
    }

    /// The row of a device that stands so among the devices of its
    /// person. `None` for one that was removed or is in a fork: no key is
    /// taken there.
    pub fn of(stands: Among) -> Option<Self> {
        match stands {
            Among::NoPhrase => Some(Self::NoPhrase),
            Among::Alone => Some(Self::Alone),
            Among::Several(_) => Some(Self::Several),
            Among::Stopped(State::NotListed | State::NotOpened) => Some(Self::NotListed),
            Among::Stopped(_) => None,
        }
    }

    /// Where a device in this row stood, in words.
    fn stood(self) -> &'static str {
        match self {
            Self::NoPhrase => "followed no recovery phrase",
            Self::Alone => "was alone under a recovery phrase",
            Self::Several => "was one of several devices",
            Self::NotListed => "was in no list of the last change",
        }
    }

    /// Where a device in this row stands, in words.
    fn stands(self) -> &'static str {
        match self {
            Self::NoPhrase => "follows no recovery phrase",
            Self::Alone => "is alone under a recovery phrase",
            Self::Several => "is one of several devices",
            Self::NotListed => "is in no list of the last change",
        }
    }
}

/// A person typed `key` at `cordelia accept`, at `now`, and said yes to
/// what the command showed for the row `stood` (decision 2026-10-04
/// §5.1, §16). The key is kept with that row and its time, and reads its
/// pair channel for an hour. `sync_on` is whether sync is on here.
///
/// Refused, with nothing kept:
///
/// - a key that has no pair channel with this device: its own, or no
///   usable public key;
/// - on a device that was removed, or is in a fork;
/// - on a device that is alone under a phrase with sync on;
/// - where the device stands in another row now than the yes was for:
///   the command asks again ([`PersonError::ChangedSincePrompt`]);
/// - a ninth key, where eight are within their hour. A key that is
///   within its hour is typed again in its place. One whose hour has
///   gone holds no place: it is kept for a day only to say what became
///   of it, and what was typed more than a day ago is forgotten first.
pub fn type_key(
    conn: &Connection,
    identity: &NodeIdentity,
    key: &[u8; 32],
    stood: Row,
    sync_on: bool,
    now: i64,
) -> Result<(), PersonError> {
    in_one(conn, || {
        derive::pair_secret(identity, key)?;
        let stands = match crate::leaving::among(conn, identity)? {
            Among::Stopped(state @ (State::Removed | State::Fork)) => {
                return Err(PersonError::Stopped(state));
            }
            Among::Alone if sync_on => return Err(PersonError::SyncIsOn),
            stands => Row::of(stands),
        };
        if stands != Some(stood) {
            return Err(PersonError::ChangedSincePrompt);
        }
        // What became of a key typed long ago is kept no longer.
        acts::forget_typed_keys(conn, now - TYPED_KEY_KEPT_SECS)?;
        // The bound is on the keys that still read their pair channel:
        // those within their hour.
        let kept = acts::typed_keys(conn)?;
        let within: Vec<&acts::TypedKey> = kept
            .iter()
            .filter(|typed| now - typed.typed_at < PAIR_KEY_TYPED_SECS)
            .collect();
        if within.len() >= MAX_TYPED_KEYS && !within.iter().any(|typed| typed.key == *key) {
            return Err(PersonError::TooManyTypedKeys);
        }
        acts::type_key(conn, key, stood.name(), now)?;
        Ok(())
    })
}

/// What became of a hand-over that a device was given to accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// The device followed no phrase: it follows the hand-over's now, and
    /// has applied its statement.
    Joined(Applied),
    /// The device was alone under another phrase: it left that one,
    /// follows the hand-over's now, and has applied its statement. Its
    /// names hold nothing of what they held.
    Moved(Applied),
    /// The hand-over is under the phrase the device already follows, and
    /// brought a change it could apply: it applied it, and carried what it
    /// held.
    Applied(Applied),
    /// The hand-over's statement was made apart from the one the device
    /// has applied: the device is in a fork, and keeps both change
    /// entries, as where it is shown such an entry.
    Fork,
    /// It was refused, and nothing changed.
    Refused(NotAccepted),
}

/// Why a hand-over was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAccepted {
    /// The key was not typed within the last hour.
    NotTypedInTheLastHour,
    /// The key typed has no pair channel with this device: it is this
    /// device's own key, or no usable public key.
    NoPairChannel,
    /// The entry is not of the pair channel of this device and the key
    /// typed.
    NotThePairChannel,
    /// Another key signed the entry than the one typed.
    SignedByAnotherKey,
    /// The hand-over says it was made an hour or more before the key was
    /// typed, or after: it is an old one, or the clocks of the two devices
    /// are more than an hour apart.
    NotMadeWithinTheHour,
    /// The entry is not the one under the name `hand-over`, does not
    /// open, or holds no bytes: nothing else in a pair channel is read.
    NotAHandOver,
    /// What the entry holds is no hand-over, or does not hold together.
    HandOver(HandOverError),
    /// The hand-over is for another device than this one.
    NotForThisDevice,
    /// The record of this device's addition was signed by another key
    /// than the one typed.
    AddedByAnotherKey,
    /// The record of this device's addition, or of its adder's, does not
    /// count under the statement.
    RecordDoesNotCount(NotCounted),
    /// This device is alone under another phrase, and sync is on there:
    /// it is turned off first.
    SyncIsOn,
    /// This device follows another phrase, and is not alone under it.
    AnotherPhrase,
    /// The hand-over brings no change that this device can apply: its
    /// statement is the one applied, or is behind it.
    BringsNoChange,
    /// The hand-over's statement is none that this device takes beside
    /// the one it has applied.
    Statement(StatementError),
    /// This device has stopped, and the hand-over's statement was made
    /// apart from the one it has applied, or is behind the change that
    /// stopped it.
    NotAfterTheChangeThatStoppedIt,
    /// This device was removed: it is given a new key first.
    Removed,
    /// This device is in a fork: the fork is settled first.
    InAFork,
    /// The key was typed, and its yes said, where the device stood in
    /// another row of §5.1 than it stands in now. `typed` is that row,
    /// and `None` for a key typed before rows were kept; `now` is the row
    /// it stands in, and `None` where it was removed or is in a fork.
    StoodElsewhere {
        typed: Option<Row>,
        now: Option<Row>,
    },
}

/// Accept the hand-over in `entry`, an entry of the pair channel of this
/// device and the key `typed` (decision 2026-10-04 §5.1, §6). `typed` is
/// the adder's key as a person typed it on this device, `typed_at` when
/// it was typed, and `sync_on` whether sync is on here.
///
/// The entry is taken only if the key typed signed it, and it was typed
/// within the last hour: at `typed_at` or after it, and less than an hour
/// after. And only if the hand-over was made less than an hour before or
/// after the key was typed: it says when it was made, by the clock of the
/// device that adds, and the entry's revision is not asked. What is then
/// done goes by the state this device is in (see the module's
/// documentation, and [`Accepted`]).
///
/// An error is this device's, and not the hand-over's: nothing changed.
/// Before anything else, and whatever then comes of it, the hand-overs
/// this device itself made that are not within two hours of `now` go from
/// its store ([`drop_old_hand_overs`]).
///
/// **What the caller owes:** nothing here remembers what was taken. A
/// hand-over is taken by the state the device is in when it is given,
/// each time it is given with a key typed within the hour. One that was
/// taken, given again with the same key and the same time of typing, is
/// judged afresh: a device that joined by it, and then within the hour
/// made a phrase of its own, with sync off, is moved back. So once this
/// has succeeded ([`Accepted::Joined`], [`Accepted::Moved`] or
/// [`Accepted::Applied`]) the caller spends the typed key: it gives that
/// key, as typed then, to no later call. A person who means it types the
/// key again.
pub fn accept(
    conn: &Connection,
    identity: &NodeIdentity,
    typed: &[u8; 32],
    typed_at: i64,
    sync_on: bool,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Accepted, PersonError> {
    drop_old_hand_overs(conn, now)?;
    let accepted = in_one(conn, || {
        let hand_over = match hand_over_in(identity, typed, typed_at, entry, now)? {
            Ok(hand_over) => hand_over,
            Err(why) => return Ok(Accepted::Refused(why)),
        };
        let brought = Brought::of(&hand_over)?;
        // A device that comes to follow a phrase holds a name for each
        // folder it maps (§5.2, §6): its folders then meet the person's
        // channels as on any first sync.
        let joined = |applied: Applied| -> Result<Applied, PersonError> {
            crate::names::hold_mapped(conn, identity, now)?;
            Ok(applied)
        };
        let Some(held) = held(conn)? else {
            return brought
                .applied_on(conn, identity, None, &brought.following, now)
                .and_then(joined)
                .map(Accepted::Joined);
        };
        let under_the_same = held.following.phrase_key == brought.following.phrase_key;
        match held.state {
            State::Removed => Ok(Accepted::Refused(NotAccepted::Removed)),
            State::Fork => Ok(Accepted::Refused(NotAccepted::InAFork)),
            _ if under_the_same => brought.taken_by(conn, identity, &held, now),
            State::Applied if is_alone(conn, &held, &identity.public_key())? => {
                if sync_on {
                    return Ok(Accepted::Refused(NotAccepted::SyncIsOn));
                }
                leave(conn, &held)?;
                // What it handed a key under the phrase it leaves is
                // written over at each relay that was sent it, and it
                // keeps nothing more of any hand-over it made (§6).
                write_over_dropped(conn, identity, now)?;
                held_rows::forget_hand_overs(conn)?;
                brought
                    .applied_on(conn, identity, None, &brought.following, now)
                    .and_then(joined)
                    .map(Accepted::Moved)
            }
            _ => Ok(Accepted::Refused(NotAccepted::AnotherPhrase)),
        }
    });
    match accepted {
        // The statement was applied and then undone: rule 3 did not hold.
        Err(PersonError::RecordNotCounted(why)) => {
            Ok(Accepted::Refused(NotAccepted::RecordDoesNotCount(why)))
        }
        accepted => accepted,
    }
}

/// Whether a key that was typed at `typed_at` still opens its pair
/// channel at `now` (decision 2026-10-04 §2.2): for an hour from when it
/// was typed, and not before.
pub fn within_its_hour(typed_at: i64, now: i64) -> bool {
    now.checked_sub(typed_at)
        .is_some_and(|ago| (0..PAIR_KEY_TYPED_SECS).contains(&ago))
}

/// The keys that a person typed at `cordelia accept` and that still read
/// their pair channels at `now`: each was typed within the last hour, and
/// no hand-over was taken with it since (decision 2026-10-04 §2.2, §5.1).
pub fn keys_that_read(conn: &Connection, now: i64) -> Result<Vec<TypedKey>, PersonError> {
    Ok(acts::typed_keys(conn)?
        .into_iter()
        .filter(|typed| typed.taken_at.is_none() && within_its_hour(typed.typed_at, now))
        .collect())
}

/// Give [`accept`] an entry that came from the pair channel of the key
/// `typed`, as the device keeps that key (decision 2026-10-04 §5.1): what
/// the node does with what its one door for a pair channel lets through.
/// `sync_on` is whether sync is on here.
///
/// One transaction: the key is read again as the device keeps it now, the
/// hand-over is accepted or refused, and what became of it is kept with
/// the key, for a person to read. **The typed key is spent where the
/// hand-over was taken** ([`Accepted::Joined`], [`Accepted::Moved`],
/// [`Accepted::Applied`]), and where it showed a fork: no later entry is
/// given to [`accept`] with it, until a person types it again.
///
/// **A key is spent only in the row its yes named** (§5.1, §16). Where
/// the device stands in another row now than when the key was typed,
/// nothing is given to [`accept`]: the hand-over is refused
/// ([`NotAccepted::StoodElsewhere`]), and why is kept with the key. And
/// **a device that comes to follow a phrase by a hand-over forgets every
/// other key that was typed**: none of them is spent under what the
/// device has become.
///
/// `None` where the key reads nothing now: a person typed it again since,
/// it is spent, or its hour has gone. Nothing was given to [`accept`].
pub fn accept_typed(
    conn: &Connection,
    identity: &NodeIdentity,
    typed: &TypedKey,
    sync_on: bool,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Option<Accepted>, PersonError> {
    in_one(conn, || {
        let kept = acts::typed_key(conn, &typed.key)?.filter(|kept| {
            kept.typed_at == typed.typed_at
                && kept.taken_at.is_none()
                && within_its_hour(kept.typed_at, now)
        });
        let Some(kept) = kept else {
            return Ok(None);
        };
        // The yes was for the row that the device stood in then.
        let typed_in = Row::named(&kept.stood);
        let stands = Row::of(crate::leaving::among(conn, identity)?);
        if typed_in.is_none() || typed_in != stands {
            let refused = Accepted::Refused(NotAccepted::StoodElsewhere {
                typed: typed_in,
                now: stands,
            });
            acts::say_of_typed_key(conn, &typed.key, typed.typed_at, &refused.says())?;
            return Ok(Some(refused));
        }
        let accepted = accept(
            conn,
            identity,
            &typed.key,
            typed.typed_at,
            sync_on,
            entry,
            now,
        )?;
        let said = accepted.says();
        match &accepted {
            Accepted::Joined(_) | Accepted::Moved(_) | Accepted::Applied(_) | Accepted::Fork => {
                acts::spend_typed_key(conn, &typed.key, typed.typed_at, now, &said)?;
            }
            Accepted::Refused(_) => {
                acts::say_of_typed_key(conn, &typed.key, typed.typed_at, &said)?;
            }
        }
        // The device follows a phrase that it did not follow: every other
        // key that was typed is forgotten.
        if matches!(&accepted, Accepted::Joined(_) | Accepted::Moved(_)) {
            acts::forget_other_typed_keys(conn, &typed.key)?;
        }
        Ok(Some(accepted))
    })
}

impl Accepted {
    /// What became of the hand-over, in words for a person.
    pub fn says(&self) -> String {
        match self {
            Self::Joined(applied) => format!(
                "this device has joined: it follows the recovery phrase of the device whose key \
                 was typed, and has applied change {}",
                applied.number
            ),
            Self::Moved(applied) => format!(
                "this device has left the recovery phrase it followed alone, and has joined: it \
                 has applied change {}",
                applied.number
            ),
            Self::Applied(applied) => format!(
                "this device has applied change {}, which it was handed",
                applied.number
            ),
            Self::Fork => "what was handed over is a change made apart from the one this device \
                           had applied: two changes were made apart, and are settled with the \
                           phrase (`cordelia settle`)"
                .into(),
            Self::Refused(why) => why.says(),
        }
    }
}

impl NotAccepted {
    /// Why the hand-over was not accepted, in words for a person.
    pub fn says(&self) -> String {
        match self {
            Self::NotTypedInTheLastHour => {
                "the hour in which that key could hand this device what it needs has gone".into()
            }
            Self::NoPairChannel => "that key has no channel with this device: it is this \
                                    device's own key, or no device's"
                .into(),
            Self::NotThePairChannel | Self::SignedByAnotherKey | Self::NotAHandOver => {
                "what was found is not a hand-over from the device whose key was typed".into()
            }
            Self::HandOver(why) => format!("what was handed over does not hold together: {why}"),
            Self::NotMadeWithinTheHour => "what was handed over was made more than an hour \
                                           before or after the key was typed here: it is an \
                                           old one, or the clocks of the two devices are more \
                                           than an hour apart. Run `cordelia add-device` again \
                                           on the other device"
                .into(),
            Self::NotForThisDevice => {
                "what was handed over is for another device than this one".into()
            }
            Self::AddedByAnotherKey => "what was handed over adds this device in the name of \
                                        another device than the one whose key was typed"
                .into(),
            Self::RecordDoesNotCount(why) => format!(
                "the device whose key was typed cannot add this one now ({})",
                match why {
                    NotCounted::Removed => "this device's key was removed",
                    NotCounted::CountsAlready => "this device counts already",
                    NotCounted::MayNotAdd =>
                        "it was itself added, since the last change, by a device added since",
                    NotCounted::NoRoom => "64 devices count already: a change makes room",
                }
            ),
            Self::SyncIsOn => "sync is on here: `cordelia sync off` first, and then `cordelia \
                               accept` again"
                .into(),
            Self::AnotherPhrase => "what was handed over is under another recovery phrase than \
                                    the one this device follows, and this device is one of \
                                    several: nothing moved. To join other devices it leaves \
                                    these first: it is removed from them, or `cordelia init \
                                    --new-key` starts it afresh"
                .into(),
            Self::BringsNoChange => "what was handed over brings no change that this device has \
                                     not applied: nothing was done"
                .into(),
            Self::Statement(why) => {
                format!("the change that was handed over is none that this device takes: {why}")
            }
            Self::NotAfterTheChangeThatStoppedIt => "what was handed over is not the change \
                                                     that stopped this device, nor one made \
                                                     after it: add this device again from a \
                                                     device that has that change"
                .into(),
            Self::Removed => "this device was removed: `cordelia init --new-key` first".into(),
            Self::InAFork => "this device has seen two changes made apart: the fork is settled \
                              first (`cordelia settle`)"
                .into(),
            Self::StoodElsewhere { typed, now } => format!(
                "that key was typed {}, and its yes was for that. This device {} now: what the \
                 key handed over was not taken. Run `cordelia accept` again, and read what its \
                 yes says",
                match typed {
                    Some(row) => format!("while this device {}", row.stood()),
                    None => "before this device kept what a yes was for".to_string(),
                },
                match now {
                    Some(row) => row.stands(),
                    None => "has stopped",
                }
            ),
        }
    }
}

/// Read the hand-over in `entry`, where it is one that this device takes
/// (decision 2026-10-04 §2.2, §6). The error inside says why it is not.
fn hand_over_in(
    identity: &NodeIdentity,
    typed: &[u8; 32],
    typed_at: i64,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Result<HandOver, NotAccepted>, PersonError> {
    // A pair channel is read only with a key typed in the last hour. Two
    // times that are too far apart to subtract are not within an hour.
    if !within_its_hour(typed_at, now) {
        return Ok(Err(NotAccepted::NotTypedInTheLastHour));
    }
    let pair = match derive::pair_secret(identity, typed) {
        Ok(pair) => pair,
        Err(DeriveError::Crypto(e)) => return Err(e.into()),
        Err(_) => return Ok(Err(NotAccepted::NoPairChannel)),
    };
    if entry.channel != derive::channel_id(&pair)? {
        return Ok(Err(NotAccepted::NotThePairChannel));
    }
    // One thing is taken from a pair channel, written by the other
    // device's key: the entry under the name `hand-over`.
    if entry.author != *typed {
        return Ok(Err(NotAccepted::SignedByAnotherKey));
    }
    let Ok(inside) = entry.open(&pair) else {
        return Ok(Err(NotAccepted::NotAHandOver));
    };
    let Value::Other(bytes) = &inside.value else {
        return Ok(Err(NotAccepted::NotAHandOver));
    };
    if inside.name != HAND_OVER_NAME {
        return Ok(Err(NotAccepted::NotAHandOver));
    }
    let hand_over = match HandOver::from_bytes(bytes) {
        Ok(hand_over) => hand_over,
        Err(e) => return Ok(Err(NotAccepted::HandOver(e))),
    };
    // And only where it was made about when the key was typed: a pair
    // channel outlives a phrase, and what was handed long ago is not what
    // the person means now. The time is the one the hand-over says, which
    // its signer signed with the rest.
    if !made_within_the_hour(hand_over.made_at, typed_at) {
        return Ok(Err(NotAccepted::NotMadeWithinTheHour));
    }
    if !hand_over.is_for(&identity.public_key()) {
        return Ok(Err(NotAccepted::NotForThisDevice));
    }
    // The record of the addition is the word of the device that adds: the
    // one whose key was typed.
    let by_another = |record: &SignedAddition| record.addition.adder != *typed;
    if hand_over.addition.as_ref().is_some_and(by_another) {
        return Ok(Err(NotAccepted::AddedByAnotherKey));
    }
    Ok(Ok(hand_over))
}

/// Whether a hand-over that says it was made at `made`, in seconds, was
/// made less than an hour before or after the key was typed.
fn made_within_the_hour(made: u64, typed_at: i64) -> bool {
    let Ok(made) = i64::try_from(made) else {
        return false;
    };
    made.checked_sub(typed_at)
        .and_then(i64::checked_abs)
        .is_some_and(|apart| apart < PAIR_KEY_TYPED_SECS)
}

/// What a hand-over brings, as a change that a device may apply.
struct Brought<'a> {
    hand_over: &'a HandOver,
    /// The hand-over's change entry, checked.
    entry: CheckedEntry,
    /// What a device follows that follows the hand-over's phrase.
    following: Following,
}

impl<'a> Brought<'a> {
    fn of(hand_over: &'a HandOver) -> Result<Self, PersonError> {
        let entry = hand_over.change_entry.clone().check()?;
        let following = Following {
            phrase_key: hand_over.statement.statement.phrase_key,
            statement_key: hand_over.statement_key,
            phrase_channel: entry.channel,
        };
        Ok(Self {
            hand_over,
            entry,
            following,
        })
    }

    fn statement(&self) -> &Statement {
        &self.hand_over.statement.statement
    }

    /// The hand-over as a change for a device that follows `following`, or
    /// comes to follow it.
    fn change<'b>(&'b self, following: &'b Following) -> Change<'b> {
        Change {
            following,
            statement: &self.hand_over.statement,
            secret: &self.hand_over.secret,
            entry: &self.entry,
        }
    }

    /// Apply the statement on this device, which follows `following`, or
    /// comes to follow it. `before` is what the device held under that
    /// phrase, and what it carries from.
    ///
    /// Rule 3 of §4.2: the statement lists this device, or a record of its
    /// addition comes with it and counts.
    fn applied_on(
        &self,
        conn: &Connection,
        identity: &NodeIdentity,
        before: Option<&Held>,
        following: &Following,
        now: i64,
    ) -> Result<Applied, PersonError> {
        let change = self.change(following);
        match &self.hand_over.addition {
            None => apply_judged(conn, identity, before, &change, now),
            Some(addition) => {
                let adders_own = self.hand_over.adders_own.as_ref();
                apply_added(conn, identity, before, &change, addition, adders_own, now)
            }
        }
    }

    /// What a device does with a hand-over under the phrase it already
    /// follows (decision 2026-10-04 §5.1): it takes one that brings a
    /// change it can apply, and no other.
    ///
    /// The statement is judged beside the one applied (§4.2). One that
    /// lists the device, or comes with a record of its addition, is
    /// applied, and the device carries what it holds. One that was made
    /// apart shows as a fork, on a device that has not stopped. Any other
    /// moves nothing.
    ///
    /// A device that has stopped, because it is in no list or could not
    /// open a change, takes only the statement that stopped it, or one
    /// made after that: it is not brought back behind a change it has
    /// seen.
    ///
    /// The hand-over's change entry is the one the device will keep and
    /// show. It is that statement's own entry under what the device
    /// follows, in the channel of the phrase it follows, or the hand-over
    /// is refused.
    fn taken_by(
        &self,
        conn: &Connection,
        identity: &NodeIdentity,
        held: &Held,
        now: i64,
    ) -> Result<Accepted, PersonError> {
        let refused = |why: HandOverError| Ok(Accepted::Refused(NotAccepted::HandOver(why)));
        match its_own_entry(&self.change(&held.following)) {
            Ok(()) => {}
            Err(PersonError::ChangeEntry(e)) => return refused(HandOverError::ChangeEntry(e)),
            Err(PersonError::NotTheStatementsEntry) => {
                return refused(HandOverError::NotTheStatementsEntry);
            }
            Err(e) => return Err(e),
        }
        let own = identity.public_key();
        let follows = &held.following.phrase_key;
        let judgement = match judge(
            &self.hand_over.statement,
            &held.statement.statement,
            &own,
            follows,
        ) {
            Ok(judgement) => judgement,
            Err(e) => return Ok(Accepted::Refused(NotAccepted::Statement(e))),
        };
        match judgement {
            Judgement::Behind => Ok(Accepted::Refused(NotAccepted::BringsNoChange)),
            Judgement::Removed => Ok(Accepted::Refused(NotAccepted::NotForThisDevice)),
            Judgement::Fork if held.state == State::Applied => {
                // The entry was opened as this statement's own, and the
                // statement judged, just above: shown to a device that
                // has not stopped, it is a fork, and can be nothing
                // else.
                match shown(conn, identity, &self.entry, now)? {
                    Shown::Fork => Ok(Accepted::Fork),
                    other => Err(PersonError::Held(format!(
                        "a statement made apart was shown, and was {other:?}"
                    ))),
                }
            }
            Judgement::Fork => Ok(Accepted::Refused(
                NotAccepted::NotAfterTheChangeThatStoppedIt,
            )),
            Judgement::Applies | Judgement::NotListed => {
                if held.state != State::Applied
                    && !self.is_after_what_stopped(conn, identity, held)?
                {
                    return Ok(Accepted::Refused(
                        NotAccepted::NotAfterTheChangeThatStoppedIt,
                    ));
                }
                self.applied_on(conn, identity, Some(held), &held.following, now)
                    .map(Accepted::Applied)
            }
        }
    }

    /// Whether the hand-over's statement is the one that stopped this
    /// device, or was made after it and keeps its removals. The statement
    /// that stopped it is in the change entry it keeps as the latest.
    fn is_after_what_stopped(
        &self,
        conn: &Connection,
        identity: &NodeIdentity,
        held: &Held,
    ) -> Result<bool, PersonError> {
        let following = &held.following;
        let stopped_by = change_entry::open_for_device(
            &latest_entry(conn)?,
            &following.phrase_key,
            &following.phrase_channel,
            &following.statement_key,
            identity,
        )
        .map_err(|e| PersonError::Held(format!("the entry that stopped this device: {e}")))?
        .statement
        .statement;
        let handed = self.statement();
        Ok(*handed == stopped_by
            || (handed.has_on_chain(&stopped_by.link()?)
                && handed.keeps_the_removals_of(&stopped_by)))
    }
}

/// Whether this device is alone under the phrase it follows (decision
/// 2026-10-04 §5.1): its statement lists no other device, and it has
/// added none. A record of an addition that it keeps, counted or not, is
/// a device added.
pub(crate) fn is_alone(
    conn: &Connection,
    held: &Held,
    own: &[u8; 32],
) -> Result<bool, PersonError> {
    let statement = &held.statement.statement;
    let lists_no_other = statement.devices.iter().all(|device| device.key == *own);
    Ok(lists_no_other && held_rows::additions(conn)?.is_empty())
}

/// A device that is alone under a phrase leaves it, to start afresh under
/// another (decision 2026-10-04 §4.2, §5.1): its names forget what they
/// held, and it forgets every secret it holds under that phrase.
///
/// The store drops every entry of every channel that the device can name
/// of the generations it leaves: the one it has applied, and each one it
/// left before and still holds the secret of. For each, that is the
/// personal channel, and the channel of each name it holds now. It keeps
/// its names: each has its channel under the statement it then applies.
///
/// What it follows, its statement and the change entry it keeps are
/// replaced where it applies the statement it is handed. It keeps no
/// record of an addition, and no entry of a statement made apart: it is
/// alone, and in no fork. The hand-overs it made go too: each holds a
/// secret of the phrase it leaves. What it kept of each relay for a
/// channel that it leaves goes with the channel.
///
/// **Its folders forget what they had agreed** (decision 2026-10-04
/// §5.2), with what they wrote down of index lines: each then meets the
/// channel it comes to as on any first sync, and nothing it lacks is
/// taken for a delete. And it keeps no note of the names that a personal
/// channel it left had listed: they were another phrase's.
///
/// Whoever calls this then writes a delete over each hand-over that
/// went ([`write_over_dropped`]) and empties the table of hand-overs
/// (decision 2026-10-04 §6): a device that has left keeps nothing of the
/// keys it added under the phrase it left. What it hands one of them
/// next is above the delete, where one was written.
pub(crate) fn leave(conn: &Connection, held: &Held) -> Result<(), PersonError> {
    // What is held holds together: the secret applied is the statement's.
    applied_secret(conn, &held.statement.statement)?;
    drop_hand_overs(conn, |_| false)?;
    let names = held_rows::names(conn)?;
    for generation in held_rows::secrets(conn)? {
        let personal = derive::personal_secret(&generation.secret)?;
        entries::remove_channel(conn, &derive::channel_id(&personal)?)?;
        kept_rows::forget_channel(conn, &derive::channel_id(&personal)?)?;
        for name in &names {
            let own = derive::own_secret(&generation.secret, &name.name)?;
            entries::remove_channel(conn, &derive::channel_id(&own)?)?;
            kept_rows::forget_channel(conn, &derive::channel_id(&own)?)?;
        }
    }
    held_rows::forget_secrets(conn)?;
    sync_state::forget_folders_except(conn, &[])?;
    held_rows::forget_names_before(conn, None)?;
    meta::remove(conn, meta::PERSON_NOT_CARRIED)?;
    meta::remove(conn, meta::PERSON_REMOVED_A_KEY)?;
    meta::remove(conn, meta::PERSON_NAMES_CARRIED)?;
    meta::remove(conn, meta::PERSON_REMOVED_LABELS)?;
    meta::remove(conn, meta::PERSON_NOT_SHOWN)?;
    meta::remove(conn, meta::PERSON_LOOK_PENDING)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::person::{first_statement, who_counts};
    use crate::several::{
        Machine, OTHER_WORDS, Several, change_that_does_not_open_for, entry_by, listed_as,
        signed_in, text,
    };
    use crate::take::{NotTaken, Taken, take};
    use cordelia_crypto::change_entry::ForPhrase;
    use cordelia_crypto::phrase::Phrase;

    const HOUR: i64 = 60 * 60;

    /// What a device applies that joins a person's devices, or moves to
    /// them: statement 1, with nothing left and nothing carried.
    fn first() -> Applied {
        Applied {
            number: 1,
            left: None,
            carried: 0,
            no_version: Vec::new(),
            not_carried: Vec::new(),
        }
    }

    /// Device `new` accepts `hand_over` with the key of device `typed`,
    /// typed just now.
    fn accepted(
        s: &Several,
        new: usize,
        typed: &[u8; 32],
        sync_on: bool,
        hand_over: &CheckedEntry,
    ) -> Accepted {
        let on = &s[new];
        accept(
            &on.conn,
            &on.identity,
            typed,
            s.now,
            sync_on,
            hand_over,
            s.now,
        )
        .unwrap()
    }

    /// The bytes of the hand-over in `entry`, an entry of the pair channel
    /// whose secret is `pair`.
    fn bytes_in(entry: &CheckedEntry, pair: &[u8; 32]) -> Vec<u8> {
        match entry.open(pair).unwrap().value {
            Value::Other(bytes) => bytes,
            other => panic!("{other:?}"),
        }
    }

    /// The hand-over in `entry`, which device `adder` made for the device
    /// whose key is `new`.
    fn hand_over_of(s: &Several, adder: usize, new: &[u8; 32], entry: &CheckedEntry) -> HandOver {
        let pair = derive::pair_secret(&s[adder].identity, new).unwrap();
        HandOver::from_bytes(&bytes_in(entry, &pair)).unwrap()
    }

    /// A device that follows another phrase, and what it hands the device
    /// whose key is `new`: a hand-over under that other phrase.
    fn handed_by_a_stranger(new: &Machine, now: i64) -> (Machine, CheckedEntry) {
        let stranger = Machine::new(90);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        first_statement(&stranger.conn, &stranger.identity, &other, "stranger", now).unwrap();
        let added = add_device(
            &stranger.conn,
            &stranger.identity,
            &new.key(),
            "theirs",
            now,
        );
        (stranger, added.unwrap().hand_over)
    }

    // ── The device that adds ─────────────────────────────────────────

    /// The device that adds makes the record of the addition, writes it
    /// in the personal channel, and makes the hand-over in the pair
    /// channel of the two keys, at the time it is made. Both wait in its
    /// store.
    #[test]
    fn test_the_device_that_adds_writes_the_record_and_makes_the_hand_over() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        let added = s.hand(0, 1);
        let (adder, new) = (&s[0], &s[1]);
        let personal = adder.personal();

        // The record: this device's own entry in the personal channel,
        // under the name of the key it adds, holding bytes.
        let entry = added.record.clone().unwrap();
        assert_eq!(entry.channel, derive::channel_id(&personal).unwrap());
        assert_eq!((entry.author, entry.rev), (adder.key(), 1));
        let inside = entry.open(&personal).unwrap();
        assert_eq!(inside.name, added_name(&new.key()).unwrap());
        assert_eq!(inside.chain, Some(Vec::new()));
        let Value::Other(bytes) = inside.value else {
            panic!("a record is bytes");
        };
        let record = SignedAddition::from_bytes(&bytes).unwrap();
        record.verify().unwrap();
        let statement = adder.held().statement;
        assert_eq!(record.addition.device, new.listed());
        assert_eq!(record.addition.adder, adder.key());
        assert_eq!(record.addition.under, statement.statement.link().unwrap());
        assert_eq!(record.addition.at, s.now as u64);
        // The device that adds counts the key from then.
        assert_eq!(added.seen, Some(AdditionSeen::Counted));
        assert!(adder.counts(&new.key()));

        // The hand-over: this device's own entry under `hand-over` in the
        // pair channel, which each of the two derives.
        let pair = derive::pair_secret(&adder.identity, &new.key()).unwrap();
        assert_eq!(
            pair,
            derive::pair_secret(&new.identity, &adder.key()).unwrap()
        );
        let entry = &added.hand_over;
        assert_eq!(entry.channel, derive::channel_id(&pair).unwrap());
        // Its revision is the time it was made, by the adder's clock.
        let made = s.now;
        assert_eq!((entry.author, entry.rev), (adder.key(), made as u64));
        let inside = entry.open(&pair).unwrap();
        assert_eq!(inside.name, HAND_OVER_NAME);
        assert_eq!(inside.chain, Some(Vec::new()));
        let hand_over = hand_over_of(&s, 0, &new.key(), entry);
        assert_eq!(hand_over.made_at, made as u64);
        assert_eq!(hand_over.statement, statement);
        assert_eq!(hand_over.secret, adder.secret());
        assert_eq!(
            hand_over.statement_key,
            adder.held().following.statement_key
        );
        assert_eq!(hand_over.change_entry, adder.latest().into_entry());
        assert_eq!(hand_over.addition, Some(record));
        assert_eq!(hand_over.adders_own, None);
        assert!(hand_over.is_for(&new.key()));

        // Both wait in the store.
        let stored = adder.stored();
        assert!(stored.contains(added.record.as_ref().unwrap()));
        assert_eq!(
            adder.stored_in(&pair),
            std::slice::from_ref(&added.hand_over)
        );
        // What the adder keeps of the hand-over is where it is, its very
        // revision and the time it says: what is written over it, once it
        // has gone, is one above that revision and no lower.
        let kept = held_rows::handed_over(&adder.conn, &new.key())
            .unwrap()
            .expect("the hand-over is kept of");
        assert_eq!(
            (kept.channel, kept.rev, kept.made_at, kept.held),
            (entry.channel, entry.rev, made, true)
        );

        // Added again, later: a record above the first, for a key that
        // counts already, and a hand-over at the time it is made, which
        // takes the place of the first in the store.
        let add = |now: i64| add_device(&adder.conn, &adder.identity, &new.key(), "device 1", now);
        let again = add(made + 100).unwrap();
        assert_eq!(again.record.as_ref().unwrap().rev, 2);
        assert_eq!(
            again.seen,
            Some(AdditionSeen::NotCounted(NotCounted::CountsAlready))
        );
        assert_eq!(again.hand_over.rev, made as u64 + 100);
        assert_eq!(
            adder.stored_in(&pair),
            std::slice::from_ref(&again.hand_over)
        );
        assert_eq!(who_counts(&adder.conn).unwrap().devices(), 2);

        // Two made in one second, and one made after the clock was set
        // back: each is one above the one before, and takes its place.
        let same_second = add(made + 100).unwrap();
        assert_eq!(same_second.hand_over.rev, made as u64 + 101);
        let set_back = add(made - 5000).unwrap();
        assert_eq!(set_back.hand_over.rev, made as u64 + 102);
        // Each says the time it was made, whatever its revision.
        let says = |added: &Added| hand_over_of(&s, 0, &new.key(), &added.hand_over).made_at;
        assert_eq!(
            [says(&again), says(&same_second), says(&set_back)],
            [made as u64 + 100, made as u64 + 100, made as u64 - 5000]
        );
        assert_eq!(
            adder.stored_in(&pair),
            std::slice::from_ref(&set_back.hand_over)
        );
        // A clock that says a time before 1970 gives no revision: nothing
        // is written. What the device handed before says a time far ahead
        // of such a clock, and goes first.
        assert_eq!(drop_old_hand_overs(&adder.conn, -5).unwrap(), 1);
        assert!(adder.stored_in(&pair).is_empty());
        let before = adder.everything();
        let fresh = Machine::new(8);
        assert!(matches!(
            add_device(&adder.conn, &adder.identity, &fresh.key(), "device 8", -5),
            Err(PersonError::Entry(_))
        ));
        assert_eq!(adder.everything(), before);
    }

    /// A record is written at one above this device's own entry in its
    /// slot, whatever another key has written there: a device that counts
    /// cannot stop another adding a key by writing under the record's
    /// name, at the last revision the statement has.
    #[test]
    fn test_no_other_keys_entry_stops_a_record_being_written() {
        use crate::take::{NotRead, Record, take};
        use cordelia_core::protocol::{REV_BAND_SIZE, REV_COUNT_BITS};

        let mut s = Several::of_one_person(2);
        let new = Machine::new(7);
        let name = added_name(&new.key()).unwrap();
        let top = (1 << REV_COUNT_BITS) + REV_BAND_SIZE - 1;
        let in_the_way = entry_by(
            &s[1].identity,
            &s[0].personal(),
            top,
            &name,
            text("in the way"),
            &[],
        );
        let adder = &s[0];
        assert_eq!(
            take(&adder.conn, &adder.identity, &in_the_way, s.now).unwrap(),
            Taken::Own {
                stored: entries::Outcome::Stored,
                record: Some(Record::NotRead(NotRead::NoBytes)),
                came_to_count: 0,
                came_to_add: 0,
            }
        );

        // Device 0 adds the key all the same: its record is its own entry
        // there, at revision 1, and says nothing of the other.
        let now = s.tick();
        let (adder, other) = (&s[0], &s[1]);
        let added = add_device(&adder.conn, &adder.identity, &new.key(), "device 7", now);
        let record = added.unwrap().record.unwrap();
        assert_eq!((record.author, record.rev), (adder.key(), 1));
        let inside = record.open(&adder.personal()).unwrap();
        assert_eq!((inside.name, inside.chain), (name, Some(Vec::new())));
        assert!(adder.counts(&new.key()));
        // A device that is given it reads the record from it: the key
        // counts, and may add, since a device of the statement added it.
        assert_eq!(
            take(&other.conn, &other.identity, &record, now).unwrap(),
            Taken::Own {
                stored: entries::Outcome::Stored,
                record: Some(Record::Seen(AdditionSeen::Counted)),
                came_to_count: 1,
                came_to_add: 1,
            }
        );
    }

    /// A key that the statement already lists is handed the change again,
    /// with no record: it is one of the person's devices already.
    #[test]
    fn test_a_key_that_the_statement_lists_is_handed_the_change_with_no_record() {
        let mut s = Several::of_one_person(2);
        let change = s.change(0, &[0, 1], &[]);
        let now = s.tick();
        let (adder, listed) = (&s[0], &s[1]);
        let before = adder.stored().len();
        // The label is the statement's: what is given here is not used.
        let added = add_device(&adder.conn, &adder.identity, &listed.key(), "", now).unwrap();
        assert_eq!((added.record, added.seen), (None, None));
        assert!(held_rows::additions(&adder.conn).unwrap().is_empty());
        // Nothing is written but the hand-over. The one that added the
        // device went from the store when the change was applied.
        assert_eq!(adder.stored().len(), before + 1);
        assert!(adder.stored().contains(&added.hand_over));
        assert_eq!(added.hand_over.rev, now as u64);

        let hand_over = hand_over_of(&s, 0, &listed.key(), &added.hand_over);
        assert_eq!((&hand_over.addition, &hand_over.adders_own), (&None, &None));
        assert_eq!(hand_over.statement.statement.number, 2);
        assert_eq!(hand_over.change_entry, change.clone().into_entry());
        assert!(hand_over.is_for(&listed.key()));
    }

    /// A device that was itself added since the statement hands over the
    /// record of its own addition with the record it makes.
    #[test]
    fn test_a_device_that_was_added_hands_over_the_record_of_its_own_addition() {
        let mut s = Several::new(4);
        s.make_phrase(0);
        let first = s.hand(0, 1);
        assert!(matches!(
            s.accept(1, 0, &first.hand_over),
            Accepted::Joined(_)
        ));
        let its_own = hand_over_of(&s, 0, &s.key(1), &first.hand_over).addition;

        let second = s.hand(1, 2);
        assert_eq!(second.seen, Some(AdditionSeen::Counted));
        let hand_over = hand_over_of(&s, 1, &s.key(2), &second.hand_over);
        assert_eq!(hand_over.adders_own, its_own);
        let record = hand_over.addition.unwrap();
        assert_eq!(
            (record.addition.adder, record.addition.device.key),
            (s.key(1), s.key(2))
        );
        // The device that is added counts both by them.
        assert!(matches!(
            s.accept(2, 1, &second.hand_over),
            Accepted::Joined(_)
        ));
        let kept = held_rows::additions(&s[2].conn).unwrap();
        let said: Vec<([u8; 32], [u8; 32], bool)> = kept
            .iter()
            .map(|one| (one.adder, one.key, one.counted))
            .collect();
        assert_eq!(
            said,
            [(s.key(0), s.key(1), true), (s.key(1), s.key(2), true)]
        );

        // Device 2 was added by a device added since, and may not add. A
        // device of the statement adds it too: it may then, and what it
        // hands over has that record with it, and not the first it kept.
        let by_a_listed = s.hand(0, 2);
        let lets_it_add = hand_over_of(&s, 0, &s.key(2), &by_a_listed.hand_over).addition;
        s.pass(0, 2);
        let third = s.hand(2, 3);
        let hand_over = hand_over_of(&s, 2, &s.key(3), &third.hand_over);
        assert_eq!(hand_over.adders_own, lets_it_add);
        assert_eq!(hand_over.adders_own.unwrap().addition.adder, s.key(0));
        assert!(matches!(
            s.accept(3, 2, &third.hand_over),
            Accepted::Joined(_)
        ));
    }

    /// Adding is refused on a device that is not in, for a key that was
    /// removed, on a device that may not add, and where the device counts
    /// 64 already. Nothing is written.
    #[test]
    fn test_adding_is_refused_on_a_device_or_for_a_key_that_may_not() {
        let new = Machine::new(7);
        let add = |on: &Machine, key: &[u8; 32], label: &str| {
            let before = on.everything();
            let added = add_device(&on.conn, &on.identity, key, label, 5);
            if added.is_err() {
                assert_eq!(on.everything(), before);
            }
            added
        };

        // A device that follows no phrase.
        let alone = Machine::new(8);
        assert!(matches!(
            add(&alone, &new.key(), "new"),
            Err(PersonError::FollowsNoPhrase)
        ));

        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1], &[2]);
        let on = &s[0];
        // A key that the statement lists as removed.
        assert!(matches!(
            add(on, &s.key(2), "back again"),
            Err(PersonError::KeyRemoved)
        ));
        // Its own key, a key that is no usable public key, and a label
        // that a statement could not carry.
        assert!(matches!(
            add(on, &on.key(), "itself"),
            Err(PersonError::Derive(DeriveError::OwnKey))
        ));
        assert!(matches!(
            add(on, &[0u8; 32], "no key"),
            Err(PersonError::Derive(_))
        ));
        assert!(matches!(
            add(on, &new.key(), ""),
            Err(PersonError::Statement(StatementError::LabelLength(0)))
        ));
        assert!(matches!(
            add(on, &new.key(), " new"),
            Err(PersonError::Statement(StatementError::LabelSpaceAtAnEnd))
        ));

        // A device that has stopped: in a fork, removed, in no list, or
        // listed in a change it could not open.
        for state in [
            State::Fork,
            State::Removed,
            State::NotListed,
            State::NotOpened,
        ] {
            held_rows::set_state(&on.conn, state).unwrap();
            assert!(matches!(
                add(on, &new.key(), "new"),
                Err(PersonError::Stopped(stopped)) if stopped == state
            ));
            // Nor does it hand the change to a key that its statement
            // lists: for that key it would make no record, and it is
            // refused all the same.
            assert!(matches!(
                add(on, &s.key(1), "device 1"),
                Err(PersonError::Stopped(stopped)) if stopped == state
            ));
        }
        held_rows::set_state(&on.conn, State::Applied).unwrap();

        // The statement lists devices 0 and 1. With 62 more that count,
        // the device counts 64: it adds no other. It still hands the
        // change to a key that the statement lists.
        let statement = on.held().statement.statement;
        for n in 100..162 {
            let record = Addition::under(&statement, listed_as(n), on.key(), 5)
                .unwrap()
                .sign(&on.identity)
                .unwrap();
            assert_eq!(
                see_addition(&on.conn, &record, 5).unwrap(),
                AdditionSeen::Counted
            );
        }
        assert_eq!(who_counts(&on.conn).unwrap().devices(), 64);
        assert!(matches!(
            add(on, &new.key(), "new"),
            Err(PersonError::NoRoom)
        ));
        let listed = add(on, &s.key(1), "device 1").unwrap();
        assert_eq!(listed.record, None);
        // And to a key that counts already by a record it keeps: that key
        // takes no room. The record it makes for it adds nobody.
        let counted = add(on, &listed_as(130).key, "added again").unwrap();
        assert!(counted.record.is_some());
        assert_eq!(
            counted.seen,
            Some(AdditionSeen::NotCounted(NotCounted::CountsAlready))
        );
        assert_eq!(who_counts(&on.conn).unwrap().devices(), 64);
        assert!(matches!(
            add(on, &new.key(), "new"),
            Err(PersonError::NoRoom)
        ));
        // The control: with room for one, it is added.
        held_rows::clear_additions(&on.conn).unwrap();
        assert_eq!(
            add(on, &new.key(), "new").unwrap().seen,
            Some(AdditionSeen::Counted)
        );
    }

    /// What adding would do is asked with nothing written, and is what
    /// adding then does: each refusal, a key that the statement lists, a
    /// key that counts already, and a key that was not in the last
    /// change.
    #[test]
    fn test_what_adding_would_do_is_asked_with_nothing_written() {
        let new = Machine::new(7);
        let would = |on: &Machine, key: &[u8; 32], label: &str| {
            let before = on.everything();
            let would = would_add(&on.conn, &on.identity, key, label);
            assert_eq!(on.everything(), before);
            // It is refused as adding is refused, or adding is not.
            let added = add_device(&on.conn, &on.identity, key, label, 5);
            match (&would, &added) {
                (Ok(_), Ok(_)) => {}
                (Err(asked), Err(done)) => assert_eq!(asked.to_string(), done.to_string()),
                other => panic!("{other:?}"),
            }
            would
        };
        let alone = Machine::new(8);
        assert!(matches!(
            would(&alone, &new.key(), "new"),
            Err(PersonError::FollowsNoPhrase)
        ));

        let mut s = Several::of_one_person(4);
        // Statement 2 lists devices 0 and 1, removes device 2, and says
        // nothing of device 3.
        s.change(0, &[0, 1], &[2]);
        let on = &s[0];
        assert!(matches!(
            would(on, &s.key(2), "back again"),
            Err(PersonError::KeyRemoved)
        ));
        assert!(matches!(
            would(on, &on.key(), "itself"),
            Err(PersonError::Derive(DeriveError::OwnKey))
        ));
        assert!(matches!(
            would(on, &new.key(), ""),
            Err(PersonError::Statement(StatementError::LabelLength(0)))
        ));
        for state in [
            State::Fork,
            State::Removed,
            State::NotListed,
            State::NotOpened,
        ] {
            held_rows::set_state(&on.conn, state).unwrap();
            for key in [new.key(), s.key(1)] {
                assert!(matches!(
                    would(on, &key, "new"),
                    Err(PersonError::Stopped(stopped)) if stopped == state
                ));
            }
        }
        held_rows::set_state(&on.conn, State::Applied).unwrap();

        // A key that the statement lists: the statement's label stands.
        assert_eq!(
            would(on, &s.key(1), "another name").unwrap(),
            WouldAdd::HandsAgain {
                label: "device 1".into()
            }
        );
        // A key that was not in the last change is said to be that,
        // under the label it was known by.
        assert_eq!(
            would_add(&on.conn, &on.identity, &s.key(3), "desktop").unwrap(),
            WouldAdd::Adds {
                counts_already: false,
                left_out_as: Some("device 3".into())
            }
        );
        // A new key, and then the same key once it counts by a record.
        assert_eq!(
            would_add(&on.conn, &on.identity, &new.key(), "new").unwrap(),
            WouldAdd::Adds {
                counts_already: false,
                left_out_as: None
            }
        );
        add_device(&on.conn, &on.identity, &new.key(), "new", 5).unwrap();
        assert_eq!(
            would_add(&on.conn, &on.identity, &new.key(), "new").unwrap(),
            WouldAdd::Adds {
                counts_already: true,
                left_out_as: None
            }
        );
        // With 64 that count, a record would be made for no other key:
        // and still for one that counts already.
        let statement = on.held().statement.statement;
        for n in 100..161 {
            let record = Addition::under(&statement, listed_as(n), on.key(), 5)
                .unwrap()
                .sign(&on.identity)
                .unwrap();
            see_addition(&on.conn, &record, 5).unwrap();
        }
        assert_eq!(who_counts(&on.conn).unwrap().devices(), 64);
        assert!(matches!(
            would(on, &Machine::new(200).key(), "one more"),
            Err(PersonError::NoRoom)
        ));
        assert_eq!(
            would_add(&on.conn, &on.identity, &listed_as(130).key, "again").unwrap(),
            WouldAdd::Adds {
                counts_already: true,
                left_out_as: None
            }
        );

        // A device that may not add: one that a device added since has
        // added.
        let mut s = Several::of_one_person(2);
        assert!(matches!(
            s.add(1, 0),
            Accepted::Refused(_) | Accepted::Applied(_)
        ));
        let third = Machine::new(9);
        let by_one = add_device(&s[1].conn, &s[1].identity, &third.key(), "third", s.now).unwrap();
        let joined = accept(
            &third.conn,
            &third.identity,
            &s.key(1),
            s.now,
            false,
            &by_one.hand_over,
            s.now,
        )
        .unwrap();
        assert!(matches!(joined, Accepted::Joined(_)));
        assert!(matches!(
            would(&third, &new.key(), "new"),
            Err(PersonError::MayNotAdd)
        ));
    }

    // ── The device that accepts ──────────────────────────────────────

    /// A key that a person typed reads its pair channel for an hour, and
    /// until a hand-over is taken with it: then it is spent, and what is
    /// given with it again is given to nobody.
    #[test]
    fn test_a_typed_key_is_spent_where_a_hand_over_is_taken_with_it() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        let added = s.hand(0, 1);
        let now = s.tick();
        let (on, adder) = (&s[1], s.key(0));
        assert!(keys_that_read(&on.conn, now).unwrap().is_empty());
        acts::type_key(&on.conn, &adder, "no_phrase", now).unwrap();
        let typed = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        assert_eq!(
            keys_that_read(&on.conn, now).unwrap(),
            std::slice::from_ref(&typed)
        );
        assert_eq!(keys_that_read(&on.conn, now + HOUR - 1).unwrap().len(), 1);
        assert!(keys_that_read(&on.conn, now + HOUR).unwrap().is_empty());
        assert!(keys_that_read(&on.conn, now - 1).unwrap().is_empty());

        let accepted = accept_typed(&on.conn, &on.identity, &typed, false, &added.hand_over, now)
            .unwrap()
            .expect("the key reads");
        assert!(matches!(accepted, Accepted::Joined(_)));
        assert!(on.follows_a_phrase());
        let spent = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        assert_eq!(spent.taken_at, Some(now));
        assert_eq!(spent.said, Some(accepted.says()));
        assert!(accepted.says().starts_with("this device has joined"));
        assert!(keys_that_read(&on.conn, now + 1).unwrap().is_empty());

        // The device then leaves, by a person's act of its own. The same
        // hand-over, given again with the key as it was typed then, is
        // given to nobody: the device is not moved back.
        leave(&on.conn, &on.held()).unwrap();
        held_rows::forget_person(&on.conn).unwrap();
        let before = on.everything();
        let again = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            now + 2,
        );
        assert_eq!(again.unwrap(), None);
        assert_eq!(on.everything(), before);
        assert!(!on.follows_a_phrase());
        // A person who means it types the key again.
        acts::type_key(&on.conn, &adder, "no_phrase", now + 3).unwrap();
        let typed = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        let again = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            now + 3,
        )
        .unwrap();
        assert!(matches!(again, Some(Accepted::Joined(_))));
    }

    /// A key typed at `cordelia accept` is kept with the row of §5.1 that
    /// its yes named, and only where the device stands in that row
    /// (decision 2026-10-04 §5.1, §16). Refused, with nothing kept: where
    /// the device stands in another row; a key that is the device's own;
    /// on a device that was removed; and alone under a phrase with sync
    /// on.
    #[test]
    fn test_a_typed_key_is_kept_with_the_row_that_its_yes_named() {
        let stood = |on: &Machine, key: &[u8; 32]| {
            acts::typed_key(&on.conn, key)
                .unwrap()
                .map(|typed| typed.stood)
        };
        let mut s = Several::new(3);
        let now = s.tick();
        // A device that follows no phrase.
        let (on, key) = (&s[1], s.key(0));
        for other in [Row::Alone, Row::Several, Row::NotListed] {
            assert!(matches!(
                type_key(&on.conn, &on.identity, &key, other, false, now),
                Err(PersonError::ChangedSincePrompt)
            ));
        }
        assert!(matches!(
            type_key(&on.conn, &on.identity, &on.key(), Row::NoPhrase, false, now),
            Err(PersonError::Derive(_))
        ));
        assert!(acts::typed_keys(&on.conn).unwrap().is_empty());
        type_key(&on.conn, &on.identity, &key, Row::NoPhrase, true, now).unwrap();
        assert_eq!(stood(on, &key).as_deref(), Some("no_phrase"));

        // Alone under a phrase: with sync off, and in that row.
        s.make_phrase(0);
        let (on, key) = (&s[0], s.key(1));
        assert!(matches!(
            type_key(&on.conn, &on.identity, &key, Row::NoPhrase, false, now),
            Err(PersonError::ChangedSincePrompt)
        ));
        assert!(matches!(
            type_key(&on.conn, &on.identity, &key, Row::Alone, true, now),
            Err(PersonError::SyncIsOn)
        ));
        assert_eq!(stood(on, &key), None);
        type_key(&on.conn, &on.identity, &key, Row::Alone, false, now).unwrap();
        assert_eq!(stood(on, &key).as_deref(), Some("alone"));

        // One of several, with sync on or off: typed again, the key is
        // kept in the row it was typed in this time.
        assert!(matches!(s.add(0, 1), Accepted::Joined(_)));
        let (on, key) = (&s[0], s.key(1));
        assert!(matches!(
            type_key(&on.conn, &on.identity, &key, Row::Alone, false, now),
            Err(PersonError::ChangedSincePrompt)
        ));
        assert_eq!(stood(on, &key).as_deref(), Some("alone"));
        type_key(&on.conn, &on.identity, &key, Row::Several, true, now).unwrap();
        assert_eq!(stood(on, &key).as_deref(), Some("several"));

        // A device that was removed keeps no key, whatever the yes named.
        s.change(0, &[0], &[1]);
        s.pass(0, 1);
        let (on, key) = (&s[1], s.key(0));
        assert_eq!(on.state(), State::Removed);
        for row in [Row::NoPhrase, Row::Alone, Row::Several, Row::NotListed] {
            assert!(matches!(
                type_key(&on.conn, &on.identity, &key, row, false, now),
                Err(PersonError::Stopped(State::Removed))
            ));
        }

        // Each row has its name, and a device that has stopped stands in
        // the fourth, or in none.
        for row in [Row::NoPhrase, Row::Alone, Row::Several, Row::NotListed] {
            assert_eq!(Row::named(row.name()), Some(row));
        }
        assert_eq!(Row::named(""), None);
        assert_eq!(Row::named("removed"), None);
        assert_eq!(Row::of(Among::NoPhrase), Some(Row::NoPhrase));
        assert_eq!(Row::of(Among::Alone), Some(Row::Alone));
        assert_eq!(Row::of(Among::Several(3)), Some(Row::Several));
        for stopped in [State::NotListed, State::NotOpened] {
            assert_eq!(Row::of(Among::Stopped(stopped)), Some(Row::NotListed));
        }
        for stopped in [State::Removed, State::Fork] {
            assert_eq!(Row::of(Among::Stopped(stopped)), None);
        }
    }

    /// A key typed under one row's yes is not spent under another row's
    /// act (decision 2026-10-04 §16). A new device types a key, and
    /// nothing arrives. It comes to be alone under a phrase of its own,
    /// with sync off, and the hand-over arrives within the hour: taken,
    /// it would have the device leave the phrase it has just made. It is
    /// not taken, and why is kept with the key.
    #[test]
    fn test_a_key_is_spent_only_in_the_row_that_its_yes_named() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        let added = s.hand(0, 1);
        let now = s.tick();
        let (on, adder) = (&s[1], s.key(0));
        type_key(&on.conn, &on.identity, &adder, Row::NoPhrase, false, now).unwrap();
        let typed = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        // It comes to follow a phrase of its own, with the key still
        // kept as it was typed.
        let its_own = Phrase::parse(OTHER_WORDS).unwrap();
        first_statement(&on.conn, &on.identity, &its_own, "device 1", now).unwrap();
        assert_eq!(acts::typed_keys(&on.conn).unwrap().len(), 1);

        let given = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            now + 5,
        )
        .unwrap();
        let refused = Accepted::Refused(NotAccepted::StoodElsewhere {
            typed: Some(Row::NoPhrase),
            now: Some(Row::Alone),
        });
        assert_eq!(given, Some(refused.clone()));
        assert_eq!(
            on.held().following.phrase_key,
            its_own.public_key().unwrap()
        );
        let kept = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        assert_eq!((kept.taken_at, kept.said), (None, Some(refused.says())));
        assert_eq!(
            refused.says(),
            "that key was typed while this device followed no recovery phrase, and its yes was \
             for that. This device is alone under a recovery phrase now: what the key handed \
             over was not taken. Run `cordelia accept` again, and read what its yes says"
        );

        // The control: typed again where the device stands, with its yes
        // for that, the same hand-over is taken, and the device moves.
        type_key(&on.conn, &on.identity, &adder, Row::Alone, false, now + 6).unwrap();
        let typed = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        let given = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            now + 6,
        )
        .unwrap();
        assert!(matches!(given, Some(Accepted::Moved(_))), "{given:?}");

        // A key that was typed before rows were kept stands in none: it
        // is typed again.
        let mut s = Several::new(2);
        s.make_phrase(0);
        let added = s.hand(0, 1);
        let now = s.tick();
        let (on, adder) = (&s[1], s.key(0));
        acts::type_key(&on.conn, &adder, "", now).unwrap();
        let typed = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        let given =
            accept_typed(&on.conn, &on.identity, &typed, false, &added.hand_over, now).unwrap();
        let refused = Accepted::Refused(NotAccepted::StoodElsewhere {
            typed: None,
            now: Some(Row::NoPhrase),
        });
        assert_eq!(given, Some(refused.clone()));
        assert!(!on.follows_a_phrase());
        assert!(
            refused
                .says()
                .contains("before this device kept what a yes was for")
        );
    }

    /// Making a phrase, and following one, each forget the keys that were
    /// typed (decision 2026-10-04 §16): none is spent under what the
    /// device has become. The key with which a hand-over was taken stays,
    /// spent, to say what became of it. (A device that leaves a phrase
    /// forgets everything a person typed there with the rest.)
    #[test]
    fn test_making_a_phrase_and_following_one_forget_the_keys_that_were_typed() {
        // Following one: two keys were typed, and one hands over.
        let mut s = Several::new(3);
        s.make_phrase(0);
        let added = s.hand(0, 2);
        let now = s.tick();
        let on = &s[2];
        for key in [s.key(1), s.key(0)] {
            type_key(&on.conn, &on.identity, &key, Row::NoPhrase, false, now).unwrap();
        }
        let typed = acts::typed_key(&on.conn, &s.key(0)).unwrap().unwrap();
        let given =
            accept_typed(&on.conn, &on.identity, &typed, false, &added.hand_over, now).unwrap();
        assert!(matches!(given, Some(Accepted::Joined(_))), "{given:?}");
        let kept = acts::typed_keys(&on.conn).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].key, kept[0].taken_at), (s.key(0), Some(now)));

        // Making one, on a device that followed none.
        let mut s = Several::new(2);
        let now = s.tick();
        let on = &s[0];
        type_key(&on.conn, &on.identity, &s.key(1), Row::NoPhrase, false, now).unwrap();
        let made = crate::person::first_entry(&s.phrase, &on.key(), "device 0").unwrap();
        crate::leaving::start_again(
            &on.conn,
            &on.identity,
            Among::NoPhrase,
            &made.entry,
            &made.statement_key,
            now,
        )
        .unwrap();
        assert!(on.follows_a_phrase());
        assert!(acts::typed_keys(&on.conn).unwrap().is_empty());
        // And on a device that was alone under one, which leaves it.
        type_key(&on.conn, &on.identity, &s.key(1), Row::Alone, false, now).unwrap();
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let made = crate::person::first_entry(&other, &on.key(), "device 0").unwrap();
        crate::leaving::start_again(
            &on.conn,
            &on.identity,
            Among::Alone,
            &made.entry,
            &made.statement_key,
            now + 1,
        )
        .unwrap();
        assert!(acts::typed_keys(&on.conn).unwrap().is_empty());
    }

    /// A device keeps at most eight typed keys that are within their
    /// hour, and a ninth is refused (decision 2026-10-04 §16). A key that
    /// is within its hour is typed again in its place. One whose hour
    /// has gone holds no place, though it is kept for a day to say what
    /// became of it; and one that was typed more than a day ago is
    /// forgotten.
    #[test]
    fn test_a_device_keeps_eight_typed_keys_and_refuses_a_ninth() {
        use cordelia_core::protocol::{PAIR_KEY_TYPED_SECS, TYPED_KEY_KEPT_SECS};
        let s = Several::new(1);
        let (on, now) = (&s[0], s.now);
        let key = |n: u16| crate::several::identity_of(100 + n).public_key();
        let types =
            |n: u16, at: i64| type_key(&on.conn, &on.identity, &key(n), Row::NoPhrase, false, at);
        let kept = || acts::typed_keys(&on.conn).unwrap().len();
        for n in 0..8 {
            types(n, now + i64::from(n)).unwrap();
        }
        let refused = types(8, now + 8).unwrap_err();
        assert!(matches!(refused, PersonError::TooManyTypedKeys));
        assert!(
            refused
                .to_string()
                .contains("each holds its place for an hour from when it was typed"),
            "{refused}"
        );
        assert_eq!(kept(), 8);
        assert_eq!(acts::typed_key(&on.conn, &key(8)).unwrap(), None);
        // One of the eight, typed again.
        types(3, now + 9).unwrap();
        let again = acts::typed_key(&on.conn, &key(3)).unwrap().unwrap();
        assert_eq!(again.typed_at, now + 9);
        assert_eq!(kept(), 8);

        // Until the hour of the first has gone there is no room: at its
        // last second a ninth is refused still.
        let an_hour_on = now + PAIR_KEY_TYPED_SECS;
        assert!(matches!(
            types(8, an_hour_on - 1),
            Err(PersonError::TooManyTypedKeys)
        ));
        // The hour of the first has gone: it holds no place, and a ninth
        // key is taken. The first is kept all the same, to say what
        // became of it.
        types(8, an_hour_on).unwrap();
        assert_eq!(kept(), 9);
        assert!(acts::typed_key(&on.conn, &key(0)).unwrap().is_some());
        // Eight are within their hour again (1, 2, and 4 to 8, and 3):
        // another is refused, and so is the first, typed again, which
        // would be a ninth.
        for n in [9, 0] {
            assert!(
                matches!(types(n, an_hour_on), Err(PersonError::TooManyTypedKeys)),
                "{n}"
            );
        }
        // Five seconds on, the hours of five more have gone (1, 2, 4 and
        // 5; 3 was typed again later): there is room for four.
        for n in [9, 10, 11, 0] {
            types(n, an_hour_on + 5).unwrap();
        }
        assert!(matches!(
            types(12, an_hour_on + 5),
            Err(PersonError::TooManyTypedKeys)
        ));
        assert_eq!(kept(), 12);

        // A day after it was typed a key is kept no longer.
        let a_day_on = now + TYPED_KEY_KEPT_SECS + 2;
        types(12, a_day_on).unwrap();
        assert_eq!(acts::typed_key(&on.conn, &key(1)).unwrap(), None);
        assert!(acts::typed_key(&on.conn, &key(2)).unwrap().is_some());
    }

    /// A hand-over that is refused spends no key: what became of it is
    /// kept for a person to read, and the node goes on asking. Once the
    /// hour has gone, or the key was typed again, what comes through
    /// under the old typing is given to nobody.
    #[test]
    fn test_a_refused_hand_over_spends_no_key_and_an_old_typing_reads_nothing() {
        let mut s = Several::new(3);
        s.make_phrase(0);
        // What device 0 hands device 2 is not for device 1.
        let for_another = s.hand(0, 2);
        let added = s.hand(0, 1);
        let now = s.tick();
        let (on, adder) = (&s[1], s.key(0));
        acts::type_key(&on.conn, &adder, "no_phrase", now).unwrap();
        let typed = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        let empty = on.everything();

        let refused = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &for_another.hand_over,
            now,
        )
        .unwrap()
        .unwrap();
        assert_eq!(refused, Accepted::Refused(NotAccepted::NotThePairChannel));
        assert_eq!(on.everything(), empty);
        let kept = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        assert_eq!(kept.taken_at, None);
        assert_eq!(kept.said, Some(refused.says()));
        assert_eq!(keys_that_read(&on.conn, now).unwrap().len(), 1);

        // The hour has gone: nothing is given to accept.
        let late = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            now + HOUR,
        );
        assert_eq!(late.unwrap(), None);
        assert_eq!(on.everything(), empty);
        // The key was typed again since: the old typing reads nothing.
        acts::type_key(&on.conn, &adder, "no_phrase", now + 10).unwrap();
        let old = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            now + 11,
        );
        assert_eq!(old.unwrap(), None);
        assert_eq!(on.everything(), empty);
        // And the new one does.
        let typed = acts::typed_key(&on.conn, &adder).unwrap().unwrap();
        let taken = accept_typed(
            &on.conn,
            &on.identity,
            &typed,
            false,
            &added.hand_over,
            now + 11,
        );
        assert!(matches!(taken.unwrap(), Some(Accepted::Joined(_))));
    }

    /// Each way a hand-over is not accepted is said in words of its own,
    /// and so is each way it is.
    #[test]
    fn test_what_became_of_a_hand_over_is_said_in_words() {
        let refusals = [
            NotAccepted::NotTypedInTheLastHour,
            NotAccepted::NoPairChannel,
            NotAccepted::NotAHandOver,
            NotAccepted::HandOver(HandOverError::Truncated),
            NotAccepted::NotMadeWithinTheHour,
            NotAccepted::NotForThisDevice,
            NotAccepted::AddedByAnotherKey,
            NotAccepted::RecordDoesNotCount(NotCounted::NoRoom),
            NotAccepted::SyncIsOn,
            NotAccepted::AnotherPhrase,
            NotAccepted::BringsNoChange,
            NotAccepted::Statement(StatementError::UndoesARemoval),
            NotAccepted::NotAfterTheChangeThatStoppedIt,
            NotAccepted::Removed,
            NotAccepted::InAFork,
        ];
        let mut said: Vec<String> = refusals.iter().map(NotAccepted::says).collect();
        let applied = first();
        said.extend([
            Accepted::Joined(applied.clone()).says(),
            Accepted::Moved(applied.clone()).says(),
            Accepted::Applied(applied).says(),
            Accepted::Fork.says(),
        ]);
        for (n, one) in said.iter().enumerate() {
            assert!(!one.is_empty());
            assert!(!said[..n].contains(one), "{one}");
        }
        // The ways on that the table of §5.1 names.
        assert!(NotAccepted::SyncIsOn.says().contains("`cordelia sync off`"));
        assert!(
            NotAccepted::Removed
                .says()
                .contains("`cordelia init --new-key`")
        );
        assert!(NotAccepted::InAFork.says().contains("`cordelia settle`"));
        assert!(NotAccepted::AnotherPhrase.says().contains("nothing moved"));
        assert!(Accepted::Fork.says().contains("`cordelia settle`"));
        assert_eq!(
            Accepted::Refused(NotAccepted::Removed).says(),
            NotAccepted::Removed.says()
        );
    }

    /// The entry is taken only if the key that was typed signed it, in
    /// the pair channel of that key and this device, under the name
    /// `hand-over`, and only if the key was typed within the last hour.
    #[test]
    fn test_a_hand_over_is_taken_only_from_the_key_typed_within_the_last_hour() {
        let mut s = Several::new(4);
        s.make_phrase(0);
        assert!(matches!(s.add(0, 3), Accepted::Joined(_)));
        let added = s.hand(0, 1);
        let (adder, new, now) = (&s[0], &s[1], s.now);
        let pair = derive::pair_secret(&adder.identity, &new.key()).unwrap();
        let bytes = bytes_in(&added.hand_over, &pair);
        let empty = new.everything();
        let refused = |typed: &[u8; 32], typed_at: i64, entry: &CheckedEntry| {
            let outcome =
                accept(&new.conn, &new.identity, typed, typed_at, false, entry, now).unwrap();
            assert_eq!(new.everything(), empty);
            match outcome {
                Accepted::Refused(why) => why,
                other => panic!("{other:?}"),
            }
        };
        let adder_key = adder.key();
        let made = now as u64;

        // Typed an hour ago, longer ago, and at a time that is yet to
        // come. And at a time so far from now that the two cannot be
        // subtracted.
        for typed_at in [
            now - HOUR,
            now - HOUR - 1,
            now - 9 * HOUR,
            now + 1,
            i64::MAX,
            i64::MIN,
        ] {
            assert_eq!(
                refused(&adder_key, typed_at, &added.hand_over),
                NotAccepted::NotTypedInTheLastHour,
                "{typed_at}"
            );
        }
        // A clock so far back that the time the hand-over was made cannot
        // be set beside the time the key was typed.
        let long_ago = accept(
            &new.conn,
            &new.identity,
            &adder_key,
            i64::MIN + 5,
            false,
            &added.hand_over,
            i64::MIN + 10,
        );
        assert_eq!(
            long_ago.unwrap(),
            Accepted::Refused(NotAccepted::NotMadeWithinTheHour)
        );
        assert_eq!(new.everything(), empty);
        // Another key was typed than the one that signed: the entry is of
        // another pair channel than that key's. And this device's own
        // key, or one that is no key, has none.
        assert_eq!(
            refused(&s.key(3), now, &added.hand_over),
            NotAccepted::NotThePairChannel
        );
        assert_eq!(
            refused(&new.key(), now, &added.hand_over),
            NotAccepted::NoPairChannel
        );
        assert_eq!(
            refused(&[0u8; 32], now, &added.hand_over),
            NotAccepted::NoPairChannel
        );
        // An entry of the pair channel that another key signed than the
        // one typed: this device's own.
        let own = entry_by(
            &new.identity,
            &pair,
            made,
            HAND_OVER_NAME,
            Value::Other(bytes.clone()),
            &[],
        );
        assert_eq!(
            refused(&adder_key, now, &own),
            NotAccepted::SignedByAnotherKey
        );

        // The hand-over as the adder signs it, saying another time: made
        // an hour before the key was typed, or longer before, or an hour
        // after, or longer after. Its entry is at the revision of now.
        let saying = |made_at: u64| {
            let hand_over = HandOver {
                made_at,
                ..HandOver::from_bytes(&bytes).unwrap()
            };
            let value = Value::Other(hand_over.to_bytes().unwrap());
            entry_by(&adder.identity, &pair, made, HAND_OVER_NAME, value, &[])
        };
        let hour = HOUR as u64;
        for says in [
            made - hour,
            made - 2 * hour,
            1,
            0,
            made + hour,
            made + 9 * hour,
            u64::MAX,
        ] {
            assert_eq!(
                refused(&adder_key, now, &saying(says)),
                NotAccepted::NotMadeWithinTheHour,
                "{says}"
            );
        }

        // Nothing else in a pair channel is read: an entry under another
        // name, one that holds a text, and one that does not open.
        let by_the_adder =
            |name: &str, value: Value| entry_by(&adder.identity, &pair, made, name, value, &[]);
        let misnamed = by_the_adder("hand-over-2", Value::Other(bytes.clone()));
        assert_eq!(
            refused(&adder_key, now, &misnamed),
            NotAccepted::NotAHandOver
        );
        let a_text = by_the_adder(HAND_OVER_NAME, text("a hand-over"));
        assert_eq!(refused(&adder_key, now, &a_text), NotAccepted::NotAHandOver);
        let elsewhere = entry_by(
            &adder.identity,
            &[0xee; 32],
            made,
            HAND_OVER_NAME,
            text("x"),
            &[],
        );
        let unread = signed_in(
            &pair,
            &adder.identity,
            added.hand_over.slot,
            made,
            elsewhere.content.clone(),
        );
        assert_eq!(refused(&adder_key, now, &unread), NotAccepted::NotAHandOver);
        // Bytes that are no hand-over, and a hand-over that does not hold
        // together: its secret is another than the statement commits to.
        let no_hand_over = by_the_adder(HAND_OVER_NAME, Value::Other(vec![1, 2, 3]));
        assert!(matches!(
            refused(&adder_key, now, &no_hand_over),
            NotAccepted::HandOver(_)
        ));
        let mut changed = bytes.clone();
        let secret_at = 8 + 2 + adder.held().statement.to_bytes().unwrap().len();
        changed[secret_at] ^= 1;
        let does_not_hold = by_the_adder(HAND_OVER_NAME, Value::Other(changed));
        assert_eq!(
            refused(&adder_key, now, &does_not_hold),
            NotAccepted::HandOver(HandOverError::SecretNotCommitted)
        );

        // A hand-over that is for another device: device 0 made it for
        // device 2.
        let for_another = s.hand(0, 2);
        let theirs = derive::pair_secret(&s[0].identity, &s.key(2)).unwrap();
        let moved = entry_by(
            &s[0].identity,
            &pair,
            s.now as u64,
            HAND_OVER_NAME,
            Value::Other(bytes_in(&for_another.hand_over, &theirs)),
            &[],
        );
        let (new, now) = (&s[1], s.now);
        let refused = |typed: &[u8; 32], entry: &CheckedEntry| {
            let outcome = accept(&new.conn, &new.identity, typed, now, false, entry, now).unwrap();
            assert_eq!(new.everything(), empty);
            outcome
        };
        assert_eq!(
            refused(&adder_key, &moved),
            Accepted::Refused(NotAccepted::NotForThisDevice)
        );
        // A record of this device's addition that another device signed
        // than the one whose key was typed: device 3 made it.
        let by_another = s.hand(3, 1);
        let (new, now) = (&s[1], s.now);
        let theirs = derive::pair_secret(&s[3].identity, &new.key()).unwrap();
        let relayed = entry_by(
            &s[0].identity,
            &pair,
            now as u64,
            HAND_OVER_NAME,
            Value::Other(bytes_in(&by_another.hand_over, &theirs)),
            &[],
        );
        let outcome = accept(
            &new.conn,
            &new.identity,
            &adder_key,
            now,
            false,
            &relayed,
            now,
        );
        assert_eq!(
            outcome.unwrap(),
            Accepted::Refused(NotAccepted::AddedByAnotherKey)
        );
        assert_eq!(new.everything(), empty);

        // The control: the entry that the key typed signed, typed one
        // second less than an hour ago.
        let joined = accept(
            &new.conn,
            &new.identity,
            &adder_key,
            now - HOUR + 1,
            false,
            &added.hand_over,
            now,
        );
        assert_eq!(joined.unwrap(), Accepted::Joined(first()));

        // And one that was made one second less than an hour before the
        // key was typed, and one made as long after: each is taken.
        for (n, apart) in [(7, 1 - HOUR), (8, HOUR - 1)] {
            let (adder, new) = (&s[0], Machine::new(n));
            let added = add_device(&adder.conn, &adder.identity, &new.key(), "new", now + apart);
            assert_eq!(added.as_ref().unwrap().hand_over.rev, (now + apart) as u64);
            let taken = accept(
                &new.conn,
                &new.identity,
                &adder_key,
                now,
                false,
                &added.unwrap().hand_over,
                now,
            );
            assert_eq!(taken.unwrap(), Accepted::Joined(first()), "{apart}");
        }
        // The entry's revision is not asked: a hand-over that says it was
        // made now is taken from an entry at the first revision, and from
        // one nine hours ahead.
        for (n, rev) in [(9, 1), (10, made + 9 * hour)] {
            let (adder, new) = (&s[0], Machine::new(n));
            let added = add_device(&adder.conn, &adder.identity, &new.key(), "new", now);
            let pair = derive::pair_secret(&adder.identity, &new.key()).unwrap();
            let entry = entry_by(
                &adder.identity,
                &pair,
                rev,
                HAND_OVER_NAME,
                Value::Other(bytes_in(&added.unwrap().hand_over, &pair)),
                &[],
            );
            let taken = accept(
                &new.conn,
                &new.identity,
                &adder_key,
                now,
                false,
                &entry,
                now,
            );
            assert_eq!(taken.unwrap(), Accepted::Joined(first()), "{rev}");
        }
    }

    /// The revision of a hand-over's entry only orders the hand-overs of
    /// one device to another, and can run ahead of the clock for good.
    /// When a hand-over was made is what it says itself, and that is what
    /// is set beside the time the key was typed.
    #[test]
    fn test_a_hand_over_is_taken_by_the_time_it_says_whatever_its_revision() {
        let mut s = Several::new(3);
        s.make_phrase(0);
        let now = s.now;
        let adder = &s[0];
        let add = |new: usize, at: i64| {
            add_device(&adder.conn, &adder.identity, &s.key(new), "new", at)
                .unwrap()
                .hand_over
        };
        let typed = |new: usize, entry: &CheckedEntry, at: i64| {
            let on = &s[new];
            accept(&on.conn, &on.identity, &adder.key(), at, false, entry, at).unwrap()
        };

        // The adder's clock is three hours ahead. What it hands device 1
        // says so, and is refused: it was made long after the key was
        // typed.
        let ahead = add(1, now + 3 * HOUR);
        assert_eq!(ahead.rev, (now + 3 * HOUR) as u64);
        assert_eq!(
            typed(1, &ahead, now + 5),
            Accepted::Refused(NotAccepted::NotMadeWithinTheHour)
        );
        // The clock is set right, and it hands over again. The entry is
        // one above the one before, hours ahead of the clock: the
        // hand-over says the time it was made, and is taken.
        let right = add(1, now + 10);
        assert_eq!(right.rev, ahead.rev + 1);
        assert_eq!(
            hand_over_of(&s, 0, &s.key(1), &right).made_at,
            (now + 10) as u64
        );
        assert_eq!(typed(1, &right, now + 20), Accepted::Joined(first()));

        // About 3,700 hand-overs to device 2 within an hour, each one
        // above the one before: the last is at a revision more than an
        // hour ahead of the clock, and is taken all the same.
        let first_of_them = add(2, now);
        // What the device keeps of the 3,699th: its revision.
        held_rows::note_hand_over(
            &adder.conn,
            &s.key(2),
            &first_of_them.channel,
            first_of_them.rev + 3_698,
            now + 59,
        )
        .unwrap();
        let last = add(2, now + 60);
        assert_eq!(last.rev, now as u64 + 3_699);
        assert!(last.rev - (now as u64 + 60) > HOUR as u64);
        assert_eq!(typed(2, &last, now + 61), Accepted::Joined(first()));
    }

    /// What a key signed before it was added was refused, and not kept.
    /// The device that adds it takes the record as any record is taken:
    /// the key counts from then, and what it signed is taken when the
    /// caller gives it again, which is what the caller owes.
    #[test]
    fn test_what_a_key_signed_before_it_was_added_is_taken_once_it_is_given_again() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        s.hold(&[0], "notes");
        let notes = s[0].own("notes");
        let theirs = entry_by(&s[1].identity, &notes, 1, "a.md", text("early"), &[]);
        let given = |s: &Several| take(&s[0].conn, &s[0].identity, &theirs, s.now).unwrap();
        assert_eq!(given(&s), Taken::Refused(NotTaken::SignerDoesNotCount));

        let added = s.hand(0, 1);
        assert!(added.record.is_some());
        assert_eq!(added.seen, Some(AdditionSeen::Counted));
        // Nothing of it was kept, and nothing here gives it again.
        assert!(s[0].stored_in(&notes).is_empty());
        assert_eq!(
            given(&s),
            Taken::Own {
                stored: entries::Outcome::Stored,
                record: None,
                came_to_count: 0,
                came_to_add: 0,
            }
        );
    }

    /// Nothing remembers what a device has accepted: a hand-over is taken
    /// by the state the device is in each time it is given, with a key
    /// typed within the hour. A device that joined, and then within the
    /// hour made a phrase of its own, with sync off, is moved back where
    /// the same hand-over is given again with the same typing. So the
    /// caller spends the typed key once a hand-over has been taken.
    #[test]
    fn test_a_hand_over_given_again_with_the_same_typing_is_judged_afresh() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        let added = s.hand(0, 1);
        let typed_at = s.tick();
        let (adder, new) = (&s[0], &s[1]);
        let given = |sync_on: bool, now: i64| {
            let typed = adder.key();
            let entry = &added.hand_over;
            accept(
                &new.conn,
                &new.identity,
                &typed,
                typed_at,
                sync_on,
                entry,
                now,
            )
            .unwrap()
        };
        assert_eq!(given(false, typed_at + 1), Accepted::Joined(first()));
        // Given again as it stands, it brings nothing.
        assert_eq!(
            given(false, typed_at + 2),
            Accepted::Refused(NotAccepted::BringsNoChange)
        );

        // Within the hour the device makes a phrase of its own. By an act
        // that is not built here it follows none, and then it makes its
        // first statement.
        new.conn
            .execute_batch(
                "DELETE FROM person; DELETE FROM person_secrets;
                 DELETE FROM person_change_entries; DELETE FROM person_additions;
                 DELETE FROM person_names; DELETE FROM entries;",
            )
            .unwrap();
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        first_statement(&new.conn, &new.identity, &other, &new.label, typed_at + 60).unwrap();
        let follows = || new.held().following.phrase_key;
        assert_eq!(follows(), other.public_key().unwrap());

        // The same hand-over, with the same typing. With sync on it moves
        // nothing. With sync off the device is moved back.
        assert_eq!(
            given(true, typed_at + 120),
            Accepted::Refused(NotAccepted::SyncIsOn)
        );
        assert_eq!(follows(), other.public_key().unwrap());
        assert_eq!(given(false, typed_at + 120), Accepted::Moved(first()));
        assert_eq!(follows(), s.phrase.public_key().unwrap());
        assert_eq!(new.secret(), adder.secret());

        // The typing is spent by the hour, and by nothing else here.
        assert_eq!(
            given(false, typed_at + HOUR),
            Accepted::Refused(NotAccepted::NotTypedInTheLastHour)
        );
    }

    /// A hand-over holds the person secret, and does not stay in the store
    /// of the device that made it: it goes two hours after the time it
    /// says it was made. What the device keeps of it is its revision, and
    /// the next it makes for that key is above it.
    #[test]
    fn test_a_hand_over_leaves_the_store_two_hours_after_the_time_it_says() {
        let mut s = Several::new(4);
        s.make_phrase(0);
        let now = s.now;
        let adder = &s[0];
        let pair = |new: usize| derive::pair_secret(&adder.identity, &s.key(new)).unwrap();
        let add = |new: usize, at: i64| {
            add_device(&adder.conn, &adder.identity, &s.key(new), "new", at)
                .unwrap()
                .hand_over
        };
        let drop_at = |at: i64| drop_old_hand_overs(&adder.conn, at).unwrap();
        let kept = |new: usize| {
            let last = held_rows::handed_over(&adder.conn, &s.key(new)).unwrap();
            let last = last.unwrap();
            (last.rev, last.made_at, last.held)
        };

        // One second short of two hours after it was made, it stays.
        let made = add(1, now);
        assert_eq!(drop_at(now + 2 * HOUR - 1), 0);
        assert_eq!(adder.stored_in(&pair(1)), std::slice::from_ref(&made));
        assert_eq!(kept(1), (made.rev, now, true));
        // At two hours it goes, and what is kept is its revision.
        let others = adder.stored().len() - 1;
        assert_eq!(drop_at(now + 2 * HOUR), 1);
        assert!(adder.stored_in(&pair(1)).is_empty());
        assert_eq!(adder.stored().len(), others);
        assert_eq!(kept(1), (made.rev, now, false));
        assert_eq!(drop_at(now + 3 * HOUR), 0);

        // The next for that key is above it, though the store holds none
        // and the clock was set back.
        let next = add(1, now - 100);
        assert_eq!(next.rev, made.rev + 1);
        assert_eq!(adder.stored_in(&pair(1)), std::slice::from_ref(&next));
        assert_eq!(kept(1), (made.rev + 1, now - 100, true));

        // A device that adds drops them first: two hours after the time
        // that one says, it is gone.
        let later = add(2, now - 100 + 2 * HOUR);
        assert!(adder.stored_in(&pair(1)).is_empty());
        assert_eq!(adder.stored_in(&pair(2)), std::slice::from_ref(&later));
        // A device that accepts drops them first, whatever comes of what
        // it is given.
        let at = now - 100 + 4 * HOUR;
        let given = accept(
            &adder.conn,
            &adder.identity,
            &s.key(3),
            at,
            false,
            &later,
            at,
        );
        assert_eq!(
            given.unwrap(),
            Accepted::Refused(NotAccepted::NotThePairChannel)
        );
        assert!(adder.stored_in(&pair(2)).is_empty());
        assert_eq!(kept(2), (later.rev, now - 100 + 2 * HOUR, false));
        // So does one that fails: this device does not add itself.
        let again = add(2, at);
        assert!(
            add_device(
                &adder.conn,
                &adder.identity,
                &adder.key(),
                "",
                at + 2 * HOUR
            )
            .is_err()
        );
        assert!(adder.stored_in(&pair(2)).is_empty());
        assert_eq!(kept(2), (again.rev, at, false));

        // One that says a time two hours or more ahead of the clock was
        // made by a clock since set back. It goes too, and does not wait
        // for that time.
        let ahead = add(3, now + 10 * HOUR);
        assert_eq!(drop_at(now + 8 * HOUR + 1), 0);
        assert_eq!(adder.stored_in(&pair(3)), std::slice::from_ref(&ahead));
        assert_eq!(drop_at(now + 8 * HOUR), 1);
        assert!(adder.stored_in(&pair(3)).is_empty());
        // The next is above it, hours ahead of the clock.
        assert_eq!(add(3, now + 8 * HOUR).rev, ahead.rev + 1);

        // A clock that cannot be set beside the time a hand-over says:
        // the hand-over goes. The two are further apart than a number
        // of seconds can say, one way and then the other.
        assert_eq!(drop_at(i64::MIN + now + 8 * HOUR), 1);
        add(3, now + 8 * HOUR);
        assert_eq!(drop_at(i64::MIN), 1);
        assert!(adder.stored_in(&pair(3)).is_empty());
    }

    /// Every hand-over a device made goes from its store when it applies
    /// a statement: each holds the secret of the statement it leaves. The
    /// next it makes for a key is above the last all the same.
    #[test]
    fn test_a_hand_over_leaves_the_store_when_a_statement_is_applied() {
        let mut s = Several::new(4);
        s.make_phrase(0);
        assert!(matches!(s.add(0, 1), Accepted::Joined(_)));
        let pair = |s: &Several, of: usize, new: usize| {
            derive::pair_secret(&s[of].identity, &s.key(new)).unwrap()
        };
        let kept = |s: &Several, of: usize, new: usize| {
            let last = held_rows::handed_over(&s[of].conn, &s.key(new)).unwrap();
            let last = last.unwrap();
            (last.rev, last.held)
        };

        // Each of the two has handed a key the change, and each holds
        // what it handed.
        let by_0 = s.hand(0, 2).hand_over;
        let by_1 = s.hand(1, 3).hand_over;
        assert_eq!(s[0].stored_in(&pair(&s, 0, 2)), std::slice::from_ref(&by_0));
        assert_eq!(s[1].stored_in(&pair(&s, 1, 3)), std::slice::from_ref(&by_1));
        // The one that added device 1 is there still, too.
        assert_eq!(s[0].stored_in(&pair(&s, 0, 1)).len(), 1);

        // Device 0 makes a change, and applies it as it is shown it:
        // everything it handed is gone.
        let now = s.now;
        let change = s.change(0, &[0, 1], &[]);
        assert!(s[0].stored_in(&pair(&s, 0, 2)).is_empty());
        assert!(s[0].stored_in(&pair(&s, 0, 1)).is_empty());
        assert_eq!(kept(&s, 0, 2), (by_0.rev, false));
        // Device 1 is handed the change, and applies it as it accepts:
        // what it handed is gone.
        let handed = s.hand(0, 1).hand_over;
        assert!(matches!(s.accept(1, 0, &handed), Accepted::Applied(_)));
        assert_eq!(s[1].latest(), change);
        assert!(s[1].stored_in(&pair(&s, 1, 3)).is_empty());
        assert_eq!(kept(&s, 1, 3), (by_1.rev, false));

        // The next that device 0 makes for the key is above the last,
        // though it is made at a time before it and the store held none.
        let adder = &s[0];
        let next = add_device(
            &adder.conn,
            &adder.identity,
            &s.key(2),
            "device 2",
            now - 50,
        );
        let next = next.unwrap().hand_over;
        assert_eq!(next.rev, by_0.rev + 1);
        assert_eq!(adder.stored_in(&pair(&s, 0, 2)), [next]);
    }

    /// Every hand-over a device made goes from its store when it leaves
    /// its phrase for another: each holds a secret of the phrase it
    /// leaves. The next it makes for a key is above the last all the
    /// same.
    ///
    /// Two things keep this from being seen from outside. A device that
    /// has added a key is not alone, and one that applies a statement
    /// drops what it handed: nothing here leaves a device alone with a
    /// hand-over in its store. Each device here is put in that state by
    /// hand, as one would be that had lost the record it made. And a
    /// device that leaves a phrase applies the statement it is handed in
    /// the same step, which drops what it handed too. So the first device
    /// here only leaves: leaving does not lean on the other two.
    #[test]
    fn test_a_hand_over_leaves_the_store_when_the_device_leaves_its_phrase() {
        // A device that only leaves.
        let mut s = Several::new(2);
        s.make_phrase(0);
        let old = s.hand(0, 1).hand_over;
        let on = &s[0];
        held_rows::clear_additions(&on.conn).unwrap();
        let pair = derive::pair_secret(&on.identity, &s.key(1)).unwrap();
        assert_eq!(on.stored_in(&pair), std::slice::from_ref(&old));
        leave(&on.conn, &on.held()).unwrap();
        assert!(on.stored_in(&pair).is_empty());
        let last = held_rows::handed_over(&on.conn, &s.key(1)).unwrap();
        let last = last.unwrap();
        assert_eq!((last.rev, last.held), (old.rev, false));

        // A device that leaves, and applies what it is handed.
        let mut s = Several::new(3);
        s.make_phrase(0);
        let old = s.hand(0, 1).hand_over;
        let made = s.now;
        held_rows::clear_additions(&s[0].conn).unwrap();
        let pair = derive::pair_secret(&s[0].identity, &s.key(1)).unwrap();
        assert_eq!(s[0].stored_in(&pair), std::slice::from_ref(&old));
        let old_secret = s[0].secret();
        assert_eq!(hand_over_of(&s, 0, &s.key(1), &old).secret, old_secret);

        // It leaves its phrase for the one that device 2 made.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let on = &s[2];
        first_statement(&on.conn, &on.identity, &other, &on.label, s.now).unwrap();
        let handed = s.hand(2, 0);
        assert_eq!(s.accept(0, 2, &handed.hand_over), Accepted::Moved(first()));
        assert_ne!(s[0].secret(), old_secret);
        // What it handed under the phrase it left is gone, and it keeps
        // nothing of any hand-over it made: not the key, and not the
        // revision.
        assert!(s[0].stored_in(&pair).is_empty());
        let adder = &s[0];
        assert_eq!(
            held_rows::handed_over(&adder.conn, &s.key(1)).unwrap(),
            None
        );
        assert!(held_rows::hand_overs_gone(&adder.conn).unwrap().is_empty());

        // It adds device 1 again under the phrase it follows now, in the
        // second in which it made the old one. No relay was sent the old
        // one: there is nothing for the new one to be above.
        let new = add_device(&adder.conn, &adder.identity, &s.key(1), "device 1", made);
        let new = new.unwrap().hand_over;
        assert_eq!(new.rev, old.rev);
        assert_eq!(adder.stored_in(&pair), std::slice::from_ref(&new));
        assert_eq!(hand_over_of(&s, 0, &s.key(1), &new).secret, adder.secret());
    }

    /// A relay that was sent a hand-over holds it still when the device
    /// that made it has dropped it. So that device writes a delete over
    /// it, one revision above, which waits in its store to be sent. None
    /// is written over a hand-over that the store still holds, where no
    /// relay was sent anything of the pair channel, or a second time.
    #[test]
    fn test_a_delete_is_written_over_a_hand_over_that_has_gone_where_a_relay_was_sent_it() {
        const RELAY: [u8; 32] = [0xa1; 32];
        let mut s = Several::new(4);
        s.make_phrase(0);
        let now = s.now;
        let adder = &s[0];
        let pair = |new: usize| derive::pair_secret(&adder.identity, &s.key(new)).unwrap();
        let add = |new: usize, at: i64| {
            add_device(&adder.conn, &adder.identity, &s.key(new), "new", at)
                .unwrap()
                .hand_over
        };
        let write_over = |at: i64| write_over_dropped(&adder.conn, &adder.identity, at).unwrap();
        let (to_1, _to_2) = (add(1, now), add(2, now));
        // A relay was sent the first, and none was sent the second.
        kept_rows::sending(&adder.conn, &RELAY, &to_1.channel).unwrap();

        // While the store holds them, nothing is written over either.
        assert_eq!(write_over(now + 60), 0);
        assert_eq!(adder.stored_in(&pair(1)), std::slice::from_ref(&to_1));
        // Two hours on both go, and a delete is written over the first:
        // this device's own entry under the hand-over's name, one
        // revision above it.
        let later = now + 2 * HOUR;
        assert_eq!(drop_old_hand_overs(&adder.conn, later).unwrap(), 2);
        assert!(adder.stored_in(&pair(1)).is_empty());
        assert_eq!(write_over(later), 1);
        let over = adder.stored_in(&pair(1));
        assert_eq!(over.len(), 1);
        assert_eq!(
            (over[0].author, over[0].rev, over[0].delete),
            (adder.key(), to_1.rev + 1, true)
        );
        assert_eq!(over[0].slot, to_1.slot);
        let inside = over[0].open(&pair(1)).unwrap();
        assert_eq!(
            (inside.name.as_str(), inside.value),
            (HAND_OVER_NAME, Value::Delete)
        );
        // Over the second, which no relay was sent, nothing is written.
        assert!(adder.stored_in(&pair(2)).is_empty());
        // And nothing a second time.
        assert_eq!(write_over(later + 60), 0);
        assert_eq!(adder.stored_in(&pair(1)), over);
        // What the device keeps of the hand-over is as it was.
        let last = held_rows::handed_over(&adder.conn, &s.key(1)).unwrap();
        let last = last.unwrap();
        assert_eq!((last.rev, last.held), (to_1.rev, false));

        // The next that it makes for that key is above the delete, though
        // the clock was set back: it takes the delete's place.
        let next = add(1, now - 100);
        assert_eq!(next.rev, to_1.rev + 2);
        assert_eq!(adder.stored_in(&pair(1)), std::slice::from_ref(&next));
        // And once that one has gone, the delete over it is above it.
        assert_eq!(drop_old_hand_overs(&adder.conn, later).unwrap(), 1);
        assert_eq!(write_over(later), 1);
        let over = adder.stored_in(&pair(1));
        assert_eq!((over[0].rev, over[0].delete), (to_1.rev + 3, true));

        // A device that made none writes none.
        let other = &s[1];
        assert_eq!(
            write_over_dropped(&other.conn, &other.identity, later).unwrap(),
            0
        );
    }

    /// A device that leaves its phrase writes a delete over what it had
    /// handed over and a relay was sent, in the step in which it leaves,
    /// and then keeps nothing of any hand-over it made. The next that it
    /// makes for that key is above the delete. What it kept of a relay
    /// for a channel that it leaves goes with the channel.
    #[test]
    fn test_a_device_that_leaves_writes_over_what_it_handed_and_keeps_nothing_of_it() {
        const RELAY: [u8; 32] = [0xa1; 32];
        const MARK: [u8; 8] = [0x4d, 1, 2, 3, 4, 5, 6, 7];
        let mut s = Several::new(4);
        s.make_phrase(0);
        s.hold(&[0], "notes");
        let sent = s.hand(0, 1).hand_over;
        s.hand(0, 3);
        let made = s.now;
        held_rows::clear_additions(&s[0].conn).unwrap();
        let on = &s[0];
        kept_rows::sending(&on.conn, &RELAY, &sent.channel).unwrap();
        // It has a place at the relay in each channel of its own.
        let left = [
            derive::channel_id(&on.personal()).unwrap(),
            derive::channel_id(&on.own("notes")).unwrap(),
        ];
        for channel in &left {
            kept_rows::keep_place(&on.conn, &RELAY, channel, &MARK, 3).unwrap();
            kept_rows::sent(&on.conn, &RELAY, channel, 2).unwrap();
        }

        // It leaves its phrase for the one that device 2 made.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let by = &s[2];
        first_statement(&by.conn, &by.identity, &other, &by.label, s.now).unwrap();
        let handed = s.hand(2, 0);
        assert_eq!(s.accept(0, 2, &handed.hand_over), Accepted::Moved(first()));

        let on = &s[0];
        let pair = derive::pair_secret(&on.identity, &s.key(1)).unwrap();
        let over = on.stored_in(&pair);
        assert_eq!(over.len(), 1);
        assert_eq!((over[0].rev, over[0].delete), (sent.rev + 1, true));
        // Nothing is written over the one that no relay was sent.
        let other_pair = derive::pair_secret(&on.identity, &s.key(3)).unwrap();
        assert!(on.stored_in(&other_pair).is_empty());
        // The table of hand-overs is empty.
        for key in [s.key(1), s.key(3)] {
            assert_eq!(held_rows::handed_over(&on.conn, &key).unwrap(), None);
        }
        assert!(held_rows::hand_overs_held(&on.conn).unwrap().is_empty());
        assert!(held_rows::hand_overs_gone(&on.conn).unwrap().is_empty());
        // That the relay was sent the hand-over is kept: the delete is
        // for it. Nothing is kept of the channels that were left.
        assert!(kept_rows::keeps_any(&on.conn, &RELAY, &sent.channel).unwrap());
        for channel in &left {
            assert!(!kept_rows::keeps_any_anywhere(&on.conn, channel).unwrap());
        }

        // The next that it makes for the key, in the second in which it
        // made the one before, is above the delete.
        let new = add_device(&on.conn, &on.identity, &s.key(1), "device 1", made);
        assert_eq!(new.unwrap().hand_over.rev, sent.rev + 2);
    }

    /// What a device kept of a relay for a channel of the generation it
    /// leaves goes with the channel when it applies a statement, and what
    /// its store had taken by then is what it carried.
    #[test]
    fn test_applying_a_statement_forgets_the_places_in_the_channels_it_leaves() {
        const RELAY: [u8; 32] = [0xa1; 32];
        const MARK: [u8; 8] = [0x4d, 1, 2, 3, 4, 5, 6, 7];
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        s.write(0, "notes", "a.md", "a text");
        let on = &s[0];
        let left = [
            derive::channel_id(&on.personal()).unwrap(),
            derive::channel_id(&on.own("notes")).unwrap(),
        ];
        let pair = derive::pair_secret(&on.identity, &s.key(1)).unwrap();
        let pair = derive::channel_id(&pair).unwrap();
        for channel in left.iter().chain([&pair]) {
            kept_rows::keep_place(&on.conn, &RELAY, channel, &MARK, 3).unwrap();
        }
        let carried_before = kept_rows::carried_up_to(&on.conn).unwrap();

        s.change(0, &[0, 1], &[]);
        let on = &s[0];
        for channel in &left {
            assert!(!kept_rows::keeps_any_anywhere(&on.conn, channel).unwrap());
        }
        // A pair channel is of no generation: what is kept of it stays.
        assert!(kept_rows::keeps_any(&on.conn, &RELAY, &pair).unwrap());
        // What it carried is everything its store had taken before it
        // wrote that it has applied: that word is the one entry since.
        let carried = kept_rows::carried_up_to(&on.conn).unwrap();
        assert!(carried > carried_before);
        let personal = derive::channel_id(&on.personal()).unwrap();
        assert_eq!(
            kept_rows::last_taken(&on.conn, &personal).unwrap(),
            carried + 1
        );
        let notes = derive::channel_id(&on.own("notes")).unwrap();
        assert_eq!(kept_rows::last_taken(&on.conn, &notes).unwrap(), carried);
    }

    /// A pair channel is one channel whatever phrase either device
    /// follows. A device hands a key the change under one phrase, leaves
    /// that phrase for another, and adds the key again: the later
    /// hand-over takes the place of the earlier, in its store and in any
    /// store, and the device that accepts joins the phrase the adder
    /// follows now. The old one, shown again, is not taken: by its age
    /// alone on a device that follows no phrase, and whatever its age on
    /// one that follows another.
    #[test]
    fn test_a_hand_over_under_a_new_phrase_takes_the_place_of_one_under_the_old() {
        let mut s = Several::new(3);
        s.make_phrase(0);
        // Statement 3 of its phrase: a number above the first of any
        // phrase it could come to follow.
        s.change(0, &[0], &[]);
        s.change(0, &[0], &[]);
        assert_eq!(s[0].number(), 3);
        let old = s.hand(0, 1);
        let (old_made, old_secret) = (s.now, s[0].secret());
        let pair = derive::pair_secret(&s[0].identity, &s.key(1)).unwrap();
        assert_eq!(s[0].stored_in(&pair), std::slice::from_ref(&old.hand_over));

        // Device 0 is alone again, and leaves its phrase for the one that
        // device 2 made.
        s.change(0, &[0], &[]);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let on = &s[2];
        first_statement(&on.conn, &on.identity, &other, &on.label, s.now).unwrap();
        let handed = s.hand(2, 0);
        assert_eq!(s.accept(0, 2, &handed.hand_over), Accepted::Moved(first()));

        // The old one is shown to device 1, which follows no phrase, with
        // the key of device 0 typed an hour after it was made: nothing
        // but its age refuses it.
        let on = &s[1];
        let shown_old = |to: &Machine, typed_at: i64| {
            let (typed, entry) = (s.key(0), &old.hand_over);
            accept(
                &to.conn,
                &to.identity,
                &typed,
                typed_at,
                false,
                entry,
                typed_at,
            )
            .unwrap()
        };
        let before = on.everything();
        assert_eq!(
            shown_old(on, old_made + HOUR),
            Accepted::Refused(NotAccepted::NotMadeWithinTheHour)
        );
        assert_eq!(on.everything(), before);
        // A device with that key and nothing else, where the key is typed
        // one second sooner, takes it: statement 3 of the old phrase.
        let twin = Machine::new(1);
        let joined = Applied {
            number: 3,
            ..first()
        };
        assert_eq!(
            shown_old(&twin, old_made + HOUR - 1),
            Accepted::Joined(joined)
        );
        assert_eq!(twin.secret(), old_secret);

        // It adds device 1 again, under statement 1 of the phrase it
        // follows now.
        let new = s.hand(0, 1);
        assert_eq!(s[0].number(), 1);
        assert_eq!(new.hand_over.rev, s.now as u64);
        assert!(new.hand_over.rev > old.hand_over.rev);
        assert_eq!(s[0].stored_in(&pair), std::slice::from_ref(&new.hand_over));
        // A store that held the old one takes the new one in its place,
        // and does not take the old one back.
        let relay = Machine::new(9);
        let given = |entry: &CheckedEntry| entries::store(&relay.conn, entry, s.now).unwrap();
        assert_eq!(given(&old.hand_over), entries::Outcome::Stored);
        assert_eq!(given(&new.hand_over), entries::Outcome::Stored);
        assert_eq!(given(&old.hand_over), entries::Outcome::OlderThanHeld);
        assert_eq!(relay.stored_in(&pair), std::slice::from_ref(&new.hand_over));

        // The device that accepts joins the phrase the adder follows now.
        assert_eq!(s.accept(1, 0, &new.hand_over), Accepted::Joined(first()));
        assert_eq!(
            s[1].held().following.phrase_key,
            other.public_key().unwrap()
        );
        assert_eq!(s[1].secret(), s[0].secret());
        // The old one, shown again, is not taken.
        let before = s[1].everything();
        assert_eq!(
            s.accept(1, 0, &old.hand_over),
            Accepted::Refused(NotAccepted::AnotherPhrase)
        );
        assert_eq!(s[1].everything(), before);
    }

    /// A hand-over that was made an hour or more before the key was typed
    /// is an old one. It is refused in every state in which a device takes
    /// one that was made within the hour.
    #[test]
    fn test_a_hand_over_made_long_before_the_key_was_typed_is_refused_in_each_row() {
        // Device `new` is given `hand_over`, with the key of device
        // `adder` typed two hours after it was made, an hour after, and
        // one second less than an hour after: what the last gives.
        let old_and_then_not = |s: &Several, new: usize, adder: usize, hand_over: &CheckedEntry| {
            let (on, made) = (&s[new], hand_over.rev as i64);
            let typed = |at: i64| {
                accept(
                    &on.conn,
                    &on.identity,
                    &s.key(adder),
                    at,
                    false,
                    hand_over,
                    at,
                )
                .unwrap()
            };
            let before = on.everything();
            for later in [2 * HOUR, HOUR] {
                assert_eq!(
                    typed(made + later),
                    Accepted::Refused(NotAccepted::NotMadeWithinTheHour)
                );
                assert_eq!(on.everything(), before);
            }
            typed(made + HOUR - 1)
        };

        // A device that follows no phrase.
        let mut s = Several::new(2);
        s.make_phrase(0);
        let added = s.hand(0, 1);
        assert_eq!(
            old_and_then_not(&s, 1, 0, &added.hand_over),
            Accepted::Joined(first())
        );

        // A device that is alone under a phrase, with sync off.
        let mut s = Several::new(2);
        s.make_phrase(0);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let on = &s[1];
        first_statement(&on.conn, &on.identity, &other, &on.label, s.now).unwrap();
        let added = s.hand(0, 1);
        assert_eq!(
            old_and_then_not(&s, 1, 0, &added.hand_over),
            Accepted::Moved(first())
        );

        // A device that is one of several, handed a change it can apply.
        let mut s = Several::of_one_person(2);
        s.change(0, &[0, 1], &[]);
        let told = s.hand(0, 1);
        assert!(matches!(
            old_and_then_not(&s, 1, 0, &told.hand_over),
            Accepted::Applied(Applied { number: 2, .. })
        ));

        // A device that is in no list.
        let mut s = Several::of_one_person(2);
        s.change(0, &[0], &[]);
        assert_eq!(s.pass(0, 1)[0], Taken::Shown(Shown::NotListed));
        let added = s.hand(0, 1);
        assert!(matches!(
            old_and_then_not(&s, 1, 0, &added.hand_over),
            Accepted::Applied(Applied { number: 2, .. })
        ));

        // A device that is listed in a change it could not open.
        let mut s = Several::of_one_person(2);
        let secret = [0x42; 32];
        let next = s[0].held().statement.statement;
        let next = next
            .next(s.key(0), &secret, s.listed(&[0, 1]), &[])
            .unwrap()
            .sign(&s.phrase.signing_key().unwrap())
            .unwrap();
        let change = change_that_does_not_open_for(&s.phrase, &next, secret, 1);
        for (n, outcome) in [(0, None), (1, Some(Shown::NotOpened))] {
            let on = &s[n];
            let shown = shown(&on.conn, &on.identity, &change, s.now).unwrap();
            assert!(outcome.is_none_or(|expected| shown == expected), "{n}");
        }
        assert_eq!(s[0].number(), 2);
        let told = s.hand(0, 1);
        assert!(matches!(
            old_and_then_not(&s, 1, 0, &told.hand_over),
            Accepted::Applied(Applied { number: 2, .. })
        ));
    }

    /// The first row of the table: a device that follows no phrase takes
    /// the statement, the secret and the phrase it then follows, keeps the
    /// change entry, applies, and writes that it has.
    #[test]
    fn test_a_device_that_follows_no_phrase_takes_the_statement_the_secret_and_the_phrase() {
        let mut s = Several::new(3);
        s.make_phrase(0);
        let added = s.hand(0, 1);
        assert_eq!(s.accept(1, 0, &added.hand_over), Accepted::Joined(first()));
        let (adder, new) = (&s[0], &s[1]);
        assert_eq!(new.held(), adder.held());
        assert_eq!(new.secret(), adder.secret());
        assert_eq!(new.latest(), adder.latest());
        assert_eq!(new.state(), State::Applied);
        // It keeps the record of its addition, counted: the statement does
        // not list it, and it counts by the record.
        assert!(!new.held().statement.statement.lists(&new.key()));
        let kept = held_rows::additions(&new.conn).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(
            (kept[0].key, kept[0].adder, kept[0].counted),
            (new.key(), adder.key(), true)
        );
        assert!(new.counts(&new.key()) && new.counts(&adder.key()));
        // It has written that it has applied the statement.
        assert_eq!(new.word_of(&new.key()), Some(text("1")));
        assert_eq!(new.stored().len(), 1);

        // Whether sync is on there makes no difference: what its folders
        // hold has stayed on the machine.
        let added = s.hand(0, 2);
        assert_eq!(
            accepted(&s, 2, &s.key(0), true, &added.hand_over),
            Accepted::Joined(first())
        );
    }

    /// A device applies a statement that does not list it only where the
    /// record of its addition counts under that statement: one that
    /// lists 64 devices has no room for it.
    #[test]
    fn test_a_device_is_not_added_under_a_statement_that_has_no_room_for_it() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        let mut stay = s.listed(&[0]);
        stay.extend((100..163).map(listed_as));
        let on = &s[0];
        let change = make_change_on(&s, 0, stay);
        assert!(matches!(
            shown(&on.conn, &on.identity, &change, s.now).unwrap(),
            Shown::Applied(_)
        ));
        assert_eq!(who_counts(&on.conn).unwrap().devices(), 64);

        // The hand-over, made past the device that adds, which refuses.
        let new = &s[1];
        let statement = on.held().statement;
        let record = Addition::under(&statement.statement, new.listed(), on.key(), 5)
            .unwrap()
            .sign(&on.identity)
            .unwrap();
        let hand_over = HandOver {
            made_at: s.now as u64,
            statement,
            secret: on.secret(),
            statement_key: on.held().following.statement_key,
            change_entry: on.latest().into_entry(),
            addition: Some(record),
            adders_own: None,
        };
        let pair = derive::pair_secret(&on.identity, &new.key()).unwrap();
        let entry = entry_by(
            &on.identity,
            &pair,
            s.now as u64,
            HAND_OVER_NAME,
            Value::Other(hand_over.to_bytes().unwrap()),
            &[],
        );
        let empty = new.everything();
        assert_eq!(
            accepted(&s, 1, &on.key(), false, &entry),
            Accepted::Refused(NotAccepted::RecordDoesNotCount(NotCounted::NoRoom))
        );
        assert_eq!(new.everything(), empty);
        assert!(!new.follows_a_phrase());
    }

    /// A change made on device `maker` with the fixture's phrase, in which
    /// the devices `stay` stay. It is not shown to any device.
    fn make_change_on(s: &Several, maker: usize, stay: Vec<Device>) -> CheckedEntry {
        let on = &s[maker];
        crate::change::make_change(
            &s.phrase,
            &on.held().statement,
            &on.latest(),
            &on.key(),
            stay,
            &[],
        )
        .unwrap()
    }

    /// The second row: a device that is alone under a phrase is refused
    /// while sync is on there. With sync off it leaves that phrase and
    /// takes this one, and its names forget what they held.
    #[test]
    fn test_a_device_alone_under_a_phrase_leaves_it_only_with_sync_off() {
        let mut s = Several::new(3);
        s.make_phrase(0);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        for n in [1, 2] {
            let on = &s[n];
            first_statement(&on.conn, &on.identity, &other, &on.label, s.now).unwrap();
        }
        s.hold(&[1], "notes");
        s.write(1, "notes", "a.md", "under the phrase it made");
        let old = (s[1].personal(), s[1].own("notes"));
        assert_eq!(s[1].stored().len(), 2);

        let added = s.hand(0, 1);
        let before = s[1].everything();
        assert_eq!(
            accepted(&s, 1, &s.key(0), true, &added.hand_over),
            Accepted::Refused(NotAccepted::SyncIsOn)
        );
        assert_eq!(s[1].everything(), before);

        // A device that has stopped under the phrase it follows is not
        // moved to another, though its statement lists it alone: it takes
        // only a hand-over under its own phrase.
        for state in [State::NotListed, State::NotOpened] {
            held_rows::set_state(&s[1].conn, state).unwrap();
            let stopped = s[1].everything();
            assert_eq!(
                accepted(&s, 1, &s.key(0), false, &added.hand_over),
                Accepted::Refused(NotAccepted::AnotherPhrase),
                "{state:?}"
            );
            assert_eq!(s[1].everything(), stopped);
        }
        held_rows::set_state(&s[1].conn, State::Applied).unwrap();

        assert_eq!(
            accepted(&s, 1, &s.key(0), false, &added.hand_over),
            Accepted::Moved(first())
        );
        let (adder, moved) = (&s[0], &s[1]);
        assert_eq!(moved.held(), adder.held());
        assert_eq!(moved.secret(), adder.secret());
        assert_eq!(moved.latest(), adder.latest());
        assert_eq!(moved.apart(), None);
        // It holds the one secret, and none of the phrase it left.
        assert_eq!(held_rows::secrets(&moved.conn).unwrap().len(), 1);
        // It keeps its name, in the name's channel under the secret it
        // took, and the name holds nothing of what it held.
        let names = held_rows::names(&moved.conn).unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(
            (names[0].name.as_str(), names[0].channel),
            ("notes", derive::channel_id(&moved.own("notes")).unwrap())
        );
        assert_eq!(moved.slot("notes", "a.md").current, None);
        assert!(moved.stored_in(&old.0).is_empty() && moved.stored_in(&old.1).is_empty());
        // What its store holds is its word that it has applied.
        assert_eq!(moved.stored().len(), 1);
        assert_eq!(moved.word_of(&moved.key()), Some(text("1")));
        assert!(moved.counts(&adder.key()) && moved.counts(&moved.key()));
        assert_eq!(who_counts(&moved.conn).unwrap().devices(), 2);

        // A device that has added one is not alone, though its statement
        // lists no other: it is not moved, with sync off.
        let on = &s[2];
        add_device(
            &on.conn,
            &on.identity,
            &Machine::new(7).key(),
            "device 7",
            s.now,
        )
        .unwrap();
        let added = s.hand(0, 2);
        let before = s[2].everything();
        assert_eq!(
            accepted(&s, 2, &s.key(0), false, &added.hand_over),
            Accepted::Refused(NotAccepted::AnotherPhrase)
        );
        assert_eq!(s[2].everything(), before);
    }

    /// A device that leaves a phrase drops what its store holds of every
    /// generation it leaves: the one it has applied, and each one it left
    /// before and still holds the secret of.
    #[test]
    fn test_leaving_a_phrase_drops_what_the_store_holds_of_every_generation_left() {
        let mut s = Several::new(2);
        s.make_phrase(0);
        // Device 1 is alone under a phrase of its own, at its second
        // statement: it holds the secret it left, too.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let on = &s[1];
        first_statement(&on.conn, &on.identity, &other, &on.label, s.now).unwrap();
        s.hold(&[1], "notes");
        let first = s[1].secret();
        let on = &s[1];
        let change = crate::change::make_change(
            &other,
            &on.held().statement,
            &on.latest(),
            &on.key(),
            vec![on.listed()],
            &[],
        )
        .unwrap();
        assert!(matches!(
            shown(&on.conn, &on.identity, &change, s.now).unwrap(),
            Shown::Applied(_)
        ));
        s.write(1, "notes", "a.md", "under its second statement");
        // Entries of the generation it left, as a store holds them that
        // was written to past the rule.
        let on = &s[1];
        let left = [
            derive::personal_secret(&first).unwrap(),
            derive::own_secret(&first, "notes").unwrap(),
        ];
        for channel in &left {
            let entry = entry_by(&on.identity, channel, 3, "a.md", text("left behind"), &[]);
            entries::store(&on.conn, &entry, s.now).unwrap();
        }
        let applied = [on.personal(), on.own("notes")];
        for channel in left.iter().chain(&applied) {
            assert_eq!(on.stored_in(channel).len(), 1);
        }
        assert_eq!(held_rows::secrets(&on.conn).unwrap().len(), 2);

        let added = s.hand(0, 1);
        assert!(matches!(
            s.accept(1, 0, &added.hand_over),
            Accepted::Moved(_)
        ));
        let moved = &s[1];
        for channel in left.iter().chain(&applied) {
            assert!(moved.stored_in(channel).is_empty());
        }
        assert_eq!(held_rows::secrets(&moved.conn).unwrap().len(), 1);
        assert_eq!(moved.stored().len(), 1);
    }

    /// The third row: a device that is one of several takes only a
    /// hand-over under the phrase it already follows that brings a change
    /// it can apply. One whose statement was made apart shows as a fork.
    /// Any other moves nothing.
    #[test]
    fn test_one_of_several_takes_only_a_change_it_can_apply_under_its_phrase() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.write(1, "notes", "a.md", "one");

        // Under another phrase: nothing, with sync off as with it on.
        let (stranger, theirs) = handed_by_a_stranger(&s[1], s.now);
        let before = s[1].everything();
        for sync_on in [false, true] {
            assert_eq!(
                accepted(&s, 1, &stranger.key(), sync_on, &theirs),
                Accepted::Refused(NotAccepted::AnotherPhrase)
            );
        }
        // Under its own phrase, with the statement it has applied: no
        // change is brought.
        let again = s.hand(0, 1);
        assert_eq!(
            accepted(&s, 1, &s.key(0), false, &again.hand_over),
            Accepted::Refused(NotAccepted::BringsNoChange)
        );
        assert_eq!(s[1].everything(), before);

        // A change that no relay has told it of, told by hand: it applies
        // it, and carries what it holds.
        let change = s.change(0, &[0, 1, 2], &[]);
        let told = s.hand(0, 1);
        assert_eq!(told.record, None);
        assert_eq!(
            s.accept(1, 0, &told.hand_over),
            Accepted::Applied(Applied {
                number: 2,
                left: Some(1),
                carried: 1,
                no_version: Vec::new(),
                not_carried: Vec::new(),
            })
        );
        assert_eq!(s[1].secret(), s[0].secret());
        assert_eq!(s[1].latest(), change);
        assert_eq!(s[1].text("notes", "a.md").as_deref(), Some("one"));
        // Told again, it brings no change.
        assert_eq!(
            s.accept(1, 0, &told.hand_over),
            Accepted::Refused(NotAccepted::BringsNoChange)
        );
        // It keeps no record of an addition now, and its statement lists
        // the others: it is one of several still, and is not moved.
        assert!(held_rows::additions(&s[1].conn).unwrap().is_empty());
        assert_eq!(
            accepted(&s, 1, &stranger.key(), false, &theirs),
            Accepted::Refused(NotAccepted::AnotherPhrase)
        );

        // Device 2 has made a change of its own, apart. Handed the other,
        // it is in a fork, as where it is shown that entry.
        let its_own = s.change(2, &[0, 1, 2], &[]);
        let told = s.hand(0, 2);
        assert_eq!(s.accept(2, 0, &told.hand_over), Accepted::Fork);
        assert_eq!(s[2].state(), State::Fork);
        assert_eq!(s[2].latest(), its_own);
        assert_eq!(s[2].apart(), Some(change));
        assert_eq!(s[2].number(), 2);
    }

    /// The fourth row: a device that is in no list takes only a hand-over
    /// under the phrase it already follows, and then carries what it
    /// holds.
    #[test]
    fn test_a_device_in_no_list_takes_only_a_hand_over_under_its_phrase_and_carries() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.write(2, "notes", "a.md", "what device 2 holds");
        // Device 1 stays. Device 2 was added since, and is neither kept
        // nor removed: it is in no list.
        let change = s.change(0, &[0, 1], &[]);
        assert_eq!(s.pass(0, 2)[0], Taken::Shown(Shown::NotListed));
        assert_eq!((s[2].state(), s[2].number()), (State::NotListed, 1));
        let stopped = s[2].everything();

        // Under another phrase.
        let (stranger, theirs) = handed_by_a_stranger(&s[2], s.now);
        assert_eq!(
            accepted(&s, 2, &stranger.key(), false, &theirs),
            Accepted::Refused(NotAccepted::AnotherPhrase)
        );
        // From a device that has not heard of the change: the statement
        // it hands over is the one this device has applied.
        let behind = s.hand(1, 2);
        assert_eq!(
            s.accept(2, 1, &behind.hand_over),
            Accepted::Refused(NotAccepted::BringsNoChange)
        );
        // A statement made apart from the one that stopped it, though it
        // lists this device: it is not brought behind the change it has
        // seen.
        s.change(1, &[0, 1, 2], &[]);
        let apart = s.hand(1, 2);
        assert_eq!(apart.record, None);
        assert_eq!(
            s.accept(2, 1, &apart.hand_over),
            Accepted::Refused(NotAccepted::NotAfterTheChangeThatStoppedIt)
        );
        assert_eq!(s[2].everything(), stopped);

        // From a device that has applied the change, with a record of its
        // addition under it: it applies, keeps what it held, and carries
        // it.
        let added = s.hand(0, 2);
        assert_eq!(added.seen, Some(AdditionSeen::Counted));
        assert_eq!(
            s.accept(2, 0, &added.hand_over),
            Accepted::Applied(Applied {
                number: 2,
                left: Some(1),
                carried: 1,
                no_version: Vec::new(),
                not_carried: Vec::new(),
            })
        );
        let back = &s[2];
        assert_eq!((back.state(), back.number()), (State::Applied, 2));
        assert_eq!(back.secret(), s[0].secret());
        assert_eq!(back.latest(), change);
        assert_eq!(
            back.text("notes", "a.md").as_deref(),
            Some("what device 2 holds")
        );
        for n in 0..3 {
            assert!(back.counts(&s.key(n)), "{n}");
        }
        assert_eq!(back.word_of(&back.key()), Some(text("2")));
    }

    /// The fourth row, for a device that is listed in a change it could
    /// not open: handed the change by a device that has it, it applies.
    #[test]
    fn test_a_device_that_could_not_open_a_change_is_handed_it() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        s.write(1, "notes", "a.md", "one");
        // Statement 2 lists both, and what is sealed to device 1 does not
        // open.
        let secret = [0x42; 32];
        let next = s[0].held().statement.statement;
        let next = next
            .next(s.key(0), &secret, s.listed(&[0, 1]), &[])
            .unwrap()
            .sign(&s.phrase.signing_key().unwrap())
            .unwrap();
        let change = change_that_does_not_open_for(&s.phrase, &next, secret, 1);
        let now = s.tick();
        let (maker, listed) = (&s[0], &s[1]);
        assert!(matches!(
            shown(&maker.conn, &maker.identity, &change, now).unwrap(),
            Shown::Applied(_)
        ));
        assert_eq!(
            shown(&listed.conn, &listed.identity, &change, now).unwrap(),
            Shown::NotOpened
        );
        assert_eq!((listed.state(), listed.number()), (State::NotOpened, 1));

        // Under another phrase it takes nothing.
        let (stranger, theirs) = handed_by_a_stranger(listed, now);
        let stopped = listed.everything();
        assert_eq!(
            accepted(&s, 1, &stranger.key(), false, &theirs),
            Accepted::Refused(NotAccepted::AnotherPhrase)
        );
        assert_eq!(s[1].everything(), stopped);

        let told = s.hand(0, 1);
        assert_eq!(told.record, None);
        assert_eq!(
            s.accept(1, 0, &told.hand_over),
            Accepted::Applied(Applied {
                number: 2,
                left: Some(1),
                carried: 1,
                no_version: Vec::new(),
                not_carried: Vec::new(),
            })
        );
        assert_eq!((s[1].state(), s[1].secret()), (State::Applied, secret));
        assert_eq!(s[1].text("notes", "a.md").as_deref(), Some("one"));
    }

    /// The entry of `hand_over` as device `adder` writes it in its pair
    /// channel with device `new`: whatever the device that adds would
    /// have made.
    fn written_by(s: &Several, adder: usize, new: usize, hand_over: &HandOver) -> CheckedEntry {
        let pair = derive::pair_secret(&s[adder].identity, &s.key(new)).unwrap();
        entry_by(
            &s[adder].identity,
            &pair,
            s.now as u64,
            HAND_OVER_NAME,
            Value::Other(hand_over.to_bytes().unwrap()),
            &[],
        )
    }

    /// What hands a device `statement`, which lists it and commits to
    /// `secret`, with its change entry as the phrase makes it.
    fn handing(s: &Several, statement: Statement, secret: [u8; 32]) -> HandOver {
        let signed = statement.sign(&s.phrase.signing_key().unwrap()).unwrap();
        let entry = change_entry::entry_of(&s.phrase, &signed, &ForPhrase::first(secret)).unwrap();
        HandOver {
            made_at: s.now as u64,
            statement: signed,
            secret,
            statement_key: *s.phrase.statement_key().unwrap(),
            change_entry: entry,
            addition: None,
            adders_own: None,
        }
    }

    /// A device that has stopped takes only the statement that stopped
    /// it, or one made after it that keeps its removals. A statement made
    /// apart from the one it has applied moves nothing, and does not show
    /// as a fork there: the device has stopped.
    #[test]
    fn test_a_device_that_has_stopped_takes_only_what_was_made_after_the_change_that_stopped_it() {
        let mut s = Several::of_one_person(3);
        // Statement 2 lists all three, and device 2 applies it. Device 1
        // has not heard, and makes a change of its own, which lists
        // device 2 too.
        s.change(0, &[0, 1, 2], &[]);
        assert!(matches!(s.pass(0, 2)[0], Taken::Shown(Shown::Applied(_))));
        s.change(1, &[0, 1, 2], &[]);
        let apart = s.hand(1, 2);
        assert_eq!(apart.record, None);

        // Statement 3, made after statement 2, removes device 1 and has
        // device 2 in neither list: as a settlement leaves a device out.
        let second = s[0].held().statement.statement;
        let third = second
            .next(s.key(0), &[0x43; 32], s.listed(&[0]), &[s.key(1)])
            .unwrap();
        let stopper = handing(&s, third.clone(), [0x43; 32]);
        let entry = stopper.change_entry.clone().check().unwrap();
        let on = &s[2];
        assert_eq!(
            shown(&on.conn, &on.identity, &entry, s.now).unwrap(),
            Shown::NotListed
        );
        let stopped = on.everything();

        // The statement made apart from the one it has applied.
        assert_eq!(
            s.accept(2, 1, &apart.hand_over),
            Accepted::Refused(NotAccepted::NotAfterTheChangeThatStoppedIt)
        );
        assert_eq!(
            (s[2].everything(), s[2].state()),
            (stopped.clone(), State::NotListed)
        );

        // A statement that has the one that stopped it on its chain, lists
        // this device, and lacks the removal that the other made.
        let mut chain = third.chain.clone();
        chain.push(third.link().unwrap());
        let undoing = Statement {
            number: 4,
            maker: s.key(0),
            chain,
            commitment: cordelia_crypto::statement::commitment(&[0x44; 32]),
            devices: s.listed(&[0, 2]),
            removed: Vec::new(),
            phrase_key: third.phrase_key,
        };
        let handed = written_by(&s, 0, 2, &handing(&s, undoing, [0x44; 32]));
        assert_eq!(
            s.accept(2, 0, &handed),
            Accepted::Refused(NotAccepted::NotAfterTheChangeThatStoppedIt)
        );
        assert_eq!(s[2].everything(), stopped);

        // The control: a statement made after the one that stopped it,
        // which keeps its removal and lists this device.
        let fourth = third
            .next(s.key(0), &[0x45; 32], s.listed(&[0, 2]), &[])
            .unwrap();
        let handed = written_by(&s, 0, 2, &handing(&s, fourth, [0x45; 32]));
        assert!(matches!(
            s.accept(2, 0, &handed),
            Accepted::Applied(Applied {
                number: 4,
                left: Some(2),
                ..
            })
        ));
        assert_eq!((s[2].state(), s[2].secret()), (State::Applied, [0x45; 32]));

        // It has applied statement 4, which keeps the removal. A statement
        // made after that one that lacks the removal is none that it
        // takes: it is refused where it is judged, and nothing moves.
        let fourth = s[2].held().statement.statement;
        let mut chain = fourth.chain.clone();
        chain.push(fourth.link().unwrap());
        let undoing = Statement {
            number: 5,
            maker: s.key(0),
            chain,
            commitment: cordelia_crypto::statement::commitment(&[0x47; 32]),
            devices: s.listed(&[0, 2]),
            removed: Vec::new(),
            phrase_key: fourth.phrase_key,
        };
        let handed = written_by(&s, 0, 2, &handing(&s, undoing, [0x47; 32]));
        let before = s[2].everything();
        assert_eq!(
            s.accept(2, 0, &handed),
            Accepted::Refused(NotAccepted::Statement(StatementError::UndoesARemoval))
        );
        assert_eq!(s[2].everything(), before);
    }

    /// The change entry that a hand-over brings is the one a device keeps
    /// and shows. Under the phrase a device already follows, it is that
    /// phrase's own: an entry of another channel is refused, whoever
    /// signed it.
    #[test]
    fn test_a_hand_over_whose_change_entry_is_of_another_channel_is_refused() {
        let mut s = Several::of_one_person(2);
        let secret = [0x46; 32];
        let next = s[0].held().statement.statement;
        let next = next
            .next(s.key(0), &secret, s.listed(&[0, 1]), &[])
            .unwrap();
        let mut hand_over = handing(&s, next, secret);
        let genuine = written_by(&s, 0, 1, &hand_over);

        // The same content, signed by the phrase's key in a channel that
        // is not the phrase's.
        let elsewhere = [0x55; 32];
        let moved = signed_in(
            &elsewhere,
            &s.phrase.signing_key().unwrap(),
            change_entry::slot(&derive::channel_id(&elsewhere).unwrap()),
            2,
            hand_over.change_entry.content.clone(),
        );
        hand_over.change_entry = moved.into_entry();
        hand_over.validate().unwrap();
        let handed = written_by(&s, 0, 1, &hand_over);
        let before = s[1].everything();
        assert_eq!(
            s.accept(1, 0, &handed),
            Accepted::Refused(NotAccepted::HandOver(HandOverError::ChangeEntry(
                change_entry::ChangeEntryError::AnotherChannel
            )))
        );
        assert_eq!(s[1].everything(), before);

        // The control: with the phrase's own entry it is applied.
        assert!(matches!(
            s.accept(1, 0, &genuine),
            Accepted::Applied(Applied { number: 2, .. })
        ));
    }

    /// The last two rows: a device that was removed accepts nothing, and
    /// nor does one that is in a fork.
    #[test]
    fn test_a_device_that_was_removed_or_is_in_a_fork_accepts_nothing() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1], &[2]);
        assert_eq!(s.pass(0, 2)[0], Taken::Shown(Shown::Removed));
        // Device 1 has not heard, and makes a change of its own. Shown
        // the other, it is in a fork.
        s.change(1, &[0, 1], &[2]);
        assert_eq!(s.pass(0, 1)[0], Taken::Shown(Shown::Fork));

        let (stranger, for_the_removed) = handed_by_a_stranger(&s[2], s.now);
        let (_, for_the_forked) = handed_by_a_stranger(&s[1], s.now);
        // What device 0 hands device 1: its change, which lists device 1.
        let told = s.hand(0, 1);
        // What device 1 had handed device 2 before either change.
        let before = (s[1].everything(), s[2].everything());
        for sync_on in [false, true] {
            assert_eq!(
                accepted(&s, 2, &stranger.key(), sync_on, &for_the_removed),
                Accepted::Refused(NotAccepted::Removed)
            );
            assert_eq!(
                accepted(&s, 1, &stranger.key(), sync_on, &for_the_forked),
                Accepted::Refused(NotAccepted::InAFork)
            );
            assert_eq!(
                accepted(&s, 1, &s.key(0), sync_on, &told.hand_over),
                Accepted::Refused(NotAccepted::InAFork)
            );
        }
        assert_eq!((s[1].everything(), s[2].everything()), before);
        assert_eq!((s[1].state(), s[2].state()), (State::Fork, State::Removed));
    }
}
