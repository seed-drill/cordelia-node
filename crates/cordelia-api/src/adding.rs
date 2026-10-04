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
//! The record waits in the device's store to be sent, as anything it
//! writes in a channel of its own. The hand-over is given back and is not
//! stored: it holds the person secret, and a device keeps a secret in one
//! place (§3). Whoever sends it sends it ahead of everything else (§6).
//!
//! ## The device that accepts
//!
//! [`accept`] is given the pair channel's entry, the key a person typed
//! and when it was typed. It takes the entry only if that key signed it
//! and it was typed within the last hour. What it then does goes by the
//! state the device is in, as the table of §5.1 has it:
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

use cordelia_core::protocol::{HAND_OVER_NAME, MAX_COUNTED_DEVICES, PAIR_KEY_TYPED_SECS};
use cordelia_crypto::addition::{Addition, SignedAddition};
use cordelia_crypto::change_entry;
use cordelia_crypto::derive::{self, DeriveError};
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
use cordelia_crypto::hand_over::{HandOver, HandOverError};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::statement::{Device, Judgement, Statement, StatementError, judge};
use cordelia_storage::entries;
use cordelia_storage::person::{self as held_rows, Following, State};

use crate::person::{
    AdditionSeen, Applied, Change, Held, NotCounted, PersonError, Shown, added_name,
    applied_secret, apply_added, apply_judged, held, in_one, its_own_entry, latest_entry,
    see_addition, shown,
};
use crate::publish::{Over, Standing, written_over};

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
    /// the pair channel of the two keys. It is to be sent, and is not in
    /// this device's store.
    pub hand_over: CheckedEntry,
}

/// Add the device whose key is `new`, under `label`, from this device
/// (decision 2026-10-04 §6). Both entries are returned. The record is in
/// this device's store, and the hand-over is not.
///
/// Refused, with nothing written:
///
/// - on a device that follows no phrase, is in a fork, was removed, is in
///   no list, or could not open a change;
/// - a key that the statement lists as removed: it is not added again
///   without a new key;
/// - on a device that may not add: one that was itself added, since the
///   last statement, by a device added since;
/// - where the device already counts 64, and the key is not one that the
///   statement lists;
/// - this device's own key, a key that is no usable public key, and a
///   label that a statement could not carry.
///
/// A key that the statement already lists is handed the change again,
/// with no record, and `label` is not used: the statement's own label
/// stands.
pub fn add_device(
    conn: &Connection,
    identity: &NodeIdentity,
    new: &[u8; 32],
    label: &str,
    now: i64,
) -> Result<Added, PersonError> {
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
            statement: standing.held.statement.clone(),
            secret: standing.secret,
            statement_key: standing.held.following.statement_key,
            change_entry: latest_entry(conn)?.into_entry(),
            addition: None,
            adders_own: None,
        };
        let mut added = (None, None);
        if !statement.lists(new) {
            if standing.counting.devices() >= MAX_COUNTED_DEVICES {
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

        let hand_over = hand_over_made(identity, &pair, &hand_over)?;
        Ok(Added {
            record: added.0,
            seen: added.1,
            hand_over,
        })
    })
}

/// The time `now`, as a record gives it: seconds, and none before 1970.
fn at(now: i64) -> u64 {
    u64::try_from(now).unwrap_or(0)
}

/// Write the record of an addition in the personal channel, as this
/// device's own entry under the name of the key it adds: bytes that are
/// no text.
fn record_written(
    conn: &Connection,
    identity: &NodeIdentity,
    standing: &Standing,
    record: &SignedAddition,
    now: i64,
) -> Result<CheckedEntry, PersonError> {
    let personal = derive::personal_secret(&standing.secret)?;
    let name = added_name(&record.addition.device.key)?;
    let slot = standing.slot(conn, &personal, &name)?;
    let over = Over {
        channel: &personal,
        slot: &slot,
        merge: None,
    };
    let value = Value::Other(record.to_bytes()?);
    written_over(conn, identity, &over, &name, &value, now)?.ok_or_else(|| {
        PersonError::Held("the record's slot has no next revision under the statement".into())
    })
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

/// The hand-over as this device's entry under the name `hand-over` in
/// the pair channel whose secret is `pair`. A hand-over that the device
/// it is for would refuse is not made.
///
/// A pair channel is of no generation, and a revision in it is a plain
/// number (decision 2026-10-04 §2.3). The entry's revision is the number
/// of the statement it hands over: what is handed under a later statement
/// takes the place, at a relay, of what was handed under an earlier one,
/// and the device that adds keeps no count of its own.
fn hand_over_made(
    identity: &NodeIdentity,
    pair: &[u8; 32],
    hand_over: &HandOver,
) -> Result<CheckedEntry, PersonError> {
    let inside = Inside {
        name: HAND_OVER_NAME.to_string(),
        value: Value::Other(hand_over.to_bytes()?),
        chain: Some(Vec::new()),
    };
    let rev = hand_over.statement.statement.number;
    Ok(Entry::seal(pair, identity, rev, &inside)?.check()?)
}

// ── The device that accepts ──────────────────────────────────────────

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
}

/// Accept the hand-over in `entry`, an entry of the pair channel of this
/// device and the key `typed` (decision 2026-10-04 §5.1, §6). `typed` is
/// the adder's key as a person typed it on this device, `typed_at` when
/// it was typed, and `sync_on` whether sync is on here.
///
/// The entry is taken only if the key typed signed it, and it was typed
/// within the last hour: at `typed_at` or after it, and less than an hour
/// after. What is then done goes by the state this device is in (see the
/// module's documentation, and [`Accepted`]).
///
/// An error is this device's, and not the hand-over's: nothing changed.
pub fn accept(
    conn: &Connection,
    identity: &NodeIdentity,
    typed: &[u8; 32],
    typed_at: i64,
    sync_on: bool,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Accepted, PersonError> {
    let accepted = in_one(conn, || {
        let hand_over = match hand_over_in(identity, typed, typed_at, entry, now)? {
            Ok(hand_over) => hand_over,
            Err(why) => return Ok(Accepted::Refused(why)),
        };
        let brought = Brought::of(&hand_over)?;
        let Some(held) = held(conn)? else {
            return brought
                .applied_on(conn, identity, None, &brought.following, now)
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
                brought
                    .applied_on(conn, identity, None, &brought.following, now)
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

/// Read the hand-over in `entry`, where it is one that this device takes
/// (decision 2026-10-04 §2.2, §6). The error inside says why it is not.
fn hand_over_in(
    identity: &NodeIdentity,
    typed: &[u8; 32],
    typed_at: i64,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Result<HandOver, NotAccepted>, PersonError> {
    // A pair channel is read only with a key typed in the last hour.
    if now < typed_at || now - typed_at >= PAIR_KEY_TYPED_SECS {
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
fn is_alone(conn: &Connection, held: &Held, own: &[u8; 32]) -> Result<bool, PersonError> {
    let statement = &held.statement.statement;
    let lists_no_other = statement.devices.iter().all(|device| device.key == *own);
    Ok(lists_no_other && held_rows::additions(conn)?.is_empty())
}

/// A device that is alone under a phrase leaves it, to start afresh under
/// another (decision 2026-10-04 §4.2, §5.1): it forgets every secret it
/// holds under that phrase, and its names forget what they held, as does
/// the personal channel it leaves. It keeps its names: each has its
/// channel under the statement it then applies.
///
/// What it follows, its statement and the change entry it keeps are
/// replaced where it applies the statement it is handed. It keeps no
/// record of an addition, and no entry of a statement made apart: it is
/// alone, and in no fork.
fn leave(conn: &Connection, held: &Held) -> Result<(), PersonError> {
    let secret = applied_secret(conn, &held.statement.statement)?;
    let personal = derive::channel_id(&derive::personal_secret(&secret)?)?;
    entries::remove_channel(conn, &personal)?;
    for name in held_rows::names(conn)? {
        entries::remove_channel(conn, &name.channel)?;
    }
    held_rows::forget_secrets(conn)?;
    Ok(())
}
