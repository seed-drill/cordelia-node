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
//! ahead of everything else (§6). A pair channel is one channel for as
//! long as both keys exist, whatever phrase either device follows, and a
//! statement's number starts again under each phrase. So the hand-over's
//! revision is the time it was made, by the clock of the device that
//! adds, or one above the one it made before for that key: what is
//! handed later takes the place of what was handed before. The revision
//! only orders them. When a hand-over was made, it says itself.
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

use cordelia_core::protocol::{HAND_OVER_NAME, MAX_COUNTED_DEVICES, PAIR_KEY_TYPED_SECS};
use cordelia_core::revision::next_under;
use cordelia_crypto::addition::{Addition, SignedAddition};
use cordelia_crypto::change_entry;
use cordelia_crypto::derive::{self, DeriveError};
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
use cordelia_crypto::hand_over::{HandOver, HandOverError};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::statement::{Device, Judgement, Statement, StatementError, judge};
use cordelia_storage::entries;
use cordelia_storage::person::{self as held_rows, Following, State};

use crate::person::{
    AdditionSeen, Applied, Change, Held, NotCounted, PersonError, Refused, Shown, added_name,
    applied_secret, apply_added, apply_judged, held, in_one, its_own_entry, latest_entry,
    see_addition, shown,
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
    /// the pair channel of the two keys, at the time it was made. It is
    /// in this device's store, in the place of the one it made before for
    /// that key.
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

        let hand_over = hand_over_written(conn, identity, &pair, &hand_over, now)?;
        Ok(Added {
            record: added.0,
            seen: added.1,
            hand_over,
        })
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
/// in the pair channel whose secret is `pair`. A hand-over that the device
/// it is for would refuse is not written.
///
/// A pair channel is of no generation, and a revision in it is a plain
/// number (decision 2026-10-04 §2.3). It is one channel for as long as
/// both keys exist, whatever phrase either device follows, so nothing
/// that starts again under a phrase can number its entries. The entry's
/// revision is the time it is made, by this device's clock, in seconds:
/// what is handed later takes the place of what was handed before, in
/// this device's store and at a relay. Where this device's own entry
/// there is already at that time or above it (two made in one second, or
/// a clock that was set back), it is one above that entry.
///
/// The revision orders the hand-overs, and says nothing else: it can run
/// ahead of the clock for good. When the hand-over was made is in the
/// hand-over.
fn hand_over_written(
    conn: &Connection,
    identity: &NodeIdentity,
    pair: &[u8; 32],
    hand_over: &HandOver,
    now: i64,
) -> Result<CheckedEntry, PersonError> {
    let channel = derive::channel_id(pair)?;
    let slot = slot_id(&derive::slot_key(pair)?, HAND_OVER_NAME);
    let before = entries::author_entry(conn, &channel, &slot, &identity.public_key())?
        .map(|held| held.entry.rev);
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
    Ok(entry)
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
    /// The hand-over's statement was made apart from the one this device
    /// has applied, and its change entry was refused where it was shown to
    /// the device as one: this is why.
    NotShown(Refused),
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
/// after. And only if the hand-over was made less than an hour before or
/// after the key was typed: it says when it was made, by the clock of the
/// device that adds, and the entry's revision is not asked. What is then
/// done goes by the state this device is in (see the module's
/// documentation, and [`Accepted`]).
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
    // A pair channel is read only with a key typed in the last hour. Two
    // times that are too far apart to subtract are not within an hour.
    let typed_ago = now.checked_sub(typed_at);
    if !typed_ago.is_some_and(|ago| (0..PAIR_KEY_TYPED_SECS).contains(&ago)) {
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
                match shown(conn, identity, &self.entry, now)? {
                    Shown::Fork => Ok(Accepted::Fork),
                    // The entry was refused where it was shown: that is
                    // the hand-over's, and nothing changed.
                    Shown::Refused(why) => Ok(Accepted::Refused(NotAccepted::NotShown(why))),
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
/// alone, and in no fork. What it wrote in a pair channel stays, since
/// that channel is of no generation, and what it hands the same key next
/// is written above it.
fn leave(conn: &Connection, held: &Held) -> Result<(), PersonError> {
    // What is held holds together: the secret applied is the statement's.
    applied_secret(conn, &held.statement.statement)?;
    let names = held_rows::names(conn)?;
    for generation in held_rows::secrets(conn)? {
        let personal = derive::personal_secret(&generation.secret)?;
        entries::remove_channel(conn, &derive::channel_id(&personal)?)?;
        for name in &names {
            let own = derive::own_secret(&generation.secret, &name.name)?;
            entries::remove_channel(conn, &derive::channel_id(&own)?)?;
        }
    }
    held_rows::forget_secrets(conn)?;
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
    use crate::take::Taken;
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
        // is written.
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
        // A device that is given it reads the record from it.
        assert_eq!(
            take(&other.conn, &other.identity, &record, now).unwrap(),
            Taken::Own {
                stored: entries::Outcome::Stored,
                record: Some(Record::Seen(AdditionSeen::Counted)),
                came_to_count: 1,
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
        // Nothing is written but the hand-over, which takes the place of
        // the one that added the device.
        assert_eq!(adder.stored().len(), before);
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

    // ── The device that accepts ──────────────────────────────────────

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
        let pair = derive::pair_secret(&adder.identity, &s.key(2)).unwrap();
        let the_3699th = entry_by(
            &adder.identity,
            &pair,
            first_of_them.rev + 3_698,
            HAND_OVER_NAME,
            text("as the 3,699th left it"),
            &[],
        );
        entries::store(&adder.conn, &the_3699th, now).unwrap();
        let last = add(2, now + 60);
        assert_eq!(last.rev, now as u64 + 3_699);
        assert!(last.rev - (now as u64 + 60) > HOUR as u64);
        assert_eq!(typed(2, &last, now + 61), Accepted::Joined(first()));
    }

    /// A pair channel is one channel whatever phrase either device
    /// follows. A device hands a key the change under one phrase, leaves
    /// that phrase for another, and adds the key again: the later
    /// hand-over takes the place of the earlier, in its store and in any
    /// store, and the device that accepts joins the phrase the adder
    /// follows now. The old one, shown again, is not taken.
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
            statement_key: s.phrase.statement_key().unwrap(),
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
