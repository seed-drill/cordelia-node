//! A device and its person (decision 2026-10-04 §3 to §8): who counts,
//! what a change entry that a device is shown is to it, and applying a
//! statement with its carry.
//!
//! Plain functions over the node's database and the device's own key.
//! Nothing here sends or fetches anything, and no command or handler calls
//! it yet: it stands beside the code that the node runs.
//!
//! ## Who counts (§4.4, §6)
//!
//! A key counts if the statement the device has applied lists it as a
//! device, or a record adds it under that statement and that record was
//! signed by a device of the statement, or by a device that such a device
//! added: a chain is two long at most. A key that the applied statement
//! lists as removed never counts, and each statement lists every key
//! removed before it. A reader counts at most 64 devices in all: those of
//! the statement, and then those added since, in the order it saw their
//! records. A key that has been counted goes on counting until a statement
//! is applied that does not list it. [`see_addition`] takes a record, and
//! [`who_counts`] says who counts.
//!
//! ## A change entry that a device is shown (§4.2 to §4.6)
//!
//! [`shown`] decides what it is, and does exactly one thing with it:
//!
//! - it is the one the device keeps, or it is behind: nothing;
//! - it can be applied: it is applied, in the same step;
//! - it lists this device and the secret did not open, or it does not list
//!   this device: the device stops, and keeps the entry;
//! - it was made apart from the one applied: the device stops, and keeps
//!   both;
//! - it is not the phrase's, or not well formed: it is refused, and
//!   nothing changes.
//!
//! ## Applying (§4.2, §7.2, §7.3, §7.5)
//!
//! One transaction. The statement and the secret are stored, the device
//! leaves the generation it was in, and it carries: every current version
//! it holds, in each name it holds and of what it wrote itself in the
//! personal channel, is sealed again as its own entry in the new
//! generation, at the revision that the renumbering gives it. What the
//! store holds of the generation it left is then dropped, and the device
//! writes, in the new personal channel, that it has applied the statement
//! (§8). Where any of it fails, nothing is changed.

use rusqlite::Connection;

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{
    MAX_COUNTED_DEVICES, PERSONAL_ADDED_PREFIX, PERSONAL_APPLIED_PREFIX,
};
use cordelia_core::revision::lifted;
use cordelia_crypto::CryptoError;
use cordelia_crypto::addition::{AdditionError, SignedAddition};
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::chain;
use cordelia_crypto::change_entry::{self, ChangeEntryError, DeviceSecret, ForPhrase};
use cordelia_crypto::derive::{self, DeriveError};
use cordelia_crypto::entry::{CheckedEntry, Entry, EntryError, Inside, Link, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::phrase::Phrase;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::statement::{
    self, Device, Judgement, SignedStatement, Statement, StatementError, judge,
};
use cordelia_crypto::version::{self, Version};
use cordelia_storage::entries::{self, Outcome};
use cordelia_storage::person::{self as held_rows, Following, Kept, KeptAddition, Person, State};

/// Why something was not done with what a device holds of its person.
#[derive(Debug, thiserror::Error)]
pub enum PersonError {
    #[error("this device follows no recovery phrase")]
    FollowsNoPhrase,

    #[error("this device already follows a recovery phrase")]
    FollowsAPhrase,

    #[error("this device has stopped ({0:?}): the way on is a person's")]
    Stopped(State),

    #[error("the statement is not one this device applies: it is {0:?}")]
    NotApplied(Judgement),

    #[error("the secret is not the one that the statement commits to")]
    SecretNotCommitted,

    #[error("the change entry carries another statement than the one given with it")]
    NotTheStatementsEntry,

    #[error("the record is made under another statement than the one this device has applied")]
    RecordUnderAnotherStatement,

    #[error("the record was signed by a key that does not count")]
    RecordByAKeyThatDoesNotCount,

    #[error("what this device holds of its person does not hold together: {0}")]
    Held(String),

    #[error(transparent)]
    Statement(#[from] StatementError),

    #[error(transparent)]
    ChangeEntry(#[from] ChangeEntryError),

    #[error(transparent)]
    Entry(#[from] EntryError),

    #[error(transparent)]
    Addition(#[from] AdditionError),

    #[error(transparent)]
    Derive(#[from] DeriveError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Storage(#[from] CordeliaError),
}

/// What a device that follows a phrase holds of it, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub state: State,
    pub following: Following,
    /// The statement the device has applied.
    pub statement: SignedStatement,
}

/// What this device follows, the statement it has applied and the state
/// it is in. `None` where it follows no phrase.
///
/// The statement is checked again as it is read: one that the followed
/// phrase did not sign was changed where it lay, and is refused.
pub fn held(conn: &Connection) -> Result<Option<Held>, PersonError> {
    let Some(person) = held_rows::person(conn)? else {
        return Ok(None);
    };
    let statement = SignedStatement::from_bytes(&person.statement)
        .map_err(|e| PersonError::Held(format!("the applied statement: {e}")))?;
    if statement.statement.phrase_key != person.following.phrase_key {
        return Err(PersonError::Held(
            "the applied statement is under another phrase than the one followed".into(),
        ));
    }
    statement
        .verify()
        .map_err(|e| PersonError::Held(format!("the applied statement: {e}")))?;
    Ok(Some(Held {
        state: person.state,
        following: person.following,
        statement,
    }))
}

// ── Who counts ───────────────────────────────────────────────────────

/// Who counts, as a device knows them (decision 2026-10-04 §4.4, §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counting {
    /// The devices of the statement the device has applied.
    listed: Vec<[u8; 32]>,
    /// The keys that statement lists as removed: every key removed so far.
    removed: Vec<[u8; 32]>,
    /// The keys added since by a record that counts, in the order the
    /// device saw their records, each with the key that added it.
    added: Vec<([u8; 32], [u8; 32])>,
}

impl Counting {
    /// Who counts under `statement`, with the records the device keeps
    /// under it.
    fn of(statement: &Statement, kept: &[KeptAddition]) -> Self {
        Self {
            listed: statement.devices.iter().map(|device| device.key).collect(),
            removed: statement.removed.clone(),
            added: kept
                .iter()
                .filter(|record| record.counted)
                .map(|record| (record.key, record.adder))
                .collect(),
        }
    }

    /// Whether `key` counts: the statement lists it as a device, or a
    /// record that counts adds it. A key that the statement lists as
    /// removed never counts.
    pub fn counts(&self, key: &[u8; 32]) -> bool {
        if self.removed.contains(key) {
            return false;
        }
        self.listed.contains(key) || self.added.iter().any(|(added, _)| added == key)
    }

    /// Whether `key` may add a device: it is a device of the statement, or
    /// a device that such a device added. One that was added by a device
    /// added since may not, until a statement lists it: a chain is two
    /// long at most.
    pub fn may_add(&self, key: &[u8; 32]) -> bool {
        if self.removed.contains(key) {
            return false;
        }
        self.listed.contains(key)
            || self
                .added
                .iter()
                .any(|(added, adder)| added == key && self.listed.contains(adder))
    }

    /// How many devices count: those of the statement, and those added
    /// since.
    pub fn devices(&self) -> usize {
        self.listed.len() + self.added.len()
    }

    /// Whether the key that a link names counts: a key that counts has
    /// those first 16 bytes ([`Link::signer_of`]). It is what a chain is
    /// read with ([`cordelia_crypto::entry::known_to_follow`]).
    pub fn signer_counts(&self, signer: &[u8; 16]) -> bool {
        self.keys()
            .iter()
            .any(|key| Link::signer_of(key) == *signer)
    }

    /// Every key that counts: those of the statement, in its order, and
    /// then those added since, in the order the device saw their records.
    pub fn keys(&self) -> Vec<[u8; 32]> {
        self.listed
            .iter()
            .chain(self.added.iter().map(|(added, _)| added))
            .filter(|key| self.counts(key))
            .copied()
            .collect()
    }
}

/// Who counts for this device, under the statement it has applied.
pub fn who_counts(conn: &Connection) -> Result<Counting, PersonError> {
    let held = held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
    Ok(Counting::of(
        &held.statement.statement,
        &held_rows::additions(conn)?,
    ))
}

/// What became of a record of an addition that a device saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdditionSeen {
    /// It is kept, and the key it adds counts from now on.
    Counted,
    /// It is kept as not counted, and says why.
    NotCounted(NotCounted),
    /// The device keeps this record already. Nothing changes.
    SeenBefore,
}

/// Why a record that a device keeps does not count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCounted {
    /// The statement lists the key as removed: a removed key never counts.
    Removed,
    /// The key counts already: the statement lists it, or an earlier
    /// record added it. No later record displaces that one.
    CountsAlready,
    /// The device that signed it was itself added by a device added since
    /// the statement: a chain is two long at most.
    MayNotAdd,
    /// The device counts 64 devices already. A statement makes room.
    NoRoom,
}

/// Take a record of an addition that this device has seen (decision
/// 2026-10-04 §6): it is kept, after those seen before it, as counted or
/// not.
///
/// Refused, and not kept: a record that does not verify; one made under
/// another statement than the one this device has applied, which counts
/// for nothing; and one signed by a key that does not count, whose word
/// is not read (§4.4). A device that follows no phrase, or has stopped,
/// takes none.
///
/// A record is judged once, when it is seen, and is kept as it was
/// judged: one that did not count is not made to count by what is seen
/// later, and a key that counts is not displaced by a later record.
pub fn see_addition(
    conn: &Connection,
    record: &SignedAddition,
    now: i64,
) -> Result<AdditionSeen, PersonError> {
    in_one(conn, || {
        let held = held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
        if held.state != State::Applied {
            return Err(PersonError::Stopped(held.state));
        }
        record.verify()?;
        let statement = &held.statement.statement;
        let added = &record.addition;
        if added.under != statement.link()? {
            return Err(PersonError::RecordUnderAnotherStatement);
        }

        let kept = held_rows::additions(conn)?;
        let bytes = record.to_bytes()?;
        if kept.iter().any(|one| one.record == bytes) {
            return Ok(AdditionSeen::SeenBefore);
        }
        let counting = Counting::of(statement, &kept);
        if !counting.counts(&added.adder) {
            return Err(PersonError::RecordByAKeyThatDoesNotCount);
        }

        let seen = if statement.removes(&added.device.key) {
            AdditionSeen::NotCounted(NotCounted::Removed)
        } else if counting.counts(&added.device.key) {
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        } else if !counting.may_add(&added.adder) {
            AdditionSeen::NotCounted(NotCounted::MayNotAdd)
        } else if counting.devices() >= MAX_COUNTED_DEVICES {
            AdditionSeen::NotCounted(NotCounted::NoRoom)
        } else {
            AdditionSeen::Counted
        };
        held_rows::keep_addition(
            conn,
            &bytes,
            &added.device.key,
            &added.adder,
            seen == AdditionSeen::Counted,
            now,
        )?;
        Ok(seen)
    })
}

// ── The names a device holds ─────────────────────────────────────────

/// Hold `name` in the generation this device has applied: a name it
/// syncs, or one that a command brought in. Returns the ID of the name's
/// channel, which is derived from the person secret and the name.
///
/// The name is in its one spelling, and another is refused. A device that
/// follows no phrase has no secret, and holds no name here.
pub fn hold_name(conn: &Connection, name: &str, now: i64) -> Result<[u8; 32], PersonError> {
    in_one(conn, || {
        let held = held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
        if held.state != State::Applied {
            return Err(PersonError::Stopped(held.state));
        }
        let secret = applied_secret(conn, &held.statement.statement)?;
        let channel = derive::channel_id(&derive::own_secret(&secret, name)?)?;
        held_rows::hold_name(conn, name, &channel, now)?;
        Ok(channel)
    })
}

/// The name, in the personal channel, of the word of the device whose key
/// is `device` that it has applied a statement (decision 2026-10-04 §8):
/// `applied/` and the device's key, as a device's key is written.
pub fn applied_name(device: &[u8; 32]) -> Result<String, PersonError> {
    Ok(format!(
        "{PERSONAL_APPLIED_PREFIX}{}",
        encode_public_key(device)?
    ))
}

// ── A change entry that a device is shown ────────────────────────────

/// What a change entry that a device was shown was to it, and what was
/// done with it (decision 2026-10-04 §4.2 to §4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// It is an entry the device keeps. Nothing was done.
    Held,
    /// Its statement is the one applied, or one on the applied one's
    /// chain. Nothing was done.
    Behind,
    /// It could be applied, and was, in the same step.
    Applied(Applied),
    /// Its statement lists this device, and the secret that comes with it
    /// did not open, or was not there. The device has stopped, and keeps
    /// the entry.
    NotOpened,
    /// Its statement lists this device's key as removed. The device has
    /// stopped, and keeps the entry.
    Removed,
    /// Its statement lists this device in neither list. The device has
    /// stopped, and keeps the entry.
    NotListed,
    /// Its statement was made apart from the one applied. The device has
    /// stopped, and keeps both entries: shown either again, it is one it
    /// keeps. A device that was in a fork already keeps the two it had,
    /// and nothing changed: the statement was made apart from one of them.
    Fork,
    /// It was refused, and nothing changed.
    Refused(Refused),
}

/// Why a change entry was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// This device follows no phrase: it takes no change entry.
    FollowsNoPhrase,
    /// This device has stopped: it was removed, is in no list, or was
    /// listed in a change it could not open. The way on is a person's.
    Stopped,
    /// It is not the change entry of the phrase this device follows, or
    /// is not well formed, and says which: another key than the phrase's
    /// wrote it; it is in another channel, or in another slot than the
    /// change entry's; it says it is a delete; its content is of another
    /// size, or does not open; the statement in it is none, is under
    /// another phrase, or has another number; or what follows its
    /// statement is not the list of sealed secrets.
    NotAChangeEntry(ChangeEntryError),
}

/// What applying a statement did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The number of the statement that was applied.
    pub number: u64,
    /// The number of the statement whose generation the device left.
    /// `None` where it had applied none.
    pub left: Option<u64>,
    /// How many entries were carried into the new generation.
    pub carried: usize,
    /// The names in whose channel a slot held no version at all: what was
    /// there no longer opens. Such a slot is passed over.
    pub no_version: Vec<String>,
}

/// Decide what a change entry that this device was shown is to it, and
/// do exactly one thing with it (see [`Shown`]). `entry` has passed the
/// check that needs no key.
///
/// Its statement is judged beside the one the device has applied
/// ([`judge`]). A device that is in a fork goes on judging, so that it
/// applies the statement that settles the two, and takes no other: a
/// statement that was not made after both is a fork still. A device that
/// has stopped for another reason takes nothing: the way on is a
/// person's.
///
/// An error is this device's, and not the entry's: its database could not
/// be read or written. Nothing was changed, and the device has been shown
/// a change that it has not applied.
pub fn shown(
    conn: &Connection,
    identity: &NodeIdentity,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Shown, PersonError> {
    in_one(conn, || {
        let Some(held) = held(conn)? else {
            return Ok(Shown::Refused(Refused::FollowsNoPhrase));
        };
        let latest = latest_entry(conn)?;
        let apart = kept_entry(conn, Kept::Apart)?;
        if entry.id() == latest.id() || apart.is_some_and(|apart| entry.id() == apart.id()) {
            return Ok(Shown::Held);
        }
        if !matches!(held.state, State::Applied | State::Fork) {
            return Ok(Shown::Refused(Refused::Stopped));
        }

        // Whether it is the phrase's, and what it says to this device: it
        // is opened as the entry it is, and one that the phrase's key did
        // not write in its channel's one slot is not opened at all.
        let following = &held.following;
        let opened = match change_entry::open_for_device(
            entry,
            &following.phrase_key,
            &following.phrase_channel,
            &following.statement_key,
            identity,
        ) {
            Ok(opened) => opened,
            Err(e) => return Ok(Shown::Refused(Refused::NotAChangeEntry(e))),
        };

        let applied = &held.statement.statement;
        let own = identity.public_key();
        let judgement = match judge(&opened.statement, applied, &own, &following.phrase_key) {
            Ok(judgement) => judgement,
            Err(e) => return Ok(Shown::Refused(Refused::NotAChangeEntry(e.into()))),
        };
        match beside_the_one_apart(conn, &held, &opened.statement.statement, judgement)? {
            Judgement::Behind => Ok(Shown::Behind),
            Judgement::Fork => {
                // A device that is in a fork keeps the two entries it has.
                if held.state != State::Fork {
                    held_rows::set_state(conn, State::Fork)?;
                    held_rows::keep_change_entry(conn, Kept::Apart, entry)?;
                }
                Ok(Shown::Fork)
            }
            Judgement::Removed => {
                stop(conn, State::Removed, entry)?;
                Ok(Shown::Removed)
            }
            Judgement::NotListed => {
                stop(conn, State::NotListed, entry)?;
                Ok(Shown::NotListed)
            }
            Judgement::Applies => match opened.secret {
                DeviceSecret::Opened(secret) if opens(&opened.statement, &secret) => {
                    let change = Change {
                        following,
                        statement: &opened.statement,
                        secret: &secret,
                        entry,
                    };
                    apply_judged(conn, identity, Some(&held), &change, now).map(Shown::Applied)
                }
                _ => {
                    stop(conn, State::NotOpened, entry)?;
                    Ok(Shown::NotOpened)
                }
            },
        }
    })
}

/// What a statement is to a device that is in a fork, where `judgement`
/// is what it is beside the statement the device has applied.
///
/// A device in a fork has seen two statements made apart, and takes only
/// a statement that was made after both: the one that settles them, or
/// one made after that. Any other is a fork still, though it was made
/// after the one applied: the one kept apart is not on its chain, and
/// what that one decided would be dropped in silence. To a device that is
/// in no fork, a statement is what it was judged to be.
fn beside_the_one_apart(
    conn: &Connection,
    held: &Held,
    shown: &Statement,
    judgement: Judgement,
) -> Result<Judgement, PersonError> {
    if held.state != State::Fork || matches!(judgement, Judgement::Behind | Judgement::Fork) {
        return Ok(judgement);
    }
    let not_held = |what: String| PersonError::Held(format!("the entry kept apart: {what}"));
    let apart = kept_entry(conn, Kept::Apart)?.ok_or_else(|| not_held("there is none".into()))?;
    let apart = change_entry::open_statement(
        &apart,
        &held.following.phrase_key,
        &held.following.phrase_channel,
        &held.following.statement_key,
    )
    .map_err(|e| not_held(e.to_string()))?;
    if !shown.has_on_chain(&apart.statement.link()?) {
        return Ok(Judgement::Fork);
    }
    Ok(judgement)
}

/// The device stops, and keeps the entry that stopped it as the latest
/// it has seen. It is in no fork: the one made apart is kept no longer.
fn stop(conn: &Connection, state: State, entry: &CheckedEntry) -> Result<(), PersonError> {
    held_rows::set_state(conn, state)?;
    held_rows::keep_change_entry(conn, Kept::Latest, entry)?;
    held_rows::drop_change_entry(conn, Kept::Apart)?;
    Ok(())
}

/// The latest change entry the device has seen. A device that follows a
/// phrase keeps one.
fn latest_entry(conn: &Connection) -> Result<CheckedEntry, PersonError> {
    kept_entry(conn, Kept::Latest)?.ok_or_else(|| {
        PersonError::Held("a device that follows a phrase keeps a change entry".into())
    })
}

/// A change entry the device keeps, checked again as it is read.
fn kept_entry(conn: &Connection, kept: Kept) -> Result<Option<CheckedEntry>, PersonError> {
    held_rows::change_entry(conn, kept)?
        .map(|entry| {
            entry
                .check()
                .map_err(|e| PersonError::Held(format!("a change entry that is kept: {e}")))
        })
        .transpose()
}

// ── Applying ─────────────────────────────────────────────────────────

/// Rule 4 of §4.2: the device has the secret, and the secret opens to the
/// statement's commitment.
fn opens(statement: &SignedStatement, secret: &[u8; 32]) -> bool {
    statement.statement.commits_to(secret)
}

/// A statement with what it takes to apply it.
struct Change<'a> {
    /// What the device follows, or comes to follow with this statement.
    following: &'a Following,
    statement: &'a SignedStatement,
    secret: &'a [u8; 32],
    /// The statement's change entry, which the device keeps.
    entry: &'a CheckedEntry,
}

/// Apply `statement`, given with its `secret` and its change entry, on a
/// device that follows the statement's phrase (decision 2026-10-04 §4.2):
/// the device that made the statement applies it so (§7.2).
///
/// Every rule of §4.2 is asked here. The statement is judged beside the
/// one applied, and only one that applies is applied: the phrase the
/// device follows signed it, its number is above, the device is among its
/// devices, no removal is undone, and it was made after the one applied.
/// The secret opens to its commitment. And the entry is that statement's:
/// it is the phrase's change entry, and the statement key opens it to
/// this very statement.
///
/// Refused otherwise, with nothing changed. A statement that this device
/// is shown and cannot apply stops it only through [`shown`].
pub fn apply(
    conn: &Connection,
    identity: &NodeIdentity,
    statement: &SignedStatement,
    secret: &[u8; 32],
    entry: &CheckedEntry,
    now: i64,
) -> Result<Applied, PersonError> {
    in_one(conn, || {
        let held = held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
        if !matches!(held.state, State::Applied | State::Fork) {
            return Err(PersonError::Stopped(held.state));
        }
        let change = Change {
            following: &held.following,
            statement,
            secret,
            entry,
        };
        its_own_entry(&change)?;
        let judgement = judge(
            statement,
            &held.statement.statement,
            &identity.public_key(),
            &held.following.phrase_key,
        )?;
        let judgement = beside_the_one_apart(conn, &held, &statement.statement, judgement)?;
        if judgement != Judgement::Applies {
            return Err(PersonError::NotApplied(judgement));
        }
        apply_judged(conn, identity, Some(&held), &change, now)
    })
}

/// Make the first statement of `phrase` on this device, and apply it
/// (decision 2026-10-04 §5.2): a new secret, statement 1, which lists
/// this one device under `label`, and its change entry. The device
/// follows the phrase from then.
///
/// A device that already follows a phrase is refused: leaving one is
/// another act.
pub fn first_statement(
    conn: &Connection,
    identity: &NodeIdentity,
    phrase: &Phrase,
    label: &str,
    now: i64,
) -> Result<Applied, PersonError> {
    in_one(conn, || {
        if held_rows::person(conn)?.is_some() {
            return Err(PersonError::FollowsAPhrase);
        }
        let secret = statement::new_secret()?;
        let device = Device::new(identity.public_key(), label)?;
        let statement = Statement::first(device, &secret, phrase.public_key()?)?
            .sign(&phrase.signing_key()?)?;
        let entry = change_entry::entry_of(phrase, &statement, &ForPhrase::first(secret))?;
        let entry = entry.check()?;
        let following = Following {
            phrase_key: statement.statement.phrase_key,
            statement_key: phrase.statement_key()?,
            phrase_channel: entry.channel,
        };
        let change = Change {
            following: &following,
            statement: &statement,
            secret: &secret,
            entry: &entry,
        };
        its_own_entry(&change)?;
        apply_judged(conn, identity, None, &change, now)
    })
}

/// Whether the change's entry is its statement's own, under what the
/// device follows: it is opened as the phrase's change entry, and the
/// statement key opens it to this very statement.
fn its_own_entry(change: &Change) -> Result<(), PersonError> {
    let following = change.following;
    let carried = change_entry::open_statement(
        change.entry,
        &following.phrase_key,
        &following.phrase_channel,
        &following.statement_key,
    )?;
    if carried != *change.statement {
        return Err(PersonError::NotTheStatementsEntry);
    }
    Ok(())
}

/// Apply a statement that was judged to apply, inside the caller's
/// transaction. `before` is what the device held, or `None` where it
/// followed no phrase.
///
/// Rules 3 and 4 of §4.2 are asked again here, whoever calls: the device
/// is among the statement's devices, and the secret opens to the
/// commitment.
fn apply_judged(
    conn: &Connection,
    identity: &NodeIdentity,
    before: Option<&Held>,
    change: &Change,
    now: i64,
) -> Result<Applied, PersonError> {
    let statement = &change.statement.statement;
    if !statement.lists(&identity.public_key()) {
        return Err(PersonError::NotApplied(Judgement::NotListed));
    }
    if !opens(change.statement, change.secret) {
        return Err(PersonError::SecretNotCommitted);
    }
    let to = Generation {
        number: statement.number,
        secret: *change.secret,
    };

    // The carry, from the generation the device is leaving, channel by
    // channel: after it the store holds nothing of that generation.
    let names = held_rows::names(conn)?;
    let mut applied = Applied {
        number: to.number,
        left: None,
        carried: 0,
        no_version: Vec::new(),
    };
    if let Some(before) = before {
        let leaving = &before.statement.statement;
        let from = Generation {
            number: leaving.number,
            secret: applied_secret(conn, leaving)?,
        };
        let counting = Counting::of(leaving, &held_rows::additions(conn)?);
        applied.left = Some(from.number);

        let own = identity.public_key();
        let personal = (
            derive::personal_secret(&from.secret)?,
            derive::personal_secret(&to.secret)?,
        );
        let carry = Carry {
            identity,
            statement: from.number,
            counting: &counting,
            now,
        };
        let (carried, _) = carry.channel(conn, &personal.0, &personal.1, |version| {
            wrote_it_itself(version, &own)
        })?;
        applied.carried += carried;

        for name in &names {
            let old = derive::own_secret(&from.secret, &name.name)?;
            let new = derive::own_secret(&to.secret, &name.name)?;
            let (carried, no_version) = carry.channel(conn, &old, &new, |_| true)?;
            applied.carried += carried;
            if no_version > 0 {
                applied.no_version.push(name.name.clone());
            }
        }
    }

    // The statement and the secret, and the generation it was in is left.
    held_rows::put_person(
        conn,
        &Person {
            state: State::Applied,
            following: *change.following,
            statement: change.statement.to_bytes()?,
        },
    )?;
    held_rows::apply_secret(conn, to.number, &to.secret, now)?;
    held_rows::keep_change_entry(conn, Kept::Latest, change.entry)?;
    held_rows::drop_change_entry(conn, Kept::Apart)?;
    // Records are not carried: the statement's own list is what stands.
    held_rows::clear_additions(conn)?;
    for name in &names {
        let channel = derive::channel_id(&derive::own_secret(&to.secret, &name.name)?)?;
        held_rows::move_name(conn, &name.name, &channel)?;
    }

    write_applied(conn, identity, statement, &to.secret, now)?;
    Ok(applied)
}

/// A generation: a person secret, and the number of its statement.
struct Generation {
    number: u64,
    secret: [u8; 32],
}

/// The secret of the statement the device has applied, as its store has
/// it: the one that the statement commits to.
fn applied_secret(conn: &Connection, applied: &Statement) -> Result<[u8; 32], PersonError> {
    let held = held_rows::applied_secret(conn)?
        .ok_or_else(|| PersonError::Held("the applied statement's secret is not held".into()))?;
    if held.number != applied.number || !applied.commits_to(&held.secret) {
        return Err(PersonError::Held(
            "the secret held is not the applied statement's".into(),
        ));
    }
    Ok(held.secret)
}

/// What a carry reads the generation it leaves with (decision 2026-10-04
/// §7.3).
struct Carry<'a> {
    identity: &'a NodeIdentity,
    /// The number of the statement the device is leaving.
    statement: u64,
    /// Who counts under that statement.
    counting: &'a Counting,
    now: i64,
}

impl Carry<'_> {
    /// Carry one channel: each slot's current version, as the device's
    /// own store has it under the statement it is leaving, is sealed
    /// again as this device's own entry in the channel whose secret is
    /// `to`, where `carries` says so. Then everything the store holds of
    /// the channel it left is dropped (§7.5). Returns how many entries
    /// were carried, and how many slots held no version at all.
    ///
    /// An entry that lost a tie is not current, and is not carried. Nor
    /// is one that is no version.
    fn channel(
        &self,
        conn: &Connection,
        from: &[u8; 32],
        to: &[u8; 32],
        carries: impl Fn(&Version) -> bool,
    ) -> Result<(usize, usize), PersonError> {
        let channel = derive::channel_id(from)?;
        let (mut carried, mut no_version) = (0, 0);
        for slot in entries::channel_slots(conn, &channel)? {
            let held = entries::slot_entries(conn, &channel, &slot)?;
            let read =
                version::current(&held, from, self.statement, |key| self.counting.counts(key))?;
            let Some(version) = read.current else {
                no_version += 1;
                continue;
            };
            if !carries(&version) {
                continue;
            }
            let entry = carried_entry(self.identity, to, &version)?;
            if entries::store(conn, &entry, self.now)? != Outcome::Stored {
                return Err(PersonError::Held(
                    "the store holds an entry of this device's in a generation it has not come to"
                        .into(),
                ));
            }
            carried += 1;
        }
        // What the store holds of the channel that was left is dropped.
        entries::remove_channel(conn, &channel)?;
        Ok((carried, no_version))
    }
}

/// The entry that carries `version` into the channel whose secret is `to`
/// (decision 2026-10-04 §7.3): this device's own entry, with the same
/// name and the same value, at the revision that the renumbering gives
/// it.
///
/// It is carried from one entry of the version: this device's own where
/// it holds one, and otherwise the one whose signer has the lowest key.
/// That entry's signer and that entry's chain are what its chain is built
/// from ([`chain::carried_from`]): the entry's chain as it is where this
/// device signed it, and otherwise that entry's link first and then its
/// chain. One entry's chain is never put behind another entry's signer.
fn carried_entry(
    identity: &NodeIdentity,
    to: &[u8; 32],
    version: &Version,
) -> Result<CheckedEntry, PersonError> {
    let own = identity.public_key();
    // A version's entries are in order of their signers' keys.
    let from = version
        .entries
        .iter()
        .find(|entry| entry.author == own)
        .or(version.entries.first())
        .ok_or_else(|| PersonError::Held("a version with no entry".into()))?;
    let chain = chain::carried_from(&version.value, &from.author, from.chain.as_deref(), &own);

    let inside = Inside {
        name: version.name.clone(),
        value: version.value.clone(),
        chain: Some(chain),
    };
    Ok(Entry::seal(to, identity, lifted(version.rev), &inside)?.check()?)
}

/// Whether a version of the personal channel is carried: the device wrote
/// it there itself, and it is neither a record of an addition nor a word
/// that a statement is applied. The next statement's own list is what
/// stands, and the device writes that it has applied the next statement.
fn wrote_it_itself(version: &Version, own: &[u8; 32]) -> bool {
    version.entries.iter().any(|entry| entry.author == *own)
        && !version.name.starts_with(PERSONAL_ADDED_PREFIX)
        && !version.name.starts_with(PERSONAL_APPLIED_PREFIX)
}

/// The device writes, in the personal channel of the generation it has
/// come to, that it has applied the statement (decision 2026-10-04 §8):
/// an entry of its own, under its own name there, that says the
/// statement's number. It waits in the store to be sent.
fn write_applied(
    conn: &Connection,
    identity: &NodeIdentity,
    statement: &Statement,
    secret: &[u8; 32],
    now: i64,
) -> Result<(), PersonError> {
    let personal = derive::personal_secret(secret)?;
    let channel = derive::channel_id(&personal)?;
    let name = applied_name(&identity.public_key())?;
    let slot = slot_id(&derive::slot_key(&personal)?, &name);

    // The next revision of the slot, under the statement, as the device's
    // own store has it. Nothing is carried into it, so it is the first.
    let held = entries::slot_entries(conn, &channel, &slot)?;
    let read = version::current(&held, &personal, statement.number, |key| {
        statement.lists(key)
    })?;
    let rev = read
        .next
        .ok_or_else(|| PersonError::Held("the word has no next revision".into()))?;
    let inside = Inside {
        name,
        value: Value::Text(statement.number.to_string()),
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&personal, identity, rev, &inside)?.check()?;
    entries::store(conn, &entry, now)?;
    Ok(())
}

/// Run `work` as one: everything it writes is written, or nothing is.
///
/// It is a transaction of its own, which takes the database for writing
/// before it reads, so that what it reads is what it writes over. Inside a
/// transaction of the caller's it is a savepoint, and is whole with that
/// one.
fn in_one<T>(
    conn: &Connection,
    work: impl FnOnce() -> Result<T, PersonError>,
) -> Result<T, PersonError> {
    let storage = |e: rusqlite::Error| PersonError::Storage(CordeliaError::Storage(e.to_string()));
    let (begin, commit, undo) = if conn.is_autocommit() {
        ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK")
    } else {
        (
            "SAVEPOINT person",
            "RELEASE person",
            "ROLLBACK TO person; RELEASE person",
        )
    };
    conn.execute_batch(begin).map_err(storage)?;
    let done = work();
    if done.is_err() {
        conn.execute_batch(undo).map_err(storage)?;
        return done;
    }
    if let Err(e) = conn.execute_batch(commit) {
        let _ = conn.execute_batch(undo);
        return Err(storage(e));
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use cordelia_core::protocol::{
        CHANGE_ENTRY_BYTES, CHANGE_ENTRY_DEVICES_PART_BYTES, CHANGE_ENTRY_NAME,
        ITEM_SEAL_OVERHEAD_BYTES, LABEL_CHANGE_DEVICES, LABEL_CHANGE_SECRET, LABEL_ENTRY_AUTHOR,
        LABEL_ENTRY_CHANNEL, LABEL_ENTRY_CONTENT, LABEL_STATEMENT, MIN_ENTRY_CONTENT_BYTES,
        REV_BAND_HALF, REV_COUNT_BITS,
    };
    use cordelia_crypto::addition::Addition;
    use cordelia_crypto::aes_gcm::item_encrypt;
    use cordelia_crypto::ecies::{ecies_encrypt, ecies_encrypt_for};
    use cordelia_crypto::entry::known_to_follow;
    use cordelia_crypto::identity::x25519_pub_from_ed25519_pub;
    use cordelia_storage::db;
    use rusqlite::types::ValueRef;

    const WORDS: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const OTHER_WORDS: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 24 * 60 * 60;
    const HALF: u64 = REV_BAND_HALF;

    fn phrase() -> Phrase {
        Phrase::parse(WORDS).unwrap()
    }

    /// The device numbered `n`, with its key pair.
    fn device(n: u16) -> NodeIdentity {
        let mut seed = [0x5a; 32];
        seed[..2].copy_from_slice(&n.to_be_bytes());
        NodeIdentity::from_seed(seed).unwrap()
    }

    fn key(n: u16) -> [u8; 32] {
        device(n).public_key()
    }

    /// The devices numbered so, as a statement lists them.
    fn listed(numbers: &[u16]) -> Vec<Device> {
        numbers
            .iter()
            .map(|n| Device::new(key(*n), &format!("device {n}")).unwrap())
            .collect()
    }

    fn secret(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// The revision at `count` in `band`.
    fn at(band: u64, count: u64) -> u64 {
        (band << REV_COUNT_BITS) + count
    }

    fn text(said: &str) -> Value {
        Value::Text(said.to_string())
    }

    /// The link of a version that held the text `said`, taken from an
    /// entry that device `n` signed.
    fn link(said: &str, n: u16) -> Link {
        Link::of(&text(said), key(n))
    }

    // ── Statements, and their change entries ─────────────────────────

    /// Statements 1 to 4 of one phrase. Statement n commits to secret n.
    ///
    /// 1 lists device 0. 2 lists devices 0, 1 and 2. 3 removes device 2.
    /// 4 is made on device 1 and adds device 3.
    fn statements(phrase: &Phrase) -> [Statement; 4] {
        let one = Statement::first(
            listed(&[0]).remove(0),
            &secret(1),
            phrase.public_key().unwrap(),
        )
        .unwrap();
        let two = one
            .next(key(0), &secret(2), listed(&[0, 1, 2]), &[])
            .unwrap();
        let three = two
            .next(key(0), &secret(3), listed(&[0, 1]), &[key(2)])
            .unwrap();
        let four = three
            .next(key(1), &secret(4), listed(&[1, 0, 3]), &[])
            .unwrap();
        [one, two, three, four]
    }

    fn sign(statement: &Statement, phrase: &Phrase) -> SignedStatement {
        statement
            .clone()
            .sign(&phrase.signing_key().unwrap())
            .unwrap()
    }

    /// The change entry of `statement`, which commits to `secret`, as the
    /// phrase makes it. Made twice, it is two entries of one statement.
    fn change(phrase: &Phrase, statement: &Statement, secret: [u8; 32]) -> CheckedEntry {
        change_entry::entry_of(phrase, &sign(statement, phrase), &ForPhrase::first(secret))
            .unwrap()
            .check()
            .unwrap()
    }

    /// What a device follows that follows `phrase`.
    fn following(phrase: &Phrase) -> Following {
        Following {
            phrase_key: phrase.public_key().unwrap(),
            statement_key: phrase.statement_key().unwrap(),
            phrase_channel: derive::channel_id(&phrase.channel_secret().unwrap()).unwrap(),
        }
    }

    /// Device `n`, which follows no phrase, comes to follow `phrase` with
    /// `statement`, which lists it and commits to `secret`: as a device
    /// that is handed a statement does. Returns the change entry it keeps.
    fn follow(
        conn: &Connection,
        n: u16,
        phrase: &Phrase,
        statement: &Statement,
        secret: [u8; 32],
    ) -> CheckedEntry {
        let entry = change(phrase, statement, secret);
        let (following, signed) = (following(phrase), sign(statement, phrase));
        let change = Change {
            following: &following,
            statement: &signed,
            secret: &secret,
            entry: &entry,
        };
        its_own_entry(&change).unwrap();
        in_one(conn, || apply_judged(conn, &device(n), None, &change, NOW)).unwrap();
        entry
    }

    /// A database in which device `n` has applied statement `number` of
    /// [`statements`].
    fn device_at(n: u16, number: usize) -> Connection {
        let conn = db::open_in_memory().unwrap();
        let phrase = phrase();
        follow(
            &conn,
            n,
            &phrase,
            &statements(&phrase)[number - 1],
            secret(number as u8),
        );
        conn
    }

    /// The record that device `adder` adds device `new` under `statement`.
    fn added(statement: &Statement, adder: u16, new: u16) -> SignedAddition {
        let new = listed(&[new]).remove(0);
        Addition::under(statement, new, key(adder), NOW as u64)
            .unwrap()
            .sign(&device(adder))
            .unwrap()
    }

    // ── Channels, and what a store holds of them ─────────────────────

    /// The secret of the channel called `name` in the generation of
    /// secret `n`.
    fn own(n: u8, name: &str) -> [u8; 32] {
        derive::own_secret(&secret(n), name).unwrap()
    }

    /// The secret of the personal channel in the generation of secret `n`.
    fn personal(n: u8) -> [u8; 32] {
        derive::personal_secret(&secret(n)).unwrap()
    }

    fn id_of(channel: &[u8; 32]) -> [u8; 32] {
        derive::channel_id(channel).unwrap()
    }

    fn slot_of(channel: &[u8; 32], name: &str) -> [u8; 32] {
        slot_id(&derive::slot_key(channel).unwrap(), name)
    }

    /// An entry of the channel whose secret is `channel`, with these clear
    /// fields, signed by `author` and by the channel: whatever its content
    /// says. It passes the check, which reads no content.
    fn signed_in(
        channel: &[u8; 32],
        author: &NodeIdentity,
        slot: [u8; 32],
        rev: u64,
        delete: bool,
        content: Vec<u8>,
    ) -> CheckedEntry {
        let channel_key = derive::signing_key(channel).unwrap();
        let mut entry = Entry {
            channel: channel_key.public_key(),
            slot,
            author: author.public_key(),
            rev,
            delete,
            content,
            author_signature: [0u8; 64],
            channel_signature: [0u8; 64],
        };
        let form = entry.signed_bytes();
        entry.author_signature = author.sign(&[LABEL_ENTRY_AUTHOR, &form[..]].concat());
        entry.channel_signature = channel_key.sign(&[LABEL_ENTRY_CHANNEL, &form[..]].concat());
        entry.check().unwrap()
    }

    fn stored(conn: &Connection, entry: CheckedEntry) -> CheckedEntry {
        assert_eq!(
            entries::store(conn, &entry, NOW).unwrap(),
            Outcome::Stored,
            "{entry:?}"
        );
        entry
    }

    /// Device `n` writes `value` under `name` at `rev`, with `chain`, in
    /// the channel whose secret is `channel`, and the store takes it.
    fn put(
        conn: &Connection,
        channel: &[u8; 32],
        n: u16,
        rev: u64,
        name: &str,
        value: Value,
        chain: &[Link],
    ) -> CheckedEntry {
        let inside = Inside {
            name: name.to_string(),
            value,
            chain: Some(chain.to_vec()),
        };
        let entry = Entry::seal(channel, &device(n), rev, &inside).unwrap();
        stored(conn, entry.check().unwrap())
    }

    /// An entry in the slot of `name` that device `n` and the channel
    /// signed, and that does not open: it was sealed for another channel.
    fn put_what_does_not_open(
        conn: &Connection,
        channel: &[u8; 32],
        n: u16,
        rev: u64,
        name: &str,
    ) -> CheckedEntry {
        let inside = Inside {
            name: name.to_string(),
            value: text("sealed elsewhere"),
            chain: Some(Vec::new()),
        };
        let elsewhere = Entry::seal(&[0xee; 32], &device(n), rev, &inside).unwrap();
        let entry = signed_in(
            channel,
            &device(n),
            slot_of(channel, name),
            rev,
            false,
            elsewhere.content,
        );
        assert!(entry.open(channel).is_err());
        stored(conn, entry)
    }

    /// An entry that holds the text `said` under `name` and lacks what it
    /// should say: what follows its value is not a chain and the fill.
    fn put_what_lacks_its_chain(
        conn: &Connection,
        channel: &[u8; 32],
        n: u16,
        rev: u64,
        name: &str,
        said: &str,
    ) -> CheckedEntry {
        let mut says = (name.len() as u16).to_be_bytes().to_vec();
        says.extend_from_slice(name.as_bytes());
        says.push(1);
        says.extend_from_slice(&(said.len() as u16).to_be_bytes());
        says.extend_from_slice(said.as_bytes());
        // A count of no links, and then a byte that is no fill.
        says.extend_from_slice(&[0, 0, 7]);
        let size = (says.len() + ITEM_SEAL_OVERHEAD_BYTES)
            .next_power_of_two()
            .max(MIN_ENTRY_CONTENT_BYTES);
        says.resize(size - ITEM_SEAL_OVERHEAD_BYTES, 0);

        let slot = slot_of(channel, name);
        let mut bound = LABEL_ENTRY_CONTENT.to_vec();
        bound.extend_from_slice(&id_of(channel));
        bound.extend_from_slice(&slot);
        bound.extend_from_slice(&rev.to_be_bytes());
        let content = item_encrypt(&derive::entry_key(channel).unwrap(), &says, &bound).unwrap();
        let entry = signed_in(channel, &device(n), slot, rev, false, content);
        let opened = entry.open(channel).unwrap();
        assert_eq!((opened.value, opened.chain), (text(said), None));
        stored(conn, entry)
    }

    /// The slot of `name` in the channel whose secret is `channel`, as a
    /// device under statement `number` reads it where the devices
    /// numbered in `counts` count.
    fn read(
        conn: &Connection,
        channel: &[u8; 32],
        number: u64,
        name: &str,
        counts: &[u16],
    ) -> version::Slot {
        let held = entries::slot_entries(conn, &id_of(channel), &slot_of(channel, name)).unwrap();
        let keys: Vec<[u8; 32]> = counts.iter().map(|n| key(*n)).collect();
        version::current(&held, channel, number, |key| keys.contains(key)).unwrap()
    }

    /// The one entry of the current version of `name`, as device 1 reads
    /// it under statement 3 of [`statements`]: who signed it, its chain,
    /// its value and its revision.
    fn carried(conn: &Connection, channel: &[u8; 32], name: &str) -> Option<Carried> {
        let version = read(conn, channel, 3, name, &[0, 1]).current?;
        assert_eq!(version.entries.len(), 1, "{name}");
        Some(Carried {
            author: version.entries[0].author,
            chain: version.entries[0].chain.clone().unwrap(),
            value: version.value,
            rev: version.rev,
        })
    }

    #[derive(Debug, PartialEq)]
    struct Carried {
        author: [u8; 32],
        chain: Vec<Link>,
        value: Value,
        rev: u64,
    }

    /// Every channel of which the store holds an entry.
    fn channels(conn: &Connection) -> BTreeSet<[u8; 32]> {
        conn.prepare("SELECT DISTINCT channel_id FROM entries")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// Everything the device holds: every row of the store of entries, of
    /// its counter, and of what the device holds of its person.
    fn everything(conn: &Connection) -> Vec<String> {
        let mut all = Vec::new();
        for table in [
            "entries",
            "counters",
            "person",
            "person_secrets",
            "person_change_entries",
            "person_additions",
            "person_names",
        ] {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    let mut said = format!("{table}:");
                    for column in 0..columns {
                        said.push(' ');
                        said.push_str(&match row.get_ref(column)? {
                            ValueRef::Null => "null".to_string(),
                            ValueRef::Integer(n) => n.to_string(),
                            ValueRef::Real(n) => n.to_string(),
                            ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                            ValueRef::Blob(b) => hex::encode(b),
                        });
                    }
                    Ok(said)
                })
                .unwrap();
            all.extend(rows.map(Result::unwrap));
        }
        all.sort_unstable();
        all
    }

    /// The numbers of the secrets a device holds, each with when it was
    /// left: the applied one first.
    fn secrets(conn: &Connection) -> Vec<(u64, [u8; 32], Option<i64>)> {
        held_rows::secrets(conn)
            .unwrap()
            .into_iter()
            .map(|held| (held.number, held.secret, held.left_at))
            .collect()
    }

    fn state(conn: &Connection) -> State {
        held(conn).unwrap().unwrap().state
    }

    fn applied_number(conn: &Connection) -> u64 {
        held(conn).unwrap().unwrap().statement.statement.number
    }

    fn kept(conn: &Connection, which: Kept) -> Option<[u8; 32]> {
        kept_entry(conn, which).unwrap().map(|entry| entry.id())
    }

    // ── Change entries that say what no phrase's command makes ───────

    /// The slot of the change entry in the phrase's channel.
    fn change_slot(phrase: &Phrase) -> [u8; 32] {
        change_entry::slot(&id_of(&phrase.channel_secret().unwrap()))
    }

    /// An entry of the phrase's channel, in the change entry's slot, that
    /// the phrase's key wrote at `rev` with this content.
    fn change_with(phrase: &Phrase, rev: u64, content: Vec<u8>) -> CheckedEntry {
        signed_in(
            &phrase.channel_secret().unwrap(),
            &phrase.signing_key().unwrap(),
            change_slot(phrase),
            rev,
            false,
            content,
        )
    }

    /// The content of a change entry whose part for the devices says the
    /// bytes `statement` behind their length and then `after`, sealed for
    /// number `number` under the phrase's statement key. No device opens
    /// the part for the phrase, which is left as zeros.
    fn content_saying(phrase: &Phrase, number: u64, statement: &[u8], after: &[u8]) -> Vec<u8> {
        let mut says = (statement.len() as u16).to_be_bytes().to_vec();
        says.extend_from_slice(statement);
        says.extend_from_slice(after);
        says.resize(
            CHANGE_ENTRY_DEVICES_PART_BYTES - ITEM_SEAL_OVERHEAD_BYTES,
            0,
        );
        let mut bound = LABEL_CHANGE_DEVICES.to_vec();
        bound.extend_from_slice(&number.to_be_bytes());
        bound.extend_from_slice(&phrase.public_key().unwrap());
        let mut content = item_encrypt(&phrase.statement_key().unwrap(), &says, &bound).unwrap();
        content.resize(CHANGE_ENTRY_BYTES, 0);
        content
    }

    /// A count, and then what is sealed to each device.
    fn sealed(each: &[Vec<u8>]) -> Vec<u8> {
        let mut after = (each.len() as u16).to_be_bytes().to_vec();
        for one in each {
            after.extend_from_slice(one);
        }
        after
    }

    /// `secret` sealed to device `n` as the secret of statement 3 of the
    /// phrase: as a change entry seals it.
    fn sealed_to(n: u16, secret: &[u8; 32]) -> Vec<u8> {
        sealed_for(3, n, secret)
    }

    /// `secret` sealed to device `n` as the secret of statement `number`
    /// of the phrase.
    fn sealed_for(number: u64, n: u16, secret: &[u8; 32]) -> Vec<u8> {
        let mut info = LABEL_CHANGE_SECRET.to_vec();
        info.extend_from_slice(&number.to_be_bytes());
        info.extend_from_slice(&phrase().public_key().unwrap());
        let to = x25519_pub_from_ed25519_pub(&key(n)).unwrap();
        ecies_encrypt_for(&to, secret, &info).unwrap().to_bytes()
    }

    /// `secret` sealed to device `n` as the node seals to a key for any
    /// other use.
    fn sealed_for_another_use(n: u16, secret: &[u8; 32]) -> Vec<u8> {
        let to = x25519_pub_from_ed25519_pub(&key(n)).unwrap();
        ecies_encrypt(&to, secret).unwrap().to_bytes()
    }

    /// The change entry of `statement` with `after` its statement, in the
    /// place of the secrets sealed to its devices.
    fn change_sealing(phrase: &Phrase, statement: &Statement, after: &[u8]) -> CheckedEntry {
        let signed = sign(statement, phrase).to_bytes().unwrap();
        let content = content_saying(phrase, statement.number, &signed, after);
        change_with(phrase, statement.number, content)
    }

    // ── Who counts ───────────────────────────────────────────────────

    #[test]
    fn test_a_device_of_the_statement_counts() {
        let conn = device_at(0, 2);
        let counting = who_counts(&conn).unwrap();
        for n in [0, 1, 2] {
            assert!(counting.counts(&key(n)), "{n}");
            assert!(counting.may_add(&key(n)), "{n}");
        }
        assert!(!counting.counts(&key(3)) && !counting.may_add(&key(3)));
        assert_eq!(counting.devices(), 3);
        assert_eq!(counting.keys(), [key(0), key(1), key(2)]);
        // A link names a key by its first 16 bytes, and is asked so.
        for n in [0, 1, 2] {
            assert!(counting.signer_counts(&Link::signer_of(&key(n))), "{n}");
        }
        assert!(!counting.signer_counts(&Link::signer_of(&key(3))));
        assert!(!counting.signer_counts(&[0u8; 16]));

        // A device that follows no phrase has nobody who counts.
        let alone = db::open_in_memory().unwrap();
        assert!(matches!(
            who_counts(&alone),
            Err(PersonError::FollowsNoPhrase)
        ));
    }

    #[test]
    fn test_a_key_that_a_device_of_the_statement_added_counts() {
        let conn = device_at(0, 2);
        let [_, two, ..] = statements(&phrase());
        assert!(!who_counts(&conn).unwrap().counts(&key(7)));

        let record = added(&two, 1, 7);
        assert_eq!(
            see_addition(&conn, &record, NOW + 5).unwrap(),
            AdditionSeen::Counted
        );
        let counting = who_counts(&conn).unwrap();
        assert!(counting.counts(&key(7)));
        assert!(counting.signer_counts(&Link::signer_of(&key(7))));
        // It may add in its turn: a chain is two long.
        assert!(counting.may_add(&key(7)));
        assert_eq!(counting.devices(), 4);
        // Those of the statement, and then those added since.
        assert_eq!(counting.keys(), [key(0), key(1), key(2), key(7)]);

        // The record is kept, as counted, with who added and when.
        let kept = held_rows::additions(&conn).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].record, record.to_bytes().unwrap());
        assert_eq!((kept[0].key, kept[0].adder), (key(7), key(1)));
        assert_eq!((kept[0].counted, kept[0].seen_at), (true, NOW + 5));
    }

    /// A device that the statement lists may add, and so may a device
    /// that such a device added. A device added by one of those may not:
    /// the third of a chain does not count.
    #[test]
    fn test_a_chain_of_three_does_not_count() {
        let conn = device_at(0, 2);
        let [_, two, ..] = statements(&phrase());
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 7), NOW).unwrap(),
            AdditionSeen::Counted
        );
        // Added by a device that was added: it counts, and may not add.
        assert_eq!(
            see_addition(&conn, &added(&two, 7, 8), NOW).unwrap(),
            AdditionSeen::Counted
        );
        let counting = who_counts(&conn).unwrap();
        assert!(counting.counts(&key(8)) && !counting.may_add(&key(8)));

        assert_eq!(
            see_addition(&conn, &added(&two, 8, 9), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::MayNotAdd)
        );
        let counting = who_counts(&conn).unwrap();
        assert!(!counting.counts(&key(9)) && !counting.may_add(&key(9)));
        assert_eq!(counting.devices(), 5);
        assert_eq!(counting.keys().len(), 5);

        // It is kept, as not counted.
        let kept = held_rows::additions(&conn).unwrap();
        let said: Vec<([u8; 32], bool)> = kept.iter().map(|one| (one.key, one.counted)).collect();
        assert_eq!(said, [(key(7), true), (key(8), true), (key(9), false)]);

        // A device of the statement adds the same key: it counts.
        assert_eq!(
            see_addition(&conn, &added(&two, 1, 9), NOW).unwrap(),
            AdditionSeen::Counted
        );
        assert!(who_counts(&conn).unwrap().counts(&key(9)));
    }

    #[test]
    fn test_a_record_under_another_statement_counts_for_nothing() {
        let conn = device_at(0, 3);
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        // Under the statement before the one applied.
        assert!(matches!(
            see_addition(&conn, &added(&two, 0, 7), NOW),
            Err(PersonError::RecordUnderAnotherStatement)
        ));
        // Under another statement of the same number, made apart.
        let apart = two
            .next(key(1), &secret(3), listed(&[1, 0]), &[key(2)])
            .unwrap();
        assert_eq!(apart.number, three.number);
        assert!(matches!(
            see_addition(&conn, &added(&apart, 0, 7), NOW),
            Err(PersonError::RecordUnderAnotherStatement)
        ));
        // Under a later one that the device has not applied.
        let [.., four] = statements(&phrase);
        assert!(matches!(
            see_addition(&conn, &added(&four, 0, 7), NOW),
            Err(PersonError::RecordUnderAnotherStatement)
        ));
        assert!(held_rows::additions(&conn).unwrap().is_empty());
        assert!(!who_counts(&conn).unwrap().counts(&key(7)));

        // The control: under the one applied.
        assert_eq!(
            see_addition(&conn, &added(&three, 0, 7), NOW).unwrap(),
            AdditionSeen::Counted
        );
    }

    /// A key that the applied statement lists as removed never counts: a
    /// record that adds it again is kept as not counted, and a record
    /// that it signs is not read.
    #[test]
    fn test_a_removed_key_added_again_by_a_record_does_not_count() {
        let conn = device_at(0, 3);
        let [_, _, three, _] = statements(&phrase());
        assert_eq!(
            see_addition(&conn, &added(&three, 0, 2), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::Removed)
        );
        let counting = who_counts(&conn).unwrap();
        assert!(!counting.counts(&key(2)) && !counting.may_add(&key(2)));
        assert_eq!(counting.devices(), 2);
        let kept = held_rows::additions(&conn).unwrap();
        assert_eq!((kept.len(), kept[0].counted), (1, false));

        // What the removed key signs is not kept at all.
        assert!(matches!(
            see_addition(&conn, &added(&three, 2, 7), NOW),
            Err(PersonError::RecordByAKeyThatDoesNotCount)
        ));
        assert_eq!(held_rows::additions(&conn).unwrap().len(), 1);
        assert!(!who_counts(&conn).unwrap().counts(&key(7)));

        // A row that says a removed key counts, written past the rule,
        // does not make it count, nor let it add.
        held_rows::keep_addition(&conn, b"written past", &key(2), &key(0), true, NOW).unwrap();
        let counting = who_counts(&conn).unwrap();
        assert!(!counting.counts(&key(2)) && !counting.may_add(&key(2)));
        assert!(!counting.signer_counts(&Link::signer_of(&key(2))));
        assert_eq!(counting.keys(), [key(0), key(1)]);
    }

    /// A reader counts at most 64 devices in all: those of the statement,
    /// and those added since in the order it saw their records. The
    /// record of the sixty-fifth is kept as not counted.
    #[test]
    fn test_the_sixty_fifth_device_is_kept_as_not_counted() {
        let conn = device_at(0, 1);
        let [one, ..] = statements(&phrase());
        for n in 100..163 {
            assert_eq!(
                see_addition(&conn, &added(&one, 0, n), NOW).unwrap(),
                AdditionSeen::Counted,
                "{n}"
            );
        }
        let counting = who_counts(&conn).unwrap();
        assert_eq!(counting.devices(), 64);
        assert!(counting.counts(&key(162)));

        assert_eq!(
            see_addition(&conn, &added(&one, 0, 163), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::NoRoom)
        );
        // Whoever signs it: a device that was added may add, and has no
        // room either.
        assert_eq!(
            see_addition(&conn, &added(&one, 100, 164), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::NoRoom)
        );
        let counting = who_counts(&conn).unwrap();
        assert_eq!(counting.devices(), 64);
        assert!(!counting.counts(&key(163)) && !counting.counts(&key(164)));
        let kept = held_rows::additions(&conn).unwrap();
        assert_eq!(kept.len(), 65);
        assert_eq!(kept.iter().filter(|one| one.counted).count(), 63);
        assert!(!kept[63].counted && !kept[64].counted);

        // A statement that lists 64 devices leaves no room for a record.
        let full = db::open_in_memory().unwrap();
        let phrase = phrase();
        let numbers: Vec<u16> = (0..64).collect();
        let many = one.next(key(0), &secret(2), listed(&numbers), &[]).unwrap();
        follow(&full, 0, &phrase, &many, secret(2));
        assert_eq!(who_counts(&full).unwrap().devices(), 64);
        assert_eq!(
            see_addition(&full, &added(&many, 0, 100), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::NoRoom)
        );
        assert!(!who_counts(&full).unwrap().counts(&key(100)));
    }

    /// A device that counts can use the bound up with records of its own.
    /// Those counted first stay counted, and no key that another device
    /// added is displaced.
    #[test]
    fn test_a_hundred_records_by_one_device_displace_no_counted_key() {
        let conn = device_at(0, 2);
        let [_, two, ..] = statements(&phrase());
        assert_eq!(
            see_addition(&conn, &added(&two, 1, 7), NOW).unwrap(),
            AdditionSeen::Counted
        );
        assert_eq!(
            see_addition(&conn, &added(&two, 7, 8), NOW).unwrap(),
            AdditionSeen::Counted
        );

        // Three of the statement and two added: room for 59 more.
        let records: Vec<SignedAddition> = (200..300).map(|n| added(&two, 2, n)).collect();
        for (place, record) in records.iter().enumerate() {
            let expected = if place < 59 {
                AdditionSeen::Counted
            } else {
                AdditionSeen::NotCounted(NotCounted::NoRoom)
            };
            assert_eq!(
                see_addition(&conn, record, NOW).unwrap(),
                expected,
                "{place}"
            );
        }
        let counting = who_counts(&conn).unwrap();
        assert_eq!(counting.devices(), 64);
        // The keys counted before the hundred go on counting.
        for n in [0, 1, 2, 7, 8] {
            assert!(counting.counts(&key(n)), "{n}");
        }
        assert!(counting.may_add(&key(7)) && !counting.may_add(&key(8)));
        // Of the hundred, those seen first count, and no other.
        for n in 200..300 {
            assert_eq!(counting.counts(&key(n)), n < 259, "{n}");
        }

        // Another device's addition finds no room, and displaces nothing.
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 9), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::NoRoom)
        );
        let after = who_counts(&conn).unwrap();
        assert!(!after.counts(&key(9)));
        assert_eq!(after.keys(), counting.keys());

        // Every record is kept, in the order it was seen.
        let kept = held_rows::additions(&conn).unwrap();
        assert_eq!(kept.len(), 103);
        assert_eq!(kept[2].key, key(200));
        assert_eq!(kept[102].key, key(9));

        // Seen again, the hundred change nothing.
        for record in &records {
            assert_eq!(
                see_addition(&conn, record, NOW).unwrap(),
                AdditionSeen::SeenBefore
            );
        }
        assert_eq!(held_rows::additions(&conn).unwrap(), kept);
    }

    /// A key that has been counted goes on counting as it was counted: no
    /// later record displaces the one that added it.
    #[test]
    fn test_no_later_record_displaces_a_key_that_counts() {
        let conn = device_at(0, 2);
        let [_, two, ..] = statements(&phrase());
        see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
        see_addition(&conn, &added(&two, 7, 8), NOW).unwrap();
        let before = who_counts(&conn).unwrap();
        assert!(before.counts(&key(8)) && !before.may_add(&key(8)));

        // A device of the statement adds key 8 too. It was counted as one
        // that a device added since had added, and stays so.
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 8), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        );
        // A record for a key that the statement lists adds nothing.
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 1), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        );
        assert_eq!(who_counts(&conn).unwrap(), before);
        assert_eq!(before.devices(), 5);

        // A record that was seen is one record, however often it is seen.
        let rows = held_rows::additions(&conn).unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 7), NOW + 9).unwrap(),
            AdditionSeen::SeenBefore
        );
        assert_eq!(held_rows::additions(&conn).unwrap(), rows);
    }

    #[test]
    fn test_a_record_that_does_not_verify_or_whose_signer_does_not_count_is_not_kept() {
        let conn = device_at(0, 2);
        let [_, two, ..] = statements(&phrase());

        // A signature that does not hold, and one by another device than
        // the record names.
        let mut forged = added(&two, 0, 7);
        forged.signature[0] ^= 1;
        assert!(matches!(
            see_addition(&conn, &forged, NOW),
            Err(PersonError::Addition(AdditionError::Signature))
        ));
        let mut named = added(&two, 9, 7);
        named.addition.adder = key(0);
        assert!(matches!(
            see_addition(&conn, &named, NOW),
            Err(PersonError::Addition(AdditionError::Signature))
        ));

        // A record that a key which does not count signed: its word is
        // not read.
        let by_a_stranger = added(&two, 9, 7);
        assert!(matches!(
            see_addition(&conn, &by_a_stranger, NOW),
            Err(PersonError::RecordByAKeyThatDoesNotCount)
        ));
        assert!(held_rows::additions(&conn).unwrap().is_empty());
        assert!(!who_counts(&conn).unwrap().counts(&key(7)));

        // Once its signer counts, it is seen as any record is.
        see_addition(&conn, &added(&two, 0, 9), NOW).unwrap();
        assert_eq!(
            see_addition(&conn, &by_a_stranger, NOW).unwrap(),
            AdditionSeen::Counted
        );
    }

    /// A key that was counted goes on counting until a statement is
    /// applied that does not list it. Records are not carried to the next
    /// statement: its own list is what stands.
    #[test]
    fn test_a_key_counts_until_a_statement_is_applied_that_does_not_list_it() {
        let conn = device_at(0, 2);
        let phrase = phrase();
        let [_, two, ..] = statements(&phrase);
        see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
        see_addition(&conn, &added(&two, 0, 8), NOW).unwrap();
        let counting = who_counts(&conn).unwrap();
        assert!(counting.counts(&key(7)) && counting.counts(&key(8)));

        // The next statement lists device 7, and not device 8.
        let next = two
            .next(key(0), &secret(3), listed(&[0, 1, 7]), &[key(2)])
            .unwrap();
        let entry = change(&phrase, &next, secret(3));
        assert!(matches!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));
        let counting = who_counts(&conn).unwrap();
        assert!(counting.counts(&key(7)) && !counting.counts(&key(8)));
        assert_eq!(counting.keys(), [key(0), key(1), key(7)]);
        assert!(held_rows::additions(&conn).unwrap().is_empty());

        // The record that had added device 8 is under the statement
        // before, and counts for nothing now.
        assert!(matches!(
            see_addition(&conn, &added(&two, 0, 8), NOW),
            Err(PersonError::RecordUnderAnotherStatement)
        ));
        assert_eq!(
            see_addition(&conn, &added(&next, 7, 8), NOW).unwrap(),
            AdditionSeen::Counted
        );
    }

    #[test]
    fn test_a_device_that_follows_no_phrase_or_has_stopped_takes_no_record() {
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        let alone = db::open_in_memory().unwrap();
        assert!(matches!(
            see_addition(&alone, &added(&two, 0, 7), NOW),
            Err(PersonError::FollowsNoPhrase)
        ));

        // Device 2 is removed by statement 3, and has stopped.
        let conn = device_at(2, 2);
        let entry = change(&phrase, &three, secret(3));
        assert_eq!(
            shown(&conn, &device(2), &entry, NOW).unwrap(),
            Shown::Removed
        );
        assert!(matches!(
            see_addition(&conn, &added(&two, 0, 7), NOW),
            Err(PersonError::Stopped(State::Removed))
        ));
        assert!(held_rows::additions(&conn).unwrap().is_empty());
    }

    // ── A change entry that a device is shown ────────────────────────

    #[test]
    fn test_a_device_that_follows_no_phrase_takes_no_change_entry() {
        let conn = db::open_in_memory().unwrap();
        let phrase = phrase();
        let [one, two, ..] = statements(&phrase);
        let before = everything(&conn);
        for (statement, n) in [(&one, 1), (&two, 2)] {
            // Device 0 is listed in both, with the secret sealed to it.
            let entry = change(&phrase, statement, secret(n));
            assert_eq!(
                shown(&conn, &device(0), &entry, NOW).unwrap(),
                Shown::Refused(Refused::FollowsNoPhrase)
            );
        }
        assert_eq!(held(&conn).unwrap(), None);
        assert_eq!(everything(&conn), before);
    }

    /// The entry a device keeps, and an entry whose statement is the one
    /// applied or on its chain: nothing is done with either.
    #[test]
    fn test_the_entry_held_and_an_entry_that_is_behind_change_nothing() {
        let conn = db::open_in_memory().unwrap();
        let phrase = phrase();
        let [one, two, three, _] = statements(&phrase);
        let keeps = follow(&conn, 0, &phrase, &three, secret(3));
        put(&conn, &own(3, "team"), 0, 5, "a.md", text("a"), &[]);
        let before = everything(&conn);

        assert_eq!(shown(&conn, &device(0), &keeps, NOW).unwrap(), Shown::Held);
        // The statements before it, which are on its chain.
        for (statement, n) in [(&one, 1), (&two, 2)] {
            let entry = change(&phrase, statement, secret(n));
            assert_eq!(
                shown(&conn, &device(0), &entry, NOW).unwrap(),
                Shown::Behind
            );
        }
        // The applied statement in another entry: sealed afresh.
        let again = change(&phrase, &three, secret(3));
        assert_ne!(again.id(), keeps.id());
        assert_eq!(
            shown(&conn, &device(0), &again, NOW).unwrap(),
            Shown::Behind
        );
        assert_eq!(everything(&conn), before);
        assert_eq!(kept(&conn, Kept::Latest), Some(keeps.id()));
    }

    /// An entry that can be applied is applied in the same step: there is
    /// no state in between.
    #[test]
    fn test_an_entry_that_can_be_applied_is_applied_in_the_same_step() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        hold_name(&conn, "team", NOW).unwrap();
        put(&conn, &own(2, "team"), 0, 5, "a.md", text("a"), &[]);
        assert_eq!(applied_number(&conn), 2);

        let entry = change(&phrase, &three, secret(3));
        let outcome = shown(&conn, &device(1), &entry, NOW + 60).unwrap();
        assert_eq!(
            outcome,
            Shown::Applied(Applied {
                number: 3,
                left: Some(2),
                carried: 1,
                no_version: Vec::new(),
            })
        );

        // The statement and the secret are stored, and the generation it
        // was in is left, with the time.
        let now = held(&conn).unwrap().unwrap();
        assert_eq!(now.state, State::Applied);
        assert_eq!(now.statement, sign(&three, &phrase));
        assert_eq!(now.following, following(&phrase));
        assert_eq!(
            secrets(&conn),
            [(3, secret(3), None), (2, secret(2), Some(NOW + 60))]
        );
        // It keeps the entry, and no other.
        assert_eq!(kept(&conn, Kept::Latest), Some(entry.id()));
        assert_eq!(kept(&conn, Kept::Apart), None);
        // And it has carried.
        assert_eq!(
            carried(&conn, &own(3, "team"), "a.md").unwrap().value,
            text("a")
        );
        assert!(
            read(&conn, &own(2, "team"), 2, "a.md", &[0, 1, 2])
                .current
                .is_none()
        );

        // Shown the entry again, it is the one it keeps; shown the one
        // before, it is behind.
        assert_eq!(shown(&conn, &device(1), &entry, NOW).unwrap(), Shown::Held);
        assert_eq!(
            shown(&conn, &device(1), &change(&phrase, &two, secret(2)), NOW).unwrap(),
            Shown::Behind
        );
    }

    /// A device that was off for two changes, or three, applies the
    /// latest without having seen the ones between, and does exactly what
    /// a device does that applied each: once.
    #[test]
    fn test_a_device_two_and_three_statements_behind_applies_the_latest_alone() {
        let phrase = phrase();
        let all = statements(&phrase);
        // What device 0 holds under statement 1: a version in the bottom
        // half of band 0, one in the top half of band 0, which was moved
        // there by nothing and is no version, and one in the top half of
        // its own band, which a move lifts.
        let start = || {
            let conn = device_at(0, 1);
            hold_name(&conn, "team", NOW).unwrap();
            let team = own(1, "team");
            put(&conn, &team, 0, 5, "a.md", text("a"), &[link("before", 0)]);
            put(&conn, &team, 0, at(1, HALF + 7), "b.md", text("b"), &[]);
            put(&conn, &team, 0, at(1, 3), "c.md", Value::Delete, &[]);
            put(&conn, &personal(1), 0, 2, "syncing/me", text("team"), &[]);
            conn
        };
        let read_all = |conn: &Connection, n: u8| -> Vec<(Value, u64, Vec<Link>)> {
            let mut all = Vec::new();
            for (channel, name) in [
                (own(n, "team"), "a.md"),
                (own(n, "team"), "b.md"),
                (own(n, "team"), "c.md"),
                (personal(n), "syncing/me"),
            ] {
                let version = read(conn, &channel, u64::from(n), name, &[0])
                    .current
                    .unwrap();
                assert_eq!(version.entries.len(), 1);
                let chain = version.entries[0].chain.clone().unwrap();
                all.push((version.value, version.rev, chain));
            }
            all
        };

        for behind in [3usize, 4] {
            // It is shown the latest, and nothing between.
            let direct = start();
            let latest = change(&phrase, &all[behind - 1], secret(behind as u8));
            let outcome = shown(&direct, &device(0), &latest, NOW + 9).unwrap();
            assert_eq!(
                outcome,
                Shown::Applied(Applied {
                    number: behind as u64,
                    left: Some(1),
                    carried: 4,
                    no_version: Vec::new(),
                }),
                "{behind}"
            );
            // It never held the secrets between.
            assert_eq!(
                secrets(&direct),
                [
                    (behind as u64, secret(behind as u8), None),
                    (1, secret(1), Some(NOW + 9))
                ]
            );

            // Another store of the same device applies each in turn.
            let stepwise = start();
            for number in 2..=behind {
                let entry = change(&phrase, &all[number - 1], secret(number as u8));
                assert!(matches!(
                    shown(&stepwise, &device(0), &entry, NOW).unwrap(),
                    Shown::Applied(_)
                ));
            }
            assert_eq!(secrets(&stepwise).len(), behind);

            // Both hold each version at one revision, with one chain.
            let held = read_all(&direct, behind as u8);
            assert_eq!(held, read_all(&stepwise, behind as u8), "{behind}");
            assert_eq!(
                held,
                [
                    (text("a"), 5, vec![link("before", 0)]),
                    // Lifted once, to the band after its own, and no
                    // further.
                    (text("b"), at(2, 7), Vec::new()),
                    (Value::Delete, at(1, 3), Vec::new()),
                    (text("team"), 2, Vec::new()),
                ]
            );
            // And nothing of a generation that was left.
            let now: BTreeSet<[u8; 32]> = [
                id_of(&own(behind as u8, "team")),
                id_of(&personal(behind as u8)),
            ]
            .into();
            assert_eq!(channels(&direct), now);
            assert_eq!(channels(&stepwise), now);
        }
    }

    /// A statement that lists this device, in the phrase's own entry, with
    /// a secret in this device's place that does not open, or is not the
    /// one committed to: the device stops, and keeps the entry. Nothing of
    /// what it holds is carried or dropped. (An entry whose list of
    /// secrets is not there, or is not whole, is no change entry at all,
    /// and is refused.)
    #[test]
    fn test_a_secret_that_does_not_open_or_is_not_there_stops_the_device() {
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        // Statement 3 lists devices 0 and 1, in that order.
        let ways: [(&str, Vec<u8>); 6] = [
            (
                "sealed to another key",
                sealed(&[sealed_to(0, &secret(3)), sealed_to(9, &secret(3))]),
            ),
            (
                "another secret than the one committed to",
                sealed(&[sealed_to(0, &secret(3)), sealed_to(1, &secret(9))]),
            ),
            (
                "bytes that are no sealed secret",
                sealed(&[sealed_to(0, &secret(3)), vec![0x55; 92]]),
            ),
            (
                "the secrets in another order than the devices",
                sealed(&[sealed_to(1, &secret(3)), sealed_to(0, &secret(3))]),
            ),
            (
                "sealed to this device's key for another use",
                sealed(&[
                    sealed_to(0, &secret(3)),
                    sealed_for_another_use(1, &secret(3)),
                ]),
            ),
            (
                "sealed to this device for another statement",
                sealed(&[sealed_to(0, &secret(3)), sealed_for(4, 1, &secret(3))]),
            ),
        ];
        for (what, after) in ways {
            let conn = db::open_in_memory().unwrap();
            let keeps = follow(&conn, 1, &phrase, &two, secret(2));
            hold_name(&conn, "team", NOW).unwrap();
            put(&conn, &own(2, "team"), 0, 5, "a.md", text("a"), &[]);
            let store_before: Vec<String> = everything(&conn)
                .into_iter()
                .filter(|row| row.starts_with("entries:") || row.starts_with("person_names:"))
                .collect();

            let entry = change_sealing(&phrase, &three, &after);
            assert_ne!(entry.id(), keeps.id());
            assert_eq!(
                shown(&conn, &device(1), &entry, NOW).unwrap(),
                Shown::NotOpened,
                "{what}"
            );
            assert_eq!(state(&conn), State::NotOpened, "{what}");
            // It keeps the entry, and has applied nothing.
            assert_eq!(kept(&conn, Kept::Latest), Some(entry.id()), "{what}");
            assert_eq!(kept(&conn, Kept::Apart), None);
            assert_eq!(applied_number(&conn), 2);
            assert_eq!(secrets(&conn), [(2, secret(2), None)]);
            let store_after: Vec<String> = everything(&conn)
                .into_iter()
                .filter(|row| row.starts_with("entries:") || row.starts_with("person_names:"))
                .collect();
            assert_eq!(store_after, store_before, "{what}");

            // The way on is a person's: the same statement in an entry
            // that opens is not taken, and nothing changes.
            let stopped = everything(&conn);
            let good = change(&phrase, &three, secret(3));
            assert_eq!(
                shown(&conn, &device(1), &good, NOW).unwrap(),
                Shown::Refused(Refused::Stopped),
                "{what}"
            );
            assert_eq!(shown(&conn, &device(1), &entry, NOW).unwrap(), Shown::Held);
            assert_eq!(everything(&conn), stopped);
        }

        // The control: the same statement, with the secret sealed to each
        // device, is applied.
        let conn = device_at(1, 2);
        let good = change_sealing(
            &phrase,
            &three,
            &sealed(&[sealed_to(0, &secret(3)), sealed_to(1, &secret(3))]),
        );
        assert!(matches!(
            shown(&conn, &device(1), &good, NOW).unwrap(),
            Shown::Applied(_)
        ));
    }

    #[test]
    fn test_a_statement_that_removes_this_device_stops_it() {
        let conn = db::open_in_memory().unwrap();
        let phrase = phrase();
        let [_, two, three, four] = statements(&phrase);
        let keeps = follow(&conn, 2, &phrase, &two, secret(2));
        hold_name(&conn, "team", NOW).unwrap();
        put(&conn, &own(2, "team"), 2, 5, "a.md", text("a"), &[]);
        let store_before = channels(&conn);

        let entry = change(&phrase, &three, secret(3));
        assert_eq!(
            shown(&conn, &device(2), &entry, NOW).unwrap(),
            Shown::Removed
        );
        assert_eq!(state(&conn), State::Removed);
        // It keeps the entry that removed it, in the place of the one it
        // kept, and what it had applied stays applied.
        assert_eq!(kept(&conn, Kept::Latest), Some(entry.id()));
        assert_ne!(entry.id(), keeps.id());
        assert_eq!(applied_number(&conn), 2);
        assert_eq!(secrets(&conn), [(2, secret(2), None)]);
        assert_eq!(channels(&conn), store_before);

        // From then it takes nothing: not a later statement, and not the
        // one it had applied.
        let stopped = everything(&conn);
        assert_eq!(shown(&conn, &device(2), &entry, NOW).unwrap(), Shown::Held);
        for (statement, n) in [(&four, 4), (&two, 2)] {
            let later = change(&phrase, statement, secret(n));
            assert_eq!(
                shown(&conn, &device(2), &later, NOW).unwrap(),
                Shown::Refused(Refused::Stopped)
            );
        }
        assert_eq!(everything(&conn), stopped);
    }

    /// A statement that lists this device in neither list: it is in no
    /// list, and stops. Its key is not removed, so the status differs.
    #[test]
    fn test_a_statement_that_does_not_list_this_device_stops_it() {
        let conn = device_at(2, 2);
        let phrase = phrase();
        let [_, two, ..] = statements(&phrase);
        let without = two.next(key(0), &secret(3), listed(&[0, 1]), &[]).unwrap();
        assert!(!without.lists(&key(2)) && !without.removes(&key(2)));

        let entry = change(&phrase, &without, secret(3));
        assert_eq!(
            shown(&conn, &device(2), &entry, NOW).unwrap(),
            Shown::NotListed
        );
        assert_eq!(state(&conn), State::NotListed);
        assert_eq!(kept(&conn, Kept::Latest), Some(entry.id()));
        assert_eq!(applied_number(&conn), 2);
        assert_eq!(secrets(&conn), [(2, secret(2), None)]);

        // A later statement that lists it is not taken by itself: it is
        // added again by a person, or not at all.
        let stopped = everything(&conn);
        let again = without
            .next(key(0), &secret(4), listed(&[0, 1, 2]), &[])
            .unwrap();
        assert_eq!(
            shown(&conn, &device(2), &change(&phrase, &again, secret(4)), NOW).unwrap(),
            Shown::Refused(Refused::Stopped)
        );
        assert_eq!(everything(&conn), stopped);
    }

    /// Two statements made apart from statement 3 of [`statements`]: one
    /// at its number, and one at a higher number on that other branch.
    fn made_apart(phrase: &Phrase) -> [Statement; 2] {
        let [_, two, ..] = statements(phrase);
        // Made from statement 2 on device 1, not knowing of statement 3.
        let same_number = two
            .next(key(1), &secret(13), listed(&[1, 0, 2]), &[])
            .unwrap();
        let higher = same_number
            .next(key(1), &secret(14), listed(&[1, 0, 2]), &[])
            .unwrap();
        [same_number, higher]
    }

    /// A statement made after statement 3 of [`statements`], which commits
    /// to secret 15 and lacks the removal that statement 3 has.
    fn lacking_a_removal(phrase: &Phrase) -> Statement {
        let [_, _, three, _] = statements(phrase);
        let mut lacking = three
            .next(key(0), &secret(15), listed(&[0, 1]), &[])
            .unwrap();
        lacking.removed.clear();
        lacking.validate().unwrap();
        assert!(lacking.has_on_chain(&three.link().unwrap()));
        lacking
    }

    /// A statement that has the applied one on its chain and lacks a
    /// removal that the applied one has is refused, as one that is not
    /// well formed is. It is no fork: the device does not stop, and
    /// nothing changes.
    #[test]
    fn test_a_statement_that_lacks_a_removal_of_the_applied_one_is_refused() {
        let conn = db::open_in_memory().unwrap();
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        follow(&conn, 0, &phrase, &three, secret(3));
        hold_name(&conn, "team", NOW).unwrap();
        put(&conn, &own(3, "team"), 0, 5, "a.md", text("a"), &[]);
        let before = everything(&conn);

        // Device 0 is listed in it, with the secret sealed to it.
        let lacking = lacking_a_removal(&phrase);
        let entry = change(&phrase, &lacking, secret(15));
        let undoes = ChangeEntryError::Statement(StatementError::UndoesARemoval);
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Refused(Refused::NotAChangeEntry(undoes))
        );
        assert_eq!(state(&conn), State::Applied);
        assert_eq!(kept(&conn, Kept::Apart), None);
        assert_eq!(everything(&conn), before);
        // Nor is it applied where it is given with its secret.
        assert!(matches!(
            apply(
                &conn,
                &device(0),
                &sign(&lacking, &phrase),
                &secret(15),
                &entry,
                NOW
            ),
            Err(PersonError::Statement(StatementError::UndoesARemoval))
        ));
        assert_eq!(everything(&conn), before);

        // With the removed key among its devices again, it is the same.
        let mut back = lacking.clone();
        back.devices.push(listed(&[2]).remove(0));
        back.validate().unwrap();
        let entry = change(&phrase, &back, secret(15));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Refused(Refused::NotAChangeEntry(ChangeEntryError::Statement(
                StatementError::UndoesARemoval
            )))
        );
        assert_eq!(everything(&conn), before);

        // The device goes on: a statement made after the one applied, with
        // every removal it has, is applied.
        let [.., four] = statements(&phrase);
        let entry = change(&phrase, &four, secret(4));
        assert!(matches!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));
    }

    #[test]
    fn test_a_fork_stops_the_device_and_it_keeps_both_entries() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let secrets_of = [13, 14];
        for (place, apart) in made_apart(&phrase).iter().enumerate() {
            let conn = db::open_in_memory().unwrap();
            let keeps = follow(&conn, 0, &phrase, &three, secret(3));
            hold_name(&conn, "team", NOW).unwrap();
            put(&conn, &own(3, "team"), 0, 5, "a.md", text("a"), &[]);
            let store_before = channels(&conn);

            // Device 0 is listed in each, with the secret sealed to it:
            // it is a fork all the same.
            let entry = change(&phrase, apart, secret(secrets_of[place]));
            assert_eq!(
                shown(&conn, &device(0), &entry, NOW).unwrap(),
                Shown::Fork,
                "{place}"
            );
            assert_eq!(state(&conn), State::Fork);
            // It keeps both: the one it had applied, to go on showing,
            // and the other.
            assert_eq!(kept(&conn, Kept::Latest), Some(keeps.id()));
            assert_eq!(kept(&conn, Kept::Apart), Some(entry.id()));
            assert_eq!(applied_number(&conn), 3);
            assert_eq!(secrets(&conn), [(3, secret(3), None)]);
            assert_eq!(channels(&conn), store_before);

            // It asks for neither again: each is an entry it keeps.
            let stopped = everything(&conn);
            assert_eq!(shown(&conn, &device(0), &entry, NOW).unwrap(), Shown::Held);
            assert_eq!(shown(&conn, &device(0), &keeps, NOW).unwrap(), Shown::Held);
            assert_eq!(everything(&conn), stopped);
        }

        // In a fork, another statement made apart changes nothing: the
        // device keeps the two it has.
        let conn = db::open_in_memory().unwrap();
        let keeps = follow(&conn, 0, &phrase, &three, secret(3));
        let [same_number, higher] = made_apart(&phrase);
        let first = change(&phrase, &same_number, secret(13));
        assert_eq!(shown(&conn, &device(0), &first, NOW).unwrap(), Shown::Fork);
        let stopped = everything(&conn);
        let second = change(&phrase, &higher, secret(14));
        assert_eq!(shown(&conn, &device(0), &second, NOW).unwrap(), Shown::Fork);
        assert_eq!(everything(&conn), stopped);
        assert_eq!(kept(&conn, Kept::Latest), Some(keeps.id()));
        assert_eq!(kept(&conn, Kept::Apart), Some(first.id()));
    }

    /// A device in a fork goes on judging what it is shown, so that it
    /// applies the statement that settles the two: it is then in no fork,
    /// and keeps the settlement's entry alone.
    #[test]
    fn test_a_device_in_a_fork_applies_the_statement_that_settles_it() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let [apart, ..] = made_apart(&phrase);
        let in_a_fork = || {
            let conn = db::open_in_memory().unwrap();
            follow(&conn, 0, &phrase, &three, secret(3));
            hold_name(&conn, "team", NOW).unwrap();
            put(&conn, &own(3, "team"), 0, 5, "a.md", text("a"), &[]);
            let other = change(&phrase, &apart, secret(13));
            assert_eq!(shown(&conn, &device(0), &other, NOW).unwrap(), Shown::Fork);
            conn
        };

        // A later statement of the branch it is on, which lists it with
        // the secret sealed to it, and one that removes it: neither was
        // made after the one kept apart, and each is a fork still. Nothing
        // changes.
        let conn = in_a_fork();
        let [.., four] = statements(&phrase);
        let removing = three
            .next(key(1), &secret(4), listed(&[1]), &[key(0)])
            .unwrap();
        let stopped = everything(&conn);
        for statement in [&four, &removing] {
            let entry = change(&phrase, statement, secret(4));
            assert_eq!(shown(&conn, &device(0), &entry, NOW).unwrap(), Shown::Fork);
            assert_eq!(everything(&conn), stopped);
            // Nor is it applied where it is given with its secret.
            assert!(matches!(
                apply(
                    &conn,
                    &device(0),
                    &sign(statement, &phrase),
                    &secret(4),
                    &entry,
                    NOW
                ),
                Err(PersonError::NotApplied(Judgement::Fork))
            ));
        }
        assert_eq!(state(&conn), State::Fork);
        assert_eq!(everything(&conn), stopped);

        // The settlement lists device 0.
        let settled =
            Statement::settle(&three, &apart, key(0), &secret(20), listed(&[0, 1]), &[]).unwrap();
        let entry = change(&phrase, &settled, secret(20));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW + 5).unwrap(),
            Shown::Applied(Applied {
                number: 4,
                left: Some(3),
                carried: 1,
                no_version: Vec::new(),
            })
        );
        assert_eq!(state(&conn), State::Applied);
        assert_eq!(kept(&conn, Kept::Latest), Some(entry.id()));
        assert_eq!(kept(&conn, Kept::Apart), None);
        assert_eq!(
            secrets(&conn),
            [(4, secret(20), None), (3, secret(3), Some(NOW + 5))]
        );
        let version = read(&conn, &own(20, "team"), 4, "a.md", &[0, 1]);
        assert_eq!(version.current.unwrap().value, text("a"));

        // A statement made after the settlement, shown to a device that
        // never saw the settlement: it was made after both, and is applied.
        let conn = in_a_fork();
        let after = settled
            .next(key(0), &secret(22), listed(&[0, 1]), &[])
            .unwrap();
        let entry = change(&phrase, &after, secret(22));
        assert!(matches!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Applied(Applied {
                number: 5,
                left: Some(3),
                ..
            })
        ));
        assert_eq!(state(&conn), State::Applied);
        assert_eq!(kept(&conn, Kept::Apart), None);

        // A settlement that does not list it: it is in no list, and in no
        // fork.
        let conn = in_a_fork();
        let without =
            Statement::settle(&three, &apart, key(1), &secret(21), listed(&[1]), &[]).unwrap();
        let entry = change(&phrase, &without, secret(21));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::NotListed
        );
        assert_eq!(state(&conn), State::NotListed);
        assert_eq!(kept(&conn, Kept::Latest), Some(entry.id()));
        assert_eq!(kept(&conn, Kept::Apart), None);
        assert_eq!(applied_number(&conn), 3);
    }

    /// An entry that is not the phrase's, or is not well formed, is
    /// refused: nothing changes, and the device is in no fork.
    #[test]
    fn test_an_entry_that_is_not_the_phrases_or_not_well_formed_is_refused() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let [_, _, three, _] = statements(&phrase);
        hold_name(&conn, "team", NOW).unwrap();
        put(&conn, &own(2, "team"), 0, 5, "a.md", text("a"), &[]);

        let good = change(&phrase, &three, secret(3));
        let slot = change_slot(&phrase);
        let channel = phrase.channel_secret().unwrap();
        let signed = sign(&three, &phrase).to_bytes().unwrap();
        let both = sealed(&[sealed_to(0, &secret(3)), sealed_to(1, &secret(3))]);

        // Under another phrase: its first statement, and one that lists
        // this device with the secret sealed to it.
        let theirs = Statement::first(
            listed(&[1]).remove(0),
            &secret(1),
            other.public_key().unwrap(),
        )
        .unwrap();
        let under_another = change(&other, &theirs, secret(1));

        // The statement of another phrase, sealed in this phrase's entry.
        let foreign = sign(&theirs, &other).to_bytes().unwrap();
        // A statement with a key in both lists, which the phrase signed:
        // statement 3's bytes, with the key it removes written as a
        // device's.
        let mut in_both = three.to_bytes().unwrap();
        let removed_at = in_both.len() - 32 - 2 - 32;
        assert_eq!(in_both[removed_at..removed_at + 32], key(2));
        in_both[removed_at..removed_at + 32].copy_from_slice(&key(1));
        let by_the_phrase = phrase
            .signing_key()
            .unwrap()
            .sign(&[LABEL_STATEMENT, &in_both[..]].concat());
        in_both.extend_from_slice(&by_the_phrase);
        // A statement whose signature does not hold.
        let mut forged = signed.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;

        let size = ChangeEntryError::Size(16_384);
        let number = ChangeEntryError::Number {
            entry: 4,
            statement: 3,
        };
        // What a device that was removed can make: it holds the statement
        // key, and seals the true statement with a list of its own, which
        // opens for nobody. It signs the entry itself, in a channel whose
        // key it holds, or names the phrase's channel as it can.
        let broken = sealed(&[sealed_to(0, &secret(9)), sealed_to(1, &secret(9))]);
        let sealed_again = content_saying(&phrase, 3, &signed, &broken);
        let its_own = [0x44; 32];
        let in_its_own = signed_in(
            &its_own,
            &device(2),
            change_entry::slot(&id_of(&its_own)),
            3,
            false,
            sealed_again.clone(),
        );
        let in_the_phrases = signed_in(&channel, &device(2), slot, 3, false, sealed_again);

        let not = Refused::NotAChangeEntry;
        let refused: Vec<(&str, CheckedEntry, Refused)> = vec![
            (
                "another phrase's",
                under_another,
                not(ChangeEntryError::AnotherChannel),
            ),
            (
                "written by another key",
                signed_in(&channel, &device(9), slot, 3, false, good.content.clone()),
                not(ChangeEntryError::AnotherAuthor),
            ),
            (
                "the true statement with a broken list, in a channel of another key's",
                in_its_own,
                not(ChangeEntryError::AnotherChannel),
            ),
            (
                "the true statement with a broken list, signed by another key",
                in_the_phrases,
                not(ChangeEntryError::AnotherAuthor),
            ),
            (
                "a delete",
                signed_in(
                    &channel,
                    &phrase.signing_key().unwrap(),
                    slot,
                    3,
                    true,
                    good.content.clone(),
                ),
                not(ChangeEntryError::Delete),
            ),
            (
                "in another slot",
                signed_in(
                    &channel,
                    &phrase.signing_key().unwrap(),
                    slot_of(&channel, CHANGE_ENTRY_NAME),
                    3,
                    false,
                    good.content.clone(),
                ),
                not(ChangeEntryError::AnotherSlot),
            ),
            (
                "with no sealed secret after its statement",
                change_sealing(&phrase, &three, &[]),
                not(ChangeEntryError::Malformed),
            ),
            (
                "with a list of none",
                change_sealing(&phrase, &three, &sealed(&[])),
                not(ChangeEntryError::Malformed),
            ),
            (
                "with a list of one too few",
                change_sealing(&phrase, &three, &sealed(&[sealed_to(0, &secret(3))])),
                not(ChangeEntryError::Malformed),
            ),
            (
                "with more than the list after its statement",
                change_sealing(&phrase, &three, &[&both[..], &[0, 0, 1]].concat()),
                not(ChangeEntryError::Malformed),
            ),
            (
                "of another size",
                change_with(&phrase, 3, good.content[..16_384].to_vec()),
                Refused::NotAChangeEntry(size),
            ),
            (
                "that does not open",
                change_with(&phrase, 3, vec![0x5c; CHANGE_ENTRY_BYTES]),
                Refused::NotAChangeEntry(ChangeEntryError::DidNotOpen),
            ),
            (
                "at another number than it was sealed for",
                change_with(&phrase, 4, good.content.clone()),
                Refused::NotAChangeEntry(ChangeEntryError::DidNotOpen),
            ),
            (
                "at another number than its statement's",
                change_with(&phrase, 4, content_saying(&phrase, 4, &signed, &both)),
                Refused::NotAChangeEntry(number),
            ),
            (
                "with another phrase's statement",
                change_with(&phrase, 1, content_saying(&phrase, 1, &foreign, &both)),
                Refused::NotAChangeEntry(ChangeEntryError::AnotherPhrase),
            ),
            (
                "with a key in both lists",
                change_with(&phrase, 3, content_saying(&phrase, 3, &in_both, &both)),
                Refused::NotAChangeEntry(ChangeEntryError::Statement(StatementError::InBothLists)),
            ),
            (
                "with a statement that the phrase did not sign",
                change_with(&phrase, 3, content_saying(&phrase, 3, &forged, &both)),
                Refused::NotAChangeEntry(ChangeEntryError::Statement(StatementError::Signature)),
            ),
        ];

        let before = everything(&conn);
        for (what, entry, why) in refused {
            assert_eq!(
                shown(&conn, &device(1), &entry, NOW).unwrap(),
                Shown::Refused(why),
                "{what}"
            );
            assert_eq!(everything(&conn), before, "{what}");
        }
        assert_eq!(state(&conn), State::Applied);

        // The control: the entry they were made from is applied.
        assert!(matches!(
            shown(&conn, &device(1), &good, NOW).unwrap(),
            Shown::Applied(_)
        ));
    }

    // ── Applying ─────────────────────────────────────────────────────

    /// What device 1 holds under statement 2 of [`statements`], in two
    /// names and in the personal channel. No entry is at revision 1.
    fn holding() -> Connection {
        let conn = device_at(1, 2);
        hold_name(&conn, "team", NOW).unwrap();
        hold_name(&conn, "notes", NOW).unwrap();
        let (team, notes, personal) = (own(2, "team"), own(2, "notes"), personal(2));
        put(
            &conn,
            &team,
            1,
            5,
            "a.md",
            text("a"),
            &[link("a before", 0)],
        );
        put(&conn, &team, 0, at(2, HALF + 3), "b.md", text("b"), &[]);
        put(&conn, &team, 2, 9, "c.md", Value::Delete, &[link("c", 1)]);
        put(
            &conn,
            &team,
            0,
            77,
            "d.md",
            Value::Other(vec![0, 0xff]),
            &[],
        );
        put(&conn, &notes, 2, at(1, 4), "e.md", text("e"), &[]);
        put(
            &conn,
            &personal,
            1,
            6,
            "syncing/me",
            text("team notes"),
            &[],
        );
        conn
    }

    /// Every version device 1 holds in the generation of secret `n`, under
    /// statement `n`: by channel and name, its value and its revision.
    fn versions(conn: &Connection, n: u8) -> BTreeMap<String, (Value, u64)> {
        let mut all = BTreeMap::new();
        for (channel, secret) in [
            ("team", own(n, "team")),
            ("notes", own(n, "notes")),
            ("personal", personal(n)),
        ] {
            for slot in entries::channel_slots(conn, &id_of(&secret)).unwrap() {
                let held = entries::slot_entries(conn, &id_of(&secret), &slot).unwrap();
                let read = version::current(&held, &secret, u64::from(n), |_| true).unwrap();
                let version = read.current.unwrap();
                all.insert(
                    format!("{channel} {}", version.name),
                    (version.value, version.rev),
                );
            }
        }
        all
    }

    /// Applying is one transaction: a write that is refused part-way
    /// leaves the generation the device was in whole, and everything else
    /// as it was. Asked again, the change is applied.
    #[test]
    fn test_applying_is_one_transaction() {
        let conn = holding();
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let entry = change(&phrase, &three, secret(3));
        let before = everything(&conn);
        assert!(before.iter().any(|row| row.starts_with("entries:")));

        // Each write that applying makes, refused in its turn: the third
        // entry it carries; the drop of what it left; the statement; the
        // secret it leaves; the secret it comes to; the entry it keeps;
        // the names; and the word that it has applied, which is the last.
        let refusals = [
            "BEFORE INSERT ON entries WHEN NEW.rev = 77",
            "BEFORE DELETE ON entries",
            "BEFORE UPDATE ON person",
            "BEFORE UPDATE ON person_secrets",
            "BEFORE INSERT ON person_secrets",
            "BEFORE UPDATE ON person_change_entries",
            "BEFORE UPDATE ON person_names",
            "BEFORE INSERT ON entries WHEN NEW.rev = 1",
        ];
        for refusal in refusals {
            conn.execute_batch(&format!(
                "CREATE TEMP TRIGGER refused {refusal}
                 BEGIN SELECT RAISE(ABORT, 'a write is refused'); END;"
            ))
            .unwrap();
            let failed = shown(&conn, &device(1), &entry, NOW + 60);
            assert!(
                matches!(failed, Err(PersonError::Storage(_))),
                "{refusal}: {failed:?}"
            );
            conn.execute_batch("DROP TRIGGER refused").unwrap();
            assert_eq!(everything(&conn), before, "{refusal}");
            assert!(conn.is_autocommit(), "{refusal}");
        }
        assert_eq!(applied_number(&conn), 2);

        // At a later pass it applies, as if nothing had been tried.
        let outcome = shown(&conn, &device(1), &entry, NOW + 60).unwrap();
        assert_eq!(
            outcome,
            Shown::Applied(Applied {
                number: 3,
                left: Some(2),
                carried: 6,
                no_version: Vec::new(),
            })
        );
    }

    /// Inside a transaction of the caller's, applying is whole with that
    /// one: it is undone with it, and a failure in it undoes what it wrote
    /// and nothing that the caller wrote before.
    #[test]
    fn test_inside_a_callers_transaction_applying_is_whole_with_it() {
        let conn = holding();
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let entry = change(&phrase, &three, secret(3));
        let before = everything(&conn);

        // The caller's transaction is undone, and the change with it.
        conn.execute_batch("BEGIN").unwrap();
        assert!(matches!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));
        assert_eq!(applied_number(&conn), 3);
        assert!(!conn.is_autocommit(), "the transaction is the caller's");
        conn.execute_batch("ROLLBACK").unwrap();
        assert_eq!(everything(&conn), before);

        // A failure undoes what applying wrote, and leaves what the caller
        // wrote before it, in a transaction that is still the caller's.
        conn.execute_batch("BEGIN").unwrap();
        hold_name(&conn, "written before", NOW).unwrap();
        let with_the_callers = everything(&conn);
        assert_ne!(with_the_callers, before);
        conn.execute_batch(
            "CREATE TEMP TRIGGER refused BEFORE UPDATE ON person_names
             BEGIN SELECT RAISE(ABORT, 'a write is refused'); END;",
        )
        .unwrap();
        assert!(matches!(
            shown(&conn, &device(1), &entry, NOW),
            Err(PersonError::Storage(_))
        ));
        conn.execute_batch("DROP TRIGGER refused").unwrap();
        assert!(!conn.is_autocommit());
        assert_eq!(everything(&conn), with_the_callers);

        // The caller goes on, and commits: the change is applied.
        assert!(matches!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));
        conn.execute_batch("COMMIT").unwrap();
        assert_eq!(applied_number(&conn), 3);
        assert_eq!(
            held_rows::channel_of_name(&conn, "written before").unwrap(),
            Some(id_of(&own(3, "written before")))
        );
    }

    /// After applying, the store holds only the new generation, and each
    /// slot's current version is the value it was before, at the revision
    /// that the renumbering gives it.
    #[test]
    fn test_after_applying_the_store_holds_only_the_new_generation() {
        let conn = holding();
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let word = format!("personal {}", applied_name(&key(1)).unwrap());
        let mut before = versions(&conn, 2);
        // The word that statement 2 was applied is not carried: the device
        // writes that it has applied statement 3.
        assert_eq!(before.remove(&word), Some((text("2"), 1)));
        assert_eq!(before.len(), 6);
        let old: BTreeSet<[u8; 32]> = [
            id_of(&own(2, "team")),
            id_of(&own(2, "notes")),
            id_of(&personal(2)),
        ]
        .into();
        assert_eq!(channels(&conn), old);

        let entry = change(&phrase, &three, secret(3));
        assert!(matches!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));

        let new: BTreeSet<[u8; 32]> = [
            id_of(&own(3, "team")),
            id_of(&own(3, "notes")),
            id_of(&personal(3)),
        ]
        .into();
        assert_eq!(channels(&conn), new);
        assert!(new.is_disjoint(&old));

        // The same names, each with the value it had, at the lifted
        // revision: the one in the top half of its band is in the bottom
        // half of the next, and every other is where it was.
        let mut after = versions(&conn, 3);
        assert_eq!(after.remove(&word), Some((text("3"), 1)));
        let lifted_before: BTreeMap<String, (Value, u64)> = before
            .iter()
            .map(|(name, (value, rev))| (name.clone(), (value.clone(), lifted(*rev))))
            .collect();
        assert_eq!(after, lifted_before);
        assert_eq!(before["team b.md"].1, at(2, HALF + 3));
        assert_eq!(after["team b.md"], (text("b"), at(3, 3)));
        assert_eq!(after["team a.md"], (text("a"), 5));
        assert_eq!(after["team c.md"], (Value::Delete, 9));
        assert_eq!(after["team d.md"], (Value::Other(vec![0, 0xff]), 77));
        assert_eq!(after["notes e.md"], (text("e"), at(1, 4)));

        // Every entry there is this device's own: nothing that another
        // key signed is in the new generation.
        let authors: BTreeSet<[u8; 32]> = conn
            .prepare("SELECT DISTINCT author FROM entries")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(authors, [key(1)].into());
        // A device that reads the new channel under the new statement
        // reads each of them: device 1 counts.
        for name in ["a.md", "b.md", "c.md", "d.md"] {
            assert!(carried(&conn, &own(3, "team"), name).is_some(), "{name}");
        }
    }

    /// A version that another key signed is carried as this device's own
    /// entry, with one link put first: the version's own hash, and the
    /// key that signed the entry it was carried from. So does one that a
    /// key signed which the new statement removes: it was this device's
    /// version of the file, and its chain says who signed it.
    #[test]
    fn test_a_version_another_key_signed_is_carried_with_that_key_in_a_first_link() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        hold_name(&conn, "team", NOW).unwrap();
        let team = own(2, "team");
        let chain = [link("second", 2), link("first", 0)];
        put(&conn, &team, 0, 5, "a.md", text("third"), &chain);
        // Written by device 2, which statement 3 removes.
        put(
            &conn,
            &team,
            2,
            6,
            "b.md",
            text("late"),
            &[link("agreed", 1)],
        );
        put(&conn, &team, 2, 7, "c.md", Value::Delete, &[]);

        let entry = change(&phrase, &three, secret(3));
        shown(&conn, &device(1), &entry, NOW).unwrap();
        let new = own(3, "team");

        assert_eq!(
            carried(&conn, &new, "a.md").unwrap(),
            Carried {
                author: key(1),
                chain: vec![link("third", 0), link("second", 2), link("first", 0)],
                value: text("third"),
                rev: 5,
            }
        );
        let late = carried(&conn, &new, "b.md").unwrap();
        assert_eq!(late.author, key(1));
        assert_eq!(late.chain, [link("late", 2), link("agreed", 1)]);
        // A delete is named by zeros.
        let delete = carried(&conn, &new, "c.md").unwrap();
        assert_eq!(
            delete.chain,
            [Link {
                hash: [0u8; 16],
                signer: Link::signer_of(&key(2))
            }]
        );
        assert_eq!(delete.value, Value::Delete);

        // What that gives a reader under statement 3, for whom device 2
        // does not count. A folder that holds "agreed" is not told that
        // "late" follows it: the removed key signed a version between.
        let counting = who_counts(&conn).unwrap();
        assert_eq!(counting.keys(), [key(0), key(1)]);
        let counts = |by: &[u8; 16]| counting.signer_counts(by);
        let hash = |said: &str| text(said).chain_hash();
        assert!(!known_to_follow(Some(&late.chain), &hash("agreed"), counts));
        // A folder that took "late" itself holds the version, and nothing
        // newer than it in the chain is the removed key's.
        assert!(known_to_follow(Some(&late.chain), &hash("late"), counts));
        // The control: where the signer between still counts.
        let third = carried(&conn, &new, "a.md").unwrap().chain;
        assert!(known_to_follow(Some(&third), &hash("third"), counts));
        assert!(!known_to_follow(Some(&third), &hash("first"), counts));
        assert!(known_to_follow(Some(&third), &hash("first"), |_| true));
    }

    /// A version that this device signed is carried with its chain as it
    /// was: no link is put first.
    #[test]
    fn test_a_version_this_device_signed_is_carried_with_its_chain_as_it_was() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        hold_name(&conn, "team", NOW).unwrap();
        let team = own(2, "team");
        let chain = [link("second", 2), link("first", 0)];
        put(&conn, &team, 1, 5, "a.md", text("third"), &chain);
        put(&conn, &team, 1, 6, "new.md", text("a new file"), &[]);

        shown(&conn, &device(1), &change(&phrase, &three, secret(3)), NOW).unwrap();
        let new = own(3, "team");
        assert_eq!(
            carried(&conn, &new, "a.md").unwrap(),
            Carried {
                author: key(1),
                chain: chain.to_vec(),
                value: text("third"),
                rev: 5,
            }
        );
        assert_eq!(carried(&conn, &new, "new.md").unwrap().chain, []);
    }

    /// An entry that lost a tie is not current, and is not carried. Nor
    /// is an entry that is no version: one that does not open, one in a
    /// band it may not be in, and one whose signer does not count.
    #[test]
    fn test_a_ties_loser_and_an_entry_that_is_no_version_are_not_carried() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        hold_name(&conn, "team", NOW).unwrap();
        let team = own(2, "team");

        // A tie at one revision: the text with the higher hash is the
        // file, and a text beats a delete.
        let (one, other) = ("the text of one device", "the text of another");
        let (wins, loses) = if cordelia_crypto::sha256(one.as_bytes())
            > cordelia_crypto::sha256(other.as_bytes())
        {
            (one, other)
        } else {
            (other, one)
        };
        put(&conn, &team, 0, 5, "tie.md", text(loses), &[]);
        put(&conn, &team, 2, 5, "tie.md", text(wins), &[]);
        put(&conn, &team, 1, 5, "tie.md", Value::Delete, &[]);
        // Above a version, an entry that does not open, and one in the
        // top half of a band below the statement's.
        put(&conn, &team, 0, 5, "under.md", text("the version"), &[]);
        put_what_does_not_open(&conn, &team, 2, 9, "under.md");
        put(
            &conn,
            &team,
            1,
            at(1, HALF + 2),
            "under.md",
            text("jumped"),
            &[],
        );
        // Above a version, an entry that a key signed which does not
        // count under the statement the device is leaving.
        put(&conn, &team, 0, 5, "theirs.md", text("ours"), &[]);
        put(&conn, &team, 9, 8, "theirs.md", text("a stranger's"), &[]);

        let entry = change(&phrase, &three, secret(3));
        let outcome = shown(&conn, &device(1), &entry, NOW).unwrap();
        assert_eq!(
            outcome,
            Shown::Applied(Applied {
                number: 3,
                left: Some(2),
                carried: 3,
                no_version: Vec::new(),
            })
        );
        let new = own(3, "team");
        // One entry in each slot, and it is the version that was current.
        let held = |name: &str| {
            entries::slot_entries(&conn, &id_of(&new), &slot_of(&new, name))
                .unwrap()
                .len()
        };
        for name in ["tie.md", "under.md", "theirs.md"] {
            assert_eq!(held(name), 1, "{name}");
        }
        let tie = carried(&conn, &new, "tie.md").unwrap();
        assert_eq!((tie.value, tie.rev), (text(wins), 5));
        assert_eq!(tie.chain, [link(wins, 2)]);
        let under = carried(&conn, &new, "under.md").unwrap();
        assert_eq!((under.value, under.rev), (text("the version"), 5));
        let theirs = carried(&conn, &new, "theirs.md").unwrap();
        assert_eq!((theirs.value, theirs.rev), (text("ours"), 5));
        // The store holds three entries of the name, and the word.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 4);
    }

    /// A slot that holds no version at all is passed over: what was there
    /// no longer opens. The change is applied all the same, and says in
    /// which names there were such slots.
    #[test]
    fn test_a_slot_that_holds_no_version_is_passed_over_and_its_name_is_reported() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        for name in ["team", "notes", "empty"] {
            hold_name(&conn, name, NOW).unwrap();
        }
        let (team, notes) = (own(2, "team"), own(2, "notes"));
        put(&conn, &team, 0, 5, "a.md", text("a"), &[]);
        put_what_does_not_open(&conn, &team, 0, 6, "gone.md");
        put_what_does_not_open(&conn, &team, 2, 7, "gone.md");
        // Only an entry of a key that does not count.
        put(&conn, &team, 9, 6, "theirs.md", text("a stranger's"), &[]);
        put(&conn, &notes, 0, 5, "e.md", text("e"), &[]);
        // In the personal channel such a slot is passed over, and is no
        // name's.
        put_what_does_not_open(&conn, &personal(2), 1, 6, "syncing/me");

        let entry = change(&phrase, &three, secret(3));
        assert_eq!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::Applied(Applied {
                number: 3,
                left: Some(2),
                carried: 2,
                no_version: vec!["team".to_string()],
            })
        );
        assert_eq!(applied_number(&conn), 3);
        let new = own(3, "team");
        assert!(carried(&conn, &new, "a.md").is_some());
        assert!(carried(&conn, &new, "gone.md").is_none());
        assert!(carried(&conn, &new, "theirs.md").is_none());
        assert_eq!(
            entries::channel_slots(&conn, &id_of(&new)).unwrap().len(),
            1
        );
        assert!(carried(&conn, &own(3, "notes"), "e.md").is_some());
        // What did not open is dropped with the generation it was in.
        let now: BTreeSet<[u8; 32]> =
            [id_of(&new), id_of(&own(3, "notes")), id_of(&personal(3))].into();
        assert_eq!(channels(&conn), now);
    }

    /// Where a device holds several entries of one version, it carries
    /// from one of them: its own if it holds one, and otherwise the one
    /// whose signer has the lowest key. The carried entry has that
    /// entry's chain, and that entry's signer in its first link: no link
    /// for another signer, and no other entry's chain.
    #[test]
    fn test_of_several_entries_of_one_version_one_is_carried_from() {
        let phrase = phrase();
        let [_, two, ..] = statements(&phrase);
        let (low, high) = if key(0) < key(2) { (0, 2) } else { (2, 0) };
        let hash_of_t = text("T").chain_hash();

        // One entry by a key that counts for a reader, whose chain does
        // not hold the text T, and one by a key that does not, whose
        // chain lists T. First the key that does not count is the lower.
        for (gone, stays) in [(low, high), (high, low)] {
            let conn = device_at(1, 2);
            hold_name(&conn, "team", NOW).unwrap();
            let team = own(2, "team");
            let lists_t = [link("T", 1)];
            let without_t = [link("another text", 1)];
            put(&conn, &team, gone, 9, "a.md", text("the version"), &lists_t);
            put(
                &conn,
                &team,
                stays,
                9,
                "a.md",
                text("the version"),
                &without_t,
            );
            let version = read(&conn, &team, 2, "a.md", &[0, 1, 2]);
            assert_eq!(version.current.unwrap().entries.len(), 2);

            // The statement that device 1 applies removes one of the two.
            let next = two
                .next(key(1), &secret(3), listed(&[1, stays]), &[key(gone)])
                .unwrap();
            let entry = change(&phrase, &next, secret(3));
            assert!(matches!(
                shown(&conn, &device(1), &entry, NOW).unwrap(),
                Shown::Applied(_)
            ));

            let held = read(&conn, &own(3, "team"), 3, "a.md", &[1, stays]);
            let version = held.current.unwrap();
            assert_eq!(version.entries.len(), 1);
            assert_eq!(version.entries[0].author, key(1));
            let chain = version.entries[0].chain.clone().unwrap();
            let counting = who_counts(&conn).unwrap();
            assert_eq!(counting.keys(), [key(1), key(stays)]);
            let counts = |by: &[u8; 16]| counting.signer_counts(by);

            if gone == low {
                // Carried from the lower key's entry, with that signer in
                // the first link and that entry's chain.
                assert_eq!(chain, [link("the version", gone), link("T", 1)]);
                // A reader that holds T, and for whom that signer does not
                // count, is not told that the version follows T.
                assert!(!known_to_follow(Some(&chain), &hash_of_t, counts));
                assert!(known_to_follow(Some(&chain), &hash_of_t, |_| true));
            } else {
                // The keys the other way round: carried from the entry of
                // the key that counts, whose chain does not hold T at all.
                assert_eq!(chain, [link("the version", stays), link("another text", 1)]);
                assert!(chain.iter().all(|link| link.hash != hash_of_t));
                assert!(!known_to_follow(Some(&chain), &hash_of_t, |_| true));
            }
            // Either way one signer is named, and it is the lower key.
            assert_eq!(chain[0].signer, Link::signer_of(&key(low)));
            let higher = Link::signer_of(&key(high));
            assert!(chain.iter().all(|link| link.signer != higher));
        }

        // Where the device holds an entry of its own, it carries from
        // that one, whatever the other signers' keys: its chain as it
        // was, and no link put first. The device whose key is between the
        // other two holds its own entry beside one of a lower key, and
        // beside one of a higher key.
        let mut by_key = [0u16, 1, 2];
        by_key.sort_by_key(|n| key(*n));
        let [lower, me, higher] = by_key;
        assert!(key(lower) < key(me) && key(me) < key(higher));
        for other in [lower, higher] {
            let conn = device_at(me, 2);
            hold_name(&conn, "team", NOW).unwrap();
            let team = own(2, "team");
            let own_chain = [link("what this device wrote over", other)];
            let theirs = [link("T", me)];
            put(&conn, &team, other, 9, "a.md", text("the version"), &theirs);
            put(&conn, &team, me, 9, "a.md", text("the version"), &own_chain);

            // A statement that lists all three again.
            let renewal = two
                .next(key(me), &secret(3), listed(&[0, 1, 2]), &[])
                .unwrap();
            let entry = change(&phrase, &renewal, secret(3));
            assert!(matches!(
                shown(&conn, &device(me), &entry, NOW).unwrap(),
                Shown::Applied(_)
            ));
            let held = read(&conn, &own(3, "team"), 3, "a.md", &[0, 1, 2]);
            let version = held.current.unwrap();
            assert_eq!(version.entries.len(), 1);
            assert_eq!(version.entries[0].author, key(me));
            assert_eq!(
                version.entries[0].chain.as_deref(),
                Some(&own_chain[..]),
                "{other}"
            );
        }
    }

    /// A carried chain keeps to its 100 links: with one put first, the
    /// oldest falls off. And a link may stand in it twice: where the link
    /// that is put first is in the chain already, both stand.
    #[test]
    fn test_a_carried_chain_keeps_to_a_hundred_links() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        hold_name(&conn, "team", NOW).unwrap();
        let team = own(2, "team");
        let hundred: Vec<Link> = (0..100).map(|n| link(&format!("text {n}"), 0)).collect();
        put(&conn, &team, 0, 5, "long.md", text("the newest"), &hundred);
        // Device 1 carries its own with all 100: nothing is put first.
        put(&conn, &team, 1, 5, "own.md", text("the newest"), &hundred);
        // A file that held a text, another, and the first again, each
        // written by device 0: the same text, signed by the same key, two
        // versions before.
        let again = [link("between", 1), link("the same", 0), link("first", 1)];
        put(&conn, &team, 0, 5, "again.md", text("the same"), &again);
        // And one that device 1 wrote itself, whose chain names one link
        // twice.
        let twice = [link("A", 1), link("B", 1), link("A", 1)];
        put(&conn, &team, 1, 5, "twice.md", text("C"), &twice);

        let entry = change(&phrase, &three, secret(3));
        assert!(matches!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::Applied(Applied { carried: 4, .. })
        ));
        let new = own(3, "team");

        let long = carried(&conn, &new, "long.md").unwrap().chain;
        assert_eq!(long.len(), 100);
        assert_eq!(long[0], link("the newest", 0));
        assert_eq!(long[1..], hundred[..99]);
        assert!(!long.contains(&hundred[99]));
        assert_eq!(carried(&conn, &new, "own.md").unwrap().chain, hundred);

        assert_eq!(
            carried(&conn, &new, "again.md").unwrap().chain,
            [
                link("the same", 0),
                link("between", 1),
                link("the same", 0),
                link("first", 1)
            ]
        );
        assert_eq!(carried(&conn, &new, "twice.md").unwrap().chain, twice);
    }

    /// An entry that lacks its chain is known to follow nothing, and is
    /// carried so: with the link for its signer where another key signed
    /// it, and nothing after.
    #[test]
    fn test_an_entry_that_lacks_its_chain_is_carried_as_following_nothing() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        hold_name(&conn, "team", NOW).unwrap();
        let team = own(2, "team");
        put_what_lacks_its_chain(&conn, &team, 0, 5, "theirs.md", "a text");
        put_what_lacks_its_chain(&conn, &team, 1, 5, "own.md", "a text");

        shown(&conn, &device(1), &change(&phrase, &three, secret(3)), NOW).unwrap();
        let new = own(3, "team");
        let theirs = carried(&conn, &new, "theirs.md").unwrap();
        assert_eq!(theirs.value, text("a text"));
        assert_eq!(theirs.chain, [link("a text", 0)]);
        assert_eq!(carried(&conn, &new, "own.md").unwrap().chain, []);
    }

    /// From the personal channel a device carries what it wrote there
    /// itself. What another device wrote there is that device's to carry.
    /// Records of additions are not carried, and nor is the word that the
    /// statement before was applied.
    #[test]
    fn test_from_the_personal_channel_a_device_carries_what_it_wrote_itself() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let old = personal(2);
        let mine = applied_name(&key(1)).unwrap();
        let theirs = applied_name(&key(0)).unwrap();

        put(
            &conn,
            &old,
            1,
            6,
            "syncing/one",
            text("team"),
            &[link("t", 1)],
        );
        put(&conn, &old, 0, 6, "syncing/zero", text("notes"), &[]);
        // A name that two devices wrote under: the current version is
        // device 0's in one, and device 1's in the other.
        put(&conn, &old, 1, 3, "project/x", text("an older word"), &[]);
        put(&conn, &old, 0, 4, "project/x", text("a newer word"), &[]);
        put(&conn, &old, 0, 3, "project/y", text("an older word"), &[]);
        put(&conn, &old, 1, 4, "project/y", text("a newer word"), &[]);
        // A record of an addition that device 1 wrote there.
        put(
            &conn,
            &old,
            1,
            5,
            "added/seven",
            Value::Other(vec![7; 90]),
            &[],
        );
        put(&conn, &old, 0, 5, &theirs, text("2"), &[]);
        // The word that statement 2 was applied is there from the start.
        assert_eq!(
            read(&conn, &old, 2, &mine, &[1]).current.unwrap().value,
            text("2")
        );

        let entry = change(&phrase, &three, secret(3));
        assert_eq!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::Applied(Applied {
                number: 3,
                left: Some(2),
                carried: 2,
                no_version: Vec::new(),
            })
        );
        let new = personal(3);
        assert_eq!(
            carried(&conn, &new, "syncing/one").unwrap(),
            Carried {
                author: key(1),
                chain: vec![link("t", 1)],
                value: text("team"),
                rev: 6,
            }
        );
        let newer = carried(&conn, &new, "project/y").unwrap();
        assert_eq!((newer.value, newer.rev), (text("a newer word"), 4));
        for not_carried in ["syncing/zero", "project/x", "added/seven", theirs.as_str()] {
            assert!(carried(&conn, &new, not_carried).is_none(), "{not_carried}");
        }

        // The word is the new one, and not the old one carried.
        let word = carried(&conn, &new, &mine).unwrap();
        assert_eq!((word.value, word.rev), (text("3"), 1));
        assert_eq!(
            entries::channel_slots(&conn, &id_of(&new)).unwrap().len(),
            3
        );
        assert!(
            entries::channel_slots(&conn, &id_of(&old))
                .unwrap()
                .is_empty()
        );
    }

    /// The secret of a generation that was left is kept, with the time it
    /// was left, for 90 days by the device's own clock, and is then
    /// forgotten. The one applied is not.
    #[test]
    fn test_a_secret_that_is_left_is_kept_with_its_time_and_forgotten_after_90_days() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, four] = statements(&phrase);
        shown(&conn, &device(1), &change(&phrase, &three, secret(3)), NOW).unwrap();
        let later = NOW + 30 * DAY;
        shown(&conn, &device(1), &change(&phrase, &four, secret(4)), later).unwrap();
        assert_eq!(
            secrets(&conn),
            [
                (4, secret(4), None),
                (3, secret(3), Some(later)),
                (2, secret(2), Some(NOW)),
            ]
        );

        // One second short of 90 days after the first was left.
        assert_eq!(
            held_rows::forget_left_secrets(&conn, NOW + 90 * DAY - 1).unwrap(),
            0
        );
        assert_eq!(secrets(&conn).len(), 3);
        assert_eq!(
            held_rows::forget_left_secrets(&conn, NOW + 90 * DAY).unwrap(),
            1
        );
        assert_eq!(
            secrets(&conn),
            [(4, secret(4), None), (3, secret(3), Some(later))]
        );
        assert_eq!(
            held_rows::forget_left_secrets(&conn, later + 90 * DAY).unwrap(),
            1
        );
        assert_eq!(
            held_rows::forget_left_secrets(&conn, later + 9000 * DAY).unwrap(),
            0
        );
        assert_eq!(secrets(&conn), [(4, secret(4), None)]);
        assert_eq!(applied_number(&conn), 4);
    }

    /// A channel's ID is found from a name the device holds, and the name
    /// from it: in the generation the device has applied, and after a
    /// statement in the one it has come to.
    #[test]
    fn test_the_names_a_device_holds_move_to_the_new_generation() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let channel = hold_name(&conn, "team", NOW).unwrap();
        assert_eq!(channel, id_of(&own(2, "team")));
        assert_eq!(hold_name(&conn, "github.com/owner/repo", NOW).unwrap(), {
            id_of(&own(2, "github.com/owner/repo"))
        });
        assert_eq!(
            held_rows::channel_of_name(&conn, "team").unwrap(),
            Some(channel)
        );
        assert_eq!(
            held_rows::name_of_channel(&conn, &channel)
                .unwrap()
                .as_deref(),
            Some("team")
        );
        // Held again, it is the same name and the same channel.
        assert_eq!(hold_name(&conn, "team", NOW + 5).unwrap(), channel);
        assert_eq!(held_rows::names(&conn).unwrap().len(), 2);
        // A name in another spelling is another channel, and is refused.
        assert!(matches!(
            hold_name(&conn, "Team", NOW),
            Err(PersonError::Derive(DeriveError::NameNotTidy))
        ));
        assert!(matches!(
            hold_name(&conn, "", NOW),
            Err(PersonError::Derive(DeriveError::NameEmpty))
        ));

        shown(&conn, &device(1), &change(&phrase, &three, secret(3)), NOW).unwrap();
        let moved = id_of(&own(3, "team"));
        assert_ne!(moved, channel);
        assert_eq!(
            held_rows::channel_of_name(&conn, "team").unwrap(),
            Some(moved)
        );
        assert_eq!(
            held_rows::name_of_channel(&conn, &moved)
                .unwrap()
                .as_deref(),
            Some("team")
        );
        // The channel of the generation that was left is no name's.
        assert_eq!(held_rows::name_of_channel(&conn, &channel).unwrap(), None);
        assert_eq!(
            held_rows::channel_of_name(&conn, "github.com/owner/repo").unwrap(),
            Some(id_of(&own(3, "github.com/owner/repo")))
        );
        let names = held_rows::names(&conn).unwrap();
        assert!(names.iter().all(|name| name.held_at == NOW));

        // A device that follows no phrase has no secret, and holds no
        // name. Nor does one that has stopped.
        let alone = db::open_in_memory().unwrap();
        assert!(matches!(
            hold_name(&alone, "team", NOW),
            Err(PersonError::FollowsNoPhrase)
        ));
        let removed = device_at(2, 2);
        shown(
            &removed,
            &device(2),
            &change(&phrase, &three, secret(3)),
            NOW,
        )
        .unwrap();
        assert!(matches!(
            hold_name(&removed, "team", NOW),
            Err(PersonError::Stopped(State::Removed))
        ));
    }

    /// After applying, the device has an entry of its own in the new
    /// personal channel that says the statement's number, under the name
    /// `applied/` and its key.
    #[test]
    fn test_a_device_writes_that_it_has_applied_the_statement() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let name = applied_name(&key(1)).unwrap();
        assert_eq!(
            name,
            format!("applied/{}", encode_public_key(&key(1)).unwrap())
        );
        assert!(name.starts_with("applied/cordelia_pk1"));
        assert_ne!(name, applied_name(&key(0)).unwrap());

        // Under the statement it came to follow the phrase with.
        let said = |conn: &Connection, n: u8| {
            let slot = read(conn, &personal(n), u64::from(n), &name, &[1]);
            let version = slot.current.unwrap();
            assert_eq!(version.entries.len(), 1);
            assert_eq!(version.entries[0].author, key(1));
            assert_eq!(version.entries[0].chain, Some(Vec::new()));
            (version.value, version.rev)
        };
        assert_eq!(said(&conn, 2), (text("2"), 1));

        shown(&conn, &device(1), &change(&phrase, &three, secret(3)), NOW).unwrap();
        assert_eq!(said(&conn, 3), (text("3"), 1));
        // It is in the new personal channel only: the old one is left.
        assert!(read(&conn, &personal(2), 2, &name, &[1]).current.is_none());
        // It waits in the store to be sent, as an entry of the channel
        // that only a holder of the new secret can make.
        let stored =
            entries::slot_entries(&conn, &id_of(&personal(3)), &slot_of(&personal(3), &name))
                .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].channel, id_of(&personal(3)));
        assert!(stored[0].open(&personal(2)).is_err());
    }

    /// Whoever calls, a statement is applied only on a device that it
    /// lists, and only with a secret that opens to its commitment: a
    /// device that follows no phrase comes to follow one only so.
    #[test]
    fn test_a_statement_is_applied_only_on_a_device_it_lists_with_its_secret() {
        let conn = db::open_in_memory().unwrap();
        let phrase = phrase();
        let [_, two, ..] = statements(&phrase);
        let entry = change(&phrase, &two, secret(2));
        let (following, signed) = (following(&phrase), sign(&two, &phrase));
        let empty = everything(&conn);
        let apply_as = |n: u16, secret: [u8; 32]| {
            let change = Change {
                following: &following,
                statement: &signed,
                secret: &secret,
                entry: &entry,
            };
            in_one(&conn, || {
                apply_judged(&conn, &device(n), None, &change, NOW)
            })
        };

        // Device 5 is not among its devices.
        assert!(matches!(
            apply_as(5, secret(2)),
            Err(PersonError::NotApplied(Judgement::NotListed))
        ));
        // Device 1 is, and the secret is another than the one committed
        // to.
        assert!(matches!(
            apply_as(1, secret(3)),
            Err(PersonError::SecretNotCommitted)
        ));
        assert_eq!(held(&conn).unwrap(), None);
        assert_eq!(everything(&conn), empty);

        // The control: a device it lists, with its secret.
        assert_eq!(apply_as(1, secret(2)).unwrap().number, 2);
        assert_eq!(state(&conn), State::Applied);
        assert_eq!(secrets(&conn), [(2, secret(2), None)]);
    }

    /// The first statement of a phrase is made on a device that follows
    /// none: a new secret, statement 1 with this one device, and its
    /// change entry, applied in one step.
    #[test]
    fn test_the_first_statement_is_made_and_applied() {
        let conn = db::open_in_memory().unwrap();
        let phrase = phrase();
        let applied = first_statement(&conn, &device(0), &phrase, "Kitchen laptop", NOW);
        assert_eq!(
            applied.unwrap(),
            Applied {
                number: 1,
                left: None,
                carried: 0,
                no_version: Vec::new(),
            }
        );

        // It follows the phrase: its key, the statement key and the ID of
        // its channel, and none of its words.
        let now = held(&conn).unwrap().unwrap();
        assert_eq!(now.state, State::Applied);
        assert_eq!(now.following, following(&phrase));
        // Statement 1, made on this device, which is its one device.
        let statement = &now.statement.statement;
        assert_eq!(now.statement.verify(), Ok(()));
        assert_eq!((statement.number, statement.maker), (1, key(0)));
        assert!(statement.chain.is_empty() && statement.removed.is_empty());
        assert_eq!(
            statement.devices,
            [Device::new(key(0), "Kitchen laptop").unwrap()]
        );
        assert_eq!(who_counts(&conn).unwrap().keys(), [key(0)]);

        // A secret of its own, which the statement commits to.
        let held_secrets = secrets(&conn);
        assert_eq!(held_secrets.len(), 1);
        let (number, made, left_at) = held_secrets[0];
        assert_eq!((number, left_at), (1, None));
        assert!(statement.commits_to(&made));

        // The change entry it keeps is the phrase's, and carries that
        // statement with the secret sealed to this device and for the
        // phrase.
        let entry = kept_entry(&conn, Kept::Latest).unwrap().unwrap();
        assert_eq!(entry.channel, now.following.phrase_channel);
        assert_eq!((entry.author, entry.rev), (phrase.public_key().unwrap(), 1));
        assert_eq!(entry.slot, change_slot(&phrase));
        let opened = change_entry::open_for_device(
            &entry,
            &now.following.phrase_key,
            &now.following.phrase_channel,
            &now.following.statement_key,
            &device(0),
        )
        .unwrap();
        assert_eq!(opened.statement, now.statement);
        assert_eq!(opened.secret, DeviceSecret::Opened(made));
        let for_phrase = change_entry::open_for_phrase(
            &entry,
            &phrase.public_key().unwrap(),
            &now.following.phrase_channel,
            &phrase.seal_key().unwrap(),
        )
        .unwrap();
        assert_eq!(for_phrase, ForPhrase::first(made));

        // It has written that it has applied statement 1.
        let personal = derive::personal_secret(&made).unwrap();
        let word = read(&conn, &personal, 1, &applied_name(&key(0)).unwrap(), &[0]);
        assert_eq!(word.current.unwrap().value, text("1"));

        // A device that already follows a phrase is refused, whatever
        // the phrase: nothing changes.
        let before = everything(&conn);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        for again in [&phrase, &other] {
            assert!(matches!(
                first_statement(&conn, &device(0), again, "Kitchen laptop", NOW),
                Err(PersonError::FollowsAPhrase)
            ));
        }
        assert_eq!(everything(&conn), before);

        // Made on another machine, the same phrase gives another secret.
        let elsewhere = db::open_in_memory().unwrap();
        first_statement(&elsewhere, &device(1), &phrase, "desktop", NOW).unwrap();
        assert_ne!(secrets(&elsewhere)[0].1, made);

        // A label that a statement may not carry makes no statement, and
        // the device follows no phrase.
        let unnamed = db::open_in_memory().unwrap();
        let empty = everything(&unnamed);
        assert!(matches!(
            first_statement(&unnamed, &device(0), &phrase, " laptop", NOW),
            Err(PersonError::Statement(StatementError::LabelSpaceAtAnEnd))
        ));
        assert_eq!(held(&unnamed).unwrap(), None);
        assert_eq!(everything(&unnamed), empty);
    }

    /// A statement is applied only if every rule holds. Given with its
    /// secret and its entry, as the device that made it has them, each
    /// rule is asked: and a statement that is not applied stops nothing.
    #[test]
    fn test_a_statement_is_applied_only_if_every_rule_holds() {
        let phrase = phrase();
        let [one, two, three, four] = statements(&phrase);
        let [apart, ..] = made_apart(&phrase);
        let conn = device_at(1, 3);
        hold_name(&conn, "team", NOW).unwrap();
        put(&conn, &own(3, "team"), 0, 5, "a.md", text("a"), &[]);
        let before = everything(&conn);
        let me = device(1);
        let given = |statement: &Statement, n: u8| {
            (
                sign(statement, &phrase),
                change(&phrase, statement, secret(n)),
            )
        };

        // Rule 4: the secret opens to the commitment.
        let (statement, entry) = given(&four, 4);
        for wrong in [secret(3), secret(5), four.commitment] {
            assert!(matches!(
                apply(&conn, &me, &statement, &wrong, &entry, NOW),
                Err(PersonError::SecretNotCommitted)
            ));
        }
        // Rule 2: its number is above the applied one's.
        for (behind, n) in [(&one, 1), (&two, 2), (&three, 3)] {
            let (statement, entry) = given(behind, n);
            assert!(matches!(
                apply(&conn, &me, &statement, &secret(n), &entry, NOW),
                Err(PersonError::NotApplied(Judgement::Behind))
            ));
        }
        // Rule 6: it was made after the applied one.
        let (statement, entry) = given(&apart, 13);
        assert!(matches!(
            apply(&conn, &me, &statement, &secret(13), &entry, NOW),
            Err(PersonError::NotApplied(Judgement::Fork))
        ));
        // Rule 5: no removal is undone.
        let (statement, entry) = given(&lacking_a_removal(&phrase), 15);
        assert!(matches!(
            apply(&conn, &me, &statement, &secret(15), &entry, NOW),
            Err(PersonError::Statement(StatementError::UndoesARemoval))
        ));
        // Rule 3: it is in it.
        let without = three.next(key(0), &secret(4), listed(&[0]), &[]).unwrap();
        let (statement, entry) = given(&without, 4);
        assert!(matches!(
            apply(&conn, &me, &statement, &secret(4), &entry, NOW),
            Err(PersonError::NotApplied(Judgement::NotListed))
        ));
        let removing = three
            .next(key(0), &secret(4), listed(&[0]), &[key(1)])
            .unwrap();
        let (statement, entry) = given(&removing, 4);
        assert!(matches!(
            apply(&conn, &me, &statement, &secret(4), &entry, NOW),
            Err(PersonError::NotApplied(Judgement::Removed))
        ));
        // Rule 1: the key it follows signed it.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let theirs = Statement::first(
            listed(&[1]).remove(0),
            &secret(1),
            other.public_key().unwrap(),
        )
        .unwrap();
        let (statement, entry) = (sign(&theirs, &other), change(&other, &theirs, secret(1)));
        assert!(matches!(
            apply(&conn, &me, &statement, &secret(1), &entry, NOW),
            Err(PersonError::ChangeEntry(ChangeEntryError::AnotherChannel))
        ));
        let mut forged = sign(&four, &phrase);
        forged.signature[0] ^= 1;
        let (_, entry) = given(&four, 4);
        assert!(matches!(
            apply(&conn, &me, &forged, &secret(4), &entry, NOW),
            Err(PersonError::NotTheStatementsEntry)
        ));

        // The entry is the statement's own: not another statement's, not
        // one in another slot of the phrase's channel, and not one that
        // another key wrote there.
        let (statement, _) = given(&four, 4);
        let (_, of_another) = given(&three, 3);
        assert!(matches!(
            apply(&conn, &me, &statement, &secret(4), &of_another, NOW),
            Err(PersonError::NotTheStatementsEntry)
        ));
        let (_, good) = given(&four, 4);
        let elsewhere = signed_in(
            &phrase.channel_secret().unwrap(),
            &phrase.signing_key().unwrap(),
            slot_of(&phrase.channel_secret().unwrap(), "another name"),
            4,
            false,
            good.content.clone(),
        );
        assert!(matches!(
            apply(&conn, &me, &statement, &secret(4), &elsewhere, NOW),
            Err(PersonError::ChangeEntry(ChangeEntryError::AnotherSlot))
        ));
        let by_another = signed_in(
            &phrase.channel_secret().unwrap(),
            &device(0),
            change_slot(&phrase),
            4,
            false,
            good.content.clone(),
        );
        assert!(matches!(
            apply(&conn, &me, &statement, &secret(4), &by_another, NOW),
            Err(PersonError::ChangeEntry(ChangeEntryError::AnotherAuthor))
        ));

        // None of them changed anything, and none stopped the device.
        assert_eq!(everything(&conn), before);
        assert_eq!(state(&conn), State::Applied);

        // The control: every rule holds.
        let applied = apply(&conn, &me, &statement, &secret(4), &good, NOW).unwrap();
        assert_eq!((applied.number, applied.left), (4, Some(3)));
        assert_eq!(applied_number(&conn), 4);
        assert_eq!(kept(&conn, Kept::Latest), Some(good.id()));

        // A device that follows no phrase, and one that has stopped.
        let alone = db::open_in_memory().unwrap();
        let (statement, entry) = given(&one, 1);
        assert!(matches!(
            apply(&alone, &device(0), &statement, &secret(1), &entry, NOW),
            Err(PersonError::FollowsNoPhrase)
        ));
        let removed = device_at(2, 2);
        let (statement, entry) = given(&three, 3);
        shown(&removed, &device(2), &entry, NOW).unwrap();
        let (later, its_entry) = given(&four, 4);
        assert!(matches!(
            apply(&removed, &device(2), &later, &secret(4), &its_entry, NOW),
            Err(PersonError::Stopped(State::Removed))
        ));
        assert_eq!(statement.statement.number, 3);
    }

    /// What a device holds of its person is checked again as it is read:
    /// a statement that was changed where it lay is no statement of the
    /// phrase, and nothing is done on its word.
    #[test]
    fn test_a_statement_that_was_changed_where_it_lay_is_refused() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        assert!(held(&conn).unwrap().is_some());

        // One bit of its signature.
        let mut row = held_rows::person(&conn).unwrap().unwrap();
        let last = row.statement.len() - 1;
        row.statement[last] ^= 1;
        held_rows::put_person(&conn, &row).unwrap();
        assert!(matches!(held(&conn), Err(PersonError::Held(_))));
        let entry = change(&phrase, &three, secret(3));
        assert!(matches!(
            shown(&conn, &device(1), &entry, NOW),
            Err(PersonError::Held(_))
        ));
        assert!(matches!(who_counts(&conn), Err(PersonError::Held(_))));

        // A statement that another phrase signed, in its place.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let theirs = Statement::first(
            listed(&[1]).remove(0),
            &secret(1),
            other.public_key().unwrap(),
        )
        .unwrap();
        conn.execute(
            "UPDATE person SET statement = ?1",
            [sign(&theirs, &other).to_bytes().unwrap()],
        )
        .unwrap();
        assert!(matches!(held(&conn), Err(PersonError::Held(_))));
    }
}
