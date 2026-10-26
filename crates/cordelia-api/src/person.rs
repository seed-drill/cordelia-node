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
//! is applied that does not list it. Inside that bound, who counts does not
//! turn on the order in which the records were seen: a record that was kept
//! as not counted is judged again whenever another is kept. [`see_addition`]
//! takes a record, and [`who_counts`] says who counts.
//!
//! ## A change entry that a device is shown (§4.2 to §4.6)
//!
//! A device keeps the change it follows and up to seven heads set aside
//! (decision 2026-10-24 (removal), rule 1). One function decides what a
//! change is to it ([`decide`], rule 8), whether it is shown one
//! ([`shown`]), handed one at `cordelia accept`, or judges what it kept at
//! its first start on this version ([`judge_kept`], rule 12). It does
//! exactly one thing with it:
//!
//! - it is one the device keeps, or it is behind one: nothing;
//! - it removes this device, on any branch: the device stops;
//! - it was made after the one followed, counts this device and is clear:
//!   it is applied, in the same step; its secret does not open: the device
//!   stops;
//! - it was made after the one followed and does not list this device:
//!   the device stops;
//! - anything else is kept as a head set aside: the device goes on where
//!   the change it follows is clear, and is closed where it is not
//!   (stored as `fork`, rule 10), until the move of rule 9 is built;
//! - it is not the phrase's, or not well formed: it is refused, and
//!   nothing changes.
//!
//! ## What a device knows of removals (decision 2026-10-24 (removal))
//!
//! A device keeps every key that a change it has seen and checked lists
//! as removed, on any branch, and never takes one out (rule 2); and, for
//! the change it follows, every key that a record of an addition under it
//! adds, apart from the records and their bound (rule 3). A change is
//! **clear** where none of those keys holds its secret: no removed key is
//! among its devices or among the keys its records add. **A device seals
//! only under a clear secret** (rule 4): [`come_to`] refuses a change that
//! is not clear, and so does `Standing::to_write`
//! (`crate::publish::Standing`), where every other seal takes its secret.
//! A device that follows a change that is not clear is **closed**: stored
//! so by rule 8 (`fork`), and worked out beneath that as the gate, from
//! the commit that keeps what makes the change not clear
//! (`crate::at_relays::Stands::Closed`). It sends nothing and takes
//! nothing in a channel of its own. Who counts reads every removed
//! key ([`Counting`], rule 6).
//!
//! ## Applying (§4.2, §7.2, §7.3, §7.5)
//!
//! One transaction. The statement and the secret are stored, the device
//! leaves the generation it was in, and it carries: every current version
//! it holds, in each name it holds, and its own entry in each slot of the
//! personal channel, is sealed again as its own entry in the new
//! generation, at the revision that the renumbering gives it. What the
//! store holds of the generation it left is then dropped, and the device
//! writes, in the new personal channel, that it has applied the statement
//! (§8). Where any of it fails, nothing is changed.
//!
//! How far the store's own order had got when the carry was written is
//! kept (`cordelia_storage::at_relays`): what the device holds of its own
//! in the channel of a name, up to there, is what it carried, and is sent
//! to a relay by a rule of its own (§7.3). What it kept of each relay for
//! a channel that it left goes with the channel.

use std::collections::BTreeMap;

use rusqlite::Connection;
use zeroize::{Zeroize, Zeroizing};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{
    MAX_CHANGE_HEADS, MAX_COUNTED_DEVICES, MAX_NOT_COUNTED_RECORDS, PERSONAL_ADDED_PREFIX,
    PERSONAL_APPLIED_PREFIX, PERSONAL_APPLIED_SENT, PERSONAL_REACHED_PREFIX,
    RECOVERY_MAX_LEFT_SECRETS,
};
use cordelia_core::revision::lifted;
use cordelia_crypto::CryptoError;
use cordelia_crypto::addition::{AdditionError, SignedAddition};
use cordelia_crypto::bech32::{encode_channel_id, encode_public_key};
use cordelia_crypto::chain;
use cordelia_crypto::change_entry::{self, ChangeEntryError, DeviceSecret, ForPhrase};
use cordelia_crypto::derive::{self, DeriveError};
use cordelia_crypto::entry::{CheckedEntry, Entry, EntryError, Inside, Link, Value};
use cordelia_crypto::hand_over::HandOverError;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::phrase::Phrase;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::statement::{
    self, Device, Judgement, SignedStatement, Statement, StatementError, judge,
};
use cordelia_crypto::version::{self, Version};
use cordelia_storage::acts;
use cordelia_storage::at_relays as kept_rows;
use cordelia_storage::entries::{self, Outcome};
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, Following, KeptAddition, Person, State};
use cordelia_storage::sync_state;

/// Why something was not done with what a device holds of its person.
#[derive(Debug, thiserror::Error)]
pub enum PersonError {
    #[error("this device follows no recovery phrase")]
    FollowsNoPhrase,

    #[error("this device already follows a recovery phrase")]
    FollowsAPhrase,

    #[error("the statement is not the first of a phrase, made on this device and listing it alone")]
    NotAFirstStatement,

    #[error(
        "the statement is not a recovery's: made on this device and listing it alone, after \
         another statement"
    )]
    NotARecovery,

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

    #[error("the record of this device's addition does not count under the statement: {0:?}")]
    RecordNotCounted(NotCounted),

    #[error("what this device holds of its person changed since the prompt: nothing was made")]
    ChangedSincePrompt,

    #[error("the statement was made on another device than this one: nothing was made")]
    MadeOnAnotherDevice,

    #[error(
        "sync is on here, and this device is alone under a recovery phrase: `cordelia sync off` \
         first, so that sending its folders to another set of devices takes two acts."
    )]
    SyncIsOn,

    #[error(
        "8 keys that were typed at `cordelia accept` are within their hour on this device, and \
         a ninth is refused: each holds its place for an hour from when it was typed."
    )]
    TooManyTypedKeys,

    #[error("this device does not hold the name {0}")]
    NameNotHeld(String),

    #[error(
        "a device that was removed holds the secret of this change, as far as this device \
         knows: nothing is sealed under it. A change made with the recovery phrase on this \
         device (`cordelia renew`) lists no removed device, and goes on; where this device is \
         itself one that was removed, `cordelia devices` says so, and its way on is a new key."
    )]
    NotClear,

    #[error(
        "this device was removed: a change of the recovery phrase that it has seen removes \
         it, and nothing is sealed under a change that lists it. `cordelia init --new-key` \
         gives it a new key; it is then added as a new device."
    )]
    RemovedAsKnown,

    #[error(
        "the word that was given with the recovery phrase does not hold here: the phrase that \
         this device follows did not give it, or it was given for another device or before the \
         last change, or its ten minutes have gone by. Nothing was taken."
    )]
    NoWord,

    #[error("{0}")]
    NotCarried(String),

    #[error("a merge is written over a version, and the slot holds none")]
    MergeOverNoVersion,

    #[error("the statement lists that key as removed: it is not added again without a new key")]
    KeyRemoved,

    #[error(
        "this device may not add: it was added, since the last change, by a device added since"
    )]
    MayNotAdd,

    #[error("this device counts 64 devices already: a statement makes room")]
    NoRoom,

    #[error(
        "a device of the applied statement is neither among those that stay nor among the removed"
    )]
    NeitherStaysNorRemoved,

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
    HandOver(#[from] HandOverError),

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
    /// Every key this device knows to be removed (decision 2026-10-24
    /// (removal), rule 2): those the statement lists, and those any other
    /// change it has seen lists, on any branch.
    removed: Vec<[u8; 32]>,
    /// The keys added since by a record that counts, in the order the
    /// device saw their records.
    added: Vec<[u8; 32]>,
    /// The keys that a device of the statement has added, by any record
    /// the device keeps, counted or not.
    added_by_a_listed: Vec<[u8; 32]>,
    /// The key of every record of an addition that the device keeps,
    /// counted or not.
    recorded: Vec<[u8; 32]>,
}

impl Counting {
    /// Who counts under `statement`, with the records the device keeps
    /// under it, where `removed` are the keys the device knows to be
    /// removed besides those the statement lists (decision 2026-10-24
    /// (removal), rule 6: a key removed on any branch counts for nothing).
    pub(crate) fn of(statement: &Statement, kept: &[KeptAddition], removed: &[[u8; 32]]) -> Self {
        let keys = |records: &mut dyn Iterator<Item = &KeptAddition>| {
            records.map(|record| record.key).collect::<Vec<_>>()
        };
        let mut removed: Vec<[u8; 32]> = statement.removed.iter().chain(removed).copied().collect();
        removed.sort_unstable();
        removed.dedup();
        Self {
            listed: statement.devices.iter().map(|device| device.key).collect(),
            removed,
            added: keys(&mut kept.iter().filter(|record| record.counted)),
            added_by_a_listed: keys(
                &mut kept.iter().filter(|record| statement.lists(&record.adder)),
            ),
            recorded: keys(&mut kept.iter()),
        }
    }

    /// Every key that counts or that the device keeps a record of an
    /// addition for, each once, in order (decision 2026-10-19 §2, rule
    /// 1): the keys whose slots tell a delete of the personal channel that
    /// is no word.
    pub(crate) fn known(&self) -> Vec<[u8; 32]> {
        let mut keys: Vec<[u8; 32]> = self
            .listed
            .iter()
            .chain(&self.added)
            .chain(&self.recorded)
            .filter(|key| self.counts(key) || self.recorded.contains(key))
            .copied()
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }

    /// Who counts where `devices` are the devices of the statement, with
    /// no key removed and none added since: what a reader counts that is
    /// handed the list alone.
    pub fn of_devices(devices: &[[u8; 32]]) -> Self {
        Self {
            listed: devices.to_vec(),
            removed: Vec::new(),
            added: Vec::new(),
            added_by_a_listed: Vec::new(),
            recorded: Vec::new(),
        }
    }

    /// Whether `key` counts: the statement lists it as a device, or a
    /// record that counts adds it. A key that the device knows to be
    /// removed, on any branch, never counts (decision 2026-10-24
    /// (removal), rule 6).
    pub fn counts(&self, key: &[u8; 32]) -> bool {
        if self.is_removed(key) {
            return false;
        }
        self.listed.contains(key) || self.added.contains(key)
    }

    /// Whether the device knows `key` to be removed, on any branch
    /// (decision 2026-10-24 (removal), rule 2).
    pub fn is_removed(&self, key: &[u8; 32]) -> bool {
        self.removed.binary_search(key).is_ok()
    }

    /// Whether `key` may add a device: it is a device of the statement, or
    /// a key that counts and that such a device added. One that only
    /// devices added since have added may not, until a statement lists it:
    /// a chain is two long at most.
    ///
    /// Any record that the device keeps for the key says so, whether it
    /// was the one that made the key count or came after it: the answer
    /// does not turn on the order in which the device saw the records.
    pub fn may_add(&self, key: &[u8; 32]) -> bool {
        if !self.counts(key) {
            return false;
        }
        self.listed.contains(key) || self.added_by_a_listed.contains(key)
    }

    /// Whether a record that adds `key`, signed by `adder`, is one that
    /// lets the key add: the key counts by a record, and a device of the
    /// statement signed this one ([`Counting::may_add`]). A key that the
    /// statement lists needs none. Of several such records for one key, the
    /// order of keeping keeps one first (decision 2026-10-17 §2.2).
    fn lets_add(&self, key: &[u8; 32], adder: &[u8; 32]) -> bool {
        self.listed.contains(adder) && !self.listed.contains(key) && self.counts(key)
    }

    /// How many devices count: those of the statement, and those added
    /// since.
    pub fn devices(&self) -> usize {
        self.listed.len() + self.added.len()
    }

    /// How many keys may add a device ([`Counting::may_add`]).
    pub fn adders(&self) -> usize {
        self.keys().iter().filter(|key| self.may_add(key)).count()
    }

    /// What a record that adds `key`, signed by `adder`, is to this
    /// reader: whether the key counts by it, and where it does not, why.
    /// It is one rule, asked when a record is seen and asked again of a
    /// record that was kept as not counted.
    fn judge(&self, key: &[u8; 32], adder: &[u8; 32]) -> AdditionSeen {
        if self.is_removed(key) {
            AdditionSeen::NotCounted(NotCounted::Removed)
        } else if self.counts(key) {
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        } else if !self.may_add(adder) {
            AdditionSeen::NotCounted(NotCounted::MayNotAdd)
        } else if self.devices() >= MAX_COUNTED_DEVICES {
            AdditionSeen::NotCounted(NotCounted::NoRoom)
        } else {
            AdditionSeen::Counted
        }
    }

    /// Why a record that adds `key`, signed by `adder`, does not count
    /// for this reader as things stand: what [`Counting::judge`] says of
    /// it. `None` where it would count.
    pub fn why_not(&self, key: &[u8; 32], adder: &[u8; 32]) -> Option<NotCounted> {
        match self.judge(key, adder) {
            AdditionSeen::NotCounted(why) => Some(why),
            AdditionSeen::Counted | AdditionSeen::SeenBefore => None,
        }
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
            .chain(self.added.iter())
            .filter(|key| self.counts(key))
            .copied()
            .collect()
    }
}

/// Who counts for this device, under the statement it has applied.
pub fn who_counts(conn: &Connection) -> Result<Counting, PersonError> {
    let held = held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
    counting(
        conn,
        &held.statement.statement,
        &held_rows::additions(conn)?,
    )
}

/// Who counts under `statement`, the one this device has applied, with
/// `kept`, the records it keeps under it, and every key it knows to be
/// removed (decision 2026-10-24 (removal), rule 6).
pub(crate) fn counting(
    conn: &Connection,
    statement: &Statement,
    kept: &[KeptAddition],
) -> Result<Counting, PersonError> {
    Ok(Counting::of(statement, kept, &known_removed(conn)?))
}

/// Every key this device keeps as removed (decision 2026-10-24 (removal),
/// rule 2), as the database holds them. The door asks who counts for each
/// entry, so they are read once for each mark of `person_clear_mark`
/// (schema step 21), which every write of them makes anew, and kept only
/// where the mark is the same after the read as before it: as
/// [`follows_a_clear_change`] keeps what it works out.
fn known_removed(conn: &Connection) -> Result<std::sync::Arc<Vec<[u8; 32]>>, PersonError> {
    let mark = held_rows::clear_mark(conn)?;
    if let Some(mark) = mark
        && let Some(keys) = REMOVED_READ.with_borrow(|kept| match kept {
            Some((at, keys)) if *at == mark => Some(keys.clone()),
            _ => None,
        })
    {
        return Ok(keys);
    }
    let keys = std::sync::Arc::new(held_rows::removed_keys(conn)?);
    if let Some(mark) = mark
        && held_rows::clear_mark(conn)? == Some(mark)
    {
        REMOVED_READ.set(Some((mark, keys.clone())));
    }
    Ok(keys)
}

thread_local! {
    /// The removed keys as this thread last read them ([`known_removed`]),
    /// with the mark they were read under. One for each thread, so that
    /// what one thread reads of one database does not put out what another
    /// thread keeps of another.
    #[allow(clippy::type_complexity)]
    static REMOVED_READ: std::cell::RefCell<Option<([u8; 16], std::sync::Arc<Vec<[u8; 32]>>)>> =
        const { std::cell::RefCell::new(None) };
}

// ── What a device knows of removals ──────────────────────────────────

/// Keep the keys that `statement` lists as removed (decision 2026-10-24
/// (removal), rule 2): it is a change this device has seen and checked,
/// whether it follows it, keeps it apart, finds it behind, or is stopped
/// by it. They only grow.
pub(crate) fn know_removed(
    conn: &Connection,
    statement: &Statement,
    now: i64,
) -> Result<(), PersonError> {
    held_rows::keep_removed(conn, &statement.removed, now)?;
    Ok(())
}

/// Keep the keys that `shown` lists as removed, where the phrase that this
/// device follows signed it (decision 2026-10-24 (removal), rule 2):
/// whatever it is to the device, and though it is then refused. A change
/// shown that undoes a removal, or a hand-over refused at `cordelia
/// accept`, still says what the person removed. The device's own key is
/// left out only where the change is after the one applied and stops it
/// as removed, as [`shown`] leaves it out: it then seals nothing, and its
/// way on is a new key. Anywhere else its own key is kept, and the device
/// is closed. Nothing is kept where the phrase did not sign it.
pub(crate) fn know_removed_if_signed(
    conn: &Connection,
    identity: &NodeIdentity,
    shown: &SignedStatement,
    now: i64,
) -> Result<(), PersonError> {
    let Some(held) = held(conn)? else {
        return Ok(());
    };
    let follows = &held.following.phrase_key;
    if shown.statement.phrase_key != *follows || shown.verify().is_err() {
        return Ok(());
    }
    let own = identity.public_key();
    let mut removes = shown.statement.clone();
    if held.state != State::Fork
        && judge(shown, &held.statement.statement, &own, follows) == Ok(Judgement::Removed)
    {
        removes.removed.retain(|key| *key != own);
    }
    know_removed(conn, &removes, now)
}

/// Whether the secret of `statement`'s change is clear on this device
/// (decision 2026-10-24 (removal), rule 3): no key that the device knows
/// to be removed holds it, as far as the device knows. It is held by each
/// device the statement lists, and by each key that a record of an
/// addition under it adds, kept apart from the records' bound. Where the
/// device kept more removed keys than it can, or a change more holders,
/// it is not clear: that fails closed.
///
/// `followed` says that it is the statement the device has applied: the
/// records it keeps are all under that one, and their keys are holders
/// too, kept or not as holders, which a device stepped to this version
/// had seen before it kept holders apart.
pub(crate) fn is_clear(
    conn: &Connection,
    statement: &Statement,
    followed: bool,
) -> Result<bool, PersonError> {
    if held_rows::removed_past_bound(conn)? {
        return Ok(false);
    }
    let link = statement.link()?;
    if held_rows::holders_past_bound(conn, link.number, &link.hash)? {
        return Ok(false);
    }
    let removed = Counting::of(statement, &[], &known_removed(conn)?);
    let mut holders: Vec<[u8; 32]> = statement.devices.iter().map(|device| device.key).collect();
    holders.extend(held_rows::holders(conn, link.number, &link.hash)?);
    if followed {
        holders.extend(held_rows::additions(conn)?.iter().map(|record| record.key));
    }
    Ok(!holders.iter().any(|key| removed.is_removed(key)))
}

/// Whether the change that this device follows is clear (decision
/// 2026-10-24 (removal), rules 3 and 4): one that stands applied under a
/// change that is not is closed. False where it follows no phrase.
///
/// It is asked at the door for each entry, for each request on a
/// connection and as each stream opens, under the node's lock, so it is
/// worked out once for each mark of `person_clear_mark` (schema step 21),
/// and not on every read: every write of what it is worked out from makes
/// a new mark, by a trigger, whichever code writes it. Under a mark it has
/// worked out, it reads the mark alone. It is worked out from the row of
/// the person as the database holds it, and kept only where the mark is
/// the same after as before: so no write, kept or undone, leaves a "clear"
/// to be read under a mark that it is not true of. It fails closed.
pub fn follows_a_clear_change(conn: &Connection) -> Result<bool, PersonError> {
    let mark = held_rows::clear_mark(conn)?;
    if let Some(mark) = mark
        && let Some(clear) = clear_worked_out(&mark)
    {
        return Ok(clear);
    }
    let clear = match held(conn)? {
        Some(held) => is_clear(conn, &held.statement.statement, true)?,
        None => false,
    };
    if let Some(mark) = mark
        && held_rows::clear_mark(conn)? == Some(mark)
    {
        CLEAR_WORKED_OUT.set(Some((mark, clear)));
    }
    Ok(clear)
}

thread_local! {
    /// Whether the change followed is clear, as this thread last worked it
    /// out ([`follows_a_clear_change`]), with the mark it was worked out
    /// under. A mark is 16 random bytes, made anew by every write: one is
    /// never the mark of two databases, or of two states of one. One for
    /// each thread, as [`REMOVED_READ`] is.
    static CLEAR_WORKED_OUT: std::cell::Cell<Option<([u8; 16], bool)>> =
        const { std::cell::Cell::new(None) };
}

/// What was worked out under `mark`, where the last worked out was.
fn clear_worked_out(mark: &[u8; 16]) -> Option<bool> {
    match CLEAR_WORKED_OUT.get() {
        Some((kept, clear)) if kept == *mark => Some(clear),
        _ => None,
    }
}

/// The key that a chain names by `signer`, its first 16 bytes (decision
/// 2026-10-04 §2.3), where this device knows of exactly one such key: a
/// device of the statement it has applied, a key that a record it keeps
/// adds, a key that the statement lists as removed, or a key that it
/// shows as not in the last change. `None` where it knows of none, or of
/// more than one: a name of 16 bytes is then no key's.
///
/// It is for what a person is shown, and decides nothing: whether a link
/// counts is asked of the keys that count ([`Counting::signer_counts`]).
pub fn key_signed_as(
    conn: &Connection,
    signer: &[u8; 16],
) -> Result<Option<[u8; 32]>, PersonError> {
    let Some(held) = held(conn)? else {
        return Ok(None);
    };
    let statement = &held.statement.statement;
    let mut known: Vec<[u8; 32]> = statement
        .devices
        .iter()
        .map(|device| device.key)
        .chain(statement.removed.iter().copied())
        .chain(held_rows::additions(conn)?.iter().map(|record| record.key))
        .chain(acts::left_out(conn)?.iter().map(|shown| shown.key))
        .filter(|key| Link::signer_of(key) == *signer)
        .collect();
    known.sort_unstable();
    known.dedup();
    Ok(match known.as_slice() {
        [only] => Some(*only),
        _ => None,
    })
}

/// What became of a record of an addition that a device saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdditionSeen {
    /// It is kept, and the key it adds counts from now on.
    Counted,
    /// It is kept as not counted, and says why. It is judged again each
    /// time another record is kept, and comes to count where it then
    /// would.
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
    /// record added it. No later record displaces that one. The record is
    /// kept, and says who else added the key: where a device of the
    /// statement signed it, the key may add.
    CountsAlready,
    /// The device that signed it was itself added by a device added since
    /// the statement: a chain is two long at most. Where a record by a
    /// device of the statement is seen later for that signer, this one
    /// comes to count.
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
/// Inside the bound of 64, who counts does not turn on the order in which
/// the records were seen. A record that is kept as not counted because its
/// signer may not add yet is judged again each time another record is
/// kept, and comes to count once a record by a device of the statement is
/// kept for its signer: "8 adds 9" counts whether it was seen before "0
/// adds 8" or after it. So does whatever that lets count in its turn,
/// while a chain of two allows.
///
/// What stands: a key that counts is not displaced by a later record, and
/// goes on counting; and a record that found no room is not counted until
/// a statement makes room. Whether a key that counts may add is read from
/// every record kept for it ([`Counting::may_add`]).
///
/// The records that are kept as not counted have a bound, 256: every
/// time a device asks who counts it loads what it keeps, and a device that
/// counts can sign any number of records. Beyond the bound they go from
/// the end of the order of keeping (decision 2026-10-17 §2.2), which goes
/// by what the records say and who counts, and not by when they were
/// seen. One that went is then as a record that was never seen: given
/// again, it is judged as any record is.
///
/// One record that is not counted never goes so: for each key that counts
/// by a record, the oldest by its time that a device of the statement
/// signed. It is what lets that key add, where the record the key counts
/// by was signed by a device added since, and no number of records by
/// another device takes that from the key.
///
/// What is returned is what the record was when it was seen. A caller that
/// asks how many keys came to count with it reads [`who_counts`] before
/// and after.
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
        let counting = counting(conn, statement, &kept)?;
        if !counting.counts(&added.adder) {
            return Err(PersonError::RecordByAKeyThatDoesNotCount);
        }

        let seen = counting.judge(&added.device.key, &added.adder);
        held_rows::keep_addition(
            conn,
            &bytes,
            &added.device.key,
            &added.adder,
            seen == AdditionSeen::Counted,
            now,
        )?;
        // The key the record adds holds the change's secret, counted or
        // not, and is kept so apart from the record, which the bound below
        // may drop (decision 2026-10-24 (removal), rule 3). Where it is a
        // removed key, the change is not clear from this commit on.
        let link = statement.link()?;
        held_rows::keep_holder(conn, link.number, &link.hash, &added.device.key)?;
        judge_again(conn, statement)?;
        keep_to_the_bound(conn, statement)?;
        Ok(seen)
    })
}

/// Keep the records that are not counted, under `statement`, to their
/// bound of 256 (decision 2026-10-04 §6): beyond it they go from the end
/// of the order of keeping ([`in_the_order_of_keeping`]). The order is
/// worked out from the records and from who counts, so which records stay
/// does not turn on the order in which the device saw them (decision
/// 2026-10-17 §1, property 2).
fn keep_to_the_bound(conn: &Connection, statement: &Statement) -> Result<(), PersonError> {
    let kept = held_rows::additions(conn)?;
    // Within the bound nothing goes, and the order is not worked out: it
    // is worked out after each record a reader takes beyond it.
    if kept.iter().filter(|row| !row.counted).count() <= MAX_NOT_COUNTED_RECORDS {
        return Ok(());
    }
    let counting = counting(conn, statement, &kept)?;
    let order = in_the_order_of_keeping(statement, &counting, &kept);
    for record in order.iter().skip(MAX_NOT_COUNTED_RECORDS) {
        held_rows::drop_not_counted(conn, record.seen)?;
    }
    Ok(())
}

/// A record that is not counted, with the time it says it was made
/// (`Addition::at`). A row whose bytes end before a time says none, and
/// is put after every time.
struct Placed<'a> {
    row: &'a KeptAddition,
    at: u64,
}

impl Placed<'_> {
    /// Its place among records of one key: by the time it says, and then
    /// by its bytes, so that two readers choose the same one.
    fn by_time(&self) -> (u64, &[u8]) {
        (self.at, &self.row.record)
    }
}

/// The records that are not counted, in the order a reader keeps them
/// (decision 2026-10-17 §2.2). The first are the last to go.
///
/// 1. Those that let a key add ([`Counting::lets_add`]): for each such
///    key, the oldest by its time, and then by its bytes. There are at
///    most 63, one for each key that counts by a record.
/// 2. Those whose key the 64 kept out (`NotCounted::NoRoom`), dealt to
///    their adders in turn ([`dealt`]).
/// 3. Those whose adder counts and may not add yet
///    (`NotCounted::MayNotAdd`), dealt in the same way: such a record
///    comes to count once a record by a device of the statement is kept
///    for its adder.
/// 4. Every other, by its time, and then by key, adder and bytes.
///
/// At most 63 records are of the first kind and at most 64 keys may add,
/// so each adder that may add keeps its first `KEPT_OUT_PER_ADDER` keys
/// that the 64 kept out, whatever another key signs (§1, property 1).
/// A recovery shows its rows of records that do not count in this order
/// too (`recover::read_generation`, §2.2).
pub(crate) fn in_the_order_of_keeping<'a>(
    statement: &Statement,
    counting: &Counting,
    kept: &'a [KeptAddition],
) -> Vec<&'a KeptAddition> {
    #[cfg(test)]
    tests::ORDERS_WORKED_OUT.with(|orders| orders.set(orders.get() + 1));
    let mut let_add: Vec<Placed<'a>> = Vec::new();
    let (mut kept_out, mut may_not_add, mut rest) = (Vec::new(), Vec::new(), Vec::new());
    for row in kept.iter().filter(|row| !row.counted) {
        // The row is of a record that was verified when it was kept: its
        // time is read, and the record is not checked again.
        let at = SignedAddition::time_of(&row.record).unwrap_or(u64::MAX);
        let record = Placed { row, at };
        if counting.lets_add(&row.key, &row.adder) {
            let_add.push(record);
        } else {
            match counting.why_not(&row.key, &row.adder) {
                Some(NotCounted::NoRoom) => kept_out.push(record),
                Some(NotCounted::MayNotAdd) if counting.counts(&row.adder) => {
                    may_not_add.push(record)
                }
                _ => rest.push(record),
            }
        }
    }

    let first = one_for_each_key(let_add, &mut rest);

    let kept_out = dealt(statement, kept_out, &mut rest);
    let may_not_add = dealt(statement, may_not_add, &mut rest);
    rest.sort_by(|one, other| {
        let order = |record: &Placed<'a>| {
            let row = record.row;
            (record.at, row.key, row.adder, &row.record)
        };
        order(one).cmp(&order(other))
    });
    first
        .into_iter()
        .map(|record| record.row)
        .chain(kept_out)
        .chain(may_not_add)
        .chain(rest.into_iter().map(|record| record.row))
        .collect()
}

/// Of `records`, the oldest for each key by its time, and then by its
/// bytes, in order of key. The others go to `rest`.
fn one_for_each_key<'a>(
    mut records: Vec<Placed<'a>>,
    rest: &mut Vec<Placed<'a>>,
) -> Vec<Placed<'a>> {
    records
        .sort_by(|one, other| (one.row.key, one.by_time()).cmp(&(other.row.key, other.by_time())));
    let mut one_each: Vec<Placed<'a>> = Vec::new();
    for record in records {
        if one_each
            .last()
            .is_some_and(|kept| kept.row.key == record.row.key)
        {
            rest.push(record);
        } else {
            one_each.push(record);
        }
    }
    one_each
}

/// `records` dealt by key to their adders in turn (decision 2026-10-17
/// §2.2): each adder's first key before any adder's second, each adder's
/// second before any adder's third, and so on.
///
/// An adder has one place for each key, which the oldest of its records
/// for that key takes, by its time and then by its bytes; any other goes
/// to `rest`. An adder's keys are in the order of the time its record for
/// each says, the oldest first, and then by key: that orders only that
/// adder's own keys. Within a turn the devices of the statement come
/// first, in its order, and then the other adders by key, so no adder
/// takes another's turn by what it signs.
fn dealt<'a>(
    statement: &Statement,
    records: Vec<Placed<'a>>,
    rest: &mut Vec<Placed<'a>>,
) -> Vec<&'a KeptAddition> {
    let mut by_adder: BTreeMap<[u8; 32], Vec<Placed<'a>>> = BTreeMap::new();
    for record in records {
        by_adder.entry(record.row.adder).or_default().push(record);
    }
    let mut adders: Vec<(usize, [u8; 32], Vec<Placed<'a>>)> = Vec::new();
    for (adder, records) in by_adder {
        let mut places = one_for_each_key(records, rest);
        places.sort_by_key(|place| (place.at, place.row.key));
        let listed = statement
            .devices
            .iter()
            .position(|device| device.key == adder);
        adders.push((listed.unwrap_or(usize::MAX), adder, places));
    }
    adders.sort_by_key(|(listed, adder, _)| (*listed, *adder));

    let turns = adders
        .iter()
        .map(|(.., places)| places.len())
        .max()
        .unwrap_or(0);
    let mut order = Vec::new();
    for turn in 0..turns {
        for (.., places) in &adders {
            if let Some(place) = places.get(turn) {
                order.push(place.row);
            }
        }
    }
    order
}

/// Judge again the records that are kept as not counted, under
/// `statement`, until none of them would count (decision 2026-10-04 §6).
///
/// One comes to count where, as things now stand, it would count if it
/// were seen: its key is not removed and does not count yet, its signer
/// may add, and there is room. Each that comes to count may let another:
/// the records are asked again from the first, in the order they were
/// seen. A record keeps its place in that order.
fn judge_again(conn: &Connection, statement: &Statement) -> Result<(), PersonError> {
    loop {
        let kept = held_rows::additions(conn)?;
        let counting = counting(conn, statement, &kept)?;
        let comes_to_count = kept.iter().find(|record| {
            !record.counted && counting.judge(&record.key, &record.adder) == AdditionSeen::Counted
        });
        let Some(record) = comes_to_count else {
            return Ok(());
        };
        held_rows::count_addition(conn, record.seen)?;
    }
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

/// The name, in the personal channel, of the carried word of the device
/// whose key is `device` (decision 2026-10-19 §4, rule 4): `reached/` and
/// the device's key, as a device's key is written. Only that device's own
/// entry there is its word.
pub fn reached_name(device: &[u8; 32]) -> Result<String, PersonError> {
    Ok(format!(
        "{PERSONAL_REACHED_PREFIX}{}",
        encode_public_key(device)?
    ))
}

/// What a device's word that it has applied a statement holds (decision
/// 2026-10-04 §8): the statement's number, and, once the device has sent
/// what it carried, PERSONAL_APPLIED_SENT after it.
pub fn applied_word(number: u64, sent: bool) -> String {
    match sent {
        true => format!("{number}{PERSONAL_APPLIED_SENT}"),
        false => number.to_string(),
    }
}

/// What a word that a statement is applied says: the statement's number,
/// and whether the device has sent what it carried. `None` for a text
/// that is no such word: a number is digits and nothing else, as a device
/// writes one.
pub fn read_applied_word(word: &str) -> Option<(u64, bool)> {
    let (number, sent) = match word.strip_suffix(PERSONAL_APPLIED_SENT) {
        Some(number) => (number, true),
        None => (word, false),
    };
    let digits = !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit());
    let number: u64 = digits.then(|| number.parse().ok()).flatten()?;
    Some((number, sent))
}

/// The name, in the personal channel, of a record that adds the device
/// whose key is `device` (decision 2026-10-04 §6): `added/` and that
/// device's key, as a device's key is written. Each device that adds the
/// key has an entry of its own there.
pub fn added_name(device: &[u8; 32]) -> Result<String, PersonError> {
    Ok(format!(
        "{PERSONAL_ADDED_PREFIX}{}",
        encode_public_key(device)?
    ))
}

// ── A change entry that a device is shown ────────────────────────────

/// What a change entry that a device was shown was to it, and what was
/// done with it (decision 2026-10-04 §4.2 to §4.6; decision 2026-10-24
/// (removal), rule 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// It is an entry the device keeps: the change it follows, or a head
    /// it sets aside. Nothing was done.
    Held,
    /// Its statement is behind the change followed or a head set aside:
    /// the one applied, or one on the chain of a change the device keeps.
    /// Nothing was done but keeping the keys it removes.
    Behind,
    /// It could be applied, and was, in the same step.
    Applied(Applied),
    /// Its statement lists this device, and the secret that comes with it
    /// did not open, or was not there. The device has stopped, and keeps
    /// the entry.
    NotOpened,
    /// Its statement lists this device's key as removed, made after the
    /// change followed or apart from it (rule 8, step 3). The device has
    /// stopped, and keeps the entry.
    Removed,
    /// Its statement lists this device in neither list, and was made after
    /// the change followed. The device has stopped, and keeps the entry.
    NotListed,
    /// It is kept as a head set aside, and the change followed is still
    /// clear: the device goes on (rules 1, 8 step 6, and 11).
    SetAside,
    /// The device is closed (rule 10): the change it follows is not clear,
    /// and none it keeps that is clear is moved to in this version of the
    /// build; or the change was a ninth head. Where it could be kept, it is
    /// kept as a head set aside.
    Closed,
    /// It was refused, and nothing changed but the keys it removes, where
    /// the phrase signed it.
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
    /// another phrase, or has another number; its lineage is not its
    /// statement's; or what follows its statement is no list of sealed
    /// secrets at all, or, for a device that the statement does not list,
    /// is a list that is missing or short. Or its statement undoes a
    /// removal of a change it was made after.
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
    /// The names in whose channel a slot held no version at all, though
    /// it held an entry of a key that counts: what was there no longer
    /// opens. Such a slot is passed over.
    ///
    /// A slot that held only entries of keys that do not count is not
    /// among them. Those entries are not read: for this device the slot
    /// held nothing, and there is nothing to say of it.
    pub no_version: Vec<String>,
    /// The files whose record in a folder was dropped, each as the name
    /// it syncs under and the file's own name: in its slot the device's
    /// store held no version at all (decision 2026-10-04 §4.2). Such a
    /// file meets the new channel as a new file does: it is published as
    /// this device's own, or, where the channel has a version of that
    /// name, its text is kept beside it.
    pub not_carried: Vec<(String, String)>,
}

/// A head that a device sets aside, opened as the device opens it
/// (decision 2026-10-24 (removal), rule 1).
#[derive(Debug, Clone)]
pub(crate) struct Head {
    /// Its place among the heads set aside: what it is dropped by.
    pub(crate) place: i64,
    pub(crate) entry: CheckedEntry,
    pub(crate) statement: SignedStatement,
    /// When the device set it aside, by its own clock.
    pub(crate) set_aside_at: i64,
}

/// The heads this device sets aside, the highest number first, each
/// checked again and opened as this device opened it when it was kept:
/// one whose list of secrets is short was read so by a device that it
/// lists, and is read so again.
pub(crate) fn set_aside_heads(
    conn: &Connection,
    identity: &NodeIdentity,
    following: &Following,
) -> Result<Vec<Head>, PersonError> {
    let not_held = |what: String| PersonError::Held(format!("a head set aside: {what}"));
    let mut heads = Vec::new();
    for kept in held_rows::set_aside_entries(conn)? {
        let entry = kept.entry.check().map_err(|e| not_held(e.to_string()))?;
        let statement = change_entry::open_for_device(
            &entry,
            &following.phrase_key,
            &following.phrase_channel,
            &following.statement_key,
            identity,
        )
        .map_err(|e| not_held(e.to_string()))?
        .statement;
        heads.push(Head {
            place: kept.place,
            entry,
            statement,
            set_aside_at: kept.set_aside_at,
        });
    }
    Ok(heads)
}

/// Decide what a change entry that this device was shown is to it, and
/// do exactly one thing with it (see [`Shown`]). `entry` has passed the
/// check that needs no key.
///
/// It is rule 8 of decision 2026-10-24 (removal), the one function
/// ([`decide`]), for a change shown: one that the device keeps is held, a
/// device that has stopped for another reason than a fork takes nothing
/// (the way on is a person's), and one that is not the phrase's change
/// entry is refused.
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
        if entry.id() == followed_entry(conn)?.id() || keeps_set_aside(conn, entry)? {
            return Ok(Shown::Held);
        }
        if !matches!(held.state, State::Applied | State::Fork) {
            return Ok(Shown::Refused(Refused::Stopped));
        }

        // Whether it is the phrase's, and what it says to this device: it
        // is opened as the entry it is, and one that the phrase's key did
        // not write in its channel's one slot is not opened at all. The
        // signature, the form and the lineage are checked here (rule 8,
        // step 2).
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
        let statement = &opened.statement;
        let mut apply = |held: &Held| match &opened.secret {
            DeviceSecret::Opened(secret) if opens(statement, secret) => {
                let change = Change {
                    following: &held.following,
                    statement,
                    secret,
                    entry,
                };
                apply_judged(conn, identity, Some(held), &change, now).map(Shown::Applied)
            }
            _ => {
                stop(conn, State::NotOpened, entry)?;
                Ok(Shown::NotOpened)
            }
        };
        decide(
            conn, identity, &held, entry, statement, false, &mut apply, now,
        )
    })
}

/// Whether the device keeps `entry` as a head set aside, by its two
/// signatures, which name it.
fn keeps_set_aside(conn: &Connection, entry: &CheckedEntry) -> Result<bool, PersonError> {
    Ok(held_rows::set_aside_entries(conn)?
        .iter()
        .any(|kept| kept.entry.channel_signature == entry.channel_signature))
}

/// Rule 8 of decision 2026-10-24 (removal): one function decides what a
/// change of the phrase's is to this device, each time it is shown one
/// that it does not keep, is handed one at `cordelia accept`, and at its
/// first start on this version (rule 12). `held` is what the device holds,
/// in state applied or closed; `entry` is the change's entry, checked and
/// opened to `statement`; `apply` applies it, where step 4 says to, and is
/// asked nothing else. `by_a_record` is whether the caller brings a record
/// of this device's addition with the change, which `apply` checks counts
/// (at `cordelia accept`): a statement that does not list the device then
/// counts it all the same. In this order:
///
/// 1. A change that is the one followed, a head kept, or behind one of
///    them: nothing is done but keeping the keys it removes, as today.
/// 2. Otherwise its removed keys are kept (rule 2), with its time, and
///    each head set aside that it was made after is dropped. A change that
///    undoes a removal of one it was made after, the one followed or a
///    head, is refused (4.2, rule 5): its removed keys are kept all the
///    same.
/// 3. A change that lists this device's key as removed stops it, as
///    removed, whether it was made after the change followed or apart.
/// 4. A change made after the one followed, that counts this device and
///    is clear, is applied ([`decide`]'s `apply`): it lists the device, or
///    comes with a record of its addition.
/// 5. A change made after the one followed that neither counts this
///    device nor removes it stops it, as in no list, clear or not. One
///    that counts it by a record and is not clear goes on to step 6.
/// 6. Anything else is kept as a head set aside: a ninth closes the
///    device, and is not kept. Where the change followed is still clear,
///    the device goes on (rule 11).
/// 7. Where it is not clear, the device would move to the best clear
///    change that counts it (rule 9). The move is a later slice of the
///    build: until it is built the device closes here. It fails closed.
/// 8. Where there is none, the device is closed (rule 10).
#[allow(clippy::too_many_arguments)]
pub(crate) fn decide(
    conn: &Connection,
    identity: &NodeIdentity,
    held: &Held,
    entry: &CheckedEntry,
    statement: &SignedStatement,
    by_a_record: bool,
    apply: &mut dyn FnMut(&Held) -> Result<Shown, PersonError>,
    now: i64,
) -> Result<Shown, PersonError> {
    let own = identity.public_key();
    let heads = set_aside_heads(conn, identity, &held.following)?;
    if heads.iter().any(|head| head.entry.id() == entry.id()) {
        return Ok(Shown::Held);
    }
    // Step 1, with the check of step 2 that refuses a statement which
    // undoes a removal of a change it was made after.
    let judgement = match judged(held, &heads, statement, &own)? {
        Ok(judgement) => judgement,
        Err(e) => {
            // Refused, and still what the person removed where the phrase
            // signed it (rule 2): a change that drops a removal and makes
            // another says that the other key is removed.
            know_removed_if_signed(conn, identity, statement, now)?;
            close_if_not_clear(conn)?;
            return Ok(Shown::Refused(Refused::NotAChangeEntry(e.into())));
        }
    };
    let shown = &statement.statement;
    let link = shown.link()?;
    let behind_a_head = heads.iter().any(|head| {
        let kept = &head.statement.statement;
        kept.link().is_ok_and(|kept| kept == link) || kept.has_on_chain(&link)
    });
    if judgement == Judgement::Behind || behind_a_head {
        know_removed(conn, shown, now)?;
        return Ok(Shown::Behind);
    }

    // Step 2. Its removed keys are kept from now on, on any branch. But
    // for this device's own key where the change stops it as removed: it
    // seals nothing from then, its way on is a new key, and it still reads
    // its own store, what it carried and has yet to let go among it.
    let removes_this_device = shown.removes(&own);
    let mut removes = shown.clone();
    if removes_this_device {
        removes.removed.retain(|key| *key != own);
    }
    know_removed(conn, &removes, now)?;
    note_time(conn, entry, shown)?;
    let mut left = heads.len();
    for head in &heads {
        if shown.has_on_chain(&head.statement.statement.link()?) {
            held_rows::drop_set_aside(conn, head.place)?;
            left -= 1;
        }
    }

    // Step 3.
    if removes_this_device {
        stop(conn, State::Removed, entry)?;
        return Ok(Shown::Removed);
    }
    // Steps 4 and 5: a change made after the one followed.
    let counts = match judgement {
        Judgement::Applies => true,
        Judgement::NotListed => by_a_record,
        _ => false,
    };
    match judgement {
        _ if counts && is_clear(conn, shown, false)? => return apply(held),
        Judgement::NotListed if by_a_record => {}
        Judgement::NotListed | Judgement::Removed => {
            stop(conn, State::NotListed, entry)?;
            return Ok(Shown::NotListed);
        }
        _ => {}
    }

    // Step 6: a head set aside, the change followed and up to seven.
    if left + 1 >= MAX_CHANGE_HEADS {
        close(conn)?;
        return Ok(Shown::Closed);
    }
    held_rows::set_aside(conn, entry, now)?;
    if held.state == State::Applied && follows_a_clear_change(conn)? {
        return Ok(Shown::SetAside);
    }
    // Steps 7 and 8.
    close(conn)?;
    Ok(Shown::Closed)
}

/// What the statement `shown` is to this device beside the change it
/// follows ([`judge`]): the four rules of 4.2 that `judge` keeps for a
/// change made after the one applied. And, of each head set aside that it
/// was made after, it keeps every removal: a statement lists as removed
/// every key that any statement on its chain removes (4.2, rule 5).
///
/// The error inside is the statement's: it is no statement that this
/// device takes, and nothing is done with it. The error outside is this
/// device's.
fn judged(
    held: &Held,
    heads: &[Head],
    shown: &SignedStatement,
    own: &[u8; 32],
) -> Result<Result<Judgement, StatementError>, PersonError> {
    let following = &held.following;
    let applied = &held.statement.statement;
    let judgement = match judge(shown, applied, own, &following.phrase_key) {
        Ok(judgement) => judgement,
        Err(e) => return Ok(Err(e)),
    };
    if judgement == Judgement::Behind {
        return Ok(Ok(judgement));
    }
    for head in heads {
        let kept = &head.statement.statement;
        if shown.statement.has_on_chain(&kept.link()?)
            && !shown.statement.keeps_the_removals_of(kept)
        {
            return Ok(Err(StatementError::UndoesARemoval));
        }
    }
    Ok(Ok(judgement))
}

/// Note the time of the change of `statement`, whose entry is `entry`, as
/// its lineage says it was made (decision 2026-10-24 (removal), rule 2):
/// none for an entry of the version before, which has no lineage.
pub(crate) fn note_time(
    conn: &Connection,
    entry: &CheckedEntry,
    statement: &Statement,
) -> Result<(), PersonError> {
    let made_at = change_entry::lineage(&entry.content)?
        .and_then(|lineage| i64::try_from(lineage.made_at).ok());
    let link = statement.link()?;
    held_rows::note_change_time(conn, link.number, &link.hash, made_at)?;
    Ok(())
}

/// The device is closed (decision 2026-10-24 (removal), rule 10), where it
/// stood applied: stored as `fork`. One that is closed already, or stopped,
/// stays as it is. It keeps nothing in memory of what it read of its
/// personal channel.
fn close(conn: &Connection) -> Result<(), PersonError> {
    if held_rows::person(conn)?.is_some_and(|person| person.state == State::Applied) {
        held_rows::set_state(conn, State::Fork)?;
        crate::names::forget_kept();
    }
    Ok(())
}

/// Close this device where it stands applied under a change that is not
/// clear (decision 2026-10-24 (removal), rules 8 and 10): what it knows of
/// removals grew with no change kept, by a record that adds a removed key
/// under the change it follows (rule 3), or by the keys of a change that
/// was refused. The move of rule 9 is not built yet, so it closes. Says
/// whether it closed.
pub(crate) fn close_if_not_clear(conn: &Connection) -> Result<bool, PersonError> {
    let applied = held_rows::person(conn)?.is_some_and(|person| person.state == State::Applied);
    if !applied || follows_a_clear_change(conn)? {
        return Ok(false);
    }
    close(conn)?;
    Ok(true)
}

/// At its first start on the version that keeps every head, a device
/// judges what it kept (decision 2026-10-24 (removal), rule 12): it notes
/// the time of each change entry it keeps, and a device in a fork applies
/// rule 8 to the entry it kept apart, which step 22 set aside. It moves,
/// goes on, or stays closed: an entry of the version before has no
/// lineage, and is judged by its statement alone. Done once, where step 22
/// marked it; says whether it judged anything.
pub fn judge_kept(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<Option<Shown>, PersonError> {
    in_one(conn, || {
        if !held_rows::to_judge_kept(conn)? {
            return Ok(None);
        }
        held_rows::judged_kept(conn)?;
        let Some(held) = held(conn)? else {
            return Ok(None);
        };
        let following = held.following;
        if let Some(followed) = kept_followed(conn)? {
            let read = change_entry::open_statement(
                &followed,
                &following.phrase_key,
                &following.phrase_channel,
                &following.statement_key,
            );
            if let Ok(read) = read {
                note_time(conn, &followed, &read.statement)?;
            }
        }
        if held.state != State::Fork {
            return Ok(None);
        }
        let mut judged = None;
        for head in set_aside_heads(conn, identity, &following)? {
            held_rows::drop_set_aside(conn, head.place)?;
            // Judged as a device that is not closed: rule 8 closes it
            // again where nothing clear counts it.
            held_rows::set_state(conn, State::Applied)?;
            let held = crate::person::held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
            // A change made apart is not applied here: nothing comes of
            // step 4 for it.
            let mut apply = |_: &Held| Ok(Shown::Closed);
            let shown = decide(
                conn,
                identity,
                &held,
                &head.entry,
                &head.statement,
                false,
                &mut apply,
                now,
            )?;
            if shown == Shown::Closed {
                close(conn)?;
            }
            judged = Some(shown);
            let stays = held_rows::person(conn)?.map(|person| person.state);
            if !matches!(stays, Some(State::Applied | State::Fork)) {
                break;
            }
        }
        // A device in a fork that kept nothing apart is judged by what it
        // follows alone.
        if judged.is_none() && follows_a_clear_change(conn)? {
            held_rows::set_state(conn, State::Applied)?;
            judged = Some(Shown::SetAside);
        }
        Ok(judged)
    })
}

/// The device stops, and keeps the entry that stopped it as the one it
/// shows. It keeps no head set aside.
fn stop(conn: &Connection, state: State, entry: &CheckedEntry) -> Result<(), PersonError> {
    held_rows::set_state(conn, state)?;
    held_rows::keep_followed(conn, entry)?;
    held_rows::drop_all_set_aside(conn)?;
    // A device that has stopped keeps nothing in memory of what it read
    // of its personal channel.
    crate::names::forget_kept();
    Ok(())
}

/// The change entry of the change the device follows: on a device that
/// has stopped, the one that stopped it. A device that follows a phrase
/// keeps one.
pub(crate) fn followed_entry(conn: &Connection) -> Result<CheckedEntry, PersonError> {
    kept_followed(conn)?.ok_or_else(|| {
        PersonError::Held("a device that follows a phrase keeps a change entry".into())
    })
}

/// The change entry of the change the device follows, checked again as it
/// is read: `None` where it keeps none.
pub(crate) fn kept_followed(conn: &Connection) -> Result<Option<CheckedEntry>, PersonError> {
    held_rows::followed_entry(conn)?
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
pub(crate) struct Change<'a> {
    /// What the device follows, or comes to follow with this statement.
    pub(crate) following: &'a Following,
    pub(crate) statement: &'a SignedStatement,
    pub(crate) secret: &'a [u8; 32],
    /// The statement's change entry, which the device keeps.
    pub(crate) entry: &'a CheckedEntry,
}

/// Apply `statement`, given with its `secret` and its change entry, on a
/// device that follows the statement's phrase (decision 2026-10-04 §4.2):
/// the device that made the statement applies it so (§7.2).
///
/// Every rule of §4.2 is asked here. The statement is judged beside the
/// one applied, and only one that applies is applied: the phrase the
/// device follows signed it, its number is above, the device is among its
/// devices, no removal is undone, it was made after the one applied, and
/// it commits to another secret than the one applied.
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
        let heads = set_aside_heads(conn, identity, &held.following)?;
        let judgement = judged(&held, &heads, statement, &identity.public_key())??;
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
/// It is the two halves in one place, for a caller that holds the phrase
/// and the database both: what the command makes with the phrase
/// ([`first_entry`]), and what the node does with it ([`follow_first`]).
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
    if held_rows::person(conn)?.is_some() {
        return Err(PersonError::FollowsAPhrase);
    }
    let made = first_entry(phrase, &identity.public_key(), label)?;
    follow_first(conn, identity, &made.entry, &made.statement_key, now)
}

/// Apply the change that a command made on this device, with the phrase
/// (decision 2026-10-04 §7.1, §7.2): the node's half of `cordelia
/// remove-device`, `cordelia renew` and `cordelia settle`. `entry` is the
/// change entry that the command signed and sealed. The node opens the
/// secret that the entry seals to this device's key, and applies the
/// statement in one transaction, with its carry.
///
/// **What the prompt showed is checked again inside that transaction.**
/// `over` is what the change entry was named by of the change that the
/// device followed when the command was handed what it showed, and
/// `apart` that of the head set aside that the change settles, where it
/// settles two. Where the device follows another change now, no longer
/// keeps that head, or keeps a head where none was shown, a statement
/// arrived between the prompt and the phrase. Nothing is made, and the
/// command asks again ([`PersonError::ChangedSincePrompt`]).
///
/// A record of an addition that arrived meanwhile changes neither entry,
/// and never does that: its key is in neither of the statement's lists,
/// and is shown as not in the last change (§6, §8).
///
/// Refused besides, with nothing changed: whatever [`apply`] refuses, an
/// entry that seals no secret to this device, and a statement whose
/// maker is another key than the one this node runs under (§16).
pub fn apply_made(
    conn: &Connection,
    identity: &NodeIdentity,
    entry: &CheckedEntry,
    over: &[u8; 32],
    apart: Option<&[u8; 32]>,
    now: i64,
) -> Result<Applied, PersonError> {
    in_one(conn, || {
        let held = held(conn)?.ok_or(PersonError::FollowsNoPhrase)?;
        let heads: Vec<[u8; 32]> = set_aside_heads(conn, identity, &held.following)?
            .iter()
            .map(|head| head.entry.id())
            .collect();
        // A change that settles is made over a head set aside, which the
        // device still keeps; any other only where it keeps none (decision
        // 2026-10-24 (removal), rule 21 joins them in a later slice).
        let heads_as_shown = match apart {
            Some(apart) => heads.contains(apart),
            None => heads.is_empty(),
        };
        let as_shown = followed_entry(conn)?.id() == *over && heads_as_shown;
        if !as_shown || !matches!(held.state, State::Applied | State::Fork) {
            return Err(PersonError::ChangedSincePrompt);
        }
        let following = &held.following;
        let opened = change_entry::open_for_device(
            entry,
            &following.phrase_key,
            &following.phrase_channel,
            &following.statement_key,
            identity,
        )?;
        let DeviceSecret::Opened(secret) = opened.secret else {
            return Err(PersonError::SecretNotCommitted);
        };
        // A command makes a statement for the key in its device's key
        // file, which is the key this node runs under (§16): a statement
        // that says it was made on another device was not made by a
        // command of this one.
        if opened.statement.statement.maker != identity.public_key() {
            return Err(PersonError::MadeOnAnotherDevice);
        }
        apply(conn, identity, &opened.statement, &secret, entry, now)
    })
}

/// What the command that makes a phrase hands the node (decision
/// 2026-10-04 §5, §5.2): never the words, and nothing that signs or
/// seals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstMade {
    /// The change entry of statement 1: the statement, the new secret
    /// sealed to the one device it lists, and the part for the phrase.
    pub entry: CheckedEntry,
    /// The statement key, which every device that follows the phrase is
    /// given, and which opens the statement in each change entry.
    pub statement_key: [u8; 32],
}

/// Make the first statement of `phrase` for the device whose key is
/// `device`, under `label`, and its change entry (decision 2026-10-04
/// §5.2): the part that needs the phrase, done where the phrase is. A new
/// secret is made here, and is in the entry only sealed: to the device,
/// and to the phrase.
pub fn first_entry(
    phrase: &Phrase,
    device: &[u8; 32],
    label: &str,
) -> Result<FirstMade, PersonError> {
    let secret = Zeroizing::new(statement::new_secret()?);
    let device = Device::new(*device, label)?;
    let statement =
        Statement::first(device, &secret, phrase.public_key()?)?.sign(&phrase.signing_key()?)?;
    let mut for_phrase = ForPhrase::first(*secret);
    let entry = change_entry::entry_of(phrase, &statement, &for_phrase, crate::change::made_now());
    // The new secret is in the entry, sealed: what is left of it here is
    // overwritten.
    for_phrase.secret.zeroize();
    Ok(FirstMade {
        entry: entry?.check()?,
        statement_key: *phrase.statement_key()?,
    })
}

/// Follow the phrase whose first statement `entry` carries, on a device
/// that follows none (decision 2026-10-04 §5.2): the node's half of
/// `cordelia phrase`. `entry` is the change entry that the command made
/// with the phrase, and `statement_key` the phrase's statement key. The
/// node is handed those two, and opens the secret that the entry seals to
/// this device's key.
///
/// Refused, with nothing changed: on a device that already follows a
/// phrase; an entry that is no change entry, or that the statement key
/// does not open; a statement that is not the first of its phrase, made
/// on this device and listing it alone; and a secret that is not sealed
/// to this device, or is not the one that the statement commits to.
pub fn follow_first(
    conn: &Connection,
    identity: &NodeIdentity,
    entry: &CheckedEntry,
    statement_key: &[u8; 32],
    now: i64,
) -> Result<Applied, PersonError> {
    in_one(conn, || {
        if held_rows::person(conn)?.is_some() {
            return Err(PersonError::FollowsAPhrase);
        }
        // The phrase's key is the entry's author, and the phrase's channel
        // the entry's: the entry is signed by both, and the statement in
        // it by the first.
        let following = Following {
            phrase_key: entry.author,
            statement_key: *statement_key,
            phrase_channel: entry.channel,
        };
        let opened = change_entry::open_for_device(
            entry,
            &following.phrase_key,
            &following.phrase_channel,
            &following.statement_key,
            identity,
        )?;
        opened.statement.verify()?;
        let own = identity.public_key();
        let first = &opened.statement.statement;
        let is_first = first.number == 1
            && first.chain.is_empty()
            && first.removed.is_empty()
            && first.maker == own
            && first.devices.len() == 1
            && first.devices[0].key == own;
        if !is_first {
            return Err(PersonError::NotAFirstStatement);
        }
        let DeviceSecret::Opened(secret) = opened.secret else {
            return Err(PersonError::SecretNotCommitted);
        };
        let change = Change {
            following: &following,
            statement: &opened.statement,
            secret: &secret,
            entry,
        };
        its_own_entry(&change)?;
        apply_judged(conn, identity, None, &change, now)
    })
}

/// Follow the phrase whose statement `entry` carries, on a device that
/// follows none, where a recovery made that statement on this device
/// (decision 2026-10-04 §5.1, §9, step 4): the node's half of `cordelia
/// recover`. `entry` is the change entry that the command made with the
/// phrase, and `statement_key` the phrase's statement key. The node opens
/// the secret that the entry seals to this device's key, and applies the
/// statement: it has nothing to carry.
///
/// `left` are the secrets of the generation that was recovered from, and
/// of those before it that its change entry gave the phrase, each with
/// its statement's number. **The machine keeps them as a device keeps a
/// secret it left, for 90 days** (§3, §9): they are for the look that
/// follows, and for a carry by command after it. They are the one thing
/// that the phrase opens which the node is handed.
///
/// Refused, with nothing changed: on a device that already follows a
/// phrase; an entry that is no change entry, or that the statement key
/// does not open; a statement that is not a recovery's (made on this
/// device, listing it alone, after another statement); a secret that is
/// not sealed to this device, or is not the one that the statement
/// commits to; more secrets than an entry gives; and one that is said to
/// be of this statement or a later one.
pub fn follow_recovered(
    conn: &Connection,
    identity: &NodeIdentity,
    entry: &CheckedEntry,
    statement_key: &[u8; 32],
    left: &[(u64, [u8; 32])],
    now: i64,
) -> Result<Applied, PersonError> {
    in_one(conn, || {
        if held_rows::person(conn)?.is_some() {
            return Err(PersonError::FollowsAPhrase);
        }
        let following = Following {
            phrase_key: entry.author,
            statement_key: *statement_key,
            phrase_channel: entry.channel,
        };
        let opened = change_entry::open_for_device(
            entry,
            &following.phrase_key,
            &following.phrase_channel,
            &following.statement_key,
            identity,
        )?;
        opened.statement.verify()?;
        let own = identity.public_key();
        let made = &opened.statement.statement;
        let is_a_recoverys = made.number > 1
            && !made.chain.is_empty()
            && made.maker == own
            && made.devices.len() == 1
            && made.devices[0].key == own;
        if !is_a_recoverys {
            return Err(PersonError::NotARecovery);
        }
        let DeviceSecret::Opened(secret) = opened.secret else {
            return Err(PersonError::SecretNotCommitted);
        };
        let before_it = left
            .iter()
            .all(|(number, _)| *number >= 1 && *number < made.number);
        if left.len() > RECOVERY_MAX_LEFT_SECRETS || !before_it {
            return Err(PersonError::NotARecovery);
        }
        let change = Change {
            following: &following,
            statement: &opened.statement,
            secret: &secret,
            entry,
        };
        its_own_entry(&change)?;
        let applied = apply_judged(conn, identity, None, &change, now)?;
        for (number, left_secret) in left {
            held_rows::keep_left_secret(conn, *number, left_secret, now)?;
        }
        Ok(applied)
    })
}

/// Whether the change's entry is its statement's own, under what the
/// device follows: it is opened as the phrase's change entry, and the
/// statement key opens it to this very statement.
pub(crate) fn its_own_entry(change: &Change) -> Result<(), PersonError> {
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
/// Rule 3 of §4.2 is asked again here, whoever calls: the device is among
/// the statement's devices. Rule 4 is asked where the device comes to the
/// statement's generation ([`come_to`]): the secret opens to the
/// commitment. And the secret is another than the one the device leaves:
/// were the two one, what is carried would be dropped with what is left.
pub(crate) fn apply_judged(
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
    come_to(conn, identity, before, change, now)
}

/// Apply a statement on a device that is being added under it, inside the
/// caller's transaction (decision 2026-10-04 §4.2, rule 3; §6): the
/// statement does not list the device, and a record of its addition comes
/// with it. `addition` is that record, and `adders_own` the record of the
/// adder's own addition, where the adder was itself added since the
/// statement.
///
/// The record adds this device, under this statement, or the statement is
/// not applied. Once the statement is applied the records are taken as
/// any that the device sees ([`see_addition`]), the adder's own first, and
/// each of them counts: where one does not, the device is not in the
/// statement, and the error undoes everything.
pub(crate) fn apply_added(
    conn: &Connection,
    identity: &NodeIdentity,
    before: Option<&Held>,
    change: &Change,
    addition: &SignedAddition,
    adders_own: Option<&SignedAddition>,
    now: i64,
) -> Result<Applied, PersonError> {
    let statement = &change.statement.statement;
    let adds_this_device = addition.addition.device.key == identity.public_key();
    if !adds_this_device || addition.addition.under != statement.link()? {
        return Err(PersonError::NotApplied(Judgement::NotListed));
    }
    let applied = come_to(conn, identity, before, change, now)?;
    for record in adders_own.into_iter().chain([addition]) {
        match see_addition(conn, record, now)? {
            AdditionSeen::Counted => {}
            AdditionSeen::NotCounted(why) => return Err(PersonError::RecordNotCounted(why)),
            AdditionSeen::SeenBefore => {
                return Err(PersonError::Held(
                    "a record of an addition is kept under a statement just applied".into(),
                ));
            }
        }
    }
    Ok(applied)
}

/// The device comes to the generation of the change's statement: what
/// [`apply_judged`] and [`apply_added`] do once rule 3 is answered. It
/// stands applied under it afterwards, closed or not before.
fn come_to(
    conn: &Connection,
    identity: &NodeIdentity,
    before: Option<&Held>,
    change: &Change,
    now: i64,
) -> Result<Applied, PersonError> {
    let statement = &change.statement.statement;
    if !opens(change.statement, change.secret) {
        return Err(PersonError::SecretNotCommitted);
    }
    // Every apply seals under the change's own secret, here: its carry and
    // its word that it applied. So a change that is not clear is refused
    // here, whoever calls (decision 2026-10-24 (removal), rule 4). The
    // keys that the change it leaves and this one remove are kept first
    // (rule 2).
    if let Some(before) = before {
        know_removed(conn, &before.statement.statement, now)?;
    }
    know_removed(conn, statement, now)?;
    if !is_clear(conn, statement, false)? {
        // Where this device's own key is among the removed, no change that
        // lists it is clear, and its way on is a new key: it says so, and
        // not that a change made here goes on.
        if held_rows::removed_keys(conn)?.contains(&identity.public_key()) {
            return Err(PersonError::RemovedAsKnown);
        }
        return Err(PersonError::NotClear);
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
        not_carried: Vec::new(),
    };
    if let Some(before) = before {
        let leaving = &before.statement.statement;
        note_left_out(conn, identity, leaving, statement, now)?;
        // A device's word that it left is in the personal channel that
        // is left with this statement: it is kept where the device is
        // still listed and nobody cleared it (§7.1).
        crate::look::keep_left_words(conn, identity, leaving, statement, now)?;
        let from = Generation {
            number: leaving.number,
            secret: applied_secret(conn, leaving)?,
        };
        // The generation it comes to is another than the one it leaves:
        // the carry reads the one and writes the other, and then drops
        // the one.
        if from.secret == to.secret {
            return Err(StatementError::SameSecret.into());
        }
        // The carry reads the generation it leaves as it did before this
        // record: what a removed key wrote there, and was taken before
        // the device knew, is cut by a later slice of decision 2026-10-24
        // (removal), rule 7.
        let counting = Counting::of(leaving, &held_rows::additions(conn)?, &[]);
        applied.left = Some(from.number);

        let own = identity.public_key();
        let personal = (
            derive::personal_secret(&from.secret)?,
            derive::personal_secret(&to.secret)?,
        );
        let carry = Carry {
            identity,
            statement: from.number,
            now,
        };
        // What the personal channel that is left lists, as this device
        // held it, is noted before the store drops it: a name that no
        // device comes to list in the new one is shown (§7.3, §8).
        crate::names::note_listed_before(conn, &from.secret, from.number, &counting, now)?;
        // From the personal channel, its own entry in each slot: what
        // another key wrote there is not looked at.
        let (carried, _) = carry.channel(
            conn,
            &personal.0,
            &personal.1,
            |key| *key == own,
            is_its_word_to_carry,
        )?;
        applied.carried += carried;

        for name in &names {
            let old = derive::own_secret(&from.secret, &name.name)?;
            let new = derive::own_secret(&to.secret, &name.name)?;
            // Each folder's records, which are kept by channel, go to the
            // name's new channel with each revision renumbered (§4.2). A
            // record in whose slot the store holds no version is dropped
            // first: nothing is carried there.
            let dropped = move_records(conn, &carry, &counting, &old, &new)?;
            applied
                .not_carried
                .extend(dropped.into_iter().map(|file| (name.name.clone(), file)));
            let (carried, no_version) =
                carry.channel(conn, &old, &new, |key| counting.counts(key), |_| true)?;
            applied.carried += carried;
            if no_version > 0 {
                applied.no_version.push(name.name.clone());
            }
        }
        // Nothing of messages is carried (decision 2026-10-09 §9.1): what
        // the store holds of the messages channel that is left goes, as
        // every old channel's does, and what was kept of each relay for it.
        let messages = derive::channel_id(&derive::messages_secret(&from.secret)?)?;
        entries::remove_channel(conn, &messages)?;
        kept_rows::forget_channel(conn, &messages)?;
    }
    // What the store has taken up to here, of this device's own in the
    // channel of a name, is what it carried: what it writes from now on
    // is not (§7.3).
    kept_rows::carried_to_here(conn)?;

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
    held_rows::keep_followed(conn, change.entry)?;
    // A head set aside goes where the change applied was made after it,
    // and stays otherwise (decision 2026-10-24 (removal), rule 1). A device
    // that came to follow this phrase now keeps none.
    match before {
        Some(before) => {
            for head in set_aside_heads(conn, identity, &before.following)? {
                if statement.has_on_chain(&head.statement.statement.link()?) {
                    held_rows::drop_set_aside(conn, head.place)?;
                }
            }
        }
        None => {
            held_rows::drop_all_set_aside(conn)?;
        }
    }
    note_time(conn, change.entry, statement)?;
    // Records are not carried: the statement's own list is what stands.
    held_rows::clear_additions(conn)?;
    // Nor are the holders of the change it leaves: it seals under that
    // secret no more (decision 2026-10-24 (removal), rule 3).
    let link = statement.link()?;
    held_rows::forget_holders_but(conn, link.number, &link.hash)?;
    // What other devices said a person read is kept only of the keys this
    // statement counts, so that a key added again later counts only what
    // it lists from then; and a statement ends every bound a person set,
    // this device's own and the others' (decision 2026-10-25, rules 1.2
    // and 3.7). Nothing of messages is carried (decision 2026-10-09 §9.1).
    let counted: Vec<[u8; 32]> = statement.devices.iter().map(|device| device.key).collect();
    cordelia_storage::messages::drop_person_marks_but(conn, &counted)
        .map_err(|e| PersonError::Storage(CordeliaError::Storage(e.to_string())))?;
    cordelia_storage::messages::drop_all_bounds(conn)
        .map_err(|e| PersonError::Storage(CordeliaError::Storage(e.to_string())))?;
    // A key that was shown as left out is shown no more once a statement
    // lists it, in either list. And the notices that a person cleared
    // were of the statement that is left: its records, and the words in
    // its personal channel.
    for shown in acts::left_out(conn)? {
        if statement.lists(&shown.key) || statement.removes(&shown.key) {
            acts::drop_left_out(conn, &shown.key)?;
        }
    }
    acts::forget_cleared(conn)?;
    for name in &names {
        let channel = derive::channel_id(&derive::own_secret(&to.secret, &name.name)?)?;
        held_rows::move_name(conn, &name.name, &channel)?;
    }
    // What it handed a key under the statement it leaves holds that
    // statement's secret: the store keeps none of it.
    drop_hand_overs(conn, |_| false)?;

    write_applied(conn, identity, statement, &to.secret, now)?;
    // What a name's folders had agreed in a slot that held no version is
    // noted, for `cordelia devices` to say which files (§4.2).
    crate::look::note_not_carried(conn, &applied.not_carried)?;
    // Whether this statement removes a key that the one before did not
    // is kept now, while both are at hand (§10.1): a status says that a
    // removal is not yet applied by every device only where it does. A
    // renewal removes nobody, and a device that comes to its first
    // statement saw nobody removed.
    let removes_a_key = before.is_some_and(|before| {
        let had = &before.statement.statement;
        statement.removed.iter().any(|key| !had.removes(key))
    });
    crate::look::note_removed_a_key(conn, removes_a_key)?;
    // The look of a recovery was of the statement that is left: under
    // this one the device carried what it holds, in this transaction.
    meta::remove(conn, meta::PERSON_LOOK_PENDING)?;
    // A name that a device lists in the generation it has come to, or
    // that it left 90 days ago, is noted no more.
    held_rows::forget_names_before(conn, Some(now))?;
    Ok(applied)
}

/// Move what the folders of this device had agreed in the channel whose
/// secret is `from` to the channel whose secret is `to` (decision
/// 2026-10-04 §4.2): each record of a file, and each record of an index
/// line, with every revision in them renumbered as a version's is at a
/// move ([`lifted`]). So a record means in the new channel what it meant
/// in the old, and the ordinary cycle goes on from where it was.
///
/// A record of a file in whose slot the store holds no version at all is
/// dropped first, and not moved: nothing is carried there, and a record
/// of a version that the new channel does not hold would have the file
/// taken for one that was deleted there. Returns the files whose record
/// was dropped, each once, in order.
///
/// It is called before the carry, which drops what the store holds of the
/// channel that is left.
fn move_records(
    conn: &Connection,
    carry: &Carry,
    counting: &Counting,
    from: &[u8; 32],
    to: &[u8; 32],
) -> Result<Vec<String>, PersonError> {
    let written = |secret: &[u8; 32]| -> Result<String, PersonError> {
        Ok(encode_channel_id(&derive::channel_id(secret)?)?)
    };
    let (old, new) = (written(from)?, written(to)?);
    let channel = derive::channel_id(from)?;
    let slot_key = derive::slot_key(from)?;
    let mut dropped: Vec<String> = Vec::new();
    for (folder, file) in sync_state::files(conn, &old)? {
        let held = entries::slot_entries(conn, &channel, &slot_id(&slot_key, &file))?;
        let read = version::current(&held, from, carry.statement, |key| counting.counts(key))?;
        if read.current.is_none() {
            sync_state::forget_file(conn, &folder, &old, &file)?;
            dropped.push(file);
        }
    }
    dropped.sort();
    dropped.dedup();
    sync_state::move_channel(conn, &old, &new, lifted)?;
    Ok(dropped)
}

/// Note each key that this device counted under the statement `leaving`
/// and that `statement`, which it now applies, has in neither of its
/// lists (decision 2026-10-04 §8). Such a device holds the secret before,
/// and may not know: it is shown as "not in the last change", by the
/// label it was known by, until a person clears it or a later statement
/// lists it.
///
/// The keys are those that counted when the statement is applied: the
/// devices of the statement that is left, and those added since by a
/// record that counted. This device's own key is none of them: a device
/// that is in neither list does not apply the statement at all.
fn note_left_out(
    conn: &Connection,
    identity: &NodeIdentity,
    leaving: &Statement,
    statement: &Statement,
    now: i64,
) -> Result<(), PersonError> {
    let own = identity.public_key();
    let kept = held_rows::additions(conn)?;
    let mut counted: Vec<([u8; 32], String)> = leaving
        .devices
        .iter()
        .map(|device| (device.key, device.label.clone()))
        .collect();
    for record in kept.iter().filter(|record| record.counted) {
        let label = SignedAddition::from_bytes(&record.record)?
            .addition
            .device
            .label;
        counted.push((record.key, label));
    }
    // What this device called each key that the statement removes is
    // kept: a statement lists removed keys bare, and a person names one
    // by its label where they bring in what it wrote (§7.3).
    crate::look::note_removed_labels(conn, statement, &counted)?;
    // Each is noted. One that the statement lists, in either list, is
    // shown no more by the time the statement is applied: that is asked
    // for every key that is noted, this statement's and an earlier
    // one's, where the device comes to the statement.
    for (key, label) in counted {
        if key == own {
            continue;
        }
        acts::note_left_out(conn, &key, &label, statement.number, now)?;
    }
    Ok(())
}

/// Drop from the store the hand-overs that this device made (decision
/// 2026-10-04 §3, §6). A hand-over holds the person secret of the
/// statement it hands over, and the store is not where a device keeps a
/// secret: it stays there for as long as a device could take it, and no
/// longer.
///
/// `stays` says, of the time a hand-over says it was made, whether it
/// stays. What the device keeps of one that goes is its revision, so that
/// the next it makes for that key is above it. Returns how many went.
pub(crate) fn drop_hand_overs(
    conn: &Connection,
    stays: impl Fn(i64) -> bool,
) -> Result<usize, PersonError> {
    let mut dropped = 0;
    for last in held_rows::hand_overs_held(conn)? {
        if stays(last.made_at) {
            continue;
        }
        entries::remove_channel(conn, &last.channel)?;
        held_rows::hand_over_gone(conn, &last.key)?;
        dropped += 1;
    }
    Ok(dropped)
}

/// A generation: a person secret, and the number of its statement.
struct Generation {
    number: u64,
    secret: [u8; 32],
}

/// The secret of the statement the device has applied, as its store has
/// it: the one that the statement commits to.
pub(crate) fn applied_secret(
    conn: &Connection,
    applied: &Statement,
) -> Result<[u8; 32], PersonError> {
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
    now: i64,
}

impl Carry<'_> {
    /// Carry one channel: each slot's current version, as the device's
    /// own store has it under the statement it is leaving, is sealed
    /// again as this device's own entry in the channel whose secret is
    /// `to`, where `carries` says so. Then everything the store holds of
    /// the channel it left is dropped (§7.5). Returns how many entries
    /// were carried, and how many slots held no version at all though
    /// they held an entry of a key that is read: a slot with entries of
    /// other keys alone holds nothing here, and is not counted.
    ///
    /// `counts` says whose entries are read. In a name's channel they are
    /// the keys that count under the statement. In the personal channel
    /// it is this device's key alone: the device carries its own entry in
    /// each slot, whatever another key wrote there and at whatever
    /// revision.
    ///
    /// An entry that lost a tie is not current, and is not carried. Nor
    /// is one that is no version.
    fn channel(
        &self,
        conn: &Connection,
        from: &[u8; 32],
        to: &[u8; 32],
        counts: impl Fn(&[u8; 32]) -> bool,
        carries: impl Fn(&Version) -> bool,
    ) -> Result<(usize, usize), PersonError> {
        let channel = derive::channel_id(from)?;
        let (mut carried, mut no_version) = (0, 0);
        for slot in entries::channel_slots(conn, &channel)? {
            let held = entries::slot_entries(conn, &channel, &slot)?;
            let read = version::current(&held, from, self.statement, &counts)?;
            let Some(version) = read.current else {
                if held.iter().any(|entry| counts(&entry.author)) {
                    no_version += 1;
                }
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
        // And with it what the device kept of each relay for it.
        kept_rows::forget_channel(conn, &channel)?;
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
pub(crate) fn carried_entry(
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

/// Whether an entry of this device's own in the personal channel is
/// carried: it is neither a record of an addition, nor a word that a
/// statement is applied, nor its carried word or that word's delete
/// (decision 2026-10-19 §4, rule 4). The next statement's own list is
/// what stands, and the device writes its own words under the next
/// statement.
fn is_its_word_to_carry(version: &Version) -> bool {
    !version.name.starts_with(PERSONAL_ADDED_PREFIX)
        && !version.name.starts_with(PERSONAL_APPLIED_PREFIX)
        && !version.name.starts_with(PERSONAL_REACHED_PREFIX)
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
///
/// Where the work does not come back at all, because it unwinds, what it
/// wrote is undone as it is where the work fails: no transaction is left
/// open on the connection, and no savepoint in the caller's.
pub(crate) fn in_one<T>(
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
    let mut begun = Begun {
        conn,
        undo,
        ended: false,
    };
    match work() {
        Ok(done) => {
            // Where the commit fails, what was begun is undone as it is
            // dropped.
            conn.execute_batch(commit).map_err(storage)?;
            begun.ended = true;
            Ok(done)
        }
        Err(e) => {
            begun.ended = true;
            conn.execute_batch(undo).map_err(storage)?;
            Err(e)
        }
    }
}

/// What [`in_one`] began on a connection. Dropped before it was ended, it
/// is undone: so it is where the work unwinds.
struct Begun<'a> {
    conn: &'a Connection,
    /// What undoes it.
    undo: &'static str,
    /// Whether it was committed, or undone already.
    ended: bool,
}

impl Drop for Begun<'_> {
    fn drop(&mut self) {
        if !self.ended {
            // Nothing can be done where this fails: the connection is the
            // caller's, and says so at its next use.
            let _ = self.conn.execute_batch(self.undo);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::several::{Kept, kept_entry};

    thread_local! {
        /// How many times this thread has worked out the order of keeping.
        pub(super) static ORDERS_WORKED_OUT: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
    }

    /// A device's word that it has applied a statement holds the
    /// statement's number, and, once it has sent what it carried, says so
    /// after it (decision 2026-10-04 §8). A text that is neither is no
    /// such word.
    #[test]
    fn test_a_word_that_a_statement_is_applied_says_its_number_and_whether_all_is_sent() {
        assert_eq!(applied_word(3, false), "3");
        assert_eq!(applied_word(3, true), "3 sent");
        assert_eq!(applied_word(256, true), "256 sent");
        for (word, says) in [
            ("3", Some((3, false))),
            ("3 sent", Some((3, true))),
            ("256 sent", Some((256, true))),
            ("0", Some((0, false))),
            ("", None),
            (" sent", None),
            ("sent", None),
            ("3 sent ", None),
            ("3  sent", None),
            ("3 sent sent", None),
            ("+3", None),
            ("3.0", None),
            ("three", None),
            ("99999999999999999999999", None),
        ] {
            assert_eq!(read_applied_word(word), says, "{word:?}");
        }
        // What is written is what is read.
        for (number, sent) in [(1, false), (1, true), (77, true)] {
            let word = applied_word(number, sent);
            assert_eq!(read_applied_word(&word), Some((number, sent)));
        }
    }
    use std::collections::{BTreeMap, BTreeSet};

    use cordelia_core::protocol::{
        CHANGE_ENTRY_BYTES, CHANGE_ENTRY_DEVICES_PART_BYTES, CHANGE_ENTRY_LINEAGE_BYTES,
        CHANGE_ENTRY_NAME, ITEM_SEAL_OVERHEAD_BYTES, KEPT_OUT_PER_ADDER, LABEL_CHANGE_DEVICES,
        LABEL_CHANGE_SECRET, LABEL_ENTRY_AUTHOR, LABEL_ENTRY_CHANNEL, LABEL_ENTRY_CONTENT,
        LABEL_STATEMENT, MAX_KNOWN_HOLDERS, MAX_KNOWN_REMOVED, MIN_ENTRY_CONTENT_BYTES,
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
        change_entry::entry_of(
            phrase,
            &sign(statement, phrase),
            &ForPhrase::first(secret),
            NOW as u64,
        )
        .unwrap()
        .check()
        .unwrap()
    }

    /// What a device follows that follows `phrase`.
    fn following(phrase: &Phrase) -> Following {
        Following {
            phrase_key: phrase.public_key().unwrap(),
            statement_key: *phrase.statement_key().unwrap(),
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
            "person_hand_overs",
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
        // Nor may it add, though a device of the statement signed for it.
        assert!(!counting.may_add(&key(163)));
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

    /// A key that has been counted goes on counting: no later record
    /// displaces the one that added it, or counts it again.
    #[test]
    fn test_no_later_record_displaces_a_key_that_counts() {
        let conn = device_at(0, 2);
        let [_, two, ..] = statements(&phrase());
        see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
        see_addition(&conn, &added(&two, 7, 8), NOW).unwrap();
        let before = who_counts(&conn).unwrap();
        assert!(before.counts(&key(8)) && !before.may_add(&key(8)));

        // A device that was added adds key 8 too, and a record for a key
        // that the statement lists adds nothing.
        see_addition(&conn, &added(&two, 1, 9), NOW).unwrap();
        let before = who_counts(&conn).unwrap();
        assert_eq!(
            see_addition(&conn, &added(&two, 9, 8), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        );
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 1), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        );
        let after = who_counts(&conn).unwrap();
        assert_eq!(after.keys(), before.keys());
        assert_eq!(after.devices(), 6);
        assert!(!after.may_add(&key(8)));
        assert!(after.may_add(&key(1)));

        // A record that was seen is one record, however often it is seen.
        let rows = held_rows::additions(&conn).unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 7), NOW + 9).unwrap(),
            AdditionSeen::SeenBefore
        );
        assert_eq!(held_rows::additions(&conn).unwrap(), rows);
    }

    /// Who may add does not turn on the order in which a device saw the
    /// records. Key 8 is added by device 7, which was added since, and by
    /// device 0, which the statement lists: it may add, whichever of the
    /// two records the device saw first.
    #[test]
    fn test_who_may_add_does_not_depend_on_the_order_records_were_seen() {
        let [_, two, ..] = statements(&phrase());
        let by_an_added = added(&two, 7, 8);
        let by_a_listed = added(&two, 0, 8);

        let mut answers = Vec::new();
        for order in [[&by_an_added, &by_a_listed], [&by_a_listed, &by_an_added]] {
            let conn = device_at(0, 2);
            see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
            assert_eq!(
                see_addition(&conn, order[0], NOW).unwrap(),
                AdditionSeen::Counted
            );
            assert_eq!(
                see_addition(&conn, order[1], NOW).unwrap(),
                AdditionSeen::NotCounted(NotCounted::CountsAlready)
            );
            let counting = who_counts(&conn).unwrap();
            assert!(counting.counts(&key(8)));
            assert!(counting.may_add(&key(8)));
            assert_eq!(counting.devices(), 5);
            assert_eq!(counting.keys(), [key(0), key(1), key(2), key(7), key(8)]);
            // What key 8 adds counts.
            assert_eq!(
                see_addition(&conn, &added(&two, 8, 9), NOW).unwrap(),
                AdditionSeen::Counted
            );
            answers.push(who_counts(&conn).unwrap());
        }
        assert_eq!(answers[0], answers[1]);

        // With the record of the added device alone, key 8 may not add:
        // before the other is seen, and where it never is.
        let conn = device_at(0, 2);
        see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
        see_addition(&conn, &by_an_added, NOW).unwrap();
        assert!(!who_counts(&conn).unwrap().may_add(&key(8)));

        // A record that a device of the statement signed lets no key add
        // that does not count: a removed key here, and one that found no
        // room where the sixty-fifth is tested.
        let [_, _, three, _] = statements(&phrase());
        let conn = device_at(0, 3);
        see_addition(&conn, &added(&three, 0, 2), NOW).unwrap();
        let counting = who_counts(&conn).unwrap();
        assert!(!counting.counts(&key(2)) && !counting.may_add(&key(2)));
    }

    /// The keys that count and the keys that may add, among devices 0 to
    /// 12, in order of their numbers.
    fn counting_of(conn: &Connection) -> (Vec<u16>, Vec<u16>) {
        let counting = who_counts(conn).unwrap();
        let of = |says: &dyn Fn(&[u8; 32]) -> bool| -> Vec<u16> {
            (0..=12).filter(|n| says(&key(*n))).collect()
        };
        (
            of(&|key| counting.counts(key)),
            of(&|key| counting.may_add(key)),
        )
    }

    /// The records in each order they can be seen in.
    fn in_every_order(records: &[SignedAddition]) -> Vec<Vec<SignedAddition>> {
        if records.len() <= 1 {
            return vec![records.to_vec()];
        }
        let mut orders = Vec::new();
        for first in 0..records.len() {
            let mut rest = records.to_vec();
            let one = rest.remove(first);
            for mut order in in_every_order(&rest) {
                order.insert(0, one.clone());
                orders.push(order);
            }
        }
        orders
    }

    /// The device sees `records` in that order. One whose signer does not
    /// count is not kept, and is seen again once every other has been:
    /// until a pass in which none of those is kept.
    fn see_until_none_is_kept(conn: &Connection, records: &[SignedAddition]) {
        let mut waiting = records.to_vec();
        loop {
            let before = waiting.len();
            waiting.retain(|record| match see_addition(conn, record, NOW) {
                Ok(_) => false,
                Err(PersonError::RecordByAKeyThatDoesNotCount) => true,
                Err(e) => panic!("{e}"),
            });
            if waiting.len() == before {
                return;
            }
        }
    }

    /// "8 adds 9" is seen while device 8 may not add yet: device 7, which
    /// was itself added, had added it. The record is kept as not counted.
    /// Once "0 adds 8" is seen, device 8 may add, and the record counts:
    /// as it does where "0 adds 8" was seen first.
    #[test]
    fn test_a_record_kept_as_not_counted_counts_once_its_signer_may_add() {
        let [_, two, ..] = statements(&phrase());

        // "8 adds 9" first.
        let conn = device_at(0, 2);
        see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
        see_addition(&conn, &added(&two, 7, 8), NOW).unwrap();
        assert_eq!(
            see_addition(&conn, &added(&two, 8, 9), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::MayNotAdd)
        );
        // And a second record that device 8 signed.
        assert_eq!(
            see_addition(&conn, &added(&two, 8, 11), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::MayNotAdd)
        );
        assert_eq!(counting_of(&conn), (vec![0, 1, 2, 7, 8], vec![0, 1, 2, 7]));
        let before = held_rows::additions(&conn).unwrap();

        // "0 adds 8" adds a key that counts already. It is what lets
        // device 8 add, and both records that device 8 signed count.
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 8), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        );
        let late = counting_of(&conn);
        assert_eq!(late, (vec![0, 1, 2, 7, 8, 9, 11], vec![0, 1, 2, 7, 8]));
        // Each record is where it was in the order it was seen, and the
        // two are kept as counted now.
        let after = held_rows::additions(&conn).unwrap();
        let said: Vec<([u8; 32], bool)> = after.iter().map(|one| (one.key, one.counted)).collect();
        assert_eq!(
            said,
            [
                (key(7), true),
                (key(8), true),
                (key(9), true),
                (key(11), true),
                (key(8), false)
            ]
        );
        assert_eq!(after[..4].len(), before.len());
        for (was, is) in before.iter().zip(&after) {
            assert_eq!((was.seen, &was.record), (is.seen, &is.record));
        }
        // A link that device 9 signed is read as one of a key that counts.
        assert!(
            who_counts(&conn)
                .unwrap()
                .signer_counts(&Link::signer_of(&key(9)))
        );

        // "0 adds 8" first: the same keys count, and the same may add.
        let conn = device_at(0, 2);
        see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
        see_addition(&conn, &added(&two, 0, 8), NOW).unwrap();
        see_addition(&conn, &added(&two, 7, 8), NOW).unwrap();
        for new in [9, 11] {
            assert_eq!(
                see_addition(&conn, &added(&two, 8, new), NOW).unwrap(),
                AdditionSeen::Counted
            );
        }
        assert_eq!(counting_of(&conn), late);

        // The control: without "0 adds 8", device 9 does not count, however
        // many other records are seen.
        let conn = device_at(0, 2);
        see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
        see_addition(&conn, &added(&two, 7, 8), NOW).unwrap();
        see_addition(&conn, &added(&two, 8, 9), NOW).unwrap();
        see_addition(&conn, &added(&two, 1, 10), NOW).unwrap();
        see_addition(&conn, &added(&two, 7, 12), NOW).unwrap();
        assert_eq!(
            counting_of(&conn),
            (vec![0, 1, 2, 7, 8, 10, 12], vec![0, 1, 2, 7, 10])
        );
    }

    /// Who counts, and who may add, is the same in whatever order a device
    /// sees the records, inside the bound of 64. A record whose signer
    /// does not count yet is not kept, and is seen again.
    #[test]
    fn test_who_counts_does_not_turn_on_the_order_records_were_seen() {
        let [_, two, ..] = statements(&phrase());
        let conn = device_at(0, 2);
        // What the device counts once it has seen the records in that
        // order, from having seen none.
        let seen_in = |order: &[SignedAddition]| {
            held_rows::clear_additions(&conn).unwrap();
            see_until_none_is_kept(&conn, order);
            (
                counting_of(&conn),
                held_rows::additions(&conn).unwrap().len(),
            )
        };

        // Device 8 is added by a device that was added, and by a device of
        // the statement: it may add, and device 9 counts. In each of the
        // 24 orders.
        let four = [
            added(&two, 0, 7),
            added(&two, 7, 8),
            added(&two, 8, 9),
            added(&two, 0, 8),
        ];
        let orders = in_every_order(&four);
        assert_eq!(orders.len(), 24);
        for order in &orders {
            assert_eq!(
                seen_in(order),
                ((vec![0, 1, 2, 7, 8, 9], vec![0, 1, 2, 7, 8]), 4)
            );
        }

        // Device 9 is the third of a chain, whichever record is seen
        // first: it counts, and may not add, so device 10 does not count.
        let mut five = four.to_vec();
        five.push(added(&two, 9, 10));
        for first in 0..five.len() {
            let mut order = five.clone();
            order.rotate_left(first);
            assert_eq!(
                seen_in(&order),
                ((vec![0, 1, 2, 7, 8, 9], vec![0, 1, 2, 7, 8]), 5),
                "{first}"
            );
            order.reverse();
            assert_eq!(
                seen_in(&order),
                ((vec![0, 1, 2, 7, 8, 9], vec![0, 1, 2, 7, 8]), 5),
                "{first}"
            );
        }

        // With a record by a device of the statement for device 9, it may
        // add, and device 10 counts.
        let mut six = five.clone();
        six.push(added(&two, 1, 9));
        for first in 0..six.len() {
            let mut order = six.clone();
            order.rotate_left(first);
            assert_eq!(
                seen_in(&order),
                ((vec![0, 1, 2, 7, 8, 9, 10], vec![0, 1, 2, 7, 8, 9]), 6),
                "{first}"
            );
        }
    }

    /// The record that device `adder` adds device `new` under `statement`,
    /// saying that it was made at `at`.
    fn added_at(statement: &Statement, adder: u16, new: u16, at: i64) -> SignedAddition {
        let new = listed(&[new]).remove(0);
        Addition::under(statement, new, key(adder), at as u64)
            .unwrap()
            .sign(&device(adder))
            .unwrap()
    }

    /// Whether the device keeps `record`.
    fn keeps(conn: &Connection, record: &SignedAddition) -> bool {
        let bytes = record.to_bytes().unwrap();
        let kept = held_rows::additions(conn).unwrap();
        kept.iter().any(|one| one.record == bytes)
    }

    /// How many records the device keeps as not counted.
    fn not_counted(conn: &Connection) -> usize {
        let kept = held_rows::additions(conn).unwrap();
        kept.iter().filter(|one| !one.counted).count()
    }

    /// The records that the device keeps as not counted, as a set.
    fn kept_not_counted(conn: &Connection) -> BTreeSet<Vec<u8>> {
        let kept = held_rows::additions(conn).unwrap();
        let rows = kept.into_iter().filter(|one| !one.counted);
        rows.map(|one| one.record).collect()
    }

    /// A device keeps at most 256 records that are not counted. Beyond
    /// that the last in the order of keeping goes when a new one is kept
    /// (decision 2026-10-17 §2.2), and no record that counts goes with
    /// it. One that went is as one never seen: it is judged when it is
    /// given again.
    #[test]
    fn test_the_records_kept_as_not_counted_have_a_bound() {
        let [_, two, ..] = statements(&phrase());
        let conn = device_at(0, 2);
        see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
        see_addition(&conn, &added(&two, 7, 8), NOW).unwrap();
        // The oldest record that does not count: "8 adds 9".
        let oldest = added(&two, 8, 9);
        assert_eq!(
            see_addition(&conn, &oldest, NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::MayNotAdd)
        );
        // And 254 more, as a device that counts could sign them: records
        // for a key that the statement lists, each saying a later time.
        let again: Vec<SignedAddition> = (1..=254).map(|n| added_at(&two, 0, 1, NOW + n)).collect();
        for record in &again {
            assert_eq!(
                see_addition(&conn, record, NOW).unwrap(),
                AdditionSeen::NotCounted(NotCounted::CountsAlready)
            );
        }
        // And a row whose bytes are no record, written past the rule: it
        // says no time, and is the last of all. The device keeps 256 that
        // are not counted, which is the bound.
        held_rows::keep_addition(&conn, b"no record", &key(1), &key(0), false, NOW).unwrap();
        let no_record = || {
            let kept = held_rows::additions(&conn).unwrap();
            kept.iter().any(|one| one.record == b"no record")
        };
        assert_eq!(not_counted(&conn), 256);
        assert!(keeps(&conn, &oldest) && no_record());

        // One more that does not count: the row that is no record goes,
        // and the new one is kept. The two that count stay.
        let newest = added(&two, 8, 11);
        assert_eq!(
            see_addition(&conn, &newest, NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::MayNotAdd)
        );
        assert_eq!(not_counted(&conn), 256);
        assert!(!no_record() && keeps(&conn, &oldest) && keeps(&conn, &newest));
        assert_eq!(counting_of(&conn), (vec![0, 1, 2, 7, 8], vec![0, 1, 2, 7]));
        // And one more: the record that says the latest time goes.
        let one_more = added_at(&two, 0, 1, NOW + 255);
        see_addition(&conn, &one_more, NOW).unwrap();
        assert!(!keeps(&conn, &one_more) && again.iter().all(|one| keeps(&conn, one)));
        assert_eq!(not_counted(&conn), 256);

        // "0 adds 8" lets device 8 add. The two records that device 8
        // signed come to count, which makes room for the one that was
        // seen, and nothing goes. The record that went is not there to be
        // judged.
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 8), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        );
        assert_eq!(not_counted(&conn), 255);
        assert_eq!(
            counting_of(&conn),
            (vec![0, 1, 2, 7, 8, 9, 11], vec![0, 1, 2, 7, 8])
        );
        // Given again, it is seen as a record that was never seen.
        assert_eq!(
            see_addition(&conn, &one_more, NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        );
        assert!(keeps(&conn, &one_more));
        assert_eq!(not_counted(&conn), 256);
    }

    /// Within the bound of 256, a reader does not work out the order of
    /// keeping: nothing goes. It is worked out after each record taken
    /// beyond the bound, once.
    #[test]
    fn test_within_the_bound_the_order_of_keeping_is_not_worked_out() {
        let [_, two, ..] = statements(&phrase());
        let conn = device_at(0, 2);
        let orders = || ORDERS_WORKED_OUT.with(|orders| orders.get());
        let before = orders();
        for n in 1..=256 {
            see_addition(&conn, &added_at(&two, 0, 1, NOW + n), NOW).unwrap();
        }
        assert_eq!(not_counted(&conn), 256);
        assert_eq!(orders(), before);
        for n in 257..=260 {
            see_addition(&conn, &added_at(&two, 0, 1, NOW + n), NOW).unwrap();
        }
        assert_eq!(not_counted(&conn), 256);
        assert_eq!(orders(), before + 4);
    }

    /// A row is ordered by the time its bytes say, and its record is not
    /// checked again: it was verified when it was kept. A row written past
    /// the rule, whose bytes the record would be refused for, is ordered
    /// by its time all the same.
    #[test]
    fn test_a_row_is_ordered_by_its_time_without_its_record_checked_again() {
        let [_, two, ..] = statements(&phrase());
        let conn = device_at(0, 2);
        // A record of the rest whose form adds its own adder: no record
        // reads so, and its time is an early one.
        let mut bytes = added_at(&two, 0, 1, NOW).to_bytes().unwrap();
        bytes[..32].copy_from_slice(&key(0));
        assert!(SignedAddition::from_bytes(&bytes).is_err());
        assert_eq!(SignedAddition::time_of(&bytes), Some(NOW as u64));
        held_rows::keep_addition(&conn, &bytes, &key(0), &key(0), false, NOW).unwrap();
        let early = || {
            let kept = held_rows::additions(&conn).unwrap();
            kept.iter().any(|one| one.record == bytes)
        };
        // 256 records of the rest that say later times: the latest goes,
        // and the early row stays.
        let later: Vec<SignedAddition> = (1..=256).map(|n| added_at(&two, 0, 1, NOW + n)).collect();
        for record in &later {
            see_addition(&conn, record, NOW).unwrap();
        }
        assert_eq!(not_counted(&conn), 256);
        assert!(early());
        assert!(!keeps(&conn, &later[255]) && keeps(&conn, &later[254]));
    }

    /// The order of keeping (decision 2026-10-17 §2.2), seen from what
    /// goes: every other record first, the latest by its time; then a
    /// record whose adder may not add yet; then one whose key the 64 kept
    /// out, the last of an adder's keys before another adder's first; and
    /// never the one that lets a key add, which is the oldest by its time
    /// of those that a device of the statement signed for the key.
    #[test]
    fn test_the_records_that_do_not_count_go_from_the_end_of_the_order_of_keeping() {
        let [_, _, three, _] = statements(&phrase());
        // Statement 3 lists devices 0 and 1, and removes device 2.
        let conn = device_at(0, 3);
        let seen = |record: &SignedAddition| see_addition(&conn, record, NOW).unwrap();
        let why = |not: NotCounted| AdditionSeen::NotCounted(not);
        // Device 0 adds 7, which adds 8, and 60 more: 64 count, and 8 may
        // not add.
        for record in [added(&three, 0, 7), added(&three, 7, 8)] {
            assert_eq!(seen(&record), AdditionSeen::Counted);
        }
        for n in 100..160 {
            assert_eq!(seen(&added(&three, 0, n)), AdditionSeen::Counted, "{n}");
        }
        assert_eq!(who_counts(&conn).unwrap().devices(), 64);

        // Device 1 signs a record for 7 first, and device 0 one that
        // says an older time: device 0's is the one that lets 7 add.
        let by_1_for_7 = added_at(&three, 1, 7, NOW + 10);
        let lets_7_add = added_at(&three, 0, 7, NOW + 4);
        assert_eq!(seen(&by_1_for_7), why(NotCounted::CountsAlready));
        assert_eq!(seen(&lets_7_add), why(NotCounted::CountsAlready));
        // Two whose key the 64 kept out, one by a device of the statement
        // and one by a key that it added.
        let by_1 = added_at(&three, 1, 500, NOW + 5);
        let by_100 = added_at(&three, 100, 501, NOW);
        assert_eq!(seen(&by_1), why(NotCounted::NoRoom));
        assert_eq!(seen(&by_100), why(NotCounted::NoRoom));
        // One whose adder may not add yet: it says a later time than any
        // of the rest, and goes after all of them.
        let by_8 = added_at(&three, 8, 502, NOW + 30);
        assert_eq!(seen(&by_8), why(NotCounted::MayNotAdd));
        // And the rest: a second record of device 1's for 500, one for
        // the removed key, one for a key that the statement lists, and
        // one for 8 by a key that was added since.
        let by_1_again = added_at(&three, 1, 500, NOW + 6);
        let for_the_removed = added_at(&three, 0, 2, NOW + 3);
        let for_a_listed = added_at(&three, 0, 1, NOW + 1);
        let by_100_for_8 = added_at(&three, 100, 8, NOW + 2);
        assert_eq!(seen(&by_1_again), why(NotCounted::NoRoom));
        assert_eq!(seen(&for_the_removed), why(NotCounted::Removed));
        assert_eq!(seen(&for_a_listed), why(NotCounted::CountsAlready));
        assert_eq!(seen(&by_100_for_8), why(NotCounted::CountsAlready));
        // And a row of a record whose adder does not count, written past
        // the rule: it is among the rest, and says the latest time.
        let by_a_stranger = added_at(&three, 300, 503, NOW + 20);
        let bytes = by_a_stranger.to_bytes().unwrap();
        held_rows::keep_addition(&conn, &bytes, &key(503), &key(300), false, NOW).unwrap();

        // Device 1 fills the bound with records whose keys the 64 kept
        // out, each saying an older time than its record for 500: they
        // are its first keys.
        let fill = 256 - not_counted(&conn);
        assert_eq!(fill, 246);
        for n in 0..fill {
            let record = added_at(&three, 1, 1000 + n as u16, NOW - 2000 + n as i64);
            assert_eq!(seen(&record), why(NotCounted::NoRoom), "{n}");
        }
        assert_eq!(not_counted(&conn), 256);

        // Each record that device 1 signs next is one more than the
        // device keeps, and the last in the order goes, in this order.
        let goes = [
            &by_a_stranger,
            &by_1_for_7,
            &by_1_again,
            &for_the_removed,
            &by_100_for_8,
            &for_a_listed,
            &by_8,
            &by_1,
        ];
        for (turn, record) in goes.iter().enumerate() {
            assert!(keeps(&conn, record), "{turn}");
            let pushes = added_at(&three, 1, 3000 + turn as u16, NOW - 3000);
            assert_eq!(seen(&pushes), why(NotCounted::NoRoom), "{turn}");
            assert!(!keeps(&conn, record), "{turn}");
            // Those whose turn has not come are there still.
            assert!(
                goes[turn + 1..].iter().all(|later| keeps(&conn, later)),
                "{turn}"
            );
            assert!(keeps(&conn, &lets_7_add) && keeps(&conn, &by_100), "{turn}");
            assert_eq!(not_counted(&conn), 256, "{turn}");
        }
        let counting = who_counts(&conn).unwrap();
        assert!(counting.may_add(&key(7)) && !counting.may_add(&key(8)));
    }

    /// Records whose adder counts and may not add yet are dealt to their
    /// adders in turn, as those whose key the 64 kept out are (decision
    /// 2026-10-17 §2.2): a flood by one such adder takes from another none
    /// of its first keys, whether they were seen before it or after it.
    #[test]
    fn test_records_whose_adder_may_not_add_yet_are_dealt_to_their_adders_in_turn() {
        let [_, two, ..] = statements(&phrase());
        // Device 0 adds 7, which adds 8 and 9: neither may add.
        let of_8: Vec<SignedAddition> = (500..503).map(|n| added(&two, 8, n)).collect();
        let flood: Vec<SignedAddition> = (0..300)
            .map(|n| added_at(&two, 9, 1000 + n as u16, NOW + n))
            .collect();
        for of_8_first in [true, false] {
            let conn = device_at(0, 2);
            for record in [added(&two, 0, 7), added(&two, 7, 8), added(&two, 7, 9)] {
                see_addition(&conn, &record, NOW).unwrap();
            }
            let mut order: Vec<&SignedAddition> = flood.iter().collect();
            if of_8_first {
                order.splice(0..0, of_8.iter());
            } else {
                order.extend(of_8.iter());
            }
            for record in order {
                assert_eq!(
                    see_addition(&conn, record, NOW).unwrap(),
                    AdditionSeen::NotCounted(NotCounted::MayNotAdd)
                );
            }
            assert_eq!(not_counted(&conn), 256);
            assert!(of_8.iter().all(|one| keeps(&conn, one)), "{of_8_first}");
            for (n, record) in flood.iter().enumerate() {
                assert_eq!(keeps(&conn, record), n < 253, "{of_8_first} {n}");
            }
        }
    }

    /// Within a turn the devices of the statement come first, in its
    /// order, and then the other adders by key (decision 2026-10-17
    /// §2.2): where the last turn is cut, those are the ones that have it.
    #[test]
    fn test_within_a_turn_the_devices_of_the_statement_come_first_in_its_order() {
        let [_, two, ..] = statements(&phrase());
        // Statement 2 lists 0, 1 and 2. Device 0 adds 100 to 160: 64
        // count.
        let conn = device_at(0, 2);
        for n in 100..161 {
            see_addition(&conn, &added(&two, 0, n), NOW).unwrap();
        }
        // Two devices of the statement, and two keys that device 0 added
        // in order of key, each sign 100 records whose keys the 64 keep
        // out.
        let mut others = [100u16, 101];
        others.sort_by_key(|n| key(*n));
        let adders = [1u16, 2, others[0], others[1]];
        let of = |i: usize, j: usize| added_at(&two, adders[i], 1000 + (100 * i + j) as u16, NOW);
        for i in 0..4 {
            for j in 0..100 {
                see_addition(&conn, &of(i, j), NOW).unwrap();
            }
        }
        // How many of each adder's records are kept.
        let kept = || -> Vec<usize> {
            (0..4)
                .map(|i| (0..100).filter(|j| keeps(&conn, &of(i, *j))).count())
                .collect()
        };
        assert_eq!(not_counted(&conn), 256);
        assert_eq!(kept(), [64, 64, 64, 64]);
        // A record that lets a key add takes one place: the last turn is
        // cut, and the key that sorts last loses it.
        let lets_add = |n: u16| added_at(&two, 1, n, NOW + 1);
        see_addition(&conn, &lets_add(100), NOW).unwrap();
        assert_eq!(kept(), [64, 64, 64, 63]);
        // Two more: only the first device of the statement keeps it.
        see_addition(&conn, &lets_add(101), NOW).unwrap();
        see_addition(&conn, &lets_add(102), NOW).unwrap();
        assert_eq!(kept(), [64, 63, 63, 63]);
        assert_eq!(not_counted(&conn), 256);
    }

    /// Of the rest, two that say one time go by key, the higher first,
    /// and two of one key by adder (decision 2026-10-17 §2.2): whichever
    /// a reader saw first.
    #[test]
    fn test_of_the_rest_two_that_say_one_time_go_by_key_and_then_adder() {
        let [_, two, ..] = statements(&phrase());
        // Which of `pair` a reader keeps once the bound is passed by it,
        // where 255 records of the rest say earlier times.
        let kept_of = |pair: [&SignedAddition; 2]| {
            let conn = device_at(0, 2);
            for n in 1..=255 {
                see_addition(&conn, &added_at(&two, 0, 1, NOW + n), NOW).unwrap();
            }
            for record in pair {
                assert_eq!(
                    see_addition(&conn, record, NOW).unwrap(),
                    AdditionSeen::NotCounted(NotCounted::CountsAlready)
                );
            }
            assert_eq!(not_counted(&conn), 256);
            (keeps(&conn, pair[0]), keeps(&conn, pair[1]))
        };
        let later = NOW + 1000;
        // Two keys of the statement, by one adder: the higher key goes.
        let (low, high) = if key(0) < key(2) { (0, 2) } else { (2, 0) };
        let (of_low, of_high) = (
            added_at(&two, 1, low, later),
            added_at(&two, 1, high, later),
        );
        assert_eq!(kept_of([&of_low, &of_high]), (true, false));
        assert_eq!(kept_of([&of_high, &of_low]), (false, true));
        // One key, by two adders: the higher adder's goes.
        let (by_low, by_high) = (
            added_at(&two, low, 1, later),
            added_at(&two, high, 1, later),
        );
        assert_eq!(kept_of([&by_low, &by_high]), (true, false));
        assert_eq!(kept_of([&by_high, &by_low]), (false, true));
    }

    /// A flood of records by one device of the statement takes from
    /// another adder none of its first three keys that the 64 kept out
    /// (decision 2026-10-17 §1, property 1), whether they were seen
    /// before the flood or after it.
    #[test]
    fn test_a_flood_of_records_keeps_each_adders_first_three_kept_out() {
        let [_, two, ..] = statements(&phrase());
        // Device 0 adds keys until 64 count.
        let filled = || {
            let conn = device_at(0, 2);
            for n in 100..161 {
                see_addition(&conn, &added(&two, 0, n), NOW).unwrap();
            }
            assert_eq!(who_counts(&conn).unwrap().devices(), 64);
            conn
        };
        // Device 1 adds three keys, which the 64 keep out, and device 0
        // signs 300 more records, of 300 keys.
        let of_device_1: Vec<SignedAddition> = (500..500 + KEPT_OUT_PER_ADDER as u16)
            .map(|n| added(&two, 1, n))
            .collect();
        let flood: Vec<SignedAddition> = (0..300)
            .map(|n| added_at(&two, 0, 1000 + n as u16, NOW + n))
            .collect();
        let mut kept = Vec::new();
        for of_device_1_first in [true, false] {
            let conn = filled();
            let mut order: Vec<&SignedAddition> = flood.iter().collect();
            if of_device_1_first {
                order.splice(0..0, of_device_1.iter());
            } else {
                order.extend(of_device_1.iter());
            }
            for record in order {
                assert_eq!(
                    see_addition(&conn, record, NOW).unwrap(),
                    AdditionSeen::NotCounted(NotCounted::NoRoom)
                );
            }
            assert_eq!(not_counted(&conn), 256);
            // All three of device 1's are kept, and device 0 keeps its
            // first 253 by the time each says.
            assert!(of_device_1.iter().all(|one| keeps(&conn, one)));
            for (n, record) in flood.iter().enumerate() {
                assert_eq!(keeps(&conn, record), n < 253, "{n}");
            }
            kept.push(kept_not_counted(&conn));
        }
        assert_eq!(kept[0], kept[1]);
    }

    /// Statement 1, which lists device 0 alone, and the 64 adders that
    /// may add there: device 0, and 63 keys that it added, 100 to 162.
    /// Device 0 signs a second record for each of the 63, which is the
    /// one that lets it add: 63 records that the device never drops. So
    /// 193 places are left for keys that the 64 kept out.
    fn at_the_floor() -> (Connection, Statement, Vec<u16>) {
        let [one, ..] = statements(&phrase());
        let conn = device_at(0, 1);
        for n in 100..163 {
            see_addition(&conn, &added(&one, 0, n), NOW).unwrap();
            assert_eq!(
                see_addition(&conn, &added_at(&one, 0, n, NOW + 1), NOW).unwrap(),
                AdditionSeen::NotCounted(NotCounted::CountsAlready)
            );
        }
        let counting = who_counts(&conn).unwrap();
        assert_eq!(counting.devices(), 64);
        let adders: Vec<u16> = std::iter::once(0).chain(100..163).collect();
        assert!(adders.iter().all(|n| counting.may_add(&key(*n))));
        assert_eq!(adders.len(), MAX_COUNTED_DEVICES);
        (conn, one, adders)
    }

    /// At every bound together: 63 records that let a key add, and 64
    /// adders that may add, each of which signs five records that the 64
    /// keep out. Each adder keeps its first three by the time each says
    /// (`KEPT_OUT_PER_ADDER`), and device 0, the first of the statement,
    /// the one place left over. In two orders of seeing, the same.
    #[test]
    fn test_at_every_bound_each_adder_that_may_add_keeps_its_first_three_kept_out() {
        assert_eq!(MAX_NOT_COUNTED_RECORDS - (MAX_COUNTED_DEVICES - 1), 193);
        let mut kept = Vec::new();
        for backwards in [false, true] {
            let (conn, one, adders) = at_the_floor();
            // Adder `i`'s record `j` says the time NOW + 10 + 4 - j: its
            // records are signed newest first.
            let record = |i: usize, j: usize| {
                let new = 1000 + (5 * i + j) as u16;
                added_at(&one, adders[i], new, NOW + 14 - j as i64)
            };
            let mut all: Vec<(usize, usize)> = (0..adders.len())
                .flat_map(|i| (0..5).map(move |j| (i, j)))
                .collect();
            if backwards {
                all.reverse();
            }
            for (i, j) in all {
                assert_eq!(
                    see_addition(&conn, &record(i, j), NOW).unwrap(),
                    AdditionSeen::NotCounted(NotCounted::NoRoom)
                );
            }
            assert_eq!(not_counted(&conn), 256);
            for i in 0..adders.len() {
                // Its oldest are its last two: j of 4, 3 and 2.
                for j in 0..5 {
                    let first = 4 - j < KEPT_OUT_PER_ADDER;
                    let left_over = i == 0 && j == 1;
                    assert_eq!(keeps(&conn, &record(i, j)), first || left_over, "{i} {j}");
                }
            }
            // The records that let a key add are all kept.
            assert!((100..163).all(|n| keeps(&conn, &added_at(&one, 0, n, NOW + 1))));
            kept.push(kept_not_counted(&conn));
        }
        assert_eq!(kept[0], kept[1]);
    }

    /// An adder has one place for each key (decision 2026-10-17 §2.2):
    /// where it signs two records for one key, the second is among the
    /// rest, and does not take the place of its third key.
    #[test]
    fn test_an_adder_has_one_place_for_each_key() {
        let (conn, one, adders) = at_the_floor();
        // Key 101 signs two records for one key, and one each for two
        // more, in that order of time.
        let of_101 = [
            added_at(&one, 101, 500, NOW + 10),
            added_at(&one, 101, 500, NOW + 11),
            added_at(&one, 101, 501, NOW + 12),
            added_at(&one, 101, 502, NOW + 13),
        ];
        for record in &of_101 {
            see_addition(&conn, record, NOW).unwrap();
        }
        // Every other adder floods, with records saying older times.
        for (i, adder) in adders.iter().enumerate().filter(|(_, n)| **n != 101) {
            for j in 0..5 {
                let record = added_at(&one, *adder, 2000 + (5 * i + j) as u16, NOW);
                see_addition(&conn, &record, NOW).unwrap();
            }
        }
        assert_eq!(not_counted(&conn), 256);
        // Key 101 keeps a record for each of its three keys, and not the
        // second for the first.
        let [first, second, third, fourth] = &of_101;
        assert!(keeps(&conn, first) && keeps(&conn, third) && keeps(&conn, fourth));
        assert!(!keeps(&conn, second));
    }

    /// The records that a reader keeps do not turn on the order in which
    /// it saw them (decision 2026-10-17 §1, property 2). Two readers are
    /// given, in one order, the records that make 64 count, and then 300
    /// more of four adders, in two orders: both keep the same 256.
    #[test]
    fn test_the_records_kept_do_not_turn_on_the_order_they_were_seen() {
        let [_, two, ..] = statements(&phrase());
        // Statement 2 lists 0, 1 and 2. Device 0 adds 100 to 159, and 100
        // adds 200: 64 count, and 200 may not add.
        let filled = || {
            let conn = device_at(0, 2);
            for n in 100..160 {
                see_addition(&conn, &added(&two, 0, n), NOW).unwrap();
            }
            see_addition(&conn, &added(&two, 100, 200), NOW).unwrap();
            assert_eq!(who_counts(&conn).unwrap().devices(), 64);
            conn
        };
        // Four adders: two of the statement, one that it added, and one
        // that may not add. Each signs 75 records, for keys that the 64
        // keep out, for keys that count already, and twice for one key,
        // each saying a time that is not the order of signing, and three
        // of them each time.
        let adders = [0u16, 1, 100, 200];
        let records: Vec<SignedAddition> = (0..300i64)
            .map(|n| {
                let adder = adders[n as usize % 4];
                let at = NOW + (n * 7919) % 300 / 3;
                let new = match n % 5 {
                    0 => 1 + (n % 2) as u16,
                    1 => 600 + (n % 3) as u16,
                    _ => 1000 + n as u16,
                };
                added_at(&two, adder, new, at)
            })
            .collect();
        let mut kept = Vec::new();
        for backwards in [false, true] {
            let conn = filled();
            let mut order = records.clone();
            if backwards {
                order.reverse();
            }
            for record in &order {
                see_addition(&conn, record, NOW).unwrap();
            }
            assert_eq!(not_counted(&conn), 256);
            kept.push(kept_not_counted(&conn));
        }
        assert_eq!(kept[0], kept[1]);
    }

    /// The record that lets a key add does not turn on the order in which
    /// a reader saw the records for that key (decision 2026-10-17 §2.2):
    /// of those that devices of the statement signed, the oldest by the
    /// time it says, and then by its bytes, is kept first, and the others
    /// are among the rest.
    #[test]
    fn test_the_record_that_lets_a_key_add_does_not_turn_on_the_order_seen() {
        let [_, two, ..] = statements(&phrase());
        // Key 8 counts by a record of device 7, which was added since:
        // devices 0 and 1 of the statement each sign a record for it.
        let readers = |of_8: [&SignedAddition; 2]| {
            let mut kept = Vec::new();
            for order in [[of_8[0], of_8[1]], [of_8[1], of_8[0]]] {
                let conn = device_at(0, 2);
                see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
                see_addition(&conn, &added(&two, 7, 8), NOW).unwrap();
                for n in 100..159 {
                    see_addition(&conn, &added(&two, 0, n), NOW).unwrap();
                }
                for record in order {
                    assert_eq!(
                        see_addition(&conn, record, NOW).unwrap(),
                        AdditionSeen::NotCounted(NotCounted::CountsAlready)
                    );
                }
                // A flood of records whose keys the 64 keep out: one of
                // the two goes.
                for n in 0..300 {
                    let record = added_at(&two, 2, 1000 + n, NOW);
                    see_addition(&conn, &record, NOW).unwrap();
                }
                assert_eq!(not_counted(&conn), 256);
                assert!(who_counts(&conn).unwrap().may_add(&key(8)));
                kept.push((keeps(&conn, of_8[0]), keeps(&conn, of_8[1])));
            }
            kept
        };
        // The older by its time is kept, whichever was seen first.
        let older = added_at(&two, 1, 8, NOW + 2);
        let newer = added_at(&two, 0, 8, NOW + 5);
        assert_eq!(readers([&older, &newer]), [(true, false), (true, false)]);
        // Of two that say one time, the one whose bytes are the lower.
        let (one, other) = (added_at(&two, 0, 8, NOW), added_at(&two, 1, 8, NOW));
        let (lower, higher) = if one.to_bytes().unwrap() < other.to_bytes().unwrap() {
            (one, other)
        } else {
            (other, one)
        };
        assert_eq!(readers([&lower, &higher]), [(true, false), (true, false)]);
    }

    /// Who counts does not turn on which records beyond the bound a
    /// reader kept (decision 2026-10-17 §2.7). One reader keeps by the
    /// order of keeping, and one as a reader of the version before did,
    /// the oldest it saw going first. A record by a device of the
    /// statement then lets a key add, and each reads its channels again:
    /// both count the same keys.
    #[test]
    fn test_who_counts_does_not_turn_on_which_records_beyond_the_bound_were_kept() {
        let [_, two, ..] = statements(&phrase());
        // Device 0 adds 7, which adds 8: 8 may not add. "8 adds 9" is the
        // oldest record that does not count, and 256 records for a key
        // that the statement lists come after it: one more than a reader
        // keeps.
        let before = [added(&two, 0, 7), added(&two, 7, 8)];
        let of_8 = added(&two, 8, 9);
        let flood: Vec<SignedAddition> = (1..=256).map(|n| added_at(&two, 0, 1, NOW + n)).collect();
        let mut all: Vec<SignedAddition> = before.to_vec();
        all.push(of_8.clone());
        all.extend(flood.iter().cloned());

        let by_the_order = device_at(0, 2);
        let oldest_first = device_at(0, 2);
        for record in &all {
            see_addition(&by_the_order, record, NOW).unwrap();
            see_addition(&oldest_first, record, NOW).unwrap();
        }
        // The order of keeping keeps "8 adds 9", and lets the latest of
        // the flood go.
        let latest = flood.last().unwrap();
        assert!(keeps(&by_the_order, &of_8) && !keeps(&by_the_order, latest));
        // The other reader kept the flood, and let "8 adds 9" go.
        let rows = held_rows::additions(&oldest_first).unwrap();
        let row = rows
            .iter()
            .find(|one| one.record == of_8.to_bytes().unwrap());
        held_rows::drop_not_counted(&oldest_first, row.unwrap().seen).unwrap();
        let bytes = latest.to_bytes().unwrap();
        held_rows::keep_addition(&oldest_first, &bytes, &key(1), &key(0), false, NOW).unwrap();
        assert!(!keeps(&oldest_first, &of_8) && keeps(&oldest_first, latest));
        assert_eq!(not_counted(&oldest_first), 256);

        // Device 1 adds 8: 8 may add. Each reads its channels again.
        let lets_8_add = added(&two, 1, 8);
        for conn in [&by_the_order, &oldest_first] {
            assert_eq!(
                see_addition(conn, &lets_8_add, NOW).unwrap(),
                AdditionSeen::NotCounted(NotCounted::CountsAlready)
            );
            see_until_none_is_kept(conn, &all);
        }
        let counted = counting_of(&by_the_order);
        assert_eq!(counted, (vec![0, 1, 2, 7, 8, 9], vec![0, 1, 2, 7, 8]));
        assert_eq!(counting_of(&oldest_first), counted);
    }

    /// A key that comes to add after a flood (decision 2026-10-17 §12):
    /// while it may not add, its records are kept after those whose key
    /// the 64 kept out, and a flood of those lets them go. Once a record
    /// by a device of the statement lets it add, and the reader reads its
    /// channels again, they are among those the 64 kept out, and its
    /// first three are kept.
    #[test]
    fn test_a_key_whose_adder_comes_to_add_after_a_flood_keeps_its_first_three() {
        let [_, two, ..] = statements(&phrase());
        let conn = device_at(0, 2);
        // Device 0 adds 7, which adds 8, and 59 more: 64 count, and 8 may
        // not add.
        let mut all = vec![added(&two, 0, 7), added(&two, 7, 8)];
        all.extend((100..159).map(|n| added(&two, 0, n)));
        // Key 8 adds three keys, and device 1 floods.
        let of_8: Vec<SignedAddition> = (500..503).map(|n| added(&two, 8, n)).collect();
        all.extend(of_8.iter().cloned());
        all.extend((0..300).map(|n| added_at(&two, 1, 1000 + n, NOW)));
        for record in &all {
            see_addition(&conn, record, NOW).unwrap();
        }
        assert_eq!(who_counts(&conn).unwrap().devices(), 64);
        assert!(of_8.iter().all(|one| !keeps(&conn, one)));

        // Device 0 adds 8 too: it may add. The reader reads its channels
        // again, and keeps each of the three.
        let lets_8_add = added(&two, 0, 8);
        see_addition(&conn, &lets_8_add, NOW).unwrap();
        assert!(who_counts(&conn).unwrap().may_add(&key(8)));
        see_until_none_is_kept(&conn, &all);
        assert!(of_8.iter().all(|one| keeps(&conn, one)));
        assert!(keeps(&conn, &lets_8_add));
        assert_eq!(not_counted(&conn), 256);
        for record in &of_8 {
            assert_eq!(
                who_counts(&conn)
                    .unwrap()
                    .why_not(&record.addition.device.key, &key(8)),
                Some(NotCounted::NoRoom)
            );
        }
    }

    /// The bound of 64 stands where a record is judged again: one that
    /// would count, and finds the device counting 64 already, stays not
    /// counted. And no key that counted is displaced by it.
    #[test]
    fn test_a_record_judged_again_finds_no_room_beyond_the_bound() {
        let [_, two, ..] = statements(&phrase());
        let conn = device_at(0, 2);
        see_addition(&conn, &added(&two, 0, 7), NOW).unwrap();
        see_addition(&conn, &added(&two, 7, 8), NOW).unwrap();
        assert_eq!(
            see_addition(&conn, &added(&two, 8, 9), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::MayNotAdd)
        );
        // Three of the statement and two added: 58 more make 63, and the
        // record that is judged again takes the last place.
        for n in 100..158 {
            assert_eq!(
                see_addition(&conn, &added(&two, 1, n), NOW).unwrap(),
                AdditionSeen::Counted,
                "{n}"
            );
        }
        assert_eq!(who_counts(&conn).unwrap().devices(), 63);

        // Device 2 fills the bound first, on another device of the person.
        let full = device_at(0, 2);
        for record in held_rows::additions(&conn).unwrap() {
            let record = SignedAddition::from_bytes(&record.record).unwrap();
            see_addition(&full, &record, NOW).unwrap();
        }
        see_addition(&full, &added(&two, 2, 200), NOW).unwrap();
        assert_eq!(who_counts(&full).unwrap().devices(), 64);
        let before = who_counts(&full).unwrap().keys();
        assert_eq!(
            see_addition(&full, &added(&two, 0, 8), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        );
        // Device 8 may add now, and its record finds no room.
        let counting = who_counts(&full).unwrap();
        assert!(counting.may_add(&key(8)) && !counting.counts(&key(9)));
        assert_eq!(counting.keys(), before);
        assert_eq!(counting.devices(), 64);

        // Where there is room for one, it is counted, and the bound is
        // reached by it.
        assert_eq!(
            see_addition(&conn, &added(&two, 0, 8), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::CountsAlready)
        );
        let counting = who_counts(&conn).unwrap();
        assert!(counting.counts(&key(9)));
        assert_eq!(counting.devices(), 64);
        assert_eq!(
            see_addition(&conn, &added(&two, 2, 200), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::NoRoom)
        );
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

        // Device 2 is in neither list of another statement 3.
        let conn = device_at(2, 2);
        let without = two.next(key(0), &secret(3), listed(&[0, 1]), &[]).unwrap();
        let entry = change(&phrase, &without, secret(3));
        assert_eq!(
            shown(&conn, &device(2), &entry, NOW).unwrap(),
            Shown::NotListed
        );
        assert!(matches!(
            see_addition(&conn, &added(&two, 0, 7), NOW),
            Err(PersonError::Stopped(State::NotListed))
        ));
        assert!(held_rows::additions(&conn).unwrap().is_empty());

        // Device 1 is listed in statement 3, and its secret does not open.
        let conn = device_at(1, 2);
        let entry = change_sealing(
            &phrase,
            &three,
            &sealed(&[sealed_to(0, &secret(3)), sealed_to(9, &secret(3))]),
        );
        assert_eq!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::NotOpened
        );
        assert!(matches!(
            see_addition(&conn, &added(&two, 0, 7), NOW),
            Err(PersonError::Stopped(State::NotOpened))
        ));
        assert!(held_rows::additions(&conn).unwrap().is_empty());

        // Device 0 has applied statement 3, and sets aside a change made
        // apart from it (decision 2026-10-24 (removal), rules 1 and 11): it
        // goes on, and takes records under the change it follows alone.
        let [apart, ..] = made_apart(&phrase);
        let conn = device_at(0, 3);
        assert_eq!(
            see_addition(&conn, &added(&three, 0, 7), NOW).unwrap(),
            AdditionSeen::Counted
        );
        let entry = change(&phrase, &apart, secret(13));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::SetAside
        );
        assert_eq!(
            see_addition(&conn, &added(&three, 0, 8), NOW).unwrap(),
            AdditionSeen::Counted
        );
        assert!(matches!(
            see_addition(&conn, &added(&apart, 0, 9), NOW),
            Err(PersonError::RecordUnderAnotherStatement)
        ));
        assert_eq!(held_rows::additions(&conn).unwrap().len(), 2);
        assert!(who_counts(&conn).unwrap().counts(&key(8)));

        // A closed device takes none (rule 10).
        held_rows::set_state(&conn, State::Fork).unwrap();
        assert!(matches!(
            see_addition(&conn, &added(&three, 0, 10), NOW),
            Err(PersonError::Stopped(State::Fork))
        ));
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
                not_carried: Vec::new(),
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
                    not_carried: Vec::new(),
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
    /// a secret in this device's place that does not open, is not the one
    /// committed to, or is not there: the list is missing, or short. The
    /// device stops, and keeps the entry. Nothing of what it holds is
    /// carried or dropped.
    #[test]
    fn test_a_secret_that_does_not_open_or_is_not_there_stops_the_device() {
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        // Statement 3 lists devices 0 and 1, in that order.
        let ways: [(&str, Vec<u8>); 10] = [
            ("no list after the statement", Vec::new()),
            ("a list of none", sealed(&[])),
            ("a list of one too few", sealed(&[sealed_to(0, &secret(3))])),
            (
                "a list of this device's secret alone",
                sealed(&[sealed_to(1, &secret(3))]),
            ),
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

    /// Rule 8, step 6 (decision 2026-10-24 (removal)): a change made apart
    /// is kept as a head set aside, and where the change followed is still
    /// clear the device goes on (rule 11). Statement 3 removes device 2;
    /// each change made apart lists it, and is not clear. The device keeps
    /// the change it follows to go on showing, and the head beside it, with
    /// the time its lineage says; nothing else changes, and shown either
    /// again it is one it keeps.
    #[test]
    fn test_a_change_made_apart_is_set_aside_and_a_device_on_a_clear_change_goes_on() {
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
            // made apart, it is set aside all the same.
            let entry = change(&phrase, apart, secret(secrets_of[place]));
            assert_eq!(
                shown(&conn, &device(0), &entry, NOW).unwrap(),
                Shown::SetAside,
                "{place}"
            );
            assert_eq!(state(&conn), State::Applied);
            assert!(clear(&conn));
            assert_eq!(kept(&conn, Kept::Latest), Some(keeps.id()));
            assert_eq!(kept(&conn, Kept::Apart), Some(entry.id()));
            assert_eq!(applied_number(&conn), 3);
            assert_eq!(secrets(&conn), [(3, secret(3), None)]);
            assert_eq!(channels(&conn), store_before);
            // Its time is kept, as its lineage says it (rule 2).
            let link = apart.link().unwrap();
            let made_at = change_entry::lineage(&entry.content)
                .unwrap()
                .map(|lineage| lineage.made_at as i64);
            assert!(made_at.is_some());
            assert_eq!(
                held_rows::change_time(&conn, link.number, &link.hash).unwrap(),
                Some(made_at)
            );

            // It asks for neither again: each is an entry it keeps.
            let kept_both = everything(&conn);
            assert_eq!(shown(&conn, &device(0), &entry, NOW).unwrap(), Shown::Held);
            assert_eq!(shown(&conn, &device(0), &keeps, NOW).unwrap(), Shown::Held);
            assert_eq!(everything(&conn), kept_both);
        }

        // Rule 8, step 2: a head set aside goes where a change kept is made
        // after it. The higher of the two was made after the other.
        let conn = db::open_in_memory().unwrap();
        let keeps = follow(&conn, 0, &phrase, &three, secret(3));
        let [same_number, higher] = made_apart(&phrase);
        let first = change(&phrase, &same_number, secret(13));
        assert_eq!(
            shown(&conn, &device(0), &first, NOW).unwrap(),
            Shown::SetAside
        );
        let second = change(&phrase, &higher, secret(14));
        assert_eq!(
            shown(&conn, &device(0), &second, NOW).unwrap(),
            Shown::SetAside
        );
        assert_eq!(kept(&conn, Kept::Latest), Some(keeps.id()));
        let aside: Vec<[u8; 32]> = held_rows::set_aside_entries(&conn)
            .unwrap()
            .iter()
            .map(|head| head.entry.id())
            .collect();
        assert_eq!(aside, vec![second.id()]);
        // The one it put out is behind a head it keeps: nothing is done.
        let now_kept = everything(&conn);
        assert_eq!(
            shown(&conn, &device(0), &first, NOW).unwrap(),
            Shown::Behind
        );
        assert_eq!(everything(&conn), now_kept);
    }

    /// Rule 8, steps 3 to 5, on a device that sets a head aside: a change
    /// made after the one followed, that lists the device and is clear, is
    /// applied, and the head set aside stays, since it was not made after
    /// it; one that removes the device stops it as removed; the settlement,
    /// made after both, is applied and puts the head out; one made after
    /// the settlement is applied as well; and a settlement that does not
    /// list the device stops it, as in no list.
    #[test]
    fn test_a_device_that_sets_a_head_aside_applies_stops_or_settles_by_rule_8() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let [apart, ..] = made_apart(&phrase);
        let with_a_head = || {
            let conn = db::open_in_memory().unwrap();
            follow(&conn, 0, &phrase, &three, secret(3));
            hold_name(&conn, "team", NOW).unwrap();
            put(&conn, &own(3, "team"), 0, 5, "a.md", text("a"), &[]);
            let other = change(&phrase, &apart, secret(13));
            assert_eq!(
                shown(&conn, &device(0), &other, NOW).unwrap(),
                Shown::SetAside
            );
            (conn, other)
        };

        // Step 4: statement 4, made after 3 on its branch, lists device 0.
        let (conn, other) = with_a_head();
        let [.., four] = statements(&phrase);
        let entry = change(&phrase, &four, secret(4));
        assert!(matches!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Applied(Applied { number: 4, .. })
        ));
        assert_eq!(kept(&conn, Kept::Latest), Some(entry.id()));
        assert_eq!(kept(&conn, Kept::Apart), Some(other.id()));

        // Step 3: made after 3, it removes device 0.
        let (conn, _) = with_a_head();
        let removing = three
            .next(key(1), &secret(4), listed(&[1]), &[key(0)])
            .unwrap();
        let entry = change(&phrase, &removing, secret(4));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Removed
        );
        assert_eq!(state(&conn), State::Removed);
        assert_eq!(kept(&conn, Kept::Apart), None);

        // The settlement lists device 0.
        let (conn, _) = with_a_head();
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
                not_carried: Vec::new(),
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
        let (conn, _) = with_a_head();
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

        // Step 5: a settlement that does not list it.
        let (conn, _) = with_a_head();
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

    /// A device that sets a head aside is shown the statement that settles
    /// the two, which lists it, with a secret that does not open: it stops
    /// as any listed device does whose secret does not open (rule 8, step
    /// 4). It keeps that entry alone, and has applied nothing.
    #[test]
    fn test_a_device_that_cannot_open_the_settlement_stops() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let [apart, ..] = made_apart(&phrase);
        let settled =
            Statement::settle(&three, &apart, key(0), &secret(20), listed(&[0, 1]), &[]).unwrap();
        let ways: [(&str, Vec<u8>); 3] = [
            (
                "sealed to another key",
                sealed(&[sealed_for(4, 9, &secret(20)), sealed_for(4, 1, &secret(20))]),
            ),
            (
                "another secret than the one committed to",
                sealed(&[sealed_for(4, 0, &secret(9)), sealed_for(4, 1, &secret(20))]),
            ),
            ("no list after the statement", Vec::new()),
        ];
        for (what, after) in ways {
            let conn = db::open_in_memory().unwrap();
            follow(&conn, 0, &phrase, &three, secret(3));
            hold_name(&conn, "team", NOW).unwrap();
            put(&conn, &own(3, "team"), 0, 5, "a.md", text("a"), &[]);
            let other = change(&phrase, &apart, secret(13));
            assert_eq!(
                shown(&conn, &device(0), &other, NOW).unwrap(),
                Shown::SetAside
            );
            let store_of = |conn: &Connection| -> Vec<String> {
                everything(conn)
                    .into_iter()
                    .filter(|row| row.starts_with("entries:") || row.starts_with("person_names:"))
                    .collect()
            };
            let store_before = store_of(&conn);

            let entry = change_sealing(&phrase, &settled, &after);
            assert_eq!(
                shown(&conn, &device(0), &entry, NOW).unwrap(),
                Shown::NotOpened,
                "{what}"
            );
            assert_eq!(state(&conn), State::NotOpened, "{what}");
            assert_eq!(kept(&conn, Kept::Latest), Some(entry.id()), "{what}");
            assert_eq!(kept(&conn, Kept::Apart), None, "{what}");
            assert_eq!(applied_number(&conn), 3);
            assert_eq!(secrets(&conn), [(3, secret(3), None)]);
            assert_eq!(store_of(&conn), store_before, "{what}");

            // The way on is a person's: the settlement in an entry that
            // opens is not taken.
            let stopped = everything(&conn);
            let good = change(&phrase, &settled, secret(20));
            assert_eq!(
                shown(&conn, &device(0), &good, NOW).unwrap(),
                Shown::Refused(Refused::Stopped),
                "{what}"
            );
            assert_eq!(everything(&conn), stopped);
        }
    }

    /// A device refuses a statement that has the change it follows and a
    /// head set aside on its chain and lacks a removal that either of the
    /// two has (rule 8, step 2). Here the head removes device 1, which the
    /// change followed lists, so the device is closed (steps 6 to 8); it
    /// stays closed, and nothing changes.
    #[test]
    fn test_a_device_refuses_a_statement_that_undoes_a_removal_of_a_head_or_the_followed() {
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        // Statement 3 removes device 2. Made apart from it, on device 2,
        // one that removes device 1.
        let apart = two
            .next(key(2), &secret(13), listed(&[2, 0]), &[key(1)])
            .unwrap();
        let conn = db::open_in_memory().unwrap();
        follow(&conn, 0, &phrase, &three, secret(3));
        hold_name(&conn, "team", NOW).unwrap();
        put(&conn, &own(3, "team"), 0, 5, "a.md", text("a"), &[]);
        let other = change(&phrase, &apart, secret(13));
        assert_eq!(
            shown(&conn, &device(0), &other, NOW).unwrap(),
            Shown::Closed
        );
        let in_the_fork = everything(&conn);

        // The settlement removes both, and lists device 0 alone.
        let settled =
            Statement::settle(&three, &apart, key(0), &secret(20), listed(&[0]), &[]).unwrap();
        assert_eq!(settled.removed.len(), 2);
        let lacking = |key: [u8; 32]| {
            let mut lacking = settled.clone();
            lacking.removed.retain(|removed| *removed != key);
            lacking.validate().unwrap();
            assert!(lacking.has_on_chain(&three.link().unwrap()));
            assert!(lacking.has_on_chain(&apart.link().unwrap()));
            lacking
        };
        // What the one kept apart removed, what the one applied removed,
        // and the first with the key among its devices again.
        let mut back = lacking(key(1));
        back.devices.push(listed(&[1]).remove(0));
        back.validate().unwrap();
        for (what, statement) in [
            ("of the one kept apart", lacking(key(1))),
            ("of the one applied", lacking(key(2))),
            ("of the one kept apart, with the key listed", back),
        ] {
            let entry = change(&phrase, &statement, secret(20));
            let undoes = ChangeEntryError::Statement(StatementError::UndoesARemoval);
            assert_eq!(
                shown(&conn, &device(0), &entry, NOW).unwrap(),
                Shown::Refused(Refused::NotAChangeEntry(undoes)),
                "{what}"
            );
            assert_eq!(state(&conn), State::Fork, "{what}");
            assert_eq!(everything(&conn), in_the_fork, "{what}");
            // Nor is it applied where it is given with its secret.
            assert!(
                matches!(
                    apply(
                        &conn,
                        &device(0),
                        &sign(&statement, &phrase),
                        &secret(20),
                        &entry,
                        NOW
                    ),
                    Err(PersonError::Statement(StatementError::UndoesARemoval))
                ),
                "{what}"
            );
            assert_eq!(everything(&conn), in_the_fork, "{what}");
        }

        // The control: the settlement, which removes both, is applied.
        let entry = change(&phrase, &settled, secret(20));
        assert!(matches!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));
        assert_eq!(state(&conn), State::Applied);
    }

    /// A list that is missing or short says nothing to a device that the
    /// statement does not list: the entry is refused, and nothing changes.
    /// A device that it lists is told that its secret is not there, and
    /// keeps the entry: so a device in a fork, which kept such an entry
    /// apart, still takes the statement that settles the two.
    #[test]
    fn test_a_list_that_is_missing_or_short_stops_only_a_device_that_is_listed() {
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        let whole = sealed(&[sealed_to(0, &secret(3)), sealed_to(1, &secret(3))]);
        let short = sealed(&[sealed_to(0, &secret(3))]);
        let malformed = Shown::Refused(Refused::NotAChangeEntry(ChangeEntryError::Malformed));

        // Device 2, which statement 3 removes.
        let conn = device_at(2, 2);
        let before = everything(&conn);
        for after in [&[][..], &short] {
            let entry = change_sealing(&phrase, &three, after);
            assert_eq!(shown(&conn, &device(2), &entry, NOW).unwrap(), malformed);
            assert_eq!(everything(&conn), before);
        }
        // The control: with the list whole, it reads that it was removed.
        let entry = change_sealing(&phrase, &three, &whole);
        assert_eq!(
            shown(&conn, &device(2), &entry, NOW).unwrap(),
            Shown::Removed
        );

        // Device 2, which another statement 3 has in neither list.
        let without = two.next(key(0), &secret(3), listed(&[0, 1]), &[]).unwrap();
        let conn = device_at(2, 2);
        let before = everything(&conn);
        for after in [&[][..], &short] {
            let entry = change_sealing(&phrase, &without, after);
            assert_eq!(shown(&conn, &device(2), &entry, NOW).unwrap(), malformed);
            assert_eq!(everything(&conn), before);
        }
        let entry = change_sealing(&phrase, &without, &whole);
        assert_eq!(
            shown(&conn, &device(2), &entry, NOW).unwrap(),
            Shown::NotListed
        );

        // Device 0 has applied statement 3, and is shown one made apart
        // that lists it, in an entry with no list: it sets that entry
        // aside.
        let [apart, ..] = made_apart(&phrase);
        let conn = db::open_in_memory().unwrap();
        follow(&conn, 0, &phrase, &three, secret(3));
        let other = change_sealing(&phrase, &apart, &[]);
        assert_eq!(
            shown(&conn, &device(0), &other, NOW).unwrap(),
            Shown::SetAside
        );
        assert_eq!(kept(&conn, Kept::Apart), Some(other.id()));
        // It still takes the statement that settles the two.
        let settled =
            Statement::settle(&three, &apart, key(0), &secret(20), listed(&[0, 1]), &[]).unwrap();
        let entry = change(&phrase, &settled, secret(20));
        assert!(matches!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));
        assert_eq!(state(&conn), State::Applied);
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
                "with more than the list after its statement",
                change_sealing(&phrase, &three, &[&both[..], &[0, 0, 1]].concat()),
                not(ChangeEntryError::Malformed),
            ),
            (
                "with a list for more devices than its statement has",
                change_sealing(
                    &phrase,
                    &three,
                    &sealed(&[
                        sealed_to(0, &secret(3)),
                        sealed_to(1, &secret(3)),
                        sealed_to(1, &secret(3)),
                    ]),
                ),
                not(ChangeEntryError::Malformed),
            ),
            (
                "with a short list, and more after it",
                change_sealing(
                    &phrase,
                    &three,
                    &[&sealed(&[sealed_to(1, &secret(3))])[..], &[0, 0, 1]].concat(),
                ),
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

    /// A device refuses an entry whose lineage does not match its
    /// statement (decision 2026-10-24 rule 13): nothing changes, and the
    /// device is in no fork. An entry with no lineage, as the version
    /// before makes one, is judged by its statement alone.
    #[test]
    fn test_an_entry_whose_lineage_is_not_its_statements_is_refused() {
        use cordelia_crypto::change_entry::Lineage;
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        let good = change(&phrase, &three, secret(3));
        let region = CHANGE_ENTRY_BYTES - CHANGE_ENTRY_LINEAGE_BYTES;
        let with = |lineage: &Lineage| {
            let mut content = good.content.clone();
            content[region..].copy_from_slice(&lineage.to_bytes().unwrap());
            change_with(&phrase, 3, content)
        };
        let mut chain_changed = Lineage::of(&three, NOW as u64).unwrap();
        chain_changed.chain[1][0] ^= 1;
        let refused = [
            (
                "another statement's",
                with(&Lineage::of(&two, NOW as u64).unwrap()),
            ),
            ("with its chain changed", with(&chain_changed)),
        ];
        let before = everything(&conn);
        for (what, entry) in refused {
            assert_eq!(
                shown(&conn, &device(1), &entry, NOW).unwrap(),
                Shown::Refused(Refused::NotAChangeEntry(
                    ChangeEntryError::LineageNotItsStatement
                )),
                "{what}"
            );
            assert_eq!(everything(&conn), before, "{what}");
        }
        assert_eq!(state(&conn), State::Applied);

        // With no lineage, the entry is applied by its statement.
        let mut content = good.content.clone();
        content[region..].fill(0);
        let made_before = change_with(&phrase, 3, content);
        assert!(matches!(
            shown(&conn, &device(1), &made_before, NOW).unwrap(),
            Shown::Applied(_)
        ));

        // The control: the entry as it was made is applied on another
        // device.
        let other = device_at(0, 2);
        assert!(matches!(
            shown(&other, &device(0), &good, NOW).unwrap(),
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
        // secret it leaves; the secret it comes to; the entry it keeps and
        // its time; the names; and the word that it has applied, which is
        // the last.
        let refusals = [
            "BEFORE INSERT ON entries WHEN NEW.rev = 77",
            "BEFORE DELETE ON entries",
            "BEFORE UPDATE ON person",
            "BEFORE UPDATE ON person_secrets",
            "BEFORE INSERT ON person_secrets",
            "BEFORE INSERT ON person_change_entries",
            "BEFORE INSERT ON person_change_times",
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
                not_carried: Vec::new(),
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

    /// Work that unwinds leaves no transaction open on the connection, and
    /// nothing of what it wrote: it is undone as work that fails is. In a
    /// transaction of the caller's, what the caller wrote before stays,
    /// and the transaction is still the caller's.
    #[test]
    fn test_work_that_unwinds_is_undone_and_leaves_no_transaction_open() {
        use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

        let conn = holding();
        let before = everything(&conn);
        // The work writes, and then unwinds. (It unwinds with no message:
        // nothing is printed.)
        let unwinds = || {
            catch_unwind(AssertUnwindSafe(|| {
                in_one(&conn, || -> Result<(), PersonError> {
                    held_rows::set_state(&conn, State::Removed)?;
                    assert_eq!(state(&conn), State::Removed);
                    resume_unwind(Box::new("the work unwinds"))
                })
            }))
        };

        assert!(unwinds().is_err());
        assert!(conn.is_autocommit());
        assert_eq!(everything(&conn), before);
        assert_eq!(state(&conn), State::Applied);
        // The connection is used again as if nothing had been tried: the
        // next work begins a transaction of its own.
        hold_name(&conn, "after", NOW).unwrap();
        assert!(conn.is_autocommit());

        // Inside a transaction of the caller's.
        conn.execute_batch("BEGIN").unwrap();
        hold_name(&conn, "written before", NOW).unwrap();
        let with_the_callers = everything(&conn);
        assert!(unwinds().is_err());
        assert!(!conn.is_autocommit(), "the transaction is the caller's");
        assert_eq!(everything(&conn), with_the_callers);
        // No savepoint is left in it.
        assert!(conn.execute_batch("RELEASE person").is_err());
        conn.execute_batch("COMMIT").unwrap();
        assert_eq!(everything(&conn), with_the_callers);
        assert_eq!(state(&conn), State::Applied);
    }

    /// Work inside work, in a transaction of the caller's: each is ended
    /// once. Work that is done leaves what the work around it wrote before
    /// it, and so does work that fails.
    #[test]
    fn test_work_inside_work_is_ended_once() {
        let conn = holding();
        conn.execute_batch("BEGIN").unwrap();
        let around = in_one(&conn, || {
            held_rows::set_state(&conn, State::Fork)?;
            // Work that is done.
            in_one(&conn, || {
                held_rows::hold_name(&conn, "inside", &[0x71; 32], NOW)?;
                Ok(())
            })?;
            assert_eq!(state(&conn), State::Fork);
            // Work that fails.
            let failed = in_one(&conn, || -> Result<(), PersonError> {
                held_rows::set_state(&conn, State::Removed)?;
                Err(PersonError::FollowsAPhrase)
            });
            assert!(matches!(failed, Err(PersonError::FollowsAPhrase)));
            assert_eq!(state(&conn), State::Fork);
            Ok(())
        });
        around.unwrap();
        assert!(!conn.is_autocommit(), "the transaction is the caller's");
        conn.execute_batch("COMMIT").unwrap();
        assert_eq!(state(&conn), State::Fork);
        assert_eq!(
            held_rows::channel_of_name(&conn, "inside").unwrap(),
            Some([0x71; 32])
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

    /// Nothing of messages is carried at a statement (decision 2026-10-09
    /// §9.1): what the store held of the messages channel that is left
    /// goes in the step that applies the statement, with what was kept of
    /// each relay for it, and the new messages channel holds nothing. A
    /// message of the device's own left behind would be taken for a
    /// channel in which it only sends what it wrote.
    #[test]
    fn test_applying_a_statement_drops_the_messages_channel_that_is_left_and_carries_none() {
        let conn = holding();
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let messages = |n: u8| derive::messages_secret(&secret(n)).unwrap();
        let name = cordelia_crypto::message::message_name(&key(1), 1).unwrap();
        let value = Value::Other(cordelia_crypto::message::clearing_value());
        put(&conn, &messages(2), 1, 2, &name, value.clone(), &[]);
        put(&conn, &messages(2), 0, 2, &name, value, &[]);
        let relay = [0x77; 32];
        kept_rows::keep_place(&conn, &relay, &id_of(&messages(2)), &[1; 8], 2).unwrap();
        assert!(channels(&conn).contains(&id_of(&messages(2))));

        let entry = change(&phrase, &three, secret(3));
        assert!(matches!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));
        let held = channels(&conn);
        assert!(!held.contains(&id_of(&messages(2))));
        assert!(!held.contains(&id_of(&messages(3))));
        let kept = kept_rows::kept(&conn, &relay, &id_of(&messages(2))).unwrap();
        assert_eq!(kept.place, None);
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
                not_carried: Vec::new(),
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
    /// which names there were such slots. A slot that holds only entries
    /// of keys that do not count is passed over too, and is not said: for
    /// this device it held nothing.
    #[test]
    fn test_a_slot_that_holds_no_version_is_passed_over_and_its_name_is_reported() {
        let conn = device_at(1, 2);
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        for name in ["team", "notes", "empty", "others", "both"] {
            hold_name(&conn, name, NOW).unwrap();
        }
        let (team, notes) = (own(2, "team"), own(2, "notes"));
        put(&conn, &team, 0, 5, "a.md", text("a"), &[]);
        put_what_does_not_open(&conn, &team, 0, 6, "gone.md");
        put_what_does_not_open(&conn, &team, 2, 7, "gone.md");
        // Only an entry of a key that does not count.
        put(&conn, &team, 9, 6, "theirs.md", text("a stranger's"), &[]);
        put(&conn, &notes, 0, 5, "e.md", text("e"), &[]);
        // A name whose slots hold only entries of a key that does not
        // count: one that opens, and one that does not. It is not said.
        let others = own(2, "others");
        put(&conn, &others, 9, 6, "theirs.md", text("a stranger's"), &[]);
        put_what_does_not_open(&conn, &others, 9, 7, "more.md");
        // And one with a slot that holds an entry of each kind, of which
        // neither is a version: the entry of the key that counts no longer
        // opens, and the name is said.
        let both = own(2, "both");
        put(&conn, &both, 9, 6, "f.md", text("a stranger's"), &[]);
        put_what_does_not_open(&conn, &both, 0, 5, "f.md");
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
                no_version: vec!["both".to_string(), "team".to_string()],
                not_carried: Vec::new(),
            })
        );
        assert_eq!(applied_number(&conn), 3);
        let new = own(3, "team");
        assert!(carried(&conn, &new, "a.md").is_some());
        assert!(carried(&conn, &new, "gone.md").is_none());
        assert!(carried(&conn, &new, "theirs.md").is_none());
        // Nothing of the stranger's is carried, in any name.
        for name in ["others", "both"] {
            let channel = id_of(&own(3, name));
            assert!(entries::channel_slots(&conn, &channel).unwrap().is_empty());
        }
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

    /// A device carries into a generation it has not come to, where its
    /// store holds nothing of its own. Where the store does hold an entry
    /// of this device's in a slot it carries into, at the carried revision
    /// or above it, the entry is not stored and the change is not
    /// applied: nothing is carried over what is there, and nothing
    /// changes.
    #[test]
    fn test_a_carried_entry_that_the_store_does_not_take_stops_the_applying() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let entry = change(&phrase, &three, secret(3));
        let holding = |n: u16, rev: u64| {
            let conn = device_at(1, 2);
            hold_name(&conn, "team", NOW).unwrap();
            put(&conn, &own(2, "team"), 0, 5, "a.md", text("a"), &[]);
            put(&conn, &own(2, "team"), 0, 6, "b.md", text("b"), &[]);
            // What the store holds already in the generation it would
            // come to: an entry of device `n` under the same name.
            put(&conn, &own(3, "team"), n, rev, "a.md", text("there"), &[]);
            conn
        };

        // At the carried revision, and above it.
        for rev in [5, 9] {
            let conn = holding(1, rev);
            let before = everything(&conn);
            let failed = shown(&conn, &device(1), &entry, NOW);
            assert!(
                matches!(&failed, Err(PersonError::Held(why)) if why.contains("has not come to")),
                "{rev}: {failed:?}"
            );
            assert_eq!(everything(&conn), before, "{rev}");
            assert_eq!(state(&conn), State::Applied);
            assert_eq!(applied_number(&conn), 2);
            assert!(conn.is_autocommit());
            // What it holds in the generation it is in is still read.
            let version = read(&conn, &own(2, "team"), 2, "b.md", &[0, 1, 2]);
            assert_eq!(version.current.unwrap().value, text("b"));
        }

        // The control: below the carried revision, the carried entry takes
        // its place, and another device's entry there stops nothing.
        for (n, rev) in [(1, 4), (0, 9)] {
            let conn = holding(n, rev);
            assert!(matches!(
                shown(&conn, &device(1), &entry, NOW).unwrap(),
                Shown::Applied(Applied { carried: 2, .. })
            ));
            let held = entries::slot_entries(
                &conn,
                &id_of(&own(3, "team")),
                &slot_of(&own(3, "team"), "a.md"),
            )
            .unwrap();
            let own_entry = held.iter().find(|entry| entry.author == key(1)).unwrap();
            assert_eq!(own_entry.rev, 5);
        }
    }

    /// From the personal channel a device carries its own entry in each
    /// slot, whether or not another key's entry there has a higher
    /// revision: what it carries there is its own word, and no other
    /// key's entry stops that. What another device wrote there is that
    /// device's to carry. Records of additions are not carried, and nor
    /// is the word that the statement before was applied.
    #[test]
    fn test_from_the_personal_channel_a_device_carries_its_own_entry_in_each_slot() {
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
        // A name that two devices wrote under: device 0's entry is the
        // higher in one, and device 1's in the other.
        put(
            &conn,
            &old,
            1,
            3,
            "project/x",
            text("this device's word"),
            &[link("before", 1)],
        );
        put(&conn, &old, 0, 4, "project/x", text("a newer word"), &[]);
        put(&conn, &old, 0, 3, "project/y", text("an older word"), &[]);
        put(&conn, &old, 1, 4, "project/y", text("a newer word"), &[]);
        // And one where a key that the next statement removes wrote far
        // above this device, and wrote a delete.
        put(&conn, &old, 1, 2, "names", text("team"), &[]);
        put(&conn, &old, 2, at(2, 900), "names", Value::Delete, &[]);
        // Under the statement it is leaving, the current version of each
        // is the other key's.
        for (name, said) in [
            ("project/x", text("a newer word")),
            ("names", Value::Delete),
        ] {
            assert_eq!(
                read(&conn, &old, 2, name, &[0, 1, 2])
                    .current
                    .unwrap()
                    .value,
                said
            );
        }
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
                carried: 4,
                no_version: Vec::new(),
                not_carried: Vec::new(),
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
        // Its own word, with its own chain as it was, though another
        // key's entry stood above it.
        assert_eq!(
            carried(&conn, &new, "project/x").unwrap(),
            Carried {
                author: key(1),
                chain: vec![link("before", 1)],
                value: text("this device's word"),
                rev: 3,
            }
        );
        let names = carried(&conn, &new, "names").unwrap();
        assert_eq!((names.value, names.rev), (text("team"), 2));
        assert_eq!(names.chain, []);
        let newer = carried(&conn, &new, "project/y").unwrap();
        assert_eq!((newer.value, newer.rev), (text("a newer word"), 4));
        assert_eq!(newer.chain, []);
        for not_carried in ["syncing/zero", "added/seven", theirs.as_str()] {
            assert!(carried(&conn, &new, not_carried).is_none(), "{not_carried}");
        }

        // The word is the new one, and not the old one carried.
        let word = carried(&conn, &new, &mine).unwrap();
        assert_eq!((word.value, word.rev), (text("3"), 1));
        assert_eq!(
            entries::channel_slots(&conn, &id_of(&new)).unwrap().len(),
            5
        );
        assert!(
            entries::channel_slots(&conn, &id_of(&old))
                .unwrap()
                .is_empty()
        );
    }

    /// A device's carried word is not carried to the next statement, and
    /// nor is its delete (decision 2026-10-19 §4, rule 4): the next
    /// statement's own words are what stand. What it wrote beside them is
    /// carried as before.
    #[test]
    fn the_carried_word_and_its_delete_are_not_carried() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let old = personal(2);
        let reached = reached_name(&key(1)).unwrap();
        for (rev, word) in [(5, Value::Other(vec![1; 45])), (6, Value::Delete)] {
            let conn = device_at(1, 2);
            put(&conn, &old, 1, rev, &reached, word.clone(), &[]);
            put(&conn, &old, 1, 4, "syncing/one", text("team"), &[]);
            assert_eq!(
                read(&conn, &old, 2, &reached, &[1]).current.unwrap().value,
                word
            );
            let entry = change(&phrase, &three, secret(3));
            assert!(matches!(
                shown(&conn, &device(1), &entry, NOW).unwrap(),
                Shown::Applied(Applied { carried: 1, .. })
            ));
            let new = personal(3);
            assert!(carried(&conn, &new, &reached).is_none(), "{word:?}");
            assert_eq!(carried(&conn, &new, "syncing/one").unwrap().rev, 4);
        }
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

    /// A device that the statement does not list applies it only where a
    /// record of its own addition comes with it, under that statement,
    /// and each record that comes with it counts. It then counts by the
    /// record, which it keeps.
    #[test]
    fn test_a_device_is_applied_as_added_only_where_the_record_of_its_addition_counts() {
        let phrase = phrase();
        let [one, two, ..] = statements(&phrase);
        let following = following(&phrase);
        // Device `n` is added under `statement`, which commits to secret
        // 2, with these records.
        let join = |conn: &Connection,
                    n: u16,
                    statement: &Statement,
                    addition: &SignedAddition,
                    adders_own: Option<&SignedAddition>| {
            let entry = change(&phrase, statement, secret(2));
            let signed = sign(statement, &phrase);
            let change = Change {
                following: &following,
                statement: &signed,
                secret: &secret(2),
                entry: &entry,
            };
            in_one(conn, || {
                apply_added(conn, &device(n), None, &change, addition, adders_own, NOW)
            })
        };

        // A device of the statement added it.
        let conn = db::open_in_memory().unwrap();
        let empty = everything(&conn);
        let applied = join(&conn, 7, &two, &added(&two, 0, 7), None).unwrap();
        assert_eq!(
            applied,
            Applied {
                number: 2,
                left: None,
                carried: 0,
                no_version: Vec::new(),
                not_carried: Vec::new(),
            }
        );
        let counting = who_counts(&conn).unwrap();
        assert_eq!(counting.keys(), [key(0), key(1), key(2), key(7)]);
        assert!(counting.may_add(&key(7)));
        let kept = held_rows::additions(&conn).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].key, kept[0].counted), (key(7), true));
        // It has written that it has applied, under its own name.
        let word = read(
            &conn,
            &personal(2),
            2,
            &applied_name(&key(7)).unwrap(),
            &[7],
        );
        assert_eq!(word.current.unwrap().value, text("2"));

        // A device that was itself added since added it: the record of
        // that device's addition comes too, and is seen first.
        let conn = db::open_in_memory().unwrap();
        join(&conn, 7, &two, &added(&two, 9, 7), Some(&added(&two, 0, 9))).unwrap();
        let counting = who_counts(&conn).unwrap();
        assert_eq!(counting.keys(), [key(0), key(1), key(2), key(9), key(7)]);
        assert!(counting.may_add(&key(9)) && !counting.may_add(&key(7)));

        // Refused, with nothing changed.
        let refused = |n: u16,
                       statement: &Statement,
                       addition: &SignedAddition,
                       adders_own: Option<&SignedAddition>| {
            let conn = db::open_in_memory().unwrap();
            let outcome = join(&conn, n, statement, addition, adders_own);
            assert_eq!(held(&conn).unwrap(), None);
            assert_eq!(everything(&conn), empty);
            outcome.unwrap_err()
        };
        // A record that adds another device, and one made under another
        // statement: no record of this device's addition comes with it.
        assert!(matches!(
            refused(7, &two, &added(&two, 0, 8), None),
            PersonError::NotApplied(Judgement::NotListed)
        ));
        assert!(matches!(
            refused(7, &two, &added(&one, 0, 7), None),
            PersonError::NotApplied(Judgement::NotListed)
        ));
        // A record that a key which does not count signed, with no record
        // of that key's addition, and with one that such a key signed.
        assert!(matches!(
            refused(7, &two, &added(&two, 9, 7), None),
            PersonError::RecordByAKeyThatDoesNotCount
        ));
        assert!(matches!(
            refused(7, &two, &added(&two, 9, 7), Some(&added(&two, 8, 9))),
            PersonError::RecordByAKeyThatDoesNotCount
        ));
        // A record that does not verify.
        let mut forged = added(&two, 0, 7);
        forged.signature[0] ^= 1;
        assert!(matches!(
            refused(7, &two, &forged, None),
            PersonError::Addition(AdditionError::Signature)
        ));
        // A statement that lists 64 devices has no room for one more: the
        // record does not count, and the device is not in the statement.
        let numbers: Vec<u16> = (0..64).collect();
        let many = one.next(key(0), &secret(2), listed(&numbers), &[]).unwrap();
        assert!(matches!(
            refused(100, &many, &added(&many, 0, 100), None),
            PersonError::RecordNotCounted(NotCounted::NoRoom)
        ));

        // A record of an addition is under the name of the key it adds.
        let name = added_name(&key(7)).unwrap();
        assert_eq!(
            name,
            format!("added/{}", encode_public_key(&key(7)).unwrap())
        );
        assert!(name.starts_with("added/cordelia_pk1"));
    }

    /// The two halves of `cordelia phrase`: the command makes the first
    /// statement's change entry with the phrase, and the node is handed
    /// that entry and the statement key, never the words. It opens the
    /// secret that the entry seals to its own key.
    #[test]
    fn test_the_node_follows_a_first_statement_that_a_command_made() {
        let conn = db::open_in_memory().unwrap();
        let phrase = phrase();
        let made = first_entry(&phrase, &key(0), "laptop").unwrap();
        assert_eq!(made.statement_key, *phrase.statement_key().unwrap());
        assert_eq!(made.entry.author, phrase.public_key().unwrap());
        assert_eq!(made.entry.rev, 1);
        // Made again, it is another secret, and another entry.
        let again = first_entry(&phrase, &key(0), "laptop").unwrap();
        assert_ne!(again.entry.id(), made.entry.id());

        let applied = follow_first(&conn, &device(0), &made.entry, &made.statement_key, NOW);
        assert_eq!((applied.unwrap().number, 1), (1, 1));
        let now = held(&conn).unwrap().unwrap();
        assert_eq!(now.state, State::Applied);
        assert_eq!(now.following, following(&phrase));
        assert_eq!(
            now.statement.statement.devices,
            [Device::new(key(0), "laptop").unwrap()]
        );
        assert_eq!(
            kept_entry(&conn, Kept::Latest).unwrap().unwrap(),
            made.entry
        );
        let (_, secret, _) = secrets(&conn)[0];
        assert!(now.statement.statement.commits_to(&secret));

        // A device that follows a phrase is refused: leaving one is
        // another act.
        let before = everything(&conn);
        assert!(matches!(
            follow_first(&conn, &device(0), &again.entry, &again.statement_key, NOW),
            Err(PersonError::FollowsAPhrase)
        ));
        assert_eq!(everything(&conn), before);
    }

    /// A first statement is followed only where it is one: number 1,
    /// with no chain, made on this device and listing it alone, in an
    /// entry that the statement key opens.
    #[test]
    fn test_a_first_statement_is_followed_only_where_it_is_one_made_on_this_device() {
        let phrase = phrase();
        let refused = |entry: &CheckedEntry, statement_key: &[u8; 32]| {
            let conn = db::open_in_memory().unwrap();
            let before = everything(&conn);
            let outcome = follow_first(&conn, &device(0), entry, statement_key, NOW);
            assert_eq!(everything(&conn), before);
            outcome.unwrap_err()
        };
        let statement_key = phrase.statement_key().unwrap();

        // Made for another device.
        let for_another = first_entry(&phrase, &key(1), "laptop").unwrap();
        assert!(matches!(
            refused(&for_another.entry, &statement_key),
            PersonError::NotAFirstStatement
        ));
        // Another statement key than the phrase's: the entry does not
        // open.
        let made = first_entry(&phrase, &key(0), "laptop").unwrap();
        assert!(matches!(
            refused(&made.entry, &[7; 32]),
            PersonError::ChangeEntry(ChangeEntryError::DidNotOpen)
        ));
        // A statement that lists another device beside this one, though
        // it is numbered 1 and has no chain.
        let secret = secret(3);
        let two = Statement {
            number: 1,
            maker: key(0),
            chain: Vec::new(),
            commitment: statement::commitment(&secret),
            devices: listed(&[0, 1]),
            removed: Vec::new(),
            phrase_key: phrase.public_key().unwrap(),
        };
        let two = change(&phrase, &two, secret);
        assert!(matches!(
            refused(&two, &statement_key),
            PersonError::NotAFirstStatement
        ));
        // A statement numbered 1, with no chain, that lists this device
        // alone and a removed key beside it.
        let with_removed = Statement {
            number: 1,
            maker: key(0),
            chain: Vec::new(),
            commitment: statement::commitment(&secret),
            devices: listed(&[0]),
            removed: vec![key(5)],
            phrase_key: phrase.public_key().unwrap(),
        };
        let with_removed = change(&phrase, &with_removed, secret);
        assert!(matches!(
            refused(&with_removed, &statement_key),
            PersonError::NotAFirstStatement
        ));
        // A later statement of the phrase that lists this device alone.
        let all = statements(&phrase);
        let later = all[0].next(key(0), &secret, listed(&[0]), &[]).unwrap();
        assert_eq!((later.number, later.devices.len()), (2, 1));
        let later = change(&phrase, &later, secret);
        assert!(matches!(
            refused(&later, &statement_key),
            PersonError::NotAFirstStatement
        ));
        // The control.
        let conn = db::open_in_memory().unwrap();
        follow_first(&conn, &device(0), &made.entry, &statement_key, NOW).unwrap();
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
                not_carried: Vec::new(),
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

    /// A statement that commits to the secret that is already applied is
    /// refused: the channels of the generation it names are the ones the
    /// device is in, and what was carried there would be dropped with what
    /// is left. Nothing changes, and the device does not stop.
    #[test]
    fn test_a_statement_that_commits_to_the_applied_secret_is_refused() {
        let phrase = phrase();
        let [_, _, three, four] = statements(&phrase);
        let conn = device_at(1, 3);
        hold_name(&conn, "team", NOW).unwrap();
        put(&conn, &own(3, "team"), 1, 5, "a.md", text("a"), &[]);
        put(&conn, &own(3, "team"), 0, 6, "b.md", text("b"), &[]);
        let before = everything(&conn);

        // Statement 4, as a maker with a fault would have made it: it
        // commits to secret 3, which statement 3 does.
        let mut same = four.clone();
        same.commitment = three.commitment;
        same.validate().unwrap();
        let signed = sign(&same, &phrase);
        let entry = change(&phrase, &same, secret(3));
        let refused = ChangeEntryError::Statement(StatementError::SameSecret);
        assert_eq!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::Refused(Refused::NotAChangeEntry(refused))
        );
        assert!(matches!(
            apply(&conn, &device(1), &signed, &secret(3), &entry, NOW),
            Err(PersonError::Statement(StatementError::SameSecret))
        ));
        assert_eq!(state(&conn), State::Applied);
        assert_eq!(everything(&conn), before);

        // Where it is applied, whoever asks: the carry is not begun.
        let held = held(&conn).unwrap().unwrap();
        let given = Change {
            following: &held.following,
            statement: &signed,
            secret: &secret(3),
            entry: &entry,
        };
        let applied = in_one(&conn, || {
            apply_judged(&conn, &device(1), Some(&held), &given, NOW)
        });
        assert!(matches!(
            applied,
            Err(PersonError::Statement(StatementError::SameSecret))
        ));
        assert_eq!(everything(&conn), before);
        // What the device holds is still there, under the statement it
        // has applied.
        let version = read(&conn, &own(3, "team"), 3, "b.md", &[0, 1]);
        assert_eq!(version.current.unwrap().value, text("b"));

        // The control: statement 4 with its own secret is applied.
        let entry = change(&phrase, &four, secret(4));
        assert!(matches!(
            shown(&conn, &device(1), &entry, NOW).unwrap(),
            Shown::Applied(Applied { carried: 2, .. })
        ));
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

    // ── What a device knows of removals (decision 2026-10-24 (removal)) ──

    /// Device 0 under statement 3 of [`statements`], which removes device
    /// 2, holding the name `team` with an entry of its own there.
    fn under_three() -> Connection {
        let conn = device_at(0, 3);
        hold_name(&conn, "team", NOW).unwrap();
        put(&conn, &own(3, "team"), 0, at(3, 5), "a.md", text("a"), &[]);
        conn
    }

    /// Whether the change this device follows is clear, as every rule
    /// asks it.
    fn clear(conn: &Connection) -> bool {
        follows_a_clear_change(conn).unwrap()
    }

    fn removed(conn: &Connection) -> Vec<[u8; 32]> {
        held_rows::removed_keys(conn).unwrap()
    }

    /// A change is clear where no key the device knows to be removed is
    /// among its devices (rule 3), and the removed keys are every key that
    /// any change it has applied lists as removed (rule 2): those of
    /// statement 3 are kept when it is applied. A key kept as removed that
    /// the statement lists makes it not clear, and the device closed.
    #[test]
    fn test_a_change_is_clear_only_where_no_key_known_removed_is_among_its_devices() {
        let conn = under_three();
        assert_eq!(removed(&conn), vec![key(2)]);
        assert!(clear(&conn));
        assert_eq!(
            crate::at_relays::stands(&conn).unwrap(),
            crate::at_relays::Stands::Applied
        );
        // Device 1, which statement 3 lists, is removed on a branch this
        // device has seen (set so by hand here: no branch is kept yet).
        held_rows::keep_removed(&conn, &[key(1)], NOW).unwrap();
        assert!(!clear(&conn));
        assert_eq!(
            crate::at_relays::stands(&conn).unwrap(),
            crate::at_relays::Stands::Closed
        );
        // The row of the person is as it was: closed is worked out.
        assert_eq!(state(&conn), State::Applied);
    }

    /// Whether the change followed is clear is worked out once for each
    /// mark, and no "clear" is read after a removal is known: not after a
    /// key is kept, not after a write that made the change clear is undone,
    /// and not from another database read in turn (schema step 21).
    #[test]
    fn test_no_clear_worked_out_before_a_removal_is_read_after_it() {
        let conn = under_three();
        let closed =
            || crate::at_relays::stands(&conn).unwrap() == crate::at_relays::Stands::Closed;
        assert!(clear(&conn) && !closed());
        let mark = held_rows::clear_mark(&conn).unwrap();
        // Read again under the same mark, it is what was worked out.
        assert!(clear(&conn));
        assert_eq!(held_rows::clear_mark(&conn).unwrap(), mark);

        held_rows::keep_removed(&conn, &[key(1)], NOW).unwrap();
        assert_ne!(held_rows::clear_mark(&conn).unwrap(), mark);
        assert!(!clear(&conn) && closed());

        // A write that makes it clear, read and then undone: not clear.
        conn.execute_batch("SAVEPOINT undone").unwrap();
        conn.execute("DELETE FROM person_removed_keys", []).unwrap();
        assert!(clear(&conn) && !closed());
        conn.execute_batch("ROLLBACK TO undone; RELEASE undone")
            .unwrap();
        assert!(!clear(&conn) && closed());

        // Another database, clear, read in turn with this one.
        let other = under_three();
        for _ in 0..3 {
            assert!(clear(&other));
            assert!(!clear(&conn) && closed());
        }
        // A record that hands a removed key the secret, through the door's
        // own function: not clear from its commit.
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        assert!(clear(&other));
        see_addition(&other, &added(&three, 1, 2), NOW).unwrap();
        assert!(!clear(&other));
        // The mark past the bound of removed keys, set alone.
        let third = under_three();
        assert!(clear(&third));
        cordelia_storage::meta::set(
            &third,
            cordelia_storage::meta::PERSON_REMOVED_PAST_BOUND,
            "1",
        )
        .unwrap();
        assert!(!clear(&third));
    }

    /// A change of the phrase's that is refused after its signature is
    /// checked still says what the person removed (rule 2): shown a change
    /// 4 that drops statement 3's removal of device 2 and removes device 5,
    /// the device refuses it and keeps device 5 as removed. One whose
    /// signature does not hold says nothing.
    #[test]
    fn test_the_removed_keys_of_a_change_refused_after_its_signature_are_kept() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let conn = under_three();
        let before = everything(&conn);
        let mut drops = three
            .next(key(0), &secret(15), listed(&[0, 1]), &[key(5)])
            .unwrap();
        drops.removed = vec![key(5)];
        drops.validate().unwrap();
        let entry = change(&phrase, &drops, secret(15));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Refused(Refused::NotAChangeEntry(ChangeEntryError::Statement(
                StatementError::UndoesARemoval
            )))
        );
        assert_eq!(everything(&conn), before);
        assert_eq!(state(&conn), State::Applied);
        let mut known = vec![key(2), key(5)];
        known.sort_unstable();
        assert_eq!(removed(&conn), known);
        assert!(clear(&conn));

        // Its signature broken: nothing is kept.
        let mut forged = sign(&drops, &phrase);
        forged.statement.removed = vec![key(6)];
        know_removed_if_signed(&conn, &device(0), &forged, NOW).unwrap();
        assert_eq!(removed(&conn), known);
        // Signed, it is kept, though nothing applies it.
        let mut signed = drops.clone();
        signed.removed = vec![key(6)];
        signed.validate().unwrap();
        know_removed_if_signed(&conn, &device(0), &sign(&signed, &phrase), NOW).unwrap();
        known.push(key(6));
        known.sort_unstable();
        assert_eq!(removed(&conn), known);
    }

    /// A device whose own key is among those it knows to be removed is
    /// told that it was removed, and that its way on is a new key, and not
    /// to make a change here (rules 2 and 4): a change made here that lists
    /// it is refused so, and `cordelia devices` says so, applied or in a
    /// fork whose other branch removed it.
    #[test]
    fn test_a_device_that_knows_its_own_key_removed_is_told_it_was_removed() {
        let phrase = phrase();
        let [_, _, three, four] = statements(&phrase);
        let conn = under_three();
        held_rows::keep_removed(&conn, &[key(0)], NOW).unwrap();
        let entry = change(&phrase, &four, secret(4));
        assert!(matches!(
            apply(
                &conn,
                &device(0),
                &sign(&four, &phrase),
                &secret(4),
                &entry,
                NOW
            ),
            Err(PersonError::RemovedAsKnown)
        ));
        let at_relays = crate::state::AtRelays::default();
        let look = crate::look::look(&conn, &device(0), &at_relays, NOW).unwrap();
        assert_eq!(
            look.short.as_deref(),
            Some(crate::look::REMOVED_AS_KNOWN_SHORT)
        );
        assert_eq!(
            look.cannot_go_on.as_deref(),
            Some(crate::look::REMOVED_AS_KNOWN_WHY)
        );
        assert!(!crate::look::REMOVED_AS_KNOWN_WHY.contains("renew"));
        assert!(crate::look::REMOVED_AS_KNOWN_WHY.contains("cordelia init --new-key"));
        let _ = three;

        // Rule 8, step 3: a change made apart that removes it stops it, as
        // removed, as one made after the change followed does.
        let [same_number, _] = made_apart(&phrase);
        let conn = db::open_in_memory().unwrap();
        follow(&conn, 0, &phrase, &same_number, secret(13));
        let removes_zero = statements(&phrase)[1]
            .next(key(1), &secret(16), listed(&[1, 2]), &[key(0)])
            .unwrap();
        assert_eq!(
            shown(
                &conn,
                &device(0),
                &change(&phrase, &removes_zero, secret(16)),
                NOW
            )
            .unwrap(),
            Shown::Removed
        );
        assert_eq!(state(&conn), State::Removed);
        let look = crate::look::look(&conn, &device(0), &at_relays, NOW).unwrap();
        assert_eq!(look.state, "removed");
        assert_eq!(look.short.as_deref(), Some("this device was removed"));
    }

    /// A record under the change followed that adds a removed key makes
    /// that change not clear, as a new removed key does, though the key
    /// does not count by it (rule 3). The key is kept apart from the
    /// record: where the bound of records not counted drops the record,
    /// the change stays not clear.
    #[test]
    fn test_a_record_that_adds_a_removed_key_makes_the_change_not_clear_past_the_bound() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let conn = under_three();
        // Device 1 adds device 2, which statement 3 removes.
        let again = added(&three, 1, 2);
        assert_eq!(
            see_addition(&conn, &again, NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::Removed)
        );
        assert!(!who_counts(&conn).unwrap().counts(&key(2)));
        assert!(!clear(&conn));

        // Records by device 1 for 64 keys that count and then more that
        // the 64 keep out, until the bound drops the record of device 2.
        let mut n = 100;
        while held_rows::additions(&conn)
            .unwrap()
            .iter()
            .any(|kept| kept.key == key(2))
        {
            see_addition(&conn, &added(&three, 1, n), NOW).unwrap();
            n += 1;
            assert!(n < 1_000, "the bound never dropped the record");
        }
        assert!(
            held_rows::holders(&conn, 3, &three.hash().unwrap())
                .unwrap()
                .contains(&key(2))
        );
        assert!(!clear(&conn), "the holder went with its record");
    }

    /// Past the bound of holders a change is not clear, and past the bound
    /// of removed keys the device is closed: each fails closed (rules 2
    /// and 3).
    #[test]
    fn test_past_either_bound_the_device_is_closed() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let conn = under_three();
        let hash = three.hash().unwrap();
        for n in 0..MAX_KNOWN_HOLDERS as u32 {
            let mut holder = [0xdd; 32];
            holder[..4].copy_from_slice(&n.to_be_bytes());
            held_rows::keep_holder(&conn, 3, &hash, &holder).unwrap();
        }
        assert!(clear(&conn));
        held_rows::keep_holder(&conn, 3, &hash, &[0xcc; 32]).unwrap();
        assert!(!clear(&conn));

        let conn = under_three();
        let many: Vec<[u8; 32]> = (0..=MAX_KNOWN_REMOVED as u32)
            .map(|n| {
                let mut gone = [0xee; 32];
                gone[..4].copy_from_slice(&n.to_be_bytes());
                gone
            })
            .collect();
        held_rows::keep_removed(&conn, &many, NOW).unwrap();
        assert!(!clear(&conn));
    }

    /// The removed keys of every change a device has seen and checked are
    /// kept, whatever it is to the device (rule 2): one made apart, which
    /// it keeps apart, and one that stops it. They only grow.
    #[test]
    fn test_the_removed_keys_of_a_change_made_apart_or_that_stops_the_device_are_kept() {
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        // Device 0 follows a change made apart from statement 3, which
        // lists device 2, and is shown statement 3.
        let [same_number, _] = made_apart(&phrase);
        let conn = db::open_in_memory().unwrap();
        follow(&conn, 0, &phrase, &same_number, secret(13));
        assert!(removed(&conn).is_empty());
        let removal = change(&phrase, &three, secret(3));
        assert_eq!(
            shown(&conn, &device(0), &removal, NOW).unwrap(),
            Shown::Closed
        );
        assert_eq!(removed(&conn), vec![key(2)]);
        assert!(!clear(&conn));
        assert_eq!(state(&conn), State::Fork);

        // Device 2 under statement 2 is shown statement 3, and stops.
        let conn = device_at(2, 2);
        let _ = two;
        assert_eq!(
            shown(&conn, &device(2), &removal, NOW).unwrap(),
            Shown::Removed
        );
        // Its own key is not kept: it is stopped as removed, and still
        // reads its own store.
        assert!(removed(&conn).is_empty());
    }

    /// A change shown that could be applied, and that lists a key this
    /// device knows to be removed, is not applied (rules 2 and 4): it is set
    /// aside, and the device goes on, since the change it follows is clear
    /// (rule 8, step 6). The keys it removes are kept. Nothing else changes.
    #[test]
    fn test_a_change_that_is_not_clear_is_not_applied_and_its_removals_are_kept() {
        let phrase = phrase();
        let [_, _, three, four] = statements(&phrase);
        let conn = under_three();
        // Device 3, which statement 4 lists, is known to be removed.
        held_rows::keep_removed(&conn, &[key(3)], NOW).unwrap();
        let store = |conn: &Connection| -> Vec<String> {
            everything(conn)
                .into_iter()
                .filter(|row| !row.starts_with("person_change"))
                .collect()
        };
        let before = store(&conn);
        let entry = change(&phrase, &four, secret(4));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::SetAside
        );
        assert_eq!(store(&conn), before);
        assert_eq!(kept(&conn, Kept::Apart), Some(entry.id()));
        assert_eq!(state(&conn), State::Applied);
        assert_eq!(applied_number(&conn), 3);
        assert_eq!(removed(&conn), vec![key(2), key(3)]);
        // Asked of the change made here, as `cordelia renew` asks it: it
        // is refused, with nothing changed.
        let signed = sign(&four, &phrase);
        assert!(matches!(
            apply(&conn, &device(1), &signed, &secret(4), &entry, NOW),
            Err(PersonError::NotClear)
        ));
        assert_eq!(store(&conn), before);
        let _ = three;
    }

    /// `come_to`, where every apply seals its carry and its word, refuses
    /// a change that is not clear from each caller (rule 4): a change
    /// shown, one made here, a first change and a recovery. The rows are
    /// set so by hand.
    #[test]
    fn test_come_to_refuses_a_change_that_is_not_clear_from_each_caller() {
        let phrase = phrase();
        let [one, two, three, _] = statements(&phrase);

        // A first statement, on a device that keeps its own key as removed.
        let conn = db::open_in_memory().unwrap();
        held_rows::keep_removed(&conn, &[key(0)], NOW).unwrap();
        let made = first_entry(&phrase, &key(0), "device 0").unwrap();
        assert!(matches!(
            follow_first(&conn, &device(0), &made.entry, &made.statement_key, NOW),
            Err(PersonError::RemovedAsKnown)
        ));
        assert!(held(&conn).unwrap().is_none());

        // A recovery, the same.
        let conn = db::open_in_memory().unwrap();
        held_rows::keep_removed(&conn, &[key(0)], NOW).unwrap();
        let recovered = two
            .next(key(0), &secret(23), listed(&[0]), &[key(1), key(2)])
            .unwrap();
        let entry = change(&phrase, &recovered, secret(23));
        assert!(matches!(
            follow_recovered(
                &conn,
                &device(0),
                &entry,
                &phrase.statement_key().unwrap(),
                &[],
                NOW
            ),
            Err(PersonError::RemovedAsKnown)
        ));
        assert!(held(&conn).unwrap().is_none());

        // A change shown, and one made here: statement 3 after 2, on a
        // device that knows device 1 to be removed.
        let conn = device_at(0, 2);
        held_rows::keep_removed(&conn, &[key(1)], NOW).unwrap();
        let entry = change(&phrase, &three, secret(3));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Closed
        );
        let signed = sign(&three, &phrase);
        assert!(matches!(
            apply(&conn, &device(0), &signed, &secret(3), &entry, NOW),
            Err(PersonError::NotClear)
        ));
        assert_eq!(applied_number(&conn), 2);
        let _ = one;
    }

    /// Every seal outside an apply takes its secret at
    /// `Standing::to_write`, which refuses a secret that is not clear
    /// (rule 4): a publish and a hand-over are refused. `applied_secret`
    /// refuses nothing, and readers go on reading through it.
    #[test]
    fn test_nothing_is_sealed_under_a_secret_that_is_not_clear() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let conn = under_three();
        let write = crate::publish::Write {
            name: "team",
            file: "b.md",
            value: text("written while closed"),
            planned: crate::publish::PlannedAgainst::NoVersion,
            merge: None,
        };
        let entries_before = channels(&conn);
        see_addition(&conn, &added(&three, 1, 2), NOW).unwrap();
        assert!(matches!(
            crate::publish::Standing::to_write(&conn),
            Err(PersonError::NotClear)
        ));
        let before = everything(&conn);
        assert!(matches!(
            crate::publish::publish(&conn, &device(0), &write, NOW),
            Err(PersonError::NotClear)
        ));
        assert!(matches!(
            crate::adding::add_device(&conn, &device(0), &key(7), "device 7", NOW),
            Err(PersonError::NotClear)
        ));
        assert_eq!(everything(&conn), before);
        assert_eq!(channels(&conn), entries_before);
        // Readers read: the secret, and where it stands.
        assert_eq!(
            applied_secret(&conn, &held(&conn).unwrap().unwrap().statement.statement).unwrap(),
            secret(3)
        );
        assert!(crate::publish::Standing::of(&conn).is_ok());
    }

    /// Who counts reads every key the device knows to be removed, on any
    /// branch (rule 6): such a key counts for nothing, a record that adds
    /// it does not count, and `cordelia add-device` refuses it, though the
    /// statement applied does not list it as removed.
    #[test]
    fn test_who_counts_reads_every_key_known_to_be_removed() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let conn = under_three();
        // Device 5 is added under statement 3, and counts.
        see_addition(&conn, &added(&three, 1, 5), NOW).unwrap();
        assert!(who_counts(&conn).unwrap().counts(&key(5)));
        // Device 6 is removed on another branch: it does not count, a
        // record that adds it does not count, and it is not added.
        held_rows::keep_removed(&conn, &[key(6)], NOW).unwrap();
        assert!(clear(&conn));
        assert!(matches!(
            crate::adding::add_device(&conn, &device(0), &key(6), "device 6", NOW),
            Err(PersonError::KeyRemoved)
        ));
        assert!(matches!(
            crate::adding::would_add(&conn, &device(0), &key(6), "device 6"),
            Err(PersonError::KeyRemoved)
        ));
        assert_eq!(
            see_addition(&conn, &added(&three, 1, 6), NOW).unwrap(),
            AdditionSeen::NotCounted(NotCounted::Removed)
        );
        assert!(!who_counts(&conn).unwrap().counts(&key(6)));
        // That record handed it the secret: the change is not clear now.
        assert!(!clear(&conn));
        // Device 5 is removed on another branch: what it signs is not
        // taken, and the device takes nothing in its own channels.
        let conn = under_three();
        see_addition(&conn, &added(&three, 1, 5), NOW).unwrap();
        held_rows::keep_removed(&conn, &[key(5)], NOW).unwrap();
        assert!(!who_counts(&conn).unwrap().counts(&key(5)));
        let by_five = Entry::seal(
            &own(3, "team"),
            &device(5),
            at(3, 9),
            &Inside {
                name: "c.md".into(),
                value: text("after its removal"),
                chain: Some(Vec::new()),
            },
        )
        .unwrap()
        .check()
        .unwrap();
        assert_eq!(
            crate::take::take(&conn, &device(0), &by_five, NOW).unwrap(),
            crate::take::Taken::Refused(crate::take::NotTaken::Closed)
        );
    }

    /// A device that leaves its phrase forgets what it knew of removals:
    /// under another phrase they are another person's keys. While it
    /// follows the phrase, nothing takes one out.
    #[test]
    fn test_what_a_device_knows_of_removals_goes_only_when_it_leaves_its_phrase() {
        let phrase = phrase();
        let [_, _, three, four] = statements(&phrase);
        let conn = under_three();
        held_rows::keep_removed(&conn, &[key(9)], NOW).unwrap();
        // Statement 4 is applied: the keys only grow.
        let entry = change(&phrase, &four, secret(4));
        assert!(matches!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));
        assert_eq!(removed(&conn), vec![key(2), key(9)]);
        assert!(crate::leaving::forget(&conn, &device(0), false, NOW).unwrap());
        assert!(removed(&conn).is_empty());
        let _ = three;
    }

    /// A closed device sends nothing (rule 5): no channel of its own and
    /// no pair channel is in a pass, from the commit that kept the record
    /// that closed it. It leaves its phrase without its word that it left
    /// (rule 4), which would be sealed under a secret a removed key holds.
    #[test]
    fn test_a_closed_device_sends_nothing_and_leaves_without_its_word() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let conn = under_three();
        // A hand-over to device 7 waits in its pair channel.
        crate::adding::add_device(&conn, &device(0), &key(7), "device 7", NOW).unwrap();
        let sent = crate::at_relays::channels(&conn, &device(0)).unwrap();
        assert!(
            sent.iter()
                .any(|own| own.kind == crate::at_relays::Kind::Pair)
        );
        assert!(
            sent.iter()
                .any(|own| own.kind == crate::at_relays::Kind::Personal)
        );

        see_addition(&conn, &added(&three, 1, 2), NOW).unwrap();
        assert!(
            crate::at_relays::channels(&conn, &device(0))
                .unwrap()
                .is_empty()
        );
        assert_eq!(crate::at_relays::messages_channel(&conn).unwrap(), None);
        assert!(crate::at_relays::listed(&conn, 10).unwrap().is_empty());

        let begun = crate::leaving::begin(&conn, &device(0), NOW).unwrap();
        assert_eq!(begun.word, None);
        // Where it was not closed, it says that it left.
        let conn = under_three();
        let begun = crate::leaving::begin(&conn, &device(0), NOW).unwrap();
        assert!(begun.word.is_some());
    }

    // ── Rule 8: one function decides (decision 2026-10-24 (removal)) ──

    /// Changes made apart from statement 2 of [`statements`] on device 1:
    /// number 3 each, listing devices 0 and 1 and removing nobody, each
    /// with a secret of its own (21 and on), so that none was made after
    /// another.
    fn renewed_apart(how_many: u8) -> Vec<Statement> {
        let [_, two, ..] = statements(&phrase());
        (0..how_many)
            .map(|n| {
                two.next(key(1), &secret(21 + n), listed(&[0, 1]), &[])
                    .unwrap()
            })
            .collect()
    }

    /// Rule 8, steps 7 and 8, in this slice: a device whose change is not
    /// clear is closed, stored as `fork`, where a clear change that counts
    /// it is set aside (it fails closed until the move of rule 9 is built),
    /// and where none is clear. It keeps the head, and the keys it removes,
    /// which only grow.
    #[test]
    fn test_a_device_whose_change_is_not_clear_is_closed_until_the_move_is_built() {
        let phrase = phrase();
        let [_, two, ..] = statements(&phrase);
        // The fault: device 0 follows a renewal that lists device 2, and is
        // shown a change made apart that removes device 2 and lists it.
        let lists_two = two
            .next(key(0), &secret(13), listed(&[0, 1, 2]), &[])
            .unwrap();
        let removes_two = two
            .next(key(1), &secret(14), listed(&[1, 0]), &[key(2)])
            .unwrap();
        let conn = db::open_in_memory().unwrap();
        let keeps = follow(&conn, 0, &phrase, &lists_two, secret(13));
        assert!(clear(&conn));
        let removal = change(&phrase, &removes_two, secret(14));
        assert_eq!(
            shown(&conn, &device(0), &removal, NOW).unwrap(),
            Shown::Closed
        );
        assert_eq!(state(&conn), State::Fork);
        assert_eq!(kept(&conn, Kept::Latest), Some(keeps.id()));
        assert_eq!(kept(&conn, Kept::Apart), Some(removal.id()));
        assert_eq!(removed(&conn), vec![key(2)]);
        assert_eq!(applied_number(&conn), 3);
        assert_eq!(
            crate::at_relays::stands(&conn).unwrap(),
            crate::at_relays::Stands::Stopped(State::Fork)
        );
        // Closed, it takes a change made after the one it follows, that
        // lists it and is clear, and stands applied again (rule 10).
        let settles = Statement::settle(
            &lists_two,
            &removes_two,
            key(0),
            &secret(15),
            listed(&[0, 1]),
            &[],
        )
        .unwrap();
        let settlement = change(&phrase, &settles, secret(15));
        assert!(matches!(
            shown(&conn, &device(0), &settlement, NOW).unwrap(),
            Shown::Applied(Applied { number: 4, .. })
        ));
        assert_eq!(state(&conn), State::Applied);
        assert_eq!(kept(&conn, Kept::Apart), None);
        // The keys it removes stay removed after the head goes.
        assert_eq!(removed(&conn), vec![key(2)]);

        // Each side removes a different device: neither change is clear.
        let removes_one = two
            .next(key(0), &secret(16), listed(&[0, 2]), &[key(1)])
            .unwrap();
        let conn = db::open_in_memory().unwrap();
        follow(&conn, 0, &phrase, &removes_one, secret(16));
        assert_eq!(
            shown(
                &conn,
                &device(0),
                &change(&phrase, &removes_two, secret(14)),
                NOW
            )
            .unwrap(),
            Shown::Closed
        );
        assert_eq!(state(&conn), State::Fork);
        let mut both = vec![key(1), key(2)];
        both.sort_unstable();
        assert_eq!(removed(&conn), both);
    }

    /// Rule 1: a device keeps the change it follows and up to seven heads
    /// set aside. Where a ninth would be kept, the device is closed, and the
    /// ninth is not kept; its removed keys are kept all the same.
    #[test]
    fn test_a_ninth_head_closes_the_device() {
        let phrase = phrase();
        let apart = renewed_apart(9);
        let conn = db::open_in_memory().unwrap();
        follow(&conn, 0, &phrase, &apart[0], secret(21));
        for (n, statement) in apart.iter().enumerate().skip(1).take(7) {
            let entry = change(&phrase, statement, secret(21 + n as u8));
            assert_eq!(
                shown(&conn, &device(0), &entry, NOW).unwrap(),
                Shown::SetAside,
                "{n}"
            );
        }
        assert_eq!(held_rows::set_aside_entries(&conn).unwrap().len(), 7);
        assert_eq!(state(&conn), State::Applied);
        let mut ninth = apart[8].clone();
        ninth.removed = vec![key(5)];
        ninth.validate().unwrap();
        let entry = change(&phrase, &ninth, secret(29));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Closed
        );
        assert_eq!(state(&conn), State::Fork);
        assert_eq!(held_rows::set_aside_entries(&conn).unwrap().len(), 7);
        assert!(
            !held_rows::set_aside_entries(&conn)
                .unwrap()
                .iter()
                .any(|head| head.entry.id() == entry.id())
        );
        assert_eq!(removed(&conn), vec![key(5)]);
    }

    /// Rule 8 asks the step before each step: each step's outcome, on one
    /// device, in turn, with what it keeps after each (steps 1 to 6).
    #[test]
    fn test_each_step_of_rule_8_in_its_order() {
        let phrase = phrase();
        let [_, two, three, four] = statements(&phrase);
        let conn = db::open_in_memory().unwrap();
        let followed = follow(&conn, 0, &phrase, &three, secret(3));
        // Step 1: the change followed, another entry of its statement, and
        // one behind it.
        assert_eq!(
            shown(&conn, &device(0), &followed, NOW).unwrap(),
            Shown::Held
        );
        let again = change(&phrase, &three, secret(3));
        assert_eq!(
            shown(&conn, &device(0), &again, NOW).unwrap(),
            Shown::Behind
        );
        let behind = change(&phrase, &two, secret(2));
        assert_eq!(
            shown(&conn, &device(0), &behind, NOW).unwrap(),
            Shown::Behind
        );
        // Step 6: one made apart, kept; and one behind that head (step 1).
        let [same_number, higher] = made_apart(&phrase);
        let head = change(&phrase, &higher, secret(14));
        assert_eq!(
            shown(&conn, &device(0), &head, NOW).unwrap(),
            Shown::SetAside
        );
        let behind_the_head = change(&phrase, &same_number, secret(13));
        assert_eq!(
            shown(&conn, &device(0), &behind_the_head, NOW).unwrap(),
            Shown::Behind
        );
        assert_eq!(held_rows::set_aside_entries(&conn).unwrap().len(), 1);
        // Step 4: made after the one followed, it lists device 0 and is
        // clear: applied, with the head kept.
        let entry = change(&phrase, &four, secret(4));
        assert!(matches!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::Applied(_)
        ));
        assert_eq!(kept(&conn, Kept::Apart), Some(head.id()));
        // Step 5: made after it, it lists device 0 in neither list.
        let without = four.next(key(1), &secret(5), listed(&[1, 3]), &[]).unwrap();
        let entry = change(&phrase, &without, secret(5));
        assert_eq!(
            shown(&conn, &device(0), &entry, NOW).unwrap(),
            Shown::NotListed
        );
        assert_eq!(state(&conn), State::NotListed);
    }

    /// Rule 3 into rule 8: a record that hands a removed key the secret the
    /// device follows, taken at the door, closes it in the transaction that
    /// keeps the record, stored as `fork` (rule 10). A reader that seals
    /// nothing, as a recovery's look, is not closed by it.
    #[test]
    fn test_holders_that_grow_with_a_removed_key_close_the_device() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let record = added(&three, 1, 2);
        let name = added_name(&key(2)).unwrap();
        let personal = personal(3);
        let inside = Inside {
            name: name.clone(),
            value: Value::Other(record.to_bytes().unwrap()),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&personal, &device(1), at(3, 1), &inside)
            .unwrap()
            .check()
            .unwrap();
        let reader = under_three();
        crate::take::take_to_read(&reader, &device(0), &entry, NOW).unwrap();
        assert_eq!(state(&reader), State::Applied);
        assert!(!clear(&reader));

        let conn = under_three();
        assert_eq!(state(&conn), State::Applied);
        crate::take::take(&conn, &device(0), &entry, NOW).unwrap();
        assert_eq!(state(&conn), State::Fork);
        assert!(!clear(&conn));
        let at_relays = crate::state::AtRelays::default();
        let look = crate::look::look(&conn, &device(0), &at_relays, NOW).unwrap();
        assert_eq!(look.state, "fork");
        assert_eq!(look.cannot_go_on.as_deref(), Some(crate::look::CLOSED_WHY));
    }

    /// What `cordelia devices` says of the heads set aside (rules 10 and
    /// 11): a device that goes on names each head, with the removed key one
    /// lists and the device on which a change that removed it was made, and
    /// is not stopped; a closed one says the words of rule 10, in red.
    #[test]
    fn test_the_look_names_each_head_and_a_closed_device_says_rule_10() {
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let at_relays = crate::state::AtRelays::default();
        let conn = db::open_in_memory().unwrap();
        follow(&conn, 0, &phrase, &three, secret(3));
        let [apart, ..] = made_apart(&phrase);
        let other = change(&phrase, &apart, secret(13));
        assert_eq!(
            shown(&conn, &device(0), &other, NOW).unwrap(),
            Shown::SetAside
        );
        let look = crate::look::look(&conn, &device(0), &at_relays, NOW + 9).unwrap();
        assert_eq!(look.state, "applied");
        assert_eq!(look.cannot_go_on, None);
        assert_eq!(look.short.as_deref(), Some(crate::look::SET_ASIDE_SHORT));
        assert_eq!(look.set_aside.len(), 1);
        let head = &look.set_aside[0];
        assert_eq!(
            (head.lists.number, head.set_aside_at, head.clear),
            (3, NOW, false)
        );
        assert_eq!(head.lists_removed.len(), 1);
        assert!(
            head.says.starts_with("a change made apart on ")
                && head.says.contains("(change 3) lists ")
                && head.says.contains(", which a change made on ")
                && head.says.ends_with(" removed: it is set aside"),
            "{}",
            head.says
        );
        assert!(look.says.contains(&head.says));
        assert_eq!(look.apart.as_ref(), Some(&head.lists));

        held_rows::set_state(&conn, State::Fork).unwrap();
        let look = crate::look::look(&conn, &device(0), &at_relays, NOW).unwrap();
        assert_eq!(look.state, "fork");
        assert_eq!(
            look.cannot_go_on.as_deref(),
            Some(crate::look::CLOSED_BY_HEADS_WHY)
        );
        assert_eq!(
            crate::look::CLOSED_BY_HEADS_WHY,
            "two changes were made apart, and none that lists this device is clear of a \
             removed device: settle it with the phrase (`cordelia settle`)"
        );
        assert_eq!(look.short.as_deref(), Some("two changes were made apart"));
    }

    /// Rule 12: at its first start on this version a device in a fork
    /// judges the entry it kept apart, which step 22 set aside, by rule 8:
    /// it goes on where the change it follows is clear, stays closed where
    /// it is not, and stops where the other removes it. It notes the time
    /// of what it keeps, and judges once.
    #[test]
    fn test_at_its_first_start_a_device_in_a_fork_judges_what_it_kept() {
        let phrase = phrase();
        let [_, two, three, _] = statements(&phrase);
        let mark = |conn: &Connection| {
            cordelia_storage::meta::set(conn, cordelia_storage::meta::PERSON_JUDGE_KEPT, "1")
                .unwrap();
        };
        // As step 22 leaves a device of the version before that was in a
        // fork: its state, the entry kept apart set aside, and the mark.
        let in_a_fork = |follows: &Statement, of: u8, apart: &Statement, apart_of: u8| {
            let conn = db::open_in_memory().unwrap();
            follow(&conn, 0, &phrase, follows, secret(of));
            let entry = change(&phrase, apart, secret(apart_of));
            held_rows::set_aside(&conn, &entry, NOW).unwrap();
            held_rows::set_state(&conn, State::Fork).unwrap();
            mark(&conn);
            conn
        };

        // Two renewals made apart, both clear: it goes on.
        let apart = renewed_apart(2);
        let conn = in_a_fork(&apart[0], 21, &apart[1], 22);
        assert_eq!(
            judge_kept(&conn, &device(0), NOW).unwrap(),
            Some(Shown::SetAside)
        );
        assert_eq!(state(&conn), State::Applied);
        assert_eq!(held_rows::set_aside_entries(&conn).unwrap().len(), 1);
        let link = apart[0].link().unwrap();
        assert_eq!(
            held_rows::change_time(&conn, link.number, &link.hash).unwrap(),
            Some(Some(NOW))
        );
        // Once: the mark went with it.
        assert!(!held_rows::to_judge_kept(&conn).unwrap());
        assert_eq!(judge_kept(&conn, &device(0), NOW).unwrap(), None);

        // The other removes device 2, which the change it follows lists:
        // it stays closed.
        let lists_two = two
            .next(key(0), &secret(13), listed(&[0, 1, 2]), &[])
            .unwrap();
        let conn = in_a_fork(&lists_two, 13, &three, 3);
        assert_eq!(
            judge_kept(&conn, &device(0), NOW).unwrap(),
            Some(Shown::Closed)
        );
        assert_eq!(state(&conn), State::Fork);
        assert_eq!(removed(&conn), vec![key(2)]);
        assert_eq!(held_rows::set_aside_entries(&conn).unwrap().len(), 1);

        // The other removes device 0: it stops, as removed.
        let removes_zero = two
            .next(key(1), &secret(16), listed(&[1, 2]), &[key(0)])
            .unwrap();
        let conn = in_a_fork(&lists_two, 13, &removes_zero, 16);
        assert_eq!(
            judge_kept(&conn, &device(0), NOW).unwrap(),
            Some(Shown::Removed)
        );
        assert_eq!(state(&conn), State::Removed);

        // A device in no fork notes the time, and judges nothing.
        let conn = device_at(0, 3);
        mark(&conn);
        assert_eq!(judge_kept(&conn, &device(0), NOW).unwrap(), None);
        assert_eq!(state(&conn), State::Applied);
        assert!(!held_rows::to_judge_kept(&conn).unwrap());
    }

    /// Rule 8, steps 4 and 5, where the caller brings a record of this
    /// device's addition: a change made after the one followed that does
    /// not list the device counts it so. Clear, it is applied; not clear,
    /// it is no change in no list, and goes on to step 6. Without the
    /// record the same change stops the device, as in no list.
    #[test]
    fn test_a_change_that_counts_this_device_by_a_record_is_not_in_no_list() {
        let phrase = phrase();
        let [_, two, _, _] = statements(&phrase);
        let drops_zero = two.next(key(1), &secret(17), listed(&[1, 2]), &[]).unwrap();
        let entry = change(&phrase, &drops_zero, secret(17));
        let signed = sign(&drops_zero, &phrase);
        let decided = |conn: &Connection, by_a_record: bool| {
            let held = held(conn).unwrap().unwrap();
            let mut apply = |_: &Held| Ok(Shown::Held);
            in_one(conn, || {
                decide(
                    conn,
                    &device(0),
                    &held,
                    &entry,
                    &signed,
                    by_a_record,
                    &mut apply,
                    NOW,
                )
            })
            .unwrap()
        };

        // Clear: it is applied, by `apply`.
        let conn = device_at(0, 2);
        assert_eq!(decided(&conn, true), Shown::Held);
        assert_eq!(state(&conn), State::Applied);
        // Not clear: device 2, which both list, is known to be removed.
        let conn = device_at(0, 2);
        held_rows::keep_removed(&conn, &[key(2)], NOW).unwrap();
        assert_eq!(decided(&conn, true), Shown::Closed);
        assert_eq!(state(&conn), State::Fork);
        // The control: with no record it is in no list.
        let conn = device_at(0, 2);
        assert_eq!(decided(&conn, false), Shown::NotListed);
        assert_eq!(state(&conn), State::NotListed);
    }

    /// The hold of the node's lock on the hot paths that ask whether the
    /// change followed is clear (decision 2026-10-24 (removal), rule 5): a
    /// read of where the device stands, as `Leave::has` and `keeps` ask it,
    /// and the door, for each entry of a page of 100. Under a statement of
    /// 64 devices with long labels and 200 removed keys, with 200 more kept
    /// as removed. Measured by the lock's own counters (decision 2026-10-22
    /// §1.1), and printed. Run alone, in release:
    /// `cargo test --release -p cordelia-api --lib measure_the_hold -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn measure_the_hold_of_the_paths_that_ask_whether_a_change_is_clear() {
        use cordelia_core::load::{HistogramRead, Kind};
        use cordelia_core::lock::{TimedLock, taking};
        let phrase = phrase();
        let [_, _, three, _] = statements(&phrase);
        let mut devices = listed(&[0, 1]);
        for n in 10..72u16 {
            let label = format!("{:-<60}", format!("device {n}"));
            devices.push(Device::new(key(n), &label).unwrap());
        }
        let removed: Vec<[u8; 32]> = (100..300u16).map(key).collect();
        let big = three.next(key(0), &secret(9), devices, &removed).unwrap();
        let conn = db::open_in_memory().unwrap();
        follow(&conn, 0, &phrase, &big, secret(9));
        hold_name(&conn, "team", NOW).unwrap();
        let more: Vec<[u8; 32]> = (300..500u16).map(key).collect();
        held_rows::keep_removed(&conn, &more, NOW).unwrap();
        assert_eq!(
            crate::at_relays::stands(&conn).unwrap(),
            crate::at_relays::Stands::Applied
        );
        let page: Vec<CheckedEntry> = (0..100u64)
            .map(|n| {
                Entry::seal(
                    &own(9, "team"),
                    &device(1),
                    at(4, 10 + n),
                    &Inside {
                        name: format!("f{n}.md"),
                        value: text("a line"),
                        chain: Some(Vec::new()),
                    },
                )
                .unwrap()
                .check()
                .unwrap()
            })
            .collect();
        let db = TimedLock::new(conn);
        let said = |what: &str, read: HistogramRead| {
            let mut sum = 0;
            let median = read
                .buckets
                .iter()
                .position(|n| {
                    sum += n;
                    sum * 2 >= read.count
                })
                .unwrap();
            println!(
                "{what}: {} takes, mean {:.1} us, median at most {} us, longest {} us",
                read.count,
                read.sum_nanos as f64 / read.count as f64 / 1000.0,
                1u64 << median,
                read.max_micros
            );
        };
        for _ in 0..1000 {
            let _kind = taking(Kind::Pass);
            let guard = db.lock().unwrap();
            crate::at_relays::stands(&guard).unwrap();
        }
        said("stands", db.times().hold(Kind::Pass));
        for entry in &page {
            let _kind = taking(Kind::Cycle);
            let guard = db.lock().unwrap();
            let taken = crate::take::take(&guard, &device(0), entry, NOW).unwrap();
            assert!(
                matches!(
                    taken,
                    crate::take::Taken::Own {
                        stored: Outcome::Stored,
                        ..
                    }
                ),
                "{taken:?}"
            );
        }
        said("the door, a page of 100", db.times().hold(Kind::Cycle));
    }
}
