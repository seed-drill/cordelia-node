//! The door of a shared channel, and its reader (decision 2026-10-10
//! §2.3, §2.4, §6.1 to §6.3).
//!
//! [`taken_as_shared`] is the branch of the door ([`crate::take::take`])
//! that is tried where an entry is of no channel of the person's own, in
//! the same transaction. It takes an entry only of a channel the device
//! holds in its table of shared channels, on a device that stands applied
//! with sync on, and refuses before it stores anything:
//!
//! - **what no honest member writes** (rule 3): a delete; an entry in none
//!   of the 65 slots named for its author (`msg/<author>/0` to `/63` and
//!   `anew/<author>`, each worked out under the channel's slot key); one
//!   whose content is not its slot's size; and one whose revision is not
//!   in the bottom half of band 0. So one key can make a device store at
//!   most 65 entries of one channel, 214,016 bytes as a relay counts them.
//! - **what the room has no place for** (rule 4): an entry in a new slot of
//!   a key that the person does not know, where the keys the person does
//!   not know would then hold more than a relay gives one channel; and an
//!   entry of a key that the table let go, at or below the revisions its
//!   row kept. The person's own devices and the keys the person labelled
//!   are never refused for room.
//!
//! It stores the entry with no check that its signer counts: the signers
//! of a shared channel are other people's devices. What the store keeps,
//! the reader reads in the same write ([`index`]), only where its key is
//! among the 64 this device shows (§2.4, [`Knows::shown`]); an entry of a
//! key beyond them is stored, counted, and opened when its key comes to be
//! shown.
//!
//! [`keep`] keeps the table of shared channels with the person's lists
//! (§3.4): it holds each channel filed in force, begins taking every entry
//! of a channel dropped or moved from out of the store, and of one that no
//! list carries any more, which is then forgotten; it counts a key that
//! stops being known in the room and begins taking the room down to its
//! bound, the keys that stopped being known first; it asks a read again at
//! a label and where a key with bytes refused comes to count; and it opens
//! what waits of a key that comes to be shown. [`hourly`] begins letting a
//! quiet key go, by this device's first holding alone (§6.3).
//!
//! **Every take-out runs in steps** (§6.3, "taken out in steps"; §19, item
//! 19): what starts it is written where it is decided, its first step, so
//! that the door stores nothing more of what goes and the reader shows
//! nothing of a key whose entries are going; [`take_out_step`] then takes
//! out one key's entries at most, `SHARED_TAKE_OUT_STEP_ENTRIES`, in one
//! write, and [`take_out_in_steps`] runs the steps, each under a hold of
//! the device's lock of its own. A take-out cut short by a stop goes on at
//! the next start.

use rusqlite::Connection;

use cordelia_core::protocol::{
    AGENT_MESSAGE_CONTENT_BYTES, AGENT_MESSAGE_KEPT_DAYS, AGENT_MESSAGE_RING,
    MAX_ENTRY_CHANNEL_BYTES_AT_RELAY, REV_BAND_HALF, SHARED_ANEW_CONTENT_BYTES, SHARED_KEYS_KEPT,
    SHARED_MAX_CHANNELS, SHARED_MAX_KEYS, SHARED_READ_AGAIN_SECS, SHARED_TAKE_OUT_STEP_ENTRIES,
    entry_cost,
};
use cordelia_crypto::acts::Came as FiledAs;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{message_id, message_name, message_rev, number_of};
use cordelia_crypto::share::Card;
use cordelia_crypto::shared::{self as forms, Anew, NotShared, SharedTaken, anew_name};
use cordelia_crypto::slots::slot_id;
use cordelia_storage::entries::{self, Outcome};
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, State as HeldState};
use cordelia_storage::shared::{
    self as kept, Came, Channel, ChannelStep, Indexed, Opened, ShownKey, State,
};
use cordelia_storage::shared_pass::{self as pass_rows, ChannelOut};

use crate::person::{Counting, Held, PersonError, held, in_one};
use crate::take::{NotTaken, Taken};

/// How long after this device last first held an entry of a key that the
/// person does not know the key is let go: 30 days (§6.3).
const KEPT_SECS: i64 = AGENT_MESSAGE_KEPT_DAYS as i64 * 24 * 60 * 60;

/// What the reader made of an entry of a shared channel that the store
/// kept (decision 2026-10-10 §2.3, §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    /// A message at a live number, and what became of it in the index.
    Message(Indexed),
    /// The clearing of a number: whether the index held a message there.
    Clearing { dropped: bool },
    /// The signer's anew record, read once for this revision of it.
    Anew(Anew),
    /// An entry at a number that is not live: never opened.
    Overwritten,
    /// An entry that does not open: counted as no message.
    DidNotOpen,
    /// No message: counted, and never shown.
    NotAMessage(NotShared),
    /// Of a key beyond the 64 this device shows: stored and counted, and
    /// opened when its key comes to be shown.
    NotShown,
}

/// Which slot of its author an entry is in, as the door sees it before it
/// opens anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotOf {
    /// `msg/<author>/<n>`.
    Message,
    /// `anew/<author>`.
    Anew,
}

impl SlotOf {
    /// The size of an entry of this slot's kind (§2.3).
    fn content_bytes(self) -> usize {
        match self {
            SlotOf::Message => AGENT_MESSAGE_CONTENT_BYTES,
            SlotOf::Anew => SHARED_ANEW_CONTENT_BYTES,
        }
    }
}

/// Which of its author's 65 slots `slot` is, under the channel's slot key:
/// `None` where it is none of them (decision 2026-10-10 §2.3, rule 3).
fn slot_of(
    slot_key: &[u8; 32],
    author: &[u8; 32],
    slot: &[u8; 32],
) -> Result<Option<SlotOf>, PersonError> {
    if *slot == slot_id(slot_key, &anew_name(author)?) {
        return Ok(Some(SlotOf::Anew));
    }
    for n in 0..AGENT_MESSAGE_RING as u64 {
        if *slot == slot_id(slot_key, &message_name(author, n)?) {
            return Ok(Some(SlotOf::Message));
        }
    }
    Ok(None)
}

/// Who the person knows, as this device holds it (decision 2026-10-10
/// §2.4): its own devices, by the statement and the records of addition,
/// and the keys it labelled; and the keys its statement lists as removed.
/// Nothing a member writes enters it.
pub(crate) struct Knows {
    counting: Counting,
    removed: Vec<[u8; 32]>,
    /// The person's own devices that count: in the order of the statement
    /// and then of their additions.
    devices: Vec<[u8; 32]>,
    /// The keys labelled, by acts in force, in the order the labels were
    /// made.
    labels: Vec<[u8; 32]>,
}

impl Knows {
    pub(crate) fn of(conn: &Connection, held: &Held) -> Result<Self, PersonError> {
        let statement = &held.statement.statement;
        let additions = held_rows::additions(conn)?;
        let counting = Counting::of(statement, &additions);
        let mut devices: Vec<[u8; 32]> = Vec::new();
        let listed = statement.devices.iter().map(|device| device.key);
        for key in listed.chain(additions.iter().map(|record| record.key)) {
            if counting.counts(&key) && !devices.contains(&key) {
                devices.push(key);
            }
        }
        let mut labels: Vec<_> = crate::lists::holds(conn)?
            .labels
            .into_iter()
            .filter(|(act, _)| act.item.label.is_some())
            .map(|(act, _)| act)
            .collect();
        labels.sort_by_key(|act| (act.time, act.count, act.maker));
        let removed = statement.removed.clone();
        let labels = labels
            .into_iter()
            .map(|act| act.item.key)
            .filter(|key| !removed.contains(key))
            .collect();
        Ok(Self {
            counting,
            removed,
            devices,
            labels,
        })
    }

    /// Whether `key` is one the person knows: one of its own devices that
    /// counts, or a key it labelled.
    pub(crate) fn knows(&self, key: &[u8; 32]) -> bool {
        self.counting.counts(key) || self.labels.contains(key)
    }

    /// The keys this device shows in the channel of row `id`, in the one
    /// order of §2.4, up to 64: every key labelled, in the order the
    /// labels were made; then the person's own devices; then every other
    /// key whose entries the store holds, in the order this device first
    /// held an entry of it there (a key let go has nothing to show). A
    /// key the person's statement lists as removed is shown nothing.
    pub(crate) fn shown(&self, conn: &Connection, id: i64) -> Result<Vec<ShownKey>, PersonError> {
        let mut shown: Vec<[u8; 32]> = Vec::with_capacity(SHARED_MAX_KEYS);
        let room = SHARED_MAX_KEYS + self.labels.len() + self.devices.len() + self.removed.len();
        let others = kept::keys_held_in_order(conn, id, room)?;
        for key in self.labels.iter().chain(&self.devices).chain(&others) {
            if shown.len() == SHARED_MAX_KEYS {
                break;
            }
            if !shown.contains(key) && !self.removed.contains(key) {
                shown.push(*key);
            }
        }
        Ok(shown
            .into_iter()
            .map(|key| ShownKey {
                key,
                unlabelled: !self.knows(&key),
            })
            .collect())
    }
}

/// The secret of the channel of `row`, from its card.
fn secret_of(row: &Channel) -> Result<[u8; 32], PersonError> {
    let card = Card::from_bytes(&row.card)
        .map_err(|e| PersonError::Held(format!("the card of a shared channel: {e}")))?;
    Ok(card.secret()?)
}

/// What becomes of `entry`, of no channel of the person's own, as an entry
/// of a shared channel (decision 2026-10-10 §2.3), in the caller's
/// transaction: `None` where it is of no channel that this device holds in
/// its table of shared channels (rule 1), and nothing was done with it.
pub(crate) fn taken_as_shared(
    conn: &Connection,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Option<Taken>, PersonError> {
    let Some(row) = kept::channel(conn, &entry.channel)? else {
        return Ok(None);
    };
    if row.state != State::Held {
        return Ok(None);
    }
    let refused = |why: NotTaken| Ok(Some(Taken::Refused(why)));
    // Rule 2: as the person's own channels are, and sync off turns a
    // shared channel off as it turns messages off (§6.1).
    let Some(held) = held(conn)? else {
        return refused(NotTaken::FollowsNoPhrase);
    };
    if held.state != HeldState::Applied {
        return refused(NotTaken::Stopped(held.state));
    }
    if meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none() {
        return refused(NotTaken::SyncOff);
    }

    // Rule 3, on what the entry carries in clear, before anything is
    // stored or opened.
    if entry.delete {
        return refused(NotTaken::NotAShared);
    }
    let secret = secret_of(&row)?;
    let slot_key = derive::slot_key(&secret)?;
    let Some(kind) = slot_of(&slot_key, &entry.author, &entry.slot)? else {
        return refused(NotTaken::NotAShared);
    };
    if entry.content.len() != kind.content_bytes() {
        return refused(NotTaken::NotAShared);
    }
    // A shared channel is of no statement: a plain comparison, and never
    // `revision::may_be_under`.
    if entry.rev >= REV_BAND_HALF {
        return refused(NotTaken::NotInBandZero);
    }

    // Rule 4: the room of the keys the person does not know.
    let knows = Knows::of(conn, &held)?;
    let known = knows.knows(&entry.author);
    // A key whose entries are being taken out (§6.3, "taken out in
    // steps"). One the person now knows is taken out no more: its
    // take-out ends here, and its entry is stored. Of one it does not
    // know, the door stores nothing more, and notes the bytes as refused,
    // so that the step that ends its take-out asks a read again: an entry
    // newer than any it held of that slot, and than what a row kept.
    let held_there = entries::author_cost(conn, &entry.channel, &entry.slot, &entry.author)?;
    if pass_rows::key_going(conn, row.id, &entry.author)? {
        if known {
            pass_rows::key_ended(conn, row.id, &entry.author)?;
        } else {
            let row_of = kept::key(conn, row.id, &entry.author)?;
            let kept_rev = row_of.and_then(|of| match kind {
                SlotOf::Message => of.kept_message_rev,
                SlotOf::Anew => of.kept_anew_rev,
            });
            let newer = held_there.is_none_or(|(rev, _)| entry.rev > rev)
                && kept_rev.is_none_or(|kept_rev| entry.rev > kept_rev);
            if newer {
                let cost = entry_cost(entry.content.len());
                kept::refused(conn, row.id, &entry.author, cost, now)?;
            }
            return refused(NotTaken::SharedFull);
        }
    }
    if !known {
        let row_of = kept::key(conn, row.id, &entry.author)?;
        let kept_rev = row_of.and_then(|of| match kind {
            SlotOf::Message => of.kept_message_rev,
            SlotOf::Anew => of.kept_anew_rev,
        });
        // An entry taken out is never stored again (§6.3): no row is
        // noted and no read again is asked.
        if kept_rev.is_some_and(|kept_rev| entry.rev <= kept_rev) {
            return refused(NotTaken::SharedFull);
        }
        let cost = entry_cost(entry.content.len());
        if held_there.is_none()
            && kept::room(conn, row.id)? + cost > MAX_ENTRY_CHANNEL_BYTES_AT_RELAY
        {
            kept::refused(conn, row.id, &entry.author, cost, now)?;
            kept::keep_rows_within(conn, row.id, SHARED_KEYS_KEPT)?;
            return refused(NotTaken::SharedFull);
        }
    }

    // Rule 5: stored with no check that its signer counts.
    let stored = entries::store(conn, entry, now)?;
    if stored != Outcome::Stored {
        return Ok(Some(Taken::Shared { stored, read: None }));
    }
    let replaced = held_there.map_or(0, |(_, cost)| cost);
    let more = i64::try_from(entry_cost(entry.content.len())).unwrap_or(i64::MAX)
        - i64::try_from(replaced).unwrap_or(i64::MAX);
    kept::stored(conn, row.id, &entry.author, known, more, now)?;

    // Rule 6: only an entry of a key the device shows is opened.
    let shown = knows.shown(conn, row.id)?;
    let read = if shown.iter().any(|key| key.key == entry.author) {
        index(conn, &row, &secret, entry, now)?
    } else {
        kept::unopened(conn, row.id, &entry.author, &entry.slot)?;
        Read::NotShown
    };
    Ok(Some(Taken::Shared {
        stored,
        read: Some(read),
    }))
}

/// Read `entry`, an entry of the shared channel of `row` whose secret is
/// `secret`, which the store has just kept and whose key the device shows
/// (decision 2026-10-10 §2.3, §6.1): as the messages record's reader reads
/// an entry of the messages channel (`crate::reader::taken`), in the
/// caller's write. A message is written into the index of shared
/// messages, keyed by the channel and its ID; a clearing drops the row it
/// clears; an anew record is read once for this revision of it; anything
/// else is counted as no message.
pub fn index(
    conn: &Connection,
    row: &Channel,
    secret: &[u8; 32],
    entry: &CheckedEntry,
    now: i64,
) -> Result<Read, PersonError> {
    let slot_key = derive::slot_key(secret)?;
    let signer = entry.author;
    let is_anew = entry.slot == slot_id(&slot_key, &anew_name(&signer)?);
    let number = number_of(entry.rev);
    let in_its_slot = !is_anew
        && message_rev(number).is_some()
        && entry.slot == slot_id(&slot_key, &message_name(&signer, number)?);
    let no_message = |why: NotShared| -> Result<Read, PersonError> {
        kept::not_a_message(conn, row.id, &signer)?;
        Ok(Read::NotAMessage(why))
    };
    if !is_anew && !in_its_slot {
        return no_message(NotShared::NotInItsSlots);
    }
    let clearing = entry.rev % 2 == 1;
    if in_its_slot && !kept::hold_number(conn, row.id, &signer, number, clearing)? {
        return Ok(Read::Overwritten);
    }
    let Ok(inside) = entry.open(secret) else {
        kept::not_a_message(conn, row.id, &signer)?;
        return Ok(Read::DidNotOpen);
    };
    match forms::take(&inside.name, &signer, entry.rev, &inside.value) {
        Ok(SharedTaken::Message { number, message }) => {
            let Value::Other(value) = &inside.value else {
                return no_message(NotShared::NotInItsSlots);
            };
            let id = message_id(&signer, value);
            let opened = Opened {
                channel: row.id,
                id: &id,
                signer: &signer,
                number,
                message: &message,
                first_held: now,
                placed_at: None,
            };
            Ok(Read::Message(kept::index(conn, &opened)?))
        }
        Ok(SharedTaken::Clearing { number }) => Ok(Read::Clearing {
            dropped: kept::clear(conn, row.id, &signer, number, now)?,
        }),
        Ok(SharedTaken::Anew(record)) => Ok(Read::Anew(record)),
        Err(why) => no_message(why),
    }
}

/// Keep the table of shared channels with what this device holds of the
/// person's lists and of who the person knows, at `now` (decision
/// 2026-10-10 §3.4, §6.3), in one transaction. Run where the lists or who
/// counts may have changed: at an act, at a whole fetch, where the door
/// applied a statement or a key came to count, and in the hourly task. A
/// device that follows no phrase keeps nothing.
pub fn keep(conn: &Connection, own: &[u8; 32], now: i64) -> Result<(), PersonError> {
    in_one(conn, || {
        let Some(held) = held(conn)? else {
            return Ok(());
        };
        follow_the_lists(conn, own, now)?;
        let knows = Knows::of(conn, &held)?;
        let seen = kept::labelled(conn)?;
        let newly_labelled = knows.labels.iter().any(|key| !seen.contains(key));
        let mut labelled = knows.labels.clone();
        labelled.sort();
        kept::set_labelled(conn, &labelled)?;
        for row in kept::channels(conn)? {
            if row.state != State::Held {
                continue;
            }
            // A read again at every label, whether or not the key has a
            // row (§6.3).
            if newly_labelled {
                kept::ask_read_again(conn, row.id, now)?;
            }
            keep_known(conn, &knows, &row, now)?;
            open_shown(conn, &knows, &row, now)?;
        }
        Ok(())
    })
}

/// Hold each channel filed in force; begin taking every entry of a channel
/// dropped or moved from out of the store, with every row of a drop and
/// every row but the index of a move, and of a channel the lists hold no
/// valid act on, which is forgotten at the end (decision 2026-10-10 §3.4,
/// §6.3). What is in force, and
/// what a bound leaves out, is worked out from the lists the device reads
/// (`lists::holds_worked_out`). Of the channels moved from, the index
/// stays for the 16 moved from last.
fn follow_the_lists(conn: &Connection, own: &[u8; 32], now: i64) -> Result<(), PersonError> {
    let holds = crate::lists::holds_worked_out(conn, own, now)?;
    let filed: Vec<_> = holds.filings.iter().map(|(act, _)| &act.item).collect();
    let dropped: Vec<[u8; 32]> = holds
        .drops
        .iter()
        .map(|(act, _)| act.item.channel)
        .collect();
    let mut anywhere: Vec<[u8; 32]> = holds
        .filings
        .iter()
        .map(|(act, _)| act.item.channel)
        .chain(holds.drops.iter().map(|(act, _)| act.item.channel))
        .collect();
    for (act, _) in &holds.left_out {
        if let crate::lists::AnyAct::Filing(filing) = act {
            anywhere.push(filing.item.channel);
        }
    }
    for filing in &filed {
        // A channel whose every entry is being taken out is held again
        // only once the take-out has ended: what the door stored meanwhile
        // would go with the rest.
        let going = match kept::channel(conn, &filing.channel)? {
            Some(row) => pass_rows::channel_out(conn, row.id)?.is_some(),
            None => false,
        };
        if going {
            continue;
        }
        let came = match filing.came {
            FiledAs::Made => Came::Made,
            FiledAs::Taken(key) => Came::Taken(key),
            FiledAs::Moved(from) => Came::Moved(from),
        };
        kept::hold(
            conn,
            &filing.channel,
            &filing.card.to_bytes(),
            &filing.name,
            came,
            now,
        )?;
    }
    for row in kept::channels(conn)? {
        if filed.iter().any(|filing| filing.channel == row.channel) {
            continue;
        }
        // What starts a take-out is written here, its first step: the
        // state, so that the door stores nothing more of the channel, and
        // the take-out begun. Its entries go in steps ([`take_out_step`]).
        if dropped.contains(&row.channel) {
            let moved = filed
                .iter()
                .any(|filing| filing.came == FiledAs::Moved(row.channel));
            if matches!(row.state, State::Held | State::NotInForce) {
                let (state, how) = match moved {
                    true => (State::Moved, ChannelOut::Moved),
                    false => (State::Dropped, ChannelOut::Dropped),
                };
                kept::set_state(conn, row.id, state, now)?;
                pass_rows::begin_channel(conn, row.id, how)?;
            }
        } else if anywhere.contains(&row.channel) {
            if row.state == State::Held {
                kept::set_state(conn, row.id, State::NotInForce, now)?;
            }
        } else {
            if matches!(row.state, State::Held | State::NotInForce) {
                kept::set_state(conn, row.id, State::Dropped, now)?;
            }
            pass_rows::begin_channel(conn, row.id, ChannelOut::Forgotten)?;
        }
    }
    let mut moved: Vec<Channel> = kept::channels(conn)?
        .into_iter()
        .filter(|row| row.state == State::Moved)
        .collect();
    moved.sort_by_key(|row| std::cmp::Reverse((row.left_at, row.id)));
    for older in moved.iter().skip(SHARED_MAX_CHANNELS) {
        kept::drop_index(conn, older.id)?;
    }
    Ok(())
}

/// Keep what each key of the channel of `row` is to the person (decision
/// 2026-10-10 §6.3): a key that stops being known is counted in the room
/// from now, and where the room is then past its bound, less what the
/// take-outs begun will free, a take-out is begun of the entries of the
/// keys that stopped being known first, and then of the keys it first held
/// last, down to the bound, their bytes to be noted as refused. A key
/// with bytes refused that comes to be known is read again.
/// The table keeps at most 1,024 rows of keys that store nothing.
fn keep_known(
    conn: &Connection,
    knows: &Knows,
    row: &Channel,
    now: i64,
) -> Result<(), PersonError> {
    for key in kept::keys(conn, row.id)? {
        let known = knows.knows(&key.key);
        if known == key.known {
            continue;
        }
        kept::set_known(conn, row.id, &key.key, known, now)?;
        // A key the person comes to know is taken out no more.
        if known {
            pass_rows::key_ended(conn, row.id, &key.key)?;
        }
        if known && key.bytes_refused > 0 {
            kept::ask_read_again(conn, row.id, now)?;
        }
    }
    // What the take-outs begun will free is counted as gone already.
    let going = pass_rows::going_from_room(conn, row.id)?;
    let mut room = kept::room(conn, row.id)?.saturating_sub(going);
    if room > MAX_ENTRY_CHANNEL_BYTES_AT_RELAY {
        let mut out: Vec<kept::Key> = Vec::new();
        for key in kept::keys(conn, row.id)? {
            if !key.known && key.bytes_stored > 0 && !pass_rows::key_going(conn, row.id, &key.key)?
            {
                out.push(key);
            }
        }
        out.sort_by_key(|key| {
            (
                key.unknown_since.is_none(),
                key.unknown_since,
                std::cmp::Reverse(key.held_order),
            )
        });
        // Begun here, the keys that stopped being known first; each key's
        // entries go in a step of its own, their bytes noted as refused.
        for key in out {
            if room <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY {
                break;
            }
            pass_rows::begin_key(conn, row.id, &key.key, true)?;
            room = room.saturating_sub(key.bytes_stored);
        }
    }
    kept::keep_rows_within(conn, row.id, SHARED_KEYS_KEPT)?;
    Ok(())
}

/// Open what waits of each key the channel of `row` now shows (decision
/// 2026-10-10 §2.3, rule 6): each entry the store holds of it and the
/// reader has not read, by revision.
fn open_shown(
    conn: &Connection,
    knows: &Knows,
    row: &Channel,
    now: i64,
) -> Result<(), PersonError> {
    let waiting_keys: Vec<[u8; 32]> = kept::waiting_to_open(conn, row.id)?
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    if waiting_keys.is_empty() {
        return Ok(());
    }
    let secret = secret_of(row)?;
    for shown in knows.shown(conn, row.id)? {
        if !waiting_keys.contains(&shown.key) {
            continue;
        }
        let mut waiting: Vec<CheckedEntry> = Vec::new();
        for slot in kept::to_open(conn, row.id, &shown.key)? {
            let Some(held) = entries::author_entry(conn, &row.channel, &slot, &shown.key)? else {
                continue;
            };
            if let Ok(entry) = Entry::check(held.entry) {
                waiting.push(entry);
            }
        }
        waiting.sort_by_key(|entry| entry.rev);
        for entry in &waiting {
            index(conn, row, &secret, entry, now)?;
        }
    }
    Ok(())
}

/// What the hourly task did of the shared channels ([`hourly`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hourly {
    /// The keys let go as quiet.
    pub let_go: usize,
    /// The index rows that went at their 30 days, or held at no live
    /// number.
    pub gone: usize,
}

/// The shared channels' part of the hourly task, at `now` (decision
/// 2026-10-10 §6.3), whatever the device's state: the table is kept with
/// the lists ([`keep`]); then, in each channel held, a take-out is begun of
/// every entry of a key the person does not know of which this device has
/// first held no entry there in the last 30 days, whatever the entries
/// say, and where that makes room in a channel where a key has bytes
/// refused, the channel is read again; then what has expired, or is not
/// live, goes from the index. The keys go in steps ([`take_out_in_steps`]),
/// each row keeping the revisions it held, and the table is kept again
/// once they have gone, so that what waits of a key now shown in a let-go
/// key's place is opened.
pub fn hourly(conn: &Connection, own: &[u8; 32], now: i64) -> Result<Hourly, PersonError> {
    keep(conn, own, now)?;
    in_one(conn, || {
        let mut done = Hourly::default();
        for row in kept::channels(conn)? {
            if row.state != State::Held {
                continue;
            }
            // The choice of quiet keys is written here, in one statement,
            // the take-out's first step; each key's entries go in a step of
            // its own ([`take_out_step`]).
            let quiet = pass_rows::begin_quiet_keys(conn, row.id, now - KEPT_SECS)?;
            if quiet == 0 {
                continue;
            }
            done.let_go += quiet;
            if kept::any_refused(conn, row.id)? {
                kept::ask_read_again(conn, row.id, now)?;
            }
        }
        done.gone = kept::drop_gone(conn, now)?;
        Ok(done)
    })
}

/// What one step of a take-out did ([`take_out_step`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stepped {
    /// Nothing was begun and not ended.
    Nothing,
    /// One key's entries went from a channel that stays: a key let go, or
    /// one that stopped being known.
    Key,
    /// One key's entries, or one signer's index rows, went from a channel
    /// dropped, moved from or forgotten; or such a take-out ended.
    OfAChannel,
}

/// One step of the take-outs begun and not ended, at `now` (decision
/// 2026-10-10 §6.3, "taken out in steps"; §19, item 19), in one write:
/// one key's entries at most, `SHARED_TAKE_OUT_STEP_ENTRIES`, with its
/// index rows and what waits to be opened of it, and, for a key of a
/// channel that stays, the revisions its row keeps. So a key is never half
/// taken out, and the door's refusal at or below its kept revisions holds
/// from the step that took it. A key's take-out comes before a channel's.
/// The caller holds the lock for this step alone.
pub fn take_out_step(conn: &Connection, now: i64) -> Result<Stepped, PersonError> {
    in_one(conn, || {
        if let Some((id, key, as_refused)) = pass_rows::next_key_out(conn)? {
            let row = kept::channel_of_row(conn, id)?;
            let going_whole = pass_rows::channel_out(conn, id)?.is_some();
            if let Some(row) = row.filter(|_| !going_whole) {
                // A key the person came to know since its take-out was
                // begun is taken out no more: its take-out ends here.
                let known = match held(conn)? {
                    Some(held) => Knows::of(conn, &held)?.knows(&key),
                    None => false,
                };
                pass_rows::key_ended(conn, id, &key)?;
                if known {
                    return Ok(Stepped::Key);
                }
                let slot_key = derive::slot_key(&secret_of(&row)?)?;
                let anew_slot = slot_id(&slot_key, &anew_name(&key)?);
                let refused_before = kept::key(conn, id, &key)?.map_or(0, |of| of.bytes_refused);
                kept::take_out(conn, id, &row.channel, &key, &anew_slot, as_refused, now)?;
                // A quiet key refused something while it went: read again,
                // so that what it wrote meanwhile is stored.
                if !as_refused && refused_before > 0 {
                    kept::ask_read_again(conn, id, now)?;
                }
                kept::keep_rows_within(conn, id, SHARED_KEYS_KEPT)?;
            } else {
                pass_rows::key_ended(conn, id, &key)?;
            }
            return Ok(Stepped::Key);
        }
        let Some((id, how)) = pass_rows::next_channel_out(conn)? else {
            return Ok(Stepped::Nothing);
        };
        let Some(row) = kept::channel_of_row(conn, id)? else {
            pass_rows::channel_ended(conn, id)?;
            return Ok(Stepped::OfAChannel);
        };
        let index_too = how != ChannelOut::Moved;
        let step = kept::take_out_channel_step(
            conn,
            id,
            &row.channel,
            index_too,
            SHARED_TAKE_OUT_STEP_ENTRIES,
        )?;
        if step == ChannelStep::Done {
            match how {
                ChannelOut::Forgotten => kept::forget(conn, id)?,
                ChannelOut::Dropped | ChannelOut::Moved => {
                    kept::drop_rows(conn, id, how == ChannelOut::Moved)?;
                    pass_rows::forget(conn, id)?;
                }
            }
        }
        Ok(Stepped::OfAChannel)
    })
}

/// Every take-out begun and not ended, ended in steps, each under a hold of
/// the lock `db` of its own, the lock let go between steps (decision
/// 2026-10-10 §6.3, §8.4; §19, item 19): so no hold of it is more than one
/// key's entries. Once they have gone, the table is kept again, in a hold
/// of its own: what waits of a key that comes to be shown in a let-go key's
/// place is opened, and a channel filed again while its entries went is
/// held again. Returns how many steps
/// there were. Whoever calls says the kind of its takes of the lock.
pub fn take_out_in_steps(
    db: &cordelia_core::lock::TimedLock<Connection>,
    own: &[u8; 32],
    now: i64,
) -> Result<usize, PersonError> {
    use cordelia_core::lock::LockWhole;
    let mut steps = 0;
    // A keeping that begins another take-out is followed by its steps: a
    // few rounds at most, since each keeping begins only what brings the
    // room within its bound.
    for _ in 0..4 {
        let before = steps;
        while take_out_step(&db.lock_whole(), now)? != Stepped::Nothing {
            steps += 1;
        }
        if steps == before {
            break;
        }
        let conn = db.lock_whole();
        keep(&conn, own, now)?;
        if !pass_rows::any_going(&conn)? {
            break;
        }
    }
    Ok(steps)
}

/// [`take_out_in_steps`], on a connection the caller holds: every step,
/// one after another. For a caller that holds the store whole, and for
/// tests.
pub fn take_out_all(conn: &Connection, own: &[u8; 32], now: i64) -> Result<usize, PersonError> {
    let mut steps = 0;
    for _ in 0..4 {
        let before = steps;
        while take_out_step(conn, now)? != Stepped::Nothing {
            steps += 1;
        }
        if steps == before {
            break;
        }
        keep(conn, own, now)?;
        if !pass_rows::any_going(conn)? {
            break;
        }
    }
    Ok(steps)
}

/// The shared channels to read again from their start at `now`: each
/// held, with a read again asked, and none begun in the day before
/// (decision 2026-10-10 §6.3, `SHARED_READ_AGAIN_SECS`). One asked within
/// that day is given when the day is up. The pass begins each with
/// [`read_again_begun`].
pub fn read_again_due(conn: &Connection, now: i64) -> Result<Vec<[u8; 32]>, PersonError> {
    let again = i64::try_from(SHARED_READ_AGAIN_SECS).unwrap_or(i64::MAX);
    Ok(kept::read_again_due(conn, now, again)?
        .into_iter()
        .map(|row| row.channel)
        .collect())
}

/// The read again of the shared channel `channel` begins at `now`.
pub fn read_again_begun(
    conn: &Connection,
    channel: &[u8; 32],
    now: i64,
) -> Result<(), PersonError> {
    if let Some(row) = kept::channel(conn, channel)? {
        kept::read_again_begun(conn, row.id, now)?;
    }
    Ok(())
}

/// Every message of the shared channel `channel` that this device shows at
/// `now`, oldest first, once places are given as a show gives them
/// (decision 2026-10-10 §2.4): of the keys it shows, with a place by the
/// reader's rate and, for the keys the person has not labelled, among 64
/// in an hour for all of them. Of a channel moved from, what it showed,
/// until each expires. Nothing where the device holds no such channel, or
/// follows no phrase.
pub fn shown(
    conn: &Connection,
    identity: &NodeIdentity,
    channel: &[u8; 32],
    now: i64,
) -> Result<Vec<kept::Shown>, PersonError> {
    in_one(conn, || {
        let (Some(held), Some(row)) = (held(conn)?, kept::channel(conn, channel)?) else {
            return Ok(Vec::new());
        };
        let knows = Knows::of(conn, &held)?;
        // A channel moved from shows what it showed, until each expires,
        // and gives no place (§6.3).
        if row.state == State::Moved {
            let keys: Vec<[u8; 32]> = kept::index_signers(conn, row.id)?
                .into_iter()
                .filter(|key| !knows.removed.contains(key))
                .collect();
            return Ok(kept::shown(conn, row.id, &keys, now)?);
        }
        let keys = knows.shown(conn, row.id)?;
        kept::give_places(conn, row.id, &identity.public_key(), &keys, now)?;
        let keys: Vec<[u8; 32]> = keys.iter().map(|key| key.key).collect();
        Ok(kept::shown(conn, row.id, &keys, now)?)
    })
}

/// The keys this device shows in the shared channel `channel`, in order:
/// nothing where it holds no such channel, or follows no phrase.
pub fn shown_keys(conn: &Connection, channel: &[u8; 32]) -> Result<Vec<[u8; 32]>, PersonError> {
    let (Some(held), Some(row)) = (held(conn)?, kept::channel(conn, channel)?) else {
        return Ok(Vec::new());
    };
    Ok(Knows::of(conn, &held)?
        .shown(conn, row.id)?
        .into_iter()
        .map(|key| key.key)
        .collect())
}

/// What the judge of a share made of an entry that the typed key signed
/// in its share pair channel ([`accept_typed`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judged {
    /// A share by rules 1 to 8 of §3.2: one that may be taken, where it is
    /// the one.
    Share(Box<CheckedEntry>),
    /// No share that may be taken, and why.
    Not(NotAShare),
}

/// Why an entry of a share pair channel is no share to take (decision
/// 2026-10-10 §3.2, rules 2 to 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAShare {
    /// Rule 2: not of the share pair channel of the typed key and this
    /// device, or it does not open there.
    NotThePairChannel,
    /// Rule 3: another key signed it.
    SignedByAnotherKey,
    /// Rule 4: a delete, another name, or no share of the right length and
    /// form, with a card of the form of 2.1.
    NotAShare,
    /// Rule 5: made an hour or more before or after the key was typed.
    NotMadeWithinTheHour,
    /// Rule 6: for another device.
    NotForThisDevice,
    /// Rule 8: the card gives another ID than its name says.
    AnotherChannel,
}

/// Judge `entry`, handed from the share pair channel of the key `key`
/// typed for a channel at `typed_at`, by rules 1 to 8 of §3.2 (decision
/// 2026-10-10 §2.3, "the entries of a share pair channel never come through
/// the door"): nothing is stored, and nothing is taken here. Which of the
/// shares found is taken, and rules 9 to 11, are
/// [`crate::sharing::take_share`]'s.
///
/// `None` where the key reads nothing now (rule 1): it was not typed for a
/// channel at `typed_at`, a share was taken under that typing, or its hour
/// has gone.
pub fn accept_typed(
    conn: &Connection,
    identity: &NodeIdentity,
    key: &[u8; 32],
    typed_at: i64,
    entry: &CheckedEntry,
    now: i64,
) -> Result<Option<Judged>, PersonError> {
    use cordelia_crypto::share::{Share, share_name};
    use cordelia_storage::shared_sharing as typed_rows;
    // Rule 1.
    let reads = typed_rows::typed_key(conn, key)?.is_some_and(|row| {
        row.typed_at == typed_at
            && row.taken.is_none()
            && crate::adding::within_its_hour(row.typed_at, now)
    });
    if !reads {
        return Ok(None);
    }
    let not = |why: NotAShare| Ok(Some(Judged::Not(why)));
    // Rule 2: the share pair channel of the typed key and this device.
    let Some((pair, secret)) = crate::shared_pass::share_pair(identity, key) else {
        return not(NotAShare::NotThePairChannel);
    };
    if entry.channel != pair {
        return not(NotAShare::NotThePairChannel);
    }
    // Rule 3.
    if entry.author != *key {
        return not(NotAShare::SignedByAnotherKey);
    }
    if entry.delete {
        return not(NotAShare::NotAShare);
    }
    let Ok(inside) = entry.open(&secret) else {
        return not(NotAShare::NotThePairChannel);
    };
    // Rule 4.
    let Ok(share) = Share::from_value(&inside.value) else {
        return not(NotAShare::NotAShare);
    };
    let Some(named) = inside
        .name
        .strip_prefix(cordelia_core::protocol::SHARE_PREFIX)
        .and_then(|id| hex::decode(id).ok())
        .and_then(|id| <[u8; 32]>::try_from(id).ok())
    else {
        return not(NotAShare::NotAShare);
    };
    if inside.name != share_name(&named) {
        return not(NotAShare::NotAShare);
    }
    // Rule 5.
    if !crate::adding::made_within_the_hour(share.made, typed_at) {
        return not(NotAShare::NotMadeWithinTheHour);
    }
    // Rule 6.
    if share.for_key != identity.public_key() {
        return not(NotAShare::NotForThisDevice);
    }
    // Rule 8.
    if share.card.channel_id()? != named {
        return not(NotAShare::AnotherChannel);
    }
    Ok(Some(Judged::Share(Box::new(entry.clone()))))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::lists::{Do, Done, act, tests::filing};
    use crate::several::{Several, entry_by};
    use crate::take::take;
    use cordelia_core::protocol::{AGENT_MESSAGE_VALUE_BYTES, SHARED_ANEW_VALUE_BYTES};
    use cordelia_crypto::acts::{Came as Filed, Label};
    use cordelia_crypto::message::clearing_rev;
    use cordelia_crypto::shared::SharedMessage;

    pub(crate) const HOUR: i64 = 60 * 60;
    pub(crate) const DAY: i64 = 24 * HOUR;

    /// What one entry of each kind is counted at, as a relay counts it.
    pub(crate) const MESSAGE_COST: u64 = entry_cost(AGENT_MESSAGE_CONTENT_BYTES);
    pub(crate) const ANEW_COST: u64 = entry_cost(SHARED_ANEW_CONTENT_BYTES);

    /// What is left of a channel's room when [`fill_to`] fills it full: 963
    /// anew records and four messages, with no room for a fifth.
    pub(crate) const FULL: u64 = 1_024;

    /// A shared channel, as a test writes in it: its secret and its ID.
    #[derive(Clone, Copy)]
    pub(crate) struct Shared {
        pub(crate) secret: [u8; 32],
        pub(crate) id: [u8; 32],
    }

    impl Shared {
        /// The channel of the card made from `seed`.
        pub(crate) fn of(seed: u8) -> Self {
            let card = filing(seed, "x").card;
            Self {
                secret: card.secret().unwrap(),
                id: card.channel_id().unwrap(),
            }
        }
    }

    /// The key of member `n`: a device of another person's.
    pub(crate) fn member(n: u32) -> NodeIdentity {
        let mut seed = [0x4d; 32];
        seed[..4].copy_from_slice(&n.to_be_bytes());
        NodeIdentity::from_seed(seed).unwrap()
    }

    /// `count` devices of one person, Bob's, each with sync on.
    pub(crate) fn bob(count: u16) -> Several {
        let s = Several::of_one_person(count);
        for machine in &s.machines {
            meta::set(&machine.conn, meta::SYNC_CLAUDE_DIR, "/home/bob/.claude").unwrap();
        }
        s
    }

    /// Device `n` does `what` at `now`, and it is made; the take-outs it
    /// began are ended, as the node's next pass ends them.
    pub(crate) fn acts(s: &Several, n: usize, what: Do, now: i64) {
        let done = act(&s[n].conn, &s[n].identity, what, now).unwrap();
        assert!(matches!(done, Done::Made(_)), "{done:?}");
        out(s, n, now);
    }

    /// Device `n` ends every take-out begun, step by step, at `now`: as the
    /// node's pass does, each step under a hold of the lock of its own.
    pub(crate) fn out(s: &Several, n: usize, now: i64) {
        take_out_all(&s[n].conn, &s.key(n), now).unwrap();
    }

    /// The shared channels' part of the hourly task ([`super::hourly`]),
    /// and the take-outs it began ended in steps, as the node's hourly task
    /// does.
    pub(crate) fn hourly(
        conn: &Connection,
        own: &[u8; 32],
        now: i64,
    ) -> Result<Hourly, PersonError> {
        let done = super::hourly(conn, own, now)?;
        take_out_all(conn, own, now)?;
        Ok(done)
    }

    /// Device `n` files the channel of the card made from `seed` as `name`.
    pub(crate) fn holds(s: &Several, n: usize, seed: u8, name: &str, now: i64) -> Shared {
        acts(s, n, Do::File(filing(seed, name)), now);
        Shared::of(seed)
    }

    /// Device `n` labels `key`, or takes its label away.
    pub(crate) fn labels(s: &Several, n: usize, key: &[u8; 32], label: Option<&str>, now: i64) {
        let label = Label {
            key: *key,
            label: label.map(str::to_string),
        };
        acts(s, n, Do::Label(label), now);
    }

    /// A message saying `body`, sent at `sent`.
    pub(crate) fn says(body: &str, sent: i64) -> SharedMessage {
        SharedMessage {
            asks: false,
            sent: u64::try_from(sent).unwrap(),
            nonce: [7; 16],
            thread: [0; 16],
            answers: [0; 16],
            link: None,
            body: body.into(),
        }
    }

    /// Message `number` of `author` in `channel`, saying `body`.
    pub(crate) fn message(
        author: &NodeIdentity,
        channel: &Shared,
        number: u64,
        body: &str,
        sent: i64,
    ) -> CheckedEntry {
        let value = says(body, sent).to_value().unwrap();
        let name = message_name(&author.public_key(), number).unwrap();
        let rev = message_rev(number).unwrap();
        entry_by(
            author,
            &channel.secret,
            rev,
            &name,
            Value::Other(value),
            &[],
        )
    }

    /// The anew record of `author` in `channel` at `rev`, holding `value`.
    pub(crate) fn anew_of(
        author: &NodeIdentity,
        channel: &Shared,
        rev: u64,
        value: Vec<u8>,
    ) -> CheckedEntry {
        let name = anew_name(&author.public_key()).unwrap();
        entry_by(
            author,
            &channel.secret,
            rev,
            &name,
            Value::Other(value),
            &[],
        )
    }

    /// The empty anew record of `author` in `channel` at `rev`.
    pub(crate) fn anew(author: &NodeIdentity, channel: &Shared, rev: u64) -> CheckedEntry {
        anew_of(author, channel, rev, Anew::Empty.to_value().unwrap())
    }

    /// Device `n` is given `entry` at `now`; a take-out that it began (a
    /// statement that removed a key) is ended, as the node's next pass
    /// ends it.
    pub(crate) fn given(s: &Several, n: usize, entry: &CheckedEntry, now: i64) -> Taken {
        let taken = take(&s[n].conn, &s[n].identity, entry, now).unwrap();
        out(s, n, now);
        taken
    }

    /// Device `n` is given `entry` at `now`, and the store keeps it.
    pub(crate) fn stores(s: &Several, n: usize, entry: &CheckedEntry, now: i64) -> Option<Read> {
        match given(s, n, entry, now) {
            Taken::Shared {
                stored: Outcome::Stored,
                read,
            } => read,
            other => panic!("{other:?}"),
        }
    }

    /// The row of `channel` on device `n`.
    pub(crate) fn row(s: &Several, n: usize, channel: &Shared) -> Channel {
        kept::channel(&s[n].conn, &channel.id).unwrap().unwrap()
    }

    /// The row of `key` in `channel`'s table of keys on device `n`.
    pub(crate) fn key_row(
        s: &Several,
        n: usize,
        channel: &Shared,
        key: &[u8; 32],
    ) -> Option<kept::Key> {
        kept::key(&s[n].conn, row(s, n, channel).id, key).unwrap()
    }

    /// The rows of `channel`'s table of keys on device `n`.
    pub(crate) fn key_rows(s: &Several, n: usize, channel: &Shared) -> Vec<kept::Key> {
        kept::keys(&s[n].conn, row(s, n, channel).id).unwrap()
    }

    /// The bytes that device `n`'s store holds of `channel`, of the keys
    /// that `known` does not name, as a relay counts them: read from the
    /// store itself, and not from the room the device keeps.
    pub(crate) fn held_of_others(
        s: &Several,
        n: usize,
        channel: &Shared,
        known: &[[u8; 32]],
    ) -> u64 {
        s[n].stored_in(&channel.secret)
            .iter()
            .filter(|entry| !known.contains(&entry.author))
            .map(|entry| entry_cost(entry.content.len()))
            .sum()
    }

    /// The entries of `key` that device `n` holds in `channel`.
    pub(crate) fn held_by(
        s: &Several,
        n: usize,
        channel: &Shared,
        key: &[u8; 32],
    ) -> Vec<CheckedEntry> {
        s[n].stored_in(&channel.secret)
            .into_iter()
            .filter(|entry| entry.author == *key)
            .collect()
    }

    /// The bodies device `n` shows in `channel` at `now`, oldest first.
    pub(crate) fn bodies(s: &Several, n: usize, channel: &Shared, now: i64) -> Vec<String> {
        shown(&s[n].conn, &s[n].identity, &channel.id, now)
            .unwrap()
            .into_iter()
            .map(|shown| shown.body)
            .collect()
    }

    /// How many index rows device `n` holds of `channel`.
    pub(crate) fn indexed(s: &Several, n: usize, channel: &Shared) -> i64 {
        let id = row(s, n, channel).id;
        s[n].conn
            .query_row(
                "SELECT COUNT(*) FROM shared_index WHERE channel = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// Everything device `n` holds of shared channels and of entries:
    /// every row of the store and of each table of step 22.
    pub(crate) fn everything(s: &Several, n: usize) -> Vec<String> {
        let mut all = s[n].everything();
        for table in [
            "shared_channels",
            "shared_keys",
            "shared_unopened",
            "shared_labelled",
            "shared_index",
            "shared_numbers",
            "shared_first_held",
            "shared_signers",
            "shared_places",
        ] {
            let mut rows = s[n]
                .conn
                .prepare(&format!("SELECT * FROM {table}"))
                .unwrap();
            let columns = rows.column_count();
            let mut found = rows.query([]).unwrap();
            while let Some(row) = found.next().unwrap() {
                let values: Vec<String> = (0..columns)
                    .map(|i| format!("{:?}", row.get::<_, rusqlite::types::Value>(i).unwrap()))
                    .collect();
                all.push(format!("{table}: {}", values.join(", ")));
            }
        }
        all.sort();
        all
    }

    /// Members `from` to `from + count - 1` each write their empty anew
    /// record in `channel`, and device `n` stores each, at `now`.
    pub(crate) fn fill(s: &Several, n: usize, channel: &Shared, from: u32, count: u32, now: i64) {
        for k in from..from + count {
            stores(s, n, &anew(&member(k), channel, 1), now);
        }
    }

    /// Fill `channel` on device `n` with keys the person does not know, to
    /// within `left` bytes of its room: 963 anew records, and as many
    /// messages of the first of them as fit. Members from 100 000.
    pub(crate) fn fill_to(s: &Several, n: usize, channel: &Shared, left: u64, now: i64) {
        fill(s, n, channel, 100_000, 963, now);
        let mut room = MAX_ENTRY_CHANNEL_BYTES_AT_RELAY - 963 * ANEW_COST;
        let mut number = 1;
        while room >= left + MESSAGE_COST {
            stores(
                s,
                n,
                &message(&member(100_000), channel, number, "fill", now),
                now,
            );
            room -= MESSAGE_COST;
            number += 1;
        }
        assert_eq!(room, left);
    }

    /// The table of shared channels follows the person's lists (decision
    /// 2026-10-10 §3.4): a channel filed on the laptop is held on the
    /// desktop once it takes the laptop's list at a whole fetch, by its
    /// card, its name and how it came; renamed, it is held under the new
    /// name; dropped, it is held no more, and its seed is kept until the
    /// drop is freed.
    #[test]
    fn the_table_of_shared_channels_follows_the_lists() {
        let s = bob(2);
        let now = s.now + 10;
        // The laptop's list is fresh to the desktop once it says a whole
        // fetch.
        crate::lists::fetched_whole(&s[0].conn, &s[0].identity, now).unwrap();
        let channel = holds(&s, 0, 1, "review", now);
        let on_laptop = row(&s, 0, &channel);
        assert_eq!(
            (on_laptop.name.as_str(), on_laptop.came, on_laptop.state),
            ("review", Came::Made, State::Held)
        );
        assert_eq!(on_laptop.card, filing(1, "x").card.to_bytes());
        assert!(kept::channel(&s[1].conn, &channel.id).unwrap().is_none());

        for entry in s[0].stored() {
            take(&s[1].conn, &s[1].identity, &entry, now).unwrap();
        }
        crate::lists::fetched_whole(&s[1].conn, &s[1].identity, now).unwrap();
        let on_desktop = row(&s, 1, &channel);
        assert_eq!(
            (
                on_desktop.name.as_str(),
                on_desktop.state,
                on_desktop.first_held
            ),
            ("review", State::Held, now)
        );

        let mut renamed = filing(1, "design");
        renamed.came = Filed::Taken([5; 32]);
        acts(&s, 1, Do::File(renamed), now + 1);
        let renamed = row(&s, 1, &channel);
        assert_eq!(
            (renamed.name.as_str(), renamed.came, renamed.first_held),
            ("design", Came::Taken([5; 32]), now)
        );

        acts(&s, 1, Do::Drop(channel.id), now + 2);
        let dropped = row(&s, 1, &channel);
        assert_eq!(
            (dropped.state, dropped.left_at),
            (State::Dropped, Some(now + 2))
        );
        assert_eq!(dropped.card, on_laptop.card);
    }

    /// A member writes in the slots of another key: `msg/<another>/0` and
    /// `anew/<another>` (decision 2026-10-10 §1, property 5; §2.4). None is
    /// stored, shown or taken; the other key's own entries are. A device of
    /// the person's writes in `shared/<another device's key>` of the
    /// personal channel: no act of it is taken.
    #[test]
    fn an_entry_in_another_keys_slot_is_no_message_and_no_record() {
        let s = bob(2);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let (mallory, alice) = (member(1), member(2));
        let in_alices = |name: String, rev: u64, value: Vec<u8>| {
            entry_by(
                &mallory,
                &channel.secret,
                rev,
                &name,
                Value::Other(value),
                &[],
            )
        };
        let value = says("as alice", now).to_value().unwrap();
        let before = everything(&s, 0);
        for entry in [
            in_alices(
                message_name(&alice.public_key(), 0).unwrap(),
                128,
                value.clone(),
            ),
            in_alices(message_name(&alice.public_key(), 1).unwrap(), 2, value),
            in_alices(
                anew_name(&alice.public_key()).unwrap(),
                1,
                Anew::Empty.to_value().unwrap(),
            ),
        ] {
            assert_eq!(
                given(&s, 0, &entry, now),
                Taken::Refused(NotTaken::NotAShared)
            );
        }
        assert_eq!(everything(&s, 0), before);
        assert!(bodies(&s, 0, &channel, now).is_empty());
        // Alice's own, in her slot, is.
        assert_eq!(
            stores(&s, 0, &message(&alice, &channel, 1, "by alice", now), now),
            Some(Read::Message(Indexed::New))
        );
        assert_eq!(bodies(&s, 0, &channel, now), ["by alice"]);

        // The laptop writes a list in the desktop's slot of the personal
        // channel, with a label of its own making in it.
        let act_by_laptop = cordelia_crypto::acts::Act::make(
            Label {
                key: alice.public_key(),
                label: Some("alice".into()),
            },
            u64::try_from(now).unwrap(),
            0,
            &s[0].identity,
            crate::names::is_a_name,
        )
        .unwrap();
        let list = cordelia_crypto::acts::SharedList {
            labels: vec![act_by_laptop],
            ..Default::default()
        };
        let personal = s[0].personal();
        let name = cordelia_crypto::acts::list_name(&s.key(1)).unwrap();
        let rev = cordelia_core::revision::next_under(None, s[0].number()).unwrap();
        let value = Value::Other(list.to_value(crate::names::is_a_name).unwrap());
        let written = entry_by(&s[0].identity, &personal, rev, &name, value, &[]);
        assert!(matches!(given(&s, 1, &written, now), Taken::Own { .. }));
        crate::lists::fetched_whole(&s[1].conn, &s[1].identity, now).unwrap();
        assert!(crate::lists::holds(&s[1].conn).unwrap().labels.is_empty());
        let held = held(&s[1].conn).unwrap().unwrap();
        assert!(
            !Knows::of(&s[1].conn, &held)
                .unwrap()
                .knows(&alice.public_key())
        );
    }

    /// A member writes 16 MiB under keys it made, and Bob's tablet reaches
    /// that relay first (decision 2026-10-10 §1, property 22; §6.3, T23).
    /// The tablet takes every entry of the key Bob labelled and of Bob's
    /// own devices, and shows Alice's messages; it refuses each new slot of
    /// Carol's unlabelled key for room, takes what comes after them, and
    /// keeps Carol's key, whole, in its table with the bytes refused. When
    /// Bob labels Carol's key, the tablet reads the channel again and holds
    /// Carol's entries.
    #[test]
    fn a_member_cannot_blind_a_device_to_the_keys_its_person_knows() {
        let s = bob(2);
        let now = s.now + 10;
        let (laptop, tablet) = (0, 1);
        let (alice, carol) = (member(1), member(2));
        labels(&s, tablet, &alice.public_key(), Some("alice"), now);
        let channel = holds(&s, tablet, 1, "review", now);
        fill_to(&s, tablet, &channel, FULL, now);

        let full = |entry: &CheckedEntry, at: i64| {
            assert_eq!(
                given(&s, tablet, entry, at),
                Taken::Refused(NotTaken::SharedFull)
            );
        };
        full(&anew(&carol, &channel, 1), now);
        full(&message(&carol, &channel, 1, "carol's", now), now + 1);
        // What follows is taken: the person's own devices, and the key it
        // labelled, in new slots past the room.
        stores(&s, tablet, &anew(&alice, &channel, 1), now);
        stores(
            &s,
            tablet,
            &message(&alice, &channel, 1, "alice's", now),
            now,
        );
        stores(&s, tablet, &anew(&s[laptop].identity, &channel, 1), now);
        stores(
            &s,
            tablet,
            &message(&s[laptop].identity, &channel, 1, "the laptop's", now),
            now,
        );
        stores(
            &s,
            tablet,
            &message(&alice, &channel, 2, "alice's again", now),
            now,
        );

        let known = [alice.public_key(), s.key(laptop), s.key(tablet)];
        assert!(held_of_others(&s, tablet, &channel, &known) <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY);
        assert!(held_by(&s, tablet, &channel, &carol.public_key()).is_empty());
        assert_eq!(held_by(&s, tablet, &channel, &alice.public_key()).len(), 3);
        assert_eq!(held_by(&s, tablet, &channel, &s.key(laptop)).len(), 2);
        let refused = key_row(&s, tablet, &channel, &carol.public_key()).unwrap();
        assert_eq!(
            (
                refused.bytes_refused,
                refused.bytes_stored,
                refused.first_refused
            ),
            (ANEW_COST + MESSAGE_COST, 0, Some(now))
        );
        let shown = bodies(&s, tablet, &channel, now);
        for body in ["alice's", "alice's again", "the laptop's"] {
            assert!(shown.contains(&body.to_string()), "{shown:?}");
        }
        assert!(!shown.contains(&"carol's".to_string()));
        assert!(read_again_due(&s[tablet].conn, now).unwrap().is_empty());

        // Bob labels Carol's key: the channel is read again, and her entries
        // are taken.
        labels(&s, tablet, &carol.public_key(), Some("carol"), now + 1);
        assert_eq!(
            read_again_due(&s[tablet].conn, now + 1).unwrap(),
            [channel.id]
        );
        read_again_begun(&s[tablet].conn, &channel.id, now + 1).unwrap();
        stores(&s, tablet, &anew(&carol, &channel, 1), now + 1);
        stores(
            &s,
            tablet,
            &message(&carol, &channel, 1, "carol's", now),
            now + 1,
        );
        assert!(bodies(&s, tablet, &channel, now + 1).contains(&"carol's".to_string()));
        assert_eq!(held_by(&s, tablet, &channel, &carol.public_key()).len(), 2);
    }

    /// Deletes at a relay, and other keys at another relay, do not grow
    /// what a device holds (decision 2026-10-10 §6.3, T23): a member writes
    /// 16 MiB under keys it made, deletes them, writes 16 MiB more under
    /// other keys, and more keys at the other relay. Bob's laptop, given all
    /// of it, holds at most 16 MiB of keys Bob does not know; Dave, shared
    /// the channel next, is refused for room and kept in the table. Thirty
    /// days after the member stops, its keys are let go, the channel is
    /// read again, and the laptop holds Dave's entries.
    #[test]
    fn deletes_at_a_relay_do_not_grow_an_existing_devices_store() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        fill_to(&s, 0, &channel, FULL, now);
        let deleted = |k: u32| {
            let name = anew_name(&member(k).public_key()).unwrap();
            entry_by(&member(k), &channel.secret, 2, &name, Value::Delete, &[])
        };
        for k in 100_000..100_963 {
            assert_eq!(
                given(&s, 0, &deleted(k), now),
                Taken::Refused(NotTaken::NotAShared)
            );
        }
        let at_r1: Vec<CheckedEntry> = (200_000..200_963)
            .map(|k| anew(&member(k), &channel, 1))
            .collect();
        let dave = member(9);
        let mut at_r2: Vec<CheckedEntry> = (300_000..300_050)
            .map(|k| anew(&member(k), &channel, 1))
            .collect();
        // Sent when it is next read: what is shown of it then has not
        // expired.
        at_r2.push(message(&dave, &channel, 1, "dave's", now + 30 * DAY));
        for entry in at_r1.iter().chain(&at_r2) {
            assert_eq!(
                given(&s, 0, entry, now),
                Taken::Refused(NotTaken::SharedFull)
            );
        }
        let known = [s.key(0)];
        assert!(held_of_others(&s, 0, &channel, &known) <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY);
        assert_eq!(
            held_of_others(&s, 0, &channel, &known),
            MAX_ENTRY_CHANNEL_BYTES_AT_RELAY - FULL
        );
        let dave_row = key_row(&s, 0, &channel, &dave.public_key()).unwrap();
        assert_eq!(
            (dave_row.bytes_refused, dave_row.bytes_stored),
            (MESSAGE_COST, 0)
        );
        // 963 keys refused at the first relay and 51 at the second: every
        // row is kept, within the 1,024 of keys that store nothing.
        assert_eq!(key_rows(&s, 0, &channel).len(), 963 + 963 + 51);

        // The member stops. Thirty days on, its keys are let go, and the
        // channel is read again.
        let later = now + 30 * DAY;
        assert!(read_again_due(&s[0].conn, later).unwrap().is_empty());
        assert_eq!(hourly(&s[0].conn, &s.key(0), later).unwrap().let_go, 963);
        assert_eq!(held_of_others(&s, 0, &channel, &known), 0);
        assert_eq!(read_again_due(&s[0].conn, later).unwrap(), [channel.id]);
        read_again_begun(&s[0].conn, &channel.id, later).unwrap();
        // The second relay's page, and then the first's: its deletes are
        // refused, and its keys fill what room is left.
        for entry in &at_r2 {
            stores(&s, 0, entry, later);
        }
        for k in 100_000..100_963 {
            assert_eq!(
                given(&s, 0, &deleted(k), later),
                Taken::Refused(NotTaken::NotAShared)
            );
        }
        for entry in &at_r1 {
            given(&s, 0, entry, later);
        }
        assert_eq!(held_by(&s, 0, &channel, &dave.public_key()).len(), 1);
        assert!(bodies(&s, 0, &channel, later).contains(&"dave's".to_string()));
        assert!(held_of_others(&s, 0, &channel, &known) <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY);
    }

    /// A key that stops being known joins the room (decision 2026-10-10
    /// §6.3): with the room near full, Bob removes his label of Carol's
    /// key, and her bytes are counted in it; then Bob removes his phone,
    /// which he had labelled too, and his tablet, at once, and the room is
    /// past its bound. The entries of the key that stopped being known
    /// first go, Carol's; then, of the two that stopped at once, those of
    /// the key first held last, the tablet's; down to 16 MiB, each noted as
    /// refused. The phone's stay, counted in the room: a removed key is
    /// not known, labelled or not. A message taken out and read again once
    /// Carol is labelled again is shown under its first holding, and not as
    /// new.
    #[test]
    fn a_key_that_stops_being_known_joins_the_room() {
        let mut s = bob(4);
        let (desktop, phone, laptop, tablet) = (0, 1, 2, 3);
        let now = s.now + 10;
        let channel = holds(&s, desktop, 1, "review", now);
        let carol = member(2);
        labels(&s, desktop, &carol.public_key(), Some("carol"), now);
        labels(&s, desktop, &s.key(phone), Some("the phone"), now);
        // Written before the keys that fill the room: so each is among the
        // 64 shown by the order of first holding, whatever it is to Bob.
        let carols = message(&carol, &channel, 1, "carol's", now);
        assert_eq!(
            stores(&s, desktop, &carols, now),
            Some(Read::Message(Indexed::New))
        );
        for (device, body) in [(phone, "the phone's"), (tablet, "the tablet's")] {
            let entry = message(&s[device].identity, &channel, 1, body, now);
            stores(&s, desktop, &entry, now);
        }
        fill_to(&s, desktop, &channel, 4 * 1_024, now);
        let room_before = row(&s, desktop, &channel).room;
        assert_eq!(room_before, MAX_ENTRY_CHANNEL_BYTES_AT_RELAY - 4 * 1_024);
        let others = |s: &Several, now: i64| -> Vec<String> {
            let mut shown = bodies(s, desktop, &channel, now);
            shown.retain(|body| body != "fill");
            shown.sort();
            shown
        };
        assert_eq!(others(&s, now), ["carol's", "the phone's", "the tablet's"]);

        // Carol's label goes: her bytes are in the room, which has room
        // for them.
        labels(&s, desktop, &carol.public_key(), None, now + 1);
        let unlabelled = key_row(&s, desktop, &channel, &carol.public_key()).unwrap();
        assert_eq!(
            (unlabelled.known, unlabelled.unknown_since),
            (false, Some(now + 1))
        );
        assert_eq!(row(&s, desktop, &channel).room, room_before + MESSAGE_COST);
        assert_eq!(held_by(&s, desktop, &channel, &carol.public_key()).len(), 1);

        // The phone and the tablet are removed: the room is past its
        // bound. Carol's entries go first, and then the tablet's.
        let change = s.change(laptop, &[desktop, laptop], &[phone, tablet]);
        assert!(matches!(
            given(&s, desktop, &change, now + 2),
            Taken::Shown(crate::person::Shown::Applied(_))
        ));
        let known = [s.key(desktop), s.key(laptop)];
        assert!(held_of_others(&s, desktop, &channel, &known) <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY);
        assert_eq!(
            row(&s, desktop, &channel).room,
            MAX_ENTRY_CHANNEL_BYTES_AT_RELAY - 1_024
        );
        assert!(held_by(&s, desktop, &channel, &carol.public_key()).is_empty());
        assert!(held_by(&s, desktop, &channel, &s.key(tablet)).is_empty());
        assert_eq!(held_by(&s, desktop, &channel, &s.key(phone)).len(), 1);
        for key in [carol.public_key(), s.key(tablet)] {
            let out = key_row(&s, desktop, &channel, &key).unwrap();
            assert_eq!(
                (out.bytes_stored, out.bytes_refused, out.kept_message_rev),
                (0, MESSAGE_COST, Some(2))
            );
        }
        let phone_row = key_row(&s, desktop, &channel, &s.key(phone)).unwrap();
        assert_eq!(
            (
                phone_row.known,
                phone_row.unknown_since,
                phone_row.bytes_stored
            ),
            (false, Some(now + 2), MESSAGE_COST)
        );
        // The removed devices are shown nothing, and Carol's message went
        // with her entries.
        assert!(others(&s, now + 2).is_empty());
        assert_eq!(
            given(&s, desktop, &carols, now + 2),
            Taken::Refused(NotTaken::SharedFull)
        );

        // Labelled again, Carol's key is read again, and her message is as
        // it was.
        labels(&s, desktop, &carol.public_key(), Some("carol"), now + 3);
        assert_eq!(
            read_again_due(&s[desktop].conn, now + 3).unwrap(),
            [channel.id]
        );
        assert_eq!(
            stores(&s, desktop, &carols, now + 4),
            Some(Read::Message(Indexed::Again))
        );
        let mut shown =
            shown(&s[desktop].conn, &s[desktop].identity, &channel.id, now + 4).unwrap();
        shown.retain(|shown| shown.body != "fill");
        assert_eq!(shown.len(), 1);
        assert_eq!(
            (
                shown[0].body.as_str(),
                shown[0].first_held,
                shown[0].placed_at
            ),
            ("carol's", now, now)
        );
    }

    /// A quiet key is let go by first holding alone (decision 2026-10-10
    /// §6.3, T23): a member writes under 963 keys an anew record each, some
    /// not of form 5 and some offers that say they were made at
    /// `SHARED_ACT_TIME_MAX`, and stops; one key writes its record again
    /// twenty days on. Thirty days after this device last first held an
    /// entry of each, it is let go, whatever its entries say; the channel is
    /// read again, the records at the relay are refused at their kept
    /// revisions with no new row, and Dave's entries are then stored. A
    /// let-go key that writes anew is stored.
    #[test]
    fn a_quiet_key_is_let_go_by_first_holding_alone() {
        use cordelia_core::protocol::SHARED_ACT_TIME_MAX;
        use cordelia_crypto::share::{Card, Relays};
        use cordelia_crypto::shared::Offer;

        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let mut records = Vec::new();
        for k in 0..963u32 {
            let author = member(1_000 + k);
            let value = match k {
                0..10 => {
                    let mut value = vec![0; SHARED_ANEW_VALUE_BYTES];
                    value[0] = 6;
                    value
                }
                10..20 => {
                    let card = Card::make(Relays::new(&[[3; 32]]).unwrap()).unwrap();
                    let keys = [author.public_key()];
                    let offer =
                        Offer::make(SHARED_ACT_TIME_MAX, &channel.id, &card, &keys).unwrap();
                    Anew::Offer(offer).to_value().unwrap()
                }
                _ => Anew::Empty.to_value().unwrap(),
            };
            records.push(anew_of(&author, &channel, 1, value));
        }
        for (k, record) in records.iter().enumerate() {
            let read = stores(&s, 0, record, now).unwrap();
            match k {
                0..10 => assert!(matches!(read, Read::NotAMessage(_)), "{read:?}"),
                10..20 => assert!(matches!(read, Read::Anew(Anew::Offer(_))), "{read:?}"),
                // Bob's own device and 63 of the keys are shown: the rest
                // are stored and counted, and not read.
                _ if k < 63 => assert_eq!(read, Read::Anew(Anew::Empty)),
                _ => assert_eq!(read, Read::NotShown),
            }
        }
        for number in 1..=4 {
            stores(
                &s,
                0,
                &message(&member(1_100), &channel, number, "fill", now),
                now,
            );
        }
        let dave = member(9);
        let daves = message(&dave, &channel, 1, "dave's", now + 30 * DAY);
        assert_eq!(
            given(&s, 0, &daves, now),
            Taken::Refused(NotTaken::SharedFull)
        );
        // One key writes its record again twenty days on: its first holding
        // is then.
        let again = anew(&member(1_500), &channel, 2);
        stores(&s, 0, &again, now + 20 * DAY);

        assert_eq!(
            hourly(&s[0].conn, &s.key(0), now + 30 * DAY - 1)
                .unwrap()
                .let_go,
            0
        );
        assert!(
            read_again_due(&s[0].conn, now + 30 * DAY)
                .unwrap()
                .is_empty()
        );
        let id = row(&s, 0, &channel).id;
        let waits = |key: &[u8; 32]| {
            kept::waiting_to_open(&s[0].conn, id)
                .unwrap()
                .iter()
                .any(|(waiting, _)| waiting == key)
        };
        assert!(waits(&member(1_500).public_key()));
        assert_eq!(
            hourly(&s[0].conn, &s.key(0), now + 30 * DAY)
                .unwrap()
                .let_go,
            962
        );
        // The key that wrote again is now shown, and what waited of it was
        // opened.
        assert!(!waits(&member(1_500).public_key()));
        assert_eq!(
            shown_keys(&s[0].conn, &channel.id).unwrap(),
            [s.key(0), member(1_500).public_key()]
        );
        assert_eq!(held_of_others(&s, 0, &channel, &[s.key(0)]), ANEW_COST);
        let let_go = key_row(&s, 0, &channel, &member(1_010).public_key()).unwrap();
        assert_eq!(
            (
                let_go.bytes_stored,
                let_go.kept_anew_rev,
                let_go.bytes_refused
            ),
            (0, Some(1), 0)
        );
        assert_eq!(
            read_again_due(&s[0].conn, now + 30 * DAY).unwrap(),
            [channel.id]
        );

        // The read again: what was let go is refused at its kept revision,
        // and no row is made or changed for it.
        let later = now + 30 * DAY + 1;
        let rows = key_rows(&s, 0, &channel);
        for (k, record) in records.iter().enumerate() {
            let taken = given(&s, 0, record, later);
            if k == 500 {
                assert!(matches!(
                    taken,
                    Taken::Shared {
                        stored: Outcome::OlderThanHeld,
                        ..
                    }
                ));
            } else {
                assert_eq!(taken, Taken::Refused(NotTaken::SharedFull), "{k}");
            }
        }
        assert_eq!(key_rows(&s, 0, &channel), rows);
        assert_eq!(
            stores(&s, 0, &daves, later),
            Some(Read::Message(Indexed::New))
        );
        assert!(bodies(&s, 0, &channel, later).contains(&"dave's".to_string()));

        // A let-go key that writes again is stored: a message, and its
        // record at a higher revision.
        let back = member(1_010);
        stores(&s, 0, &message(&back, &channel, 1, "back", later), later);
        stores(&s, 0, &anew(&back, &channel, 2), later);
        assert_eq!(held_by(&s, 0, &channel, &back.public_key()).len(), 2);
    }

    /// The table keeps every key that stores an entry (decision 2026-10-10
    /// §6.3, T23): a member writes one message under each of 6,600 keys,
    /// Dave's among the first. 5,461 are stored, which fill the room, and
    /// Dave's key keeps its row; of the 1,139 refused for room, 1,024 rows
    /// are kept, the 115 refused least lately are let go, and the device
    /// says how many. Labelling a key whose row was let go reads the
    /// channel again.
    #[test]
    fn the_table_keeps_every_key_that_stores_an_entry() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let key_of = |k: u32| {
            if k == 3 {
                member(9)
            } else {
                member(10_000 + k)
            }
        };
        let mut refused = 0;
        for k in 0..6_600u32 {
            match given(
                &s,
                0,
                &message(&key_of(k), &channel, 1, "one", now),
                now + i64::from(k),
            ) {
                Taken::Shared {
                    stored: Outcome::Stored,
                    ..
                } => {}
                Taken::Refused(NotTaken::SharedFull) => refused += 1,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(refused, 1_139);
        assert_eq!(row(&s, 0, &channel).room, 5_461 * MESSAGE_COST);
        assert_eq!(5_461 * MESSAGE_COST, 16_776_192);
        let rows = key_rows(&s, 0, &channel);
        assert_eq!(
            rows.iter().filter(|key| key.bytes_stored > 0).count(),
            5_461
        );
        assert_eq!(
            rows.iter().filter(|key| key.bytes_stored == 0).count(),
            SHARED_KEYS_KEPT
        );
        assert_eq!(row(&s, 0, &channel).let_go, 115);
        assert!(
            key_row(&s, 0, &channel, &member(9).public_key())
                .is_some_and(|key| key.bytes_stored == MESSAGE_COST)
        );
        // The keys refused least lately went: the first 115 refused.
        assert!(key_row(&s, 0, &channel, &key_of(5_461).public_key()).is_none());
        assert!(key_row(&s, 0, &channel, &key_of(5_575).public_key()).is_none());
        assert!(key_row(&s, 0, &channel, &key_of(5_576).public_key()).is_some());

        labels(
            &s,
            0,
            &key_of(5_461).public_key(),
            Some("a newcomer"),
            now + 7_000,
        );
        assert_eq!(
            read_again_due(&s[0].conn, now + 7_000).unwrap(),
            [channel.id]
        );
        // Dave's key, labelled, leaves the room.
        labels(&s, 0, &member(9).public_key(), Some("dave"), now + 7_001);
        assert_eq!(row(&s, 0, &channel).room, 5_460 * MESSAGE_COST);
    }

    /// A drop or a move takes its entries (decision 2026-10-10 §6.3): at a
    /// drop the device holds no entry and no row of that channel; at a move
    /// it holds no entry of the old channel, and shows its index rows until
    /// they expire, for the 16 channels moved from last. Neither's entries
    /// are taken any more, ninety days on or a year on: a drop is never let
    /// go for its age.
    #[test]
    fn a_drop_or_a_move_takes_its_entries() {
        let s = bob(1);
        let now = s.now + 10;
        let (dropped, moved) = (holds(&s, 0, 1, "a", now), holds(&s, 0, 2, "b", now));
        let alice = member(1);
        for channel in [&dropped, &moved] {
            stores(&s, 0, &message(&alice, channel, 1, "one", now), now);
            assert_eq!(bodies(&s, 0, channel, now), ["one"]);
        }

        // A label asks a read again of both.
        labels(&s, 0, &member(2).public_key(), Some("carol"), now);
        let mut both = vec![dropped.id, moved.id];
        let mut due = read_again_due(&s[0].conn, now).unwrap();
        both.sort();
        due.sort();
        assert_eq!(due, both);

        acts(&s, 0, Do::Drop(dropped.id), now + 1);
        assert!(s[0].stored_in(&dropped.secret).is_empty());
        let row_of = row(&s, 0, &dropped);
        assert_eq!(row_of.state, State::Dropped);
        assert!(key_rows(&s, 0, &dropped).is_empty());
        assert_eq!(indexed(&s, 0, &dropped), 0);
        for table in [
            "shared_first_held",
            "shared_signers",
            "shared_places",
            "shared_unopened",
        ] {
            let rows: i64 = s[0]
                .conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE channel = ?1"),
                    [row_of.id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }

        let mut to = filing(3, "b");
        to.came = Filed::Moved(moved.id);
        acts(&s, 0, Do::Move { from: moved.id, to }, now + 2);
        assert!(s[0].stored_in(&moved.secret).is_empty());
        assert_eq!(row(&s, 0, &moved).state, State::Moved);
        assert!(key_rows(&s, 0, &moved).is_empty());
        assert_eq!(bodies(&s, 0, &moved, now + 2), ["one"]);
        assert_eq!(row(&s, 0, &Shared::of(3)).state, State::Held);
        assert!(read_again_due(&s[0].conn, now + 2).unwrap().is_empty());

        for channel in [&dropped, &moved] {
            let entry = message(&alice, channel, 2, "two", now);
            assert_eq!(
                given(&s, 0, &entry, now + 3),
                Taken::Refused(NotTaken::AnotherChannel)
            );
        }

        // A move's index stays for the 16 channels moved from last.
        let mut from = Shared::of(3);
        stores(&s, 0, &message(&alice, &from, 1, "in 3", now), now + 3);
        for seed in 4..=19u8 {
            let mut to = filing(seed, "b");
            to.came = Filed::Moved(from.id);
            acts(&s, 0, Do::Move { from: from.id, to }, now + i64::from(seed));
            from = Shared::of(seed);
            stores(
                &s,
                0,
                &message(&alice, &from, 1, "moved", now),
                now + i64::from(seed),
            );
        }
        // Seventeen moved from: the oldest, the channel of seed 2, keeps no
        // index; the channel of seed 3 keeps its own.
        assert_eq!(indexed(&s, 0, &moved), 0);
        assert_eq!(indexed(&s, 0, &Shared::of(3)), 1);

        // Ninety days on, and a year on, the drops are still written: an
        // undo is let go only past a bound, never for its age (§3.4), so
        // the rows of a channel dropped stay while the device writes its
        // drop, and nothing of it is taken.
        for later in [now + 91 * DAY, now + 365 * DAY] {
            crate::lists::fetched_whole(&s[0].conn, &s[0].identity, later).unwrap();
            assert_eq!(row(&s, 0, &dropped).state, State::Dropped);
            assert!(s[0].stored_in(&dropped.secret).is_empty());
            assert_eq!(row(&s, 0, &from).state, State::Held);
        }
    }

    /// A reader shows 64 keys, and 64 places an hour for the keys the
    /// person has not labelled (decision 2026-10-10 §1, property 23; §2.4,
    /// T23): a member makes 100 keys and writes two messages from each, and
    /// Bob has labelled four of them. The reader shows 64 by the one order:
    /// the labelled keys in the order the labels were made, Bob's own
    /// devices, and then the keys first held first, whatever they write
    /// later; it stores and counts the rest, and opens nothing of them; it
    /// gives the unlabelled keys 64 places in the hour, the newest first,
    /// and the labelled keys and Bob's own devices places outside them. A
    /// key that Bob labels later is shown, and what waited of it is opened.
    #[test]
    fn a_reader_shows_64_keys_and_64_unlabelled_places_an_hour() {
        let s = bob(2);
        let (laptop, desktop) = (0, 1);
        let now = s.now + 10;
        let channel = holds(&s, laptop, 1, "review", now);
        let key = |k: u32| member(k);
        // Four keys labelled, in an order that is not the order of their
        // keys: they are shown in the order the labels were made.
        let mut labelled = [95, 96, 97, 99].map(|k| key(k).public_key());
        labelled.sort();
        let labelled = [labelled[2], labelled[0], labelled[3], labelled[1]];
        for (n, labelled) in labelled.iter().enumerate() {
            let at = now - 10 + i64::try_from(n).unwrap();
            labels(&s, laptop, labelled, Some("labelled"), at);
        }
        let is_labelled = |k: u32| [95, 96, 97, 99].contains(&k);
        let others: Vec<u32> = (0..100).filter(|k| !is_labelled(*k)).collect();
        for k in 0..100u32 {
            for number in 1..=2u64 {
                let sent = now - 1_000 + i64::from(k) * 2 + i64::try_from(number).unwrap();
                let entry = message(&key(k), &channel, number, &format!("{k}.{number}"), sent);
                let read = stores(&s, laptop, &entry, now).unwrap();
                let shown = k < 58 || is_labelled(k);
                assert_eq!(read == Read::NotShown, !shown, "{k}");
            }
        }
        let desktops = message(&s[desktop].identity, &channel, 1, "the desktop's", now);
        stores(&s, laptop, &desktops, now);
        // Key 0 writes again, after every other: it keeps its place.
        stores(
            &s,
            laptop,
            &message(&key(0), &channel, 3, "0.3", now - 2_000),
            now,
        );

        let mut order = labelled.to_vec();
        order.extend([s.key(laptop), s.key(desktop)]);
        order.extend(others[..58].iter().map(|k| key(*k).public_key()));
        assert_eq!(shown_keys(&s[laptop].conn, &channel.id).unwrap(), order);
        let id = row(&s, laptop, &channel).id;
        let waiting = kept::waiting_to_open(&s[laptop].conn, id).unwrap();
        assert_eq!(waiting.len(), 38);
        assert!(waiting.iter().all(|(_, count)| *count == 2));

        let shown = bodies(&s, laptop, &channel, now);
        // The newest 64 of the 117 messages of the 58 keys unlabelled.
        let of_a_labelled = |body: &String| {
            [95, 96, 97, 99]
                .iter()
                .any(|k| body.starts_with(&format!("{k}.")))
        };
        let mut unlabelled: Vec<String> = shown
            .iter()
            .filter(|body| !of_a_labelled(body) && *body != "the desktop's")
            .cloned()
            .collect();
        unlabelled.sort();
        let mut newest: Vec<String> = (26..58)
            .flat_map(|k| [format!("{k}.1"), format!("{k}.2")])
            .collect();
        newest.sort();
        assert_eq!(unlabelled, newest);
        assert_eq!(shown.iter().filter(|body| of_a_labelled(body)).count(), 8);
        assert!(shown.contains(&"the desktop's".to_string()));
        assert_eq!(shown.len(), 64 + 8 + 1);
        // Within the hour no more; after it, the rest.
        assert_eq!(bodies(&s, laptop, &channel, now + HOUR - 1).len(), 73);
        assert_eq!(bodies(&s, laptop, &channel, now + HOUR).len(), 117 + 9);

        // Bob labels key 70: it is shown, after the keys labelled before
        // and before his own devices, and what waited of it is opened; key
        // 57, the last, is shown no more.
        labels(
            &s,
            laptop,
            &key(70).public_key(),
            Some("seventy"),
            now + HOUR,
        );
        let keys = shown_keys(&s[laptop].conn, &channel.id).unwrap();
        assert_eq!(keys[4], key(70).public_key());
        assert_eq!(keys[5], s.key(laptop));
        assert!(!keys.contains(&key(57).public_key()));
        let shown = bodies(&s, laptop, &channel, now + HOUR);
        assert!(shown.contains(&"70.1".to_string()) && shown.contains(&"70.2".to_string()));
        assert!(!shown.contains(&"57.1".to_string()));
        assert_eq!(
            kept::waiting_to_open(&s[laptop].conn, id).unwrap().len(),
            37
        );
    }

    /// One signer has 64 places an hour (decision 2026-10-10 §2.4, rule 4;
    /// the messages record's §6): a key Bob labelled writes 64 messages,
    /// which are shown, and then ten more within the hour, which wait for
    /// the hour to have room, newest first.
    #[test]
    fn a_signer_has_64_places_an_hour() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let alice = member(1);
        labels(&s, 0, &alice.public_key(), Some("alice"), now);
        for number in 1..=64 {
            stores(
                &s,
                0,
                &message(&alice, &channel, number, &format!("{number}"), now),
                now,
            );
        }
        assert_eq!(bodies(&s, 0, &channel, now).len(), 64);
        for number in 65..=74 {
            let entry = message(&alice, &channel, number, &format!("{number}"), now + 60);
            stores(&s, 0, &entry, now + 60);
        }
        let id = row(&s, 0, &channel).id;
        let shown = bodies(&s, 0, &channel, now + 60);
        assert!(!shown.iter().any(|body| body.parse::<u64>().unwrap() > 64));
        assert_eq!(
            kept::held_back(&s[0].conn, id, &alice.public_key(), now + 60).unwrap(),
            10
        );
        let shown = bodies(&s, 0, &channel, now + HOUR + 1);
        assert_eq!(shown.len(), 64);
        assert!((65..=74).all(|n| shown.contains(&n.to_string())));
    }

    /// A full channel still takes a slot written again (decision
    /// 2026-10-10 §2.3, rule 4; §6.3, T3): the room takes the entry that
    /// fills it to its last byte, 962 anew records and ten messages; with
    /// the room full, a key of the room writes its anew record over its
    /// empty one and its next message over a slot it holds, and each is
    /// taken; a new slot is refused, and the room is as it was.
    #[test]
    fn a_full_channel_still_takes_a_slot_written_again() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        fill(&s, 0, &channel, 100_000, 962, now);
        let first = member(100_000);
        for number in 1..=10 {
            stores(&s, 0, &message(&first, &channel, number, "fill", now), now);
        }
        assert_eq!(
            962 * ANEW_COST + 10 * MESSAGE_COST,
            MAX_ENTRY_CHANNEL_BYTES_AT_RELAY
        );
        let room = row(&s, 0, &channel).room;
        assert_eq!(room, MAX_ENTRY_CHANNEL_BYTES_AT_RELAY);
        stores(&s, 0, &anew(&first, &channel, 2), now);
        let over = message(&first, &channel, 65, "over slot 1", now);
        stores(&s, 0, &over, now);
        let new = message(&member(100_001), &channel, 1, "new", now);
        assert_eq!(
            given(&s, 0, &new, now),
            Taken::Refused(NotTaken::SharedFull)
        );
        assert_eq!(row(&s, 0, &channel).room, room);
        assert_eq!(held_of_others(&s, 0, &channel, &[s.key(0)]), room);
    }

    /// The reader takes a message only in its ring, at a live number
    /// (decision 2026-10-10 §2.3, §6.1; the messages record's §2.5): an
    /// entry in a slot of its author's ring at a number of another slot is
    /// stored and counted as no message; a message of the messages
    /// channel's form, and a value that does not open, are counted so too;
    /// a message is indexed by its signer's ID of its value; a number that
    /// the ring has passed is overwritten, and its message's row goes; a
    /// clearing at a number that is not live counts nothing.
    #[test]
    fn the_reader_takes_only_a_message_in_its_ring_at_a_live_number() {
        use crate::several::signed_in;
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let alice = member(1);
        let key = alice.public_key();
        let id = row(&s, 0, &channel).id;
        let counted = || {
            kept::signer(&s[0].conn, id, &key)
                .unwrap()
                .unwrap_or_default()
        };

        // Number 7 in the slot of number 5.
        let value = says("out of place", now).to_value().unwrap();
        let name = message_name(&key, 5).unwrap();
        let misplaced = entry_by(&alice, &channel.secret, 14, &name, Value::Other(value), &[]);
        assert_eq!(
            stores(&s, 0, &misplaced, now),
            Some(Read::NotAMessage(NotShared::NotInItsSlots))
        );
        // It is passed over before its number is held: H stays at none.
        assert_eq!((counted().not_messages, counted().highest), (1, 0));
        // A message of the messages channel's form.
        let own_form = cordelia_crypto::message::Message {
            asks: false,
            sent: 1,
            nonce: [0; 16],
            thread: [0; 16],
            answers: [0; 16],
            from: "~".into(),
            to: cordelia_crypto::message::To::All,
            link: None,
            body: "of the messages channel".into(),
        };
        let value = own_form.to_value(crate::names::is_a_name).unwrap();
        let name = message_name(&key, 2).unwrap();
        let of_form_1 = entry_by(&alice, &channel.secret, 4, &name, Value::Other(value), &[]);
        assert!(matches!(
            stores(&s, 0, &of_form_1, now),
            Some(Read::NotAMessage(NotShared::Message(_)))
        ));
        assert_eq!(counted().not_messages, 2);
        // A content of a message's size that does not open.
        let slot = slot_id(
            &derive::slot_key(&channel.secret).unwrap(),
            &message_name(&key, 3).unwrap(),
        );
        let unread = signed_in(
            &channel.secret,
            &alice,
            slot,
            6,
            vec![9; AGENT_MESSAGE_CONTENT_BYTES],
        );
        assert_eq!(stores(&s, 0, &unread, now), Some(Read::DidNotOpen));
        assert_eq!(counted().not_messages, 3);
        assert_eq!(bodies(&s, 0, &channel, now), Vec::<String>::new());

        // A message, by the ID of its value and its signer.
        let first = message(&alice, &channel, 10, "number 10", now);
        assert_eq!(
            stores(&s, 0, &first, now),
            Some(Read::Message(Indexed::New))
        );
        let value = says("number 10", now).to_value().unwrap();
        let held: Vec<u8> = s[0]
            .conn
            .query_row("SELECT id FROM shared_index", [], |row| row.get(0))
            .unwrap();
        assert_eq!(held, message_id(&key, &value).to_vec());
        assert_eq!(bodies(&s, 0, &channel, now), ["number 10"]);

        // Number 74 passes number 10 by the ring: 10 is live no longer.
        let passed = message(&alice, &channel, 74, "number 74", now);
        assert_eq!(
            stores(&s, 0, &passed, now),
            Some(Read::Message(Indexed::New))
        );
        assert_eq!(indexed(&s, 0, &channel), 1);
        assert_eq!(bodies(&s, 0, &channel, now), ["number 74"]);
        assert_eq!(counted().highest, 74);
        // Number 10 is not live: overwritten, and counted so.
        let before = counted().overwritten;
        let late = message(&alice, &channel, 10, "number 10 again", now);
        assert_eq!(
            given(&s, 0, &late, now),
            Taken::Shared {
                stored: Outcome::OlderThanHeld,
                read: None,
            }
        );
        // Number 1, below the number counted from (2), is counted as
        // overwritten.
        let edge = message(&alice, &channel, 1, "number 1", now);
        assert_eq!(stores(&s, 0, &edge, now), Some(Read::Overwritten));
        assert_eq!(counted().overwritten, before + 1);
        // A clearing at a number that is not live counts nothing, below
        // the number counted from too.
        let name = message_name(&key, 1).unwrap();
        let cleared = entry_by(
            &alice,
            &channel.secret,
            clearing_rev(1).unwrap(),
            &name,
            Value::Other(cordelia_crypto::message::clearing_value()),
            &[],
        );
        assert_eq!(stores(&s, 0, &cleared, now), Some(Read::Overwritten));
        assert_eq!(counted().overwritten, before + 1);
    }

    /// What a maker in no list filed or labelled is passed over on this
    /// device (decision 2026-10-10 §3.4): the phone files a channel and
    /// labels Alice's key, and the desktop takes both from its list; once a
    /// settlement leaves the phone in no list, its acts are passed over as
    /// if no list carried them: a channel that no list carries a valid act
    /// on keeps no entry and no row, and Alice's key is no longer one Bob
    /// knows.
    #[test]
    fn what_a_maker_in_no_list_filed_or_labelled_is_passed_over_here() {
        let mut s = bob(3);
        let (desktop, phone, laptop) = (0, 1, 2);
        let now = s.now + 10;
        let alice = member(1);
        crate::lists::fetched_whole(&s[phone].conn, &s[phone].identity, now).unwrap();
        let channel = holds(&s, phone, 1, "review", now);
        labels(&s, phone, &alice.public_key(), Some("alice"), now);
        for entry in s[phone].stored() {
            take(&s[desktop].conn, &s[desktop].identity, &entry, now).unwrap();
        }
        crate::lists::fetched_whole(&s[desktop].conn, &s[desktop].identity, now).unwrap();
        assert_eq!(row(&s, desktop, &channel).state, State::Held);
        let held_by_desktop = held(&s[desktop].conn).unwrap().unwrap();
        assert!(
            Knows::of(&s[desktop].conn, &held_by_desktop)
                .unwrap()
                .knows(&alice.public_key())
        );
        stores(&s, desktop, &message(&alice, &channel, 1, "one", now), now);

        // The phone is in neither list of the next statement.
        let change = s.change(laptop, &[desktop, laptop], &[]);
        assert!(matches!(
            given(&s, desktop, &change, now + 1),
            Taken::Shown(crate::person::Shown::Applied(_))
        ));
        // The phone's acts are passed over: no list carries a valid act on
        // the channel, and the desktop keeps no entry and no row of it.
        assert!(
            kept::channel(&s[desktop].conn, &channel.id)
                .unwrap()
                .is_none()
        );
        assert!(s[desktop].stored_in(&channel.secret).is_empty());
        let held_by_desktop = held(&s[desktop].conn).unwrap().unwrap();
        assert!(
            !Knows::of(&s[desktop].conn, &held_by_desktop)
                .unwrap()
                .knows(&alice.public_key())
        );
        let entry = message(&alice, &channel, 2, "two", now);
        assert_eq!(
            given(&s, desktop, &entry, now + 1),
            Taken::Refused(NotTaken::AnotherChannel)
        );
    }

    /// A key with bytes refused that comes to count is read again (decision
    /// 2026-10-10 §6.3): a key that is not yet Bob's device writes in a
    /// full channel and is refused for room; Bob adds it as a device, and
    /// the desktop, given the record of its addition, reads the channel
    /// again and takes its entries, which the room no longer refuses.
    #[test]
    fn a_key_with_bytes_refused_that_comes_to_count_is_read_again() {
        let mut s = Several::new(3);
        s.make_phrase(0);
        assert!(matches!(s.add(0, 1), crate::adding::Accepted::Joined(_)));
        s.meet(&[0, 1]);
        meta::set(&s[1].conn, meta::SYNC_CLAUDE_DIR, "/home/bob/.claude").unwrap();
        let (desktop, new) = (1, 2);
        let now = s.now + 10;
        let channel = holds(&s, desktop, 1, "review", now);
        fill_to(&s, desktop, &channel, FULL, now);
        let theirs = message(&s[new].identity, &channel, 1, "a new device's", now);
        assert_eq!(
            given(&s, desktop, &theirs, now),
            Taken::Refused(NotTaken::SharedFull)
        );
        let refused = key_row(&s, desktop, &channel, &s.key(new)).unwrap();
        assert_eq!(refused.bytes_refused, MESSAGE_COST);
        assert!(read_again_due(&s[desktop].conn, now).unwrap().is_empty());

        assert!(matches!(s.add(0, new), crate::adding::Accepted::Joined(_)));
        let later = s.now + 10;
        for entry in s[0].stored() {
            take(&s[desktop].conn, &s[desktop].identity, &entry, later).unwrap();
        }
        assert!(s[desktop].counts(&s.key(new)));
        assert_eq!(
            read_again_due(&s[desktop].conn, later).unwrap(),
            [channel.id]
        );
        stores(&s, desktop, &theirs, later);
    }

    /// Reading again is once a day for each channel (decision 2026-10-10
    /// §6.3, T23): a member lets one key go quiet each hour where Dave was
    /// refused for room; the channel is read again at most once a day, and
    /// a label within the day reads it when the day is up. Another channel
    /// keeps a day of its own.
    #[test]
    fn reading_again_is_once_a_day_for_each_channel() {
        let s = bob(1);
        let now = s.now + 10;
        let (channel, other) = (holds(&s, 0, 1, "a", now), holds(&s, 0, 2, "b", now));
        // 963 keys, one first held each hour from now; and Dave refused.
        for k in 0..963u32 {
            stores(
                &s,
                0,
                &anew(&member(k), &channel, 1),
                now + i64::from(k) * HOUR,
            );
        }
        for number in 1..=4 {
            stores(
                &s,
                0,
                &message(&member(0), &channel, number, "fill", now),
                now,
            );
        }
        let dave = member(9_999);
        let at = now + 963 * HOUR;
        assert_eq!(
            given(&s, 0, &message(&dave, &channel, 1, "dave's", at), at),
            Taken::Refused(NotTaken::SharedFull)
        );
        let start = now + 30 * DAY;
        assert_eq!(hourly(&s[0].conn, &s.key(0), start).unwrap().let_go, 1);
        assert_eq!(read_again_due(&s[0].conn, start).unwrap(), [channel.id]);
        read_again_begun(&s[0].conn, &channel.id, start).unwrap();
        for hour in 1..24 {
            let t = start + hour * HOUR;
            assert_eq!(
                hourly(&s[0].conn, &s.key(0), t).unwrap().let_go,
                1,
                "{hour}"
            );
            assert!(read_again_due(&s[0].conn, t).unwrap().is_empty(), "{hour}");
            if hour == 2 {
                labels(&s, 0, &member(77).public_key(), Some("a label"), t);
                // The other channel is read again at once: its day is its
                // own.
                assert_eq!(read_again_due(&s[0].conn, t).unwrap(), [other.id]);
                read_again_begun(&s[0].conn, &other.id, t).unwrap();
            }
        }
        let day = start + 24 * HOUR;
        assert_eq!(
            read_again_due(&s[0].conn, day - 1).unwrap(),
            Vec::<[u8; 32]>::new()
        );
        assert_eq!(read_again_due(&s[0].conn, day).unwrap(), [channel.id]);
        read_again_begun(&s[0].conn, &channel.id, day).unwrap();
        assert!(read_again_due(&s[0].conn, day).unwrap().is_empty());
        assert!(
            read_again_due(&s[0].conn, day + 24 * HOUR)
                .unwrap()
                .is_empty()
        );
    }

    /// One ID in two channels is two messages (decision 2026-10-10 §4.2):
    /// a member writes one value in two channels, and the index holds two
    /// rows, one in each, each shown in its own channel. A clearing in one
    /// drops the row of that one alone.
    #[test]
    fn one_id_in_two_channels_is_two_messages() {
        let s = bob(1);
        let now = s.now + 10;
        let (one, two) = (holds(&s, 0, 1, "a", now), holds(&s, 0, 2, "b", now));
        let alice = member(1);
        for channel in [&one, &two] {
            let read = stores(&s, 0, &message(&alice, channel, 1, "the same", now), now);
            assert_eq!(read, Some(Read::Message(Indexed::New)));
        }
        let ids: Vec<(i64, Vec<u8>)> = s[0]
            .conn
            .prepare("SELECT channel, id FROM shared_index ORDER BY channel")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].1, ids[1].1);
        assert_ne!(ids[0].0, ids[1].0);
        assert_eq!(bodies(&s, 0, &one, now), ["the same"]);
        assert_eq!(bodies(&s, 0, &two, now), ["the same"]);

        let name = message_name(&alice.public_key(), 1).unwrap();
        let cleared = entry_by(
            &alice,
            &one.secret,
            clearing_rev(1).unwrap(),
            &name,
            Value::Other(cordelia_crypto::message::clearing_value()),
            &[],
        );
        assert_eq!(
            stores(&s, 0, &cleared, now),
            Some(Read::Clearing { dropped: true })
        );
        assert!(bodies(&s, 0, &one, now).is_empty());
        assert_eq!(bodies(&s, 0, &two, now), ["the same"]);
    }

    /// A shared message goes from the index at its 30 days, by the hourly
    /// task, overwritten first (decision 2026-10-10 §6.1; the messages
    /// record's §7.1), and its entry stays in the store.
    #[test]
    fn a_shared_message_goes_from_the_index_at_its_30_days() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "a", now);
        let alice = member(1);
        // Labelled, so that it is not let go as quiet at the same moment.
        labels(&s, 0, &alice.public_key(), Some("alice"), now);
        stores(
            &s,
            0,
            &message(&alice, &channel, 1, "a body nothing else says", now),
            now,
        );
        assert_eq!(bodies(&s, 0, &channel, now), ["a body nothing else says"]);
        s[0].conn
            .execute_batch(
                "CREATE TEMP TABLE overwritten (body BLOB);
                 CREATE TEMP TRIGGER kept_body BEFORE DELETE ON main.shared_index
                 BEGIN INSERT INTO overwritten VALUES (CAST(old.body AS BLOB)); END;",
            )
            .unwrap();
        assert_eq!(
            hourly(&s[0].conn, &s.key(0), now + 30 * DAY - 1)
                .unwrap()
                .gone,
            0
        );
        // The node's hourly task runs the shared channels' part.
        crate::reader::hourly(&s[0].conn, &s[0].identity, now + 30 * DAY, false).unwrap();
        assert_eq!(indexed(&s, 0, &channel), 0);
        let body: Vec<u8> = s[0]
            .conn
            .query_row("SELECT body FROM overwritten", [], |row| row.get(0))
            .unwrap();
        assert_eq!(body, vec![0; "a body nothing else says".len()]);
        assert_eq!(held_by(&s, 0, &channel, &alice.public_key()).len(), 1);
    }

    /// The bound of a message's value is the one an entry of a message slot
    /// seals at: what the door's size check rests on.
    #[test]
    fn a_message_and_an_anew_record_seal_at_their_slots_sizes() {
        let channel = Shared::of(1);
        let alice = member(1);
        assert_eq!(
            says("x", 0).to_value().unwrap().len(),
            AGENT_MESSAGE_VALUE_BYTES
        );
        assert_eq!(
            message(&alice, &channel, 1, "x", 0).content.len(),
            AGENT_MESSAGE_CONTENT_BYTES
        );
        assert_eq!(
            anew(&alice, &channel, 1).content.len(),
            SHARED_ANEW_CONTENT_BYTES
        );
    }

    /// The holds of the lock of `kind` taken since `before`: how many, the
    /// longest in microseconds, and how many were over 100 ms.
    fn holds_since(
        db: &cordelia_core::lock::TimedLock<Connection>,
        kind: cordelia_core::load::Kind,
        before: &cordelia_core::load::HistogramRead,
    ) -> (u64, u64, u64) {
        let after = db.times().hold(kind);
        let over_100 = cordelia_core::protocol::LOCK_COUNTED_OVER_MS
            .iter()
            .position(|ms| *ms == 100)
            .unwrap();
        (
            after.count - before.count,
            after.max_micros,
            after.over[over_100] - before.over[over_100],
        )
    }

    /// **A take-out holds the lock one key at a time** (decision 2026-10-10
    /// §6.3, "taken out in steps"; §13; §19, item 19): a drop of a channel
    /// at 42 MiB, and the hourly task letting 5,461 quiet keys go, each take
    /// the lock once for each key, and no hold of it is over 100 ms (bar 5
    /// of the scale test, decision 2026-10-22). A stop between two steps
    /// leaves no key half taken out: each key is whole in the store and
    /// still going, or gone with its revisions kept; the door stores
    /// nothing more of a key going, and the reader shows nothing of it; and
    /// the next start ends the take-out.
    ///
    /// Not under coverage (CI's coverage job builds with `--cfg
    /// coverage`): its counters are in the holds it bounds, and they ran
    /// over 100 ms there on 28 October; CI's test job runs it whole.
    #[test]
    #[cfg_attr(
        coverage,
        ignore = "under coverage, its counters are in the holds it bounds"
    )]
    fn a_take_out_holds_the_lock_one_key_at_a_time() {
        use cordelia_core::load::Kind;
        use cordelia_core::lock::{LockWhole, TimedLock, taking};
        use cordelia_core::protocol::{
            AGENT_MESSAGE_CONTENT_BYTES as MESSAGE, MAX_ENTRY_CHANNEL_BYTES_AT_RELAY as ROOM,
        };

        // ── A drop of a channel at 42 MiB ──
        let mut s = bob(1);
        let now = s.now + 10;
        let own = s.key(0);
        let channel = holds(&s, 0, 1, "review", now);
        // 5,461 keys the person does not know, a message each, fill the
        // room: 16 MiB as counted.
        let unknown = ROOM / entry_cost(MESSAGE);
        assert_eq!(unknown, 5_461);
        for k in 0..unknown as u32 {
            let entry = message(&member(10_000 + k), &channel, 1, "m", now);
            entries::store(&s[0].conn, &entry, now).unwrap();
        }
        // And 128 keys at their whole 214,016 bytes each: as many as the
        // person's own devices and labelled keys can be.
        for k in 0..128 {
            let key = member(20_000 + k);
            for number in 1..=AGENT_MESSAGE_RING as u64 {
                let entry = message(&key, &channel, number, "m", now);
                entries::store(&s[0].conn, &entry, now).unwrap();
            }
            entries::store(&s[0].conn, &anew(&key, &channel, 1), now).unwrap();
        }
        let held = entries::channel_cost(&s[0].conn, &channel.id).unwrap();
        assert_eq!(held, unknown * entry_cost(MESSAGE) + 128 * 214_016);
        assert!(held > 42 * 1024 * 1024, "{held}");
        // The drop is made: its first step, under the act's hold.
        let done = act(&s[0].conn, &s[0].identity, Do::Drop(channel.id), now + 1).unwrap();
        assert!(matches!(done, Done::Made(_)), "{done:?}");
        assert_eq!(row(&s, 0, &channel).state, State::Dropped);
        // The door stores nothing more of a channel whose entries are going.
        assert!(
            crate::shared::taken_as_shared(
                &s[0].conn,
                &message(&member(1), &channel, 9, "late", now),
                now
            )
            .unwrap()
            .is_none()
        );
        let machine = s.machines.remove(0);
        let db = TimedLock::new(machine.conn);
        let before = db.times().hold(Kind::Pass);
        {
            let _pass = taking(Kind::Pass);
            take_out_in_steps(&db, &own, now + 2).unwrap();
        }
        let (takes, longest, over) = holds_since(&db, Kind::Pass, &before);
        assert!(takes >= unknown + 128, "{takes}");
        assert_eq!(over, 0, "the longest hold was {longest} µs");
        let conn = db.lock_whole();
        assert_eq!(entries::channel_cost(&conn, &channel.id).unwrap(), 0);
        assert!(!pass_rows::any_going(&conn).unwrap());
        drop(conn);

        // ── The hourly task lets 5,461 quiet keys go ──
        let mut s = bob(1);
        let own = s.key(0);
        let identity = NodeIdentity::from_seed(*s[0].identity.seed()).unwrap();
        let channel = holds(&s, 0, 1, "review", now);
        let id = row(&s, 0, &channel).id;
        let keys: Vec<NodeIdentity> = (0..unknown as u32).map(|k| member(30_000 + k)).collect();
        for key in &keys {
            let entry = message(key, &channel, 1, "m", now);
            entries::store(&s[0].conn, &entry, now).unwrap();
            let cost = i64::try_from(entry_cost(MESSAGE)).unwrap();
            kept::stored(&s[0].conn, id, &key.public_key(), false, cost, now).unwrap();
        }
        let machine = s.machines.remove(0);
        let db = TimedLock::new(machine.conn);
        let later = now + 30 * DAY;
        let before = db.times().hold(Kind::Checkpoint);
        {
            let _checkpoint = taking(Kind::Checkpoint);
            // The choice of quiet keys, written in one hold.
            let chosen = super::hourly(&db.lock_whole(), &own, later).unwrap();
            assert_eq!(chosen.let_go, keys.len());
            // A stop after a hundred steps.
            for _ in 0..100 {
                assert_eq!(
                    take_out_step(&db.lock_whole(), later).unwrap(),
                    Stepped::Key
                );
            }
        }
        // What the store holds after the stop, read under a hold of
        // another kind.
        {
            let conn = db.lock_whole();
            let mut gone = 0;
            for key in &keys {
                let key = key.public_key();
                let going = pass_rows::key_going(&conn, id, &key).unwrap();
                let left = conn
                    .query_row(
                        "SELECT COUNT(*) FROM entries WHERE channel_id = ?1 AND author = ?2",
                        rusqlite::params![&channel.id[..], &key[..]],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap();
                let row_of = kept::key(&conn, id, &key).unwrap().unwrap();
                match going {
                    // Whole in the store, and still going.
                    true => assert_eq!((left, row_of.kept_message_rev), (1, None)),
                    // Gone, with its revisions kept.
                    false => {
                        assert_eq!(left, 0);
                        assert_eq!(row_of.kept_message_rev, Some(2));
                        gone += 1;
                    }
                }
            }
            assert_eq!(gone, 100);
            // The door stores nothing more of a key going, and the reader
            // shows nothing of it.
            // The first key still going: the next in the order shown.
            let going = &keys[100];
            assert!(pass_rows::key_going(&conn, id, &going.public_key()).unwrap());
            let next = message(going, &channel, 2, "after the stop", later);
            assert_eq!(
                take(&conn, &identity, &next, later).unwrap(),
                Taken::Refused(NotTaken::SharedFull)
            );
            assert!(
                !shown_keys(&conn, &channel.id)
                    .unwrap()
                    .contains(&going.public_key())
            );
        }
        // The next start ends it.
        {
            let _checkpoint = taking(Kind::Checkpoint);
            take_out_in_steps(&db, &own, later).unwrap();
        }
        let (takes, longest, over) = holds_since(&db, Kind::Checkpoint, &before);
        assert!(takes >= unknown, "{takes}");
        assert_eq!(over, 0, "the longest hold was {longest} µs");
        let conn = db.lock_whole();
        assert_eq!(entries::channel_cost(&conn, &channel.id).unwrap(), 0);
        assert!(!pass_rows::any_going(&conn).unwrap());
        assert_eq!(kept::room(&conn, id).unwrap(), 0);
    }

    /// A channel filed again while its entries are being taken out is held
    /// again only once the take-out has ended (decision 2026-10-10 §6.3):
    /// meanwhile the door stores nothing of it, and what it held goes whole.
    #[test]
    fn a_channel_filed_again_while_its_entries_go_is_held_once_they_have_gone() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        stores(&s, 0, &message(&member(1), &channel, 1, "one", now), now);
        let conn = &s[0].conn;
        let made = act(conn, &s[0].identity, Do::Drop(channel.id), now + 1).unwrap();
        assert!(matches!(made, Done::Made(_)));
        let made = act(conn, &s[0].identity, Do::File(filing(1, "review")), now + 2).unwrap();
        assert!(matches!(made, Done::Made(_)));
        assert_eq!(row(&s, 0, &channel).state, State::Dropped);
        let late = message(&member(1), &channel, 2, "two", now + 2);
        assert!(taken_as_shared(conn, &late, now + 2).unwrap().is_none());
        take_out_all(conn, &s.key(0), now + 3).unwrap();
        assert_eq!(row(&s, 0, &channel).state, State::Held);
        assert!(s[0].stored_in(&channel.secret).is_empty());
        assert!(bodies(&s, 0, &channel, now + 3).is_empty());
        stores(&s, 0, &late, now + 3);
        assert_eq!(bodies(&s, 0, &channel, now + 3), ["two"]);
    }

    /// What the take-outs begun will take out of the room is counted as gone
    /// already (decision 2026-10-10 §6.3): a keeping before their steps
    /// begins no more than the room needs. Carol's key stops being known in
    /// a full room, which is then past its bound: her entries are begun,
    /// and keeping again before the step begins nothing more.
    #[test]
    fn a_take_out_begun_is_counted_as_gone_from_the_room() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let carol = member(2);
        labels(&s, 0, &carol.public_key(), Some("carol"), now);
        stores(&s, 0, &message(&carol, &channel, 1, "carol's", now), now);
        fill_to(&s, 0, &channel, FULL, now);
        let conn = &s[0].conn;
        let id = row(&s, 0, &channel).id;
        let unlabel = Label {
            key: carol.public_key(),
            label: None,
        };
        let made = act(conn, &s[0].identity, Do::Label(unlabel), now + 1).unwrap();
        assert!(matches!(made, Done::Made(_)));
        let going = |conn: &Connection| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM shared_take_out_keys WHERE channel = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(going(conn), 1);
        assert!(pass_rows::key_going(conn, id, &carol.public_key()).unwrap());
        keep(conn, &s.key(0), now + 2).unwrap();
        keep(conn, &s.key(0), now + 3).unwrap();
        assert_eq!(going(conn), 1);
        take_out_all(conn, &s.key(0), now + 4).unwrap();
        assert_eq!(going(conn), 0);
        assert!(kept::room(conn, id).unwrap() <= MAX_ENTRY_CHANNEL_BYTES_AT_RELAY);
        assert!(held_by(&s, 0, &channel, &carol.public_key()).is_empty());
    }

    /// The review's sequence (decision 2026-10-10 §6.3, "taken out in
    /// steps"): Carol's key is quiet for 30 days and the hourly task begins
    /// her take-out; before its step, the person labels her. Her take-out
    /// ends with no step: her entries stay, and her row keeps no revision.
    #[test]
    fn a_key_labelled_while_it_goes_is_not_taken_out() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let (carol, dave) = (member(2), member(3));
        stores(&s, 0, &message(&carol, &channel, 1, "carol's", now), now);
        stores(&s, 0, &message(&dave, &channel, 1, "dave's", now), now);
        let conn = &s[0].conn;
        let id = row(&s, 0, &channel).id;
        let later = now + 30 * DAY;
        assert_eq!(super::hourly(conn, &s.key(0), later).unwrap().let_go, 2);
        assert!(pass_rows::key_going(conn, id, &carol.public_key()).unwrap());
        let label = Label {
            key: carol.public_key(),
            label: Some("carol".into()),
        };
        let made = act(conn, &s[0].identity, Do::Label(label), later).unwrap();
        assert!(matches!(made, Done::Made(_)));
        assert!(!pass_rows::key_going(conn, id, &carol.public_key()).unwrap());
        take_out_all(conn, &s.key(0), later).unwrap();
        let of_carol = key_row(&s, 0, &channel, &carol.public_key()).unwrap();
        assert!(of_carol.known);
        assert_eq!(of_carol.kept_message_rev, None);
        assert_eq!(held_by(&s, 0, &channel, &carol.public_key()).len(), 1);
        assert!(held_by(&s, 0, &channel, &dave.public_key()).is_empty());
        stores(&s, 0, &message(&carol, &channel, 2, "again", later), later);
        assert_eq!(bodies(&s, 0, &channel, later), ["again"]);
    }

    /// A key the person knows when its step comes is not taken out, however
    /// its take-out was begun; and the door stores what it writes, ending
    /// its take-out, rather than refusing it as full (§6.3).
    #[test]
    fn a_key_known_when_its_step_comes_is_not_taken_out() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let carol = member(2);
        labels(&s, 0, &carol.public_key(), Some("carol"), now);
        stores(&s, 0, &message(&carol, &channel, 1, "one", now), now);
        let conn = &s[0].conn;
        let id = row(&s, 0, &channel).id;

        // The step finds her known: it ends her take-out and takes nothing.
        pass_rows::begin_key(conn, id, &carol.public_key(), false).unwrap();
        assert_eq!(take_out_step(conn, now + 1).unwrap(), Stepped::Key);
        assert!(!pass_rows::key_going(conn, id, &carol.public_key()).unwrap());
        assert_eq!(held_by(&s, 0, &channel, &carol.public_key()).len(), 1);
        assert_eq!(
            key_row(&s, 0, &channel, &carol.public_key())
                .unwrap()
                .kept_message_rev,
            None
        );

        // The door finds her known while she goes: it stores her entry.
        pass_rows::begin_key(conn, id, &carol.public_key(), false).unwrap();
        let two = message(&carol, &channel, 2, "two", now + 2);
        assert!(matches!(
            take(conn, &s[0].identity, &two, now + 2).unwrap(),
            Taken::Shared {
                stored: Outcome::Stored,
                ..
            }
        ));
        assert!(!pass_rows::key_going(conn, id, &carol.public_key()).unwrap());
        out(&s, 0, now + 2);
        assert_eq!(held_by(&s, 0, &channel, &carol.public_key()).len(), 2);
        assert_eq!(bodies(&s, 0, &channel, now + 2), ["one", "two"]);
        // Quiet for 30 days, she is known: the hourly task lets her go not.
        let later = now + 2 + 30 * DAY;
        assert_eq!(super::hourly(conn, &s.key(0), later).unwrap().let_go, 0);
        assert!(!pass_rows::key_going(conn, id, &carol.public_key()).unwrap());
    }

    /// A step of a channel's take-out takes out at most
    /// `SHARED_TAKE_OUT_STEP_ENTRIES` of one key's entries (§6.3): the door
    /// stores no more than that of a key, and the bound holds of a store
    /// that holds more all the same.
    #[test]
    fn a_step_takes_out_at_most_its_bound_of_one_keys_entries() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let carol = member(2);
        let more = SHARED_TAKE_OUT_STEP_ENTRIES as u64 + 5;
        for n in 0..more {
            let name = format!("other/{n}");
            let entry = entry_by(
                &carol,
                &channel.secret,
                2,
                &name,
                Value::Other(vec![1]),
                &[],
            );
            entries::store(&s[0].conn, &entry, now).unwrap();
        }
        let conn = &s[0].conn;
        let id = row(&s, 0, &channel).id;
        pass_rows::begin_channel(conn, id, ChannelOut::Dropped).unwrap();
        assert_eq!(take_out_step(conn, now).unwrap(), Stepped::OfAChannel);
        assert_eq!(held_by(&s, 0, &channel, &carol.public_key()).len(), 5);
    }

    /// A quiet key that writes while its entries go: the door refuses the
    /// entry and notes it, and the step that ends the take-out asks a read
    /// again, which stores it (§6.3).
    #[test]
    fn what_a_quiet_key_writes_while_it_goes_is_read_again() {
        let s = bob(1);
        let now = s.now + 10;
        let channel = holds(&s, 0, 1, "review", now);
        let carol = member(2);
        stores(&s, 0, &message(&carol, &channel, 1, "one", now), now);
        let conn = &s[0].conn;
        let later = now + 30 * DAY;
        assert_eq!(super::hourly(conn, &s.key(0), later).unwrap().let_go, 1);
        assert!(read_again_due(conn, later).unwrap().is_empty());
        let two = message(&carol, &channel, 2, "two", later);
        assert_eq!(
            take(conn, &s[0].identity, &two, later).unwrap(),
            Taken::Refused(NotTaken::SharedFull)
        );
        // One it holds already is refused and not noted.
        let refused = |s: &Several| {
            key_row(s, 0, &channel, &carol.public_key())
                .unwrap()
                .bytes_refused
        };
        assert_eq!(refused(&s), MESSAGE_COST);
        let one = message(&carol, &channel, 1, "one", now);
        assert_eq!(
            take(conn, &s[0].identity, &one, later).unwrap(),
            Taken::Refused(NotTaken::SharedFull)
        );
        assert_eq!(refused(&s), MESSAGE_COST);
        take_out_all(conn, &s.key(0), later).unwrap();
        assert_eq!(read_again_due(conn, later).unwrap(), [channel.id]);
        read_again_begun(conn, &channel.id, later).unwrap();
        // The read again hands it again, and the store keeps it.
        stores(&s, 0, &two, later);
        assert_eq!(bodies(&s, 0, &channel, later), ["two"]);
    }
}
