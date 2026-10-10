//! The sender of messages between the person's own agents (decision
//! 2026-10-09 §2.3, §2.4, §6, §7.1, §9.1).
//!
//! Everything a device does to send, as functions over its store and the
//! node's clock, each given the time it acts at. Nothing here prints:
//! each refusal is a value with the word that the record gives it
//! ([`Refused::word`]), for a route to answer with.
//!
//! - **[`send`]** makes the node's checks of §4.3 that are the sender's,
//!   in their order, and writes the message: its entry in the slot of its
//!   number, its index row, its row of numbers held, its row of first
//!   holding and its place, the record of the send and the kept value,
//!   in one transaction (§2.3, F9).
//! - **The next number** is one above the highest number of any entry the
//!   device holds in its own ring in the generation applied, clearings
//!   included, read from the store each time ([`next_number`]).
//! - **Sending again** (§2.3, C18): a message that not every relay has
//!   taken is kept apart, and written again under the next number where a
//!   relay answers that it holds another entry of the device's at that
//!   revision ([`answered`]), or hands back the device's own entry over
//!   it (the reader marks that, [`crate::reader::taken`]). At most four
//!   numbers for a message ([`write_again`]).
//! - **Clearing** (§2.3): the middle step of the hourly task writes the
//!   entry that clears each of the device's own messages whose 30 days
//!   are up ([`clear_expired`]).
//!
//! **Before its first fetch of the messages channel since it started, a
//! device writes nothing there** (§2.3): no message, no message sent
//! again and no clearing. Whoever calls says whether the channel was
//! fetched, as `OwnChannels::first_fetch_done` answers it ([`fetched`]).

use std::time::Instant;

use rusqlite::Connection;

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{
    AGENT_MESSAGE_PAIR_UNREAD_MAX, AGENT_MESSAGE_RING, AGENT_MESSAGE_SENDS_MAX,
    AGENT_MESSAGES_PER_DEVICE_PER_HOUR, AGENT_MESSAGES_PER_FOLDER_PER_HOUR,
};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{
    self, Message, NotAMessage, To, clearing_rev, clearing_value, message_id, message_name,
    message_rev, number_of,
};
use cordelia_crypto::slots::slot_id;
use cordelia_storage::StorageError;
use cordelia_storage::entries::{self, Outcome};
use cordelia_storage::messages::{self as held, Id, Kept, Opened};
use cordelia_storage::meta;

use crate::at_relays::{Kind, Own, Pushed, Stands, stands};
use crate::person::{PersonError, in_one};
use crate::publish::Standing;
use crate::state::OwnChannels;

/// An hour, in seconds: the window of the sender's rates (§6).
const HOUR_SECS: i64 = 60 * 60;

/// Why a device sends no message (decision 2026-10-09 §4.3). Each has the
/// word that a route answers with; the command prints its line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// The device does not stand applied (step 4).
    #[error("this device is not one of the person's devices now")]
    NotApplied,
    /// Sync is off, and so are messages (step 5, C12).
    #[error("sync is off on this device, and so are messages")]
    SyncOff,
    /// The messages channel has no place among the proofs of a
    /// connection (step 6, §2.1).
    #[error("this device has no place for the messages channel")]
    NoPlace,
    /// The folder's rate is set to 0 (step 7, §6).
    #[error("sending is off for this folder")]
    SendingOff,
    /// The messages channel has not been fetched since the node started
    /// (step 8, §2.3).
    #[error("the messages channel has not been fetched since the node started")]
    NotFetched,
    /// The next number would be above 2^42 - 1 (step 8, §2.3).
    #[error("this device has used every number a message can have")]
    NoNumbers,
    /// The device's clock is behind the newest `sent` of its own (step
    /// 8, §7.1).
    #[error("this device's clock is behind the time of a message it already sent")]
    ClockBehind,
    /// The recipient is no name the personal channel lists (step 10).
    #[error("no device of the person's syncs {0}")]
    NoSuchName(String),
    /// The folder has sent its limit in the hour (step 11).
    #[error("this agent has sent {limit} messages in the last hour")]
    FolderRate {
        limit: usize,
        /// When the next can go, by the device's clock.
        next_at: i64,
    },
    /// The device has sent 60 in the hour, sends again included (step 11).
    #[error("this device has sent {sends} messages, and {again} again, in the last hour")]
    DeviceRate {
        sends: usize,
        again: usize,
        next_at: i64,
    },
    /// The pair is held (step 12, §6). `other` is the other side of the
    /// held pair, or `None` where it is the sender's own to every name;
    /// `every` says that the refused message was to every name.
    #[error("messages between {from} and another agent wait to be read by a person")]
    PairHeld {
        from: String,
        other: held::Other,
        every: bool,
    },
}

impl Refused {
    /// The word of the refusal (decision 2026-10-09 §4.3).
    pub fn word(&self) -> &'static str {
        match self {
            Self::NotApplied => "not_applied",
            Self::SyncOff => "sync_off",
            Self::NoPlace => "no_place",
            Self::SendingOff => "sending_off",
            Self::NotFetched => "not_fetched",
            Self::NoNumbers => "no_numbers",
            Self::ClockBehind => "clock_behind",
            Self::NoSuchName(_) => "no_such_name",
            Self::FolderRate { .. } => "folder_rate",
            Self::DeviceRate { .. } => "device_rate",
            Self::PairHeld { .. } => "pair_held",
        }
    }
}

/// Why a send did not happen.
#[derive(Debug, thiserror::Error)]
pub enum NotSent {
    /// One of the refusals of §4.3.
    #[error(transparent)]
    Refused(Refused),
    /// What was asked is no message that a reader would take (§2.2): the
    /// node checks what every reader checks before it seals.
    #[error(transparent)]
    NotAMessage(NotAMessage),
    #[error(transparent)]
    Failed(#[from] PersonError),
}

/// What the device knows besides its store when it sends: the node's
/// clock, and what the node holds in memory (decision 2026-10-09 §2.1,
/// §2.3, §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct At {
    /// The node's clock, in seconds.
    pub now: i64,
    /// Whether the messages channel was fetched since the node started
    /// ([`fetched`]).
    pub fetched: bool,
    /// Whether the messages channel has no place among the proofs of a
    /// connection (`OwnChannels::no_place`).
    pub no_place: bool,
    /// The folder's limit for the hour in the configuration (`[messages]
    /// per_folder_per_hour`). It may lower `AGENT_MESSAGES_PER_FOLDER_
    /// PER_HOUR`, and is never taken above it.
    pub per_folder_per_hour: usize,
}

/// A message that the agent of a folder asks to send: its addressing
/// resolved by whoever asks (a reply's recipient, thread and `answers`
/// are the node's, from the message it answers, §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The agent of the folder the command was run in.
    pub from: String,
    pub to: To,
    pub asks: bool,
    pub link: Option<String>,
    pub body: String,
    pub thread: Id,
    pub answers: Id,
}

/// A message that was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sent {
    pub id: Id,
    /// The number it was written under.
    pub number: u64,
}

/// Whether the messages channel of the generation that this device stands
/// applied under was fetched since the node started, at `now` by its
/// monotonic clock (decision 2026-10-09 §2.3): exactly as
/// `OwnChannels::first_fetch_done` answers it of that channel. No for a
/// device that does not stand applied.
pub fn fetched(
    conn: &Connection,
    own_channels: &OwnChannels,
    now: Instant,
) -> Result<bool, PersonError> {
    Ok(crate::at_relays::messages_channel(conn)?
        .is_some_and(|channel| own_channels.first_fetch_done(&channel, now)))
}

/// The ring of this device in the messages channel of the generation it
/// stands applied under.
struct Ring<'a> {
    identity: &'a NodeIdentity,
    own: [u8; 32],
    secret: [u8; 32],
    channel: [u8; 32],
    slot_key: [u8; 32],
    statement: u64,
}

impl<'a> Ring<'a> {
    fn of(conn: &Connection, identity: &'a NodeIdentity) -> Result<Self, PersonError> {
        let standing = Standing::to_write(conn)?;
        let secret = derive::messages_secret(&standing.secret)?;
        Ok(Self {
            identity,
            own: identity.public_key(),
            channel: derive::channel_id(&secret)?,
            slot_key: derive::slot_key(&secret)?,
            secret,
            statement: standing.number(),
        })
    }

    /// The slot of message `number`, and of its clearing.
    fn slot(&self, number: u64) -> Result<[u8; 32], PersonError> {
        Ok(slot_id(&self.slot_key, &message_name(&self.own, number)?))
    }

    /// The entry of the device's own that the store holds in each slot of
    /// its ring, with the slot's place.
    fn held(&self, conn: &Connection) -> Result<Vec<(u64, CheckedEntry)>, PersonError> {
        let mut held = Vec::new();
        for place in 0..AGENT_MESSAGE_RING as u64 {
            let slot = self.slot(place)?;
            if let Some(stored) = entries::author_entry(conn, &self.channel, &slot, &self.own)? {
                held.push((place, stored.entry.check()?));
            }
        }
        Ok(held)
    }

    fn generation(&self, conn: &Connection, now: i64) -> Result<i64, PersonError> {
        kept(held::generation(conn, &self.channel, self.statement, now))
    }
}

/// The next number this device gives a message (decision 2026-10-09
/// §2.3, C1): one above the highest number of any entry of its own that
/// its store holds in the slots of its ring, in the generation it stands
/// applied under, clearings included. It is read from the store each
/// time, so it is the same after a restart. `None` once it would be above
/// the highest number a message can have.
pub fn next_number(conn: &Connection, identity: &NodeIdentity) -> Result<Option<u64>, PersonError> {
    let ring = Ring::of(conn, identity)?;
    next_in(conn, &ring)
}

fn next_in(conn: &Connection, ring: &Ring) -> Result<Option<u64>, PersonError> {
    let highest = ring
        .held(conn)?
        .iter()
        .map(|(_, entry)| number_of(entry.rev))
        .max()
        .unwrap_or(0);
    Ok(message::next_number(highest))
}

/// Send `request` as this device, at `at` (decision 2026-10-09 §2.3, §4.3,
/// §6): the node's checks of §4.3 that are the sender's, in their order,
/// the first that applies refusing, and then the message is written, in
/// one transaction. The folder's mapping (step 7) and the message a reply
/// answers (step 9) are the caller's, before this.
pub fn send(
    conn: &Connection,
    identity: &NodeIdentity,
    at: &At,
    request: &Request,
) -> Result<Sent, NotSent> {
    // A refusal writes nothing, and a failure takes back what was written.
    in_one(conn, || match sends(conn, identity, at, request) {
        Err(NotSent::Failed(e)) => Err(e),
        done => Ok(done),
    })?
}

fn sends(
    conn: &Connection,
    identity: &NodeIdentity,
    at: &At,
    request: &Request,
) -> Result<Sent, NotSent> {
    let refused = |why: Refused| Err(NotSent::Refused(why));
    let now = at.now;
    // 4. The device.
    if stands(conn)? != Stands::Applied {
        return refused(Refused::NotApplied);
    }
    // 5. Sync.
    if meta::get(conn, meta::SYNC_CLAUDE_DIR)
        .map_err(PersonError::from)?
        .is_none()
    {
        return refused(Refused::SyncOff);
    }
    // 6. Room for proofs.
    if at.no_place {
        return refused(Refused::NoPlace);
    }
    // 7. The folder's rate, where the configuration sets it to 0.
    let folder_limit = at
        .per_folder_per_hour
        .min(AGENT_MESSAGES_PER_FOLDER_PER_HOUR);
    if folder_limit == 0 {
        return refused(Refused::SendingOff);
    }
    // 8. The ring: fetched, a number left, and the clock.
    if !at.fetched {
        return refused(Refused::NotFetched);
    }
    let ring = Ring::of(conn, identity)?;
    let Some(number) = next_in(conn, &ring)? else {
        return refused(Refused::NoNumbers);
    };
    if kept(held::newest_own_sent(conn, &ring.own, now))?.is_some_and(|newest| newest > now) {
        return refused(Refused::ClockBehind);
    }
    // 10. The recipient: a name that the personal channel lists.
    if let To::Name(name) = &request.to
        && !crate::names::listed(conn)?
            .iter()
            .any(|listed| listed.name == *name)
    {
        return refused(Refused::NoSuchName(name.clone()));
    }
    // 11. The rates: the folder's, then the device's.
    let lately = kept(held::sent_lately(conn, &request.from, now))?;
    if lately.by_folder.len() >= folder_limit {
        return refused(Refused::FolderRate {
            limit: folder_limit,
            next_at: frees_at(&lately.by_folder, folder_limit),
        });
    }
    if let Some(next_at) = device_full(&lately) {
        return refused(Refused::DeviceRate {
            sends: lately.sends.len(),
            again: lately.again.len(),
            next_at,
        });
    }
    // 12. The hold.
    if let Some(other) = held_pair(conn, &request.from, &request.to, now)? {
        return refused(Refused::PairHeld {
            from: request.from.clone(),
            other,
            every: request.to == To::All,
        });
    }

    let message = Message {
        asks: request.asks,
        sent: u64::try_from(now).unwrap_or(0),
        nonce: nonce()?,
        thread: request.thread,
        answers: request.answers,
        from: request.from.clone(),
        to: request.to.clone(),
        link: request.link.clone(),
        body: request.body.clone(),
    };
    let value = message
        .to_value(crate::names::is_a_name)
        .map_err(NotSent::NotAMessage)?;
    let id = message_id(&ring.own, &value);
    let generation = written(conn, &ring, number, &value, &message, now)?;
    kept(held::drop_kept_gone(conn, generation, now))?;
    let kept_value = Kept {
        id,
        generation,
        value,
        sent: now,
        numbers: vec![number],
        again: false,
    };
    kept(held::keep(conn, &kept_value, now))?;
    kept(held::record_send(
        conn,
        now,
        Some(&request.from),
        request.to == To::All,
    ))?;
    Ok(Sent { id, number })
}

/// When a count of `limit` within the hour, of rows at `times` oldest
/// first, next has room: the hour after the row whose going leaves fewer
/// than `limit`.
fn frees_at(times: &[i64], limit: usize) -> i64 {
    let leaves = times.len().saturating_sub(limit);
    times.get(leaves).map_or(0, |at| at + HOUR_SECS)
}

/// Where the device has sent 60 in the hour, sends again included, when
/// the next can go (decision 2026-10-09 §6).
fn device_full(lately: &held::SentLately) -> Option<i64> {
    let mut all: Vec<i64> = lately.sends.iter().chain(&lately.again).copied().collect();
    if all.len() < AGENT_MESSAGES_PER_DEVICE_PER_HOUR {
        return None;
    }
    all.sort_unstable();
    Some(frees_at(&all, AGENT_MESSAGES_PER_DEVICE_PER_HOUR))
}

/// Whether a send from the agent `from` to `to` is held at `now` by the
/// pair of agents (decision 2026-10-09 §6, C8, D6, F2): the other side of
/// the held pair where it is. Counted are the messages the device holds
/// with a place, not expired, live, and that no person has read here
/// (`message_read_by_a_person`, which `log`'s yes writes). A message to
/// every name is of the pair of its sender and all.
///
/// - To a name Y, the pair of `from` and Y holds at ten.
/// - To every name, any pair with `from` on one side holds: the first in
///   order of name, and its own to every name after them.
pub fn held_pair(
    conn: &Connection,
    from: &str,
    to: &To,
    now: i64,
) -> Result<Option<held::Other>, PersonError> {
    let pairs = kept(held::pairs_with(conn, from, now))?;
    let held = |count: u64| count >= AGENT_MESSAGE_PAIR_UNREAD_MAX as u64;
    Ok(match to {
        To::Name(name) => pairs
            .into_iter()
            .find(|(other, count)| other.as_deref() == Some(name.as_str()) && held(*count))
            .map(|(other, _)| other),
        To::All => pairs
            .into_iter()
            .find(|(_, count)| held(*count))
            .map(|(other, _)| other),
    })
}

/// Sixteen random bytes, so that two messages with the same words are two
/// messages (§2.2).
fn nonce() -> Result<[u8; 16], PersonError> {
    let random = cordelia_crypto::generate_psk()?;
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&random[..16]);
    Ok(nonce)
}

/// Write `message`, whose value is `value`, as the device's own entry at
/// `number` in its ring, and into its index at once (decision 2026-10-09
/// §2.3, F9): H is raised, and its index row, its row of numbers held and
/// its row of first holding are written, with its place, which has no
/// time in any signer's hour. A message held at another number already
/// gains this one. Returns its generation.
fn written(
    conn: &Connection,
    ring: &Ring,
    number: u64,
    value: &[u8],
    message: &Message,
    now: i64,
) -> Result<i64, PersonError> {
    let rev = message_rev(number).ok_or(PersonError::Held(
        "a message's number is above the highest".into(),
    ))?;
    seal(conn, ring, number, rev, value.to_vec(), now)?;
    let generation = ring.generation(conn, now)?;
    kept(held::hold_number(
        conn, &ring.own, generation, number, false,
    ))?;
    let label = own_label(conn, &ring.own)?;
    let id = message_id(&ring.own, value);
    let opened = Opened {
        id: &id,
        signer: &ring.own,
        label: &label,
        generation,
        number,
        message,
        first_held: now,
        placed_at: Some(now),
    };
    kept(held::index(conn, &opened))?;
    Ok(generation)
}

/// Seal `value` as the device's own entry in the slot of `number` at
/// `rev`, and store it: the store must take it, being above everything
/// the device holds in its ring.
fn seal(
    conn: &Connection,
    ring: &Ring,
    number: u64,
    rev: u64,
    value: Vec<u8>,
    now: i64,
) -> Result<CheckedEntry, PersonError> {
    let inside = message::inside(message_name(&ring.own, number)?, value);
    let entry = Entry::seal(&ring.secret, ring.identity, rev, &inside)?.check()?;
    if entries::store(conn, &entry, now)? != Outcome::Stored {
        return Err(PersonError::Held(
            "the store holds an entry of this device's at or above that revision in its ring"
                .into(),
        ));
    }
    Ok(entry)
}

/// The label this device is known by: the statement's.
fn own_label(conn: &Connection, own: &[u8; 32]) -> Result<String, PersonError> {
    let standing = Standing::of(conn)?;
    crate::reader::label_of(conn, &standing.held.statement.statement, own)
}

// ── What a relay answered, and sending again ─────────────────────────

/// A relay answered a push of `entries` of the messages channel `channel`
/// with `answers`, one for each (decision 2026-10-09 §2.3, C18, F6). For
/// each message of the device's own that it keeps apart:
///
/// - **Stored or held**: that relay has taken it.
/// - **A later one held** (`Older`): it was not taken there, and nothing
///   is written again. It waits: the next pull from that relay hands back
///   the device's own later entry, which the reader marks.
/// - **Another at that revision**: the entry the relay holds is one the
///   device wrote before its store went back. The message waits to be
///   sent again under the next number.
///
/// A clearing and a list are not kept, and an answer to them changes
/// nothing here: a relay's answer of another to a clearing is ignored.
pub fn answered(
    conn: &Connection,
    identity: &NodeIdentity,
    relay: &[u8; 32],
    channel: &Own,
    entries: &[Entry],
    answers: &[Pushed],
) -> Result<(), PersonError> {
    if channel.kind != Kind::Messages || entries.len() != answers.len() {
        return Ok(());
    }
    in_one(conn, || {
        if stands(conn)? != Stands::Applied {
            return Ok(());
        }
        let ring = Ring::of(conn, identity)?;
        if ring.channel != channel.id {
            return Ok(());
        }
        let Some(generation) = kept(held::generation_of(conn, &channel.id))? else {
            return Ok(());
        };
        for (entry, answer) in entries.iter().zip(answers) {
            if entry.author != ring.own || message::is_clearing_rev(entry.rev) {
                continue;
            }
            let number = number_of(entry.rev);
            if message_rev(number).is_none() || entry.slot != ring.slot(number)? {
                continue;
            }
            let Some(id) = kept(held::kept_at(conn, generation, number))? else {
                continue;
            };
            match answer {
                Pushed::Holds => kept(held::taken_by(conn, &id, relay))?,
                Pushed::HoldsAnother => kept(held::send_again(conn, &id))?,
                _ => {}
            }
        }
        Ok(())
    })
}

/// The device took from a relay, through the door, `entry`, an entry of
/// the messages channel of `generation`, which the store kept over what
/// it held (decision 2026-10-09 §2.3, case 2): where it stands in the
/// slot, named for the device's own key `own`, of the newest number of a
/// message that not every relay has taken, it is the device's own entry
/// from its later life over that message, which would otherwise never be
/// pushed anywhere. The message waits to be sent again under the next
/// number. In the door's write.
pub(crate) fn taken_over(
    conn: &Connection,
    own: &[u8; 32],
    slot_key: &[u8; 32],
    generation: i64,
    entry: &CheckedEntry,
) -> Result<(), PersonError> {
    for kept_value in kept(held::kept(conn))? {
        if kept_value.generation != generation || kept_value.again {
            continue;
        }
        let Some(newest) = kept_value.numbers.last().copied() else {
            continue;
        };
        if entry.slot == slot_id(slot_key, &message_name(own, newest)?) {
            kept(held::send_again(conn, &kept_value.id))?;
        }
    }
    Ok(())
}

/// What one sending again did ([`write_again`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Again {
    /// Each message written again, by its ID, with its new number.
    pub written: Vec<(Id, u64)>,
    /// Each message whose kept value was dropped, before every relay took
    /// it: it needed a fifth number, or a number above the highest.
    pub dropped: Vec<Id>,
}

/// Write again, each under the next number, the messages of the device's
/// own that wait to be sent again, at `now` (decision 2026-10-09 §2.3,
/// C18), in one transaction:
///
/// - **Only after the first fetch,** where the device stands applied and
///   has sync on: before then nothing is written in the messages channel.
/// - **Each counts against the device's 60 in the hour** as a send again,
///   and against no folder's, and **waits where the hour is full.**
/// - **At most four numbers for a message:** where a fifth would be
///   needed, its kept value is dropped, and so where its next number would
///   be above the highest; its index row then says that it may not have
///   reached every relay. The fourth is written and kept like the others.
///
/// Kept values of a generation the device has left go with it (§9.1).
pub fn write_again(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
) -> Result<Again, PersonError> {
    in_one(conn, || {
        let mut again = Again::default();
        if stands(conn)? != Stands::Applied
            || meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()
            || !fetched
        {
            return Ok(again);
        }
        let ring = Ring::of(conn, identity)?;
        let generation = ring.generation(conn, now)?;
        kept(held::drop_kept_gone(conn, generation, now))?;
        for waiting in kept(held::kept(conn))? {
            if !waiting.again {
                continue;
            }
            let next = next_in(conn, &ring)?;
            let Some(number) = next.filter(|_| waiting.numbers.len() < AGENT_MESSAGE_SENDS_MAX)
            else {
                kept(held::drop_kept(conn, &waiting.id, false))?;
                again.dropped.push(waiting.id);
                continue;
            };
            let lately = kept(held::sent_lately(conn, "", now))?;
            if device_full(&lately).is_some() {
                break;
            }
            let message = Message::from_value(
                &Value::Other(waiting.value.clone()),
                crate::names::is_a_name,
            )
            .map_err(|e| PersonError::Held(format!("a kept message does not read back: {e}")))?;
            written(conn, &ring, number, &waiting.value, &message, now)?;
            kept(held::kept_under(conn, &waiting.id, number))?;
            kept(held::record_send(conn, now, None, false))?;
            again.written.push((waiting.id, number));
        }
        Ok(again)
    })
}

/// Drop each message the device keeps that every one of `relays`, the
/// relays it is set up with, has taken (decision 2026-10-09 §2.3).
pub fn taken_everywhere(conn: &Connection, relays: &[[u8; 32]]) -> Result<usize, PersonError> {
    in_one(conn, || kept(held::drop_taken_by_every(conn, relays)))
}

// ── Clearing ─────────────────────────────────────────────────────────

/// The middle step of the hourly task (decision 2026-10-09 §2.3, §7.1):
/// where the device stands applied, has sync on and has fetched the
/// messages channel since it started, it writes the entry that clears
/// each of its own messages in the generation applied whose slot still
/// holds it and whose `sent` is 30 days or more before `now`: in the same
/// slot, one revision on, of the same size. Its own index drops the
/// message as a reader's does at a clearing. Returns how many it cleared.
///
/// A clearing is never written before the first fetch, and a relay's
/// answer of another to one is ignored ([`answered`]).
pub fn clear_expired(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
) -> Result<usize, PersonError> {
    in_one(conn, || {
        if stands(conn)? != Stands::Applied
            || meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()
            || !fetched
        {
            return Ok(0);
        }
        let ring = Ring::of(conn, identity)?;
        let mut cleared = 0;
        // A clearing held in a slot does not open as a message, and is
        // passed over with what is no message.
        for (place, entry) in ring.held(conn)? {
            let number = number_of(entry.rev);
            if message_rev(number).is_none() || number % AGENT_MESSAGE_RING as u64 != place {
                continue;
            }
            let Ok(inside) = entry.open(&ring.secret) else {
                continue;
            };
            let Ok(message) = Message::from_value(&inside.value, crate::names::is_a_name) else {
                continue;
            };
            let sent = i64::try_from(message.sent).unwrap_or(i64::MAX);
            if !held::has_expired(sent, sent, now) {
                continue;
            }
            let Some(rev) = clearing_rev(number) else {
                continue;
            };
            seal(conn, &ring, number, rev, clearing_value(), now)?;
            let generation = ring.generation(conn, now)?;
            kept(held::hold_number(conn, &ring.own, generation, number, true))?;
            kept(held::clear(conn, &ring.own, generation, number, now))?;
            cleared += 1;
        }
        let generation = ring.generation(conn, now)?;
        kept(held::drop_kept_gone(conn, generation, now))?;
        Ok(cleared)
    })
}

/// What the store answered, with its error as the device's.
fn kept<T>(answer: Result<T, StorageError>) -> Result<T, PersonError> {
    answer.map_err(|e| PersonError::Storage(CordeliaError::Storage(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_core::protocol::{AGENT_MESSAGE_CONTENT_BYTES, AGENT_MESSAGE_NUMBER_MAX};
    use cordelia_crypto::message::{ReadMarks, read_name};
    use cordelia_storage::entries::Outcome;
    use cordelia_storage::person::State;
    use cordelia_storage::relay::{self, Asker, Room};

    use crate::at_relays::{Batch, Most, Which};
    use crate::several::{Several, entry_by};
    use crate::take::{Taken, take};

    const HOUR: i64 = 60 * 60;
    const DAY: i64 = 24 * HOUR;

    /// The names each device of a test syncs.
    const NAMES: [&str; 4] = ["notes", "work", "plans", "home"];

    /// `count` devices of one person, each with sync on and saying that
    /// it syncs every one of [`NAMES`], each having been given what every
    /// other holds.
    fn devices(count: u16) -> Several {
        let mut s = Several::of_one_person(count);
        for n in 0..usize::from(count) {
            meta::set(&s[n].conn, meta::SYNC_CLAUDE_DIR, "/home/laptop/.claude").unwrap();
            for name in NAMES {
                crate::names::say(&s[n].conn, &s[n].identity, name, s.now).unwrap();
            }
        }
        let all: Vec<usize> = (0..usize::from(count)).collect();
        s.meet(&all);
        s
    }

    /// The node at `now`, which has fetched the messages channel.
    fn at(now: i64) -> At {
        At {
            now,
            fetched: true,
            no_place: false,
            per_folder_per_hour: AGENT_MESSAGES_PER_FOLDER_PER_HOUR,
        }
    }

    /// A message from the agent of `from` to that of `to`, or to every
    /// name where `to` is `*`, saying `body`.
    fn says(from: &str, to: &str, body: &str) -> Request {
        Request {
            from: from.into(),
            to: match to {
                "*" => To::All,
                name => To::Name(name.into()),
            },
            asks: false,
            link: None,
            body: body.into(),
            thread: [0; 16],
            answers: [0; 16],
        }
    }

    /// Device `n` sends `request` at `now`.
    fn sends_at(s: &Several, n: usize, request: &Request, now: i64) -> Result<Sent, NotSent> {
        send(&s[n].conn, &s[n].identity, &at(now), request)
    }

    /// Device `n` sends `request` at `now`, which it must.
    fn sent(s: &Several, n: usize, request: &Request, now: i64) -> Sent {
        sends_at(s, n, request, now).unwrap_or_else(|e| panic!("{e:?}"))
    }

    /// Device `n` sends `request` at `now`, which it must, and a person
    /// then reads everything it holds: for a test of something else than
    /// the hold.
    fn sent_read(s: &Several, n: usize, request: &Request, now: i64) -> Sent {
        let done = sent(s, n, request, now);
        read_all(s, n);
        done
    }

    /// A person reads everything device `n` holds.
    fn read_all(s: &Several, n: usize) {
        s[n].conn
            .execute(
                "INSERT OR IGNORE INTO message_read_by_a_person (id) SELECT id FROM message_index",
                [],
            )
            .unwrap();
    }

    /// What device `n` was refused, sending `request` at `now`.
    fn refused(s: &Several, n: usize, request: &Request, now: i64) -> Refused {
        match sends_at(s, n, request, now) {
            Err(NotSent::Refused(why)) => why,
            other => panic!("{other:?}"),
        }
    }

    /// The secret of the messages channel device `n` stands applied under.
    fn messages_secret(s: &Several, n: usize) -> [u8; 32] {
        derive::messages_secret(&s[n].secret()).unwrap()
    }

    fn messages(s: &Several, n: usize) -> [u8; 32] {
        derive::channel_id(&messages_secret(s, n)).unwrap()
    }

    /// The entries of device `of`'s own that device `n` holds in the
    /// messages channel, each as its revision, lowest first.
    fn revs_of(s: &Several, n: usize, of: usize) -> Vec<u64> {
        let mut revs: Vec<u64> = s[n]
            .stored_in(&messages_secret(s, n))
            .iter()
            .filter(|entry| entry.author == s.key(of))
            .map(|entry| entry.rev)
            .collect();
        revs.sort_unstable();
        revs
    }

    /// Device `n` writes, as only a holder of its key would, the entry of
    /// its own `value` in the slot of `number` at `rev`.
    fn writes_own(s: &Several, n: usize, number: u64, rev: u64, value: Vec<u8>) -> CheckedEntry {
        let name = message_name(&s.key(n), number).unwrap();
        let entry = entry_by(
            &s[n].identity,
            &messages_secret(s, n),
            rev,
            &name,
            Value::Other(value),
            &[],
        );
        assert_eq!(
            entries::store(&s[n].conn, &entry, s.now).unwrap(),
            Outcome::Stored
        );
        entry
    }

    fn rows(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {sql}"), [], |row| row.get(0))
            .unwrap()
    }

    /// The bodies device `n` shows at `now`, once it has given places as
    /// a show does, oldest first.
    fn shown_on(s: &Several, n: usize, now: i64) -> Vec<String> {
        held::give_places(&s[n].conn, &s.key(n), now).unwrap();
        held::shown(&s[n].conn, now)
            .unwrap()
            .into_iter()
            .map(|shown| shown.body)
            .collect()
    }

    /// The numbers device `n` keeps message `id` sent under, and whether
    /// it waits to be sent again; `None` where it keeps it no more.
    fn kept_of(s: &Several, n: usize, id: &Id) -> Option<(Vec<u64>, bool)> {
        held::kept(&s[n].conn)
            .unwrap()
            .into_iter()
            .find(|kept| kept.id == *id)
            .map(|kept| (kept.numbers, kept.again))
    }

    /// Whether device `n`'s index says of message `id` that it may not
    /// have reached every relay.
    fn not_every_relay(s: &Several, n: usize, id: &Id) -> bool {
        s[n].conn
            .query_row(
                "SELECT not_every_relay FROM message_index WHERE id = ?1",
                [&id[..]],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// The messages channel of device `n`, as a pass goes through it.
    fn own_messages(s: &Several, n: usize) -> Own {
        crate::at_relays::channels(&s[n].conn, &s[n].identity)
            .unwrap()
            .into_iter()
            .find(|own| own.kind == Kind::Messages)
            .unwrap()
    }

    /// The value of a message from notes to work that says `body`, sent at
    /// `sent`.
    fn says_value(body: &str, sent: i64) -> Vec<u8> {
        Message {
            asks: false,
            sent: u64::try_from(sent).unwrap(),
            nonce: [1; 16],
            thread: [0; 16],
            answers: [0; 16],
            from: "notes".into(),
            to: To::Name("work".into()),
            link: None,
            body: body.into(),
        }
        .to_value(crate::names::is_a_name)
        .unwrap()
    }

    // ── A relay, as its store takes what it is pushed ───────────────

    /// A relay of a test: its own store, which takes what a device pushes
    /// as a relay takes it, and hands it as a pull does, through the
    /// device's one door. `answers`, where set, is what it says to each
    /// push in the place of what its store says.
    struct Relay {
        key: [u8; 32],
        conn: Connection,
        room: Room,
        answers: Option<Pushed>,
    }

    impl Relay {
        fn new(key: u8) -> Self {
            Self {
                key: [key; 32],
                conn: cordelia_storage::db::open_in_memory().unwrap(),
                room: Room::new(1 << 32),
                answers: None,
            }
        }

        /// Device `n` pushes it what it has not been sent of the messages
        /// channel at `now`, as a pass does, and is told what it answered.
        fn pushed(&mut self, s: &Several, n: usize, now: i64) -> Vec<Pushed> {
            let on = &s[n];
            let channel = own_messages(s, n);
            let most = Most {
                entries: 1000,
                bytes: 100_000_000,
            };
            let batch: Batch = crate::at_relays::to_send(
                &on.conn,
                &on.identity,
                &self.key,
                &channel,
                Which::Since,
                most,
                true,
            )
            .unwrap();
            let asker = Asker::Address("127.0.0.1".parse().unwrap());
            let answers: Vec<Pushed> = batch
                .entries
                .iter()
                .map(|entry| {
                    let taken = relay::take(
                        &self.conn,
                        &mut self.room,
                        &entry.clone().check().unwrap(),
                        &asker,
                        now,
                    )
                    .unwrap();
                    let said = match taken {
                        relay::Taken::Stored | relay::Taken::AlreadyHeld => Pushed::Holds,
                        relay::Taken::OlderThanHeld => Pushed::HoldsLater,
                        relay::Taken::HeldAnother => Pushed::HoldsAnother,
                        relay::Taken::Refused(_) => Pushed::NoRoom,
                    };
                    self.answers.unwrap_or(said)
                })
                .collect();
            crate::at_relays::sent(&on.conn, &self.key, &channel, &batch, &answers).unwrap();
            answered(
                &on.conn,
                &on.identity,
                &self.key,
                &channel,
                &batch.entries,
                &answers,
            )
            .unwrap();
            answers
        }

        /// Device `n` is handed, through its one door, everything the
        /// relay holds of its messages channel, at `now`.
        fn pulled(&self, s: &Several, n: usize, now: i64) -> Vec<Taken> {
            let held = entries::channel_entries_after(&self.conn, &messages(s, n), 0, 100_000);
            held.unwrap()
                .iter()
                .map(|held| {
                    let entry = held.entry.clone().check().unwrap();
                    take(&s[n].conn, &s[n].identity, &entry, now).unwrap()
                })
                .collect()
        }

        /// The entries of device `of`'s own that the relay holds, each as
        /// its revision, lowest first.
        fn revs_of(&self, s: &Several, of: usize) -> Vec<u64> {
            let held = entries::channel_entries_after(&self.conn, &messages(s, of), 0, 100_000);
            let mut revs: Vec<u64> = held
                .unwrap()
                .iter()
                .filter(|held| held.entry.author == s.key(of))
                .map(|held| held.entry.rev)
                .collect();
            revs.sort_unstable();
            revs
        }
    }

    // ── The next number ─────────────────────────────────────────────

    /// The next number is one above every number of an entry of the
    /// device's own in its ring, clearings included, as the store holds
    /// them (decision 2026-10-09 §2.3, C1): a clearing of 5 makes it 6. A
    /// list far above, and another key's entry in the device's slot,
    /// change nothing. It is read from the store each time, so a send
    /// after another gets the next.
    #[test]
    fn the_next_message_goes_above_every_number_the_device_holds_clearing_included() {
        let s = devices(2);
        let t = s.now;
        assert_eq!(next_number(&s[0].conn, &s[0].identity).unwrap(), Some(1));
        assert_eq!(sent(&s, 0, &says("notes", "work", "one"), t).number, 1);
        assert_eq!(sent(&s, 0, &says("notes", "work", "two"), t).number, 2);
        writes_own(&s, 0, 5, clearing_rev(5).unwrap(), clearing_value());
        let list = ReadMarks::default().to_value().unwrap();
        let name = read_name(&s.key(0)).unwrap();
        let entry = entry_by(
            &s[0].identity,
            &messages_secret(&s, 0),
            1 << 40,
            &name,
            Value::Other(list),
            &[],
        );
        entries::store(&s[0].conn, &entry, t).unwrap();
        // Another key's entry in this device's slot of 9.
        let other = entry_by(
            &s[1].identity,
            &messages_secret(&s, 0),
            message_rev(9).unwrap(),
            &message_name(&s.key(0), 9).unwrap(),
            Value::Other(clearing_value()),
            &[],
        );
        entries::store(&s[0].conn, &other, t).unwrap();
        assert_eq!(next_number(&s[0].conn, &s[0].identity).unwrap(), Some(6));
        assert_eq!(sent(&s, 0, &says("notes", "work", "six"), t).number, 6);
        assert_eq!(sent(&s, 0, &says("notes", "work", "seven"), t).number, 7);
        assert_eq!(revs_of(&s, 0, 0), [2, 4, 11, 12, 14, 1 << 40]);
    }

    /// After a send, before any relay has handed it back, the device's
    /// index holds the message: its row with its place, written when it
    /// was, its row of numbers held, its row of first holding and H; its
    /// place has no time in any signer's hour; and its value is kept, with
    /// its number, and the send is in the device's record (decision
    /// 2026-10-09 §2.3, §6, F9).
    #[test]
    fn a_devices_own_send_is_in_its_index_when_written() {
        let s = devices(2);
        let t = s.now + 10;
        let done = sent(&s, 0, &says("notes", "work", "a branch to look at"), t);
        let conn = &s[0].conn;
        let row: (Vec<u8>, Vec<u8>, String, i64, i64, Option<i64>) = conn
            .query_row(
                "SELECT id, signer, label, sent, first_held, placed_at FROM message_index",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            row,
            (
                done.id.to_vec(),
                s.key(0).to_vec(),
                s[0].label.clone(),
                t,
                t,
                Some(t)
            )
        );
        assert_eq!(rows(conn, "message_numbers WHERE number = 1"), 1);
        assert_eq!(rows(conn, "message_first_held WHERE number = 1"), 1);
        let generation = held::generation_of(conn, &messages(&s, 0))
            .unwrap()
            .unwrap();
        assert_eq!(
            held::signer(conn, &s.key(0), generation)
                .unwrap()
                .unwrap()
                .highest,
            1
        );
        assert_eq!(rows(conn, "message_places"), 0);
        assert_eq!(kept_of(&s, 0, &done.id), Some((vec![1], false)));
        let sends: (i64, String, bool) = conn
            .query_row(
                "SELECT sent_at, name, to_all FROM message_sends",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(sends, (t, "notes".to_string(), false));
        assert_eq!(shown_on(&s, 0, t), ["a branch to look at"]);
        // The entry is in its slot, sealed at the one size.
        let entry = s[0].stored_in(&messages_secret(&s, 0)).remove(0);
        assert_eq!(entry.rev, 2);
        assert_eq!(entry.content.len(), AGENT_MESSAGE_CONTENT_BYTES);
        let inside = entry.open(&messages_secret(&s, 0)).unwrap();
        assert_eq!(inside.name, message_name(&s.key(0), 1).unwrap());
        // The same words again are another message (§2.2).
        let again = sent(&s, 0, &says("notes", "work", "a branch to look at"), t);
        assert_ne!(again.id, done.id);
    }

    /// With an entry of its own at the highest number in its ring, a
    /// device sends nothing, refused with `no_numbers`; one below it, it
    /// sends at the highest (decision 2026-10-09 §2.3, F11).
    #[test]
    fn a_device_sends_nothing_past_the_highest_number() {
        let s = devices(2);
        let max = AGENT_MESSAGE_NUMBER_MAX;
        writes_own(
            &s,
            0,
            max - 1,
            message_rev(max - 1).unwrap(),
            clearing_value(),
        );
        let done = sent(&s, 0, &says("notes", "work", "the last"), s.now);
        assert_eq!(done.number, max);
        let refusal = refused(&s, 0, &says("notes", "work", "past it"), s.now);
        assert_eq!(refusal, Refused::NoNumbers);
        assert_eq!(refusal.word(), "no_numbers");
    }

    /// The first send after a start waits for the messages channel to be
    /// fetched (decision 2026-10-09 §2.3): refused with `not_fetched`
    /// while no relay has handed it, whether none is connected or none has
    /// answered; allowed once one has and the others have too, or once
    /// `FIRST_FETCH_WAIT_SECS` have gone by the `Instant` given; never
    /// refused on a device set up with no relay. A device that does not
    /// stand applied has not fetched it.
    #[test]
    fn the_first_send_after_a_start_waits_for_the_ring_to_be_fetched() {
        let s = devices(2);
        let conn = &s[0].conn;
        let channel = messages(&s, 0);
        let start = Instant::now();
        let wait = std::time::Duration::from_secs(cordelia_core::protocol::FIRST_FETCH_WAIT_SECS);
        let after = |secs| start + std::time::Duration::from_secs(secs);

        let own_channels = OwnChannels::default();
        own_channels.set_up_with(2);
        assert!(!fetched(conn, &own_channels, start).unwrap());
        assert!(!fetched(conn, &own_channels, start + 2 * wait).unwrap());
        let request = says("notes", "work", "first");
        let at_with = |fetched| At {
            fetched,
            ..at(s.now)
        };
        let not_fetched = send(conn, &s[0].identity, &at_with(false), &request);
        assert!(matches!(
            not_fetched,
            Err(NotSent::Refused(Refused::NotFetched))
        ));
        assert_eq!(rows(conn, "message_index"), 0);
        assert!(s[0].stored_in(&messages_secret(&s, 0)).is_empty());

        own_channels.fetched_from(&channel, "relay-a", after(1));
        assert!(!fetched(conn, &own_channels, after(1)).unwrap());
        assert!(
            !fetched(
                conn,
                &own_channels,
                after(1) + wait - std::time::Duration::from_secs(1)
            )
            .unwrap()
        );
        assert!(fetched(conn, &own_channels, after(1) + wait).unwrap());
        own_channels.fetched_from(&channel, "relay-b", after(2));
        assert!(fetched(conn, &own_channels, after(2)).unwrap());
        assert!(send(conn, &s[0].identity, &at_with(true), &request).is_ok());

        let none = OwnChannels::default();
        none.set_up_with(0);
        assert!(fetched(conn, &none, start).unwrap());

        cordelia_storage::person::set_state(conn, State::Removed).unwrap();
        assert!(!fetched(conn, &none, start).unwrap());
    }

    // ── The order of the checks ─────────────────────────────────────

    /// The sender's checks are made in the order of §4.3 (D5): with every
    /// refusal applying at once, each is answered in turn as the one
    /// before it is taken away: `not_applied`, `sync_off`, `no_place`,
    /// `sending_off`, `not_fetched`, `no_numbers`, `clock_behind`,
    /// `no_such_name`, `folder_rate`, `device_rate`, `pair_held`; and
    /// then the message is sent.
    #[test]
    fn the_senders_checks_are_made_in_the_order_of_the_record() {
        let s = devices(2);
        let t = s.now + DAY;
        let conn = &s[0].conn;
        // The pair of notes and work is held by ten from work here.
        for number in 1..=10 {
            let request = says("work", "notes", &format!("{number}"));
            sent(&s, 0, &request, t - 2 * DAY + number * 4 * 60);
        }
        // Notes has sent its 20 in the hour, and the device its 60.
        for at_ in 0..20 {
            held::record_send(conn, t - 100 + at_, Some("notes"), false).unwrap();
        }
        for at_ in 0..40 {
            held::record_send(conn, t - 100 + at_, Some("plans"), false).unwrap();
        }
        // A message of its own whose `sent` is ahead of the clock, a send
        // of home's, and an entry of its own at the highest number.
        let ahead_at = t + 60;
        held::record_send(conn, ahead_at, Some("home"), false).unwrap();
        conn.execute(
            "UPDATE message_index SET sent = ?1 WHERE from_name = 'work' AND body = '10'",
            [ahead_at],
        )
        .unwrap();
        let max = AGENT_MESSAGE_NUMBER_MAX;
        let highest = writes_own(&s, 0, max, message_rev(max).unwrap(), clearing_value());
        cordelia_storage::person::set_state(conn, State::Removed).unwrap();
        meta::remove(conn, meta::SYNC_CLAUDE_DIR).unwrap();

        let request = says("notes", "nobody", "x");
        let mut at_now = At {
            now: t,
            fetched: false,
            no_place: true,
            per_folder_per_hour: 0,
        };
        let word =
            |at_now: &At, request: &Request| match send(conn, &s[0].identity, at_now, request) {
                Err(NotSent::Refused(why)) => why.word(),
                other => panic!("{other:?}"),
            };
        assert_eq!(word(&at_now, &request), "not_applied");
        cordelia_storage::person::set_state(conn, State::Applied).unwrap();
        assert_eq!(word(&at_now, &request), "sync_off");
        meta::set(conn, meta::SYNC_CLAUDE_DIR, "/c").unwrap();
        assert_eq!(word(&at_now, &request), "no_place");
        at_now.no_place = false;
        assert_eq!(word(&at_now, &request), "sending_off");
        at_now.per_folder_per_hour = 20;
        assert_eq!(word(&at_now, &request), "not_fetched");
        at_now.fetched = true;
        assert_eq!(word(&at_now, &request), "no_numbers");
        conn.execute(
            "DELETE FROM entries WHERE author = ?1 AND rev = ?2",
            rusqlite::params![&s.key(0)[..], highest.rev as i64],
        )
        .unwrap();
        assert_eq!(word(&at_now, &request), "clock_behind");
        at_now.now = ahead_at;
        assert_eq!(word(&at_now, &request), "no_such_name");
        let request = says("notes", "work", "x");
        assert_eq!(word(&at_now, &request), "folder_rate");
        let request = says("home", "work", "x");
        assert_eq!(word(&at_now, &request), "device_rate");
        at_now.now = t + HOUR;
        // The rows of sends from 100 seconds before t are out of the
        // hour; the ten of work's, and the one ahead, are not counted.
        let request = says("notes", "work", "x");
        assert_eq!(word(&at_now, &request), "pair_held");
        let request = says("notes", "plans", "x");
        assert!(send(conn, &s[0].identity, &at_now, &request).is_ok());
    }

    // ── The rates ───────────────────────────────────────────────────

    /// The 21st message of a folder within the hour is refused with
    /// `folder_rate`, saying when the next can go; another folder of the
    /// device still sends (decision 2026-10-09 §6, R9). The configuration
    /// lowers the limit and never raises it.
    #[test]
    fn a_folder_over_its_hour_sends_nothing_more() {
        let s = devices(2);
        let t = s.now;
        for k in 0..20 {
            sent_read(&s, 0, &says("notes", "work", &format!("{k}")), t + k);
        }
        assert_eq!(
            refused(&s, 0, &says("notes", "work", "21st"), t + 30),
            Refused::FolderRate {
                limit: 20,
                next_at: t + HOUR
            }
        );
        assert_eq!(
            refused(&s, 0, &says("notes", "*", "21st"), t + 30).word(),
            "folder_rate"
        );
        sent(&s, 0, &says("plans", "work", "another folder"), t + 31);
        assert!(sends_at(&s, 0, &says("notes", "work", "an hour on"), t + HOUR).is_ok());

        let s = devices(2);
        let lowered = |per_folder_per_hour| At {
            per_folder_per_hour,
            ..at(t + 10)
        };
        for k in 0..5 {
            let request = says("notes", "work", &format!("{k}"));
            send(&s[0].conn, &s[0].identity, &lowered(5), &request).unwrap();
        }
        let sixth = send(
            &s[0].conn,
            &s[0].identity,
            &lowered(5),
            &says("notes", "work", "6"),
        );
        assert!(matches!(
            sixth,
            Err(NotSent::Refused(Refused::FolderRate { limit: 5, .. }))
        ));
        for k in 5..20 {
            let request = says("notes", "work", &format!("{k}"));
            send(&s[0].conn, &s[0].identity, &lowered(100), &request).unwrap();
            read_all(&s, 0);
        }
        let raised = send(
            &s[0].conn,
            &s[0].identity,
            &lowered(100),
            &says("notes", "work", "21"),
        );
        assert!(matches!(
            raised,
            Err(NotSent::Refused(Refused::FolderRate { limit: 20, .. }))
        ));
    }

    /// With the folder's rate set to 0, a send is refused with
    /// `sending_off`, which names no time (decision 2026-10-09 §6).
    #[test]
    fn a_folder_whose_rate_is_0_sends_nothing() {
        let s = devices(2);
        let off = At {
            per_folder_per_hour: 0,
            ..at(s.now)
        };
        let refusal = send(
            &s[0].conn,
            &s[0].identity,
            &off,
            &says("notes", "work", "x"),
        );
        assert!(matches!(
            refusal,
            Err(NotSent::Refused(Refused::SendingOff))
        ));
        assert_eq!(Refused::SendingOff.word(), "sending_off");
        assert_eq!(rows(&s[0].conn, "message_sends"), 0);
    }

    /// The 61st message of the device in the hour, across its folders, is
    /// refused with `device_rate`; a message to every name counts as one
    /// (decision 2026-10-09 §6).
    #[test]
    fn a_device_over_its_hour_sends_nothing_more_and_every_name_counts_once() {
        let s = devices(2);
        let t = s.now;
        let mut k = 0;
        for from in ["notes", "work", "plans"] {
            for one in 0..20 {
                let to = if one % 2 == 0 { "*" } else { "home" };
                sent_read(&s, 0, &says(from, to, &format!("{k}")), t + k);
                k += 1;
            }
        }
        assert_eq!(rows(&s[0].conn, "message_sends"), 60);
        assert_eq!(
            refused(&s, 0, &says("home", "notes", "61st"), t + 100),
            Refused::DeviceRate {
                sends: 60,
                again: 0,
                next_at: t + HOUR
            }
        );
        sent(&s, 0, &says("home", "notes", "an hour on"), t + HOUR);
    }

    /// With 55 sends and 5 sends again in the hour, the next send is
    /// refused with `device_rate`, which counts the two apart (decision
    /// 2026-10-09 §2.3, §4.3); the folder's own count is of its sends.
    #[test]
    fn the_device_rate_line_counts_sends_again_apart() {
        let s = devices(2);
        let t = s.now;
        for k in 0..55 {
            let from = NAMES[usize::try_from(k % 3).unwrap()];
            held::record_send(&s[0].conn, t + k, Some(from), false).unwrap();
        }
        for k in 0..5 {
            held::record_send(&s[0].conn, t + 60 + k, None, false).unwrap();
        }
        assert_eq!(
            refused(&s, 0, &says("home", "notes", "x"), t + 100),
            Refused::DeviceRate {
                sends: 55,
                again: 5,
                next_at: t + HOUR
            }
        );
        // Four sends again fewer, and it goes.
        s[0].conn
            .execute("DELETE FROM message_sends WHERE sent_at >= ?1", [t + 61])
            .unwrap();
        sent(&s, 0, &says("home", "notes", "x"), t + 100);
    }

    /// The hour frees by the device's own record of when it sent, and a
    /// clock that went back does not free it: rows later than the clock
    /// still count (decision 2026-10-09 §6, C10). A `sent` is never read
    /// for the rate.
    #[test]
    fn the_hour_frees_by_the_devices_own_record_and_a_clock_that_went_back_does_not_free_it() {
        let s = devices(2);
        let t = s.now;
        for k in 0..20 {
            sent_read(&s, 0, &says("notes", "work", &format!("{k}")), t + k * 60);
        }
        assert!(matches!(
            refused(&s, 0, &says("notes", "work", "x"), t + HOUR - 1),
            Refused::FolderRate { .. }
        ));
        // Back by a day, and the record is all later than the clock.
        let back = t - DAY;
        assert!(matches!(
            refused(&s, 0, &says("notes", "work", "x"), back),
            Refused::FolderRate { .. }
        ));
        // The `sent` of each says nothing of it.
        s[0].conn
            .execute("UPDATE message_index SET sent = sent - 2 * 3600", [])
            .unwrap();
        assert!(matches!(
            refused(&s, 0, &says("notes", "work", "x"), t + HOUR - 1),
            Refused::FolderRate { .. }
        ));
        assert!(sends_at(&s, 0, &says("notes", "work", "x"), t + HOUR).is_ok());
        // The record is kept for the hour, and no longer.
        held::drop_gone(&s[0].conn, t + 19 * 60 + HOUR - 1, Some(&messages(&s, 0))).unwrap();
        assert_eq!(rows(&s[0].conn, "message_sends"), 2);
        held::drop_gone(&s[0].conn, t + 19 * 60 + HOUR, Some(&messages(&s, 0))).unwrap();
        assert_eq!(rows(&s[0].conn, "message_sends"), 1);
    }

    // ── The clock ───────────────────────────────────────────────────

    /// Behind its newest `sent` by 300 seconds, a device sends nothing,
    /// refused with `clock_behind`; at that time it sends (decision
    /// 2026-10-09 §7.1).
    #[test]
    fn a_sender_whose_clock_is_behind_its_newest_sent_sends_nothing() {
        let s = devices(2);
        let t = s.now;
        sent(&s, 0, &says("notes", "work", "first"), t);
        let refusal = refused(&s, 0, &says("plans", "work", "behind"), t - 300);
        assert_eq!(refusal, Refused::ClockBehind);
        assert_eq!(refusal.word(), "clock_behind");
        assert_eq!(
            refused(&s, 0, &says("plans", "work", "behind"), t - 600),
            Refused::ClockBehind
        );
        sent(&s, 0, &says("plans", "work", "on time"), t);
        // Another device's message sent later says nothing of this clock.
        let mut s = s;
        sent(&s, 1, &says("work", "notes", "desktop's"), t + 300);
        s.pass(1, 0);
        sent(&s, 0, &says("plans", "home", "on laptop's time"), t + 1);
    }

    /// A device that sends at a clock set a day ahead, and is set right,
    /// sends again at once: a row of its own more than 600 seconds ahead
    /// is passed over (decision 2026-10-09 §7.1, D8).
    #[test]
    fn a_clock_that_was_ahead_for_a_moment_does_not_lock_sending_out() {
        let s = devices(2);
        let t = s.now;
        sent(&s, 0, &says("notes", "work", "a day ahead"), t + DAY);
        sent(&s, 0, &says("plans", "work", "set right"), t);
        // Ahead by 601 is passed over too; by 600 it is not.
        sent(&s, 0, &says("plans", "work", "601"), t + DAY - 601);
        sent(&s, 0, &says("home", "work", "again"), t);
        assert_eq!(
            refused(&s, 0, &says("work", "notes", "600"), t + DAY - 1201),
            Refused::ClockBehind
        );
    }

    // ── The hold ────────────────────────────────────────────────────

    /// Ten messages between two agents that have a place and that no
    /// person here has read hold the pair, in either direction; another
    /// pair still sends; every name is refused from either side of a held
    /// pair, and sent from a third; a person's mark frees it; and ten to
    /// every name hold the pair of the sender and all (decision
    /// 2026-10-09 §6, C8, D6).
    #[test]
    fn the_hold_is_by_the_pair_of_agents_and_every_name_is_a_pair_of_its_own() {
        let s = devices(2);
        let t = s.now;
        let mut now = t;
        let mut step = || {
            now += 4 * 60;
            now
        };
        let mut ids = Vec::new();
        for k in 0..10 {
            let (from, to) = if k % 2 == 0 {
                ("notes", "work")
            } else {
                ("work", "notes")
            };
            ids.push(sent(&s, 0, &says(from, to, &format!("{k}")), step()).id);
        }
        for (from, to) in [("notes", "work"), ("work", "notes")] {
            assert_eq!(
                refused(&s, 0, &says(from, to, "11th"), step()),
                Refused::PairHeld {
                    from: from.into(),
                    other: Some(to.into()),
                    every: false
                }
            );
        }
        for from in ["notes", "work"] {
            let other = if from == "notes" { "work" } else { "notes" };
            assert_eq!(
                refused(&s, 0, &says(from, "*", "to all"), step()),
                Refused::PairHeld {
                    from: from.into(),
                    other: Some(other.into()),
                    every: true
                }
            );
        }
        sent(&s, 0, &says("notes", "plans", "another pair"), step());
        sent(&s, 0, &says("plans", "*", "a third to all"), step());

        // A person reads one here: nine are left, and the pair sends.
        s[0].conn
            .execute(
                "INSERT INTO message_read_by_a_person (id) VALUES (?1)",
                [&ids[0][..]],
            )
            .unwrap();
        sent(&s, 0, &says("notes", "work", "freed"), step());
        assert!(matches!(
            refused(&s, 0, &says("work", "notes", "held again"), step()),
            Refused::PairHeld { .. }
        ));

        // Ten to every name from home: the pair of home and all.
        for k in 0..10 {
            sent(
                &s,
                0,
                &says("home", "*", &format!("all {k}")),
                step() + HOUR,
            );
        }
        let later = now + 2 * HOUR;
        assert_eq!(
            refused(&s, 0, &says("home", "*", "11th to all"), later),
            Refused::PairHeld {
                from: "home".into(),
                other: None,
                every: true
            }
        );
        sent(&s, 0, &says("home", "notes", "to a name"), later);
    }

    /// Messages held back by the reader's hour make no hold (decision
    /// 2026-10-09 §6, F2): a holder of a device's key sends 64 to a name,
    /// all placed at one show, and 16 more in the hour, which are held
    /// back. A person reads what has a place; a send between the two names
    /// goes, though the 16 are unread; once the hour is up and they have
    /// places, they hold the pair.
    #[test]
    fn held_back_messages_make_no_hold() {
        let s = devices(2);
        let t = s.now;
        let gives = |number: u64, at_: i64| {
            let message = Message {
                asks: false,
                sent: u64::try_from(at_).unwrap(),
                nonce: [u8::try_from(number % 256).unwrap(); 16],
                thread: [0; 16],
                answers: [0; 16],
                from: "work".into(),
                to: To::Name("notes".into()),
                link: None,
                body: format!("{number}"),
            };
            let value = message.to_value(crate::names::is_a_name).unwrap();
            let entry = entry_by(
                &s[0].identity,
                &messages_secret(&s, 0),
                message_rev(number).unwrap(),
                &message_name(&s.key(0), number).unwrap(),
                Value::Other(value),
                &[],
            );
            assert!(matches!(
                take(&s[1].conn, &s[1].identity, &entry, at_).unwrap(),
                Taken::Own { .. }
            ));
        };
        for number in 1..=64 {
            gives(number, t);
        }
        assert_eq!(held::give_places(&s[1].conn, &s.key(1), t).unwrap(), 64);
        for number in 65..=80 {
            gives(number, t + 60);
        }
        assert_eq!(held::give_places(&s[1].conn, &s.key(1), t + 60).unwrap(), 0);
        s[1].conn
            .execute(
                "INSERT INTO message_read_by_a_person (id)
                 SELECT id FROM message_index WHERE placed_at IS NOT NULL",
                [],
            )
            .unwrap();
        sent(&s, 1, &says("notes", "work", "goes"), t + 120);
        assert_eq!(
            held::give_places(&s[1].conn, &s.key(1), t + HOUR).unwrap(),
            16
        );
        assert!(matches!(
            refused(&s, 1, &says("notes", "work", "held"), t + HOUR),
            Refused::PairHeld { .. }
        ));
    }

    /// A held pair sends again once its messages pass their 30 days; in a
    /// second run, once 64 more numbers of their signer have made them
    /// not live; and in a third, where H stands above them before their
    /// rows have gone (decision 2026-10-09 §6, F2).
    #[test]
    fn a_hold_ends_when_its_messages_expire_or_stop_being_live() {
        for run in ["expire", "not live", "H above"] {
            let s = devices(2);
            let t = s.now;
            for number in 1..=10u64 {
                let request = says("work", "notes", &format!("{number}"));
                sent(&s, 0, &request, t + i64::try_from(number).unwrap() * 4 * 60);
            }
            let mut s = s;
            s.pass(0, 1);
            let t = t + HOUR;
            assert_eq!(shown_on(&s, 1, t).len(), 10);
            assert!(matches!(
                refused(&s, 1, &says("notes", "work", "held"), t),
                Refused::PairHeld { .. }
            ));
            let free_at = match run {
                "expire" => t + 30 * DAY,
                // H stands where they are no longer live, before their
                // rows go, as a store can hold it until the hourly task.
                "H above" => {
                    s[1].conn
                        .execute(
                            "UPDATE message_signers SET highest = 74 WHERE signer = ?1",
                            [&s.key(0)[..]],
                        )
                        .unwrap();
                    t
                }
                _ => {
                    // 64 more of work's signer, to another pair.
                    for k in 0..64i64 {
                        let request = says("plans", "home", &format!("lap {k}"));
                        sent_read(&s, 0, &request, t + 2 * HOUR + k * 4 * 60);
                    }
                    s.pass(0, 1);
                    t + 8 * HOUR
                }
            };
            sent(&s, 1, &says("notes", "work", "freed"), free_at);
        }
    }

    // ── Clearing ────────────────────────────────────────────────────

    /// 30 days after its `sent`, the sender writes in the message's slot
    /// the entry that clears it, one revision above, of the same size; its
    /// own index drops the message, and so does a device that takes the
    /// clearing (decision 2026-10-09 §2.3, property 12). Not a second
    /// before; and a message cleared is not cleared again.
    #[test]
    fn a_sender_clears_its_messages_after_thirty_days() {
        let mut s = devices(2);
        let t = s.now;
        sent(&s, 0, &says("notes", "work", "for a month"), t);
        sent(&s, 0, &says("notes", "work", "a day later"), t + DAY);
        s.pass(0, 1);
        assert_eq!(shown_on(&s, 1, t + HOUR).len(), 2);
        let conn = &s[0].conn;
        let identity = &s[0].identity;
        assert_eq!(
            clear_expired(conn, identity, t + 30 * DAY - 1, true).unwrap(),
            0
        );
        assert_eq!(
            clear_expired(conn, identity, t + 30 * DAY, true).unwrap(),
            1
        );
        assert_eq!(
            clear_expired(conn, identity, t + 30 * DAY, true).unwrap(),
            0
        );
        assert_eq!(revs_of(&s, 0, 0), [3, 4]);
        let clearing = s[0]
            .stored_in(&messages_secret(&s, 0))
            .into_iter()
            .find(|entry| entry.rev == 3)
            .unwrap();
        assert_eq!(clearing.content.len(), AGENT_MESSAGE_CONTENT_BYTES);
        assert_eq!(
            clearing.open(&messages_secret(&s, 0)).unwrap().value,
            Value::Other(clearing_value())
        );
        assert_eq!(shown_on(&s, 0, t + 30 * DAY - 2), ["a day later"]);
        s.pass(0, 1);
        assert_eq!(shown_on(&s, 1, t + 30 * DAY - 2), ["a day later"]);
        assert_eq!(rows(&s[1].conn, "message_index"), 1);
    }

    /// A device clears only its own messages: what it holds of another
    /// device's whose 30 days are up it leaves as it is (decision
    /// 2026-10-09 §2.3, property 3).
    #[test]
    fn a_device_clears_only_its_own_ring() {
        let mut s = devices(2);
        let t = s.now;
        sent(&s, 0, &says("notes", "work", "laptop's"), t);
        sent(&s, 1, &says("work", "notes", "desktop's"), t);
        s.meet(&[0, 1]);
        // An entry of desktop's own in its slot of 5 at a number whose
        // place is 6, as only a holder of its key writes: it is no message
        // of its ring, and it is not cleared.
        let out_of_place = entry_by(
            &s[1].identity,
            &messages_secret(&s, 1),
            message_rev(70).unwrap(),
            &message_name(&s.key(1), 5).unwrap(),
            Value::Other(says_value("out of place", t)),
            &[],
        );
        entries::store(&s[1].conn, &out_of_place, t).unwrap();
        let later = t + 31 * DAY;
        assert_eq!(
            clear_expired(&s[1].conn, &s[1].identity, later, true).unwrap(),
            1
        );
        assert_eq!(revs_of(&s, 1, 0), [2]);
        assert_eq!(revs_of(&s, 1, 1), [3, 140]);
        assert_eq!(
            clear_expired(&s[0].conn, &s[0].identity, later, true).unwrap(),
            1
        );
        assert_eq!(revs_of(&s, 0, 0), [3]);
        assert_eq!(revs_of(&s, 0, 1), [2]);
    }

    /// A device writes no clearing until the messages channel was
    /// fetched, nor where it does not stand applied or has sync off; and a
    /// relay's answer of another to a clearing makes nothing be written
    /// again (decision 2026-10-09 §2.3, F7).
    #[test]
    fn a_clearing_waits_for_the_first_fetch_and_another_to_it_is_ignored() {
        let s = devices(2);
        let t = s.now;
        sent(&s, 0, &says("notes", "work", "old"), t);
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        let later = t + 30 * DAY;
        assert_eq!(clear_expired(conn, identity, later, false).unwrap(), 0);
        meta::remove(conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(clear_expired(conn, identity, later, true).unwrap(), 0);
        meta::set(conn, meta::SYNC_CLAUDE_DIR, "/c").unwrap();
        cordelia_storage::person::set_state(conn, State::Removed).unwrap();
        assert_eq!(clear_expired(conn, identity, later, true).unwrap(), 0);
        cordelia_storage::person::set_state(conn, State::Applied).unwrap();
        assert_eq!(revs_of(&s, 0, 0), [2]);
        assert_eq!(clear_expired(conn, identity, later, true).unwrap(), 1);

        // Even where the device still keeps the message's value, as one
        // whose clock was set back would.
        let value = says_value("old", t + DAY);
        let kept_value = Kept {
            id: message_id(&s.key(0), &value),
            generation: held::generation_of(conn, &messages(&s, 0))
                .unwrap()
                .unwrap(),
            value,
            sent: later,
            numbers: vec![1],
            again: false,
        };
        held::keep(conn, &kept_value, later).unwrap();
        let mut relay = Relay::new(0xa1);
        relay.answers = Some(Pushed::HoldsAnother);
        assert_eq!(relay.pushed(&s, 0, later), [Pushed::HoldsAnother]);
        assert_eq!(kept_of(&s, 0, &kept_value.id), Some((vec![1], false)));
        assert_eq!(
            write_again(conn, identity, later, true).unwrap(),
            Again::default()
        );
        assert_eq!(revs_of(&s, 0, 0), [3]);
    }

    // ── Sending again ───────────────────────────────────────────────

    /// The entry of device `n`'s own at `number` that says `body`, as it
    /// wrote it in a life its store no longer holds.
    fn of_a_life_forgotten(s: &Several, n: usize, number: u64, body: &str) -> CheckedEntry {
        let message = Message {
            asks: false,
            sent: u64::try_from(s.now).unwrap(),
            nonce: [7; 16],
            thread: [0; 16],
            answers: [0; 16],
            from: "notes".into(),
            to: To::Name("work".into()),
            link: None,
            body: body.into(),
        };
        entry_by(
            &s[n].identity,
            &messages_secret(s, n),
            message_rev(number).unwrap(),
            &message_name(&s.key(n), number).unwrap(),
            Value::Other(message.to_value(crate::names::is_a_name).unwrap()),
            &[],
        )
    }

    impl Relay {
        /// The relay holds `entry`, as it took it from whoever pushed it.
        fn holds(&mut self, entry: &CheckedEntry, now: i64) {
            let asker = Asker::Address("127.0.0.2".parse().unwrap());
            let taken = relay::take(&self.conn, &mut self.room, entry, &asker, now).unwrap();
            assert_eq!(taken, relay::Taken::Stored);
        }
    }

    /// A relay answers that it holds another entry of the device's at the
    /// message's revision, one the device wrote before its store went
    /// back: the kept value is written again under the next number, and
    /// that relay takes it; a reader that holds both numbers shows it
    /// once (decision 2026-10-09 §2.3, case 1).
    #[test]
    fn a_message_that_a_relay_holds_another_entry_for_is_sent_again_under_the_next_number() {
        let mut s = devices(2);
        let t = s.now;
        let mut relay = Relay::new(0xa1);
        relay.holds(&of_a_life_forgotten(&s, 0, 1, "forgotten"), t);

        let done = sent(&s, 0, &says("notes", "work", "a branch"), t);
        assert_eq!(done.number, 1);
        assert_eq!(relay.pushed(&s, 0, t), [Pushed::HoldsAnother]);
        assert_eq!(kept_of(&s, 0, &done.id), Some((vec![1], true)));
        let again = write_again(&s[0].conn, &s[0].identity, t + 1, true).unwrap();
        assert_eq!(again.written, [(done.id, 2)]);
        assert_eq!(kept_of(&s, 0, &done.id), Some((vec![1, 2], false)));
        assert_eq!(relay.pushed(&s, 0, t + 1), [Pushed::Holds]);
        assert_eq!(relay.revs_of(&s, 0), [2, 4]);
        assert_eq!(held::taken_at(&s[0].conn, &done.id).unwrap(), [relay.key]);
        // Counted in the device's hour as a send again, and in no
        // folder's.
        let lately = held::sent_lately(&s[0].conn, "notes", t + 1).unwrap();
        assert_eq!(
            (
                lately.by_folder.len(),
                lately.sends.len(),
                lately.again.len()
            ),
            (1, 1, 1)
        );
        // Nothing waits: it is not written a third time.
        assert_eq!(
            write_again(&s[0].conn, &s[0].identity, t + 2, true).unwrap(),
            Again::default()
        );

        s.pass(0, 1);
        assert_eq!(shown_on(&s, 1, t + 2), ["a branch"]);
        assert_eq!(shown_on(&s, 0, t + 2), ["a branch"]);
    }

    /// A relay that holds a later entry of the device's in the slot
    /// answers that it holds a higher revision: the message is not taken
    /// there, and is not written again. The next pull from that relay
    /// hands back the device's later entry, which replaces the message in
    /// its store; the message is then sent once more, above it (decision
    /// 2026-10-09 §2.3, case 2, F6).
    #[test]
    fn a_message_answered_older_waits_and_is_not_sent_again_until_a_pull() {
        let s = devices(2);
        let t = s.now;
        let mut relay = Relay::new(0xa1);
        relay.holds(&of_a_life_forgotten(&s, 0, 65, "later"), t);

        let done = sent(&s, 0, &says("notes", "work", "waits"), t);
        let second = sent(&s, 0, &says("notes", "work", "taken"), t);
        assert_eq!(relay.pushed(&s, 0, t), [Pushed::HoldsLater, Pushed::Holds]);
        assert_eq!(kept_of(&s, 0, &done.id), Some((vec![1], false)));
        // Another device's entry in its own slot of that place, taken
        // through the door, says nothing of this device's ring.
        let others = entry_by(
            &s[1].identity,
            &messages_secret(&s, 0),
            message_rev(65).unwrap(),
            &message_name(&s.key(1), 65).unwrap(),
            Value::Other(says_value("desktop's", t)),
            &[],
        );
        assert!(matches!(
            take(&s[0].conn, &s[0].identity, &others, t).unwrap(),
            Taken::Own { .. }
        ));
        assert_eq!(kept_of(&s, 0, &done.id), Some((vec![1], false)));
        assert!(held::taken_at(&s[0].conn, &done.id).unwrap().is_empty());
        assert_eq!(
            write_again(&s[0].conn, &s[0].identity, t, true).unwrap(),
            Again::default()
        );
        assert_eq!(revs_of(&s, 0, 0), [2, 4]);

        relay.pulled(&s, 0, t + 1);
        assert_eq!(revs_of(&s, 0, 0), [4, 130]);
        assert_eq!(kept_of(&s, 0, &done.id), Some((vec![1], true)));
        assert_eq!(kept_of(&s, 0, &second.id), Some((vec![2], false)));
        let again = write_again(&s[0].conn, &s[0].identity, t + 1, true).unwrap();
        assert_eq!(again.written, [(done.id, 66)]);
        // What the pull handed back is offered back to it too.
        assert_eq!(relay.pushed(&s, 0, t + 1), [Pushed::Holds; 3]);
        assert!(
            held::taken_at(&s[0].conn, &done.id)
                .unwrap()
                .contains(&relay.key)
        );
        // 66 is in the slot of 2, over it.
        assert_eq!(relay.revs_of(&s, 0), [130, 132]);
    }

    /// A relay that answers another to every push makes a message go under
    /// four numbers, each a send again in the device's hour: its kept
    /// value is kept once the fourth is written, and dropped when the
    /// fourth is answered another too, and its index row then says that
    /// it may not have reached every relay. In a second run, where the
    /// next number would be above the highest, it is not sent again, and
    /// the same is said (decision 2026-10-09 §2.3).
    #[test]
    fn a_relay_that_answers_falsely_makes_a_message_go_under_at_most_four_numbers() {
        let s = devices(2);
        let t = s.now;
        let mut relay = Relay::new(0xa1);
        relay.answers = Some(Pushed::HoldsAnother);
        let done = sent(&s, 0, &says("notes", "work", "four times"), t);
        for number in 2..=4 {
            assert_eq!(relay.pushed(&s, 0, t), [Pushed::HoldsAnother]);
            let again = write_again(&s[0].conn, &s[0].identity, t, true).unwrap();
            assert_eq!(again.written, [(done.id, number)]);
        }
        assert_eq!(kept_of(&s, 0, &done.id), Some((vec![1, 2, 3, 4], false)));
        assert!(!not_every_relay(&s, 0, &done.id));
        assert_eq!(relay.pushed(&s, 0, t), [Pushed::HoldsAnother]);
        let again = write_again(&s[0].conn, &s[0].identity, t, true).unwrap();
        assert_eq!(
            again,
            Again {
                written: vec![],
                dropped: vec![done.id]
            }
        );
        assert_eq!(kept_of(&s, 0, &done.id), None);
        assert!(not_every_relay(&s, 0, &done.id));
        assert_eq!(revs_of(&s, 0, 0), [2, 4, 6, 8]);
        assert_eq!(held::sent_lately(&s[0].conn, "", t).unwrap().again.len(), 3);

        let s = devices(2);
        let done = sent(&s, 0, &says("notes", "work", "at the top"), t);
        let max = AGENT_MESSAGE_NUMBER_MAX;
        writes_own(&s, 0, max, message_rev(max).unwrap(), clearing_value());
        assert_eq!(relay.pushed(&s, 0, t)[0], Pushed::HoldsAnother);
        let again = write_again(&s[0].conn, &s[0].identity, t, true).unwrap();
        assert_eq!(again.dropped, [done.id]);
        assert!(again.written.is_empty());
        assert!(not_every_relay(&s, 0, &done.id));
    }

    /// A relay's answer of another to an entry that is not one of the
    /// device's own messages changes nothing it keeps: its list, at the
    /// revision of a kept message's number, and another key's entry in
    /// this device's slot of that number, as a holder of that key writes
    /// it (decision 2026-10-09 §2.3, property 3).
    #[test]
    fn an_answer_to_a_list_or_another_devices_entry_changes_nothing_kept() {
        let s = devices(2);
        let t = s.now;
        let done = sent(&s, 0, &says("notes", "work", "kept"), t);
        let list = entry_by(
            &s[0].identity,
            &messages_secret(&s, 0),
            message_rev(1).unwrap(),
            &read_name(&s.key(0)).unwrap(),
            Value::Other(ReadMarks::default().to_value().unwrap()),
            &[],
        );
        let others = entry_by(
            &s[1].identity,
            &messages_secret(&s, 0),
            message_rev(1).unwrap(),
            &message_name(&s.key(0), 1).unwrap(),
            Value::Other(says_value("desktop's", t)),
            &[],
        );
        let channel = own_messages(&s, 0);
        for entry in [list, others] {
            let wire = Entry::from_wire(&entry.to_wire()).unwrap();
            answered(
                &s[0].conn,
                &s[0].identity,
                &[0xa1; 32],
                &channel,
                &[wire],
                &[Pushed::HoldsAnother],
            )
            .unwrap();
            assert_eq!(kept_of(&s, 0, &done.id), Some((vec![1], false)));
        }
    }

    /// A message that waits to be sent again waits for the first fetch,
    /// and for a device that stands applied with sync on; and for room in
    /// the device's hour, which it then counts in (decision 2026-10-09
    /// §2.3).
    #[test]
    fn a_message_that_waits_to_be_sent_again_waits_for_the_first_fetch_and_the_hour() {
        let s = devices(2);
        let t = s.now;
        let done = sent(&s, 0, &says("notes", "work", "waits"), t);
        held::send_again(&s[0].conn, &done.id).unwrap();
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        assert_eq!(
            write_again(conn, identity, t, false).unwrap(),
            Again::default()
        );
        meta::remove(conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(
            write_again(conn, identity, t, true).unwrap(),
            Again::default()
        );
        meta::set(conn, meta::SYNC_CLAUDE_DIR, "/c").unwrap();
        cordelia_storage::person::set_state(conn, State::Removed).unwrap();
        assert_eq!(
            write_again(conn, identity, t, true).unwrap(),
            Again::default()
        );
        cordelia_storage::person::set_state(conn, State::Applied).unwrap();
        // With the send itself, 58 sends and one send again fill the hour.
        for k in 0..58 {
            held::record_send(conn, t + k, Some("plans"), false).unwrap();
        }
        held::record_send(conn, t + 58, None, false).unwrap();
        assert_eq!(
            write_again(conn, identity, t + 60, true).unwrap(),
            Again::default()
        );
        assert_eq!(revs_of(&s, 0, 0), [2]);
        let again = write_again(conn, identity, t + HOUR, true).unwrap();
        assert_eq!(again.written, [(done.id, 2)]);
    }

    /// Where the device writes over a message's slot itself, with the
    /// message 64 numbers on, that message is not sent again: only an
    /// entry of its own that a relay hands back over it says that it was
    /// lost (decision 2026-10-09 §2.3).
    #[test]
    fn a_slot_the_device_writes_over_itself_sends_nothing_again() {
        let s = devices(2);
        let t = s.now;
        let first = sent(&s, 0, &says("notes", "work", "first"), t);
        for k in 2..=65i64 {
            let from = NAMES[usize::try_from(k % 4).unwrap()];
            let done = sent_read(&s, 0, &says(from, "*", &format!("{k}")), t + k * 4 * 60);
            held::drop_kept(&s[0].conn, &done.id, true).unwrap();
        }
        assert_eq!(kept_of(&s, 0, &first.id), Some((vec![1], false)));
        let again = write_again(&s[0].conn, &s[0].identity, t + DAY, true).unwrap();
        assert_eq!(again, Again::default());
    }

    // ── What is kept ────────────────────────────────────────────────

    /// A message's kept value goes once every relay the device is set up
    /// with has taken it, and not before; where the device keeps 64 and
    /// writes a 65th, the oldest goes, said to be not every relay's; and
    /// 30 days after its `sent` it goes, said so too (decision 2026-10-09
    /// §2.3). With no relay, nothing is kept for one.
    #[test]
    fn a_kept_value_goes_once_every_relay_has_taken_it() {
        let s = devices(2);
        let t = s.now;
        let (mut a, mut b) = (Relay::new(0xa1), Relay::new(0xb2));
        let done = sent(&s, 0, &says("notes", "work", "to both"), t);
        a.pushed(&s, 0, t);
        assert_eq!(taken_everywhere(&s[0].conn, &[a.key, b.key]).unwrap(), 0);
        assert!(kept_of(&s, 0, &done.id).is_some());
        b.pushed(&s, 0, t);
        assert_eq!(taken_everywhere(&s[0].conn, &[a.key, b.key]).unwrap(), 1);
        assert_eq!(kept_of(&s, 0, &done.id), None);
        assert!(!not_every_relay(&s, 0, &done.id));

        let first = sent(&s, 0, &says("plans", "work", "first kept"), t + 1);
        let second = sent(&s, 0, &says("plans", "work", "second kept"), t + 2);
        assert_eq!(taken_everywhere(&s[0].conn, &[a.key]).unwrap(), 0);
        for k in 3..66i64 {
            let from = NAMES[usize::try_from(k % 4).unwrap()];
            sent_read(&s, 0, &says(from, "*", &format!("{k}")), t + k * 4 * 60);
        }
        assert_eq!(held::kept(&s[0].conn).unwrap().len(), 64);
        assert_eq!(kept_of(&s, 0, &first.id), None);
        assert!(kept_of(&s, 0, &second.id).is_some());
        assert_eq!(taken_everywhere(&s[0].conn, &[]).unwrap(), 64);
        assert!(held::kept(&s[0].conn).unwrap().is_empty());

        // 30 days after its `sent`, a kept value goes, and its row, still
        // shown where the device first held it later, says so.
        let s = devices(2);
        let old = sent(&s, 0, &says("plans", "work", "old"), t);
        s[0].conn
            .execute("UPDATE message_index SET first_held = ?1", [t + DAY])
            .unwrap();
        let late = t + 30 * DAY;
        sent(&s, 0, &says("plans", "work", "a month on"), late - 1);
        assert!(kept_of(&s, 0, &old.id).is_some());
        sent(&s, 0, &says("plans", "work", "a month on"), late);
        assert_eq!(kept_of(&s, 0, &old.id), None);
        assert!(not_every_relay(&s, 0, &old.id));

        // At a statement, what was kept of the generation left goes with
        // it, and may not have reached every relay (§9.1).
        let mut s = devices(2);
        let before = sent(&s, 0, &says("plans", "work", "before the change"), t);
        s.change(0, &[0, 1], &[]);
        let after = sent(&s, 0, &says("plans", "*", "after"), t + 60);
        assert_eq!(after.number, 1);
        assert_eq!(kept_of(&s, 0, &before.id), None);
        assert!(not_every_relay(&s, 0, &before.id));
    }

    /// The kept values of a generation the device has left go at the first
    /// hourly task after the statement, said to be not every relay's, and
    /// what is kept of the generation goes with its last index row: after
    /// the hourly task that drops its messages at their 30 days, nothing
    /// of it is left (decision 2026-10-09 §7.1, §9.1). A day after the
    /// statement its index row and the generation are still there.
    #[test]
    fn one_hourly_task_leaves_nothing_of_a_generation_left_with_a_kept_value() {
        let mut s = devices(2);
        let t = s.now;
        let done = sent(&s, 0, &says("notes", "work", "before the change"), t);
        let old = held::generation_of(&s[0].conn, &messages(&s, 0))
            .unwrap()
            .unwrap();
        s.change(0, &[0, 1], &[]);
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        assert!(kept_of(&s, 0, &done.id).is_some());
        crate::reader::hourly(conn, identity, t + DAY, true).unwrap();
        assert_eq!(kept_of(&s, 0, &done.id), None);
        assert!(not_every_relay(&s, 0, &done.id));
        assert_eq!(
            rows(conn, &format!("message_generations WHERE id = {old}")),
            1
        );

        crate::reader::hourly(conn, identity, t + 30 * DAY, true).unwrap();
        for table in [
            "message_generations WHERE id",
            "message_index WHERE generation",
            "message_numbers WHERE generation",
            "message_first_held WHERE generation",
            "message_signers WHERE generation",
            "message_places WHERE generation",
            "message_kept WHERE generation",
        ] {
            assert_eq!(rows(conn, &format!("{table} = {old}")), 0, "{table}");
        }
    }

    // ── One room, and restores ──────────────────────────────────────

    /// 200 messages and 50 lists of one device leave 65 of its entries in
    /// the messages channel, each the newest of its slot (decision
    /// 2026-10-09 §2.3, property 17).
    #[test]
    fn a_device_never_has_more_than_sixty_five_slots() {
        let s = devices(2);
        let t = s.now;
        for k in 0..200i64 {
            let from = NAMES[usize::try_from(k % 4).unwrap()];
            sent_read(&s, 0, &says(from, "*", &format!("{k}")), t + k * 4 * 60);
        }
        let name = read_name(&s.key(0)).unwrap();
        for rev in 1..=50 {
            let list = ReadMarks {
                marks: vec![[u8::try_from(rev).unwrap(); 16]],
            };
            let entry = entry_by(
                &s[0].identity,
                &messages_secret(&s, 0),
                rev,
                &name,
                Value::Other(list.to_value().unwrap()),
                &[],
            );
            entries::store(&s[0].conn, &entry, t).unwrap();
        }
        let revs = revs_of(&s, 0, 0);
        assert_eq!(revs.len(), 65);
        let mut newest: Vec<u64> = (137..=200).map(|number| 2 * number).collect();
        newest.insert(0, 50);
        assert_eq!(revs, newest);
    }

    /// A device sends 70, each taken by its relay, is quiet for 31 days
    /// while it clears all of it, and sends again: its store and the
    /// relay's take the message, at the number after the last cleared
    /// (decision 2026-10-09 §2.3, property 18).
    #[test]
    fn a_device_quiet_until_all_was_cleared_sends_again_and_is_taken() {
        let s = devices(2);
        let t = s.now;
        let mut relay = Relay::new(0xa1);
        for k in 0..70i64 {
            let from = NAMES[usize::try_from(k % 4).unwrap()];
            sent_read(&s, 0, &says(from, "work", &format!("{k}")), t + k * 4 * 60);
            relay.pushed(&s, 0, t + k * 4 * 60);
        }
        let quiet = t + 31 * DAY;
        assert_eq!(
            clear_expired(&s[0].conn, &s[0].identity, quiet, true).unwrap(),
            64
        );
        assert!(
            relay
                .pushed(&s, 0, quiet)
                .iter()
                .all(|answer| *answer == Pushed::Holds)
        );
        let cleared: Vec<u64> = (7..=70).map(|number| 2 * number + 1).collect();
        assert_eq!(relay.revs_of(&s, 0), cleared);
        assert_eq!(shown_on(&s, 0, quiet), Vec::<String>::new());

        let done = sent(&s, 0, &says("notes", "work", "back"), quiet + 60);
        assert_eq!(done.number, 71);
        assert_eq!(relay.pushed(&s, 0, quiet + 60), [Pushed::Holds]);
        assert!(relay.revs_of(&s, 0).contains(&142));
        assert_eq!(shown_on(&s, 0, quiet + 60), ["back"]);
    }

    /// The store of a device whose messages a relay B holds to N + 70,
    /// and the device itself to N: after the wait for a first fetch, with
    /// relay A, set up since the backup, holding nothing of the channel,
    /// it sends at N + 1 while B is down. Then B is reached: the pull hands
    /// back its later entries, one of which replaces the message in its
    /// store; it is sent again under N + 71, above everything B handed
    /// back, and under no other number; another device shows it once
    /// (decision 2026-10-09 §2.3, §15, F6, D3).
    #[test]
    fn a_store_restored_a_lap_behind_one_relay_uses_exactly_one_more_number() {
        let mut s = devices(2);
        let t = s.now;
        let mut b = Relay::new(0xb2);
        const N: i64 = 10;
        let mut at_ = t;
        for k in 1..=N {
            at_ = t + k * 4 * 60;
            let from = NAMES[usize::try_from(k % 4).unwrap()];
            sent_read(&s, 0, &says(from, "work", &format!("before {k}")), at_);
            b.pushed(&s, 0, at_);
            taken_everywhere(&s[0].conn, &[b.key]).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("laptop.db");
        s[0].conn
            .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
            .unwrap();
        for k in 1..=70i64 {
            at_ += 4 * 60;
            let from = NAMES[usize::try_from(k % 4).unwrap()];
            sent_read(&s, 0, &says(from, "work", &format!("later {k}")), at_);
            b.pushed(&s, 0, at_);
            taken_everywhere(&s[0].conn, &[b.key]).unwrap();
        }
        s.machines[0].conn = cordelia_storage::db::open(&backup).unwrap();
        assert_eq!(next_number(&s[0].conn, &s[0].identity).unwrap(), Some(11));

        // A holds nothing, and B is down: the device sends at N + 1.
        let a = Relay::new(0xa1);
        assert!(a.pulled(&s, 0, at_ + 60).is_empty());
        let done = sent(&s, 0, &says("notes", "work", "while B was down"), at_ + 60);
        assert_eq!(done.number, 11);

        b.pulled(&s, 0, at_ + 120);
        assert_eq!(kept_of(&s, 0, &done.id), Some((vec![11], true)));
        let again = write_again(&s[0].conn, &s[0].identity, at_ + 120, true).unwrap();
        assert_eq!(again.written, [(done.id, 81)]);
        b.pushed(&s, 0, at_ + 120);
        assert_eq!(
            write_again(&s[0].conn, &s[0].identity, at_ + 180, true).unwrap(),
            Again::default()
        );
        assert_eq!(kept_of(&s, 0, &done.id), Some((vec![11, 81], false)));
        assert!(b.revs_of(&s, 0).contains(&162));

        // Another device takes what B holds, and shows the message once.
        b.pulled(&s, 1, at_ + 240);
        let shown = shown_on(&s, 1, at_ + 240);
        let once = shown
            .iter()
            .filter(|body| *body == "while B was down")
            .count();
        assert_eq!(once, 1);
        let _ = &mut s;
    }
}
