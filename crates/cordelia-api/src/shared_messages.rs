//! What a device's agents are shown of the shared channels they subscribe
//! to, and what is kept of what they read and sent (decision 2026-10-10
//! §4.1, §6.1, §6.2, §6.4).
//!
//! - **Subscriptions** are items of the person's list (§3.4): of an agent,
//!   which is a name, on every device of the person. **Each starts when
//!   this device first takes it** ([`keep_starts`], kept with the table of
//!   shared channels, and only while its channel is held): an agent is shown only messages whose shown time and
//!   first holding here are both at or after it.
//! - **Who is shown what** ([`unread`], §6.2): a message of a channel the
//!   agent subscribes to, shown by the reader (§2.4), after the start, with
//!   no mark, in this device's table or in the latest `sread/` list of any
//!   device of the person's that counts, of that message read or sent by an
//!   agent of that name. So an agent is never shown, on any device, what an
//!   agent of its name sent.
//! - **The marks** bind the channel (`message::shared_read_mark`,
//!   `message::shared_sent_mark`), and are said to the person's own devices
//!   alone, in the `sread/` list of the person's messages channel
//!   ([`write_list`]), written, merged and written again as the `read/`
//!   list is, counted apart. Nothing about reading or sending is written in
//!   a shared channel.
//! - **The hold** ([`held`], §6.4): the loop an agent is in, at 10.

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;

use cordelia_core::CordeliaError;
use cordelia_core::protocol::AGENT_MESSAGE_ID_BYTES;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{ReadMarks, shared_read_mark, shared_sent_mark};
use cordelia_storage::messages::{Id, Mark};
use cordelia_storage::shared::{self as kept, Channel, Shown, State};
use cordelia_storage::shared_messages as rows;

use crate::marks::{HeldList, PersonList, may_write};
use crate::person::{Counting, PersonError, in_one, who_counts};

fn kept_in<T>(answer: Result<T, CordeliaError>) -> Result<T, PersonError> {
    answer.map_err(PersonError::Storage)
}

// ── Subscriptions ────────────────────────────────────────────────────

/// The subscriptions in force, as this device holds the person's lists
/// (§3.4): each channel and agent whose newest valid act subscribes.
pub fn in_force(conn: &Connection) -> Result<Vec<([u8; 32], String)>, PersonError> {
    Ok(crate::lists::holds(conn)?
        .subscriptions
        .into_iter()
        .filter(|(act, _)| act.item.subscribed)
        .map(|(act, _)| (act.item.channel, act.item.agent))
        .collect())
}

/// Keep the starts of the subscriptions with what is in force, at `now`
/// (§4.1): a subscription this device has just taken starts now; one taken
/// again in the same state keeps its start; one that ended goes. A start
/// is kept only while its channel is held here: a channel dropped, moved
/// from or not in force loses its starts, so that one taken again starts
/// again and its agents are shown nothing written while it was not held.
/// Run where the table of shared channels is kept (`shared::keep`), after
/// the channels' states.
pub fn keep_starts(conn: &Connection, now: i64) -> Result<(), PersonError> {
    let held: HashSet<[u8; 32]> = kept_in(kept::channels(conn))?
        .into_iter()
        .filter(|row| row.state == State::Held)
        .map(|row| row.channel)
        .collect();
    let starts: Vec<_> = in_force(conn)?
        .into_iter()
        .filter(|(channel, _)| held.contains(channel))
        .collect();
    // A subscription moved with its channel keeps the start it had in the
    // channel moved from (decision 2026-10-10 §7), where this device held
    // one: it is taken before the old one goes.
    let kept_starts = kept_in(rows::subscribed(conn))?;
    for row in kept_in(kept::channels(conn))? {
        let cordelia_storage::shared::Came::Moved(from) = row.came else {
            continue;
        };
        if row.state != State::Held {
            continue;
        }
        for (channel, agent) in starts.iter().filter(|(channel, _)| *channel == row.channel) {
            if let Some(old) = kept_starts
                .iter()
                .find(|start| start.channel == from && start.agent == *agent)
            {
                kept_in(rows::start_at(conn, channel, agent, old.start))?;
            }
        }
    }
    kept_in(rows::keep_subscribed(conn, &starts, now))
}

/// Where the agent `agent` subscribes to the shared channel `channel` on
/// this device: when its subscription started here.
pub fn start_of(
    conn: &Connection,
    channel: &[u8; 32],
    agent: &str,
) -> Result<Option<i64>, PersonError> {
    Ok(kept_in(rows::subscribed(conn))?
        .into_iter()
        .find(|row| row.channel == *channel && row.agent == agent)
        .map(|row| row.start))
}

/// Each shared channel held that the agent `agent` subscribes to, with when
/// its subscription started here, in the order of the channels' rows.
pub fn subscribed_by(conn: &Connection, agent: &str) -> Result<Vec<(Channel, i64)>, PersonError> {
    let starts = kept_in(rows::subscribed(conn))?;
    let mut found = Vec::new();
    for row in kept_in(kept::channels(conn))? {
        if row.state != State::Held {
            continue;
        }
        if let Some(start) = starts
            .iter()
            .find(|start| start.channel == row.channel && start.agent == agent)
        {
            found.push((row, start.start));
        }
    }
    Ok(found)
}

// ── Marks ────────────────────────────────────────────────────────────

/// Every shared mark this device holds now, worked out once for a request:
/// its own table, and the latest list of each device that counts by
/// `counting`. A list of a key that does not count says nothing.
pub struct MarksNow {
    here: HashSet<Mark>,
    lists: HashMap<Mark, Vec<[u8; 32]>>,
}

/// What [`MarksNow`] holds.
pub fn marks_now(conn: &Connection, counting: &Counting) -> Result<MarksNow, PersonError> {
    let held = kept_in(rows::marks(conn))?;
    let mut lists: HashMap<Mark, Vec<[u8; 32]>> = HashMap::new();
    for (key, mark) in held.lists {
        if counting.counts(&key) {
            lists.entry(mark).or_default().push(key);
        }
    }
    Ok(MarksNow {
        here: held.here,
        lists,
    })
}

impl MarksNow {
    fn said(&self, mark: &Mark) -> bool {
        self.here.contains(mark) || self.lists.contains_key(mark)
    }

    /// Whether an agent of `agent` sent message `id` of `channel`, on any
    /// device of the person's that counts.
    pub fn sent_by(&self, channel: &[u8; 32], id: &Id, agent: &str) -> bool {
        self.said(&shared_sent_mark(channel, id, agent))
    }

    /// Whether an agent of `agent` read message `id` of `channel`.
    pub fn read_by(&self, channel: &[u8; 32], id: &Id, agent: &str) -> bool {
        self.said(&shared_read_mark(channel, id, agent))
    }

    /// The devices whose lists say an agent of `agent` read it, in order of
    /// key.
    pub fn read_on(&self, channel: &[u8; 32], id: &Id, agent: &str) -> Vec<[u8; 32]> {
        let mut keys = self
            .lists
            .get(&shared_read_mark(channel, id, agent))
            .cloned()
            .unwrap_or_default();
        keys.sort();
        keys
    }
}

/// The agent of `agent` read, or sent, message `id` of the shared channel
/// `channel` on this device at `now` (§6.1): its mark is the newest in the
/// table. The list is written where it may be.
pub fn mark(conn: &Connection, mark: &Mark, now: i64) -> Result<(), PersonError> {
    kept_in(rows::mark(conn, mark, now))
}

/// Write the device's list of shared marks at `now`, where it is due
/// (§6.1): the table holds a mark that the list of its own in its store
/// lacks. Never before the first fetch of the messages channel since the
/// node started (`fetched`), nor where the device does not stand applied
/// or has sync off. After a statement the list held in the new generation
/// is none, so the first pass writes it again there from the table: a
/// shared channel outlives the person's statements. Returns the revision
/// written, where one was. One transaction.
pub fn write_list(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
) -> Result<Option<u64>, PersonError> {
    in_one(conn, || list_written(conn, identity, now, fetched, None))
}

/// [`write_list`], in the caller's write; with `above`, a relay answered
/// that it holds another list of the device's at that revision, and it is
/// written again above it, at most three times in a row, counted apart.
pub(crate) fn list_written(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
    above: Option<u64>,
) -> Result<Option<u64>, PersonError> {
    if !may_write(conn, fetched)? {
        return Ok(None);
    }
    let held = HeldList::of(conn, &identity.public_key(), PersonList::SharedReads)?;
    // A list of its own that does not read is a list of no marks.
    let listed: HashSet<Mark> = held
        .held
        .as_ref()
        .and_then(|(_, value)| value.as_ref())
        .and_then(|value| ReadMarks::from_value(value).ok())
        .map(|list| list.marks.into_iter().collect())
        .unwrap_or_default();
    let marks = kept_in(rows::marks_to_list(conn))?;
    let changed = marks.iter().any(|mark| !listed.contains(mark));
    let value = ReadMarks { marks }
        .to_value()
        .map_err(|e| PersonError::Held(format!("a list of shared marks: {e}")))?;
    held.write(conn, identity, now, above, changed, value)
}

/// The reader took `marks`, the `sread/` list of the device whose key is
/// `signer`, which the store kept over what it held (§6.1), in the door's
/// write. Another device's is kept in place of what was kept of it, until
/// its next, whatever generation it comes in. The device's own, `own`, is
/// one a relay handed back from its later life: its marks are merged into
/// the table, below those it holds.
pub(crate) fn list_taken(
    conn: &Connection,
    own: &[u8; 32],
    signer: &[u8; 32],
    marks: &[Mark],
    now: i64,
) -> Result<(), PersonError> {
    if signer != own {
        return kept_in(rows::keep_list(conn, signer, marks));
    }
    kept_in(rows::merge_own_list(conn, marks, now)).map(|_| ())
}

/// The shared messages' part of the hourly task, at `now` (§6.1, §6.4): the
/// `sread/` lists of keys that no longer count go, where who counts can be
/// read, and the marks of messages that have expired; and the sends of the
/// channels' hours from before the hour.
pub(crate) fn hourly(conn: &Connection, now: i64) -> Result<(), PersonError> {
    let keys = match who_counts(conn) {
        Ok(counting) => counting.keys(),
        Err(_) => return kept_in(rows::drop_old_sends(conn, now)),
    };
    kept_in(rows::keep_within(conn, &keys, now))?;
    kept_in(rows::drop_old_sends(conn, now))
}

// ── Who is shown what ────────────────────────────────────────────────

/// A message of a shared channel as an agent is shown it: its channel's
/// row, the start of the agent's subscription, and the message.
#[derive(Debug, Clone)]
pub struct Seen {
    pub row: Channel,
    pub start: i64,
    pub id: Id,
    pub message: Shown,
}

/// The ID of a row of the index.
pub(crate) fn id_of(bytes: &[u8]) -> Result<Id, PersonError> {
    bytes
        .try_into()
        .map_err(|_| PersonError::Held("a message's ID is not of its length".into()))
}

/// Every message the agent of `agent` may be shown of the shared channels
/// it subscribes to on this device, at `now` (§4.1, §6.2): shown by the
/// reader, places given as at every show (§2.4), and both shown and first
/// held at or after the start of its subscription here. Oldest first, by
/// shown time and then by ID, across the channels.
pub fn shown_to(
    conn: &Connection,
    identity: &NodeIdentity,
    agent: &str,
    now: i64,
) -> Result<Vec<Seen>, PersonError> {
    let mut seen = Vec::new();
    for (row, start) in subscribed_by(conn, agent)? {
        for message in crate::shared::shown(conn, identity, &row.channel, now)? {
            if message.shown_at < start || message.first_held < start {
                continue;
            }
            seen.push(Seen {
                row: row.clone(),
                start,
                id: id_of(&message.id)?,
                message,
            });
        }
    }
    seen.sort_by(|a, b| {
        (a.message.shown_at, a.id, a.row.id).cmp(&(b.message.shown_at, b.id, b.row.id))
    });
    Ok(seen)
}

/// The messages unread by the agent of `agent` at `now` (§6.2), oldest
/// first: of [`shown_to`], each with no mark of it read or sent by an agent
/// of that name, here or by the list of a device that counts.
pub fn unread(
    conn: &Connection,
    identity: &NodeIdentity,
    agent: &str,
    now: i64,
) -> Result<Vec<Seen>, PersonError> {
    let marks = marks_now(conn, &who_counts(conn)?)?;
    Ok(shown_to(conn, identity, agent, now)?
        .into_iter()
        .filter(|seen| {
            !marks.read_by(&seen.row.channel, &seen.id, agent)
                && !marks.sent_by(&seen.row.channel, &seen.id, agent)
        })
        .collect())
}

/// Whether `given`, 8 to 32 hex characters, begins the ID of a shared
/// message that the agent of `agent` may be shown at `now`: the channel of
/// the first, where one does. What the one function that sends asks of a
/// reply to the person's own agents (§4.2, `reply_elsewhere`).
pub fn names_a_shared_message(
    conn: &Connection,
    identity: &NodeIdentity,
    agent: &str,
    given: &str,
    now: i64,
) -> Result<Option<[u8; 32]>, PersonError> {
    let prefix = given.to_ascii_lowercase();
    Ok(shown_to(conn, identity, agent, now)?
        .into_iter()
        .find(|seen| hex::encode(seen.id).starts_with(&prefix))
        .map(|seen| seen.row.channel))
}

/// The thread a shown message is in: its `thread`, or its own ID.
pub fn thread_of(message: &Shown) -> Result<Id, PersonError> {
    let id = id_of(&message.id)?;
    Ok(match id_of(&message.thread) {
        Ok(thread) if thread != [0; AGENT_MESSAGE_ID_BYTES] => thread,
        _ => id,
    })
}

// ── The hold ─────────────────────────────────────────────────────────

/// How many messages hold the agent of `agent` in the shared channel of
/// `row`, at `now` (§6.4): its own there (those an agent of its name sent,
/// on any device of the person, as this device knows from its sent marks),
/// and those of other keys that answer one of them or are in a thread in
/// which it wrote; each shown with a place, live, not expired, after its
/// subscription began here, and that no person here has read. At 10 it
/// sends no more there. Ten that others write among themselves hold
/// nobody.
pub fn held(
    conn: &Connection,
    identity: &NodeIdentity,
    row: &Channel,
    agent: &str,
    now: i64,
) -> Result<u64, PersonError> {
    let Some(start) = start_of(conn, &row.channel, agent)? else {
        return Ok(0);
    };
    let marks = marks_now(conn, &who_counts(conn)?)?;
    let read_here = kept_in(rows::read_by_a_person(conn, row.id))?;
    let shown: Vec<Shown> = crate::shared::shown(conn, identity, &row.channel, now)?
        .into_iter()
        .filter(|message| message.shown_at >= start && message.first_held >= start)
        .collect();
    let mut own: HashSet<Id> = HashSet::new();
    let mut threads: HashSet<Id> = HashSet::new();
    for message in &shown {
        let id = id_of(&message.id)?;
        if marks.sent_by(&row.channel, &id, agent) {
            own.insert(id);
            threads.insert(thread_of(message)?);
        }
    }
    let mut waiting = 0;
    for message in &shown {
        let id = id_of(&message.id)?;
        if read_here.contains(&id) {
            continue;
        }
        let in_the_loop = own.contains(&id)
            || own.contains(&id_of(&message.answers).unwrap_or([0; AGENT_MESSAGE_ID_BYTES]))
            || threads.contains(&thread_of(message)?);
        if in_the_loop {
            waiting += 1;
        }
    }
    Ok(waiting)
}
