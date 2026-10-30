//! What the person's agents read (decision 2026-10-09 §2.4, §7.2, §9.1).
//!
//! **Read by an agent** is for an agent's name. A device keeps its own
//! table of the marks its agents made, and says them to the person's
//! other devices in its list, the one entry in its slot `read/<its key>`
//! of the messages channel. Each device keeps the latest list of each
//! other device that counts.
//!
//! - **Marking** ([`read_here`]): the agent of a folder read a message
//!   addressed to it, and its mark is the newest in the table. The list is
//!   then written again, where it may be.
//! - **The list** ([`write_list`]): written from the table, the newest
//!   marks first, as many as a list holds (120), whatever became of their
//!   messages (a mark stays as a bare hash when its message's row goes),
//!   one revision above the list of the device's own that its store
//!   holds. **Never before the first fetch** of the messages channel since
//!   the node started, nor where the device does not stand applied or has
//!   sync off: a mark made then waits in the table for the first list
//!   after. It is written where the table holds a mark that the list held
//!   lacks, so a pass writes the first list of a new generation, and the
//!   list after one that a relay handed back.
//! - **A list taken** ([`list_taken`], from the reader, in the door's
//!   write, only where the store kept it): another device's replaces what
//!   was kept of that device; the device's own, from its later life, is
//!   merged into its table as older than any mark there, before the next
//!   is written.
//! - **A relay's answer of another** to the device's list ([`answered`]):
//!   the list is written again above that revision. An answer that the
//!   relay holds a later one needs nothing: the next pull hands it back.
//! - **Whether a message is read** is worked out when it is shown
//!   ([`read_on`], [`unread`]), from the table and the lists of the keys
//!   that count now: a list that arrives before the message it marks loses
//!   nothing, and one from a key that no longer counts says nothing.
//!
//! **What a device that lies in its list can do:** hide a message from the
//! summaries of the other devices' agents of that name. Not from `log` by
//! that list, nor from `read`, which show every message that is named or
//! held, with the devices whose lists say it was read.
//!
//! ## What a person read (decision 2026-10-25, rule 1)
//!
//! **Read by a person** counts on every device of the person's. A device
//! keeps a person's read here in its own table, and says the newest 120 to
//! the other devices in its list of a person's reads, the one entry in its
//! slot `person/<its key>`, of form 3 ([`write_person_list`]), by the rules
//! of the agents' list: never before the first fetch, nor where the device
//! does not stand applied or has sync off; wherever the table holds an ID
//! that the list held lacks, so `log`'s write that marks writes it too; one
//! revision above the list held; and again above a relay's answer of
//! another, at most three times in a row, counted apart from the agents'
//! list.
//!
//! - **A list taken** ([`person_list_taken`]): another key's adds each of
//!   its IDs to what is kept of that key, **as a union**, so that a read
//!   that falls out of a newer list stays read. The device's own, from its
//!   later life, adds each ID whose message it holds to its own table, and
//!   keeps the rest under its own key.
//! - **Whether a message is read by a person** is worked out when it is
//!   asked ([`person_read_now`]): a row of its own table, or a row of
//!   another key's lists under a key that counts now.
//!
//! **What a device that lies in that list can do:** hide a message from
//! `log` on every device, and end its hold. `log` then says on which device
//! a person read each message it does not show (rule 5).

use rusqlite::Connection;

use std::collections::{HashMap, HashSet};

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{AGENT_MESSAGE_SENDS_MAX, REV_BAND_HALF};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{Entry, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{
    self, PersonReads, ReadMarks, hold_name, person_name, read_name, sread_name,
};
use cordelia_crypto::slots::slot_id;
use cordelia_storage::StorageError;
use cordelia_storage::entries::{self, Outcome};
use cordelia_storage::messages::{self as held, Id, Mark, Shown};
use cordelia_storage::meta;

use crate::at_relays::{Kind, Own, Pushed, Stands, stands};
use crate::person::{Counting, PersonError, in_one, who_counts};
use crate::publish::Standing;

/// What [`read_here`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Marked {
    /// The message is one the agent's mark is made for, and the table now
    /// holds it.
    pub marked: bool,
    /// The revision of the list written after it, where one was.
    pub list: Option<u64>,
}

/// The agent of `name`, the agent of the folder a command was run in,
/// read message `id` on this device at `now` by the node's clock (decision
/// 2026-10-09 §4.1, §7.2): where the message is shown here and addressed
/// to that agent, to its name or to every name, and is not one that agent
/// sent from this device, its mark is the newest in the device's own
/// table. The device's list is then written again where it may be
/// ([`write_list`]): `fetched` says whether the messages channel was
/// fetched since the node started. One transaction.
pub fn read_here(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    id: &Id,
    now: i64,
    fetched: bool,
) -> Result<Marked, PersonError> {
    in_one(conn, || {
        let own = identity.public_key();
        let shown = kept(held::shown(conn, now))?;
        let Some(message) = shown.iter().find(|shown| shown.id[..] == id[..]) else {
            return Ok(Marked::default());
        };
        if !is_for(message, &own, name) {
            return Ok(Marked::default());
        }
        kept(held::mark_read(conn, id, name, now))?;
        Ok(Marked {
            marked: true,
            list: list_written(conn, identity, now, fetched, None)?,
        })
    })
}

/// Whether `message` is one that the agent of `name` on the device whose
/// key is `own` is shown (decision 2026-10-09 §3, §7.2): to its name or to
/// every name, and not sent by it from this device.
pub(crate) fn is_for(message: &Shown, own: &[u8; 32], name: &str) -> bool {
    let to_it = message.to.as_deref().is_none_or(|to| to == name);
    let its_own = message.signer[..] == own[..] && message.from == name;
    to_it && !its_own
}

/// Write the device's list of what its agents read, at `now`, where it is
/// due (decision 2026-10-09 §2.4): the table holds a mark that the list of
/// its own in its store lacks, or there is none in the generation applied
/// and the table holds a mark. Never before the first fetch (`fetched`),
/// nor where the device does not stand applied or has sync off. Returns
/// the revision written, where one was. One transaction.
pub fn write_list(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
) -> Result<Option<u64>, PersonError> {
    in_one(conn, || list_written(conn, identity, now, fetched, None))
}

/// The list's slot, and the list of the device's own that its store holds
/// there in the messages channel of the generation applied, with its
/// revision.
struct Held {
    secret: [u8; 32],
    slot: [u8; 32],
    list: Option<(u64, Vec<Mark>)>,
}

impl Held {
    fn of(conn: &Connection, own: &[u8; 32]) -> Result<Self, PersonError> {
        let standing = Standing::to_write(conn)?;
        let secret = derive::messages_secret(&standing.secret)?;
        let channel = derive::channel_id(&secret)?;
        let slot = slot_id(&derive::slot_key(&secret)?, &read_name(own)?);
        let stored = entries::author_entry(conn, &channel, &slot, own)?;
        let list = match stored {
            Some(stored) => {
                let entry = stored.entry.check()?;
                // A list of its own that does not read is a list of no
                // marks: the next goes above it all the same.
                let marks = entry
                    .open(&secret)
                    .ok()
                    .and_then(|inside| ReadMarks::from_value(&inside.value).ok())
                    .map(|list| list.marks)
                    .unwrap_or_default();
                Some((entry.rev, marks))
            }
            None => None,
        };
        Ok(Self { secret, slot, list })
    }
}

/// [`write_list`], in the caller's write. With `above`, a relay answered
/// that it holds another list of the device's at that revision: the list
/// is written again where that is the revision of the list the store
/// holds, whatever the table says. **A list's marks go under at most four
/// revisions** (`AGENT_MESSAGE_SENDS_MAX`, as a message's numbers do): a
/// relay that answers falsely can make the device write its list again
/// three times for each list it writes for a mark it lacked, and no more
/// (`meta::MESSAGES_LIST_AGAIN` counts them, and a list written for a new
/// mark starts the count again).
fn list_written(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
    above: Option<u64>,
) -> Result<Option<u64>, PersonError> {
    if !fetched
        || stands(conn)? != Stands::Applied
        || meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_none()
    {
        return Ok(None);
    }
    let own = identity.public_key();
    let held = Held::of(conn, &own)?;
    let marks = kept(held::marks_to_list(conn))?;
    let (rev, listed) = held.list.unwrap_or((0, Vec::new()));
    let again: usize = meta::get(conn, meta::MESSAGES_LIST_AGAIN)?
        .and_then(|again| again.parse().ok())
        .unwrap_or(0);
    let due = match above {
        Some(answered) => rev == answered && again + 1 < AGENT_MESSAGE_SENDS_MAX,
        None => marks.iter().any(|mark| !listed.contains(mark)),
    };
    // A list stays in the bottom half of band 0, as the messages do: a
    // holder of the key that wrote one at its top leaves none above it.
    let next = rev + 1;
    if !due || next >= REV_BAND_HALF {
        return Ok(None);
    }
    let again = match above {
        Some(_) => again + 1,
        None => 0,
    };
    meta::set(conn, meta::MESSAGES_LIST_AGAIN, &again.to_string())?;
    let value = ReadMarks { marks }
        .to_value()
        .map_err(|e| PersonError::Held(format!("a list of read marks: {e}")))?;
    let inside = message::inside(read_name(&own)?, value);
    let entry = Entry::seal(&held.secret, identity, next, &inside)?.check()?;
    if entries::store(conn, &entry, now)? != Outcome::Stored {
        return Err(PersonError::Held(
            "the store holds a list of this device's at or above that revision".into(),
        ));
    }
    kept(held::wrote_list(conn))?;
    Ok(Some(next))
}

/// A relay answered a push of `entries` of the messages channel `channel`
/// with `answers`, one for each (decision 2026-10-09 §2.4). Where it holds
/// another list of the device's at the revision of the one pushed, the
/// list is written again above it, at `now`, where it may be (`fetched`,
/// [`write_list`]). Returns the revision written, where one was.
pub fn answered(
    conn: &Connection,
    identity: &NodeIdentity,
    channel: &Own,
    entries: &[Entry],
    answers: &[Pushed],
    now: i64,
    fetched: bool,
) -> Result<Option<u64>, PersonError> {
    if channel.kind != Kind::Messages || entries.len() != answers.len() {
        return Ok(None);
    }
    in_one(conn, || {
        if stands(conn)? != Stands::Applied {
            return Ok(None);
        }
        // The slot is the list's in the generation applied: its name is
        // made under that channel's slot key. Each of the three lists is
        // matched by its own slot, and written again apart (decision
        // 2026-10-25, rules 1 and 2).
        let own = identity.public_key();
        let held = Held::of(conn, &own)?;
        let another = |slot: &[u8; 32]| {
            entries
                .iter()
                .zip(answers)
                .find(|(entry, answer)| {
                    **answer == Pushed::HoldsAnother && entry.author == own && entry.slot == *slot
                })
                .map(|(entry, _)| entry.rev)
        };
        let person = HeldList::of(conn, &own, PersonList::Reads)?;
        if let Some(rev) = another(&person.slot) {
            person_list_written(conn, identity, now, fetched, Some(rev))?;
        }
        let bounds = HeldList::of(conn, &own, PersonList::Bounds)?;
        if let Some(rev) = another(&bounds.slot) {
            crate::bounds::answered_another(conn, identity, now, fetched, rev)?;
        }
        // The list of shared marks is matched by its own slot too, and
        // written again apart (decision 2026-10-10 §6.1).
        let shared = HeldList::of(conn, &own, PersonList::SharedReads)?;
        if let Some(rev) = another(&shared.slot) {
            crate::shared_messages::list_written(conn, identity, now, fetched, Some(rev))?;
        }
        match another(&held.slot) {
            Some(rev) => list_written(conn, identity, now, fetched, Some(rev)),
            None => Ok(None),
        }
    })
}

/// The reader took `marks`, the list of the device whose key is `signer`,
/// which the store kept over what it held (decision 2026-10-09 §7.2), in
/// the door's write. Another device's list is kept in place of what was
/// kept of it. The device's own, `own`, is one a relay handed back from
/// its later life: its marks are merged into the table below those made
/// since the device last wrote its list and above the rest, each found by
/// the messages held and the names mapped here.
pub(crate) fn list_taken(
    conn: &Connection,
    own: &[u8; 32],
    signer: &[u8; 32],
    marks: &[Mark],
    now: i64,
) -> Result<(), PersonError> {
    if signer != own {
        return kept(held::keep_list(conn, signer, marks));
    }
    kept(held::merge_own_list(conn, marks, &mapped(conn)?, now)).map(|_| ())
}

/// The names that the folders of this device are mapped to.
fn mapped(conn: &Connection) -> Result<Vec<String>, PersonError> {
    let mappings = crate::sync::mappings(conn)
        .map_err(|e| PersonError::Storage(CordeliaError::Storage(e.to_string())))?;
    Ok(mappings.into_iter().map(|mapping| mapping.name).collect())
}

/// The marks' part of the hourly task (decision 2026-10-09 §7.2), at
/// `now`, in the caller's write: the list of each key that no longer
/// counts goes, where who counts can be read; each bare hash whose message
/// the device now holds is given its ID and name, and one still bare 30
/// days after it was merged goes. And what is kept of other devices'
/// lists of a person's reads is kept within its bounds: 120 of each key of
/// messages not held, for 30 days (decision 2026-10-25, rule 1.2).
pub(crate) fn hourly(conn: &Connection, now: i64) -> Result<(), PersonError> {
    if let Ok(counting) = who_counts(conn) {
        kept(held::drop_lists_but(conn, &counting.keys()))?;
    }
    kept(held::keep_person_marks(conn, now))?;
    kept(held::keep_bare_marks(conn, &mapped(conn)?, now)).map(|_| ())
}

/// Where it is said that an agent of `name` read message `id` (decision
/// 2026-10-09 §4.1, §7.2): on this device, and the keys that count whose
/// latest list says so.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadOn {
    pub here: bool,
    /// In order of key.
    pub devices: Vec<[u8; 32]>,
}

impl ReadOn {
    /// Whether it is read by an agent of that name.
    pub fn is_read(&self) -> bool {
        self.here || !self.devices.is_empty()
    }
}

/// Where it is said that an agent of `name` read message `id`, worked out
/// now (decision 2026-10-09 §7.2): from the device's own table, a bare
/// hash among it, and the latest list of each device that counts, by
/// `counting`, which the caller works out once for its request. What
/// `read` and `log` say of a message, and what decides whether it is
/// unread.
pub fn read_on(
    conn: &Connection,
    id: &Id,
    name: &str,
    counting: &Counting,
) -> Result<ReadOn, PersonError> {
    let said = kept(held::read_by(conn, id, name))?;
    Ok(ReadOn {
        here: said.here,
        devices: said
            .lists
            .into_iter()
            .filter(|key| counting.counts(key))
            .collect(),
    })
}

/// What [`read_on`] says of every message and name at once, read with two
/// statements (decision 2026-10-09 §7.2, §8): the marks of the device's
/// own table, a bare hash among them, and those of the latest list of
/// each key that counts by `counting`. The status asks it of each message
/// and each name mapped.
pub struct ReadNow(std::collections::HashSet<Mark>);

/// The marks that say a message read now.
pub fn read_now(conn: &Connection, counting: &Counting) -> Result<ReadNow, PersonError> {
    let read = kept(held::read_marks(conn))?;
    let mut marks: std::collections::HashSet<Mark> = read.here.into_iter().collect();
    marks.extend(
        read.lists
            .into_iter()
            .filter(|(key, _)| counting.counts(key))
            .map(|(_, mark)| mark),
    );
    Ok(ReadNow(marks))
}

impl ReadNow {
    /// Whether an agent of `name` read message `id`.
    pub fn is_read(&self, id: &Id, name: &str) -> bool {
        self.0.contains(&message::read_mark(id, name))
    }
}

/// The messages shown at `now` that are unread by the agent of `name` on
/// this device (decision 2026-10-09 §7.2): addressed to its name or to
/// every name, not sent by it from this device, and read by no agent of
/// that name, here or by the list of a device that counts by `counting`.
/// Oldest first. It gives no place: a show gives places first.
pub fn unread(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    now: i64,
    counting: &Counting,
) -> Result<Vec<Shown>, PersonError> {
    let own = identity.public_key();
    let mut unread = Vec::new();
    for message in kept(held::shown(conn, now))? {
        if !is_for(&message, &own, name) {
            continue;
        }
        let id: Id = message.id[..]
            .try_into()
            .map_err(|_| PersonError::Held("a message's ID is not of its length".into()))?;
        if !read_on(conn, &id, name, counting)?.is_read() {
            unread.push(message);
        }
    }
    Ok(unread)
}

// ── What a person read (decision 2026-10-25, rule 1) ────────────────

/// One of the device's lists of what a person did at a terminal (decision
/// 2026-10-25, rules 1 and 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersonList {
    /// What a person read on it, in `person/<its key>`.
    Reads,
    /// The bounds a person set on it, in `hold/<its key>`.
    Bounds,
    /// The shared messages its agents read and sent, in `sread/<its key>`
    /// (decision 2026-10-10 §6.1).
    SharedReads,
}

impl PersonList {
    fn name(self, own: &[u8; 32]) -> Result<String, PersonError> {
        Ok(match self {
            Self::Reads => person_name(own)?,
            Self::Bounds => hold_name(own)?,
            Self::SharedReads => sread_name(own)?,
        })
    }

    /// The count of lists written again in a row for a relay's answer of
    /// another: each list's apart from the others'.
    fn again_key(self) -> &'static str {
        match self {
            Self::Reads => meta::MESSAGES_PERSON_AGAIN,
            Self::Bounds => meta::MESSAGES_BOUNDS_AGAIN,
            Self::SharedReads => meta::MESSAGES_SREAD_AGAIN,
        }
    }
}

/// The slot of one of those lists in the generation applied, and the list
/// of the device's own that its store holds there: its revision, and its
/// value where it opens.
pub(crate) struct HeldList {
    list: PersonList,
    secret: [u8; 32],
    pub(crate) slot: [u8; 32],
    pub(crate) held: Option<(u64, Option<Value>)>,
}

impl HeldList {
    pub(crate) fn of(
        conn: &Connection,
        own: &[u8; 32],
        list: PersonList,
    ) -> Result<Self, PersonError> {
        let standing = Standing::to_write(conn)?;
        let secret = derive::messages_secret(&standing.secret)?;
        let channel = derive::channel_id(&secret)?;
        let slot = slot_id(&derive::slot_key(&secret)?, &list.name(own)?);
        let held = match entries::author_entry(conn, &channel, &slot, own)? {
            Some(stored) => {
                let entry = stored.entry.check()?;
                let value = entry.open(&secret).ok().map(|inside| inside.value);
                Some((entry.rev, value))
            }
            None => None,
        };
        Ok(Self {
            list,
            secret,
            slot,
            held,
        })
    }

    /// The revision of the list held, or 0.
    pub(crate) fn rev(&self) -> u64 {
        self.held.as_ref().map_or(0, |(rev, _)| *rev)
    }

    /// Write `value` as the list, one revision above the list held, at
    /// `now`, where it is due (decision 2026-10-25, rules 1 and 2, as
    /// decision 2026-10-09 §2.4 has the agents' list written): `changed`,
    /// it holds what the list held does not; or, with `above`, a relay
    /// answered that it holds another of the device's at that revision, the
    /// revision of the list held, and it has been written again so fewer
    /// than three times in a row. The caller has checked that it may write
    /// ([`may_write`]): never before the first fetch, nor where the device
    /// does not stand applied or has sync off. A list stays in the bottom
    /// half of band 0. Returns the revision written, where one was. In the
    /// caller's write.
    pub(crate) fn write(
        &self,
        conn: &Connection,
        identity: &NodeIdentity,
        now: i64,
        above: Option<u64>,
        changed: bool,
        value: Vec<u8>,
    ) -> Result<Option<u64>, PersonError> {
        let rev = self.rev();
        let due = match above {
            Some(answered) => self.takes_answer(conn, answered)?,
            None => changed,
        };
        let next = rev + 1;
        if !due || next >= REV_BAND_HALF {
            return Ok(None);
        }
        let again = match above {
            Some(_) => self.again(conn)? + 1,
            None => 0,
        };
        meta::set(conn, self.list.again_key(), &again.to_string())?;
        let inside = message::inside(self.list.name(&identity.public_key())?, value);
        let entry = Entry::seal(&self.secret, identity, next, &inside)?.check()?;
        if entries::store(conn, &entry, now)? != Outcome::Stored {
            return Err(PersonError::Held(
                "the store holds a list of this device's at or above that revision".into(),
            ));
        }
        Ok(Some(next))
    }
}

impl HeldList {
    /// How many times in a row the list was written again for a relay's
    /// answer of another.
    fn again(&self, conn: &Connection) -> Result<usize, PersonError> {
        Ok(meta::get(conn, self.list.again_key())?
            .and_then(|again| again.parse().ok())
            .unwrap_or(0))
    }

    /// Whether a relay's answer that it holds another list of the device's
    /// at `answered` is one the list is written again for (decision
    /// 2026-10-09 §2.4, decision 2026-10-25, rules 1 and 2): it names the
    /// revision of the list held, and the list has been written again so
    /// fewer than three times in a row (`AGENT_MESSAGE_SENDS_MAX`).
    pub(crate) fn takes_answer(
        &self,
        conn: &Connection,
        answered: u64,
    ) -> Result<bool, PersonError> {
        Ok(self.rev() == answered && self.again(conn)? + 1 < AGENT_MESSAGE_SENDS_MAX)
    }
}

/// Whether the device may write a list in the messages channel now: it
/// has fetched the channel since the node started, stands applied, and has
/// sync on (decision 2026-10-09 §2.4).
pub(crate) fn may_write(conn: &Connection, fetched: bool) -> Result<bool, PersonError> {
    Ok(fetched
        && stands(conn)? == Stands::Applied
        && meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_some())
}

/// Write the device's list of what a person read on it, at `now`, where it
/// is due (decision 2026-10-25, rule 1): its table of a person's reads
/// holds an ID that the list of its own in its store lacks. Never before
/// the first fetch (`fetched`), nor where the device does not stand
/// applied or has sync off. Returns the revision written, where one was.
/// One transaction.
pub fn write_person_list(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
) -> Result<Option<u64>, PersonError> {
    in_one(conn, || {
        person_list_written(conn, identity, now, fetched, None)
    })
}

/// [`write_person_list`], in the caller's write; with `above`, a relay
/// answered that it holds another list of the device's at that revision.
pub(crate) fn person_list_written(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
    above: Option<u64>,
) -> Result<Option<u64>, PersonError> {
    if !may_write(conn, fetched)? {
        return Ok(None);
    }
    let held = HeldList::of(conn, &identity.public_key(), PersonList::Reads)?;
    // A list of its own that does not read is a list of no IDs: the next
    // goes above it all the same.
    let listed: HashSet<held::Id> = held
        .held
        .as_ref()
        .and_then(|(_, value)| value.as_ref())
        .and_then(|value| PersonReads::from_value(value).ok())
        .map(|list| list.ids.into_iter().collect())
        .unwrap_or_default();
    let ids = kept(held::person_ids_to_list(conn))?;
    let changed = ids.iter().any(|id| !listed.contains(id));
    let value = PersonReads { ids }
        .to_value()
        .map_err(|e| PersonError::Held(format!("a list of a person's reads: {e}")))?;
    held.write(conn, identity, now, above, changed, value)
}

/// The reader took `ids`, the list of a person's reads of the device whose
/// key is `signer`, which the store kept over what it held (decision
/// 2026-10-25, rule 1), in the door's write. Another key's IDs are each
/// added to what is kept of it, and nothing is taken away. The device's
/// own, `own`, is one a relay handed back from its later life: each ID
/// whose message it holds is added to its own table, and the rest are kept
/// under its own key.
pub(crate) fn person_list_taken(
    conn: &Connection,
    own: &[u8; 32],
    signer: &[u8; 32],
    ids: &[held::Id],
    now: i64,
) -> Result<(), PersonError> {
    if signer != own {
        return kept(held::keep_person_list(conn, signer, ids, now));
    }
    let mut not_held = Vec::new();
    // The oldest first, so that the newest of the list is the newest here.
    for id in ids.iter().rev() {
        match kept(held::holds_message(conn, id))? {
            true => {
                kept(held::mark_read_by_a_person(conn, id))?;
            }
            false => not_held.push(*id),
        }
    }
    not_held.reverse();
    kept(held::keep_person_list(conn, own, &not_held, now))
}

/// Where a person read a message, as it is worked out now (decision
/// 2026-10-25, rule 1.3): on this device, or by the lists of the keys that
/// count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersonReadOn {
    pub here: bool,
    /// The keys that count whose lists say so, in order of key.
    pub devices: Vec<[u8; 32]>,
}

impl PersonReadOn {
    /// Whether it is read by a person.
    pub fn is_read(&self) -> bool {
        self.here || !self.devices.is_empty()
    }
}

/// What a person read, read with two statements for every message at once
/// (decision 2026-10-25, rule 1.3): the device's own table, and the lists
/// of the keys that count by `counting`, which the caller works out once.
pub struct PersonRead {
    here: HashSet<held::Id>,
    lists: HashMap<held::Id, Vec<[u8; 32]>>,
}

/// What a person read, now.
pub fn person_read_now(conn: &Connection, counting: &Counting) -> Result<PersonRead, PersonError> {
    let read = kept(held::person_reads(conn))?;
    let mut lists: HashMap<held::Id, Vec<[u8; 32]>> = HashMap::new();
    for (key, id) in read.lists {
        if counting.counts(&key) {
            lists.entry(id).or_default().push(key);
        }
    }
    for keys in lists.values_mut() {
        keys.sort();
    }
    Ok(PersonRead {
        here: read.here.into_iter().collect(),
        lists,
    })
}

impl PersonRead {
    /// Where a person read message `id`.
    pub fn on(&self, id: &held::Id) -> PersonReadOn {
        PersonReadOn {
            here: self.here.contains(id),
            devices: self.lists.get(id).cloned().unwrap_or_default(),
        }
    }

    /// Whether a person read message `id`, here or on a device that counts.
    pub fn is_read(&self, id: &held::Id) -> bool {
        self.here.contains(id) || self.lists.contains_key(id)
    }
}

// ── What a pass found last (issue #221) ──────────────────────────────

/// What a device's passes found last of what decides whether its list of
/// a person's reads, its list of bounds (decision 2026-10-25, rules 1 and
/// 2), and its list of shared marks (decision 2026-10-10 §6.1), is due,
/// kept in memory between passes. Each pass asks whether
/// either list is due, at each relay; asked in full, that opens the list
/// the store holds and checks the statement, under the lock, each time.
/// What decides it is read here with a few reads of the store and nothing
/// checked or opened: where it is what it was at a pass that wrote and
/// changed nothing, the list is not due, and nothing more is done. A
/// change to any of it, and a bound reaching the time it leaves the list,
/// asks in full again, once.
#[derive(Debug, Default)]
pub struct ListsSeen {
    /// The statement the device stands applied under, and the messages
    /// channel and the two lists' slots under it.
    under: Option<Under>,
    reads: Option<Inputs>,
    bounds: Option<Inputs>,
    shared_reads: Option<Inputs>,
}

#[derive(Debug)]
struct Under {
    statement: Vec<u8>,
    channel: [u8; 32],
    reads_slot: [u8; 32],
    bounds_slot: [u8; 32],
    shared_reads_slot: [u8; 32],
}

/// What decides whether one of the lists is due, but the time.
#[derive(Debug, PartialEq, Eq)]
struct Inputs {
    /// The statement applied, as the store holds it: the generation, the
    /// secret and the keys of the statement.
    statement: Vec<u8>,
    sync: Option<String>,
    fetched: bool,
    /// The revision of the device's own list in its slot, where the store
    /// holds one: it replaces a list only with a higher one.
    rev: Option<u64>,
    /// The rows that the list is made from, as the store reads them.
    rows: Rows,
    /// The time at which a pass asks in full again whatever else holds:
    /// the first at which one of the device's own bounds leaves the list.
    until: i64,
}

#[derive(Debug, PartialEq, Eq)]
enum Rows {
    Reads(Vec<held::Id>),
    Bounds {
        rows: Vec<held::BoundRow>,
        additions: Vec<cordelia_storage::person::KeptAddition>,
    },
    /// The marks of the device's table of shared marks that a list holds.
    SharedReads(Vec<Mark>),
}

impl ListsSeen {
    /// The messages channel and the lists' slots under `statement`: worked
    /// out once for each statement applied.
    fn under(
        &mut self,
        conn: &Connection,
        own: &[u8; 32],
        statement: &[u8],
    ) -> Result<&Under, PersonError> {
        if self
            .under
            .as_ref()
            .is_none_or(|under| under.statement != statement)
        {
            let standing = Standing::to_write(conn)?;
            let secret = derive::messages_secret(&standing.secret)?;
            let slot_key = derive::slot_key(&secret)?;
            self.under = Some(Under {
                statement: statement.to_vec(),
                channel: derive::channel_id(&secret)?,
                reads_slot: slot_id(&slot_key, &person_name(own)?),
                bounds_slot: slot_id(&slot_key, &hold_name(own)?),
                shared_reads_slot: slot_id(&slot_key, &sread_name(own)?),
            });
        }
        match &self.under {
            Some(under) => Ok(under),
            None => unreachable!("set just above"),
        }
    }

    /// What decides whether `list` is due now, read from the store, with
    /// whether the messages channel was fetched since the node started by
    /// `fetched` of its ID. `None` where the device does not stand applied:
    /// then nothing is due, and the caller asks in full, which says so at
    /// no cost.
    fn inputs(
        &mut self,
        conn: &Connection,
        own: &[u8; 32],
        list: PersonList,
        fetched: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<Option<Inputs>, PersonError> {
        let Some(person) = cordelia_storage::person::person(conn)? else {
            return Ok(None);
        };
        if person.state != cordelia_storage::person::State::Applied {
            return Ok(None);
        }
        let under = self.under(conn, own, &person.statement)?;
        let (channel, slot) = match list {
            PersonList::Reads => (under.channel, under.reads_slot),
            PersonList::Bounds => (under.channel, under.bounds_slot),
            PersonList::SharedReads => (under.channel, under.shared_reads_slot),
        };
        let rev = entries::author_cost(conn, &channel, &slot, own)?.map(|(rev, _)| rev);
        let (rows, until) = match list {
            PersonList::Reads => (Rows::Reads(kept(held::person_ids_to_list(conn))?), i64::MAX),
            PersonList::Bounds => {
                let rows = kept(held::bounds(conn))?;
                let until = rows
                    .iter()
                    .filter(|row| row.key == *own)
                    .map(crate::bounds::listed_until)
                    .min()
                    .unwrap_or(i64::MAX);
                let additions = cordelia_storage::person::additions(conn)?;
                (Rows::Bounds { rows, additions }, until)
            }
            PersonList::SharedReads => (
                Rows::SharedReads(
                    cordelia_storage::shared_messages::marks_to_list(conn)
                        .map_err(PersonError::Storage)?,
                ),
                i64::MAX,
            ),
        };
        Ok(Some(Inputs {
            statement: person.statement,
            sync: meta::get(conn, meta::SYNC_CLAUDE_DIR)?,
            fetched: fetched(&channel),
            rev,
            rows,
            until,
        }))
    }

    fn seen(&mut self, list: PersonList) -> &mut Option<Inputs> {
        match list {
            PersonList::Reads => &mut self.reads,
            PersonList::Bounds => &mut self.bounds,
            PersonList::SharedReads => &mut self.shared_reads,
        }
    }

    /// Ask whether `list` is due by `write`, given `fetched` of the
    /// messages channel's ID, where what decides it is not what it was at
    /// a pass that changed nothing, and before the time it is asked again
    /// at. Returns what `write` returned, or `None` where it was not
    /// asked. Its answer is kept where `write` changed nothing in the
    /// store; anything else is asked in full at the next pass.
    pub(crate) fn where_changed(
        &mut self,
        conn: &Connection,
        own: &[u8; 32],
        list: PersonList,
        now: i64,
        fetched: impl FnOnce(&[u8; 32]) -> bool,
        write: impl FnOnce(bool) -> Result<Option<u64>, PersonError>,
    ) -> Result<Option<u64>, PersonError> {
        let inputs = match self.inputs(conn, own, list, fetched) {
            Ok(inputs) => inputs,
            Err(e) => {
                *self.seen(list) = None;
                return Err(e);
            }
        };
        let Some(inputs) = inputs else {
            *self.seen(list) = None;
            return write(false);
        };
        if now < inputs.until && self.seen(list).as_ref() == Some(&inputs) {
            return Ok(None);
        }
        let before = conn.total_changes();
        let written = write(inputs.fetched);
        let unchanged = matches!(written, Ok(None)) && conn.total_changes() == before;
        *self.seen(list) = unchanged.then_some(inputs);
        written
    }
}

/// [`write_person_list`], as each pass asks it: where what decides it is
/// what it was at a pass that wrote nothing, nothing is opened or checked
/// ([`ListsSeen`]). `fetched` says, of the messages channel's ID, whether
/// it was fetched since the node started.
pub fn write_person_list_where_changed(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: impl FnOnce(&[u8; 32]) -> bool,
    seen: &mut ListsSeen,
) -> Result<Option<u64>, PersonError> {
    seen.where_changed(
        conn,
        &identity.public_key(),
        PersonList::Reads,
        now,
        fetched,
        |fetched| write_person_list(conn, identity, now, fetched),
    )
}

/// What the store answered, with its error as the device's.
fn kept<T>(answer: Result<T, StorageError>) -> Result<T, PersonError> {
    answer.map_err(|e| PersonError::Storage(CordeliaError::Storage(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_core::protocol::{AGENT_MESSAGE_KEPT_DAYS, AGENT_MESSAGES_PER_FOLDER_PER_HOUR};
    use cordelia_crypto::entry::CheckedEntry;
    use cordelia_crypto::message::{To, read_mark};
    use cordelia_storage::entries::StoredEntry;

    use crate::sender::{Address, At, Request, no_reply, send};
    use crate::several::Several;
    use crate::take::{Taken, take};

    const DAY: i64 = 24 * 60 * 60;

    /// `count` devices of one person, each with sync on and saying that it
    /// syncs `notes`, `work` and `~`, each having been given what every
    /// other holds.
    fn devices(count: u16) -> Several {
        let mut s = Several::of_one_person(count);
        for n in 0..usize::from(count) {
            meta::set(&s[n].conn, meta::SYNC_CLAUDE_DIR, "/home/laptop/.claude").unwrap();
            for name in ["notes", "work", "~"] {
                crate::names::say(&s[n].conn, &s[n].identity, name, s.now).unwrap();
            }
        }
        let all: Vec<usize> = (0..usize::from(count)).collect();
        s.meet(&all);
        s
    }

    /// Device `n` sends `body` from the agent of `from` to that of `to`,
    /// or to every name where `to` is `*`, at `now`; a person there then
    /// reads everything it holds, so that no pair is held. Its ID.
    fn sends(s: &Several, n: usize, from: &str, to: &str, body: &str, now: i64) -> Id {
        let at = At {
            now,
            fetched: true,
            no_place: false,
            mapped: true,
            per_folder_per_hour: AGENT_MESSAGES_PER_FOLDER_PER_HOUR,
            shared_fetched: false,
            shared_reached: false,
        };
        let request = Request {
            from: from.into(),
            address: Address::Own(match to {
                "*" => To::All,
                name => To::Name(name.into()),
            }),
            asks: false,
            link: None,
            body: body.into(),
            thread: [0; 16],
            answers: [0; 16],
        };
        let sent = send(&s[n].conn, &s[n].identity, &at, &request, no_reply).unwrap();
        s[n].conn
            .execute(
                "INSERT OR IGNORE INTO message_read_by_a_person (id) SELECT id FROM message_index",
                [],
            )
            .unwrap();
        sent.id
    }

    /// Device `n` gives places at `now`, as a show does.
    fn shows(s: &Several, n: usize, now: i64) {
        held::give_places(&s[n].conn, &s.key(n), now).unwrap();
    }

    /// The agent of `name` on device `n` reads `id` at `now`, the channel
    /// fetched where `fetched`.
    fn reads(s: &Several, n: usize, name: &str, id: &Id, now: i64, fetched: bool) -> Marked {
        shows(s, n, now);
        read_here(&s[n].conn, &s[n].identity, name, id, now, fetched).unwrap()
    }

    /// The bodies of what is unread by the agent of `name` on device `n`
    /// at `now`, once places are given.
    fn unread_on(s: &Several, n: usize, name: &str, now: i64) -> Vec<String> {
        shows(s, n, now);
        let counting = who_counts(&s[n].conn).unwrap();
        unread(&s[n].conn, &s[n].identity, name, now, &counting)
            .unwrap()
            .into_iter()
            .map(|shown| shown.body)
            .collect()
    }

    /// The secret of the messages channel device `n` stands applied under.
    fn messages_secret(s: &Several, n: usize) -> [u8; 32] {
        derive::messages_secret(&s[n].secret()).unwrap()
    }

    /// The list of its own that device `n` holds in the messages channel
    /// it stands applied under, as its entry.
    fn own_list(s: &Several, n: usize) -> Option<StoredEntry> {
        let secret = messages_secret(s, n);
        let slot = slot_id(
            &derive::slot_key(&secret).unwrap(),
            &read_name(&s.key(n)).unwrap(),
        );
        let channel = derive::channel_id(&secret).unwrap();
        entries::author_entry(&s[n].conn, &channel, &slot, &s.key(n)).unwrap()
    }

    /// That list's revision and marks.
    fn listed(s: &Several, n: usize) -> Option<(u64, Vec<Mark>)> {
        let entry = own_list(s, n)?.entry.check().unwrap();
        let inside = entry.open(&messages_secret(s, n)).unwrap();
        Some((
            entry.rev,
            ReadMarks::from_value(&inside.value).unwrap().marks,
        ))
    }

    fn checked(stored: &StoredEntry) -> CheckedEntry {
        stored.entry.clone().check().unwrap()
    }

    /// The marks of device `n`'s own table, newest first, each with
    /// whether it is kept with its ID.
    fn table(s: &Several, n: usize) -> Vec<(Mark, bool)> {
        s[n].conn
            .prepare("SELECT mark, id IS NOT NULL FROM message_read_here ORDER BY seq DESC")
            .unwrap()
            .query_map([], |row| {
                let mark: Vec<u8> = row.get(0)?;
                Ok((mark.try_into().unwrap(), row.get(1)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// The agent of a folder marks only a message addressed to it, and not
    /// one it sent from this device (decision 2026-10-09 §4.1, §7.2): a
    /// message to its name and one to every name are marked, as is one to
    /// every name that another agent of the device sent; one to another
    /// name, and its own, are not.
    #[test]
    fn a_mark_is_made_only_for_a_message_to_the_folders_agent() {
        let mut s = devices(2);
        let t = s.now;
        let to_it = sends(&s, 0, "~", "notes", "to notes", t);
        let to_all = sends(&s, 0, "~", "*", "to all", t);
        let to_work = sends(&s, 0, "~", "work", "to work", t);
        let same_name = sends(&s, 0, "notes", "*", "from notes elsewhere", t);
        s.pass(0, 1);
        let own = sends(&s, 1, "notes", "*", "its own", t);
        let others = sends(&s, 1, "work", "*", "another's", t);
        for (id, marked) in [
            (to_it, true),
            (to_all, true),
            (to_work, false),
            (same_name, true),
            (own, false),
            (others, true),
        ] {
            assert_eq!(reads(&s, 1, "notes", &id, t, true).marked, marked);
            assert_eq!(
                read_on(&s[1].conn, &id, "notes", &who_counts(&s[1].conn).unwrap())
                    .unwrap()
                    .here,
                marked
            );
        }
        // A message that is not shown yet is not marked.
        let later = sends(&s, 0, "~", "notes", "later", t + 1);
        s.pass(0, 1);
        let marked = read_here(&s[1].conn, &s[1].identity, "notes", &later, t + 1, true);
        assert_eq!(marked.unwrap(), Marked::default());
    }

    /// The marks read at once say what `read_on` says of each message and
    /// name (decision 2026-10-09 §7.2): a mark of the device's own table
    /// counts, with its ID and name or as a bare hash, and a list's mark
    /// counts only where its key counts now.
    #[test]
    fn the_marks_read_at_once_say_what_read_on_says() {
        let s = devices(2);
        let t = s.now;
        let conn = &s[0].conn;
        let marked = sends(&s, 0, "~", "notes", "marked here", t);
        held::mark_read(conn, &marked, "notes", t).unwrap();
        let bare = [0xb1; 16];
        conn.execute(
            "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
             VALUES (?1, 1000, ?2, ?2)",
            rusqlite::params![&read_mark(&bare, "notes")[..], t],
        )
        .unwrap();
        let listed = [0xc1; 16];
        held::keep_list(conn, &s.key(1), &[read_mark(&listed, "notes")]).unwrap();
        let not_counted = [0xd1; 16];
        held::keep_list(conn, &[0x99; 32], &[read_mark(&not_counted, "notes")]).unwrap();
        let counting = who_counts(conn).unwrap();
        let now = read_now(conn, &counting).unwrap();
        for (id, read) in [
            (marked, true),
            (bare, true),
            (listed, true),
            (not_counted, false),
            ([0xe1; 16], false),
        ] {
            for name in ["notes", "work"] {
                let one = read_on(conn, &id, name, &counting).unwrap().is_read();
                assert_eq!(one, read && name == "notes", "{id:?} {name}");
                assert_eq!(now.is_read(&id, name), one, "{id:?} {name}");
            }
        }
    }

    /// A list that arrives before the message it marks loses nothing
    /// (decision 2026-10-09 §7.2, D7): the desktop takes the laptop's list,
    /// then the message, which is read there by the laptop's word; and
    /// read nowhere for another name.
    #[test]
    fn a_list_that_arrives_before_the_message_it_marks_loses_nothing() {
        let mut s = devices(3);
        let t = s.now;
        let id = sends(&s, 0, "~", "*", "for every agent", t);
        let message = s[0]
            .stored_in(&messages_secret(&s, 0))
            .into_iter()
            .find(|entry| entry.author == s.key(0))
            .unwrap();
        s.pass(0, 1);
        reads(&s, 1, "notes", &id, t, true);
        let list = checked(&own_list(&s, 1).unwrap());
        assert!(matches!(
            take(&s[2].conn, &s[2].identity, &list, t).unwrap(),
            Taken::Own { .. }
        ));
        assert_eq!(unread_on(&s, 2, "notes", t), Vec::<String>::new());
        take(&s[2].conn, &s[2].identity, &message, t).unwrap();
        assert_eq!(unread_on(&s, 2, "notes", t), Vec::<String>::new());
        assert_eq!(unread_on(&s, 2, "work", t), ["for every agent"]);
        assert_eq!(
            read_on(&s[2].conn, &id, "notes", &who_counts(&s[2].conn).unwrap()).unwrap(),
            ReadOn {
                here: false,
                devices: vec![s.key(1)]
            }
        );
    }

    /// Another device's list is kept only where the store keeps it, each
    /// mark once, in place of the one before (decision 2026-10-09 §7.2): a
    /// list below the one held, handed again, changes nothing.
    #[test]
    fn a_list_is_kept_only_where_the_store_keeps_it() {
        let mut s = devices(3);
        let t = s.now;
        let first = sends(&s, 0, "~", "notes", "first", t);
        let second = sends(&s, 0, "~", "notes", "second", t);
        s.pass(0, 1);
        s.pass(0, 2);
        reads(&s, 1, "notes", &first, t, true);
        let older = checked(&own_list(&s, 1).unwrap());
        reads(&s, 1, "notes", &second, t, true);
        let newer = checked(&own_list(&s, 1).unwrap());
        take(&s[2].conn, &s[2].identity, &newer, t).unwrap();
        assert_eq!(unread_on(&s, 2, "notes", t), Vec::<String>::new());
        take(&s[2].conn, &s[2].identity, &older, t).unwrap();
        assert_eq!(unread_on(&s, 2, "notes", t), Vec::<String>::new());
        // Neither is for the agent of `work`.
        assert_eq!(unread_on(&s, 2, "work", t), Vec::<String>::new());

        // A newer list that holds one mark twice, and not the other.
        let name = read_name(&s.key(1)).unwrap();
        let mark = read_mark(&first, "notes");
        let value = ReadMarks {
            marks: vec![mark, mark],
        }
        .to_value()
        .unwrap();
        let twice = Entry::seal(
            &messages_secret(&s, 1),
            &s[1].identity,
            newer.rev + 1,
            &message::inside(name, value),
        )
        .unwrap()
        .check()
        .unwrap();
        take(&s[2].conn, &s[2].identity, &twice, t).unwrap();
        assert_eq!(unread_on(&s, 2, "notes", t), ["second"]);
        let rows: i64 = s[2]
            .conn
            .query_row("SELECT COUNT(*) FROM message_lists", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    /// A device writes no list before its first fetch of the messages
    /// channel since it started (decision 2026-10-09 §2.3, §2.4, D7): an
    /// agent reads before it, and the mark waits in the table; the first
    /// list after the fetch holds it. Nor where sync is off.
    #[test]
    fn a_device_writes_no_list_before_its_first_fetch() {
        let mut s = devices(2);
        let t = s.now;
        let id = sends(&s, 0, "~", "notes", "read early", t);
        s.pass(0, 1);
        let marked = reads(&s, 1, "notes", &id, t, false);
        assert_eq!(
            marked,
            Marked {
                marked: true,
                list: None
            }
        );
        assert!(own_list(&s, 1).is_none());
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, false).unwrap(),
            None
        );
        assert!(own_list(&s, 1).is_none());

        meta::remove(&s[1].conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, true).unwrap(),
            None
        );
        meta::set(&s[1].conn, meta::SYNC_CLAUDE_DIR, "/home/laptop/.claude").unwrap();
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, true).unwrap(),
            Some(1)
        );
        assert_eq!(listed(&s, 1), Some((1, vec![read_mark(&id, "notes")])));
        // Nothing new is marked: nothing is written again.
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, true).unwrap(),
            None
        );
    }

    /// The laptop's agents read ten messages: nine to `notes`, by its
    /// agent, and one to every name, by the agent of `work`. Its store is
    /// then restored to before those reads. The messages, the tenth, to
    /// `notes`, unread, and its later list.
    fn restored_after_ten_reads(s: &mut Several) -> (Vec<Id>, CheckedEntry) {
        let t = s.now;
        let mut ids: Vec<Id> = (0..10)
            .map(|k| sends(s, 0, "~", "notes", &format!("number {k}"), t))
            .collect();
        ids.push(sends(s, 0, "~", "*", "to every agent", t));
        s.pass(0, 1);
        for id in &ids[..9] {
            reads(s, 1, "notes", id, t, true);
        }
        reads(s, 1, "work", &ids[10], t, true);
        let later = checked(&own_list(s, 1).unwrap());
        assert_eq!(later.rev, 10);
        s[1].conn
            .execute_batch("DELETE FROM message_read_here")
            .unwrap();
        s[1].conn
            .execute(
                "DELETE FROM entries WHERE author = ?1 AND slot = ?2",
                rusqlite::params![&s.key(1)[..], &later.slot[..]],
            )
            .unwrap();
        (ids, later)
    }

    /// The marks of the ten reads of [`restored_after_ten_reads`], newest
    /// first.
    fn ten_read(ids: &[Id]) -> Vec<Mark> {
        let mut ten = vec![read_mark(&ids[10], "work")];
        ten.extend(ids[..9].iter().rev().map(|id| read_mark(id, "notes")));
        ten
    }

    /// A store restored to before ten reads takes its own later list from
    /// a relay, and merges it into its table before it writes the next
    /// (decision 2026-10-09 §2.4, §7.2, D7): the next list holds the ten
    /// marks and the new one, at a revision above the relay's, and its
    /// table holds the ID and the name of each of the ten, found by the
    /// name each message is to, or by a name mapped here for one to every
    /// name. Handed the same list again, which its store does not keep, it
    /// merges nothing.
    #[test]
    fn a_device_merges_its_own_list_from_a_relay_before_it_writes_the_next() {
        let mut s = devices(2);
        let t = s.now;
        let (ids, later) = restored_after_ten_reads(&mut s);
        let mapped = serde_json::json!([{ "folder": "/home/laptop/work", "name": "work" }]);
        meta::set(&s[1].conn, meta::SYNC_CLAUDE_MAPPINGS, &mapped.to_string()).unwrap();
        assert!(table(&s, 1).is_empty());
        take(&s[1].conn, &s[1].identity, &later, t).unwrap();
        let ten: Vec<(Mark, bool)> = ten_read(&ids)
            .into_iter()
            .map(|mark| (mark, true))
            .collect();
        assert_eq!(table(&s, 1), ten);

        let marked = reads(&s, 1, "notes", &ids[9], t, true);
        assert_eq!(marked.list, Some(11));
        let mut eleven = vec![read_mark(&ids[9], "notes")];
        eleven.extend(ten_read(&ids));
        assert_eq!(listed(&s, 1), Some((11, eleven)));

        let before = table(&s, 1);
        take(&s[1].conn, &s[1].identity, &later, t).unwrap();
        assert_eq!(table(&s, 1), before);
    }

    /// A restored store that reads before its first fetch writes no list
    /// until it has fetched (decision 2026-10-09 §2.4, §11): the mark
    /// waits; the fetch hands back its own later list, which is merged; and
    /// the list it then writes holds the new mark first and the later
    /// list's after, above the later list.
    #[test]
    fn a_restored_store_that_reads_before_its_first_fetch_writes_no_list_until_it_has_fetched() {
        let mut s = devices(2);
        let t = s.now;
        let (ids, later) = restored_after_ten_reads(&mut s);
        assert_eq!(reads(&s, 1, "notes", &ids[9], t, false).list, None);
        assert!(own_list(&s, 1).is_none());
        take(&s[1].conn, &s[1].identity, &later, t).unwrap();
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, false).unwrap(),
            None
        );
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, true).unwrap(),
            Some(11)
        );
        let mut eleven = vec![read_mark(&ids[9], "notes")];
        eleven.extend(ten_read(&ids));
        assert_eq!(listed(&s, 1), Some((11, eleven)));
    }

    /// A list stays in the bottom half of band 0 (decision 2026-10-09
    /// §2.3, §2.4): where a holder of the device's key wrote its list at the
    /// top of it, no list is written above.
    #[test]
    fn no_list_is_written_above_the_bottom_half_of_band_0() {
        for (top, written) in [(REV_BAND_HALF - 2, true), (REV_BAND_HALF - 1, false)] {
            let mut s = devices(2);
            let t = s.now;
            let id = sends(&s, 0, "~", "notes", "read", t);
            s.pass(0, 1);
            let value = ReadMarks::default().to_value().unwrap();
            let entry = Entry::seal(
                &messages_secret(&s, 1),
                &s[1].identity,
                top,
                &message::inside(read_name(&s.key(1)).unwrap(), value),
            )
            .unwrap()
            .check()
            .unwrap();
            entries::store(&s[1].conn, &entry, t).unwrap();
            let marked = reads(&s, 1, "notes", &id, t, true);
            assert_eq!(marked.list, written.then_some(top + 1), "{top}");
        }
    }

    /// A relay that answers that it holds another list of the device's at
    /// the revision pushed has the list written again above it; an answer
    /// that it holds a later one writes nothing, and so does any answer
    /// before the first fetch (decision 2026-10-09 §2.4).
    #[test]
    fn a_list_answered_another_is_written_again_above_it() {
        let mut s = devices(2);
        let t = s.now;
        let id = sends(&s, 0, "~", "notes", "read", t);
        s.pass(0, 1);
        reads(&s, 1, "notes", &id, t, true);
        sends(&s, 1, "work", "*", "its own", t);
        let pushed = own_list(&s, 1).unwrap().entry;
        let own = crate::at_relays::channels(&s[1].conn, &s[1].identity).unwrap();
        let channel = own.iter().find(|own| own.kind == Kind::Messages).unwrap();
        let answer = |answer: Pushed, fetched: bool| {
            answered(
                &s[1].conn,
                &s[1].identity,
                channel,
                std::slice::from_ref(&pushed),
                &[answer],
                t,
                fetched,
            )
            .unwrap()
        };
        // Another to a message, or in another channel, writes no list.
        let message = s[1]
            .stored_in(&messages_secret(&s, 1))
            .into_iter()
            .find(|entry| entry.author == s.key(1) && entry.rev == 2);
        let message = message.unwrap().into_entry();
        let another = |channel: &Own, entry: &Entry| {
            answered(
                &s[1].conn,
                &s[1].identity,
                channel,
                std::slice::from_ref(entry),
                &[Pushed::HoldsAnother],
                t,
                true,
            )
            .unwrap()
        };
        let personal = own.iter().find(|own| own.kind == Kind::Personal).unwrap();
        assert_eq!(another(personal, &pushed), None);
        // Answers that are not one for each entry say nothing.
        let two = [pushed.clone(), message.clone()];
        let short = answered(
            &s[1].conn,
            &s[1].identity,
            channel,
            &two,
            &[Pushed::HoldsAnother],
            t,
            true,
        );
        assert_eq!(short.unwrap(), None);
        assert_eq!(answer(Pushed::HoldsLater, true), None);
        assert_eq!(answer(Pushed::Holds, true), None);
        assert_eq!(answer(Pushed::HoldsAnother, false), None);
        assert_eq!(listed(&s, 1).unwrap().0, 1);
        assert_eq!(answer(Pushed::HoldsAnother, true), Some(2));
        assert_eq!(listed(&s, 1), Some((2, vec![read_mark(&id, "notes")])));
        // Another to the device's message at the list's revision writes no
        // list: it is not the list's slot.
        assert_eq!(message.rev, 2);
        assert_eq!(another(channel, &message), None);
        // Answered so again for the list below the one held: nothing.
        assert_eq!(answer(Pushed::HoldsAnother, true), None);
    }

    /// A relay that answers another to every list pushed makes the device
    /// write a list's marks under at most four revisions (decision
    /// 2026-10-09 §2.4, `AGENT_MESSAGE_SENDS_MAX`, as a message's numbers):
    /// three lists written again, and no fourth, until a list is written
    /// for a mark the device lacked, which starts the count again.
    #[test]
    fn a_relay_that_answers_falsely_makes_a_list_go_under_at_most_four_revisions() {
        let mut s = devices(2);
        let t = s.now;
        let first = sends(&s, 0, "~", "notes", "first", t);
        let second = sends(&s, 0, "~", "notes", "second", t);
        s.pass(0, 1);
        assert_eq!(reads(&s, 1, "notes", &first, t, true).list, Some(1));
        let own = crate::at_relays::channels(&s[1].conn, &s[1].identity).unwrap();
        let channel = own.iter().find(|own| own.kind == Kind::Messages).unwrap();
        let answer_newest = |s: &Several| {
            let newest = own_list(s, 1).unwrap().entry;
            answered(
                &s[1].conn,
                &s[1].identity,
                channel,
                std::slice::from_ref(&newest),
                &[Pushed::HoldsAnother],
                t,
                true,
            )
            .unwrap()
        };
        let written: Vec<Option<u64>> = (0..4).map(|_| answer_newest(&s)).collect();
        assert_eq!(written, [Some(2), Some(3), Some(4), None]);
        assert_eq!(listed(&s, 1).unwrap().0, 4);

        assert_eq!(reads(&s, 1, "notes", &second, t, true).list, Some(5));
        let written: Vec<Option<u64>> = (0..4).map(|_| answer_newest(&s)).collect();
        assert_eq!(written, [Some(6), Some(7), Some(8), None]);
    }

    /// A list counts only where its signer is the key its slot is named for
    /// (decision 2026-10-09 §2.2, §2.4, property 3): the store keeps one
    /// entry for each author in a slot, so another device of the person can
    /// sign a list in `read/<this device's key>`. This device takes it
    /// through the door and keeps nothing of it: its table, the lists it
    /// keeps and what is unread are as they were, and it is counted as no
    /// message of its signer.
    #[test]
    fn a_list_in_this_devices_slot_signed_by_another_key_is_no_list() {
        let mut s = devices(2);
        let t = s.now;
        let id = sends(&s, 1, "~", "notes", "for the laptop", t);
        s.pass(1, 0);
        let unread_before = unread_on(&s, 0, "notes", t);
        assert_eq!(unread_before, ["for the laptop"]);
        let value = ReadMarks {
            marks: vec![read_mark(&id, "notes")],
        }
        .to_value()
        .unwrap();
        let entry = Entry::seal(
            &messages_secret(&s, 1),
            &s[1].identity,
            1,
            &message::inside(read_name(&s.key(0)).unwrap(), value),
        )
        .unwrap()
        .check()
        .unwrap();
        let rows = |s: &Several, table: &str| -> i64 {
            s[0].conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        assert!(matches!(
            take(&s[0].conn, &s[0].identity, &entry, t).unwrap(),
            Taken::Own { .. }
        ));
        assert_eq!(rows(&s, "message_read_here"), 0);
        assert_eq!(rows(&s, "message_lists"), 0);
        assert_eq!(unread_on(&s, 0, "notes", t), unread_before);
        let generation = held::generation_of(
            &s[0].conn,
            &derive::channel_id(&messages_secret(&s, 0)).unwrap(),
        )
        .unwrap()
        .unwrap();
        let signer = held::signer(&s[0].conn, &s.key(1), generation).unwrap();
        assert_eq!(signer.unwrap().not_messages, 1);
    }

    /// After a statement, a device's first list in the new generation is
    /// written from its table once it has fetched the new channel, and
    /// holds the newest marks of its table (decision 2026-10-09 §2.4,
    /// §9.1, F8): the laptop's agent of `notes` reads three messages;
    /// after a renewal the desktop keeps the laptop's list until the new
    /// one replaces it, and neither announces nor counts the three.
    #[test]
    fn the_first_list_after_a_statement_holds_the_marks_of_what_is_still_shown() {
        let mut s = devices(3);
        let t = s.now;
        let ids: Vec<Id> = (0..3)
            .map(|k| sends(&s, 0, "~", "notes", &format!("number {k}"), t))
            .collect();
        s.pass(0, 1);
        s.pass(0, 2);
        for id in &ids {
            reads(&s, 1, "notes", id, t, true);
        }
        s.pass(1, 2);
        assert_eq!(unread_on(&s, 2, "notes", t), Vec::<String>::new());

        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        assert!(own_list(&s, 1).is_none(), "the new channel holds nothing");
        // The desktop keeps the laptop's list across the statement.
        assert_eq!(unread_on(&s, 2, "notes", t), Vec::<String>::new());
        s[2].conn.execute("DELETE FROM message_lists", []).unwrap();
        assert_eq!(unread_on(&s, 2, "notes", t).len(), 3);

        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, false).unwrap(),
            None
        );
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, true).unwrap(),
            Some(1)
        );
        let marks: Vec<Mark> = ids.iter().rev().map(|id| read_mark(id, "notes")).collect();
        assert_eq!(listed(&s, 1), Some((1, marks)));
        s.pass(1, 2);
        assert_eq!(unread_on(&s, 2, "notes", t), Vec::<String>::new());
    }

    /// A mark stays in the table as a bare hash when its message's row
    /// goes, and is in the next list (decision 2026-10-09 §7.2, F8): the
    /// row goes at the hourly task once its 30 days are up, the mark
    /// stays, and goes 30 days after it became bare, as a merged bare
    /// hash goes 30 days after it was merged.
    #[test]
    fn a_mark_stays_as_a_bare_hash_when_its_message_goes() {
        let mut s = devices(2);
        let t = s.now;
        let id = sends(&s, 0, "~", "notes", "a month", t);
        s.pass(0, 1);
        reads(&s, 1, "notes", &id, t, true);
        held::merge_own_list(&s[1].conn, &[[0xb1; 16]], &[], t + DAY).unwrap();
        let mark = read_mark(&id, "notes");
        let month = i64::from(AGENT_MESSAGE_KEPT_DAYS) * DAY;
        let hourly = |now: i64| {
            crate::reader::hourly(&s[1].conn, &s[1].identity, now, true).unwrap();
        };
        // The merged mark was listed after the one said: it is above it.
        hourly(t + month - 1);
        assert_eq!(table(&s, 1), [([0xb1; 16], false), (mark, true)]);
        hourly(t + month);
        assert_eq!(table(&s, 1), [([0xb1; 16], false), (mark, false)]);
        assert!(
            read_on(&s[1].conn, &id, "notes", &who_counts(&s[1].conn).unwrap())
                .unwrap()
                .here
        );
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t + month, true).unwrap(),
            Some(2)
        );
        assert_eq!(listed(&s, 1), Some((2, vec![[0xb1; 16], mark])));
        hourly(t + DAY + month);
        assert_eq!(table(&s, 1), [(mark, false)]);
        hourly(t + 2 * month - 1);
        assert_eq!(table(&s, 1), [(mark, false)]);
        hourly(t + 2 * month);
        assert!(table(&s, 1).is_empty());
    }

    /// A mark outlasts its message's row on the device that made it
    /// (decision 2026-10-09 §2.4, §7.2): whether a message is shown is each
    /// device's own. The sender's clock is 5 days ahead; the laptop first
    /// holds m1 at t and the desktop at t + 4 days, so the desktop shows it
    /// until t + 34 days. The laptop's agent reads m1, and the desktop
    /// takes its list. At t + 31 days m1 has gone from the laptop's index,
    /// and its agent reads m2: the list it writes still holds m1's mark,
    /// and the desktop's agent is not shown m1 again.
    #[test]
    fn a_mark_outlasts_its_messages_row_on_the_device_that_made_it() {
        let s = devices(3);
        let t = s.now;
        let ahead = 5 * DAY;
        let entry_of = |s: &Several, number: u64| {
            s[0].stored_in(&messages_secret(s, 0))
                .into_iter()
                .find(|entry| {
                    entry.author == s.key(0) && Some(entry.rev) == message::message_rev(number)
                })
                .unwrap()
        };
        let m1 = sends(&s, 0, "~", "notes", "m1", t + ahead);
        let first = entry_of(&s, 1);
        take(&s[1].conn, &s[1].identity, &first, t).unwrap();
        take(&s[2].conn, &s[2].identity, &first, t + 4 * DAY).unwrap();
        assert_eq!(reads(&s, 1, "notes", &m1, t, true).list, Some(1));
        let list = checked(&own_list(&s, 1).unwrap());
        take(&s[2].conn, &s[2].identity, &list, t + 4 * DAY).unwrap();
        assert!(unread_on(&s, 2, "notes", t + 4 * DAY).is_empty());

        let later = t + 31 * DAY;
        crate::reader::hourly(&s[1].conn, &s[1].identity, later, true).unwrap();
        assert!(held::shown(&s[1].conn, later).unwrap().is_empty());
        let m2 = sends(&s, 0, "~", "notes", "m2", later + ahead);
        take(&s[1].conn, &s[1].identity, &entry_of(&s, 2), later).unwrap();
        assert_eq!(reads(&s, 1, "notes", &m2, later, true).list, Some(2));
        let list = checked(&own_list(&s, 1).unwrap());
        take(&s[2].conn, &s[2].identity, &list, later).unwrap();

        let shown: Vec<String> = held::shown(&s[2].conn, later)
            .unwrap()
            .into_iter()
            .map(|shown| shown.body)
            .collect();
        assert_eq!(shown, ["m1"], "the desktop still shows m1");
        assert_eq!(unread_on(&s, 2, "notes", later), Vec::<String>::new());
        assert_eq!(
            read_on(&s[2].conn, &m1, "notes", &who_counts(&s[2].conn).unwrap())
                .unwrap()
                .devices,
            [s.key(1)]
        );
    }

    /// A mark merged from the device's own list, whose message it holds
    /// and has not yet given a place, is in the next list (decision
    /// 2026-10-09 §2.4, §7.2): it is given its ID and name, and the list
    /// written above the merged one, when the agent reads another message,
    /// holds it after the new mark, so that the other devices do not lose
    /// it.
    #[test]
    fn a_merged_mark_of_a_message_held_and_not_yet_placed_is_in_the_next_list() {
        let mut s = devices(2);
        let t = s.now;
        let to_read = sends(&s, 0, "~", "notes", "to read", t);
        s.pass(0, 1);
        shows(&s, 1, t);
        let held_only = sends(&s, 0, "~", "notes", "held, not shown", t);
        s.pass(0, 1);
        let placed: Option<i64> = s[1]
            .conn
            .query_row(
                "SELECT placed_at FROM message_index WHERE id = ?1",
                [&held_only[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(placed, None);
        let mark = read_mark(&held_only, "notes");
        let value = ReadMarks { marks: vec![mark] }.to_value().unwrap();
        let later = Entry::seal(
            &messages_secret(&s, 1),
            &s[1].identity,
            1,
            &message::inside(read_name(&s.key(1)).unwrap(), value),
        )
        .unwrap()
        .check()
        .unwrap();
        take(&s[1].conn, &s[1].identity, &later, t).unwrap();
        assert_eq!(table(&s, 1), [(mark, true)]);
        let marked = read_here(&s[1].conn, &s[1].identity, "notes", &to_read, t, true);
        assert_eq!(marked.unwrap().list, Some(2));
        assert_eq!(
            listed(&s, 1),
            Some((2, vec![read_mark(&to_read, "notes"), mark]))
        );
    }

    /// A restored store whose backup said more marks than a list holds
    /// lists its later list's marks above them (decision 2026-10-09 §2.4,
    /// §7.2): the backup held 130 marks left bare and wrote its list of the
    /// newest 120; its later life read a message and wrote a list above
    /// it. Taken back, that list's new mark is merged above the 130, and
    /// the list written at the next read holds the new read, then the
    /// later list's mark, then the newest 118 of the backup.
    #[test]
    fn a_restored_store_that_said_more_than_a_list_holds_lists_its_later_marks_first() {
        let mut s = devices(2);
        let t = s.now;
        let bare: Vec<Mark> = (1..=130u8).map(|k| [k; 16]).collect();
        for (seq, mark) in (1..).zip(&bare) {
            s[1].conn
                .execute(
                    "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                     VALUES (?1, ?2, ?3, ?3)",
                    rusqlite::params![&mark[..], seq, t],
                )
                .unwrap();
        }
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, true).unwrap(),
            Some(1)
        );
        let id = sends(&s, 0, "~", "notes", "read in the later life", t);
        s.pass(0, 1);
        let mark = read_mark(&id, "notes");
        let mut later = vec![mark];
        later.extend(bare[11..].iter().rev());
        let value = ReadMarks {
            marks: later.clone(),
        }
        .to_value()
        .unwrap();
        let entry = Entry::seal(
            &messages_secret(&s, 1),
            &s[1].identity,
            2,
            &message::inside(read_name(&s.key(1)).unwrap(), value),
        )
        .unwrap()
        .check()
        .unwrap();
        take(&s[1].conn, &s[1].identity, &entry, t).unwrap();
        assert_eq!(table(&s, 1)[0], (mark, true));
        // The bound of 120 bare hashes drops the backup's oldest ten.
        assert_eq!(table(&s, 1).len(), 121);

        let next = sends(&s, 0, "~", "notes", "read after the restore", t);
        s.pass(0, 1);
        let marked = reads(&s, 1, "notes", &next, t, true);
        assert_eq!(marked.list, Some(3));
        let mut newest = vec![read_mark(&next, "notes")];
        newest.extend(&later[..119]);
        assert_eq!(listed(&s, 1), Some((3, newest)));
    }

    /// A relay's answer of another to an entry in this device's list's
    /// slot that another key signed writes no list (decision 2026-10-09
    /// §2.4): a push sends every author's entries of the messages channel,
    /// and a key that counts can write in the slot `read/<this device's
    /// key>`; only an answer to the device's own list, at the revision it
    /// holds, writes it again.
    #[test]
    fn an_answer_of_another_to_another_keys_entry_in_the_lists_slot_writes_no_list() {
        let mut s = devices(2);
        let t = s.now;
        let id = sends(&s, 0, "~", "notes", "read", t);
        s.pass(0, 1);
        assert_eq!(reads(&s, 1, "notes", &id, t, true).list, Some(1));
        let value = ReadMarks::default().to_value().unwrap();
        let others = Entry::seal(
            &messages_secret(&s, 1),
            &s[0].identity,
            1,
            &message::inside(read_name(&s.key(1)).unwrap(), value),
        )
        .unwrap();
        let own = own_list(&s, 1).unwrap().entry;
        assert_eq!((others.slot, others.rev), (own.slot, own.rev));
        let channels = crate::at_relays::channels(&s[1].conn, &s[1].identity).unwrap();
        let channel = channels
            .iter()
            .find(|own| own.kind == Kind::Messages)
            .unwrap();
        let another = |entry: &Entry| {
            answered(
                &s[1].conn,
                &s[1].identity,
                channel,
                std::slice::from_ref(entry),
                &[Pushed::HoldsAnother],
                t,
                true,
            )
            .unwrap()
        };
        assert_eq!(another(&others), None);
        assert_eq!(listed(&s, 1).unwrap().0, 1);
        assert_eq!(another(&own), Some(2));
    }

    /// A device whose agents read more messages than a list holds between
    /// two fetches of its list by another loses the oldest of those marks
    /// for that device (decision 2026-10-09 §7.2): three agents of the
    /// laptop read 41 messages to every name, 123 marks; the list holds the
    /// newest 120, and the desktop shows the message read first as unread
    /// to each of those names, by the list's word.
    #[test]
    fn more_reads_than_a_list_holds_leave_the_oldest_unread_on_another_device() {
        let mut s = devices(3);
        let t = s.now;
        let ids: Vec<Id> = (0..41)
            .map(|k| sends(&s, 0, "~", "*", &format!("number {k}"), t + k * 200))
            .collect();
        s.pass(0, 1);
        s.pass(0, 2);
        let now = t + 41 * 200;
        for id in &ids {
            for name in ["notes", "work", "~"] {
                reads(&s, 1, name, id, now, true);
            }
        }
        let (_, marks) = listed(&s, 1).unwrap();
        assert_eq!(marks.len(), 120);
        assert_eq!(marks[0], read_mark(&ids[40], "~"));
        assert_eq!(marks[119], read_mark(&ids[1], "notes"));
        s.pass(1, 2);
        for name in ["notes", "work", "~"] {
            assert_eq!(unread_on(&s, 2, name, now), ["number 0"], "{name}");
        }
    }

    /// What a device that lies in its list can do (decision 2026-10-09
    /// §7.2, §11, T22): it lists the mark of a message that no agent read,
    /// and the other devices' summaries of that name neither show nor count
    /// it; `log`, which shows every message held, still shows it, and says
    /// on which device it was read; `read` still reads it. Once that device
    /// no longer counts its list says nothing, and the hourly task drops it.
    #[test]
    fn a_device_that_lies_in_its_list_hides_from_summaries_and_not_from_log() {
        let mut s = devices(3);
        let t = s.now;
        let id = sends(&s, 0, "~", "notes", "never read", t);
        s.pass(0, 2);
        let lie = ReadMarks {
            marks: vec![read_mark(&id, "notes")],
        }
        .to_value()
        .unwrap();
        let entry = Entry::seal(
            &messages_secret(&s, 1),
            &s[1].identity,
            1,
            &message::inside(read_name(&s.key(1)).unwrap(), lie),
        )
        .unwrap()
        .check()
        .unwrap();
        take(&s[2].conn, &s[2].identity, &entry, t).unwrap();
        assert!(unread_on(&s, 2, "notes", t).is_empty());
        // `log` lists it, and says on which device an agent read it.
        let asked = crate::messages::LogAsked {
            folder: None,
            since: None,
            mark: &[],
            fetched: true,
        };
        let log = crate::messages::log_of(&s[2].conn, &s[2].identity, &asked, t, |_| false)
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(log.threads.len(), 1);
        let listed = &log.threads[0].1[0];
        assert_eq!(listed.id, id);
        let said = listed.said.as_ref().unwrap();
        assert_eq!(said.body, "never read");
        assert_eq!(said.read_on, ["device 1"]);
        assert!(!said.read_here);
        assert_eq!(
            read_on(&s[2].conn, &id, "notes", &who_counts(&s[2].conn).unwrap()).unwrap(),
            ReadOn {
                here: false,
                devices: vec![s.key(1)]
            }
        );
        assert!(
            read_here(&s[2].conn, &s[2].identity, "notes", &id, t, true)
                .unwrap()
                .marked
        );
        s[2].conn
            .execute("DELETE FROM message_read_here", [])
            .unwrap();

        // The device is removed: its list says nothing on the desktop, and
        // goes at the hourly task.
        let own = crate::at_relays::channels(&s[1].conn, &s[1].identity).unwrap();
        let messages = own.into_iter().find(|own| own.kind == Kind::Messages);
        s.change(0, &[0, 2], &[1]);
        s.meet(&[0, 2]);
        assert_eq!(
            read_on(&s[2].conn, &id, "notes", &who_counts(&s[2].conn).unwrap()).unwrap(),
            ReadOn::default()
        );
        assert_eq!(unread_on(&s, 2, "notes", t), ["never read"]);
        let rows = |s: &Several| -> i64 {
            s[2].conn
                .query_row("SELECT COUNT(*) FROM message_lists", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(rows(&s), 1);
        crate::reader::hourly(&s[2].conn, &s[2].identity, t + 1, true).unwrap();
        assert_eq!(rows(&s), 0);

        // The removed device, once it has applied its removal, writes no
        // list, though its table holds a mark it never listed.
        let mark = read_mark(&id, "work");
        s[1].conn
            .execute(
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (?1, 1, ?2, ?2)",
                rusqlite::params![&mark[..], t],
            )
            .unwrap();
        s.pass(0, 1);
        assert!(matches!(stands(&s[1].conn).unwrap(), Stands::Stopped(_)));
        assert_eq!(
            write_list(&s[1].conn, &s[1].identity, t, true).unwrap(),
            None
        );
        // Nor where a relay answers another to its list.
        let list = entry.into_entry();
        let answer = answered(
            &s[1].conn,
            &s[1].identity,
            &messages.unwrap(),
            std::slice::from_ref(&list),
            &[Pushed::HoldsAnother],
            t,
            true,
        );
        assert_eq!(answer.unwrap(), None);
    }

    /// Device `n`'s own list of a person's reads that its store holds, as
    /// its revision and IDs.
    fn person_listed(s: &Several, n: usize) -> Option<(u64, Vec<held::Id>)> {
        let secret = messages_secret(s, n);
        let slot = slot_id(
            &derive::slot_key(&secret).unwrap(),
            &person_name(&s.key(n)).unwrap(),
        );
        let channel = derive::channel_id(&secret).unwrap();
        let entry = entries::author_entry(&s[n].conn, &channel, &slot, &s.key(n))
            .unwrap()?
            .entry
            .check()
            .unwrap();
        let inside = entry.open(&secret).unwrap();
        Some((
            entry.rev,
            PersonReads::from_value(&inside.value).unwrap().ids,
        ))
    }

    /// A device writes no list of a person's reads before its first fetch
    /// of the messages channel since it started, nor with sync off, and
    /// writes it once both hold (decision 2026-10-25, rule 1, as decision
    /// 2026-10-09 §2.4 has the agents' list): nothing new, nothing again.
    #[test]
    fn the_persons_list_waits_for_the_first_fetch_and_for_sync() {
        let s = devices(2);
        let t = s.now;
        // A person here read what it sent, as `sends` marks it.
        let id = sends(&s, 0, "~", "notes", "read early", t);
        let write = |fetched: bool| write_person_list(&s[0].conn, &s[0].identity, t, fetched);
        assert_eq!(write(false).unwrap(), None);
        assert!(person_listed(&s, 0).is_none());
        meta::remove(&s[0].conn, meta::SYNC_CLAUDE_DIR).unwrap();
        assert_eq!(write(true).unwrap(), None);
        assert!(person_listed(&s, 0).is_none());
        meta::set(&s[0].conn, meta::SYNC_CLAUDE_DIR, "/home/laptop/.claude").unwrap();
        assert_eq!(write(true).unwrap(), Some(1));
        assert_eq!(person_listed(&s, 0), Some((1, vec![id])));
        assert_eq!(write(true).unwrap(), None);
    }

    /// A relay that answers another to every list of a person's reads
    /// pushed makes the device write it under at most four revisions: three
    /// written again, and no fourth, until it is written for an ID it
    /// lacked, which starts the count again (decision 2026-10-25, rule 1).
    /// The count is the list's own: the agents' list is written again for
    /// its own answer all the same.
    #[test]
    fn a_relay_that_answers_another_to_the_persons_list_gets_three_more_at_most() {
        let mut s = devices(2);
        let t = s.now;
        sends(&s, 0, "~", "notes", "first", t);
        assert_eq!(
            write_person_list(&s[0].conn, &s[0].identity, t, true).unwrap(),
            Some(1)
        );
        let own = crate::at_relays::channels(&s[0].conn, &s[0].identity).unwrap();
        let channel = own.iter().find(|own| own.kind == Kind::Messages).unwrap();
        let person_entry = |s: &Several| {
            let secret = messages_secret(s, 0);
            let slot = slot_id(
                &derive::slot_key(&secret).unwrap(),
                &person_name(&s.key(0)).unwrap(),
            );
            let channel = derive::channel_id(&secret).unwrap();
            entries::author_entry(&s[0].conn, &channel, &slot, &s.key(0))
                .unwrap()
                .unwrap()
                .entry
        };
        let answer_newest = |s: &Several| {
            answered(
                &s[0].conn,
                &s[0].identity,
                channel,
                std::slice::from_ref(&person_entry(s)),
                &[Pushed::HoldsAnother],
                t,
                true,
            )
            .unwrap();
            person_listed(s, 0).unwrap().0
        };
        let written: Vec<u64> = (0..4).map(|_| answer_newest(&s)).collect();
        assert_eq!(written, [2, 3, 4, 4]);
        sends(&s, 0, "~", "work", "second", t);
        assert_eq!(
            write_person_list(&s[0].conn, &s[0].identity, t, true).unwrap(),
            Some(5)
        );
        let written: Vec<u64> = (0..4).map(|_| answer_newest(&s)).collect();
        assert_eq!(written, [6, 7, 8, 8]);
        // The agents' list counts apart: its first answer of another
        // writes it again.
        let id = sends(&s, 1, "~", "notes", "for laptop", t);
        s.pass(1, 0);
        assert_eq!(reads(&s, 0, "notes", &id, t, true).list, Some(1));
        let list = own_list(&s, 0).unwrap().entry;
        let again = answered(
            &s[0].conn,
            &s[0].identity,
            channel,
            std::slice::from_ref(&list),
            &[Pushed::HoldsAnother],
            t,
            true,
        );
        assert_eq!(again.unwrap(), Some(2));
    }

    /// A pass asks in full whether the list of a person's reads is due only
    /// where what decides it changed since a pass that changed nothing
    /// (issue #221): ten passes after the list is written ask nothing and
    /// change nothing in the store; a person's new read, the first fetch
    /// and a list of the device's own at a higher revision are each asked
    /// once, and what is written is what the pass would write asked in
    /// full.
    #[test]
    fn the_persons_list_is_asked_again_only_where_what_decides_it_changed() {
        let s = devices(2);
        let t = s.now;
        let asked = std::cell::Cell::new(0);
        let pass = |seen: &mut ListsSeen, fetched: bool| {
            let write = |fetched: bool| {
                asked.set(asked.get() + 1);
                write_person_list(&s[0].conn, &s[0].identity, t, fetched)
            };
            seen.where_changed(
                &s[0].conn,
                &s.key(0),
                PersonList::Reads,
                t,
                |_| fetched,
                write,
            )
            .unwrap()
        };
        let mut seen = ListsSeen::default();
        let first = sends(&s, 0, "~", "notes", "first", t);
        assert_eq!(pass(&mut seen, true), Some(1));
        // The pass after a write asks again, once.
        assert_eq!(pass(&mut seen, true), None);
        assert_eq!(asked.get(), 2);
        let changes = s[0].conn.total_changes();
        for _ in 0..10 {
            assert_eq!(pass(&mut seen, true), None);
        }
        assert_eq!(asked.get(), 2, "nothing changed: nothing is asked");
        assert_eq!(s[0].conn.total_changes(), changes);

        // A person's new read.
        let second = sends(&s, 0, "~", "work", "second", t);
        assert_eq!(pass(&mut seen, true), Some(2));
        assert_eq!(person_listed(&s, 0), Some((2, vec![second, first])));
        assert_eq!(pass(&mut seen, true), None);
        assert_eq!(asked.get(), 4);

        // The channel not fetched since a start, then fetched.
        assert_eq!(pass(&mut seen, false), None);
        assert_eq!(pass(&mut seen, false), None);
        assert_eq!(asked.get(), 5);
        assert_eq!(pass(&mut seen, true), None);
        assert_eq!(asked.get(), 6);

        // A list of its own at a higher revision, as a relay's answer of
        // another has the device write.
        assert_eq!(
            person_list_written(&s[0].conn, &s[0].identity, t, true, Some(2)).unwrap(),
            Some(3)
        );
        assert_eq!(pass(&mut seen, true), None);
        assert_eq!(asked.get(), 7);
        assert_eq!(pass(&mut seen, true), None);
        assert_eq!(asked.get(), 7);
    }
}
