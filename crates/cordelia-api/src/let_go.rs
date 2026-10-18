//! The read before a carried name is let go (decision 2026-10-17 §4.2).
//!
//! The check protects one thing: a version of a carried name that is
//! nowhere else in the generation applied. So it asks the relays, and not
//! the device's notes of what it sent. **Before the name is let go, the
//! device reads the name's channel at each relay that it is set up with**
//! ([`crate::own_read`]), round after round from the place reached, and
//! looks at what each relay handed.
//!
//! - **The entries asked about are every entry of the name's channel that
//!   this device signed,** as the store holds them when the read ends: at
//!   most one in each slot, its current version there, one that lost a
//!   tie, or one that another device wrote over. A carried entry is this
//!   device's own (`person::carried_entry`).
//! - **An entry is held where one relay handed, in its slot, in that
//!   read,** the same version signed by a key that counts, or entries
//!   that, read as a slot is read (`version::current`, with who counts and
//!   under the statement applied), give the slot a current version at a
//!   higher revision ([`held_in`]). Anything else is held by no relay.
//!   One relay is enough.
//! - **The read goes on** while an entry asked about is held by no relay,
//!   a relay is still read in part, and RECOVERY_READ_ON_MAX_SECS have
//!   not gone by from its first round ([`reads_on`]).
//! - **Every let-go is bound to its read:** what was found is found with
//!   the place in the store's order of the last entry that the store took
//!   of the channel ([`Found::taken`]), and the name is let go only where
//!   the store has taken nothing of the channel since (decision 2026-10-17
//!   §4.2 item 8, [`crate::sync::let_go_of_a_carried_name`]).
//!
//! **The read runs outside the database's lock** (§4.2 item 3): the lock
//! is taken to know the name's channel, and after each round to look at
//! what was handed, and never while the relays are asked.
//!
//! **Where an entry is held by no relay, the name is let go with it only
//! on a typed `discard`** (decision 2026-10-17 §5, §1 property 5), which
//! the command asks at a terminal. What the read found is kept with it
//! ([`crate::own_read::OwnRead::found`]), and the word lets go of that
//! and of nothing else ([`crate::sync::discard_a_carried_name`]).
//!
//! **A device that has stopped reads no relay** (§4.4): its own notes
//! decide ([`noted`]). Where they say that it sent a version that it
//! signed to no relay, the same word is asked, bound to the count it took
//! from them; where they say none, the name goes at once.

use std::time::{Duration, Instant};

use rusqlite::Connection;

use cordelia_core::protocol::{
    CARRY_READ_MAX_SECS, LEFT_SECRET_KEPT_DAYS, RECOVERY_READ_ON_MAX_SECS,
};
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::version::{self, Version};
use cordelia_storage::at_relays as kept_rows;
use cordelia_storage::entries;
use cordelia_storage::person as held_rows;

use crate::error::ApiError;
use crate::own_read::{OwnRead, OwnReads, ReadAt, ReadId};
use crate::person::PersonError;
use crate::publish::Standing;
use crate::state::{AppState, AtRelays, OwnAsk};

/// What the read found, as the store held the name's channel when it
/// ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// How many entries were asked about: every entry of the channel that
    /// this device signed.
    pub asked: usize,
    /// The place in the store's order of each of those that no relay
    /// held, in that order.
    pub not_held: Vec<i64>,
    /// The place in the store's order of the last entry that the store had
    /// taken of the channel ([`kept_rows::last_taken`]): a let-go is bound
    /// to it.
    pub taken: i64,
}

impl Found {
    /// Whether one relay or another held each entry asked about.
    pub fn each_held(&self) -> bool {
        self.not_held.is_empty()
    }
}

/// Whether one relay's `handed`, the entries that it handed in one slot
/// in a read, hold `own`, this device's entry in that slot (decision
/// 2026-10-17 §4.2 item 5): they are read as a slot is read, with
/// `secret` the channel's, `statement` the number of the statement
/// applied and `counts` who counts, and give it a current version at a
/// higher revision than `own`'s, or a version at `own`'s revision with
/// `own`'s value. So an entry that a key which does not count signed is
/// nothing here, and one that does not open, is over its bound, or is in
/// a band above the statement moves nothing on. And an entry of this
/// device's that lost a tie is held only where its own version is
/// handed: the winner of the tie does not hold it.
pub fn held_in(
    handed: &[CheckedEntry],
    own: &CheckedEntry,
    secret: &[u8; 32],
    statement: u64,
    counts: impl Fn(&[u8; 32]) -> bool,
) -> Result<bool, PersonError> {
    let read = version::current(handed, secret, statement, &counts)?;
    let Some(current) = read.current else {
        return Ok(false);
    };
    if current.rev > own.rev {
        return Ok(true);
    }
    // The version that the entry is, read alone: an entry that is no
    // version is the same version as nothing.
    let mine = version::current(std::slice::from_ref(own), secret, statement, &counts)?.current;
    let same = |version: &Version| {
        mine.as_ref()
            .is_some_and(|mine| version.rev == mine.rev && version.value == mine.value)
    };
    Ok(same(&current) || read.lost.iter().any(same))
}

/// What the read `read` of the channel of `name` found, as the store
/// holds the channel now (see the module's documentation). The caller
/// holds the database's lock, and nothing is written.
///
/// Refused where the device does not stand under a statement. Whoever
/// lets go by it checks that the channel read is the name's channel
/// still ([`crate::sync::let_go_of_a_carried_name`]).
pub fn found(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    read: &OwnRead,
) -> Result<Found, PersonError> {
    let standing = Standing::to_write(conn)?;
    let secret = standing.name_secret(conn, name)?;
    let channel = read.channel;
    let own = identity.public_key();
    let counts = |key: &[u8; 32]| standing.counting.counts(key);
    let mut found = Found {
        asked: 0,
        not_held: Vec::new(),
        taken: kept_rows::last_taken(conn, &channel)?,
    };
    for slot in entries::channel_slots(conn, &channel)? {
        let Some(stored) = entries::author_entry(conn, &channel, &slot, &own)? else {
            continue;
        };
        let Ok(mine) = stored.entry.check() else {
            continue;
        };
        found.asked += 1;
        let mut held = false;
        for at in &read.at {
            let Some(handed) = at.handed.get(&slot) else {
                continue;
            };
            if held_in(handed, &mine, &secret, standing.number(), counts)? {
                held = true;
                break;
            }
        }
        if !held {
            found.not_held.push(stored.seq);
        }
    }
    found.not_held.sort_unstable();
    Ok(found)
}

/// How long the check reads a name's channel, at most, from its first
/// round.
const READ_ON_MOST: Duration = Duration::from_secs(RECOVERY_READ_ON_MAX_SECS);

/// Whether the read `read`, which found `found`, is read on at `now`
/// (decision 2026-10-17 §4.2 item 1): not where each entry asked about is
/// held at one relay, nor where no relay is read in part (each has handed
/// the channel to its end, holds none of it, or was not reached in a
/// round), nor from RECOVERY_READ_ON_MAX_SECS after its first round.
pub fn reads_on(read: &OwnRead, found: &Found, now: Instant) -> bool {
    !found.each_held()
        && read.at.iter().any(|at| at.read.reads_on())
        && now.saturating_duration_since(read.begun) < READ_ON_MOST
}

/// What came of a round of the read before a carried name is let go.
#[derive(Debug)]
pub enum Round {
    /// The read goes on: the command asks for the next round under its
    /// ID, and says what each relay has handed so far.
    Reading { read: ReadId, at: OwnRead },
    /// The read has ended, and found this.
    Ended {
        read: ReadId,
        at: OwnRead,
        found: Found,
    },
}

/// How long a round is waited for, at most: a little longer than the
/// round itself may take, as a read through the door is waited for, so
/// that the last page asked for before its end is still waited for.
fn round_wait() -> Duration {
    Duration::from_secs(CARRY_READ_MAX_SECS) + Duration::from_secs(30)
}

/// Read one round of the read before `name`, a carried name, is let go:
/// the first, where `read` is `None`, and otherwise the next of the read
/// that it names. The node reads with places of its own, outside the
/// database's lock ([`crate::own_read`]); the lock is taken after the
/// round, to look at what was handed ([`found`]). Within a round's time,
/// and a little more, whatever the node does.
///
/// Refused, with what the command says: where the node keeps no such
/// read of the name's channel ([`started_again_says`]); where the node
/// could not begin the read, or a round of it did not end in its time
/// ([`not_read_says`]).
pub async fn round(state: &AppState, name: &str, read: Option<ReadId>) -> Result<Round, ApiError> {
    let lock = || {
        state
            .db
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))
    };
    let channel = held_rows::channel_of_name(&*lock()?, name)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::BadRequest(format!("{name} is not mapped on this device")))?;
    // A node with no network reads no relay.
    if state.push_tx.is_none() {
        return Err(ApiError::Conflict(not_read_says(name)));
    }
    let reads = state.own_channels.reads();
    let until = Instant::now() + Duration::from_secs(CARRY_READ_MAX_SECS);
    let read = match read {
        None => {
            let (answer, answered) = tokio::sync::oneshot::channel();
            state.own_channels.ask_own(OwnAsk::Begin {
                channel,
                until,
                answer,
            });
            match tokio::time::timeout(round_wait(), answered).await {
                Ok(Ok(Some(read))) => read,
                _ => return Err(ApiError::Conflict(not_read_says(name))),
            }
        }
        Some(read) => {
            let ours = reads
                .get(&read, Instant::now())
                .is_some_and(|kept| kept.channel == channel);
            if !ours {
                return Err(ApiError::Conflict(started_again_says(name)));
            }
            let (answer, answered) = tokio::sync::oneshot::channel();
            state.own_channels.ask_own(OwnAsk::ReadOn {
                read,
                until,
                answer,
            });
            match tokio::time::timeout(round_wait(), answered).await {
                // A read that the node no longer keeps is found so below.
                Ok(Ok(_)) => read,
                _ => return Err(ApiError::Conflict(not_read_says(name))),
            }
        }
    };
    let db = lock()?;
    let Some(at) = reads.get(&read, Instant::now()) else {
        return Err(ApiError::Conflict(started_again_says(name)));
    };
    let found = found(&db, &state.identity, name, &at).map_err(crate::commands::refused)?;
    Ok(match reads_on(&at, &found, Instant::now()) {
        true => Round::Reading { read, at },
        false => {
            // A discard lets go of what this read found, and of nothing
            // that the store takes after it (decision 2026-10-17 §5.2).
            reads.found(&read, found.clone(), Instant::now());
            Round::Ended { read, at, found }
        }
    })
}

/// What the notes of a device that has stopped say of the name `name`
/// (decision 2026-10-17 §4.4): where they say that it sent to no relay an
/// entry of the name's channel that it signed
/// ([`kept_rows::places_sent_to_no_relay`]), the count is kept under an
/// ID among `reads`, as a read at no relay, at `now`, and is given back
/// with it: a `discard` is bound to it as to a read. `None` where they say
/// none, or the device holds no such name: the name then goes at once.
/// The caller holds the database's lock.
pub fn noted(
    conn: &Connection,
    identity: &NodeIdentity,
    reads: &OwnReads,
    name: &str,
    now: Instant,
) -> Result<Option<(ReadId, Found)>, PersonError> {
    let Some(channel) = held_rows::channel_of_name(conn, name)? else {
        return Ok(None);
    };
    let not_held = kept_rows::places_sent_to_no_relay(conn, &channel, &identity.public_key())?;
    if not_held.is_empty() {
        return Ok(None);
    }
    let under = crate::at_relays::kept_id(conn)?.unwrap_or_default();
    let read = reads.begin(&channel, &under, &[], now)?;
    let found = Found {
        asked: not_held.len(),
        not_held,
        taken: kept_rows::last_taken(conn, &channel)?,
    };
    reads.found(&read, found.clone(), now);
    Ok(Some((read, found)))
}

/// The name as a command is typed with it: home memory's name is quoted,
/// so that a shell does not read it as the home directory.
fn typed(name: &str) -> String {
    match name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        true => name.to_string(),
        false => format!("'{name}'"),
    }
}

/// The name as a line says it: home memory's name is said as that, as
/// the command says it in every line of its own.
fn shown(name: &str) -> String {
    match name == crate::sync::HOME_NAME {
        true => "home memory".to_string(),
        false => name.to_string(),
    }
}

/// What is said where the node no longer keeps the read that a command
/// asks to go on with (decision 2026-10-17 §4.6): it was started again
/// during the read, and kept nothing of it.
pub fn started_again_says(name: &str) -> String {
    let shown = shown(name);
    format!(
        "{shown} is still held: the node was started again since {shown} was read. Run \
         `cordelia sync unmap {}` again.",
        typed(name)
    )
}

/// What is said where a folder was mapped to the name while it was read
/// (decision 2026-10-17 §4.2 item 8): the store's order does not show it,
/// since a folder takes nothing in until its first cycle. The name is
/// held by that folder now. Nothing tells the person to unmap the name
/// again: that would unmap the folder.
pub fn folder_mapped_says(name: &str) -> String {
    let shown = shown(name);
    format!(
        "{shown} is still held: a folder was mapped to {shown} while the relays were read, and \
         {shown} is held by that folder now. Nothing was let go."
    )
}

/// What is said where the store took something of the name's channel
/// since the read ended (decision 2026-10-17 §4.2 item 8, §4.6): what was
/// let go would not be what the read asked about.
pub fn took_something_says(name: &str) -> String {
    format!(
        "{} is not let go: this device took something of it while it was read. Run \
         `cordelia sync unmap {}` again.",
        shown(name),
        typed(name)
    )
}

/// What is said where the node refuses a `discard` (decision 2026-10-17
/// §5.2, §5.3, §1 property 9): the read is no longer kept for its age, or
/// another read of the name took its place, or the number sent is not
/// the one it found, or the store took something of the name's channel
/// since it ended. Nothing was let go.
pub fn changed_says(name: &str) -> String {
    format!(
        "{} is still held: what was read has changed since, or is too old. Run `cordelia \
         sync unmap {}` again.",
        shown(name),
        typed(name)
    )
}

/// What is said where the node could not begin the read, or a round of
/// it did not end in its time: nothing was let go.
pub fn not_read_says(name: &str) -> String {
    format!(
        "{} is not let go: this device could not read the relays just now. Run `cordelia \
         sync unmap {}` again.",
        shown(name),
        typed(name)
    )
}

/// How long ago `secs` seconds is, in words.
fn ago(secs: i64) -> String {
    let (n, unit) = match secs.max(0) {
        s if s < 60 => return "just now".into(),
        s if s < 3600 => (s / 60, "minute"),
        s if s < 86_400 => (s / 3600, "hour"),
        s => (s / 86_400, "day"),
    };
    match n {
        1 => format!("1 {unit} ago"),
        n => format!("{n} {unit}s ago"),
    }
}

/// What is said of each relay where the name is not let go: how its read
/// ended, and how many of the entries that no relay held it had no room
/// for, and when it last refused something for room, where the device
/// keeps that. `said` is where the device stands at the relays, as the
/// node last said it, and `now` the time in seconds.
pub fn relays_say(
    conn: &Connection,
    read: &OwnRead,
    found: &Found,
    said: &AtRelays,
    now: i64,
) -> Result<Vec<String>, PersonError> {
    let mut lines = Vec::with_capacity(read.at.len());
    for at in &read.at {
        let how = match at.read {
            ReadAt::ToItsEnd => "read to its end.".to_string(),
            ReadAt::HoldsNone => "holds none of it.".to_string(),
            ReadAt::InPart => "read in part.".to_string(),
            ReadAt::NotReached => "not reached.".to_string(),
            ReadAt::Reading => format!(
                "read in part, for {} minutes.",
                RECOVERY_READ_ON_MAX_SECS / 60
            ),
        };
        let mut line = format!("  {}: {how}", at.relay);
        let refused = match at.key {
            Some(key) => kept_rows::waiting_refused(conn, &key, &read.channel)?,
            None => Vec::new(),
        };
        let no_room = found
            .not_held
            .iter()
            .filter(|seq| refused.contains(seq))
            .count();
        if no_room > 0 {
            let them = match (no_room, found.not_held.len()) {
                (1, 1) => "it".to_string(),
                (n, _) => format!("{n} of them"),
            };
            line.push_str(&format!(" It had no room for {them}"));
            let last = said
                .relays
                .iter()
                .find(|relay| relay.relay == at.relay)
                .and_then(|relay| relay.no_room);
            if let Some(last) = last {
                line.push_str(&format!(", the last time {}", ago(now - last.at)));
            }
            line.push('.');
        }
        lines.push(line);
    }
    Ok(lines)
}

/// What the node says where `name` is not let go because no relay that
/// the device is set up with held `not_held` of its versions in the read
/// (decision 2026-10-17 §4.6): [`not_held_lines`], and how to let it go
/// now ([`at_a_terminal_says`]). With no terminal the word is never asked.
pub fn not_held_says(name: &str, not_held: usize, relays: &[String]) -> String {
    format!(
        "{} {}",
        not_held_lines(name, not_held, relays),
        at_a_terminal_says(name, not_held)
    )
}

/// How a name that is not let go, with `not_held` versions that no relay
/// holds, is let go now, with them (decision 2026-10-17 §4.6, §5.3): at a
/// terminal, where the word is asked.
pub fn at_a_terminal_says(name: &str, not_held: usize) -> String {
    let them = match not_held {
        1 => "it",
        _ => "them",
    };
    format!(
        "To let it go now, with {them}, run `cordelia sync unmap {}` at a terminal.",
        typed(name)
    )
}

/// The lines of [`not_held_says`] that a terminal shows before the word
/// is asked (decision 2026-10-17 §5.3): how many versions no relay held,
/// a line for each relay ([`relays_say`]), and that the device goes on
/// sending them.
pub fn not_held_lines(name: &str, not_held: usize, relays: &[String]) -> String {
    let (it, them) = match not_held {
        1 => ("1 of its versions".to_string(), "it"),
        n => (format!("{n} of its versions"), "them"),
    };
    let shown = shown(name);
    let mut said = format!(
        "{shown} is not let go: no relay that this device is set up with held {it} when it was \
         read just now."
    );
    for line in relays {
        said.push('\n');
        said.push_str(line);
    }
    said.push_str(&format!(
        "\nThis device goes on sending {them}, and {shown} can be let go once a relay holds \
         {them}."
    ));
    said
}

/// What a device that has stopped says first where its own notes say that
/// it sent `not_held` versions of `name` to no relay (decision 2026-10-17
/// §4.4, §5.3, §1 property 8): why it stopped, that it cannot read the
/// relays, and what its notes say. Where it can be added again (it is in
/// no list, or could not open a change), that what is let go now is not
/// among what it would carry then.
pub fn stopped_says(name: &str, state: held_rows::State, not_held: usize) -> String {
    use held_rows::State;
    let name = shown(name);
    let why = match state {
        State::Removed => "it was removed",
        State::NotListed => "it is in no list of the last change",
        State::NotOpened => "it could not open the last change",
        State::Fork | State::Applied => "two changes were made apart",
    };
    let versions = match not_held {
        1 => "1 version".to_string(),
        n => format!("{n} versions"),
    };
    let mut said = format!(
        "This device has stopped ({why}), and sends nothing more. It cannot read the relays to \
         learn whether they hold {name}. Its own notes say that it sent {versions} of {name}, \
         which it wrote or carried, to no relay."
    );
    if matches!(state, State::NotListed | State::NotOpened) {
        said.push_str(
            " If this device is added again, it carries what it holds: what is let go now is not \
             among it.",
        );
    }
    said
}

/// For how many more days, at most, this device holds the secret of a
/// generation that it left (decision 2026-10-17 §5.2): the latest it left,
/// which it keeps for LEFT_SECRET_KEPT_DAYS from then, counted up to a
/// whole day from `now`, in seconds. `None` where it holds none.
pub fn left_secret_days(conn: &Connection, now: i64) -> Result<Option<i64>, PersonError> {
    const DAY: i64 = 24 * 60 * 60;
    let latest = held_rows::secrets(conn)?
        .into_iter()
        .filter_map(|secret| secret.left_at)
        .max();
    Ok(latest.map(|left_at| {
        let until = left_at.saturating_add(i64::from(LEFT_SECRET_KEPT_DAYS) * DAY);
        (until.saturating_sub(now) + DAY - 1).div_euclid(DAY).max(1)
    }))
}

/// Where the `not_held` versions of `name` that a `discard` lets go of
/// may still be (decision 2026-10-17 §5.2, §5.3): what a carry brought is
/// still at the relays, in the channel it was carried from, for `days`
/// more days at most, where the device holds a secret of a generation it
/// left, and the command that carried it brings it in again; what was
/// written on this device since goes for good. `folder` is whether a
/// folder was mapped to the name ([`crate::names::brought_in`]): it keeps
/// its files. It promises nothing that the device does not know.
///
/// **On a device that has stopped** (`stopped`), a carry is refused: what
/// a carry brought is brought in again by the same commands on another of
/// the person's devices, and the days that this device holds its secrets
/// for are no help, so they are not said.
pub fn where_says(
    name: &str,
    not_held: usize,
    days: Option<i64>,
    folder: bool,
    stopped: bool,
) -> String {
    let typed_name = typed(name);
    let name = shown(name);
    let (those, are) = match not_held {
        1 => ("that version".to_string(), "it is"),
        n => (format!("those {n} versions"), "they are"),
    };
    let folder_keeps = match folder {
        true => format!(
            " A folder that was mapped to {name} keeps its files: what it wrote may still be there."
        ),
        false => String::new(),
    };
    let Some(days) = days else {
        return format!(
            "Letting {name} go now drops {those} from this device: {are} on this device \
             alone.{folder_keeps}"
        );
    };
    let days = match days {
        1 => "1 more day".to_string(),
        n => format!("{n} more days"),
    };
    let which = match not_held {
        1 => "whether it is one".to_string(),
        n => format!("which of the {n} those are"),
    };
    let carried = match stopped {
        false => format!(
            "A version that a carry brought into {name} is still at the relays, in the channel it \
             was carried from, for {days} at most: `cordelia sync carry {typed_name}` brings in \
             again what a device that counts wrote, and `cordelia sync carry {typed_name} --from \
             <device>`, with the recovery phrase, what a removed device wrote."
        ),
        true => format!(
            "A version that a carry brought into {name} is still at the relays, in the channel it \
             was carried from. This device carries nothing while it has stopped: on another of \
             your devices, `cordelia sync carry {typed_name}` brings in again what a device that \
             counts wrote, and `cordelia sync carry {typed_name} --from <device>`, with the \
             recovery phrase, what a removed device wrote."
        ),
    };
    format!(
        "Letting {name} go now drops {those} from this device. {carried}{folder_keeps} A version \
         written on this device since it was carried is on this device alone, and goes for good: \
         this device does not keep {which}."
    )
}

/// What the node answers in place of a refusal where the command asks at
/// a terminal and `name` is let go only on the word (decision 2026-10-17
/// §5.2): the read's ID `read`, as hex, and `versions`, the number found,
/// which the command sends back with the word; `said`, what is said
/// first; and `where`, where the versions may still be ([`where_says`]),
/// on a device that has stopped where `stopped`. `now` is the time in
/// seconds.
pub fn word_asked(
    conn: &Connection,
    name: &str,
    read: &ReadId,
    versions: usize,
    said: String,
    now: i64,
    stopped: bool,
) -> Result<serde_json::Value, PersonError> {
    let days = left_secret_days(conn, now)?;
    let folder = crate::names::brought_in(conn)?.contains(name);
    Ok(serde_json::json!({
        "read": hex::encode(read),
        "versions": versions,
        "said": said,
        "where": where_says(name, versions, days, folder, stopped),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::own_read::OwnReads;

    /// **The read before a let-go goes on for RECOVERY_READ_ON_MAX_SECS
    /// at most, from its first round** (decision 2026-10-17 §4.2 item 1):
    /// a round is begun while a relay is read in part and an entry is held
    /// by no relay, until that time has gone by. Where each entry is held,
    /// or no relay is read in part, none is begun.
    #[test]
    fn test_the_read_before_a_let_go_reads_on_for_so_long_at_most() {
        let reads = OwnReads::default();
        let begun = Instant::now();
        let relays = ["relay-one".to_string(), "relay-two".to_string()];
        let id = reads.begin(&[1; 32], &[2; 32], &relays, begun).unwrap();
        let mut read = reads.get(&id, begun).unwrap();
        let not_held = Found {
            asked: 2,
            not_held: vec![7],
            taken: 9,
        };
        let most = Duration::from_secs(RECOVERY_READ_ON_MAX_SECS);
        let just = Duration::from_millis(1);
        assert!(reads_on(&read, &not_held, begun));
        assert!(reads_on(&read, &not_held, begun + most - just));
        assert!(!reads_on(&read, &not_held, begun + most));
        // Each entry held: no round more.
        let each_held = Found {
            not_held: Vec::new(),
            ..not_held.clone()
        };
        assert!(!reads_on(&read, &each_held, begun));
        // One relay read on is enough; none, and there is no round more.
        read.at[0].read = ReadAt::ToItsEnd;
        assert!(reads_on(&read, &not_held, begun));
        read.at[1].read = ReadAt::NotReached;
        assert!(!reads_on(&read, &not_held, begun));
    }

    /// **Where the versions that a `discard` lets go of may still be**
    /// (decision 2026-10-17 §5.2, §5.3): what a carry brought, at the
    /// relays, for as many days as the device holds the latest secret it
    /// left, and the commands that bring it in again; that what was
    /// written here goes for good; that a folder that was mapped keeps its
    /// files; and, where the device holds no secret of a generation it
    /// left, that they are on this device alone.
    #[test]
    fn test_where_the_versions_a_discard_lets_go_of_may_still_be() {
        assert_eq!(
            where_says("lab", 3, Some(61), false, false),
            "Letting lab go now drops those 3 versions from this device. A version that a carry \
             brought into lab is still at the relays, in the channel it was carried from, for 61 \
             more days at most: `cordelia sync carry lab` brings in again what a device that \
             counts wrote, and `cordelia sync carry lab --from <device>`, with the recovery \
             phrase, what a removed device wrote. A version written on this device since it was \
             carried is on this device alone, and goes for good: this device does not keep which \
             of the 3 those are."
        );
        // A folder was mapped to it: the sentence follows the second.
        let folder = where_says("lab", 3, Some(61), true, false);
        assert!(
            folder.contains(
                "what a removed device wrote. A folder that was mapped to lab keeps its files: \
                 what it wrote may still be there. A version written on this device"
            ),
            "{folder}"
        );
        let one = where_says("~", 1, Some(1), false, false);
        assert!(
            one.starts_with("Letting home memory go now drops that version from"),
            "{one}"
        );
        assert!(
            one.contains("for 1 more day at most: `cordelia sync carry '~'`"),
            "{one}"
        );
        assert!(
            one.ends_with("this device does not keep whether it is one."),
            "{one}"
        );
        // On a device that has stopped, which carries nothing: another
        // device brings it in again, and no days are said.
        let stopped = where_says("lab", 3, Some(61), true, true);
        assert_eq!(
            stopped,
            "Letting lab go now drops those 3 versions from this device. A version that a carry \
             brought into lab is still at the relays, in the channel it was carried from. This \
             device carries nothing while it has stopped: on another of your devices, `cordelia \
             sync carry lab` brings in again what a device that counts wrote, and `cordelia sync \
             carry lab --from <device>`, with the recovery phrase, what a removed device wrote. A \
             folder that was mapped to lab keeps its files: what it wrote may still be there. A \
             version written on this device since it was carried is on this device alone, and \
             goes for good: this device does not keep which of the 3 those are."
        );
        // No secret of a generation it left.
        assert_eq!(
            where_says("lab", 3, None, false, false),
            "Letting lab go now drops those 3 versions from this device: they are on this device \
             alone."
        );
        assert_eq!(
            where_says("lab", 1, None, true, false),
            "Letting lab go now drops that version from this device: it is on this device alone. \
             A folder that was mapped to lab keeps its files: what it wrote may still be there."
        );
    }

    /// For how many more days the device holds the latest secret that it
    /// left (decision 2026-10-17 §5.2): LEFT_SECRET_KEPT_DAYS from when it
    /// left it, up to a whole day, by the latest of them. None where it
    /// holds none it left.
    #[test]
    fn test_the_days_left_of_the_latest_secret_left() {
        let conn = cordelia_storage::db::open_in_memory().unwrap();
        const DAY: i64 = 86_400;
        let now = 1_800_000_000;
        assert_eq!(left_secret_days(&conn, now).unwrap(), None);
        held_rows::apply_secret(&conn, 3, &[3; 32], now - 40 * DAY).unwrap();
        assert_eq!(left_secret_days(&conn, now).unwrap(), None);
        held_rows::keep_left_secret(&conn, 2, &[2; 32], now - 40 * DAY).unwrap();
        assert_eq!(left_secret_days(&conn, now).unwrap(), Some(50));
        // The one left latest, though of a lower number; part of a day is
        // counted as one.
        held_rows::keep_left_secret(&conn, 1, &[9; 32], now - 29 * DAY - 3600).unwrap();
        assert_eq!(left_secret_days(&conn, now).unwrap(), Some(61));
        assert_eq!(
            left_secret_days(&conn, now + 61 * DAY - 3601).unwrap(),
            Some(1)
        );
    }

    /// What a device that has stopped says first before a `discard`
    /// (decision 2026-10-17 §5.3): the words of its status, and the
    /// sentence of what it would carry only where it can be added again.
    #[test]
    fn test_what_a_device_that_has_stopped_says_before_a_discard() {
        use held_rows::State;
        assert_eq!(
            stopped_says("lab", State::NotListed, 3),
            "This device has stopped (it is in no list of the last change), and sends nothing \
             more. It cannot read the relays to learn whether they hold lab. Its own notes say \
             that it sent 3 versions of lab, which it wrote or carried, to no relay. If this \
             device is added again, it carries what it holds: what is let go now is not among it."
        );
        let opened = stopped_says("lab", State::NotOpened, 1);
        assert!(opened.starts_with("This device has stopped (it could not open the last change)"));
        assert!(opened.contains("it sent 1 version of lab,") && opened.contains("added again"));
        for (state, why) in [
            (State::Removed, "(it was removed)"),
            (State::Fork, "(two changes were made apart)"),
        ] {
            let said = stopped_says("lab", state, 2);
            assert!(
                said.contains(why) && !said.contains("added again"),
                "{said}"
            );
        }
    }

    /// **An entry of this device's that is no version is the same version
    /// as nothing** (decision 2026-10-17 §4.2 item 5): handed beside a
    /// version at its revision, it is not held by it, though the version
    /// is current there. Its own version handed holds a real entry.
    #[test]
    fn test_an_own_entry_that_is_no_version_is_held_by_no_version_at_its_revision() {
        use crate::several::{Several, entry_by, identity_of, signed_in, text};
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "lab");
        let secret = s[0].own("lab");
        let theirs = entry_by(&identity_of(1), &secret, 1, "a.md", text("a"), &[]);
        let no_version = signed_in(&secret, &identity_of(0), theirs.slot, 1, vec![7; 256]);
        let mine = entry_by(&identity_of(0), &secret, 1, "a.md", text("a"), &[]);
        let counts = |_: &[u8; 32]| true;
        let handed = std::slice::from_ref(&theirs);
        assert!(!held_in(handed, &no_version, &secret, 1, counts).unwrap());
        assert!(held_in(handed, &mine, &secret, 1, counts).unwrap());
    }

    /// What is said of how long ago a relay last had no room.
    #[test]
    fn test_how_long_ago_is_said() {
        assert_eq!(ago(59), "just now");
        assert_eq!(ago(60), "1 minute ago");
        assert_eq!(ago(150), "2 minutes ago");
        assert_eq!(ago(3600), "1 hour ago");
        assert_eq!(ago(2 * 86_400), "2 days ago");
        assert_eq!(ago(-5), "just now");
    }

    /// Home memory's name is quoted in a command to copy; any other is
    /// written as it is.
    #[test]
    fn test_a_name_is_typed_so_that_a_shell_reads_it() {
        assert_eq!(typed("lab"), "lab");
        assert_eq!(typed("my-notes.v2"), "my-notes.v2");
        assert_eq!(typed("~"), "'~'");
        assert!(started_again_says("~").ends_with("Run `cordelia sync unmap '~'` again."));
    }
}
