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

use std::time::{Duration, Instant};

use rusqlite::Connection;

use cordelia_core::protocol::{CARRY_READ_MAX_SECS, RECOVERY_READ_ON_MAX_SECS};
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::version::{self, Version};
use cordelia_storage::at_relays as kept_rows;
use cordelia_storage::entries;
use cordelia_storage::person as held_rows;

use crate::error::ApiError;
use crate::own_read::{OwnRead, ReadAt, ReadId};
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
        false => Round::Ended { read, at, found },
    })
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

/// What is said where what was read has changed since the read ended in
/// a way that the store's order does not show (decision 2026-10-17 §4.2
/// item 8, §5.3): a folder was mapped to the name while it was read.
pub fn changed_since_says(name: &str) -> String {
    format!(
        "{} is still held: what was read has changed since, or is too old. Run `cordelia sync \
         unmap {}` again.",
        shown(name),
        typed(name)
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
/// (decision 2026-10-17 §4.6): a line for each relay ([`relays_say`]),
/// and that the device goes on sending them.
pub fn not_held_says(name: &str, not_held: usize, relays: &[String]) -> String {
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
         {them}. To let it go now, with {them}, run `cordelia sync unmap {}` at a terminal.",
        typed(name)
    ));
    said
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
