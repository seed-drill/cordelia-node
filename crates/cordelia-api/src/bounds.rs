//! What a person allowed: a bound for each pair of agents, set only by a
//! person at a terminal, in place of the usual hold of ten (decision
//! 2026-10-25, rules 2 and 3).
//!
//! - **Setting one** ([`allow`]): `cordelia msg allow` at a terminal asks
//!   the node for the look, asks its question, and asks again with yes.
//!   The bound is the device's own row of `message_bounds` for its pair,
//!   in place of the one before, with its `set` and its `at` (rule 3.1),
//!   and the device's list of bounds is written in the same write.
//! - **The list** ([`write_bounds_list`]): the device's own bounds, each
//!   until 7 days and 10 minutes after its `at` by its own clock, or until
//!   a later one of another key for its pair is held (rule 3.5), in the
//!   slot `hold/<its key>`, of form 4, by the rules of the agents' list.
//! - **A list taken** ([`list_taken`], from the reader, in the door's
//!   write): another key's replaces what was held of that key, each bound
//!   keeping when this device first held it (rule 3.3); the device's own,
//!   from its later life, is merged by pair. A list of form 4 that does not
//!   read drops that key's bounds ([`no_list`]); a form this version does
//!   not know leaves them.
//! - **Which bound holds a pair** ([`in_force`]) is worked out when it is
//!   asked, from the device's own bounds and those of the keys that count
//!   (rules 3.2, 3.3, 3.8). A statement drops every bound (rule 3.7,
//!   [`crate::person`]).
//!
//! **Only the person at a terminal sets a bound,** and the command is the
//! only test for that: a program that holds the node's token can set any
//! bound through the route (rule 5).

use rusqlite::Connection;

use cordelia_core::CordeliaError;
use cordelia_core::protocol::{
    AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS, AGENT_MESSAGE_PAIR_BOUND_MAX_SECS,
    AGENT_MESSAGE_PAIR_UNREAD_MAX,
};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::message::{PairBound, PairBounds};
use cordelia_storage::StorageError;
use cordelia_storage::messages::{self as held, BoundRow};
use cordelia_storage::meta;

pub use cordelia_storage::messages::Pair;

use crate::at_relays::{Stands, stands};
use crate::marks::{HeldList, PersonList, may_write};
use crate::person::{Counting, PersonError, in_one, who_counts};
use crate::sender::Refused;

/// The usual hold, as a bound: what a listed 10 is (rule 3.2).
const USUAL: u8 = AGENT_MESSAGE_PAIR_UNREAD_MAX as u8;

/// The bound in force for a pair on this device (decision 2026-10-25,
/// rule 3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InForce {
    /// The usual hold of 10: no bound, one that has ended, or a listed 10.
    Usual,
    /// A bound a person set: `bound`, or any where `None`, until `until`
    /// by this device's clock, set on the device whose key is `on`.
    Set {
        bound: Option<u8>,
        until: i64,
        on: [u8; 32],
    },
}

impl InForce {
    /// The count at which sending between the pair stops, or `None` where
    /// only the hourly limits stop it.
    pub fn stops_at(&self) -> Option<u64> {
        match self {
            Self::Usual => Some(AGENT_MESSAGE_PAIR_UNREAD_MAX as u64),
            Self::Set { bound, .. } => bound.map(u64::from),
        }
    }
}

/// When `row` ends on this device (decision 2026-10-25, rule 3.3): `for`
/// seconds after the earlier of its `at` and when this device first held
/// it. A clock behind shortens it; a clock ahead gains nothing.
pub fn ends_at(row: &BoundRow) -> i64 {
    let at = i64::try_from(row.at).unwrap_or(i64::MAX);
    at.min(row.first_held)
        .saturating_add(i64::from(row.for_secs))
}

/// What orders two bounds of one pair (decision 2026-10-25, rule 3.2): the
/// later `set`, and of two with one `set` the lower bound (a number before
/// any), then the lower key. The greater decides.
fn order(row: &BoundRow) -> (u64, std::cmp::Reverse<u16>, std::cmp::Reverse<[u8; 32]>) {
    let rank = row.bound.map_or(u16::MAX, u16::from);
    (row.set, std::cmp::Reverse(rank), std::cmp::Reverse(row.key))
}

/// The bounds that say something now (rule 3.8): the device's own, and
/// those of the keys that count.
fn speaking<'a>(
    rows: &'a [BoundRow],
    own: &'a [u8; 32],
    counting: &'a Counting,
) -> impl Iterator<Item = &'a BoundRow> + 'a {
    rows.iter()
        .filter(move |row| row.key == *own || counting.counts(&row.key))
}

/// The bound that decides for `pair` among `rows` (rule 3.2), where any
/// says something.
fn deciding<'a>(
    rows: &'a [BoundRow],
    own: &'a [u8; 32],
    counting: &'a Counting,
    pair: &Pair,
) -> Option<&'a BoundRow> {
    speaking(rows, own, counting)
        .filter(|row| row.pair == *pair)
        .max_by_key(|row| order(row))
}

/// The bound in force for `pair` at `now`, of `rows` (decision 2026-10-25,
/// rules 3.2 and 3.3): the one that decides; the usual hold where it has
/// ended, whatever an older one would still allow, where it is a 10, and
/// where there is none.
pub fn in_force_of(
    rows: &[BoundRow],
    own: &[u8; 32],
    counting: &Counting,
    pair: &Pair,
    now: i64,
) -> InForce {
    match deciding(rows, own, counting, pair) {
        None => InForce::Usual,
        Some(row) if row.bound == Some(USUAL) || now >= ends_at(row) => InForce::Usual,
        Some(row) => InForce::Set {
            bound: row.bound,
            until: ends_at(row),
            on: row.key,
        },
    }
}

/// The bound in force for `pair` at `now` on this device.
pub fn in_force(
    conn: &Connection,
    own: &[u8; 32],
    counting: &Counting,
    pair: &Pair,
    now: i64,
) -> Result<InForce, PersonError> {
    let rows = kept(held::bounds(conn))?;
    Ok(in_force_of(&rows, own, counting, pair, now))
}

/// Each pair whose bound in force at `now` is not the usual hold (decision
/// 2026-10-25, rule 4), in order of pair: what `cordelia status` says.
pub fn set_now(
    conn: &Connection,
    own: &[u8; 32],
    counting: &Counting,
    now: i64,
) -> Result<Vec<(Pair, InForce)>, PersonError> {
    let rows = kept(held::bounds(conn))?;
    let mut pairs: Vec<Pair> = speaking(&rows, own, counting)
        .map(|row| row.pair.clone())
        .collect();
    pairs.sort();
    pairs.dedup();
    Ok(pairs
        .into_iter()
        .map(|pair| {
            let in_force = in_force_of(&rows, own, counting, &pair, now);
            (pair, in_force)
        })
        .filter(|(_, in_force)| *in_force != InForce::Usual)
        .collect())
}

/// The device's own bounds that it lists at `now`, the latest `set` first,
/// and those that it lists no more (decision 2026-10-25, rule 3.5): each
/// until 7 days and 10 minutes after its `at`, by its own clock, or until
/// it holds a bound for that pair with a later `set` from another key that
/// counts, which then decides in its place.
fn own_listed(
    rows: &[BoundRow],
    own: &[u8; 32],
    counting: &Counting,
    now: i64,
) -> (Vec<BoundRow>, Vec<BoundRow>) {
    let listed_secs = i64::try_from(AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS).unwrap_or(i64::MAX);
    let (mut listed, gone): (Vec<BoundRow>, Vec<BoundRow>) = rows
        .iter()
        .filter(|row| row.key == *own)
        .cloned()
        .partition(|row| {
            let at = i64::try_from(row.at).unwrap_or(i64::MAX);
            let within = now < at.saturating_add(listed_secs);
            let overridden = rows.iter().any(|other| {
                other.key != *own
                    && counting.counts(&other.key)
                    && other.pair == row.pair
                    && other.set > row.set
            });
            within && !overridden
        });
    listed.sort_by(|x, y| y.set.cmp(&x.set).then_with(|| x.pair.cmp(&y.pair)));
    (listed, gone)
}

/// A bound as a list of bounds holds it.
fn as_listed(row: &BoundRow) -> PairBound {
    PairBound {
        a: row.pair.a.clone(),
        b: row.pair.b.clone(),
        bound: row.bound,
        set: row.set,
        at: row.at,
        for_secs: row.for_secs,
    }
}

/// When the device's own bound `row` leaves its list, by its own clock
/// (rule 3.5): what the refusal for room says of each pair.
pub fn listed_until(row: &BoundRow) -> i64 {
    let listed_secs = i64::try_from(AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS).unwrap_or(i64::MAX);
    i64::try_from(row.at)
        .unwrap_or(i64::MAX)
        .saturating_add(listed_secs)
}

/// Write the device's list of the bounds a person set on it, at `now`,
/// where what it lists changed (decision 2026-10-25, rules 2 and 3.5): its
/// own bounds, each until it leaves the list, those that left dropped
/// first. Never before the first fetch (`fetched`), nor where the device
/// does not stand applied or has sync off. Returns the revision written,
/// where one was. One transaction.
pub fn write_bounds_list(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
) -> Result<Option<u64>, PersonError> {
    in_one(conn, || list_written(conn, identity, now, fetched, None))
}

/// [`write_bounds_list`], as each pass asks it: where what decides it is
/// what it was at a pass that wrote and dropped nothing, and none of the
/// device's own bounds has reached the time it leaves the list, nothing is
/// opened or checked ([`crate::marks::ListsSeen`]). `fetched` says, of the
/// messages channel's ID, whether it was fetched since the node started.
pub fn write_bounds_list_where_changed(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: impl FnOnce(&[u8; 32]) -> bool,
    seen: &mut crate::marks::ListsSeen,
) -> Result<Option<u64>, PersonError> {
    seen.where_changed(
        conn,
        &identity.public_key(),
        PersonList::Bounds,
        now,
        fetched,
        |fetched| write_bounds_list(conn, identity, now, fetched),
    )
}

/// [`write_bounds_list`], in the caller's write; with `above`, a relay
/// answered that it holds another list of the device's at that revision.
fn list_written(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
    above: Option<u64>,
) -> Result<Option<u64>, PersonError> {
    if !may_write(conn, fetched)? {
        return Ok(None);
    }
    let own = identity.public_key();
    let counting = who_counts(conn)?;
    let rows = kept(held::bounds(conn))?;
    let (listed, gone) = own_listed(&rows, &own, &counting, now);
    for row in &gone {
        kept(held::drop_bound(conn, &own, &row.pair))?;
    }
    let held_list = HeldList::of(conn, &own, PersonList::Bounds)?;
    let was: Vec<PairBound> = held_list
        .held
        .as_ref()
        .and_then(|(_, value)| value.as_ref())
        .and_then(|value| PairBounds::from_value(value, crate::names::is_a_name).ok())
        .map(|list| list.bounds)
        .unwrap_or_default();
    let bounds: Vec<PairBound> = listed.iter().map(as_listed).collect();
    let changed = bounds != was;
    let value = PairBounds { bounds }
        .to_value(crate::names::is_a_name)
        .map_err(|e| PersonError::Held(format!("a list of bounds: {e}")))?;
    held_list.write(conn, identity, now, above, changed, value)
}

/// A relay answered that it holds another list of bounds of the device's
/// at `rev` (decision 2026-10-25, rule 2), in the caller's write: its store
/// went back, or the relay lies. Only where the device may write its list,
/// the answer names the revision of the list it holds, and it has written
/// that list again so fewer than three times in a row, as
/// [`HeldList::write`] writes again: the device then drops those of its
/// own bounds set before this start that allow more than the usual hold
/// (`any`, or a number above 10), which may be ones its later life ended,
/// and keeps a 10 or a lower number, the safe side either way; and it
/// writes its list above that revision.
pub(crate) fn answered_another(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
    fetched: bool,
    rev: u64,
) -> Result<Option<u64>, PersonError> {
    let own = identity.public_key();
    if !may_write(conn, fetched)?
        || !HeldList::of(conn, &own, PersonList::Bounds)?.takes_answer(conn, rev)?
    {
        return Ok(None);
    }
    let start = this_start(conn)?;
    for row in kept(held::bounds(conn))? {
        if row.key == own && row.start != Some(start) && allows_more_than_usual(&row) {
            kept(held::drop_bound(conn, &own, &row.pair))?;
        }
    }
    list_written(conn, identity, now, fetched, Some(rev))
}

/// Whether `row` allows more to wait than the usual hold: `any`, or a
/// number above 10 (decision 2026-10-25, rule 2).
fn allows_more_than_usual(row: &BoundRow) -> bool {
    row.bound.is_none_or(|bound| bound > USUAL)
}

/// The reader took `list`, the list of bounds of the device whose key is
/// `signer`, which the store kept over what it held (decision 2026-10-25,
/// rule 2), in the door's write, at `now`.
///
/// - **Another key's** replaces what was held of it. A bound with the key,
///   the pair and the `set` of one held keeps when this device first held
///   it (rule 3.3); any other was first held now.
/// - **The device's own, `own`,** is one a relay handed back from its later
///   life (a store restored from a backup): for each pair the bound with
///   the later `set` is kept, and an own bound that the later list lacks is
///   kept only where it was set since this start. Its next list goes above
///   it.
pub(crate) fn list_taken(
    conn: &Connection,
    own: &[u8; 32],
    signer: &[u8; 32],
    list: &PairBounds,
    now: i64,
) -> Result<(), PersonError> {
    let rows = kept(held::bounds(conn))?;
    let of_it: Vec<&BoundRow> = rows.iter().filter(|row| row.key == *signer).collect();
    if signer != own {
        kept(held::drop_bounds_of(conn, signer))?;
        for bound in &list.bounds {
            let pair = Pair {
                a: bound.a.clone(),
                b: bound.b.clone(),
            };
            let first_held = of_it
                .iter()
                .find(|row| row.pair == pair && row.set == bound.set)
                .map_or(now, |row| row.first_held);
            kept(held::put_bound(
                conn,
                &row_of(signer, pair, bound, first_held, None),
            ))?;
        }
        return Ok(());
    }
    let start = this_start(conn)?;
    for row in &of_it {
        let in_later = list
            .bounds
            .iter()
            .any(|bound| bound.a == row.pair.a && bound.b == row.pair.b);
        if !in_later && row.start != Some(start) {
            kept(held::drop_bound(conn, own, &row.pair))?;
        }
    }
    for bound in &list.bounds {
        let pair = Pair {
            a: bound.a.clone(),
            b: bound.b.clone(),
        };
        let held_now = of_it.iter().find(|row| row.pair == pair);
        match held_now {
            Some(row) if row.set >= bound.set => {}
            _ => kept(held::put_bound(conn, &row_of(own, pair, bound, now, None)))?,
        }
    }
    Ok(())
}

/// The reader took an entry in the slot of the list of bounds of `signer`
/// that is of form 4 and does not read (decision 2026-10-25, rule 2): a
/// bound that cannot be read holds nothing, and that key's bounds go, in
/// the door's write. The device's own bounds are its own acts, and stay: a
/// list of its own that does not read is a holder of its key's.
pub(crate) fn no_list(
    conn: &Connection,
    own: &[u8; 32],
    signer: &[u8; 32],
) -> Result<(), PersonError> {
    if signer == own {
        return Ok(());
    }
    kept(held::drop_bounds_of(conn, signer)).map(|_| ())
}

fn row_of(
    key: &[u8; 32],
    pair: Pair,
    bound: &PairBound,
    first_held: i64,
    start: Option<i64>,
) -> BoundRow {
    BoundRow {
        key: *key,
        pair,
        bound: bound.bound,
        set: bound.set,
        at: bound.at,
        for_secs: bound.for_secs,
        first_held,
        start,
    }
}

/// The node started (decision 2026-10-25, rule 2): the start is counted,
/// so that a bound set from now on is known to be of this start. Returns
/// the new start.
pub fn started(conn: &Connection) -> Result<i64, PersonError> {
    in_one(conn, || {
        let start = this_start(conn)?.saturating_add(1);
        meta::set(conn, meta::MESSAGES_START, &start.to_string())?;
        Ok(start)
    })
}

/// The start of the node, as [`started`] counted it: 0 before the first.
fn this_start(conn: &Connection) -> Result<i64, PersonError> {
    Ok(meta::get(conn, meta::MESSAGES_START)?
        .and_then(|start| start.parse().ok())
        .unwrap_or(0))
}

// ── Setting a bound ──────────────────────────────────────────────────

/// What a person asks `cordelia msg allow` for (decision 2026-10-25, rule
/// 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allow {
    pub pair: Pair,
    /// 1 to 64, or `None` for any. A 10 is the usual hold.
    pub bound: Option<u8>,
    /// How long it holds, in seconds: 60 to 604,800. A 10 is for 604,800,
    /// whatever was given.
    pub for_secs: u32,
}

impl Allow {
    /// The `for` that is set: 604,800 for a 10 (rule 3.3).
    fn for_set(&self) -> u32 {
        match self.bound {
            Some(USUAL) => AGENT_MESSAGE_PAIR_BOUND_MAX_SECS,
            _ => self.for_secs,
        }
    }
}

/// What [`allow`] answers: the look, and what was set where it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    /// How many messages of the pair count towards its hold now.
    pub waiting: u64,
    /// The bound in force before anything was set.
    pub was: InForce,
    /// When what is asked for would end, or ends where it was set.
    pub until: i64,
    /// Whether it was set.
    pub set: bool,
    /// The revision of the list of bounds written, where one was.
    pub list: Option<u64>,
}

/// `cordelia msg allow` at `now` by the node's clock (decision 2026-10-25,
/// rules 2 and 3), in one write: the look where `yes` is false, and the
/// bound set where it is true. The node's checks are made in the record's
/// order, the first that applies refusing: the device (step 4 of §4.3 of
/// decision 2026-10-09), sync (step 5), the first fetch (`fetched`), each
/// name, and the room in the device's list (rule 3.6).
///
/// The bound is the device's own for its pair, in place of the one before:
/// its `at` is `now`, and its `set` the later of `now` and one second
/// after the latest `set` the device holds for that pair from any key that
/// says something, stopping at the top of its 8 bytes (rule 3.1). It holds
/// from when the device holds it, so it was first held now. The device's
/// list is written in the same write, where it may.
pub fn allow(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &Allow,
    now: i64,
    fetched: bool,
    yes: bool,
) -> Result<Allowed, AllowNot> {
    in_one(conn, || {
        Ok(match allowing(conn, identity, asked, now, fetched, yes) {
            Err(AllowNot::Failed(e)) => return Err(e),
            done => done,
        })
    })?
}

/// Why [`allow`] set nothing.
#[derive(Debug)]
pub enum AllowNot {
    Refused(Refused),
    Failed(PersonError),
}

impl From<PersonError> for AllowNot {
    fn from(e: PersonError) -> Self {
        Self::Failed(e)
    }
}

fn allowing(
    conn: &Connection,
    identity: &NodeIdentity,
    asked: &Allow,
    now: i64,
    fetched: bool,
    yes: bool,
) -> Result<Allowed, AllowNot> {
    let refused = |why: Refused| Err(AllowNot::Refused(why));
    if stands(conn)? != Stands::Applied {
        return refused(Refused::NotApplied);
    }
    if meta::get(conn, meta::SYNC_CLAUDE_DIR)
        .map_err(PersonError::from)?
        .is_none()
    {
        return refused(Refused::SyncOff);
    }
    if !fetched {
        return refused(Refused::NotFetched);
    }
    let listed = crate::names::listed(conn)?;
    for name in std::iter::once(&asked.pair.a).chain(asked.pair.b.as_ref()) {
        if !listed.iter().any(|one| one.name == *name) {
            return refused(Refused::NoSuchName(name.clone()));
        }
    }
    let own = identity.public_key();
    let counting = who_counts(conn)?;
    let rows = kept(held::bounds(conn))?;
    let was = in_force_of(&rows, &own, &counting, &asked.pair, now);
    let waiting = waiting(conn, &asked.pair, now, &counting)?;
    let at = u64::try_from(now).unwrap_or(0);
    let set = speaking(&rows, &own, &counting)
        .filter(|row| row.pair == asked.pair)
        .map(|row| row.set.saturating_add(1))
        .fold(at, u64::max);
    let row = BoundRow {
        key: own,
        pair: asked.pair.clone(),
        bound: asked.bound,
        set,
        at,
        for_secs: asked.for_set(),
        first_held: now,
        start: Some(this_start(conn)?),
    };
    // Room (rule 3.6): what the list would hold, with this in place of
    // the device's own for its pair.
    let (listed_now, _) = own_listed(&rows, &own, &counting, now);
    let mut would: Vec<BoundRow> = listed_now
        .iter()
        .filter(|held| held.pair != asked.pair)
        .cloned()
        .collect();
    would.push(row.clone());
    let fits = PairBounds::fit(&would.iter().map(as_listed).collect::<Vec<_>>());
    let holds_it = listed_now.iter().any(|held| held.pair == asked.pair);
    if !fits && !holds_it {
        return refused(Refused::BoundsFull(
            listed_now
                .iter()
                .map(|held| (held.pair.clone(), listed_until(held)))
                .collect(),
        ));
    }
    let until = ends_at(&row);
    if !yes {
        return Ok(Allowed {
            waiting,
            was,
            until,
            set: false,
            list: None,
        });
    }
    kept(held::put_bound(conn, &row))?;
    let list = list_written(conn, identity, now, fetched, None)?;
    Ok(Allowed {
        waiting,
        was,
        until,
        set: true,
        list,
    })
}

/// How many messages of `pair` count towards its hold at `now` (decision
/// 2026-10-09 §6): those `pairs_with` counts of its first name with the
/// other side.
pub fn waiting(
    conn: &Connection,
    pair: &Pair,
    now: i64,
    counting: &Counting,
) -> Result<u64, PersonError> {
    Ok(
        kept(held::pairs_with(conn, &pair.a, now, &counting.keys()))?
            .into_iter()
            .find(|(other, _)| *other == pair.b)
            .map_or(0, |(_, count)| count),
    )
}

/// What the store answered, with its error as the device's.
fn kept<T>(answer: Result<T, StorageError>) -> Result<T, PersonError> {
    answer.map_err(|e| PersonError::Storage(CordeliaError::Storage(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_core::protocol::AGENT_MESSAGES_PER_FOLDER_PER_HOUR;
    use cordelia_crypto::derive;
    use cordelia_crypto::entry::{CheckedEntry, Entry};
    use cordelia_crypto::message::{self, To};
    use cordelia_crypto::slots::slot_id;
    use cordelia_storage::entries;

    use crate::sender::{At, NotSent, Request, no_reply, send};
    use crate::several::Several;
    use crate::take::take;

    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;

    /// `count` devices of one person, each with sync on, saying that it
    /// syncs `notes`, `work` and `plans`, each mapping a folder to each,
    /// each having been given what every other holds.
    fn devices(count: u16) -> Several {
        let mut s = Several::of_one_person(count);
        for n in 0..usize::from(count) {
            let conn = &s[n].conn;
            meta::set(conn, meta::SYNC_CLAUDE_DIR, "/home/sam/.claude").unwrap();
            for name in ["notes", "work", "plans"] {
                crate::names::say(conn, &s[n].identity, name, s.now).unwrap();
            }
        }
        let all: Vec<usize> = (0..usize::from(count)).collect();
        s.meet(&all);
        s
    }

    fn pair() -> Pair {
        Pair::of("notes", Some("work"))
    }

    /// A person on device `n` allows `bound` (None for any) for the pair
    /// of notes and work, for `for_secs`, at `now` by that device's
    /// clock, and says yes.
    fn allows(s: &Several, n: usize, bound: Option<u8>, for_secs: u32, now: i64) -> Allowed {
        allows_pair(s, n, &pair(), bound, for_secs, now)
    }

    fn allows_pair(
        s: &Several,
        n: usize,
        pair: &Pair,
        bound: Option<u8>,
        for_secs: u32,
        now: i64,
    ) -> Allowed {
        let asked = Allow {
            pair: pair.clone(),
            bound,
            for_secs,
        };
        match allow(&s[n].conn, &s[n].identity, &asked, now, true, true) {
            Ok(allowed) => allowed,
            Err(AllowNot::Refused(why)) => panic!("refused: {why:?}"),
            Err(AllowNot::Failed(e)) => panic!("{e}"),
        }
    }

    /// The count at which sending between notes and work stops on device
    /// `n` at `now`, or `None` for any.
    fn stops_on(s: &Several, n: usize, now: i64) -> Option<u64> {
        in_force_on(s, n, now).stops_at()
    }

    fn in_force_on(s: &Several, n: usize, now: i64) -> InForce {
        let counting = who_counts(&s[n].conn).unwrap();
        in_force(&s[n].conn, &s.key(n), &counting, &pair(), now).unwrap()
    }

    /// The messages secret device `n` stands applied under.
    fn secret_of(s: &Several, n: usize) -> [u8; 32] {
        derive::messages_secret(&s[n].secret()).unwrap()
    }

    /// Device `n`'s own list of bounds that its store holds.
    fn list_of(s: &Several, n: usize) -> Option<CheckedEntry> {
        let secret = secret_of(s, n);
        let slot = slot_id(
            &derive::slot_key(&secret).unwrap(),
            &message::hold_name(&s.key(n)).unwrap(),
        );
        let channel = derive::channel_id(&secret).unwrap();
        entries::author_entry(&s[n].conn, &channel, &slot, &s.key(n))
            .unwrap()
            .map(|stored| stored.entry.check().unwrap())
    }

    /// What that list holds.
    fn listed(s: &Several, n: usize) -> Vec<PairBound> {
        let Some(entry) = list_of(s, n) else {
            return Vec::new();
        };
        let inside = entry.open(&secret_of(s, n)).unwrap();
        PairBounds::from_value(&inside.value, crate::names::is_a_name)
            .unwrap()
            .bounds
    }

    /// Device `to` takes device `from`'s list of bounds at `now`, by `to`'s
    /// clock.
    fn hears(s: &Several, from: usize, to: usize, now: i64) {
        if let Some(entry) = list_of(s, from) {
            take(&s[to].conn, &s[to].identity, &entry, now).unwrap();
        }
    }

    /// Device `n` writes its list at `now`, as a pass does.
    fn lists(s: &Several, n: usize, now: i64) -> Option<u64> {
        write_bounds_list(&s[n].conn, &s[n].identity, now, true).unwrap()
    }

    /// Device `n` sends from `from` to `to` at `now`.
    fn sends(s: &Several, n: usize, from: &str, to: &str, now: i64) -> Result<(), NotSent> {
        let at = At {
            now,
            fetched: true,
            no_place: false,
            mapped: true,
            per_folder_per_hour: AGENT_MESSAGES_PER_FOLDER_PER_HOUR,
        };
        let request = Request {
            from: from.into(),
            to: To::Name(to.into()),
            asks: false,
            link: None,
            body: format!("from {from} at {now}"),
            thread: [0; 16],
            answers: [0; 16],
        };
        send(&s[n].conn, &s[n].identity, &at, &request, no_reply).map(|_| ())
    }

    /// The desktop sets 30, then the laptop, having heard of it, sets any:
    /// both hold by any; when the laptop's ends, both hold at 10, though
    /// the desktop's 30 would still run (decision 2026-10-25, rules 3.1 and
    /// 3.2).
    #[test]
    fn the_bound_set_last_decides() {
        let s = devices(2);
        let t = s.now + MINUTE;
        allows(&s, 1, Some(30), 8 * 3600, t);
        hears(&s, 1, 0, t + 1);
        assert_eq!(stops_on(&s, 0, t + 1), Some(30));
        allows(&s, 0, None, 3600, t + 2);
        hears(&s, 0, 1, t + 3);
        for n in [0, 1] {
            assert_eq!(stops_on(&s, n, t + 10), None, "device {n}");
            assert_eq!(stops_on(&s, n, t + 2 + HOUR), Some(10), "device {n}");
        }
        // The desktop's 30 would run another seven hours: it holds nothing.
        assert!(t + 8 * HOUR > t + 2 + HOUR);
        assert_eq!(stops_on(&s, 1, t + 4 * HOUR), Some(10));
    }

    /// A later act decides whatever the clocks say (decision 2026-10-25,
    /// rule 3.1): the desktop's clock 9 minutes ahead sets any; the laptop,
    /// having heard of it, sets 10, whose `set` is a second after the
    /// any's, and both hold at 10. With the laptop's clock an hour behind,
    /// the same.
    #[test]
    fn a_later_act_decides_whatever_the_clocks_say() {
        for behind in [0, HOUR] {
            let s = devices(2);
            let t = s.now + MINUTE;
            allows(&s, 1, None, 3600, t + 9 * MINUTE);
            hears(&s, 1, 0, t + 1 - behind);
            assert_eq!(stops_on(&s, 0, t + 1 - behind), None);
            allows(&s, 0, Some(10), 3600, t + 2 - behind);
            let any = listed(&s, 1)[0].set;
            let ten = listed(&s, 0)[0].clone();
            assert_eq!(ten.set, any + 1, "behind {behind}");
            assert_eq!(ten.at, (t + 2 - behind) as u64);
            assert_eq!(ten.for_secs, AGENT_MESSAGE_PAIR_BOUND_MAX_SECS);
            hears(&s, 0, 1, t + 3 + 9 * MINUTE);
            assert_eq!(stops_on(&s, 0, t + 3 - behind), Some(10));
            assert_eq!(stops_on(&s, 1, t + 3 + 9 * MINUTE), Some(10));
            // A listed 10 is the usual hold.
            assert_eq!(in_force_on(&s, 1, t + 3 + 9 * MINUTE), InForce::Usual);
        }
    }

    /// A 10 set before an older bound is heard of still decides (decision
    /// 2026-10-25, rules 3.2 and 3.5): the desktop, with no relay, sets
    /// any; an hour later the laptop sets 10; the desktop reaches a relay;
    /// both hold at 10, and the desktop no longer lists its any.
    #[test]
    fn a_ten_set_before_an_older_bound_is_heard_of_still_decides() {
        let s = devices(2);
        let t = s.now + MINUTE;
        allows(&s, 1, None, 8 * 3600, t);
        allows(&s, 0, Some(10), 3600, t + HOUR);
        hears(&s, 1, 0, t + HOUR + 1);
        hears(&s, 0, 1, t + HOUR + 1);
        assert_eq!(stops_on(&s, 0, t + HOUR + 2), Some(10));
        assert_eq!(stops_on(&s, 1, t + HOUR + 2), Some(10));
        assert_eq!(listed(&s, 1).len(), 1);
        assert_eq!(lists(&s, 1, t + HOUR + 2), Some(2));
        assert!(listed(&s, 1).is_empty());
        assert_eq!(listed(&s, 0).len(), 1);
        assert_eq!(stops_on(&s, 1, t + HOUR + 3), Some(10));
    }

    /// An older bound does not come back from a relay that is behind
    /// (decision 2026-10-25, rules 3.2 and 3.5): the laptop lists any, the
    /// desktop then 20 for an hour; relay2 holds only the laptop's first
    /// list; a third device pulls from relay2 and from relay1, in either
    /// order, and with relay1 lacking the laptop's later list too, and
    /// holds by the 20, and at 10 once the 20 has ended.
    #[test]
    fn an_older_bound_does_not_come_back_from_a_relay_that_is_behind() {
        for case in 0..3 {
            let s = devices(3);
            let t = s.now + MINUTE;
            allows(&s, 0, None, 24 * 3600, t);
            let relay2 = list_of(&s, 0).unwrap();
            hears(&s, 0, 1, t + 1);
            allows(&s, 1, Some(20), 3600, t + 2);
            hears(&s, 1, 0, t + 3);
            assert_eq!(
                lists(&s, 0, t + 3),
                Some(2),
                "the any leaves the laptop's list"
            );
            assert!(listed(&s, 0).is_empty());
            let laptop_later = list_of(&s, 0).unwrap();
            let desktop = list_of(&s, 1).unwrap();
            let third = &s[2];
            let given = |entry: &CheckedEntry| {
                take(&third.conn, &third.identity, entry, t + 4).unwrap();
            };
            match case {
                0 => {
                    given(&relay2);
                    given(&laptop_later);
                    given(&desktop);
                }
                1 => {
                    given(&laptop_later);
                    given(&desktop);
                    given(&relay2);
                }
                _ => {
                    given(&relay2);
                    given(&desktop);
                }
            }
            assert_eq!(stops_on(&s, 2, t + 5), Some(20), "case {case}");
            assert_eq!(stops_on(&s, 2, t + 2 + HOUR), Some(10), "case {case}");
            assert_eq!(stops_on(&s, 2, t + 10 * HOUR), Some(10), "case {case}");
        }
    }

    /// Two bounds set in one second, by two devices that had not heard of
    /// each other: the lower decides on both, a number before any
    /// (decision 2026-10-25, rule 3.2).
    #[test]
    fn two_bounds_set_in_one_second() {
        for (laptop, desktop, decides) in [
            (Some(20), None, Some(20)),
            (Some(20), Some(5), Some(5)),
            (None, Some(30), Some(30)),
        ] {
            let s = devices(2);
            let t = s.now + MINUTE;
            allows(&s, 0, laptop, 3600, t);
            allows(&s, 1, desktop, 3600, t);
            hears(&s, 0, 1, t + 1);
            hears(&s, 1, 0, t + 1);
            assert_eq!(listed(&s, 0)[0].set, listed(&s, 1)[0].set);
            for n in [0, 1] {
                assert_eq!(stops_on(&s, n, t + 2), decides, "{laptop:?} {desktop:?}");
            }
        }
    }

    /// Of two like bounds with one `set`, the lower key decides (decision
    /// 2026-10-25, rule 3.2): every device names the same device as the
    /// one it was set on.
    #[test]
    fn of_two_like_bounds_in_one_second_the_lower_key_decides() {
        let s = devices(2);
        let t = s.now + MINUTE;
        allows(&s, 0, Some(20), 3600, t);
        allows(&s, 1, Some(20), 3600, t);
        hears(&s, 0, 1, t + 1);
        hears(&s, 1, 0, t + 1);
        let lower = s.key(0).min(s.key(1));
        for n in [0, 1] {
            match in_force_on(&s, n, t + 2) {
                InForce::Set { bound, on, .. } => {
                    assert_eq!(bound, Some(20));
                    assert_eq!(on, lower, "device {n}");
                }
                other => panic!("{other:?}"),
            }
        }
    }

    /// The list of bounds counts its writes again apart from the list of a
    /// person's reads (decision 2026-10-25, rules 1 and 2): once the
    /// person's list has been written again three times in a row for a
    /// relay's answers, the list of bounds is written again for its own,
    /// three times, and then the person's list writes no fourth.
    #[test]
    fn the_list_of_bounds_counts_its_writes_again_apart() {
        use crate::at_relays::{Kind, Pushed};
        let s = devices(2);
        let t = s.now + MINUTE;
        allows(&s, 0, Some(20), 3600, t);
        // A person here read what it sent.
        sends(&s, 0, "notes", "work", t).unwrap();
        s[0].conn
            .execute(
                "INSERT INTO message_read_by_a_person (id) SELECT id FROM message_index",
                [],
            )
            .unwrap();
        crate::marks::write_person_list(&s[0].conn, &s[0].identity, t, true).unwrap();
        let channels = crate::at_relays::channels(&s[0].conn, &s[0].identity).unwrap();
        let channel = channels
            .iter()
            .find(|own| own.kind == Kind::Messages)
            .unwrap();
        let slot_of = |name: String| {
            let secret = secret_of(&s, 0);
            slot_id(&derive::slot_key(&secret).unwrap(), &name)
        };
        let newest = |name: String| {
            let secret = secret_of(&s, 0);
            entries::author_entry(
                &s[0].conn,
                &derive::channel_id(&secret).unwrap(),
                &slot_of(name),
                &s.key(0),
            )
            .unwrap()
            .unwrap()
            .entry
        };
        let person = || newest(message::person_name(&s.key(0)).unwrap());
        let bounds = || newest(message::hold_name(&s.key(0)).unwrap());
        let another = |entry: Entry| {
            crate::marks::answered(
                &s[0].conn,
                &s[0].identity,
                channel,
                std::slice::from_ref(&entry),
                &[Pushed::HoldsAnother],
                t,
                true,
            )
            .unwrap();
        };
        for _ in 0..4 {
            another(person());
        }
        assert_eq!(person().rev, 4);
        for _ in 0..4 {
            another(bounds());
        }
        assert_eq!(bounds().rev, 4);
        another(person());
        assert_eq!(person().rev, 4);
    }

    /// A clock ahead gains nothing (decision 2026-10-25, rule 3.3): the
    /// desktop's clock an hour ahead sets 20 for an hour; on the laptop it
    /// ends an hour after the laptop first held it, and does so across
    /// the desktop's next list, which keeps when the laptop first held it.
    #[test]
    fn a_clock_ahead_gains_nothing() {
        let s = devices(2);
        let t = s.now + MINUTE;
        allows(&s, 1, Some(20), 3600, t + HOUR);
        hears(&s, 1, 0, t + 10);
        assert_eq!(stops_on(&s, 0, t + 10), Some(20));
        assert_eq!(stops_on(&s, 0, t + 10 + HOUR - 1), Some(20));
        assert_eq!(stops_on(&s, 0, t + 10 + HOUR), Some(10));
        // The desktop sets another pair: its list is written again, and
        // the laptop keeps when it first held the first.
        let other = Pair::of("plans", Some("work"));
        allows_pair(&s, 1, &other, Some(5), 3600, t + HOUR + 20);
        hears(&s, 1, 0, t + 30 * MINUTE);
        assert_eq!(listed(&s, 1).len(), 2);
        assert_eq!(stops_on(&s, 0, t + 10 + HOUR), Some(10));
        assert_eq!(stops_on(&s, 0, t + 10 + HOUR - 1), Some(20));
    }

    /// A clock a year ahead lists seven days and holds nothing new on a
    /// device that was off (decision 2026-10-25, rules 3.1, 3.3 and 3.5):
    /// the desktop, its clock a year ahead, sets any; the laptop, having
    /// heard of it, sets 20, whose `set` is a year ahead and whose `at` is
    /// now; each is listed 7 days and 10 minutes by its own clock; and a
    /// third device that comes back after three weeks holds neither.
    #[test]
    fn a_clock_a_year_ahead_lists_seven_days_and_holds_nothing_new_on_a_device_that_was_off() {
        let s = devices(3);
        let t = s.now + MINUTE;
        let year = 365 * DAY;
        allows(&s, 1, None, 7 * 24 * 3600, t + year);
        hears(&s, 1, 0, t + 1);
        allows(&s, 0, Some(20), 7 * 24 * 3600, t + 2);
        let twenty = listed(&s, 0)[0].clone();
        assert_eq!(twenty.set, (t + year) as u64 + 1);
        assert_eq!(twenty.at, (t + 2) as u64);
        let listed_secs = AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS as i64;
        // Each by its own clock.
        assert_eq!(lists(&s, 0, t + 2 + listed_secs - 1), None);
        assert_eq!(listed(&s, 0).len(), 1);
        lists(&s, 0, t + 2 + listed_secs);
        assert!(listed(&s, 0).is_empty());
        assert_eq!(lists(&s, 1, t + year + listed_secs - 1), None);
        assert_eq!(listed(&s, 1).len(), 1);
        lists(&s, 1, t + year + listed_secs);
        assert!(listed(&s, 1).is_empty());
        // The third device comes back after three weeks: neither holds.
        hears(&s, 0, 2, t + 21 * DAY);
        hears(&s, 1, 2, t + 21 * DAY);
        assert_eq!(stops_on(&s, 2, t + 21 * DAY), Some(10));
        assert!(kept(held::bounds(&s[2].conn)).unwrap().is_empty());
    }

    /// A `set` at the top of its field ties (decision 2026-10-25, rule
    /// 3.1): a key lists any with `set` at the top; the laptop's later 10's
    /// `set` stays there, and the 10 decides.
    #[test]
    fn a_set_at_the_top_of_its_field_ties() {
        let s = devices(2);
        let t = s.now + MINUTE;
        let any = PairBounds {
            bounds: vec![PairBound {
                a: "notes".into(),
                b: Some("work".into()),
                bound: None,
                set: u64::MAX,
                at: t as u64,
                for_secs: 3600,
            }],
        };
        let value = any.to_value(crate::names::is_a_name).unwrap();
        let entry = Entry::seal(
            &secret_of(&s, 1),
            &s[1].identity,
            1,
            &message::inside(message::hold_name(&s.key(1)).unwrap(), value),
        )
        .unwrap()
        .check()
        .unwrap();
        take(&s[0].conn, &s[0].identity, &entry, t).unwrap();
        assert_eq!(stops_on(&s, 0, t + 1), None);
        allows(&s, 0, Some(10), 3600, t + 2);
        assert_eq!(listed(&s, 0)[0].set, u64::MAX);
        assert_eq!(stops_on(&s, 0, t + 3), Some(10));
    }

    /// A bound that ends holds a pair over 10 at once (decision 2026-10-25,
    /// rule 3.4): under 20, twelve wait unread and a send goes; once the
    /// 20 has ended, the next send is refused at once.
    #[test]
    fn a_bound_that_ends_holds_a_pair_over_10_at_once() {
        let s = devices(2);
        let t = s.now + MINUTE;
        allows(&s, 0, Some(20), 3600, t);
        for k in 0..12 {
            sends(&s, 0, "notes", "work", t + k).unwrap();
        }
        assert_eq!(
            waiting(
                &s[0].conn,
                &pair(),
                t + 20,
                &who_counts(&s[0].conn).unwrap()
            )
            .unwrap(),
            12
        );
        sends(&s, 0, "work", "notes", t + 20).unwrap();
        match sends(&s, 0, "work", "notes", t + HOUR) {
            Err(NotSent::Refused(Refused::PairHeld { waiting, bound, .. })) => {
                assert_eq!((waiting, bound), (13, 10));
            }
            other => panic!("{other:?}"),
        }
    }

    /// A bound set while a pair is held (decision 2026-10-25, hard case 2):
    /// raised above the count, a send goes at once and nothing is marked
    /// read; lowered to the count, a send is refused at once.
    #[test]
    fn a_bound_set_while_a_pair_is_held() {
        let s = devices(2);
        let t = s.now + MINUTE;
        for k in 0..10 {
            sends(&s, 0, "notes", "work", t + k).unwrap();
        }
        assert!(matches!(
            sends(&s, 0, "notes", "work", t + 10),
            Err(NotSent::Refused(Refused::PairHeld { .. }))
        ));
        let allowed = allows(&s, 0, Some(20), 3600, t + 11);
        assert_eq!(allowed.waiting, 10);
        assert_eq!(allowed.was, InForce::Usual);
        sends(&s, 0, "notes", "work", t + 12).unwrap();
        let read: i64 = s[0]
            .conn
            .query_row("SELECT COUNT(*) FROM message_read_by_a_person", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(read, 0);
        allows(&s, 0, Some(11), 3600, t + 13);
        match sends(&s, 0, "notes", "work", t + 14) {
            Err(NotSent::Refused(Refused::PairHeld { waiting, bound, .. })) => {
                assert_eq!((waiting, bound), (11, 11));
            }
            other => panic!("{other:?}"),
        }
    }

    /// A bound stays listed for seven days and ten minutes after its `at`,
    /// by its own clock, and then leaves the list, which is written again
    /// (decision 2026-10-25, rule 3.5).
    #[test]
    fn a_bound_stays_listed_for_seven_days_and_ten_minutes() {
        let s = devices(2);
        let t = s.now + MINUTE;
        let allowed = allows(&s, 0, Some(20), 3600, t);
        assert_eq!(allowed.list, Some(1));
        let listed_secs = AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS as i64;
        assert_eq!(listed_secs, 7 * DAY + 10 * MINUTE);
        assert_eq!(lists(&s, 0, t + listed_secs - 1), None);
        assert_eq!(listed(&s, 0).len(), 1);
        assert_eq!(lists(&s, 0, t + listed_secs), Some(2));
        assert!(listed(&s, 0).is_empty());
        assert!(kept(held::bounds(&s[0].conn)).unwrap().is_empty());
        assert_eq!(lists(&s, 0, t + listed_secs + 1), None);
    }

    /// A statement ends every bound (decision 2026-10-25, rule 3.7): a
    /// renewal, and a removal; each device drops every row, its own and
    /// the others', in the transaction that applies it, and writes no list
    /// in the new generation until one is set again.
    #[test]
    fn a_statement_ends_every_bound() {
        for removes in [false, true] {
            let mut s = devices(3);
            let t = s.now + MINUTE;
            allows(&s, 0, Some(20), 3600, t);
            allows_pair(&s, 1, &Pair::of("plans", None), None, 3600, t);
            hears(&s, 0, 1, t + 1);
            hears(&s, 1, 0, t + 1);
            assert_eq!(kept(held::bounds(&s[1].conn)).unwrap().len(), 2);
            match removes {
                false => s.change(0, &[0, 1, 2], &[]),
                true => s.change(0, &[0, 1], &[2]),
            };
            let stay: Vec<usize> = if removes { vec![0, 1] } else { vec![0, 1, 2] };
            s.meet(&stay);
            for n in [0, 1] {
                assert_eq!(s[n].number(), 2);
                assert!(kept(held::bounds(&s[n].conn)).unwrap().is_empty(), "{n}");
                assert_eq!(stops_on(&s, n, t + 2), Some(10));
                assert_eq!(lists(&s, n, t + 2), None);
                assert!(list_of(&s, n).is_none());
            }
            allows(&s, 0, Some(15), 3600, t + 3);
            assert_eq!(listed(&s, 0).len(), 1);
        }
    }

    /// A bound from a key that no longer counts says nothing (decision
    /// 2026-10-25, rule 3.8): it stops holding at once.
    #[test]
    fn a_bound_from_a_key_that_no_longer_counts_says_nothing() {
        let s = devices(2);
        let t = s.now + MINUTE;
        let row = BoundRow {
            key: [0x99; 32],
            pair: pair(),
            bound: None,
            set: u64::MAX,
            at: t as u64,
            for_secs: 3600,
            first_held: t,
            start: None,
        };
        held::put_bound(&s[0].conn, &row).unwrap();
        assert_eq!(stops_on(&s, 0, t + 1), Some(10));
        // The control: under a key that counts, it holds.
        held::put_bound(
            &s[0].conn,
            &BoundRow {
                key: s.key(1),
                ..row
            },
        )
        .unwrap();
        assert_eq!(stops_on(&s, 0, t + 1), None);
    }

    /// A pass asks in full whether the list of bounds is due only where
    /// what decides it changed since a pass that changed nothing, or once
    /// one of the device's own bounds reaches the time it leaves the list
    /// (issue #221): ten passes ask nothing; a second bound set here, and
    /// another device's list taken, are each asked once; and at the second
    /// a bound leaves the list it is asked, and the list written without it.
    #[test]
    fn the_list_of_bounds_is_asked_again_only_where_what_decides_it_changed() {
        let s = devices(2);
        let t = s.now;
        allows(&s, 0, Some(20), 2 * HOUR as u32, t);
        let asked = std::cell::Cell::new(0);
        let pass = |seen: &mut crate::marks::ListsSeen, now: i64| {
            let write = |fetched: bool| {
                asked.set(asked.get() + 1);
                write_bounds_list(&s[0].conn, &s[0].identity, now, fetched)
            };
            seen.where_changed(
                &s[0].conn,
                &s.key(0),
                PersonList::Bounds,
                now,
                |_| true,
                write,
            )
            .unwrap()
        };
        let mut seen = crate::marks::ListsSeen::default();
        pass(&mut seen, t + 1);
        pass(&mut seen, t + 2);
        let warm = asked.get();
        assert!(warm <= 2);
        let changes = s[0].conn.total_changes();
        for i in 0..10 {
            assert_eq!(pass(&mut seen, t + 3 + i), None);
        }
        assert_eq!(asked.get(), warm, "nothing changed: nothing is asked");
        assert_eq!(s[0].conn.total_changes(), changes);

        // A bound set here for another pair.
        allows_pair(
            &s,
            0,
            &Pair::of("plans", None),
            Some(30),
            HOUR as u32,
            t + 20,
        );
        assert_eq!(pass(&mut seen, t + 21), None);
        assert_eq!(asked.get(), warm + 1);
        assert_eq!(pass(&mut seen, t + 22), None);
        assert_eq!(asked.get(), warm + 1);

        // Another device's list, for a pair this device has no bound of.
        allows_pair(&s, 1, &Pair::of("work", None), Some(5), HOUR as u32, t + 30);
        hears(&s, 1, 0, t + 31);
        assert_eq!(pass(&mut seen, t + 32), None);
        assert_eq!(asked.get(), warm + 2);

        // The first of its own bounds to leave the list: asked once that
        // time comes, and written without it.
        let own = s.key(0);
        let leaves = kept(held::bounds(&s[0].conn))
            .unwrap()
            .iter()
            .filter(|row| row.key == own)
            .map(listed_until)
            .min()
            .unwrap();
        assert_eq!(pass(&mut seen, leaves - 1), None);
        assert_eq!(asked.get(), warm + 2);
        assert_eq!(listed(&s, 0).len(), 2);
        assert!(pass(&mut seen, leaves).is_some());
        assert_eq!(asked.get(), warm + 3);
        assert_eq!(listed(&s, 0).len(), 1);
    }
}
