//! The person's lists of shared channels, in the personal channel
//! (decision 2026-10-10 §3.4, §3.5).
//!
//! Each device writes one list, under `shared/` and its key: the
//! channels the person files, the drops, the subscriptions and the
//! labels, each an act signed by the device that made it
//! ([`cordelia_crypto::acts`]). What a device holds is its own list, and
//! what it left out of it past a bound; it keeps them beside the entry
//! (`cordelia_storage::shared_lists`), and writes its list whenever it
//! changes.
//!
//! - **An act** ([`act`]) is dated one above what the device holds of the
//!   item, and above every act and fetched time of a key that counts,
//!   each taken as at most 90 days ahead of its clock; at
//!   `SHARED_ACT_TIME_MAX` its count goes above the highest held there
//!   ([`dated`]). It is put in the device's own list, and the list is
//!   written at once.
//! - **At a whole fetch** of the personal channel ([`fetched_whole`]) a
//!   device whose own list is not fresh takes out what it held then and
//!   another device's fresh list has since let go ([`come_back`]); it
//!   then takes, for each item, the newest act among its own list and
//!   the fresh lists of its person's other devices that count
//!   ([`take_lists`]), frees an undone act 90 days after it first held it,
//!   keeps each part within its bound, and writes its list where what it
//!   holds changed, where 30 days have passed since it last wrote it, or
//!   where the fetched time it last wrote is ahead of its clock.
//! - **Which act is in force** is decided by the statement and the
//!   records of addition alone ([`Makers`]): an act whose maker counts,
//!   or is a key the statement lists as removed, is in force; one whose
//!   maker this device counted and a statement left in no list is held
//!   and not in force; one of any other key is not taken at all.
//! - **A recovery** reads the lists of the devices it shows, fresh by the
//!   newest fetched time among them ([`recovered`]).
//!
//! Plain functions over the node's database and the device's own key.
//! Nothing here sends anything: what is written waits in the store, and
//! the node sends it.

use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::Connection;

use cordelia_core::protocol::{
    KEYED_TOMBSTONE_RETENTION_DAYS, SHARED_ACT_TIME_MAX, SHARED_MAX_CHANNELS, SHARED_MAX_DROPPED,
    SHARED_MAX_LABELS, SHARED_MAX_SUBSCRIPTIONS, SHARED_WORDS_WRITTEN_AGAIN_DAYS,
};
use cordelia_core::revision::{band, next_under};
use cordelia_crypto::acts::{
    Act, Dropped, Filing, Item, Label, ListError, SharedList, Subscription, list_name,
};
use cordelia_crypto::derive;
use cordelia_crypto::entry::{CheckedEntry, Entry, Inside, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::slots::slot_id;
use cordelia_storage::entries;
use cordelia_storage::shared_lists::{self as kept_rows, FirstHeld, Freed, Kept, Part};

use crate::names::is_a_name;
use crate::person::{Counting, PersonError, in_one};
use crate::publish::Standing;

/// How long a list stays fresh, an undone act is held before it is freed,
/// and how far ahead of the device's clock another act's time is taken in
/// dating (decision 2026-10-10 §3.4).
const KEPT_SECS: i64 = KEYED_TOMBSTONE_RETENTION_DAYS as i64 * 24 * 60 * 60;

/// How long after a device last wrote its list it writes it again at a
/// whole fetch, where nothing else has changed (§3.4).
const WRITTEN_AGAIN_SECS: i64 = SHARED_WORDS_WRITTEN_AGAIN_DAYS as i64 * 24 * 60 * 60;

/// What an act's maker is to this device (decision 2026-10-10 §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Maker {
    /// A device of the person's that counts.
    Counts,
    /// A key that the person's statement lists as removed: its acts are
    /// in force, and named with what undoes them (§3.5).
    Removed,
    /// A key that this device counted, and that a statement since lists
    /// neither as a device nor as removed (a settlement, or a recovery):
    /// its acts are held, and not in force.
    InNoList,
}

impl Maker {
    /// Whether an act of this maker is in force.
    pub fn in_force(self) -> bool {
        self != Maker::InNoList
    }
}

/// Who the makers are, by the statement the device has applied, the
/// records of addition it keeps and the keys a statement left out, and
/// nothing else (§3.4): two devices that hold the same take the same acts.
pub struct Makers {
    counting: Counting,
    removed: Vec<[u8; 32]>,
    left_out: Vec<[u8; 32]>,
}

impl Makers {
    fn of(conn: &Connection, standing: &Standing) -> Result<Self, PersonError> {
        let left_out = cordelia_storage::acts::left_out(conn)?;
        Ok(Self {
            counting: standing.counting.clone(),
            removed: standing.held.statement.statement.removed.clone(),
            left_out: left_out.into_iter().map(|left| left.key).collect(),
        })
    }

    /// What `key` is as a maker: `None` where it is none of the three, a
    /// key that was never a device of the person's as this device knows
    /// them, whose acts are not taken at all.
    pub fn maker(&self, key: &[u8; 32]) -> Option<Maker> {
        if self.counting.counts(key) {
            Some(Maker::Counts)
        } else if self.removed.contains(key) {
            Some(Maker::Removed)
        } else if self.left_out.contains(key) {
            Some(Maker::InNoList)
        } else {
            None
        }
    }

    /// Where a maker stands past a bound: those that count first, then
    /// removed keys, then those not in force.
    fn rank(&self, key: &[u8; 32]) -> u8 {
        match self.maker(key) {
            Some(Maker::Counts) => 0,
            Some(Maker::Removed) => 1,
            Some(Maker::InNoList) => 2,
            None => 3,
        }
    }
}

/// What each act's check gave ([`AnyAct::holds`]), by its bytes as a list
/// writes them: an act that many lists carry is checked once.
#[derive(Default)]
struct Checked(RefCell<HashMap<Vec<u8>, bool>>);

impl Checked {
    /// Whether `act` may be taken: its maker is one of the person's as
    /// [`Makers`] knows them, and it holds.
    fn takes(&self, act: &AnyAct, makers: &Makers) -> bool {
        makers.maker(&act.maker()).is_some()
            && *self
                .0
                .borrow_mut()
                .entry(act.written())
                .or_insert_with(|| act.holds())
    }
}

/// An act of any kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyAct {
    Filing(Act<Filing>),
    Drop(Act<Dropped>),
    Subscription(Act<Subscription>),
    Label(Act<Label>),
}

/// An item: what it is within, and the bytes that name it there.
type Key = (Part, Vec<u8>);

impl AnyAct {
    /// The item the act is on. A filing and a drop of one channel are one
    /// item.
    pub fn key(&self) -> (Part, Vec<u8>) {
        match self {
            AnyAct::Filing(act) => (Part::Channel, act.item.item()),
            AnyAct::Drop(act) => (Part::Channel, act.item.item()),
            AnyAct::Subscription(act) => (Part::Subscription, act.item.item()),
            AnyAct::Label(act) => (Part::Label, act.item.item()),
        }
    }

    /// The act's time, its count, its maker's key and its signature.
    fn fields(&self) -> (u64, u64, [u8; 32], [u8; 64]) {
        match self {
            AnyAct::Filing(a) => (a.time, a.count, a.maker, a.signature),
            AnyAct::Drop(a) => (a.time, a.count, a.maker, a.signature),
            AnyAct::Subscription(a) => (a.time, a.count, a.maker, a.signature),
            AnyAct::Label(a) => (a.time, a.count, a.maker, a.signature),
        }
    }

    pub fn time(&self) -> u64 {
        self.fields().0
    }

    pub fn count(&self) -> u64 {
        self.fields().1
    }

    pub fn maker(&self) -> [u8; 32] {
        self.fields().2
    }

    fn signature(&self) -> [u8; 64] {
        self.fields().3
    }

    /// Whether it may be taken for what it says: its maker's signature
    /// holds, its time and its count are within the bound, and its fields
    /// agree ([`Act::holds`]).
    pub fn holds(&self) -> bool {
        match self {
            AnyAct::Filing(a) => a.holds(),
            AnyAct::Drop(a) => a.holds(),
            AnyAct::Subscription(a) => a.holds(),
            AnyAct::Label(a) => a.holds(),
        }
    }

    /// The act as a list writes it.
    fn written(&self) -> Vec<u8> {
        let written = match self {
            AnyAct::Filing(a) => a.written(),
            AnyAct::Drop(a) => a.written(),
            AnyAct::Subscription(a) => a.written(),
            AnyAct::Label(a) => a.written(),
        };
        // An act that was read from a list, or made, is written again.
        written.unwrap_or_default()
    }

    /// Whether it undoes: a drop, an unsubscription or a removed label,
    /// which frees its place 90 days after a device first held it (§3.4).
    pub fn undone(&self) -> bool {
        match self {
            AnyAct::Filing(_) => false,
            AnyAct::Drop(_) => true,
            AnyAct::Subscription(a) => !a.item.subscribed,
            AnyAct::Label(a) => a.item.label.is_none(),
        }
    }
}

/// What orders two acts on one item, the greater above (decision
/// 2026-10-10 §3.4): the time; then whether the maker counts; then, at
/// `SHARED_ACT_TIME_MAX` alone, the item's count; then the maker's key;
/// and last the act's bytes as a list writes them, so that two acts that
/// agree in all else are ordered alike on every device.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Order {
    time: u64,
    counts: bool,
    count: u64,
    maker: [u8; 32],
    written: Vec<u8>,
}

impl Order {
    fn of(time: u64, count: u64, maker: [u8; 32], written: Vec<u8>, makers: &Makers) -> Self {
        Self {
            time,
            counts: makers.maker(&maker) == Some(Maker::Counts),
            count: if time == SHARED_ACT_TIME_MAX {
                count
            } else {
                0
            },
            maker,
            written,
        }
    }

    fn of_act(act: &AnyAct, makers: &Makers) -> Self {
        Self::of(act.time(), act.count(), act.maker(), act.written(), makers)
    }

    fn of_freed(freed: &Freed, makers: &Makers) -> Self {
        Self::of(
            freed.time,
            freed.count,
            freed.maker,
            freed.act.clone(),
            makers,
        )
    }
}

/// Every act of a list, of every part.
fn acts_of(list: &SharedList) -> Vec<AnyAct> {
    let mut acts: Vec<AnyAct> = Vec::new();
    acts.extend(list.filings.iter().cloned().map(AnyAct::Filing));
    acts.extend(list.drops.iter().cloned().map(AnyAct::Drop));
    acts.extend(list.subscriptions.iter().cloned().map(AnyAct::Subscription));
    acts.extend(list.labels.iter().cloned().map(AnyAct::Label));
    acts
}

/// A list of `acts`, each part in order of item, so that two lists that
/// hold the same acts are the same bytes.
fn list_of(acts: impl IntoIterator<Item = AnyAct>, fetched: u64) -> SharedList {
    let mut acts: Vec<AnyAct> = acts.into_iter().collect();
    acts.sort_by_key(AnyAct::key);
    let mut list = SharedList {
        fetched,
        ..SharedList::default()
    };
    for act in acts {
        match act {
            AnyAct::Filing(a) => list.filings.push(a),
            AnyAct::Drop(a) => list.drops.push(a),
            AnyAct::Subscription(a) => list.subscriptions.push(a),
            AnyAct::Label(a) => list.labels.push(a),
        }
    }
    list
}

/// Whether two lists hold the same acts, whatever their fetched times.
fn same_acts(one: &SharedList, other: &SharedList) -> bool {
    list_of(acts_of(one), 0) == list_of(acts_of(other), 0)
}

/// What a device holds of its person's lists: its own list and what it
/// left out, when it wrote and fetched, when it first held each act, and
/// the acts it freed.
#[derive(Debug, Clone, Default)]
struct Lists {
    list: SharedList,
    left_out: SharedList,
    written_at: Option<i64>,
    fetched_at: Option<i64>,
    first_held: BTreeMap<Key, ([u8; 64], i64)>,
    freed: BTreeMap<Key, Freed>,
}

fn not_held(what: &str, e: ListError) -> PersonError {
    PersonError::Held(format!("{what}: {e}"))
}

impl Lists {
    fn load(conn: &Connection) -> Result<Self, PersonError> {
        let mut lists = Lists::default();
        if let Some(kept) = kept_rows::kept(conn)? {
            let read = |bytes: Vec<u8>, what: &str| {
                SharedList::from_value(&Value::Other(bytes), is_a_name)
                    .map_err(|e| not_held(what, e))
            };
            lists.list = read(kept.list, "the list this device keeps")?;
            lists.left_out = read(kept.left_out, "what this device left out of its list")?;
            lists.written_at = kept.written_at;
            lists.fetched_at = kept.fetched_at;
        }
        for held in kept_rows::first_held(conn)? {
            lists
                .first_held
                .insert((held.part, held.item), (held.signature, held.first_held));
        }
        for freed in kept_rows::freed(conn)? {
            lists.freed.insert((freed.part, freed.item.clone()), freed);
        }
        Ok(lists)
    }

    fn save(&self, conn: &Connection) -> Result<(), PersonError> {
        let value =
            |list: &SharedList, what: &str| list.to_value(is_a_name).map_err(|e| not_held(what, e));
        kept_rows::keep(
            conn,
            &Kept {
                list: value(&self.list, "the list this device keeps")?,
                left_out: value(&self.left_out, "what this device left out")?,
                written_at: self.written_at,
                fetched_at: self.fetched_at,
            },
        )?;
        let held: Vec<FirstHeld> = self
            .first_held
            .iter()
            .map(|((part, item), (signature, first_held))| FirstHeld {
                part: *part,
                item: item.clone(),
                signature: *signature,
                first_held: *first_held,
            })
            .collect();
        kept_rows::keep_first_held(conn, &held)?;
        for freed in kept_rows::freed(conn)? {
            if !self.freed.contains_key(&(freed.part, freed.item.clone())) {
                kept_rows::let_go(conn, freed.part, &freed.item)?;
            }
        }
        for freed in self.freed.values() {
            kept_rows::keep_freed(conn, freed)?;
        }
        Ok(())
    }

    /// Every act the device holds: its list's, and what it left out.
    fn held(&self) -> Vec<AnyAct> {
        let mut held = acts_of(&self.list);
        held.extend(acts_of(&self.left_out));
        held
    }

    /// When the device first held the act it holds on `key`, where it
    /// holds that act.
    fn first_held_of(&self, act: &AnyAct) -> Option<i64> {
        let (signature, at) = self.first_held.get(&act.key())?;
        (*signature == act.signature()).then_some(*at)
    }

    /// Whether its own list is fresh to itself at `now`: it wrote it less
    /// than 90 days before, and the fetched time it wrote, taken as no
    /// later than its clock, is less than 90 days behind it.
    fn own_is_fresh(&self, now: i64) -> bool {
        self.written_at
            .is_some_and(|written| is_fresh(written, self.list.fetched, now))
    }
}

/// Whether a list first held at `first_held` and saying `fetched` is fresh
/// to a reader at `now` (§3.4): both less than 90 days behind its clock.
/// A fetched time is taken as no later than the clock: one ahead of it is
/// behind it by nothing. A fetched time is at most `SHARED_ACT_TIME_MAX`,
/// which a list's reader refuses past.
fn is_fresh(first_held: i64, fetched: u64, now: i64) -> bool {
    let fetched = i64::try_from(fetched).unwrap_or(i64::MAX);
    now - first_held < KEPT_SECS && now - fetched < KEPT_SECS
}

/// The list of another device of the person's, as this device's store
/// holds it.
#[derive(Debug, Clone)]
struct Read {
    writer: [u8; 32],
    list: SharedList,
    /// When this device first held the list, at the revision it holds.
    first_held: i64,
}

impl Read {
    fn is_fresh(&self, now: i64) -> bool {
        is_fresh(self.first_held, self.list.fetched, now)
    }

    /// Whether the list holds an act on `key`.
    fn carries(&self, key: &Key) -> bool {
        acts_of(&self.list).iter().any(|act| act.key() == *key)
    }
}

/// The list of each other device of the person's that counts, as this
/// device's store holds it in the personal channel of the generation
/// applied: that device's own entry under its own list's name, and no
/// other's (§3.4). One that is a delete, in a band above the statement's,
/// does not open or is no list is passed over.
fn lists_held(
    conn: &Connection,
    standing: &Standing,
    own: &[u8; 32],
) -> Result<Vec<Read>, PersonError> {
    let personal = derive::personal_secret(&standing.secret)?;
    let channel = derive::channel_id(&personal)?;
    let slot_key = derive::slot_key(&personal)?;
    let mut read = Vec::new();
    for writer in standing.counting.keys() {
        if writer == *own {
            continue;
        }
        let name = list_name(&writer)?;
        let slot = slot_id(&slot_key, &name);
        let Some(held) = entries::author_entry(conn, &channel, &slot, &writer)? else {
            continue;
        };
        let Ok(entry) = held.entry.check() else {
            continue;
        };
        if band(entry.rev) > standing.number() {
            continue;
        }
        // An entry opens only in the slot of its name. A delete holds no
        // list.
        let Ok(inside) = entry.open(&personal) else {
            continue;
        };
        if let Ok(list) = SharedList::from_value(&inside.value, is_a_name) {
            read.push(Read {
                writer,
                list,
                first_held: held.stored_at,
            });
        }
    }
    Ok(read)
}

/// Of `candidates` on one item, the newest that may be taken, by
/// [`Order`]: each is checked only until one is.
fn newest_taken(
    candidates: Vec<AnyAct>,
    makers: &Makers,
    checked: &Checked,
) -> Option<(AnyAct, Order)> {
    let mut ordered: Vec<(Order, AnyAct)> = candidates
        .into_iter()
        .map(|act| (Order::of_act(&act, makers), act))
        .collect();
    ordered.sort_by(|a, b| b.0.cmp(&a.0));
    ordered.dedup_by(|a, b| a.0 == b.0);
    ordered
        .into_iter()
        .find(|(_, act)| checked.takes(act, makers))
        .map(|(order, act)| (act, order))
}

/// Where each act goes once each part is kept within its bound (§3.4):
/// in the list, left out, or freed before its 90 days (a drop past 64).
struct Bounded {
    list: Vec<AnyAct>,
    left_out: Vec<AnyAct>,
    freed_early: Vec<AnyAct>,
}

/// Keep each part of `chosen`, one act for each item, within its bound
/// (§3.4, "past a bound"): the items whose makers count first, then those
/// of removed keys, then those not in force; within each, of
/// subscriptions and labels, the undone items first; then the newest
/// first. A filing, a
/// subscription or a label past its bound is left out, up to as many
/// again; a drop past 64 is freed.
fn within_bounds(chosen: Vec<AnyAct>, makers: &Makers) -> Bounded {
    let mut bounded = Bounded {
        list: Vec::new(),
        left_out: Vec::new(),
        freed_early: Vec::new(),
    };
    // Each part: which acts are of it, its bound, and whether an act past
    // it is freed rather than left out.
    type OfPart = fn(&AnyAct) -> bool;
    let parts: [(OfPart, usize, bool); 4] = [
        (
            |act| matches!(act, AnyAct::Filing(_)),
            SHARED_MAX_CHANNELS,
            false,
        ),
        (
            |act| matches!(act, AnyAct::Drop(_)),
            SHARED_MAX_DROPPED,
            true,
        ),
        (
            |act| matches!(act, AnyAct::Subscription(_)),
            SHARED_MAX_SUBSCRIPTIONS,
            false,
        ),
        (
            |act| matches!(act, AnyAct::Label(_)),
            SHARED_MAX_LABELS,
            false,
        ),
    ];
    for (of_part, most, freed_past) in parts {
        let mut acts: Vec<&AnyAct> = chosen.iter().filter(|act| of_part(act)).collect();
        acts.sort_by_cached_key(|act| {
            (
                makers.rank(&act.maker()),
                !act.undone(),
                Reverse(Order::of_act(act, makers)),
            )
        });
        for (at, act) in acts.into_iter().enumerate() {
            match (at < most, freed_past, at < 2 * most) {
                (true, _, _) => bounded.list.push(act.clone()),
                (false, true, _) => bounded.freed_early.push(act.clone()),
                (false, false, true) => bounded.left_out.push(act.clone()),
                (false, false, false) => {}
            }
        }
    }
    bounded
}

/// The newest act on each item among `acts`, as a device takes them
/// (§3.4): an act whose maker is one of the person's and that holds, and
/// an undone act (a drop, an unsubscription, a removed label) only of an
/// item that an act among them does, or that `held_items` names. `above`
/// gives, for an item, what an act must order above to be taken. One act
/// for each item.
fn newest_of_each(
    acts: impl IntoIterator<Item = AnyAct>,
    held_items: &BTreeSet<Key>,
    above: impl Fn(&Key) -> Option<Order>,
    makers: &Makers,
    checked: &Checked,
) -> Vec<AnyAct> {
    let mut by_item: BTreeMap<Key, Vec<AnyAct>> = BTreeMap::new();
    for act in acts {
        by_item.entry(act.key()).or_default().push(act);
    }
    // An undo of what nobody did is not taken: a device in someone else's
    // hands cannot fill the person's places, or push out the person's
    // drops, with undoes of items that were never there (§3.4).
    let done: BTreeSet<Key> = by_item
        .iter()
        .filter(|(_, acts)| {
            acts.iter()
                .any(|act| !act.undone() && checked.takes(act, makers))
        })
        .map(|(key, _)| key.clone())
        .collect();
    let mut chosen = Vec::new();
    for (key, acts) in by_item {
        let floor = above(&key);
        let candidates: Vec<AnyAct> = acts
            .into_iter()
            .filter(|act| !act.undone() || done.contains(&key) || held_items.contains(&key))
            .filter(|act| {
                floor
                    .as_ref()
                    .is_none_or(|floor| Order::of_act(act, makers) > *floor)
            })
            .collect();
        if let Some((act, _)) = newest_taken(candidates, makers, checked) {
            chosen.push(act);
        }
    }
    chosen
}

/// Take the lists of the person's other devices (§3.4): for each item,
/// the newest act among the device's own list, what it left out, and the
/// lists of `others` that are fresh to it at `now`. An act it freed holds
/// back every act on its item that orders at or below it, while a fresh
/// list carries the item; once none does, it is let go. An undone act
/// that the device first held 90 days before is freed. Each part is kept
/// within its bound.
fn take_lists(lists: &mut Lists, others: &[Read], makers: &Makers, now: i64) {
    let fresh: Vec<&Read> = others.iter().filter(|read| read.is_fresh(now)).collect();
    let mut candidates = lists.held();
    for read in &fresh {
        candidates.extend(acts_of(&read.list));
    }
    let held_items: BTreeSet<Key> = lists
        .held()
        .iter()
        .map(AnyAct::key)
        .chain(lists.freed.keys().cloned())
        .collect();
    let freed = &lists.freed;
    let above = |key: &Key| freed.get(key).map(|freed| Order::of_freed(freed, makers));
    let chosen = newest_of_each(candidates, &held_items, above, makers, &Checked::default());

    // The act now held on each item keeps its first holding where it is
    // the act held before; another act on the item is first held now.
    let mut first_held = BTreeMap::new();
    let mut kept = Vec::new();
    for act in chosen {
        let at = lists.first_held_of(&act).unwrap_or(now);
        if act.undone() && now - at >= KEPT_SECS {
            free(lists, &act, now);
            continue;
        }
        first_held.insert(act.key(), (act.signature(), at));
        kept.push(act);
    }
    let bounded = within_bounds(kept, makers);
    for act in &bounded.freed_early {
        free(lists, act, now);
        first_held.remove(&act.key());
    }
    let left: BTreeSet<Key> = bounded
        .list
        .iter()
        .chain(&bounded.left_out)
        .map(AnyAct::key)
        .collect();
    first_held.retain(|key, _| left.contains(key));
    lists.first_held = first_held;
    lists.list = list_of(bounded.list, lists.list.fetched);
    lists.left_out = list_of(bounded.left_out, 0);

    // An act freed is kept while a fresh list carries its item, the
    // device's own among them; once none does, it is let go.
    let carried: BTreeSet<Key> = fresh
        .iter()
        .flat_map(|read| acts_of(&read.list))
        .chain(lists.held())
        .map(|act| act.key())
        .collect();
    lists.freed.retain(|key, _| carried.contains(key));
}

/// The device takes `act` out of its list, and keeps it as freed, in the
/// place of any act freed on its item before: that one held back every
/// act at or below it, so `act` orders above it.
fn free(lists: &mut Lists, act: &AnyAct, now: i64) {
    let key = act.key();
    let freed = Freed {
        part: key.0,
        item: key.1.clone(),
        time: act.time(),
        count: act.count(),
        maker: act.maker(),
        act: act.written(),
        freed_at: now,
    };
    lists.freed.insert(key, freed);
}

/// A device whose own list is not fresh to itself comes back (§3.4, "a
/// device that comes back"): it takes out of its own list, and of what it
/// left out of it, each item that
/// it held at its previous whole fetch, `previous`, and has made no act on
/// since, where another device that counts has a list fresh to it, whose
/// fetched time is after the item's time, and which holds nothing for the
/// item. Where no other list is fresh, nothing is taken out.
fn come_back(lists: &mut Lists, others: &[Read], previous: Option<i64>, now: i64) {
    let fresh: Vec<&Read> = others.iter().filter(|read| read.is_fresh(now)).collect();
    let let_go = |act: &AnyAct| {
        let held_then = previous
            .zip(lists.first_held_of(act))
            .is_some_and(|(previous, first_held)| first_held <= previous);
        held_then
            && fresh
                .iter()
                .any(|read| read.list.fetched > act.time() && !read.carries(&act.key()))
    };
    let list: Vec<AnyAct> = acts_of(&lists.list)
        .into_iter()
        .filter(|act| !let_go(act))
        .collect();
    let left_out: Vec<AnyAct> = acts_of(&lists.left_out)
        .into_iter()
        .filter(|act| !let_go(act))
        .collect();
    lists.list = list_of(list, lists.list.fetched);
    lists.left_out = list_of(left_out, 0);
}

/// The time and the count that a new act on `key` is dated with (§3.4):
/// one above the greatest of the device's clock, the newest time it holds
/// for the item (of an act it freed there among them), and every other
/// act's time and list's fetched time that it holds of a key that
/// counts, each taken as at most 90 days ahead of its clock; never above
/// `SHARED_ACT_TIME_MAX`. At the bound its count is one above the
/// highest count held there for the item from a maker that counts, a
/// freed act's among them, and never above the bound; below it, 0.
///
/// The acts of removed keys are left out of that last part, so that a
/// thief cannot lift the dating of every item.
fn dated(
    lists: &Lists,
    others: &[Read],
    makers: &Makers,
    checked: &Checked,
    key: &Key,
    now: i64,
) -> (u64, u64) {
    let now = u64::try_from(now).unwrap_or(0);
    let ahead = now.saturating_add(KEPT_SECS as u64);
    let mut held = lists.held();
    for read in others {
        held.extend(acts_of(&read.list));
    }
    // What a device would not take does not date its acts.
    let held: Vec<AnyAct> = held
        .into_iter()
        .filter(|act| checked.takes(act, makers))
        .collect();
    let freed = lists.freed.get(key);

    let of_item = held
        .iter()
        .filter(|act| act.key() == *key)
        .map(AnyAct::time)
        .chain(freed.map(|freed| freed.time))
        .max()
        .unwrap_or(0);
    let fetched = others
        .iter()
        .map(|read| read.list.fetched)
        .chain(std::iter::once(lists.list.fetched));
    let of_others = held
        .iter()
        .filter(|act| makers.maker(&act.maker()) == Some(Maker::Counts))
        .map(AnyAct::time)
        .chain(fetched)
        .map(|time| time.min(ahead))
        .max()
        .unwrap_or(0);
    let time = now
        .max(of_item)
        .max(of_others)
        .saturating_add(1)
        .min(SHARED_ACT_TIME_MAX);
    if time < SHARED_ACT_TIME_MAX {
        return (time, 0);
    }
    let at_the_bound = held
        .iter()
        .filter(|act| {
            act.key() == *key
                && act.time() == SHARED_ACT_TIME_MAX
                && makers.maker(&act.maker()) == Some(Maker::Counts)
        })
        .map(AnyAct::count)
        .chain(
            freed
                .filter(|freed| freed.time == SHARED_ACT_TIME_MAX)
                .map(|freed| freed.count),
        )
        .max();
    let count = at_the_bound.map_or(0, |count| count.saturating_add(1).min(SHARED_ACT_TIME_MAX));
    (time, count)
}

/// Write the device's own list, under its own name in the personal
/// channel of the generation applied, one revision above the one it
/// wrote there before, saying `fetched` (§3.4). It waits in the store to
/// be sent.
fn write_list(
    conn: &Connection,
    identity: &NodeIdentity,
    standing: &Standing,
    lists: &mut Lists,
    fetched: u64,
    now: i64,
) -> Result<(), PersonError> {
    lists.list.fetched = fetched;
    let value = lists
        .list
        .to_value(is_a_name)
        .map_err(|e| not_held("this device's list", e))?;
    let personal = derive::personal_secret(&standing.secret)?;
    let channel = derive::channel_id(&personal)?;
    let own = identity.public_key();
    let name = list_name(&own)?;
    let slot = slot_id(&derive::slot_key(&personal)?, &name);
    let before = entries::author_entry(conn, &channel, &slot, &own)?.map(|held| held.entry.rev);
    let rev = next_under(before, standing.number()).ok_or_else(|| {
        PersonError::Held(
            "this device's own list is at the last revision under the statement".into(),
        )
    })?;
    let inside = Inside {
        name,
        value: Value::Other(value),
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&personal, identity, rev, &inside)?.check()?;
    entries::store(conn, &entry, now)?;
    lists.written_at = Some(now);
    Ok(())
}

/// What a person does to the list (decision 2026-10-10 §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Do {
    /// File a channel, or file a filed channel under another name.
    File(Filing),
    /// Drop a filed channel, by its ID.
    Drop([u8; 32]),
    /// Move from a filed channel, by its ID, to a channel made anew: a
    /// filing in the old one's place, and a drop of the old one kept
    /// apart, so that a move needs no free place.
    Move { from: [u8; 32], to: Filing },
    /// Subscribe an agent to a channel, or end its subscription.
    Subscribe(Subscription),
    /// Give a key a label, or take its label away.
    Label(Label),
}

/// What became of what a person did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// The acts were made, put in the device's list, and the list written.
    Made(Vec<AnyAct>),
    /// Nothing was made.
    Refused(Refused),
}

/// Why nothing was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The list holds as many of that part as it may: 16 channels filed,
    /// 32 subscriptions or 64 labels. A drop and a move take no place.
    Full(Part),
    /// No channel of that ID is filed.
    NotFiled,
    /// The channel moved to is filed already.
    Filed,
    /// There is nothing for it to undo: no such subscription, or no label.
    NothingToUndo,
    /// What it holds cannot be written in a list: a name that is not a
    /// name, or a label of more than 64 bytes.
    NotWritten(ListError),
}

/// Do `what` on this device, at `now` (§3.4): each act dated by
/// [`dated`], signed by the device, put in its list in the place of what
/// it held on that item, and the list written at once with the fetched
/// time it has. A device that does not stand applied makes nothing.
pub fn act(
    conn: &Connection,
    identity: &NodeIdentity,
    what: Do,
    now: i64,
) -> Result<Done, PersonError> {
    in_one(conn, || {
        let standing = Standing::to_write(conn)?;
        let makers = Makers::of(conn, &standing)?;
        let own = identity.public_key();
        let others = lists_held(conn, &standing, &own)?;
        let mut lists = Lists::load(conn)?;
        let checked = Checked::default();
        // What the device holds on an item: in its list, or left out.
        let held = lists.held();
        let held_on = |key: &Key| held.iter().find(|act| act.key() == *key);
        // A place is taken by an item in force in the list (§3.4): an act
        // not in force, or one left out past a bound, takes none.
        let in_list: Vec<AnyAct> = acts_of(&lists.list)
            .into_iter()
            .filter(|act| makers.maker(&act.maker()).is_some_and(Maker::in_force))
            .collect();
        let placed = |key: &Key| in_list.iter().any(|act| act.key() == *key);
        let full = |of: fn(&AnyAct) -> bool, most: usize, key: &Key| {
            in_list.iter().filter(|act| of(act)).count() >= most && !placed(key)
        };
        let filed = |channel: &[u8; 32]| {
            let key = (Part::Channel, channel.to_vec());
            matches!(held_on(&key), Some(AnyAct::Filing(_)))
        };
        let dated_for = |key: &Key| dated(&lists, &others, &makers, &checked, key, now);
        let made: Result<Vec<AnyAct>, ListError> = match &what {
            Do::File(filing) => {
                let key = (Part::Channel, filing.channel.to_vec());
                let of = |act: &AnyAct| matches!(act, AnyAct::Filing(_));
                if full(of, SHARED_MAX_CHANNELS, &key) {
                    return Ok(Done::Refused(Refused::Full(Part::Channel)));
                }
                make(filing.clone(), dated_for(&key), identity).map(|a| vec![AnyAct::Filing(a)])
            }
            Do::Drop(channel) => {
                if !filed(channel) {
                    return Ok(Done::Refused(Refused::NotFiled));
                }
                let key = (Part::Channel, channel.to_vec());
                let dropped = Dropped { channel: *channel };
                make(dropped, dated_for(&key), identity).map(|a| vec![AnyAct::Drop(a)])
            }
            Do::Move { from, to } => {
                if !filed(from) {
                    return Ok(Done::Refused(Refused::NotFiled));
                }
                let key = (Part::Channel, to.channel.to_vec());
                if placed(&key) {
                    return Ok(Done::Refused(Refused::Filed));
                }
                let from_key = (Part::Channel, from.to_vec());
                let dropped = Dropped { channel: *from };
                let filing = make(to.clone(), dated_for(&key), identity);
                let drop = make(dropped, dated_for(&from_key), identity);
                filing.and_then(|filing| Ok(vec![AnyAct::Filing(filing), AnyAct::Drop(drop?)]))
            }
            Do::Subscribe(subscription) => {
                let key = (Part::Subscription, subscription.item());
                let subscribed = matches!(
                    held_on(&key),
                    Some(AnyAct::Subscription(held)) if held.item.subscribed
                );
                if !subscription.subscribed && !subscribed {
                    return Ok(Done::Refused(Refused::NothingToUndo));
                }
                let of = |act: &AnyAct| matches!(act, AnyAct::Subscription(_));
                if full(of, SHARED_MAX_SUBSCRIPTIONS, &key) {
                    return Ok(Done::Refused(Refused::Full(Part::Subscription)));
                }
                make(subscription.clone(), dated_for(&key), identity)
                    .map(|a| vec![AnyAct::Subscription(a)])
            }
            Do::Label(label) => {
                let key = (Part::Label, label.key.to_vec());
                let labelled = matches!(
                    held_on(&key),
                    Some(AnyAct::Label(held)) if held.item.label.is_some()
                );
                if label.label.is_none() && !labelled {
                    return Ok(Done::Refused(Refused::NothingToUndo));
                }
                let of = |act: &AnyAct| matches!(act, AnyAct::Label(_));
                if full(of, SHARED_MAX_LABELS, &key) {
                    return Ok(Done::Refused(Refused::Full(Part::Label)));
                }
                make(label.clone(), dated_for(&key), identity).map(|a| vec![AnyAct::Label(a)])
            }
        };
        let made = match made {
            Ok(made) => made,
            Err(e) => return Ok(Done::Refused(Refused::NotWritten(e))),
        };

        let keys: BTreeSet<Key> = made.iter().map(AnyAct::key).collect();
        let mut held: Vec<AnyAct> = lists
            .held()
            .into_iter()
            .filter(|act| !keys.contains(&act.key()))
            .collect();
        for act in &made {
            lists.first_held.insert(act.key(), (act.signature(), now));
            held.push(act.clone());
        }
        let bounded = within_bounds(held, &makers);
        for act in &bounded.freed_early {
            free(&mut lists, act, now);
            lists.first_held.remove(&act.key());
        }
        lists.list = list_of(bounded.list, lists.list.fetched);
        lists.left_out = list_of(bounded.left_out, 0);
        let fetched = lists
            .fetched_at
            .map_or(lists.list.fetched, |at| u64::try_from(at).unwrap_or(0));
        write_list(conn, identity, &standing, &mut lists, fetched, now)?;
        lists.save(conn)?;
        Ok(Done::Made(made))
    })
}

/// An act on `item`, dated with `(time, count)` and signed by
/// `identity`; refused where what the item holds cannot be written in a
/// list.
fn make<T: Item>(
    item: T,
    (time, count): (u64, u64),
    identity: &NodeIdentity,
) -> Result<Act<T>, ListError> {
    Act::make(item, time, count, identity, is_a_name)
}

/// What a device does at a whole fetch of the personal channel, a pull
/// of it to its end from at least one of its relays in one pass, at `now`
/// (§3.4): where its own list is not fresh to itself, it comes back
/// ([`come_back`]); it takes the lists of the others ([`take_lists`]);
/// and it writes its list, with this fetch's time as its fetched time,
/// where what it holds changed, where 30 days have passed since it last
/// wrote it, or where the fetched time it last wrote is ahead of its
/// clock. Returns whether it wrote its list.
///
/// The fetch's time is kept whatever the device holds: it is the fetched
/// time its next act is written with. A device that holds nothing, where
/// no other device of the person's has written a list, writes no list. A
/// device that does not stand applied does nothing; one whose database
/// cannot be read says so.
pub fn fetched_whole(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<bool, PersonError> {
    in_one(conn, || {
        let standing = match Standing::to_write(conn) {
            Ok(standing) => standing,
            Err(PersonError::FollowsNoPhrase | PersonError::Stopped(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        let makers = Makers::of(conn, &standing)?;
        let others = lists_held(conn, &standing, &identity.public_key())?;
        let mut lists = Lists::load(conn)?;
        let before = lists.list.clone();
        let previous = lists.fetched_at;
        if lists.written_at.is_some() && !lists.own_is_fresh(now) {
            come_back(&mut lists, &others, previous, now);
        }
        lists.fetched_at = Some(now);
        take_lists(&mut lists, &others, &makers, now);

        let fetched = u64::try_from(now).unwrap_or(0);
        let due = lists
            .written_at
            .is_some_and(|written| now - written >= WRITTEN_AGAIN_SECS || before.fetched > fetched);
        let changed = !same_acts(&before, &lists.list);
        let wrote = changed || due;
        if wrote {
            write_list(conn, identity, &standing, &mut lists, fetched, now)?;
        }
        lists.save(conn)?;
        Ok(wrote)
    })
}

/// What a device holds of the person's lists, each act with what its
/// maker is to it (§3.4): its own list's acts, and what it left out past
/// a bound, which is not in force on this device. Nothing on a device
/// that follows no phrase.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Holds {
    pub filings: Vec<(Act<Filing>, Maker)>,
    pub drops: Vec<(Act<Dropped>, Maker)>,
    pub subscriptions: Vec<(Act<Subscription>, Maker)>,
    pub labels: Vec<(Act<Label>, Maker)>,
    pub left_out: Vec<(AnyAct, Maker)>,
}

/// What this device holds of the person's lists.
pub fn holds(conn: &Connection) -> Result<Holds, PersonError> {
    let Ok(standing) = Standing::of(conn) else {
        return Ok(Holds::default());
    };
    let makers = Makers::of(conn, &standing)?;
    let lists = Lists::load(conn)?;
    // A device takes no act of a key it does not know, so its list holds
    // none.
    let with = |maker: [u8; 32]| makers.maker(&maker).unwrap_or(Maker::InNoList);
    Ok(Holds {
        filings: lists
            .list
            .filings
            .iter()
            .map(|act| (act.clone(), with(act.maker)))
            .collect(),
        drops: lists
            .list
            .drops
            .iter()
            .map(|act| (act.clone(), with(act.maker)))
            .collect(),
        subscriptions: lists
            .list
            .subscriptions
            .iter()
            .map(|act| (act.clone(), with(act.maker)))
            .collect(),
        labels: lists
            .list
            .labels
            .iter()
            .map(|act| (act.clone(), with(act.maker)))
            .collect(),
        left_out: acts_of(&lists.left_out)
            .into_iter()
            .map(|act| {
                let maker = with(act.maker());
                (act, maker)
            })
            .collect(),
    })
}

/// Whether the person has filed a shared channel under `name`, as this
/// device holds it: a filing in force in its list (decision 2026-10-10
/// §2.2). `cordelia sync map` refuses such a name.
pub fn is_filed_under(conn: &Connection, name: &str) -> Result<bool, PersonError> {
    Ok(holds(conn)?
        .filings
        .iter()
        .any(|(act, maker)| maker.in_force() && act.item.name == name))
}

/// Each other device of the person's whose list, as this device holds
/// it, says a fetched time ahead of this device's clock at `now`, with
/// that time: one of the two clocks is off (§3.4).
pub fn ahead_of_this_clock(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<Vec<([u8; 32], u64)>, PersonError> {
    let Ok(standing) = Standing::of(conn) else {
        return Ok(Vec::new());
    };
    let now = u64::try_from(now).unwrap_or(0);
    Ok(lists_held(conn, &standing, &identity.public_key())?
        .into_iter()
        .filter(|read| read.list.fetched > now)
        .map(|read| (read.writer, read.list.fetched))
        .collect())
}

/// Each other device of the person's whose list, as this device holds
/// it, was first held less than 90 days before `now` and says a fetched
/// time 90 days or more behind this device's clock, with that time: it is
/// not fresh, so none of its acts are taken here, and one of the two
/// clocks is off (§3.4, "a clock that is wrong").
pub fn behind_this_clock(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<Vec<([u8; 32], u64)>, PersonError> {
    let Ok(standing) = Standing::of(conn) else {
        return Ok(Vec::new());
    };
    Ok(lists_held(conn, &standing, &identity.public_key())?
        .into_iter()
        .filter(|read| now - read.first_held < KEPT_SECS && !read.is_fresh(now))
        .map(|read| (read.writer, read.list.fetched))
        .collect())
}

/// What the person answered of a device at a recovery (decision
/// 2026-10-04 §9, step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answered {
    /// The person has it: it is in no list until it is added again.
    Have,
    /// It is lost: a removed key.
    Lost,
    /// It may be in someone else's hands: a removed key, whose list does
    /// not say what the newest fetched time is.
    Hands,
}

/// What a recovery takes of the lists of the devices it shows (decision
/// 2026-10-10 §3.5), at the recovering machine's clock `now`: the newest
/// act on each item among the lists that are fresh to it, each part kept
/// within its bound, as the list of the new machine and what it leaves
/// out. `maker` says what each maker is under the statement the recovery
/// makes: a device answered `lost` or `hands` is a removed key, one
/// answered `have` is in no list, and a key that is none of these is no
/// maker whose acts are taken.
///
/// A list is fresh to a recovery where its fetched time is less than 90
/// days behind the newest fetched time among the lists it reads, each
/// taken as no later than `now`, and the lists of devices answered
/// `hands` left out of that newest time: so no list, however far ahead
/// it is dated, makes the others stale. Where every list is of such a
/// device, the newest is theirs.
pub fn recovered(
    lists: &[([u8; 32], Answered, SharedList)],
    maker: impl Fn(&[u8; 32]) -> Option<Maker>,
    now: i64,
) -> (SharedList, SharedList) {
    let at = |list: &SharedList| i64::try_from(list.fetched).unwrap_or(i64::MAX).min(now);
    let newest_of = |hands_too: bool| {
        lists
            .iter()
            .filter(|(_, answered, _)| hands_too || *answered != Answered::Hands)
            .map(|(_, _, list)| at(list))
            .max()
    };
    let Some(newest) = newest_of(false).or_else(|| newest_of(true)) else {
        return (SharedList::default(), SharedList::default());
    };
    let makers = Makers::from_fn(maker, lists);
    let fresh = lists
        .iter()
        .filter(|(_, _, list)| newest - at(list) < KEPT_SECS)
        .flat_map(|(_, _, list)| acts_of(list));
    let checked = Checked::default();
    let chosen = newest_of_each(fresh, &BTreeSet::new(), |_| None, &makers, &checked);
    let bounded = within_bounds(chosen, &makers);
    (list_of(bounded.list, 0), list_of(bounded.left_out, 0))
}

impl Makers {
    /// The makers that `maker` says, for every maker of an act in `lists`.
    fn from_fn(
        maker: impl Fn(&[u8; 32]) -> Option<Maker>,
        lists: &[([u8; 32], Answered, SharedList)],
    ) -> Self {
        let (mut counting, mut removed, mut left_out) = (Vec::new(), Vec::new(), Vec::new());
        let keys: BTreeSet<[u8; 32]> = lists
            .iter()
            .flat_map(|(_, _, list)| acts_of(list))
            .map(|act| act.maker())
            .collect();
        for key in keys {
            match maker(&key) {
                Some(Maker::Counts) => counting.push(key),
                Some(Maker::Removed) => removed.push(key),
                Some(Maker::InNoList) => left_out.push(key),
                None => {}
            }
        }
        Self {
            counting: Counting::of_devices(&counting),
            removed,
            left_out,
        }
    }
}

/// The list of each key of `shown` among `handed`, the entries of a
/// personal channel whose secret is `personal`: that key's own entry
/// under its own list's name, the newest it signed there (§3.5). One that
/// is a delete, does not open or is no list is passed over.
pub fn lists_in(
    handed: &[CheckedEntry],
    personal: &[u8; 32],
    shown: &[[u8; 32]],
) -> Result<Vec<([u8; 32], SharedList)>, PersonError> {
    let channel = derive::channel_id(personal)?;
    let slot_key = derive::slot_key(personal)?;
    let mut found = Vec::new();
    for key in shown {
        let name = list_name(key)?;
        let slot = slot_id(&slot_key, &name);
        let newest = handed
            .iter()
            .filter(|entry| entry.channel == channel && entry.slot == slot && entry.author == *key)
            .max_by_key(|entry| entry.rev);
        // An entry opens only in the slot of its name. A delete holds no
        // list, and nothing older is read.
        let Some(Ok(inside)) = newest.map(|entry| entry.open(personal)) else {
            continue;
        };
        if let Ok(list) = SharedList::from_value(&inside.value, is_a_name) {
            found.push((*key, list));
        }
    }
    Ok(found)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::several::Several;
    use crate::take::take;
    use cordelia_crypto::acts::Came;
    use cordelia_crypto::share::{Card, Relays};
    use cordelia_storage::person::{self as held_rows, Kept as KeptEntry};

    const DAY: i64 = 24 * 60 * 60;

    /// A filing of the channel of the card made from `seed`, under `name`.
    pub(crate) fn filing(seed: u8, name: &str) -> Filing {
        let mut bytes = vec![seed; 32];
        bytes.extend_from_slice(&Relays::new(&[[3; 32]]).unwrap().to_bytes());
        let card = Card::from_bytes(&bytes).unwrap();
        Filing {
            channel: card.channel_id().unwrap(),
            card,
            name: name.into(),
            came: Came::Made,
        }
    }

    /// The ID of the channel of the card made from `seed`.
    fn channel(seed: u8) -> [u8; 32] {
        filing(seed, "x").channel
    }

    fn subscription(seed: u8, agent: &str, subscribed: bool) -> Subscription {
        Subscription {
            channel: channel(seed),
            agent: agent.into(),
            subscribed,
        }
    }

    fn label(key: u8, label: Option<&str>) -> Label {
        Label {
            key: [key; 32],
            label: label.map(str::to_string),
        }
    }

    /// `count` devices of one person, of whom the first `added` are
    /// added: the phrase is made on device 0, which adds each of the
    /// others, and each has been given what every other holds.
    fn person(count: u16, added: usize) -> Several {
        let mut s = Several::new(count);
        s.make_phrase(0);
        for new in 1..added {
            s.add(0, new);
        }
        let all: Vec<usize> = (0..added).collect();
        s.meet(&all);
        s
    }

    /// Device `n` does `what` at `now`, and it is made.
    fn on(s: &Several, n: usize, what: Do, now: i64) -> Vec<AnyAct> {
        match act(&s[n].conn, &s[n].identity, what, now).unwrap() {
            Done::Made(made) => made,
            other => panic!("{other:?}"),
        }
    }

    /// Device `n` does `what` at `now`, and it is refused.
    fn refused(s: &Several, n: usize, what: Do, now: i64) -> Refused {
        match act(&s[n].conn, &s[n].identity, what, now).unwrap() {
            Done::Refused(refused) => refused,
            other => panic!("{other:?}"),
        }
    }

    /// Device `to` is given, at `now`, everything device `from` holds:
    /// the change entry it keeps, and then every entry of its store.
    fn give(s: &Several, from: usize, to: usize, now: i64) {
        let kept = held_rows::change_entry(&s[from].conn, KeptEntry::Latest).unwrap();
        let entries = kept.map(|entry| entry.check().unwrap()).into_iter();
        for entry in entries.chain(s[from].stored()) {
            take(&s[to].conn, &s[to].identity, &entry, now).unwrap();
        }
    }

    /// Device `n` makes a whole fetch at `now`. Returns whether it wrote
    /// its list.
    fn fetch(s: &Several, n: usize, now: i64) -> bool {
        fetched_whole(&s[n].conn, &s[n].identity, now).unwrap()
    }

    /// Device `to` is given what each of `from` holds, and makes a whole
    /// fetch, at `now`.
    fn fetch_from(s: &Several, from: &[usize], to: usize, now: i64) -> bool {
        for from in from {
            give(s, *from, to, now);
        }
        fetch(s, to, now)
    }

    /// What device `n` keeps as its own list.
    fn kept(s: &Several, n: usize) -> SharedList {
        Lists::load(&s[n].conn).unwrap().list
    }

    /// Every act in device `n`'s list that is in force there.
    fn in_force(s: &Several, n: usize) -> Vec<AnyAct> {
        let holds = holds(&s[n].conn).unwrap();
        let mut acts = Vec::new();
        acts.extend(
            holds
                .filings
                .into_iter()
                .map(|(a, m)| (AnyAct::Filing(a), m)),
        );
        acts.extend(holds.drops.into_iter().map(|(a, m)| (AnyAct::Drop(a), m)));
        acts.extend(
            holds
                .subscriptions
                .into_iter()
                .map(|(a, m)| (AnyAct::Subscription(a), m)),
        );
        acts.extend(holds.labels.into_iter().map(|(a, m)| (AnyAct::Label(a), m)));
        acts.into_iter()
            .filter(|(_, maker)| maker.in_force())
            .map(|(act, _)| act)
            .collect()
    }

    /// The names of the channels filed in force on device `n`, in order.
    fn filed(s: &Several, n: usize) -> Vec<String> {
        let mut names: Vec<String> = in_force(s, n)
            .into_iter()
            .filter_map(|act| match act {
                AnyAct::Filing(filing) => Some(filing.item.name),
                _ => None,
            })
            .collect();
        names.sort();
        names
    }

    /// Whether `agent` subscribes to the channel of `seed` in force on
    /// device `n`: `None` where no act on it is in force there.
    fn subscribes(s: &Several, n: usize, seed: u8, agent: &str) -> Option<bool> {
        in_force(s, n).into_iter().find_map(|act| match act {
            AnyAct::Subscription(a) if a.item.channel == channel(seed) && a.item.agent == agent => {
                Some(a.item.subscribed)
            }
            _ => None,
        })
    }

    /// The label in force on device `n` for the key of `key` bytes.
    fn labelled(s: &Several, n: usize, key: u8) -> Option<Option<String>> {
        in_force(s, n).into_iter().find_map(|act| match act {
            AnyAct::Label(a) if a.item.key == [key; 32] => Some(a.item.label),
            _ => None,
        })
    }

    /// Device `n` writes `value` in the personal channel as its own entry
    /// under the list name of `slot_of`, one revision above what it wrote
    /// there, at `now`: a list made by hand.
    fn write_by_hand(s: &Several, n: usize, slot_of: &[u8; 32], value: Vec<u8>, now: i64) {
        let personal = s[n].personal();
        let id = derive::channel_id(&personal).unwrap();
        let name = list_name(slot_of).unwrap();
        let slot = slot_id(&derive::slot_key(&personal).unwrap(), &name);
        let before = entries::author_entry(&s[n].conn, &id, &slot, &s.key(n))
            .unwrap()
            .map(|held| held.entry.rev);
        let rev = next_under(before, s[n].number()).unwrap();
        let inside = Inside {
            name,
            value: Value::Other(value),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&personal, &s[n].identity, rev, &inside)
            .unwrap()
            .check()
            .unwrap();
        entries::store(&s[n].conn, &entry, now).unwrap();
    }

    /// The value of a list of `acts`, as a device writes it, saying
    /// `fetched`.
    fn value_of(acts: Vec<AnyAct>, fetched: u64) -> Vec<u8> {
        list_of(acts, fetched).to_value(is_a_name).unwrap()
    }

    // ── Who made an act, and which acts are taken ─────────────────────

    /// An act made on the laptop and copied by the desktop and the phone
    /// holds the laptop's key and signature in every list (decision
    /// 2026-10-10 §1, property 9; §3.4): each device's list, as it keeps
    /// it and as it wrote it. And two acts on one item, made at one time
    /// by two devices that count, are ordered by their makers' keys, the
    /// greater above, alike on every device.
    #[test]
    fn every_act_names_its_maker_and_a_copy_keeps_it() {
        let s = person(3, 3);
        let now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        let made = on(&s, 0, Do::Label(label(9, Some("bob"))), now + 1);
        let AnyAct::Label(made) = &made[0] else {
            panic!("{made:?}");
        };
        assert_eq!(made.maker, s.key(0));
        for n in [1, 2] {
            assert!(fetch_from(&s, &[0], n, now + 2));
        }
        for n in 0..3 {
            let list = kept(&s, n);
            assert_eq!(list.labels.len(), 1, "device {n}");
            assert_eq!(list.labels[0].maker, s.key(0), "device {n}");
            assert_eq!(list.labels[0].signature, made.signature, "device {n}");
            assert_eq!(list.labels[0], *made, "device {n}");
        }
        for n in [1, 2] {
            give(&s, n, 0, now + 3);
        }
        let written = lists_held(&s[0].conn, &standing(&s, 0), &s.key(0)).unwrap();
        assert_eq!(written.len(), 2);
        for read in &written {
            assert_eq!(
                read.list.labels,
                std::slice::from_ref(made),
                "{:?}",
                read.writer
            );
        }

        // The desktop and the phone each label one key at one time, apart:
        // the greater key's label is the lesser in bytes.
        let at = now + 100;
        let greater = if s.key(1) > s.key(2) { 1 } else { 2 };
        let text = |n: usize| if n == greater { "a" } else { "z" };
        for n in [1, 2] {
            on(&s, n, Do::Label(label(7, Some(text(n)))), at);
        }
        for n in 0..3 {
            fetch_from(&s, &[0, 1, 2], n, at + 1);
        }
        for n in 0..3 {
            let label = labelled(&s, n, 7);
            assert_eq!(label, Some(Some("a".to_string())), "device {n}");
            let held = kept(&s, n);
            let of_7 = held.labels.iter().find(|a| a.item.key == [7; 32]).unwrap();
            assert_eq!(of_7.maker, s.key(greater), "device {n}");
            assert_eq!(of_7.time, u64::try_from(at + 1).unwrap(), "device {n}");
        }
    }

    /// Where the device stands, as one that may write.
    fn standing(s: &Several, n: usize) -> Standing {
        Standing::to_write(&s[n].conn).unwrap()
    }

    /// Two acts on one item that agree in time, count, maker and whether
    /// it counts are ordered by their bytes as a list writes them, the
    /// greater above (decision 2026-10-10 §3.4): a filing and a drop of
    /// one channel, both signed by the laptop at one time, one in the
    /// laptop's list and one in the desktop's, are taken alike by every
    /// device, whichever list it holds as its own.
    #[test]
    fn two_acts_alike_but_for_their_bytes_are_ordered_by_them_on_every_device() {
        let s = person(4, 4);
        let now = s.now + 10;
        for n in 0..4 {
            fetch(&s, n, now);
        }
        let at = u64::try_from(now + 5).unwrap();
        let filed = Act::make(filing(1, "review"), at, 0, &s[0].identity, is_a_name).unwrap();
        let dropped = Act::make(
            Dropped {
                channel: channel(1),
            },
            at,
            0,
            &s[0].identity,
            is_a_name,
        )
        .unwrap();
        let (filed, dropped) = (AnyAct::Filing(filed), AnyAct::Drop(dropped));
        let greater = if filed.written() > dropped.written() {
            filed.clone()
        } else {
            dropped.clone()
        };
        let other = if greater == filed { &dropped } else { &filed };
        assert_ne!(filed.written(), dropped.written());
        // The laptop's list holds the filing and the desktop's the drop.
        for (n, act) in [(0, &filed), (1, &dropped)] {
            write_by_hand(&s, n, &s.key(n), value_of(vec![act.clone()], at), now + 6);
            let mut lists = Lists::load(&s[n].conn).unwrap();
            lists.list = list_of(vec![act.clone()], at);
            lists.written_at = Some(now + 6);
            lists
                .first_held
                .insert(act.key(), (act.signature(), now + 6));
            lists.save(&s[n].conn).unwrap();
        }
        // The phone takes the laptop's list first, the tablet the
        // desktop's; then each the other.
        fetch_from(&s, &[0], 2, now + 7);
        fetch_from(&s, &[1], 3, now + 7);
        for n in 0..4 {
            fetch_from(&s, &[0, 1], n, now + 8);
        }
        for n in 0..4 {
            assert_eq!(
                acts_of(&kept(&s, n)),
                std::slice::from_ref(&greater),
                "device {n}"
            );
            assert!(!acts_of(&kept(&s, n)).contains(other), "device {n}");
        }
    }

    /// A device takes no act whose signature fails, whose maker is
    /// another device that never made it, or whose time is above
    /// `SHARED_ACT_TIME_MAX` (decision 2026-10-10 §1, property 9; §3.4):
    /// the desktop's list holds each, and the laptop holds none of them.
    /// An act whose maker was never a device of the person's is not in
    /// force; nor is one that a device of the person's wrote in another
    /// device's slot, which is not that device's list.
    #[test]
    fn an_act_whose_signature_fails_or_whose_maker_was_never_a_device_is_not_taken() {
        let s = person(3, 3);
        let now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        let at = u64::try_from(now + 1).unwrap();
        let desktop = &s[1].identity;
        let stranger = NodeIdentity::from_seed([0x77; 32]).unwrap();
        // A signature that fails: the desktop's, over another time.
        let mut forged = Act::make(label(1, Some("one")), at, 0, desktop, is_a_name).unwrap();
        forged.time += 1;
        // A key that was never a device of the person's.
        let never = Act::make(label(2, Some("two")), at, 0, &stranger, is_a_name).unwrap();
        // The laptop named as its maker, signed by the desktop.
        let mut as_laptop = Act::make(label(3, Some("three")), at, 0, desktop, is_a_name).unwrap();
        as_laptop.maker = s.key(0);
        // A time above the bound, signed.
        let past = Act::make(
            label(4, Some("four")),
            SHARED_ACT_TIME_MAX + 1,
            0,
            desktop,
            is_a_name,
        )
        .unwrap();
        // A count above the bound, signed.
        let counted = Act::make(
            label(5, Some("five")),
            SHARED_ACT_TIME_MAX,
            SHARED_ACT_TIME_MAX + 1,
            desktop,
            is_a_name,
        )
        .unwrap();
        // And one that holds, which is taken.
        let honest = Act::make(label(6, Some("six")), at, 0, desktop, is_a_name).unwrap();
        let acts = [
            forged,
            never.clone(),
            as_laptop,
            past,
            counted,
            honest.clone(),
        ]
        .map(AnyAct::Label)
        .to_vec();
        write_by_hand(&s, 1, &s.key(1), value_of(acts, at), now + 2);
        // The desktop also writes a list in the phone's slot.
        let in_another = Act::make(label(8, Some("eight")), at, 0, desktop, is_a_name).unwrap();
        write_by_hand(
            &s,
            1,
            &s.key(2),
            value_of(vec![AnyAct::Label(in_another)], at),
            now + 2,
        );

        assert!(fetch_from(&s, &[1], 0, now + 3));
        let held = kept(&s, 0);
        let keys: Vec<[u8; 32]> = held.labels.iter().map(|a| a.item.key).collect();
        assert_eq!(keys, [[6; 32]]);
        assert_eq!(labelled(&s, 0, 6), Some(Some("six".into())));
        assert!(!acts_of(&held).contains(&AnyAct::Label(never)));
        assert!(holds(&s[0].conn).unwrap().left_out.is_empty());
        for key in [1, 2, 3, 4, 5, 8] {
            assert_eq!(labelled(&s, 0, key), None, "{key}");
        }
    }

    /// Which makers' acts are in force is decided by the statement and the
    /// records of addition alone (decision 2026-10-10 §3.4, "a key in no
    /// list"): the laptop and the desktop counted the phone by a record of
    /// addition, and a settlement left it in no list. On both, and on a
    /// tablet added afterwards, the phone's acts are held and not in
    /// force; once a statement removes the phone, all three take them, as
    /// a removed key's.
    #[test]
    fn which_makers_are_valid_comes_from_the_statement_alone() {
        let mut s = person(4, 3);
        let mut now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        // The laptop labelled the key first; the phone's label is later.
        on(&s, 0, Do::Label(label(9, Some("bob"))), now);
        fetch_from(&s, &[0], 2, now);
        on(&s, 2, Do::Label(label(9, Some("alice"))), now + 1);
        on(
            &s,
            2,
            Do::Subscribe(subscription(1, "github.com/owner/repo", true)),
            now + 1,
        );
        on(&s, 2, Do::File(filing(1, "review")), now + 1);
        for n in [0, 1] {
            fetch_from(&s, &[2], n, now + 2);
            assert_eq!(labelled(&s, n, 9), Some(Some("alice".into())), "device {n}");
            assert!(is_filed_under(&s[n].conn, "review").unwrap(), "device {n}");
        }
        // The settlement lists the laptop and the desktop, and neither
        // keeps nor removes the phone.
        s.now = now + 3;
        s.change(0, &[0, 1], &[]);
        now = s.now + 1;
        give(&s, 0, 1, now);
        for n in [0, 1] {
            assert!(!s[n].counts(&s.key(2)), "device {n}");
            fetch_from(&s, &[0, 1], n, now);
        }
        s.now = now;
        s.add(0, 3);
        now = s.now + 1;
        fetch_from(&s, &[0, 1], 3, now);
        // The tablet never counted the phone: the phone is no maker it
        // knows, and it holds none of its acts.
        fetch_from(&s, &[0, 1], 3, now + 1);
        assert!(holds(&s[3].conn).unwrap().labels.is_empty());
        assert!(holds(&s[3].conn).unwrap().subscriptions.is_empty());
        assert!(!is_filed_under(&s[3].conn, "review").unwrap());
        for n in [0, 1] {
            fetch_from(&s, &[0, 1, 3], n, now + 1);
            assert_eq!(labelled(&s, n, 9), None, "device {n}");
            assert_eq!(
                subscribes(&s, n, 1, "github.com/owner/repo"),
                None,
                "device {n}"
            );
            let holds = holds(&s[n].conn).unwrap();
            let of_phone: Vec<Maker> = holds
                .labels
                .iter()
                .map(|(_, m)| *m)
                .chain(holds.subscriptions.iter().map(|(_, m)| *m))
                .collect();
            assert_eq!(of_phone, [Maker::InNoList, Maker::InNoList], "device {n}");
            assert!(!is_filed_under(&s[n].conn, "review").unwrap(), "device {n}");
        }
        // The phone is removed.
        s.now = now + 2;
        s.change(0, &[0, 1, 3], &[2]);
        now = s.now + 1;
        for n in [1, 3] {
            give(&s, 0, n, now);
        }
        for n in [0, 1, 3] {
            fetch_from(&s, &[0, 1, 3], n, now + 1);
            assert_eq!(labelled(&s, n, 9), Some(Some("alice".into())), "device {n}");
            assert_eq!(
                subscribes(&s, n, 1, "github.com/owner/repo"),
                Some(true),
                "device {n}"
            );
            let holds = holds(&s[n].conn).unwrap();
            assert_eq!(holds.labels[0].1, Maker::Removed, "device {n}");
            assert!(is_filed_under(&s[n].conn, "review").unwrap(), "device {n}");
            assert!(!is_filed_under(&s[n].conn, "other").unwrap(), "device {n}");
        }
    }

    // ── The dating of an act ───────────────────────────────────────────

    /// The time an act says, as a number.
    fn at(act: &AnyAct) -> i64 {
        i64::try_from(act.time()).unwrap()
    }

    /// A subscription dated a day ahead of the desktop's clock is taken
    /// by the desktop; an unsubscription the desktop makes at once is
    /// dated above it, and wins on every device (decision 2026-10-10
    /// §3.4): no act is refused for a clock.
    #[test]
    fn a_word_dated_ahead_is_followed_by_the_next_act() {
        let s = person(3, 3);
        let now = s.now + 10;
        let ahead = now + DAY;
        fetch(&s, 0, ahead);
        for n in [1, 2] {
            fetch(&s, n, now);
        }
        let made = on(&s, 0, Do::Subscribe(subscription(1, "notes", true)), ahead);
        assert_eq!(at(&made[0]), ahead + 1);
        fetch_from(&s, &[0], 2, now + 1);
        fetch_from(&s, &[0], 1, now + 1);
        assert_eq!(subscribes(&s, 1, 1, "notes"), Some(true));
        let undone = on(
            &s,
            1,
            Do::Subscribe(subscription(1, "notes", false)),
            now + 2,
        );
        assert_eq!(at(&undone[0]), ahead + 2);
        for n in [0, 2] {
            fetch_from(&s, &[0, 1], n, now + 3);
        }
        for n in 0..3 {
            assert_eq!(subscribes(&s, n, 1, "notes"), Some(false), "device {n}");
        }
    }

    /// The acts of the person's devices that count, and the fetched times
    /// of their lists, lift the dating of every item, each taken as at
    /// most 90 days ahead of the device's clock; those of a removed key
    /// lift no other item's (decision 2026-10-10 §3.4).
    #[test]
    fn the_acts_of_a_removed_key_lift_the_dating_of_no_other_item() {
        let mut s = person(3, 3);
        let mut now = s.now + 10;
        for n in [0, 1] {
            fetch(&s, n, now);
        }
        // The phone's clock is a year ahead; its fetched time and its act
        // lift the laptop's next act by 90 days and no more.
        let year = 365 * DAY;
        fetch(&s, 2, now + year);
        let thief = on(&s, 2, Do::Label(label(9, Some("alice"))), now + year);
        fetch_from(&s, &[2], 0, now + 1);
        let lifted = on(&s, 0, Do::Label(label(5, Some("bob"))), now + 2);
        assert_eq!(at(&lifted[0]), now + 2 + KEPT_SECS + 1);
        // A device of the person's whose clock is 30 days ahead lifts it
        // by that.
        fetch(&s, 1, now + 30 * DAY);
        on(&s, 1, Do::Label(label(6, Some("carol"))), now + 30 * DAY);
        fetch_from(&s, &[1], 0, now + 3);

        // Once the phone is removed, its act no longer lifts the dating.
        s.now = now + 4;
        s.change(0, &[0, 1], &[2]);
        now = s.now + 1;
        give(&s, 0, 1, now);
        for n in [0, 1] {
            fetch_from(&s, &[0, 1], n, now);
        }
        let own_kept = kept(&s, 0);
        assert!(own_kept.labels.iter().any(|a| a.maker == s.key(2)));
        let next = on(&s, 0, Do::Label(label(7, Some("dave"))), now + 1);
        // Lifted by the laptop's own act, the newest of a key that counts,
        // and not by the phone's year.
        assert!(at(&lifted[0]) < now + 1 + KEPT_SECS);
        assert_eq!(at(&next[0]), at(&lifted[0]) + 1);
        // On the phone's own item, its act still decides: the next act
        // there goes above it.
        let over = on(&s, 0, Do::Label(label(9, Some("not alice"))), now + 2);
        assert_eq!(at(&over[0]), at(&thief[0]) + 1);
    }

    /// The phone subscribes a folder at `SHARED_ACT_TIME_MAX`, and the
    /// desktop copies it; the phone is removed; the laptop's
    /// unsubscription goes above it at the same time, since its maker
    /// counts, and is taken on every device; the statement carries every
    /// list unchanged (decision 2026-10-10 §3.4).
    #[test]
    fn an_act_at_the_bound_leaves_room_to_undo_it() {
        let (s, _) = undone_at_the_bound(1);
        for (n, other) in STAY {
            assert_eq!(subscribes(&s, n, 1, "notes"), Some(false), "device {n}");
            let held = kept(&s, n);
            let act = &held.subscriptions[0];
            assert_eq!(
                (act.time, act.count, act.maker),
                (SHARED_ACT_TIME_MAX, 0, s.key(1))
            );
            // Its list in the new personal channel is the list it keeps.
            let written = lists_held(&s[other].conn, &standing(&s, other), &s.key(other)).unwrap();
            let written = written.iter().find(|read| read.writer == s.key(n)).unwrap();
            assert!(same_acts(&written.list, &held), "device {n}");
        }
    }

    /// The two devices that stay in [`undone_at_the_bound`], each with the
    /// other: the laptop's key is above the tablet's, and the phone, which
    /// is removed, has a key above both, so that only its being removed
    /// puts their acts above its own at one time.
    const STAY: [(usize, usize); 2] = [(1, 3), (3, 1)];

    /// The device removed in [`undone_at_the_bound`].
    const THIEF: usize = 0;

    /// Two devices of the person's, with the subscription that a third,
    /// in someone else's hands, made at the bound undone after its removal
    /// by device `undoer`, one of the two: the other took the undo a second
    /// later, and each has taken the other's list since. Returns when the
    /// undo was made.
    fn undone_at_the_bound(undoer: usize) -> (Several, i64) {
        let mut s = person(4, 4);
        let key = |n: usize| crate::several::identity_of(n as u16).public_key();
        assert!(key(THIEF) > key(1) && key(1) > key(3));
        let mut now = s.now + 10;
        for (n, _) in STAY {
            fetch(&s, n, now);
        }
        let bound = i64::try_from(SHARED_ACT_TIME_MAX).unwrap();
        fetch(&s, THIEF, bound);
        let made = on(
            &s,
            THIEF,
            Do::Subscribe(subscription(1, "notes", true)),
            bound,
        );
        assert_eq!((made[0].time(), made[0].count()), (SHARED_ACT_TIME_MAX, 0));
        for (n, _) in STAY {
            fetch_from(&s, &[THIEF], n, now + 1);
            assert_eq!(subscribes(&s, n, 1, "notes"), Some(true), "device {n}");
        }
        // The lists as they stand before the statement, which carries
        // each as it is.
        let before: Vec<SharedList> = STAY.iter().map(|(n, _)| kept(&s, *n)).collect();
        s.now = now + 2;
        s.change(1, &[1, 3], &[THIEF]);
        now = s.now + 1;
        give(&s, 1, 3, now);
        for (n, other) in STAY {
            give(&s, n, other, now);
        }
        for (at, (n, other)) in STAY.into_iter().enumerate() {
            let carried = lists_held(&s[other].conn, &standing(&s, other), &s.key(other)).unwrap();
            let carried = carried.iter().find(|read| read.writer == s.key(n)).unwrap();
            assert_eq!(carried.list, before[at], "device {n}");
        }
        let other = if undoer == 1 { 3 } else { 1 };
        let made_at = now + 1;
        let undone = on(
            &s,
            undoer,
            Do::Subscribe(subscription(1, "notes", false)),
            made_at,
        );
        assert_eq!(
            (undone[0].time(), undone[0].count()),
            (SHARED_ACT_TIME_MAX, 0)
        );
        fetch_from(&s, &[undoer], other, made_at + 1);
        fetch_from(&s, &[other], undoer, made_at + 1);
        (s, made_at)
    }

    /// After that undo, its 90 days pass on the device that made it,
    /// which frees it while the other's list, fresh, still carries it. The
    /// other, whose key is the lower, subscribes the folder, at the bound
    /// with a count above the undo's; then the device that freed the undo
    /// unsubscribes it, with a count above that. Each takes effect on
    /// every device, by its count, and the freed undo holds neither back.
    /// No other item's acts are dated at the bound (decision 2026-10-10
    /// §3.4).
    #[test]
    fn two_acts_after_an_undo_at_the_bound_each_take_effect() {
        let (higher, lower) = (1, 3);
        let (s, made_at) = undone_at_the_bound(higher);
        let later = made_at + KEPT_SECS;
        fetch_from(&s, &[lower], higher, later);
        let lists = Lists::load(&s[higher].conn).unwrap();
        assert!(lists.list.subscriptions.is_empty());
        assert_eq!(lists.freed.len(), 1);
        assert_eq!(subscribes(&s, higher, 1, "notes"), None);
        assert_eq!(subscribes(&s, lower, 1, "notes"), Some(false));

        fetch(&s, lower, later);
        let sub = on(
            &s,
            lower,
            Do::Subscribe(subscription(1, "notes", true)),
            later,
        );
        assert_eq!((sub[0].time(), sub[0].count()), (SHARED_ACT_TIME_MAX, 1));
        fetch_from(&s, &[lower], higher, later + 1);
        for n in [higher, lower] {
            assert_eq!(subscribes(&s, n, 1, "notes"), Some(true), "device {n}");
        }
        let unsub = on(
            &s,
            higher,
            Do::Subscribe(subscription(1, "notes", false)),
            later + 2,
        );
        assert_eq!(
            (unsub[0].time(), unsub[0].count()),
            (SHARED_ACT_TIME_MAX, 2)
        );
        fetch_from(&s, &[higher], lower, later + 3);
        for n in [higher, lower] {
            assert_eq!(subscribes(&s, n, 1, "notes"), Some(false), "device {n}");
        }
        let other = on(&s, lower, Do::Label(label(4, Some("bob"))), later + 4);
        assert!(other[0].time() < SHARED_ACT_TIME_MAX);
        assert_eq!(other[0].count(), 0);
    }

    /// While a fresh list still carries the item, an undo freed at the
    /// bound holds back an act at or below it, and the next act on the
    /// item is counted above it (decision 2026-10-10 §3.4).
    #[test]
    fn a_freed_act_at_the_bound_holds_back_what_orders_at_or_below_it() {
        let (s, made_at) = undone_at_the_bound(1);
        // The laptop frees the undo while the tablet's list, fresh, still
        // carries it.
        let later = made_at + KEPT_SECS;
        fetch_from(&s, &[3], 1, later);
        let lists = Lists::load(&s[1].conn).unwrap();
        assert!(lists.list.subscriptions.is_empty());
        let freed: Vec<&Freed> = lists.freed.values().collect();
        assert_eq!(freed.len(), 1);
        assert_eq!((freed[0].time, freed[0].count), (SHARED_ACT_TIME_MAX, 0));
        assert_eq!(subscribes(&s, 1, 1, "notes"), None);
        // Given the tablet's list again, which carries the undo itself, the
        // laptop does not take it back.
        fetch_from(&s, &[3], 1, later);
        assert!(kept(&s, 1).subscriptions.is_empty());
        assert_eq!(Lists::load(&s[1].conn).unwrap().freed.len(), 1);
        // The next act there is counted above the freed one.
        let sub = on(
            &s,
            1,
            Do::Subscribe(subscription(1, "notes", true)),
            later + 2,
        );
        assert_eq!((sub[0].time(), sub[0].count()), (SHARED_ACT_TIME_MAX, 1));
    }

    /// The laptop writes a fetched time a year ahead (decision 2026-10-10
    /// §3.4, "a clock that is wrong"): the desktop's next acts are dated
    /// no more than 90 days ahead of its clock, nothing is refused, and no
    /// item is taken out of the desktop's list; the laptop, its clock put
    /// right, writes its list again at its next whole fetch.
    #[test]
    fn a_fetched_time_far_ahead_refuses_nothing() {
        let s = person(2, 2);
        let now = s.now + 10;
        let year = 365 * DAY;
        fetch(&s, 1, now);
        on(&s, 1, Do::File(filing(1, "review")), now + 1);
        on(
            &s,
            1,
            Do::Subscribe(subscription(1, "notes", true)),
            now + 1,
        );
        fetch_from(&s, &[1], 0, now + year);
        on(&s, 0, Do::Label(label(9, Some("bob"))), now + year);
        assert!(fetch(&s, 0, now + year + 1) || kept(&s, 0).fetched > 0);

        let held_before = acts_of(&kept(&s, 1));
        fetch_from(&s, &[0], 1, now + 2);
        let acts = [
            on(&s, 1, Do::Label(label(5, Some("carol"))), now + 3),
            on(
                &s,
                1,
                Do::Subscribe(subscription(2, "notes", true)),
                now + 3,
            ),
            on(&s, 1, Do::File(filing(2, "design")), now + 3),
        ];
        for made in acts {
            assert!(at(&made[0]) <= now + 3 + KEPT_SECS + 1, "{made:?}");
        }
        let held = acts_of(&kept(&s, 1));
        for act in held_before {
            assert!(held.contains(&act), "{act:?}");
        }
        assert_eq!(filed(&s, 1), ["design", "review"]);

        // Its clock put right, the laptop writes its list again.
        let ahead = kept(&s, 0).fetched;
        assert!(ahead > u64::try_from(now + 100).unwrap());
        fetch_from(&s, &[1], 0, now + 100);
        assert_eq!(kept(&s, 0).fetched, u64::try_from(now + 100).unwrap());
        assert!(!fetch(&s, 0, now + 101));
    }

    // ── Fresh lists ─────────────────────────────────────────────────────

    /// A list is fresh by the reader's first holding of it and by its
    /// fetched time (decision 2026-10-10 §3.4, "fresh"): a writer whose
    /// clock is 120 days ahead has its undo freed 90 days after each
    /// reader first held it, by the reader's clock; a reader whose clock
    /// is 120 days ahead finds the others' fetched times 120 days behind
    /// its clock, and takes their acts once its clock is put right; and a
    /// device whose clock is 31 days behind another's fetched time makes
    /// an act that is dated above every act and fetched time it holds, and
    /// wins on every device, and the device names the other, whose
    /// fetched time is ahead of its clock.
    #[test]
    fn freshness_goes_by_first_holding_and_the_fetch() {
        let fresh = || {
            let s = person(3, 3);
            let now = s.now + 10;
            for n in 0..3 {
                fetch(&s, n, now);
            }
            (s, now)
        };

        // The laptop's clock is 120 days ahead: it subscribes and then
        // unsubscribes.
        let (s, now) = fresh();
        let ahead = now + 120 * DAY;
        fetch(&s, 0, ahead);
        on(&s, 0, Do::Subscribe(subscription(1, "notes", true)), ahead);
        fetch_from(&s, &[0], 1, now + 9);
        on(
            &s,
            0,
            Do::Subscribe(subscription(1, "notes", false)),
            ahead + 1,
        );
        fetch_from(&s, &[0], 1, now + 10);
        assert_eq!(subscribes(&s, 1, 1, "notes"), Some(false));
        // The desktop frees it 90 days after it first held it, by its own
        // clock, and not a second before; the laptop by its own.
        fetch(&s, 1, now + 10 + KEPT_SECS - 1);
        assert_eq!(kept(&s, 1).subscriptions.len(), 1);
        fetch(&s, 1, now + 10 + KEPT_SECS);
        assert!(kept(&s, 1).subscriptions.is_empty());
        fetch(&s, 0, ahead + KEPT_SECS);
        assert_eq!(kept(&s, 0).subscriptions.len(), 1);
        fetch(&s, 0, ahead + 1 + KEPT_SECS);
        assert!(kept(&s, 0).subscriptions.is_empty());

        // The phone's clock is 120 days ahead of the desktop's: the
        // desktop's fetched time is 120 days behind it, and the phone
        // takes the desktop's act once its clock is put right.
        let (s, now) = fresh();
        on(&s, 1, Do::Label(label(4, Some("bob"))), now + 1);
        fetch_from(&s, &[1], 2, now + 120 * DAY);
        assert_eq!(labelled(&s, 2, 4), None);
        fetch_from(&s, &[1], 2, now + 2);
        assert_eq!(labelled(&s, 2, 4), Some(Some("bob".into())));

        // The desktop's list says a fetched time 31 days ahead of the
        // laptop's clock.
        let (s, now) = fresh();
        let desktop = now + 31 * DAY;
        fetch(&s, 1, desktop);
        on(&s, 1, Do::Label(label(5, Some("carol"))), desktop);
        fetch_from(&s, &[1], 0, now + 1);
        let ahead_here = ahead_of_this_clock(&s[0].conn, &s[0].identity, now + 1).unwrap();
        assert_eq!(ahead_here, [(s.key(1), u64::try_from(desktop).unwrap())]);
        // Its own list, ahead of its clock put right, it does not name.
        give(&s, 0, 1, now + 1);
        assert!(
            ahead_of_this_clock(&s[1].conn, &s[1].identity, now + 1)
                .unwrap()
                .is_empty()
        );
        let made = on(&s, 0, Do::Label(label(5, Some("not carol"))), now + 2);
        assert_eq!(at(&made[0]), desktop + 2);
        for n in [1, 2] {
            fetch_from(&s, &[0, 1], n, desktop + 3);
        }
        for n in 0..3 {
            assert_eq!(
                labelled(&s, n, 5),
                Some(Some("not carol".into())),
                "device {n}"
            );
        }
    }

    // ── Places, bounds and freeing ──────────────────────────────────────

    /// A drop and a move take no place (decision 2026-10-10 §3.4): with
    /// 16 channels filed a 17th is refused, a drop frees a place at once,
    /// and a move goes through with 16 held. A stolen phone's 16 filings,
    /// newer than the person's, are what the devices hold while it counts;
    /// once it is removed they are left out on every device, before the
    /// person's own.
    #[test]
    fn a_drop_and_a_move_take_no_place() {
        let mut s = person(3, 3);
        let mut now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        for seed in 0..16 {
            on(&s, 0, Do::File(filing(seed, &format!("c{seed}"))), now + 1);
        }
        assert_eq!(
            refused(&s, 0, Do::File(filing(16, "c16")), now + 2),
            Refused::Full(Part::Channel)
        );
        // Filed again under another name, a channel takes its own place.
        on(&s, 0, Do::File(filing(3, "renamed")), now + 2);
        on(&s, 0, Do::Drop(channel(0)), now + 3);
        on(&s, 0, Do::File(filing(16, "c16")), now + 3);
        assert_eq!(kept(&s, 0).filings.len(), 16);
        on(
            &s,
            0,
            Do::Move {
                from: channel(1),
                to: Filing {
                    came: Came::Moved(channel(1)),
                    ..filing(17, "c1")
                },
            },
            now + 4,
        );
        let held = kept(&s, 0);
        assert_eq!(held.filings.len(), 16);
        assert_eq!(held.drops.len(), 2);
        assert!(filed(&s, 0).contains(&"renamed".to_string()));
        let person_s: Vec<String> = filed(&s, 0);

        // The phone, in someone else's hands while it counts, writes a
        // list of 16 filings of its own, later.
        fetch_from(&s, &[0], 1, now + 5);
        let at = u64::try_from(now + 1000).unwrap();
        let phone_s: Vec<AnyAct> = (100..116)
            .map(|seed| {
                let made = Act::make(
                    filing(seed, &format!("p{seed}")),
                    at,
                    0,
                    &s[2].identity,
                    is_a_name,
                );
                AnyAct::Filing(made.unwrap())
            })
            .collect();
        write_by_hand(&s, 2, &s.key(2), value_of(phone_s, at), now + 6);
        for n in [0, 1] {
            fetch_from(&s, &[2], n, now + 7);
            let names = filed(&s, n);
            assert!(names.iter().all(|name| name.starts_with('p')), "{names:?}");
            assert_eq!(holds(&s[n].conn).unwrap().left_out.len(), 16, "device {n}");
        }
        s.now = now + 8;
        s.change(0, &[0, 1], &[2]);
        now = s.now + 1;
        give(&s, 0, 1, now);
        for n in [0, 1] {
            fetch_from(&s, &[0, 1], n, now);
            assert_eq!(filed(&s, n), person_s, "device {n}");
            let left_out = holds(&s[n].conn).unwrap().left_out;
            assert_eq!(left_out.len(), 16, "device {n}");
            assert!(
                left_out
                    .iter()
                    .all(|(act, maker)| act.maker() == s.key(2) && *maker == Maker::Removed)
            );
        }
    }

    /// Past a bound the undone items stay (decision 2026-10-10 §3.4,
    /// "past a bound"): the laptop and the desktop, apart, file 17
    /// channels between them, and the laptop drops 64 while the desktop
    /// drops one more that both held; and they make 33 subscriptions, 13
    /// of them undone. Each, with the other's list, keeps every undone
    /// subscription and leaves out the oldest in force, and leaves out the
    /// oldest filing, naming both as left out. The laptop frees its oldest
    /// drop early, and its freed record holds it back while the desktop's
    /// list carries it.
    #[test]
    fn past_a_bound_the_undone_items_stay() {
        let s = person(2, 2);
        let now = s.now + 10;
        for n in 0..2 {
            fetch(&s, n, now);
        }
        on(&s, 0, Do::File(filing(0, "d0")), now + 1);
        on(&s, 0, Do::File(filing(64, "d64")), now + 1);
        fetch_from(&s, &[0], 1, now + 2);
        // Apart: the laptop drops 64 channels, the oldest first; the
        // desktop drops one more.
        on(&s, 0, Do::Drop(channel(0)), now + 3);
        for seed in 1..64u8 {
            let t = now + 3 + i64::from(seed) * 2;
            on(&s, 0, Do::File(filing(seed, &format!("d{seed}"))), t);
            on(&s, 0, Do::Drop(channel(seed)), t + 1);
        }
        on(&s, 1, Do::Drop(channel(64)), now + 200);
        let t = now + 300;
        for seed in 0..17u8 {
            let n = usize::from(seed % 2);
            on(
                &s,
                n,
                Do::File(filing(100 + seed, &format!("f{seed:02}"))),
                t + i64::from(seed),
            );
        }
        let t = now + 400;
        // The 13 the desktop undoes, each subscribed on both devices first:
        // an undo is taken only of what a device holds or held.
        for k in 0..13u8 {
            let agent = format!("u{k:02}");
            on(&s, 0, Do::Subscribe(subscription(200, &agent, true)), t);
            on(&s, 1, Do::Subscribe(subscription(200, &agent, true)), t);
            on(
                &s,
                1,
                Do::Subscribe(subscription(200, &agent, false)),
                t + 100 + i64::from(k),
            );
        }
        // 19 more on the laptop, which fill its 32, and one on the desktop.
        for k in 0..19u8 {
            on(
                &s,
                0,
                Do::Subscribe(subscription(200, &format!("a{k:02}"), true)),
                t + 200 + i64::from(k),
            );
        }
        on(
            &s,
            1,
            Do::Subscribe(subscription(200, "a19", true)),
            t + 250,
        );
        // And 65 labels between them.
        let t = now + 700;
        for k in 0..65u8 {
            let n = usize::from(k % 2);
            on(
                &s,
                n,
                Do::Label(label(k, Some(&format!("k{k:02}")))),
                t + i64::from(k),
            );
        }
        // The desktop takes the laptop's list first, with its 64 drops.
        for _ in 0..2 {
            for n in [1, 0] {
                fetch_from(&s, &[1 - n], n, now + 900);
            }
        }
        for n in 0..2 {
            let held = kept(&s, n);
            assert_eq!(held.filings.len(), 16, "device {n}");
            assert!(
                !held.filings.iter().any(|a| a.item.name == "f00"),
                "device {n}"
            );
            let left_out = holds(&s[n].conn).unwrap().left_out;
            let left: Vec<String> = left_out
                .iter()
                .map(|(act, _)| match act {
                    AnyAct::Filing(a) => a.item.name.clone(),
                    AnyAct::Subscription(a) => a.item.agent.clone(),
                    AnyAct::Label(a) => a.item.label.clone().unwrap(),
                    other => panic!("{other:?}"),
                })
                .collect();
            assert_eq!(left, ["f00", "a00", "k00"], "device {n}");
            assert_eq!(held.labels.len(), 64, "device {n}");
            assert_eq!(held.subscriptions.len(), 32, "device {n}");
            let undone = held
                .subscriptions
                .iter()
                .filter(|a| !a.item.subscribed)
                .count();
            assert_eq!(undone, 13, "device {n}");
        }
        // The laptop holds 64 drops, and freed its oldest early.
        let laptop = kept(&s, 0);
        assert_eq!(laptop.drops.len(), 64);
        assert!(!laptop.drops.iter().any(|a| a.item.channel == channel(0)));
        assert!(laptop.drops.iter().any(|a| a.item.channel == channel(64)));
        let freed: Vec<Vec<u8>> = Lists::load(&s[0].conn)
            .unwrap()
            .freed
            .into_keys()
            .map(|(_, item)| item)
            .collect();
        assert_eq!(freed, [channel(0).to_vec()]);
        // The desktop took the drops of the channels it held, the oldest
        // among them; the laptop, given its list again, does not take it.
        let desktop: Vec<[u8; 32]> = kept(&s, 1).drops.iter().map(|a| a.item.channel).collect();
        assert_eq!(desktop.len(), 2);
        assert!(desktop.contains(&channel(0)) && desktop.contains(&channel(64)));
        fetch_from(&s, &[1], 0, now + 901);
        let laptop = kept(&s, 0);
        assert_eq!(laptop.drops.len(), 64);
        assert!(!laptop.drops.iter().any(|a| a.item.channel == channel(0)));
        assert!(!filed(&s, 0).contains(&"d0".to_string()));
    }

    /// An undone act frees its place 90 days after a device first held it
    /// (decision 2026-10-10 §3.4): a drop, an unsubscription and a removed
    /// label each leave the laptop's list then, and not a second before.
    /// While the phone's list, fresh, still carries the older filing that
    /// the drop undid, the laptop does not take it back.
    #[test]
    fn an_undone_act_frees_its_place_90_days_after_it_was_first_held() {
        let s = person(3, 3);
        let now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        on(&s, 0, Do::File(filing(1, "review")), now + 1);
        on(
            &s,
            0,
            Do::Subscribe(subscription(1, "notes", true)),
            now + 1,
        );
        on(&s, 0, Do::Label(label(9, Some("bob"))), now + 1);
        fetch_from(&s, &[0], 2, now + 2);
        assert_eq!(filed(&s, 2), ["review"]);
        // The laptop undoes all three; the phone is never given it.
        let undone_at = now + 3;
        on(&s, 0, Do::Drop(channel(1)), undone_at);
        on(
            &s,
            0,
            Do::Subscribe(subscription(1, "notes", false)),
            undone_at,
        );
        on(&s, 0, Do::Label(label(9, None)), undone_at);
        // A 17th channel: the drop frees a place at once.
        for seed in 2..18 {
            on(
                &s,
                0,
                Do::File(filing(seed, &format!("c{seed}"))),
                undone_at,
            );
        }
        assert_eq!(kept(&s, 0).filings.len(), 16);
        // The phone goes on fetching, with no word of the laptop's.
        for day in [30, 60, 89] {
            fetch(&s, 2, now + day * DAY);
        }
        fetch_from(&s, &[2], 0, undone_at + KEPT_SECS - 1);
        let held = kept(&s, 0);
        assert_eq!(
            (
                held.drops.len(),
                held.subscriptions.len(),
                held.labels.len()
            ),
            (1, 1, 1)
        );
        fetch_from(&s, &[2], 0, undone_at + KEPT_SECS);
        let held = kept(&s, 0);
        assert_eq!(
            (
                held.drops.len(),
                held.subscriptions.len(),
                held.labels.len()
            ),
            (0, 0, 0)
        );
        // The phone's list carries what the laptop undid, and the laptop
        // takes none of it back.
        let phone = kept(&s, 2);
        assert_eq!(
            (
                phone.filings.len(),
                phone.subscriptions.len(),
                phone.labels.len()
            ),
            (1, 1, 1)
        );
        assert!(!filed(&s, 0).contains(&"review".to_string()));
        assert_eq!(subscribes(&s, 0, 1, "notes"), None);
        assert_eq!(labelled(&s, 0, 9), None);
        assert_eq!(Lists::load(&s[0].conn).unwrap().freed.len(), 3);
        // Nor at the next whole fetch, with the phone's list still fresh.
        fetch_from(&s, &[2], 0, undone_at + KEPT_SECS + 1);
        assert!(!filed(&s, 0).contains(&"review".to_string()));
        assert_eq!(subscribes(&s, 0, 1, "notes"), None);
        assert_eq!(labelled(&s, 0, 9), None);
        // Once the phone's list is no longer fresh, the laptop lets the
        // freed acts go, and takes nothing back.
        fetch(&s, 0, now + 89 * DAY + KEPT_SECS);
        assert!(Lists::load(&s[0].conn).unwrap().freed.is_empty());
        assert!(!filed(&s, 0).contains(&"review".to_string()));
        assert_eq!(subscribes(&s, 0, 1, "notes"), None);
    }

    /// A drop of a channel nobody filed is not taken (decision 2026-10-10
    /// §3.4): a device takes a drop only of a channel that a list it holds
    /// files, or that it holds or held itself.
    #[test]
    fn a_drop_of_a_channel_nobody_filed_is_not_taken() {
        let s = person(3, 3);
        let now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        let at = u64::try_from(now + 1).unwrap();
        let drop_of = |seed: u8, at: u64| {
            AnyAct::Drop(
                Act::make(
                    Dropped {
                        channel: channel(seed),
                    },
                    at,
                    0,
                    &s[1].identity,
                    is_a_name,
                )
                .unwrap(),
            )
        };
        // The desktop's list holds a drop of a channel it filed, and one
        // of a channel that nobody did.
        let filed_too =
            AnyAct::Filing(Act::make(filing(2, "two"), at, 0, &s[1].identity, is_a_name).unwrap());
        write_by_hand(
            &s,
            1,
            &s.key(1),
            value_of(vec![drop_of(1, at), filed_too], at),
            now + 2,
        );
        fetch_from(&s, &[1], 0, now + 3);
        assert!(kept(&s, 0).drops.is_empty());
        assert_eq!(filed(&s, 0), ["two"]);
        // A drop of a channel the laptop holds is taken.
        let later = vec![drop_of(1, at + 1), drop_of(2, at + 1)];
        write_by_hand(&s, 1, &s.key(1), value_of(later, at + 1), now + 4);
        fetch_from(&s, &[1], 0, now + 5);
        let drops: Vec<[u8; 32]> = kept(&s, 0).drops.iter().map(|a| a.item.channel).collect();
        assert_eq!(drops, [channel(2)]);
        assert!(filed(&s, 0).is_empty());

        // The phone, which held neither, is given the laptop's list, with
        // the drop, and a list of the desktop's that files the channel
        // before it: the drop is of a channel a list it holds files.
        let earlier =
            AnyAct::Filing(Act::make(filing(2, "two"), at, 0, &s[1].identity, is_a_name).unwrap());
        write_by_hand(&s, 1, &s.key(1), value_of(vec![earlier], at + 2), now + 6);
        fetch_from(&s, &[0, 1], 2, now + 7);
        let drops: Vec<[u8; 32]> = kept(&s, 2).drops.iter().map(|a| a.item.channel).collect();
        assert_eq!(drops, [channel(2)]);
        assert!(filed(&s, 2).is_empty());

        // A filing whose signature fails files nothing: the drop beside it
        // is not taken.
        let mut forged = Act::make(filing(3, "three"), at, 0, &s[1].identity, is_a_name).unwrap();
        forged.time += 1;
        write_by_hand(
            &s,
            1,
            &s.key(1),
            value_of(vec![AnyAct::Filing(forged)], at + 3),
            now + 8,
        );
        write_by_hand(
            &s,
            0,
            &s.key(0),
            value_of(vec![drop_of(3, at + 3)], at + 3),
            now + 8,
        );
        fetch_from(&s, &[0, 1], 2, now + 9);
        assert_eq!(kept(&s, 2).drops.len(), 1);
        assert!(filed(&s, 2).is_empty());
    }

    /// A device takes a drop of a channel it held itself, though it
    /// freed its own drop of it (decision 2026-10-10 §3.4): the laptop
    /// drops a channel and frees the drop 90 days on; the desktop, which
    /// still carries it, files the channel again and drops it; the laptop,
    /// which was given only that last drop, takes it.
    #[test]
    fn a_drop_of_a_channel_this_device_held_is_taken_after_it_freed_its_own() {
        let s = person(2, 2);
        let now = s.now + 10;
        for n in 0..2 {
            fetch(&s, n, now);
        }
        on(&s, 0, Do::File(filing(1, "review")), now + 1);
        fetch_from(&s, &[0], 1, now + 2);
        on(&s, 0, Do::Drop(channel(1)), now + 3);
        fetch_from(&s, &[0], 1, now + 4);
        assert!(filed(&s, 1).is_empty());
        let later = now + 3 + KEPT_SECS;
        fetch(&s, 1, later - 1);
        fetch_from(&s, &[1], 0, later);
        assert!(kept(&s, 0).drops.is_empty());
        assert_eq!(Lists::load(&s[0].conn).unwrap().freed.len(), 1);
        on(&s, 1, Do::File(filing(1, "review")), later + 1);
        let dropped = on(&s, 1, Do::Drop(channel(1)), later + 2);
        fetch_from(&s, &[1], 0, later + 3);
        assert_eq!(acts_of(&kept(&s, 0)), dropped);
    }

    /// An act is refused where its part is full and it would take a new
    /// place, where it drops or moves from a channel not filed, moves to
    /// one filed, or undoes what is not there, and where what it holds
    /// cannot be written in a list. A device that does not stand applied
    /// makes nothing.
    #[test]
    fn an_act_is_refused_past_its_part_and_where_it_has_nothing_to_do() {
        let mut s = person(2, 2);
        let now = s.now + 10;
        fetch(&s, 0, now);
        assert_eq!(refused(&s, 0, Do::Drop(channel(1)), now), Refused::NotFiled);
        let moved = Do::Move {
            from: channel(1),
            to: filing(2, "two"),
        };
        assert_eq!(refused(&s, 0, moved, now), Refused::NotFiled);
        on(&s, 0, Do::File(filing(1, "one")), now);
        on(&s, 0, Do::File(filing(2, "two")), now);
        let moved = Do::Move {
            from: channel(1),
            to: filing(2, "two"),
        };
        assert_eq!(refused(&s, 0, moved, now), Refused::Filed);
        let none = Do::Subscribe(subscription(1, "notes", false));
        assert_eq!(refused(&s, 0, none, now), Refused::NothingToUndo);
        assert_eq!(
            refused(&s, 0, Do::Label(label(1, None)), now),
            Refused::NothingToUndo
        );
        for k in 0..32u8 {
            on(
                &s,
                0,
                Do::Subscribe(subscription(1, &format!("a{k}"), true)),
                now,
            );
        }
        let more = Do::Subscribe(subscription(1, "a32", true));
        assert_eq!(refused(&s, 0, more, now), Refused::Full(Part::Subscription));
        // Undone, a subscription keeps its place, and is done again.
        on(&s, 0, Do::Subscribe(subscription(1, "a0", false)), now);
        let again = Do::Subscribe(subscription(1, "a0", false));
        assert_eq!(refused(&s, 0, again, now), Refused::NothingToUndo);
        on(&s, 0, Do::Subscribe(subscription(1, "a0", true)), now);
        for k in 0..64u8 {
            on(&s, 0, Do::Label(label(k, Some("k"))), now);
        }
        let more = Do::Label(label(64, Some("k")));
        assert_eq!(refused(&s, 0, more, now), Refused::Full(Part::Label));
        on(&s, 0, Do::Label(label(1, Some("again"))), now);
        let long = Do::Label(label(2, Some(&"l".repeat(65))));
        on(&s, 0, Do::Label(label(1, None)), now);
        let again = Do::Label(label(1, None));
        assert_eq!(refused(&s, 0, again, now), Refused::NothingToUndo);
        assert!(matches!(
            refused(&s, 0, long, now),
            Refused::NotWritten(ListError::Label)
        ));
        let not_a_name = Do::File(filing(3, "Not A Name"));
        assert!(matches!(
            refused(&s, 0, not_a_name, now),
            Refused::NotWritten(ListError::Name)
        ));

        // Removed, the desktop makes nothing.
        s.now = now + 1;
        s.change(0, &[0], &[1]);
        give(&s, 0, 1, now + 2);
        let made = act(
            &s[1].conn,
            &s[1].identity,
            Do::File(filing(3, "three")),
            now + 2,
        );
        assert!(matches!(made, Err(PersonError::Stopped(_))), "{made:?}");
    }

    // ── When a list is written ─────────────────────────────────────────

    /// The entry of device `n`'s own list in the personal channel, as its
    /// store holds it: its revision and its list.
    fn written(s: &Several, n: usize) -> Option<(u64, SharedList)> {
        let personal = s[n].personal();
        let id = derive::channel_id(&personal).unwrap();
        let name = list_name(&s.key(n)).unwrap();
        let slot = slot_id(&derive::slot_key(&personal).unwrap(), &name);
        let held = entries::author_entry(&s[n].conn, &id, &slot, &s.key(n)).unwrap()?;
        let rev = held.entry.rev;
        let inside = held.entry.check().unwrap().open(&personal).unwrap();
        assert_eq!(inside.name, name);
        Some((
            rev,
            SharedList::from_value(&inside.value, is_a_name).unwrap(),
        ))
    }

    /// A device writes its list at each act of its own, at once, with the
    /// fetched time of its last whole fetch; and at a whole fetch only
    /// where what it took changed its list, where 30 days have passed
    /// since it last wrote it, or where the fetched time it last wrote is
    /// ahead of its clock, with that fetch's time (decision 2026-10-10
    /// §3.4). A device that holds nothing writes no list.
    #[test]
    fn a_device_writes_its_list_at_an_act_and_at_a_whole_fetch_only_where_it_must() {
        let s = person(2, 2);
        let now = s.now + 10;
        assert!(!fetch(&s, 0, now));
        assert!(!fetch(&s, 0, now + 1));
        assert_eq!(written(&s, 0), None);
        on(&s, 0, Do::Label(label(1, Some("bob"))), now + 5);
        let (rev, list) = written(&s, 0).unwrap();
        assert_eq!(list.fetched, u64::try_from(now + 1).unwrap());
        assert_eq!(list, kept(&s, 0));
        // Nothing changed: not written again.
        assert!(!fetch(&s, 0, now + 6));
        assert_eq!(written(&s, 0).unwrap().0, rev);
        // The desktop's act, taken: written, with the fetch's time.
        fetch(&s, 1, now + 7);
        on(&s, 1, Do::Label(label(2, Some("carol"))), now + 7);
        assert!(fetch_from(&s, &[1], 0, now + 8));
        let (again, list) = written(&s, 0).unwrap();
        assert!(again > rev);
        assert_eq!(list.fetched, u64::try_from(now + 8).unwrap());
        // 30 days on, and not a second before.
        let written_at = now + 8;
        assert!(!fetch(&s, 0, written_at + WRITTEN_AGAIN_SECS - 1));
        assert!(fetch(&s, 0, written_at + WRITTEN_AGAIN_SECS));
        let (_, list) = written(&s, 0).unwrap();
        assert_eq!(
            list.fetched,
            u64::try_from(written_at + WRITTEN_AGAIN_SECS).unwrap()
        );
        // A fetched time ahead of its clock, the clock put right.
        assert!(fetch(&s, 0, written_at + WRITTEN_AGAIN_SECS - 10));
        assert!(!fetch(&s, 0, written_at + WRITTEN_AGAIN_SECS - 9));
        assert_eq!(WRITTEN_AGAIN_SECS, 30 * DAY);
        assert_eq!(KEPT_SECS, 90 * DAY);
    }

    // ── Coming back ─────────────────────────────────────────────────────

    /// A device away for more than 90 days brings nothing back (decision
    /// 2026-10-10 §3.4, "a device that comes back"), off, and running with
    /// no relay reached: the desktop holds a filing and a subscription;
    /// the laptop drops the channel and unsubscribes; 91 days pass and the
    /// laptop and the phone free the undo. Neither, nor a tablet added
    /// then, takes the desktop's list; the desktop, back, finds its own
    /// list not fresh, takes the filing and the subscription out of it,
    /// and holds neither. What it did while it reached no relay it keeps.
    #[test]
    fn a_device_away_for_more_than_90_days_brings_nothing_back() {
        for running in [false, true] {
            let mut s = person(4, 3);
            let now = s.now + 10;
            for n in 0..3 {
                fetch(&s, n, now);
            }
            on(&s, 0, Do::File(filing(1, "review")), now + 1);
            on(
                &s,
                0,
                Do::Subscribe(subscription(1, "notes", true)),
                now + 1,
            );
            for n in [1, 2] {
                fetch_from(&s, &[0], n, now + 2);
            }
            assert_eq!(filed(&s, 1), ["review"]);
            give(&s, 1, 0, now + 3);
            // The desktop is away. The laptop undoes both; the phone takes it.
            on(&s, 0, Do::Drop(channel(1)), now + 4);
            on(
                &s,
                0,
                Do::Subscribe(subscription(1, "notes", false)),
                now + 4,
            );
            fetch_from(&s, &[0], 2, now + 5);
            if running {
                // Running with no relay, the desktop labels a key.
                on(&s, 1, Do::Label(label(9, Some("bob"))), now + 50 * DAY);
            }
            let back = now + 91 * DAY;
            for n in [0, 2] {
                fetch_from(&s, &[0, 2], n, back);
                assert!(kept(&s, n).drops.is_empty(), "device {n}");
            }
            for n in [0, 2] {
                fetch_from(&s, &[0, 2], n, back + 1);
            }
            s.now = back + 2;
            s.add(0, 3);
            for n in [0, 2, 3] {
                fetch_from(&s, &[0, 1, 2], n, back + 3);
                assert!(filed(&s, n).is_empty(), "device {n}");
                assert_eq!(subscribes(&s, n, 1, "notes"), None, "device {n}");
                assert_eq!(labelled(&s, n, 9), None, "device {n}");
            }
            // The desktop is back.
            assert!(fetch_from(&s, &[0, 2, 3], 1, back + 4));
            assert!(filed(&s, 1).is_empty(), "running: {running}");
            assert_eq!(subscribes(&s, 1, 1, "notes"), None, "running: {running}");
            let label = labelled(&s, 1, 9);
            assert_eq!(
                label,
                running.then(|| Some("bob".to_string())),
                "running: {running}"
            );
            for n in [0, 2, 3] {
                fetch_from(&s, &[1], n, back + 5);
                assert!(filed(&s, n).is_empty(), "device {n}");
                assert_eq!(labelled(&s, n, 9), running.then(|| Some("bob".to_string())));
            }
        }

        // A person's one laptop, with three channels, two subscriptions
        // and four labels, is shut for 91 days: opened, it holds them all
        // after its first whole fetch.
        let s = person(1, 1);
        let now = s.now + 10;
        fetch(&s, 0, now);
        for seed in 1..=3 {
            on(&s, 0, Do::File(filing(seed, &format!("c{seed}"))), now + 1);
        }
        for agent in ["notes", "~"] {
            on(&s, 0, Do::Subscribe(subscription(1, agent, true)), now + 1);
        }
        for key in 1..=4 {
            on(&s, 0, Do::Label(label(key, Some("k"))), now + 1);
        }
        let before = in_force(&s, 0);
        assert_eq!(before.len(), 9);
        assert!(fetch(&s, 0, now + 91 * DAY));
        assert_eq!(in_force(&s, 0), before);
    }

    /// An act made with no relay survives coming back (decision 2026-10-10
    /// §3.4): the laptop reaches no relay from day 0; on day 95 it
    /// subscribes a folder; the desktop writes its list on day 97; on day
    /// 100 the laptop reaches a relay, and the subscription is kept on
    /// every device. What the laptop held at its last whole fetch, and the
    /// desktop's list still carries, it keeps too.
    #[test]
    fn an_act_made_with_no_relay_survives_coming_back() {
        let s = person(2, 2);
        let now = s.now + 10;
        for n in 0..2 {
            fetch(&s, n, now);
        }
        on(&s, 1, Do::File(filing(1, "review")), now + 1);
        on(&s, 1, Do::Label(label(4, Some("bob"))), now + 1);
        fetch_from(&s, &[1], 0, now + 2);
        on(
            &s,
            0,
            Do::Subscribe(subscription(1, "notes", true)),
            now + 95 * DAY,
        );
        // The desktop fetches all the while, with no word of the laptop's.
        for day in [30, 60, 90, 97] {
            fetch(&s, 1, now + day * DAY);
        }
        on(&s, 1, Do::Label(label(4, None)), now + 97 * DAY);
        assert!(fetch_from(&s, &[1], 0, now + 100 * DAY));
        fetch_from(&s, &[0], 1, now + 100 * DAY + 1);
        for n in 0..2 {
            assert_eq!(subscribes(&s, n, 1, "notes"), Some(true), "device {n}");
            assert_eq!(filed(&s, n), ["review"], "device {n}");
            assert_eq!(labelled(&s, n, 4), Some(None), "device {n}");
        }
    }

    /// A list is read only from its writer's own entry under its own
    /// name, in the generation applied (decision 2026-10-10 §3.4): one
    /// that is a delete, or in a band above the statement's, is passed
    /// over, and the newest one that is not is read.
    #[test]
    fn a_list_is_read_only_from_its_writers_own_entry_under_the_statement() {
        let s = person(2, 2);
        let now = s.now + 10;
        for n in 0..2 {
            fetch(&s, n, now);
        }
        on(&s, 1, Do::Label(label(4, Some("bob"))), now + 1);
        give(&s, 1, 0, now + 2);
        let read = |s: &Several| lists_held(&s[0].conn, &standing(s, 0), &s.key(0)).unwrap();
        assert_eq!(read(&s).len(), 1);
        assert_eq!(read(&s)[0].list.labels.len(), 1);
        assert_eq!(read(&s)[0].first_held, now + 2);

        // An entry of the desktop's at a revision in the band above the
        // statement's, put in the laptop's store as it is.
        let personal = s[1].personal();
        let name = list_name(&s.key(1)).unwrap();
        let above = (s[1].number() + 1) << cordelia_core::protocol::REV_COUNT_BITS;
        let inside = Inside {
            name: name.clone(),
            value: Value::Other(value_of(Vec::new(), 1)),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&personal, &s[1].identity, above, &inside).unwrap();
        entries::store(&s[0].conn, &entry.check().unwrap(), now + 3).unwrap();
        assert!(read(&s).is_empty());
        // And a delete of the desktop's there.
        let id = derive::channel_id(&personal).unwrap();
        let slot = slot_id(&derive::slot_key(&personal).unwrap(), &name);
        s[0].conn
            .execute(
                "DELETE FROM entries WHERE channel_id = ?1 AND slot = ?2",
                rusqlite::params![id.as_slice(), slot.as_slice()],
            )
            .unwrap();
        let deleted = Inside {
            value: Value::Delete,
            ..inside
        };
        let entry = Entry::seal(&personal, &s[1].identity, 5, &deleted).unwrap();
        entries::store(&s[0].conn, &entry.check().unwrap(), now + 4).unwrap();
        assert!(read(&s).is_empty());
        give(&s, 1, 0, now + 5);
        assert!(read(&s).is_empty(), "the delete is at a higher revision");
    }

    /// A device whose own list is fresh takes nothing out at a whole
    /// fetch, though another device's fresh list, fetched after the item,
    /// holds nothing for it; nor does one whose own list is not fresh,
    /// where the other list was fetched before the item's time (decision
    /// 2026-10-10 §3.4, "a device that comes back").
    #[test]
    fn a_device_whose_own_list_is_fresh_takes_nothing_out() {
        let s = person(2, 2);
        let now = s.now + 10;
        for n in 0..2 {
            fetch(&s, n, now);
        }
        on(&s, 0, Do::File(filing(1, "review")), now + 1);
        fetch(&s, 0, now + 2);
        // The desktop fetches after the filing, with no word of it.
        fetch(&s, 1, now + 3);
        on(&s, 1, Do::Label(label(4, Some("bob"))), now + 3);
        assert!(fetch_from(&s, &[1], 0, now + 4));
        assert_eq!(filed(&s, 0), ["review"]);

        // Away for 91 days, holding a filing that the desktop, whose clock
        // was 100 days ahead, dated: the phone's list, fresh, holds nothing
        // for it, and was fetched before the filing's time.
        let s = person(3, 3);
        let now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        on(&s, 2, Do::Label(label(4, Some("bob"))), now + 1);
        fetch(&s, 1, now + 100 * DAY);
        let ahead = on(&s, 1, Do::File(filing(1, "review")), now + 100 * DAY);
        fetch_from(&s, &[1], 0, now + 1);
        fetch(&s, 0, now + 2);
        for day in [31, 61, 91] {
            fetch(&s, 2, now + day * DAY);
        }
        let back = now + 92 * DAY;
        give(&s, 2, 0, back);
        let phone = lists_held(&s[0].conn, &standing(&s, 0), &s.key(0)).unwrap();
        let phone = phone.iter().find(|read| read.writer == s.key(2)).unwrap();
        assert!(phone.is_fresh(back));
        assert!(phone.list.fetched < ahead[0].time());
        fetch(&s, 0, back);
        assert_eq!(filed(&s, 0), ["review"]);

        // Away for 91 days, holding an unsubscription that the desktop's
        // list, fresh, does not hold: it carries the older subscription in
        // its place, so the laptop keeps its own act.
        let s = person(2, 2);
        let now = s.now + 10;
        for n in 0..2 {
            fetch(&s, n, now);
        }
        on(
            &s,
            1,
            Do::Subscribe(subscription(1, "notes", true)),
            now + 1,
        );
        fetch_from(&s, &[1], 0, now + 2);
        on(
            &s,
            0,
            Do::Subscribe(subscription(1, "notes", false)),
            now + 3,
        );
        fetch(&s, 0, now + 4);
        for day in [30, 60, 90] {
            fetch(&s, 1, now + day * DAY);
        }
        fetch_from(&s, &[1], 0, now + 4 + KEPT_SECS);
        assert_ne!(subscribes(&s, 0, 1, "notes"), Some(true));
    }

    // ── A recovery's read ───────────────────────────────────────────────

    /// A list of `acts`, saying `fetched`.
    fn list(acts: Vec<AnyAct>, fetched: i64) -> SharedList {
        list_of(acts, u64::try_from(fetched).unwrap())
    }

    /// A recovery takes the lists of the devices it shows by the newest
    /// fetched time among them, each taken as no later than its clock, and
    /// the lists of devices in someone else's hands left out of that
    /// newest time (decision 2026-10-10 §3.5): the desktop, in someone
    /// else's hands, says a time a year ahead, and the laptop's and the
    /// phone's lists, 100 and 120 days behind the clock, are taken all the
    /// same, the tablet's 200 days behind the laptop's is not. The
    /// desktop's act is taken, as a removed key's, and the laptop's, which
    /// the person has, is held and not in force.
    #[test]
    fn a_recovery_reads_the_lists_by_the_newest_fetch_of_devices_not_in_other_hands() {
        let s = person(4, 4);
        let now = s.now + 400 * DAY;
        let at = |days: i64| u64::try_from(now - days * DAY).unwrap();
        let made = |n: usize, item: AnyAct| -> AnyAct {
            let by = &s[n].identity;
            match item {
                AnyAct::Label(a) => {
                    AnyAct::Label(Act::make(a.item, a.time, 0, by, is_a_name).unwrap())
                }
                AnyAct::Subscription(a) => {
                    AnyAct::Subscription(Act::make(a.item, a.time, 0, by, is_a_name).unwrap())
                }
                AnyAct::Filing(a) => {
                    AnyAct::Filing(Act::make(a.item, a.time, 0, by, is_a_name).unwrap())
                }
                AnyAct::Drop(a) => {
                    AnyAct::Drop(Act::make(a.item, a.time, 0, by, is_a_name).unwrap())
                }
            }
        };
        let unsigned = |item: AnyAct| item;
        let draft = |n: usize, what: AnyAct| made(n, unsigned(what));
        let label_at = |key: u8, time: u64| {
            AnyAct::Label(Act {
                item: label(key, Some("k")),
                time,
                count: 0,
                maker: [0; 32],
                signature: [0; 64],
            })
        };
        let subscription_at = |time: u64| {
            AnyAct::Subscription(Act {
                item: subscription(1, "notes", true),
                time,
                count: 0,
                maker: [0; 32],
                signature: [0; 64],
            })
        };
        let filing_at = |time: u64| {
            AnyAct::Filing(Act {
                item: filing(1, "review"),
                time,
                count: 0,
                maker: [0; 32],
                signature: [0; 64],
            })
        };

        let laptop = list(vec![draft(0, subscription_at(at(101)))], now - 100 * DAY);
        let phone = list(vec![draft(2, filing_at(at(121)))], now - 120 * DAY);
        let desktop = list(vec![draft(1, label_at(4, at(5)))], now + 365 * DAY);
        let tablet = list(vec![draft(3, label_at(5, at(301)))], now - 300 * DAY);
        let maker = |key: &[u8; 32]| {
            if *key == s.key(0) {
                Some(Maker::InNoList)
            } else {
                Some(Maker::Removed)
            }
        };
        let lists = [
            (s.key(0), Answered::Have, laptop.clone()),
            (s.key(1), Answered::Hands, desktop.clone()),
            (s.key(2), Answered::Lost, phone.clone()),
            (s.key(3), Answered::Lost, tablet.clone()),
        ];
        let (taken, left_out) = recovered(&lists, maker, now);
        assert!(left_out.filings.is_empty() && left_out.labels.is_empty());
        assert_eq!(taken.subscriptions, laptop.subscriptions);
        assert_eq!(taken.filings, phone.filings);
        assert_eq!(taken.labels, desktop.labels);

        // A list of a device not in someone else's hands that says a time
        // ahead is taken as the clock: then the laptop's, 100 days behind
        // it, is not fresh, and the phone's, 70 behind it, is.
        let phone = list(vec![draft(2, filing_at(at(71)))], now - 70 * DAY);
        let ahead = list(vec![draft(3, label_at(5, at(1)))], now + 30 * DAY);
        let lists = [
            (s.key(0), Answered::Have, laptop.clone()),
            (s.key(2), Answered::Lost, phone.clone()),
            (s.key(3), Answered::Lost, ahead.clone()),
        ];
        let (taken, _) = recovered(&lists, maker, now);
        assert!(taken.subscriptions.is_empty());
        assert_eq!(taken.filings, phone.filings);
        assert_eq!(taken.labels, ahead.labels);

        // Where every list is of a device in someone else's hands, the
        // newest is theirs.
        let lists = [(s.key(1), Answered::Hands, desktop.clone())];
        let (taken, _) = recovered(&lists, maker, now);
        assert_eq!(taken.labels, desktop.labels);
        assert_eq!(recovered(&[], maker, now).0, SharedList::default());
    }

    /// The lists a recovery reads of the entries handed are each shown
    /// device's own newest entry under its own list's name (decision
    /// 2026-10-10 §3.5): not another device's entry in its slot, not a
    /// delete, and nothing of a device not shown.
    #[test]
    fn the_lists_a_recovery_reads_are_each_shown_devices_own() {
        let s = person(3, 3);
        let personal = s[0].personal();
        let entry = |n: usize, of: usize, rev: u64, value: Value| {
            let inside = Inside {
                name: list_name(&s.key(of)).unwrap(),
                value,
                chain: Some(Vec::new()),
            };
            Entry::seal(&personal, &s[n].identity, rev, &inside)
                .unwrap()
                .check()
                .unwrap()
        };
        let of = |fetched: u64| Value::Other(value_of(Vec::new(), fetched));
        let handed = [
            entry(0, 0, 1, of(1)),
            entry(0, 0, 2, of(2)),
            entry(1, 0, 3, of(3)),
            entry(1, 1, 1, of(4)),
            entry(1, 1, 2, Value::Delete),
            entry(2, 2, 1, of(5)),
        ];
        let read = lists_in(&handed, &personal, &[s.key(0), s.key(1)]).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].0, s.key(0));
        assert_eq!(read[0].1.fetched, 2);
        let read = lists_in(&handed, &personal, &[s.key(2)]).unwrap();
        assert_eq!(
            read.iter()
                .map(|(_, list)| list.fetched)
                .collect::<Vec<_>>(),
            [5]
        );
        let other = derive::personal_secret(&[9; 32]).unwrap();
        assert!(lists_in(&handed, &other, &[s.key(2)]).unwrap().is_empty());
    }

    // ── The order and the dating, as they are worked out ────────────────

    /// What orders two acts on one item (decision 2026-10-10 §3.4): the
    /// time; then whether the maker counts; then, at `SHARED_ACT_TIME_MAX`
    /// alone, the item's count; then the maker's key; and last the act's
    /// bytes; the greater above at each.
    #[test]
    fn two_acts_on_one_item_are_ordered_by_time_maker_count_key_and_bytes() {
        let s = person(3, 3);
        let makers = Makers::of(&s[0].conn, &standing(&s, 0)).unwrap();
        let stranger = NodeIdentity::from_seed([0x77; 32]).unwrap();
        let (high, low) = (&s[0].identity, &s[1].identity);
        assert!(high.public_key() > low.public_key());
        assert!(stranger.public_key() > low.public_key());
        let order = |by: &NodeIdentity, subscribed: bool, time: u64, count: u64| {
            let item = subscription(1, "notes", subscribed);
            let act = AnyAct::Subscription(Act::make(item, time, count, by, is_a_name).unwrap());
            Order::of_act(&act, &makers)
        };
        let bound = SHARED_ACT_TIME_MAX;
        // The later time, whatever else.
        assert!(order(low, true, 11, 0) > order(high, true, 10, 0));
        assert!(order(&stranger, true, 11, 0) > order(high, true, 10, 0));
        // At one time, a maker that counts.
        assert!(order(low, true, 10, 0) > order(&stranger, true, 10, 0));
        assert!(order(low, true, bound, 0) > order(&stranger, true, bound, 9));
        // Below the bound the count orders nothing; at it, before the key.
        assert!(order(high, true, 10, 0) > order(low, true, 10, 5));
        assert!(order(low, true, bound, 1) > order(high, true, bound, 0));
        // Then the key; and last the bytes: a subscription above its end,
        // one act's bytes above the other's.
        assert!(order(high, true, 10, 0) > order(low, true, 10, 0));
        assert!(order(high, true, 10, 0) > order(high, false, 10, 0));
        assert_eq!(order(high, true, 10, 0), order(high, true, 10, 0));
    }

    /// A new act is dated one above the greatest of the clock, the newest
    /// time the device holds for the item, an act freed there among them,
    /// and every other act's time and list's fetched time of a key that
    /// counts, each taken as at most 90 days ahead; at the bound, with a
    /// count one above the highest held there of a maker that counts, a
    /// freed act's among them, and never above the bound (decision
    /// 2026-10-10 §3.4).
    #[test]
    fn a_new_act_is_dated_above_what_the_device_holds() {
        let s = person(3, 3);
        // A key the last statement left out, which the device knows, and
        // one it does not.
        let stranger = NodeIdentity::from_seed([0x77; 32]).unwrap();
        let unknown = NodeIdentity::from_seed([0x66; 32]).unwrap();
        cordelia_storage::acts::note_left_out(&s[0].conn, &stranger.public_key(), "phone", 1, 1)
            .unwrap();
        let makers = Makers::of(&s[0].conn, &standing(&s, 0)).unwrap();
        let now: i64 = 1_000_000_000;
        let clock = u64::try_from(now).unwrap();
        let ahead = u64::try_from(KEPT_SECS).unwrap();
        let bound = SHARED_ACT_TIME_MAX;
        let key = (Part::Label, vec![9; 32]);
        let other_key = (Part::Label, vec![8; 32]);
        let act_on = |by: &NodeIdentity, key: u8, time: u64, count: u64| {
            AnyAct::Label(Act::make(label(key, Some("k")), time, count, by, is_a_name).unwrap())
        };
        let with = |acts: Vec<AnyAct>| Lists {
            list: list_of(acts, 0),
            ..Lists::default()
        };
        let freed_at = |time: u64, count: u64| {
            let mut lists = Lists::default();
            let freed = Freed {
                part: Part::Label,
                item: vec![9; 32],
                time,
                count,
                maker: s.key(1),
                act: vec![1],
                freed_at: now,
            };
            lists.freed.insert(key.clone(), freed);
            lists
        };
        let dated_with = |lists: &Lists, others: &[Read], key: &Key| {
            dated(lists, others, &makers, &Checked::default(), key, now)
        };

        assert_eq!(dated_with(&Lists::default(), &[], &key), (clock + 1, 0));
        // The item's own newest time, uncapped, of any maker it takes.
        let far = clock + 5 * ahead;
        let lists = with(vec![act_on(&stranger, 9, far, 0)]);
        assert_eq!(dated_with(&lists, &[], &key), (far + 1, 0));
        // Not of a key it does not know, nor of an act that does not hold.
        let lists = with(vec![act_on(&unknown, 9, far, 0)]);
        assert_eq!(dated_with(&lists, &[], &key), (clock + 1, 0));
        let mut forged = act_on(&s[1].identity, 9, far, 0);
        if let AnyAct::Label(act) = &mut forged {
            act.signature[0] ^= 1;
        }
        assert_eq!(dated_with(&with(vec![forged]), &[], &key), (clock + 1, 0));
        assert_eq!(dated_with(&lists, &[], &other_key), (clock + 1, 0));
        // An act freed on the item.
        assert_eq!(
            dated_with(&freed_at(clock + 500, 0), &[], &key),
            (clock + 501, 0)
        );
        assert_eq!(
            dated_with(&freed_at(clock + 500, 0), &[], &other_key),
            (clock + 1, 0)
        );
        // Another item's act of a key that counts, at most 90 days ahead.
        let lists = with(vec![act_on(&s[1].identity, 4, clock + 20, 0)]);
        assert_eq!(dated_with(&lists, &[], &key), (clock + 21, 0));
        let lists = with(vec![act_on(&s[1].identity, 4, far, 0)]);
        assert_eq!(dated_with(&lists, &[], &key), (clock + ahead + 1, 0));
        // The fetched times of the lists it holds, its own among them.
        let read = |fetched: u64| Read {
            writer: s.key(1),
            list: list_of(Vec::new(), fetched),
            first_held: now,
        };
        assert_eq!(
            dated_with(&Lists::default(), &[read(clock + 7)], &key),
            (clock + 8, 0)
        );
        assert_eq!(
            dated_with(&Lists::default(), &[read(far)], &key),
            (clock + ahead + 1, 0)
        );
        let own = Lists {
            list: list_of(Vec::new(), clock + 9),
            ..Lists::default()
        };
        assert_eq!(dated_with(&own, &[], &key), (clock + 10, 0));
        // At the bound: one above the highest count there of a maker that
        // counts, a freed act's among them; never above the bound.
        let lists = with(vec![act_on(&s[1].identity, 9, bound, 4)]);
        assert_eq!(dated_with(&lists, &[], &key), (bound, 5));
        let lists = with(vec![act_on(&stranger, 9, bound, 4)]);
        assert_eq!(dated_with(&lists, &[], &key), (bound, 0));
        assert_eq!(dated_with(&freed_at(bound, 7), &[], &key), (bound, 8));
        assert_eq!(dated_with(&freed_at(bound - 1, 7), &[], &key), (bound, 0));
        assert_eq!(
            dated_with(&freed_at(bound, bound), &[], &key),
            (bound, bound)
        );
    }

    /// A list that a device first held 90 days before is not fresh to it,
    /// though the fetched time it says is ahead of the device's clock
    /// (decision 2026-10-10 §3.4, "fresh"): the desktop, back after 91
    /// days, finds that no other list is fresh, and keeps what it held.
    #[test]
    fn a_list_first_held_90_days_before_is_not_fresh_whatever_its_fetched_time() {
        let s = person(2, 2);
        let now = s.now + 10;
        fetch(&s, 0, now + 200 * DAY);
        on(&s, 0, Do::Label(label(5, Some("bob"))), now + 200 * DAY);
        fetch(&s, 1, now);
        on(&s, 1, Do::Label(label(6, Some("carol"))), now + 1);
        fetch_from(&s, &[0], 1, now + 2);
        assert_eq!(labelled(&s, 1, 5), Some(Some("bob".into())));
        let back = now + 2 + KEPT_SECS;
        let laptop = lists_held(&s[1].conn, &standing(&s, 1), &s.key(1)).unwrap();
        assert!(!laptop[0].is_fresh(back));
        assert!(laptop[0].is_fresh(back - 1));
        fetch(&s, 1, back);
        assert_eq!(labelled(&s, 1, 6), Some(Some("carol".into())));
    }

    /// An act taken from another device's list is first held when it is
    /// taken, not when an earlier act on its item was: an unsubscription
    /// the desktop makes 89 days after its subscription is freed on the
    /// laptop 90 days after the laptop took it.
    #[test]
    fn an_act_taken_in_the_place_of_another_is_first_held_when_it_is_taken() {
        let s = person(2, 2);
        let now = s.now + 10;
        for n in 0..2 {
            fetch(&s, n, now);
        }
        on(
            &s,
            1,
            Do::Subscribe(subscription(1, "notes", true)),
            now + 1,
        );
        fetch_from(&s, &[1], 0, now + 2);
        let undone_at = now + 89 * DAY;
        fetch(&s, 1, undone_at);
        on(
            &s,
            1,
            Do::Subscribe(subscription(1, "notes", false)),
            undone_at,
        );
        fetch_from(&s, &[1], 0, undone_at + 1);
        assert_eq!(subscribes(&s, 0, 1, "notes"), Some(false));
        fetch(&s, 0, undone_at + KEPT_SECS);
        assert_eq!(kept(&s, 0).subscriptions.len(), 1);
        fetch(&s, 0, undone_at + 1 + KEPT_SECS);
        assert!(kept(&s, 0).subscriptions.is_empty());
    }

    // ── Makers the person never had, places, and undoes of nothing ──────

    /// The acts of a key that was never a device of the person's, as the
    /// device knows them, are not taken at all (decision 2026-10-10
    /// §3.4): a drop of the person's channel signed by such a key, in a
    /// list of a device that counts, undoes nothing, and 16 filings of it
    /// take no place; nor does a removal of the device whose list held
    /// them make them anything.
    #[test]
    fn an_act_of_a_key_the_person_never_had_undoes_nothing_and_takes_no_place() {
        let mut s = person(3, 3);
        let mut now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        on(&s, 0, Do::File(filing(1, "review")), now + 1);
        let stranger = NodeIdentity::from_seed([0x55; 32]).unwrap();
        let at = u64::try_from(now + 2).unwrap();
        let mut acts = vec![AnyAct::Drop(
            Act::make(
                Dropped {
                    channel: channel(1),
                },
                at,
                0,
                &stranger,
                is_a_name,
            )
            .unwrap(),
        )];
        for seed in 100..116 {
            let made = Act::make(filing(seed, "theirs"), at, 0, &stranger, is_a_name);
            acts.push(AnyAct::Filing(made.unwrap()));
        }
        write_by_hand(&s, 1, &s.key(1), value_of(acts, at), now + 3);
        fetch_from(&s, &[1], 0, now + 4);
        assert_eq!(filed(&s, 0), ["review"]);
        assert_eq!(acts_of(&kept(&s, 0)).len(), 1);
        on(&s, 0, Do::File(filing(2, "design")), now + 5);
        s.now = now + 6;
        s.change(0, &[0, 2], &[1]);
        now = s.now + 1;
        give(&s, 0, 2, now);
        for n in [0, 2] {
            fetch_from(&s, &[0, 1, 2], n, now);
            assert_eq!(filed(&s, n), ["design", "review"], "device {n}");
        }
    }

    /// A place is taken by an item in force alone (decision 2026-10-10
    /// §3.4): with 16 filings of a key a settlement left out, held and not
    /// in force, the laptop files a channel, and holds it in force before
    /// them. A rename of a filing that is left out takes a place as a new
    /// filing does; a drop of it needs none.
    #[test]
    fn a_place_is_taken_only_by_an_item_in_force() {
        let mut s = person(3, 3);
        let mut now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        for seed in 100..116 {
            on(&s, 2, Do::File(filing(seed, &format!("p{seed}"))), now + 1);
        }
        fetch_from(&s, &[2], 0, now + 2);
        s.now = now + 3;
        s.change(0, &[0, 1], &[]);
        now = s.now + 1;
        fetch(&s, 0, now);
        assert!(filed(&s, 0).is_empty());
        assert_eq!(kept(&s, 0).filings.len(), 16);
        on(&s, 0, Do::File(filing(1, "review")), now + 1);
        assert_eq!(filed(&s, 0), ["review"]);
        let held = holds(&s[0].conn).unwrap();
        assert_eq!(held.filings.len(), 16);
        assert_eq!(held.left_out.len(), 1);
        // The left-out filing, renamed, would be a new item in force.
        for seed in 2..17 {
            on(&s, 0, Do::File(filing(seed, &format!("c{seed}"))), now + 2);
        }
        let left = match &holds(&s[0].conn).unwrap().left_out[..] {
            [(AnyAct::Filing(left), _), ..] => left.item.channel,
            other => panic!("{other:?}"),
        };
        let rename = Filing {
            channel: left,
            ..filing(100, "renamed")
        };
        let rename = Filing {
            card: holds(&s[0].conn)
                .unwrap()
                .left_out
                .iter()
                .find_map(|(act, _)| match act {
                    AnyAct::Filing(a) if a.item.channel == left => Some(a.item.card.clone()),
                    _ => None,
                })
                .unwrap(),
            ..rename
        };
        assert_eq!(
            refused(&s, 0, Do::File(rename), now + 3),
            Refused::Full(Part::Channel)
        );
        on(&s, 0, Do::Drop(left), now + 3);
    }

    /// An unsubscription or a removed label is taken only of what this
    /// device holds or held, or what a list it takes does (decision
    /// 2026-10-10 §3.4): the desktop's list undoes a subscription and a
    /// label that nobody made, and the laptop takes neither; it takes the
    /// undoing of its own.
    #[test]
    fn an_undo_of_what_nobody_did_is_not_taken() {
        let s = person(2, 2);
        let now = s.now + 10;
        for n in 0..2 {
            fetch(&s, n, now);
        }
        on(
            &s,
            0,
            Do::Subscribe(subscription(1, "notes", true)),
            now + 1,
        );
        on(&s, 0, Do::Label(label(4, Some("bob"))), now + 1);
        let at = u64::try_from(now + 50).unwrap();
        let by = &s[1].identity;
        let undo =
            |sub: Subscription| AnyAct::Subscription(Act::make(sub, at, 0, by, is_a_name).unwrap());
        let unlabel =
            |key| AnyAct::Label(Act::make(label(key, None), at, 0, by, is_a_name).unwrap());
        let mut acts: Vec<AnyAct> = (0..31)
            .map(|k| undo(subscription(2, &format!("x{k:02}"), false)))
            .collect();
        acts.push(undo(subscription(1, "notes", false)));
        acts.push(unlabel(5));
        acts.push(unlabel(4));
        write_by_hand(&s, 1, &s.key(1), value_of(acts, at), now + 3);
        fetch_from(&s, &[1], 0, now + 4);
        let held = kept(&s, 0);
        assert_eq!(held.subscriptions.len(), 1);
        assert_eq!(held.labels.len(), 1);
        assert_eq!(subscribes(&s, 0, 1, "notes"), Some(false));
        assert_eq!(labelled(&s, 0, 4), Some(None));
        on(
            &s,
            0,
            Do::Subscribe(subscription(3, "notes", true)),
            now + 5,
        );
    }

    /// Past a bound the makers that count come first, and then within
    /// each the undone items (decision 2026-10-10 §3.4): a phone in
    /// someone else's hands subscribes 32 agents and unsubscribes them,
    /// and while it counts its undoes push the laptop's subscription out;
    /// once it is removed, the laptop's own is back in force, and the
    /// phone's undoes give way.
    #[test]
    fn past_a_bound_the_makers_that_count_come_before_a_removed_keys_undoes() {
        let mut s = person(3, 3);
        let mut now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        on(
            &s,
            0,
            Do::Subscribe(subscription(1, "notes", true)),
            now + 1,
        );
        for k in 0..32 {
            let agent = format!("x{k:02}");
            on(&s, 2, Do::Subscribe(subscription(2, &agent, true)), now + 2);
        }
        fetch_from(&s, &[2], 0, now + 3);
        for k in 0..32 {
            let agent = format!("x{k:02}");
            on(
                &s,
                2,
                Do::Subscribe(subscription(2, &agent, false)),
                now + 4,
            );
        }
        fetch_from(&s, &[2], 0, now + 5);
        assert_eq!(subscribes(&s, 0, 1, "notes"), None);
        s.now = now + 6;
        s.change(0, &[0, 1], &[2]);
        now = s.now + 1;
        fetch(&s, 0, now);
        assert_eq!(subscribes(&s, 0, 1, "notes"), Some(true));
        let left = holds(&s[0].conn).unwrap().left_out;
        assert_eq!(left.len(), 1);
        assert!(
            matches!(&left[0], (AnyAct::Subscription(a), Maker::Removed) if !a.item.subscribed)
        );
    }

    /// A list whose fetched time is 90 days or more behind the reader's
    /// clock, first held in the last 90 days, is not fresh, so none of its
    /// acts are taken; the reader names it as of a device whose clock is
    /// off, and that device names the reader's list as ahead of its own
    /// (decision 2026-10-10 §3.4, "a clock that is wrong").
    #[test]
    fn a_list_whose_clock_is_90_days_behind_is_named_and_not_taken() {
        let s = person(2, 2);
        let now = s.now + 400 * DAY;
        let behind = now - 100 * DAY;
        fetch(&s, 0, now);
        fetch(&s, 1, behind);
        on(&s, 1, Do::Label(label(4, Some("bob"))), behind);
        fetch_from(&s, &[1], 0, now);
        assert_eq!(labelled(&s, 0, 4), None);
        let named = behind_this_clock(&s[0].conn, &s[0].identity, now).unwrap();
        assert_eq!(named, [(s.key(1), u64::try_from(behind).unwrap())]);
        assert!(
            behind_this_clock(&s[0].conn, &s[0].identity, now + KEPT_SECS)
                .unwrap()
                .is_empty()
        );
        let fresh_enough = now - KEPT_SECS + 1;
        assert!(
            behind_this_clock(&s[0].conn, &s[0].identity, fresh_enough)
                .unwrap()
                .is_empty()
        );
        on(&s, 0, Do::Label(label(5, Some("carol"))), now + 1);
        give(&s, 0, 1, behind + 1);
        let ahead = ahead_of_this_clock(&s[1].conn, &s[1].identity, behind + 1).unwrap();
        assert_eq!(ahead.len(), 1);
        assert_eq!(ahead[0].0, s.key(0));
        // Its clock put right, the desktop's list is taken.
        fetch(&s, 1, now + 2);
        fetch_from(&s, &[1], 0, now + 3);
        assert_eq!(labelled(&s, 0, 4), Some(Some("bob".into())));
    }

    /// A device that comes back takes out of what it left out past a
    /// bound, as of its list, what the others have let go (decision
    /// 2026-10-10 §3.4): the desktop takes the laptop's 15 filings, files
    /// two of its own and leaves out the oldest; the laptop, which never
    /// took the desktop's, drops that channel and frees the drop. The
    /// desktop, back after 91 days, holds nothing of it, and it does not
    /// come back when a place is freed.
    #[test]
    fn a_device_that_comes_back_takes_out_what_it_left_out_too() {
        let s = person(3, 3);
        let now = s.now + 10;
        for n in 0..3 {
            fetch(&s, n, now);
        }
        for seed in 0..15 {
            on(
                &s,
                0,
                Do::File(filing(seed, &format!("c{seed:02}"))),
                now + 1,
            );
        }
        fetch_from(&s, &[0], 1, now + 2);
        on(&s, 1, Do::File(filing(15, "c15")), now + 100);
        on(&s, 2, Do::File(filing(16, "c16")), now + 100);
        fetch_from(&s, &[2], 1, now + 101);
        let left = holds(&s[1].conn).unwrap().left_out;
        assert!(matches!(&left[..], [(AnyAct::Filing(a), _)] if a.item.name == "c00"));
        fetch(&s, 1, now + 101);
        // The laptop drops it, and frees the drop after 90 days.
        on(&s, 0, Do::Drop(channel(0)), now + 3);
        for day in [30, 60, 91] {
            fetch(&s, 0, now + day * DAY);
        }
        assert!(kept(&s, 0).drops.is_empty());
        let back = now + 92 * DAY;
        fetch_from(&s, &[0], 1, back);
        assert!(holds(&s[1].conn).unwrap().left_out.is_empty());
        on(&s, 1, Do::Drop(channel(1)), back + 1);
        fetch(&s, 1, back + 2);
        assert!(!filed(&s, 1).contains(&"c00".to_string()));
        assert!(filed(&s, 1).len() < 16);
    }

    /// A whole fetch on a device whose database cannot be read is an
    /// error, and not a fetch at which nothing was done.
    #[test]
    fn a_whole_fetch_that_cannot_read_the_database_says_so() {
        let s = person(1, 1);
        s[0].conn
            .execute("DROP TABLE person_additions", [])
            .unwrap();
        assert!(fetched_whole(&s[0].conn, &s[0].identity, s.now + 1).is_err());
        let alone = Several::new(1);
        assert!(!fetched_whole(&alone[0].conn, &alone[0].identity, alone.now).unwrap());
    }
}
