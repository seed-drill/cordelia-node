//! The person's lists of shared channels, in the personal channel
//! (decision 2026-10-10 §3.4, §3.5, §20).
//!
//! Each device writes one list, under `shared/` and its key: the
//! channels the person files, the drops, the subscriptions and the
//! labels, each an act signed by the device that made it
//! ([`cordelia_crypto::acts`]). **What is in force is worked out from the
//! lists each time** ([`compute`]), as a chain of functions of the lists a
//! device reads and of the statement and the records of addition it
//! applies, and of nothing else that a rule of order reads (property 26):
//!
//! 1. **the lists read** ([`lists_read`]): the list of each device of the
//!    person's that counts, its own entry under its own name, whatever its
//!    age; and the device's own, the list it last wrote or its own entry,
//!    the one at the higher revision;
//! 2. **the valid acts:** an act whose signature holds and whose maker
//!    counts, or is a removed key whose act this device took before that
//!    key's cut time ([`Removals`]); an act of a maker that counts only
//!    from that maker's own list, where the lists read hold one, and from
//!    a copy only where they hold none. Every other act is passed over, as
//!    if no list carried it;
//! 3. **the newest valid act on each item,** by [`Order`];
//! 4. **what is written, within the bounds, in one pass:** of each part,
//!    the items in force and the undoes kept for something together, then
//!    the undoes of nothing below them; within each, makers that count
//!    first, then the newest. What falls past a bound is not written, and
//!    its item is not in force.
//!
//! - **An act** ([`act`]) is dated one above the device's clock and the
//!   newest valid act on its item ([`Computed::dated`]), signed, put in the
//!   device's list, and the list is written at once.
//! - **At a whole fetch, at a statement applied and where a key came to
//!   count** ([`fetched_whole`], [`follow`]) a device works out its list
//!   again and writes it where it differs from the list it last wrote.
//! - **Where the door stores a device's list** ([`took`]) the device keeps
//!   when it took each act that list brings, and works nothing out.
//! - **A recovery** reads the lists of the devices it shows as any device
//!   reads ([`recovered`]).
//!
//! Plain functions over the node's database and the device's own key.
//! Nothing here sends anything: what is written waits in the store, and
//! the node sends it.

use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::Connection;

use cordelia_core::protocol::{
    PERSONAL_SHARED_PREFIX, SHARED_ACT_TIME_MAX, SHARED_MAX_CHANNELS, SHARED_MAX_DROPPED,
    SHARED_MAX_LABELS, SHARED_MAX_SUBSCRIPTIONS,
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
use cordelia_storage::shared_lists::{self as kept_rows, Kept, Taken, TakenRow};

use crate::names::is_a_name;
use crate::person::{Counting, PersonError, in_one};
use crate::publish::Standing;

/// What an act's maker is to this device (decision 2026-10-10 §3.4). A
/// key that is neither is no valid maker: its acts are passed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Maker {
    /// A device of the person's that counts.
    Counts,
    /// A key that this device knows to be removed: its acts taken before
    /// its cut time are valid, and named with what undoes them (§3.5).
    Removed,
}

/// The cut on a removed key's acts (decision 2026-10-24, rule 2 and rule
/// 6; decision 2026-10-10 property 9): which acts of the key this device
/// took count for nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cut {
    /// The key is removed, and no cut is read: every act this device took
    /// counts. For what reads only which keys are removed ([`holds`]), and
    /// a recovery's machine, which took no act before; the lists are worked
    /// out with the cut times ([`ByTheCuts`]).
    StatementAlone,
    /// The cut times of the removal record, rule 2: for each generation
    /// (the number of a statement this device applied) on the chain of a
    /// change removing the key, the cut time, or `None` where no change on
    /// its chain has a time. **The filler lists every generation of that
    /// chain,** the one the change was made after and each earlier one this
    /// device applied, each with the cut time: an act taken in a
    /// generation that is not listed is taken as taken in a generation
    /// made apart from the removal, and counts for nothing; one taken in a
    /// listed generation counts for nothing at or after its cut time, or
    /// at any time where there is none.
    Times(Vec<(u64, Option<i64>)>),
}

/// The time of taking kept for an act that the person took at a
/// recovery's terminal, with the phrase ([`write_recovered`]): no cut takes
/// it back (decision 2026-10-24 (removal), rule 6, "one way in is a
/// person's"). No clock reads it.
pub const TAKEN_BY_THE_PERSONS_WORD: i64 = i64::MIN;

impl Cut {
    /// Whether an act this device took as `taken` counts for nothing.
    pub fn cuts(&self, taken: Taken) -> bool {
        if taken.taken_at == TAKEN_BY_THE_PERSONS_WORD {
            return false;
        }
        match self {
            Cut::StatementAlone => false,
            Cut::Times(times) => match times.iter().find(|(g, _)| *g == taken.generation) {
                None | Some((_, None)) => true,
                Some((_, Some(at))) => taken.taken_at >= *at,
            },
        }
    }
}

/// Which keys this device knows to be removed, and the cut on each: the
/// interface that the removal record's build fills (decision 2026-10-24,
/// rule 2, "a table beside `person_change_entries`"; [`ByTheCuts`]).
pub trait Removals {
    /// `None` where `key` is not a removed key; its cut where it is.
    fn removal(&self, key: &[u8; 32]) -> Option<Cut>;
}

/// Each key of a list as removed, with no cut time ([`Cut::StatementAlone`]):
/// where nothing is cut, only which keys are removed matters. What
/// [`holds`] reads, which cuts nothing, with every key the device knows to
/// be removed; and a recovery's machine, which took no act before.
pub struct ByTheStatement {
    removed: Vec<[u8; 32]>,
}

impl ByTheStatement {
    pub fn of(removed: &[[u8; 32]]) -> Self {
        Self {
            removed: removed.to_vec(),
        }
    }
}

impl Removals for ByTheStatement {
    fn removal(&self, key: &[u8; 32]) -> Option<Cut> {
        self.removed.contains(key).then_some(Cut::StatementAlone)
    }
}

/// The removal record's answer (decision 2026-10-24, rules 2 and 6; the
/// shared record's property 9 and §20, item 7): every key this device
/// knows to be removed, on any branch, with its cut ([`Cut::Times`]). The
/// generations listed for a key are those by number on the chain of every
/// change it noted that removes the key, and at which it noted no other
/// change: an act taken in any other generation, a removal of the key,
/// one made after it or one made apart among them, counts for nothing,
/// and one taken in a listed generation counts for nothing at or after the
/// key's cut time. A key it knows no change of removes has every act cut.
pub struct ByTheCuts {
    cuts: Vec<([u8; 32], Cut)>,
}

impl ByTheCuts {
    pub(crate) fn read(
        conn: &Connection,
        statement: &cordelia_crypto::statement::Statement,
    ) -> Result<Self, PersonError> {
        let noted = crate::cut::Cuts::read(conn)?;
        let mut cuts = Vec::new();
        for key in crate::person::removed_known(conn, statement)? {
            let times = match noted.act_generations(&key) {
                Some((at, generations)) => generations.into_iter().map(|g| (g, at)).collect(),
                None => Vec::new(),
            };
            cuts.push((key, Cut::Times(times)));
        }
        Ok(Self { cuts })
    }
}

impl Removals for ByTheCuts {
    fn removal(&self, key: &[u8; 32]) -> Option<Cut> {
        self.cuts
            .iter()
            .find(|(removed, _)| removed == key)
            .map(|(_, cut)| cut.clone())
    }
}

/// Who the makers are, by the statement the device applies, the records
/// of addition it keeps and the removed keys with their cuts, and nothing
/// else (§3.4): two devices that hold the same take the same acts.
pub struct Makers {
    counting: Counting,
    removals: Box<dyn Removals>,
}

impl Makers {
    pub fn new(counting: Counting, removals: impl Removals + 'static) -> Self {
        Self {
            counting,
            removals: Box::new(removals),
        }
    }

    /// The makers where this device stands, for working the lists out:
    /// every key it knows to be removed, with its cut ([`ByTheCuts`]).
    fn of(conn: &Connection, standing: &Standing) -> Result<Self, PersonError> {
        Ok(Self::new(
            standing.counting.clone(),
            ByTheCuts::read(conn, &standing.held.statement.statement)?,
        ))
    }

    /// The makers where this device stands, for naming what it holds:
    /// every key it knows to be removed, with no cut, which naming does not
    /// read ([`ByTheStatement`]). It reads no change noted.
    fn named(conn: &Connection, standing: &Standing) -> Result<Self, PersonError> {
        Ok(Self::new(
            standing.counting.clone(),
            ByTheStatement::of(&crate::person::removed_known(
                conn,
                &standing.held.statement.statement,
            )?),
        ))
    }

    /// What `key` is as a maker: `None` where it is neither a device that
    /// counts nor a removed key, and its acts are passed over.
    pub fn maker(&self, key: &[u8; 32]) -> Option<Maker> {
        if self.removals.removal(key).is_some() {
            Some(Maker::Removed)
        } else if self.counting.counts(key) {
            Some(Maker::Counts)
        } else {
            None
        }
    }

    fn counts(&self, key: &[u8; 32]) -> bool {
        self.maker(key) == Some(Maker::Counts)
    }

    /// Whether an act of `key`, taken as `taken`, counts for nothing by
    /// the removal's cut.
    fn cut(&self, key: &[u8; 32], taken: Taken) -> bool {
        self.removals
            .removal(key)
            .is_some_and(|cut| cut.cuts(taken))
    }
}

/// What each act's check of its signature gave, by its bytes as a list
/// writes them: an act that many lists carry is checked once.
#[derive(Default)]
struct Checked(RefCell<HashMap<Vec<u8>, bool>>);

impl Checked {
    fn holds(&self, act: &AnyAct) -> bool {
        *self
            .0
            .borrow_mut()
            .entry(act.written())
            .or_insert_with(|| act.holds())
    }
}

/// When this device took each act, by its signature, and what an act it
/// has not taken yet is taken as: the generation it applies, at its clock.
/// Beside each, the latest generation whose lists carried it.
#[derive(Debug, Clone, Default)]
pub struct Takings {
    known: HashMap<[u8; 64], Taken>,
    carried_in: HashMap<[u8; 64], u64>,
    now: Option<Taken>,
}

impl Takings {
    /// Each act taken as it is first read, `now`.
    pub fn now(now: Taken) -> Self {
        Self {
            now: Some(now),
            ..Self::default()
        }
    }

    /// What is kept, with each act first read now stamped no earlier than
    /// the newest time of taking kept, as an arrival is (decision
    /// 2026-10-24 (removal), rule 7): a clock stepped back moves no act
    /// taken after a cut to before it.
    fn load(conn: &Connection, now: Taken) -> Result<Self, PersonError> {
        let mut takings = Self::now(now);
        let mut newest = now.taken_at;
        for (signature, row) in kept_rows::taken(conn)? {
            newest = newest.max(row.taken.taken_at);
            takings.known.insert(signature, row.taken);
            takings.carried_in.insert(signature, row.carried_in);
        }
        takings.now = Some(Taken {
            taken_at: newest,
            ..now
        });
        Ok(takings)
    }

    /// Record that `signature` was taken at `taken`, where it was not.
    pub fn record(&mut self, signature: [u8; 64], taken: Taken) {
        self.known.entry(signature).or_insert(taken);
    }

    fn now_or_zero(&self) -> Taken {
        self.now.unwrap_or(Taken {
            generation: 0,
            taken_at: 0,
        })
    }

    fn of(&self, act: &AnyAct) -> Taken {
        self.known
            .get(&act.signature())
            .copied()
            .unwrap_or(self.now_or_zero())
    }

    /// What is kept: every act of `carried`, which the lists read carry,
    /// with when it was taken, as carried in the generation applied; and
    /// each act that the latest generation before it carried, until the
    /// lists of this one carry it. So the rows outlive the change from one
    /// generation to the next, before the lists of the new one arrive; an
    /// act that the lists of this generation carried and no longer carry
    /// goes, and the rows are at most what two generations carry.
    fn rows(&self, carried: &BTreeSet<[u8; 64]>) -> Vec<([u8; 64], TakenRow)> {
        let now = self.now_or_zero();
        let before = self
            .carried_in
            .values()
            .copied()
            .filter(|generation| *generation < now.generation)
            .max();
        let carried_now = carried.iter().map(|signature| {
            let taken = self.known.get(signature).copied().unwrap_or(now);
            let row = TakenRow {
                taken,
                carried_in: now.generation,
            };
            (*signature, row)
        });
        let carried_before = self.known.iter().filter_map(|(signature, taken)| {
            let carried_in = self.carried_in.get(signature).copied();
            (!carried.contains(signature) && carried_in.is_some() && carried_in == before).then(
                || {
                    let row = TakenRow {
                        taken: *taken,
                        carried_in: carried_in.unwrap_or_default(),
                    };
                    (*signature, row)
                },
            )
        });
        let mut rows: Vec<([u8; 64], TakenRow)> = carried_now.chain(carried_before).collect();
        rows.sort_by_key(|(signature, _)| *signature);
        rows
    }
}

/// What a list's item is within: a channel (filed or dropped), a
/// subscription, or a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    Channel,
    Subscription,
    Label,
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
pub type Key = (Part, Vec<u8>);

impl AnyAct {
    /// The item the act is on. A filing and a drop of one channel are one
    /// item.
    pub fn key(&self) -> Key {
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

    pub fn signature(&self) -> [u8; 64] {
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
    pub fn written(&self) -> Vec<u8> {
        let written = match self {
            AnyAct::Filing(a) => a.written(),
            AnyAct::Drop(a) => a.written(),
            AnyAct::Subscription(a) => a.written(),
            AnyAct::Label(a) => a.written(),
        };
        // An act that was read from a list, or made, is written again.
        written.unwrap_or_default()
    }

    /// Whether it is an undo: a drop, an unsubscription or a removed
    /// label. A filing, a subscription in the state subscribed and a label
    /// with a label are of a kind in force (§3.4).
    pub fn undoes(&self) -> bool {
        match self {
            AnyAct::Filing(_) => false,
            AnyAct::Drop(_) => true,
            AnyAct::Subscription(a) => !a.item.subscribed,
            AnyAct::Label(a) => a.item.label.is_none(),
        }
    }

    /// The part of a list it is written in: filings and drops are two
    /// parts with two bounds.
    fn part(&self) -> usize {
        match self {
            AnyAct::Filing(_) => 0,
            AnyAct::Drop(_) => 1,
            AnyAct::Subscription(_) => 2,
            AnyAct::Label(_) => 3,
        }
    }
}

/// What orders two acts on one item, the greater above (decision
/// 2026-10-10 §3.4): the time; then whether the maker counts; then, at
/// `SHARED_ACT_TIME_MAX` alone, the item's count; then the maker's key;
/// and last the act's bytes as a list writes them, so that two acts that
/// agree in all else are ordered alike on every device.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Order {
    time: u64,
    counts: bool,
    count: u64,
    maker: [u8; 32],
    written: Vec<u8>,
}

impl Order {
    pub fn of(act: &AnyAct, makers: &Makers) -> Self {
        let time = act.time();
        Self {
            time,
            counts: makers.counts(&act.maker()),
            count: if time == SHARED_ACT_TIME_MAX {
                act.count()
            } else {
                0
            },
            maker: act.maker(),
            written: act.written(),
        }
    }
}

/// Every act of a list, of every part.
pub fn acts_of(list: &SharedList) -> Vec<AnyAct> {
    let mut acts: Vec<AnyAct> = Vec::new();
    acts.extend(list.filings.iter().cloned().map(AnyAct::Filing));
    acts.extend(list.drops.iter().cloned().map(AnyAct::Drop));
    acts.extend(list.subscriptions.iter().cloned().map(AnyAct::Subscription));
    acts.extend(list.labels.iter().cloned().map(AnyAct::Label));
    acts
}

/// A list of `acts`, each part in order of item, so that two lists that
/// hold the same acts are the same bytes.
pub fn list_of(acts: impl IntoIterator<Item = AnyAct>) -> SharedList {
    let mut acts: Vec<AnyAct> = acts.into_iter().collect();
    acts.sort_by_key(AnyAct::key);
    let mut list = SharedList::default();
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

/// The bound of each part of a list: 16 filings, 64 drops, 32
/// subscriptions and 64 labels (§3.4). A test works with smaller ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds([usize; 4]);

impl Bounds {
    /// The bounds of a list.
    pub const OF_A_LIST: Bounds = Bounds([
        SHARED_MAX_CHANNELS,
        SHARED_MAX_DROPPED,
        SHARED_MAX_SUBSCRIPTIONS,
        SHARED_MAX_LABELS,
    ]);

    /// Bounds of `filings`, `drops`, `subscriptions` and `labels`.
    pub const fn of(filings: usize, drops: usize, subscriptions: usize, labels: usize) -> Self {
        Bounds([filings, drops, subscriptions, labels])
    }
}

/// What a device works out from the lists it reads (§3.4).
#[derive(Debug, Clone, Default)]
pub struct Computed {
    /// The valid acts on each item, the newest first.
    valid: BTreeMap<Key, Vec<AnyAct>>,
    /// The writers of the lists that carry each valid act, by its bytes.
    carriers: HashMap<Vec<u8>, BTreeSet<[u8; 32]>>,
    /// What the device writes: the newest valid act on each item within
    /// the bounds, in force or an undo.
    pub written: Vec<AnyAct>,
    /// The newest valid act on each item that a bound left out: not
    /// written, and not in force.
    pub past_bound: Vec<AnyAct>,
    /// Each key whose acts the lists carry, signed, and passed over: a key
    /// that is no valid maker, or a removed key's act taken after its cut.
    pub passed_over: BTreeSet<[u8; 32]>,
    /// Each act passed over, once, by its maker and its bytes: how many
    /// acts of each key passed over the lists carry (decision 2026-10-10
    /// §9, `passed_over`).
    passed: BTreeSet<([u8; 32], Vec<u8>)>,
    /// The signatures of the acts of valid makers that the lists carry
    /// ([`carried`]): what is kept of when each was taken.
    taken: BTreeSet<[u8; 64]>,
}

/// The signatures of every act of a valid maker that `lists` carry, a
/// copy among them and whether or not its signature holds: what a device
/// keeps of when it took each (decision 2026-10-10 property 9). The door
/// keeps the same where it stores a list ([`took`]), so an act's time of
/// taking is when this device first held it, and the cut on a maker
/// removed later reads that time, not the time it was worked out again.
/// No rule of order reads it.
fn carried(lists: &[([u8; 32], SharedList)], makers: &Makers) -> BTreeSet<[u8; 64]> {
    lists
        .iter()
        .flat_map(|(_, list)| acts_of(list))
        .filter(|act| makers.maker(&act.maker()).is_some())
        .map(|act| act.signature())
        .collect()
}

/// What `lists`, each with the key of its writer, come to (decision
/// 2026-10-10 §3.4): the chain of functions of property 26. `makers` says
/// what each maker is; `takings` when this device took each act, which
/// only the removal's cut reads.
pub fn compute(
    lists: &[([u8; 32], SharedList)],
    makers: &Makers,
    takings: &Takings,
    bounds: Bounds,
) -> Computed {
    let checked = Checked::default();
    let writers: BTreeSet<[u8; 32]> = lists.iter().map(|(writer, _)| *writer).collect();
    let mut computed = Computed {
        taken: carried(lists, makers),
        ..Computed::default()
    };
    let mut valid: BTreeMap<Vec<u8>, AnyAct> = BTreeMap::new();

    // 1. The valid acts, each once, with the lists that carry it.
    for (writer, list) in lists {
        for act in acts_of(list) {
            let maker = act.maker();
            let Some(of) = makers.maker(&maker) else {
                if checked.holds(&act) {
                    computed.passed_over.insert(maker);
                    computed.passed.insert((maker, act.written()));
                }
                continue;
            };
            // An act of a maker that counts is taken from its own list
            // where the lists read hold one.
            if of == Maker::Counts && writers.contains(&maker) && *writer != maker {
                continue;
            }
            if !checked.holds(&act) {
                continue;
            }
            if of == Maker::Removed && makers.cut(&maker, takings.of(&act)) {
                computed.passed_over.insert(maker);
                computed.passed.insert((maker, act.written()));
                continue;
            }
            let written = act.written();
            computed
                .carriers
                .entry(written.clone())
                .or_default()
                .insert(*writer);
            valid.entry(written).or_insert(act);
        }
    }

    // 2. The valid acts on each item, the newest first.
    for act in valid.into_values() {
        computed.valid.entry(act.key()).or_default().push(act);
    }
    for acts in computed.valid.values_mut() {
        acts.sort_by_cached_key(|act| Reverse(Order::of(act, makers)));
    }

    // 3 and 4. The newest on each item, ranked in its part, within the
    // bound, in one pass.
    let mut parts: [Vec<Ranked>; 4] = Default::default();
    for acts in computed.valid.values() {
        let newest = &acts[0];
        // The items in force and the undoes kept for something together,
        // then the undoes of nothing below them.
        let group = u8::from(newest.undoes() && !kept_for_something(acts));
        parts[newest.part()].push((
            group,
            !makers.counts(&newest.maker()),
            Reverse(Order::of(newest, makers)),
            newest.clone(),
        ));
    }
    for (part, mut ranked) in parts.into_iter().enumerate() {
        ranked.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
        for (at, (_, _, _, act)) in ranked.into_iter().enumerate() {
            if at < bounds.0[part] {
                computed.written.push(act);
            } else {
                computed.past_bound.push(act);
            }
        }
    }
    computed
}

/// The newest valid act on an item, with what ranks it in its part past a
/// bound: its group (0: in force or an undo kept for something; 1: an undo
/// of nothing below it), whether its maker does not count, and its order,
/// the newest first.
type Ranked = (u8, bool, Reverse<Order>, AnyAct);

/// Whether the newest of `acts`, the valid acts on one item, the newest
/// first, is an undo kept for something: of the valid acts below it, the
/// newest is of a kind in force (§3.4).
fn kept_for_something(acts: &[AnyAct]) -> bool {
    acts.first().is_some_and(AnyAct::undoes) && acts.get(1).is_some_and(|below| !below.undoes())
}

/// Why an item cannot take a new act: a device that counts holds it at
/// the time bound with the highest count (§3.4, `held_at_bound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldAtBound(pub [u8; 32]);

impl Computed {
    /// Each key whose acts the lists carry and that are passed over, with
    /// how many of its acts they carry, each once (§9).
    pub fn passed_over_acts(&self) -> Vec<([u8; 32], usize)> {
        let mut counted: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for (maker, _) in &self.passed {
            *counted.entry(*maker).or_default() += 1;
        }
        counted.into_iter().collect()
    }

    /// The newest valid act on `key`.
    pub fn newest(&self, key: &Key) -> Option<&AnyAct> {
        self.valid.get(key).and_then(|acts| acts.first())
    }

    /// Whether `key` is in force: the newest valid act on it is of a kind
    /// in force, and within the bound.
    pub fn in_force(&self, key: &Key) -> bool {
        self.written
            .iter()
            .any(|act| act.key() == *key && !act.undoes())
    }

    /// Whether a filing, a subscribe or a label on `key`, in `part`, takes
    /// no new place there (§3.4): the newest valid act on the item is of a
    /// kind in force, written (the new act takes its place) or past a
    /// bound (an act on an item past a bound is never refused for room);
    /// or it is an undo kept for something that the device writes in that
    /// same part, whose place the new act takes. Any other is a new item,
    /// which a full part refuses: a drop is in another part than the
    /// filings, so a filing of a dropped channel takes a new place among
    /// the 16, whatever older filing is carried below the drop.
    fn holds_a_place(&self, key: &Key, part: usize) -> bool {
        let Some(acts) = self.valid.get(key) else {
            return false;
        };
        let newest = &acts[0];
        !newest.undoes()
            || (newest.part() == part
                && kept_for_something(acts)
                && self.written.iter().any(|act| act.key() == *key))
    }

    /// The items in force and the undoes kept for something that the
    /// device writes in `part`, and the writers of the lists that carry the
    /// acts below those undoes.
    #[cfg(test)]
    fn placed(&self, part: usize) -> (usize, Vec<[u8; 32]>) {
        self.placed_but(part, |_| false)
    }

    /// The same, less the acts that `passed` names.
    fn placed_but(&self, part: usize, passed: impl Fn(&AnyAct) -> bool) -> (usize, Vec<[u8; 32]>) {
        let mut devices = BTreeSet::new();
        let mut placed = 0;
        for act in self
            .written
            .iter()
            .filter(|act| act.part() == part && !passed(act))
        {
            let acts = &self.valid[&act.key()];
            if !act.undoes() {
                placed += 1;
            } else if kept_for_something(acts) {
                placed += 1;
                if let Some(carriers) = self.carriers.get(&acts[1].written()) {
                    devices.extend(carriers.iter().copied());
                }
            }
        }
        (placed, devices.into_iter().collect())
    }

    /// The time and the count that a new act is dated with, above every
    /// valid act of `above` (§3.4): one above the greatest of the device's
    /// clock and their times, and never above `SHARED_ACT_TIME_MAX`. At the
    /// bound its count is one above the highest count among those at the
    /// bound whose makers count, or 1 where none does; below it, 0. Where a
    /// device that counts holds one at the bound with the highest count,
    /// nothing can go above it.
    fn dated_above<'a>(
        above: impl Iterator<Item = &'a AnyAct> + Clone,
        makers: &Makers,
        now: i64,
    ) -> Result<(u64, u64), HeldAtBound> {
        let now = u64::try_from(now).unwrap_or(0);
        let newest = above.clone().map(AnyAct::time).max().unwrap_or(0);
        let time = now.max(newest).saturating_add(1).min(SHARED_ACT_TIME_MAX);
        if time < SHARED_ACT_TIME_MAX {
            return Ok((time, 0));
        }
        let highest = above
            .filter(|act| act.time() == SHARED_ACT_TIME_MAX && makers.counts(&act.maker()))
            .max_by_key(|act| act.count());
        match highest {
            None => Ok((time, 1)),
            Some(act) if act.count() >= SHARED_ACT_TIME_MAX => Err(HeldAtBound(act.maker())),
            Some(act) => Ok((time, act.count() + 1)),
        }
    }

    /// The time and the count of a new act on `key` ([`Self::dated_above`]
    /// the valid acts on it).
    pub fn dated(&self, key: &Key, makers: &Makers, now: i64) -> Result<(u64, u64), HeldAtBound> {
        let on_item = self.valid.get(key).map(Vec::as_slice).unwrap_or(&[]);
        Self::dated_above(on_item.iter(), makers, now)
    }

    /// The time and the count of the filing that `shared anew` or `shared
    /// move` makes on `key`: above the valid acts on it and above every
    /// valid filing that can be gone above, so that it is the newest in
    /// the filings part but for a filing of another channel that a device
    /// that counts holds at the time bound with the highest count. Only an
    /// act on `key` itself held so refuses it (`held_at_bound`, §3.4).
    fn dated_first_of_the_filings(
        &self,
        key: &Key,
        makers: &Makers,
        now: i64,
    ) -> Result<(u64, u64), HeldAtBound> {
        let held = |act: &AnyAct| {
            act.time() == SHARED_ACT_TIME_MAX
                && act.count() >= SHARED_ACT_TIME_MAX
                && makers.counts(&act.maker())
        };
        let filings = self
            .valid
            .iter()
            .flat_map(|(item, acts)| acts.iter().map(move |act| (item, act)))
            .filter(|(item, act)| *item == key || (matches!(act, AnyAct::Filing(_)) && !held(act)))
            .map(|(_, act)| act);
        Self::dated_above(filings, makers, now)
    }
}

/// The lists a device reads (§3.4, "What a device reads"): the list of each
/// device of the person's that counts, as this device's store holds it in
/// the personal channel of the generation applied, that device's own entry
/// under its own list's name and no other's, whatever its age; and the
/// device's own: of the list it last wrote and its own entry there, the
/// one at the higher revision. One that is a delete, in a band above the
/// statement's, does not open or is no list is passed over whole.
fn lists_read(
    conn: &Connection,
    standing: &Standing,
    own: &[u8; 32],
) -> Result<Vec<([u8; 32], SharedList)>, PersonError> {
    let personal = derive::personal_secret(&standing.secret)?;
    let channel = derive::channel_id(&personal)?;
    let slot_key = derive::slot_key(&personal)?;
    let entry_of = |writer: &[u8; 32]| -> Result<Option<(u64, SharedList)>, PersonError> {
        let slot = slot_id(&slot_key, &list_name(writer)?);
        let Some(held) = entries::author_entry(conn, &channel, &slot, writer)? else {
            return Ok(None);
        };
        let Ok(entry) = held.entry.check() else {
            return Ok(None);
        };
        if band(entry.rev) > standing.number() {
            return Ok(None);
        }
        // An entry opens only in the slot of its name. A delete holds no
        // list.
        let Ok(inside) = entry.open(&personal) else {
            return Ok(None);
        };
        Ok(SharedList::from_value(&inside.value, is_a_name)
            .ok()
            .map(|list| (entry.rev, list)))
    };
    let mut read = Vec::new();
    let kept = kept_rows::kept(conn)?.and_then(|kept| {
        SharedList::from_value(&Value::Other(kept.list), is_a_name)
            .ok()
            .map(|list| (kept.rev, list))
    });
    let own_entry = entry_of(own)?;
    let own_list = match (kept, own_entry) {
        (Some(kept), Some(entry)) if entry.0 > kept.0 => Some(entry.1),
        (Some(kept), _) => Some(kept.1),
        (None, entry) => entry.map(|entry| entry.1),
    };
    if let Some(list) = own_list {
        read.push((*own, list));
    }
    for writer in standing.counting.keys() {
        if writer == *own {
            continue;
        }
        if let Some((_, list)) = entry_of(&writer)? {
            read.push((writer, list));
        }
    }
    Ok(read)
}

/// Where a device stands to work out its lists: what it reads, who the
/// makers are, and when it took each act.
struct Reading {
    standing: Standing,
    makers: Makers,
    lists: Vec<([u8; 32], SharedList)>,
    takings: Takings,
}

impl Reading {
    fn of(
        conn: &Connection,
        standing: Standing,
        own: &[u8; 32],
        now: i64,
    ) -> Result<Self, PersonError> {
        let makers = Makers::of(conn, &standing)?;
        let lists = lists_read(conn, &standing, own)?;
        let takings = Takings::load(
            conn,
            Taken {
                generation: standing.number(),
                taken_at: now,
            },
        )?;
        Ok(Self {
            standing,
            makers,
            lists,
            takings,
        })
    }

    fn compute(&self) -> Computed {
        compute(&self.lists, &self.makers, &self.takings, Bounds::OF_A_LIST)
    }

    /// The device's own list among those read, `list` in its place.
    fn with_own(&mut self, own: &[u8; 32], list: SharedList) {
        self.lists.retain(|(writer, _)| writer != own);
        self.lists.insert(0, (*own, list));
    }
}

fn not_held(what: &str, e: ListError) -> PersonError {
    PersonError::Held(format!("{what}: {e}"))
}

/// Whether the list this device last wrote holds exactly `acts`.
fn last_written_is(conn: &Connection, acts: &[AnyAct]) -> Result<bool, PersonError> {
    let Some(kept) = kept_rows::kept(conn)? else {
        return Ok(acts.is_empty());
    };
    let list = SharedList::from_value(&Value::Other(kept.list), is_a_name)
        .map_err(|e| not_held("the list this device last wrote", e))?;
    Ok(list_of(acts_of(&list)) == list_of(acts.iter().cloned()))
}

/// Write `acts` as the device's own list, under its own name in the
/// personal channel of the generation applied, one revision above the
/// one it wrote there before, and keep it as the list it last wrote
/// (§3.4). It waits in the store to be sent.
fn write_list(
    conn: &Connection,
    identity: &NodeIdentity,
    standing: &Standing,
    acts: &[AnyAct],
    now: i64,
) -> Result<(), PersonError> {
    let value = list_of(acts.iter().cloned())
        .to_value(is_a_name)
        .map_err(|e| not_held("this device's list", e))?;
    let personal = derive::personal_secret(&standing.secret)?;
    let channel = derive::channel_id(&personal)?;
    let own = identity.public_key();
    let name = list_name(&own)?;
    let slot = slot_id(&derive::slot_key(&personal)?, &name);
    let held = entries::author_entry(conn, &channel, &slot, &own)?.map(|held| held.entry.rev);
    let kept = kept_rows::kept(conn)?
        .map(|kept| kept.rev)
        .filter(|rev| band(*rev) == standing.number());
    let before = held.max(kept);
    let rev = next_under(before, standing.number()).ok_or_else(|| {
        PersonError::Held(
            "this device's own list is at the last revision under the statement".into(),
        )
    })?;
    let inside = Inside {
        name,
        value: Value::Other(value.clone()),
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&personal, identity, rev, &inside)?.check()?;
    entries::store(conn, &entry, now)?;
    kept_rows::keep(conn, &Kept { list: value, rev })?;
    Ok(())
}

/// What a person does to the list (decision 2026-10-10 §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Do {
    /// File a channel, or file a filed channel under another name.
    File(Filing),
    /// Drop a filed channel, by its ID.
    Drop([u8; 32]),
    /// The filing that `shared anew` or `shared move` makes: from a filed
    /// channel, by its ID, to a channel made anew. A filing dated the
    /// newest of the filings, never refused for room, and a drop of the
    /// old one, which takes no place.
    Move { from: [u8; 32], to: Filing },
    /// The same, with each agent that subscribed to the old channel
    /// subscribed to the new (decision 2026-10-10 §7: `shared move` "moves
    /// each subscription of the old channel to the new, each a new act").
    /// The subscriptions are never refused for room: a move is never
    /// refused but by `held_at_bound`.
    MoveWith {
        from: [u8; 32],
        to: Filing,
        agents: Vec<String>,
    },
    /// The drops a removal makes of the channels past their bound that it
    /// makes anew (decision 2026-10-10 §3.5): a drop of each, which takes
    /// no place, and no filing of the new channel, which takes the old
    /// one's place past the bound. The lists of the new generation carry
    /// no filing of such a channel, since the one list that did is of the
    /// generation before: so it is not refused as `NotFiled`.
    DropPastBound(Vec<[u8; 32]>),
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

/// Why nothing was made (§3.4, "What a new act is refused for").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// A filing, a subscribe or a label of a new item, where its part
    /// already holds as many items in force and undoes kept for something
    /// as its bound (`too_many_channels`, `too_many_subscriptions`,
    /// `too_many_labels`): with the devices whose lists carry the acts
    /// below those undoes, since writing or removing them frees places.
    Full { part: Part, devices: Vec<[u8; 32]> },
    /// No channel of that ID is filed (`no_such_channel`).
    NotFiled,
    /// The channel moved to is filed already.
    Filed,
    /// There is nothing for it to undo: no such subscription, or no label.
    NothingToUndo,
    /// A device that still counts holds the item at the time bound with
    /// the highest count (`held_at_bound`): no act can go above it until
    /// the person removes that device.
    HeldAtBound([u8; 32]),
    /// What it holds cannot be written in a list: a name that is not a
    /// name, or a label of more than 64 bytes.
    NotWritten(ListError),
}

/// Do `what` on this device, at `now` (§3.4): each act dated above every
/// valid act on its item ([`Computed::dated`]), signed by the device, put
/// in its list, and the list written at once. A device that does not stand
/// applied makes nothing.
pub fn act(
    conn: &Connection,
    identity: &NodeIdentity,
    what: Do,
    now: i64,
) -> Result<Done, PersonError> {
    in_one(conn, || {
        let own = identity.public_key();
        let mut reading = Reading::of(conn, Standing::to_write(conn)?, &own, now)?;
        let computed = reading.compute();
        let made = match decide(&computed, &reading.makers, identity, &what, now) {
            Ok(made) => made,
            Err(refused) => return Ok(Done::Refused(refused)),
        };

        // The new acts in the device's own list, in the place of what it
        // writes on their items; then worked out again from the lists.
        let keys: BTreeSet<Key> = made.iter().map(AnyAct::key).collect();
        let own_list = computed
            .written
            .iter()
            .filter(|act| !keys.contains(&act.key()))
            .cloned()
            .chain(made.iter().cloned());
        reading.with_own(&own, list_of(own_list));
        let taken = reading.takings.now_or_zero();
        for act in &made {
            reading.takings.record(act.signature(), taken);
        }
        let computed = reading.compute();
        write_list(conn, identity, &reading.standing, &computed.written, now)?;
        kept_rows::keep_taken(conn, &reading.takings.rows(&computed.taken))?;
        // The table of shared channels follows the list (decision
        // 2026-10-10 §3.4, §6.3).
        crate::shared::keep(conn, &own, now)?;
        Ok(Done::Made(made))
    })
}

/// The acts that `what` makes, or why it makes none (§3.4).
fn decide(
    computed: &Computed,
    makers: &Makers,
    identity: &NodeIdentity,
    what: &Do,
    now: i64,
) -> Result<Vec<AnyAct>, Refused> {
    let newest = |key: &Key| computed.newest(key);
    let filed = |channel: &[u8; 32]| {
        matches!(
            newest(&(Part::Channel, channel.to_vec())),
            Some(AnyAct::Filing(_))
        )
    };
    // A filing, a subscribe or a label of a new item is refused where its
    // part holds its bound of items in force and undoes kept for
    // something; an act on an item that holds a place takes that place.
    // A subscription of a channel that is filed no more (moved from, or
    // dropped) shows nothing and cannot be undone by its name: it holds no
    // room, so that the subscriptions a move moves do not fill the room of
    // the old ones (decision 2026-10-10 §7). The list's bound still writes
    // the newest first.
    let unfiled = |act: &AnyAct| match act {
        AnyAct::Subscription(subscription) => matches!(
            newest(&(Part::Channel, subscription.item.channel.to_vec())),
            Some(AnyAct::Drop(_))
        ),
        _ => false,
    };
    let room = |key: &Key, part: usize, bound: usize, as_part: Part| {
        if computed.holds_a_place(key, part) {
            return Ok(());
        }
        let (placed, devices) = computed.placed_but(part, unfiled);
        if placed >= bound {
            return Err(Refused::Full {
                part: as_part,
                devices,
            });
        }
        Ok(())
    };
    let dated = |key: &Key| {
        computed
            .dated(key, makers, now)
            .map_err(|HeldAtBound(device)| Refused::HeldAtBound(device))
    };
    let signed = |made: Result<AnyAct, ListError>| made.map_err(Refused::NotWritten);
    match what {
        Do::File(filing) => {
            let key = (Part::Channel, filing.channel.to_vec());
            room(&key, 0, SHARED_MAX_CHANNELS, Part::Channel)?;
            let made = make(filing.clone(), dated(&key)?, identity).map(AnyAct::Filing);
            Ok(vec![signed(made)?])
        }
        Do::Drop(channel) => {
            if !filed(channel) {
                return Err(Refused::NotFiled);
            }
            let key = (Part::Channel, channel.to_vec());
            let dropped = Dropped { channel: *channel };
            Ok(vec![signed(
                make(dropped, dated(&key)?, identity).map(AnyAct::Drop),
            )?])
        }
        Do::DropPastBound(channels) => channels
            .iter()
            .map(|channel| {
                let key = (Part::Channel, channel.to_vec());
                let dropped = Dropped { channel: *channel };
                signed(make(dropped, dated(&key)?, identity).map(AnyAct::Drop))
            })
            .collect(),
        Do::MoveWith { from, to, agents } => {
            let mut made = decide(
                computed,
                makers,
                identity,
                &Do::Move {
                    from: *from,
                    to: to.clone(),
                },
                now,
            )?;
            for agent in agents {
                let subscription = Subscription {
                    channel: to.channel,
                    agent: agent.clone(),
                    subscribed: true,
                };
                let key = (Part::Subscription, subscription.item());
                let made_one = make(subscription, dated(&key)?, identity);
                made.push(signed(made_one.map(AnyAct::Subscription))?);
            }
            Ok(made)
        }
        Do::Move { from, to } => {
            if !filed(from) {
                return Err(Refused::NotFiled);
            }
            let key = (Part::Channel, to.channel.to_vec());
            if filed(&to.channel) {
                return Err(Refused::Filed);
            }
            let at = computed
                .dated_first_of_the_filings(&key, makers, now)
                .map_err(|HeldAtBound(device)| Refused::HeldAtBound(device))?;
            let from_key = (Part::Channel, from.to_vec());
            let dropped = Dropped { channel: *from };
            let filing = signed(make(to.clone(), at, identity).map(AnyAct::Filing))?;
            let drop = signed(make(dropped, dated(&from_key)?, identity).map(AnyAct::Drop))?;
            Ok(vec![filing, drop])
        }
        Do::Subscribe(subscription) => {
            let key = (Part::Subscription, subscription.item());
            if subscription.subscribed {
                room(&key, 2, SHARED_MAX_SUBSCRIPTIONS, Part::Subscription)?;
            } else if !matches!(
                newest(&key),
                Some(AnyAct::Subscription(held)) if held.item.subscribed
            ) {
                return Err(Refused::NothingToUndo);
            }
            let made = make(subscription.clone(), dated(&key)?, identity);
            Ok(vec![signed(made.map(AnyAct::Subscription))?])
        }
        Do::Label(label) => {
            let key = (Part::Label, label.key.to_vec());
            if label.label.is_some() {
                room(&key, 3, SHARED_MAX_LABELS, Part::Label)?;
            } else if !matches!(
                newest(&key),
                Some(AnyAct::Label(held)) if held.item.label.is_some()
            ) {
                return Err(Refused::NothingToUndo);
            }
            let made = make(label.clone(), dated(&key)?, identity);
            Ok(vec![signed(made.map(AnyAct::Label))?])
        }
    }
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

/// What a device does where the lists it reads, or who counts, may have
/// changed, at `now` (§3.4): it works out its list again from the lists it
/// reads, and writes it where it differs from the list it last wrote; and
/// the table of shared channels follows. Returns whether it wrote its
/// list. A device that does not stand applied writes nothing; one whose
/// database cannot be read says so.
pub fn follow(conn: &Connection, identity: &NodeIdentity, now: i64) -> Result<bool, PersonError> {
    in_one(conn, || {
        let own = identity.public_key();
        let standing = match Standing::to_write(conn) {
            Ok(standing) => standing,
            Err(PersonError::FollowsNoPhrase | PersonError::Stopped(_) | PersonError::NotClear) => {
                // It writes nothing; the table of shared channels still
                // follows who counts. A closed device too (decision
                // 2026-10-24 (removal), rule 10): who is shown, and the
                // labels, follow what it knows.
                crate::shared::keep(conn, &own, now)?;
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        let reading = Reading::of(conn, standing, &own, now)?;
        let computed = reading.compute();
        let wrote = !last_written_is(conn, &computed.written)?;
        if wrote {
            write_list(conn, identity, &reading.standing, &computed.written, now)?;
        }
        kept_rows::keep_taken(conn, &reading.takings.rows(&computed.taken))?;
        crate::shared::keep(conn, &own, now)?;
        Ok(wrote)
    })
}

/// What a device does at a whole fetch of the personal channel, a pull
/// of it to its end from at least one of its relays in one pass, at `now`
/// ([`follow`]). It sets no fetched time: nothing in a list says when it
/// was fetched (decision 2026-10-10 §20, items 1 and 9).
pub fn fetched_whole(
    conn: &Connection,
    identity: &NodeIdentity,
    now: i64,
) -> Result<bool, PersonError> {
    follow(conn, identity, now)
}

/// What the door does where it stored `entry`, an entry of the personal
/// channel whose secret is `personal`, at `now` (decision 2026-10-10
/// property 9, §20 item 7): where it is a device's list, each act of a
/// valid maker that the lists read carry and that this device had not
/// taken is taken now, in the generation it applies; each it had taken
/// keeps its time. It works nothing out and writes no list: an act's time
/// of taking is when this device first held it, whether or not it worked
/// its lists out then. A device that does not stand applied keeps nothing.
pub fn took(
    conn: &Connection,
    own: &[u8; 32],
    entry: &CheckedEntry,
    personal: &[u8; 32],
    now: i64,
) -> Result<(), PersonError> {
    let is_a_list = entry
        .open(personal)
        .is_ok_and(|inside| inside.name.starts_with(PERSONAL_SHARED_PREFIX));
    if !is_a_list {
        return Ok(());
    }
    in_one(conn, || {
        let Ok(standing) = Standing::of(conn) else {
            return Ok(());
        };
        let reading = Reading::of(conn, standing, own, now)?;
        let carried = carried(&reading.lists, &reading.makers);
        kept_rows::keep_taken(conn, &reading.takings.rows(&carried))?;
        Ok(())
    })
}

/// What a device holds of the person's lists, each act with what its
/// maker is to it (§3.4): the acts it writes, in force or undoes; what a
/// bound left out, which is not in force; and the keys whose acts it
/// passed over. Nothing on a device that follows no phrase.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Holds {
    pub filings: Vec<(Act<Filing>, Maker)>,
    pub drops: Vec<(Act<Dropped>, Maker)>,
    pub subscriptions: Vec<(Act<Subscription>, Maker)>,
    pub labels: Vec<(Act<Label>, Maker)>,
    pub left_out: Vec<(AnyAct, Maker)>,
    pub passed_over: Vec<[u8; 32]>,
    /// Of those, each with how many of its acts the lists carry (§9).
    pub passed_over_acts: Vec<([u8; 32], usize)>,
}

impl Holds {
    fn of(written: &[AnyAct], past_bound: &[AnyAct], makers: &Makers) -> Self {
        let mut holds = Holds::default();
        for act in written {
            let Some(maker) = makers.maker(&act.maker()) else {
                continue;
            };
            match act.clone() {
                AnyAct::Filing(a) => holds.filings.push((a, maker)),
                AnyAct::Drop(a) => holds.drops.push((a, maker)),
                AnyAct::Subscription(a) => holds.subscriptions.push((a, maker)),
                AnyAct::Label(a) => holds.labels.push((a, maker)),
            }
        }
        for act in past_bound {
            if let Some(maker) = makers.maker(&act.maker()) {
                holds.left_out.push((act.clone(), maker));
            }
        }
        holds
    }
}

/// What this device holds of the person's lists, as the list it last
/// wrote says: what it writes, each act with its maker. Cheap: it reads one
/// row, and checks no signature again. Nothing is left out or passed over
/// in it; [`holds_worked_out`] says those.
pub fn holds(conn: &Connection) -> Result<Holds, PersonError> {
    let Ok(standing) = Standing::of(conn) else {
        return Ok(Holds::default());
    };
    let makers = Makers::named(conn, &standing)?;
    let Some(kept) = kept_rows::kept(conn)? else {
        return Ok(Holds::default());
    };
    let list = SharedList::from_value(&Value::Other(kept.list), is_a_name)
        .map_err(|e| not_held("the list this device last wrote", e))?;
    Ok(Holds::of(&acts_of(&list), &[], &makers))
}

/// What this device holds of the person's lists, worked out from the
/// lists it reads now, at `now`: what it would write, what a bound leaves
/// out, and the keys whose acts it passes over.
pub fn holds_worked_out(conn: &Connection, own: &[u8; 32], now: i64) -> Result<Holds, PersonError> {
    let Ok(standing) = Standing::of(conn) else {
        return Ok(Holds::default());
    };
    let reading = Reading::of(conn, standing, own, now)?;
    let computed = reading.compute();
    let mut holds = Holds::of(&computed.written, &computed.past_bound, &reading.makers);
    holds.passed_over_acts = computed.passed_over_acts();
    holds.passed_over = computed.passed_over.into_iter().collect();
    Ok(holds)
}

/// Whether the person has filed a shared channel under `name`, as this
/// device holds it: a filing in its list (decision 2026-10-10 §2.2).
/// `cordelia sync map` refuses such a name.
pub fn is_filed_under(conn: &Connection, name: &str) -> Result<bool, PersonError> {
    Ok(holds(conn)?
        .filings
        .iter()
        .any(|(act, _)| act.item.name == name))
}

/// What a recovery takes of the lists of the devices it shows (decision
/// 2026-10-10 §3.5): it applies the rules of 3.4 to every list of the
/// devices it shows, with no test of age or of a clock, and with valid
/// makers by the statement it makes, `maker`: a device answered `lost` or
/// `hands` is a removed key, one answered `have` is in no list, so its
/// acts are passed over until it is added again. Returns what the new
/// machine writes, and what a bound leaves out.
///
/// Today a removed key's acts are taken by the statement alone; under the
/// removal record the acts of a key answered `lost` or `hands` are those
/// the look read before the change (its rule 6).
pub fn recovered(
    lists: &[([u8; 32], SharedList)],
    maker: impl Fn(&[u8; 32]) -> Option<Maker>,
) -> (SharedList, SharedList) {
    let keys: BTreeSet<[u8; 32]> = lists
        .iter()
        .flat_map(|(_, list)| acts_of(list))
        .map(|act| act.maker())
        .collect();
    let (mut counting, mut removed) = (Vec::new(), Vec::new());
    for key in keys {
        match maker(&key) {
            Some(Maker::Counts) => counting.push(key),
            Some(Maker::Removed) => removed.push(key),
            None => {}
        }
    }
    let makers = Makers::new(
        Counting::of_devices(&counting),
        ByTheStatement::of(&removed),
    );
    let computed = compute(lists, &makers, &Takings::default(), Bounds::OF_A_LIST);
    (list_of(computed.written), list_of(computed.past_bound))
}

/// The machine of a recovery writes, as its own list, what the recovery
/// takes of `lists`, the lists of the devices it showed (§3.5), with the
/// keys of `gone` as removed keys and every other in no list: the acts of
/// a device it removes are taken, as copies; the acts of one the person
/// still has are passed over until it is added again. The table of shared
/// channels follows. In the caller's transaction.
pub fn write_recovered(
    conn: &Connection,
    identity: &NodeIdentity,
    lists: &[([u8; 32], SharedList)],
    gone: &[[u8; 32]],
    now: i64,
) -> Result<(), PersonError> {
    let (written, _) = recovered(lists, |key| gone.contains(key).then_some(Maker::Removed));
    let standing = Standing::to_write(conn)?;
    let acts = acts_of(&written);
    write_list(conn, identity, &standing, &acts, now)?;
    // The person took these at the recovery's terminal, with the phrase,
    // from the lists of the generation recovered from: a removed device's
    // acts among them by the person's word, as the look takes what a lost
    // device wrote (decision 2026-10-24 (removal), rule 6, "one way in is
    // a person's"). So each is kept as taken by the person's word, in the
    // generation recovered from, and the cut of the device the recovery
    // removes does not take them back when this machine works its lists
    // out: this machine noted no time of that generation, so the cut would
    // otherwise take back everything of the device's.
    let statement = &standing.held.statement.statement;
    let recovered_from = statement.chain.iter().map(|link| link.number).max();
    if let Some(generation) = recovered_from {
        let rows: Vec<([u8; 64], TakenRow)> = acts
            .iter()
            .map(|act| {
                let taken = Taken {
                    generation,
                    taken_at: TAKEN_BY_THE_PERSONS_WORD,
                };
                (
                    act.signature(),
                    TakenRow {
                        taken,
                        carried_in: statement.number,
                    },
                )
            })
            .collect();
        kept_rows::keep_taken(conn, &rows)?;
    }
    crate::shared::keep(conn, &identity.public_key(), now)?;
    Ok(())
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

/// A test's device writes, as its own list, a filing of `filing` at the
/// time bound with the highest count: no act can go above that item while
/// the device counts (`held_at_bound`).
#[cfg(test)]
pub(crate) fn held_at_the_bound(
    conn: &Connection,
    identity: &NodeIdentity,
    filing: Filing,
    now: i64,
) -> Result<(), PersonError> {
    let act = Act::make(
        filing,
        SHARED_ACT_TIME_MAX,
        SHARED_ACT_TIME_MAX,
        identity,
        is_a_name,
    )
    .map_err(|e| not_held("an act", e))?;
    in_one(conn, || {
        let standing = Standing::to_write(conn)?;
        write_list(conn, identity, &standing, &[AnyAct::Filing(act)], now)
    })
}

#[cfg(test)]
pub(crate) mod tests;
