//! The counters of the scale test (decision 2026-10-22 §1, §7.3).
//!
//! What section 1.2 of the record measures inside a node, as atomic
//! counters and fixed histograms: the requests a relay is asked by stream
//! kind, what became of them and their bytes; its connections and those it
//! turned away; what its governor did; and what a device asked of each
//! relay and held back. The waits and holds of the node's lock are timed
//! by the lock itself ([`crate::lock`]).
//!
//! **Each is an atomic, read with no lock** (§1.1, rule 3): the local API
//! serves them at `/api/v1/metrics/load` through [`render`], and that read
//! takes nothing that the node's work takes. A counter only counts: none is
//! read by anything the node does, so the node does what it did without
//! them (§7.3).
//!
//! Each counts from the node's start. Whoever reads them takes the
//! difference between two reads for a minute's figure; a gauge (the
//! connections open, the governor's peers) is what it was when last set.

use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use crate::lock::{LockTimes, Nested};
use crate::protocol::{LOAD_HISTOGRAM_BUCKETS, LOAD_RELAYS_COUNTED, LOCK_COUNTED_OVER_MS};

// ── A histogram ──────────────────────────────────────────────────────

/// Lengths of time, in buckets of powers of two from 1 µs to 16 s and one
/// for what is longer (decision 2026-10-22 §1.2), with their sum, the
/// longest, and how many were longer than each of LOCK_COUNTED_OVER_MS.
///
/// A record is a few additions to atomics that no reader holds up: the
/// count is not kept apart, since it is the sum of the buckets, and the
/// longest is written only when a record is longer than it (§1.1, rule 5).
#[derive(Debug, Default)]
pub struct Histogram {
    buckets: [AtomicU64; LOAD_HISTOGRAM_BUCKETS + 1],
    sum_nanos: AtomicU64,
    max_micros: AtomicU64,
    over: [AtomicU64; LOCK_COUNTED_OVER_MS.len()],
}

/// What a [`Histogram`] held when it was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HistogramRead {
    /// How many fell in each bucket, not summed: bucket `i` holds the
    /// lengths over 2^(i-1) µs and up to 2^i µs, the first those up to
    /// 1 µs, and the last those over 2^(LOAD_HISTOGRAM_BUCKETS - 1) µs.
    pub buckets: [u64; LOAD_HISTOGRAM_BUCKETS + 1],
    /// How many were recorded.
    pub count: u64,
    /// Their sum, in nanoseconds.
    pub sum_nanos: u64,
    /// The longest, in microseconds.
    pub max_micros: u64,
    /// How many were longer than each of LOCK_COUNTED_OVER_MS.
    pub over: [u64; LOCK_COUNTED_OVER_MS.len()],
}

/// The bucket that a length of `micros` falls in: the least `i` for which
/// it is at most 2^i µs, or the one past the last bound.
fn bucket_of(micros: u64) -> usize {
    let i = match micros {
        0 | 1 => 0,
        _ => (u64::BITS - (micros - 1).leading_zeros()) as usize,
    };
    i.min(LOAD_HISTOGRAM_BUCKETS)
}

impl Histogram {
    /// Record one length.
    pub fn record(&self, length: Duration) {
        let nanos = u64::try_from(length.as_nanos()).unwrap_or(u64::MAX);
        let micros = nanos / 1000;
        self.buckets[bucket_of(micros)].fetch_add(1, Ordering::Relaxed);
        if nanos > 0 {
            self.sum_nanos.fetch_add(nanos, Ordering::Relaxed);
        }
        if micros > self.max_micros.load(Ordering::Relaxed) {
            self.max_micros.fetch_max(micros, Ordering::Relaxed);
        }
        for (over, ms) in self.over.iter().zip(LOCK_COUNTED_OVER_MS) {
            if micros > ms * 1000 {
                over.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// What it holds now.
    pub fn read(&self) -> HistogramRead {
        let buckets = std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed));
        HistogramRead {
            buckets,
            count: buckets.iter().sum(),
            sum_nanos: self.sum_nanos.load(Ordering::Relaxed),
            max_micros: self.max_micros.load(Ordering::Relaxed),
            over: std::array::from_fn(|i| self.over[i].load(Ordering::Relaxed)),
        }
    }
}

// ── The kinds ────────────────────────────────────────────────────────

/// A kind of take of the node's lock, by the request or task it is in
/// (decision 2026-10-22 §1.1, rule 4; §1.2). At a relay: the reads (a
/// pull, a short show, a proof), the writes (a push, a whole show, the
/// stream between relays and a relay's own pull and passing on), and the
/// sweeps. On a device: its passes, its sync cycle, its local API, its
/// sweep and its hourly task, which ends with the checkpoint. Any other is
/// `Other`, which is declared last: a kind is added before it, and in
/// [`Kind::ALL`] at its place, or the build fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    ShowWhole,
    ShowShort,
    Proof,
    Pull,
    Push,
    Relays,
    Sweep,
    Checkpoint,
    Pass,
    Cycle,
    Api,
    Other,
}

impl Kind {
    /// Every kind, in the order they are served.
    pub const ALL: [Kind; 12] = [
        Kind::ShowWhole,
        Kind::ShowShort,
        Kind::Proof,
        Kind::Pull,
        Kind::Push,
        Kind::Relays,
        Kind::Sweep,
        Kind::Checkpoint,
        Kind::Pass,
        Kind::Cycle,
        Kind::Api,
        Kind::Other,
    ];

    /// Its name, as the route serves it.
    pub fn name(self) -> &'static str {
        match self {
            Kind::ShowWhole => "show_whole",
            Kind::ShowShort => "show_short",
            Kind::Proof => "proof",
            Kind::Pull => "pull",
            Kind::Push => "push",
            Kind::Relays => "relays",
            Kind::Sweep => "sweep",
            Kind::Checkpoint => "checkpoint",
            Kind::Pass => "pass",
            Kind::Cycle => "cycle",
            Kind::Api => "api",
            Kind::Other => "other",
        }
    }
}

// Kind::ALL holds every kind, each at its own place (`kind as usize`, by
// which the lock's histograms are indexed), and ends with Other, the kind
// declared last: so a kind declared and left out of it, or put at another
// place, fails the build.
const _: () = {
    let mut i = 0;
    while i < Kind::ALL.len() {
        assert!(Kind::ALL[i] as usize == i);
        i += 1;
    }
    assert!(Kind::Other as usize == Kind::ALL.len() - 1);
};

/// A kind of request on the streams of entries (decision 2026-10-22
/// §1.2): a show, whole or in short; a proof; a pull; a push; and the
/// stream between relays (0x14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    ShowWhole,
    ShowShort,
    Proof,
    Pull,
    Push,
    Relays,
}

impl Stream {
    /// Every kind of request, in the order they are served.
    pub const ALL: [Stream; 6] = [
        Stream::ShowWhole,
        Stream::ShowShort,
        Stream::Proof,
        Stream::Pull,
        Stream::Push,
        Stream::Relays,
    ];

    /// The kind of take of the lock that a request of this kind is.
    pub fn kind(self) -> Kind {
        match self {
            Stream::ShowWhole => Kind::ShowWhole,
            Stream::ShowShort => Kind::ShowShort,
            Stream::Proof => Kind::Proof,
            Stream::Pull => Kind::Pull,
            Stream::Push => Kind::Push,
            Stream::Relays => Kind::Relays,
        }
    }

    /// Its name, as the route serves it: its kind's.
    pub fn name(self) -> &'static str {
        self.kind().name()
    }
}

/// What became of a request that a relay read (decision 2026-10-22
/// §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answered {
    /// An answer was written: counted once it is.
    Answered,
    /// It asked for more than the asker may be handed for now: refused,
    /// and no breach.
    NotNow,
    /// It was over the connection's or the address's count: refused, a
    /// breach.
    RefusedForRate,
    /// It could not be served, or its answer could not be written:
    /// nothing was said.
    NotServed,
    /// It was no request for the stream it came on.
    Stray,
    /// It was longer than a small message, from a peer that is not a
    /// listed relay, and no large permit came for it within
    /// STREAM_TIMEOUT_SECS: refused with ERR_LARGE_MESSAGE_LATER, to be
    /// sent again, and no breach. Its frame was not read: the bytes in
    /// counted for it are its length's.
    LargeLater,
}

impl Answered {
    /// Every answer, in the order they are served.
    pub const ALL: [Answered; 6] = [
        Answered::Answered,
        Answered::NotNow,
        Answered::RefusedForRate,
        Answered::NotServed,
        Answered::Stray,
        Answered::LargeLater,
    ];

    /// Its name, as the route serves it.
    pub fn name(self) -> &'static str {
        match self {
            Answered::Answered => "answered",
            Answered::NotNow => "not_now",
            Answered::RefusedForRate => "refused_for_rate",
            Answered::NotServed => "not_served",
            Answered::Stray => "stray",
            Answered::LargeLater => "large_later",
        }
    }
}

/// Why a relay refused an entry in a request it answered (decision
/// 2026-10-22 §1.2): it had no room for it, or the asker's address had
/// made it take as many new channels as one may for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Room,
    NewChannels,
}

impl Refusal {
    /// Every refusal, in the order they are served.
    pub const ALL: [Refusal; 2] = [Refusal::Room, Refusal::NewChannels];

    /// Its name, as the route serves it.
    pub fn name(self) -> &'static str {
        match self {
            Refusal::Room => "refused_for_room",
            Refusal::NewChannels => "refused_for_new_channels",
        }
    }
}

/// Why a node turned an inbound connection away (decision 2026-10-22
/// §1.2): its bound on connections, the bound for an address, the bound
/// for a subnet; or the address is refused for a time, after a breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnedAway {
    Bound,
    Address,
    Subnet,
    RefusedForATime,
}

impl TurnedAway {
    /// Every reason, in the order they are served.
    pub const ALL: [TurnedAway; 4] = [
        TurnedAway::Bound,
        TurnedAway::Address,
        TurnedAway::Subnet,
        TurnedAway::RefusedForATime,
    ];

    /// Its name, as the route serves it.
    pub fn name(self) -> &'static str {
        match self {
            TurnedAway::Bound => "bound",
            TurnedAway::Address => "address",
            TurnedAway::Subnet => "subnet",
            TurnedAway::RefusedForATime => "refused_for_a_time",
        }
    }
}

// ── Counts by relay ──────────────────────────────────────────────────

/// A slot that holds no relay yet.
const FREE: u8 = 0;
/// A slot whose key is being written.
const WRITING: u8 = 1;
/// A slot whose key is written: it counts for that relay.
const READY: u8 = 2;

/// The counts of one relay, by its key.
#[derive(Debug)]
struct RelaySlot<const C: usize> {
    state: AtomicU8,
    key: [AtomicU64; 4],
    counts: [AtomicU64; C],
}

impl<const C: usize> Default for RelaySlot<C> {
    fn default() -> Self {
        Self {
            state: AtomicU8::new(FREE),
            key: Default::default(),
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl<const C: usize> RelaySlot<C> {
    fn is_of(&self, key: &[u8; 32]) -> bool {
        self.key
            .iter()
            .zip(key.as_chunks::<8>().0)
            .all(|(part, of)| part.load(Ordering::Relaxed) == u64::from_le_bytes(*of))
    }

    fn key(&self) -> [u8; 32] {
        let mut key = [0; 32];
        for (part, to) in self.key.iter().zip(key.as_chunks_mut::<8>().0) {
            to.copy_from_slice(&part.load(Ordering::Relaxed).to_le_bytes());
        }
        key
    }
}

/// What is counted of each relay, by its key, in the order the relays
/// took their slots; and of the rest, where any relay is counted there.
pub type ByKey<T> = (Vec<([u8; 32], T)>, Option<T>);

/// `C` counts for each relay, by its key, with no lock (decision
/// 2026-10-22 §1.2, the requests to each relay and the closures of the
/// link to each).
///
/// A relay takes a slot the first time it is counted, and keeps it for as
/// long as the node runs. Past LOAD_RELAYS_COUNTED relays, the rest are
/// counted together. Two that take a slot for one key at the same moment
/// may both take one: the slots of a key are summed when they are read.
#[derive(Debug)]
pub struct ByRelay<const C: usize> {
    slots: [RelaySlot<C>; LOAD_RELAYS_COUNTED],
    rest: [AtomicU64; C],
}

impl<const C: usize> Default for ByRelay<C> {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| RelaySlot::default()),
            rest: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl<const C: usize> ByRelay<C> {
    /// The counts of the relay `key`, where it has a slot.
    fn find(&self, key: &[u8; 32]) -> Option<&[AtomicU64; C]> {
        self.slots
            .iter()
            .find(|slot| slot.state.load(Ordering::Acquire) == READY && slot.is_of(key))
            .map(|slot| &slot.counts)
    }

    /// The counts of the relay `key`: its slot, a free slot that it takes
    /// now, or the rest.
    fn of(&self, key: &[u8; 32]) -> &[AtomicU64; C] {
        if let Some(counts) = self.find(key) {
            return counts;
        }
        for slot in &self.slots {
            let taken =
                slot.state
                    .compare_exchange(FREE, WRITING, Ordering::AcqRel, Ordering::Acquire);
            if taken.is_ok() {
                for (part, of) in slot.key.iter().zip(key.as_chunks::<8>().0) {
                    part.store(u64::from_le_bytes(*of), Ordering::Relaxed);
                }
                slot.state.store(READY, Ordering::Release);
                return &slot.counts;
            }
        }
        &self.rest
    }

    /// Count the relay `key`, so that it has a slot from now on.
    pub fn counts(&self, key: &[u8; 32]) {
        self.of(key);
    }

    /// Add `n` to the count `at` of the relay `key`.
    pub fn add(&self, key: &[u8; 32], at: usize, n: u64) {
        self.of(key)[at].fetch_add(n, Ordering::Relaxed);
    }

    /// Add `n` to the count `at` of the relay `key`, where it has a slot,
    /// and to nothing where it has none.
    pub fn add_where_counted(&self, key: &[u8; 32], at: usize, n: u64) {
        if let Some(counts) = self.find(key) {
            counts[at].fetch_add(n, Ordering::Relaxed);
        }
    }

    /// What each relay has, by its key, the slots of one key summed, in
    /// the order the relays took their slots; and the rest, where any
    /// relay is counted there.
    pub fn read(&self) -> ByKey<[u64; C]> {
        let mut each: Vec<([u8; 32], [u64; C])> = Vec::new();
        for slot in &self.slots {
            if slot.state.load(Ordering::Acquire) != READY {
                continue;
            }
            let key = slot.key();
            let counts: [u64; C] = std::array::from_fn(|i| slot.counts[i].load(Ordering::Relaxed));
            match each.iter_mut().find(|(of, _)| *of == key) {
                Some((_, kept)) => kept.iter_mut().zip(counts).for_each(|(k, c)| *k += c),
                None => each.push((key, counts)),
            }
        }
        let rest: [u64; C] = std::array::from_fn(|i| self.rest[i].load(Ordering::Relaxed));
        (each, rest.iter().any(|n| *n > 0).then_some(rest))
    }
}

// ── What a relay is asked ────────────────────────────────────────────

/// What a relay is asked on the streams of entries, by stream kind
/// (decision 2026-10-22 §1.2): the requests, counted when each is read;
/// what became of each, an answer once it is written; each entry it
/// refused in the answers it gave, for room and for the allowance of new
/// channels; and the bytes in and out, as each frame is read and written.
#[derive(Debug, Default)]
pub struct StreamCounts {
    requests: [AtomicU64; Stream::ALL.len()],
    answers: [[AtomicU64; Answered::ALL.len()]; Stream::ALL.len()],
    refused: [[AtomicU64; Refusal::ALL.len()]; Stream::ALL.len()],
    bytes_in: [AtomicU64; Stream::ALL.len()],
    bytes_out: [AtomicU64; Stream::ALL.len()],
}

impl StreamCounts {
    /// A request of `stream` was read, in a frame of `bytes`.
    pub fn read(&self, stream: Stream, bytes: usize) {
        self.requests[stream as usize].fetch_add(1, Ordering::Relaxed);
        self.bytes_in[stream as usize].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// A request of `stream` was `answered`.
    pub fn answered(&self, stream: Stream, answered: Answered) {
        self.answers[stream as usize][answered as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// An entry in the answer to a request of `stream` was refused for
    /// `why`.
    pub fn refused(&self, stream: Stream, why: Refusal) {
        self.refused[stream as usize][why as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The answer to a request of `stream` was written, in a frame of
    /// `bytes`.
    pub fn wrote(&self, stream: Stream, bytes: usize) {
        self.bytes_out[stream as usize].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// The requests of `stream` read so far.
    pub fn requests(&self, stream: Stream) -> u64 {
        self.requests[stream as usize].load(Ordering::Relaxed)
    }

    /// The requests of `stream` that were `answered` so far.
    pub fn answers(&self, stream: Stream, answered: Answered) -> u64 {
        self.answers[stream as usize][answered as usize].load(Ordering::Relaxed)
    }

    /// The entries refused for `why` in answers to `stream` so far.
    pub fn refusals(&self, stream: Stream, why: Refusal) -> u64 {
        self.refused[stream as usize][why as usize].load(Ordering::Relaxed)
    }

    /// The bytes of `stream` read and written so far.
    pub fn bytes(&self, stream: Stream) -> (u64, u64) {
        (
            self.bytes_in[stream as usize].load(Ordering::Relaxed),
            self.bytes_out[stream as usize].load(Ordering::Relaxed),
        )
    }
}

// ── Connections ──────────────────────────────────────────────────────

/// Where a closure of the link to a relay is counted, of its counts.
const CLOSURES: usize = 0;

/// A node's connections (decision 2026-10-22 §1.2): how many are open, as
/// a gauge set each time one is made or goes; how many have gone, for any
/// reason, those warm churn closed among them (the governor counts those
/// apart, so the rest are the difference); those it turned away, by why;
/// and the closures of the link to each relay that it is set up with or
/// lists by key.
#[derive(Debug, Default)]
pub struct ConnectionCounts {
    open: AtomicU64,
    closed: AtomicU64,
    turned_away: [AtomicU64; TurnedAway::ALL.len()],
    relays: ByRelay<1>,
}

impl ConnectionCounts {
    /// `open` connections are open now.
    pub fn set_open(&self, open: usize) {
        self.open.store(open as u64, Ordering::Relaxed);
    }

    /// The connection to `peer` has gone, for whatever reason: it is
    /// counted, and as a closure of a relay's link where `peer` is a relay
    /// that is counted ([`Self::counts_relay`]).
    pub fn closed(&self, peer: &[u8; 32]) {
        self.closed.fetch_add(1, Ordering::Relaxed);
        self.relays.add_where_counted(peer, CLOSURES, 1);
    }

    /// The closures of the link to the relay `key` are counted from now
    /// on.
    pub fn counts_relay(&self, key: &[u8; 32]) {
        self.relays.counts(key);
    }

    /// An inbound connection was turned away for `why`.
    pub fn turned_away(&self, why: TurnedAway) {
        self.turned_away[why as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The connections open, as last set.
    pub fn open(&self) -> u64 {
        self.open.load(Ordering::Relaxed)
    }

    /// The connections gone so far.
    pub fn closed_so_far(&self) -> u64 {
        self.closed.load(Ordering::Relaxed)
    }

    /// The closures of the link to the relay `key` so far: none where it
    /// is not counted.
    pub fn closures_of(&self, key: &[u8; 32]) -> u64 {
        self.relays
            .find(key)
            .map_or(0, |counts| counts[CLOSURES].load(Ordering::Relaxed))
    }

    /// The inbound connections turned away for `why` so far.
    pub fn turned_away_for(&self, why: TurnedAway) -> u64 {
        self.turned_away[why as usize].load(Ordering::Relaxed)
    }
}

// ── The governor ─────────────────────────────────────────────────────

/// Who a connection that warm churn closed was to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    Device,
    Relay,
}

impl Peer {
    /// Every kind of peer, in the order they are served.
    pub const ALL: [Peer; 2] = [Peer::Device, Peer::Relay];

    /// Its name, as the route serves it.
    pub fn name(self) -> &'static str {
        match self {
            Peer::Device => "device",
            Peer::Relay => "relay",
        }
    }
}

/// What a node's governor did (decision 2026-10-22 §1.2): its churns,
/// counted where the interval has passed and before warm churn looks at
/// its peers, so that a churn counts where warm churn closes nothing; the
/// connections that warm churn closed, of devices and of relays; and its
/// peers hot, warm and cold, as its tick last counted them, apart from the
/// count of connections.
#[derive(Debug, Default)]
pub struct GovernorCounts {
    churns: AtomicU64,
    closed_by_warm_churn: [AtomicU64; Peer::ALL.len()],
    hot: AtomicU64,
    warm: AtomicU64,
    cold: AtomicU64,
}

impl GovernorCounts {
    /// The churn interval passed, and churn runs.
    pub fn churned(&self) {
        self.churns.fetch_add(1, Ordering::Relaxed);
    }

    /// Warm churn closed the connection to a `peer`.
    pub fn closed_by_warm_churn(&self, peer: Peer) {
        self.closed_by_warm_churn[peer as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The governor's tick counted these peers.
    pub fn set_peers(&self, hot: usize, warm: usize, cold: usize) {
        self.hot.store(hot as u64, Ordering::Relaxed);
        self.warm.store(warm as u64, Ordering::Relaxed);
        self.cold.store(cold as u64, Ordering::Relaxed);
    }

    /// The churns so far.
    pub fn churns(&self) -> u64 {
        self.churns.load(Ordering::Relaxed)
    }

    /// The connections that warm churn closed so far, to `peer`s.
    pub fn closed_by_warm_churn_of(&self, peer: Peer) -> u64 {
        self.closed_by_warm_churn[peer as usize].load(Ordering::Relaxed)
    }

    /// The peers hot, warm and cold, as the tick last counted them.
    pub fn peers(&self) -> (u64, u64, u64) {
        (
            self.hot.load(Ordering::Relaxed),
            self.warm.load(Ordering::Relaxed),
            self.cold.load(Ordering::Relaxed),
        )
    }
}

// ── What a device asks ───────────────────────────────────────────────

/// Where each of a device's counts for a relay is: its requests and
/// their bytes by stream kind, then those it held back and those the
/// relay refused for now.
const ASKED: usize = 0;
const ASKED_BYTES: usize = Stream::ALL.len();
const HELD_BACK: usize = 2 * Stream::ALL.len();
const REFUSED_FOR_NOW: usize = HELD_BACK + 1;
const DEVICE_COUNTS: usize = REFUSED_FOR_NOW + 1;

/// What a device asked of each relay (decision 2026-10-22 §1.2): the
/// requests by stream kind and their bytes, counted as each is sent; the
/// requests it held back by its own pace (OWN_ENTRY_REQUESTS_PER_MINUTE);
/// and those the relay refused for now.
///
/// **Refused for now** is what the relay reset with ERR_RATE_LIMIT: a
/// request over the connection's or the address's count (the relay's
/// `refused_for_rate`, a breach) and one for more than the device may be
/// handed for now (its `not_now`, no breach) are reset with the same code,
/// and a device cannot tell them apart. So it is cross-checked against the
/// relay's `refused_for_rate` and `not_now` together.
#[derive(Debug, Default)]
pub struct DeviceCounts {
    relays: ByRelay<DEVICE_COUNTS>,
}

/// What a device counts of one relay, as it was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceRead {
    pub asked: [u64; Stream::ALL.len()],
    pub asked_bytes: [u64; Stream::ALL.len()],
    pub held_back: u64,
    /// Reset by the relay with ERR_RATE_LIMIT: for rate, or not now.
    pub refused_for_now: u64,
}

impl DeviceRead {
    fn of(counts: [u64; DEVICE_COUNTS]) -> Self {
        Self {
            asked: std::array::from_fn(|i| counts[ASKED + i]),
            asked_bytes: std::array::from_fn(|i| counts[ASKED_BYTES + i]),
            held_back: counts[HELD_BACK],
            refused_for_now: counts[REFUSED_FOR_NOW],
        }
    }
}

impl DeviceCounts {
    /// A request of `stream` was sent to the relay `relay`, in a frame of
    /// `bytes`.
    pub fn asked(&self, relay: &[u8; 32], stream: Stream, bytes: usize) {
        let counts = self.relays.of(relay);
        counts[ASKED + stream as usize].fetch_add(1, Ordering::Relaxed);
        counts[ASKED_BYTES + stream as usize].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// A request to the relay `relay` was held back: the device had asked
    /// it as much as it asks a relay in a minute.
    pub fn held_back(&self, relay: &[u8; 32]) {
        self.relays.add(relay, HELD_BACK, 1);
    }

    /// The relay `relay` refused a request for now: it reset its stream
    /// with ERR_RATE_LIMIT, for rate or not now.
    pub fn refused_for_now(&self, relay: &[u8; 32]) {
        self.relays.add(relay, REFUSED_FOR_NOW, 1);
    }

    /// What is counted of the relay `key`: nothing where it has no slot.
    pub fn of(&self, key: &[u8; 32]) -> DeviceRead {
        self.relays
            .find(key)
            .map_or_else(DeviceRead::default, |counts| {
                DeviceRead::of(std::array::from_fn(|i| counts[i].load(Ordering::Relaxed)))
            })
    }

    /// What is counted of each relay, by its key; and of the rest, where
    /// any relay is counted there.
    pub fn read(&self) -> ByKey<DeviceRead> {
        let (each, rest) = self.relays.read();
        (
            each.into_iter()
                .map(|(key, counts)| (key, DeviceRead::of(counts)))
                .collect(),
            rest.map(DeviceRead::of),
        )
    }
}

// ── A node's counters, and the route's text ──────────────────────────

/// Every counter of a node but the lock's own (decision 2026-10-22
/// §7.3). Each part is shared with what counts in it: the streams with a
/// relay's entries, the connections with the connection manager and the
/// loop that accepts, the governor with the governor, and a device's with
/// its leave.
#[derive(Debug, Default)]
pub struct Load {
    pub streams: Arc<StreamCounts>,
    pub connections: Arc<ConnectionCounts>,
    pub governor: Arc<GovernorCounts>,
    pub device: Arc<DeviceCounts>,
}

/// One histogram, in the text form of `/api/v1/metrics`: its buckets
/// summed, its sum in microseconds, its count, its longest, and how many
/// were longer than each of LOCK_COUNTED_OVER_MS.
fn histogram(out: &mut String, name: &str, label: &str, read: &HistogramRead) {
    let mut summed = 0;
    for (i, n) in read.buckets.iter().enumerate() {
        summed += n;
        let _ = match i < LOAD_HISTOGRAM_BUCKETS {
            true => writeln!(
                out,
                "{name}_bucket{{{label},le=\"{}\"}} {summed}",
                1u64 << i
            ),
            false => writeln!(out, "{name}_bucket{{{label},le=\"+Inf\"}} {summed}"),
        };
    }
    let micros = read.sum_nanos / 1000;
    let part = read.sum_nanos % 1000;
    let _ = writeln!(out, "{name}_sum{{{label}}} {micros}.{part:03}");
    let _ = writeln!(out, "{name}_count{{{label}}} {}", read.count);
    let _ = writeln!(out, "{name}_max{{{label}}} {}", read.max_micros);
    for (ms, n) in LOCK_COUNTED_OVER_MS.iter().zip(read.over) {
        let _ = writeln!(out, "{name}_over{{{label},ms=\"{ms}\"}} {n}");
    }
}

/// A family's HELP and TYPE.
fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// The label of a relay: its key in hex, or "rest" for those counted
/// together.
fn relay_label(key: Option<&[u8; 32]>) -> String {
    key.map_or_else(|| "rest".to_string(), hex::encode)
}

/// Every counter of a node, `load` and the times of its lock `lock`, in
/// the text form that `/api/v1/metrics` uses (decision 2026-10-22 §1.1,
/// rule 3), and how long it has run. It reads atomics and nothing else.
pub fn render(load: &Load, lock: &LockTimes, uptime_secs: f64) -> String {
    let mut out = String::new();
    family(&mut out, "cordelia_uptime_seconds", "gauge", "Node uptime");
    let _ = writeln!(out, "cordelia_uptime_seconds {uptime_secs:.1}");

    // The lock, by kind of take, and the two mutexes taken under it.
    for (name, help, of) in [
        (
            "cordelia_lock_wait_microseconds",
            "From asking for the node's lock to holding it, by kind of take",
            LockTimes::wait as fn(&LockTimes, Kind) -> HistogramRead,
        ),
        (
            "cordelia_lock_hold_microseconds",
            "How long the node's lock was held, by kind of take",
            LockTimes::hold,
        ),
    ] {
        family(&mut out, name, "histogram", help);
        for kind in Kind::ALL {
            let label = format!("kind=\"{}\"", kind.name());
            histogram(&mut out, name, &label, &of(lock, kind));
        }
    }
    let name = "cordelia_lock_given_up_total";
    family(
        &mut out,
        name,
        "counter",
        "Takes of the node's lock that tried until their time was up and were not had, by kind",
    );
    for kind in Kind::ALL {
        let n = lock.given_up(kind);
        let _ = writeln!(out, "{name}{{kind=\"{}\"}} {n}", kind.name());
    }
    let name = "cordelia_lock_nested_wait_microseconds";
    family(
        &mut out,
        name,
        "histogram",
        "Waits for the rates and the room while the node's lock is held",
    );
    for nested in Nested::ALL {
        let label = format!("mutex=\"{}\"", nested.name());
        histogram(&mut out, name, &label, &lock.nested(nested));
    }

    // What a relay is asked.
    let streams = &load.streams;
    let name = "cordelia_requests_total";
    family(&mut out, name, "counter", "Requests read, by stream kind");
    for stream in Stream::ALL {
        let n = streams.requests[stream as usize].load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}{{kind=\"{}\"}} {n}", stream.name());
    }
    let name = "cordelia_answers_total";
    family(
        &mut out,
        name,
        "counter",
        "What became of each request read",
    );
    for stream in Stream::ALL {
        for answered in Answered::ALL {
            let n = streams.answers[stream as usize][answered as usize].load(Ordering::Relaxed);
            let (kind, answer) = (stream.name(), answered.name());
            let _ = writeln!(out, "{name}{{kind=\"{kind}\",answer=\"{answer}\"}} {n}");
        }
    }
    let name = "cordelia_entries_refused_total";
    family(
        &mut out,
        name,
        "counter",
        "Entries refused in the answers given, for room or for new channels",
    );
    for stream in Stream::ALL {
        for why in Refusal::ALL {
            let n = streams.refused[stream as usize][why as usize].load(Ordering::Relaxed);
            let (kind, answer) = (stream.name(), why.name());
            let _ = writeln!(out, "{name}{{kind=\"{kind}\",answer=\"{answer}\"}} {n}");
        }
    }
    let name = "cordelia_stream_bytes_total";
    family(&mut out, name, "counter", "Bytes of frames, by stream kind");
    for stream in Stream::ALL {
        for (direction, of) in [("in", &streams.bytes_in), ("out", &streams.bytes_out)] {
            let n = of[stream as usize].load(Ordering::Relaxed);
            let kind = stream.name();
            let _ = writeln!(
                out,
                "{name}{{kind=\"{kind}\",direction=\"{direction}\"}} {n}"
            );
        }
    }

    // Connections.
    let connections = &load.connections;
    family(
        &mut out,
        "cordelia_connections_open",
        "gauge",
        "Connections open",
    );
    let _ = writeln!(out, "cordelia_connections_open {}", connections.open());
    family(
        &mut out,
        "cordelia_connections_closed_total",
        "counter",
        "Connections gone, for any reason, warm churn's among them",
    );
    let closed = connections.closed.load(Ordering::Relaxed);
    let _ = writeln!(out, "cordelia_connections_closed_total {closed}");
    let name = "cordelia_connections_turned_away_total";
    family(&mut out, name, "counter", "Inbound connections turned away");
    for why in TurnedAway::ALL {
        let n = connections.turned_away[why as usize].load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}{{why=\"{}\"}} {n}", why.name());
    }
    let name = "cordelia_relay_link_closures_total";
    family(
        &mut out,
        name,
        "counter",
        "Closures of the link to each relay",
    );
    let (each, rest) = connections.relays.read();
    for (key, counts) in &each {
        let relay = relay_label(Some(key));
        let _ = writeln!(out, "{name}{{relay=\"{relay}\"}} {}", counts[CLOSURES]);
    }
    if let Some(counts) = rest {
        let _ = writeln!(out, "{name}{{relay=\"rest\"}} {}", counts[CLOSURES]);
    }

    // The governor.
    let governor = &load.governor;
    family(
        &mut out,
        "cordelia_churns_total",
        "counter",
        "Churns: each time the churn interval passed",
    );
    let _ = writeln!(out, "cordelia_churns_total {}", governor.churns());
    let name = "cordelia_closed_by_warm_churn_total";
    family(
        &mut out,
        name,
        "counter",
        "Connections closed by warm churn",
    );
    for peer in Peer::ALL {
        let n = governor.closed_by_warm_churn_of(peer);
        let _ = writeln!(out, "{name}{{peer=\"{}\"}} {n}", peer.name());
    }
    let name = "cordelia_governor_peers";
    family(
        &mut out,
        name,
        "gauge",
        "The governor's peers by state, at its tick",
    );
    let (hot, warm, cold) = governor.peers();
    for (state, n) in [("hot", hot), ("warm", warm), ("cold", cold)] {
        let _ = writeln!(out, "{name}{{state=\"{state}\"}} {n}");
    }

    // What a device asked of each relay.
    let (each, rest) = load.device.read();
    let relays: Vec<(String, DeviceRead)> = each
        .iter()
        .map(|(key, read)| (relay_label(Some(key)), *read))
        .chain(rest.map(|read| (relay_label(None), read)))
        .collect();
    for (name, help, of) in [
        (
            "cordelia_device_requests_total",
            "Requests a device sent to each relay, by stream kind",
            (|read: &DeviceRead| read.asked) as fn(&DeviceRead) -> [u64; 6],
        ),
        (
            "cordelia_device_request_bytes_total",
            "Bytes of the requests a device sent to each relay, by stream kind",
            |read: &DeviceRead| read.asked_bytes,
        ),
    ] {
        family(&mut out, name, "counter", help);
        for (relay, read) in &relays {
            for (stream, n) in Stream::ALL.iter().zip(of(read)) {
                let kind = stream.name();
                let _ = writeln!(out, "{name}{{relay=\"{relay}\",kind=\"{kind}\"}} {n}");
            }
        }
    }
    for (name, help, of) in [
        (
            "cordelia_device_held_back_total",
            "Requests a device held back by its own pace, for each relay",
            (|read: &DeviceRead| read.held_back) as fn(&DeviceRead) -> u64,
        ),
        (
            "cordelia_device_refused_for_now_total",
            "Requests each relay refused a device for now (ERR_RATE_LIMIT): its refused_for_rate and not_now",
            |read: &DeviceRead| read.refused_for_now,
        ),
    ] {
        family(&mut out, name, "counter", help);
        for (relay, read) in &relays {
            let _ = writeln!(out, "{name}{{relay=\"{relay}\"}} {}", of(read));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Each line of the route's text that holds a value, by its name and
    /// labels.
    fn values(text: &str) -> BTreeMap<String, String> {
        text.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .filter_map(|line| line.rsplit_once(' '))
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    /// The lines whose value changed from `before` to `after`.
    fn moved(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Vec<String> {
        after
            .iter()
            .filter(|(name, value)| before.get(*name) != Some(*value))
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn said(load: &Load) -> BTreeMap<String, String> {
        values(&render(load, &LockTimes::default(), 0.0))
    }

    /// Each kind of request is the kind of take of the same name, and
    /// every kind, answer, refusal, reason and peer has a name of its own.
    #[test]
    fn each_kind_of_request_is_the_take_of_its_name_and_every_name_is_its_own() {
        for stream in Stream::ALL {
            assert_eq!(stream.name(), stream.kind().name());
            assert_eq!(Kind::ALL[stream as usize], stream.kind());
        }
        let names: Vec<&str> = Kind::ALL.iter().map(|kind| kind.name()).collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), names.len());
        for (i, kind) in Kind::ALL.iter().enumerate() {
            assert_eq!(*kind as usize, i);
        }
        for (i, answered) in Answered::ALL.iter().enumerate() {
            assert_eq!(*answered as usize, i);
        }
        for (i, why) in TurnedAway::ALL.iter().enumerate() {
            assert_eq!(*why as usize, i);
        }
        for (i, why) in Refusal::ALL.iter().enumerate() {
            assert_eq!(*why as usize, i);
        }
        for (i, peer) in Peer::ALL.iter().enumerate() {
            assert_eq!(*peer as usize, i);
        }
    }

    /// A length falls in the least bucket whose bound it is at most:
    /// powers of two from 1 µs to 16 s, and one for what is longer.
    #[test]
    fn a_length_falls_in_the_least_bucket_of_powers_of_two_that_holds_it() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(1), 0);
        assert_eq!(bucket_of(2), 1);
        assert_eq!(bucket_of(3), 2);
        assert_eq!(bucket_of(4), 2);
        assert_eq!(bucket_of(5), 3);
        assert_eq!(bucket_of(12), 4);
        assert_eq!(bucket_of(1 << 24), 24);
        assert_eq!(bucket_of((1 << 24) + 1), LOAD_HISTOGRAM_BUCKETS);
        assert_eq!(bucket_of(u64::MAX), LOAD_HISTOGRAM_BUCKETS);
    }

    /// A histogram counts each length in its bucket, sums them, keeps the
    /// longest, and counts those over 5, 50, 100 and 250 ms.
    #[test]
    fn a_histogram_counts_sums_and_keeps_the_longest_and_those_over_each_length() {
        let h = Histogram::default();
        h.record(Duration::from_nanos(12_500));
        h.record(Duration::from_millis(6));
        h.record(Duration::from_millis(60));
        h.record(Duration::from_millis(300));
        h.record(Duration::from_millis(5));
        let read = h.read();
        assert_eq!(read.count, 5);
        assert_eq!(read.buckets[4], 1, "12 µs is over 8 and up to 16");
        assert_eq!(
            read.buckets[13], 2,
            "5 and 6 ms are over 4,096 and up to 8,192 µs"
        );
        assert_eq!(read.buckets[16], 1);
        assert_eq!(read.buckets[19], 1);
        assert_eq!(read.sum_nanos, 12_500 + 371_000_000);
        assert_eq!(read.max_micros, 300_000);
        // 5 ms is not over 5 ms.
        assert_eq!(read.over, [3, 2, 1, 1]);
    }

    /// The route's text says each histogram's buckets summed, with their
    /// bounds, and its sum, count, longest and counts over each length.
    #[test]
    fn a_histogram_is_said_with_its_buckets_summed() {
        let h = Histogram::default();
        h.record(Duration::from_micros(3));
        h.record(Duration::from_micros(20_000_000));
        let mut out = String::new();
        histogram(&mut out, "h", "kind=\"pull\"", &h.read());
        let said = values(&out);
        assert_eq!(said["h_bucket{kind=\"pull\",le=\"1\"}"], "0");
        assert_eq!(said["h_bucket{kind=\"pull\",le=\"4\"}"], "1");
        assert_eq!(said["h_bucket{kind=\"pull\",le=\"16777216\"}"], "1");
        assert_eq!(said["h_bucket{kind=\"pull\",le=\"+Inf\"}"], "2");
        assert_eq!(said["h_sum{kind=\"pull\"}"], "20000003.000");
        assert_eq!(said["h_count{kind=\"pull\"}"], "2");
        assert_eq!(said["h_max{kind=\"pull\"}"], "20000000");
        assert_eq!(said["h_over{kind=\"pull\",ms=\"250\"}"], "1");
    }

    /// Each count of a relay's streams moves for what it counts and for
    /// nothing else: a request read and its bytes in, what became of it,
    /// an entry refused, and the bytes out.
    #[test]
    fn each_count_of_the_streams_moves_for_what_it_counts_and_for_nothing_else() {
        let load = Load::default();
        let before = said(&load);
        load.streams.read(Stream::Pull, 40);
        assert_eq!(
            moved(&before, &said(&load)),
            [
                "cordelia_requests_total{kind=\"pull\"}",
                "cordelia_stream_bytes_total{kind=\"pull\",direction=\"in\"}",
            ]
        );
        let before = said(&load);
        load.streams.answered(Stream::Push, Answered::NotNow);
        assert_eq!(
            moved(&before, &said(&load)),
            ["cordelia_answers_total{kind=\"push\",answer=\"not_now\"}"]
        );
        let before = said(&load);
        load.streams
            .refused(Stream::ShowWhole, Refusal::NewChannels);
        assert_eq!(
            moved(&before, &said(&load)),
            [
                "cordelia_entries_refused_total{kind=\"show_whole\",answer=\"refused_for_new_channels\"}"
            ]
        );
        let before = said(&load);
        load.streams.wrote(Stream::Relays, 7);
        let after = said(&load);
        assert_eq!(
            moved(&before, &after),
            ["cordelia_stream_bytes_total{kind=\"relays\",direction=\"out\"}"]
        );
        assert_eq!(
            after["cordelia_stream_bytes_total{kind=\"relays\",direction=\"out\"}"],
            "7"
        );
    }

    /// Each count of the connections moves for what it counts and for
    /// nothing else: the gauge as it is set, a closure, a closure of a
    /// relay's link where that relay is counted, and each reason a
    /// connection is turned away.
    #[test]
    fn each_count_of_the_connections_moves_for_what_it_counts_and_for_nothing_else() {
        let load = Load::default();
        let before = said(&load);
        load.connections.set_open(3);
        let after = said(&load);
        assert_eq!(moved(&before, &after), ["cordelia_connections_open"]);
        assert_eq!(after["cordelia_connections_open"], "3");

        let (relay, device) = ([7; 32], [8; 32]);
        load.connections.counts_relay(&relay);
        let before = said(&load);
        load.connections.closed(&device);
        assert_eq!(
            moved(&before, &said(&load)),
            ["cordelia_connections_closed_total"]
        );
        let before = said(&load);
        load.connections.closed(&relay);
        let label = format!(
            "cordelia_relay_link_closures_total{{relay=\"{}\"}}",
            hex::encode(relay)
        );
        assert_eq!(
            moved(&before, &said(&load)),
            ["cordelia_connections_closed_total".to_string(), label]
        );
        for why in TurnedAway::ALL {
            let before = said(&load);
            load.connections.turned_away(why);
            assert_eq!(
                moved(&before, &said(&load)),
                [format!(
                    "cordelia_connections_turned_away_total{{why=\"{}\"}}",
                    why.name()
                )]
            );
        }
    }

    /// Each count of the governor moves for what it counts and for
    /// nothing else; its peers are said apart from the connections.
    #[test]
    fn each_count_of_the_governor_moves_for_what_it_counts_and_for_nothing_else() {
        let load = Load::default();
        let before = said(&load);
        load.governor.churned();
        assert_eq!(moved(&before, &said(&load)), ["cordelia_churns_total"]);
        for peer in Peer::ALL {
            let before = said(&load);
            load.governor.closed_by_warm_churn(peer);
            assert_eq!(
                moved(&before, &said(&load)),
                [format!(
                    "cordelia_closed_by_warm_churn_total{{peer=\"{}\"}}",
                    peer.name()
                )]
            );
        }
        let before = said(&load);
        load.governor.set_peers(1, 2, 0);
        let after = said(&load);
        assert_eq!(
            moved(&before, &after),
            [
                "cordelia_governor_peers{state=\"hot\"}",
                "cordelia_governor_peers{state=\"warm\"}",
            ]
        );
        assert_eq!(after["cordelia_connections_open"], "0");
    }

    /// Each count of what a device asks moves for what it counts, for the
    /// relay it was asked of, and for nothing else.
    #[test]
    fn each_count_of_a_device_moves_for_what_it_counts_and_for_nothing_else() {
        let load = Load::default();
        let (one, other) = ([1; 32], [2; 32]);
        load.device.asked(&other, Stream::ShowShort, 1);
        let at = |what: &str, relay: &[u8; 32], kind: Option<&str>| match kind {
            Some(kind) => format!("{what}{{relay=\"{}\",kind=\"{kind}\"}}", hex::encode(relay)),
            None => format!("{what}{{relay=\"{}\"}}", hex::encode(relay)),
        };
        let before = said(&load);
        load.device.asked(&other, Stream::Pull, 120);
        let after = said(&load);
        assert_eq!(
            moved(&before, &after),
            [
                at("cordelia_device_request_bytes_total", &other, Some("pull")),
                at("cordelia_device_requests_total", &other, Some("pull")),
            ]
        );
        let before = said(&load);
        load.device.held_back(&other);
        assert_eq!(
            moved(&before, &said(&load)),
            [at("cordelia_device_held_back_total", &other, None)]
        );
        let before = said(&load);
        load.device.refused_for_now(&other);
        assert_eq!(
            moved(&before, &said(&load)),
            [at("cordelia_device_refused_for_now_total", &other, None)]
        );
        // A relay asked for the first time is said from then on, and
        // nothing of the other moves.
        let before = said(&load);
        load.device.asked(&one, Stream::Push, 9);
        let after = said(&load);
        assert!(
            moved(&before, &after)
                .iter()
                .all(|line| line.contains(&hex::encode(one)))
        );
        assert_eq!(
            after[&at("cordelia_device_requests_total", &one, Some("push"))],
            "1"
        );
        assert_eq!(
            after[&at("cordelia_device_requests_total", &other, Some("pull"))],
            "1"
        );
    }

    /// Each relay has a slot of its own, up to LOAD_RELAYS_COUNTED; the
    /// rest are counted together; and a relay that is not counted is
    /// added to nothing where only counted ones are.
    #[test]
    fn each_relay_is_counted_apart_up_to_the_slots_and_the_rest_together() {
        let by: ByRelay<1> = ByRelay::default();
        for n in 0..LOAD_RELAYS_COUNTED + 2 {
            by.add(&[n as u8; 32], 0, n as u64 + 1);
        }
        let (each, rest) = by.read();
        assert_eq!(each.len(), LOAD_RELAYS_COUNTED);
        for (n, (key, counts)) in each.iter().enumerate() {
            assert_eq!(*key, [n as u8; 32]);
            assert_eq!(counts[0], n as u64 + 1);
        }
        let past = LOAD_RELAYS_COUNTED as u64;
        assert_eq!(rest, Some([(past + 1) + (past + 2)]));

        let by: ByRelay<1> = ByRelay::default();
        by.add_where_counted(&[9; 32], 0, 1);
        assert_eq!(by.read(), (Vec::new(), None));
        by.counts(&[9; 32]);
        by.add_where_counted(&[9; 32], 0, 1);
        assert_eq!(by.read(), (vec![([9; 32], [1])], None));
    }

    /// Relays counted from many threads at once are each counted, and
    /// their counts are whole: the slots of a key taken twice are summed.
    #[test]
    fn relays_counted_from_many_threads_at_once_keep_every_count() {
        let by: Arc<ByRelay<1>> = Arc::default();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let by = by.clone();
                std::thread::spawn(move || {
                    for n in 0..1000u32 {
                        by.add(&[(n % 4) as u8; 32], 0, 1);
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        let (each, rest) = by.read();
        assert_eq!(rest, None);
        assert_eq!(each.len(), 4);
        assert!(each.iter().all(|(_, counts)| counts[0] == 2000));
    }
}
