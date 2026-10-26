//! The leave to use a connection to a relay (decision 2026-10-04 §4.6,
//! §16).
//!
//! A show comes before everything, and it is a rule of the connection. The
//! build keeps it as a rule of time, and calls it leave:
//!
//! - **A device has leave on a connection for SHOW_LEAVE_SECS from an
//!   answer there which says that the relay holds no later change than the
//!   one the device keeps**: that it holds the entry shown; that it took
//!   it; or that it would have taken it and did not, for room or for the
//!   address's allowance. No other answer gives leave: not another entry,
//!   or word of one; not "show it whole"; not a stream that is reset or
//!   that times out.
//! - **A device in a fork has no leave anywhere, nor has one that has
//!   stopped,** nor one that follows no phrase: it has nothing to show.
//! - **Leave ends at once, at every relay, when the entry that the device
//!   keeps changes.** It is given for the entry that was shown, and what
//!   the device keeps is read from its database each time leave is asked.
//! - **A device that wakes asks every relay first.** When the node starts,
//!   or reaches a relay after having reached none, there is no leave
//!   anywhere until each relay it is set up with has answered a show, or
//!   WAKE_WAIT_SECS have gone by.
//! - **A device that was answered with a change and could not apply it**
//!   has no leave anywhere until it has: whatever becomes of the
//!   connection that the change came on.
//! - **A machine that slept wakes.** Leave is measured on a clock that
//!   does not run while a machine sleeps, and the connections that it
//!   had still look open when it opens its lid. So at each pass the time
//!   of day is set beside that clock: where the time of day has run
//!   ahead of it by more than a leave lasts since the pass before, every
//!   leave is dropped, and the device wakes as one that reaches a relay
//!   after having reached none.
//!
//! With leave, a device still asks only so much of a relay in a minute
//! (OWN_ENTRY_REQUESTS_PER_MINUTE): a relay counts the requests on these
//! streams, and one over its count is a breach. The relay counts them
//! for the device's key, whatever connection they come on, so the device
//! counts them for the relay, across a reconnect.
//!
//! [`Leave`] is the one thing that holds this, and the one way to the
//! streams of a channel of the device's own. [`Leave::open`] opens a
//! stream to prove a channel's key, to pull a page or to push entries. It
//! asks for leave when the stream is opened, and again before what came
//! back is taken: what arrives after the leave has run out is dropped.
//! What came back is read with no database, and then handed, under the
//! lock of the database that the leave was asked under, to whoever takes
//! it, and to nobody else.
//!
//! **A request is sent only under the change entry that it was built
//! under** (§16). Whoever asks says which entry the device kept when the
//! request was made: its channels are those of that entry's statement.
//! Where the device keeps another by the time the stream is to be
//! opened, or by the time its answer is to be taken, a change was
//! applied in between, on this connection or on any other: nothing is
//! sent, and nothing is taken. So nothing is sent in a channel that the
//! device has left, and nothing is written down of one.
//!
//! **One channel is read without leave: the pair channel of a key typed
//! at `cordelia accept`,** for the hour that `accept` allows (§4.6, §5.1).
//! A device that follows no phrase has nothing to show, and one that has
//! stopped has no leave, and each has to be handed a change.
//! [`Leave::pair`] is the one door for that, beside the one way in, and
//! it can do nothing else. It is given a key, and no channel and no
//! request: the key must be one that the device keeps as typed within
//! the last hour, with no hand-over taken since, which is read from the
//! database here. The channel is derived here, from that key and the
//! device's own. The requests are made here: a proof of that channel's
//! key, and pulls of its pages from the start, each on from the place the
//! last reached, until one says there is no more (at most
//! RELAY_ENTRY_PULL_PAGES). Nothing is pushed, and no place is kept. What comes back is given to
//! [`cordelia_api::adding::accept_typed`], which judges a hand-over by
//! the state the device is in, and to nothing else.
//!
//! **And one door is for a carry that a person asked for** (§7.3, §7.5,
//! §9): `cordelia sync carry` and `cordelia recover` read, at a relay, a
//! channel of a generation that the device has left, or never followed.
//! That is no channel of the device's own, and nothing of the leave is
//! about it: [`Leave::left`] asks none and gives none. It is as narrow as
//! the door for a typed key:
//!
//! - It is given a channel's ID and a proof of that channel's key for
//!   this very connection, made by whoever holds the channel's secret: the
//!   node, for a generation whose secret it keeps, or the command that
//!   was typed the phrase, in its own process. No secret passes here.
//! - **A channel of the device's own, under the statement it has applied,
//!   is refused:** those are read through the one way in, with its
//!   leave, and through nothing else.
//! - Two requests are made, each built here: the proof, and a pull of
//!   one page from a place. Each counts against what the device asks of
//!   a relay in a minute. **Nothing is pushed.**
//! - What comes back is checked as whatever a device is sent is checked,
//!   and handed to the caller: the entries of that channel, and the place
//!   to ask after next. **Nothing is stored here, and no place is kept:**
//!   what is taken of it is decided by the one function that judges a
//!   version for a carry (`cordelia_api::carry::bring`), and by nothing
//!   else.
//!
//! **And two doors are for the channels shared between people** (decision
//! 2026-10-10 §8.4), whose streams are opened without a show and without
//! leave, on a device that stands applied with sync on:
//!
//! - [`Leave::shared`] is given a channel's ID and which of three requests
//!   (a proof, a pull with a `limit`, a push of what waits), and builds the
//!   request itself, from the table of shared channels read under the
//!   database's lock: it refuses a channel that is not held there or does
//!   not live at the connection's relay. What comes back to a pull is given
//!   to the one door ([`cordelia_api::take::take`]); a push's answers are
//!   kept with what waits at each relay.
//! - [`Leave::share_pair`] is given a key typed for a channel and nothing
//!   else, as [`Leave::pair`] is given a key typed to join devices: it
//!   derives the share pair channel itself, proves it and reads its pages
//!   from the start, and gives each entry by the typed key to whoever
//!   judges a share. [`Leave::share_pair_push`] pushes a share entry that
//!   this device wrote in its share pair channel with the key it is for.
//!
//! **Each counts against a counter of its own** (`SHARED_REQUESTS_PER_MINUTE`
//! for each relay over a minute), never against what the device asks for its
//! own channels: past it the request is not sent, and that is not counted as
//! held back by the device's pace. A request that a relay refuses for now is
//! counted for the relay as every door counts one.
//!
//! A connection is a [`Link`], which keeps the connection to itself:
//! outside this file there is no way to open a stream on one but
//! [`Leave::show`], [`Leave::open`], [`Leave::pair`], [`Leave::left`],
//! [`Leave::shared`], [`Leave::share_pair`] and [`Leave::share_pair_push`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cordelia_api::adding::{self, Accepted};
use cordelia_api::at_relays::{self, Stands};
use cordelia_api::at_relays::{Most, Pushed};
use cordelia_api::shared_pass::{self, NotUsable};
use cordelia_api::state::{AppState, Came};
use cordelia_core::NodeId;
use cordelia_core::load::DeviceCounts;
use cordelia_core::lock::{LockWhole, TimedLock};
use cordelia_core::protocol::{
    BAN_THRESHOLD, BAN_WINDOW_SECS, ENTRY_PAGE_MAX_ENTRIES, ENTRY_WIRE_OVERHEAD_BYTES,
    ERR_RATE_LIMIT, FRAME_LENGTH_BYTES, OWN_ENTRY_REQUESTS_PER_MINUTE, RELAY_ENTRY_PULL_PAGES,
    SESSION_VALUE_BYTES, SHARED_REQUESTS_PER_MINUTE, SHOW_LEAVE_SECS, WAKE_WAIT_SECS, entry_cost,
};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::{derive, proof};
use cordelia_network::messages::{
    ChannelProve, EntryPull, EntryPush, EntryRefused, EntryShow, EntryShowShort, Protocol,
    PushAnswer, ShowAnswer, WireMessage,
};
use cordelia_network::rate_limit::RateCounter;
use cordelia_network::{codec, transport};
use cordelia_storage::acts::TypedKey;
use cordelia_storage::person::State;
use cordelia_storage::relay::NO_MARK;
use rusqlite::Connection;

/// How long a leave lasts.
const LEAVE: Duration = Duration::from_secs(SHOW_LEAVE_SECS);

/// The window in which a relay counts breaches of its rates, and the
/// device what a relay refused for now.
const BAN_WINDOW: Duration = Duration::from_secs(BAN_WINDOW_SECS);

/// How long a device that wakes waits for its relays.
const WAKE_WAIT: Duration = Duration::from_secs(WAKE_WAIT_SECS);

/// Lock a mutex, also one whose holder panicked: what it guards is times
/// and names, which are whole after any one step.
fn lock<L: LockWhole + ?Sized>(mutex: &L) -> L::Guard<'_> {
    mutex.lock_whole()
}

/// The time, as a device's side of its relays reads it: the system's, and
/// as far ahead of it as a test has set it. One clock is shared by
/// everything that waits, so that a test can let a wait go by.
#[derive(Debug, Clone, Default)]
pub struct Clock {
    ahead_ms: Arc<AtomicU64>,
    /// How far the time of day is ahead besides: time that went by while
    /// the clock that waits are measured by stood still.
    slept_ms: Arc<AtomicU64>,
}

impl Clock {
    /// The system's clock.
    pub fn system() -> Self {
        Self::default()
    }

    /// Now.
    pub fn now(&self) -> Instant {
        Instant::now() + Duration::from_millis(self.ahead_ms.load(Ordering::Relaxed))
    }

    /// Now, in seconds, in UTC.
    pub fn unix(&self) -> i64 {
        self.wall_ms() / 1000
    }

    /// The time of day now, in milliseconds, in UTC: the clock that goes
    /// on while a machine sleeps, and that can be set.
    pub fn wall_ms(&self) -> i64 {
        chrono::Utc::now()
            .timestamp_millis()
            .saturating_add(self.ahead_of_the_day_ms())
    }

    /// The time of day `now`, in seconds, in UTC, as read from the node's
    /// clock ([`cordelia_api::state::SyncControl::now`]), and as far
    /// ahead of it as a test has run this clock: none in a node.
    pub fn unix_from(&self, now: i64) -> i64 {
        now.saturating_add(self.ahead_of_the_day_ms() / 1000)
    }

    /// How far ahead a test has run the time of day, in milliseconds.
    fn ahead_of_the_day_ms(&self) -> i64 {
        let ahead = self
            .ahead_ms
            .load(Ordering::Relaxed)
            .saturating_add(self.slept_ms.load(Ordering::Relaxed));
        i64::try_from(ahead).unwrap_or(i64::MAX)
    }

    /// Run the clock ahead by `by`, from where it is. For tests.
    pub fn run_ahead(&self, by: Duration) {
        let by = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.ahead_ms.fetch_add(by, Ordering::Relaxed);
    }

    /// The machine slept for `by`: the time of day runs ahead by that,
    /// and the clock that waits are measured by does not. For tests.
    pub fn slept(&self, by: Duration) {
        let by = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.slept_ms.fetch_add(by, Ordering::Relaxed);
    }
}

/// Whether a machine slept between two readings of its two clocks: the
/// time of day ran ahead of the clock that cannot go back by more than a
/// leave lasts. Each reading is that clock, and the time of day in
/// milliseconds.
///
/// A time of day that was set back says nothing, and nor does one that
/// was set ahead by less than a leave: a leave that a sleep of that
/// length leaves standing is checked again by the show that follows.
fn slept_between(before: (Instant, i64), now: (Instant, i64)) -> bool {
    let ran = now.0.saturating_duration_since(before.0);
    let by_the_day = u64::try_from(now.1.saturating_sub(before.1)).unwrap_or(0);
    Duration::from_millis(by_the_day).saturating_sub(ran) > LEAVE
}

/// What tells one connection from every other that this node has or had:
/// the value that both ends export from its TLS session.
pub type LinkId = [u8; SESSION_VALUE_BYTES];

/// A connection to a relay that this device is set up with.
///
/// It keeps the connection to itself: a stream is opened on it by
/// [`Leave::show`] and [`Leave::open`], and by nothing else.
#[derive(Clone)]
pub struct Link {
    name: String,
    relay: NodeId,
    conn: quinn::Connection,
    /// The value of the connection's TLS session, where it gives one.
    session: Option<[u8; SESSION_VALUE_BYTES]>,
    id: LinkId,
}

impl Link {
    /// The connection `conn` to the relay whose node key is `relay`, and
    /// that the device knows as `name`: what its configuration calls it.
    pub fn new(name: impl Into<String>, relay: NodeId, conn: quinn::Connection) -> Self {
        let session = transport::session_value(&conn).ok();
        // A connection whose session gives no value is like no other, and
        // not like itself the next time it is asked about: nothing is
        // remembered of it, and no proof holds on it.
        let id = session.unwrap_or_else(|| {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let mut id = [0u8; SESSION_VALUE_BYTES];
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            id[..8].copy_from_slice(&n.to_be_bytes());
            id
        });
        Self {
            name: name.into(),
            relay,
            conn,
            session,
            id,
        }
    }

    /// What the device's configuration calls the relay.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The relay's node key.
    pub fn relay(&self) -> &NodeId {
        &self.relay
    }

    /// What tells this connection from every other that this node has or
    /// had: a new connection to the same relay is another.
    pub fn id(&self) -> LinkId {
        self.id
    }

    /// The value that both ends export from this connection's TLS
    /// session, which a proof is made over. `None` where the session
    /// gives none.
    pub fn session(&self) -> Option<[u8; SESSION_VALUE_BYTES]> {
        self.session
    }

    /// Whether the connection is still open.
    pub fn is_open(&self) -> bool {
        self.conn.close_reason().is_none()
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Why there is no leave to use a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoLeave {
    /// The node is still waking: a relay it is set up with has not
    /// answered a show yet, and the wait for it has not gone by.
    Waking,
    /// The device follows no phrase: it has no channel of its own.
    NoPhrase,
    /// The device has stopped, or is in a fork.
    Stopped(State),
    /// The device was answered with a change that it could not apply.
    NotApplied,
    /// No answer on this connection gives leave now: none was had, or the
    /// last is SHOW_LEAVE_SECS old, or it was to another entry than the
    /// one the device keeps now. A show gives it again.
    NotGiven,
}

/// Why a stream was not opened, or what came back on it was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// There was no leave: when the stream was to be opened, or by the
    /// time its answer came back. Nothing was taken.
    NoLeave(NoLeave),
    /// The relay did not answer: the stream was refused, or reset, or
    /// timed out.
    NotAnswered(String),
    /// What was asked is not asked on a stream of a channel.
    NotARequest,
    /// The device has asked as much of this relay as it asks in a minute.
    /// Nothing was sent: it is asked again later.
    AskedEnough,
    /// The device keeps another change entry than the one the request
    /// was built under: it applied a change since. Nothing was sent, or
    /// nothing of what came back was taken. The channels are read afresh.
    KeptAnother,
    /// A request that the relay refused for now: it reset the stream with
    /// ERR_RATE_LIMIT ([`refused_for_now`]), as it does where it has
    /// handed the connection what it may in a minute. That is also how a
    /// relay refuses a breach of its rates: whoever waits it out asks
    /// again only a few times. Nothing was taken.
    NotNow,
    /// Nothing was sent: the relay has refused for now as many requests
    /// as the device gives one in BAN_WINDOW_SECS, and the request was
    /// held to that count ([`Asked::gated`], [`Leave::at_its_count`]).
    RefusedEnough,
}

/// What is asked on a stream for a channel of the device's own: the
/// request, and what the change entry was named by that the device kept
/// when the request was built.
#[derive(Debug, Clone, Copy)]
pub struct Asked<'a> {
    /// What the change entry is named by that the request was built
    /// under: its channels are those of that entry's statement.
    pub under: &'a [u8; 32],
    /// A proof of a channel's key, a pull of a page, or a push of
    /// entries.
    pub request: &'a WireMessage,
    /// Whether the request is held to the relay's count of refusals for
    /// now ([`Leave::at_its_count`]): a read's are, and a pass's are not.
    pub gated: bool,
}

/// What a relay handed of the pair channel of a key that a person typed
/// ([`Leave::pair`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairRead {
    /// The key reads nothing now: its hour has gone, a hand-over was
    /// taken with it, or a person has typed it again since. Nothing was
    /// asked of the relay.
    NotNow,
    /// The relay does not hold the channel, as it answered the proof.
    NotHeld,
    /// What became of each entry that the relay handed and that the
    /// device of the typed key signed, in the relay's order.
    Read(Vec<Accepted>),
}

/// Which request the door of a shared channel's streams builds
/// ([`Leave::shared`], decision 2026-10-10 §8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedAsk {
    /// A proof of the channel's key.
    Prove,
    /// A pull of one page from the place the device keeps, of at most
    /// `limit` entries.
    Pull { limit: u32 },
    /// A push of what waits for the relay, within `most`.
    Push { most: Most },
}

/// What became of a request of a shared channel ([`Leave::shared`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedDone {
    /// The proof was answered: whether the relay holds the channel.
    Proved(bool),
    /// A page was taken: how many entries it held, what the relay handed as
    /// it counts it, whether the pull got somewhere by it, and whether it
    /// held nothing.
    Page {
        entries: usize,
        handed: u64,
        got_somewhere: bool,
        end: bool,
    },
    /// A push was answered: how many entries were sent, how many the relay
    /// refused for room or for the address's allowance, and what they are
    /// counted at.
    Pushed {
        sent: usize,
        refused: usize,
        cost: u64,
    },
    /// Nothing waits for the relay within what may be pushed: nothing was
    /// asked.
    NothingWaits,
}

/// Why nothing was asked through a door of a shared channel, or what came
/// back was not taken (decision 2026-10-10 §8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedRefused {
    /// The door refuses the channel here: not held, not at this relay, the
    /// device does not stand applied, or sync is off. Nothing was asked,
    /// or nothing taken.
    NotUsable(NotUsable),
    /// The shared pass has asked as much of this relay as it asks in a
    /// minute: nothing was sent.
    AskedEnough,
    /// The relay refused the request for now, and that was counted for it.
    NotNow,
    /// The relay did not answer, or not as it answers such a request; or
    /// the device could not read its own store.
    NotAnswered(String),
}

/// What a relay handed of the share pair channel of a key typed for a
/// channel ([`Leave::share_pair`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharePairRead<A> {
    /// The key reads nothing now: nothing was asked of the relay.
    NotNow,
    /// The relay does not hold the channel, as it answered the proof.
    NotHeld,
    /// What the judge made of each entry that the relay handed and that the
    /// typed key signed, in the relay's order.
    Read(Vec<A>),
}

/// What a relay handed of a channel of a generation that the device has
/// left, or never followed ([`Leave::left`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeftPage {
    /// The relay does not hold the channel, as it answered the proof: or
    /// the proof did not hold there. A relay says neither which.
    NotHeld,
    /// One page: the entries of that channel that it handed, each
    /// checked; the size on the wire of each entry that it handed,
    /// whatever became of it; and the place to ask after next.
    Page {
        entries: Vec<CheckedEntry>,
        handed: Vec<usize>,
        mark: [u8; cordelia_core::protocol::CHANNEL_MARK_BYTES],
        next: u64,
    },
}

/// Why nothing was read through the door for a carry ([`Leave::left`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeftRefused {
    /// The channel is one of the device's own, under the statement it has
    /// applied: it is read through the one way in, and through nothing
    /// else.
    OwnChannel,
    /// The device has asked as much of this relay as it asks in a minute.
    AskedEnough,
    /// The relay refused the pull for now, on a connection that is still
    /// open ([`Refused::NotNow`]), and that was counted for it. The
    /// proof, where one was sent, was answered.
    NotNow,
    /// The relay is at its count of refusals for now
    /// ([`Leave::at_its_count`]): the pull was not sent. The proof, where
    /// one was sent, was answered.
    AtItsCount,
    /// The relay did not answer, or not as it answers such a request.
    NotAnswered(String),
}

/// What a read through the door for a carry is said to have ended with
/// where the proof was refused for now ([`Refused::NotNow`]): the relay
/// took no more from the connection for now, over its allowance.
const PROOF_NOT_NOW: &str = "the proof was refused for now: the relay takes no more from this \
                             connection in this minute";

/// What a show was answered, and what it cost to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowAnswered {
    /// What the relay answered.
    pub answer: ShowAnswer,
    /// The bytes of the message that showed the entry.
    pub bytes: usize,
}

/// A leave that an answer gave.
#[derive(Debug, Clone, Copy)]
struct Given {
    /// When the answer was had.
    at: Instant,
    /// What the entry that was shown is named by: the one the device kept
    /// then.
    entry: [u8; 32],
}

/// Since the node last woke.
#[derive(Debug, Clone)]
struct Woke {
    /// When it woke: when it reached a relay after having reached none.
    at: Instant,
    /// The same moment, by the time of day, in seconds.
    wall: i64,
    /// The relays that have answered a show since, by name.
    heard: HashSet<String>,
    /// Whether the waking is over: every relay had answered, or the wait
    /// had gone by, when leave was last asked.
    awake: bool,
}

#[derive(Debug, Default)]
struct Inner {
    /// The leave on each connection, by what tells it from any other.
    given: HashMap<LinkId, Given>,
    /// Since the node last woke. `None` while it reaches no relay.
    woke: Option<Woke>,
    /// While it reaches no relay: since when, by the time of day, in
    /// seconds. From the node's start, a sleep, or the pass that found no
    /// connection open.
    unwoken_since: Option<i64>,
    /// The relays that the device is set up with, by name.
    set_up_with: Vec<String>,
    /// Whether the device was answered with a change that it could not
    /// apply, and has not applied since.
    not_applied: bool,
    /// The two clocks as they were read at the pass before.
    last: Option<(Instant, i64)>,
    /// What was asked of each relay in the last minute, on the streams of
    /// a channel, by the relay's name: on whatever connection.
    asked: HashMap<String, RateCounter>,
    /// The requests that each relay refused for now, by its node key,
    /// each by when ([`Leave::refused_for_now`]).
    refused_for_now: HashMap<[u8; 32], VecDeque<Instant>>,
    /// What the shared pass asked of each relay in the last minute, by the
    /// relay's name: its own counter, apart from `asked` (decision
    /// 2026-10-10 §8.4).
    shared_asked: HashMap<String, RateCounter>,
}

impl Inner {
    /// Whether one thing more may be asked of the relay called `relay`
    /// in this minute, on a stream of a channel. Where it may, it is
    /// counted.
    fn may_ask(&mut self, relay: &str) -> bool {
        self.asked
            .entry(relay.to_string())
            .or_insert_with(|| {
                RateCounter::new(Duration::from_secs(60), OWN_ENTRY_REQUESTS_PER_MINUTE)
            })
            .check_and_record()
    }

    /// Whether one request more of a shared channel or a share pair
    /// channel may be asked of the relay called `relay` in this minute
    /// (decision 2026-10-10 §8.4): its own counter, at
    /// SHARED_REQUESTS_PER_MINUTE. Where it may, it is counted.
    fn may_ask_shared(&mut self, relay: &str) -> bool {
        self.shared_asked
            .entry(relay.to_string())
            .or_insert_with(|| {
                RateCounter::new(Duration::from_secs(60), SHARED_REQUESTS_PER_MINUTE)
            })
            .check_and_record()
    }

    /// Whether the node is still waking at `now`.
    fn is_waking(&mut self, now: Instant) -> bool {
        let Some(woke) = &mut self.woke else {
            // It reaches no relay: there is nothing to have leave on.
            return true;
        };
        if !woke.awake {
            let all_heard = self
                .set_up_with
                .iter()
                .all(|relay| woke.heard.contains(relay));
            woke.awake = all_heard || now.saturating_duration_since(woke.at) >= WAKE_WAIT;
        }
        !woke.awake
    }
}

/// The leave to use each connection to a relay, and whether the node is
/// still waking (see the module's documentation).
#[derive(Debug)]
pub struct Leave {
    clock: Clock,
    inner: Mutex<Inner>,
    /// What the device asked of each relay, held back and was refused for
    /// now: counted, and read by nothing here (decision 2026-10-22 §1.2,
    /// §7.3).
    counts: Arc<DeviceCounts>,
}

impl Leave {
    /// For a node that has reached no relay yet, and reads the time from
    /// `clock`.
    pub fn new(clock: Clock) -> Self {
        Self {
            clock,
            inner: Mutex::default(),
            counts: Arc::default(),
        }
    }

    /// The same leave, counting what the device asks in `counts`: the
    /// node's counters (decision 2026-10-22 §7.3).
    pub fn counting(mut self, counts: Arc<DeviceCounts>) -> Self {
        self.counts = counts;
        self
    }

    /// What the device asks of `link`'s relay is counted as `protocol`'s
    /// kind, with the bytes of its frame, as it is written (decision
    /// 2026-10-22 §1.2): what `exchange` calls once the request is sent.
    fn counts_as_sent<'a>(
        &'a self,
        link: &'a Link,
        protocol: Protocol,
        request: &'a WireMessage,
    ) -> impl FnOnce(usize) + 'a {
        move |bytes| {
            if let Some(stream) = protocol.counted_as(Some(request)) {
                self.counts.asked(&link.relay().0, stream, bytes);
            }
        }
    }

    /// May one thing more be asked of `link`'s relay in this minute?
    /// Where it may not, the request is held back by the device's own
    /// pace, and that is counted (decision 2026-10-22 §1.2).
    fn may_ask_of(&self, link: &Link) -> bool {
        self.may_ask_of_relay(link.name(), link.relay())
    }

    /// [`Self::may_ask_of`], of the relay called `name` whose node key is
    /// `relay`.
    fn may_ask_of_relay(&self, name: &str, relay: &NodeId) -> bool {
        let may = lock(&self.inner).may_ask(name);
        if !may {
            self.counts.held_back(&relay.0);
        }
        may
    }

    /// What the node reaches now: `set_up_with` is every relay it is set
    /// up with, by name, and `reached` the connections it has to them.
    ///
    /// A node that reaches a relay after having reached none wakes: there
    /// is no leave anywhere until each relay it is set up with has
    /// answered a show, or the wait has gone by. So does one whose
    /// machine slept since the pass before ([`slept_between`]): every
    /// leave it was given is dropped. What is kept of a connection that
    /// is gone is forgotten.
    ///
    /// It is called at each pass, and the two clocks are read here. Says
    /// whether the machine slept since the pass before.
    pub fn reaches(&self, set_up_with: &[String], reached: &[&Link]) -> bool {
        let now = self.clock.now();
        let read = (now, self.clock.wall_ms());
        let mut inner = lock(&self.inner);
        inner.set_up_with = set_up_with.to_vec();
        let open: HashSet<LinkId> = reached.iter().map(|link| link.id()).collect();
        inner.given.retain(|link, _| open.contains(link));
        // What was asked of a relay is kept across a reconnect, for as
        // long as the device is set up with the relay.
        inner.asked.retain(|relay, _| set_up_with.contains(relay));
        inner
            .shared_asked
            .retain(|relay, _| set_up_with.contains(relay));
        // The lid was closed, and is open: the connections still look
        // open, and a leave still looks young, by a clock that stood
        // still. Every relay is asked first, as when the node starts.
        let slept = inner.last.is_some_and(|before| slept_between(before, read));
        let wall = read.1 / 1000;
        if slept || inner.last.is_none() {
            inner.unwoken_since = Some(wall);
        }
        if slept {
            inner.given.clear();
            inner.woke = None;
        }
        inner.last = Some(read);
        if reached.is_empty() {
            if inner.woke.take().is_some() {
                inner.unwoken_since = Some(wall);
            }
        } else if inner.woke.is_none() {
            inner.woke = Some(Woke {
                at: now,
                wall,
                heard: HashSet::new(),
                awake: false,
            });
        }
        slept
    }

    /// Whether the node is still waking.
    pub fn is_waking(&self) -> bool {
        lock(&self.inner).is_waking(self.clock.now())
    }

    /// When the node last woke, by the time of day, in seconds: where it
    /// reaches no relay, and so has not woken, since when it has reached
    /// none, from its start or a sleep (decision 2026-10-19 §5, D2 and
    /// T1). `None` before its first pass.
    pub fn woke_at(&self) -> Option<i64> {
        let inner = lock(&self.inner);
        inner
            .woke
            .as_ref()
            .map(|woke| woke.wall)
            .or(inner.unwoken_since)
    }

    /// Whether the relay called `name` has answered a show since the node
    /// last woke.
    pub fn has_heard(&self, name: &str) -> bool {
        lock(&self.inner)
            .woke
            .as_ref()
            .is_some_and(|woke| woke.heard.contains(name))
    }

    /// The device was answered with a change that it could not apply
    /// (`true`), or has applied it since (`false`). Until it has, there
    /// is no leave anywhere: it sends nothing and takes nothing in a
    /// channel of its own (decision 2026-10-04 §4.2). That is so on every
    /// connection, and whatever becomes of the one that the change came
    /// on: a connection that closes takes nothing back.
    pub fn could_not_apply(&self, could_not: bool) {
        lock(&self.inner).not_applied = could_not;
    }

    /// Whether the device was answered with a change that it has not
    /// applied.
    pub fn is_not_applied(&self) -> bool {
        lock(&self.inner).not_applied
    }

    /// Whether there is leave to use `link` now, and why not where there
    /// is none. `conn` is the device's database, which says where the
    /// device stands and which entry it keeps.
    pub fn has(&self, conn: &Connection, link: &Link) -> Result<(), NoLeave> {
        let now = self.clock.now();
        let mut inner = lock(&self.inner);
        if inner.is_waking(now) {
            return Err(NoLeave::Waking);
        }
        if inner.not_applied {
            return Err(NoLeave::NotApplied);
        }
        match at_relays::stands(conn) {
            Ok(Stands::Applied) => {}
            Ok(Stands::NoPhrase) => return Err(NoLeave::NoPhrase),
            Ok(Stands::Stopped(state)) => return Err(NoLeave::Stopped(state)),
            Err(_) => return Err(NoLeave::NotGiven),
        }
        let Some(given) = inner.given.get(&link.id()) else {
            return Err(NoLeave::NotGiven);
        };
        if now.saturating_duration_since(given.at) >= LEAVE {
            return Err(NoLeave::NotGiven);
        }
        // Leave ends at once when the entry that the device keeps
        // changes: it was given for the one that was shown.
        match at_relays::kept_id(conn) {
            Ok(Some(kept)) if kept == given.entry => Ok(()),
            _ => Err(NoLeave::NotGiven),
        }
    }

    /// Show `entry` on `link`: whole, or in short, by its revision and
    /// what it is named by. Returns what the relay answered, and how many
    /// bytes the show was.
    ///
    /// No leave is asked: this is what gives it. An answer that says the
    /// relay holds no later change than the entry gives leave on the
    /// connection from now, for that entry. Any other answer ends what
    /// leave there was. A stream that is not answered changes nothing.
    pub async fn show(
        &self,
        link: &Link,
        entry: &CheckedEntry,
        short: bool,
    ) -> Result<ShowAnswered, String> {
        let request = if short {
            WireMessage::EntryShowShort(EntryShowShort {
                channel: entry.channel,
                slot: entry.slot,
                author: entry.author,
                rev: entry.rev,
                id: entry.id(),
            })
        } else {
            WireMessage::EntryShow(EntryShow {
                entry: entry.to_wire(),
            })
        };
        let bytes = codec::encode_message(&request).map_or(0, |bytes| bytes.len());
        let answer = match self
            .ask_counted(link, Protocol::EntryShow, &request)
            .await?
        {
            WireMessage::EntryShown(shown) => shown.answer,
            _ => return Err("a show was not answered as one".into()),
        };
        let now = self.clock.now();
        let mut inner = lock(&self.inner);
        if let Some(woke) = &mut inner.woke {
            woke.heard.insert(link.name.clone());
        }
        if gives_leave(&answer) {
            inner.given.insert(
                link.id(),
                Given {
                    at: now,
                    entry: entry.id(),
                },
            );
        } else {
            inner.given.remove(&link.id());
        }
        Ok(ShowAnswered { answer, bytes })
    }

    /// Open a stream for a channel of the device's own on `link`, ask
    /// what is `asked` on it, and hand what came back to `read` and then
    /// to `take`: a proof of a channel's key, a pull of a page, or a push
    /// of entries, each on the stream of its own.
    ///
    /// The stream is refused where there is no leave ([`Leave::has`]),
    /// where the device keeps another change entry now than the one the
    /// request was built under ([`Asked::under`]), and where it has asked
    /// as much on this connection as it asks of a relay in a minute.
    ///
    /// **Which entry the device keeps is asked again once the stream is
    /// open, and before anything is written on it** (decision 2026-10-04
    /// §16). A relay can hold the opening of a stream back, for as long
    /// as the one timeout. Where the device has applied a change
    /// meanwhile, the request is for a channel that it has left: the
    /// stream is let go with nothing sent on it.
    ///
    /// `opened` is called once the stream is about to be opened, under
    /// the lock of the database that the leave was asked under: for what
    /// is kept of a request whatever comes back. It is not called for a
    /// stream that is refused.
    ///
    /// `read` is given the answer with no database: it checks what came
    /// back. Leave is then asked again, and whether the device still
    /// keeps that entry, and `take` is called with what `read` made,
    /// under the lock of the database that both were asked under: so
    /// nothing that came back is taken without leave, what arrives after
    /// the leave has run out is dropped, and so is what arrives after a
    /// change was applied.
    pub async fn open<R, T>(
        &self,
        db: &TimedLock<Connection>,
        link: &Link,
        asked: Asked<'_>,
        opened: impl FnOnce(&Connection),
        read: impl FnOnce(WireMessage) -> R,
        take: impl FnOnce(&Connection, R) -> T,
    ) -> Result<T, Refused> {
        let Asked {
            under,
            request,
            gated,
        } = asked;
        let protocol = match request {
            WireMessage::ChannelProve(_) => Protocol::ChannelProve,
            WireMessage::EntryPull(_) => Protocol::EntryPull,
            WireMessage::EntryPush(_) => Protocol::EntryPush,
            _ => return Err(Refused::NotARequest),
        };
        {
            let conn = lock(db);
            self.may_use(&conn, link, under)?;
            // A read sends nothing to a relay at its count of refusals for
            // now: one more may be the breach that has it cut off the
            // address.
            if gated && self.at_its_count(&link.relay().0) {
                return Err(Refused::RefusedEnough);
            }
            if !self.may_ask_of(link) {
                return Err(Refused::AskedEnough);
            }
            opened(&conn);
        }
        let (mut send, mut recv) = open_stream(&link.conn)
            .await
            .map_err(Refused::NotAnswered)?;
        // The stream is open, which may have taken the relay a while:
        // the request is written only where the device still keeps the
        // entry that it was built under.
        let still = self.keeps(&lock(db), under);
        if let Err(refused) = still {
            let _ = send.reset(0u32.into());
            let _ = recv.stop(0u32.into());
            return Err(refused);
        }
        // A request that the relay refused for now is said so, and
        // counted for the relay; any other failure is said as it was.
        let answer = exchange(
            send,
            recv,
            protocol,
            request,
            self.counts_as_sent(link, protocol, request),
        )
        .await
        .map_err(|e| self.refused(link, &e))?;
        let answer = read(answer);
        let conn = lock(db);
        self.may_use(&conn, link, under)?;
        Ok(take(&conn, answer))
    }

    /// The one door beside the one way in (decision 2026-10-04 §4.6):
    /// read, on `link`, the pair channel of this device and the key
    /// `typed`, which a person typed at `cordelia accept`, and give what
    /// the device of that key wrote there to
    /// [`adding::accept_typed`]. No leave is asked: a device that follows
    /// no phrase has nothing to show, and one that has stopped has no
    /// leave, and each is handed a change this way.
    ///
    /// It does that and nothing else (see the module's documentation):
    ///
    /// - The key is read again from the database, under its lock: one
    ///   that the device does not keep as typed then, within its hour and
    ///   with no hand-over taken, reads nothing, and the relay is asked
    ///   nothing.
    /// - The channel is this device's pair channel with that key, derived
    ///   here. No caller names a channel.
    /// - The requests are made, each built here: a proof of the channel's
    ///   key, and pulls of its pages, from the start and on from the place
    ///   that each page reaches, until a page holds nothing or leaves the
    ///   place where it was, the key reads nothing more, or
    ///   RELAY_ENTRY_PULL_PAGES pages were read (decision 2026-10-22
    ///   (memory), rule 3). Each counts against what the device asks of a
    ///   relay in a minute. Nothing is pushed.
    /// - Of what comes back, each entry of that channel that the typed
    ///   key signed is given to [`adding::accept_typed`], under the
    ///   database's lock, and to nothing else: none is stored, and no
    ///   place is kept. An entry of another channel, or by another key,
    ///   is dropped.
    ///
    /// `sync_on` says whether sync is on here, as the database says it.
    ///
    /// A hand-over that is taken has the device apply a statement, so
    /// each is given to [`adding::accept_typed`] as what may change which
    /// channels are the device's own is done
    /// ([`AppState::as_a_change_where`], decision 2026-10-04 §4.2):
    /// where one is taken, it waits for a sync cycle that is running to
    /// stop, and counts as a change of settings. One that is refused
    /// counts as none.
    pub async fn pair(
        &self,
        state: &AppState,
        link: &Link,
        typed: &TypedKey,
        sync_on: impl Fn(&Connection) -> bool,
    ) -> Result<PairRead, Refused> {
        let (db, identity) = (&state.db, &state.identity);
        let reads = |conn: &Connection, now: i64| {
            adding::keys_that_read(conn, now).is_ok_and(|keys| {
                keys.iter()
                    .any(|kept| kept.key == typed.key && kept.typed_at == typed.typed_at)
            })
        };
        let unix = || self.clock.unix_from(state.sync_control.now());
        if !reads(&lock(db), unix()) {
            return Ok(PairRead::NotNow);
        }
        let not = |why: &str| Refused::NotAnswered(why.to_string());
        let secret =
            derive::pair_secret(identity, &typed.key).map_err(|_| not("no pair channel"))?;
        let channel = derive::channel_id(&secret).map_err(|_| not("no pair channel"))?;
        let session = link.session().ok_or_else(|| not("no session"))?;
        let proof =
            proof::make(&secret, &session, &identity.public_key()).map_err(|_| not("no proof"))?;

        let prove = WireMessage::ChannelProve(ChannelProve { channel, proof });
        let proved = match self.asks(link, Protocol::ChannelProve, &prove).await? {
            WireMessage::ChannelProved(proved) => proved.proved,
            _ => return Err(not("a proof was not answered as one")),
        };
        if !proved {
            return Ok(PairRead::NotHeld);
        }
        let set_up = state.own_channels.relays_set_up_as();
        let mut read = Vec::new();
        // The channel is read from the start, and on from the place that
        // each page reaches, until a page says there is no more (decision
        // 2026-10-22 (memory), rule 3): a page for a device holds one entry
        // of the largest size, and a pair channel can hold more than one (a
        // hand-over is padded to that size), so the typed key's hand-over
        // may be on a later page. At most RELAY_ENTRY_PULL_PAGES pages are
        // read, and none once the key reads nothing more.
        let mut place = (NO_MARK, 0);
        for _ in 0..RELAY_ENTRY_PULL_PAGES {
            let pull = WireMessage::EntryPull(EntryPull {
                channel,
                mark: place.0,
                after: place.1,
                limit: ENTRY_PAGE_MAX_ENTRIES,
            });
            // A page that fails after another was read ends the read with
            // what that one gave: what was accepted is not undone.
            let page = match self.asks(link, Protocol::EntryPull, &pull).await {
                Ok(WireMessage::EntryPulled(page)) => page,
                Ok(_) if read.is_empty() => {
                    return Err(not("a pull was not answered with a page"));
                }
                Err(refused) if read.is_empty() => return Err(refused),
                _ => break,
            };
            // Each entry is checked as whatever a device is sent is checked,
            // with no database held.
            let handed: Vec<CheckedEntry> = page
                .entries
                .iter()
                .take(ENTRY_PAGE_MAX_ENTRIES as usize)
                .filter_map(|bytes| Entry::from_wire(bytes).ok()?.check().ok())
                .filter(|entry| entry.channel == channel && entry.author == typed.key)
                .collect();
            for entry in &handed {
                let now = unix();
                // It is a change of settings only where the hand-over was
                // taken: a statement was applied, or the device's state
                // changed. A device that is moved has left the phrase it
                // followed: the node then keeps no note of which relays had
                // handed the channels it held.
                let (accepted, _) = state.as_a_change_where(
                    |conn| {
                        at_relays::telling_a_change(conn, |conn| {
                            let sync_on = sync_on(conn);
                            adding::accept_typed(
                                conn, identity, typed, sync_on, entry, &set_up, now,
                            )
                        })
                    },
                    |(accepted, changed)| match accepted {
                        Ok(Some(Accepted::Moved(_))) => Came::Left,
                        _ if *changed => Came::Changed,
                        _ => Came::Nothing,
                    },
                );
                match accepted {
                    Ok(Some(accepted)) => read.push(accepted),
                    // The key reads nothing more: it was spent, or typed
                    // again, or its hour went by.
                    Ok(None) => return Ok(PairRead::Read(read)),
                    Err(e) => return Err(not(&format!("could not judge a hand-over: {e}"))),
                }
            }
            // A page that holds nothing, or that leaves the place where it
            // was, is the channel's end. And a key that was spent by what
            // this page held reads nothing more.
            let reached = (page.mark, page.next);
            if page.entries.is_empty() || reached == place || !reads(&lock(db), unix()) {
                break;
            }
            place = reached;
        }
        Ok(PairRead::Read(read))
    }

    /// The door for a carry that a person asked for (decision 2026-10-04
    /// §7.3, §7.5, §9): read, on `link`, one page of the channel whose ID
    /// is `channel`, which is of a generation that the device has left or
    /// never followed, from the place `place`. `proof` is the proof of
    /// that channel's key for this connection, made by whoever holds the
    /// channel's secret; with `prove`, it is sent before the page is
    /// asked for, as it is once for a channel on a connection.
    ///
    /// It does that and nothing else (see the module's documentation):
    ///
    /// - **No leave is asked, and none is given.** The channel is no
    ///   channel of the device's own: a device that follows no phrase
    ///   reads this way, at a recovery, and so does one that has
    ///   applied a statement and reads what it left.
    /// - **A channel of the device's own is refused,** as the database
    ///   says which those are, under its lock: there is one way in to
    ///   those. So is the messages channel of the generation it stands
    ///   applied under, whether or not sync is on (decision 2026-10-09
    ///   §2.1).
    /// - The two requests are built here, and each counts against what
    ///   the device asks of a relay in a minute. Nothing is pushed.
    /// - Of what comes back, the entries of that channel that pass the
    ///   check are handed to the caller, with the place to ask after
    ///   next. An entry of another channel is dropped. Nothing is
    ///   stored, and no place is kept.
    pub async fn left(
        &self,
        state: &AppState,
        link: &Link,
        channel: &[u8; 32],
        proof: &[u8; 64],
        place: ([u8; cordelia_core::protocol::CHANNEL_MARK_BYTES], u64),
        prove: bool,
    ) -> Result<LeftPage, LeftRefused> {
        let not = |why: &str| LeftRefused::NotAnswered(why.to_string());
        let (own, messages) = {
            let db = lock(&state.db);
            let own = at_relays::channels(&db, &state.identity);
            own.and_then(|own| Ok((own, at_relays::messages_channel(&db)?)))
        }
        .map_err(|e| not(&format!("could not read the device's own channels: {e}")))?;
        if own.iter().any(|own| own.id == *channel) || messages == Some(*channel) {
            return Err(LeftRefused::OwnChannel);
        }
        let asks = |refused: Refused| match refused {
            Refused::AskedEnough => LeftRefused::AskedEnough,
            Refused::NotAnswered(why) => LeftRefused::NotAnswered(why),
            other => LeftRefused::NotAnswered(format!("{other:?}")),
        };
        if prove {
            let request = WireMessage::ChannelProve(ChannelProve {
                channel: *channel,
                proof: *proof,
            });
            let answer = match self.asks(link, Protocol::ChannelProve, &request).await {
                // Refused for now: said as a proof's, not as a page's.
                Err(Refused::NotNow) => return Err(not(PROOF_NOT_NOW)),
                answer => answer,
            };
            match answer.map_err(asks)? {
                WireMessage::ChannelProved(proved) if proved.proved => {}
                WireMessage::ChannelProved(_) => return Ok(LeftPage::NotHeld),
                _ => return Err(not("a proof was not answered as one")),
            }
        }
        // The pull is held to the relay's count as it goes out, as each
        // request of a read is ([`Self::open`]): a refusal at another door
        // may have come while the proof was answered, and one more may be
        // the breach that has the relay cut off the address.
        if self.at_its_count(&link.relay().0) {
            return Err(LeftRefused::AtItsCount);
        }
        let (mark, after) = place;
        let pull = WireMessage::EntryPull(EntryPull {
            channel: *channel,
            mark,
            after,
            limit: ENTRY_PAGE_MAX_ENTRIES,
        });
        let answer = self.asks(link, Protocol::EntryPull, &pull).await;
        let page = match answer {
            Err(Refused::NotNow) => return Err(LeftRefused::NotNow),
            answer => answer.map_err(asks)?,
        };
        let page = match page {
            WireMessage::EntryPulled(page) => page,
            _ => return Err(not("a pull was not answered with a page")),
        };
        if page.entries.len() > ENTRY_PAGE_MAX_ENTRIES as usize {
            return Err(not("a page holds more than a page may"));
        }
        // Each entry is checked as whatever a device is sent is checked,
        // with no database held, and only an entry of that channel is
        // handed on.
        let handed = page.entries.iter().map(|bytes| bytes.len()).collect();
        let entries = page
            .entries
            .iter()
            .filter_map(|bytes| Entry::from_wire(bytes).ok()?.check().ok())
            .filter(|entry| entry.channel == *channel)
            .collect();
        Ok(LeftPage::Page {
            entries,
            handed,
            mark: page.mark,
            next: page.next,
        })
    }

    /// The door of a shared channel's streams (decision 2026-10-10 §8.4):
    /// on `link`, ask of the shared channel `channel` what `ask` says, and
    /// take what comes back. No show is made and no leave asked.
    ///
    /// It does that and nothing else (see the module's documentation):
    ///
    /// - Under the database's lock, it reads the channel from the table of
    ///   shared channels, and refuses one that is not held there, or whose
    ///   card does not name the connection's relay by its key; and it
    ///   refuses where the device does not stand applied under the latest
    ///   statement it has seen, or sync is off. It builds the request
    ///   itself: the proof, from the channel's secret; the pull, from the
    ///   place it keeps there, with `limit`; the push, of what waits there
    ///   within `most`.
    /// - It counts the request against the shared pass's own counter, and
    ///   never against what the device asks for its own channels. Past it,
    ///   nothing is sent ([`SharedRefused::AskedEnough`]).
    /// - What comes back is checked with no database held, and then taken
    ///   under the lock, where the channel is asked for again: a page's
    ///   entries through the one door, and the place past them; a push's
    ///   answers with what waits at that relay.
    ///
    /// `counted` is given what the request costs of a byte share: what the
    /// relay handed in a page, as it counts it, before the page is taken;
    /// what the entries pushed are counted at, before they are sent.
    pub async fn shared(
        &self,
        state: &AppState,
        link: &Link,
        channel: &[u8; 32],
        ask: SharedAsk,
        counted: impl FnOnce(u64),
    ) -> Result<SharedDone, SharedRefused> {
        let relay = link.relay().0;
        let identity = &state.identity;
        let own = identity.public_key();
        let store =
            |e: cordelia_api::person::PersonError| SharedRefused::NotAnswered(e.to_string());
        let (usable, request, batch, asked_from) = {
            let conn = lock(&state.db);
            let usable = shared_pass::usable(&conn, channel, &relay)
                .map_err(store)?
                .map_err(SharedRefused::NotUsable)?;
            match ask {
                SharedAsk::Prove => {
                    let proof = link
                        .session()
                        .and_then(|session| usable.proof(&session, &own))
                        .ok_or_else(|| SharedRefused::NotAnswered("no proof".into()))?;
                    let request = WireMessage::ChannelProve(ChannelProve {
                        channel: *channel,
                        proof,
                    });
                    (usable, request, Vec::new(), (NO_MARK, 0))
                }
                SharedAsk::Pull { limit } => {
                    let place = shared_pass::place(&conn, &usable, &relay).map_err(store)?;
                    let request = WireMessage::EntryPull(EntryPull {
                        channel: *channel,
                        mark: place.0,
                        after: place.1,
                        limit: limit.clamp(1, ENTRY_PAGE_MAX_ENTRIES),
                    });
                    (usable, request, Vec::new(), place)
                }
                SharedAsk::Push { most } => {
                    let batch = shared_pass::to_send(&conn, identity, &usable, &relay, most)
                        .map_err(store)?;
                    if batch.is_empty() {
                        return Ok(SharedDone::NothingWaits);
                    }
                    let request = WireMessage::EntryPush(EntryPush {
                        entries: batch.iter().map(|entry| entry.to_wire().into()).collect(),
                    });
                    (usable, request, batch, (NO_MARK, 0))
                }
            }
        };
        let protocol = match &request {
            WireMessage::ChannelProve(_) => Protocol::ChannelProve,
            WireMessage::EntryPull(_) => Protocol::EntryPull,
            _ => Protocol::EntryPush,
        };
        // The shared pass's own counter: what it does not ask is not held
        // back by the device's pace, and is not counted as such.
        if !lock(&self.inner).may_ask_shared(link.name()) {
            return Err(SharedRefused::AskedEnough);
        }
        let cost: u64 = batch
            .iter()
            .map(|entry| entry_cost(entry.content.len()))
            .sum();
        let mut counted = Some(counted);
        if !batch.is_empty()
            && let Some(counted) = counted.take()
        {
            counted(cost);
        }
        let answer = self.asks_shared(link, protocol, &request).await?;
        match (ask, answer) {
            (SharedAsk::Prove, WireMessage::ChannelProved(proved)) => {
                if !proved.proved {
                    let conn = lock(&state.db);
                    shared_pass::not_held_at(&conn, &usable, &relay).map_err(store)?;
                }
                Ok(SharedDone::Proved(proved.proved))
            }
            (SharedAsk::Pull { .. }, WireMessage::EntryPulled(page)) => {
                if page.entries.len() > ENTRY_PAGE_MAX_ENTRIES as usize {
                    return Err(SharedRefused::NotAnswered(
                        "a page holds more than a page may".into(),
                    ));
                }
                // What the relay handed counts against the share, whatever
                // is then done with it.
                let handed: u64 = page
                    .entries
                    .iter()
                    .map(|bytes| entry_cost(bytes.len().saturating_sub(ENTRY_WIRE_OVERHEAD_BYTES)))
                    .sum();
                if let Some(counted) = counted.take() {
                    counted(handed);
                }
                let entries: Option<Vec<CheckedEntry>> = page
                    .entries
                    .iter()
                    .map(|bytes| Entry::from_wire(bytes).ok()?.check().ok())
                    .collect();
                let Some(entries) = entries else {
                    return Err(SharedRefused::NotAnswered(
                        "a page holds an entry that does not check".into(),
                    ));
                };
                let now = self.clock.unix_from(state.sync_control.now());
                let conn = lock(&state.db);
                // Asked again: the channel may have been dropped, or the
                // device may stand elsewhere, while the page was asked for.
                let usable = shared_pass::usable(&conn, channel, &relay)
                    .map_err(store)?
                    .map_err(SharedRefused::NotUsable)?;
                let taken = shared_pass::take_page(
                    &conn,
                    identity,
                    &usable,
                    &relay,
                    asked_from,
                    (&entries, page.mark, page.next),
                    now,
                )
                .map_err(store)?;
                let Some(taken) = taken else {
                    return Err(SharedRefused::NotAnswered(
                        "a page holds an entry of another channel".into(),
                    ));
                };
                Ok(SharedDone::Page {
                    entries: entries.len(),
                    handed,
                    got_somewhere: taken.got_somewhere,
                    end: entries.is_empty(),
                })
            }
            (SharedAsk::Push { .. }, WireMessage::EntryPushed(pushed)) => {
                if pushed.answers.len() != batch.len() {
                    return Err(SharedRefused::NotAnswered(
                        "a push was not answered for each entry".into(),
                    ));
                }
                let answers: Vec<Pushed> = pushed.answers.iter().map(pushed_as).collect();
                let conn = lock(&state.db);
                let refused =
                    shared_pass::pushed(&conn, &usable, &relay, &batch, &answers).map_err(store)?;
                Ok(SharedDone::Pushed {
                    sent: batch.len(),
                    refused,
                    cost,
                })
            }
            _ => Err(SharedRefused::NotAnswered(
                "a request was not answered as one".into(),
            )),
        }
    }

    /// The door of the share pair channel of a key typed for a channel
    /// (decision 2026-10-10 §2.3, §3.2, §8.4): read, on `link`, the share
    /// pair channel of this device and `key`, and give what the device of
    /// that key wrote there to `accept`, which judges a share, and to
    /// nothing else. No show is made and no leave asked.
    ///
    /// It does that and nothing else, as [`Leave::pair`] does for a key
    /// typed to join devices:
    ///
    /// - Under the database's lock, `reads` says whether the key reads now
    ///   (typed for a channel within its hour, and taken with no share): a
    ///   key that does not reads nothing, and the relay is asked nothing.
    ///   So does a device that does not stand applied with sync on.
    /// - The channel is the share pair channel of `key` and this device,
    ///   derived here. No caller names a channel.
    /// - The requests are made here, each counted against the shared pass's
    ///   own counter: a proof of the channel's key, and pulls of its pages
    ///   from the start, each with `limit` and on from the place the last
    ///   reached, until a page holds nothing or leaves the place where it
    ///   was, the key reads nothing more, or RELAY_ENTRY_PULL_PAGES pages
    ///   were read. Nothing is pushed.
    /// - `counted` is given what the relay handed in each page, as it counts
    ///   it, before the page is read, as [`Leave::shared`] gives it: so the
    ///   caller counts it in the device's whole count and in the shared
    ///   pass's quarter, and sizes `limit` to that quarter. The proof's place
    ///   on the connection is the caller's to check and keep, as it is for
    ///   a shared channel (not yet called: slice 6 calls it).
    /// - Of what comes back, each entry of that channel that `key` signed
    ///   is given to `accept`, under the database's lock: none is stored,
    ///   and no place is kept. An entry of another channel, or by another
    ///   key, is dropped.
    pub async fn share_pair<A>(
        &self,
        state: &AppState,
        link: &Link,
        key: &[u8; 32],
        limit: u32,
        mut counted: impl FnMut(u64),
        reads: impl Fn(&Connection, i64) -> bool,
        accept: impl Fn(&Connection, &CheckedEntry, i64) -> Result<Option<A>, String>,
    ) -> Result<SharePairRead<A>, SharedRefused> {
        let (db, identity) = (&state.db, &state.identity);
        let unix = || self.clock.unix_from(state.sync_control.now());
        let still = |conn: &Connection, now: i64| {
            matches!(shared_pass::may_open(conn), Ok(Ok(()))) && reads(conn, now)
        };
        if !still(&lock(db), unix()) {
            return Ok(SharePairRead::NotNow);
        }
        let not = |why: &str| SharedRefused::NotAnswered(why.to_string());
        let (channel, secret) =
            shared_pass::share_pair(identity, key).ok_or_else(|| not("no share pair channel"))?;
        let session = link.session().ok_or_else(|| not("no session"))?;
        let proof =
            proof::make(&secret, &session, &identity.public_key()).map_err(|_| not("no proof"))?;
        let prove = WireMessage::ChannelProve(ChannelProve { channel, proof });
        if !lock(&self.inner).may_ask_shared(link.name()) {
            return Err(SharedRefused::AskedEnough);
        }
        let proved = match self
            .asks_shared(link, Protocol::ChannelProve, &prove)
            .await?
        {
            WireMessage::ChannelProved(proved) => proved.proved,
            _ => return Err(not("a proof was not answered as one")),
        };
        if !proved {
            return Ok(SharePairRead::NotHeld);
        }
        let mut read = Vec::new();
        let mut place = (NO_MARK, 0);
        for _ in 0..RELAY_ENTRY_PULL_PAGES {
            if !lock(&self.inner).may_ask_shared(link.name()) {
                break;
            }
            let pull = WireMessage::EntryPull(EntryPull {
                channel,
                mark: place.0,
                after: place.1,
                limit: limit.clamp(1, ENTRY_PAGE_MAX_ENTRIES),
            });
            let page = match self.asks_shared(link, Protocol::EntryPull, &pull).await {
                Ok(WireMessage::EntryPulled(page)) => page,
                Ok(_) if read.is_empty() => return Err(not("a pull was not answered with a page")),
                Err(refused) if read.is_empty() => return Err(refused),
                _ => break,
            };
            // What the relay handed counts against the share, whatever is
            // then done with it.
            counted(
                page.entries
                    .iter()
                    .map(|bytes| entry_cost(bytes.len().saturating_sub(ENTRY_WIRE_OVERHEAD_BYTES)))
                    .sum(),
            );
            let handed: Vec<CheckedEntry> = page
                .entries
                .iter()
                .take(ENTRY_PAGE_MAX_ENTRIES as usize)
                .filter_map(|bytes| Entry::from_wire(bytes).ok()?.check().ok())
                .filter(|entry| entry.channel == channel && entry.author == *key)
                .collect();
            for entry in &handed {
                let now = unix();
                let conn = lock(db);
                if !still(&conn, now) {
                    return Ok(SharePairRead::Read(read));
                }
                match accept(&conn, entry, now) {
                    Ok(Some(judged)) => read.push(judged),
                    Ok(None) => return Ok(SharePairRead::Read(read)),
                    Err(e) => return Err(not(&format!("could not judge a share: {e}"))),
                }
            }
            let reached = (page.mark, page.next);
            if page.entries.is_empty() || reached == place || !still(&lock(db), unix()) {
                break;
            }
            place = reached;
        }
        Ok(SharePairRead::Read(read))
    }

    /// Push, on `link`, `entry`: a share that this device wrote in its share
    /// pair channel with `key`, and that its store holds (decision
    /// 2026-10-10 §3.1, §8.4). Any other entry is refused, and nothing is
    /// asked. Counted against the shared pass's own counter. Returns what
    /// the relay answered of it.
    pub async fn share_pair_push(
        &self,
        state: &AppState,
        link: &Link,
        key: &[u8; 32],
        entry: &CheckedEntry,
    ) -> Result<Pushed, SharedRefused> {
        let not = |why: &str| SharedRefused::NotAnswered(why.to_string());
        {
            let conn = lock(&state.db);
            if let Ok(Err(not_usable)) = shared_pass::may_open(&conn) {
                return Err(SharedRefused::NotUsable(not_usable));
            }
            let own = shared_pass::is_own_share(&conn, &state.identity, key, entry);
            if !own.map_err(|e| not(&e.to_string()))? {
                return Err(SharedRefused::NotUsable(NotUsable::NotHeld));
            }
        }
        if !lock(&self.inner).may_ask_shared(link.name()) {
            return Err(SharedRefused::AskedEnough);
        }
        let push = WireMessage::EntryPush(EntryPush {
            entries: vec![entry.to_wire().into()],
        });
        match self.asks_shared(link, Protocol::EntryPush, &push).await? {
            WireMessage::EntryPushed(pushed) if pushed.answers.len() == 1 => {
                Ok(pushed_as(&pushed.answers[0]))
            }
            _ => Err(not("a push was not answered for its entry")),
        }
    }

    /// Ask `request` of the relay at `link` on a stream of `protocol`, for
    /// a shared channel or a share pair channel, once its counter has let
    /// it through: a request that the relay refused for now is said so, and
    /// counted for the relay ([`Self::refused`]), as every door counts one.
    async fn asks_shared(
        &self,
        link: &Link,
        protocol: Protocol,
        request: &WireMessage,
    ) -> Result<WireMessage, SharedRefused> {
        let (send, recv) = open_stream(&link.conn)
            .await
            .map_err(SharedRefused::NotAnswered)?;
        let answer = exchange(
            send,
            recv,
            protocol,
            request,
            self.counts_as_sent(link, protocol, request),
        )
        .await;
        answer.map_err(|e| match self.refused(link, &e) {
            Refused::NotNow => SharedRefused::NotNow,
            Refused::NotAnswered(why) => SharedRefused::NotAnswered(why),
            other => SharedRefused::NotAnswered(format!("{other:?}")),
        })
    }

    /// Ask `request` of the relay at `link` on a stream of `protocol`,
    /// for the pair channel of a typed key, or for a channel of a
    /// generation that was left, where the device has not asked as much
    /// of that relay as it asks in a minute. A request that the relay
    /// refused for now is said so, and counted for the relay
    /// ([`Self::refused`]).
    async fn asks(
        &self,
        link: &Link,
        protocol: Protocol,
        request: &WireMessage,
    ) -> Result<WireMessage, Refused> {
        if !self.may_ask_of(link) {
            return Err(Refused::AskedEnough);
        }
        let (send, recv) = open_stream(&link.conn)
            .await
            .map_err(Refused::NotAnswered)?;
        let answer = exchange(
            send,
            recv,
            protocol,
            request,
            self.counts_as_sent(link, protocol, request),
        )
        .await;
        answer.map_err(|e| self.refused(link, &e))
    }

    /// What a request that failed with `e` was refused with: for now,
    /// where the relay reset it with ERR_RATE_LIMIT ([`refused_for_now`]),
    /// which is counted for the relay ([`Self::refused_at`]); otherwise
    /// it was not answered, as it failed.
    fn refused(&self, link: &Link, e: &codec::CodecError) -> Refused {
        match refused_for_now(e) {
            true => {
                self.refused_at(link);
                Refused::NotNow
            }
            false => Refused::NotAnswered(e.to_string()),
        }
    }

    /// Ask `request` of the relay at `link` on a new stream of
    /// `protocol`, and read its answer: every step has the codec's one
    /// timeout. Where the relay refuses it for now, that is counted for
    /// the relay ([`Self::refused_for_now`]). What failed is said as it
    /// was.
    async fn ask_counted(
        &self,
        link: &Link,
        protocol: Protocol,
        request: &WireMessage,
    ) -> Result<WireMessage, String> {
        let (send, recv) = open_stream(&link.conn).await?;
        let sent = self.counts_as_sent(link, protocol, request);
        exchange(send, recv, protocol, request, sent)
            .await
            .map_err(|e| {
                if refused_for_now(&e) {
                    self.refused_at(link);
                }
                e.to_string()
            })
    }

    /// Whether the relay whose node key is `relay` has refused for now as
    /// many requests within BAN_WINDOW_SECS as the device gives one,
    /// BAN_THRESHOLD - 1: a relay cuts off an address at BAN_THRESHOLD
    /// breaches in that window, and refuses a breach with the same reset.
    pub fn at_its_count(&self, relay: &[u8; 32]) -> bool {
        self.refused_for_now(relay) >= (BAN_THRESHOLD - 1) as usize
    }

    /// The relay at `link` refused a request for now: it is counted, with
    /// its time, for the relay's node key, and those it refused before the
    /// window are forgotten.
    fn refused_at(&self, link: &Link) {
        self.refused_by(link.relay().0);
    }

    /// The relay whose node key is `relay` refused a request for now
    /// ([`Self::refused_at`]).
    fn refused_by(&self, relay: [u8; 32]) {
        self.counts.refused_for_now(&relay);
        let now = self.clock.now();
        let mut inner = lock(&self.inner);
        // Those older than the window are forgotten first, so that a relay
        // that refuses pass after pass keeps no more than the window holds.
        refusals_within(&mut inner.refused_for_now, &relay, now);
        let refused = inner.refused_for_now.entry(relay).or_default();
        refused.push_back(now);
    }

    /// How many requests the relay whose node key is `relay` refused for
    /// now within BAN_WINDOW_SECS, on any connection: a show, a proof, a
    /// pull or a push, of a pass, of a read of a channel of the device's
    /// own, through the door for a carry, or for a typed key (decision
    /// 2026-10-17 §4.2). A relay refuses so a breach of its rates, and
    /// cuts off an address at BAN_THRESHOLD breaches within that window.
    /// A refusal counts until the window has gone by since it was given,
    /// as the relay counts it; a relay with none left is forgotten.
    pub fn refused_for_now(&self, relay: &[u8; 32]) -> usize {
        let now = self.clock.now();
        refusals_within(&mut lock(&self.inner).refused_for_now, relay, now)
    }

    /// Whether a request that was built under the change entry named
    /// `under` may use `link` now: there is leave, and the device keeps
    /// that entry still.
    fn may_use(&self, conn: &Connection, link: &Link, under: &[u8; 32]) -> Result<(), Refused> {
        self.has(conn, link).map_err(Refused::NoLeave)?;
        self.keeps(conn, under)
    }

    /// Whether the device still keeps the change entry named `under` as
    /// the latest: the one that a request was built under.
    fn keeps(&self, conn: &Connection, under: &[u8; 32]) -> Result<(), Refused> {
        match at_relays::kept_id(conn) {
            Ok(Some(kept)) if kept == *under => Ok(()),
            _ => Err(Refused::KeptAnother),
        }
    }
}

/// What a relay's answer for one entry of a push means for sending it.
fn pushed_as(answer: &PushAnswer) -> Pushed {
    match answer {
        PushAnswer::Stored | PushAnswer::Held => Pushed::Holds,
        PushAnswer::Older => Pushed::HoldsLater,
        PushAnswer::Another => Pushed::HoldsAnother,
        PushAnswer::Refused(EntryRefused::NotSigned) => Pushed::DoesNotCheck,
        PushAnswer::Refused(EntryRefused::NoRoom) => Pushed::NoRoom,
        PushAnswer::Refused(EntryRefused::OverLimit) => Pushed::OverAllowance,
    }
}

/// Whether an answer to a show gives leave: it says that the relay holds
/// no later change than the entry shown. It holds that entry; it took it;
/// or it holds none or an earlier one, would have taken this one, and did
/// not, for room or for the address's allowance.
fn gives_leave(answer: &ShowAnswer) -> bool {
    matches!(
        answer,
        ShowAnswer::Held
            | ShowAnswer::Taken
            | ShowAnswer::Refused(EntryRefused::NoRoom | EntryRefused::OverLimit)
    )
}

/// Open a new stream on `conn`, within the codec's one timeout. The peer
/// says how many streams a connection may have open at once, so it can
/// hold this back for as long as that timeout.
async fn open_stream(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    match tokio::time::timeout(codec::STREAM_TIMEOUT, conn.open_bi()).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(format!("open_bi failed: {e}")),
        Err(_) => Err("open_bi timed out".into()),
    }
}

/// Ask one thing on a stream that is open, of `protocol`, and read its
/// answer: what `codec::send_request` does, with `sent` called once the
/// request is written, with the bytes of its frame (decision 2026-10-22
/// §1.2). The bytes on the wire are the same.
async fn exchange(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    protocol: Protocol,
    request: &WireMessage,
    sent: impl FnOnce(usize),
) -> Result<WireMessage, codec::CodecError> {
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let answer = async {
        let frame = codec::encode_message(request)?;
        codec::write_protocol_byte(&mut stream, protocol).await?;
        codec::write_raw_frame(&mut stream, &frame).await?;
        sent(FRAME_LENGTH_BYTES + frame.len());
        codec::read_frame(&mut stream, protocol).await
    }
    .await;
    let _ = send.finish();
    answer
}

/// Whether a request failed because the relay reset its stream with
/// ERR_RATE_LIMIT: the answer, or the request, was cut off with that
/// code. A connection that was lost is not that.
fn refused_for_now(e: &codec::CodecError) -> bool {
    let codec::CodecError::Io(io) = e else {
        return false;
    };
    let code = quinn::VarInt::from_u32(ERR_RATE_LIMIT);
    let Some(inner) = io.get_ref() else {
        return false;
    };
    matches!(inner.downcast_ref(), Some(quinn::ReadError::Reset(at)) if *at == code)
        || matches!(inner.downcast_ref(), Some(quinn::WriteError::Stopped(at)) if *at == code)
}

/// How many requests the relay whose node key is `relay` refused for
/// now within BAN_WINDOW_SECS of `now`, of those kept in `refused`: each
/// older is forgotten, and so is a relay that has none left. A refusal
/// counts at the window's very end, as a relay counts a breach.
fn refusals_within(
    refused: &mut HashMap<[u8; 32], VecDeque<Instant>>,
    relay: &[u8; 32],
    now: Instant,
) -> usize {
    let Some(at) = refused.get_mut(relay) else {
        return 0;
    };
    at.retain(|at| now.saturating_duration_since(*at) <= BAN_WINDOW);
    let within = at.len();
    if within == 0 {
        refused.remove(relay);
    }
    within
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a relay refused for now before the window is forgotten as it
    /// refuses again: a relay that refuses request after request, and is
    /// never asked how many, keeps no more than the window holds.
    #[test]
    fn a_relay_that_refuses_again_keeps_no_more_than_the_window_holds() {
        let clock = Clock::system();
        let leave = Leave::new(clock.clone());
        let relay = [1; 32];
        let kept = |leave: &Leave| {
            let inner = lock(&leave.inner);
            inner.refused_for_now.get(&relay).map_or(0, |at| at.len())
        };
        leave.refused_by(relay);
        leave.refused_by(relay);
        assert_eq!(kept(&leave), 2);
        clock.run_ahead(BAN_WINDOW + Duration::from_secs(1));
        leave.refused_by(relay);
        assert_eq!(kept(&leave), 1);
        assert_eq!(leave.refused_for_now(&relay), 1);
    }

    /// A refusal for now counts for its relay within BAN_WINDOW_SECS of
    /// when it was given, and no longer: one 600 seconds old counts, as
    /// a relay counts a breach that old, and one 601 seconds old does not;
    /// a relay with none left is forgotten. Another relay's are its own.
    #[test]
    fn a_refusal_for_now_counts_for_its_relay_within_the_window_and_no_longer() {
        assert_eq!(BAN_WINDOW, Duration::from_secs(600));
        let (one, other) = ([1; 32], [2; 32]);
        let given = Instant::now();
        let secs = Duration::from_secs;
        let mut refused = HashMap::new();
        refused.insert(one, VecDeque::from([given]));
        refused.insert(other, VecDeque::from([given + secs(300)]));
        assert_eq!(refusals_within(&mut refused, &one, given + secs(599)), 1);
        assert_eq!(refusals_within(&mut refused, &one, given + secs(600)), 1);
        assert_eq!(refusals_within(&mut refused, &one, given + secs(601)), 0);
        assert!(!refused.contains_key(&one));
        assert_eq!(refusals_within(&mut refused, &other, given + secs(601)), 1);
        assert_eq!(refusals_within(&mut refused, &[3; 32], given), 0);
    }

    /// A request is refused for now where its answer was reset, or its
    /// request stopped, with ERR_RATE_LIMIT, and by nothing else: not by
    /// another code, not by a connection that was lost, not by an answer
    /// that does not decode.
    #[test]
    fn a_request_is_refused_for_now_only_by_the_rate_limits_code() {
        let code = quinn::VarInt::from_u32(ERR_RATE_LIMIT);
        let other = quinn::VarInt::from_u32(0);
        let io = |e: std::io::Error| codec::CodecError::Io(e);
        assert!(refused_for_now(&io(quinn::ReadError::Reset(code).into())));
        assert!(refused_for_now(
            &io(quinn::WriteError::Stopped(code).into())
        ));
        assert!(!refused_for_now(&io(quinn::ReadError::Reset(other).into())));
        assert!(!refused_for_now(&io(
            quinn::WriteError::Stopped(other).into()
        )));
        let lost = quinn::ConnectionError::LocallyClosed;
        assert!(!refused_for_now(&io(quinn::ReadError::ConnectionLost(
            lost.clone()
        )
        .into())));
        assert!(!refused_for_now(&io(quinn::WriteError::ConnectionLost(
            lost
        )
        .into())));
        let bare = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        assert!(!refused_for_now(&io(bare)));
        assert!(!refused_for_now(&codec::CodecError::CborDecode(
            "no".into()
        )));
    }

    /// The clock is the system's, and as far ahead of it as it was run:
    /// both the time that waits are measured by and the time of day.
    #[test]
    fn a_clock_runs_ahead_by_what_a_test_sets() {
        let clock = Clock::system();
        let (began, began_unix) = (Instant::now(), chrono::Utc::now().timestamp());
        assert!(clock.now() >= began);
        assert!(clock.now() < began + Duration::from_secs(5));
        clock.run_ahead(Duration::from_secs(30));
        assert!(clock.now() >= began + Duration::from_secs(30));
        assert!(clock.now() < began + Duration::from_secs(35));
        assert!((began_unix + 30..began_unix + 35).contains(&clock.unix()));
        // It is one clock for whoever holds a copy of it.
        let copy = clock.clone();
        copy.run_ahead(Duration::from_secs(7200));
        assert!(clock.now() >= began + Duration::from_secs(7230));
        assert!((began_unix + 7230..began_unix + 7235).contains(&clock.unix()));
    }

    /// A machine slept where the time of day ran ahead of the clock that
    /// cannot go back by more than a leave lasts: to the millisecond. A
    /// time of day that was set back says nothing.
    #[test]
    fn a_machine_slept_where_the_time_of_day_ran_ahead_by_more_than_a_leave() {
        assert_eq!(LEAVE, Duration::from_secs(10));
        let began = Instant::now();
        let at = |ran_ms: u64, by_the_day_ms: i64| {
            let before = (began, 1_800_000_000_000i64);
            let now = (
                began + Duration::from_millis(ran_ms),
                1_800_000_000_000i64 + by_the_day_ms,
            );
            slept_between(before, now)
        };
        // Both clocks ran alike: two seconds, ten, an hour.
        for ran in [0, 2_000, 10_000, 3_600_000] {
            assert!(!at(ran, ran as i64), "{ran}");
        }
        // The time of day ran ahead by a leave, and by a millisecond
        // more.
        assert!(!at(2_000, 12_000));
        assert!(at(2_000, 12_001));
        assert!(at(0, 8 * 3_600_000));
        // It was set back, or stood still.
        assert!(!at(2_000, -3_600_000));
        assert!(!at(60_000, 0));
        assert!(!at(0, i64::MIN));
        assert!(at(0, i64::MAX - 1_800_000_000_000));
    }

    /// The test clock sleeps: the time of day runs ahead, and the clock
    /// that waits are measured by does not.
    #[test]
    fn a_clock_that_slept_ran_ahead_by_the_day_alone() {
        let clock = Clock::system();
        let (began, began_ms) = (clock.now(), clock.wall_ms());
        clock.slept(Duration::from_secs(3600));
        assert!(clock.now() < began + Duration::from_secs(5));
        let after = clock.wall_ms() - began_ms;
        assert!((3_600_000..3_605_000).contains(&after), "{after}");
        assert!(slept_between(
            (began, began_ms),
            (clock.now(), clock.wall_ms())
        ));
        // Run ahead, both go on together.
        let (began, began_ms) = (clock.now(), clock.wall_ms());
        clock.run_ahead(Duration::from_secs(3600));
        assert!(clock.now() >= began + Duration::from_secs(3600));
        assert!(!slept_between(
            (began, began_ms),
            (clock.now(), clock.wall_ms())
        ));
    }

    /// Each answer to a show that says the relay holds no later change
    /// gives leave, and no other does.
    #[test]
    fn only_an_answer_that_says_no_later_change_is_held_gives_leave() {
        for answer in [
            ShowAnswer::Held,
            ShowAnswer::Taken,
            ShowAnswer::Refused(EntryRefused::NoRoom),
            ShowAnswer::Refused(EntryRefused::OverLimit),
        ] {
            assert!(gives_leave(&answer), "{answer:?}");
        }
        for answer in [
            ShowAnswer::Another(vec![1, 2, 3]),
            ShowAnswer::Other {
                rev: 7,
                id: [9; 32],
            },
            ShowAnswer::Whole,
            ShowAnswer::Refused(EntryRefused::NotSigned),
        ] {
            assert!(!gives_leave(&answer), "{answer:?}");
        }
    }

    /// A device asks so much of one relay in a minute, on the streams of
    /// a channel, and no more. What it asks of another relay is counted
    /// apart.
    #[test]
    fn a_device_asks_only_so_much_of_one_relay_in_a_minute() {
        assert_eq!(OWN_ENTRY_REQUESTS_PER_MINUTE, 2_250);
        let mut inner = Inner::default();
        for n in 0..OWN_ENTRY_REQUESTS_PER_MINUTE {
            assert!(inner.may_ask("one"), "{n}");
        }
        assert!(!inner.may_ask("one"));
        assert!(!inner.may_ask("one"));
        assert!(inner.may_ask("other"));
    }

    /// The shared pass's requests are counted against a counter of their
    /// own, at SHARED_REQUESTS_PER_MINUTE for each relay, and never against
    /// what the device asks for its own channels; nor do the device's own
    /// count against the shared pass's (decision 2026-10-10 §8.4).
    #[test]
    fn a_shared_request_is_counted_apart_from_the_devices_own() {
        assert_eq!(SHARED_REQUESTS_PER_MINUTE, 600);
        let mut inner = Inner::default();
        for n in 0..SHARED_REQUESTS_PER_MINUTE {
            assert!(inner.may_ask_shared("one"), "{n}");
        }
        assert!(!inner.may_ask_shared("one"));
        assert!(inner.may_ask_shared("other"));
        for n in 0..OWN_ENTRY_REQUESTS_PER_MINUTE {
            assert!(inner.may_ask("one"), "{n}");
        }
        assert!(!inner.may_ask("one"));
        let mut inner = Inner::default();
        for _ in 0..OWN_ENTRY_REQUESTS_PER_MINUTE {
            inner.may_ask("one");
        }
        assert!(inner.may_ask_shared("one"));
    }

    /// A node that reaches no relay is waking. Once it reaches one, it is
    /// waking until every relay it is set up with has answered, or the
    /// wait has gone by: whichever comes first.
    #[test]
    fn a_node_wakes_until_each_relay_has_answered_or_the_wait_has_gone_by() {
        assert_eq!(WAKE_WAIT, Duration::from_secs(30));
        let now = Instant::now();
        let both = vec!["one".to_string(), "two".to_string()];
        let mut inner = Inner {
            set_up_with: both.clone(),
            ..Inner::default()
        };
        // It reaches none.
        assert!(inner.is_waking(now));
        assert!(inner.is_waking(now + Duration::from_secs(3600)));

        let woke = |heard: &[&str]| Woke {
            at: now,
            wall: 0,
            heard: heard.iter().map(|name| name.to_string()).collect(),
            awake: false,
        };
        // One of two has answered: waking, up to the wait.
        inner.woke = Some(woke(&["one"]));
        assert!(inner.is_waking(now));
        assert!(inner.is_waking(now + Duration::from_millis(29_999)));
        assert!(!inner.is_waking(now + Duration::from_secs(30)));
        // And awake from then, whatever the time says later.
        assert!(!inner.is_waking(now));

        // Both have answered: awake at once.
        inner.woke = Some(woke(&["one", "two"]));
        assert!(!inner.is_waking(now));
        // A relay that it is not set up with does not stand for one that
        // it is.
        inner.woke = Some(woke(&["one", "three"]));
        assert!(inner.is_waking(now));
        // Set up with none, there is nobody to wait for.
        inner.set_up_with.clear();
        inner.woke = Some(woke(&[]));
        assert!(!inner.is_waking(now));
    }
    /// A request held back by the device's own pace is counted for its
    /// relay, and a request that may be asked is not (decision 2026-10-22
    /// §1.2): a relay asked as much as a device asks in a minute holds
    /// back the next, and another relay's are its own.
    #[test]
    fn a_request_held_back_by_the_devices_own_pace_is_counted_for_its_relay() {
        let counts = Arc::new(DeviceCounts::default());
        let leave = Leave::new(Clock::system()).counting(counts.clone());
        let (one, other) = (NodeId([1; 32]), NodeId([2; 32]));
        for n in 0..OWN_ENTRY_REQUESTS_PER_MINUTE {
            assert!(leave.may_ask_of_relay("one", &one), "{n}");
        }
        assert_eq!(counts.of(&one.0).held_back, 0);
        assert!(!leave.may_ask_of_relay("one", &one));
        assert!(!leave.may_ask_of_relay("one", &one));
        assert!(leave.may_ask_of_relay("other", &other));
        assert_eq!(counts.of(&one.0).held_back, 2);
        assert_eq!(counts.of(&other.0).held_back, 0);
        assert_eq!(
            counts.of(&one.0).asked,
            [0; 6],
            "nothing held back is asked"
        );
    }

    /// A request that a relay refused for now, for rate or not now, is
    /// counted for that relay (decision 2026-10-22 §1.2), and for no
    /// other.
    #[test]
    fn a_request_refused_for_now_is_counted_for_its_relay() {
        let counts = Arc::new(DeviceCounts::default());
        let leave = Leave::new(Clock::system()).counting(counts.clone());
        leave.refused_by([1; 32]);
        leave.refused_by([1; 32]);
        leave.refused_by([2; 32]);
        assert_eq!(counts.of(&[1; 32]).refused_for_now, 2);
        assert_eq!(counts.of(&[2; 32]).refused_for_now, 1);
        assert_eq!(counts.of(&[1; 32]).held_back, 0);
    }
}
