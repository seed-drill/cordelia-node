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
//! device's own. The two requests are made here: a proof of that
//! channel's key, and a pull of its first page. Nothing is pushed, and no
//! place is kept. What comes back is given to
//! [`cordelia_api::adding::accept_typed`], which judges a hand-over by
//! the state the device is in, and to nothing else.
//!
//! A connection is a [`Link`], which keeps the connection to itself:
//! outside this file there is no way to open a stream on one but
//! [`Leave::show`], [`Leave::open`] and [`Leave::pair`].

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cordelia_api::adding::{self, Accepted};
use cordelia_api::at_relays::{self, Stands};
use cordelia_api::state::AppState;
use cordelia_core::NodeId;
use cordelia_core::protocol::{
    ENTRY_PAGE_MAX_ENTRIES, OWN_ENTRY_REQUESTS_PER_MINUTE, SESSION_VALUE_BYTES, SHOW_LEAVE_SECS,
    WAKE_WAIT_SECS,
};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::{derive, proof};
use cordelia_network::messages::{
    ChannelProve, EntryPull, EntryRefused, EntryShow, EntryShowShort, Protocol, ShowAnswer,
    WireMessage,
};
use cordelia_network::rate_limit::RateCounter;
use cordelia_network::{codec, transport};
use cordelia_storage::acts::TypedKey;
use cordelia_storage::person::State;
use cordelia_storage::relay::NO_MARK;
use rusqlite::Connection;

/// How long a leave lasts.
const LEAVE: Duration = Duration::from_secs(SHOW_LEAVE_SECS);

/// How long a device that wakes waits for its relays.
const WAKE_WAIT: Duration = Duration::from_secs(WAKE_WAIT_SECS);

/// Lock a mutex, also one whose holder panicked: what it guards is times
/// and names, which are whole after any one step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
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
        let ahead = self
            .ahead_ms
            .load(Ordering::Relaxed)
            .saturating_add(self.slept_ms.load(Ordering::Relaxed));
        chrono::Utc::now()
            .timestamp_millis()
            .saturating_add(i64::try_from(ahead).unwrap_or(i64::MAX))
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
}

impl Leave {
    /// For a node that has reached no relay yet, and reads the time from
    /// `clock`.
    pub fn new(clock: Clock) -> Self {
        Self {
            clock,
            inner: Mutex::default(),
        }
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
    /// It is called at each pass, and the two clocks are read here.
    pub fn reaches(&self, set_up_with: &[String], reached: &[&Link]) {
        let now = self.clock.now();
        let read = (now, self.clock.wall_ms());
        let mut inner = lock(&self.inner);
        inner.set_up_with = set_up_with.to_vec();
        let open: HashSet<LinkId> = reached.iter().map(|link| link.id()).collect();
        inner.given.retain(|link, _| open.contains(link));
        // What was asked of a relay is kept across a reconnect, for as
        // long as the device is set up with the relay.
        inner.asked.retain(|relay, _| set_up_with.contains(relay));
        // The lid was closed, and is open: the connections still look
        // open, and a leave still looks young, by a clock that stood
        // still. Every relay is asked first, as when the node starts.
        if inner.last.is_some_and(|before| slept_between(before, read)) {
            inner.given.clear();
            inner.woke = None;
        }
        inner.last = Some(read);
        if reached.is_empty() {
            inner.woke = None;
        } else if inner.woke.is_none() {
            inner.woke = Some(Woke {
                at: now,
                heard: HashSet::new(),
                awake: false,
            });
        }
    }

    /// Whether the node is still waking.
    pub fn is_waking(&self) -> bool {
        lock(&self.inner).is_waking(self.clock.now())
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
        let answer = match ask(&link.conn, Protocol::EntryShow, &request).await? {
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
        db: &Mutex<Connection>,
        link: &Link,
        asked: Asked<'_>,
        opened: impl FnOnce(&Connection),
        read: impl FnOnce(WireMessage) -> R,
        take: impl FnOnce(&Connection, R) -> T,
    ) -> Result<T, Refused> {
        let Asked { under, request } = asked;
        let protocol = match request {
            WireMessage::ChannelProve(_) => Protocol::ChannelProve,
            WireMessage::EntryPull(_) => Protocol::EntryPull,
            WireMessage::EntryPush(_) => Protocol::EntryPush,
            _ => return Err(Refused::NotARequest),
        };
        {
            let conn = lock(db);
            self.may_use(&conn, link, under)?;
            if !lock(&self.inner).may_ask(link.name()) {
                return Err(Refused::AskedEnough);
            }
            opened(&conn);
        }
        let answer = ask(&link.conn, protocol, request)
            .await
            .map_err(Refused::NotAnswered)?;
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
    /// - Two requests are made, each built here: a proof of the
    ///   channel's key, and a pull of its first page, from the start.
    ///   Each counts against what the device asks of a relay in a
    ///   minute. Nothing is pushed.
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
    /// ([`AppState::as_a_change`], decision 2026-10-04 §4.2): it waits
    /// for a sync cycle that is running to stop, and counts as a change
    /// of settings.
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
        if !reads(&lock(db), self.clock.unix()) {
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
        let pull = WireMessage::EntryPull(EntryPull {
            channel,
            mark: NO_MARK,
            after: 0,
            limit: ENTRY_PAGE_MAX_ENTRIES,
        });
        let page = match self.asks(link, Protocol::EntryPull, &pull).await? {
            WireMessage::EntryPulled(page) => page,
            _ => return Err(not("a pull was not answered with a page")),
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
        let mut read = Vec::new();
        for entry in &handed {
            let now = self.clock.unix();
            let accepted = state.as_a_change(|conn| {
                adding::accept_typed(conn, identity, typed, sync_on(conn), entry, now)
            });
            match accepted {
                Ok(Some(accepted)) => read.push(accepted),
                // The key reads nothing more: it was spent, or typed
                // again, or its hour went by.
                Ok(None) => break,
                Err(e) => return Err(not(&format!("could not judge a hand-over: {e}"))),
            }
        }
        Ok(PairRead::Read(read))
    }

    /// Ask `request` of the relay at `link` on a stream of `protocol`,
    /// for the pair channel of a typed key, where the device has not
    /// asked as much of that relay as it asks in a minute.
    async fn asks(
        &self,
        link: &Link,
        protocol: Protocol,
        request: &WireMessage,
    ) -> Result<WireMessage, Refused> {
        if !lock(&self.inner).may_ask(link.name()) {
            return Err(Refused::AskedEnough);
        }
        ask(&link.conn, protocol, request)
            .await
            .map_err(Refused::NotAnswered)
    }

    /// Whether a request that was built under the change entry named
    /// `under` may use `link` now: there is leave, and the device keeps
    /// that entry still.
    fn may_use(&self, conn: &Connection, link: &Link, under: &[u8; 32]) -> Result<(), Refused> {
        self.has(conn, link).map_err(Refused::NoLeave)?;
        match at_relays::kept_id(conn) {
            Ok(Some(kept)) if kept == *under => Ok(()),
            _ => Err(Refused::KeptAnother),
        }
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

/// Ask `conn` one thing on a new stream of `protocol`, and read its
/// answer. Every step has the codec's one timeout.
async fn ask(
    conn: &quinn::Connection,
    protocol: Protocol,
    request: &WireMessage,
) -> Result<WireMessage, String> {
    let (mut send, mut recv) =
        match tokio::time::timeout(codec::STREAM_TIMEOUT, conn.open_bi()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(format!("open_bi failed: {e}")),
            Err(_) => return Err("open_bi timed out".into()),
        };
    let mut stream = tokio::io::join(&mut recv, &mut send);
    let answer = codec::send_request(&mut stream, protocol, request)
        .await
        .map_err(|e| e.to_string());
    let _ = send.finish();
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
