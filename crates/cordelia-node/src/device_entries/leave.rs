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
//!   has no leave anywhere until it has.
//!
//! With leave, a device still asks only so much of a relay in a minute
//! (OWN_ENTRY_REQUESTS_PER_MINUTE on one connection): a relay counts the
//! requests on these streams, and one over its count is a breach.
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
//! A connection is a [`Link`], which keeps the connection to itself:
//! outside this file there is no way to open a stream on one but
//! [`Leave::show`] and [`Leave::open`].

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cordelia_api::at_relays::{self, Stands};
use cordelia_core::NodeId;
use cordelia_core::protocol::{
    OWN_ENTRY_REQUESTS_PER_MINUTE, SESSION_VALUE_BYTES, SHOW_LEAVE_SECS, WAKE_WAIT_SECS,
};
use cordelia_crypto::entry::CheckedEntry;
use cordelia_network::messages::{
    EntryRefused, EntryShow, EntryShowShort, Protocol, ShowAnswer, WireMessage,
};
use cordelia_network::rate_limit::RateCounter;
use cordelia_network::{codec, transport};
use cordelia_storage::person::State;
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
        let ahead = self.ahead_ms.load(Ordering::Relaxed) / 1000;
        chrono::Utc::now()
            .timestamp()
            .saturating_add(i64::try_from(ahead).unwrap_or(i64::MAX))
    }

    /// Run the clock ahead by `by`, from where it is. For tests.
    pub fn run_ahead(&self, by: Duration) {
        let by = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.ahead_ms.fetch_add(by, Ordering::Relaxed);
    }
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
    /// The connections on which the device was answered with a change
    /// that it could not apply.
    not_applied: HashSet<LinkId>,
    /// What was asked on each connection in the last minute, on the
    /// streams of a channel.
    asked: HashMap<LinkId, RateCounter>,
}

impl Inner {
    /// Whether one thing more may be asked on the connection `link` in
    /// this minute, on a stream of a channel. Where it may, it is
    /// counted.
    fn may_ask(&mut self, link: LinkId) -> bool {
        self.asked
            .entry(link)
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
    /// answered a show, or the wait has gone by. What is kept of a
    /// connection that is gone is forgotten.
    pub fn reaches(&self, set_up_with: &[String], reached: &[&Link]) {
        let now = self.clock.now();
        let mut inner = lock(&self.inner);
        inner.set_up_with = set_up_with.to_vec();
        let open: HashSet<LinkId> = reached.iter().map(|link| link.id()).collect();
        inner.given.retain(|link, _| open.contains(link));
        inner.not_applied.retain(|link| open.contains(link));
        inner.asked.retain(|link, _| open.contains(link));
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

    /// The device was answered on `link` with a change that it could not
    /// apply (`false`), or has dealt with what it was answered with there
    /// (`true`). Until it has, there is no leave anywhere: it sends
    /// nothing and takes nothing in a channel of its own (decision
    /// 2026-10-04 §4.2).
    pub fn dealt_with(&self, link: &Link, done: bool) {
        let mut inner = lock(&self.inner);
        if done {
            inner.not_applied.remove(&link.id());
        } else {
            inner.not_applied.insert(link.id());
        }
    }

    /// Whether the device was answered with a change that it has not
    /// applied.
    pub fn is_not_applied(&self) -> bool {
        !lock(&self.inner).not_applied.is_empty()
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
        if !inner.not_applied.is_empty() {
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
    /// `request` on it, and hand what came back to `read` and then to
    /// `take`: a proof of a channel's key, a pull of a page, or a push of
    /// entries, each on the stream of its own.
    ///
    /// It is refused where there is no leave ([`Leave::has`]), and where
    /// the device has asked as much on this connection as it asks of a
    /// relay in a minute. `read` is
    /// given the answer with no database: it checks what came back.
    /// Leave is then asked again, and `take` is called with what `read`
    /// made, under the lock of the database that the leave was asked
    /// under: so nothing that came back is taken without leave, and what
    /// arrives after the leave has run out is dropped.
    pub async fn open<R, T>(
        &self,
        db: &Mutex<Connection>,
        link: &Link,
        request: &WireMessage,
        read: impl FnOnce(WireMessage) -> R,
        take: impl FnOnce(&Connection, R) -> T,
    ) -> Result<T, Refused> {
        let protocol = match request {
            WireMessage::ChannelProve(_) => Protocol::ChannelProve,
            WireMessage::EntryPull(_) => Protocol::EntryPull,
            WireMessage::EntryPush(_) => Protocol::EntryPush,
            _ => return Err(Refused::NotARequest),
        };
        self.has(&lock(db), link).map_err(Refused::NoLeave)?;
        if !lock(&self.inner).may_ask(link.id()) {
            return Err(Refused::AskedEnough);
        }
        let answer = ask(&link.conn, protocol, request)
            .await
            .map_err(Refused::NotAnswered)?;
        let answer = read(answer);
        let conn = lock(db);
        self.has(&conn, link).map_err(Refused::NoLeave)?;
        Ok(take(&conn, answer))
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

    /// A device asks so much on one connection in a minute, on the
    /// streams of a channel, and no more. What it asks on another
    /// connection is counted apart.
    #[test]
    fn a_device_asks_only_so_much_on_one_connection_in_a_minute() {
        assert_eq!(OWN_ENTRY_REQUESTS_PER_MINUTE, 2_250);
        let mut inner = Inner::default();
        let (one, other) = ([1u8; SESSION_VALUE_BYTES], [2u8; SESSION_VALUE_BYTES]);
        for n in 0..OWN_ENTRY_REQUESTS_PER_MINUTE {
            assert!(inner.may_ask(one), "{n}");
        }
        assert!(!inner.may_ask(one));
        assert!(!inner.may_ask(one));
        assert!(inner.may_ask(other));
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
