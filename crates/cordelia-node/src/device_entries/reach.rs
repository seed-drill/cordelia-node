//! Whether a device can reach each relay it is set up with, and each
//! relay's class (decision 2026-10-19 §1, rule 2).
//!
//! What a relay is known to hold is kept in the database
//! ([`cordelia_api::at_relays::known`]). This is what is kept in memory,
//! by the relay's name and key together, and goes with a restart:
//!
//! - **whether it is reached:** a connection to it is open, and the latest
//!   show of the kept entry on that connection got an answer that says
//!   whether it holds it;
//! - **its reference:** the latest of the node's start, a sleep that the
//!   device woke from, the moment the kept entry last changed, and the
//!   moment the relay was last reached. A wake for any other reason does
//!   not move it: a pass that finds no connection open moves nothing here;
//! - **the attempts at it**, each begun and then ended: a dial (a lookup
//!   that resolves is part of it, and no attempt by itself), a lookup of
//!   its name that does not resolve, a show of the kept entry on an open
//!   connection; and each tick of the dial loop that passes it over
//!   because another relay answers at its address, an attempt begun and
//!   failed at once. A dial that connects is not ended until a show on
//!   that connection says something, or the connection closes first;
//! - **whether it is out of reach, and since when.** It becomes so at the
//!   first moment that it has not been reached since its reference, which
//!   is OUT_OF_REACH_SECS or more before now; at least one attempt at it
//!   was begun after the reference and within OUT_OF_REACH_SECS before
//!   now; and every attempt begun after the reference has failed, with
//!   none in flight. It stays out of reach until it is reached, or its
//!   reference moves: a state with a start and an end, not a window that
//!   slides;
//! - **since when it has lacked the change**, every show answered on it
//!   since saying that it does not hold it; and since when it has refused,
//!   for room or for the address's allowance, what waits there.
//!
//! The moments are on the node's own clock, which does not run while the
//! machine sleeps; each is kept with the time of day it was noted at, for
//! what a person reads.
//!
//! [`class`] puts a relay in one of the five classes of the wait after a
//! change, from what is kept here and in the database, or in none while
//! time can still move it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cordelia_api::at_relays::known::RelayId;
use cordelia_api::state::{Class, Holds, Reach as Reached, Waits};
use cordelia_core::protocol::OUT_OF_REACH_SECS;

use super::leave::{Clock, LinkId};

/// How long a relay fails before it is out of reach; how long it refuses
/// the change, or what waits, before that is a class.
const OUT_OF_REACH: Duration = Duration::from_secs(OUT_OF_REACH_SECS);

/// Lock a mutex, also one whose holder panicked: what it guards is times
/// and counts, which are whole after any one step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// A moment, on the node's own clock and by the time of day it was noted
/// at, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Moment {
    at: Instant,
    wall: i64,
}

impl Moment {
    /// The moment `at`, which is not after `now`, by the time of day.
    fn back_from(now: Moment, at: Instant) -> Moment {
        let ago = now.at.saturating_duration_since(at).as_secs();
        Moment {
            at,
            wall: now
                .wall
                .saturating_sub(i64::try_from(ago).unwrap_or(i64::MAX)),
        }
    }
}

/// What a show of the kept entry said, at the end of its round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    /// That the relay holds the entry shown.
    Holds,
    /// That it does not: no room, over the allowance, or another entry.
    Lacks,
    /// Neither: "not signed", "show it whole" to a whole show, a reply
    /// that is no answer to a show, a reset, a time-out, and a round of
    /// shows that ran out. A failed attempt.
    Neither,
}

/// What is kept of one relay.
#[derive(Debug, Clone)]
struct Of {
    /// Whether it holds the kept entry, as the database last said. `None`
    /// before the first pass says.
    holds: Option<Holds>,
    /// The connection on which it is reached, where it is.
    reached: Option<LinkId>,
    last_reached: Option<Moment>,
    /// The attempts in flight: dials, shows, and a dial that connected
    /// and waits for a show on its connection to say something.
    dials: u32,
    shows: u32,
    awaiting: bool,
    /// When the latest attempt began that began after the reference.
    last_begun: Option<Instant>,
    /// When this relay's state was last looked at.
    looked: Instant,
    out_since: Option<Moment>,
    /// Since when it has lacked the change, with every show answered on
    /// it since saying so.
    lacking_since: Option<Moment>,
    /// Whether something of the device's own waits to be sent there, as
    /// the pass last found; and since when the relay has refused it at
    /// each offer.
    waits: Option<bool>,
    refusing_waits_since: Option<Instant>,
    /// When it gave its latest answer about the kept entry.
    answered_at: Option<i64>,
}

impl Of {
    fn new(now: Moment) -> Self {
        Self {
            holds: None,
            reached: None,
            last_reached: None,
            dials: 0,
            shows: 0,
            awaiting: false,
            last_begun: None,
            looked: now.at,
            out_since: None,
            lacking_since: None,
            waits: None,
            refusing_waits_since: None,
            answered_at: None,
        }
    }

    /// Its reference: the latest of `common` (the start, a sleep, the
    /// change of the kept entry) and the moment it was last reached.
    fn reference(&self, common: Moment) -> Moment {
        match self.last_reached {
            Some(reached) if reached.at > common.at => reached,
            _ => common,
        }
    }

    /// The reference moved to `now`: the five minutes start again.
    fn starts_again(&mut self, now: Moment) {
        self.last_begun = None;
        self.out_since = None;
        self.looked = now.at;
    }

    /// Whether an attempt is in flight.
    fn in_flight(&self) -> bool {
        self.dials > 0 || self.shows > 0 || self.awaiting
    }

    /// Bring the state up to `now`: where it was out of reach at any
    /// moment since it was last looked at, it is from the first such
    /// moment. Between two events only time moves, and with it two
    /// bounds: the reference's five minutes are over from one moment on,
    /// and the latest attempt is within the last five minutes until
    /// another.
    fn settle(&mut self, common: Moment, now: Moment) {
        let since = self.looked;
        self.looked = now.at.max(since);
        if self.out_since.is_some() || self.reached.is_some() || self.in_flight() {
            return;
        }
        let Some(begun) = self.last_begun else {
            return;
        };
        let from = since.max(self.reference(common).at + OUT_OF_REACH);
        let until = now.at.min(begun + OUT_OF_REACH);
        if from <= until {
            self.out_since = Some(Moment::back_from(now, from));
        }
    }

    /// It answered that it holds the kept entry, or that it does not.
    fn holds_now(&mut self, holds: Holds, now: Moment) -> bool {
        let was_lacking = self.holds == Some(Holds::Lacks);
        self.holds = Some(holds);
        match holds {
            Holds::Lacks => {
                self.lacking_since.get_or_insert(now);
                !was_lacking
            }
            Holds::Holds | Holds::Neither => {
                self.lacking_since = None;
                false
            }
        }
    }
}

#[derive(Debug)]
struct Inner {
    /// The latest of the node's start, a sleep, and the moment the kept
    /// entry last changed.
    common: Moment,
    /// The kept entry, as the pass last found it: `None` before it has.
    kept: Option<Option<[u8; 32]>>,
    /// Whether the device has a change entry to show: it follows a phrase
    /// and has not stopped, or is in a fork.
    shows: bool,
    relays: HashMap<RelayId, Of>,
    /// The relays that came to lack the change since the dial loop last
    /// asked.
    came_to_lack: HashSet<RelayId>,
}

impl Inner {
    fn of(&mut self, relay: &RelayId, now: Moment) -> &mut Of {
        let common = self.common;
        let of = self
            .relays
            .entry(relay.clone())
            .or_insert_with(|| Of::new(now));
        of.settle(common, now);
        of
    }
}

/// What a device knows, in memory, of whether it can reach each relay
/// (see the module's documentation). One is shared by the passes, the dial
/// loop and the lookups of names.
#[derive(Debug)]
pub struct Reach {
    clock: Clock,
    inner: Mutex<Inner>,
    /// Woken where a relay comes to lack the change: the lookups of names
    /// are made at once.
    lookups: tokio::sync::Notify,
}

impl Reach {
    /// For a node that starts now, reading the time from `clock`.
    pub fn new(clock: Clock) -> Arc<Self> {
        let now = Moment {
            at: clock.now(),
            wall: clock.unix(),
        };
        Arc::new(Self {
            clock,
            inner: Mutex::new(Inner {
                common: now,
                kept: None,
                shows: false,
                relays: HashMap::new(),
                came_to_lack: HashSet::new(),
            }),
            lookups: tokio::sync::Notify::new(),
        })
    }

    fn now(&self) -> Moment {
        Moment {
            at: self.clock.now(),
            wall: self.clock.unix(),
        }
    }

    /// Do `work` with what is kept of `relay`, brought up to now.
    fn with<T>(&self, relay: &RelayId, work: impl FnOnce(&mut Of, Moment, Moment) -> T) -> T {
        let now = self.now();
        let mut inner = lock(&self.inner);
        let common = inner.common;
        let of = inner.of(relay, now);
        let done = work(of, common, now);
        of.settle(common, now);
        done
    }

    // ── What the pass says ──────────────────────────────────────────

    /// What a pass found: `kept`, the change entry that the device keeps;
    /// `shows`, whether it has one to show; and for each relay that it is
    /// set up with, whether that relay holds the kept entry and when it
    /// gave its latest answer about it. A relay it is set up with no
    /// longer is forgotten.
    ///
    /// **A new kept entry moves every relay's reference**, and each
    /// relay that lacks it has lacked it since now. Each relay that comes
    /// to lack the change is told the dial loop, and the lookups of names
    /// are woken (rule 3).
    pub fn observe(
        &self,
        kept: Option<[u8; 32]>,
        shows: bool,
        each: &[(RelayId, Holds, Option<i64>)],
    ) {
        let now = self.now();
        let mut inner = lock(&self.inner);
        if inner.kept.is_some_and(|was| was != kept) {
            inner.common = now;
            for of in inner.relays.values_mut() {
                of.starts_again(now);
                of.lacking_since = None;
                of.holds = None;
            }
        }
        inner.kept = Some(kept);
        inner.shows = shows;
        inner
            .relays
            .retain(|relay, _| each.iter().any(|(set_up, ..)| set_up == relay));
        let mut woke = false;
        for (relay, holds, answered_at) in each {
            let common = inner.common;
            let of = inner.of(relay, now);
            // A relay not seen since the start, or since the kept entry
            // changed, has lacked the change since then: the node knows
            // nothing from before.
            let since = if of.holds.is_none() { common } else { now };
            let was_lacking = of.holds == Some(Holds::Lacks);
            of.holds = Some(*holds);
            of.answered_at = *answered_at;
            match holds {
                Holds::Lacks => {
                    of.lacking_since.get_or_insert(since);
                }
                Holds::Holds | Holds::Neither => of.lacking_since = None,
            }
            if *holds == Holds::Lacks && !was_lacking && shows {
                inner.came_to_lack.insert(relay.clone());
                woke = true;
            }
        }
        drop(inner);
        if woke {
            self.lookups.notify_one();
        }
    }

    /// The machine slept, and the device woke from it: every relay's
    /// reference moves to now.
    pub fn slept(&self) {
        let now = self.now();
        let mut inner = lock(&self.inner);
        inner.common = now;
        for of in inner.relays.values_mut() {
            of.starts_again(now);
        }
    }

    /// A show of the kept entry is made to `relay`: an attempt begins.
    pub fn show_begins(&self, relay: &RelayId) {
        self.with(relay, |of, _, now| {
            of.shows = of.shows.saturating_add(1);
            of.last_begun = Some(now.at);
        });
    }

    /// The round of shows to `relay` on the connection `link` ended with
    /// what it `said`; `holds` is what the kept entry is known of it by
    /// then, where it said something. An answer that says something
    /// makes the relay reached on that connection; one that says neither
    /// is a failed attempt, and the relay is reached there no more.
    pub fn show_ends(&self, relay: &RelayId, link: LinkId, said: Said, holds: Holds) {
        let woke = self.with(relay, |of, _, now| {
            of.shows = of.shows.saturating_sub(1);
            of.awaiting = false;
            match said {
                Said::Holds | Said::Lacks => {
                    of.reached = Some(link);
                    of.last_reached = Some(now);
                    of.starts_again(now);
                    of.answered_at = Some(now.wall);
                    of.holds_now(holds, now)
                }
                Said::Neither => {
                    if of.reached == Some(link) {
                        of.reached = None;
                        of.last_reached = Some(now);
                        of.starts_again(now);
                    }
                    false
                }
            }
        });
        if woke {
            let mut inner = lock(&self.inner);
            if inner.shows {
                inner.came_to_lack.insert(relay.clone());
            }
        }
    }

    /// Something of the device's own waits to be sent to `relay`, or
    /// nothing does, as the pass found.
    pub fn waits(&self, relay: &RelayId, something: bool) {
        self.with(relay, |of, _, _| {
            of.waits = Some(something);
            if !something {
                of.refusing_waits_since = None;
            }
        });
    }

    /// `relay` refused, for room or for the address's allowance, what of
    /// the device's own was offered it.
    pub fn refused_what_waits(&self, relay: &RelayId) {
        self.with(relay, |of, _, now| {
            of.refusing_waits_since.get_or_insert(now.at);
        });
    }

    /// `relay` took something of the device's own that was offered it.
    pub fn took_what_waits(&self, relay: &RelayId) {
        self.with(relay, |of, _, _| of.refusing_waits_since = None);
    }

    // ── What the dial loop and the lookups say ──────────────────────

    /// A dial of `relay` begins.
    pub fn dial_begins(&self, relay: &RelayId) {
        self.with(relay, |of, _, now| {
            of.dials = of.dials.saturating_add(1);
            of.last_begun = Some(now.at);
        });
    }

    /// A dial at `relay`'s address ended: with a connection to it, made
    /// with its key, or not. A dial that this relay did not begin, made at
    /// its address for another, is an attempt begun and ended now.
    pub fn dial_ends(&self, relay: &RelayId, connected: bool) {
        self.with(relay, |of, _, now| {
            match of.dials {
                0 => of.last_begun = Some(now.at),
                _ => of.dials -= 1,
            }
            of.awaiting |= connected;
        });
    }

    /// An attempt at `relay` was begun and failed now: a lookup of its
    /// name that did not resolve, or a tick of the dial loop that passed
    /// it over because another relay answers at its address.
    pub fn failed(&self, relay: &RelayId) {
        self.with(relay, |of, _, now| of.last_begun = Some(now.at));
    }

    /// No connection to `relay` is open: a dial that connected and was
    /// waiting for a show has failed, and the relay is reached no more.
    pub fn connection_gone(&self, relay: &RelayId) {
        self.with(relay, |of, _, now| {
            of.awaiting = false;
            if of.reached.take().is_some() {
                of.last_reached = Some(now);
                of.starts_again(now);
            }
        });
    }

    /// The connection to `relay` that is open now, where one is: where
    /// none is, or another than the one it was reached on, a dial that
    /// connected and waited for a show has failed, and the relay is
    /// reached no more.
    pub fn connection(&self, relay: &RelayId, open: Option<LinkId>) {
        self.with(relay, |of, _, now| {
            if open.is_none() {
                of.awaiting = false;
            }
            if of.reached.is_some() && of.reached != open {
                of.reached = None;
                of.last_reached = Some(now);
                of.starts_again(now);
            }
        });
    }

    /// Whether `relay` lacks the change while the device has one to show:
    /// it is dialled at the pace of a node that is cut off (rule 3).
    pub fn lacks(&self, relay: &RelayId) -> bool {
        let inner = lock(&self.inner);
        inner.shows
            && inner
                .relays
                .get(relay)
                .is_some_and(|of| of.holds == Some(Holds::Lacks))
    }

    /// The relays that came to lack the change since this was last
    /// asked: a wait already set to dial each is cut (rule 3).
    pub fn came_to_lack(&self) -> Vec<RelayId> {
        lock(&self.inner).came_to_lack.drain().collect()
    }

    /// Woken where a relay comes to lack the change: the lookups of names
    /// are made at once (rule 3).
    pub fn lookups(&self) -> &tokio::sync::Notify {
        &self.lookups
    }

    // ── What is read ────────────────────────────────────────────────

    /// Whether `relay` is out of reach now.
    pub fn is_out_of_reach(&self, relay: &RelayId) -> bool {
        self.with(relay, |of, _, _| of.out_since.is_some())
    }

    /// Whether `relay` is reached now.
    pub fn is_reached(&self, relay: &RelayId) -> bool {
        self.with(relay, |of, _, _| of.reached.is_some())
    }

    /// What is known of `relay`'s reach now, and its class: what a
    /// status and the wait after a change read.
    pub fn of(&self, relay: &RelayId) -> Reached {
        self.with(relay, |of, common, now| {
            let reached = of.reached.is_some();
            let holds = of.holds.unwrap_or_default();
            let five_minutes =
                |since: Instant| now.at.saturating_duration_since(since) >= OUT_OF_REACH;
            let refused_since = of
                .lacking_since
                .filter(|_| reached && holds == Holds::Lacks);
            let refused_long = refused_since.is_some_and(|since| five_minutes(since.at));
            let waits = of.waits.filter(|_| reached).map(|something| {
                match (something, of.refusing_waits_since) {
                    (false, _) => Waits::Nothing,
                    (true, Some(since)) if five_minutes(since) => Waits::Refused,
                    (true, _) => Waits::Moving,
                }
            });
            let out = of.out_since.is_some();
            Reached {
                key: relay.key,
                holds,
                reached,
                out_of_reach_since: of.out_since.map(|since| since.wall),
                reference: of.reference(common).wall,
                last_reached: of.last_reached.map(|at| at.wall),
                refused_since: refused_since.map(|since| since.wall),
                waits,
                answered_at: of.answered_at,
                class: class(holds, reached, out, waits, refused_long),
            }
        })
    }
}

/// The class of a relay in the wait after a change (decision 2026-10-19
/// §1), or none while time can still move it:
///
/// - **OK:** reached, holds the change, and nothing waits there;
/// - **STUCK:** reached, holds the change, and refuses what waits;
/// - **OUT, holding:** out of reach, and holds the change;
/// - **OUT, lacking:** out of reach, and lacks the change;
/// - **REFUSING:** reached, lacks the change, and has refused it for five
///   minutes.
///
/// A relay in the third state, which neither holds nor lacks the change,
/// is in none: nothing acts on it. `waits` is what waits there, known
/// only where it is reached, and `refused_long` whether it has refused
/// the change for five minutes.
pub fn class(
    holds: Holds,
    reached: bool,
    out_of_reach: bool,
    waits: Option<Waits>,
    refused_long: bool,
) -> Option<Class> {
    match (reached, holds) {
        (true, Holds::Holds) => match waits {
            Some(Waits::Nothing) => Some(Class::Ok),
            Some(Waits::Refused) => Some(Class::Stuck),
            Some(Waits::Moving) | None => None,
        },
        (true, Holds::Lacks) => refused_long.then_some(Class::Refusing),
        (false, Holds::Holds) if out_of_reach => Some(Class::OutHolding),
        (false, Holds::Lacks) if out_of_reach => Some(Class::OutLacking),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_api::at_relays::known::{self, Answer, OfRelay};

    /// The change entry the device keeps, and another.
    const KEPT: [u8; 32] = [1; 32];
    const LATER: [u8; 32] = [2; 32];
    /// A relay's node key.
    const KEY: [u8; 32] = [7; 32];

    fn relay(name: &str) -> RelayId {
        RelayId {
            name: name.into(),
            key: Some(KEY),
        }
    }

    fn link(n: u8) -> LinkId {
        [n; 32]
    }

    /// A node that starts now, with a clock that the test moves, and that
    /// keeps `KEPT`, which each of `relays` holds as `holds` says.
    fn started(relays: &[(&RelayId, Holds)]) -> (Arc<Reach>, Clock) {
        let clock = Clock::system();
        let reach = Reach::new(clock.clone());
        observe(&reach, KEPT, relays);
        (reach, clock)
    }

    fn observe(reach: &Reach, kept: [u8; 32], relays: &[(&RelayId, Holds)]) {
        let each: Vec<(RelayId, Holds, Option<i64>)> = relays
            .iter()
            .map(|(relay, holds)| ((*relay).clone(), *holds, None))
            .collect();
        reach.observe(Some(kept), true, &each);
    }

    /// The clock moves to `secs` after the start, from where it is.
    struct At {
        clock: Clock,
        secs: u64,
    }

    impl At {
        fn new(clock: &Clock) -> Self {
            Self {
                clock: clock.clone(),
                secs: 0,
            }
        }

        fn to(&mut self, secs: u64) {
            assert!(
                secs >= self.secs,
                "the clock goes back from {} to {secs}",
                self.secs
            );
            self.clock.run_ahead(Duration::from_secs(secs - self.secs));
            self.secs = secs;
        }
    }

    /// A dial of `relay` that fails.
    fn dial_fails(reach: &Reach, relay: &RelayId) {
        reach.dial_begins(relay);
        reach.dial_ends(relay, false);
    }

    /// A round of shows on `link` that said `said`.
    fn shown(reach: &Reach, relay: &RelayId, link: LinkId, said: Said, holds: Holds) {
        reach.show_begins(relay);
        reach.show_ends(relay, link, said, holds);
    }

    /// Since when, in seconds after the start, `relay` is out of reach.
    fn out_since(reach: &Reach, relay: &RelayId, start: i64) -> Option<i64> {
        reach
            .of(relay)
            .out_of_reach_since
            .map(|since| since - start)
    }

    /// A relay is out of reach once five minutes have gone with every
    /// attempt failed (decision 2026-10-19 §1): not at 299 seconds, and
    /// at 300.
    #[test]
    fn a_relay_is_out_of_reach_after_five_minutes_of_failed_attempts() {
        let b = relay("b");
        let (reach, clock) = started(&[(&b, Holds::Lacks)]);
        let start = reach.of(&b).reference;
        let mut at = At::new(&clock);
        for secs in (0..=270).step_by(30) {
            at.to(secs);
            dial_fails(&reach, &b);
        }
        at.to(299);
        assert!(!reach.is_out_of_reach(&b));
        assert_eq!(reach.of(&b).class, None);
        at.to(300);
        assert!(reach.is_out_of_reach(&b));
        let since = out_since(&reach, &b, start).unwrap();
        assert!((299..=300).contains(&since), "{since}");
        assert_eq!(reach.of(&b).class, Some(Class::OutLacking));
        // It stays so, though nothing more is tried, until something
        // moves it.
        at.to(3600);
        assert!(reach.is_out_of_reach(&b));
    }

    /// An attempt in flight keeps a relay from being out of reach, and it
    /// is out of reach from the moment that attempt fails (decision
    /// 2026-10-19 §1).
    #[test]
    fn not_while_an_attempt_is_in_flight() {
        let b = relay("b");
        let (reach, clock) = started(&[(&b, Holds::Lacks)]);
        let start = reach.of(&b).reference;
        let mut at = At::new(&clock);
        at.to(10);
        dial_fails(&reach, &b);
        at.to(290);
        reach.dial_begins(&b);
        at.to(400);
        assert!(!reach.is_out_of_reach(&b), "a dial is in flight");
        at.to(401);
        reach.dial_ends(&b, false);
        let since = out_since(&reach, &b, start).unwrap();
        assert!((400..=401).contains(&since), "{since}");
        // So is a show, and a dial that connected and waits for a show.
        let c = relay("c");
        observe(&reach, KEPT, &[(&b, Holds::Lacks), (&c, Holds::Lacks)]);
        reach.dial_begins(&c);
        reach.dial_ends(&c, true);
        at.to(1000);
        assert!(!reach.is_out_of_reach(&c), "it waits for a show");
        reach.show_begins(&c);
        at.to(1100);
        assert!(!reach.is_out_of_reach(&c), "a show is in flight");
        reach.show_ends(&c, link(1), Said::Neither, Holds::Lacks);
        assert!(reach.is_out_of_reach(&c));
        // A dial that connected, whose connection then closed before a
        // show on it said anything, failed.
        let e = relay("e");
        observe(&reach, LATER, &[(&e, Holds::Lacks)]);
        at.to(1110);
        reach.dial_begins(&e);
        reach.dial_ends(&e, true);
        at.to(1120);
        reach.connection(&e, None);
        at.to(1399);
        assert!(!reach.is_out_of_reach(&e));
        at.to(1400);
        assert!(reach.is_out_of_reach(&e));
    }

    /// With no attempt after the reference, a relay is not out of reach,
    /// however long it has not been reached (decision 2026-10-19 §1).
    #[test]
    fn not_with_no_attempt_in_the_five_minutes() {
        let (b, c) = (relay("b"), relay("c"));
        let (reach, clock) = started(&[(&b, Holds::Lacks), (&c, Holds::Lacks)]);
        let mut at = At::new(&clock);
        at.to(10);
        dial_fails(&reach, &c);
        // A new kept entry: c's attempt is before the reference.
        at.to(50);
        observe(&reach, LATER, &[(&b, Holds::Lacks), (&c, Holds::Lacks)]);
        at.to(3600);
        assert!(!reach.is_out_of_reach(&b), "never tried");
        assert!(
            !reach.is_out_of_reach(&c),
            "tried only before the reference"
        );
        assert_eq!(reach.of(&b).class, None);
        // A dial that began more than five minutes before it failed: no
        // attempt was begun within the five minutes.
        let d = relay("d");
        observe(&reach, LATER, &[(&d, Holds::Lacks)]);
        at.to(3610);
        reach.dial_begins(&d);
        at.to(4000);
        reach.dial_ends(&d, false);
        at.to(5000);
        assert!(
            !reach.is_out_of_reach(&d),
            "its one attempt began too long ago"
        );
    }

    /// A new kept entry starts the five minutes again (decision
    /// 2026-10-19 §1): a relay out of reach is out of reach no more, and
    /// is so again five minutes after the change.
    #[test]
    fn a_new_kept_entry_starts_the_five_minutes_again() {
        let b = relay("b");
        let (reach, clock) = started(&[(&b, Holds::Lacks)]);
        let start = reach.of(&b).reference;
        let mut at = At::new(&clock);
        for secs in (0..=330).step_by(30) {
            at.to(secs);
            dial_fails(&reach, &b);
        }
        assert!(reach.is_out_of_reach(&b));
        at.to(350);
        observe(&reach, LATER, &[(&b, Holds::Lacks)]);
        assert!(!reach.is_out_of_reach(&b));
        let reference = reach.of(&b).reference - start;
        assert!((349..=350).contains(&reference), "{reference}");
        for secs in (360..=630).step_by(30) {
            at.to(secs);
            dial_fails(&reach, &b);
        }
        at.to(649);
        assert!(!reach.is_out_of_reach(&b));
        at.to(650);
        assert!(reach.is_out_of_reach(&b));
        // The same entry again moves nothing.
        observe(&reach, LATER, &[(&b, Holds::Lacks)]);
        assert!(reach.is_out_of_reach(&b));
    }

    /// Being reached ends it at once (decision 2026-10-19 §1).
    #[test]
    fn being_reached_ends_it_at_once() {
        let b = relay("b");
        let (reach, clock) = started(&[(&b, Holds::Lacks)]);
        let mut at = At::new(&clock);
        for secs in (0..=300).step_by(30) {
            at.to(secs);
            dial_fails(&reach, &b);
        }
        assert!(reach.is_out_of_reach(&b));
        reach.dial_begins(&b);
        reach.dial_ends(&b, true);
        assert!(reach.is_out_of_reach(&b), "connected is not reached");
        shown(&reach, &b, link(1), Said::Lacks, Holds::Lacks);
        assert!(!reach.is_out_of_reach(&b));
        assert!(reach.is_reached(&b));
        assert_eq!(reach.of(&b).out_of_reach_since, None);
        // While it is reached, failed attempts make it no less so: its
        // name stops resolving, and the connection stays.
        for secs in (330..=1000).step_by(30) {
            at.to(secs);
            reach.failed(&b);
        }
        assert!(!reach.is_out_of_reach(&b));
    }

    /// A relay that is connected and whose shows get no answer that says
    /// whether it holds the entry is out of reach (decision 2026-10-19
    /// §1): each show is a failed attempt, and a dial that connected is
    /// ended by the first of them. Its connection stays open.
    #[test]
    fn a_connected_relay_whose_shows_go_unanswered_is_out_of_reach() {
        let b = relay("b");
        let (reach, clock) = started(&[(&b, Holds::Lacks)]);
        let mut at = At::new(&clock);
        reach.dial_begins(&b);
        reach.dial_ends(&b, true);
        for secs in [10, 100, 200] {
            at.to(secs);
            shown(&reach, &b, link(1), Said::Neither, Holds::Lacks);
        }
        at.to(299);
        assert!(!reach.is_out_of_reach(&b));
        at.to(300);
        assert!(reach.is_out_of_reach(&b));
        assert!(!reach.is_reached(&b));
        // A relay reached on that connection is reached there no more
        // once a show on it says neither.
        let c = relay("c");
        observe(&reach, KEPT, &[(&b, Holds::Lacks), (&c, Holds::Lacks)]);
        shown(&reach, &c, link(2), Said::Holds, Holds::Holds);
        assert!(reach.is_reached(&c));
        shown(&reach, &c, link(2), Said::Neither, Holds::Holds);
        assert!(!reach.is_reached(&c));
    }

    /// Another key answering at a relay's address, at each tick of the
    /// dial loop, and a lookup of its name that does not resolve, at each
    /// lookup, are each a failed attempt (decision 2026-10-19 §1).
    #[test]
    fn another_key_and_a_name_that_does_not_resolve_are_failed_attempts() {
        let (wrong_key, no_name) = (relay("wrong key"), relay("no name"));
        let (reach, clock) = started(&[(&wrong_key, Holds::Lacks), (&no_name, Holds::Lacks)]);
        let mut at = At::new(&clock);
        for secs in 0..=300 {
            at.to(secs);
            reach.failed(&wrong_key);
            if secs % 30 == 0 {
                reach.failed(&no_name);
            }
            let out = secs >= 300;
            assert_eq!(reach.is_out_of_reach(&wrong_key), out, "{secs}");
            assert_eq!(reach.is_out_of_reach(&no_name), out, "{secs}");
        }
        // A dial made at its address for another relay, which another key
        // answers for it, is an attempt at it too, begun and failed then.
        let shared = relay("shared");
        observe(&reach, LATER, &[(&shared, Holds::Lacks)]);
        for secs in (310..=600).step_by(30) {
            at.to(secs);
            reach.dial_ends(&shared, false);
        }
        assert!(!reach.is_out_of_reach(&shared));
        at.to(610);
        reach.dial_ends(&shared, false);
        assert!(reach.is_out_of_reach(&shared));
    }

    /// Only a start, a sleep, a new kept entry and the relay being reached
    /// move its reference (decision 2026-10-19 §1). A failed attempt, a
    /// connection that closes on a relay that was not reached, and
    /// another relay being reached move nothing.
    #[test]
    fn a_start_a_sleep_a_new_kept_entry_and_being_reached_each_move_the_reference() {
        let (a, b) = (relay("a"), relay("b"));
        let (reach, clock) = started(&[(&a, Holds::Lacks), (&b, Holds::Lacks)]);
        let start = reach.of(&b).reference;
        let reference = |relay: &RelayId| reach.of(relay).reference - start;
        let near = |got: i64, want: i64| (want - 1..=want).contains(&got);
        assert_eq!(reference(&b), 0, "the start");
        let mut at = At::new(&clock);
        at.to(50);
        dial_fails(&reach, &b);
        reach.connection(&b, None);
        shown(&reach, &a, link(1), Said::Holds, Holds::Holds);
        reach.connection(&a, None);
        assert_eq!(reference(&b), 0, "nothing of these moves b's");
        assert!(near(reference(&a), 50), "a was reached");
        at.to(100);
        reach.slept();
        assert!(near(reference(&b), 100), "a sleep");
        at.to(200);
        observe(&reach, LATER, &[(&a, Holds::Lacks), (&b, Holds::Lacks)]);
        assert!(near(reference(&b), 200), "a new kept entry");
        at.to(250);
        shown(&reach, &b, link(2), Said::Lacks, Holds::Lacks);
        at.to(260);
        assert!(near(reference(&b), 250), "reached");
        reach.connection(&b, None);
        assert!(
            near(reference(&b), 260),
            "last reached as the connection closed"
        );
        // The last reached time is said, for a person.
        assert!(near(reach.of(&b).last_reached.unwrap() - start, 260));
    }

    /// The attempt that makes a relay out of reach must be within the
    /// five minutes before now and after the reference (decision
    /// 2026-10-19 §1): a relay whose first attempt after the reference
    /// comes at minute nine is out of reach at minute nine.
    #[test]
    fn an_attempt_must_be_in_the_last_five_minutes_and_after_the_reference() {
        let b = relay("b");
        let (reach, clock) = started(&[(&b, Holds::Lacks)]);
        let start = reach.of(&b).reference;
        let mut at = At::new(&clock);
        at.to(539);
        assert!(!reach.is_out_of_reach(&b));
        at.to(540);
        dial_fails(&reach, &b);
        let since = out_since(&reach, &b, start).unwrap();
        assert!((539..=540).contains(&since), "{since}");
        // An attempt that is no longer within the five minutes holds
        // nothing up: once out of reach, it stays.
        let c = relay("c");
        observe(&reach, KEPT, &[(&b, Holds::Lacks), (&c, Holds::Lacks)]);
        at.to(560);
        dial_fails(&reach, &c);
        at.to(2000);
        let since = out_since(&reach, &c, start).unwrap();
        assert!((559..=560).contains(&since), "{since}");
    }

    /// A relay that held the change and then answers "no room" at every
    /// show is REFUSING five minutes after it came to lack it (decision
    /// 2026-10-19 §1); an answer that it holds it starts that again.
    #[test]
    fn a_relay_that_held_and_then_refuses_is_refusing_five_minutes_on() {
        let a = relay("a");
        let (reach, clock) = started(&[(&a, Holds::Lacks)]);
        let mut at = At::new(&clock);
        at.to(1000);
        shown(&reach, &a, link(1), Said::Holds, Holds::Holds);
        reach.waits(&a, false);
        assert_eq!(reach.of(&a).class, Some(Class::Ok));
        for secs in (1100..=1399).step_by(60) {
            at.to(secs);
            shown(&reach, &a, link(1), Said::Lacks, Holds::Lacks);
        }
        at.to(1399);
        assert_eq!(
            reach.of(&a).class,
            None,
            "four minutes and more is not five"
        );
        at.to(1400);
        shown(&reach, &a, link(1), Said::Lacks, Holds::Lacks);
        assert_eq!(reach.of(&a).class, Some(Class::Refusing));
        // It took it after all: the five minutes start again from its
        // next refusal.
        at.to(1460);
        shown(&reach, &a, link(1), Said::Holds, Holds::Holds);
        at.to(1520);
        shown(&reach, &a, link(1), Said::Lacks, Holds::Lacks);
        at.to(1800);
        assert_eq!(reach.of(&a).class, None);
        at.to(1820);
        assert_eq!(reach.of(&a).class, Some(Class::Refusing));
    }

    /// Every state that is in no class comes to one, by what the node
    /// meets (decision 2026-10-19 §1): a sequence of answers, failed
    /// attempts and steps of the clock from each kind of state that
    /// section 1 lists, and the relay is in a class within five minutes
    /// and the time of an attempt, or within fifteen where its shows are
    /// answered "not signed" or "show it whole" at the pace of the wait
    /// that doubles.
    #[test]
    fn every_unclassed_state_ends_in_a_class() {
        let r = relay("r");
        type Step = Box<dyn Fn(&Reach, u64)>;
        // Each case: how it starts, what the node meets each second, the
        // class it comes to, and the bound on when.
        let cases: Vec<(&str, Holds, Step, Class, u64)> = vec![
            (
                "not reached and lacking: a failed dial every 30 s (rule 3)",
                Holds::Lacks,
                Box::new(|reach: &Reach, secs| {
                    if secs % 30 == 5 {
                        dial_fails(reach, &relay("r"));
                    }
                }),
                Class::OutLacking,
                OUT_OF_REACH_SECS + 30,
            ),
            (
                "not reached and holding: a failed dial within 900 s",
                Holds::Holds,
                Box::new(|reach: &Reach, secs| {
                    if secs == 899 {
                        dial_fails(reach, &relay("r"));
                    }
                }),
                Class::OutHolding,
                900,
            ),
            (
                "connected, its whole shows answered \"not signed\" at a wait that doubles",
                Holds::Lacks,
                Box::new(|reach: &Reach, secs| {
                    if secs == 0 {
                        reach.dial_begins(&relay("r"));
                        reach.dial_ends(&relay("r"), true);
                    }
                    if [1, 61, 181, 421].contains(&secs) {
                        shown(reach, &relay("r"), link(1), Said::Neither, Holds::Lacks);
                    }
                }),
                Class::OutLacking,
                15 * 60,
            ),
            (
                "reached and lacking for less than five minutes: it goes on refusing",
                Holds::Lacks,
                Box::new(|reach: &Reach, secs| {
                    if secs % 60 == 0 {
                        shown(reach, &relay("r"), link(1), Said::Lacks, Holds::Lacks);
                    }
                }),
                Class::Refusing,
                OUT_OF_REACH_SECS,
            ),
            (
                "reached and lacking for less than five minutes: it takes the change",
                Holds::Lacks,
                Box::new(|reach: &Reach, secs| {
                    let said = match secs < 120 {
                        true => (Said::Lacks, Holds::Lacks),
                        false => (Said::Holds, Holds::Holds),
                    };
                    if secs % 60 == 0 {
                        shown(reach, &relay("r"), link(1), said.0, said.1);
                        reach.waits(&relay("r"), false);
                    }
                }),
                Class::Ok,
                OUT_OF_REACH_SECS,
            ),
            (
                "reached and holding, something waits: refused at each offer",
                Holds::Holds,
                Box::new(|reach: &Reach, secs| {
                    if secs == 0 {
                        shown(reach, &relay("r"), link(1), Said::Holds, Holds::Holds);
                    }
                    if secs % 60 == 0 {
                        reach.waits(&relay("r"), true);
                        reach.refused_what_waits(&relay("r"));
                    }
                }),
                Class::Stuck,
                OUT_OF_REACH_SECS,
            ),
            (
                "reached and holding, something waits: it takes it",
                Holds::Holds,
                Box::new(|reach: &Reach, secs| {
                    if secs == 0 {
                        shown(reach, &relay("r"), link(1), Said::Holds, Holds::Holds);
                        reach.waits(&relay("r"), true);
                        reach.refused_what_waits(&relay("r"));
                    }
                    if secs == 200 {
                        reach.took_what_waits(&relay("r"));
                        reach.waits(&relay("r"), false);
                    }
                }),
                Class::Ok,
                OUT_OF_REACH_SECS,
            ),
            (
                "reached and holding, then \"no room\" at every show",
                Holds::Holds,
                Box::new(|reach: &Reach, secs| {
                    let said = match secs {
                        0 => (Said::Holds, Holds::Holds),
                        _ => (Said::Lacks, Holds::Lacks),
                    };
                    if secs % 30 == 0 {
                        shown(reach, &relay("r"), link(1), said.0, said.1);
                    }
                }),
                Class::Refusing,
                OUT_OF_REACH_SECS + 30,
            ),
        ];
        for (case, holds, step, class, bound) in cases {
            let (reach, clock) = started(&[(&r, holds)]);
            let mut at = At::new(&clock);
            let mut came = None;
            for secs in 0..=bound {
                at.to(secs);
                step(&reach, secs);
                if let Some(class) = reach.of(&r).class {
                    came = Some((class, secs));
                    break;
                }
            }
            let (got, secs) = came.unwrap_or_else(|| panic!("{case}: in no class by {bound} s"));
            assert_eq!(got, class, "{case}, at {secs} s");
            assert!(secs > 0, "{case}: in a class from the start");
        }
    }

    /// The classes that the node gives agree with the model of appendix A
    /// over every state of one relay that it enumerates (decision
    /// 2026-10-19 §1, appendix A): 96 states, each put in its class by
    /// the node's own functions, what is known of the relay first
    /// ([`known::holds`]) and then [`class`]. A relay given no key holds
    /// the change only while connected.
    #[test]
    fn the_classes_agree_with_the_model_over_every_relay_state() {
        const ANSWERS: [&str; 6] = ["none", "held", "took", "noroom", "over", "another"];
        const WAITS: [&str; 3] = ["nothing", "moving", "stuck"];
        let mut states = 0;
        for keyed in [true, false] {
            for connected in [true, false] {
                for reached in [true, false] {
                    for out in [true, false] {
                        for answer in ANSWERS {
                            for waits in WAITS {
                                for refused_long in [true, false] {
                                    if reached && !connected
                                        || reached && out
                                        || reached && answer == "none"
                                        || !reached && (waits != "nothing" || refused_long)
                                    {
                                        continue;
                                    }
                                    let says_holds = matches!(answer, "held" | "took");
                                    let model_holds = says_holds && (keyed || connected);
                                    if model_holds && refused_long {
                                        continue;
                                    }
                                    states += 1;
                                    let model = match (reached, model_holds, out) {
                                        (true, true, _) => match waits {
                                            "nothing" => Some(Class::Ok),
                                            "stuck" => Some(Class::Stuck),
                                            _ => None,
                                        },
                                        (true, false, _) => refused_long.then_some(Class::Refusing),
                                        (false, true, true) => Some(Class::OutHolding),
                                        (false, false, true) => Some(Class::OutLacking),
                                        _ => None,
                                    };
                                    let of = OfRelay {
                                        relay: RelayId {
                                            name: "r".into(),
                                            key: keyed.then_some(KEY),
                                        },
                                        answer: (answer != "none").then_some(Answer {
                                            entry: KEPT,
                                            holds: says_holds,
                                            by: KEY,
                                            at: 0,
                                        }),
                                        mark: None,
                                    };
                                    let holds = known::holds(
                                        Some(&of),
                                        Some(KEPT),
                                        connected.then_some(KEY),
                                    );
                                    assert_eq!(holds == Holds::Holds, model_holds, "{of:?}");
                                    let waits = match waits {
                                        "nothing" => Waits::Nothing,
                                        "moving" => Waits::Moving,
                                        _ => Waits::Refused,
                                    };
                                    let waits = reached.then_some(waits);
                                    let node = class(holds, reached, out, waits, refused_long);
                                    assert_eq!(
                                        node, model,
                                        "keyed {keyed}, connected {connected}, reached {reached}, out {out}, {answer}, {waits:?}, refused {refused_long}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(states, 96, "the model's states of one relay");
    }

    /// A relay that comes to lack the change is told the dial loop once,
    /// and the lookups of names are woken (decision 2026-10-19, rule 3).
    /// One that holds it, or neither holds nor lacks it, is not; nor is
    /// any while the device has no change entry to show.
    #[tokio::test]
    async fn a_relay_that_comes_to_lack_the_change_is_said_once_and_wakes_the_lookups() {
        let (a, b, c) = (relay("a"), relay("b"), relay("c"));
        let (reach, _clock) =
            started(&[(&a, Holds::Lacks), (&b, Holds::Holds), (&c, Holds::Neither)]);
        assert_eq!(reach.came_to_lack(), vec![a.clone()]);
        assert!(reach.came_to_lack().is_empty(), "said once");
        tokio::time::timeout(Duration::from_secs(1), reach.lookups().notified())
            .await
            .expect("the lookups are woken");
        assert!(reach.lacks(&a) && !reach.lacks(&b) && !reach.lacks(&c));
        // A new kept entry: each that lacks it comes to lack it.
        observe(
            &reach,
            LATER,
            &[(&a, Holds::Lacks), (&b, Holds::Lacks), (&c, Holds::Neither)],
        );
        let mut came = reach.came_to_lack();
        came.sort_by(|x, y| x.name.cmp(&y.name));
        assert_eq!(came, vec![a.clone(), b.clone()]);
        // A relay set up no longer is forgotten.
        observe(&reach, LATER, &[(&a, Holds::Lacks)]);
        assert!(reach.lacks(&a) && !reach.lacks(&b));
        // Nothing to show: nothing lacks, and nothing comes to.
        let each = [
            (a.clone(), Holds::Lacks, None),
            (b.clone(), Holds::Lacks, None),
        ];
        reach.observe(Some([3; 32]), false, &each);
        assert!(!reach.lacks(&a) && !reach.lacks(&b));
        assert!(reach.came_to_lack().is_empty());
    }

    /// A relay that never held the change has lacked it since the start,
    /// as far as the node knows, though the first pass finds it later
    /// (decision 2026-10-19 §1): one that answers "no room" at every show
    /// is REFUSING five minutes after the start.
    #[test]
    fn a_relay_that_never_held_the_change_has_lacked_it_since_the_start() {
        let a = relay("a");
        let clock = Clock::system();
        let reach = Reach::new(clock.clone());
        let mut at = At::new(&clock);
        at.to(200);
        observe(&reach, KEPT, &[(&a, Holds::Lacks)]);
        for secs in (200..=299).step_by(20) {
            at.to(secs);
            shown(&reach, &a, link(1), Said::Lacks, Holds::Lacks);
        }
        assert_eq!(reach.of(&a).class, None);
        at.to(300);
        assert_eq!(reach.of(&a).class, Some(Class::Refusing));
    }

    /// A relay that holds the change refuses what waits there only once it
    /// has refused it at each offer for five minutes (decision 2026-10-19
    /// §1): a relay that takes something, or at which nothing waits,
    /// starts the five minutes again.
    #[test]
    fn what_waits_is_refused_for_five_minutes_before_a_relay_is_stuck() {
        let a = relay("a");
        let (reach, clock) = started(&[(&a, Holds::Holds)]);
        let mut at = At::new(&clock);
        shown(&reach, &a, link(1), Said::Holds, Holds::Holds);
        reach.waits(&a, true);
        reach.refused_what_waits(&a);
        at.to(100);
        // It takes something, and refuses the rest.
        reach.took_what_waits(&a);
        at.to(150);
        reach.refused_what_waits(&a);
        at.to(400);
        assert_eq!(reach.of(&a).waits, Some(Waits::Moving));
        assert_eq!(reach.of(&a).class, None);
        at.to(450);
        assert_eq!(reach.of(&a).class, Some(Class::Stuck));
        // Nothing waits: it is OK, and what waits later is refused anew.
        reach.waits(&a, false);
        assert_eq!(reach.of(&a).class, Some(Class::Ok));
        at.to(500);
        reach.waits(&a, true);
        reach.refused_what_waits(&a);
        at.to(790);
        assert_eq!(reach.of(&a).class, None, "refused since nothing waited");
        at.to(800);
        assert_eq!(reach.of(&a).class, Some(Class::Stuck));
    }
}
