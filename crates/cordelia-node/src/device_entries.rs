//! A device's side of its relays, for the channels of its own: the entries
//! of channels from their secrets (decision 2026-10-04 §2.4, §4.6, §7.3).
//!
//! What a device does with an entry is in `cordelia_api`: plain functions
//! over its database ([`cordelia_api::at_relays`], and the one door,
//! [`cordelia_api::take`]). This is who asks them, and when: the passes
//! that the node makes on its timers, over the connections it has to the
//! relays it is set up with.
//!
//! **Only a personal node has any of it**, and it does nothing on a device
//! that follows no phrase: no stream is opened, and nothing is logged.
//!
//! ## A pass
//!
//! [`DeviceEntries::pass`] is run on the node's two timers, and one pass
//! runs at a time:
//!
//! - **The whole pass**, as often as the node fetches. The hand-overs
//!   that this device made and that are two hours old go from its store,
//!   and a delete is written over each that a relay was sent (§6). Then
//!   the device **shows** its change entry on every connection, and deals
//!   with what it is answered (§4.6): the first time on a connection
//!   whole, and from then on in short. And then, at each relay where it
//!   has leave, for each channel of its own: it **proves** the channel's
//!   key, once on a connection and again after a day; **pulls** the
//!   channel from the place it keeps, each page through the one door;
//!   and **pushes** what that relay has not been sent, and then what it
//!   carried into the channel of a name, by the rule of §7.3. Once a day
//!   it proves the channel of every name that its personal channel lists
//!   and that it does not hold (§2.5).
//! - **The pass that sends**, as often as the node sends what waits, and
//!   when something is written: it pushes what each relay has not been
//!   sent, and nothing else.
//!
//! ## Leave
//!
//! Every stream for a channel of the device's own is opened through
//! [`Leave::open`], and through nothing else: [`leave`] says what leave
//! is. Whatever finds no leave shows again by itself, and tries once
//! more: the pass, the timer that sends, and a publish alike. So a lost
//! answer costs one short show, and a pass that is long shows again as it
//! goes.
//!
//! A device that wakes shows on every connection first, in either pass,
//! and does nothing more until each relay it is set up with has answered
//! or the wait has gone by.
//!
//! ## What it keeps
//!
//! In its database, for each relay and channel: its place there, and how
//! far it has sent (`cordelia_storage::at_relays`). In memory, and gone
//! with the connection: which entry it showed whole there, and which
//! channels it proved there and when. In memory, for as long as the node
//! runs: what a status reads, and how long a channel that found no room
//! at a relay is left before it is sent there again.

pub mod leave;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cordelia_api::adding::{drop_old_hand_overs, write_over_dropped};
use cordelia_api::at_relays::{
    self, Answered, Batch, Kind, Most, Own, Page, PageTaken, Pushed, Sent, Stands, Which,
};
use cordelia_api::person::Shown;
use cordelia_api::state::{AppState, AtRelay, AtRelays, CannotGoOn, NoRoom};
use cordelia_core::protocol::{
    CHANNEL_PROOF_AGAIN_SECS, ENTRY_OVERHEAD_BYTES, ENTRY_PAGE_MAX_BYTES, ENTRY_PAGE_MAX_ENTRIES,
    MAX_CHANNELS_PROVED_ON_A_CONNECTION, MAX_ITEM_BYTES, OUTBOX_BYTES_PER_MINUTE,
    OUTBOX_FLUSH_INTERVAL_SECS, OUTBOX_REFUSED_RETRY_MAX_SECS, RELAY_ENTRY_PULL_PAGES, entry_cost,
};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_network::messages::{
    ChannelProve, EntryPull, EntryPush, EntryRefused, PushAnswer, ShowAnswer, WireMessage,
};
use cordelia_network::rate_limit::ByteCounter;
use cordelia_storage::person::State;
use rusqlite::Connection;

pub use leave::{Clock, Leave, Link, LinkId, NoLeave, Refused};

/// How long a proof stands before the channel's key is proved again on a
/// connection that lasts.
const PROOF_AGAIN: Duration = Duration::from_secs(CHANNEL_PROOF_AGAIN_SECS);

/// The most shows on one connection in one pass: the entry in short, then
/// whole, and again for each change that the device applies on the way.
const SHOWS_IN_A_PASS: usize = 6;

/// Lock a mutex, also one whose holder panicked: what it guards is whole
/// after any one step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// A relay that the device is set up with: what its configuration calls
/// it, and the connection to it where there is one.
#[derive(Debug, Clone)]
pub struct Relay {
    pub name: String,
    pub link: Option<Link>,
}

/// Which pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// Show, prove, pull and push: as often as the node fetches.
    Whole,
    /// Push what waits: as often as the node sends, and at a publish.
    Send,
}

/// What a device has asked of one relay since the node started, for a
/// status and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Shows of the whole entry that were answered.
    pub whole_shows: u64,
    /// Shows in short that were answered.
    pub short_shows: u64,
    /// The bytes of the shows that were answered.
    pub shown_bytes: u64,
    /// Proofs that were answered.
    pub proofs: u64,
    /// Pages that were taken.
    pub pages: u64,
    /// Entries of those pages.
    pub pulled: u64,
    /// Pushes that were answered.
    pub pushes: u64,
    /// Entries of those pushes.
    pub pushed: u64,
}

/// What became of one step of a relay's pass.
enum Step {
    /// It was done, and this is whether nothing is left of it to do:
    /// the channel is read to its end, or everything was sent.
    Done(bool),
    /// The relay's pass ends here: there is no leave that a show gives
    /// back, or the relay did not answer.
    Stop,
}

/// What is kept of one connection, and gone with it.
#[derive(Default)]
struct OfLink {
    /// The entry that was last shown whole on it, by what it is named by:
    /// only that one may be shown in short.
    shown_whole: Option<[u8; 32]>,
    /// The channels whose keys were proved on it, and when.
    proved: HashMap<[u8; 32], Instant>,
    /// When the channels of the names that the personal channel lists
    /// were last proved on it, all of them.
    listed_proved: Option<Instant>,
}

/// What is kept of one relay, by its name, for as long as the node runs.
#[derive(Default)]
struct OfRelay {
    /// Whether it holds the entry named so, as it last answered a show of
    /// that entry.
    holds: Option<([u8; 32], bool)>,
    /// Its last refusal for room.
    no_room: Option<NoRoom>,
    counts: Counts,
    /// What was pushed to it in the last minute: a device paces itself,
    /// so that it is never the one refused for going over.
    sent: Option<ByteCounter>,
}

/// A channel that found no room at a relay: how often in a row, and when
/// it is sent there again.
struct LeftFor {
    refusals: u32,
    until: Instant,
}

#[derive(Default)]
struct Kept {
    links: HashMap<LinkId, OfLink>,
    relays: HashMap<String, OfRelay>,
    /// By the relay's key and the channel's ID.
    left: HashMap<([u8; 32], [u8; 32]), LeftFor>,
    /// The relay that answered with a change which the device could not
    /// apply, and why.
    not_applied: Option<(String, String)>,
}

/// A device's side of its relays, for the channels of its own (see the
/// module's documentation).
pub struct DeviceEntries {
    state: Arc<AppState>,
    clock: Clock,
    leave: Leave,
    kept: Mutex<Kept>,
    /// One pass at a time.
    running: tokio::sync::Mutex<()>,
}

impl DeviceEntries {
    /// For the node whose state is `state`, reading the time from `clock`.
    pub fn new(state: Arc<AppState>, clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            state,
            leave: Leave::new(clock.clone()),
            clock,
            kept: Mutex::default(),
            running: tokio::sync::Mutex::new(()),
        })
    }

    /// The leave to use each connection.
    pub fn leave(&self) -> &Leave {
        &self.leave
    }

    /// What the device has asked of the relay called `relay` since the
    /// node started.
    pub fn counts(&self, relay: &str) -> Counts {
        lock(&self.kept)
            .relays
            .get(relay)
            .map(|of| of.counts)
            .unwrap_or_default()
    }

    /// Make one pass over `relays`: every relay that the device is set up
    /// with, each with its connection where there is one. A pass that
    /// finds another running does nothing.
    pub async fn pass(self: &Arc<Self>, relays: &[Relay], kind: Pass) {
        let Ok(_running) = self.running.try_lock() else {
            return;
        };
        let links: Vec<&Link> = relays
            .iter()
            .filter_map(|relay| relay.link.as_ref())
            .filter(|link| link.is_open())
            .collect();
        let stands = at_relays::stands(&lock(&self.state.db));
        let stands = match stands {
            Ok(stands) => stands,
            Err(e) => {
                tracing::debug!(error = %e, "could not read where this device stands");
                return;
            }
        };
        // A device that follows no phrase has no channel of its own: it
        // opens no stream, and nothing is said of it but in the status.
        if stands == Stands::NoPhrase {
            self.say(relays, stands);
            return;
        }
        let names: Vec<String> = relays.iter().map(|relay| relay.name.clone()).collect();
        self.leave.reaches(&names, &links);
        self.forget_gone(&links);
        // The connection on which a change could not be applied is gone:
        // nothing is held up by it now.
        if !self.leave.is_not_applied() {
            lock(&self.kept).not_applied = None;
        }

        let whole = kind == Pass::Whole;
        if whole {
            self.hand_overs();
        }
        // A device that was removed, is in no list, or could not open a
        // change shows nothing: it takes no change entry, and the way on
        // is a person's.
        if matches!(stands, Stands::Stopped(state) if state != State::Fork) {
            self.say(relays, stands);
            return;
        }

        // The show comes before everything. The whole pass shows on every
        // connection, and a device that wakes asks every relay first.
        let waking = self.leave.is_waking();
        let mut shows = tokio::task::JoinSet::new();
        for link in &links {
            if whole || (waking && !self.leave.has_heard(link.name())) {
                let (engine, link) = (Arc::clone(self), (*link).clone());
                shows.spawn(async move { engine.show_at(&link).await });
            }
        }
        while shows.join_next().await.is_some() {}

        let stands = at_relays::stands(&lock(&self.state.db)).unwrap_or(stands);
        if stands == Stands::Applied && !self.leave.is_waking() {
            let mut passes = tokio::task::JoinSet::new();
            for link in &links {
                // The whole pass has just shown on every connection: one
                // whose answer gave no leave is left for the next pass.
                // The pass that sends has not, and shows where it finds
                // something to send and no leave.
                if whole && self.leave.has(&lock(&self.state.db), link).is_err() {
                    continue;
                }
                let (engine, link) = (Arc::clone(self), (*link).clone());
                passes.spawn(async move { engine.relay_pass(&link, kind).await });
            }
            while passes.join_next().await.is_some() {}
        }
        let stands = at_relays::stands(&lock(&self.state.db)).unwrap_or(stands);
        self.say(relays, stands);
    }

    // ── What the adder of a device owes ─────────────────────────────

    /// The hand-overs that this device made and that are two hours old go
    /// from its store, and a delete is written over each hand-over that
    /// has gone and that a relay was sent (decision 2026-10-04 §6). The
    /// delete waits in the store, and a pass pushes it.
    fn hand_overs(&self) {
        let now = self.clock.unix();
        let db = lock(&self.state.db);
        match drop_old_hand_overs(&db, now) {
            Ok(0) => {}
            Ok(dropped) => tracing::info!(dropped, "hand-overs left the store: two hours old"),
            Err(e) => tracing::debug!(error = %e, "could not drop the old hand-overs"),
        }
        match write_over_dropped(&db, &self.state.identity, now) {
            Ok(0) => {}
            Ok(written) => {
                tracing::info!(
                    written,
                    "a delete was written over each hand-over that a relay was sent"
                );
            }
            Err(e) => tracing::debug!(error = %e, "could not write over the hand-overs"),
        }
    }

    // ── The show ────────────────────────────────────────────────────

    /// Show the change entry that the device keeps on `link`, and deal
    /// with what it is answered, until an answer leaves nothing more to
    /// show (decision 2026-10-04 §2.4 item 5, §4.6).
    async fn show_at(&self, link: &Link) {
        // The entry is shown whole where it was not yet on this
        // connection, where the relay asks for it, and where the relay
        // tells of another that the device does not keep.
        let mut whole = false;
        for _ in 0..SHOWS_IN_A_PASS {
            let shows = match at_relays::to_show(&lock(&self.state.db)) {
                Ok(Some(shows)) => shows,
                Ok(None) => return,
                Err(e) => {
                    tracing::debug!(error = %e, "could not read the change entry to show");
                    return;
                }
            };
            let entry = &shows.entry;
            let shown_whole = lock(&self.kept)
                .links
                .get(&link.id())
                .and_then(|of| of.shown_whole);
            let short = !whole && shown_whole == Some(entry.id());
            let answered = match self.leave.show(link, entry, short).await {
                Ok(answered) => answered,
                // A short show that is not answered is followed by a
                // whole one.
                Err(_) if short => {
                    whole = true;
                    continue;
                }
                Err(e) => {
                    tracing::debug!(relay = link.name(), error = %e, "a show was not answered");
                    return;
                }
            };
            self.shown(link, entry, short, answered.bytes);
            match answered.answer {
                ShowAnswer::Held | ShowAnswer::Taken => {
                    self.holds(link, entry, true);
                    self.dealt_with(link);
                    return;
                }
                ShowAnswer::Refused(EntryRefused::NoRoom | EntryRefused::OverLimit) => {
                    // The relay holds none, or an earlier one, and would
                    // have taken this one: it holds no later change.
                    let over_allowance =
                        answered.answer == ShowAnswer::Refused(EntryRefused::OverLimit);
                    self.holds(link, entry, false);
                    self.no_room(link, over_allowance, true);
                    self.dealt_with(link);
                    return;
                }
                ShowAnswer::Refused(EntryRefused::NotSigned) => {
                    tracing::warn!(
                        relay = link.name(),
                        "a relay says that the change entry this device keeps is not signed as it must be"
                    );
                    return;
                }
                ShowAnswer::Whole if short => whole = true,
                // "Show it whole" is no answer to the whole entry.
                ShowAnswer::Whole => return,
                ShowAnswer::Other { id, .. } => {
                    // The relay holds another. One that the device keeps,
                    // made apart from its own, it asks no more about. For
                    // any other it shows its own whole, and is answered
                    // with the entry.
                    self.holds(link, entry, false);
                    if !short || shows.apart == Some(id) {
                        return;
                    }
                    whole = true;
                }
                ShowAnswer::Another(bytes) => {
                    self.holds(link, entry, false);
                    let Some(another) = Entry::from_wire(&bytes)
                        .ok()
                        .and_then(|entry| entry.check().ok())
                    else {
                        tracing::warn!(
                            relay = link.name(),
                            "a relay answered a show with what is no entry; nothing is done with it"
                        );
                        return;
                    };
                    if !self.answered_with(link, entry, &another) {
                        return;
                    }
                    // It applied the change: it shows what it keeps now.
                    whole = false;
                }
            }
        }
    }

    /// The device was answered on `link` with `another`, where it showed
    /// `shown`: the entry goes through the one door. Returns whether the
    /// device applied a change by it, and so keeps another entry now.
    fn answered_with(&self, link: &Link, shown: &CheckedEntry, another: &CheckedEntry) -> bool {
        let now = self.clock.unix();
        let outcome = {
            let db = lock(&self.state.db);
            at_relays::answered(&db, &self.state.identity, shown, another, now)
        };
        let relay = link.name();
        match outcome {
            Ok(Answered::Shown(Shown::Applied(applied))) => {
                tracing::info!(
                    relay,
                    statement = applied.number,
                    carried = applied.carried,
                    "applied a change that a relay held"
                );
                self.dealt_with(link);
                true
            }
            Ok(Answered::Shown(Shown::Fork)) => {
                tracing::warn!(
                    relay,
                    "a relay holds a change made apart from the one this device applied: it keeps both, and stops"
                );
                false
            }
            Ok(Answered::Shown(
                stopped @ (Shown::Removed | Shown::NotListed | Shown::NotOpened),
            )) => {
                tracing::warn!(
                    relay,
                    ?stopped,
                    "a relay holds a change by which this device stops"
                );
                false
            }
            Ok(Answered::Shown(Shown::Held | Shown::Behind)) => false,
            Ok(Answered::Shown(Shown::Refused(why))) => {
                tracing::debug!(
                    relay,
                    ?why,
                    "the entry that a relay answered a show with was refused"
                );
                false
            }
            Ok(Answered::NotOfTheSlot | Answered::NotTaken) => {
                tracing::warn!(
                    relay,
                    "a relay answered a show with an entry of another slot; nothing is done with it"
                );
                false
            }
            // The device's own fault, and not the entry's: it has been
            // answered with a change that it has not applied, and neither
            // sends nor takes anywhere until it has.
            Err(e) => {
                tracing::warn!(relay, error = %e, "could not apply the change that a relay answered with");
                self.leave.dealt_with(link, false);
                lock(&self.kept).not_applied = Some((relay.to_string(), e.to_string()));
                false
            }
        }
    }

    /// A show on `link` was answered: of `entry`, in short or whole, in
    /// so many bytes.
    fn shown(&self, link: &Link, entry: &CheckedEntry, short: bool, bytes: usize) {
        let mut kept = lock(&self.kept);
        if !short {
            kept.links.entry(link.id()).or_default().shown_whole = Some(entry.id());
        }
        let of = kept.relays.entry(link.name().to_string()).or_default();
        if short {
            of.counts.short_shows += 1;
        } else {
            of.counts.whole_shows += 1;
        }
        of.counts.shown_bytes += bytes as u64;
        // A show counts at the relay as what is pushed does.
        let cost = if short {
            ENTRY_OVERHEAD_BYTES as u64
        } else {
            entry_cost(entry.content.len())
        };
        paced(of).record(cost);
    }

    /// The relay at `link` answered a show of `entry`: it holds it, or it
    /// does not.
    fn holds(&self, link: &Link, entry: &CheckedEntry, holds: bool) {
        let mut kept = lock(&self.kept);
        let of = kept.relays.entry(link.name().to_string()).or_default();
        of.holds = Some((entry.id(), holds));
    }

    /// The relay at `link` refused something that it would have taken.
    fn no_room(&self, link: &Link, over_allowance: bool, of_the_change: bool) {
        let at = self.clock.unix();
        let mut kept = lock(&self.kept);
        let of = kept.relays.entry(link.name().to_string()).or_default();
        if of.no_room.is_none() {
            tracing::info!(
                relay = link.name(),
                over_allowance,
                of_the_change,
                "a relay had no room for what this device sent; it is kept, and sent again"
            );
        }
        of.no_room = Some(NoRoom {
            at,
            over_allowance,
            of_the_change,
        });
    }

    /// What the device was answered with on `link` is dealt with.
    fn dealt_with(&self, link: &Link) {
        self.leave.dealt_with(link, true);
        let mut kept = lock(&self.kept);
        if kept
            .not_applied
            .as_ref()
            .is_some_and(|(relay, _)| relay == link.name())
        {
            kept.not_applied = None;
        }
    }

    // ── One relay's pass ────────────────────────────────────────────

    /// The pass at one relay: each channel of the device's own, in the
    /// order that [`at_relays::channels`] gives.
    async fn relay_pass(&self, link: &Link, kind: Pass) {
        let own = {
            let db = lock(&self.state.db);
            at_relays::channels(&db, &self.state.identity)
        };
        let own = match own {
            Ok(own) => own,
            Err(e) => {
                tracing::debug!(error = %e, "could not read this device's channels");
                return;
            }
        };
        let whole = kind == Pass::Whole;
        for channel in &own {
            let mut read_to_its_end = false;
            if whole && channel.is_pulled() {
                match self.prove(link, channel, true).await {
                    Step::Done(true) => {}
                    Step::Done(false) => continue,
                    Step::Stop => return,
                }
                match self.pull(link, channel).await {
                    Step::Done(caught_up) => read_to_its_end = caught_up,
                    Step::Stop => return,
                }
            }
            let sent = match self.push(link, channel, Which::Since).await {
                Step::Done(sent) => sent,
                Step::Stop => return,
            };
            // What was carried into a name goes after the channel was
            // fetched from the relay, and after what came since (§7.3).
            if read_to_its_end
                && sent
                && matches!(channel.kind, Kind::Name(_))
                && matches!(self.push(link, channel, Which::Carried).await, Step::Stop)
            {
                return;
            }
        }
        if whole {
            self.prove_listed(link, own.len()).await;
        }
    }

    /// Ask `request` on a stream for a channel of the device's own, on
    /// `link`. Where there is no leave that a show gives, the device shows
    /// again, and asks once more.
    async fn through<R, T>(
        &self,
        link: &Link,
        request: &WireMessage,
        read: impl Fn(WireMessage) -> R,
        take: impl Fn(&Connection, R) -> T,
    ) -> Result<T, Refused> {
        let db = &self.state.db;
        match self.leave.open(db, link, request, &read, &take).await {
            Err(Refused::NoLeave(NoLeave::NotGiven)) => {
                self.show_at(link).await;
                self.leave.open(db, link, request, &read, &take).await
            }
            done => done,
        }
    }

    /// Prove the key of `channel` on `link`, where it was not proved
    /// there within the day (decision 2026-10-04 §2.4 item 3, §2.5).
    /// `held` says that the device holds the channel: a relay that
    /// answers no does not hold it, and is sent it from the start.
    ///
    /// What is remembered is that the proof was made and answered, and
    /// not what was answered: a relay remembers a proof that held for a
    /// channel it does not hold yet.
    async fn prove(&self, link: &Link, channel: &Own, held: bool) -> Step {
        let now = self.clock.now();
        {
            let kept = lock(&self.kept);
            let proved = kept.links.get(&link.id()).map(|of| &of.proved);
            let lately = proved
                .and_then(|proved| proved.get(&channel.id))
                .is_some_and(|at| now.saturating_duration_since(*at) < PROOF_AGAIN);
            if lately {
                return Step::Done(true);
            }
            // A relay remembers so many channels for a connection, and
            // looks at no proof beyond them.
            let room = proved.is_none_or(|proved| {
                proved.contains_key(&channel.id)
                    || proved.len() < MAX_CHANNELS_PROVED_ON_A_CONNECTION
            });
            if !room {
                return Step::Done(false);
            }
        }
        let own_key = self.state.identity.public_key();
        let Some(proof) = link
            .session()
            .and_then(|session| channel.proof(&session, &own_key))
        else {
            return Step::Done(false);
        };
        let request = WireMessage::ChannelProve(ChannelProve {
            channel: channel.id,
            proof,
        });
        let relay = link.relay().0;
        let answered = self
            .through(
                link,
                &request,
                |answer| match answer {
                    WireMessage::ChannelProved(proved) => Some(proved.proved),
                    _ => None,
                },
                |db, proved| {
                    if proved == Some(false) && held {
                        let _ = at_relays::not_held_at(db, &relay, &channel.id);
                    }
                    proved
                },
            )
            .await;
        match answered {
            Ok(Some(_)) => {
                let mut kept = lock(&self.kept);
                let of = kept.links.entry(link.id()).or_default();
                of.proved.insert(channel.id, now);
                kept.relays
                    .entry(link.name().to_string())
                    .or_default()
                    .counts
                    .proofs += 1;
                Step::Done(true)
            }
            Ok(None) => Step::Done(false),
            Err(_) => Step::Stop,
        }
    }

    /// Once a day on a connection, prove the channel of every name that
    /// the personal channel lists and that the device does not hold
    /// (decision 2026-10-04 §2.5): a name whose only device is gone is
    /// not dropped while any device of the person's is on. `own` is how
    /// many channels the device holds: with those, at most as many as a
    /// relay remembers for a connection.
    async fn prove_listed(&self, link: &Link, own: usize) {
        let now = self.clock.now();
        let due = lock(&self.kept)
            .links
            .get(&link.id())
            .and_then(|of| of.listed_proved)
            .is_none_or(|at| now.saturating_duration_since(at) >= PROOF_AGAIN);
        if !due {
            return;
        }
        let most = MAX_CHANNELS_PROVED_ON_A_CONNECTION.saturating_sub(own);
        let listed = at_relays::listed(&lock(&self.state.db), most);
        let Ok(listed) = listed else { return };
        for channel in &listed {
            if !matches!(self.prove(link, channel, false).await, Step::Done(true)) {
                return;
            }
        }
        lock(&self.kept)
            .links
            .entry(link.id())
            .or_default()
            .listed_proved = Some(now);
    }

    /// Pull `channel` from the relay at `link`, from the place that the
    /// device keeps there: so many pages in one pass, each through the
    /// one door, with its place (decision 2026-10-04 §2.4 item 3, §16).
    /// Says whether the channel was read to its end.
    async fn pull(&self, link: &Link, channel: &Own) -> Step {
        let relay = link.relay().0;
        for _ in 0..RELAY_ENTRY_PULL_PAGES {
            let place = at_relays::place(&lock(&self.state.db), &relay, &channel.id);
            let Ok((mark, after)) = place else {
                return Step::Done(false);
            };
            let request = WireMessage::EntryPull(EntryPull {
                channel: channel.id,
                mark,
                after,
                limit: ENTRY_PAGE_MAX_ENTRIES,
            });
            let now = self.clock.unix();
            let taken = self
                .through(
                    link,
                    &request,
                    |answer| {
                        let WireMessage::EntryPulled(page) = answer else {
                            return None;
                        };
                        // A page is bounded where it is read, and again
                        // here. Each entry is checked as whatever a
                        // device is sent is checked: one that fails makes
                        // this no page.
                        if page.entries.len() > ENTRY_PAGE_MAX_ENTRIES as usize {
                            return None;
                        }
                        let entries: Option<Vec<CheckedEntry>> = page
                            .entries
                            .iter()
                            .map(|bytes| Entry::from_wire(bytes).ok()?.check().ok())
                            .collect();
                        Some((entries?, page.mark, page.next))
                    },
                    |db, page| {
                        let (entries, mark, next) = page?;
                        let page = Page {
                            relay: &relay,
                            channel,
                            entries: &entries,
                            mark,
                            next,
                        };
                        match at_relays::take_page(db, &self.state.identity, &page, now) {
                            Ok(PageTaken::Taken { read_again, .. }) => {
                                Some((entries.len(), read_again))
                            }
                            Ok(PageTaken::NotThePage) => None,
                            Err(e) => {
                                tracing::debug!(error = %e, "could not take a page");
                                None
                            }
                        }
                    },
                )
                .await;
            match taken {
                Ok(Some((0, _))) => return Step::Done(true),
                Ok(Some((entries, read_again))) => {
                    let mut kept = lock(&self.kept);
                    let of = kept.relays.entry(link.name().to_string()).or_default();
                    of.counts.pages += 1;
                    of.counts.pulled += entries as u64;
                    if read_again {
                        tracing::debug!(
                            relay = link.name(),
                            "a key came to count, or to may add: every channel is read again from the start"
                        );
                    }
                }
                // What came back was no page of the channel: it is left
                // for the next pass.
                Ok(None) => return Step::Done(false),
                Err(_) => return Step::Stop,
            }
        }
        Step::Done(false)
    }

    /// Push to the relay at `link` what it has not been sent of
    /// `channel`, and act on each answer (decision 2026-10-04 §2.4 items
    /// 1 and 2, §7.3). Says whether everything was sent.
    async fn push(&self, link: &Link, channel: &Own, which: Which) -> Step {
        let relay = link.relay().0;
        loop {
            if self.is_left(&relay, &channel.id) {
                return Step::Done(false);
            }
            let Some(bytes) = self.room_to_push(link) else {
                return Step::Done(false);
            };
            let most = Most {
                entries: ENTRY_PAGE_MAX_ENTRIES as usize,
                bytes,
            };
            let batch = {
                let db = lock(&self.state.db);
                at_relays::to_send(&db, &self.state.identity, &relay, channel, which, most)
            };
            let batch = match batch {
                Ok(batch) if batch.is_empty() => return Step::Done(true),
                Ok(batch) => batch,
                Err(e) => {
                    tracing::debug!(error = %e, "could not read what to send");
                    return Step::Done(false);
                }
            };
            // Nothing of it is sent: what was passed over is said so.
            if batch.entries.is_empty() {
                let db = lock(&self.state.db);
                if at_relays::sent(&db, &relay, channel, &batch, &[]).is_err() {
                    return Step::Done(false);
                }
                continue;
            }
            let done = match self.push_batch(link, channel, &batch).await {
                Ok(Some(done)) => done,
                Ok(None) => return Step::Done(false),
                Err(_) => return Step::Stop,
            };
            if done.do_not_check > 0 {
                tracing::warn!(
                    relay = link.name(),
                    entries = done.do_not_check,
                    "a relay refused entries as not signed as they must be; they are not sent there again"
                );
            }
            match done.refused {
                Some(refused) => {
                    self.no_room(link, refused == Pushed::OverAllowance, false);
                    self.leave_for_a_while(&relay, &channel.id);
                    return Step::Done(false);
                }
                None if done == Sent::default() => return Step::Done(false),
                None => {
                    lock(&self.kept).left.remove(&(relay, channel.id));
                }
            }
        }
    }

    /// Push one batch, and tell the store what the relay answered.
    /// `None` where what came back was no answer to it.
    async fn push_batch(
        &self,
        link: &Link,
        channel: &Own,
        batch: &Batch,
    ) -> Result<Option<Sent>, Refused> {
        let relay = link.relay().0;
        let request = WireMessage::EntryPush(EntryPush {
            entries: batch
                .entries
                .iter()
                .map(|entry| entry.to_wire().into())
                .collect(),
        });
        let cost: u64 = batch
            .entries
            .iter()
            .map(|entry| entry_cost(entry.content.len()))
            .sum();
        {
            let mut kept = lock(&self.kept);
            paced(kept.relays.entry(link.name().to_string()).or_default()).record(cost);
        }
        let sent = batch.entries.len();
        let done = self
            .through(
                link,
                &request,
                |answer| {
                    let WireMessage::EntryPushed(pushed) = answer else {
                        return None;
                    };
                    // One answer for each entry, or the answer says
                    // nothing of any.
                    if pushed.answers.len() != sent {
                        return None;
                    }
                    let answers: Vec<Pushed> = pushed.answers.iter().map(pushed_as).collect();
                    Some(answers)
                },
                |db, answers| {
                    let answers = answers?;
                    at_relays::sent(db, &relay, channel, batch, &answers).ok()
                },
            )
            .await?;
        if done.is_some() {
            let mut kept = lock(&self.kept);
            let of = kept.relays.entry(link.name().to_string()).or_default();
            of.counts.pushes += 1;
            of.counts.pushed += sent as u64;
        }
        Ok(done)
    }

    /// How many bytes may go to the relay at `link` in the next push,
    /// given what went to it in the last minute. `None` where there is
    /// not room for one entry of the largest size.
    fn room_to_push(&self, link: &Link) -> Option<usize> {
        let mut kept = lock(&self.kept);
        let room = paced(kept.relays.entry(link.name().to_string()).or_default()).room();
        (room >= entry_cost(MAX_ITEM_BYTES)).then(|| ENTRY_PAGE_MAX_BYTES.min(room as usize))
    }

    /// Whether `channel` is left for now at `relay`: it found no room
    /// there, and the wait since has not gone by.
    fn is_left(&self, relay: &[u8; 32], channel: &[u8; 32]) -> bool {
        let now = self.clock.now();
        lock(&self.kept)
            .left
            .get(&(*relay, *channel))
            .is_some_and(|left| now < left.until)
    }

    /// `channel` found no room at `relay`: it is left for a while, a
    /// little longer each time, as the node leaves what a relay refuses
    /// today.
    fn leave_for_a_while(&self, relay: &[u8; 32], channel: &[u8; 32]) {
        let now = self.clock.now();
        let mut kept = lock(&self.kept);
        let left = kept.left.entry((*relay, *channel)).or_insert(LeftFor {
            refusals: 0,
            until: now,
        });
        left.refusals = left.refusals.saturating_add(1);
        left.until = now + refused_wait(left.refusals);
    }

    // ── What is kept, and what is said ──────────────────────────────

    /// Forget what was kept of each connection that is gone: a proof, and
    /// what a relay remembers of what it was shown, are for the one
    /// connection.
    fn forget_gone(&self, links: &[&Link]) {
        let mut kept = lock(&self.kept);
        kept.links
            .retain(|id, _| links.iter().any(|link| link.id() == *id));
    }

    /// Say where the device stands at its relays, for a status.
    fn say(&self, relays: &[Relay], stands: Stands) {
        let latest = at_relays::kept_id(&lock(&self.state.db)).ok().flatten();
        let kept = lock(&self.kept);
        let relays = relays
            .iter()
            .map(|relay| {
                let of = kept.relays.get(&relay.name);
                AtRelay {
                    relay: relay.name.clone(),
                    // What it answered of an entry that the device keeps
                    // no more says nothing of the one it keeps now.
                    holds_latest: of
                        .and_then(|of| of.holds)
                        .filter(|(entry, _)| Some(*entry) == latest)
                        .map(|(_, holds)| holds),
                    heard_since_woke: self.leave.has_heard(&relay.name),
                    no_room: of.and_then(|of| of.no_room),
                }
            })
            .collect();
        let cannot_go_on = match stands {
            Stands::NoPhrase => Some(CannotGoOn::NoPhrase),
            Stands::Stopped(State::Removed) => Some(CannotGoOn::Removed),
            Stands::Stopped(State::NotListed) => Some(CannotGoOn::NotListed),
            Stands::Stopped(State::Fork) => Some(CannotGoOn::Fork),
            Stands::Stopped(State::NotOpened) => Some(CannotGoOn::NotOpened),
            Stands::Stopped(State::Applied) | Stands::Applied => kept
                .not_applied
                .clone()
                .map(|(relay, why)| CannotGoOn::NotApplied { relay, why }),
        };
        self.state.own_channels.say(AtRelays {
            relays,
            cannot_go_on,
        });
    }
}

/// What a device has pushed to a relay in the last minute.
fn paced(of: &mut OfRelay) -> &mut ByteCounter {
    of.sent
        .get_or_insert_with(|| ByteCounter::new(Duration::from_secs(60), OUTBOX_BYTES_PER_MINUTE))
}

/// What a relay's answer for one entry means for sending it.
fn pushed_as(answer: &PushAnswer) -> Pushed {
    match answer {
        PushAnswer::Stored | PushAnswer::Held | PushAnswer::Older => Pushed::Holds,
        PushAnswer::Refused(EntryRefused::NotSigned) => Pushed::DoesNotCheck,
        PushAnswer::Refused(EntryRefused::NoRoom) => Pushed::NoRoom,
        PushAnswer::Refused(EntryRefused::OverLimit) => Pushed::OverAllowance,
    }
}

/// How long a channel is left after the `refusals`-th refusal for room in
/// a row: the time between two sends, doubled each time, up to
/// OUTBOX_REFUSED_RETRY_MAX_SECS.
fn refused_wait(refusals: u32) -> Duration {
    let secs = OUTBOX_FLUSH_INTERVAL_SECS
        .saturating_mul(1u64 << refusals.min(16))
        .min(OUTBOX_REFUSED_RETRY_MAX_SECS);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A channel that finds no room is left a little longer each time, up
    /// to ten minutes.
    #[test]
    fn a_channel_that_found_no_room_is_left_a_little_longer_each_time() {
        let waits: Vec<u64> = (1..=10).map(|n| refused_wait(n).as_secs()).collect();
        assert_eq!(waits, [4, 8, 16, 32, 64, 128, 256, 512, 600, 600]);
        assert_eq!(refused_wait(u32::MAX).as_secs(), 600);
    }

    /// Each answer to a push says one of four things for sending: the
    /// relay holds the entry, whichever way; it does not check; there is
    /// no room; or the address is over its allowance.
    #[test]
    fn each_answer_to_a_push_is_read_as_what_it_means_for_sending() {
        for holds in [PushAnswer::Stored, PushAnswer::Held, PushAnswer::Older] {
            assert_eq!(pushed_as(&holds), Pushed::Holds);
        }
        assert_eq!(
            pushed_as(&PushAnswer::Refused(EntryRefused::NotSigned)),
            Pushed::DoesNotCheck
        );
        assert_eq!(
            pushed_as(&PushAnswer::Refused(EntryRefused::NoRoom)),
            Pushed::NoRoom
        );
        assert_eq!(
            pushed_as(&PushAnswer::Refused(EntryRefused::OverLimit)),
            Pushed::OverAllowance
        );
    }
}
