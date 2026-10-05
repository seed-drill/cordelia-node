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
//! [`DeviceEntries::pass`] is run on the node's two timers. **Each relay
//! has its turn in a pass, by itself, and one turn runs at a time at one
//! relay:** a relay that is slow to answer, or does not answer at all,
//! holds up its own turn and no other relay's (§16). What couples the
//! relays is the rule for a device that wakes, below, and nothing else.
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
//! or the wait has gone by. While it wakes, one pass at a time asks the
//! relays, and waits for all of them: that is the rule. Once it is
//! awake, no relay waits for another.
//!
//! ## A show that gets no leave
//!
//! A relay that answers a show with "show it whole" to the whole entry,
//! with word of another that it then does not hand, or with an entry
//! that is behind or that the device refuses, gives no leave, and would
//! be shown the whole entry again at every pass: 33 KB each time. Such a
//! show is made again after a wait that doubles, as what a relay refuses
//! for room is sent again ([`refused_wait`]), for that relay and that
//! entry. An answer that gives leave ends the wait, and so does another
//! entry to show. Where the entry that a relay answered with is one that
//! the device refuses, what a status reads says so for that relay.
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
use cordelia_api::take::Taken;
use cordelia_core::protocol::{
    CHANNEL_PROOF_AGAIN_SECS, ENTRY_OVERHEAD_BYTES, ENTRY_PAGE_MAX_BYTES, ENTRY_PAGE_MAX_ENTRIES,
    ENTRY_WIRE_OVERHEAD_BYTES, MAX_CHANNELS_PROVED_ON_A_CONNECTION, MAX_ITEM_BYTES,
    OUTBOX_BYTES_PER_MINUTE, OUTBOX_FLUSH_INTERVAL_SECS, OUTBOX_REFUSED_RETRY_MAX_SECS,
    PUSH_BYTES_PER_PEER_PER_MINUTE, RELAY_ENTRY_PULL_PAGES, entry_cost,
};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_network::messages::{
    ChannelProve, EntryPull, EntryPush, EntryRefused, PushAnswer, ShowAnswer, WireMessage,
};
use cordelia_network::rate_limit::ByteCounter;
use cordelia_storage::entries::Outcome;
use cordelia_storage::person::State;
use cordelia_storage::relay::{Mark, NO_MARK};
use rusqlite::Connection;

pub use leave::{Asked, Clock, Leave, Link, LinkId, NoLeave, Refused};

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

/// Where a pass asks: a connection to a relay, and what the change entry
/// was named by that the device kept when the pass read its channels.
struct At<'a> {
    link: &'a Link,
    under: [u8; 32],
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
    /// How many entries of the device's own it said it holds in another
    /// form.
    another_form: usize,
    /// The entry whose show last got no leave there, by what it is named
    /// by, how often in a row, and when it is shown there again.
    show_left: Option<([u8; 32], LeftFor)>,
    /// Why the device refuses the entry that the relay last answered a
    /// show with, where it does.
    refuses: Option<String>,
    counts: Counts,
    /// What was pushed to it in the last minute: a device paces itself,
    /// so that it is never the one refused for going over.
    sent: Option<ByteCounter>,
    /// What it handed in pages in the last minute: a device takes from
    /// one relay no more than a relay may hand a connection.
    taken: Option<ByteCounter>,
}

/// What became of the shows of one round at a relay.
#[derive(Default)]
struct Round {
    /// What the entry that was shown last is named by.
    entry: Option<[u8; 32]>,
    /// Whether an entry was shown whole.
    whole: bool,
    /// Whether the relay answered any of them.
    answered: bool,
}

/// A channel that found no room at a relay, or a show that got no leave
/// there: how often in a row, and when it is sent or made there again.
struct LeftFor {
    refusals: u32,
    until: Instant,
}

/// What a relay refused, for room, of one part of a channel (decision
/// 2026-10-04 §16).
struct Left {
    wait: LeftFor,
    /// Whether nothing of it is sent until the wait has gone by: the
    /// relay stopped there, at a channel it would not begin or at what
    /// was carried. Otherwise only what it refused waits, and what
    /// follows is still offered.
    all: bool,
}

/// A relay by its key, a channel by its ID, and the part of it.
type Part = ([u8; 32], [u8; 32], Which);

/// A change that the device was answered with and could not apply
/// (decision 2026-10-04 §4.2): it is kept, whatever becomes of the
/// connection it came on, and tried again at each pass.
struct NotApplied {
    /// The relay that answered with it, by its name.
    relay: String,
    /// Why it could not be applied, as the last try said.
    why: String,
    /// The entry that was shown, and the one that the relay answered
    /// with.
    shown: CheckedEntry,
    answer: CheckedEntry,
}

#[derive(Default)]
struct Kept {
    links: HashMap<LinkId, OfLink>,
    relays: HashMap<String, OfRelay>,
    /// What a relay refused for room, and when it is sent there again.
    left: HashMap<Part, Left>,
    /// A change that the device was answered with and could not apply.
    not_applied: Option<NotApplied>,
}

/// A device's side of its relays, for the channels of its own (see the
/// module's documentation).
pub struct DeviceEntries {
    state: Arc<AppState>,
    clock: Clock,
    leave: Leave,
    kept: Mutex<Kept>,
    /// While the device wakes, one pass at a time asks every relay first.
    waking: tokio::sync::Mutex<()>,
    /// One turn at a time at each relay, by the relay's name.
    turns: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl DeviceEntries {
    /// For the node whose state is `state`, reading the time from `clock`.
    pub fn new(state: Arc<AppState>, clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            state,
            leave: Leave::new(clock.clone()),
            clock,
            kept: Mutex::default(),
            waking: tokio::sync::Mutex::new(()),
            turns: Mutex::default(),
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
    /// with, each with its connection where there is one.
    ///
    /// Each relay has its turn, and the turns run beside one another: it
    /// comes back when each has ended. A relay at which a turn of an
    /// earlier pass is still running is left out of this one, and no
    /// other relay waits for it.
    pub async fn pass(self: &Arc<Self>, relays: &[Relay], kind: Pass) {
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
        // A change that could not be applied is tried again, whichever
        // relays are reached now.
        self.try_again();

        let whole = kind == Pass::Whole;
        if whole {
            self.hand_overs();
            self.forget_done(relays);
        }
        // A device that was removed, is in no list, or could not open a
        // change shows nothing: it takes no change entry, and the way on
        // is a person's.
        if matches!(stands, Stands::Stopped(state) if state != State::Fork) {
            self.say(relays, stands);
            return;
        }

        // A device that wakes asks every relay first, in either pass, and
        // does nothing more until each has answered or the wait has gone
        // by (§4.6). That is the one thing that couples its relays: while
        // it wakes, one pass asks them all, and waits for them all.
        let mut shown: HashMap<LinkId, bool> = HashMap::new();
        if self.leave.is_waking() {
            let Ok(_waking) = self.waking.try_lock() else {
                return;
            };
            let mut shows = tokio::task::JoinSet::new();
            for link in &links {
                if whole || !self.leave.has_heard(link.name()) {
                    let (engine, link) = (Arc::clone(self), (*link).clone());
                    shows.spawn(async move { (link.id(), engine.show_at(&link).await) });
                }
            }
            while let Some(done) = shows.join_next().await {
                if let Ok((link, gave_leave)) = done {
                    shown.insert(link, gave_leave);
                }
            }
            if self.leave.is_waking() {
                self.say(relays, stands);
                return;
            }
        }

        // Awake: each relay has its turn, and none waits for another.
        let mut turns = tokio::task::JoinSet::new();
        for link in &links {
            let shown = shown.get(&link.id()).copied();
            let (engine, link) = (Arc::clone(self), (*link).clone());
            turns.spawn(async move { engine.turn(&link, kind, shown).await });
        }
        while turns.join_next().await.is_some() {}
        let stands = at_relays::stands(&lock(&self.state.db)).unwrap_or(stands);
        self.say(relays, stands);
    }

    /// One relay's turn in a pass: the show, where the pass makes one,
    /// and then the relay's pass. `shown` says that this pass has shown
    /// on the connection
    /// already, while the device woke, and whether that show gave leave.
    ///
    /// One turn runs at a time at a relay. A turn that finds another
    /// running there does nothing: that one is waiting for the relay,
    /// and a second would wait with it.
    ///
    /// The whole pass shows on every connection. Where the answer to
    /// this turn's show gave no leave, the relay is left for the next
    /// pass: it is what the relay answered here and now that is asked,
    /// and not how long ago another relay answered. The pass that sends
    /// makes no show of its own, and shows where it finds something to
    /// send and no leave.
    async fn turn(&self, link: &Link, kind: Pass, shown: Option<bool>) {
        let turn = {
            let mut turns = lock(&self.turns);
            Arc::clone(turns.entry(link.name().to_string()).or_default())
        };
        let Ok(_turn) = turn.try_lock() else {
            return;
        };
        let whole = kind == Pass::Whole;
        let gave_leave = match shown {
            Some(gave_leave) => Some(gave_leave),
            None if whole => Some(self.show_at(link).await),
            None => None,
        };
        // (A device that has stopped, or is in a fork, has no channel
        // that a pass goes through. And one that wakes while this turn
        // runs has no leave from then on, anywhere: the one way in
        // refuses what the turn asks.)
        if whole && gave_leave != Some(true) {
            return;
        }
        self.relay_pass(link, kind).await;
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

    // ── What is kept for nothing ────────────────────────────────────

    /// Forget what is kept of the relays and has no more use, in the
    /// store and in memory, since nothing else does (decision 2026-10-04
    /// §6, §16): of a relay that the device is no longer set up with, of
    /// a pair channel whose delete went everywhere, and of a channel that
    /// is the device's no longer.
    ///
    /// Which relays the device is set up with is known by their keys
    /// while every one of them is connected, and not otherwise: nothing
    /// is forgotten of any relay then. `relays` may be fewer than the
    /// node is configured with, since a relay whose name does not
    /// resolve is not among them: every one is connected where each of
    /// `relays` is, and they are as many as the node said it is
    /// configured with.
    fn forget_done(&self, relays: &[Relay]) {
        let configured = self.state.own_channels.relays_set_up();
        let set_up: Option<Vec<[u8; 32]>> = relays
            .iter()
            .map(|relay| {
                let link = relay.link.as_ref().filter(|link| link.is_open())?;
                Some(link.relay().0)
            })
            .collect();
        let set_up = set_up.filter(|keys| Some(keys.len()) == configured);
        let own = {
            let db = lock(&self.state.db);
            let own = &self.state.identity;
            match at_relays::forget_what_is_done(&db, own, set_up.as_deref()) {
                Ok(forgotten) if forgotten == Default::default() => {}
                Ok(forgotten) => tracing::debug!(
                    relays = forgotten.relays,
                    pair_channels = forgotten.pairs,
                    "what was kept of relays that are set up no longer, and of pair channels whose delete went everywhere, is forgotten"
                ),
                Err(e) => tracing::debug!(error = %e, "could not forget what is kept for nothing"),
            }
            at_relays::channels(&db, own)
        };
        let Ok(own) = own else {
            return;
        };
        let own: Vec<[u8; 32]> = own.iter().map(|channel| channel.id).collect();
        lock(&self.kept)
            .left
            .retain(|part, _| still_of_use(part, set_up.as_deref(), &own));
    }

    // ── A change that could not be applied ──────────────────────────

    /// Try again the change that the device was answered with and could
    /// not apply, where there is one (decision 2026-10-04 §4.2): at each
    /// pass, whatever became of the connection it came on. Until it is
    /// dealt with, there is no leave anywhere.
    fn try_again(&self) {
        let Some((shown, answer)) = lock(&self.kept)
            .not_applied
            .as_ref()
            .map(|kept| (kept.shown.clone(), kept.answer.clone()))
        else {
            return;
        };
        let now = self.clock.unix();
        let outcome = {
            let db = lock(&self.state.db);
            at_relays::answered(&db, &self.state.identity, &shown, &answer, now)
        };
        match outcome {
            // The entry went through the one door, and the device did
            // with it what a change entry has it do: nothing waits now.
            Ok(done) => {
                tracing::info!(?done, "a change that could not be applied was dealt with");
                self.applied();
            }
            Err(e) => {
                if let Some(kept) = &mut lock(&self.kept).not_applied {
                    kept.why = e.to_string();
                }
            }
        }
    }

    /// The device has no change that it was answered with and has not
    /// applied.
    fn applied(&self) {
        lock(&self.kept).not_applied = None;
        self.leave.could_not_apply(false);
    }

    // ── The show ────────────────────────────────────────────────────

    /// Show the change entry that the device keeps on `link`, and deal
    /// with what it is answered, until an answer leaves nothing more to
    /// show (decision 2026-10-04 §2.4 item 5, §4.6). Returns whether the
    /// last answer gave leave to use the connection.
    ///
    /// Where the relay answered, the entry was shown whole, and there is
    /// no leave, the show is made again there only after a wait, a little
    /// longer each time (§16): nothing is shown while it lasts. An answer
    /// that gives leave ends it.
    async fn show_at(&self, link: &Link) -> bool {
        let mut round = Round::default();
        let gave_leave = self.show_round(link, &mut round).await;
        let now = self.clock.now();
        let mut kept = lock(&self.kept);
        let of = kept.relays.entry(link.name().to_string()).or_default();
        if gave_leave {
            of.show_left = None;
            of.refuses = None;
        } else if let (true, true, Some(entry)) = (round.whole, round.answered, round.entry) {
            let refusals = match &of.show_left {
                Some((shown, left)) if *shown == entry => left.refusals.saturating_add(1),
                _ => 1,
            };
            let until = now + refused_wait(refusals);
            of.show_left = Some((entry, LeftFor { refusals, until }));
        }
        gave_leave
    }

    /// Whether a show of the entry named `entry` waits at the relay
    /// called `relay`: its last show there got no leave, and the wait
    /// since has not gone by.
    fn show_waits(&self, relay: &str, entry: &[u8; 32]) -> bool {
        let now = self.clock.now();
        lock(&self.kept)
            .relays
            .get(relay)
            .and_then(|of| of.show_left.as_ref())
            .is_some_and(|(shown, left)| shown == entry && now < left.until)
    }

    /// [`Self::show_at`], for one round of shows, with what became of
    /// them said in `round`.
    async fn show_round(&self, link: &Link, round: &mut Round) -> bool {
        // The entry is shown whole where it was not yet on this
        // connection, where the relay asks for it, and where the relay
        // tells of another that the device does not keep.
        let mut whole = false;
        for _ in 0..SHOWS_IN_A_PASS {
            let shows = match at_relays::to_show(&lock(&self.state.db)) {
                Ok(Some(shows)) => shows,
                Ok(None) => return false,
                Err(e) => {
                    tracing::debug!(error = %e, "could not read the change entry to show");
                    return false;
                }
            };
            let entry = &shows.entry;
            round.entry = Some(entry.id());
            if self.show_waits(link.name(), &entry.id()) {
                return false;
            }
            let shown_whole = lock(&self.kept)
                .links
                .get(&link.id())
                .and_then(|of| of.shown_whole);
            let short = !whole && shown_whole == Some(entry.id());
            round.whole |= !short;
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
                    return false;
                }
            };
            round.answered = true;
            self.shown(link, entry, short, answered.bytes);
            match answered.answer {
                ShowAnswer::Held | ShowAnswer::Taken => {
                    self.holds(link, entry, true);
                    return true;
                }
                ShowAnswer::Refused(EntryRefused::NoRoom | EntryRefused::OverLimit) => {
                    // The relay holds none, or an earlier one, and would
                    // have taken this one: it holds no later change.
                    let over_allowance =
                        answered.answer == ShowAnswer::Refused(EntryRefused::OverLimit);
                    self.holds(link, entry, false);
                    self.no_room(link, over_allowance, true);
                    return true;
                }
                ShowAnswer::Refused(EntryRefused::NotSigned) => {
                    tracing::warn!(
                        relay = link.name(),
                        "a relay says that the change entry this device keeps is not signed as it must be"
                    );
                    return false;
                }
                ShowAnswer::Whole if short => whole = true,
                // "Show it whole" is no answer to the whole entry.
                ShowAnswer::Whole => return false,
                ShowAnswer::Other { id, .. } => {
                    // The relay holds another. One that the device keeps,
                    // made apart from its own, it asks no more about. For
                    // any other it shows its own whole, and is answered
                    // with the entry.
                    self.holds(link, entry, false);
                    if !short || shows.apart == Some(id) {
                        return false;
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
                        return false;
                    };
                    if !self.answered_with(link, entry, &another) {
                        return false;
                    }
                    // It applied the change: it shows what it keeps now.
                    whole = false;
                }
            }
        }
        false
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
                self.applied();
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
                // An entry that is no change entry this device takes, held
                // by the relay in the place of its own: the relay gives
                // no leave for as long as it holds it, and the status
                // says so.
                if let cordelia_api::person::Refused::NotAChangeEntry(why) = &why {
                    let mut kept = lock(&self.kept);
                    let of = kept.relays.entry(relay.to_string()).or_default();
                    of.refuses = Some(why.to_string());
                }
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
            // sends nor takes anywhere until it has. The entry is kept,
            // and tried again at each pass.
            Err(e) => {
                tracing::warn!(relay, error = %e, "could not apply the change that a relay answered with");
                self.leave.could_not_apply(true);
                lock(&self.kept).not_applied = Some(NotApplied {
                    relay: relay.to_string(),
                    why: e.to_string(),
                    shown: shown.clone(),
                    answer: another.clone(),
                });
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

    // ── One relay's pass ────────────────────────────────────────────

    /// The pass at one relay: each channel of the device's own, in the
    /// order that [`at_relays::channels`] gives.
    ///
    /// The channels are those of the statement whose change entry the
    /// device keeps when the pass begins, and each request of the pass is
    /// built under that entry ([`Leave::open`]). Where the device comes
    /// to keep another, by a show on this connection or on any other,
    /// the pass ends there: the next reads the device's channels afresh.
    async fn relay_pass(&self, link: &Link, kind: Pass) {
        let read = {
            let db = lock(&self.state.db);
            let own = at_relays::channels(&db, &self.state.identity);
            own.and_then(|own| Ok((own, at_relays::kept_id(&db)?)))
        };
        let (own, under) = match read {
            Ok((own, Some(under))) => (own, under),
            Ok((_, None)) => return,
            Err(e) => {
                tracing::debug!(error = %e, "could not read this device's channels");
                return;
            }
        };
        let at = At { link, under };
        let whole = kind == Pass::Whole;
        for channel in &own {
            let mut read_to_its_end = false;
            if whole && channel.is_pulled() {
                match self.prove(&at, channel, true).await {
                    Step::Done(true) => {}
                    Step::Done(false) => continue,
                    Step::Stop => return,
                }
                match self.pull(&at, channel).await {
                    Step::Done(caught_up) => read_to_its_end = caught_up,
                    Step::Stop => return,
                }
            }
            let sent = match self.push(&at, channel, Which::Since).await {
                Step::Done(sent) => sent,
                Step::Stop => return,
            };
            // What was carried into a name goes after the channel was
            // fetched from the relay, and after what came since (§7.3).
            if read_to_its_end
                && sent
                && matches!(channel.kind, Kind::Name(_))
                && matches!(self.push(&at, channel, Which::Carried).await, Step::Stop)
            {
                return;
            }
        }
        if whole {
            self.prove_listed(&at, own.len()).await;
        }
    }

    /// Ask `request` on a stream for a channel of the device's own, at
    /// `at`. Where there is no leave that a show gives, the device shows
    /// again, and asks once more. Where that show had it apply a change,
    /// it keeps another entry than the one the request was built under:
    /// the one way in refuses the request then, as it refuses any that
    /// was built under an entry the device keeps no more, and the pass
    /// at this relay ends (decision 2026-10-04 §16).
    ///
    /// `opened` is called under the database's lock once a stream is
    /// about to be opened, and not for one that is refused.
    async fn through<R, T>(
        &self,
        at: &At<'_>,
        request: &WireMessage,
        opened: impl Fn(&Connection),
        read: impl Fn(WireMessage) -> R,
        take: impl Fn(&Connection, R) -> T,
    ) -> Result<T, Refused> {
        let db = &self.state.db;
        let asked = Asked {
            under: &at.under,
            request,
        };
        let link = at.link;
        let open = || self.leave.open(db, link, asked, &opened, &read, &take);
        match open().await {
            Err(Refused::NoLeave(NoLeave::NotGiven)) => {
                self.show_at(link).await;
                open().await
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
    async fn prove(&self, at: &At<'_>, channel: &Own, held: bool) -> Step {
        let link = at.link;
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
                at,
                &request,
                |_| (),
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
    async fn prove_listed(&self, at: &At<'_>, own: usize) {
        let link = at.link;
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
            if !matches!(self.prove(at, channel, false).await, Step::Done(true)) {
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
    ///
    /// **A pull goes on only while it gets somewhere** (§16). A page that
    /// does not move the device's place in the relay's holding, or that
    /// comes under no mark and holds nothing the store did not hold, ends
    /// the channel's pull for this pass: a relay that hands the same page
    /// again and again is asked once a pass, and not ten times. And what
    /// a device takes from one relay in a minute is bounded at what a
    /// relay may hand a connection, counted for the relay and not for
    /// the connection: a new connection has no allowance of its own.
    async fn pull(&self, at: &At<'_>, channel: &Own) -> Step {
        let link = at.link;
        let relay = link.relay().0;
        for _ in 0..RELAY_ENTRY_PULL_PAGES {
            if !self.room_to_take(link) {
                return Step::Done(false);
            }
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
                    at,
                    &request,
                    |_| (),
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
                        // What the relay handed counts as taken from it,
                        // whatever is then done with it.
                        let handed: u64 = page
                            .entries
                            .iter()
                            .map(|bytes| counted_as_handed(bytes.len()))
                            .sum();
                        self.took(link, handed);
                        let entries: Option<Vec<CheckedEntry>> = page
                            .entries
                            .iter()
                            .map(|bytes| Entry::from_wire(bytes).ok()?.check().ok())
                            .collect();
                        Some((entries?, page.mark, page.next))
                    },
                    |db, page| {
                        let (entries, page_mark, next) = page?;
                        let page = Page {
                            relay: &relay,
                            channel,
                            entries: &entries,
                            mark: page_mark,
                            next,
                        };
                        match at_relays::take_page(db, &self.state.identity, &page, now) {
                            Ok(PageTaken::Taken { each, read_again }) => Some(PageSeen {
                                entries: entries.len(),
                                read_again,
                                got_somewhere: got_somewhere(
                                    (mark, after),
                                    (page_mark, next),
                                    &each,
                                    read_again,
                                ),
                            }),
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
                Ok(Some(page)) if page.entries == 0 => return Step::Done(true),
                Ok(Some(page)) => {
                    let mut kept = lock(&self.kept);
                    let of = kept.relays.entry(link.name().to_string()).or_default();
                    of.counts.pages += 1;
                    of.counts.pulled += page.entries as u64;
                    if page.read_again {
                        tracing::debug!(
                            relay = link.name(),
                            "a key came to count, or to may add: every channel is read again from the start"
                        );
                    }
                    // A page that got nowhere: the channel is left for
                    // the next pass.
                    if !page.got_somewhere {
                        return Step::Done(false);
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
    ///
    /// The device goes on past an entry that the relay has no room for
    /// (§16): what follows it is still offered, at this pass and at each
    /// one after, and the entry is offered again once a wait has gone
    /// by, which doubles each time. Where the relay will not begin the
    /// channel, nothing of it is offered until then.
    async fn push(&self, at: &At<'_>, channel: &Own, which: Which) -> Step {
        let link = at.link;
        let relay = link.relay().0;
        let part = (relay, channel.id, which);
        let mut again = match self.left(&part) {
            Some(true) => return Step::Done(false),
            Some(false) => false,
            None => true,
        };
        loop {
            let Some(bytes) = self.room_to_push(link) else {
                return Step::Done(false);
            };
            let most = Most {
                entries: ENTRY_PAGE_MAX_ENTRIES as usize,
                bytes,
            };
            let batch = {
                let db = lock(&self.state.db);
                let own = &self.state.identity;
                at_relays::to_send(&db, own, &relay, channel, which, most, again)
            };
            let batch = match batch {
                Ok(batch) if batch.is_empty() => {
                    // Nothing waits there: no wait is kept.
                    if !batch.waits {
                        lock(&self.kept).left.remove(&part);
                    }
                    return Step::Done(!batch.waits);
                }
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
            let done = match self.push_batch(at, channel, &batch).await {
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
            if done.another > 0 {
                tracing::warn!(
                    relay = link.name(),
                    entries = done.another,
                    "a relay holds entries of this device's own in another form, at their revisions; they are not sent there again, and the next edit goes above both"
                );
                let mut kept = lock(&self.kept);
                let of = kept.relays.entry(link.name().to_string()).or_default();
                of.another_form += done.another;
            }
            let stopped = done.refused.is_some();
            if stopped || done.no_room > 0 {
                self.no_room(link, done.refused == Some(Pushed::OverAllowance), false);
                // The wait begins, or doubles, once for what was offered:
                // and not for what is refused while it lasts.
                if again || stopped {
                    self.leave_for_a_while(part, stopped);
                }
                again = false;
                if stopped {
                    return Step::Done(false);
                }
            } else if done == Sent::default() {
                return Step::Done(false);
            }
        }
    }

    /// Push one batch, and tell the store what the relay answered.
    /// `None` where what came back was no answer to it.
    async fn push_batch(
        &self,
        at: &At<'_>,
        channel: &Own,
        batch: &Batch,
    ) -> Result<Option<Sent>, Refused> {
        let link = at.link;
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
                at,
                &request,
                // That the relay is sent something of a pair channel is
                // kept from before it is sent, whatever comes back: and
                // only once there is leave to send it.
                |db| {
                    if let Err(e) = at_relays::opened_for(db, &relay, channel, batch) {
                        tracing::debug!(error = %e, "could not keep that a relay is sent a channel");
                    }
                },
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

    /// Whether the device takes a page more from the relay at `link`
    /// now: what that relay handed it in the last minute leaves room for
    /// one entry of the largest size, within what a relay may hand a
    /// connection in a minute.
    fn room_to_take(&self, link: &Link) -> bool {
        let mut kept = lock(&self.kept);
        let of = kept.relays.entry(link.name().to_string()).or_default();
        taken_from(of).room() >= entry_cost(MAX_ITEM_BYTES)
    }

    /// The relay at `link` handed a page that is counted at `bytes`.
    fn took(&self, link: &Link, bytes: u64) {
        let mut kept = lock(&self.kept);
        let of = kept.relays.entry(link.name().to_string()).or_default();
        taken_from(of).record(bytes);
    }

    /// How many bytes may go to the relay at `link` in the next push,
    /// given what went to it in the last minute. `None` where there is
    /// not room for one entry of the largest size.
    fn room_to_push(&self, link: &Link) -> Option<usize> {
        let mut kept = lock(&self.kept);
        let room = paced(kept.relays.entry(link.name().to_string()).or_default()).room();
        (room >= entry_cost(MAX_ITEM_BYTES)).then(|| ENTRY_PAGE_MAX_BYTES.min(room as usize))
    }

    /// Whether something of `part` is left for now: the relay found no
    /// room for it, and the wait since has not gone by. `Some(true)`
    /// where nothing of the part is sent until then, and `Some(false)`
    /// where only what the relay refused waits.
    fn left(&self, part: &Part) -> Option<bool> {
        let now = self.clock.now();
        lock(&self.kept)
            .left
            .get(part)
            .filter(|left| now < left.wait.until)
            .map(|left| left.all)
    }

    /// The relay found no room for something of `part`: that is left for
    /// a while, a little longer each time, as the node leaves what a
    /// relay refuses today. `all` says that the relay stopped there, and
    /// nothing of the part is sent until then.
    fn leave_for_a_while(&self, part: Part, all: bool) {
        let now = self.clock.now();
        let mut kept = lock(&self.kept);
        let left = kept.left.entry(part).or_insert(Left {
            wait: LeftFor {
                refusals: 0,
                until: now,
            },
            all,
        });
        left.all = all;
        left.wait.refusals = left.wait.refusals.saturating_add(1);
        left.wait.until = now + refused_wait(left.wait.refusals);
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
                    another_form: of.map_or(0, |of| of.another_form),
                    refuses: of.and_then(|of| of.refuses.clone()),
                }
            })
            .collect();
        let cannot_go_on = match stands {
            Stands::NoPhrase => Some(CannotGoOn::NoPhrase),
            Stands::Stopped(State::Removed) => Some(CannotGoOn::Removed),
            Stands::Stopped(State::NotListed) => Some(CannotGoOn::NotListed),
            Stands::Stopped(State::Fork) => Some(CannotGoOn::Fork),
            Stands::Stopped(State::NotOpened) => Some(CannotGoOn::NotOpened),
            Stands::Stopped(State::Applied) | Stands::Applied => {
                kept.not_applied
                    .as_ref()
                    .map(|kept| CannotGoOn::NotApplied {
                        relay: kept.relay.clone(),
                        why: kept.why.clone(),
                    })
            }
        };
        self.state.own_channels.say(AtRelays {
            relays,
            cannot_go_on,
        });
    }
}

/// What became of a page that a relay handed.
struct PageSeen {
    /// How many entries it held.
    entries: usize,
    /// Whether a key came to count by it, so that every channel is read
    /// again from the start.
    read_again: bool,
    /// Whether the pull got somewhere by it ([`got_somewhere`]).
    got_somewhere: bool,
}

/// Whether a pull got somewhere by a page: it was `asked` from a mark and
/// a place, the page says the mark and the place to ask from next
/// (`told`), and `each` is what became of its entries.
///
/// It did where the place moved on within the holding, or the holding is
/// another than the one asked in. Under the mark of no holding there is
/// no place to move: it did only where the store took an entry that it
/// did not hold. A page by which every channel is read again from the
/// start is one that got somewhere, though every place went back.
fn got_somewhere(asked: (Mark, u64), told: (Mark, u64), each: &[Taken], read_again: bool) -> bool {
    if read_again {
        return true;
    }
    if told.0 == NO_MARK {
        return each.iter().any(|taken| {
            matches!(
                taken,
                Taken::Own {
                    stored: Outcome::Stored,
                    ..
                }
            )
        });
    }
    told.0 != asked.0 || told.1 > asked.1
}

/// What the bytes of an entry that a relay handed are counted at, as the
/// relay counts what it hands: the entry's content, and what an entry
/// takes beyond it.
fn counted_as_handed(wire_bytes: usize) -> u64 {
    entry_cost(wire_bytes.saturating_sub(ENTRY_WIRE_OVERHEAD_BYTES))
}

/// What a relay has handed a device in pages in the last minute, within
/// what a relay may hand a connection in one.
fn taken_from(of: &mut OfRelay) -> &mut ByteCounter {
    of.taken.get_or_insert_with(|| {
        ByteCounter::new(Duration::from_secs(60), PUSH_BYTES_PER_PEER_PER_MINUTE)
    })
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
        PushAnswer::Another => Pushed::HoldsAnother,
        PushAnswer::Refused(EntryRefused::NotSigned) => Pushed::DoesNotCheck,
        PushAnswer::Refused(EntryRefused::NoRoom) => Pushed::NoRoom,
        PushAnswer::Refused(EntryRefused::OverLimit) => Pushed::OverAllowance,
    }
}

/// Whether what is kept in memory of `part` still has a use: its channel
/// is among `own`, the channels of the device's own now, and its relay is
/// among `set_up`, the relays that the device is set up with, where
/// those are known.
fn still_of_use(part: &Part, set_up: Option<&[[u8; 32]]>, own: &[[u8; 32]]) -> bool {
    let (relay, channel, _) = part;
    own.contains(channel) && set_up.is_none_or(|set_up| set_up.contains(relay))
}

/// How long a channel is left after the `refusals`-th refusal for room in
/// a row, and a show after the `refusals`-th in a row that got no leave:
/// the time between two sends, doubled each time, up to
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

    /// What is kept in memory of a relay and a channel is kept while
    /// the channel is the device's own and the relay is one it is set up
    /// with: and, where the relays it is set up with are not all known,
    /// whatever the relay.
    #[test]
    fn what_is_kept_of_a_part_is_of_use_while_its_channel_and_its_relay_are_the_devices() {
        let (relay, other_relay) = ([1u8; 32], [2u8; 32]);
        let (channel, other_channel) = ([3u8; 32], [4u8; 32]);
        for which in [Which::Since, Which::Carried] {
            let part = (relay, channel, which);
            assert!(still_of_use(&part, Some(&[relay]), &[channel]));
            assert!(still_of_use(
                &part,
                Some(&[other_relay, relay]),
                &[other_channel, channel]
            ));
            // The channel is the device's no longer.
            assert!(!still_of_use(&part, Some(&[relay]), &[other_channel]));
            assert!(!still_of_use(&part, Some(&[relay]), &[]));
            assert!(!still_of_use(&part, None, &[other_channel]));
            // The relay is set up no longer.
            assert!(!still_of_use(&part, Some(&[other_relay]), &[channel]));
            assert!(!still_of_use(&part, Some(&[]), &[channel]));
            // Which relays are set up is not known: nothing is forgotten
            // of any.
            assert!(still_of_use(&part, None, &[channel]));
        }
    }

    /// A channel that finds no room is left a little longer each time, up
    /// to ten minutes.
    #[test]
    fn a_channel_that_found_no_room_is_left_a_little_longer_each_time() {
        let waits: Vec<u64> = (1..=10).map(|n| refused_wait(n).as_secs()).collect();
        assert_eq!(waits, [4, 8, 16, 32, 64, 128, 256, 512, 600, 600]);
        assert_eq!(refused_wait(u32::MAX).as_secs(), 600);
    }

    /// A pull got somewhere by a page where its place moved on within the
    /// holding, or the holding is another; under no mark, only where the
    /// store took something new; and always where everything is read
    /// again.
    #[test]
    fn a_pull_gets_somewhere_by_a_page_that_moves_its_place_or_brings_something_new() {
        const MARK: Mark = [7; 8];
        let own = |stored: Outcome| Taken::Own {
            stored,
            record: None,
            came_to_count: 0,
            came_to_add: 0,
        };
        let stored = [own(Outcome::Stored)];
        let held = [own(Outcome::AlreadyHeld)];
        let held_and_stored = [own(Outcome::AlreadyHeld), own(Outcome::Stored)];
        let held_and_refused = [
            own(Outcome::AlreadyHeld),
            Taken::Refused(cordelia_api::take::NotTaken::SignerDoesNotCount),
        ];
        // Within one holding: the place moved on, or it did not.
        assert!(got_somewhere((MARK, 4), (MARK, 5), &held, false));
        assert!(!got_somewhere((MARK, 4), (MARK, 4), &stored, false));
        assert!(!got_somewhere((MARK, 4), (MARK, 3), &stored, false));
        // Another holding than the one asked in, from its start.
        assert!(got_somewhere((MARK, 4), ([8; 8], 0), &held, false));
        assert!(got_somewhere((NO_MARK, 0), (MARK, 1), &held, false));
        // Under no mark: only what the store did not hold.
        assert!(got_somewhere(
            (NO_MARK, 0),
            (NO_MARK, 9),
            &held_and_stored,
            false
        ));
        assert!(!got_somewhere(
            (NO_MARK, 0),
            (NO_MARK, 9),
            &held_and_refused,
            false
        ));
        assert!(!got_somewhere((MARK, 4), (NO_MARK, 9), &held, false));
        // Everything is read again from the start: that is somewhere.
        assert!(got_somewhere((MARK, 4), (MARK, 4), &held, true));
        // What a relay handed is counted as the relay counts it.
        assert_eq!(
            counted_as_handed(ENTRY_WIRE_OVERHEAD_BYTES + 256),
            256 + 1024
        );
        assert_eq!(counted_as_handed(3), entry_cost(0));
    }

    /// Each answer to a push says one of five things for sending: the
    /// relay holds the entry, whichever way; it holds another at that
    /// revision; it does not check; there is no room; or the address is
    /// over its allowance.
    #[test]
    fn each_answer_to_a_push_is_read_as_what_it_means_for_sending() {
        for holds in [PushAnswer::Stored, PushAnswer::Held, PushAnswer::Older] {
            assert_eq!(pushed_as(&holds), Pushed::Holds);
        }
        assert_eq!(pushed_as(&PushAnswer::Another), Pushed::HoldsAnother);
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
