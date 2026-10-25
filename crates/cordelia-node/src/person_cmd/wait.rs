//! The wait after a change, and its three ends (decision 2026-10-19 §4,
//! rule 8).
//!
//! The ends are stated over each relay's class, which the node puts it in
//! ([`cordelia_node::device_entries::reach::class`]) and its look carries,
//! and over the device's own word and the node's `word_to_come`. Nothing
//! here works out a class or a word's conditions again: a command and a
//! node that worked them out apart could disagree, and wait on each other
//! for ever.
//!
//! - **Safety:** ends 1 and 2 need every relay to hold the change. So the
//!   wait never says that the machine may be closed, and never ends with
//!   status 0, while a relay lacks the change.
//! - **Liveness:** where each relay is in a class, and the node will not
//!   write over the device's own word, one end holds. Every other state is
//!   one that time moves (decision 2026-10-19 §1).

use cordelia_api::look::{ReachLook, joined};
use cordelia_api::state::{Class, Holds, LacksFor};
use cordelia_core::protocol::{BACKOFF_BASE_SECS, BOOTNODE_RESOLVE_RETRY_SECS, OUT_OF_REACH_SECS};
use serde_json::Value;

use super::{NOT_AT_EVERY_RELAY_STATUS, is_own, list, text};

/// How the node tries a relay, as its look says (decision 2026-10-19 §5,
/// S9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dial {
    /// It is connected.
    Connected,
    /// It is not connected, and is dialled.
    Dialled,
    /// Its name does not resolve: it is looked up.
    LookedUp,
    /// Another relay answers at its address: it is not dialled.
    NotDialled,
    /// It is given no key, at the place of a relay given one: it is never
    /// reached.
    NoKey,
}

/// One relay that the device is set up with, as the look shows it.
#[derive(Debug, Clone)]
pub(crate) struct RelayAt {
    /// The name that the configuration gives it.
    pub name: String,
    /// What the node knows of its reach. A look gives it of every relay
    /// ([`relays_of`]); `None` only in a test.
    pub reach: Option<ReachLook>,
    pub dial: Dial,
    /// Whether nothing that this device carried waits there, where the
    /// look says.
    pub has_what_was_carried: Option<bool>,
}

impl RelayAt {
    /// Its class, as the node put it.
    pub fn class(&self) -> Option<Class> {
        self.reach.as_ref().and_then(|reach| reach.class)
    }

    /// Whether it holds the change. A relay in the third state does not:
    /// in the wait after a change every relay holds it or lacks it, and
    /// one that is not known to hold it is taken to lack it.
    pub fn holds(&self) -> bool {
        self.reach
            .as_ref()
            .is_some_and(|reach| reach.holds == Holds::Holds)
    }

    /// Whether it is reached.
    pub fn reached(&self) -> bool {
        self.reach.as_ref().is_some_and(|reach| reach.reached)
    }

    /// Whether it is out of reach.
    pub fn out_of_reach(&self) -> bool {
        self.reach
            .as_ref()
            .is_some_and(|reach| reach.out_of_reach_since.is_some())
    }
}

/// The relays that a look shows, in the order of the configuration.
///
/// **A relay whose reach cannot be read is an error**, and so the end of
/// the wait (decision 2026-10-19 §4, rule 8): it is in no class, so no end
/// would ever hold. That is a look from a node of another version, or one
/// that says what this command does not know.
pub(crate) fn relays_of(seen: &Value) -> anyhow::Result<Vec<RelayAt>> {
    list(seen, "relays")
        .map(|relay| {
            let name = text(relay, "relay").to_string();
            let reach = serde_json::from_value(relay["reach"].clone()).map_err(|e| {
                anyhow::anyhow!("the node says of {name} what this command cannot read ({e})")
            })?;
            Ok(RelayAt {
                name,
                reach: Some(reach),
                dial: match relay["dial"].as_str() {
                    Some("connected") => Dial::Connected,
                    Some("looked_up") => Dial::LookedUp,
                    Some("not_dialled") => Dial::NotDialled,
                    Some("no_key") => Dial::NoKey,
                    _ => Dial::Dialled,
                },
                has_what_was_carried: relay["has_what_was_carried"].as_bool(),
            })
        })
        .collect()
}

/// The device's own word under the change: none, the carried word, or
/// `sent` (decision 2026-10-19 §4, rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnWord {
    None,
    Carried,
    Sent,
}

/// This device's own word under the change numbered `number`, as the look
/// reads it. Which row is its own goes by its key (decision 2026-10-04
/// §16).
pub(crate) fn own_word(seen: &Value, number: u64, own: &[u8; 32]) -> OwnWord {
    let rows = || {
        list(seen, "devices")
            .chain(list(seen, "added"))
            .filter(|device| is_own(device, own))
            .filter(|device| device["applied"].as_u64() == Some(number))
    };
    if rows().any(|device| device["sent"] == true) {
        return OwnWord::Sent;
    }
    match rows().any(|device| device["carried_word"].is_object()) {
        true => OwnWord::Carried,
        false => OwnWord::None,
    }
}

/// How the wait after a change ends (decision 2026-10-19 §4, rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// End 1, status 0: every relay is OK, and the device's own word is
    /// `sent`.
    Done,
    /// End 2, status 0: every relay holds the change, one at least is OK,
    /// and the node will not write over the device's own word.
    Warned,
    /// End 3, status 3: every relay is in a class, and some relay lacks
    /// the change, or none is OK and the node will not write over the
    /// device's own word.
    NotDone,
}

impl End {
    /// The exit status of the command that ends so.
    pub fn status(self) -> i32 {
        match self {
            End::Done | End::Warned => 0,
            End::NotDone => NOT_AT_EVERY_RELAY_STATUS,
        }
    }
}

/// A relay's class, and whether it holds the change: what the ends are
/// stated over.
pub(crate) type Classed = (Option<Class>, bool);

fn is(class: Class) -> impl Fn(&Classed) -> bool {
    move |(at, _)| *at == Some(class)
}

/// End 1: every relay is OK, and the device's own word is `sent`.
pub(crate) fn ends_done(relays: &[Classed], word: OwnWord) -> bool {
    !relays.is_empty() && relays.iter().all(is(Class::Ok)) && word == OwnWord::Sent
}

/// End 2: every relay holds the change (each is OK, STUCK, or OUT and
/// holding); at least one is OK, so what the device carried is whole at a
/// relay that it reaches; and the node will not write over the device's
/// own word. That word is then `sent`, the carried word, or none under a
/// look that stays pending: `sent` is accepted beside the carried word, or
/// a device that wrote `sent` and then lost a relay that holds the change
/// would have no end.
pub(crate) fn ends_warned(relays: &[Classed], word_to_come: bool) -> bool {
    let every_holds = relays
        .iter()
        .all(|(class, _)| matches!(class, Some(Class::Ok | Class::Stuck | Class::OutHolding)));
    every_holds && relays.iter().any(is(Class::Ok)) && !word_to_come
}

/// End 3: every relay is in a class, and either some relay lacks the
/// change, or none is OK and the node will not write over the device's own
/// word. Nothing is asked of the word where a relay lacks the change:
/// safety does not need it, and the word may wait on a whole pass.
///
/// With no relay it does not hold: the node has not yet said where it
/// stands at its relays (a look before its first pass), and a node always
/// has one to dial.
pub(crate) fn ends_not_done(relays: &[Classed], word_to_come: bool) -> bool {
    let every_classed = !relays.is_empty() && relays.iter().all(|(class, _)| class.is_some());
    let one_lacks = relays.iter().any(|(_, holds)| !holds);
    let none_ok = !relays.iter().any(is(Class::Ok));
    every_classed && (one_lacks || (none_ok && !word_to_come))
}

/// The first of the three ends that holds, or none while time can still
/// move a relay or the word (decision 2026-10-19 §4, rule 8). `relays` is
/// each relay's class and whether it holds the change; `word_to_come` is
/// the node's word that its next whole pass would write `sent` or the
/// carried word.
pub(crate) fn end_of(relays: &[Classed], word: OwnWord, word_to_come: bool) -> Option<End> {
    if ends_done(relays, word) {
        Some(End::Done)
    } else if ends_warned(relays, word_to_come) {
        Some(End::Warned)
    } else if ends_not_done(relays, word_to_come) {
        Some(End::NotDone)
    } else {
        None
    }
}

/// Whether what the look says of `relay`'s reach is about the change entry
/// that the device keeps, as the look names it (`latest`): the node's last
/// pass found that entry kept.
pub(crate) fn is_about_the_kept_entry(relay: &RelayAt, seen: &Value) -> bool {
    let kept = seen["latest"].as_str();
    kept.is_some()
        && relay
            .reach
            .as_ref()
            .and_then(|reach| reach.about.as_deref())
            == kept
}

/// What a look after the change numbered `number` says of its end: its
/// relays, the device's own word, and the end that holds, where one does.
/// Each relay's class and the node's `word_to_come` are read from the
/// look, as the node gives them.
///
/// **No end holds while what is known of a relay is about another entry
/// than the change** (decision 2026-10-19 §4, rule 8): the look reads the
/// change from the database, and the classes from the node's last pass,
/// which may have been before the change was made. Each relay's reach
/// names the entry it is about, and that must be the kept entry that the
/// look names. A look that does not say whether a word is to come, or
/// says of a relay what cannot be read, is an error.
pub(crate) fn end_of_look(
    seen: &Value,
    number: u64,
    own: &[u8; 32],
) -> anyhow::Result<(Vec<RelayAt>, OwnWord, Option<End>)> {
    let relays = relays_of(seen)?;
    let word = own_word(seen, number, own);
    let Some(word_to_come) = seen["word_to_come"].as_bool() else {
        anyhow::bail!("the node does not say whether its next pass writes a word");
    };
    if !relays
        .iter()
        .all(|relay| is_about_the_kept_entry(relay, seen))
    {
        return Ok((relays, word, None));
    }
    let classes: Vec<Classed> = relays
        .iter()
        .map(|relay| (relay.class(), relay.holds()))
        .collect();
    let end = end_of(&classes, word, word_to_come);
    Ok((relays, word, end))
}

// ── A recovery's wait ───────────────────────────────────────────────

/// How a recovery's wait for the change at each relay ends (decision
/// 2026-10-19 §4, rule 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryEnd {
    /// Every relay holds the change: R1, and status 0.
    Recovered,
    /// Not done for a recovery, status 3: some relay lacks the change, and
    /// each relay that lacks it is OUT and lacking, or REFUSING.
    NotDone,
}

impl RecoveryEnd {
    /// The exit status of the recovery that ends so.
    pub fn status(self) -> i32 {
        match self {
            RecoveryEnd::Recovered => 0,
            RecoveryEnd::NotDone => NOT_AT_EVERY_RELAY_STATUS,
        }
    }
}

/// A recovery's end with status 0: every relay holds the change. There is
/// no condition on what waits, nor on the machine's own word: its look may
/// stay pending until the next statement, and then neither word is
/// written.
pub(crate) fn ends_recovered(relays: &[Classed]) -> bool {
    !relays.is_empty() && relays.iter().all(|(_, holds)| *holds)
}

/// Not done for a recovery: some relay lacks the change, and each relay
/// that lacks it is OUT and lacking, or REFUSING. A relay that holds the
/// change is asked nothing: what waits there is said by the lines that
/// came before the wait. With no relay it does not hold, as end 3 does
/// not: the node has not yet said where it stands at its relays.
pub(crate) fn ends_recovery_not_done(relays: &[Classed]) -> bool {
    let lacking = || relays.iter().filter(|(_, holds)| !holds);
    let each_settled =
        lacking().all(|(class, _)| matches!(class, Some(Class::OutLacking | Class::Refusing)));
    lacking().next().is_some() && each_settled
}

/// The first of a recovery's two ends that holds, or none while time can
/// still move a relay that lacks the change (decision 2026-10-19 §4, rule
/// 9).
pub(crate) fn recovery_end_of(relays: &[Classed]) -> Option<RecoveryEnd> {
    if ends_recovered(relays) {
        Some(RecoveryEnd::Recovered)
    } else if ends_recovery_not_done(relays) {
        Some(RecoveryEnd::NotDone)
    } else {
        None
    }
}

/// What a look after a recovery says of its end: its relays, and the end
/// that holds, where one does. Each relay's class is read from the look,
/// as the node gives it.
///
/// **No end holds while what is known of a relay is about another entry
/// than the recovery's change** (decision 2026-10-19 §4, rule 9, as rule
/// 8 has it): the classes come from the node's last pass, which may have
/// been before the change was kept. Each relay's reach names the entry
/// it is about, and that must be the kept entry that the look names. A
/// look that says of a relay what cannot be read is an error, and so the
/// end of the wait with status 3.
pub(crate) fn recovery_end_of_look(
    seen: &Value,
) -> anyhow::Result<(Vec<RelayAt>, Option<RecoveryEnd>)> {
    let relays = relays_of(seen)?;
    if !relays
        .iter()
        .all(|relay| is_about_the_kept_entry(relay, seen))
    {
        return Ok((relays, None));
    }
    let classes: Vec<Classed> = relays
        .iter()
        .map(|relay| (relay.class(), relay.holds()))
        .collect();
    let end = recovery_end_of(&classes);
    Ok((relays, end))
}

/// Where the device no longer stands in its phrase, as the look says, what
/// the wait after a change, and a recovery's, says before it ends with
/// status 3: the line, and `None` where it stands. A device that was
/// removed, that is in no list, that could not open the change, or that
/// follows no phrase shows the change to no relay, and what the node knows
/// of each relay's reach is then of the entry before: no end of the wait
/// would hold for good. A device in a fork still shows its own entry, and
/// its wait ends as rule 8 has it (decision 2026-10-19 §4, rule 8).
pub(crate) fn no_longer_stands(seen: &Value) -> Option<String> {
    let state = text(seen, "state");
    if !matches!(state, "removed" | "not_listed" | "not_opened" | "no_phrase") {
        return None;
    }
    let why = seen["cannot_go_on"].as_str().unwrap_or(state);
    Some(format!(
        "This device no longer stands in its phrase ({why}): it shows the change to no relay, \
         and what each relay holds is not known from here. This command ends here, with status \
         {NOT_AT_EVERY_RELAY_STATUS}. It does not say that you may close this machine. `cordelia \
         devices` says what is so."
    ))
}

/// R0: what a recovery says where a relay does not hold the change when
/// its look has ended (decision 2026-10-19 §5), and that each line after
/// it has its time (decision 2026-10-24, rule 3).
pub(crate) fn recovery_first_line() -> String {
    format!(
        "This command stays until every relay holds the change. It ends sooner, with status \
         {NOT_AT_EVERY_RELAY_STATUS}, once each relay that is not known to hold it cannot be \
         reached, or refuses it, for five minutes. Stopping it stops nothing: the node goes on, \
         and the recovery stays made. {TIMES_SAID}"
    )
}

/// What a recovery's wait says at its end (decision 2026-10-19 §5): R1;
/// or S8 for each relay that lacks the change, in the order of the
/// configuration, then S9 where a relay is reached, then S10 or S11. It
/// never says that the machine may be closed.
pub(crate) fn recovery_end_lines(end: RecoveryEnd, relays: &[RelayAt], now: i64) -> Vec<String> {
    match end {
        RecoveryEnd::Recovered => vec!["Every relay holds the change.".into()],
        RecoveryEnd::NotDone => {
            let lacking: Vec<&RelayAt> = relays.iter().filter(|relay| !relay.holds()).collect();
            not_done_lines(relays, &lacking, now)
        }
    }
}

// ── The words ───────────────────────────────────────────────────────

// `<when>` and `<since>` are written where a status writes its lines, so
// that the wait and the status never say a time two ways.
pub(crate) use cordelia_api::look::{since, when};

/// `<since>` of a relay, where the look says what is known of its reach.
fn since_of(relay: &RelayAt, now: i64) -> String {
    match &relay.reach {
        Some(reach) => since(reach, now),
        None => "has not answered".into(),
    }
}

/// "it" or "them", for a list of `n` things.
fn it_them(n: usize) -> &'static str {
    if n == 1 { "it" } else { "them" }
}

/// A verb for a list of `n` relays: `one` where there is one, `many`
/// otherwise.
fn verb(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}

/// The names of `relays`, in a sentence.
fn names(relays: &[&RelayAt]) -> String {
    let names: Vec<String> = relays.iter().map(|relay| relay.name.clone()).collect();
    joined(&names)
}

/// The first line of the wait (decision 2026-10-19 §5, S1), and that each
/// line after it has its time (decision 2026-10-24, rule 3).
pub(crate) fn first_line() -> String {
    format!(
        "You may close this machine once every relay holds the change, and what this device \
         carried is at a relay that it reaches. This command stays until then, and says what \
         is missing. It ends sooner, with status {NOT_AT_EVERY_RELAY_STATUS}, where for five \
         minutes a relay that is not known to hold the change cannot be reached or refuses it, \
         or where no relay that this machine reaches has what this device carried. It then \
         does not say that you may close this machine. Stopping it stops nothing: the node \
         goes on. {TIMES_SAID}"
    )
}

/// What S1 and R0 end with (decision 2026-10-24, rule 3): the lines of
/// an end, under the line that the wait has ended, have no time.
const TIMES_SAID: &str = "Until the wait ends, each line below starts with the time it was said, \
                          in UTC.";

/// What the wait says of a relay that is out of reach, while it goes on
/// (decision 2026-10-19 §5, S2 and S3; decision 2026-10-24, rule 7): that
/// it cannot be reached from here, and since what.
pub(crate) fn out_of_reach_line(relay: &RelayAt, now: i64) -> String {
    let since = since_of(relay, now);
    match relay.holds() {
        true => format!(
            "{} holds the change, and cannot be reached from here: it {since}",
            relay.name
        ),
        false => format!(
            "keep this machine on: {} cannot be reached from here, and is not known to hold the \
             change yet: it {since}",
            relay.name
        ),
    }
}

/// The minutes for which the wait waits out a relay (decision 2026-10-19
/// §1): what its count says it waits (decision 2026-10-24, rule 4).
const WAITED_MINUTES: u64 = OUT_OF_REACH_SECS / 60;

/// What the wait says, once each minute counted, of a relay that it waits
/// out (decision 2026-10-24, rule 4), at `now`: one that is not reached
/// and not out of reach, by the whole minutes since its reference; and one
/// that is reached and refuses the change, by those since it came to
/// refuse it, from minute 1 to minute 4. Nothing at minute 0, and nothing
/// of a relay in a class: once it is out of reach S2 or S3 says so. The
/// count is a word to the person: the node's own clock ends the wait.
///
/// The minutes are those of the wait, from the reference: from minute 5
/// the line says that the relay has not been reached in them, and not for
/// how long it has not been, since it may have been lost before the
/// reference (`<since>` says when it was last reached).
pub(crate) fn count_line(relay: &RelayAt, now: i64) -> Option<String> {
    let reach = relay.reach.as_ref().filter(|reach| reach.class.is_none())?;
    let minutes = |since: i64| u64::try_from(now.saturating_sub(since)).unwrap_or(0) / 60;
    let name = &relay.name;
    if !reach.reached {
        if reach.out_of_reach_since.is_some() {
            return None;
        }
        return match minutes(reach.reference) {
            0 => None,
            m if m < WAITED_MINUTES => Some(format!(
                "{name} has not been reached for {m} of the {WAITED_MINUTES} minutes that this \
                 command waits for it"
            )),
            m => Some(format!(
                "{name} has not been reached in the {m} minutes that this command has waited \
                 for it. This command stops waiting for it once this machine has tried it again \
                 and failed."
            )),
        };
    }
    if reach.holds != Holds::Lacks {
        return None;
    }
    let m = minutes(reach.refused_since?);
    (1..WAITED_MINUTES).contains(&m).then(|| {
        format!(
            "{name} has refused the change for {m} of the {WAITED_MINUTES} minutes that this \
             command waits for it"
        )
    })
}

/// How long the wait goes with no new line before it says that it is
/// still waiting, and again after (decision 2026-10-24, rule 3).
const STILL_WAITING_SECS: i64 = 60;

/// A time of day as each line of the wait says it, in UTC, with seconds
/// (decision 2026-10-24, rule 3).
fn clock(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|at| at.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| format!("{at}"))
}

/// A line of the wait as it is said at `at`: two spaces in, its time, two
/// spaces, and its words.
fn timed(at: i64, line: &str) -> String {
    format!("  {}  {line}", clock(at))
}

/// What the wait has said, and when (decision 2026-10-24, rule 3).
///
/// - **A line is new** where it was not in the last look, judged by its
///   words without the time: it is said once, with the time it is said. A
///   line that drops out of the look says nothing.
/// - **Where no line has been said for a minute,** the wait says that it
///   is still waiting, with the time of the last line that was not that
///   (S1 or R0 where none has come since), and again a minute after the
///   last line of any kind. Not at a look that ends the wait: the line
///   that it has ended is said then.
/// - **Each end begins with a line of its own,** with its time
///   ([`Self::ended`]); the lines of the end come under it, with none.
///
/// The time is read from the clock that the wait is given, and nothing of
/// what the wait decides reads a time it says.
pub(crate) struct Told {
    /// The lines of the last look, by their words.
    said: Vec<String>,
    /// When the last line was said that was not the line that the wait is
    /// still waiting.
    last_line: i64,
    /// When the last line of any kind was said.
    last_said: i64,
}

impl Told {
    /// A wait whose first line was said at `at`.
    pub fn from(at: i64) -> Self {
        Self {
            said: Vec::new(),
            last_line: at,
            last_said: at,
        }
    }

    /// What the wait says of a look at `at` whose lines are `now`, a line
    /// each, as each is printed. `ends` is whether the look ends the wait.
    pub fn of_look(&mut self, now: Vec<String>, at: i64, ends: bool) -> Vec<String> {
        let new: Vec<String> = now
            .iter()
            .filter(|line| !self.said.contains(line))
            .map(|line| timed(at, line))
            .collect();
        self.said = now;
        if !new.is_empty() {
            (self.last_line, self.last_said) = (at, at);
            return new;
        }
        if ends || at.saturating_sub(self.last_said) < STILL_WAITING_SECS {
            return Vec::new();
        }
        self.last_said = at;
        vec![timed(
            at,
            &format!("still waiting: no new line since {}", clock(self.last_line)),
        )]
    }

    /// The line that each end of the wait begins with, said at `at`.
    pub fn ended(at: i64) -> String {
        timed(at, "The wait has ended.")
    }
}

/// The relays at which nothing that this device carried waits
/// (`<held>`), and the others (`<not yet>`), by its rows of what it sent:
/// two sets that never overlap (decision 2026-10-19 §5). Where its own
/// word is `sent`, nothing that it carried waits at any relay.
fn held_and_not_yet(relays: &[RelayAt], word: OwnWord) -> (Vec<&RelayAt>, Vec<&RelayAt>) {
    relays.iter().partition(|relay| {
        word == OwnWord::Sent
            || relay.has_what_was_carried == Some(true)
            || relay.class() == Some(Class::Ok)
    })
}

/// S6b: a relay that holds the change and refuses what waits there.
fn stuck_line(relay: &RelayAt, now: i64) -> String {
    let since = relay
        .reach
        .as_ref()
        .and_then(|reach| reach.refusing_waits_since)
        .map(|at| format!(" since {}", when(at, now)))
        .unwrap_or_default();
    format!(
        "  {} holds the change. It has refused for room what this device still has to send \
         there{since}.",
        relay.name
    )
}

/// What the wait says at its end, a line each (decision 2026-10-19 §5):
/// end 1's line; S6, S6b and S7 at end 2; S8, S9 and one of S10, S10b and
/// S11 at end 3.
pub(crate) fn end_lines(end: End, relays: &[RelayAt], word: OwnWord, now: i64) -> Vec<String> {
    match end {
        End::Done => vec![
            "Every relay holds the change, and this device has sent what it holds: this machine \
             may be closed. `cordelia devices` shows which devices have applied the change."
                .into(),
        ],
        End::Warned => warned_lines(relays, word, now),
        End::NotDone => {
            let not_ok: Vec<&RelayAt> = relays
                .iter()
                .filter(|relay| relay.class() != Some(Class::Ok))
                .collect();
            not_done_lines(relays, &not_ok, now)
        }
    }
}

/// End 2: S6 for each relay that is OUT and holding, S6b for each that is
/// STUCK, then S7.
fn warned_lines(relays: &[RelayAt], word: OwnWord, now: i64) -> Vec<String> {
    let (held, not_yet) = held_and_not_yet(relays, word);
    let mut lines = Vec::new();
    for relay in relays {
        match relay.class() {
            Some(Class::OutHolding) => {
                let since = since_of(relay, now);
                lines.push(match held.iter().any(|at| at.name == relay.name) {
                    true => format!(
                        "  {} holds the change and all that this device carried, and cannot be \
                         reached from here: it {since}.",
                        relay.name
                    ),
                    false => format!(
                        "  {} holds the change, and cannot be reached from here: it {since}. \
                         Some of what this device carried is not there yet.",
                        relay.name
                    ),
                });
            }
            Some(Class::Stuck) => lines.push(stuck_line(relay, now)),
            _ => {}
        }
    }
    let mut last = vec!["Every relay holds the change. You may close this machine.".to_string()];
    if !held.is_empty() {
        last.push(format!(
            "All that this device carried is at {}.",
            names(&held)
        ));
    }
    if !not_yet.is_empty() {
        last.push(format!(
            "{} {} the rest when this machine next reaches {}.",
            names(&not_yet),
            verb(not_yet.len(), "gets", "get"),
            it_them(not_yet.len())
        ));
    }
    let waits_for: Vec<&RelayAt> = relays
        .iter()
        .filter(|relay| matches!(relay.class(), Some(Class::OutHolding | Class::Stuck)))
        .collect();
    if !waits_for.is_empty() {
        last.push(format!(
            "What this device writes from now on waits for {}.",
            names(&waits_for)
        ));
    }
    last.push("`cordelia devices` shows which devices have applied the change.".into());
    lines.push(last.join(" "));
    lines
}

/// S8 of a relay that is reached and refuses the change, by its latest
/// answer that said it lacks it: no room for it, or another change. A
/// relay is REFUSING only once it has been reached and lacked the change
/// for five minutes, by answers given since the node started, so the node
/// has noted why. Were it not noted, the line would say only what the
/// class says: that the relay has not taken the change.
fn refusing_line(relay: &RelayAt, now: i64) -> String {
    let lacks_for = relay
        .reach
        .as_ref()
        .and_then(|reach| reach.lacks_for.clone());
    match lacks_for {
        Some(LacksFor::Room(refused)) => format!(
            "  {} is reached, and has not taken the change: it had no room for it at {} ({}).",
            relay.name,
            when(refused.at, now),
            match refused.over_allowance {
                true => "this address is over its allowance of new channels there",
                false => "it is full",
            }
        ),
        Some(LacksFor::Another { why }) => format!(
            "  {} is reached, and holds a change that this device does not take ({}). It does \
             not take this one in its place.",
            relay.name,
            why.as_deref()
                .unwrap_or("it is another change than the one this device keeps")
        ),
        None => format!("  {} is reached, and has not taken the change.", relay.name),
    }
}

/// End 3: S8 for each relay of `said_of`, in the order of the
/// configuration (at end 3 of the wait after a change, each that is not
/// OK; at a recovery's, each that lacks the change); then S9 where a relay
/// is reached; then S10, S10b or S11. It never says that the machine may
/// be closed.
fn not_done_lines(relays: &[RelayAt], said_of: &[&RelayAt], now: i64) -> Vec<String> {
    let mut lines = Vec::new();
    for relay in said_of {
        match relay.class() {
            Some(Class::OutLacking) => lines.push(format!(
                "  {} cannot be reached from here, and is not known to hold the change: it {}.",
                relay.name,
                since_of(relay, now)
            )),
            Some(Class::Refusing) => lines.push(refusing_line(relay, now)),
            Some(Class::OutHolding) => lines.push(format!(
                "  {} holds the change, and cannot be reached from here: it {}.",
                relay.name,
                since_of(relay, now)
            )),
            Some(Class::Stuck) => lines.push(stuck_line(relay, now)),
            Some(Class::Ok) | None => {}
        }
    }
    let lacking: Vec<&RelayAt> = relays.iter().filter(|relay| !relay.holds()).collect();
    let reached = relays.iter().any(RelayAt::reached);
    let why = why_not_done(relays);
    if reached && !why.is_empty() {
        lines.push(why);
    }
    let ends = format!(
        "This command ends here, with status {NOT_AT_EVERY_RELAY_STATUS}. It does not say that \
         you may close this machine."
    );
    lines.push(match (reached, lacking.is_empty()) {
        (true, false) => format!(
            "The change is not known to be at {}. {ends} `cordelia devices`, here or on a device \
             of yours that reaches {}, says when {} the latest change.",
            names(&lacking),
            it_them(lacking.len()),
            verb(lacking.len(), "it holds", "they hold")
        ),
        (true, true) => {
            let stuck: Vec<&RelayAt> = relays
                .iter()
                .filter(|relay| relay.class() == Some(Class::Stuck))
                .collect();
            format!(
                "Every relay holds the change. What this device carried is at no relay that \
                 this machine reaches: {} {} it for room. {ends} Keep it on. `cordelia devices` \
                 says when what it carried is sent.",
                names(&stuck),
                verb(stuck.len(), "refuses", "refuse")
            )
        }
        (false, _) => {
            let mut said = vec!["No relay can be reached from here.".to_string()];
            if !relays.iter().any(RelayAt::holds) {
                said.push(
                    "None is known to hold the change. No other device of yours can hear of it \
                     until one does."
                        .into(),
                );
            }
            said.push(format!(
                "{ends} Keep it on, on a network from which a relay can be reached. `cordelia \
                 devices` says what is missing."
            ));
            said.join(" ")
        }
    });
    lines
}

/// S9: why a device of the person's may not have heard of the change, and
/// what this machine does about each relay that lacks it, a sentence for
/// each kind of relay, in this order, each only where there is one.
fn why_not_done(relays: &[RelayAt]) -> String {
    let lacking: Vec<&RelayAt> = relays.iter().filter(|relay| !relay.holds()).collect();
    let out: Vec<&RelayAt> = relays
        .iter()
        .filter(|relay| relay.class() == Some(Class::OutLacking))
        .collect();
    let refusing: Vec<&RelayAt> = relays
        .iter()
        .filter(|relay| relay.class() == Some(Class::Refusing))
        .collect();
    let dialled_so = |dial: Dial| -> Vec<&RelayAt> {
        out.iter()
            .copied()
            .filter(|relay| relay.dial == dial)
            .collect()
    };
    let mut said: Vec<String> = Vec::new();
    if !lacking.is_empty() {
        said.push(format!(
            "A device of yours that reaches only {} may not have heard of the change.",
            names(&lacking)
        ));
        said.push(
            "Until it does, it goes on in the channels from before the change, where every \
             device that held their secret can still read what it writes."
                .into(),
        );
    }
    if !out.is_empty() {
        let them = it_them(out.len());
        said.push(format!(
            "{} {} the change from a device that has applied it and reaches {them}, this one \
             included, and from a relay that works with {them}.",
            names(&out),
            verb(out.len(), "takes", "take")
        ));
    }
    let dialled = dialled_so(Dial::Dialled);
    if !dialled.is_empty() {
        said.push(format!(
            "While this machine is on it dials {} every {BACKOFF_BASE_SECS} seconds.",
            it_them(dialled.len())
        ));
    }
    let looked_up = dialled_so(Dial::LookedUp);
    if !looked_up.is_empty() {
        said.push(format!(
            "It looks {} up every {BOOTNODE_RESOLVE_RETRY_SECS} seconds.",
            verb(looked_up.len(), "its name", "their names")
        ));
    }
    let shown = dialled_so(Dial::Connected);
    if !shown.is_empty() {
        said.push(format!(
            "It shows {} the change again at most every ten minutes.",
            it_them(shown.len())
        ));
    }
    let not_dialled = dialled_so(Dial::NotDialled);
    if !not_dialled.is_empty() {
        said.push(format!(
            "It cannot dial {} while another relay answers at its address.",
            names(&not_dialled)
        ));
    }
    let no_key = dialled_so(Dial::NoKey);
    if !no_key.is_empty() {
        let n = no_key.len();
        said.push(format!(
            "{} {} given no key, at the address of a relay given one, so this machine never \
             reaches {}. To have {} reached, give {} that relay's key, or remove {} from your \
             configuration.",
            names(&no_key),
            verb(n, "is", "are"),
            it_them(n),
            it_them(n),
            verb(n, "it", "each"),
            it_them(n)
        ));
    }
    if !refusing.is_empty() {
        let n = refusing.len();
        said.push(format!(
            "{} {} the change. A device that reaches {} hears of it only once {} it, or from \
             another relay.",
            names(&refusing),
            verb(n, "refuses", "refuse"),
            it_them(n),
            verb(n, "it takes", "they take")
        ));
    }
    said.join(" ")
}

/// What the wait says on standard error where it could not go on, once
/// the change is made (decision 2026-10-19 §5).
pub(crate) fn could_not_go_on(number: u64, error: &anyhow::Error) -> String {
    format!(
        "The change is made (change {number}). This command could not go on: {error:#}. Do not \
         make the change again. `cordelia devices` shows whether each relay holds it."
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use cordelia_api::at_relays::known::{self, Answer, OfRelay, RelayId};
    use cordelia_api::look::relays as looked;
    use cordelia_api::state::{AtRelay, AtRelays, NoRoom, Reach as Reached, Waits};
    use cordelia_crypto::bech32::encode_public_key;
    use cordelia_crypto::identity::NodeIdentity;
    use cordelia_node::device_entries::reach::{Reach, Said, class};
    use cordelia_node::device_entries::{Clock, LinkId};
    use serde_json::json;
    use std::time::Duration;

    /// The change entry that the device keeps: the change just made.
    const KEPT: [u8; 32] = [1; 32];
    /// The change entry that the device kept before it.
    const BEFORE: [u8; 32] = [2; 32];
    /// The key that a relay answers with.
    const BY: [u8; 32] = [7; 32];

    // ── Appendix A, over the node's own functions ───────────────────

    /// One relay's state, as appendix A enumerates it, with its class put
    /// by the node's own function.
    #[derive(Debug, Clone, Copy)]
    struct OneRelay {
        keyed: bool,
        connected: bool,
        reached: bool,
        class: Option<Class>,
        holds: bool,
    }

    /// Every state of one relay that appendix A enumerates: whether it is
    /// given a key; whether a connection to it is open; whether it is
    /// reached; whether it is out of reach; its latest answer about the
    /// kept entry; what waits there; and whether it has refused the change
    /// for five minutes. Whether it holds the change is the node's
    /// [`known::holds`] of what is kept of it, and its class the node's
    /// [`class`].
    fn every_relay_state() -> Vec<OneRelay> {
        // Each answer as the database keeps it: whether it holds the
        // entry. "Another" is about the kept entry, and says that it does
        // not hold it, as "no room" and "over the allowance" do.
        let answers: [Option<bool>; 6] = [
            None,
            Some(true),
            Some(true),
            Some(false),
            Some(false),
            Some(false),
        ];
        let waits = [Waits::Nothing, Waits::Moving, Waits::Refused];
        let mut states = Vec::new();
        for keyed in [true, false] {
            for connected in [true, false] {
                for reached in [true, false] {
                    for out in [true, false] {
                        for answer in answers {
                            for waits in waits {
                                for refused_long in [true, false] {
                                    if (reached && !connected)
                                        || (reached && out)
                                        || (reached && answer.is_none())
                                        || (!reached && (waits != Waits::Nothing || refused_long))
                                    {
                                        continue;
                                    }
                                    let of = OfRelay {
                                        relay: RelayId {
                                            name: "relay.example:9474".into(),
                                            key: keyed.then_some(BY),
                                        },
                                        answer: answer.map(|holds| Answer {
                                            entry: KEPT,
                                            holds,
                                            by: BY,
                                            at: 0,
                                        }),
                                        mark: None,
                                    };
                                    let held = known::holds(
                                        Some(&of),
                                        Some(KEPT),
                                        connected.then_some(BY),
                                    );
                                    let holds = held == Holds::Holds;
                                    if holds && refused_long {
                                        continue;
                                    }
                                    let waits = reached.then_some(waits);
                                    states.push(OneRelay {
                                        keyed,
                                        connected,
                                        reached,
                                        class: class(held, reached, out, waits, refused_long),
                                        holds,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        states
    }

    /// Whether the node's next whole pass would write `sent` or the
    /// carried word, by their conditions over the classes (decision
    /// 2026-10-19, rules 1 and 4), as appendix A states them. It is the
    /// model's, not the node's: the node's `at_relays::word_to_come` works
    /// the same conditions out from its store, which no enumeration of
    /// millions of states can build, and its own tests hold it to them
    /// (`word_to_come_is_what_the_next_pass_would_write`). Over the node's
    /// own word, the looks of
    /// [`the_wait_never_says_may_be_closed_or_ends_with_0_while_a_relay_lacks_the_change`]
    /// take both values of it.
    fn word_to_come(relays: &[OneRelay], word: OwnWord, pending: bool) -> bool {
        let every_ok = relays.iter().all(|r| r.class == Some(Class::Ok));
        let can_sent = !pending && word != OwnWord::Sent && every_ok;
        let can_carried = !pending
            && word == OwnWord::None
            && relays.iter().any(|r| r.class == Some(Class::Ok))
            && relays.iter().all(|r| {
                matches!(
                    r.class,
                    Some(Class::Ok | Class::Stuck | Class::OutHolding | Class::OutLacking)
                )
            })
            && !every_ok;
        can_sent || can_carried
    }

    /// The ends of the wait after a change, over every state of two and
    /// three relays that appendix A enumerates, with each relay's class
    /// and whether it holds the change put by the node's own functions,
    /// and the ends by the command's own (decision 2026-10-19 §4, rule 8;
    /// appendix A).
    ///
    /// - **Safety:** no end with status 0 while a relay lacks the change,
    ///   nor while a relay given no key is not connected; end 2 only where
    ///   a relay is reached; end 3 never beside an end with status 0.
    /// - **Liveness:** in every state in which each relay is in a class and
    ///   the node will not write over the device's word, one end holds;
    ///   and wherever each relay is in a class and one lacks the change,
    ///   end 3 holds, whatever the word.
    /// - **The same for a recovery's wait** (rule 9): neither end with
    ///   status 0 holds while a relay lacks the change, nor while a relay
    ///   given no key is not connected; its two ends never hold together;
    ///   and wherever each relay holds the change, or is OUT and lacking,
    ///   or REFUSING, one of them holds, whatever the word.
    ///
    /// The counts are appendix A's.
    #[test]
    fn the_ends_are_safe_and_live_over_every_state() {
        let one = every_relay_state();
        assert_eq!(one.len(), 96);
        let words = [
            (OwnWord::None, false),
            (OwnWord::None, true),
            (OwnWord::Carried, false),
            (OwnWord::Sent, false),
        ];
        let check = |relays: &[OneRelay], counts: &mut (usize, usize, usize)| {
            let classed: Vec<Classed> = relays.iter().map(|r| (r.class, r.holds)).collect();
            let lacks = relays.iter().any(|r| !r.holds);
            let every_classed = relays.iter().all(|r| r.class.is_some());
            for (word, pending) in words {
                counts.0 += 1;
                let to_come = word_to_come(relays, word, pending);
                let e1 = ends_done(&classed, word);
                let e2 = ends_warned(&classed, to_come);
                let e3 = ends_not_done(&classed, to_come);
                assert!(!((e1 || e2) && lacks), "SAFETY {relays:?} {word:?}");
                assert!(!e2 || relays.iter().any(|r| r.reached), "{relays:?}");
                assert!(
                    !((e1 || e2) && relays.iter().any(|r| !r.keyed && !r.connected)),
                    "{relays:?}"
                );
                assert!(!(e3 && (e1 || e2)), "{relays:?} {word:?}");
                // The first that holds is the end.
                let end = end_of(&classed, word, to_come);
                assert_eq!(end.is_some(), e1 || e2 || e3);
                assert_eq!(end.is_some_and(|end| end.status() == 0), e1 || e2);
                if every_classed && !to_come {
                    counts.1 += 1;
                    assert!(e1 || e2 || e3, "LIVENESS {relays:?} {word:?} {pending}");
                }
                if every_classed && lacks {
                    assert!(e3, "end 3 waits on the word: {relays:?} {word:?}");
                }
            }
            // A recovery's wait asks nothing of the word.
            let recovered = ends_recovered(&classed);
            let not_done = ends_recovery_not_done(&classed);
            assert!(!(recovered && lacks), "SAFETY of a recovery {relays:?}");
            assert!(
                !(recovered && relays.iter().any(|r| !r.keyed && !r.connected)),
                "{relays:?}"
            );
            assert!(!(recovered && not_done), "{relays:?}");
            let end = recovery_end_of(&classed);
            assert_eq!(end.is_some(), recovered || not_done);
            assert_eq!(end.is_some_and(|end| end.status() == 0), recovered);
            let stable = relays
                .iter()
                .all(|r| r.holds || matches!(r.class, Some(Class::OutLacking | Class::Refusing)));
            if stable {
                counts.2 += 1;
                assert!(recovered || not_done, "LIVENESS of a recovery {relays:?}");
            }
        };
        let mut two = (0, 0, 0);
        for a in &one {
            for b in &one {
                check(&[*a, *b], &mut two);
            }
        }
        assert_eq!((two.0, two.1), (36_864, 9_744));
        let mut three = (0, 0, 0);
        for a in &one {
            for b in &one {
                for c in &one {
                    check(&[*a, *b, *c], &mut three);
                }
            }
        }
        assert_eq!((three.0, three.1), (3_538_944, 489_120));
        // Of each relay state, how many a recovery's wait has an end in.
        let stable = one
            .iter()
            .filter(|r| r.holds || matches!(r.class, Some(Class::OutLacking | Class::Refusing)))
            .count();
        assert_eq!(two.2, stable.pow(2));
        assert_eq!(three.2, stable.pow(3));
    }

    /// End 3 asks nothing of the device's own word where a relay lacks the
    /// change (decision 2026-10-19 §4, rule 8): it holds whatever the word
    /// and whatever the node says of the word to come. Where no relay
    /// lacks it and none is OK, it waits for the word.
    #[test]
    fn end_three_does_not_wait_on_the_word_where_a_relay_lacks_the_change() {
        let ok = (Some(Class::Ok), true);
        for word in [OwnWord::None, OwnWord::Carried, OwnWord::Sent] {
            for to_come in [false, true] {
                for lacking in [
                    (Some(Class::OutLacking), false),
                    (Some(Class::Refusing), false),
                ] {
                    assert_eq!(end_of(&[ok, lacking], word, to_come), Some(End::NotDone));
                    assert_eq!(end_of(&[lacking], word, to_come), Some(End::NotDone));
                }
            }
        }
        // No relay lacks it, and none is OK: the word to come is waited
        // for, and then end 3.
        let stuck = (Some(Class::Stuck), true);
        let out = (Some(Class::OutHolding), true);
        assert_eq!(end_of(&[stuck, out], OwnWord::None, true), None);
        assert_eq!(
            end_of(&[stuck, out], OwnWord::None, false),
            Some(End::NotDone)
        );
        // A relay in no class holds every end back.
        let moving = (None, false);
        assert_eq!(
            end_of(
                &[moving, (Some(Class::OutLacking), false)],
                OwnWord::Sent,
                false
            ),
            None
        );
        // With no relay listed, nothing ends: the node has not yet said
        // where it stands at its relays.
        for word in [OwnWord::None, OwnWord::Carried, OwnWord::Sent] {
            for to_come in [false, true] {
                assert_eq!(end_of(&[], word, to_come), None);
            }
        }
    }

    /// Each case that the table of rule 8 names reaches its end, with its
    /// status (decision 2026-10-19 §4, rule 8).
    #[test]
    fn each_case_of_the_table_of_rule_8_reaches_its_end() {
        let ok = (Some(Class::Ok), true);
        let stuck = (Some(Class::Stuck), true);
        let out_holding = (Some(Class::OutHolding), true);
        let out_lacking = (Some(Class::OutLacking), false);
        let refusing = (Some(Class::Refusing), false);
        for (case, relays, word, to_come, end, status) in [
            (
                "B down; A takes the change and all that waits",
                vec![ok, out_lacking],
                OwnWord::Carried,
                false,
                End::NotDone,
                3,
            ),
            (
                "B took everything, then went down before `sent`",
                vec![ok, out_holding],
                OwnWord::Carried,
                false,
                End::Warned,
                0,
            ),
            (
                "`sent` was written; then B was lost",
                vec![ok, out_holding],
                OwnWord::Sent,
                false,
                End::Warned,
                0,
            ),
            (
                "B's name does not resolve",
                vec![ok, out_lacking],
                OwnWord::None,
                true,
                End::NotDone,
                3,
            ),
            (
                "B has the wrong key at A's address",
                vec![ok, out_lacking],
                OwnWord::None,
                true,
                End::NotDone,
                3,
            ),
            (
                "B connected, its shows go unanswered",
                vec![ok, out_lacking],
                OwnWord::Carried,
                false,
                End::NotDone,
                3,
            ),
            (
                "A refuses the change; B out of reach",
                vec![refusing, out_lacking],
                OwnWord::None,
                false,
                End::NotDone,
                3,
            ),
            (
                "A alone, refusing the change",
                vec![refusing],
                OwnWord::None,
                false,
                End::NotDone,
                3,
            ),
            (
                "A STUCK; B OK",
                vec![stuck, ok],
                OwnWord::Carried,
                false,
                End::Warned,
                0,
            ),
            (
                "A STUCK; no relay OK",
                vec![stuck],
                OwnWord::None,
                false,
                End::NotDone,
                3,
            ),
            (
                "no relay reached, none holds",
                vec![out_lacking, out_lacking],
                OwnWord::None,
                false,
                End::NotDone,
                3,
            ),
            (
                "no relay reached, each holds",
                vec![out_holding, out_holding],
                OwnWord::None,
                false,
                End::NotDone,
                3,
            ),
            (
                "A holds another change: a fork",
                vec![refusing, ok],
                OwnWord::None,
                false,
                End::NotDone,
                3,
            ),
            (
                "B answered `not signed`",
                vec![ok, out_lacking],
                OwnWord::None,
                true,
                End::NotDone,
                3,
            ),
            (
                "A drops every three minutes; B down",
                vec![ok, out_lacking],
                OwnWord::None,
                true,
                End::NotDone,
                3,
            ),
            (
                "B given no key, its name names another host",
                vec![ok, out_lacking],
                OwnWord::Carried,
                false,
                End::NotDone,
                3,
            ),
            (
                "every relay OK and `sent`",
                vec![ok, ok],
                OwnWord::Sent,
                false,
                End::Done,
                0,
            ),
        ] {
            let ended = end_of(&relays, word, to_come);
            assert_eq!(ended, Some(end), "{case}");
            assert_eq!(end.status(), status, "{case}");
        }
        // A relay given no key holds the change only while connected to
        // the key that answered: out of reach, it lacks it, and the wait
        // ends at end 3, not end 2.
        let gone = OfRelay {
            relay: RelayId {
                name: "b.example:9474".into(),
                key: None,
            },
            answer: Some(Answer {
                entry: KEPT,
                holds: true,
                by: BY,
                at: 0,
            }),
            mark: None,
        };
        let held = known::holds(Some(&gone), Some(KEPT), None);
        let b = (class(held, false, true, None, false), held == Holds::Holds);
        assert_eq!(b, (Some(Class::OutLacking), false));
        assert_eq!(
            end_of(&[ok, b], OwnWord::Carried, false),
            Some(End::NotDone)
        );
        let again = known::holds(Some(&gone), Some(KEPT), Some(BY));
        assert_eq!(again, Holds::Holds);
        assert_eq!(
            known::holds(Some(&gone), Some(KEPT), Some([8; 32])),
            Holds::Lacks
        );
    }

    /// A recovery's wait ends by the relays that lack the change
    /// (decision 2026-10-19 §4, rule 9): at R1, with status 0, where every
    /// relay holds it, whatever its class; not done, with status 3, where
    /// each relay that lacks it is OUT and lacking, or REFUSING; and at
    /// neither while a relay that lacks it is in no class. A look that
    /// lists no relay ends nothing.
    #[test]
    fn a_recovery_ends_by_the_relays_that_lack_the_change() {
        let ok = (Some(Class::Ok), true);
        let stuck = (Some(Class::Stuck), true);
        let moving = (None, true);
        let out_holding = (Some(Class::OutHolding), true);
        let out_lacking = (Some(Class::OutLacking), false);
        let refusing = (Some(Class::Refusing), false);
        let lacks_for_now = (None, false);
        for holding in [vec![ok], vec![stuck, moving], vec![out_holding, ok]] {
            assert_eq!(recovery_end_of(&holding), Some(RecoveryEnd::Recovered));
            // Where no relay lacks the change, a recovery is not "not done".
            assert!(!ends_recovery_not_done(&holding), "{holding:?}");
        }
        for lacking in [
            vec![ok, out_lacking],
            vec![refusing],
            vec![moving, out_lacking, refusing],
        ] {
            assert_eq!(recovery_end_of(&lacking), Some(RecoveryEnd::NotDone));
        }
        for waits in [vec![ok, lacks_for_now], vec![lacks_for_now, out_lacking]] {
            assert_eq!(recovery_end_of(&waits), None);
        }
        assert_eq!(recovery_end_of(&[]), None);
        assert_eq!(RecoveryEnd::Recovered.status(), 0);
        assert_eq!(RecoveryEnd::NotDone.status(), 3);
    }

    // ── The looks, as the node gives them ───────────────────────────

    /// What a relay is, by the events that the node meets.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Scenario {
        Ok,
        Moving,
        Stuck,
        LacksForAMoment,
        Refusing,
        OutHolding,
        OutLacking,
        Dialling,
        KeylessGone,
    }

    const SCENARIOS: [Scenario; 9] = [
        Scenario::Ok,
        Scenario::Moving,
        Scenario::Stuck,
        Scenario::LacksForAMoment,
        Scenario::Refusing,
        Scenario::OutHolding,
        Scenario::OutLacking,
        Scenario::Dialling,
        Scenario::KeylessGone,
    ];

    /// What the node knows of a relay's reach once it has met the events
    /// of `scenario`, by its own [`Reach`], with a clock that the test
    /// runs ahead.
    pub(crate) fn reached(scenario: Scenario) -> Reached {
        let clock = Clock::system();
        let reach = Reach::new(clock.clone());
        let key = (scenario != Scenario::KeylessGone).then_some(BY);
        let relay = RelayId {
            name: "relay.example:9474".into(),
            key,
        };
        let link: LinkId = [3; 32];
        let held = match scenario {
            Scenario::Ok
            | Scenario::Moving
            | Scenario::Stuck
            | Scenario::OutHolding
            | Scenario::KeylessGone => Holds::Holds,
            _ => Holds::Lacks,
        };
        reach.observe(Some(KEPT), true, &[(relay.clone(), held, None)]);
        let five_minutes = Duration::from_secs(300);
        let fails_for_five_minutes = || {
            for _ in 0..11 {
                reach.dial_begins(&relay);
                reach.dial_ends(&relay, false);
                clock.run_ahead(Duration::from_secs(30));
            }
        };
        let shown = |said: Said, holds: Holds| {
            reach.connection(&relay, Some(link));
            reach.show_begins(&relay);
            reach.show_ends(&relay, link, said, holds);
        };
        match scenario {
            Scenario::Ok => {
                shown(Said::Holds, Holds::Holds);
                reach.waits(&relay, false);
            }
            Scenario::Moving => {
                shown(Said::Holds, Holds::Holds);
                reach.waits(&relay, true);
            }
            Scenario::Stuck => {
                shown(Said::Holds, Holds::Holds);
                reach.waits(&relay, true);
                reach.refused_what_waits(&relay);
                clock.run_ahead(five_minutes);
            }
            Scenario::LacksForAMoment => shown(Said::Lacks, Holds::Lacks),
            Scenario::Refusing => {
                shown(Said::Lacks, Holds::Lacks);
                clock.run_ahead(five_minutes);
            }
            Scenario::OutHolding | Scenario::OutLacking => fails_for_five_minutes(),
            Scenario::Dialling => reach.dial_begins(&relay),
            Scenario::KeylessGone => {
                shown(Said::Holds, Holds::Holds);
                reach.connection(&relay, None);
                fails_for_five_minutes();
            }
        }
        reach.of(&relay)
    }

    /// A look after change 3, built by the node's own function from where
    /// the device stands at each relay (`cordelia_api::look::relays`), with
    /// this device's own word and the node's `word_to_come`.
    pub(crate) fn look_at(relays: &[(Scenario, Reached)], word: OwnWord, to_come: bool) -> Value {
        let at = AtRelays {
            relays: relays
                .iter()
                .enumerate()
                .map(|(n, (scenario, reach))| AtRelay {
                    relay: format!("relay-{n}.example:9474"),
                    holds_latest: None,
                    heard_since_woke: true,
                    no_room: (*scenario == Scenario::Refusing).then_some(NoRoom {
                        at: 0,
                        over_allowance: false,
                        of: cordelia_api::state::RefusedOf::Change,
                    }),
                    another_form: 0,
                    refuses: None,
                    reach: Reached {
                        lacks_for: (*scenario == Scenario::Refusing).then_some(LacksFor::Room(
                            NoRoom {
                                at: 0,
                                over_allowance: false,
                                of: cordelia_api::state::RefusedOf::Change,
                            },
                        )),
                        ..reach.clone()
                    },
                    key: reach.key,
                })
                .collect(),
            cannot_go_on: None,
            word_to_come: to_come,
            woke_at: None,
        };
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let mut relays = serde_json::to_value(looked(&at)).unwrap();
        for relay in relays.as_array_mut().unwrap() {
            relay["dial"] = "dialled".into();
        }
        json!({
            "change": 3,
            "latest": hex::encode(KEPT),
            "relays": relays,
            "word_to_come": to_come,
            "devices": [{
                "key": encode_public_key(&own).unwrap(),
                "applied": 3,
                "sent": word == OwnWord::Sent,
                "carried_word": match word {
                    OwnWord::Carried => json!({ "keys": [], "more": 0, "not_yet": 0 }),
                    _ => Value::Null,
                },
            }],
        })
    }

    /// [`end_of_look`], of a look that can be read.
    fn end_of_look_ok(
        seen: &Value,
        number: u64,
        own: &[u8; 32],
    ) -> (Vec<RelayAt>, OwnWord, Option<End>) {
        end_of_look(seen, number, own).unwrap()
    }

    /// The wait never says that the machine may be closed, and never ends
    /// with status 0, while a relay lacks the change (decision 2026-10-19
    /// §4, rule 8): over every combination, as the node gives them, of the
    /// state of two and of three relays, the device's own word, and the
    /// word to come. Each look is built by the node's own functions from
    /// the events each relay met, not written by the test: what waits, and
    /// a refusal, come together only as the node gives them.
    #[test]
    fn the_wait_never_says_may_be_closed_or_ends_with_0_while_a_relay_lacks_the_change() {
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let states: Vec<(Scenario, Reached)> = SCENARIOS
            .iter()
            .map(|scenario| (*scenario, reached(*scenario)))
            .collect();
        // Each scenario is what it is named.
        let class_of =
            |scenario: Scenario| states.iter().find(|(s, _)| *s == scenario).unwrap().1.class;
        assert_eq!(class_of(Scenario::Ok), Some(Class::Ok));
        assert_eq!(class_of(Scenario::Moving), None);
        assert_eq!(class_of(Scenario::Stuck), Some(Class::Stuck));
        assert_eq!(class_of(Scenario::LacksForAMoment), None);
        assert_eq!(class_of(Scenario::Refusing), Some(Class::Refusing));
        assert_eq!(class_of(Scenario::OutHolding), Some(Class::OutHolding));
        assert_eq!(class_of(Scenario::OutLacking), Some(Class::OutLacking));
        assert_eq!(class_of(Scenario::Dialling), None);
        assert_eq!(class_of(Scenario::KeylessGone), Some(Class::OutLacking));
        // Since when a relay that is STUCK has refused what waits, by the
        // time of day; none where nothing waits.
        let of = |scenario: Scenario| &states.iter().find(|(s, _)| *s == scenario).unwrap().1;
        assert!(of(Scenario::Stuck).refusing_waits_since.is_some());
        assert_eq!(of(Scenario::Ok).refusing_waits_since, None);
        assert_eq!(of(Scenario::Moving).refusing_waits_since, None);
        let mut ends = [0usize; 3];
        let mut check = |relays: &[(Scenario, Reached)]| {
            let lacks = relays.iter().any(|(_, reach)| reach.holds != Holds::Holds);
            for word in [OwnWord::None, OwnWord::Carried, OwnWord::Sent] {
                for to_come in [false, true] {
                    let seen = look_at(relays, word, to_come);
                    let (looked, read, end) = end_of_look(&seen, 3, &own).unwrap();
                    assert_eq!(read, word);
                    let Some(end) = end else { continue };
                    ends[match end {
                        End::Done => 0,
                        End::Warned => 1,
                        End::NotDone => 2,
                    }] += 1;
                    let lines = end_lines(end, &looked, read, 0).join("\n");
                    if lacks {
                        assert_eq!(end, End::NotDone, "{relays:?} {word:?} {to_come}");
                        assert_ne!(end.status(), 0);
                        assert!(!lines.contains("may be closed"), "{lines}");
                        assert!(!lines.contains("You may close"), "{lines}");
                    }
                }
            }
        };
        for a in &states {
            for b in &states {
                check(&[a.clone(), b.clone()]);
                for c in &states {
                    check(&[a.clone(), b.clone(), c.clone()]);
                }
            }
        }
        // Each end is met.
        assert!(ends.iter().all(|n| *n > 0), "{ends:?}");
    }

    /// The command reads `word_to_come` from the node's look, and never
    /// works the word's conditions out itself (decision 2026-10-19 §4,
    /// rule 8): the same relays and the same own word end at end 2 where
    /// the node says that no word is to come, and wait where it says one
    /// is.
    #[test]
    fn the_command_reads_word_to_come_from_the_node() {
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let relays = [
            (Scenario::Ok, reached(Scenario::Ok)),
            (Scenario::OutHolding, reached(Scenario::OutHolding)),
        ];
        for word in [OwnWord::None, OwnWord::Carried, OwnWord::Sent] {
            let (_, _, end) = end_of_look_ok(&look_at(&relays, word, false), 3, &own);
            assert_eq!(end, Some(End::Warned), "{word:?}");
            let (_, _, end) = end_of_look_ok(&look_at(&relays, word, true), 3, &own);
            assert_eq!(end, None, "{word:?}");
        }
        // Every relay OK: end 1 waits for `sent`, which is to come.
        let ok = [
            (Scenario::Ok, reached(Scenario::Ok)),
            (Scenario::Ok, reached(Scenario::Ok)),
        ];
        let (_, _, end) = end_of_look_ok(&look_at(&ok, OwnWord::Carried, true), 3, &own);
        assert_eq!(end, None);
        let (_, _, end) = end_of_look_ok(&look_at(&ok, OwnWord::Sent, false), 3, &own);
        assert_eq!(end, Some(End::Done));
        // A relay in the third state is not taken to hold the change.
        let mut seen = look_at(&relays, OwnWord::Sent, false);
        seen["relays"][1]["reach"]["holds"] = "neither".into();
        let read = relays_of(&seen).unwrap();
        assert!(read[0].holds() && !read[1].holds());
        // How the node tries each relay is read from the look.
        for (said, dial) in [
            ("connected", Dial::Connected),
            ("dialled", Dial::Dialled),
            ("looked_up", Dial::LookedUp),
            ("not_dialled", Dial::NotDialled),
        ] {
            seen["relays"][0]["dial"] = said.into();
            assert_eq!(relays_of(&seen).unwrap()[0].dial, dial);
        }
        // The own word is this change's: a word under the change before
        // is no word.
        let mut seen = look_at(&ok, OwnWord::Sent, false);
        seen["devices"][0]["applied"] = 2.into();
        assert_eq!(end_of_look_ok(&seen, 3, &own).1, OwnWord::None);
        assert_eq!(end_of_look_ok(&seen, 3, &own).2, Some(End::Warned));
        // Where no relay is OK and none lacks the change, the same.
        let stuck = [(Scenario::Stuck, reached(Scenario::Stuck))];
        let (_, _, end) = end_of_look_ok(&look_at(&stuck, OwnWord::None, true), 3, &own);
        assert_eq!(end, None);
        let (_, _, end) = end_of_look_ok(&look_at(&stuck, OwnWord::None, false), 3, &own);
        assert_eq!(end, Some(End::NotDone));
    }

    /// A recovery's wait gives no end on what the node knows of its relays
    /// from before the change (decision 2026-10-19 §4, rule 9, as rule 8
    /// has it): a look whose relays' reach is about another entry than the
    /// kept entry it names, or that names none, gives no R1 and no status
    /// 0, and no end at all. Once every relay's reach is about the kept
    /// entry, the end holds. A relay whose reach cannot be read is an
    /// error.
    #[test]
    fn a_recoverys_look_whose_classes_are_about_the_entry_before_ends_nothing() {
        let ok = (Scenario::Ok, reached(Scenario::Ok));
        let out = (Scenario::OutHolding, reached(Scenario::OutHolding));
        let lacking = (Scenario::OutLacking, reached(Scenario::OutLacking));
        for (relays, end) in [
            (vec![ok.clone(), out.clone()], RecoveryEnd::Recovered),
            (vec![ok.clone(), lacking.clone()], RecoveryEnd::NotDone),
        ] {
            let seen = look_at(&relays, OwnWord::None, false);
            assert_eq!(recovery_end_of_look(&seen).unwrap().1, Some(end));
            let mut before = seen.clone();
            before["latest"] = hex::encode(BEFORE).into();
            assert_eq!(recovery_end_of_look(&before).unwrap().1, None, "{end:?}");
            let mut one = seen.clone();
            one["relays"][1]["reach"]["about"] = hex::encode(BEFORE).into();
            assert_eq!(recovery_end_of_look(&one).unwrap().1, None, "{end:?}");
            let mut none = seen.clone();
            none.as_object_mut().unwrap().remove("latest");
            assert_eq!(recovery_end_of_look(&none).unwrap().1, None, "{end:?}");
            let mut unread = seen.clone();
            unread["relays"][0]["reach"] = "what this command cannot read".into();
            assert!(recovery_end_of_look(&unread).is_err(), "{end:?}");
            let mut missing = seen.clone();
            missing["relays"][1]
                .as_object_mut()
                .unwrap()
                .remove("reach");
            assert!(recovery_end_of_look(&missing).is_err(), "{end:?}");
        }
    }

    /// No end holds on what the node knows of its relays from before the
    /// change (decision 2026-10-19 §4, rule 8): a look whose relays' reach
    /// is about another entry than the kept entry it names, or that names
    /// none, gives no end, so no status 0 and no "may be closed", whatever
    /// the classes say. Once every relay's reach is about the kept entry,
    /// the end holds.
    #[test]
    fn a_look_whose_classes_are_about_the_entry_before_ends_nothing() {
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let ok = (Scenario::Ok, reached(Scenario::Ok));
        let out = (Scenario::OutHolding, reached(Scenario::OutHolding));
        let lacking = (Scenario::OutLacking, reached(Scenario::OutLacking));
        for (relays, word, end) in [
            (vec![ok.clone(), ok.clone()], OwnWord::Sent, End::Done),
            (vec![ok.clone(), out.clone()], OwnWord::Carried, End::Warned),
            (
                vec![ok.clone(), lacking.clone()],
                OwnWord::None,
                End::NotDone,
            ),
        ] {
            let seen = look_at(&relays, word, false);
            assert_eq!(end_of_look_ok(&seen, 3, &own).2, Some(end));
            // The kept entry is the change; the classes are of the one
            // before it.
            let mut before = seen.clone();
            before["latest"] = hex::encode(BEFORE).into();
            assert_eq!(end_of_look_ok(&before, 3, &own).2, None, "{end:?}");
            // One relay's reach is of the entry before.
            let mut one = seen.clone();
            one["relays"][1]["reach"]["about"] = hex::encode(BEFORE).into();
            assert_eq!(end_of_look_ok(&one, 3, &own).2, None, "{end:?}");
            // The node has not found the kept entry yet; the look names
            // none.
            let mut none = seen.clone();
            none["relays"][0]["reach"]["about"] = Value::Null;
            assert_eq!(end_of_look_ok(&none, 3, &own).2, None, "{end:?}");
            let mut unnamed = seen.clone();
            unnamed.as_object_mut().unwrap().remove("latest");
            assert_eq!(end_of_look_ok(&unnamed, 3, &own).2, None, "{end:?}");
            // Nor where neither the look nor any relay names one.
            for relay in unnamed["relays"].as_array_mut().unwrap() {
                relay["reach"]["about"] = Value::Null;
            }
            assert_eq!(end_of_look_ok(&unnamed, 3, &own).2, None, "{end:?}");
        }
    }

    /// A look that cannot be read ends the wait as an error (decision
    /// 2026-10-19 §4, rule 8; status 3): a relay with no reach, or with
    /// one that says what this command does not know, would be in no class
    /// for ever; and a look that does not say whether a word is to come.
    #[test]
    fn a_look_that_cannot_be_read_ends_the_wait_as_an_error() {
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let relays = [
            (Scenario::Ok, reached(Scenario::Ok)),
            (Scenario::OutHolding, reached(Scenario::OutHolding)),
        ];
        let seen = look_at(&relays, OwnWord::Carried, false);
        assert!(end_of_look(&seen, 3, &own).is_ok());
        let mut none = seen.clone();
        none["relays"][1].as_object_mut().unwrap().remove("reach");
        let error = end_of_look(&none, 3, &own).unwrap_err().to_string();
        assert!(
            error.contains("the node says of relay-1.example:9474 what this command cannot read"),
            "{error}"
        );
        let mut unknown = seen.clone();
        unknown["relays"][0]["reach"]["class"] = "lost".into();
        assert!(end_of_look(&unknown, 3, &own).is_err());
        let mut unsaid = seen.clone();
        unsaid.as_object_mut().unwrap().remove("word_to_come");
        let error = end_of_look(&unsaid, 3, &own).unwrap_err().to_string();
        assert!(
            error.contains("whether its next pass writes a word"),
            "{error}"
        );
    }

    // ── The words ───────────────────────────────────────────────────

    /// 12:00 UTC on 2026-10-20, in seconds.
    fn noon() -> i64 {
        chrono::DateTime::parse_from_rfc3339("2026-10-20T12:00:00Z")
            .unwrap()
            .timestamp()
    }

    /// A relay as a look shows it, at `noon() - ago` for each of its times.
    fn relay_at(name: &str, class: Option<Class>, holds: bool, dial: Dial) -> RelayAt {
        let reached = matches!(class, Some(Class::Ok | Class::Stuck | Class::Refusing));
        RelayAt {
            name: name.into(),
            reach: Some(ReachLook {
                about: Some(hex::encode(KEPT)),
                lacks_for: None,
                class,
                holds: if holds { Holds::Holds } else { Holds::Lacks },
                reached,
                out_of_reach_since: matches!(class, Some(Class::OutHolding | Class::OutLacking))
                    .then_some(noon() - 60),
                reference: noon() - 600,
                reference_by: cordelia_api::state::ReferenceBy::Change,
                last_reached: None,
                refused_since: None,
                waits: None,
                refusing_waits_since: (class == Some(Class::Stuck)).then_some(noon() - 420),
                no_room: None,
                answered_at: None,
                lacking_secs: None,
            }),
            dial,
            has_what_was_carried: None,
        }
    }

    /// S9 of a relay given no key at a keyed relay's place, word for word
    /// (decision 2026-10-19 §5; decision 2026-10-17 §1): it is never
    /// reached, and the person is told what to do. It is not said to be
    /// dialled every 30 seconds.
    #[test]
    fn s9_says_what_to_do_of_a_relay_given_no_key_at_a_keyed_relays_place() {
        let ok = relay_at("a.example:9474", Some(Class::Ok), true, Dial::Connected);
        let keyless = |name: &str| relay_at(name, Some(Class::OutLacking), false, Dial::NoKey);
        let s9 = |relays: &[RelayAt]| -> String {
            let lines = end_lines(End::NotDone, relays, OwnWord::None, noon());
            let s9 = lines
                .iter()
                .find(|line| line.starts_with("A device of yours"));
            s9.cloned().unwrap_or_default()
        };
        let one = s9(&[ok.clone(), keyless("b.example:9474")]);
        assert!(
            one.contains(
                "b.example:9474 is given no key, at the address of a relay given one, so this \
                 machine never reaches it. To have it reached, give it that relay's key, or \
                 remove it from your configuration."
            ),
            "{one}"
        );
        assert!(!one.contains("dials"), "{one}");
        let two = s9(&[ok, keyless("b.example:9474"), keyless("c.example:9474")]);
        assert!(
            two.contains(
                "b.example:9474 and c.example:9474 are given no key, at the address of a relay \
                 given one, so this machine never reaches them. To have them reached, give each \
                 that relay's key, or remove them from your configuration."
            ),
            "{two}"
        );
    }

    /// Each line of the wait after a change, word for word (decision
    /// 2026-10-19 §5): S1, S2, S3, S6, S6b, S7, S8, S9, S10, S10b and S11;
    /// `<since>` in its forms and `<when>` with and without its date;
    /// what is said on an error in the wait; and H1 and H2 (rule 14). S1
    /// says that each line has its time, and S2, S3, S6 and S8 that a
    /// relay out of reach cannot be reached from here (decision 2026-10-24,
    /// rules 3 and 7).
    #[test]
    fn each_line_word_for_word() {
        let now = noon();
        assert_eq!(
            first_line(),
            "You may close this machine once every relay holds the change, and what this device \
             carried is at a relay that it reaches. This command stays until then, and says \
             what is missing. It ends sooner, with status 3, where for five minutes a relay \
             that is not known to hold the change cannot be reached or refuses it, or where no \
             relay that this machine reaches has what this device carried. It then does not say \
             that you may close this machine. Stopping it stops nothing: the node goes on. Until \
             the wait ends, each line below starts with the time it was said, in UTC."
        );

        // `<when>`, today and not; `<since>`, both forms.
        assert_eq!(when(now - 600, now), "11:50 UTC");
        assert_eq!(when(now - 13 * 3600, now), "23:00 UTC on 2026-10-19");
        let a = relay_at(
            "a.example:9474",
            Some(Class::OutLacking),
            false,
            Dial::Dialled,
        );
        let mut reach = a.reach.clone().unwrap();
        assert_eq!(
            since(&reach, now),
            "has not answered since this device applied the change at 11:50 UTC"
        );
        reach.last_reached = Some(now - 300);
        reach.reference = now - 300;
        reach.reference_by = cordelia_api::state::ReferenceBy::Reached;
        assert_eq!(since(&reach, now), "has not been reached since 11:55 UTC");
        // Reached, and then the kept entry changed: since the change, and
        // when it was last reached.
        reach.reference = now - 120;
        reach.reference_by = cordelia_api::state::ReferenceBy::Change;
        assert_eq!(
            since(&reach, now),
            "has not answered since this device applied the change at 11:58 UTC (it was last \
             reached at 11:55 UTC)"
        );

        // S2 and S3.
        assert_eq!(
            out_of_reach_line(&a, now),
            "keep this machine on: a.example:9474 cannot be reached from here, and is not known \
             to hold the change yet: it has not answered since this device applied the change at \
             11:50 UTC"
        );
        let b = relay_at(
            "b.example:9474",
            Some(Class::OutHolding),
            true,
            Dial::Dialled,
        );
        assert_eq!(
            out_of_reach_line(&b, now),
            "b.example:9474 holds the change, and cannot be reached from here: it has not \
             answered since this device applied the change at 11:50 UTC"
        );

        // End 2: S6 in both forms, S6b, and S7.
        let ok = relay_at("a.example:9474", Some(Class::Ok), true, Dial::Connected);
        let mut out_whole = relay_at(
            "b.example:9474",
            Some(Class::OutHolding),
            true,
            Dial::Dialled,
        );
        out_whole.has_what_was_carried = Some(true);
        let stuck = relay_at("c.example:9474", Some(Class::Stuck), true, Dial::Connected);
        let lines = end_lines(
            End::Warned,
            &[ok.clone(), out_whole.clone()],
            OwnWord::Carried,
            now,
        );
        assert_eq!(
            lines,
            [
                "  b.example:9474 holds the change and all that this device carried, and cannot \
                 be reached from here: it has not answered since this device applied the change \
                 at 11:50 UTC.",
                "Every relay holds the change. You may close this machine. All that this device \
                 carried is at a.example:9474 and b.example:9474. What this device writes from \
                 now on waits for b.example:9474. `cordelia devices` shows which devices have \
                 applied the change.",
            ]
        );
        let lines = end_lines(
            End::Warned,
            &[ok.clone(), b.clone(), stuck.clone()],
            OwnWord::Carried,
            now,
        );
        assert_eq!(
            lines,
            [
                "  b.example:9474 holds the change, and cannot be reached from here: it has not \
                 answered since this device applied the change at 11:50 UTC. Some of what this \
                 device carried is not there yet.",
                "  c.example:9474 holds the change. It has refused for room what this device \
                 still has to send there since 11:53 UTC.",
                "Every relay holds the change. You may close this machine. All that this device \
                 carried is at a.example:9474. b.example:9474 and c.example:9474 get the rest \
                 when this machine next reaches them. What this device writes from now on waits \
                 for b.example:9474 and c.example:9474. `cordelia devices` shows which devices \
                 have applied the change.",
            ]
        );
        let lines = end_lines(End::Warned, &[ok.clone(), b.clone()], OwnWord::Carried, now);
        assert!(
            lines[1].contains("b.example:9474 gets the rest when this machine next reaches it."),
            "{lines:?}"
        );
        // On the `sent` path, every relay has all that this device carried.
        let lines = end_lines(End::Warned, &[ok.clone(), b.clone()], OwnWord::Sent, now);
        assert!(
            lines[0].contains("holds the change and all that this device carried"),
            "{lines:?}"
        );
        assert!(
            lines[1]
                .contains("All that this device carried is at a.example:9474 and b.example:9474."),
            "{lines:?}"
        );
        // End 1.
        assert_eq!(
            end_lines(End::Done, std::slice::from_ref(&ok), OwnWord::Sent, now),
            [
                "Every relay holds the change, and this device has sent what it holds: this \
              machine may be closed. `cordelia devices` shows which devices have applied the \
              change."
            ]
        );

        // End 3, a relay reached: S8 of each kind, S9 and S10.
        let mut full = relay_at(
            "d.example:9474",
            Some(Class::Refusing),
            false,
            Dial::Connected,
        );
        let room = |over_allowance| {
            Some(LacksFor::Room(NoRoom {
                at: now - 900,
                over_allowance,
                of: cordelia_api::state::RefusedOf::Change,
            }))
        };
        full.reach.as_mut().unwrap().lacks_for = room(false);
        let mut over = full.clone();
        over.name = "e.example:9474".into();
        over.reach.as_mut().unwrap().lacks_for = room(true);
        let mut another = relay_at(
            "f.example:9474",
            Some(Class::Refusing),
            false,
            Dial::Connected,
        );
        another.reach.as_mut().unwrap().lacks_for = Some(LacksFor::Another {
            why: Some("another key than the phrase's wrote it".into()),
        });
        let unresolved = relay_at(
            "g.example:9474",
            Some(Class::OutLacking),
            false,
            Dial::LookedUp,
        );
        let unanswered = relay_at(
            "h.example:9474",
            Some(Class::OutLacking),
            false,
            Dial::Connected,
        );
        let wrong_key = relay_at(
            "i.example:9474",
            Some(Class::OutLacking),
            false,
            Dial::NotDialled,
        );
        let relays = [
            ok.clone(),
            a.clone(),
            b.clone(),
            stuck.clone(),
            full,
            over,
            another,
            unresolved,
            unanswered,
            wrong_key,
        ];
        let lines = end_lines(End::NotDone, &relays, OwnWord::None, now);
        assert_eq!(
            lines,
            [
                "  a.example:9474 cannot be reached from here, and is not known to hold the \
                 change: it has not answered since this device applied the change at 11:50 UTC.",
                "  b.example:9474 holds the change, and cannot be reached from here: it has not \
                 answered since this device applied the change at 11:50 UTC.",
                "  c.example:9474 holds the change. It has refused for room what this device \
                 still has to send there since 11:53 UTC.",
                "  d.example:9474 is reached, and has not taken the change: it had no room for \
                 it at 11:45 UTC (it is full).",
                "  e.example:9474 is reached, and has not taken the change: it had no room for \
                 it at 11:45 UTC (this address is over its allowance of new channels there).",
                "  f.example:9474 is reached, and holds a change that this device does not take \
                 (another key than the phrase's wrote it). It does not take this one in its \
                 place.",
                "  g.example:9474 cannot be reached from here, and is not known to hold the \
                 change: it has not answered since this device applied the change at 11:50 UTC.",
                "  h.example:9474 cannot be reached from here, and is not known to hold the \
                 change: it has not answered since this device applied the change at 11:50 UTC.",
                "  i.example:9474 cannot be reached from here, and is not known to hold the \
                 change: it has not answered since this device applied the change at 11:50 UTC.",
                "A device of yours that reaches only a.example:9474, d.example:9474, \
                 e.example:9474, f.example:9474, g.example:9474, h.example:9474 and \
                 i.example:9474 may not have heard of the change. Until it does, it goes on in \
                 the channels from before the change, where every device that held their secret \
                 can still read what it writes. a.example:9474, g.example:9474, h.example:9474 \
                 and i.example:9474 take the change from a device that has applied it and \
                 reaches them, this one included, and from a relay that works with them. While \
                 this machine is on it dials it every 30 seconds. It looks its name up every 30 \
                 seconds. It shows it the change again at most every ten minutes. It cannot dial \
                 i.example:9474 while another relay answers at its address. d.example:9474, \
                 e.example:9474 and f.example:9474 refuse the change. A device that reaches \
                 them hears of it only once they take it, or from another relay.",
                "The change is not known to be at a.example:9474, d.example:9474, \
                 e.example:9474, f.example:9474, g.example:9474, h.example:9474 and \
                 i.example:9474. This command ends here, with status 3. It does not say that \
                 you may close this machine. `cordelia devices`, here or on a device of yours \
                 that reaches them, says when they hold the latest change.",
            ]
        );
        // A relay that holds another change, with no reason known, and one
        // of which no reason was noted.
        let mut other = relay_at(
            "m.example:9474",
            Some(Class::Refusing),
            false,
            Dial::Connected,
        );
        other.reach.as_mut().unwrap().lacks_for = Some(LacksFor::Another { why: None });
        let unnoted = relay_at(
            "n.example:9474",
            Some(Class::Refusing),
            false,
            Dial::Connected,
        );
        let lines = end_lines(End::NotDone, &[other, unnoted], OwnWord::None, now);
        assert_eq!(
            lines[..2],
            [
                "  m.example:9474 is reached, and holds a change that this device does not take \
                 (it is another change than the one this device keeps). It does not take this \
                 one in its place.",
                "  n.example:9474 is reached, and has not taken the change.",
            ]
        );
        // One relay of each kind: the singular.
        let mut two_dialled = a.clone();
        two_dialled.name = "j.example:9474".into();
        let mut two_looked_up = relay_at(
            "k.example:9474",
            Some(Class::OutLacking),
            false,
            Dial::LookedUp,
        );
        let mut two_shown = relay_at(
            "l.example:9474",
            Some(Class::OutLacking),
            false,
            Dial::Connected,
        );
        let lines = end_lines(
            End::NotDone,
            &[
                ok.clone(),
                a.clone(),
                two_dialled,
                relays[7].clone(),
                two_looked_up.clone(),
                relays[8].clone(),
                two_shown.clone(),
            ],
            OwnWord::None,
            now,
        );
        let s9 = &lines[lines.len() - 2];
        assert!(
            s9.contains("While this machine is on it dials them every 30 seconds."),
            "{s9}"
        );
        assert!(
            s9.contains("It looks their names up every 30 seconds."),
            "{s9}"
        );
        assert!(
            s9.contains("It shows them the change again at most every ten minutes."),
            "{s9}"
        );
        two_looked_up.reach.as_mut().unwrap().class = Some(Class::Refusing);
        two_looked_up.reach.as_mut().unwrap().reached = true;
        two_shown.reach.as_mut().unwrap().class = Some(Class::Ok);
        two_shown.reach.as_mut().unwrap().holds = Holds::Holds;
        let lines = end_lines(
            End::NotDone,
            &[two_shown, two_looked_up],
            OwnWord::None,
            now,
        );
        assert_eq!(
            lines[1],
            "A device of yours that reaches only k.example:9474 may not have heard of the \
             change. Until it does, it goes on in the channels from before the change, where \
             every device that held their secret can still read what it writes. k.example:9474 \
             refuses the change. A device that reaches it hears of it only once it takes it, \
             or from another relay."
        );
        assert_eq!(
            lines[2],
            "The change is not known to be at k.example:9474. This command ends here, with \
             status 3. It does not say that you may close this machine. `cordelia devices`, \
             here or on a device of yours that reaches it, says when it holds the latest change."
        );
        let lines = end_lines(End::NotDone, &[ok.clone(), a.clone()], OwnWord::None, now);
        assert!(
            lines[1].contains(
                "a.example:9474 takes the change from a device that has applied it and reaches it, \
             this one included, and from a relay that works with it."
            ),
            "{lines:?}"
        );

        // S10b: every relay holds the change, none is OK, one is reached.
        let lines = end_lines(
            End::NotDone,
            &[stuck.clone(), b.clone()],
            OwnWord::None,
            now,
        );
        assert_eq!(
            lines.last().unwrap(),
            "Every relay holds the change. What this device carried is at no relay that this \
             machine reaches: c.example:9474 refuses it for room. This command ends here, with \
             status 3. It does not say that you may close this machine. Keep it on. `cordelia \
             devices` says when what it carried is sent."
        );
        // S9 says nothing of a relay that lacks nothing.
        assert_eq!(lines.len(), 3, "{lines:?}");

        // S11, with and without its second part.
        let lines = end_lines(
            End::NotDone,
            &[a.clone(), relays[7].clone()],
            OwnWord::None,
            now,
        );
        assert_eq!(
            lines.last().unwrap(),
            "No relay can be reached from here. None is known to hold the change. No other \
             device of yours can hear of it until one does. This command ends here, with status \
             3. It does not say that you may close this machine. Keep it on, on a network from \
             which a relay can be reached. `cordelia devices` says what is missing."
        );
        assert_eq!(
            lines.len(),
            3,
            "S9 is said only where a relay is reached: {lines:?}"
        );
        let lines = end_lines(End::NotDone, std::slice::from_ref(&b), OwnWord::None, now);
        assert_eq!(
            lines,
            [
                "  b.example:9474 holds the change, and cannot be reached from here: it has not \
                 answered since this device applied the change at 11:50 UTC.",
                "No relay can be reached from here. This command ends here, with status 3. It \
                 does not say that you may close this machine. Keep it on, on a network from \
                 which a relay can be reached. `cordelia devices` says what is missing.",
            ]
        );

        // An error in the wait.
        assert_eq!(
            could_not_go_on(4, &anyhow::anyhow!("the node did not answer")),
            "The change is made (change 4). This command could not go on: the node did not \
             answer. Do not make the change again. `cordelia devices` shows whether each relay \
             holds it."
        );

        // H1, in the help of each command that makes a change, and H2.
        use clap::CommandFactory;
        let h1 = "Keep this machine on until the command says you can close it. Where a relay \
                  that is not known to hold the change cannot be reached, or refuses it, the \
                  command says so and ends with status 3, without saying that you can. Any \
                  status other than 0, 1 and 2 means that the change is made: do not make it \
                  again.";
        let h2 = "After the look the command waits for every relay to hold the change. Where one \
                  that is not known to hold it cannot be reached, or refuses it, the command \
                  says so and ends with status 3. Any status other than 0, 1 and 2 means that \
                  the recovery is made: do not run it again. Keep this machine on.";
        let mut cli = crate::Cli::command();
        let help_of = |cli: &mut clap::Command, name: &str| {
            cli.find_subcommand_mut(name)
                .expect("a command")
                .render_long_help()
                .to_string()
                .replace('\n', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        for name in ["remove-device", "renew", "settle"] {
            let help = help_of(&mut cli, name);
            assert!(help.contains(h1), "{name}: {help}");
        }
        assert!(help_of(&mut cli, "recover").contains(h2));
    }

    /// The wait after a change, and a recovery's, end with status 3 where
    /// the device no longer stands in its phrase (decision 2026-10-19 §4,
    /// rule 8): removed, in no list, unable to open the change, or with no
    /// phrase, it shows the change to no relay, and no end would hold. A
    /// device in a fork, and one that stands, go on.
    #[test]
    fn the_wait_ends_where_the_device_no_longer_stands_in_its_phrase() {
        let look = |state: &str| json!({ "state": state, "cannot_go_on": "why it cannot" });
        for state in ["removed", "not_listed", "not_opened", "no_phrase"] {
            assert_eq!(
                no_longer_stands(&look(state)).as_deref(),
                Some(
                    "This device no longer stands in its phrase (why it cannot): it shows the \
                     change to no relay, and what each relay holds is not known from here. This \
                     command ends here, with status 3. It does not say that you may close this \
                     machine. `cordelia devices` says what is so."
                ),
                "{state}"
            );
        }
        let said = no_longer_stands(&json!({ "state": "removed" })).unwrap();
        assert!(said.contains("(removed)"), "{said}");
        for state in ["applied", "fork", ""] {
            assert_eq!(no_longer_stands(&look(state)), None, "{state}");
        }
    }
}
