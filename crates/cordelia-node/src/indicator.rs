//! One state, one level and a short summary of this device's memory
//! sync, for status bars: `cordelia status --line` (the Claude Code status
//! line) and `cordelia status --json` (bar widgets and scripts).
//!
//! **The level is worked out here, in the command, and nowhere else**
//! (decision 2026-10-04 §10.1): red, amber or none. Only the command
//! knows whether the running node is its own version. A panel draws the
//! level that `--json` gives it, and works nothing out itself.
//!
//! - **Red** is what a person should act on now. **Amber** is what a
//!   person should know of, and need not act on in the folders. Two lists
//!   decide, and not a principle ([`holds`]).
//! - **The level is the gravest that holds, and the line shows the first
//!   thing of that level** ([`shown`]), so that the mark and the words
//!   never disagree. A tooltip lists everything that holds.
//! - **The state is worked out as it was** ([`derive`]), whatever the
//!   level, for a panel that draws from it alone.
//! - **Before any level:** a device that is not set up, a node that is
//!   stopped or was not asked, and a relay or a bootnode are states of
//!   their own, with no level. A level is for a personal node that runs.
//! - **What is about folders needs sync on, something mapped and a
//!   report. What is about a person's devices holds wherever this device
//!   follows a phrase,** with sync on or off, and with or without a folder
//!   mapped: a device that maps nothing is still one of the person's. **A
//!   node that is held up is red whatever sync says.**
//! - **The line and the level never disagree:** where a state is
//!   `attention` and there is no level, the line and the bar draw as they
//!   did before there was one ([`line`], [`bar`]).

/// A sync report older than this means the adapter has stopped cycling
/// (it runs every `cordelia_sync::claude::CYCLE_SECS`).
pub const STALE_REPORT_SECS: i64 = 60;

/// What the state is derived from.
#[derive(Debug, Default, Clone)]
pub struct Facts {
    /// `cordelia init` has run on this device.
    pub initialised: bool,
    /// The node answers on its local API.
    pub running: bool,
    /// The node was not asked: its API address is not one that a command
    /// asks. It is then not known to be stopped.
    pub not_asked: bool,
    pub role: String,
    pub peers_hot: u64,
    /// What was written here and a relay has not been sent yet: how many
    /// of the device's own channels have something waiting.
    pub outbox_waiting: u64,
    /// `cordelia sync claude` is on.
    pub sync_enabled: bool,
    /// Age of the last sync cycle's report, by the wall clock; `None`
    /// before the first cycle.
    pub report_age_secs: Option<i64>,
    /// For how long the node has stored no report, in seconds, by its
    /// own clock, which does not run while the machine sleeps: since the
    /// later of its start and the last report it stored. `None` beside a
    /// node that does not say.
    pub no_report_secs: Option<u64>,
    pub errors: Vec<String>,
    /// Conflict files waiting for someone to merge them.
    pub conflicts: Vec<String>,
    /// Memory files that are too large to sync (full paths).
    pub too_large: Vec<String>,
    /// Folders that wait for their channel to be fetched from a relay
    /// before their first cycle there (decision 2026-10-04 §6).
    pub projects_waiting: usize,
    /// Where the device stands under a recovery phrase, as the node says
    /// it: `no_phrase`, `applied`, or why it has stopped (`fork`,
    /// `removed`, `not_listed`, `not_opened`, `closed`). Empty where the node did
    /// not say.
    pub stands: String,
    /// Folders the last cycle synced or is waiting to sync.
    pub folders: usize,
    /// What the node is held up by, as it says it, where it is (decision
    /// 2026-10-04 §10.1): `later_database` where its database is from a
    /// later version, `step_failed` where a step of its schema did not
    /// finish, or `earlier_database` where it is from a Cordelia
    /// before alpha.19 (decision 2026-11-10 (older kind), rule 6). It runs
    /// no cycle and no pass meanwhile.
    pub held: Option<String>,
    /// How many folders are mapped, as the node's settings have them.
    pub mapped: usize,
    /// For how long the node has run, in seconds, where it says.
    pub uptime_secs: Option<u64>,
    /// For how long no relay has been connected, in seconds, by the
    /// node's own clock, which does not run while the machine sleeps.
    /// `None` while one is connected, and beside a node that does not
    /// say: a missing relay then gives no level.
    pub no_relay_secs: Option<u64>,
    /// The running node is another version than this command.
    pub other_version: bool,
    /// What the node says of this person's devices.
    pub devices: Devices,
    /// What the personal channel holds, from the last report that read
    /// it, with the device that signed each part where the node names it
    /// (decision 2026-10-19 §2). `None` where the report holds none.
    pub channel: Option<Channel>,
    /// The pairs of the person's agents held now, waiting for the person
    /// to read their messages, as the node counts them by the test a send
    /// makes (`held_pairs` of the status's `messages`, decision
    /// 2026-10-25, rule 4). 0 where none, or the node does not say.
    pub held_pairs: u64,
}

/// What the personal channel holds, as a relay counts it, as the last
/// cycle that read it found (decision 2026-10-19 §2, rules 2 to 4).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Channel {
    /// The channel's total, in bytes.
    pub total: u64,
    /// Of it, the bytes that are words.
    pub words: u64,
    /// Each key that signed an entry of it.
    pub by: Vec<Signer>,
}

/// A key that signed part of the personal channel, as a status names it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Signer {
    /// The key, as a device's key is written.
    pub key: String,
    /// Whether it is this device's.
    pub this_device: bool,
    /// The label it is known by, made printable; empty where the node
    /// knows none.
    pub label: String,
    /// The first four words of its key's fingerprint.
    pub words_of_key: String,
    /// Its bytes of words.
    pub words: u64,
    /// Its bytes of what is not a word.
    pub not_words: u64,
}

impl Channel {
    /// Whether the channel is past the line (decision 2026-10-19 §2, rule
    /// 3): what the warning and the sizes of `cordelia devices` turn on.
    pub fn past_the_line(&self) -> bool {
        self.total > cordelia_core::protocol::PERSONAL_CHANNEL_WARN_BYTES
    }

    /// What the warning says (decision 2026-10-19 §2, rule 4): the first
    /// of its four forms that holds. A key has filled most of the channel
    /// where it signed more than half of what is not words, and what it
    /// signed that is not words is more than a quarter of the total; in
    /// honest use what is not a word is far less than a quarter of the
    /// line, so only the third form shows.
    pub fn warning(&self) -> String {
        let not_words = self.total.saturating_sub(self.words);
        let filled = |signer: &&Signer| {
            signer.not_words.saturating_mul(2) > not_words
                && signer.not_words.saturating_mul(4) > self.total
        };
        let other = self.by.iter().filter(|s| !s.this_device).find(filled);
        if let Some(other) = other {
            // By the name you gave it, or by its words where you gave
            // none: `remove-device` shows the words before its yes
            // (decision 2026-11-11 (plain words), rule 4).
            return format!(
                "memory: {} has filled most of what your devices keep at a relay. If it is not \
                 yours, or you no longer use it, remove it: cordelia remove-device {}",
                device_named(&other.label, &other.words_of_key),
                other.key
            );
        }
        if self.by.iter().filter(|s| s.this_device).any(|s| filled(&s)) {
            return "memory: this device has filled most of what your devices keep at a relay. \
                    If you no longer use it, remove it from another of your devices."
                .into();
        }
        if self.words.saturating_mul(2) >= self.total {
            return "memory: you sync nearly as many names as a relay can keep for your devices. \
                    A name you add now may not reach your other devices. Stop syncing names you \
                    no longer need, on every device that syncs them: their room comes back \
                    slowly, at least 90 days later. Or remove a device you no longer use: its \
                    room comes back at once."
                .into();
        }
        "memory: what your devices keep at a relay is nearly full. Run cordelia devices to see \
         how much each device keeps there."
            .into()
    }
}

/// What a status goes by of a person's devices (decision 2026-10-04 §8,
/// §10.1), as the node's look at them gives it. Nothing of it holds where
/// the node did not say.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Devices {
    /// The device has applied a statement, and was answered with a
    /// change that it could not apply: it sends nothing and takes
    /// nothing until it can.
    pub not_applied: bool,
    /// A removal stands that some device has not applied: for how long,
    /// in seconds, since this device applied it. `None` where none does,
    /// or where this device does not know since when.
    pub removal_not_applied_secs: Option<u64>,
    /// The devices that removal removed, as a line names them
    /// ([`device_named`]): empty where the node does not say which.
    pub removed_named: Vec<String>,
    /// The device goes on with a head set aside (decision 2026-10-24
    /// (removal), rule 11): how long ago, in seconds, it set aside the
    /// newest. `None` where it sets none aside, or is closed.
    pub set_aside_secs: Option<u64>,
    /// How many devices were added since the last change and are not
    /// cleared.
    pub added_not_cleared: usize,
    /// Those devices, but this one, as a line names them
    /// ([`device_named`]), where the node names them: the line names them,
    /// and not a count (decision 2026-11-11 (plain words), rule 2).
    pub added_named: Vec<String>,
    /// Whether this device is among them: it was added, and is told so.
    pub added_this_device: bool,
    /// What the node's look says first of where this device stands
    /// (`short`), where it says: which way on a device that has stopped
    /// has ([`stopped_says`]).
    pub short: String,
    /// How many devices have said that they left.
    pub said_left: usize,
    /// Each relay that is not known to hold the latest change (decision
    /// 2026-10-19 §1), connected or not. A relay in the third state is not
    /// among them.
    pub not_known_to_hold: Vec<NotKnown>,
    /// How long ago, in seconds, the later of when this device came to
    /// keep the change entry it keeps and when this version first started
    /// on its database: a relay not known to hold the latest change is
    /// amber for seven days from it. `None` where the node did not say.
    pub known_since_secs: Option<u64>,
    /// For each relay that holds the latest change and is out of reach:
    /// for how long it has been out of reach, in seconds.
    pub out_of_reach_secs: Vec<u64>,
    /// Whether a relay is reached: a connection to it is open, and it
    /// answered the latest show of the kept entry on it.
    pub one_reached: bool,
    /// For each relay that has refused something for room, or for the
    /// address's allowance: how long ago it last did, in seconds.
    pub no_room_secs: Vec<u64>,
    /// How many names that a device which still counts had listed are
    /// listed by no device yet in the generation applied. A name that
    /// only a device which counts no longer had listed is not among them:
    /// it is in `cordelia devices`, and in no level.
    pub names_not_listed: usize,
    /// For how long this device has applied the change, in seconds,
    /// where it knows.
    pub applied_secs: Option<u64>,
    /// How many names this device has still to send.
    pub names_to_go: usize,
    /// For how long the first of them has waited, in seconds.
    pub to_go_secs: Option<u64>,
    /// How many of those names the device holds by a carry that a person
    /// asked for, or by a recovery, with no folder mapped to them: what
    /// was brought in there waits whatever sync says.
    pub carried_to_go: usize,
    /// For how long the first of those has waited, in seconds.
    pub carried_to_go_secs: Option<u64>,
    /// Those names, where the node gives them.
    pub carried_named: Vec<String>,
    /// How long ago, in seconds, this device applied a statement that
    /// removed a key that held a shared channel which the person still
    /// holds and has not made anew and moved from, or dropped: a channel
    /// not yet clean (decision 2026-10-10 §9; decision 2026-10-24, rule
    /// 25). The latest such, where there are several. `None` where none.
    pub removed_holds_shared_secs: Option<u64>,
    /// The shared channels not yet clean that the status names, each with
    /// the removed devices that still have it: those of a removal applied
    /// within the seven days. The status says one line for each (decision
    /// 2026-11-11 (plain words), rules 2 and 3).
    pub removed_holds_shared: Vec<HeldShared>,
    /// What each amber line of a repository this device follows says
    /// (decision 2026-11-06 (joining), rules 4.5 to 4.7, 5 and 6): the
    /// joining record's ambers, by the person's ruling of 6 November.
    pub repository_ambers: Vec<String>,
}

/// A shared channel not yet clean, as the status names it: by its name,
/// with each removed device that still has it, as a line names a device
/// ([`device_named`]). No device where the node names none: the channel
/// was first held after the removal (issue #279).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HeldShared {
    pub channel: String,
    pub devices: Vec<String>,
}

// A device in a line of the status, as every line of it names one: by
// its fingerprint words, then the name you gave it, quoted, or by its
// words alone where you gave none. A line names a device it tells of, a
// removed one, one added or one that fills the room, always so: each is a
// device you decide about, and its name may be another's (decision
// 2026-11-11 (plain words), rule 4). And things a line names, a few and
// then how many more (rule 2).
pub use cordelia_api::look::{named_device as device_named, named_few};

/// A relay that is not known to hold the latest change, as a status goes
/// by it (decision 2026-10-19, rule 11).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NotKnown {
    /// For how long it has lacked the change, in seconds, by the node's
    /// own clock: from the later of when it came to lack it, the node's
    /// start, a sleep and the change of the kept entry.
    pub lacking_secs: u64,
    /// How long ago its latest answer about the kept entry was, in
    /// seconds, where it gave one: a relay that held the change and then
    /// says that it has no room for it is said for seven days from that.
    pub said_secs: Option<u64>,
    /// Whether it is out of reach (decision 2026-10-24, rule 7): the line
    /// says so.
    pub out_of_reach: bool,
}

/// How grave what holds is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// What a person should act on now.
    Red,
    /// What a person should know of, and need not act on in the folders.
    Amber,
}

impl Level {
    /// The name used in `cordelia status --json`, and as a class of the
    /// bar form.
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Red => "red",
            Level::Amber => "amber",
        }
    }
}

/// One thing that holds, of the two lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holds {
    pub level: Level,
    /// What it is, in a word, for whoever reads a status by a program.
    pub what: &'static str,
    /// What the line says of it.
    pub says: String,
}

/// What the line says, without its first word "memory": what a tooltip
/// and the plain status say beside their own label (decision 2026-10-24,
/// rule 5).
pub fn without_memory(says: &str) -> &str {
    says.strip_prefix("memory: ")
        .or_else(|| says.strip_prefix("memory "))
        .unwrap_or(says)
}

/// What the line says of the one fact of a shared channel that sets a
/// level (decision 2026-10-10 §9), for one channel not reset on this
/// device since a removal, each of which is made anew once (decision
/// 2026-10-24, rule 23): which removed devices can still read there, that
/// this device sends nothing there, and the one command (decision
/// 2026-11-11 (plain words), rules 2 and 3). The words are the node's
/// notice of the channel, word for word, which the plain status then says
/// once. A channel first held after the removal names no device.
pub fn removed_holds_shared_says(held: &HeldShared) -> String {
    format!(
        "shared: {}",
        cordelia_api::shared_anew::not_clean_named_line(&held.channel, &held.devices)
    )
}

/// The same, short, for the line where it is the summary (`--line`, and a
/// panel's header): who can still read there, the first removed device
/// and how many more, and the one command; that this device sends nothing
/// there is said in the status and its notice.
pub fn removed_holds_shared_summary(held: &HeldShared) -> String {
    let shown = cordelia_api::messages::cleaned(&held.channel);
    let word = cordelia_api::shared_routes::shell_word(&held.channel);
    match held.devices.first() {
        Some(first) => format!(
            "shared: \"{shown}\": {}, which you removed, can still read new messages there. To \
             stop that: cordelia shared reset {word}",
            named_few(
                std::slice::from_ref(first),
                held.devices.len(),
                "",
                "devices"
            )
        ),
        None => format!(
            "shared: \"{shown}\" has not been reset since you removed a device. To reset it: \
             cordelia shared reset {word}"
        ),
    }
}

/// The word of that hold, which the plain status says on a line of its
/// own, `Shared:`, and not under `Memory:` (decision 2026-10-10 §9; the
/// words of a change, rule 5).
pub const SHARED_HOLD: &str = "shared_removed_device_holds";

/// What the plain status says on its line `Shared:`: the hold's words
/// without their first word, as `Memory:` says its own.
pub fn without_shared(says: &str) -> &str {
    says.strip_prefix("shared: ").unwrap_or(says)
}

/// Whether `holds` is the one hold of a removed device that holds a shared
/// channel.
pub fn is_shared(holds: &Holds) -> bool {
    holds.what == SHARED_HOLD
}

/// The word of each amber of a repository this device follows (decision
/// 2026-11-06 (joining), rule 6), which the plain status says under the
/// repository and not under `Memory:`.
pub const REPOSITORY_HOLD: &str = "shared_repository";

/// What the line says of an amber line of a repository: its words, after
/// `shared: `.
pub fn repository_says(says: &str) -> String {
    format!("shared: {says}")
}

impl Holds {
    /// What a tooltip and the plain status say of it, beside the line:
    /// what the line would say, without its first word.
    pub fn detail(&self) -> String {
        let said = without_memory(&self.says);
        match self.level {
            Level::Red => format!("Needs you: {said}"),
            Level::Amber => format!("To know: {said}"),
        }
    }
}

/// What `cordelia status` shows: the state, the level, the line's words,
/// and everything that holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub state: State,
    /// The gravest level that holds, or none.
    pub level: Option<Level>,
    /// The first thing of that level, a shared channel's short
    /// ([`removed_holds_shared_summary`]); with no level, what the state
    /// says.
    pub summary: String,
    /// Everything that holds, red first, each list in its order.
    pub holds: Vec<Holds>,
}

/// A thing that will pass by itself is amber once it has lasted this
/// long.
const AMBER_WAIT_SECS: u64 = cordelia_core::protocol::STATUS_AMBER_WAIT_SECS;

/// A removal that some device has not applied is amber for this long
/// after this device applied it.
const REMOVAL_SHOWN_SECS: u64 =
    cordelia_core::protocol::REMOVAL_NOT_APPLIED_SHOWN_DAYS as u64 * 24 * 60 * 60;

/// A relay not known to hold the latest change is amber for this long
/// (decision 2026-10-19, rule 11): as long as a removal that some device
/// has not applied.
const RELAY_NOT_KNOWN_SHOWN_SECS: u64 = REMOVAL_SHOWN_SECS;

/// Names that no device lists yet in the new generation are amber for
/// this long after this device applied the change: as long as a removal
/// that some device has not applied.
const NOT_LISTED_SHOWN_SECS: u64 = REMOVAL_SHOWN_SECS;

/// A relay's refusal for room is taken to stand for this long.
const NO_ROOM_STANDS_SECS: u64 = cordelia_core::protocol::NO_ROOM_STANDS_SECS;

/// Whether the sync cycle has stalled: there is a report, and the node
/// has stored none for longer than a cycle takes, **counted from the
/// later of its start and the last it stored, by the node's own clock**
/// (decision 2026-10-04 §10.1).
///
/// One clock is read for both halves. A cycle counts as stalled from the
/// node's start, and not from the time of a report that an earlier run
/// stored: otherwise every start after a stop of more than a minute
/// would be stalled for some seconds. And the node's own clock does not
/// run while the machine sleeps: a machine that wakes is not stalled for
/// the time it slept, until its next cycle.
///
/// Beside a node that does not say for how long it has stored none, the
/// report's age is read by the wall clock, and the node's start by its
/// own, as an earlier version read them.
fn stalled(f: &Facts) -> bool {
    if f.report_age_secs.is_none() {
        return false;
    }
    if let Some(secs) = f.no_report_secs {
        return secs > STALE_REPORT_SECS as u64;
    }
    let old = f.report_age_secs.is_some_and(|age| age > STALE_REPORT_SECS);
    old && f.uptime_secs.is_none_or(|up| up > STALE_REPORT_SECS as u64)
}

/// Why a device that has stopped syncs nothing, as the line says it:
/// `f.stands` is where the node says it stands, and the look's few words
/// (`f.devices.short`) say which way on there is, as `cordelia devices`
/// says it: `renew` where a device you removed has the secret, `settle`
/// where changes were made separately, and none where this device itself
/// was removed (`init --new-key`, which `Devices:` says). Where the look
/// does not say, no command. `None` where it has not stopped.
fn stopped_says(f: &Facts) -> Option<&'static str> {
    use cordelia_api::look::{CLOSED_SHORT, REMOVED_AS_KNOWN_SHORT, short_why};
    let short = f.devices.short.as_str();
    let renew = "memory not syncing: a device you removed still has the secret this device uses; \
                 run cordelia renew";
    Some(match f.stands.as_str() {
        // Decision 2026-10-24 (removal), rules 2, 4 and 10: closed, stored
        // as a fork was, or applied under a change that is not clear.
        "fork" | "closed" if short == REMOVED_AS_KNOWN_SHORT => {
            "memory not syncing: this device was removed"
        }
        "fork" | "closed" if short == CLOSED_SHORT => renew,
        "fork" if short == short_why(cordelia_storage::person::State::Fork) => {
            "memory not syncing: two changes to your devices were made separately; run cordelia \
             settle"
        }
        "fork" => {
            "memory not syncing: a device you removed has the secret of each change that includes \
             this device"
        }
        "closed" => {
            "memory not syncing: a device you removed still has the secret this device uses"
        }
        "removed" => "memory not syncing: this device was removed",
        "not_listed" => "memory not syncing: not in the last change to your devices",
        "not_opened" => "memory not syncing: a change to your devices could not be opened",
        _ => return None,
    })
}

/// Why a node is held up, as the line says it: `by` is what the node
/// says it is held up by.
fn held_says(by: &str) -> &'static str {
    match by {
        "later_database" => "memory not syncing: the database is from a later version",
        // Decision 2026-11-10 (older kind), rule 6.
        "earlier_database" => "memory not syncing: the database is from before 0.2.0-alpha.19",
        // Rule 9 of the same record.
        "step_failed" => "memory not syncing: a step of the database did not finish",
        _ => "memory not syncing: the node cannot go on",
    }
}

/// What a device that follows no phrase says in the line (decision
/// 2026-11-10 (older kind), rule 9).
const NO_PHRASE_SAYS: &str = "memory stays here: no recovery phrase yet";

/// What the line says of a device that was answered with a change that
/// it could not apply.
const NOT_APPLIED_SAYS: &str =
    "memory not syncing: a change to your devices could not be used here";

/// Everything that holds, of the two lists, in their order: red first
/// (decision 2026-10-04 §10.1). None before any level: on a device that
/// is not set up, beside a node that is stopped or was not asked, and on
/// a relay or a bootnode.
///
/// **Red,** in this order. The first two hold whatever sync says, and
/// the rest with sync on:
/// 1. this device has stopped: it was removed, or is in no list, or is
///    in a fork, or was answered with a change that it could not open or
///    apply;
/// 2. the node is held up: its database is from a later version, or
///    from before alpha.19;
/// 3. it follows no phrase, where something is mapped: nothing it holds
///    syncs until a person acts;
/// 4. sync errors, a file that could not be synced among them;
/// 5. a cycle that has stalled;
/// 6. conflict files;
/// 7. files too large.
///
/// **Amber,** in this order. What is about folders holds only with sync
/// on, something mapped and a report: with none of them, nothing would
/// move anyway. What is about a person's devices holds wherever this
/// device follows a phrase, with sync on or off, and with or without a
/// folder mapped.
/// 0. the personal channel past the line, as the last report that read
///    it found (decision 2026-10-19 §2, rule 3): first, above every line
///    that the overflow itself can cause;
/// 1. no relay connected for more than five minutes, by the node's own
///    clock;
/// 2. entries that relays keep refusing;
/// 3. a running node that is not the version this command is;
/// 4. a removal that some device has not applied, for seven days from
///    when this device applied it; a head set aside by a device that goes
///    on, for seven days from when it was set aside (decision 2026-10-24
///    (removal), rule 11); and after them, a removed device that still
///    holds a shared channel the person has not made anew, for seven days
///    from when this device applied that removal (decision 2026-10-10 §9):
///    the one fact of a shared channel that sets a level;
/// 5. a device added since the last change that nobody has cleared;
/// 6. a device that has said it left;
/// 7. names that a recovery, or a carry by command, holds with no folder
///    mapped to them, and of which what was brought in is not yet sent,
///    for more than five minutes: a machine that has just recovered maps
///    nothing, and may have sync off;
/// 8. a relay not known to hold the latest change, connected or not,
///    once it has lacked it for more than five minutes by the node's own
///    clock, and for seven days from the latest of when this device came
///    to keep the change entry, when this version first started on it,
///    and that relay's latest answer about the entry (decision 2026-10-19,
///    rule 11): after that it is in `cordelia
///    devices` only. A relay in the third state is not counted;
/// 9. a relay that refuses a new channel for room, or for the address's
///    allowance;
/// 10. names that a device which still counts had listed and that no
///     device lists in the new generation, once that has lasted for more
///     than five minutes, and for seven days from when this device
///     applied the change: after that they are in `cordelia devices`
///     only, as a removal is, so that a device in a drawer does not keep
///     every line amber for good; or names not yet sent, for more than
///     five minutes: those of them that the seventh does not say;
/// 11. a relay that holds the latest change and is out of reach, while
///     another is reached: the least of them, and one that can last for
///     good, so it comes last and hides nothing (rule 11);
/// 12. pairs of the person's agents held, waiting for the person to read
///     their messages (decision 2026-10-25, rule 4): below every hold
///     about the person's devices and memory, so that it hides none of
///     them, with sync on or off, wherever the node counts one;
/// 13. each amber line of a repository this device follows (decision
///     2026-11-06 (joining), rules 4.5 to 4.7, 5 and 6): a key that
///     joined, a key dropped from the list, a changed channel line, rule
///     1's gate, a new channel line to put in the list, a key left out
///     that its channel line does not name, and a device of the person's
///     left out of the channel the list names. The person ruled on 6
///     November that these ambers stand beside the one of decision
///     2026-10-10 §9, property 16. Last, so that they hide nothing of the
///     person's own, with sync on or off.
///
/// What is about folders (0 to 3, and 9 to 11) holds only with sync on,
/// something mapped and a report; the eighth, as 4 to 7, wherever this
/// device follows a phrase.
pub fn holds(f: &Facts) -> Vec<Holds> {
    let mut out: Vec<Holds> = Vec::new();
    let personal_and_running = f.initialised && !f.not_asked && f.running && f.role == "personal";
    if !personal_and_running {
        return out;
    }
    let on = f.sync_enabled;
    let report = f.report_age_secs.is_some();
    // What is about folders: nothing of it moves with sync off, with
    // nothing mapped, or before a first report.
    let of_folders = on && f.mapped > 0 && report;
    // What is about a person's devices: wherever the device follows a
    // phrase.
    let follows_a_phrase = f.stands != "no_phrase";
    let mut red = |what: &'static str, says: String| {
        out.push(Holds {
            level: Level::Red,
            what,
            says,
        })
    };
    let count = |n: usize, one: &str| format!("{n} {}", plural(n as u64, one));

    // Whatever sync says: a device that has stopped, and a node that is
    // held up. Nothing here asks whether sync is on: a node that is held
    // up refuses the request that would say so.
    if let Some(says) = stopped_says(f) {
        red("stopped", says.into());
    } else if f.devices.not_applied {
        red("stopped", NOT_APPLIED_SAYS.into());
    }
    if let Some(by) = f.held.as_deref() {
        red("held", held_says(by).into());
    }
    if on {
        if f.stands == "no_phrase" && f.mapped > 0 {
            red("no_phrase", NO_PHRASE_SAYS.into());
        }
        if !f.errors.is_empty() {
            red("errors", "memory sync error".into());
        }
        if stalled(f) {
            red("stalled", "memory sync stalled".into());
        }
        if !f.conflicts.is_empty() {
            let conflicts = count(f.conflicts.len(), "conflict");
            red("conflicts", format!("memory: {conflicts}"));
        }
        if !f.too_large.is_empty() {
            let files = count(f.too_large.len(), "file");
            red("too_large", format!("memory: {files} too large"));
        }
    }

    let mut amber = |what: &'static str, says: String| {
        out.push(Holds {
            level: Level::Amber,
            what,
            says,
        })
    };
    let long = |secs: &u64| *secs > AMBER_WAIT_SECS;
    let d = &f.devices;
    if of_folders {
        // First among the amber memory lines, above every line that the
        // overflow itself can cause, so that the line a person sees names
        // the cause (decision 2026-10-19 §2, rule 3).
        if let Some(channel) = f.channel.as_ref().filter(|c| c.past_the_line()) {
            amber("channel_nearly_full", channel.warning());
        }
        if let Some(secs) = f.no_relay_secs.filter(long) {
            amber(
                "no_relay",
                format!("memory: no relay for {} minutes", secs / 60),
            );
        }
        if f.other_version {
            amber(
                "other_version",
                "memory: the node is another version (restart it)".into(),
            );
        }
    }
    if follows_a_phrase {
        if d.removal_not_applied_secs
            .is_some_and(|secs| secs <= REMOVAL_SHOWN_SECS)
        {
            let removed = named_few(
                &d.removed_named,
                d.removed_named.len().max(1),
                "a device",
                "devices",
            );
            amber(
                "removal_not_applied",
                format!("memory: not every device knows yet that you removed {removed}"),
            );
        }
        if d.set_aside_secs
            .is_some_and(|secs| secs <= REMOVAL_SHOWN_SECS)
        {
            amber(
                "set_aside",
                "memory: a change to your devices was made separately, and put aside".into(),
            );
        }
        // The one fact of a shared channel that sets a level (decision
        // 2026-10-10 §9, property 16): a removed device still holds a
        // shared channel that the person has not made anew, for seven days
        // from when this device applied the removal. A fact about the
        // person's own removal, and about nothing a shared channel holds.
        if d.removed_holds_shared_secs
            .is_some_and(|secs| secs <= REMOVAL_SHOWN_SECS)
        {
            for held in &d.removed_holds_shared {
                amber(SHARED_HOLD, removed_holds_shared_says(held));
            }
        }
        // Said from this device's view: where it alone was added, that it
        // was; else the others, by name.
        let others =
            d.added_not_cleared - usize::from(d.added_this_device).min(d.added_not_cleared);
        if others > 0 {
            let devices = named_few(&d.added_named, others, "a device", "devices");
            let (was, them) = match others {
                1 => ("was", "it"),
                _ => ("were", "them"),
            };
            amber(
                "added",
                format!(
                    "memory: {devices} {was} added. If you did not add {them}, remove {them}; if \
                     you did, run cordelia devices --clear"
                ),
            );
        } else if d.added_not_cleared > 0 {
            amber(
                "added",
                "memory: this device was added to your devices. To mark that seen: cordelia \
                 devices --clear"
                    .into(),
            );
        }
        match d.said_left {
            0 => {}
            1 => amber("left", "memory: a device has left".into()),
            n => amber("left", format!("memory: {n} devices have left")),
        }
        // What a recovery, or a carry by command, brought in and has
        // not yet sent: no folder is mapped to those names, so nothing
        // of them turns on what sync says.
        if d.carried_to_go > 0 && d.carried_to_go_secs.as_ref().is_some_and(long) {
            let names = named_few(&d.carried_named, d.carried_to_go, "1 name", "names");
            amber(
                "carried",
                format!("memory: {names} copied over, not yet sent"),
            );
        }
        // A relay that lacks the change, connected or not: nothing else
        // stands once the command that made the change has ended
        // (decision 2026-10-19, rule 11). For seven days from the later of
        // when this device came to keep the entry and the relay's latest
        // answer about it, so that a relay that this site can never reach
        // does not hide what comes after it for good, and one that says it
        // lacks the entry long after is said all the same.
        let within = |secs: &u64| *secs <= RELAY_NOT_KNOWN_SHOWN_SECS;
        let still_shown = |relay: &&NotKnown| {
            d.known_since_secs.is_none_or(|secs| within(&secs))
                || relay.said_secs.as_ref().is_some_and(within)
        };
        let lacking: Vec<&NotKnown> = d
            .not_known_to_hold
            .iter()
            .filter(|relay| long(&relay.lacking_secs))
            .filter(still_shown)
            .collect();
        // Each that is out of reach is said so (decision 2026-10-24, rule
        // 7): the count, its place and its days do not change.
        let out = lacking.iter().filter(|relay| relay.out_of_reach).count();
        // Which relays, and how many, `cordelia devices` says (decision
        // 2026-11-11 (plain words), rule 4).
        let said = match (lacking.len(), out) {
            (0, _) => None,
            (1, 0) => Some(format!("memory: a relay may not have {LATEST}")),
            (_, 0) => Some(format!("memory: some relays may not have {LATEST}")),
            (1, _) => Some(format!(
                "memory: a relay is out of reach and may not have {LATEST}"
            )),
            (n, out) if out == n => Some(format!(
                "memory: some relays are out of reach and may not have {LATEST}"
            )),
            (_, 1) => Some(format!(
                "memory: some relays may not have {LATEST}, and one of them is out of reach"
            )),
            (_, _) => Some(format!(
                "memory: some relays may not have {LATEST}, and some of them are out of reach"
            )),
        };
        if let Some(said) = said {
            amber("relay_without_latest", said);
        }
    }
    if of_folders {
        folders_after(f, &mut out);
    }
    // Then agents held for their person, who alone ends it.
    if f.held_pairs > 0 {
        out.push(Holds {
            level: Level::Amber,
            what: MESSAGES_HOLD,
            says: MESSAGES_HELD_SAYS.into(),
        });
    }
    // Last, so that they hide nothing of the person's own: the ambers of
    // the repositories this device follows (decision 2026-11-06 (joining),
    // rule 6, by the person's ruling of 6 November).
    for says in &f.devices.repository_ambers {
        out.push(Holds {
            level: Level::Amber,
            what: REPOSITORY_HOLD,
            says: repository_says(says),
        });
    }
    out
}

/// What a relay may lack, as the lines of relays say it.
const LATEST: &str = "the latest change to your devices";

/// The hold of agents that wait for their person (decision 2026-10-25,
/// rule 4).
pub const MESSAGES_HOLD: &str = "messages_held";

/// Whether `holds` is the hold of agents that wait for their person.
pub fn is_messages_held(holds: &Holds) -> bool {
    holds.what == MESSAGES_HOLD
}

/// What the line says where pairs of the person's agents are held: "you"
/// are the one who ends it, by reading. It names no count, which the
/// status's `held_pairs` carries: a pair may be of an agent and every
/// agent.
pub const MESSAGES_HELD_SAYS: &str =
    "agents wait for you to read their messages; run cordelia msg log";

/// The amber of folders after a person's devices (9 to 11 of [`holds`]),
/// pushed onto `out`.
fn folders_after(f: &Facts, out: &mut Vec<Holds>) {
    let mut amber = |what: &'static str, says: String| {
        out.push(Holds {
            level: Level::Amber,
            what,
            says,
        })
    };
    let long = |secs: &u64| *secs > AMBER_WAIT_SECS;
    let count = |n: usize, one: &str| format!("{n} {}", plural(n as u64, one));
    let d = &f.devices;
    if d.no_room_secs.iter().any(|ago| *ago <= NO_ROOM_STANDS_SECS) {
        amber("relay_no_room", "memory: a relay has no room".into());
    }
    let shown_still = |secs: &u64| long(secs) && *secs <= NOT_LISTED_SHOWN_SECS;
    let not_listed = d.names_not_listed > 0 && d.applied_secs.as_ref().is_some_and(shown_still);
    // The names that a carry holds with no folder are said above, and
    // not a second time here.
    let of_folders_to_go = d.names_to_go.saturating_sub(d.carried_to_go);
    let not_sent = of_folders_to_go > 0 && d.to_go_secs.as_ref().is_some_and(long);
    if not_listed {
        let names = count(d.names_not_listed, "name");
        amber("names", format!("memory: {names} synced by no device yet"));
    } else if not_sent {
        let names = count(of_folders_to_go, "name");
        amber("names", format!("memory: {names} not yet sent"));
    }
    // The warning of the ruling (decision 2026-10-19 §0, rule 11): said
    // only while another relay is reached, and so never beside "no relay".
    match d.out_of_reach_secs.as_slice() {
        _ if !d.one_reached => {}
        [] => {}
        [secs] => {
            // Rounded up: a relay that has just come to be out of reach is
            // so for a minute, and not for none.
            let minutes = secs.div_ceil(60).max(1);
            amber(
                "relay_out_of_reach",
                format!(
                    "memory: a relay out of reach for {minutes} {}",
                    plural(minutes, "minute")
                ),
            )
        }
        several => amber(
            "relay_out_of_reach",
            format!("memory: {} relays out of reach", several.len()),
        ),
    }
}

/// What the facts take from the running node's status (`GET
/// /api/v1/status`), `live`: that it runs, and what it says of itself and
/// of what waits to be sent.
///
/// **Of its `messages` object only `held_pairs` is taken** (decision
/// 2026-10-25, rule 4): pairs of agents held for their person set an
/// amber hold. Nothing else of messages raises the level, appears among
/// the holds, or changes the line or the bar (decision 2026-10-09 §8,
/// C13). `cordelia status --json` carries the object as the node gave it.
pub fn running(f: &mut Facts, live: &serde_json::Value) {
    f.running = true;
    f.uptime_secs = live["uptime_secs"].as_u64();
    // By the node's own clock. A node that does not say gives none.
    f.no_relay_secs = live["no_relay_secs"].as_u64();
    // Only the command knows that the node is another version than it.
    f.other_version = live["version"].as_str() != Some(env!("CARGO_PKG_VERSION"));
    f.held = live["held"]["by"].as_str().map(str::to_string);
    f.peers_hot = live["peers_hot"].as_u64().unwrap_or(0);
    f.outbox_waiting = live["outbox_waiting"].as_u64().unwrap_or(0);
    f.held_pairs = live["messages"]["held_pairs"].as_u64().unwrap_or(0);
}

/// What the facts take from the status's `shared` object (decision
/// 2026-10-10 §9, property 16), at `now` in seconds: **only
/// `removed_device_holds`,** each removed device that still holds shared
/// channels the person has not made anew, with since when; **and each line
/// of `repositories` that is amber,** the joining record's ambers, by the
/// person's ruling of 6 November (decision 2026-11-06 (joining), rule 6).
/// Nothing else of the object is read: nothing else a shared channel
/// holds, waits for or is refused sets a level, appears among the holds,
/// or changes the line.
pub fn shared(devices: &mut Devices, shared: &serde_json::Value, now: i64) {
    devices.repository_ambers = shared["repositories"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|repository| repository["lines"].as_array().into_iter().flatten())
        .filter(|line| line["amber"] == true)
        .filter_map(|line| line["says"].as_str().map(str::to_string))
        .collect();
    let mut latest: Option<u64> = None;
    let mut named: Vec<HeldShared> = Vec::new();
    for holds in shared["removed_device_holds"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(since) = holds["since"]
            .as_str()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
        else {
            continue;
        };
        let ago = now.saturating_sub(since.timestamp()).max(0) as u64;
        latest = Some(latest.map_or(ago, |latest| latest.min(ago)));
        if ago > REMOVAL_SHOWN_SECS {
            continue;
        }
        // Each removed device alone, by the name the person gave it
        // (decision 2026-11-11 (plain words), rule 2).
        let devices: Vec<String> = holds["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|device| {
                device_named(
                    device["label"].as_str().unwrap_or_default(),
                    device["words"].as_str().unwrap_or_default(),
                )
            })
            .collect();
        for channel in holds["channels"].as_array().into_iter().flatten() {
            let Some(channel) = channel.as_str() else {
                continue;
            };
            // A channel named twice is said once, with each device.
            match named.iter_mut().find(|held| held.channel == channel) {
                Some(held) => {
                    for device in &devices {
                        if !held.devices.contains(device) {
                            held.devices.push(device.clone());
                        }
                    }
                }
                None => named.push(HeldShared {
                    channel: channel.to_string(),
                    devices: devices.clone(),
                }),
            }
        }
    }
    devices.removed_holds_shared_secs = latest;
    devices.removed_holds_shared = named;
}

/// What `cordelia status` shows (see the module's documentation): the
/// state as it always was, the gravest level that holds, and for the
/// line the first thing of that level, or what the state says where
/// there is none.
pub fn shown(f: &Facts) -> Shown {
    let (state, of_the_state) = derive(f);
    let holds = holds(f);
    let first = |level: Level| holds.iter().find(|holds| holds.level == level);
    let gravest = first(Level::Red).or_else(|| first(Level::Amber));
    // The hold of a shared channel is said short there: the first of
    // them is of the first channel (decision 2026-11-11 (plain words)).
    let summary = match gravest {
        Some(holds) if is_shared(holds) => f
            .devices
            .removed_holds_shared
            .first()
            .map_or_else(|| holds.says.clone(), removed_holds_shared_summary),
        Some(holds) => holds.says.clone(),
        None => of_the_state,
    };
    Shown {
        state,
        level: gravest.map(|holds| holds.level),
        summary,
        holds,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Connected, everything written here has reached a relay.
    Synced,
    /// Connected, still sending, joining a project, or starting.
    Syncing,
    /// Running but no relay connected; changes wait here.
    Offline,
    /// Needs the person: a conflict to merge, or sync errors.
    Attention,
    /// The node runs but syncs nothing: `cordelia sync claude` is off, or
    /// no folder is mapped.
    Off,
    /// Set up, but the node is not running.
    Stopped,
    /// `cordelia init` has not run: nothing to show.
    Uninitialised,
}

impl State {
    /// The name used in `cordelia status --json`.
    pub fn as_str(self) -> &'static str {
        match self {
            State::Synced => "synced",
            State::Syncing => "syncing",
            State::Offline => "offline",
            State::Attention => "attention",
            State::Off => "off",
            State::Stopped => "stopped",
            State::Uninitialised => "uninitialised",
        }
    }
}

/// The state and a short summary ("memory synced", "memory: 1 conflict"):
/// the state as a panel that draws from it alone has always been given
/// it, and what the line says where no level holds ([`shown`]).
pub fn derive(f: &Facts) -> (State, String) {
    use State::*;
    if !f.initialised {
        return (Uninitialised, "cordelia not set up".into());
    }
    if f.not_asked {
        return (
            Attention,
            "memory: node not asked (see `cordelia status`)".into(),
        );
    }
    if !f.running {
        return (Stopped, "memory: node stopped".into());
    }
    if f.role != "personal" {
        return match f.peers_hot {
            0 => (Offline, format!("{}: no peers", f.role)),
            n => (Synced, format!("{}: {n} {}", f.role, plural(n, "peer"))),
        };
    }
    // A node that is held up runs no cycle and no pass, with sync on or
    // off, and refuses what would change anything (decision 2026-10-04
    // §10.1): `cordelia status` says why.
    if let Some(by) = f.held.as_deref() {
        return (Attention, held_says(by).into());
    }
    // A device that has stopped needs the person, with sync on or off
    // (decision 2026-10-04 §10.1): it was removed, or is in no list, or
    // is in a fork, or was answered with a change that it could not open
    // or apply. It is one of the person's devices whatever it syncs, and
    // is never said to be synced, or resting.
    if let Some(says) = stopped_says(f) {
        return (Attention, says.into());
    }
    if f.devices.not_applied {
        return (Attention, NOT_APPLIED_SAYS.into());
    }
    // Only a device that has applied a statement publishes anything
    // (decision 2026-10-04 §5.2). **With no phrase, sync on and something
    // mapped, the state is `attention`** (decision 2026-10-04 §10.1), so
    // that a panel which draws from the state alone does not show the
    // device as synced: nothing it holds syncs until a person acts. A
    // device that is not to be added turns sync off.
    let no_phrase = f.stands == "no_phrase";
    if no_phrase && f.sync_enabled && f.mapped > 0 {
        return (Attention, NO_PHRASE_SAYS.into());
    }
    let (state, says) = of_its_folders(f);
    // With sync off, or nothing mapped, the state is what it would be
    // without that, and the words still say it. What needs the person is
    // said first.
    if no_phrase && state != Attention {
        return (state, NO_PHRASE_SAYS.into());
    }
    (state, says)
}

/// The state of a personal node that runs, is not held up and has not
/// stopped, by what it says of its folders ([`derive`]).
fn of_its_folders(f: &Facts) -> (State, String) {
    use State::*;
    if !f.sync_enabled {
        return (Off, "memory sync off".into());
    }
    if !f.errors.is_empty() {
        return (Attention, "memory sync error".into());
    }
    match f.report_age_secs {
        None => {
            return (Syncing, "memory sync starting".into());
        }
        Some(_) if stalled(f) => {
            return (Attention, "memory sync stalled".into());
        }
        Some(_) => {}
    }
    // A conflict and a file too large are counted from every folder of
    // the report, so they are said where nothing syncs, as `holds` says
    // them.
    if !f.conflicts.is_empty() {
        let n = f.conflicts.len() as u64;
        return (Attention, format!("memory: {n} {}", plural(n, "conflict")));
    }
    if !f.too_large.is_empty() {
        let n = f.too_large.len() as u64;
        return (
            Attention,
            format!("memory: {n} {} too large", plural(n, "file")),
        );
    }
    if f.folders == 0 {
        return (Off, "memory: nothing mapped".into());
    }
    if f.peers_hot == 0 {
        return match f.outbox_waiting {
            0 => (Offline, "memory offline".into()),
            n => (Offline, format!("memory offline, {n} waiting")),
        };
    }
    if f.outbox_waiting > 0 {
        return (Syncing, format!("memory sending {}", f.outbox_waiting));
    }
    if f.projects_waiting > 0 {
        let n = f.projects_waiting as u64;
        return (
            Syncing,
            format!("memory fetching {n} {}", plural(n, "folder")),
        );
    }
    (Synced, "memory synced".into())
}

/// The mark of amber: the line's, and that of each amber line the plain
/// status says of a repository followed.
pub const AMBER_MARK: &str = "◆";

/// One line for a status bar: a mark and the summary, coloured unless
/// `color` is false. Empty when there is nothing to show.
///
/// The mark and its colour go by the level, where one holds: red has the
/// mark that attention always had. **Amber has a mark of its own:**
/// "sending" is drawn yellow, and amber must not look like it. With no
/// level they go by the state, as they always did.
pub fn line(state: State, level: Option<Level>, summary: &str, color: bool) -> String {
    let (mark, code) = match (level, state) {
        (_, State::Uninitialised) => return String::new(),
        (Some(Level::Red), _) => ("▲", "31"),          // red
        (Some(Level::Amber), _) => (AMBER_MARK, "33"), // yellow, and its own mark
        (None, State::Synced) => ("●", "32"),          // green
        (None, State::Syncing) => ("◐", "33"),         // yellow
        (None, State::Attention) => ("▲", "31"),       // red
        (None, State::Offline | State::Off | State::Stopped) => ("○", "2"), // dim
    };
    if color {
        format!("\x1b[{code}m{mark} {summary}\x1b[0m")
    } else {
        format!("{mark} {summary}")
    }
}

/// What a bar shows: an icon, a tooltip, and the state and the level as
/// classes.
///
/// The JSON is the shape Waybar's custom modules take, which Omarchy's bar
/// reads too: `text`, `tooltip` and `class`. The class is the state name,
/// and with a level the level's name after it (`red`, `amber`). **`active`,
/// which Omarchy highlights, is added with red; and, where there is no
/// level, with the state `attention`, as it was before there was a
/// level:** no state lost its highlight, and the bar never rests while
/// the line is red. Amber is never `active`. The icons are Nerd Font
/// glyphs: a level has its own, and with none the state has.
/// Empty when there is nothing to show.
pub fn bar(state: State, level: Option<Level>, summary: &str, details: &[String]) -> String {
    let icon = match (level, state) {
        (_, State::Uninitialised) => return String::new(),
        (Some(Level::Red), _) => "\u{f0026}",    // alert
        (Some(Level::Amber), _) => "\u{f002a}",  // alert, in outline
        (None, State::Synced) => "\u{f09d1}",    // brain
        (None, State::Syncing) => "\u{f04e6}",   // sync
        (None, State::Offline) => "\u{f0164}",   // cloud off
        (None, State::Attention) => "\u{f0026}", // alert
        (None, State::Off | State::Stopped) => "\u{f04b2}", // sleep
    };
    let mut tooltip = format!("Cordelia: {summary}");
    for line in details {
        tooltip.push('\n');
        tooltip.push_str(line);
    }
    let class = match level {
        Some(Level::Red) => serde_json::json!([state.as_str(), "red", "active"]),
        Some(Level::Amber) => serde_json::json!([state.as_str(), "amber"]),
        None if state == State::Attention => serde_json::json!([state.as_str(), "active"]),
        None => serde_json::json!(state.as_str()),
    };
    serde_json::json!({ "text": icon, "tooltip": tooltip, "class": class }).to_string()
}

/// `3m ago`, `2h ago`, `5d ago`, for a time `secs` seconds in the past.
pub fn ago(secs: i64) -> String {
    match secs.max(0) {
        s if s < 60 => "just now".into(),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86_400),
    }
}

fn plural(n: u64, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synced() -> Facts {
        Facts {
            initialised: true,
            running: true,
            role: "personal".into(),
            peers_hot: 2,
            sync_enabled: true,
            report_age_secs: Some(3),
            folders: 2,
            mapped: 2,
            uptime_secs: Some(3_600),
            stands: "applied".into(),
            ..Default::default()
        }
    }

    /// What is shown of a synced device with one thing changed.
    fn with(edit: &dyn Fn(&mut Facts)) -> Shown {
        let mut f = synced();
        edit(&mut f);
        shown(&f)
    }

    /// What holds, each in a word, in the order it is listed.
    fn whats(shown: &Shown) -> Vec<&'static str> {
        shown.holds.iter().map(|holds| holds.what).collect()
    }

    type Edit = &'static dyn Fn(&mut Facts);

    /// Each thing of the red list, alone: what makes it, its word, and
    /// what the line says of it.
    const RED: [(Edit, &str, &str); 11] = [
        (
            &|f| f.stands = "removed".into(),
            "stopped",
            "memory not syncing: this device was removed",
        ),
        (
            &|f| f.stands = "not_listed".into(),
            "stopped",
            "memory not syncing: not in the last change to your devices",
        ),
        (
            &|f| f.stands = "fork".into(),
            "stopped",
            "memory not syncing: a device you removed has the secret of each change that \
             includes this device",
        ),
        (
            &|f| f.stands = "not_opened".into(),
            "stopped",
            "memory not syncing: a change to your devices could not be opened",
        ),
        (
            &|f| f.devices.not_applied = true,
            "stopped",
            "memory not syncing: a change to your devices could not be used here",
        ),
        (
            &|f| f.held = Some("earlier_database".into()),
            "held",
            "memory not syncing: the database is from before 0.2.0-alpha.19",
        ),
        (
            &|f| f.stands = "no_phrase".into(),
            "no_phrase",
            "memory stays here: no recovery phrase yet",
        ),
        (
            &|f| f.errors = vec!["x".into()],
            "errors",
            "memory sync error",
        ),
        (
            &|f| f.report_age_secs = Some(STALE_REPORT_SECS + 1),
            "stalled",
            "memory sync stalled",
        ),
        (
            &|f| f.conflicts = vec!["a".into(), "b".into()],
            "conflicts",
            "memory: 2 conflicts",
        ),
        (
            &|f| f.too_large = vec!["a.md".into()],
            "too_large",
            "memory: 1 file too large",
        ),
    ];

    /// Each thing of the amber list, alone, in the list's order.
    const AMBER: [(Edit, &str, &str); 11] = [
        (
            &|f| {
                f.peers_hot = 0;
                f.no_relay_secs = Some(360);
            },
            "no_relay",
            "memory: no relay for 6 minutes",
        ),
        (
            &|f| f.other_version = true,
            "other_version",
            "memory: the node is another version (restart it)",
        ),
        (
            &|f| f.devices.removal_not_applied_secs = Some(3_600),
            "removal_not_applied",
            "memory: not every device knows yet that you removed a device",
        ),
        (
            &|f| f.devices.added_not_cleared = 1,
            "added",
            "memory: a device was added. If you did not add it, remove it; if you did, run \
             cordelia devices --clear",
        ),
        (
            &|f| f.devices.said_left = 1,
            "left",
            "memory: a device has left",
        ),
        (
            &|f| {
                f.devices.names_to_go = 1;
                f.devices.carried_to_go = 1;
                f.devices.carried_to_go_secs = Some(400);
            },
            "carried",
            "memory: 1 name copied over, not yet sent",
        ),
        (
            &|f| f.devices.not_known_to_hold = lacking_for(&[10, 400]),
            "relay_without_latest",
            "memory: a relay may not have the latest change to your devices",
        ),
        (
            &|f| f.devices.no_room_secs = vec![30],
            "relay_no_room",
            "memory: a relay has no room",
        ),
        (
            &|f| {
                f.devices.names_not_listed = 2;
                f.devices.applied_secs = Some(400);
            },
            "names",
            "memory: 2 names synced by no device yet",
        ),
        (
            &|f| {
                f.devices.names_to_go = 1;
                f.devices.to_go_secs = Some(400);
            },
            "names",
            "memory: 1 name not yet sent",
        ),
        (
            &|f| {
                f.devices.out_of_reach_secs = vec![420];
                f.devices.one_reached = true;
            },
            "relay_out_of_reach",
            "memory: a relay out of reach for 7 minutes",
        ),
    ];

    /// The things of the amber list that are about a person's devices:
    /// the rest of it is about folders.
    const OF_DEVICES: [&str; 5] = [
        "removal_not_applied",
        "added",
        "left",
        "carried",
        "relay_without_latest",
    ];

    /// What has no level, as it always was: each says its own.
    const NO_LEVEL: [(Edit, State, &str); 6] = [
        (
            &|f| f.report_age_secs = None,
            State::Syncing,
            "memory sync starting",
        ),
        (
            &|f| {
                f.folders = 0;
                f.mapped = 0;
            },
            State::Off,
            "memory: nothing mapped",
        ),
        (&|f| f.peers_hot = 0, State::Offline, "memory offline"),
        (
            &|f| f.outbox_waiting = 4,
            State::Syncing,
            "memory sending 4",
        ),
        (
            &|f| f.projects_waiting = 1,
            State::Syncing,
            "memory fetching 1 folder",
        ),
        (&|_| {}, State::Synced, "memory synced"),
    ];

    /// For each thing that the two lists name, the level (decision
    /// 2026-10-04 §10.1): red for what a person should act on now, amber
    /// for what a person should know of. And none otherwise, with what
    /// the state says, as it always was.
    #[test]
    fn each_thing_of_the_two_lists_has_its_level() {
        for (edit, what, says) in RED {
            let shown = with(edit);
            assert_eq!(shown.level, Some(Level::Red), "{what}");
            assert_eq!(whats(&shown), [what]);
            assert_eq!(shown.summary, says);
        }
        for (edit, what, says) in AMBER {
            let shown = with(edit);
            assert_eq!(shown.level, Some(Level::Amber), "{what}");
            assert_eq!(whats(&shown), [what]);
            assert_eq!(shown.summary, says);
        }
        for (edit, state, says) in NO_LEVEL {
            let shown = with(edit);
            assert_eq!(shown.level, None, "{says}");
            assert!(shown.holds.is_empty(), "{says}");
            assert_eq!((shown.state, shown.summary.as_str()), (state, says));
        }
        // A node that is held up by a database from a later version.
        let later = with(&|f| f.held = Some("later_database".into()));
        assert_eq!(later.level, Some(Level::Red));
        assert_eq!(
            later.summary,
            "memory not syncing: the database is from a later version"
        );
        // More than one of a kind is counted.
        let several = with(&|f| {
            f.devices.said_left = 2;
            f.devices.added_not_cleared = 3;
            f.devices.not_known_to_hold = lacking_for(&[400, 500]);
        });
        let says: Vec<&str> = several.holds.iter().map(|h| h.says.as_str()).collect();
        assert_eq!(
            says,
            [
                "memory: 3 devices were added. If you did not add them, remove them; if you did, \
                 run cordelia devices --clear",
                "memory: 2 devices have left",
                "memory: some relays may not have the latest change to your devices",
            ]
        );
    }

    /// The order of the red list, and of the amber list after it
    /// (decision 2026-10-04 §10.1): with everything holding at once,
    /// each is listed in its place, and the line says the first.
    #[test]
    fn the_two_lists_are_in_their_order() {
        let everything = |f: &mut Facts| {
            for (edit, _, _) in RED.iter().skip(5).chain(AMBER.iter()) {
                edit(f);
            }
        };
        // A device that has stopped (it stands as one thing at a time).
        let stopped = with(&|f| {
            everything(f);
            f.stands = "removed".into();
        });
        let amber = [
            "no_relay",
            "other_version",
            "removal_not_applied",
            "added",
            "left",
            "carried",
            "relay_without_latest",
            "relay_no_room",
            "names",
            "relay_out_of_reach",
        ];
        let red = [
            "stopped",
            "held",
            "errors",
            "stalled",
            "conflicts",
            "too_large",
        ];
        let both: Vec<&str> = red.iter().chain(amber.iter()).copied().collect();
        assert_eq!(whats(&stopped), both);
        assert_eq!(stopped.level, Some(Level::Red));
        assert_eq!(
            stopped.summary,
            "memory not syncing: this device was removed"
        );
        // One that follows no phrase: after the node's being held up,
        // and ahead of everything else.
        let no_phrase = with(&everything);
        let mut red_with_no_phrase = red.to_vec();
        red_with_no_phrase[0] = "held";
        red_with_no_phrase[1] = "no_phrase";
        assert_eq!(whats(&no_phrase)[..6], red_with_no_phrase);
        // Answered with a change that it could not apply, with nothing
        // else of the device's own: in the first place too.
        let not_applied = with(&|f| {
            everything(f);
            f.stands = "applied".into();
            f.devices.not_applied = true;
        });
        assert_eq!(whats(&not_applied)[..3], ["stopped", "held", "errors"]);

        // The amber list alone, in its order, says its first.
        let all_amber = with(&|f| {
            for (edit, _, _) in AMBER {
                edit(f);
            }
        });
        assert_eq!(whats(&all_amber), amber);
        assert_eq!(all_amber.level, Some(Level::Amber));
        assert_eq!(all_amber.summary, "memory: no relay for 6 minutes");
        // Names not yet listed are said before names not yet sent, and
        // a relay out of reach after everything.
        let says: Vec<&str> = all_amber.holds.iter().map(|h| h.says.as_str()).collect();
        assert_eq!(
            says[says.len() - 2..],
            [
                "memory: 2 names synced by no device yet",
                "memory: a relay out of reach for 7 minutes"
            ]
        );
    }

    // ── The personal channel near a relay's room (decision 2026-10-19) ─

    /// The four forms of the warning, word for word (decision 2026-10-19
    /// §2, rule 4).
    const ANOTHER_FILLED: &str = "memory: (able bake cold dune) \"laptop\" has filled most of \
        what your devices keep at a relay. If it is not yours, or you no longer use it, remove \
        it: cordelia remove-device cordelia1laptopkey";
    const THIS_FILLED: &str = "memory: this device has filled most of what your devices keep \
        at a relay. If you no longer use it, remove it from another of your devices.";
    const NAMES_FILL: &str = "memory: you sync nearly as many names as a relay can keep for \
        your devices. A name you add now may not reach your other devices. Stop syncing names \
        you no longer need, on every device that syncs them: their room comes back slowly, at \
        least 90 days later. Or remove a device you no longer use: its room comes back at once.";
    const NEARLY_FULL: &str = "memory: what your devices keep at a relay is nearly full. Run \
        cordelia devices to see how much each device keeps there.";

    /// What one word is counted as.
    const WORD: u64 = 1_280;

    /// A channel of `words` bytes of words, whose bytes that are not
    /// words are signed by this device (`this`) and by the laptop
    /// (`laptop`).
    fn channel_of(words: u64, this: u64, laptop: u64) -> Channel {
        Channel {
            total: words + this + laptop,
            words,
            by: vec![
                Signer {
                    key: "cordelia1thiskey".into(),
                    this_device: true,
                    label: "desktop".into(),
                    words_of_key: "acid baby cage dart".into(),
                    words: words / 2,
                    not_words: this,
                },
                Signer {
                    key: "cordelia1laptopkey".into(),
                    this_device: false,
                    label: "laptop".into(),
                    words_of_key: "able bake cold dune".into(),
                    words: words - words / 2,
                    not_words: laptop,
                },
            ],
        }
    }

    /// The status turns amber where the personal channel passes the line,
    /// 12 MiB, and not at it (decision 2026-10-19 §2, rule 3): 12,583,168
    /// bytes is the first total past it that a store can hold (every
    /// total is a multiple of 256). Like the other memory lines it shows
    /// with sync on and a folder mapped, and not otherwise.
    #[test]
    fn the_status_is_amber_past_the_line() {
        let line = cordelia_core::protocol::PERSONAL_CHANNEL_WARN_BYTES;
        assert_eq!(line, 12_582_912);
        let at = |total: u64| {
            move |f: &mut Facts| {
                f.channel = Some(Channel {
                    total,
                    words: total,
                    by: Vec::new(),
                })
            }
        };
        let past = with(&at(line + 256));
        assert_eq!(past.level, Some(Level::Amber));
        assert_eq!(whats(&past), ["channel_nearly_full"]);
        assert_eq!(past.summary, NAMES_FILL);
        let on_it = with(&at(line));
        assert_eq!(on_it.level, None);
        assert!(on_it.holds.is_empty());
        assert_eq!(on_it.summary, "memory synced");
        // None with sync off, and none with no folder mapped.
        let off = with(&|f| {
            at(line + 256)(f);
            f.sync_enabled = false;
        });
        assert!(!whats(&off).contains(&"channel_nearly_full"), "{off:?}");
        let nothing_mapped = with(&|f| {
            at(line + 256)(f);
            f.mapped = 0;
            f.folders = 0;
        });
        assert!(nothing_mapped.holds.is_empty(), "{nothing_mapped:?}");
        // Nor with no report that read the channel.
        assert!(with(&|f| f.channel = None).holds.is_empty());
    }

    /// The warning is first among the amber memory lines (decision
    /// 2026-10-19 §2, rule 3): with the channel past the line, each of the
    /// eleven lines that the overflow itself can cause is made to hold in
    /// turn, and the line shown is the warning each time, with the other
    /// line after it.
    #[test]
    fn the_warning_is_shown_before_every_other_amber_memory_line() {
        assert_eq!(AMBER.len(), 11);
        let past = channel_of(12 * 1024 * 1024, 0, WORD);
        assert!(past.past_the_line());
        for (edit, what, says) in AMBER {
            let shown = with(&|f| {
                f.channel = Some(past.clone());
                edit(f);
            });
            assert_eq!(shown.level, Some(Level::Amber), "{what}");
            assert_eq!(shown.summary, NAMES_FILL, "with {what}");
            assert_eq!(whats(&shown), ["channel_nearly_full", what]);
            assert_eq!(shown.holds[1].says, says);
        }
        // Everything amber at once: the warning first.
        let all = with(&|f| {
            f.channel = Some(past.clone());
            for (edit, _, _) in AMBER {
                edit(f);
            }
        });
        assert_eq!(whats(&all)[0], "channel_nearly_full");
        assert_eq!(all.summary, NAMES_FILL);
    }

    /// What the warning says depends on what fills the channel (decision
    /// 2026-10-19 §2, rule 4): the first form that holds. Another device
    /// with more than half of what is not words, and more than a quarter
    /// of the total, is named, with the command that removes it; at
    /// exactly half, or at exactly a quarter, it is not. This device in
    /// its place has a form of its own. Words at half the total or more
    /// give the form of names; and below half, with no device past half
    /// of the rest, the last form.
    #[test]
    fn the_warning_says_what_fills_the_channel() {
        let half_of_not_words = 4_000 * WORD;
        // Words below half the total in each of these.
        let words = 2_000 * WORD;
        // Another device with half of what is not words and one entry
        // more, and more than a quarter of the total.
        let another = channel_of(words, half_of_not_words - WORD, half_of_not_words + WORD);
        assert!(another.past_the_line());
        assert!(4 * (half_of_not_words + WORD) > another.total);
        assert_eq!(another.warning(), ANOTHER_FILLED);
        // At exactly half of what is not words: not named.
        let at_half = channel_of(words, half_of_not_words, half_of_not_words);
        assert_eq!(at_half.warning(), NEARLY_FULL);
        // At exactly a quarter of the total, though past half of what is
        // not words: not named. The words are then past half the total.
        let quarter = 2_500 * WORD;
        let at_a_quarter = channel_of(5_500 * WORD, 2_000 * WORD, quarter);
        assert_eq!(4 * quarter, at_a_quarter.total);
        assert!(2 * quarter > at_a_quarter.total - at_a_quarter.words);
        assert_eq!(at_a_quarter.warning(), NAMES_FILL);
        // One entry over the quarter, of the same total: named.
        let over_a_quarter = channel_of(5_499 * WORD, 2_000 * WORD, quarter + WORD);
        assert_eq!(over_a_quarter.total, at_a_quarter.total);
        assert_eq!(over_a_quarter.warning(), ANOTHER_FILLED);
        // This device in its place.
        let this = channel_of(words, half_of_not_words + WORD, half_of_not_words - WORD);
        assert_eq!(this.warning(), THIS_FILLED);
        // Words at exactly half the total, what is not words shared.
        let names = channel_of(8_000 * WORD, 4_000 * WORD, 4_000 * WORD);
        assert_eq!(2 * names.words, names.total);
        assert_eq!(names.warning(), NAMES_FILL);
        // Words below half, with two devices each at half of the rest.
        let neither = channel_of(8_000 * WORD - WORD, 4_000 * WORD, 4_000 * WORD);
        assert!(2 * neither.words < neither.total);
        assert_eq!(neither.warning(), NEARLY_FULL);
        // A device with no name from you is named by the words of its
        // key; one with a name, by its words and then its name, quoted, as
        // no words can be forged in it (decision 2026-11-11 (plain words),
        // rule 4): `remove-device` asks of it.
        let mut no_label = another.clone();
        no_label.by[1].label.clear();
        assert!(
            no_label
                .warning()
                .starts_with("memory: the device (able bake cold dune) has")
        );
        let mut forged = another.clone();
        forged.by[1].label = "x\" (acid baby cage dart".into();
        assert!(
            forged
                .warning()
                .starts_with("memory: (able bake cold dune) \"x\\\" (acid baby cage dart\" has"),
            "{}",
            forged.warning()
        );
        // And the status says it.
        let shown = with(&|f| f.channel = Some(another.clone()));
        assert_eq!(shown.summary, ANOTHER_FILLED);
    }

    /// The level is the gravest that holds, and the line shows the first
    /// thing of that level (decision 2026-10-04 §10.1): for each pair of
    /// one red thing, one amber thing and one thing of no level, the
    /// level is the graver and the line is that thing's. So the mark and
    /// the words never disagree.
    #[test]
    fn the_level_is_the_gravest_and_the_line_is_its_first_thing() {
        // Things that can hold together with any other here: where a
        // thing of no level is "nothing mapped" or "starting", there is
        // no amber at all, which has its own test.
        let none = &NO_LEVEL[2..];
        for (red, _, red_says) in RED {
            for (amber, amber_what, _) in AMBER {
                for (plain, _, _) in none {
                    let shown = with(&|f| {
                        plain(f);
                        amber(f);
                        red(f);
                    });
                    assert_eq!(shown.level, Some(Level::Red), "{red_says}");
                    assert_eq!(shown.summary, red_says, "with {amber_what}");
                    // The tooltip has everything: the amber thing too.
                    // (What is about a person's devices holds only where
                    // the device follows a phrase.)
                    let no_phrase = whats(&shown).contains(&"no_phrase");
                    if !(no_phrase && OF_DEVICES.contains(&amber_what)) {
                        assert!(whats(&shown).contains(&amber_what), "{red_says}");
                    }
                }
            }
        }
        for (amber, _, amber_says) in AMBER {
            for (plain, _, plain_says) in none {
                let shown = with(&|f| {
                    plain(f);
                    amber(f);
                });
                assert_eq!(shown.level, Some(Level::Amber), "{amber_says}");
                assert_eq!(shown.summary, amber_says, "with {plain_says}");
            }
        }
        // A conflict beside no relay for six minutes: red, the conflict.
        let both = with(&|f| {
            f.peers_hot = 0;
            f.no_relay_secs = Some(360);
            f.conflicts = vec!["a".into()];
        });
        assert_eq!(both.level, Some(Level::Red));
        assert_eq!(both.summary, "memory: 1 conflict");
        assert_eq!(whats(&both), ["conflicts", "no_relay"]);
    }

    /// Before any level (decision 2026-10-04 §10.1): a device that is not
    /// set up, a node that is stopped or was not asked, a relay and a
    /// bootnode are states of their own, shown as they always were, with
    /// no level, whatever else is said of them.
    #[test]
    fn what_is_not_a_personal_node_that_runs_has_no_level() {
        let everything = |f: &mut Facts| {
            for (edit, _, _) in RED.iter().skip(5).chain(AMBER.iter()) {
                edit(f);
            }
        };
        let cases: [(Edit, State, &str); 5] = [
            (
                &|f| f.initialised = false,
                State::Uninitialised,
                "cordelia not set up",
            ),
            (
                &|f| f.running = false,
                State::Stopped,
                "memory: node stopped",
            ),
            (
                &|f| {
                    f.running = false;
                    f.not_asked = true;
                },
                State::Attention,
                "memory: node not asked (see `cordelia status`)",
            ),
            (
                &|f| f.role = "relay".into(),
                State::Offline,
                "relay: no peers",
            ),
            (
                &|f| f.role = "bootnode".into(),
                State::Offline,
                "bootnode: no peers",
            ),
        ];
        for (edit, state, says) in cases {
            for stands in ["applied", "removed", "no_phrase"] {
                let shown = with(&|f| {
                    everything(f);
                    f.stands = stands.into();
                    edit(f);
                });
                assert_eq!(shown.level, None, "{says}");
                assert!(shown.holds.is_empty(), "{says}");
                assert_eq!((shown.state, shown.summary.as_str()), (state, says));
            }
        }
    }

    /// A node that is held up is red whatever sync says (decision
    /// 2026-10-04 §10.1): its database is of a later version, or from
    /// before alpha.19 (decision 2026-11-10 (older kind), rule 6). Nothing
    /// asks whether sync is on first: a node that is held refuses the
    /// request that would say so, and the command then knows neither
    /// whether sync is on, nor what is mapped, nor where the device
    /// stands.
    #[test]
    fn a_node_that_is_held_up_is_red_whatever_sync_says() {
        for (by, says) in [
            (
                "later_database",
                "memory not syncing: the database is from a later version",
            ),
            (
                "earlier_database",
                "memory not syncing: the database is from before 0.2.0-alpha.19",
            ),
        ] {
            let held = |edit: &dyn Fn(&mut Facts)| {
                with(&|f| {
                    f.held = Some(by.into());
                    edit(f);
                })
            };
            let cases: [&dyn Fn(&mut Facts); 5] = [
                &|_| {},
                &|f| f.sync_enabled = false,
                &|f| {
                    f.sync_enabled = false;
                    f.mapped = 0;
                    f.folders = 0;
                },
                &|f| f.stands = "no_phrase".into(),
                // As the command has it beside a node that refuses every
                // request but that of its status.
                &|f| {
                    *f = Facts {
                        initialised: true,
                        running: true,
                        role: "personal".into(),
                        held: f.held.clone(),
                        ..Default::default()
                    }
                },
            ];
            for edit in cases {
                let shown = held(edit);
                assert_eq!(
                    (shown.level, shown.state),
                    (Some(Level::Red), State::Attention),
                    "{by}"
                );
                assert_eq!(shown.summary, says);
                assert!(whats(&shown).contains(&"held"), "{by}");
            }
            // With sync off it is all that holds.
            assert_eq!(whats(&held(&|f| f.sync_enabled = false)), ["held"]);
        }
    }

    /// What is about a person's devices holds wherever this device
    /// follows a phrase, with sync on or off, and with or without a
    /// folder mapped or a report (decision 2026-10-04 §10.1): red for a
    /// device that has stopped, with the state `attention`; amber for a
    /// removal that some device has not applied, an addition that nobody
    /// cleared, and a device that said it left. A device that maps
    /// nothing is still one of the person's. What is about folders needs
    /// sync on, something mapped and a report: none of it holds
    /// otherwise.
    #[test]
    fn what_is_about_a_persons_devices_holds_whatever_sync_says() {
        let wheres: [(Edit, &str); 4] = [
            (&|f| f.sync_enabled = false, "sync off"),
            (
                &|f| {
                    f.mapped = 0;
                    f.folders = 0;
                },
                "nothing mapped",
            ),
            (&|f| f.report_age_secs = None, "no report yet"),
            (
                &|f| {
                    f.sync_enabled = false;
                    f.mapped = 0;
                    f.folders = 0;
                    f.report_age_secs = None;
                },
                "none of the three",
            ),
        ];
        for (place, where_) in wheres {
            // Red, and `attention`: each way a device has stopped.
            for (stopped, what, says) in &RED[..5] {
                let shown = with(&|f| {
                    stopped(f);
                    place(f);
                });
                assert_eq!(
                    (shown.level, shown.state),
                    (Some(Level::Red), State::Attention),
                    "{says}, {where_}"
                );
                assert_eq!(shown.summary, *says, "{where_}");
                assert_eq!(whats(&shown), [*what], "{where_}");
            }
            // Amber: each of the five, alone, with the state as it is
            // without it.
            for (amber, what, says) in &AMBER[2..7] {
                let without = with(place);
                let shown = with(&|f| {
                    amber(f);
                    place(f);
                });
                assert_eq!(shown.level, Some(Level::Amber), "{says}, {where_}");
                assert_eq!(shown.summary, *says, "{where_}");
                assert_eq!(whats(&shown), [*what], "{where_}");
                assert_eq!(shown.state, without.state, "{where_}");
            }
            // Everything amber at once: the five, in their order, and
            // nothing that is about folders.
            let all = with(&|f| {
                for (edit, _, _) in AMBER {
                    edit(f);
                }
                place(f);
            });
            assert_eq!(whats(&all), OF_DEVICES, "{where_}");
            // A device that follows no phrase is no person's: none of
            // them holds there.
            let no_phrase = with(&|f| {
                for (edit, _, _) in AMBER {
                    edit(f);
                }
                place(f);
                f.stands = "no_phrase".into();
            });
            let held = whats(&no_phrase);
            assert!(
                OF_DEVICES.iter().all(|what| !held.contains(what)),
                "{where_}"
            );
        }
        // With sync off, the line says the first of them, and the state
        // is `off` still.
        let off = with(&|f| {
            f.sync_enabled = false;
            f.devices.added_not_cleared = 1;
        });
        assert_eq!(
            (off.state, off.level, off.summary.as_str()),
            (
                State::Off,
                Some(Level::Amber),
                "memory: a device was added. If you did not add it, remove it; if you did, run \
                 cordelia devices --clear"
            )
        );
        // Sync off with errors, conflicts and no relay:
        // nothing of folders holds, and the line says off.
        let off = with(&|f| {
            for (edit, _, _) in RED.iter().skip(7).chain(&AMBER[..2]).chain(&AMBER[7..]) {
                edit(f);
            }
            f.sync_enabled = false;
        });
        assert_eq!((off.level, off.state), (None, State::Off));
        assert!(off.holds.is_empty());
        assert_eq!(off.summary, "memory sync off");
    }

    /// Where this device was answered with a change that it could not
    /// apply, the state is `attention`, and not `synced` (decision
    /// 2026-10-04 §10.1): it sends nothing and takes nothing until it
    /// can. So it is with sync off, and with nothing mapped; and a node
    /// that is held up, or a device that has stopped for good, says that
    /// first.
    #[test]
    fn a_device_that_could_not_apply_a_change_is_attention_and_not_synced() {
        let says = "memory not syncing: a change to your devices could not be used here";
        let not_applied = |edit: &dyn Fn(&mut Facts)| {
            let mut f = synced();
            f.devices.not_applied = true;
            edit(&mut f);
            derive(&f)
        };
        assert_eq!(not_applied(&|_| {}), (State::Attention, says.into()));
        assert_eq!(
            not_applied(&|f| f.sync_enabled = false),
            (State::Attention, says.into())
        );
        assert_eq!(
            not_applied(&|f| {
                f.mapped = 0;
                f.folders = 0;
            }),
            (State::Attention, says.into())
        );
        assert_eq!(
            not_applied(&|f| f.errors = vec!["x".into()]),
            (State::Attention, says.into())
        );
        assert_eq!(
            not_applied(&|f| f.stands = "fork".into()).1,
            "memory not syncing: a device you removed has the secret of each change that \
             includes this device"
        );
        assert_eq!(
            not_applied(&|f| f.held = Some("earlier_database".into())).1,
            "memory not syncing: the database is from before 0.2.0-alpha.19"
        );
        // Without it, synced.
        assert_eq!(derive(&synced()).0, State::Synced);
    }

    /// The line and the level never disagree, and no state lost its
    /// highlight (decision 2026-10-04 §10.1). Over every pair of things
    /// that can be said of a node, with sync on and off, with and without
    /// a folder mapped, and under a phrase and under none: where the
    /// state is `attention`, either a level holds or the line and the bar
    /// draw as they did before there was a level, in red and `active`;
    /// with red the line is red and the bar `active`; with amber the line
    /// has amber's mark and the bar is not `active`; and with no level
    /// and another state nothing is highlighted.
    #[test]
    fn the_line_and_the_level_never_disagree() {
        let things: Vec<Edit> = RED
            .iter()
            .map(|(edit, _, _)| *edit)
            .chain(AMBER.iter().map(|(edit, _, _)| *edit))
            .chain(NO_LEVEL.iter().map(|(edit, _, _)| *edit))
            .chain([
                (&|f: &mut Facts| f.running = false) as Edit,
                &|f: &mut Facts| f.not_asked = true,
                &|f: &mut Facts| f.role = "relay".into(),
            ])
            .collect();
        let places: [Edit; 5] = [
            &|_| {},
            &|f| f.sync_enabled = false,
            &|f| {
                f.mapped = 0;
                f.folders = 0;
            },
            &|f| {
                if f.stands == "applied" {
                    f.stands = "no_phrase".into();
                }
            },
            &|f| {
                f.sync_enabled = false;
                if f.stands == "applied" {
                    f.stands = "no_phrase".into();
                }
            },
        ];
        let (mut seen, mut attention_alone) = (0, 0);
        for one in &things {
            for other in &things {
                for place in places {
                    let shown = with(&|f| {
                        one(f);
                        other(f);
                        place(f);
                    });
                    let line = line(shown.state, shown.level, "x", false);
                    let drawn: serde_json::Value =
                        serde_json::from_str(&bar(shown.state, shown.level, "x", &[])).unwrap();
                    let active = drawn["class"]
                        .as_array()
                        .is_some_and(|class| class.iter().any(|class| class == "active"));
                    let red = line.starts_with('▲');
                    match (shown.level, shown.state) {
                        (Some(Level::Red), _) => assert!(red && active, "{shown:?}"),
                        (Some(Level::Amber), _) => {
                            assert!(line.starts_with('◆') && !active, "{shown:?}")
                        }
                        (None, State::Attention) => {
                            attention_alone += 1;
                            assert!(red && active, "{shown:?}");
                        }
                        (None, _) => assert!(!red && !active, "{shown:?}"),
                    }
                    // With a level, the line says a thing of that level.
                    if let Some(level) = shown.level {
                        let first = shown.holds.iter().find(|holds| holds.level == level);
                        assert_eq!(Some(&shown.summary), first.map(|holds| &holds.says));
                    }
                    seen += 1;
                }
            }
        }
        assert_eq!(seen, things.len() * things.len() * places.len());
        // A node that was not asked is `attention` with no level: it is
        // drawn as it always was.
        assert!(attention_alone > 0);
    }

    /// With nothing mapped, or with no report yet, there is no amber of
    /// folders: nothing would move anyway (decision 2026-10-04 §10.1).
    /// Red is red all the same: errors and a stalled cycle.
    #[test]
    fn with_nothing_mapped_or_no_report_yet_there_is_no_amber_of_folders() {
        let of_folders = |f: &mut Facts| {
            for (edit, _, _) in AMBER[..2].iter().chain(&AMBER[7..]) {
                edit(f);
            }
        };
        let nothing_mapped = with(&|f| {
            of_folders(f);
            f.mapped = 0;
            f.folders = 0;
        });
        assert_eq!(nothing_mapped.level, None);
        assert!(nothing_mapped.holds.is_empty());
        assert_eq!(nothing_mapped.summary, "memory: nothing mapped");
        // No relay for six minutes with nothing mapped: no level, and
        // the line says that nothing is mapped.
        let no_relay = with(&|f| {
            f.mapped = 0;
            f.folders = 0;
            f.peers_hot = 0;
            f.no_relay_secs = Some(360);
        });
        assert_eq!((no_relay.level, no_relay.state), (None, State::Off));
        assert_eq!(no_relay.summary, "memory: nothing mapped");
        let no_report = with(&|f| {
            of_folders(f);
            f.report_age_secs = None;
        });
        assert_eq!(no_report.level, None);
        assert_eq!(no_report.summary, "memory sync starting");
        // Each thing of folders needs all three: with one of them
        // missing, none holds.
        for (edit, what, _) in AMBER[..2].iter().chain(&AMBER[7..]) {
            for missing in [
                (&|f: &mut Facts| f.mapped = 0) as &dyn Fn(&mut Facts),
                &|f: &mut Facts| f.report_age_secs = None,
                &|f: &mut Facts| f.sync_enabled = false,
            ] {
                let shown = with(&|f| {
                    edit(f);
                    missing(f);
                });
                assert!(!whats(&shown).contains(what), "{what}");
            }
        }

        // Red with nothing mapped: errors, and a stalled cycle.
        for (edit, what) in [
            (
                (&|f: &mut Facts| f.errors = vec!["x".into()]) as &dyn Fn(&mut Facts),
                "errors",
            ),
            (
                &|f: &mut Facts| f.report_age_secs = Some(STALE_REPORT_SECS + 1),
                "stalled",
            ),
        ] {
            let shown = with(&|f| {
                of_folders(f);
                f.mapped = 0;
                f.folders = 0;
                edit(f);
            });
            assert_eq!(shown.level, Some(Level::Red), "{what}");
            assert_eq!(whats(&shown), [what]);
        }
    }

    /// A device that follows no phrase is red, and its state `attention`,
    /// only with sync on and something mapped (decision 2026-10-04
    /// §10.1): nothing it holds syncs until a person acts. With sync off,
    /// or nothing mapped, the state is what it would be without that, and
    /// the words still say it: "no recovery phrase yet".
    #[test]
    fn no_phrase_is_red_only_with_sync_on_and_something_mapped() {
        let no_phrase = |edit: &dyn Fn(&mut Facts)| {
            with(&|f| {
                f.stands = "no_phrase".into();
                edit(f);
            })
        };
        let new_install = "memory stays here: no recovery phrase yet";
        let mapped = no_phrase(&|_| {});
        assert_eq!(
            (mapped.level, mapped.state, mapped.summary.as_str()),
            (Some(Level::Red), State::Attention, new_install)
        );
        // Nothing mapped: off, as it would be, and the words say it.
        let nothing = no_phrase(&|f| {
            f.mapped = 0;
            f.folders = 0;
        });
        assert_eq!(
            (nothing.level, nothing.state, nothing.summary.as_str()),
            (None, State::Off, new_install)
        );
        assert!(nothing.holds.is_empty());
        // Sync off: off, and the words say it; with something mapped,
        // and with nothing.
        for mapped in [2, 0] {
            let off = no_phrase(&|f| {
                f.sync_enabled = false;
                f.mapped = mapped;
            });
            assert_eq!(
                (off.level, off.state, off.summary.as_str()),
                (None, State::Off, new_install)
            );
        }
        // Nothing mapped and no report yet: starting, as it would be.
        let starting = no_phrase(&|f| {
            f.mapped = 0;
            f.folders = 0;
            f.report_age_secs = None;
        });
        assert_eq!(
            (starting.level, starting.state, starting.summary.as_str()),
            (None, State::Syncing, new_install)
        );
        // What needs the person with nothing mapped is said first.
        let error = no_phrase(&|f| {
            f.mapped = 0;
            f.errors = vec!["x".into()];
        });
        assert_eq!(
            (error.level, error.state, error.summary.as_str()),
            (Some(Level::Red), State::Attention, "memory sync error")
        );
    }

    /// A conflict and a file too large in a report whose folders do not
    /// sync: the state says them as the level does, and not "nothing
    /// mapped".
    #[test]
    fn the_state_says_a_conflict_where_no_folder_of_the_report_syncs() {
        let agree = |edit: &dyn Fn(&mut Facts), says: &str| {
            let mut f = synced();
            f.folders = 0;
            edit(&mut f);
            let shown = shown(&f);
            assert_eq!(derive(&f), (State::Attention, says.into()), "{f:?}");
            assert_eq!(
                (shown.level, shown.summary.as_str()),
                (Some(Level::Red), says)
            );
        };
        for mapped in [0, 1] {
            agree(
                &|f| {
                    f.mapped = mapped;
                    f.conflicts = vec!["x".into()];
                },
                "memory: 1 conflict",
            );
            agree(
                &|f| {
                    f.mapped = mapped;
                    f.too_large = vec!["a/memory/b.md".into()];
                },
                "memory: 1 file too large",
            );
        }
    }

    /// The waits (decision 2026-10-04 §10.1). No relay: none at four
    /// minutes, amber at six, by the node's own clock; none beside a node
    /// that does not say since when. A relay not known to hold the latest
    /// change: amber once it has lacked it for more than five minutes
    /// (decision 2026-10-19, rule 11). Names not yet in the new generation, or not yet
    /// sent: amber after more than five minutes, and the first of them
    /// for seven days from when the change was applied. A removal that some
    /// device has not applied: amber for its first seven days. A relay's
    /// refusal for room: while it is recent.
    #[test]
    fn what_passes_by_itself_is_amber_only_once_it_has_lasted() {
        let level = |edit: &dyn Fn(&mut Facts)| with(edit).level;
        let amber = Some(Level::Amber);
        let offline = |secs: Option<u64>| {
            level(&|f| {
                f.peers_hot = 0;
                f.no_relay_secs = secs;
            })
        };
        assert_eq!(offline(Some(240)), None);
        assert_eq!(offline(Some(300)), None);
        assert_eq!(offline(Some(301)), amber);
        assert_eq!(offline(Some(360)), amber);
        // A node that does not say since when: a missing relay gives no
        // level, however long it may have been.
        assert_eq!(offline(None), None);
        assert_eq!(
            with(&|f| {
                f.peers_hot = 0;
                f.no_relay_secs = Some(240);
            })
            .summary,
            "memory offline"
        );

        let without_latest =
            |secs: u64| level(&|f| f.devices.not_known_to_hold = lacking_for(&[secs]));
        assert_eq!(without_latest(10), None);
        assert_eq!(without_latest(300), None);
        assert_eq!(without_latest(301), amber);

        let not_listed = |secs: Option<u64>| {
            level(&|f| {
                f.devices.names_not_listed = 1;
                f.devices.applied_secs = secs;
            })
        };
        assert_eq!(not_listed(Some(300)), None);
        assert_eq!(not_listed(Some(301)), amber);
        assert_eq!(not_listed(None), None);
        // For seven days from when this device applied the change, and
        // no longer: a device in a drawer does not keep the line amber.
        let week = 7 * 24 * 60 * 60;
        assert_eq!(not_listed(Some(week)), amber);
        assert_eq!(not_listed(Some(week + 1)), None);
        assert_eq!(not_listed(Some(90 * 24 * 60 * 60)), None);
        // Names still to send are said then, where some wait.
        let both = with(&|f| {
            f.devices.names_not_listed = 1;
            f.devices.applied_secs = Some(week + 1);
            f.devices.names_to_go = 2;
            f.devices.to_go_secs = Some(400);
        });
        assert_eq!(both.summary, "memory: 2 names not yet sent");
        let to_go = |secs: Option<u64>| {
            level(&|f| {
                f.devices.names_to_go = 1;
                f.devices.to_go_secs = secs;
            })
        };
        assert_eq!(to_go(Some(2)), None);
        assert_eq!(to_go(Some(300)), None);
        assert_eq!(to_go(Some(301)), amber);
        assert_eq!(to_go(None), None);
        // What a carry holds with no folder, and has not yet sent: so
        // too, and on a machine that maps nothing, with sync off.
        let carried = |secs: Option<u64>| {
            level(&|f| {
                f.sync_enabled = false;
                f.mapped = 0;
                f.folders = 0;
                f.devices.names_to_go = 2;
                f.devices.carried_to_go = 2;
                f.devices.carried_to_go_secs = secs;
            })
        };
        assert_eq!(carried(Some(300)), None);
        assert_eq!(carried(Some(301)), amber);
        assert_eq!(carried(None), None);
        assert_eq!(level(&|f| f.devices.carried_to_go_secs = Some(900)), None);
        // Those names are said once: what is said of names still to send
        // is of the others.
        let both = with(&|f| {
            f.devices.names_to_go = 3;
            f.devices.to_go_secs = Some(400);
            f.devices.carried_to_go = 2;
            f.devices.carried_to_go_secs = Some(400);
        });
        let says: Vec<&str> = both.holds.iter().map(|h| h.says.as_str()).collect();
        assert_eq!(
            says,
            [
                "memory: 2 names copied over, not yet sent",
                "memory: 1 name not yet sent"
            ]
        );
        let only_carried = with(&|f| {
            f.devices.names_to_go = 2;
            f.devices.to_go_secs = Some(400);
            f.devices.carried_to_go = 2;
            f.devices.carried_to_go_secs = Some(400);
        });
        assert_eq!(whats(&only_carried), ["carried"]);
        // A time with nothing that waits is nothing.
        assert_eq!(level(&|f| f.devices.to_go_secs = Some(900)), None);
        assert_eq!(level(&|f| f.devices.applied_secs = Some(900)), None);

        let day = 24 * 60 * 60;
        let removal = |secs: u64| level(&|f| f.devices.removal_not_applied_secs = Some(secs));
        assert_eq!(removal(0), amber);
        assert_eq!(removal(7 * day), amber);
        assert_eq!(removal(7 * day + 1), None);

        // A head set aside by a device that goes on: amber for seven days
        // from when it was set aside (decision 2026-10-24 (removal), rule
        // 11), and said so.
        let set_aside = |secs: u64| level(&|f| f.devices.set_aside_secs = Some(secs));
        assert_eq!(set_aside(0), amber);
        assert_eq!(set_aside(7 * day), amber);
        assert_eq!(set_aside(7 * day + 1), None);
        let aside = with(&|f| f.devices.set_aside_secs = Some(60));
        assert_eq!(whats(&aside), ["set_aside"]);
        assert_eq!(
            aside.summary,
            "memory: a change to your devices was made separately, and put aside"
        );
        // After a removal not yet applied by every device, and before a
        // device added since.
        let three = with(&|f| {
            f.devices.set_aside_secs = Some(60);
            f.devices.removal_not_applied_secs = Some(60);
            f.devices.added_not_cleared = 1;
        });
        assert_eq!(whats(&three), ["removal_not_applied", "set_aside", "added"]);

        let no_room = |ago: u64| level(&|f| f.devices.no_room_secs = vec![ago]);
        assert_eq!(no_room(0), amber);
        assert_eq!(no_room(NO_ROOM_STANDS_SECS), amber);
        assert_eq!(no_room(NO_ROOM_STANDS_SECS + 1), None);
        assert_eq!(level(&|f| f.devices.no_room_secs = vec![9_000, 20]), amber);
    }

    /// One clock says whether the cycle has stalled (decision 2026-10-04
    /// §10.1): for how long the node has stored no report, by its own
    /// clock, which does not run while the machine sleeps. A machine
    /// that wakes holds a report that is hours old by the wall clock,
    /// and is not stalled; and a cycle that has stored none for more
    /// than a minute of the node's own time has stalled, however fresh
    /// the wall clock makes its report. With no report at all, nothing
    /// has stalled: the cycle is starting.
    #[test]
    fn a_machine_that_wakes_is_not_stalled_for_the_time_it_slept() {
        let of = |age: Option<i64>, none_for: Option<u64>| {
            let shown = with(&|f| {
                f.report_age_secs = age;
                f.no_report_secs = none_for;
            });
            (shown.level, shown.state, shown.summary)
        };
        let synced = (None, State::Synced, "memory synced".to_string());
        let stalled = (
            Some(Level::Red),
            State::Attention,
            "memory sync stalled".to_string(),
        );
        // It slept for eight hours, and its last cycle was three
        // seconds of its own time ago.
        assert_eq!(of(Some(8 * 3_600), Some(3)), synced);
        assert_eq!(of(Some(8 * 3_600), Some(STALE_REPORT_SECS as u64)), synced);
        assert_eq!(
            of(Some(8 * 3_600), Some(STALE_REPORT_SECS as u64 + 1)),
            stalled
        );
        // The wall clock was set back: the report looks fresh, and no
        // cycle has stored one for two minutes.
        assert_eq!(of(Some(1), Some(120)), stalled);
        assert_eq!(of(Some(-500), Some(120)), stalled);
        // No report: starting, whatever the node says.
        assert_eq!(of(None, Some(900)).2, "memory sync starting");
        // A node that has just started beside a report of an earlier
        // run: it has stored none for as long as it has run.
        let just_started = with(&|f| {
            f.report_age_secs = Some(600);
            f.uptime_secs = Some(10);
            f.no_report_secs = Some(10);
        });
        assert_eq!(just_started.level, None);
        // A node that does not say is read as an earlier version read
        // it: by the report's age, and the node's start.
        assert_eq!(of(Some(8 * 3_600), None), stalled);
        assert_eq!(of(Some(3), None), synced);
    }

    /// Beside a node that does not say for how long it has stored no
    /// report, a cycle counts as stalled from the node's start (decision
    /// 2026-10-04 §10.1): a report that an earlier run stored does not
    /// make a node that has just started stalled, in the level or in the
    /// state.
    #[test]
    fn a_report_of_an_earlier_run_does_not_make_a_node_that_just_started_stalled() {
        let started = |up: Option<u64>| {
            with(&|f| {
                f.report_age_secs = Some(600);
                f.uptime_secs = up;
            })
        };
        let just = started(Some(10));
        assert_eq!((just.level, just.state), (None, State::Synced));
        assert_eq!(just.summary, "memory synced");
        let at_the_bound = started(Some(STALE_REPORT_SECS as u64));
        assert_eq!(at_the_bound.level, None);
        let later = started(Some(STALE_REPORT_SECS as u64 + 1));
        assert_eq!(
            (later.level, later.state),
            (Some(Level::Red), State::Attention)
        );
        assert_eq!(later.summary, "memory sync stalled");
        // A node that does not say for how long it has run: by the
        // report alone.
        assert_eq!(started(None).level, Some(Level::Red));
        // A report that is fresh is fresh.
        let fresh = with(&|f| f.uptime_secs = Some(10));
        assert_eq!(fresh.level, None);
    }

    /// The state is worked out as it was, whatever the level (decision
    /// 2026-10-04 §10.1), for a panel that draws from it alone: entries
    /// that relays refuse are `attention`, though the level is amber; and
    /// a node of another version does not change the state.
    #[test]
    fn the_state_is_as_it_was_whatever_the_level() {
        let of = |edit: &dyn Fn(&mut Facts)| {
            let shown = with(edit);
            (shown.state, shown.level)
        };
        assert_eq!(
            of(&|f| f.other_version = true),
            (State::Synced, Some(Level::Amber))
        );
        assert_eq!(
            of(&|f| {
                f.other_version = true;
                f.outbox_waiting = 2;
            }),
            (State::Syncing, Some(Level::Amber))
        );
        assert_eq!(
            of(&|f| {
                f.peers_hot = 0;
                f.no_relay_secs = Some(400);
            }),
            (State::Offline, Some(Level::Amber))
        );
        // Each thing of a person's devices leaves the state as it was.
        for (edit, what, _) in &AMBER[2..] {
            assert_eq!(of(edit), (State::Synced, Some(Level::Amber)), "{what}");
        }
        // And for every thing of the two lists, the state is what it is
        // with the level left out of account.
        for (edit, what, _) in RED.iter().chain(AMBER.iter()) {
            let mut f = synced();
            edit(&mut f);
            assert_eq!(shown(&f).state, derive(&f).0, "{what}");
        }
    }

    /// What a tooltip and the plain status say of a thing that holds,
    /// beside the line.
    #[test]
    fn what_holds_is_said_beside_the_line() {
        let detail = |level: Level, says: &str| {
            Holds {
                level,
                what: "x",
                says: says.into(),
            }
            .detail()
        };
        assert_eq!(
            detail(Level::Red, "memory: 1 conflict"),
            "Needs you: 1 conflict"
        );
        assert_eq!(
            detail(Level::Red, "memory sync error"),
            "Needs you: sync error"
        );
        assert_eq!(
            detail(Level::Amber, "memory: no relay for 6 minutes"),
            "To know: no relay for 6 minutes"
        );
        assert_eq!(
            (Level::Red.as_str(), Level::Amber.as_str()),
            ("red", "amber")
        );
    }

    fn state(f: &Facts) -> (State, String) {
        derive(f)
    }

    #[test]
    fn a_connected_idle_device_is_synced() {
        assert_eq!(state(&synced()), (State::Synced, "memory synced".into()));
    }

    #[test]
    fn states_in_order_of_precedence() {
        let with = |edit: &dyn Fn(&mut Facts)| {
            let mut f = synced();
            edit(&mut f);
            state(&f)
        };
        assert_eq!(with(&|f| f.initialised = false).0, State::Uninitialised);
        assert_eq!(
            with(&|f| f.running = false),
            (State::Stopped, "memory: node stopped".into())
        );
        // A node that was not asked is not said to be stopped.
        let (not_asked, summary) = with(&|f| {
            f.running = false;
            f.not_asked = true;
        });
        assert_eq!(not_asked, State::Attention);
        assert!(summary.contains("not asked"), "{summary}");
        let not_set_up = with(&|f| {
            f.initialised = false;
            f.not_asked = true;
        });
        assert_eq!(not_set_up.0, State::Uninitialised);
        assert_eq!(
            with(&|f| f.sync_enabled = false),
            (State::Off, "memory sync off".into())
        );
        assert_eq!(
            with(&|f| f.errors = vec!["x".into()]),
            (State::Attention, "memory sync error".into())
        );
        assert_eq!(
            with(&|f| f.report_age_secs = None),
            (State::Syncing, "memory sync starting".into())
        );
        assert_eq!(
            with(&|f| f.report_age_secs = Some(STALE_REPORT_SECS + 1)),
            (State::Attention, "memory sync stalled".into())
        );
        // Sync is on, and nothing syncs: not an error, but not "synced".
        assert_eq!(
            with(&|f| f.folders = 0),
            (State::Off, "memory: nothing mapped".into())
        );
        assert_eq!(
            with(&|f| f.conflicts = vec!["a".into(), "b".into()]),
            (State::Attention, "memory: 2 conflicts".into())
        );
        // So does a file that has grown too large to sync.
        assert_eq!(
            with(&|f| f.too_large = vec!["a.md".into()]),
            (State::Attention, "memory: 1 file too large".into())
        );
        // A conflict needs the person even while offline.
        assert_eq!(
            with(&|f| {
                f.peers_hot = 0;
                f.conflicts = vec!["a".into()];
            }),
            (State::Attention, "memory: 1 conflict".into())
        );
        assert_eq!(
            with(&|f| f.peers_hot = 0),
            (State::Offline, "memory offline".into())
        );
        assert_eq!(
            with(&|f| {
                f.peers_hot = 0;
                f.outbox_waiting = 3;
            }),
            (State::Offline, "memory offline, 3 waiting".into())
        );
        assert_eq!(
            with(&|f| f.outbox_waiting = 4),
            (State::Syncing, "memory sending 4".into())
        );
        assert_eq!(
            with(&|f| f.projects_waiting = 1),
            (State::Syncing, "memory fetching 1 folder".into())
        );
    }

    /// Only a device that has applied a statement publishes anything
    /// (decision 2026-10-04 §5.2). One that follows no phrase, or has
    /// stopped, is never said to be synced, whatever its last cycle
    /// listed and however many relays it reaches: the one is off, and the
    /// other needs the person.
    #[test]
    fn a_device_that_publishes_nothing_is_not_said_to_be_synced() {
        let stands = |stands: &str| {
            let mut f = synced();
            f.stands = stands.into();
            state(&f)
        };
        assert_eq!(stands("applied"), (State::Synced, "memory synced".into()));
        // A node that did not say where it stands is read as before.
        assert_eq!(stands(""), (State::Synced, "memory synced".into()));
        // With no phrase the state is `attention`, and it says that it
        // has no recovery phrase yet (decision 2026-10-04 §10.1).
        assert_eq!(
            stands("no_phrase"),
            (
                State::Attention,
                "memory stays here: no recovery phrase yet".into()
            )
        );
        for (stopped, says) in [
            (
                "fork",
                "a device you removed has the secret of each change that includes this device",
            ),
            ("removed", "this device was removed"),
            ("not_listed", "not in the last change to your devices"),
            ("not_opened", "a change to your devices could not be opened"),
            (
                "closed",
                "a device you removed still has the secret this device uses",
            ),
        ] {
            assert_eq!(
                stands(stopped),
                (State::Attention, format!("memory not syncing: {says}"))
            );
        }
        // The way on, by what the look says first (`short`), as `Devices:`
        // says it: none where this device itself was removed.
        use cordelia_api::look::{CLOSED_SHORT, REMOVED_AS_KNOWN_SHORT, short_why};
        let fork = short_why(cordelia_storage::person::State::Fork);
        for (stopped, short, says) in [
            (
                "closed",
                CLOSED_SHORT,
                "a device you removed still has the secret this device uses; run cordelia renew",
            ),
            ("closed", REMOVED_AS_KNOWN_SHORT, "this device was removed"),
            (
                "fork",
                CLOSED_SHORT,
                "a device you removed still has the secret this device uses; run cordelia renew",
            ),
            ("fork", REMOVED_AS_KNOWN_SHORT, "this device was removed"),
            (
                "fork",
                fork,
                "two changes to your devices were made separately; run cordelia settle",
            ),
        ] {
            let mut f = synced();
            f.stands = stopped.into();
            f.devices.short = short.into();
            assert_eq!(
                state(&f),
                (State::Attention, format!("memory not syncing: {says}")),
                "{stopped} {short}"
            );
        }
        // With sync off, a device with no phrase is off, and still
        // says that it has none; one that has stopped needs the person
        // all the same.
        let mut f = synced();
        f.stands = "no_phrase".into();
        f.sync_enabled = false;
        assert_eq!(
            state(&f),
            (
                State::Off,
                "memory stays here: no recovery phrase yet".into()
            )
        );
        f.stands = "removed".into();
        assert_eq!(
            state(&f),
            (
                State::Attention,
                "memory not syncing: this device was removed".into()
            )
        );
    }

    /// A node that is held up is said to be so, ahead of everything that
    /// a running personal node says of its memory: it runs no cycle and
    /// no pass, with sync on or off (decision 2026-10-04 §10.1).
    #[test]
    fn a_node_that_is_held_up_needs_the_person_whatever_else_it_says() {
        let held = |by: &str, edit: &dyn Fn(&mut Facts)| {
            let mut f = synced();
            f.held = Some(by.into());
            edit(&mut f);
            state(&f)
        };
        let earlier = (
            State::Attention,
            "memory not syncing: the database is from before 0.2.0-alpha.19".to_string(),
        );
        assert_eq!(held("earlier_database", &|_| {}), earlier);
        assert_eq!(
            held("earlier_database", &|f| f.sync_enabled = false),
            earlier
        );
        assert_eq!(
            held("earlier_database", &|f| f.stands = "no_phrase".into()),
            earlier
        );
        assert_eq!(
            held("earlier_database", &|f| f.errors = vec!["x".into()]),
            earlier
        );
        assert_eq!(
            held("later_database", &|f| f.sync_enabled = false),
            (
                State::Attention,
                "memory not syncing: the database is from a later version".into()
            )
        );
        assert_eq!(
            held("something that a later node says", &|_| {}),
            (
                State::Attention,
                "memory not syncing: the node cannot go on".into()
            )
        );
        // A node that is not running, or was not asked, says that first.
        assert_eq!(
            held("earlier_database", &|f| f.running = false).0,
            State::Stopped
        );
    }

    #[test]
    fn relays_report_their_peers() {
        let mut f = synced();
        f.role = "relay".into();
        f.sync_enabled = false;
        assert_eq!(state(&f), (State::Synced, "relay: 2 peers".into()));
        f.peers_hot = 0;
        assert_eq!(state(&f), (State::Offline, "relay: no peers".into()));
    }

    #[test]
    fn lines_are_marked_and_optionally_coloured() {
        assert_eq!(
            line(State::Synced, None, "memory synced", false),
            "● memory synced"
        );
        assert_eq!(
            line(
                State::Attention,
                Some(Level::Red),
                "memory: 1 conflict",
                true
            ),
            "\x1b[31m▲ memory: 1 conflict\x1b[0m"
        );
        assert_eq!(line(State::Uninitialised, None, "x", true), "");
        assert_eq!(line(State::Uninitialised, Some(Level::Red), "x", true), "");
    }

    /// In the line's colours, amber has a mark of its own (decision
    /// 2026-10-04 §10.1): "sending" is drawn yellow, and amber must not
    /// look like it. Red has the mark that attention has. With no level
    /// the mark goes by the state, as it always did.
    #[test]
    fn amber_has_a_mark_of_its_own_in_the_line() {
        let amber = line(State::Attention, Some(Level::Amber), "x", false);
        let sending = line(State::Syncing, None, "x", false);
        let red = line(State::Attention, Some(Level::Red), "x", false);
        assert_eq!(amber, "◆ x");
        assert_eq!(sending, "◐ x");
        assert_eq!(red, "▲ x");
        // Whatever the state, the level's mark.
        for state in [
            State::Synced,
            State::Syncing,
            State::Offline,
            State::Attention,
            State::Off,
        ] {
            assert_eq!(line(state, Some(Level::Amber), "x", false), "◆ x");
            assert_eq!(
                line(state, Some(Level::Amber), "x", true),
                "\x1b[33m◆ x\x1b[0m"
            );
            assert_eq!(
                line(state, Some(Level::Red), "x", true),
                "\x1b[31m▲ x\x1b[0m"
            );
        }
        // With no level: by the state.
        let marks: Vec<String> = [
            State::Synced,
            State::Syncing,
            State::Offline,
            State::Attention,
            State::Off,
            State::Stopped,
        ]
        .into_iter()
        .map(|state| line(state, None, "x", false))
        .collect();
        assert_eq!(marks, ["● x", "◐ x", "○ x", "▲ x", "○ x", "○ x"]);
    }

    #[test]
    fn bars_get_an_icon_a_tooltip_and_the_state_as_class() {
        let v: serde_json::Value = serde_json::from_str(&bar(
            State::Synced,
            None,
            "memory synced",
            &["Relays: 2 connected".into()],
        ))
        .unwrap();
        assert_eq!(v["text"], "\u{f09d1}");
        assert_eq!(v["tooltip"], "Cordelia: memory synced\nRelays: 2 connected");
        assert_eq!(v["class"], "synced");

        assert_eq!(bar(State::Uninitialised, None, "x", &[]), "");
        assert_eq!(bar(State::Uninitialised, Some(Level::Red), "x", &[]), "");
    }

    /// The bar form carries a class for each level, after the state's
    /// (decision 2026-10-04 §10.1). `active`, which Omarchy's bar
    /// highlights, goes with red, and never with amber; and with no
    /// level it goes with the state `attention`, as it did before there
    /// was a level. Each level has an icon of its own.
    #[test]
    fn the_bar_has_a_class_for_each_level_and_active_with_red_or_attention() {
        let of = |state: State, level: Option<Level>| -> serde_json::Value {
            serde_json::from_str(&bar(state, level, "x", &[])).unwrap()
        };
        let red = of(State::Attention, Some(Level::Red));
        assert_eq!(
            red["class"],
            serde_json::json!(["attention", "red", "active"])
        );
        assert_eq!(red["text"], "\u{f0026}");
        let amber = of(State::Attention, Some(Level::Amber));
        assert_eq!(amber["class"], serde_json::json!(["attention", "amber"]));
        assert_eq!(amber["text"], "\u{f002a}");
        assert_ne!(amber["text"], red["text"]);
        // Whatever the state is, the level's classes follow it.
        assert_eq!(
            of(State::Offline, Some(Level::Amber))["class"],
            serde_json::json!(["offline", "amber"])
        );
        assert_eq!(
            of(State::Synced, Some(Level::Red))["class"],
            serde_json::json!(["synced", "red", "active"])
        );
        // With no level: the state alone, and `active` with `attention`
        // and no other state.
        for state in [
            State::Synced,
            State::Syncing,
            State::Offline,
            State::Off,
            State::Stopped,
        ] {
            assert_eq!(of(state, None)["class"], state.as_str());
        }
        assert_eq!(
            of(State::Attention, None)["class"],
            serde_json::json!(["attention", "active"])
        );
        assert_eq!(of(State::Attention, None)["text"], "\u{f0026}");
    }

    #[test]
    fn ages_read_naturally() {
        assert_eq!(ago(5), "just now");
        assert_eq!(ago(200), "3m ago");
        assert_eq!(ago(7300), "2h ago");
        assert_eq!(ago(200_000), "2d ago");
    }

    /// Messages never hold a level or change the line (decision 2026-10-09
    /// §8, C13, property 15): a node's status with a thousand unread, a
    /// thousand waiting and a relay that refuses the messages channel for
    /// room gives the same facts, `state`, `level`, `summary`, `holds`,
    /// line and bar as one with none, and as one that says nothing of
    /// messages. Both from a device that is synced and from one that waits.
    #[test]
    fn messages_never_hold_a_level_or_change_the_line() {
        let messages = |n: u64| {
            serde_json::json!({
                "unread_by_an_agent": n,
                "unread_by_a_person": n,
                "waiting": n,
                "refused_for_room": n,
                "filled_by": (n > 0).then(|| serde_json::json!({ "label": "laptop", "entries": n })),
                "held_back": n,
                "overwritten": n,
                "no_place": n > 0,
            })
        };
        for (waiting, peers) in [(0, 2), (3, 2), (0, 0)] {
            let live = |with: Option<serde_json::Value>| {
                let mut live = serde_json::json!({
                    "status": "running",
                    "version": env!("CARGO_PKG_VERSION"),
                    "uptime_secs": 3_600,
                    "peers_hot": peers,
                    "outbox_waiting": waiting,
                    "no_relay_secs": (peers == 0).then_some(4_000),
                });
                if let Some(with) = with {
                    live["messages"] = with;
                }
                live
            };
            let seen = |live: serde_json::Value| {
                let mut f = synced();
                running(&mut f, &live);
                let shown = shown(&f);
                let line = line(shown.state, shown.level, &shown.summary, false);
                let bar = bar(shown.state, shown.level, &shown.summary, &[]);
                (format!("{f:?}"), shown, line, bar)
            };
            let none = seen(live(None));
            assert_eq!(seen(live(Some(messages(0)))), none, "{waiting} {peers}");
            assert_eq!(seen(live(Some(messages(1000)))), none, "{waiting} {peers}");
        }
        // The control: what waits of the device's own is a fact.
        let mut f = synced();
        running(&mut f, &serde_json::json!({ "outbox_waiting": 1000 }));
        assert_eq!(f.outbox_waiting, 1000);
    }

    // ── Agents held for their person (decision 2026-10-25, rule 4) ───

    const ONE_PAIR_HELD: &str = "agents wait for you to read their messages; run cordelia msg log";

    /// Pairs of agents held for their person are amber, named
    /// `messages_held`, in words with "you" as the subject, the same for
    /// one pair and for more: the count is the JSON's. Taken from `held_pairs` of
    /// the node's `messages`, and from nothing else of it; with sync on or
    /// off and with or without a folder mapped. The status line shows it
    /// as it shows any amber.
    #[test]
    fn agents_held_for_their_person_are_amber() {
        assert_eq!(MESSAGES_HOLD, "messages_held");
        let one = with(&|f| f.held_pairs = 1);
        assert_eq!(one.level, Some(Level::Amber));
        assert_eq!(whats(&one), [MESSAGES_HOLD]);
        assert_eq!(one.summary, ONE_PAIR_HELD);
        let two = with(&|f| f.held_pairs = 2);
        assert_eq!(two.summary, ONE_PAIR_HELD);
        assert_eq!(MESSAGES_HELD_SAYS, ONE_PAIR_HELD);
        assert_eq!(with(&|f| f.held_pairs = 0).level, None);
        for edit in [(&|f: &mut Facts| f.sync_enabled = false) as Edit, &|f| {
            f.mapped = 0
        }] {
            let shown = with(&|f| {
                edit(f);
                f.held_pairs = 1;
            });
            assert_eq!(shown.level, Some(Level::Amber), "{shown:?}");
            assert_eq!(shown.holds.last().unwrap().what, MESSAGES_HOLD);
        }
        // The status line: amber's mark and the words.
        assert_eq!(
            line(one.state, one.level, &one.summary, false),
            format!("◆ {ONE_PAIR_HELD}")
        );
        // From the node's status.
        let mut f = synced();
        let live = serde_json::json!({ "messages": { "held_pairs": 3, "unread_by_a_person": 40 } });
        running(&mut f, &live);
        assert_eq!(f.held_pairs, 3);
        running(&mut f, &serde_json::json!({}));
        assert_eq!(f.held_pairs, 0);
    }

    /// It ranks below every hold about the person's devices and memory,
    /// red and amber: beside each, the level and the line are what that
    /// one alone gives, and the hold of agents comes last among the holds,
    /// so that it hides none of them.
    #[test]
    fn agents_held_rank_below_every_hold_of_devices_and_memory() {
        let past = channel_of(12 * 1024 * 1024, 0, WORD);
        let mut edits: Vec<Edit> = RED.iter().map(|(edit, _, _)| *edit).collect();
        edits.extend(AMBER.iter().map(|(edit, _, _)| *edit));
        let shared: Edit = &|f| {
            f.devices.removed_holds_shared = vec![HeldShared::default()];
            f.devices.removed_holds_shared_secs = Some(60);
        };
        edits.push(shared);
        let mut checked = 0;
        for edit in edits {
            let alone = with(edit);
            let both = with(&|f| {
                edit(f);
                f.held_pairs = 1;
            });
            assert_eq!(both.level, alone.level, "{alone:?}");
            assert_eq!(both.summary, alone.summary, "{alone:?}");
            if alone.level.is_some() {
                let (last, before) = both.holds.split_last().unwrap();
                assert_eq!(last.what, MESSAGES_HOLD, "{both:?}");
                assert_eq!(before, &alone.holds[..], "{both:?}");
                checked += 1;
            }
        }
        assert!(checked >= RED.len() + AMBER.len(), "{checked}");
        // The personal channel past its line, first among the amber.
        let both = with(&|f| {
            f.channel = Some(past.clone());
            f.held_pairs = 2;
        });
        assert_eq!(both.summary, NAMES_FILL);
        assert_eq!(whats(&both), ["channel_nearly_full", MESSAGES_HOLD]);
        // A red hold and a memory hold together: red decides, and the
        // hold of agents is still last, amber.
        let all = with(&|f| {
            f.conflicts = vec!["notes.md".into()];
            f.other_version = true;
            f.held_pairs = 1;
        });
        assert_eq!(all.level, Some(Level::Red));
        assert_eq!(all.summary, "memory: 1 conflict");
        assert_eq!(whats(&all), ["conflicts", "other_version", MESSAGES_HOLD]);
        assert_eq!(all.holds.last().unwrap().level, Level::Amber);
    }

    // ── A relay out of reach (decision 2026-10-19, rule 11) ──────────

    /// Relays that have lacked the change for these seconds, with no
    /// answer said of them.
    fn lacking_for(secs: &[u64]) -> Vec<NotKnown> {
        secs.iter()
            .map(|secs| NotKnown {
                lacking_secs: *secs,
                said_secs: None,
                out_of_reach: false,
            })
            .collect()
    }

    const NOT_KNOWN: &str = "memory: a relay may not have the latest change to your devices";

    /// A relay that lacks the change for more than five minutes.
    fn lacking(f: &mut Facts) {
        f.devices.not_known_to_hold = lacking_for(&[301]);
        f.devices.known_since_secs = Some(400);
    }

    /// A relay not known to hold the latest change is amber connected or
    /// not, with sync on or off, with or without a folder mapped and a
    /// report: wherever the device follows a phrase, as the other amber of
    /// a person's devices (decision 2026-10-19, rule 11).
    #[test]
    fn a_relay_that_lacks_the_change_is_amber_connected_or_not_with_sync_on_or_off() {
        let places: [Edit; 6] = [
            &|_| {},
            &|f| f.sync_enabled = false,
            &|f| {
                f.mapped = 0;
                f.folders = 0;
            },
            &|f| f.report_age_secs = None,
            // No relay connected at all.
            &|f| {
                f.peers_hot = 0;
                f.no_relay_secs = Some(60);
            },
            &|f| {
                f.sync_enabled = false;
                f.mapped = 0;
                f.report_age_secs = None;
                f.peers_hot = 0;
            },
        ];
        for (n, place) in places.iter().enumerate() {
            let shown = with(&|f| {
                lacking(f);
                place(f);
            });
            assert_eq!(shown.level, Some(Level::Amber), "{n}");
            assert_eq!(shown.summary, NOT_KNOWN, "{n}");
            // Not where the device follows no phrase.
            let alone = with(&|f| {
                lacking(f);
                place(f);
                f.stands = "no_phrase".into();
            });
            assert!(!whats(&alone).contains(&"relay_without_latest"), "{n}");
        }
        // Not before five minutes.
        let soon = with(&|f| {
            lacking(f);
            f.devices.not_known_to_hold = lacking_for(&[300, 12]);
        });
        assert_eq!(soon.level, None);
        // Each that has lacked it for long enough is counted.
        let two = with(&|f| {
            lacking(f);
            f.devices.not_known_to_hold = lacking_for(&[400, 12, 900]);
        });
        assert_eq!(
            two.summary,
            "memory: some relays may not have the latest change to your devices"
        );
    }

    /// For seven days from the latest of when this device came to keep the
    /// change entry, when this version first started on it, and the
    /// relay's latest answer about the entry, and then not (decision
    /// 2026-10-19, rule 11): after that it is in `cordelia devices` only. A
    /// node that does not say since when is not cut short: the amber errs
    /// toward being said.
    #[test]
    fn for_seven_days_and_then_not() {
        let week = 7 * 24 * 60 * 60;
        let since = |secs: Option<u64>| {
            with(&|f| {
                lacking(f);
                f.devices.known_since_secs = secs;
            })
        };
        assert_eq!(since(Some(week)).summary, NOT_KNOWN);
        assert_eq!(since(Some(week + 1)).level, None);
        assert_eq!(since(Some(90 * 24 * 60 * 60)).level, None);
        assert_eq!(since(None).summary, NOT_KNOWN);
        // A relay that answers that it lacks the entry long after it came
        // to be kept is said for seven days from that answer.
        let said = |secs: Option<u64>| {
            with(&|f| {
                lacking(f);
                f.devices.known_since_secs = Some(30 * 24 * 60 * 60);
                f.devices.not_known_to_hold[0].said_secs = secs;
            })
        };
        assert_eq!(said(Some(60)).summary, NOT_KNOWN);
        assert_eq!(said(Some(week)).summary, NOT_KNOWN);
        assert_eq!(said(Some(week + 1)).level, None);
        assert_eq!(said(None).level, None);
        // Once it is no longer said, what came after it is.
        let after = with(&|f| {
            lacking(f);
            f.devices.known_since_secs = Some(week + 1);
            f.devices.no_room_secs = vec![30];
        });
        assert_eq!(after.summary, "memory: a relay has no room");
    }

    /// Its place (decision 2026-10-19, rule 11): after names carried, not
    /// yet sent, and so after every other amber of a person's devices, and
    /// before the amber of folders after it. A device added since, or one
    /// that left, is not hidden by it; "a relay has no room" is, and the
    /// tooltip says both.
    #[test]
    fn its_place_is_after_names_carried() {
        let all = with(&|f| {
            for (edit, _, _) in &AMBER[2..] {
                edit(f);
            }
        });
        let whats = whats(&all);
        let at = |what: &str| whats.iter().position(|w| *w == what).unwrap();
        assert_eq!(at("relay_without_latest"), at("carried") + 1, "{whats:?}");
        assert!(
            at("relay_without_latest") < at("relay_no_room"),
            "{whats:?}"
        );
        assert!(at("relay_without_latest") < at("names"), "{whats:?}");
        for (edit, what, says) in &AMBER[2..6] {
            let shown = with(&|f| {
                lacking(f);
                edit(f);
            });
            assert_eq!(shown.summary, *says, "{what}");
        }
        let no_room = with(&|f| {
            lacking(f);
            f.devices.no_room_secs = vec![30];
        });
        assert_eq!(no_room.summary, NOT_KNOWN);
        let details: Vec<String> = no_room.holds.iter().map(Holds::detail).collect();
        assert_eq!(
            details,
            [
                "To know: a relay may not have the latest change to your devices",
                "To know: a relay has no room",
            ]
        );
    }

    /// A relay that holds the change and is out of reach is amber only
    /// while another relay is reached, only with sync on, a folder mapped
    /// and a report, as "no relay" is, and last among the amber (decision
    /// 2026-10-19, rule 11). Where no relay is reached, it is not said.
    #[test]
    fn a_relay_out_of_reach_is_amber_last_only_with_folders_and_only_with_one_reached() {
        let out = |f: &mut Facts| {
            f.devices.out_of_reach_secs = vec![61];
            f.devices.one_reached = true;
        };
        let shown = with(&out);
        assert_eq!(shown.level, Some(Level::Amber));
        assert_eq!(shown.summary, "memory: a relay out of reach for 2 minutes");
        // Its minutes are rounded up: never none.
        for (secs, says) in [(0, "1 minute"), (60, "1 minute"), (420, "7 minutes")] {
            let shown = with(&|f| {
                out(f);
                f.devices.out_of_reach_secs = vec![secs];
            });
            let line = format!("memory: a relay out of reach for {says}");
            assert_eq!(shown.summary, line, "{secs}");
        }
        let two = with(&|f| {
            out(f);
            f.devices.out_of_reach_secs = vec![61, 4000];
        });
        assert_eq!(two.summary, "memory: 2 relays out of reach");
        let places: [Edit; 4] = [
            &|f| f.devices.one_reached = false,
            &|f| f.sync_enabled = false,
            &|f| {
                f.mapped = 0;
                f.folders = 0;
            },
            &|f| f.report_age_secs = None,
        ];
        for (n, place) in places.iter().enumerate() {
            let shown = with(&|f| {
                out(f);
                place(f);
            });
            assert!(!whats(&shown).contains(&"relay_out_of_reach"), "{n}");
        }
        // With no relay reached, "no relay" is said, and this is not.
        let none = with(&|f| {
            out(f);
            f.devices.one_reached = false;
            f.peers_hot = 0;
            f.no_relay_secs = Some(400);
        });
        assert_eq!(whats(&none), ["no_relay"]);
        // Last: after every other amber, which it hides nothing of.
        for (edit, what, says) in &AMBER[..10] {
            let shown = with(&|f| {
                out(f);
                edit(f);
            });
            assert_eq!(shown.summary, *says, "{what}");
            assert_eq!(whats(&shown).last(), Some(&"relay_out_of_reach"), "{what}");
        }
    }

    /// **The line says that a relay is out of reach where every relay it
    /// counts is** (decision 2026-10-24, rule 7): two relays out of reach
    /// and lacking the change; one of each, by the count and how many are
    /// out of reach; one alone. The count, its place and its five minutes
    /// do not change, and a relay that holds the change and is out of
    /// reach still gives "a relay out of reach for <m> minutes", last.
    #[test]
    fn the_line_says_out_of_reach_where_every_relay_it_counts_is() {
        let out_of = |out: &[bool]| -> Vec<NotKnown> {
            out.iter()
                .map(|out| NotKnown {
                    lacking_secs: 400,
                    said_secs: None,
                    out_of_reach: *out,
                })
                .collect()
        };
        let with_relays = |out: &[bool]| {
            with(&|f| {
                lacking(f);
                f.devices.not_known_to_hold = out_of(out);
            })
        };
        assert_eq!(
            with_relays(&[true, true]).summary,
            "memory: some relays are out of reach and may not have the latest change to your \
             devices"
        );
        assert_eq!(
            with_relays(&[true, false]).summary,
            "memory: some relays may not have the latest change to your devices, and one of them \
             is out of reach"
        );
        assert_eq!(
            with_relays(&[true]).summary,
            "memory: a relay is out of reach and may not have the latest change to your devices"
        );
        assert_eq!(with_relays(&[false]).summary, NOT_KNOWN);
        assert_eq!(
            with_relays(&[false, false]).summary,
            "memory: some relays may not have the latest change to your devices"
        );
        // Not before five minutes, out of reach or not.
        let soon = with(&|f| {
            lacking(f);
            f.devices.not_known_to_hold = out_of(&[true]);
            f.devices.not_known_to_hold[0].lacking_secs = 300;
        });
        assert_eq!(soon.level, None);
        // Its place is as before, and the warning of a relay that holds the
        // change and is out of reach is still last.
        let both = with(&|f| {
            lacking(f);
            f.devices.not_known_to_hold = out_of(&[true]);
            f.devices.out_of_reach_secs = vec![61];
            f.devices.one_reached = true;
        });
        assert_eq!(
            both.summary,
            "memory: a relay is out of reach and may not have the latest change to your devices"
        );
        assert_eq!(whats(&both), ["relay_without_latest", "relay_out_of_reach"]);
        assert_eq!(
            both.holds.last().unwrap().says,
            "memory: a relay out of reach for 2 minutes"
        );
    }

    /// The two records of 2026-10-19 place their amber lines together: the
    /// personal channel past the line first among every amber line (names
    /// at the limit, §2, rule 3); a relay not known to hold the latest
    /// change right after names carried, not yet sent; and a relay out of
    /// reach last (a relay out of reach, rule 11). With everything amber at
    /// once, each is where its record puts it, and the line says the first.
    #[test]
    fn the_lines_of_both_records_keep_their_places_together() {
        let past = channel_of(12 * 1024 * 1024, 0, WORD);
        let all = with(&|f| {
            f.channel = Some(past.clone());
            for (edit, _, _) in AMBER {
                edit(f);
            }
        });
        let order = whats(&all);
        let at = |what: &str| order.iter().position(|w| *w == what).unwrap();
        assert_eq!(order[0], "channel_nearly_full", "{order:?}");
        assert_eq!(all.summary, NAMES_FILL);
        assert_eq!(at("relay_without_latest"), at("carried") + 1, "{order:?}");
        assert_eq!(order.last(), Some(&"relay_out_of_reach"), "{order:?}");
        // Each of the relay's lines alone beside the warning: after it.
        for edit in [
            (&|f: &mut Facts| f.devices.not_known_to_hold = lacking_for(&[400])) as Edit,
            &|f| {
                f.devices.out_of_reach_secs = vec![420];
                f.devices.one_reached = true;
            },
        ] {
            let shown = with(&|f| {
                f.channel = Some(past.clone());
                edit(f);
            });
            assert_eq!(whats(&shown)[0], "channel_nearly_full");
            assert_eq!(shown.summary, NAMES_FILL);
        }
    }

    // ── A shared channel (decision 2026-10-10 §9) ────────────────────

    /// A moment `secs` seconds before `now`, in RFC 3339.
    fn before(now: i64, secs: i64) -> String {
        chrono::DateTime::from_timestamp(now - secs, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    /// The `shared` object of a status with every field at its worst, as a
    /// shared channel can make it, and `holds` as its removed devices.
    fn shared_at_its_worst(holds: serde_json::Value) -> serde_json::Value {
        let n = 1_000;
        let channel = serde_json::json!({
            "id": "00", "name": "review-with-alice", "words": "able bake cold dune",
            "keys": n, "labelled": n, "new_since_written": n, "not_moved_yet": n,
            "unread_by_an_agent": n, "unread_by_a_person": n, "held_back": n,
            "beyond_shown": n, "subscribed": ["github.com/owner/repo"], "waiting": n,
            "not_stored": n, "refused_for_room": n,
            "refused_keys": [{ "key": "cordelia_pk1x", "words": "a b c d e f",
                               "first_refused": "2026-10-01T00:00:00Z", "bytes": n }],
            "rows_let_go": n, "refused_at_a_relay": n, "reached": false,
            "relays": [{ "relay": "relay.example.org:9474", "words": "a b c d",
                         "connected": false, "not_reached": "not_own" }],
            "offers": [{ "fault": "held" }], "also_a_name": true,
        });
        // Each line a repository's view says that is not amber, as rule 6
        // has them (decision 2026-11-06 (joining)), and one whose `amber`
        // is not the value true.
        let plain = [
            "behind",
            "late",
            "not_a_list",
            "followed_elsewhere",
            "waiting",
            "not_listed",
            "no_channel",
            "made_anew",
            "not_own_relay",
            "too_many_channels",
            "name_taken",
            "dropped",
            "moved",
            "handing",
            "not_clean",
            "not_reached",
            "channel_full",
            "not_held",
            "twin_listed",
        ];
        let mut lines: Vec<serde_json::Value> = plain
            .iter()
            .map(|word| serde_json::json!({ "word": word, "says": "x", "amber": false }))
            .collect();
        lines.push(serde_json::json!({ "word": "joined", "says": "x", "amber": "true" }));
        let repository = serde_json::json!({
            "identity": "example.org/team/project", "name": "team/project", "held": true,
            "channel": "00", "words": "able bake cold dune",
            "read": { "at": "2026-10-01T00:00:00Z", "commit": "a", "from": "clone",
                      "fetched": null, "says": "x" },
            "members": [{ "label": "alice-laptop", "key": "cordelia_pk1x",
                          "words": "a b c d e f", "in": false }],
            "unread_by_an_agent": n, "unread_by_a_person": n, "lines": lines,
        });
        serde_json::json!({
            "channels": vec![channel; 16],
            "typed": [{ "key": "cordelia_pk1x", "channel": "x", "until": "", "became": "x" }],
            "removed_device_holds": holds,
            "acts_of_removed_devices": [{ "device": "laptop", "act": "label",
                                          "item": "x", "undo": "cordelia label x --none" }],
            "passed_over": [{ "key": "cordelia_pk1x", "acts": n }],
            "past_a_bound": ["x"],
            "repositories": vec![repository; 16],
        })
    }

    /// Nothing shared holds a level or changes the line but two facts
    /// (decision 2026-10-10 §9, property 16, §13 item 16, as the person
    /// ruled on 6 November for the ambers of decision 2026-11-06
    /// (joining), rule 6): with every field of the `shared` object at its
    /// worst, no removed device, and no repository's line amber, the facts,
    /// `holds`, `derive`, the line and the bar are as without it, for a
    /// device that is synced, one that waits, one with no relay, and one
    /// with sync off.
    #[test]
    fn nothing_shared_holds_a_level_or_changes_the_line() {
        let now = 2_000_000_000;
        let worst = shared_at_its_worst(serde_json::json!([]));
        for edit in [
            (&|_: &mut Facts| {}) as Edit,
            &|f| f.outbox_waiting = 3,
            &|f| {
                f.peers_hot = 0;
                f.no_relay_secs = Some(4_000);
            },
            &|f| f.sync_enabled = false,
        ] {
            let seen = |shared: Option<&serde_json::Value>| {
                let mut f = synced();
                edit(&mut f);
                if let Some(shared) = shared {
                    super::shared(&mut f.devices, shared, now);
                }
                let shown = shown(&f);
                let line = line(shown.state, shown.level, &shown.summary, false);
                let bar = bar(shown.state, shown.level, &shown.summary, &[]);
                (format!("{f:?}"), derive(&f), holds(&f), shown, line, bar)
            };
            assert_eq!(seen(Some(&worst)), seen(None));
            assert_eq!(seen(Some(&serde_json::Value::Null)), seen(None));
        }
    }

    /// Each amber line of a repository this device follows is a hold of its
    /// own, amber, with its words after `shared: ` (decision 2026-11-06
    /// (joining), rule 6, by the person's ruling of 6 November): last, after
    /// a removed device that holds a shared channel and agents held for
    /// their person, so that it hides nothing of the person's own; with sync
    /// off too. Only a line whose `amber` is true is one.
    #[test]
    fn a_repositorys_amber_lines_make_the_line_amber_and_come_last() {
        let now = 2_000_000_000;
        let joined = "bob-desktop joined team/project from the list at aaaa";
        let gate = "carol-laptop is on the list of team/project but was left out of it: delete \
                    its line in a pull request, or wait for that device to write in the channel";
        let with_lines = |holds: serde_json::Value| {
            let mut shared = shared_at_its_worst(holds);
            let lines = &mut shared["repositories"][3]["lines"];
            let lines = lines.as_array_mut().unwrap();
            lines.push(serde_json::json!({ "word": "joined", "says": joined, "amber": true }));
            lines.push(serde_json::json!({ "word": "left_out", "says": gate, "amber": true }));
            shared
        };
        let seen = |shared: &serde_json::Value, edit: Edit| {
            let mut f = synced();
            edit(&mut f);
            super::shared(&mut f.devices, shared, now);
            shown(&f)
        };
        let shown = seen(&with_lines(serde_json::json!([])), &|_| {});
        assert_eq!(shown.level, Some(Level::Amber));
        assert_eq!(whats(&shown), [REPOSITORY_HOLD, REPOSITORY_HOLD]);
        assert_eq!(shown.summary, format!("shared: {joined}"));
        assert_eq!(shown.holds[1].says, repository_says(gate));
        // With sync off, and with nothing mapped: still amber.
        for edit in [(&|f: &mut Facts| f.sync_enabled = false) as Edit, &|f| {
            f.mapped = 0;
            f.folders = 0;
        }] {
            let shown = seen(&with_lines(serde_json::json!([])), edit);
            assert_eq!(whats(&shown), [REPOSITORY_HOLD, REPOSITORY_HOLD]);
        }
        // Last: after the hold of a removed device and agents held.
        let holding = serde_json::json!([
            { "device": "tablet", "channels": ["review"], "since": before(now, 60) },
        ]);
        let all = seen(&with_lines(holding), &|f| f.held_pairs = 1);
        assert_eq!(
            whats(&all),
            [SHARED_HOLD, MESSAGES_HOLD, REPOSITORY_HOLD, REPOSITORY_HOLD]
        );
        // Below red: a red line still says what is red.
        let red = seen(&with_lines(serde_json::json!([])), &|f| {
            f.errors = vec!["x".into()];
        });
        assert_eq!(red.level, Some(Level::Red));
    }

    /// A removed device that holds a shared channel makes the line amber for
    /// seven days (decision 2026-10-10 §9, property 16, §13 item 16): of six
    /// days it is amber, of eight it is not; a channel made anew and moved
    /// from, or dropped, is listed by the node no more, and ends it; an act
    /// of the removed key still in force, with no channel held, is not amber.
    /// It holds with sync off and with nothing mapped, as every fact of the
    /// person's devices does, and not on a device that follows no phrase.
    /// Each channel is a line of its own, which names the channel and each
    /// removed device by the name you gave it, or by its words where you
    /// gave none, and gives the one command (decision 2026-11-11 (plain
    /// words), rules 2 and 3).
    #[test]
    fn a_removed_device_that_holds_a_shared_channel_makes_the_line_amber_for_seven_days() {
        let now = 2_000_000_000;
        let day = 24 * 60 * 60;
        let tablet = serde_json::json!({ "key": "k1", "label": "tablet", "words": "a b c d" });
        let phone = serde_json::json!({ "key": "k2", "label": "phone", "words": "e f g h" });
        let holding = |days: i64, channels: &[&str]| {
            shared_at_its_worst(serde_json::json!([
                {
                    "device": "\"tablet\" (a b c d)", "devices": [tablet],
                    "channels": channels, "since": before(now, days * day),
                },
            ]))
        };
        let with_shared = |shared: &serde_json::Value, edit: Edit| {
            let mut f = synced();
            edit(&mut f);
            super::shared(&mut f.devices, shared, now);
            shown(&f)
        };
        // It says that the device was removed, by its words and name: a
        // device of yours may have its name (decision 2026-11-11 (plain
        // words), rule 4).
        let review = "shared: \"review\": (a b c d) \"tablet\", which you removed, can still read \
                      new messages there, and this device sends nothing there until you reset \
                      it. To stop that: cordelia shared reset review";
        let six = with_shared(&holding(6, &["review", "design"]), &|_| {});
        assert_eq!(six.level, Some(Level::Amber));
        assert_eq!(whats(&six), [SHARED_HOLD, SHARED_HOLD]);
        assert_eq!(six.holds[0].says, review);
        // The line where it is the summary says it short: the first
        // device and how many more, and the command.
        let short = "shared: \"review\": (a b c d) \"tablet\", which you removed, can still read \
                     new messages there. To stop that: cordelia shared reset review";
        assert_eq!(six.summary, short);
        assert!(six.summary.chars().count() < 160, "{}", six.summary);
        assert_eq!(six.holds[1].says, review.replace("review", "design"));
        let one = with_shared(&holding(6, &["review"]), &|_| {});
        assert_eq!(one.summary, short);
        assert_eq!(one.holds[0].says, review);
        assert_eq!(whats(&one), [SHARED_HOLD]);
        // A channel named by two removals is one line, which names each
        // device.
        let twice = with_shared(
            &shared_at_its_worst(serde_json::json!([
                { "devices": [tablet], "channels": ["review"], "since": before(now, 2 * day) },
                { "devices": [phone], "channels": ["review"], "since": before(now, day) },
            ])),
            &|_| {},
        );
        assert_eq!(whats(&twice), [SHARED_HOLD]);
        assert_eq!(
            twice.summary,
            short.replace("\"tablet\"", "\"tablet\" and 1 more")
        );
        assert_eq!(
            twice.holds[0].says,
            review.replace(
                "(a b c d) \"tablet\"",
                "(a b c d) \"tablet\" and (e f g h) \"phone\""
            )
        );
        // A device with no name from you is named by its words; a channel
        // first held after the removal names none, and this device writes
        // nothing there until it is reset; a name the shell would read is
        // quoted in the command.
        let unnamed = serde_json::json!({ "key": "k3", "label": "", "words": "i j k l" });
        let others = with_shared(
            &shared_at_its_worst(serde_json::json!([
                { "devices": [unnamed], "channels": ["design review"], "since": before(now, day) },
                { "devices": [], "channels": ["later"], "since": before(now, day / 2) },
            ])),
            &|_| {},
        );
        assert_eq!(
            others
                .holds
                .iter()
                .map(|holds| holds.says.as_str())
                .collect::<Vec<_>>(),
            [
                "shared: \"design review\": the device (i j k l), which you removed, can still \
                 read new messages there, and this device sends nothing there until you reset \
                 it. To stop that: cordelia shared reset 'design review'",
                "shared: \"later\" has not been reset on this device since you removed a device, \
                 so this device sends nothing there until you reset it: cordelia shared reset \
                 later",
            ]
        );
        // Of eight days, it is in `cordelia devices` only.
        let eight = with_shared(&holding(8, &["review"]), &|_| {});
        assert_eq!((eight.level, eight.holds.len()), (None, 0));
        assert_eq!(eight.summary, "memory synced");
        // The hold keeps its seven days by itself too, whatever fills the
        // facts.
        for (days, amber) in [(6, true), (8, false)] {
            let shown = with(&|f| {
                f.devices.removed_holds_shared = vec![HeldShared {
                    channel: "review".into(),
                    devices: vec![device_named("tablet", "a b c d")],
                }];
                f.devices.removed_holds_shared_secs = Some(days * day as u64);
            });
            assert_eq!(whats(&shown).contains(&SHARED_HOLD), amber, "{days} days");
        }
        // Made anew and moved from, or dropped: the node lists it no more.
        let done = with_shared(&holding(6, &[]), &|_| {});
        assert_eq!((done.level, done.holds.len()), (None, 0));
        let none = with_shared(&shared_at_its_worst(serde_json::json!([])), &|_| {});
        assert_eq!((none.level, none.holds.len()), (None, 0));
        // Of two removals, the channels of the one within the seven days.
        let two = shared_at_its_worst(serde_json::json!([
            { "devices": [phone], "channels": ["old"], "since": before(now, 9 * day) },
            { "devices": [tablet], "channels": ["review"], "since": before(now, day) },
        ]));
        let two = with_shared(&two, &|_| {});
        assert_eq!(two.summary, short);
        assert_eq!(whats(&two), [SHARED_HOLD]);
        // With sync off, and with nothing mapped: still amber.
        for edit in [(&|f: &mut Facts| f.sync_enabled = false) as Edit, &|f| {
            f.mapped = 0;
            f.folders = 0;
        }] {
            let shown = with_shared(&holding(6, &["review"]), edit);
            assert_eq!(whats(&shown), [SHARED_HOLD]);
        }
        // A device that follows no phrase knows of no removal.
        let no_phrase = with_shared(&holding(6, &["review"]), &|f| {
            f.stands = "no_phrase".into();
            f.sync_enabled = false;
        });
        assert!(!whats(&no_phrase).contains(&SHARED_HOLD));
        // Its place: after a removal not yet applied, before what follows.
        let both = with_shared(&holding(6, &["review"]), &|f| {
            f.devices.removal_not_applied_secs = Some(3_600);
            f.devices.added_not_cleared = 1;
        });
        assert_eq!(whats(&both), ["removal_not_applied", SHARED_HOLD, "added"]);
        // The plain status says it on a line of its own, without its word.
        assert_eq!(
            without_shared(&six.holds[0].says),
            review.strip_prefix("shared: ").unwrap()
        );
        assert!(is_shared(&six.holds[0]));
    }
}
