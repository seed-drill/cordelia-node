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
//!   their own, with no level. A level is for a personal node that runs,
//!   with sync on.

/// A sync report older than this means the adapter has stopped cycling
/// (it runs every `cordelia_sync::claude::CYCLE_SECS`).
pub const STALE_REPORT_SECS: i64 = 60;

/// How many times in a row relays must refuse an item before status asks
/// for attention. A relay that is briefly unable to store (it is being
/// restarted, its disk is being cleared) refuses once or twice, and the
/// item is delivered within seconds.
pub const REFUSALS_BEFORE_ATTENTION: u64 = 3;

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
    /// Of those, the ones relays keep refusing ([`REFUSALS_BEFORE_ATTENTION`]
    /// times in a row or more). They are still offered, now and then.
    pub outbox_refused: u64,
    /// `cordelia sync claude` is on.
    pub sync_enabled: bool,
    /// Age of the last sync cycle's report; `None` before the first cycle.
    pub report_age_secs: Option<i64>,
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
    /// `removed`, `not_listed`, `not_opened`). Empty where the node did
    /// not say.
    pub stands: String,
    /// Folders the last cycle synced or is waiting to sync.
    pub folders: usize,
    /// Whether this device took this version with what an earlier one
    /// held (decision 2026-10-04 §10.1): with no phrase it is then "not
    /// added yet", and otherwise it is a new install.
    pub moved_on: bool,
    /// What the node is held up by, as it says it, where it is (decision
    /// 2026-10-04 §10.1): `first_start` while its first start on this
    /// version is not done, or `later_database` where its database is
    /// from a later version. It runs no cycle and no pass meanwhile.
    pub held: Option<String>,
    /// The notice of what stopped syncing, while the node stores one
    /// (decision 2026-10-04 §10.1).
    pub notice: Option<Stopped>,
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
    /// How many devices were added since the last change and are not
    /// cleared.
    pub added_not_cleared: usize,
    /// How many devices have said that they left.
    pub said_left: usize,
    /// For each relay that does not hold the latest change and is
    /// connected: for how long it has been connected, in seconds, by the
    /// node's own clock.
    pub without_latest_secs: Vec<u64>,
    /// For each relay that has refused something for room, or for the
    /// address's allowance: how long ago it last did, in seconds.
    pub no_room_secs: Vec<u64>,
    /// How many names no device lists yet in the generation applied.
    pub names_not_listed: usize,
    /// For how long this device has applied the change, in seconds,
    /// where it knows.
    pub applied_secs: Option<u64>,
    /// How many names this device has still to send.
    pub names_to_go: usize,
    /// For how long the first of them has waited, in seconds.
    pub to_go_secs: Option<u64>,
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

impl Holds {
    /// What a tooltip and the plain status say of it, beside the line:
    /// what the line would say, without its first word.
    pub fn detail(&self) -> String {
        let says = self.says.as_str();
        let said = says
            .strip_prefix("memory: ")
            .or_else(|| says.strip_prefix("memory "))
            .unwrap_or(says);
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
    /// The first thing of that level; with no level, what the state says.
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

/// A relay's refusal for room is taken to stand for this long.
const NO_ROOM_STANDS_SECS: u64 = cordelia_core::protocol::NO_ROOM_STANDS_SECS;

/// Whether the sync cycle has stalled: its last report is older than a
/// cycle takes, **and the node has run for longer than that.** A cycle
/// counts as stalled from the node's start, and not from the time of a
/// report that an earlier run stored: otherwise every start after a stop
/// of more than a minute would be stalled for some seconds.
fn stalled(f: &Facts) -> bool {
    let old = f.report_age_secs.is_some_and(|age| age > STALE_REPORT_SECS);
    old && f.uptime_secs.is_none_or(|up| up > STALE_REPORT_SECS as u64)
}

/// Why a device that has stopped syncs nothing, as the line says it:
/// `stands` is where the node says it stands. `None` where it has not
/// stopped.
fn stopped_says(stands: &str) -> Option<&'static str> {
    Some(match stands {
        "fork" => "memory not syncing: two changes made apart",
        "removed" => "memory not syncing: this device was removed",
        "not_listed" => "memory not syncing: not in the last change",
        "not_opened" => "memory not syncing: a change could not be opened",
        _ => return None,
    })
}

/// Why a node is held up, as the line says it: `by` is what the node
/// says it is held up by.
fn held_says(by: &str) -> &'static str {
    match by {
        "first_start" => "memory not syncing: the first start on this version is not done",
        "later_database" => "memory not syncing: the database is from a later version",
        _ => "memory not syncing: the node is held up",
    }
}

/// What a device that follows no phrase says in the line: that it is not
/// added yet, where it took this version with what an earlier one held,
/// and that it has no recovery phrase yet, where it is a new install.
fn no_phrase_says(moved_on: bool) -> &'static str {
    match moved_on {
        true => "memory: not added yet",
        false => "memory stays here: no recovery phrase yet",
    }
}

/// Everything that holds, of the two lists, in their order: red first
/// (decision 2026-10-04 §10.1). None before any level: on a device that
/// is not set up, beside a node that is stopped or was not asked, on a
/// relay or a bootnode, and with sync off.
///
/// **Red,** in this order:
/// 1. this device has stopped: it was removed, or is in no list, or is
///    in a fork, or was answered with a change that it could not open or
///    apply;
/// 2. the node is held up: its first start on this version has not
///    succeeded, or its database is from a later version;
/// 3. it follows no phrase, where something is mapped: nothing it holds
///    syncs until a person acts;
/// 4. sync errors, a file that could not be synced among them;
/// 5. a cycle that has stalled;
/// 6. folders that stopped syncing (the notice), where there is no
///    report yet or no folder is mapped;
/// 7. conflict files;
/// 8. files too large;
/// 9. folders that stopped syncing.
///
/// **Amber,** in this order, and only with something mapped and a
/// report: with neither, nothing would move anyway.
/// 1. no relay connected for more than five minutes, by the node's own
///    clock;
/// 2. entries that relays keep refusing;
/// 3. a running node that is not the version this command is;
/// 4. a removal that some device has not applied, for seven days from
///    when this device applied it;
/// 5. a device added since the last change that nobody has cleared;
/// 6. a device that has said it left;
/// 7. a relay that has been connected for more than five minutes and
///    does not hold the latest change;
/// 8. a relay that refuses a new channel for room, or for the address's
///    allowance;
/// 9. names that are not yet in the new generation, or not yet sent,
///    for more than five minutes.
pub fn holds(f: &Facts) -> Vec<Holds> {
    let mut out: Vec<Holds> = Vec::new();
    let personal_and_running = f.initialised && !f.not_asked && f.running && f.role == "personal";
    if !personal_and_running || !f.sync_enabled {
        return out;
    }
    let mut red = |what: &'static str, says: String| {
        out.push(Holds {
            level: Level::Red,
            what,
            says,
        })
    };
    let count = |n: usize, one: &str| format!("{n} {}", plural(n as u64, one));

    if let Some(says) = stopped_says(&f.stands) {
        red("stopped", says.into());
    } else if f.devices.not_applied {
        red(
            "stopped",
            "memory not syncing: a change could not be applied".into(),
        );
    }
    if let Some(by) = f.held.as_deref() {
        red("held", held_says(by).into());
    }
    if f.stands == "no_phrase" && f.mapped > 0 {
        red("no_phrase", no_phrase_says(f.moved_on).into());
    }
    if !f.errors.is_empty() {
        red("errors", "memory sync error".into());
    }
    if stalled(f) {
        red("stalled", "memory sync stalled".into());
    }
    let report = f.report_age_secs.is_some();
    let notice = f.notice.as_ref().filter(|notice| notice.counts());
    // Where "starting" or "nothing mapped" would be said, the notice is.
    let notice_first = !report || f.mapped == 0;
    if let Some(notice) = notice.filter(|_| notice_first) {
        red("stopped_syncing", notice.says());
    }
    if !f.conflicts.is_empty() {
        let conflicts = count(f.conflicts.len(), "conflict");
        red("conflicts", format!("memory: {conflicts}"));
    }
    if !f.too_large.is_empty() {
        let files = count(f.too_large.len(), "file");
        red("too_large", format!("memory: {files} too large"));
    }
    if let Some(notice) = notice.filter(|_| !notice_first) {
        red("stopped_syncing", notice.says());
    }

    // With nothing mapped, or with no report yet, there is no amber.
    if f.mapped == 0 || !report {
        return out;
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
    if let Some(secs) = f.no_relay_secs.filter(long) {
        amber(
            "no_relay",
            format!("memory: no relay for {} minutes", secs / 60),
        );
    }
    if f.outbox_refused > 0 {
        let n = f.outbox_refused;
        amber("refused", format!("memory: {n} not taken by a relay"));
    }
    if f.other_version {
        amber(
            "other_version",
            "memory: the node is another version (restart it)".into(),
        );
    }
    if d.removal_not_applied_secs
        .is_some_and(|secs| secs <= REMOVAL_SHOWN_SECS)
    {
        amber(
            "removal_not_applied",
            "memory: a removal not yet applied by every device".into(),
        );
    }
    if d.added_not_cleared > 0 {
        let devices = count(d.added_not_cleared, "device");
        amber("added", format!("memory: {devices} added, not yet cleared"));
    }
    match d.said_left {
        0 => {}
        1 => amber("left", "memory: a device has left".into()),
        n => amber("left", format!("memory: {n} devices have left")),
    }
    match d
        .without_latest_secs
        .iter()
        .filter(|secs| long(secs))
        .count()
    {
        0 => {}
        1 => amber(
            "relay_without_latest",
            "memory: a relay does not hold the latest change".into(),
        ),
        n => amber(
            "relay_without_latest",
            format!("memory: {n} relays do not hold the latest change"),
        ),
    }
    if d.no_room_secs.iter().any(|ago| *ago <= NO_ROOM_STANDS_SECS) {
        amber("relay_no_room", "memory: a relay has no room".into());
    }
    let not_listed = d.names_not_listed > 0 && d.applied_secs.as_ref().is_some_and(long);
    let not_sent = d.names_to_go > 0 && d.to_go_secs.as_ref().is_some_and(long);
    if not_listed {
        let names = count(d.names_not_listed, "name");
        amber(
            "names",
            format!("memory: {names} not yet listed by a device"),
        );
    } else if not_sent {
        let names = count(d.names_to_go, "name");
        amber("names", format!("memory: {names} not yet sent"));
    }
    out
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
    Shown {
        state,
        level: gravest.map(|holds| holds.level),
        summary: gravest.map_or(of_the_state, |holds| holds.says.clone()),
        holds,
    }
}

/// The notice that a device whose stored scope was on is given: the
/// folders that stopped syncing when only mapped folders came to sync.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stopped {
    /// How many folders it names that no mapping syncs now.
    pub folders: usize,
    /// Whether one of its records names no folder: what stopped then is
    /// not known.
    pub not_known: bool,
}

impl Stopped {
    /// Whether it still asks for the person: while it names a folder
    /// that is not mapped now, or a record of it names none. A notice
    /// whose folders are all mapped does not.
    pub fn counts(&self) -> bool {
        self.folders > 0 || self.not_known
    }

    /// In a few words: how many folders stopped, counting those it names
    /// that are not mapped now; or that folders did, where it names none
    /// that is not.
    pub fn says(&self) -> String {
        match self.folders as u64 {
            0 => "memory: folders stopped syncing".into(),
            n => format!("memory: {n} {} stopped syncing", plural(n, "folder")),
        }
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
    if !f.sync_enabled {
        return (Off, "memory sync off".into());
    }
    // Only a device that has applied a statement publishes anything
    // (decision 2026-10-04 §5.2). One that follows no phrase yet syncs
    // nothing, and one that has stopped needs the person: neither is said
    // to be synced, whatever its last cycle listed.
    //
    // **With no phrase the state is `attention`** (decision 2026-10-04
    // §10.1), so that a panel which draws from the state alone does not
    // show the device as synced, or as resting: nothing it holds syncs
    // until a person acts. A device that is not to be added turns sync
    // off. It is "not added yet" where it took this version with what an
    // earlier one held, and has "no recovery phrase yet" where it is a
    // new install.
    if f.stands == "no_phrase" {
        return (Attention, no_phrase_says(f.moved_on).into());
    }
    if let Some(says) = stopped_says(&f.stands) {
        return (Attention, says.into());
    }
    if !f.errors.is_empty() {
        return (Attention, "memory sync error".into());
    }
    // Folders that stopped syncing need the person (decision 2026-10-04
    // §10.1): the notice is `attention`, so that a panel which draws from
    // the state alone shows it. It is said in the place of "starting" and
    // of "nothing mapped", and after a conflict and a file too large,
    // which it never hides.
    let stopped = f.notice.as_ref().filter(|notice| notice.counts());
    match f.report_age_secs {
        None => {
            return match stopped {
                Some(notice) => (Attention, notice.says()),
                None => (Syncing, "memory sync starting".into()),
            };
        }
        Some(_) if stalled(f) => {
            return (Attention, "memory sync stalled".into());
        }
        Some(_) => {}
    }
    if f.folders == 0 {
        return match stopped {
            Some(notice) => (Attention, notice.says()),
            None => (Off, "memory: nothing mapped".into()),
        };
    }
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
    if let Some(notice) = stopped {
        return (Attention, notice.says());
    }
    if f.peers_hot == 0 {
        return match f.outbox_waiting {
            0 => (Offline, "memory offline".into()),
            n => (Offline, format!("memory offline, {n} waiting")),
        };
    }
    if f.outbox_refused > 0 {
        let n = f.outbox_refused;
        return (Attention, format!("memory: {n} not taken by a relay"));
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
        (Some(Level::Red), _) => ("▲", "31"),    // red
        (Some(Level::Amber), _) => ("◆", "33"),  // yellow, and its own mark
        (None, State::Synced) => ("●", "32"),    // green
        (None, State::Syncing) => ("◐", "33"),   // yellow
        (None, State::Attention) => ("▲", "31"), // red
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
/// which Omarchy highlights, is added with red alone.** The icons are Nerd
/// Font glyphs: a level has its own, and with none the state has.
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
    const RED: [(Edit, &str, &str); 12] = [
        (
            &|f| f.stands = "removed".into(),
            "stopped",
            "memory not syncing: this device was removed",
        ),
        (
            &|f| f.stands = "not_listed".into(),
            "stopped",
            "memory not syncing: not in the last change",
        ),
        (
            &|f| f.stands = "fork".into(),
            "stopped",
            "memory not syncing: two changes made apart",
        ),
        (
            &|f| f.stands = "not_opened".into(),
            "stopped",
            "memory not syncing: a change could not be opened",
        ),
        (
            &|f| f.devices.not_applied = true,
            "stopped",
            "memory not syncing: a change could not be applied",
        ),
        (
            &|f| f.held = Some("first_start".into()),
            "held",
            "memory not syncing: the first start on this version is not done",
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
        (
            &|f| {
                f.notice = Some(Stopped {
                    folders: 3,
                    not_known: false,
                })
            },
            "stopped_syncing",
            "memory: 3 folders stopped syncing",
        ),
    ];

    /// Each thing of the amber list, alone, in the list's order.
    const AMBER: [(Edit, &str, &str); 10] = [
        (
            &|f| {
                f.peers_hot = 0;
                f.no_relay_secs = Some(360);
            },
            "no_relay",
            "memory: no relay for 6 minutes",
        ),
        (
            &|f| f.outbox_refused = 2,
            "refused",
            "memory: 2 not taken by a relay",
        ),
        (
            &|f| f.other_version = true,
            "other_version",
            "memory: the node is another version (restart it)",
        ),
        (
            &|f| f.devices.removal_not_applied_secs = Some(3_600),
            "removal_not_applied",
            "memory: a removal not yet applied by every device",
        ),
        (
            &|f| f.devices.added_not_cleared = 1,
            "added",
            "memory: 1 device added, not yet cleared",
        ),
        (
            &|f| f.devices.said_left = 1,
            "left",
            "memory: a device has left",
        ),
        (
            &|f| f.devices.without_latest_secs = vec![10, 400],
            "relay_without_latest",
            "memory: a relay does not hold the latest change",
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
            "memory: 2 names not yet listed by a device",
        ),
        (
            &|f| {
                f.devices.names_to_go = 1;
                f.devices.to_go_secs = Some(400);
            },
            "names",
            "memory: 1 name not yet sent",
        ),
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
        // A device that took this version with what an earlier one held
        // is "not added yet".
        let not_added = with(&|f| {
            f.stands = "no_phrase".into();
            f.moved_on = true;
        });
        assert_eq!(not_added.level, Some(Level::Red));
        assert_eq!(not_added.summary, "memory: not added yet");
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
            f.devices.without_latest_secs = vec![400, 500];
        });
        let says: Vec<&str> = several.holds.iter().map(|h| h.says.as_str()).collect();
        assert_eq!(
            says,
            [
                "memory: 3 devices added, not yet cleared",
                "memory: 2 devices have left",
                "memory: 2 relays do not hold the latest change",
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
            "refused",
            "other_version",
            "removal_not_applied",
            "added",
            "left",
            "relay_without_latest",
            "relay_no_room",
            "names",
        ];
        let red = [
            "stopped",
            "held",
            "errors",
            "stalled",
            "conflicts",
            "too_large",
            "stopped_syncing",
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
        assert_eq!(whats(&no_phrase)[..7], red_with_no_phrase);
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
        // Names not yet listed are said before names not yet sent.
        assert_eq!(
            all_amber.holds.last().unwrap().says,
            "memory: 2 names not yet listed by a device"
        );
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
                    assert!(whats(&shown).contains(&amber_what), "{red_says}");
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
        // Offline for two minutes, with entries that relays keep
        // refusing: amber, and the line says refused, not offline.
        let offline = with(&|f| {
            f.peers_hot = 0;
            f.no_relay_secs = Some(120);
            f.outbox_refused = 1;
        });
        assert_eq!(offline.level, Some(Level::Amber));
        assert_eq!(offline.summary, "memory: 1 not taken by a relay");
        assert_eq!(offline.state, State::Offline);
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
    /// no level. So is a personal node with sync off: the line says off.
    #[test]
    fn what_is_not_a_personal_node_that_runs_with_sync_on_has_no_level() {
        let everything = |f: &mut Facts| {
            for (edit, _, _) in RED.iter().skip(5).chain(AMBER.iter()) {
                edit(f);
            }
        };
        let cases: [(Edit, State, &str); 6] = [
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
            (
                &|f| {
                    f.sync_enabled = false;
                    f.held = None;
                },
                State::Off,
                "memory sync off",
            ),
        ];
        for (edit, state, says) in cases {
            let shown = with(&|f| {
                everything(f);
                edit(f);
            });
            assert_eq!(shown.level, None, "{says}");
            assert!(shown.holds.is_empty(), "{says}");
            assert_eq!((shown.state, shown.summary.as_str()), (state, says));
        }
        // Sync off with a notice stored: no level, and the line says off.
        let off = with(&|f| {
            f.sync_enabled = false;
            f.notice = Some(Stopped {
                folders: 3,
                not_known: false,
            });
        });
        assert_eq!((off.level, off.state), (None, State::Off));
        assert_eq!(off.summary, "memory sync off");
        // A node that is held up with sync off: no level, and the state
        // and the line say that it is held up, as they did.
        let held = with(&|f| {
            f.sync_enabled = false;
            f.held = Some("first_start".into());
        });
        assert_eq!((held.level, held.state), (None, State::Attention));
        assert_eq!(
            held.summary,
            "memory not syncing: the first start on this version is not done"
        );
    }

    /// With nothing mapped, or with no report yet, there is no amber:
    /// nothing would move anyway (decision 2026-10-04 §10.1). Red is red
    /// all the same: the notice, errors and a stalled cycle.
    #[test]
    fn with_nothing_mapped_or_no_report_yet_there_is_no_amber() {
        let all_amber = |f: &mut Facts| {
            for (edit, _, _) in AMBER {
                edit(f);
            }
        };
        let nothing_mapped = with(&|f| {
            all_amber(f);
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
            all_amber(f);
            f.report_age_secs = None;
        });
        assert_eq!(no_report.level, None);
        assert_eq!(no_report.summary, "memory sync starting");

        // Red with nothing mapped: errors, a stalled cycle, the notice.
        for (edit, what) in [
            (
                (&|f: &mut Facts| f.errors = vec!["x".into()]) as &dyn Fn(&mut Facts),
                "errors",
            ),
            (
                &|f: &mut Facts| f.report_age_secs = Some(STALE_REPORT_SECS + 1),
                "stalled",
            ),
            (
                &|f: &mut Facts| {
                    f.notice = Some(Stopped::default()).map(|mut n| {
                        n.not_known = true;
                        n
                    })
                },
                "stopped_syncing",
            ),
        ] {
            let shown = with(&|f| {
                all_amber(f);
                f.mapped = 0;
                f.folders = 0;
                edit(f);
            });
            assert_eq!(shown.level, Some(Level::Red), "{what}");
            assert_eq!(whats(&shown), [what]);
        }
    }

    /// A device that follows no phrase is red where something is mapped
    /// (decision 2026-10-04 §10.1): nothing it holds syncs until a person
    /// acts. With nothing mapped that makes no level; its state is
    /// `attention` either way, so that a panel which draws from the state
    /// does not show it as synced.
    #[test]
    fn no_phrase_is_red_only_where_something_is_mapped() {
        let mapped = with(&|f| f.stands = "no_phrase".into());
        assert_eq!(
            (mapped.level, mapped.state),
            (Some(Level::Red), State::Attention)
        );
        let nothing = with(&|f| {
            f.stands = "no_phrase".into();
            f.mapped = 0;
            f.folders = 0;
        });
        assert_eq!((nothing.level, nothing.state), (None, State::Attention));
        assert_eq!(nothing.summary, "memory stays here: no recovery phrase yet");
        // With nothing mapped and a notice: red, and the line says that
        // folders stopped syncing.
        let notice = with(&|f| {
            f.stands = "no_phrase".into();
            f.moved_on = true;
            f.mapped = 0;
            f.folders = 0;
            f.report_age_secs = None;
            f.notice = Some(Stopped {
                folders: 2,
                not_known: false,
            });
        });
        assert_eq!(notice.level, Some(Level::Red));
        assert_eq!(notice.summary, "memory: 2 folders stopped syncing");
        assert_eq!(whats(&notice), ["stopped_syncing"]);
        // With something mapped as well: "not added yet" comes first.
        let both = with(&|f| {
            f.stands = "no_phrase".into();
            f.moved_on = true;
            f.notice = Some(Stopped {
                folders: 2,
                not_known: false,
            });
        });
        assert_eq!(both.summary, "memory: not added yet");
        assert_eq!(whats(&both), ["no_phrase", "stopped_syncing"]);
    }

    /// The notice in the line (decision 2026-10-04 §10.1). With one
    /// mapping in step: red, and the line says that folders stopped
    /// syncing. With no mapping: the same, and not "nothing mapped". With
    /// no report yet: the same, and not "starting". Beside a conflict:
    /// the line says the conflict, and everything that holds has both.
    /// With sync off, the line says off. A notice whose folders are all
    /// mapped does not count.
    #[test]
    fn the_notice_is_red_and_never_hides_an_error_a_conflict_or_a_large_file() {
        let notice = |f: &mut Facts| {
            f.notice = Some(Stopped {
                folders: 3,
                not_known: false,
            })
        };
        let says = "memory: 3 folders stopped syncing";
        let in_step = with(&notice);
        assert_eq!(
            (in_step.level, in_step.summary.as_str()),
            (Some(Level::Red), says)
        );
        let no_mapping = with(&|f| {
            notice(f);
            f.mapped = 0;
            f.folders = 0;
        });
        assert_eq!(
            (no_mapping.level, no_mapping.summary.as_str()),
            (Some(Level::Red), says)
        );
        let no_report = with(&|f| {
            notice(f);
            f.report_age_secs = None;
        });
        assert_eq!(
            (no_report.level, no_report.summary.as_str()),
            (Some(Level::Red), says)
        );
        // Beside a conflict, and beside a file too large: after them.
        let conflict = with(&|f| {
            notice(f);
            f.conflicts = vec!["a".into()];
            f.too_large = vec!["b.md".into()];
        });
        assert_eq!(conflict.summary, "memory: 1 conflict");
        assert_eq!(
            whats(&conflict),
            ["conflicts", "too_large", "stopped_syncing"]
        );
        // With no mapping, where "nothing mapped" would be said, it is
        // ahead of a conflict that an earlier report still lists; an
        // error and a stalled cycle are ahead of it.
        let ahead = with(&|f| {
            notice(f);
            f.mapped = 0;
            f.conflicts = vec!["a".into()];
            f.errors = vec!["x".into()];
            f.report_age_secs = Some(STALE_REPORT_SECS + 1);
        });
        assert_eq!(
            whats(&ahead),
            ["errors", "stalled", "stopped_syncing", "conflicts"]
        );
        // With sync off: off, and no level.
        let off = with(&|f| {
            notice(f);
            f.sync_enabled = false;
        });
        assert_eq!((off.level, off.summary.as_str()), (None, "memory sync off"));
        // A notice whose folders are all mapped does not count; one of
        // whose records names none does.
        let all_mapped = with(&|f| f.notice = Some(Stopped::default()));
        assert_eq!(
            (all_mapped.level, all_mapped.summary.as_str()),
            (None, "memory synced")
        );
        let names_none = with(&|f| {
            f.notice = Some(Stopped {
                folders: 0,
                not_known: true,
            })
        });
        assert_eq!(names_none.level, Some(Level::Red));
        assert_eq!(names_none.summary, "memory: folders stopped syncing");
    }

    /// The waits (decision 2026-10-04 §10.1). No relay: none at four
    /// minutes, amber at six, by the node's own clock; none beside a node
    /// that does not say since when. A relay that does not hold the
    /// latest change: amber once it has been connected for more than
    /// five minutes. Names not yet in the new generation, or not yet
    /// sent: amber after more than five minutes. A removal that some
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

        let without_latest = |secs: u64| level(&|f| f.devices.without_latest_secs = vec![secs]);
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
        // A time with nothing that waits is nothing.
        assert_eq!(level(&|f| f.devices.to_go_secs = Some(900)), None);
        assert_eq!(level(&|f| f.devices.applied_secs = Some(900)), None);

        let day = 24 * 60 * 60;
        let removal = |secs: u64| level(&|f| f.devices.removal_not_applied_secs = Some(secs));
        assert_eq!(removal(0), amber);
        assert_eq!(removal(7 * day), amber);
        assert_eq!(removal(7 * day + 1), None);

        let no_room = |ago: u64| level(&|f| f.devices.no_room_secs = vec![ago]);
        assert_eq!(no_room(0), amber);
        assert_eq!(no_room(NO_ROOM_STANDS_SECS), amber);
        assert_eq!(no_room(NO_ROOM_STANDS_SECS + 1), None);
        assert_eq!(level(&|f| f.devices.no_room_secs = vec![9_000, 20]), amber);
    }

    /// A cycle counts as stalled from the node's start (decision
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
    /// 2026-10-04 §10.1), for a panel that draws from it alone: the
    /// notice is `attention`; entries that relays refuse are `attention`,
    /// though the level is amber; and a node of another version does not
    /// change the state.
    #[test]
    fn the_state_is_as_it_was_whatever_the_level() {
        let of = |edit: &dyn Fn(&mut Facts)| {
            let shown = with(edit);
            (shown.state, shown.level)
        };
        let notice = of(&|f| {
            f.notice = Some(Stopped {
                folders: 1,
                not_known: false,
            })
        });
        assert_eq!(notice, (State::Attention, Some(Level::Red)));
        assert_eq!(
            of(&|f| f.outbox_refused = 1),
            (State::Attention, Some(Level::Amber))
        );
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
        for (edit, what, _) in &AMBER[3..] {
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
        // Relays keep refusing one of them: that needs the person.
        assert_eq!(
            with(&|f| {
                f.outbox_waiting = 4;
                f.outbox_refused = 1;
            }),
            (State::Attention, "memory: 1 not taken by a relay".into())
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
        // With no phrase the state is `attention`: a new install says
        // that it has no recovery phrase yet, and a device that took
        // this version with what an earlier one held, that it is not
        // added yet (decision 2026-10-04 §10.1).
        assert_eq!(
            stands("no_phrase"),
            (
                State::Attention,
                "memory stays here: no recovery phrase yet".into()
            )
        );
        let mut moved_on = synced();
        moved_on.stands = "no_phrase".into();
        moved_on.moved_on = true;
        assert_eq!(
            state(&moved_on),
            (State::Attention, "memory: not added yet".into())
        );
        // Under a phrase, having moved on changes nothing.
        moved_on.stands = "applied".into();
        assert_eq!(state(&moved_on), (State::Synced, "memory synced".into()));
        for (stopped, says) in [
            ("fork", "two changes made apart"),
            ("removed", "this device was removed"),
            ("not_listed", "not in the last change"),
            ("not_opened", "a change could not be opened"),
        ] {
            assert_eq!(
                stands(stopped),
                (State::Attention, format!("memory not syncing: {says}"))
            );
        }
        // With sync off, that is what is said.
        let mut f = synced();
        f.stands = "no_phrase".into();
        f.sync_enabled = false;
        assert_eq!(state(&f), (State::Off, "memory sync off".into()));
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
        let first_start = (
            State::Attention,
            "memory not syncing: the first start on this version is not done".to_string(),
        );
        assert_eq!(held("first_start", &|_| {}), first_start);
        assert_eq!(
            held("first_start", &|f| f.sync_enabled = false),
            first_start
        );
        assert_eq!(
            held("first_start", &|f| f.stands = "no_phrase".into()),
            first_start
        );
        assert_eq!(
            held("first_start", &|f| f.errors = vec!["x".into()]),
            first_start
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
                "memory not syncing: the node is held up".into()
            )
        );
        // A node that is not running, or was not asked, says that first.
        assert_eq!(
            held("first_start", &|f| f.running = false).0,
            State::Stopped
        );
    }

    /// The notice of what stopped syncing is `attention` (decision
    /// 2026-10-04 §10.1), so that a panel which draws from the state
    /// alone shows it. It is said where "starting" and "nothing mapped"
    /// would be, and never over an error, a stalled cycle, a conflict or
    /// a file too large. With sync off the state is off. A notice whose
    /// folders are all mapped does not count.
    #[test]
    fn the_notice_of_what_stopped_needs_the_person() {
        let stopped = |folders: usize, not_known: bool| Stopped { folders, not_known };
        let with = |notice: Stopped, edit: &dyn Fn(&mut Facts)| {
            let mut f = synced();
            f.notice = Some(notice);
            edit(&mut f);
            state(&f)
        };
        let three = (
            State::Attention,
            "memory: 3 folders stopped syncing".to_string(),
        );
        // With a mapping in step.
        assert_eq!(with(stopped(3, false), &|_| {}), three);
        assert_eq!(
            with(stopped(1, false), &|_| {}),
            (State::Attention, "memory: 1 folder stopped syncing".into())
        );
        // Where it names none, and where it names some and one record
        // names none.
        assert_eq!(
            with(stopped(0, true), &|_| {}),
            (State::Attention, "memory: folders stopped syncing".into())
        );
        assert_eq!(with(stopped(3, true), &|_| {}), three);
        // With no mapping: not "nothing mapped". With no report yet: not
        // "starting".
        assert_eq!(with(stopped(3, false), &|f| f.folders = 0), three);
        assert_eq!(
            with(stopped(3, false), &|f| f.report_age_secs = None),
            three
        );
        // Offline, sending, joining: the notice is said first.
        assert_eq!(with(stopped(3, false), &|f| f.peers_hot = 0), three);
        assert_eq!(with(stopped(3, false), &|f| f.outbox_waiting = 2), three);
        assert_eq!(with(stopped(3, false), &|f| f.projects_waiting = 1), three);
        // It hides no error, no stalled cycle, no conflict and no file
        // too large.
        for (edit, says) in [
            (
                (&|f: &mut Facts| f.errors = vec!["x".into()]) as &dyn Fn(&mut Facts),
                "memory sync error",
            ),
            (
                &|f: &mut Facts| f.report_age_secs = Some(STALE_REPORT_SECS + 1),
                "memory sync stalled",
            ),
            (
                &|f: &mut Facts| f.conflicts = vec!["a".into()],
                "memory: 1 conflict",
            ),
            (
                &|f: &mut Facts| f.too_large = vec!["a.md".into()],
                "memory: 1 file too large",
            ),
        ] {
            assert_eq!(
                with(stopped(3, false), edit),
                (State::Attention, says.to_string())
            );
        }
        // With sync off, the state is off.
        assert_eq!(
            with(stopped(3, false), &|f| f.sync_enabled = false),
            (State::Off, "memory sync off".into())
        );
        // A notice whose folders are all mapped does not count.
        assert_eq!(
            with(stopped(0, false), &|_| {}),
            (State::Synced, "memory synced".into())
        );
        assert_eq!(
            with(stopped(0, false), &|f| f.folders = 0),
            (State::Off, "memory: nothing mapped".into())
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

    /// The bar form carries a class for each level, after the state's,
    /// and its `active`, which Omarchy's bar highlights, goes with red
    /// alone (decision 2026-10-04 §10.1). Each level has an icon of its
    /// own.
    #[test]
    fn the_bar_has_a_class_for_each_level_and_active_with_red_alone() {
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
        // With no level: the state alone, and never `active`, whatever
        // the state.
        for state in [
            State::Synced,
            State::Syncing,
            State::Offline,
            State::Attention,
            State::Off,
            State::Stopped,
        ] {
            assert_eq!(of(state, None)["class"], state.as_str());
        }
        assert_eq!(of(State::Attention, None)["text"], "\u{f0026}");
    }

    #[test]
    fn ages_read_naturally() {
        assert_eq!(ago(5), "just now");
        assert_eq!(ago(200), "3m ago");
        assert_eq!(ago(7300), "2h ago");
        assert_eq!(ago(200_000), "2d ago");
    }
}
