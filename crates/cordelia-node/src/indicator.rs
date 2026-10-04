//! One state and a short summary of this device's memory sync, for status
//! bars: `cordelia status --line` (the Claude Code status line) and
//! `cordelia status --json` (bar widgets and scripts).

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
    /// Items written here that no relay has stored yet.
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
    /// Projects this device is waiting to be added to.
    pub projects_waiting: usize,
    /// Folders the last cycle synced or is waiting to sync.
    pub folders: usize,
    /// Everything found syncs (`--all`), not only mapped folders.
    pub sync_all: bool,
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

/// The state and a short summary ("memory synced", "memory: 1 conflict").
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
    if !f.sync_enabled {
        return (Off, "memory sync off".into());
    }
    if !f.errors.is_empty() {
        return (Attention, "memory sync error".into());
    }
    match f.report_age_secs {
        None => return (Syncing, "memory sync starting".into()),
        Some(age) if age > STALE_REPORT_SECS => {
            return (Attention, "memory sync stalled".into());
        }
        Some(_) => {}
    }
    if f.folders == 0 {
        let summary = if f.sync_all {
            "memory: nothing to sync"
        } else {
            "memory: nothing mapped"
        };
        return (Off, summary.into());
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
            format!("memory joining {n} {}", plural(n, "project")),
        );
    }
    (Synced, "memory synced".into())
}

/// One line for a status bar: a mark and the summary, coloured unless
/// `color` is false. Empty when there is nothing to show.
pub fn line(state: State, summary: &str, color: bool) -> String {
    let (mark, code) = match state {
        State::Synced => ("●", "32"),                               // green
        State::Syncing => ("◐", "33"),                              // yellow
        State::Attention => ("▲", "31"),                            // red
        State::Offline | State::Off | State::Stopped => ("○", "2"), // dim
        State::Uninitialised => return String::new(),
    };
    if color {
        format!("\x1b[{code}m{mark} {summary}\x1b[0m")
    } else {
        format!("{mark} {summary}")
    }
}

/// What a bar shows: an icon, a tooltip, and the state as a class.
///
/// The JSON is the shape Waybar's custom modules take, which Omarchy's bar
/// reads too: `text`, `tooltip` and `class`. The class is the state name;
/// `active` is added when the person is needed, which Omarchy highlights.
/// The icons are Nerd Font glyphs. Empty when there is nothing to show.
pub fn bar(state: State, summary: &str, details: &[String]) -> String {
    let icon = match state {
        State::Synced => "\u{f09d1}",               // brain
        State::Syncing => "\u{f04e6}",              // sync
        State::Offline => "\u{f0164}",              // cloud off
        State::Attention => "\u{f0026}",            // alert
        State::Off | State::Stopped => "\u{f04b2}", // sleep
        State::Uninitialised => return String::new(),
    };
    let mut tooltip = format!("Cordelia: {summary}");
    for line in details {
        tooltip.push('\n');
        tooltip.push_str(line);
    }
    let class = if state == State::Attention {
        serde_json::json!([state.as_str(), "active"])
    } else {
        serde_json::json!(state.as_str())
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
            ..Default::default()
        }
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
            with(&|f| {
                f.folders = 0;
                f.sync_all = true;
            }),
            (State::Off, "memory: nothing to sync".into())
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
            (State::Syncing, "memory joining 1 project".into())
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
            line(State::Synced, "memory synced", false),
            "● memory synced"
        );
        assert_eq!(
            line(State::Attention, "memory: 1 conflict", true),
            "\x1b[31m▲ memory: 1 conflict\x1b[0m"
        );
        assert_eq!(line(State::Uninitialised, "x", true), "");
    }

    #[test]
    fn bars_get_an_icon_a_tooltip_and_the_state_as_class() {
        let v: serde_json::Value = serde_json::from_str(&bar(
            State::Synced,
            "memory synced",
            &["Relays: 2 connected".into()],
        ))
        .unwrap();
        assert_eq!(v["text"], "\u{f09d1}");
        assert_eq!(v["tooltip"], "Cordelia: memory synced\nRelays: 2 connected");
        assert_eq!(v["class"], "synced");

        // Needing the person adds `active`, which Omarchy's bar highlights.
        let v: serde_json::Value =
            serde_json::from_str(&bar(State::Attention, "memory: 1 conflict", &[])).unwrap();
        assert_eq!(v["class"], serde_json::json!(["attention", "active"]));

        assert_eq!(bar(State::Uninitialised, "x", &[]), "");
    }

    #[test]
    fn ages_read_naturally() {
        assert_eq!(ago(5), "just now");
        assert_eq!(ago(200), "3m ago");
        assert_eq!(ago(7300), "2h ago");
        assert_eq!(ago(200_000), "2d ago");
    }
}
