//! A personal node's first start on this version (decision 2026-10-04
//! §10.1).
//!
//! [`take`] makes the first start that the store defines
//! ([`cordelia_storage::first_start`]) on the node's database, and says
//! what became of it: the mark alone, or the copy and the step. A node
//! makes it when it starts, once the port of its local API is bound and
//! before its sync loop and its first pass are started. A relay and a
//! bootnode make none.
//!
//! **Until it has succeeded the node is held up**
//! ([`crate::state::HeldUp`]): it runs no cycle and no pass, and refuses
//! every request that changes anything, except one that turns sync off
//! ([`refuse_while_held`]). It answers status, which says why. It does
//! not stop: under a service that restarts what stops, stopping would be
//! a loop, and a stopped node can say nothing. It is tried again when a
//! cycle would have run, after a wait that doubles with each try that
//! fails ([`wait_after`]).
//!
//! **A node whose database is from a later version is held up too,** for
//! as long as it runs: it changes nothing, so it takes no request but
//! those of its status, and says so there.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use actix_web::HttpRequest;

use cordelia_core::protocol::{
    FIRST_START_RETRY_BASE_SECS, FIRST_START_RETRY_MAX_SECS, FIRST_START_RETRY_SLACK_SECS,
};
use cordelia_storage::first_start::{self, Copied, Done, Due, RoomThere};

use crate::error::ApiError;
use crate::state::{AppState, Held};

/// The requests that a node whose first start is not done still answers,
/// beside every `GET`: each reads, and writes nothing. They are what
/// `cordelia status`, `cordelia sync status`, `cordelia devices` and
/// `cordelia history` ask, and the local API's two that read.
pub const ANSWERED_WHILE_HELD: [&str; 6] = [
    "/api/v1/sync/status",
    "/api/v1/devices/list",
    "/api/v1/history/list",
    "/api/v1/history/show",
    "/api/v1/channels/entries",
    "/api/v1/channels/identity",
];

/// The request that turns sync on or off. A node whose first start is
/// not done takes it where it turns sync off, and its handler refuses
/// the rest ([`crate::sync::claude`]).
pub const SYNC_SETTING: &str = "/api/v1/sync/claude";

/// Refuse a request that a node which is held up does not answer, with
/// why it is held up (decision 2026-10-04 §10.1). Every handler that
/// checks the node's token comes through here, so a route that is added
/// is refused until it is listed.
///
/// - Held up for its first start, a node answers every `GET`, the
///   requests that only read ([`ANSWERED_WHILE_HELD`]), and the one that
///   may turn sync off ([`SYNC_SETTING`]).
/// - Held up by a database from a later version, it answers every `GET`
///   and nothing else. What it would read is not its database, and it
///   writes nothing there: turning sync off is refused too, since the
///   setting is in that database.
pub fn refuse_while_held(req: &HttpRequest, state: &AppState) -> Result<(), ApiError> {
    let Some(held) = state.held.why() else {
        return Ok(());
    };
    let path = req.path();
    let answered = match &held {
        _ if req.method() == actix_web::http::Method::GET => true,
        Held::FirstStart(_) => ANSWERED_WHILE_HELD.contains(&path) || path == SYNC_SETTING,
        Held::LaterDatabase(_) => false,
    };
    match answered {
        true => Ok(()),
        false => Err(ApiError::Held(held.says().to_string())),
    }
}

/// What is said of a first start that is not done: why, that nothing was
/// changed, and that the node tries again by itself.
fn not_done(why: &first_start::NotDone) -> String {
    format!(
        "the first start on this version is not done: {why}. Nothing was changed, and nothing \
         syncs until it is done: the node tries again by itself, and needs no restart."
    )
}

/// What is said while the copy is being made: the node answers what asks
/// how it stands from the moment its port is bound (decision 2026-10-04
/// §10.1).
pub const COPY_BEING_MADE: &str = "the first start on this version is under way: a copy of the \
     database from before this version is being made. Nothing syncs until it is done.";

/// What one start of a node keeps between its tries at the first start
/// (decision 2026-10-04 §10.1).
#[derive(Default)]
pub struct Tries {
    /// A copy that was made and checked, and that no step has used: it
    /// is used again where only the step failed.
    copied: Option<Copied>,
    /// How many tries have failed, one after another.
    failed: u32,
    /// When the next may be made: the wait doubles with each that fails.
    not_before: Option<Instant>,
    /// The reason that was last said in the log: each is said once.
    said: Option<String>,
}

/// How long the node waits after `failed` tries that failed, one after
/// another, before it tries again: the cycle's interval after the first,
/// and twice as long after each further one, up to ten minutes. A start
/// that cannot succeed does not write its copy every few seconds.
pub fn wait_after(failed: u32) -> Duration {
    let doubled = FIRST_START_RETRY_BASE_SECS
        .checked_shl(failed.saturating_sub(1))
        .unwrap_or(u64::MAX);
    Duration::from_secs(doubled.min(FIRST_START_RETRY_MAX_SECS))
}

/// What a personal node does about its first start on this version when
/// it starts, once the port of its local API is bound and before
/// anything else is started (decision 2026-10-04 §10.1). Returns whether
/// the first start is done.
///
/// Where a mark is all there is to write, or there is nothing to do, it
/// is done here. Where a copy is to be made, the node is held up, with
/// words that say a copy is being made, and the copy and the step are
/// made by the first [`take`]: the node's server is answering by then,
/// so a command that asks how the node stands is told, and is not left
/// to say that the node cannot be reached. Held up, the node runs no
/// cycle and no pass, and refuses what changes anything, until the step
/// has succeeded.
pub fn take_at_start(state: &AppState, version: &str, room: RoomThere) -> bool {
    let due = {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        first_start::due(&db, &state.home_dir)
    };
    match due {
        Ok(Due::Step) => {
            state.held.hold(Held::FirstStart(COPY_BEING_MADE.into()));
            false
        }
        _ => take(state, version, room),
    }
}

/// [`take_at`], now.
pub fn take(state: &AppState, version: &str, room: RoomThere) -> bool {
    take_at(state, version, room, Instant::now())
}

/// Make the node's first start on this version, where it is still to be
/// made (decision 2026-10-04 §10.1). `version` is the node's own, `room`
/// how the free room on the volume is learned, and `now` the time on a
/// clock that does not go back. Returns whether it is done.
///
/// Where it is done the node is held up no longer. Where it is not, the
/// node is held up, with why. A node that is held up by a database from
/// a later version stays so: nothing is tried on that database.
///
/// - **The copy is made on a connection of its own,** without the node's
///   lock: the node goes on answering what asks how it stands, and says
///   that a copy is being made. The lock is taken for the step, which
///   uses that copy: this run of the node made it, and writes nothing of
///   this while its first start is not done. (A database that is in no
///   file is copied on the node's own connection.)
/// - **A copy that was made is used again** by a later try of this run
///   where only the step failed, and by no other run: a new start makes
///   a new copy, and keeps the one it finds as the earlier one.
/// - **The tries back off:** after one that failed, nothing is tried
///   before its wait has passed ([`wait_after`]), counted from when the
///   try began, but for a second of slack for the timer that calls this.
pub fn take_at(state: &AppState, version: &str, room: RoomThere, now: Instant) -> bool {
    if matches!(state.held.why(), Some(Held::LaterDatabase(_))) {
        return false;
    }
    let mut tries = state.held.tries();
    let slack = Duration::from_secs(FIRST_START_RETRY_SLACK_SECS);
    if tries.not_before.is_some_and(|at| now + slack < at) {
        return false;
    }
    let started = make(state, version, room, &mut tries.copied);
    match started {
        Ok(started) => {
            match &started.done {
                Done::Already(_) => {}
                Done::Marked => tracing::info!(
                    "first start on this version: nothing of the older kind is held, and \
                     the mark is written"
                ),
                Done::Stepped { copy, notice } => {
                    tracing::info!(
                        copy = %copy.display(),
                        notice = notice.is_some(),
                        "first start on this version: the database was copied and moved on; \
                         this device follows no recovery phrase, and is added again with \
                         `cordelia phrase` here or `cordelia accept`"
                    );
                    // Folders stopped syncing with this step: it is said
                    // here, once, with how many. A status says it until a
                    // person has seen it.
                    if let Some(notice) = notice {
                        tracing::warn!("{}", folders_stopped_says(notice));
                    }
                }
            }
            let key_files = started.key_files;
            if key_files.removed > 0 {
                tracing::info!(
                    key_files = key_files.removed,
                    "removed the key files of the older channels"
                );
            }
            // A key file that could not be removed is no reason not to go
            // on. The node says how many, and looks again when it next
            // starts.
            if key_files.left > 0 {
                tracing::warn!(
                    key_files = key_files.left,
                    "could not remove every key file of the older channels; they are left, \
                     and looked for again at the next start"
                );
            }
            // Nor is one that no copy holds: it is left where it is, and
            // the status says how many.
            if key_files.in_place > 0 {
                tracing::warn!(
                    key_files = key_files.in_place,
                    "{}",
                    key_files_in_place_says(key_files.in_place)
                );
            }
            state.held.set_key_files_in_place(key_files.in_place);
            *tries = Tries::default();
            state.held.release();
            true
        }
        Err(why) => {
            let says = not_done(&why);
            // Said once for each reason: it is tried again and again. The
            // room there is on the volume is no part of the reason: it is
            // another number at every try.
            let reason = match &why {
                first_start::NotDone::NotCopied(not) => not.why.clone(),
                first_start::NotDone::Failed(why) => why.clone(),
            };
            if tries.said.as_deref() != Some(reason.as_str()) {
                tracing::error!("{says}");
                tries.said = Some(reason);
            }
            tries.failed = tries.failed.saturating_add(1);
            tries.not_before = Some(now + wait_after(tries.failed));
            state.held.hold(Held::FirstStart(says));
            false
        }
    }
}

/// What the log says, once, where the step of the first start leaves a
/// notice (decision 2026-10-04 §10.1): how many folders stopped syncing,
/// or that which did is not known, and where they are listed.
pub fn folders_stopped_says(notice: &first_start::Notice) -> String {
    let listed = "only mapped folders sync, and they had synced because everything found did. \
                  `cordelia sync status` lists them, with the command that maps each";
    match notice.folders.as_ref().map(Vec::len) {
        Some(1) => format!("sync: 1 folder stopped syncing on this device: {listed}"),
        Some(n) => format!("sync: {n} folders stopped syncing on this device: {listed}"),
        None => "sync: folders stopped syncing on this device, and which is not known (no \
                 report of the last cycle was kept): only mapped folders sync, and they had \
                 synced because everything found did. `cordelia sync status` lists what is \
                 found, with the command that maps each folder"
            .to_string(),
    }
}

/// What a status says of key files of the older channels that were left
/// where they are, since no copy holds them (decision 2026-10-04 §10.1).
pub fn key_files_in_place_says(files: usize) -> String {
    match files {
        1 => "1 key file of an older version was left in place: no copy beside the database \
              holds it"
            .to_string(),
        n => format!(
            "{n} key files of an older version were left in place: no copy beside the \
             database holds them"
        ),
    }
}

/// One try at the first start: the copy on a connection of its own,
/// where one is to be made and the database is in a file, and then the
/// rest under the node's lock.
fn make(
    state: &AppState,
    version: &str,
    room: RoomThere,
    copied: &mut Option<Copied>,
) -> Result<first_start::FirstStart, first_start::NotDone> {
    let (due, database) = {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        let database = db.path().filter(|path| !path.is_empty()).map(PathBuf::from);
        (first_start::due(&db, &state.home_dir)?, database)
    };
    if let (Due::Step, None, Some(database)) = (&due, &copied, &database) {
        state.held.hold(Held::FirstStart(COPY_BEING_MADE.into()));
        let copy = first_start::copy_apart(database, &state.home_dir, version, room)
            .map_err(first_start::NotDone::NotCopied)?;
        *copied = Some(copy);
    }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    first_start::first_start(
        &db,
        &state.home_dir,
        version,
        chrono::Utc::now(),
        room,
        copied,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_storage::first_start::{Mark, mark, released, room_not_known};
    use cordelia_storage::{db, meta};

    use crate::several::{Machine, state_of};

    /// The version that makes the first start in these tests.
    const VERSION: &str = "0.2.0-test";

    /// A node's state over a database in `dir`, which is its folder.
    fn node_in(dir: &std::path::Path) -> AppState {
        let mut machine = Machine::new(1);
        machine.conn = db::open(&dir.join("cordelia.db")).unwrap();
        let mut state = state_of(machine);
        state.home_dir = dir.to_path_buf();
        state
    }

    /// A node whose folder holds a database and key files in the released
    /// version's form.
    fn released_node(dir: &std::path::Path) -> AppState {
        let conn = released::database(&dir.join("cordelia.db")).unwrap();
        released::fill(&conn, dir).unwrap();
        drop(conn);
        node_in(dir)
    }

    fn copies_in(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("before-"))
            .collect();
        names.sort();
        names
    }

    fn channels(state: &AppState) -> i64 {
        let db = state.db.lock().unwrap();
        db.query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
            .unwrap()
    }

    fn mark_of(state: &AppState) -> Option<Mark> {
        mark(&state.db.lock().unwrap()).unwrap()
    }

    /// A node that starts on a database of the released version makes
    /// the copy and takes the step; one that starts on a first install
    /// writes the mark and makes no copy (decision 2026-10-04 §10.1).
    /// Neither is held up, and a second start does nothing more.
    #[test]
    fn test_a_first_start_is_made_once_and_the_node_is_not_held_up() {
        let dir = tempfile::tempdir().unwrap();
        let state = released_node(dir.path());
        assert_eq!(channels(&state), 6);
        assert!(take(&state, VERSION, &room_not_known));
        assert_eq!(state.held.why(), None);
        assert_eq!(channels(&state), 0);
        assert_eq!(copies_in(dir.path()), ["before-0.2.0-test"]);
        let stepped = Mark {
            stepped: true,
            version: VERSION.into(),
        };
        assert_eq!(mark_of(&state), Some(stepped.clone()));
        // Again, and in a later version: nothing more.
        assert!(take(&state, VERSION, &room_not_known));
        assert!(take(&state, "9.9.9", &room_not_known));
        assert_eq!(copies_in(dir.path()), ["before-0.2.0-test"]);
        assert_eq!(mark_of(&state), Some(stepped));

        let dir = tempfile::tempdir().unwrap();
        let state = node_in(dir.path());
        assert!(take(&state, VERSION, &room_not_known));
        assert_eq!(state.held.why(), None);
        assert!(copies_in(dir.path()).is_empty());
        let marked = Mark {
            stepped: false,
            version: VERSION.into(),
        };
        assert_eq!(mark_of(&state), Some(marked));
    }

    /// Where the first start cannot be made the node is held up, and says
    /// why, with the room that the copy needs; nothing is changed. Tried
    /// again once it can be made, it is made, and the node is held up no
    /// longer (decision 2026-10-04 §10.1).
    #[cfg(unix)]
    #[test]
    fn test_a_first_start_that_cannot_be_made_holds_the_node_up_until_it_can() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let state = released_node(dir.path());
        // What is left of a copy cannot be removed: a folder in it cannot
        // be looked into.
        let closed = dir.path().join("before-0.2.0-test.partial").join("closed");
        std::fs::create_dir_all(&closed).unwrap();
        std::fs::write(closed.join("a-file"), "x").unwrap();
        let mode = |mode: u32| {
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        mode(0o000);

        let began = Instant::now();
        let after = |secs: u64| began + Duration::from_secs(secs);
        assert!(!take_at(&state, VERSION, &room_not_known, began));
        let Some(Held::FirstStart(why)) = state.held.why() else {
            panic!("{:?}", state.held.why());
        };
        assert!(
            why.starts_with(
                "the first start on this version is not done: the copy of the database"
            ),
            "{why}"
        );
        assert!(why.contains("bytes of room"), "{why}");
        assert!(why.contains("the node tries again by itself"), "{why}");
        assert_eq!(channels(&state), 6);
        assert_eq!(mark_of(&state), None);
        assert!(
            meta::get(&state.db.lock().unwrap(), meta::SYNC_CLAUDE_REPORT)
                .unwrap()
                .is_some()
        );
        // Again, with nothing changed: it is held up still.
        assert!(!take_at(&state, VERSION, &room_not_known, after(5)));
        assert_eq!(state.held.why(), Some(Held::FirstStart(why)));

        mode(0o700);
        assert!(take_at(&state, VERSION, &room_not_known, after(15)));
        assert_eq!(state.held.why(), None);
        assert_eq!(channels(&state), 0);
        assert_eq!(copies_in(dir.path()), ["before-0.2.0-test"]);
    }

    /// The tries at a first start that keeps failing back off (decision
    /// 2026-10-04 §10.1): after one that failed nothing is tried before
    /// its wait has passed, and the wait doubles from the cycle's five
    /// seconds to ten minutes. A try that succeeds ends it.
    #[test]
    fn test_the_tries_at_a_first_start_back_off() {
        let waits: Vec<u64> = (1..=9).map(|failed| wait_after(failed).as_secs()).collect();
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 320, 600, 600]);
        assert_eq!(wait_after(0).as_secs(), 5);
        assert_eq!(wait_after(u32::MAX).as_secs(), 600);

        let dir = tempfile::tempdir().unwrap();
        let state = released_node(dir.path());
        // The volume has no room: each try asks, and none makes a copy.
        let asked = std::cell::Cell::new(0);
        let room = std::cell::Cell::new(Some(0));
        let room_there = |_: &std::path::Path| {
            asked.set(asked.get() + 1);
            room.get()
        };
        let began = Instant::now();
        let tried_at = |secs: u64| {
            let before = asked.get();
            let done = take_at(
                &state,
                VERSION,
                &room_there,
                began + Duration::from_secs(secs),
            );
            (done, asked.get() > before)
        };
        // The first try, and then one after each wait: five seconds, ten,
        // twenty. Before a wait has passed nothing is tried, whatever
        // asks.
        assert_eq!(tried_at(0), (false, true));
        assert_eq!(tried_at(0), (false, false));
        assert_eq!(tried_at(3), (false, false));
        assert_eq!(tried_at(5), (false, true));
        assert_eq!(tried_at(10), (false, false));
        assert_eq!(tried_at(13), (false, false));
        assert_eq!(tried_at(15), (false, true));
        assert_eq!(tried_at(33), (false, false));
        // A try is made up to a second before its wait has passed: the
        // timer that asks is not exact.
        assert_eq!(tried_at(34), (false, true));
        let Some(Held::FirstStart(why)) = state.held.why() else {
            panic!("{:?}", state.held.why());
        };
        assert!(why.contains("too little room"), "{why}");
        assert!(why.contains("and the volume has 0"), "{why}");
        assert!(copies_in(dir.path()).is_empty());
        assert_eq!(channels(&state), 6);

        // There is room: the next try, when its wait has passed, makes
        // the first start, and nothing is waited for after it.
        room.set(None);
        assert_eq!(tried_at(72), (false, false));
        assert_eq!(tried_at(74), (true, true));
        assert_eq!(state.held.why(), None);
        assert_eq!(tried_at(74), (true, false));
        assert_eq!(channels(&state), 0);
    }

    /// A node that has a copy to make is held up when it starts, with
    /// words that say a copy is being made, and has changed nothing; the
    /// first try then makes the copy and takes the step. The copy is made
    /// without the node's lock, so the node answers what asks how it
    /// stands meanwhile (decision 2026-10-04 §10.1). A node that has only
    /// a mark to write writes it when it starts, and is not held up.
    #[test]
    fn test_a_copy_is_made_after_the_start_and_without_the_nodes_lock() {
        let dir = tempfile::tempdir().unwrap();
        let state = released_node(dir.path());
        assert!(!take_at_start(&state, VERSION, &room_not_known));
        assert_eq!(
            state.held.why(),
            Some(Held::FirstStart(COPY_BEING_MADE.into()))
        );
        assert!(COPY_BEING_MADE.contains("a copy of the database"));
        assert!(COPY_BEING_MADE.contains("is being made"));
        assert_eq!(channels(&state), 6);
        assert_eq!(mark_of(&state), None);
        assert!(copies_in(dir.path()).is_empty());

        // While the copy is made: the lock is free, and the node says
        // that a copy is being made.
        let seen = std::cell::RefCell::new(Vec::new());
        let while_copying = |_: &std::path::Path| {
            let free = state.db.try_lock().is_ok();
            seen.borrow_mut().push((free, state.held.why()));
            None
        };
        assert!(take(&state, VERSION, &while_copying));
        let seen = seen.into_inner();
        assert!(!seen.is_empty());
        for (free, held) in seen {
            assert!(free, "the node's lock was held while the copy was made");
            assert_eq!(held, Some(Held::FirstStart(COPY_BEING_MADE.into())));
        }
        assert_eq!(state.held.why(), None);
        assert_eq!(channels(&state), 0);
        assert_eq!(copies_in(dir.path()), ["before-0.2.0-test"]);

        // A try that follows one that failed says, while its copy is
        // made, that a copy is being made.
        let dir = tempfile::tempdir().unwrap();
        let state = released_node(dir.path());
        let began = Instant::now();
        let no_room = |_: &std::path::Path| Some(0);
        assert!(!take_at(&state, VERSION, &no_room, began));
        assert!(
            matches!(state.held.why(), Some(Held::FirstStart(why)) if why.contains("is not done"))
        );
        let said = std::cell::RefCell::new(Vec::new());
        let while_copying = |_: &std::path::Path| {
            said.borrow_mut().push(state.held.why());
            None
        };
        let later = began + Duration::from_secs(5);
        assert!(take_at(&state, VERSION, &while_copying, later));
        let said = said.into_inner();
        assert!(!said.is_empty());
        for held in said {
            assert_eq!(held, Some(Held::FirstStart(COPY_BEING_MADE.into())));
        }

        let dir = tempfile::tempdir().unwrap();
        let state = node_in(dir.path());
        assert!(take_at_start(&state, VERSION, &room_not_known));
        assert_eq!(state.held.why(), None);
        assert_eq!(mark_of(&state).map(|mark| mark.stepped), Some(false));
    }

    /// A copy that a try made is used by the next where only the step
    /// failed: the node makes one copy, however often it tries (decision
    /// 2026-10-04 §10.1).
    #[test]
    fn test_a_copy_is_made_once_where_the_step_keeps_failing() {
        let dir = tempfile::tempdir().unwrap();
        let state = released_node(dir.path());
        state
            .db
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_row BEFORE DELETE ON trusted_keys BEGIN
                     SELECT RAISE(ABORT, 'this row stays');
                 END;",
            )
            .unwrap();
        // The room is asked where a copy is begun, and nowhere else.
        let asked = std::cell::Cell::new(0);
        let room_there = |_: &std::path::Path| {
            asked.set(asked.get() + 1);
            None
        };
        let began = Instant::now();
        let after = |secs: u64| began + Duration::from_secs(secs);
        assert!(!take_at(&state, VERSION, &room_there, began));
        let copies = asked.get();
        assert!(copies > 0);
        let Some(Held::FirstStart(why)) = state.held.why() else {
            panic!("{:?}", state.held.why());
        };
        assert!(why.contains("this row stays"), "{why}");
        assert!(!take_at(&state, VERSION, &room_there, after(5)));
        assert!(!take_at(&state, VERSION, &room_there, after(15)));
        assert_eq!(asked.get(), copies, "the copy was made again");
        assert_eq!(copies_in(dir.path()), ["before-0.2.0-test"]);

        state
            .db
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER no_row")
            .unwrap();
        assert!(take_at(&state, VERSION, &room_there, after(35)));
        assert_eq!(asked.get(), copies, "the copy was made again");
        assert_eq!(copies_in(dir.path()), ["before-0.2.0-test"]);
        assert_eq!(channels(&state), 0);
    }

    /// What the log says where the step of the first start leaves a
    /// notice (decision 2026-10-04 §10.1): how many folders stopped
    /// syncing, one said as one, or that which did is not known; and
    /// where they are listed.
    #[test]
    fn test_the_log_says_how_many_folders_stopped_at_the_first_start() {
        use cordelia_storage::first_start::{Notice, StoppedFolder};
        let notice = |folders: Option<usize>| Notice {
            at: "2026-10-07T08:00:00+00:00".into(),
            dir: Some("/home/sam/.claude".into()),
            folders: folders.map(|n| {
                (0..n)
                    .map(|i| StoppedFolder {
                        folder: format!("/home/sam/.claude/projects/-f{i}"),
                        cwd: None,
                        name: None,
                    })
                    .collect()
            }),
        };
        let one = folders_stopped_says(&notice(Some(1)));
        assert!(
            one.starts_with("sync: 1 folder stopped syncing on this device: only mapped"),
            "{one}"
        );
        let three = folders_stopped_says(&notice(Some(3)));
        assert!(
            three.starts_with("sync: 3 folders stopped syncing on this device: only mapped"),
            "{three}"
        );
        for says in [&one, &three] {
            assert!(says.contains("`cordelia sync status` lists them"), "{says}");
        }
        let not_known = folders_stopped_says(&notice(None));
        assert!(
            not_known.starts_with(
                "sync: folders stopped syncing on this device, and which is not known"
            ),
            "{not_known}"
        );
        assert!(not_known.contains("lists what is found"), "{not_known}");
    }

    /// Key files of the older channels that no copy holds are left in
    /// place, and the node notes how many, for its status to say
    /// (decision 2026-10-04 §10.1).
    #[test]
    fn test_key_files_that_no_copy_holds_are_counted_for_the_status() {
        let dir = tempfile::tempdir().unwrap();
        let state = node_in(dir.path());
        assert!(take(&state, VERSION, &room_not_known));
        assert_eq!(state.held.key_files_in_place(), 0);
        let keys = dir.path().join("channel-keys");
        std::fs::create_dir(&keys).unwrap();
        for name in ["grp_one.key", "grp_one.slot"] {
            std::fs::write(keys.join(name), [5u8; 32]).unwrap();
        }
        assert!(take(&state, VERSION, &room_not_known));
        assert_eq!(state.held.key_files_in_place(), 2);
        assert!(keys.join("grp_one.key").exists());
        assert_eq!(
            key_files_in_place_says(2),
            "2 key files of an older version were left in place: no copy beside the database \
             holds them"
        );
        assert!(
            key_files_in_place_says(1)
                .starts_with("1 key file of an older version was left in place")
        );
    }
}
