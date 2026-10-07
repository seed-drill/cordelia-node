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
//! a loop, and a stopped node can say nothing. It is tried again each
//! time a cycle would have run.

use actix_web::HttpRequest;

use cordelia_storage::first_start::{self, Done};

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
/// Held up for its first start, a node answers every `GET`, the requests
/// that only read ([`ANSWERED_WHILE_HELD`]), and the one that may turn
/// sync off ([`SYNC_SETTING`]).
pub fn refuse_while_held(req: &HttpRequest, state: &AppState) -> Result<(), ApiError> {
    let Some(held) = state.held.why() else {
        return Ok(());
    };
    let path = req.path();
    let answered = match &held {
        _ if req.method() == actix_web::http::Method::GET => true,
        Held::FirstStart(_) => ANSWERED_WHILE_HELD.contains(&path) || path == SYNC_SETTING,
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

/// Make the node's first start on this version, where it is still to be
/// made (decision 2026-10-04 §10.1). `version` is the node's own. Returns
/// whether it is done.
///
/// Where it is done the node is held up no longer. Where it is not, the
/// node is held up, with why.
///
/// It is made under one hold of the database's lock, the copy included:
/// nothing else of the node reads or writes meanwhile.
pub fn take(state: &AppState, version: &str) -> bool {
    let started = {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        first_start::first_start(&db, &state.home_dir, version, chrono::Utc::now())
    };
    match started {
        Ok(started) => {
            match &started.done {
                Done::Already(_) => {}
                Done::Marked => tracing::info!(
                    "first start on this version: nothing of the older kind is held, and \
                     the mark is written"
                ),
                Done::Stepped { copy, notice } => tracing::info!(
                    copy = %copy.display(),
                    notice = notice.is_some(),
                    "first start on this version: the database was copied and moved on; this \
                     device follows no recovery phrase, and is added again with `cordelia \
                     phrase` here or `cordelia accept`"
                ),
            }
            if started.key_files_removed > 0 {
                tracing::info!(
                    key_files = started.key_files_removed,
                    "removed the key files of the older channels"
                );
            }
            // A key file that could not be removed is no reason not to go
            // on. The node says how many, and looks again when it next
            // starts.
            if started.key_files_left > 0 {
                tracing::warn!(
                    key_files = started.key_files_left,
                    "could not remove every key file of the older channels; they are left, \
                     and looked for again at the next start"
                );
            }
            state.held.release();
            true
        }
        Err(why) => {
            let says = not_done(&why);
            // Said once for each reason: it is tried every few seconds.
            if state.held.why().as_ref().map(Held::says) != Some(says.as_str()) {
                tracing::error!("{says}");
            }
            state.held.hold(Held::FirstStart(says));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordelia_storage::first_start::{Mark, mark, released};
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
        assert!(take(&state, VERSION));
        assert_eq!(state.held.why(), None);
        assert_eq!(channels(&state), 0);
        assert_eq!(copies_in(dir.path()), ["before-0.2.0-test"]);
        let stepped = Mark {
            stepped: true,
            version: VERSION.into(),
        };
        assert_eq!(mark_of(&state), Some(stepped.clone()));
        // Again, and in a later version: nothing more.
        assert!(take(&state, VERSION));
        assert!(take(&state, "9.9.9"));
        assert_eq!(copies_in(dir.path()), ["before-0.2.0-test"]);
        assert_eq!(mark_of(&state), Some(stepped));

        let dir = tempfile::tempdir().unwrap();
        let state = node_in(dir.path());
        assert!(take(&state, VERSION));
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

        assert!(!take(&state, VERSION));
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
        assert!(!take(&state, VERSION));
        assert!(state.held.why().is_some());

        mode(0o700);
        assert!(take(&state, VERSION));
        assert_eq!(state.held.why(), None);
        assert_eq!(channels(&state), 0);
        assert_eq!(copies_in(dir.path()), ["before-0.2.0-test"]);
    }
}
