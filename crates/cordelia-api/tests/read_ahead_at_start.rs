//! A node reads its personal channel ahead once as it starts, with the
//! lock let go: a read of it under the lock after start then checks and
//! opens nothing that was stored before.
//!
//! What a node keeps of its personal channel between reads is the
//! process's, so this test is a binary of its own: no other test reads
//! another channel beside it.

use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use cordelia_api::names::{listed, not_read_ahead, read_ahead_at_start, say};
use cordelia_api::person::{first_statement, hold_name};
use cordelia_api::state::{AppState, Held};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::phrase::Phrase;

/// After a node's read ahead at start, a read of the personal channel
/// under the lock checks and opens none of the entries stored: every one
/// is kept as it is stored. Before it, each would have been. A node that
/// is not personal, or that is held up, reads nothing ahead.
#[test]
fn test_after_start_a_read_under_the_lock_checks_nothing_again() {
    let conn = cordelia_storage::db::open_in_memory().unwrap();
    let identity = NodeIdentity::generate().unwrap();
    let phrase = Phrase::generate().unwrap();
    let now = 1_790_000_000;
    first_statement(&conn, &identity, &phrase, "desktop", now).unwrap();
    let names = ["lab", "notes", "team", "work"];
    for name in names {
        hold_name(&conn, name, now).unwrap();
        assert!(say(&conn, &identity, name, now).unwrap());
    }
    let stored = not_read_ahead(&conn).unwrap();
    assert!(stored >= names.len(), "{stored}");

    let state = std::sync::Arc::new(AppState {
        db: Mutex::new(conn),
        identity,
        bearer_token: "t".into(),
        home_dir: std::env::temp_dir().join("cordelia-read-ahead-test-no-such-directory"),
        started_at: std::time::Instant::now(),
        sync_errors: AtomicU64::new(0),
        peers_hot: AtomicU64::new(0),
        peers_warm: AtomicU64::new(0),
        push_tx: None,
        announce_tx: None,
        peers: Default::default(),
        relays: Default::default(),
        outbox_refused: Default::default(),
        relist: Default::default(),
        sync_control: Default::default(),
        own_channels: Default::default(),
        held: Default::default(),
        history: Default::default(),
    });
    // Neither a node of another role nor one that is held up reads
    // ahead.
    assert!(read_ahead_at_start(state.clone(), false).is_none());
    state.held.hold(Held::FirstStart("a test".into()));
    assert!(read_ahead_at_start(state.clone(), true).is_none());
    assert_eq!(not_read_ahead(&state.db.lock().unwrap()).unwrap(), stored);
    state.held.release();

    read_ahead_at_start(state.clone(), true)
        .expect("a personal node that is not held up reads ahead")
        .join()
        .unwrap();

    let conn = state.db.lock().unwrap();
    assert_eq!(not_read_ahead(&conn).unwrap(), 0);
    // The read under the lock finds every name, and leaves nothing to
    // check after it either.
    let found: Vec<String> = listed(&conn).unwrap().into_iter().map(|l| l.name).collect();
    assert_eq!(found, names);
    assert_eq!(not_read_ahead(&conn).unwrap(), 0);
}
