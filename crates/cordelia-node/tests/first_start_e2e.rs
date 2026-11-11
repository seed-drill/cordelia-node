//! A node's start, with real processes: the port of its local API, the
//! lock and the mode of its data directory, and the refusal of a
//! database from a later version or from before alpha.19 (decision
//! 2026-10-04 §10.1; decision 2026-11-10 (older kind), rule 6).
//!
//! Every node is a process of its own, started through the harness on
//! this machine.

mod common;

use std::path::Path;

use common::*;
use rusqlite::Connection;

/// The version of the node that these tests start: their own.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Put a database as alpha.19 left one, at schema step 33, in the place
/// of the database that `cordelia init` made for `node`, which has not
/// been started (decision 2026-11-10 (older kind), rule 4). Its key, its
/// token and its configuration stay. Sync is on there for the Claude Code
/// directory of the node's own home, which is the test's.
fn as_alpha_19_left_it(node: &Node) {
    use cordelia_storage::meta;
    let data = node.data_dir();
    for file in ["cordelia.db", "cordelia.db-wal", "cordelia.db-shm"] {
        let _ = std::fs::remove_file(data.join(file));
    }
    let conn = Connection::open(data.join("cordelia.db")).unwrap();
    cordelia_storage::schema::init_db_as_alpha_19(&conn).unwrap();
    let dir = node.home().join(".claude").display().to_string();
    meta::set(&conn, meta::SYNC_CLAUDE_DIR, &dir).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
}

/// The node's database, opened beside the node for reading: no step of
/// the schema is run on it.
fn database_of(node: &Node) -> Connection {
    let conn = Connection::open_with_flags(
        node.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    conn.busy_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    conn
}

fn schema_version(conn: &Connection) -> u32 {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}

/// Wait for `node`, started, to end by itself, and say how it ended.
fn ends_by_itself(node: &mut Node) -> std::process::ExitStatus {
    let mut child = node.child.take().unwrap();
    let began = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if began.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            panic!("the node went on:\n{}", node.log_tail());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// A node that cannot bind the port of its local API, because another
/// holds it, changes nothing (decision 2026-10-04 §10.1): the database is
/// as alpha.19 left it, byte for byte, at its schema step; step 34 is not
/// taken.
#[test]
fn a_node_that_cannot_bind_its_port_changes_nothing() {
    let mut device = node("laptop", "personal", None);
    as_alpha_19_left_it(&device);
    let database = std::fs::read(device.data_dir().join("cordelia.db")).unwrap();
    // Its data directory is open to others, as an earlier version made it.
    #[cfg(unix)]
    set_mode(&device.data_dir(), 0o775);
    // Another holds the port.
    let held = std::net::TcpListener::bind(("127.0.0.1", device.http)).unwrap();

    device.start();
    let ended = ends_by_itself(&mut device);
    assert!(!ended.success());
    let log = std::fs::read_to_string(device.log()).unwrap();
    assert!(log.contains("the node's API cannot listen at"), "{log}");
    // It says what the likely reason is, and the way on.
    let restart = cordelia_api::commands::restart_command(std::env::consts::OS);
    assert!(
        log.contains(&format!(
            "A node is probably running already, as the service: `cordelia status` says. To \
             restart it:\n  {restart}"
        )),
        "{log}"
    );
    drop(held);
    // Not the mode of its data directory either.
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&device.data_dir()), 0o775);
        assert!(!log.contains(MADE_PRIVATE), "{log}");
    }

    assert_eq!(
        std::fs::read(device.data_dir().join("cordelia.db")).unwrap(),
        database
    );
    assert_eq!(
        schema_version(&database_of(&device)),
        cordelia_storage::schema::ALPHA_19_VERSION
    );
}

/// The mode of what is at `path`, as far as who may read, write and
/// enter it.
#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// What a node's log says where it set its data directory to its owner's
/// alone.
#[cfg(unix)]
const MADE_PRIVATE: &str = "could be read, written or entered by others than its owner and its \
                            group: it is now its owner's alone (mode 0700)";

/// `cordelia init` makes the data directory its owner's alone. A node
/// that is started on one that others can read, write or enter, as an
/// earlier version made it, sets it to mode 0700 and says so once in its
/// log: at its next start there is nothing to set, and nothing is said.
/// One shared with its group, and with nobody else, is left as it is.
/// The key, the token and the database are 0600 as they were, and the
/// configuration file, which the harness keeps beside the data directory
/// and not in it, is left as it is.
#[cfg(unix)]
#[test]
fn a_node_that_starts_makes_its_data_directory_its_owners_alone() {
    let mut device = node("laptop", "personal", None);
    let data = device.data_dir();
    assert_eq!(mode_of(&data), 0o700, "as `cordelia init` made it");

    set_mode(&data, 0o775);
    set_mode(&device.config(), 0o664);
    device.start();
    wait_for("the device is up", &[&device], 30, || healthy(&device));
    assert_eq!(mode_of(&data), 0o700);
    assert_eq!(mode_of(&device.config()), 0o664);
    for file in ["identity.key", "node-token", "cordelia.db"] {
        assert_eq!(mode_of(&data.join(file)), 0o600, "{file}");
    }
    let log = std::fs::read_to_string(device.log()).unwrap();
    assert_eq!(log.matches(MADE_PRIVATE).count(), 1, "{log}");

    // Started again: it is its owner's alone already.
    device.stop();
    device.start();
    wait_for("the device is up again", &[&device], 30, || {
        healthy(&device)
    });
    assert_eq!(mode_of(&data), 0o700);
    let log = std::fs::read_to_string(device.log()).unwrap();
    assert_eq!(log.matches(MADE_PRIVATE).count(), 0, "{log}");

    // Shared with its group on purpose, and open to nobody else: it is
    // left as it is, at every start, and nothing is said.
    device.stop();
    set_mode(&data, 0o750);
    device.start();
    wait_for("the device is up a third time", &[&device], 30, || {
        healthy(&device)
    });
    assert_eq!(mode_of(&data), 0o750);
    let log = std::fs::read_to_string(device.log()).unwrap();
    assert_eq!(log.matches(MADE_PRIVATE).count(), 0, "{log}");
    assert!(
        !log.contains("could be read, written or entered by others"),
        "{log}"
    );
}

/// A second node started on the data directory of one that runs says so
/// and changes nothing (decision 2026-10-04 §10.1): the first holds the
/// lock for as long as it runs, and goes on. Once the first has stopped,
/// a node starts there as any does.
#[test]
fn a_second_node_on_the_same_data_directory_says_so_and_changes_nothing() {
    let mut device = node("laptop", "personal", None);
    device.start();
    wait_for("device healthy", &[&device], 30, || healthy(&device));
    let token = device.token();

    let (ended, said) = device.second_on_its_data_dir();
    assert_eq!(ended, Some(false), "{said}");
    assert!(
        said.contains("another node is running on the data directory"),
        "{said}"
    );
    assert!(said.contains("Nothing was changed."), "{said}");
    assert_eq!(device.token(), token);
    wait_for("the first goes on", &[&device], 30, || healthy(&device));

    // With the first stopped, the directory is free again.
    device.stop();
    device.start();
    wait_for("device healthy again", &[&device], 30, || healthy(&device));
}

/// What a node says of itself to `cordelia status --json`.
fn status_of(node: &Node) -> serde_json::Value {
    serde_json::from_str(&node.cli(&["status", "--json"])).unwrap()
}

/// A node that is held up is red whatever sync says (decision 2026-10-04
/// §10.1): `cordelia status` gives the level red and the state
/// `attention`, with `says` in the line, which is drawn in red, and the
/// bar is `active`.
fn held_up_is_red(node: &Node, says: &str) {
    let status = status_of(node);
    assert_eq!(
        (&status["level"], &status["state"]),
        (&serde_json::json!("red"), &serde_json::json!("attention")),
        "{status}"
    );
    assert_eq!(status["summary"], says, "{status}");
    assert_eq!(status["holds"][0]["what"], "held", "{status}");
    let line = node.cli(&["status", "--line"]);
    assert!(line.contains(&format!("▲ {says}")), "{line}");
    let bar: serde_json::Value = serde_json::from_str(&node.cli(&["status", "--waybar"])).unwrap();
    assert_eq!(
        bar["class"],
        serde_json::json!(["attention", "red", "active"]),
        "{bar}"
    );
}

/// Leave `node`'s database as a later version of the program would: with
/// a table that this version does not know, at a schema version above
/// this one's. Returns that version, and the bytes of the file.
fn as_a_later_version_left_it(node: &Node) -> (u32, Vec<u8>) {
    let later = cordelia_storage::schema::SCHEMA_VERSION + 3;
    let path = node.data_dir().join("cordelia.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE of_a_later_version (what TEXT);
             INSERT INTO of_a_later_version VALUES ('kept');",
        )
        .unwrap();
        cordelia_storage::meta::set(&conn, cordelia_storage::meta::SYNC_CLAUDE_DIR, "/a/dir")
            .unwrap();
        conn.pragma_update(None, "user_version", later).unwrap();
    }
    (later, std::fs::read(&path).unwrap())
}

/// A database from a later version is refused by the node, which stays
/// up and says so, and by each command that opens the database itself
/// (decision 2026-10-04 §10.1): both versions are named, and nothing is
/// changed. A node of a role that carries what others hand it does not
/// start without its database: it says the same, and stops.
#[test]
fn a_database_from_a_later_version_is_refused_by_the_node_and_by_each_command() {
    let mut device = node("laptop", "personal", None);
    let (later, database) = as_a_later_version_left_it(&device);
    let own = cordelia_storage::schema::SCHEMA_VERSION;
    let named = |said: &str| {
        for words in [
            format!(
                "is from a later version of Cordelia than this one: it is at schema version {later}"
            ),
            format!("this is Cordelia {VERSION}, which knows schema version {own} and none after"),
            "Nothing was changed.".to_string(),
        ] {
            assert!(said.contains(&words), "{words:?} is not in:\n{said}");
        }
    };
    let unchanged = |device: &Node| {
        assert_eq!(
            std::fs::read(device.data_dir().join("cordelia.db")).unwrap(),
            database
        );
    };
    let token = device.token();

    // Each command that opens the database itself.
    named(&device.refused(&["channels"]));
    named(&device.refused(&["stats"]));
    named(&device.refused(&["init", "--force"]));
    assert_eq!(device.token(), token);
    // `cordelia status` says so where it would have read the database,
    // and goes on.
    let said = device.cli(&["status"]);
    named(&said);
    assert!(said.contains("Not read:"), "{said}");
    assert!(said.contains("Running:   no"), "{said}");
    unchanged(&device);

    // The node stays up, and says so. It takes no request but those of
    // its status: turning sync off is refused too.
    device.start();
    wait_for("device healthy", &[&device], 30, || healthy(&device));
    let status = status_of(&device);
    assert_eq!(status["state"], "attention", "{status}");
    assert_eq!(
        status["summary"], "memory not syncing: the database is from a later version",
        "{status}"
    );
    assert_eq!(status["held"]["by"], "later_database", "{status}");
    named(status["held"]["why"].as_str().unwrap());
    // It is red, though the node refuses the request that would say
    // whether sync is on.
    held_up_is_red(
        &device,
        "memory not syncing: the database is from a later version",
    );
    let said = device.cli(&["status"]);
    assert!(said.contains("Held up:   the database at"), "{said}");
    for refused in [
        &["sync", "off"][..],
        &["sync", "claude"],
        &["devices"],
        &["sync", "status"],
    ] {
        named(&device.refused(refused));
    }
    // A cycle would have run by now: none has, and nothing was tried.
    std::thread::sleep(std::time::Duration::from_secs(
        cordelia_sync::claude::CYCLE_SECS + 1,
    ));
    assert_eq!(status_of(&device)["held"]["by"], "later_database");
    device.stop();
    unchanged(&device);

    // A relay does not start on one: it says why, and stops.
    let mut relay = node("relay", "relay", None);
    let (_, database) = as_a_later_version_left_it(&relay);
    relay.start();
    assert!(!ends_by_itself(&mut relay).success());
    named(&std::fs::read_to_string(relay.log()).unwrap());
    assert_eq!(
        std::fs::read(relay.data_dir().join("cordelia.db")).unwrap(),
        database
    );
}

/// Leave `node`'s database as alpha.18 left one: at schema step 32. Returns
/// the bytes of the file.
fn as_alpha_18_left_it(node: &Node) -> Vec<u8> {
    as_alpha_19_left_it(node);
    let path = node.data_dir().join("cordelia.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 32).unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }
    std::fs::read(&path).unwrap()
}

/// A database from a Cordelia before alpha.19 is refused by the node, which
/// stays up, held, and says so, and by each command that opens the
/// database itself, in the words of decision 2026-11-10 (older kind), rule
/// 6: this version cannot open it and changed nothing, and the two ways
/// on, with the data directory. Nothing is changed. The log names the
/// step. A node of a role that carries what others hand it does not start
/// without its database: it says the same, and stops.
#[test]
fn a_database_from_before_alpha_19_is_refused_by_the_node_and_by_each_command() {
    let mut device = node("laptop", "personal", None);
    let database = as_alpha_18_left_it(&device);
    let named = |said: &str, data: &Path| {
        for words in [
            "This database is from a Cordelia before 0.2.0-alpha.19. This version cannot open \
             it, and changed nothing."
                .to_string(),
            "To keep it: install 0.2.0-alpha.19 (`CORDELIA_VERSION=v0.2.0-alpha.19`, for the \
             install command or a relay's image), start it once, then install this version \
             again."
                .to_string(),
            format!(
                "Or start afresh: move {} aside and run `cordelia init`. Then run `cordelia \
                 phrase` on your first device, add this one from another of yours, or run \
                 `cordelia recover`.",
                data.display()
            ),
        ] {
            assert!(said.contains(&words), "{words:?} is not in:\n{said}");
        }
    };
    let data = device.data_dir();
    let unchanged = |device: &Node| {
        assert_eq!(
            std::fs::read(device.data_dir().join("cordelia.db")).unwrap(),
            database
        );
    };
    let token = device.token();

    // Each command that opens the database itself.
    named(&device.refused(&["channels"]), &data);
    named(&device.refused(&["stats"]), &data);
    named(&device.refused(&["init", "--force"]), &data);
    assert_eq!(device.token(), token);
    // `cordelia status` says so where it would have read the database,
    // and goes on.
    let said = device.cli(&["status"]);
    named(&said, &data);
    assert!(said.contains("Not read:"), "{said}");
    unchanged(&device);

    // The node stays up, held, and says so. It takes no request but those
    // of its status. Its log names the step.
    device.start();
    wait_for("device healthy", &[&device], 30, || healthy(&device));
    let says = "memory not syncing: the database is from before 0.2.0-alpha.19";
    let status = status_of(&device);
    assert_eq!(status["held"]["by"], "earlier_database", "{status}");
    named(status["held"]["why"].as_str().unwrap(), &data);
    held_up_is_red(&device, says);
    let log = std::fs::read_to_string(device.log()).unwrap();
    assert!(log.contains("the database is at schema step 32"), "{log}");
    for refused in [
        &["sync", "off"][..],
        &["sync", "claude"],
        &["devices"],
        &["sync", "status"],
    ] {
        named(&device.refused(refused), &data);
    }
    // With the node running, a command says the same.
    named(&device.refused(&["stats"]), &data);
    // A cycle would have run by now: none has, and nothing was tried.
    std::thread::sleep(std::time::Duration::from_secs(
        cordelia_sync::claude::CYCLE_SECS + 1,
    ));
    assert_eq!(status_of(&device)["held"]["by"], "earlier_database");
    device.stop();
    unchanged(&device);

    // A relay does not start on one: it says why, names the step in its
    // log, and stops.
    let mut relay = node("relay", "relay", None);
    let database = as_alpha_18_left_it(&relay);
    relay.start();
    assert!(!ends_by_itself(&mut relay).success());
    let log = std::fs::read_to_string(relay.log()).unwrap();
    named(&log, &relay.data_dir());
    assert!(log.contains("the database is at schema step 32"), "{log}");
    assert_eq!(
        std::fs::read(relay.data_dir().join("cordelia.db")).unwrap(),
        database
    );
}
