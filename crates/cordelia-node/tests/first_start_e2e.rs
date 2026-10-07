//! A node's first start on this version, with real processes (decision
//! 2026-10-04 §10.1): a personal node whose database is in the released
//! version's form copies it and moves it on, once, after the port of its
//! local API is bound; a relay makes no copy and takes no step.
//!
//! Every node is a process of its own, started through the harness on
//! this machine, with a relay of the test's own where it has one.

mod common;

use std::path::Path;

use common::*;
use cordelia_storage::first_start::{self, released};
use rusqlite::Connection;

/// The version of the node that these tests start: their own.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Put a database and key files in the released version's form in the
/// place of the database that `cordelia init` made for `node`, which has
/// not been started. Its key, its token and its configuration stay.
///
/// Sync is on there for the Claude Code directory of the node's own home,
/// which is the test's, and the folder `work/lab` in that home is mapped
/// to the name `lab`: no folder of whoever runs the tests is named.
fn in_the_released_form(node: &Node) -> Connection {
    use cordelia_storage::meta;
    let data = node.data_dir();
    for file in ["cordelia.db", "cordelia.db-wal", "cordelia.db-shm"] {
        let _ = std::fs::remove_file(data.join(file));
    }
    let conn = released::database(&data.join("cordelia.db")).unwrap();
    released::fill(&conn, &data).unwrap();
    let home = node.home();
    let dir = home.join(".claude").display().to_string();
    meta::set(&conn, meta::SYNC_CLAUDE_DIR, &dir).unwrap();
    let mapped = serde_json::json!([{ "folder": lab_of(node), "name": "lab" }]);
    meta::set(&conn, meta::SYNC_CLAUDE_MAPPINGS, &mapped.to_string()).unwrap();
    conn
}

/// The folder in `node`'s home that is mapped to the name `lab`.
fn lab_of(node: &Node) -> String {
    node.home().join("work/lab").display().to_string()
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

fn rows(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

/// How many rows each table of the older kind holds, by its name.
fn older_rows(conn: &Connection) -> Vec<(&'static str, i64)> {
    first_start::OLDER_TABLES
        .iter()
        .chain(&first_start::AGREED_TABLES)
        .map(|table| (*table, rows(conn, table)))
        .collect()
}

fn schema_version(conn: &Connection) -> u32 {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}

/// The names in a folder, in order.
fn names_in(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The names in a node's folder that are of a copy.
fn copies_of(node: &Node) -> Vec<String> {
    let mut names = names_in(&node.data_dir());
    names.retain(|name| name.starts_with("before-"));
    names
}

fn has_guard(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = ?1)",
        [first_start::GUARD],
        |row| row.get(0),
    )
    .unwrap()
}

/// A device whose database is in the released version's form is started
/// on this version (decision 2026-10-04 §10.1). The copy is there, with
/// every older row and each key file. Every older row and the older key
/// files are gone from the node's own, and its key, its token and its
/// configuration are as they were. A second start changes nothing, and
/// makes no second copy.
#[test]
fn a_device_of_the_released_version_is_copied_and_moved_on_when_it_starts() {
    let relay = relay_started();
    let mut device = node("laptop", "personal", Some(relay.p2p));
    let before = {
        let conn = in_the_released_form(&device);
        assert_eq!(schema_version(&conn), 10);
        older_rows(&conn)
    };
    assert!(before.iter().all(|(_, rows)| *rows > 0), "{before:?}");
    let own = |device: &Node| -> Vec<Vec<u8>> {
        [
            device.data_dir().join("identity.key"),
            device.data_dir().join("node-token"),
            device.config(),
        ]
        .iter()
        .map(|file| std::fs::read(file).unwrap())
        .collect()
    };
    let own_before = own(&device);

    device.start();
    wait_for("device healthy", &[&relay, &device], 30, || {
        healthy(&device)
    });

    // The copy, beside the database: at this schema's version, with every
    // older row and each key file.
    let name = format!("before-{VERSION}");
    assert_eq!(copies_of(&device), std::slice::from_ref(&name));
    let copy = device.data_dir().join(&name);
    assert_eq!(names_in(&copy), ["channel-keys", "cordelia.db"]);
    assert_eq!(names_in(&copy.join("channel-keys")), released::KEY_FILES);
    {
        let copied = Connection::open_with_flags(
            copy.join("cordelia.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(
            schema_version(&copied),
            cordelia_storage::schema::SCHEMA_VERSION
        );
        assert_eq!(older_rows(&copied), before);
        assert_eq!(first_start::mark(&copied).unwrap(), None);
    }
    // The node's own: nothing of the older kind, the mark, and the guard.
    {
        let conn = database_of(&device);
        let now = older_rows(&conn);
        assert!(now.iter().all(|(_, rows)| *rows == 0), "{now:?}");
        let mark = first_start::mark(&conn).unwrap().unwrap();
        assert_eq!((mark.stepped, mark.version.as_str()), (true, VERSION));
        assert!(has_guard(&conn));
    }
    assert!(names_in(&device.data_dir().join("channel-keys")).is_empty());
    assert_eq!(own(&device), own_before);

    // A second start changes nothing, and makes no second copy.
    let copied = std::fs::read(copy.join("cordelia.db")).unwrap();
    device.stop();
    device.start();
    wait_for("device healthy again", &[&relay, &device], 30, || {
        healthy(&device)
    });
    assert_eq!(copies_of(&device), [name]);
    assert_eq!(std::fs::read(copy.join("cordelia.db")).unwrap(), copied);
    assert_eq!(own(&device), own_before);
    // A key file of an older channel that is found at a later start is
    // removed then, whatever the mark says.
    device.stop();
    let left = device.data_dir().join("channel-keys").join("grp_lab.key");
    std::fs::write(&left, [1u8; 32]).unwrap();
    device.start();
    wait_for(
        "device healthy a third time",
        &[&relay, &device],
        30,
        || healthy(&device),
    );
    assert!(!left.exists());
}

/// A node that cannot bind the port of its local API, because another
/// holds it, changes nothing (decision 2026-10-04 §10.1): the database is
/// as it was, at the released version's schema, with every older row and
/// each key file; there is no copy and no mark.
#[test]
fn a_node_that_cannot_bind_its_port_changes_nothing() {
    let mut device = node("laptop", "personal", None);
    let before = {
        let conn = in_the_released_form(&device);
        older_rows(&conn)
    };
    let database = std::fs::read(device.data_dir().join("cordelia.db")).unwrap();
    // Another holds the port.
    let held = std::net::TcpListener::bind(("127.0.0.1", device.http)).unwrap();

    device.start();
    let mut child = device.child.take().unwrap();
    let began = std::time::Instant::now();
    let ended = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if began.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            panic!(
                "the node went on though its port was held:\n{}",
                device.log_tail()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    assert!(!ended.success());
    let log = std::fs::read_to_string(device.log()).unwrap();
    assert!(log.contains("the node's API cannot listen at"), "{log}");
    drop(held);

    assert_eq!(
        std::fs::read(device.data_dir().join("cordelia.db")).unwrap(),
        database
    );
    assert!(copies_of(&device).is_empty());
    assert_eq!(
        names_in(&device.data_dir().join("channel-keys")),
        released::KEY_FILES
    );
    let conn = database_of(&device);
    assert_eq!(schema_version(&conn), 10);
    assert_eq!(older_rows(&conn), before);
}

/// A relay's database is stepped as any version steps it: it keeps every
/// older row and each key file, makes no copy, and has no mark (decision
/// 2026-10-04 §10.1). A relay goes on carrying the older kind.
#[test]
fn a_relay_keeps_every_older_row_and_makes_no_copy() {
    let mut relay = node("relay", "relay", None);
    let before = {
        let conn = in_the_released_form(&relay);
        older_rows(&conn)
    };
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    relay.stop();

    let conn = database_of(&relay);
    assert_eq!(
        schema_version(&conn),
        cordelia_storage::schema::SCHEMA_VERSION
    );
    assert_eq!(older_rows(&conn), before);
    assert_eq!(first_start::mark(&conn).unwrap(), None);
    assert!(!has_guard(&conn));
    assert!(copies_of(&relay).is_empty());
    assert_eq!(
        names_in(&relay.data_dir().join("channel-keys")),
        released::KEY_FILES
    );
}

/// A relay that is started on a database which a personal node moved on
/// removes the guard (decision 2026-10-04 §10.1): the guard is a
/// device's, and a relay takes channels of the older kind.
#[test]
fn a_relay_that_is_started_on_a_devices_database_removes_the_guard() {
    let mut relay = node("relay", "relay", None);
    drop(in_the_released_form(&relay));
    {
        let conn = cordelia_storage::db::open(&relay.data_dir().join("cordelia.db")).unwrap();
        let moved_on =
            first_start::first_start(&conn, &relay.data_dir(), VERSION, chrono::Utc::now());
        assert!(moved_on.is_ok(), "{moved_on:?}");
        assert!(has_guard(&conn));
    }
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    relay.stop();

    let conn = Connection::open(relay.data_dir().join("cordelia.db")).unwrap();
    assert!(!has_guard(&conn));
    // A channel of the older kind can be made there again.
    conn.execute(
        "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                               created_at, updated_at)
         VALUES ('grp_new', 'group', 'realtime', 'invite_only', X'AA', '2026-10-07', '2026-10-07')",
        [],
    )
    .unwrap();
    let log = std::fs::read_to_string(relay.log()).unwrap();
    assert!(
        log.contains("removed the guard that a personal node set on this database"),
        "{log}"
    );
}

/// What a node says of itself to `cordelia status --json`.
fn status_of(node: &Node) -> serde_json::Value {
    serde_json::from_str(&node.cli(&["status", "--json"])).unwrap()
}

/// Until its first start on this version has succeeded a node stays up,
/// runs no cycle and no pass, refuses every request that changes
/// anything except one that turns sync off, and says why in its status
/// (decision 2026-10-04 §10.1). It tries again each time a cycle would
/// have run: once the copy can be made, it is made and the step taken,
/// with no restart.
#[cfg(unix)]
#[test]
fn a_node_whose_first_start_cannot_be_made_stays_up_and_makes_it_once_it_can() {
    use std::os::unix::fs::PermissionsExt;
    let relay = relay_started();
    let mut device = node("laptop", "personal", Some(relay.p2p));
    let before = {
        let conn = in_the_released_form(&device);
        older_rows(&conn)
    };
    // What is left of a copy cannot be removed: a folder in it cannot be
    // looked into.
    let partial = format!("before-{VERSION}.partial");
    let closed = device.data_dir().join(&partial).join("closed");
    std::fs::create_dir_all(&closed).unwrap();
    std::fs::write(closed.join("a-file"), "x").unwrap();
    let mode = |mode: u32| {
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    mode(0o000);

    device.start();
    let all = [&relay, &device];
    wait_for("device healthy", &all, 30, || healthy(&device));

    // It stays up, and says why, with the room that the copy needs.
    let status = status_of(&device);
    assert_eq!(status["state"], "attention", "{status}");
    assert_eq!(
        status["summary"], "memory not syncing: the first start on this version is not done",
        "{status}"
    );
    assert_eq!(status["held"]["by"], "first_start", "{status}");
    let why = status["held"]["why"].as_str().unwrap().to_string();
    assert!(
        why.starts_with("the first start on this version is not done: the copy of the database"),
        "{why}"
    );
    assert!(why.contains("bytes of room"), "{why}");
    let said = device.cli(&["status"]);
    assert!(said.contains(&format!("Held up:   {why}")), "{said}");
    let line = device.cli(&["status", "--line"]);
    assert!(
        line.contains("the first start on this version is not done"),
        "{line}"
    );

    // Nothing was changed: every older row and each key file is there,
    // and there is no mark.
    let unchanged = |device: &Node| {
        let conn = database_of(device);
        assert_eq!(older_rows(&conn), before);
        assert_eq!(first_start::mark(&conn).unwrap(), None);
        assert_eq!(
            names_in(&device.data_dir().join("channel-keys")),
            released::KEY_FILES
        );
        assert_eq!(copies_of(device), std::slice::from_ref(&partial));
    };
    unchanged(&device);

    // A request that changes anything is refused, with why: a mapping,
    // and sync turned on.
    let other = device.home().join("work/other").display().to_string();
    std::fs::create_dir_all(&other).unwrap();
    let refused = device.refused(&["sync", "map", &other, "notes"]);
    assert!(
        refused.contains("the first start on this version is not done"),
        "{refused}"
    );
    let dir = device.home().join(".claude").display().to_string();
    let refused = device.refused(&["sync", "claude", "--dir", &dir]);
    assert!(
        refused.contains("the first start on this version is not done"),
        "{refused}"
    );
    // No cycle has run: the stored report is the one the released
    // version left, though a cycle would have run several times by now.
    std::thread::sleep(std::time::Duration::from_secs(
        2 * cordelia_sync::claude::CYCLE_SECS + 1,
    ));
    let sync = device.post("/api/v1/sync/status", serde_json::json!({}));
    assert_eq!(
        sync["report"]["at"], "2026-10-05T09:12:44.512203817+00:00",
        "{sync}"
    );
    assert_eq!(sync["enabled"], true, "{sync}");
    unchanged(&device);
    // And it has tried again, and said the reason once.
    let log = std::fs::read_to_string(device.log()).unwrap();
    assert_eq!(
        log.matches("the first start on this version is not done")
            .count(),
        1,
        "{log}"
    );

    // Turning sync off is taken.
    let off = device.cli(&["sync", "off"]);
    assert!(off.contains("Sync is off."), "{off}");
    let sync = device.post("/api/v1/sync/status", serde_json::json!({}));
    assert_eq!(sync["enabled"], false, "{sync}");
    assert_eq!(
        sync["report"]["at"], "2026-10-05T09:12:44.512203817+00:00",
        "{sync}"
    );

    // The copy can be made: the node makes its first start by itself.
    mode(0o700);
    wait_for("the node makes its first start", &all, 30, || {
        status_of(&device)["held"].is_null().then_some(())
    });
    assert_eq!(copies_of(&device), [format!("before-{VERSION}")]);
    let conn = database_of(&device);
    let now = older_rows(&conn);
    assert!(now.iter().all(|(_, rows)| *rows == 0), "{now:?}");
    let mark = first_start::mark(&conn).unwrap().unwrap();
    assert_eq!((mark.stepped, mark.version.as_str()), (true, VERSION));
    assert!(names_in(&device.data_dir().join("channel-keys")).is_empty());
    let status = status_of(&device);
    assert_eq!(status["summary"], "memory sync off", "{status}");
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
        assert!(copies_of(device).is_empty());
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
    let mut child = relay.child.take().unwrap();
    let began = std::time::Instant::now();
    let ended = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if began.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            panic!("the relay went on:\n{}", relay.log_tail());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    assert!(!ended.success());
    named(&std::fs::read_to_string(relay.log()).unwrap());
    assert_eq!(
        std::fs::read(relay.data_dir().join("cordelia.db")).unwrap(),
        database
    );
}

/// `cordelia swarm-init` opens the database before it writes anything:
/// one from a later version is refused, and no key and no token is
/// written (decision 2026-10-04 §10.1). The node is of a role that
/// carries the older kind: on a personal node the command sets up
/// nothing at all.
#[test]
fn a_swarm_node_is_not_set_up_over_a_database_from_a_later_version() {
    let lead = node("lead", "personal", None);
    let child = node("child", "relay", None);
    let (later, database) = as_a_later_version_left_it(&child);
    // A folder that holds a database and no key yet.
    for file in ["identity.key", "node-token"] {
        std::fs::remove_file(child.data_dir().join(file)).unwrap();
    }
    let lead_key = lead.data_dir().join("identity.key").display().to_string();
    let out = child.command(&[
        "swarm-init",
        "--index",
        "1",
        "--lead-identity",
        &lead_key,
        "--lead-entity-id",
        "lead",
    ]);
    assert!(!out.status.success());
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains(&format!("it is at schema version {later}")),
        "{said}"
    );
    assert!(said.contains("Nothing was changed."), "{said}");
    for file in ["identity.key", "node-token"] {
        assert!(!child.data_dir().join(file).exists(), "{file}");
    }
    assert_eq!(
        std::fs::read(child.data_dir().join("cordelia.db")).unwrap(),
        database
    );
}

/// A personal node carries no channel of the older kind, and the commands
/// that read or wrote that kind say what a device has now (decision
/// 2026-10-04 §10): `cordelia channels` and `cordelia stats` say the
/// names it holds and the entries of its own channels, and `cordelia
/// swarm-init` sets up nothing. None of them writes: after the first
/// start's step the tables of the older kind are empty, and stay so.
#[test]
fn the_commands_of_the_older_kind_say_what_a_device_has_now_and_write_nothing() {
    let relay = relay_started();
    let mut device = node("laptop", "personal", Some(relay.p2p));
    drop(in_the_released_form(&device));
    device.start();
    wait_for("device healthy", &[&relay, &device], 30, || {
        healthy(&device)
    });
    let nothing_older = |device: &Node| {
        let now = older_rows(&database_of(device));
        assert!(now.iter().all(|(_, rows)| *rows == 0), "{now:?}");
        assert!(names_in(&device.data_dir().join("channel-keys")).is_empty());
    };
    nothing_older(&device);

    // It follows no phrase yet, and so holds no name.
    let channels = device.cli(&["channels"]);
    assert!(channels.starts_with("No names."), "{channels}");
    assert!(!channels.contains("cordelia subscribe"), "{channels}");
    let stats = device.cli(&["stats"]);
    assert!(stats.contains("Names:            0 held"), "{stats}");
    assert!(stats.contains("Stored:           0 entries"), "{stats}");
    let stats: serde_json::Value = serde_json::from_str(&device.cli(&["stats", "--json"])).unwrap();
    assert_eq!(stats["channels_subscribed"], 0, "{stats}");
    assert_eq!(stats["items_stored"], 0, "{stats}");
    let status = device.get("/api/v1/status").unwrap();
    assert_eq!(status["channels_subscribed"], 0, "{status}");
    let metrics = device.get_text("/api/v1/metrics");
    assert!(
        metrics.contains("cordelia_channels_subscribed 0"),
        "{metrics}"
    );

    // `cordelia swarm-init` sets up nothing on it, and says why.
    let lead_key = device.data_dir().join("identity.key").display().to_string();
    let key = std::fs::read(device.data_dir().join("identity.key")).unwrap();
    let out = device.command(&[
        "swarm-init",
        "--index",
        "1",
        "--lead-identity",
        &lead_key,
        "--lead-entity-id",
        "lead",
    ]);
    assert!(!out.status.success());
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("a personal node carries no swarm channel in this version"),
        "{said}"
    );
    assert_eq!(
        std::fs::read(device.data_dir().join("identity.key")).unwrap(),
        key
    );
    nothing_older(&device);
    // With no key yet in the node's folder, too: nothing is written.
    let fresh = node("another", "personal", None);
    for file in ["identity.key", "node-token"] {
        std::fs::remove_file(fresh.data_dir().join(file)).unwrap();
    }
    let out = fresh.command(&[
        "swarm-init",
        "--index",
        "1",
        "--lead-identity",
        &lead_key,
        "--lead-entity-id",
        "lead",
    ]);
    assert!(!out.status.success());
    for file in ["identity.key", "node-token"] {
        assert!(!fresh.data_dir().join(file).exists(), "{file}");
    }
    assert!(names_in(&fresh.data_dir().join("channel-keys")).is_empty());
}
