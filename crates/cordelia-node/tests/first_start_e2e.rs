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
    // The node answers from the moment its port is bound: the copy and
    // the step are made by then, or are being made, and its status says
    // which.
    wait_for("the first start is made", &[&relay, &device], 60, || {
        status_of(&device)["held"].is_null().then_some(())
    });
    // What the schema's steps said when the database was opened is in
    // the log: logging is set up before that.
    let log = std::fs::read_to_string(device.log()).unwrap();
    assert!(
        log.contains("applying migration v11 (entries of a channel from its secret)"),
        "{log}"
    );

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

    // The device follows no phrase: it is not added yet, and says so.
    // Its state asks for the person, and nothing is published or
    // fetched.
    let status = wait_for(
        "the device says where it stands",
        &[&relay, &device],
        30,
        || {
            let status = status_of(&device);
            (status["sync"]["stands"] == "no_phrase").then_some(status)
        },
    );
    assert_eq!(status["state"], "attention", "{status}");
    assert_eq!(status["summary"], "memory: not added yet", "{status}");
    assert_eq!(status["sync"]["moved_on"], true, "{status}");
    assert_eq!(status["person"]["state"], "no_phrase", "{status}");
    assert_eq!(status["person"]["short"], "not added yet", "{status}");
    assert_eq!(status["outbox_waiting"], 0, "{status}");
    let said = device.cli(&["status"]);
    assert!(said.contains("Devices:   not added yet"), "{said}");
    assert!(
        said.contains(
            "not added yet: this device has taken a version of Cordelia in which every device \
             is added again, and memory stays on this machine until it is."
        ),
        "{said}"
    );
    let devices = device.cli(&["devices"]);
    assert!(devices.contains("not added yet:"), "{devices}");
    let sync = wait_for("a cycle has run", &[&relay, &device], 30, || {
        let out = device.cli(&["sync", "status"]);
        out.contains("Nothing is sent from this device")
            .then_some(out)
    });
    assert!(sync.contains("not added yet"), "{sync}");
    // The relay was shown nothing, and holds nothing of it.
    let held: serde_json::Value = serde_json::from_str(&relay.cli(&["stats", "--json"])).unwrap();
    assert_eq!(held["items_stored"], 0, "{held}");
    {
        let conn = database_of(&relay);
        assert_eq!(rows(&conn, "entries"), 0);
        assert_eq!(rows(&conn, "items"), 0);
    }
    {
        let conn = database_of(&device);
        assert_eq!(rows(&conn, "entries"), 0);
        assert_eq!(rows(&conn, "person"), 0);
    }

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
    // The guard is a device's, and a device's start leaves it.
    assert!(has_guard(&database_of(&device)));
    // A key file of an older channel that is found at a later start is
    // removed then, whatever the mark says, where the copy holds it: one
    // that the copy holds under that name with the same bytes goes, and
    // one that no copy holds is left in place, and the status says so.
    device.stop();
    let keys = device.data_dir().join("channel-keys");
    let (held, not_held) = (keys.join("grp_lab.key"), keys.join("grp_since.key"));
    std::fs::copy(copy.join("channel-keys").join("grp_lab.key"), &held).unwrap();
    std::fs::write(&not_held, [1u8; 32]).unwrap();
    device.start();
    wait_for(
        "device healthy a third time",
        &[&relay, &device],
        30,
        || healthy(&device),
    );
    assert!(!held.exists());
    assert_eq!(std::fs::read(&not_held).unwrap(), [1u8; 32]);
    let status = status_of(&device);
    assert_eq!(status["key_files_in_place"], 1, "{status}");
    let said = device.cli(&["status"]);
    assert!(
        said.contains("Key files: 1 key file of an older version was left in place"),
        "{said}"
    );
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
    // Its data directory is open to others, as an earlier version made it.
    #[cfg(unix)]
    set_mode(&device.data_dir(), 0o775);
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
    assert!(copies_of(&device).is_empty());
    assert_eq!(
        names_in(&device.data_dir().join("channel-keys")),
        released::KEY_FILES
    );
    let conn = database_of(&device);
    assert_eq!(schema_version(&conn), 10);
    assert_eq!(older_rows(&conn), before);
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
const MADE_PRIVATE: &str = "could be read, written or entered by others: it is now its owner's \
                            alone (mode 0700)";

/// `cordelia init` makes the data directory its owner's alone. A node
/// that is started on one that others can read, write or enter, as an
/// earlier version made it, sets it to mode 0700 and says so once in its
/// log: at its next start there is nothing to set, and nothing is said.
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
}

/// A node answers from the moment its port is bound, while the copy of
/// its first start is still being made (decision 2026-10-04 §10.1): its
/// status says that a copy is being made, a command that asks how it
/// stands is told so, and a request that changes anything is refused, as
/// by any node whose first start has not succeeded. Here the database is
/// large enough for the copy to take a while.
#[test]
fn a_node_answers_while_the_copy_of_its_first_start_is_being_made() {
    let mut device = node("laptop", "personal", None);
    {
        let conn = in_the_released_form(&device);
        conn.execute_batch("CREATE TABLE ballast (held BLOB NOT NULL);")
            .unwrap();
        for _ in 0..96 {
            conn.execute("INSERT INTO ballast VALUES (randomblob(1048576))", [])
                .unwrap();
        }
    }
    let other = device.home().join("work/other").display().to_string();
    std::fs::create_dir_all(&other).unwrap();

    device.start();
    // Asked as often as it can be, from the first answer on.
    let began = std::time::Instant::now();
    let mut under_way = None;
    loop {
        assert!(
            began.elapsed() < std::time::Duration::from_secs(120),
            "the node never made its first start:\n{}",
            device.log_tail()
        );
        let Some(status) = device.get("/api/v1/status") else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        };
        let Some(why) = status["held"]["why"].as_str() else {
            break;
        };
        assert_eq!(status["held"]["by"], "first_start", "{status}");
        assert!(why.contains("is under way"), "{why}");
        if under_way.is_none() {
            // A command is told how the node stands, and one that
            // changes anything is refused with the same words.
            let said = device.cli(&["status"]);
            let refused = device.command(&["sync", "map", &other, "notes"]);
            under_way = Some((why.to_string(), said, refused));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let (why, said, refused) = under_way.expect("the node answered only once the copy was made");
    assert!(
        why.contains("a copy of the database from before this version is being made"),
        "{why}"
    );
    // (A command that was asked as the copy ended may have found the
    // node done: what it said then is not judged.)
    if said.contains("Held up:") {
        assert!(said.contains("is under way"), "{said}");
    }
    if !refused.status.success() {
        let refused = String::from_utf8_lossy(&refused.stderr);
        assert!(refused.contains("is under way"), "{refused}");
    }
    // The copy was made whole, and the step taken.
    assert_eq!(copies_of(&device), [format!("before-{VERSION}")]);
    let copy = device.data_dir().join(format!("before-{VERSION}"));
    let copied = Connection::open_with_flags(
        copy.join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(rows(&copied, "ballast"), 96);
    let conn = database_of(&device);
    let mark = first_start::mark(&conn).unwrap().unwrap();
    assert_eq!((mark.stepped, mark.version.as_str()), (true, VERSION));
}

/// A data directory is one node's (decision 2026-10-04 §10.1): a second
/// node that is started on the directory of one that runs, with ports of
/// its own, says so and stops, and has changed nothing. Here the first
/// is held up before its first start, so that anything the second did to
/// the database would show: every older row and each key file is there,
/// there is no mark, and no second copy was begun. Once the first has
/// stopped, a node starts there as any does.
#[cfg(unix)]
#[test]
fn a_second_node_on_the_same_data_directory_says_so_and_changes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let mut device = node("laptop", "personal", None);
    let before = {
        let conn = in_the_released_form(&device);
        older_rows(&conn)
    };
    // The first cannot make its copy, and is held up: what is left of a
    // copy cannot be removed.
    let partial = format!("before-{VERSION}.partial");
    let closed = device.data_dir().join(&partial).join("closed");
    std::fs::create_dir_all(&closed).unwrap();
    std::fs::write(closed.join("a-file"), "x").unwrap();
    let mode = |mode: u32| {
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    mode(0o000);
    device.start();
    wait_for("device healthy", &[&device], 30, || healthy(&device));
    wait_for("the first try has failed", &[&device], 30, || {
        status_of(&device)["held"]["why"]
            .as_str()
            .is_some_and(|why| why.contains("is not done"))
            .then_some(())
    });
    // The second could make the copy, were it to try.
    mode(0o700);
    std::fs::remove_dir_all(device.data_dir().join(&partial)).unwrap();

    let (ended, said) = device.second_on_its_data_dir();
    assert_eq!(ended, Some(false), "{said}");
    assert!(
        said.contains("another node is running on the data directory"),
        "{said}"
    );
    assert!(said.contains("Nothing was changed."), "{said}");
    {
        let conn = database_of(&device);
        assert_eq!(older_rows(&conn), before);
        assert_eq!(first_start::mark(&conn).unwrap(), None);
    }
    assert_eq!(
        names_in(&device.data_dir().join("channel-keys")),
        released::KEY_FILES
    );
    // The first goes on, and makes its first start when it next tries.
    wait_for("the first makes its first start", &[&device], 120, || {
        status_of(&device)["held"].is_null().then_some(())
    });
    assert_eq!(copies_of(&device), [format!("before-{VERSION}")]);

    // With the first stopped, the directory is free again.
    device.stop();
    device.start();
    wait_for("device healthy again", &[&device], 30, || healthy(&device));
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
        let moved_on = first_start::first_start(
            &conn,
            &relay.data_dir(),
            VERSION,
            chrono::Utc::now(),
            &first_start::room_not_known,
            &mut None,
        );
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

/// Until its first start on this version has succeeded a node stays up,
/// runs no cycle and no pass, refuses every request that changes
/// anything except one that turns sync off, and says why in its status
/// (decision 2026-10-04 §10.1). It tries again by itself, after a wait
/// that doubles with each try that fails: once the copy can be made, it
/// is made and the step taken, with no restart.
#[cfg(unix)]
#[test]
fn a_node_whose_first_start_cannot_be_made_stays_up_and_makes_it_once_it_can() {
    use cordelia_storage::meta;
    use std::os::unix::fs::PermissionsExt;
    let relay = relay_started();
    let mut device = node("laptop", "personal", Some(relay.p2p));
    let before = {
        let conn = in_the_released_form(&device);
        // The scope is on by being absent with a directory set, as an
        // install from before mappings has it.
        meta::remove(&conn, meta::SYNC_CLAUDE_ALL).unwrap();
        older_rows(&conn)
    };
    let scope = |device: &Node| meta::get(&database_of(device), meta::SYNC_CLAUDE_ALL).unwrap();
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

    // It stays up, and says why, with the room that the copy needs and
    // the room there is. (Until its first try has failed it says that a
    // copy is being made.)
    let status = wait_for("the first try has failed", &all, 30, || {
        let status = status_of(&device);
        let not_done = status["held"]["why"]
            .as_str()
            .is_some_and(|why| why.contains("is not done"));
        not_done.then_some(status)
    });
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
    assert!(why.contains("bytes of room, and the volume has "), "{why}");
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
        // Nor is anything written of the settings: the step reads the
        // scope as it is stored.
        assert_eq!(scope(device), None);
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
    // The scope that was on by being absent is written down as on, so
    // that the step still finds it so with the directory gone.
    assert_eq!(scope(&device).as_deref(), Some("on"));
    // A node that is held up is red whatever sync says: with sync off
    // the level, the state, the line and the bar say so still.
    held_up_is_red(
        &device,
        "memory not syncing: the first start on this version is not done",
    );

    // The copy can be made: the node makes its first start by itself,
    // at its next try. (The tries back off, and several have failed by
    // now: the next is within a minute and a half of the last.)
    mode(0o700);
    wait_for("the node makes its first start", &all, 120, || {
        status_of(&device)["held"].is_null().then_some(())
    });
    assert_eq!(copies_of(&device), [format!("before-{VERSION}")]);
    let conn = database_of(&device);
    let now = older_rows(&conn);
    assert!(now.iter().all(|(_, rows)| *rows == 0), "{now:?}");
    let mark = first_start::mark(&conn).unwrap().unwrap();
    assert_eq!((mark.stepped, mark.version.as_str()), (true, VERSION));
    assert!(names_in(&device.data_dir().join("channel-keys")).is_empty());
    // Sync is off and the device follows no phrase: its state is off,
    // nothing holds, and the words still say that it is not added yet.
    let status = status_of(&device);
    assert_eq!(status["summary"], "memory: not added yet", "{status}");
    assert_eq!(status["state"], "off", "{status}");
    assert!(status["level"].is_null(), "{status}");
    // The device is left the notice of what stopped, though sync was
    // turned off before the step could be taken; and the scope is off.
    let notices = first_start::notices(&conn).unwrap();
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(
        notices[0].dir.as_deref(),
        Some(device.home().join(".claude").display().to_string().as_str())
    );
    assert_eq!(notices[0].folders.as_ref().map(Vec::len), Some(2));
    assert_eq!(scope(&device).as_deref(), Some("off"));
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

/// What `node` holds under the name `lab`, by key: each key's revision,
/// and its text.
fn held_under_lab(node: &Node) -> Vec<(String, u64, Option<String>)> {
    let answer = node.post(
        "/api/v1/channels/entries",
        serde_json::json!({ "channel": "lab" }),
    );
    let mut held: Vec<(String, u64, Option<String>)> = answer["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            (
                entry["key"].as_str().unwrap_or_default().to_string(),
                entry["rev"].as_u64().unwrap_or(0),
                entry["content"].as_str().map(str::to_string),
            )
        })
        .collect();
    held.sort();
    held
}

/// With real processes (decision 2026-10-04 §10, §10.1): a device in the
/// released version's form is started on this version, a recovery phrase
/// is made there, and its mapped folders are published as a first sync.
/// What the folder holds is the first version of each file in the name's
/// channel, at revision 1; the relay holds it; and nothing in the folder
/// is changed.
#[test]
fn a_phrase_is_made_on_a_device_of_the_released_version_and_its_folders_are_published() {
    let relay = relay_started();
    let mut device = node("laptop", "personal", Some(relay.p2p));
    drop(in_the_released_form(&device));
    // The memory of the folder that is mapped, as the device has it.
    let lab = lab_of(&device);
    std::fs::create_dir_all(&lab).unwrap();
    let memory = claude_folder(&device.home(), Path::new(&lab));
    let files = [
        ("MEMORY.md", "- [Notes](notes.md)\n"),
        ("notes.md", "what the laptop knows\n"),
    ];
    for (name, text) in files {
        std::fs::write(memory.join(name), text).unwrap();
    }
    let in_the_folder = |memory: &Path| -> Vec<(String, String)> {
        let mut all: Vec<(String, String)> = names_in(memory)
            .into_iter()
            .filter(|name| !name.starts_with('.'))
            .map(|name| {
                let text = std::fs::read_to_string(memory.join(&name)).unwrap();
                (name, text)
            })
            .collect();
        all.sort();
        all
    };
    let as_it_was = in_the_folder(&memory);
    assert_eq!(as_it_was.len(), 2);

    device.start();
    let all = [&relay, &device];
    wait_for("device healthy", &all, 30, || healthy(&device));
    wait_for("device reaches its relay", &all, 60, || {
        has_hot_peer(&device)
    });
    // Not added yet: sync is on and the folder is mapped, and nothing
    // of it is published. The folder is as it was.
    wait_for("a cycle has run", &all, 30, || {
        let out = device.cli(&["sync", "status"]);
        out.contains("Nothing is sent from this device")
            .then_some(())
    });
    assert_eq!(rows(&database_of(&device), "entries"), 0);
    assert_eq!(rows(&database_of(&relay), "entries"), 0);
    assert_eq!(in_the_folder(&memory), as_it_was);

    // The phrase is made on this device: its folders are published.
    let words = makes_a_phrase(&device, "laptop");
    assert_eq!(words.split_whitespace().count(), 12);
    wait_for("the device has published its folder", &all, 90, || {
        (held_under_lab(&device).len() == 2).then_some(())
    });
    let published = held_under_lab(&device);
    let expected: Vec<(String, u64, Option<String>)> = files
        .iter()
        .map(|(name, text)| (name.to_string(), 1, Some(text.to_string())))
        .collect();
    assert_eq!(published, expected);
    wait_for("the device has sent what it holds", &all, 90, || {
        let seen = person_of(&device);
        let relays = seen["relays"].as_array()?;
        let sent = seen["names"]["to_go"].as_array()?.is_empty()
            && seen["waiting"]
                .as_array()?
                .iter()
                .all(|relay| relay["waits"] == 0);
        (!relays.is_empty() && relays.iter().all(|relay| relay["holds_latest"] == true) && sent)
            .then_some(())
    });
    // The relay holds the change, the device's words and the two files.
    assert!(rows(&database_of(&relay), "entries") >= 4);
    // Nothing in the folder was changed, and nothing was kept beside it.
    assert_eq!(in_the_folder(&memory), as_it_was);
    // The device says what it has now.
    let status = wait_for("the device is synced", &all, 60, || {
        let status = status_of(&device);
        (status["state"] == "synced").then_some(status)
    });
    assert_eq!(status["sync"]["stands"], "applied", "{status}");
    let channels = device.cli(&["channels"]);
    assert!(
        channels.lines().any(|line| line.starts_with("lab ")),
        "{channels}"
    );
    // Nothing of the older kind came back, and the copy is as it was.
    let conn = database_of(&device);
    let older = older_rows(&conn);
    assert!(
        older
            .iter()
            .filter(|(table, _)| first_start::OLDER_TABLES.contains(table))
            .all(|(_, rows)| *rows == 0),
        "{older:?}"
    );
    assert_eq!(copies_of(&device), [format!("before-{VERSION}")]);
}

/// The stored scope is off whenever sync is on (decision 2026-10-04
/// §10.1): a node that starts with sync on writes it off, from a scope
/// that is stored on and from none stored with a directory set, as a
/// database that an earlier build left has it. With sync off it writes
/// nothing, and the command that turns sync on then does. Its first
/// start on this version is done here, and takes no part.
#[test]
fn a_node_that_starts_with_sync_on_writes_the_stored_scope_off() {
    use cordelia_storage::meta;
    let relay = relay_started();
    let mut device = device_started("laptop", &relay);
    let all = [&relay];
    let dir = device.home().join(".claude").display().to_string();
    let said = device.cli(&["sync", "claude", "--dir", &dir]);
    assert!(said.starts_with("Sync turned on.\n"), "{said}");
    let scope = |device: &Node| meta::get(&database_of(device), meta::SYNC_CLAUDE_ALL).unwrap();
    assert_eq!(scope(&device).as_deref(), Some("off"));
    // The node is stopped, and its database is left as `stored` has the
    // scope; then it is started.
    let started_from = |device: &mut Node, stored: Option<&str>| {
        device.stop();
        {
            let conn = Connection::open(device.data_dir().join("cordelia.db")).unwrap();
            match stored {
                Some(stored) => meta::set(&conn, meta::SYNC_CLAUDE_ALL, stored).unwrap(),
                None => meta::remove(&conn, meta::SYNC_CLAUDE_ALL).unwrap(),
            }
        }
        device.start();
        wait_for("device healthy", &all, 30, || healthy(device));
    };
    for stored in [Some("on"), None] {
        started_from(&mut device, stored);
        wait_for("the scope is written off", &all, 30, || {
            (scope(&device).as_deref() == Some("off")).then_some(())
        });
    }

    // With sync off nothing is written at a start: the scope is as it
    // was left. Turning sync on writes it off.
    device.cli(&["sync", "off"]);
    started_from(&mut device, Some("on"));
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert_eq!(scope(&device).as_deref(), Some("on"));
    device.cli(&["sync", "claude"]);
    assert_eq!(scope(&device).as_deref(), Some("off"));
    let status = status_of(&device);
    assert_eq!(status["sync"]["all"], false, "{status}");
}

/// The same device with the scope stored on has the notice (decision
/// 2026-10-04 §10.1): the date, the Claude Code directory, and each folder
/// that the last stored report shows as syncing without a mapping. The
/// scope is off afterwards, and the report is removed. (The notice is
/// stored here; showing it is not this test's.)
#[test]
fn a_device_whose_scope_was_stored_on_has_the_notice_of_what_stopped() {
    use cordelia_storage::meta;
    let relay = relay_started();
    let mut device = node("laptop", "personal", Some(relay.p2p));
    {
        let conn = in_the_released_form(&device);
        meta::set(&conn, meta::SYNC_CLAUDE_ALL, "on").unwrap();
    }
    let began = chrono::Utc::now();
    device.start();
    wait_for("device healthy", &[&relay, &device], 30, || {
        healthy(&device)
    });

    let conn = database_of(&device);
    let notices = first_start::notices(&conn).unwrap();
    assert_eq!(notices.len(), 1, "{notices:?}");
    let notice = &notices[0];
    let at = chrono::DateTime::parse_from_rfc3339(&notice.at).unwrap();
    assert!(
        at >= began - chrono::Duration::seconds(1) && at <= chrono::Utc::now(),
        "{}",
        notice.at
    );
    assert_eq!(
        notice.dir.as_deref(),
        Some(device.home().join(".claude").display().to_string().as_str())
    );
    let stopped: Vec<(&str, Option<&str>, Option<&str>)> = notice
        .folders
        .as_deref()
        .unwrap()
        .iter()
        .map(|folder| {
            (
                folder.folder.as_str(),
                folder.cwd.as_deref(),
                folder.name.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        stopped,
        [
            (
                "/home/sam/.claude/projects/-home-sam-work-tools",
                Some("/home/sam/work/tools"),
                Some("github.com/sam/tools")
            ),
            (
                "/home/sam/.claude/projects/-home-sam",
                Some("/home/sam"),
                Some("~")
            ),
        ]
    );
    assert_eq!(
        meta::get(&conn, meta::SYNC_CLAUDE_ALL).unwrap().as_deref(),
        Some("off")
    );
    let status = status_of(&device);
    assert_eq!(status["sync"]["all"], false, "{status}");
    // The log says it, once, with how many: a person who reads the log
    // of the start that stopped them is told there too.
    let log = std::fs::read_to_string(device.log()).unwrap();
    assert_eq!(
        log.matches("sync: 2 folders stopped syncing on this device")
            .count(),
        1,
        "{log}"
    );
    let warned = log
        .lines()
        .find(|line| line.contains("folders stopped syncing on this device"));
    assert!(warned.is_some_and(|line| line.contains("WARN")), "{log}");
    // The step wrote the scope off itself: the start that follows it
    // found the scope off, and said nothing of one that was stored on.
    assert!(
        !log.contains("what was stored said that everything found on this machine syncs"),
        "{log}"
    );
    // The report that the notice was made from is removed: a cycle of
    // this version has stored its own since, or none has run yet.
    let report = meta::get(&conn, meta::SYNC_CLAUDE_REPORT).unwrap();
    assert!(
        report.is_none_or(|report| !report.contains("2026-10-05T09:12:44")),
        "the released version's report is still stored"
    );
}

// ── Only what is mapped syncs ────────────────────────────────────────

/// The name that a clone made by [`clone_at`] is found under: its remote.
const TOOLS: &str = "github.com/seed-drill/cordelia-node";

/// A git repository at `rel` under `home`, with a remote: what a version
/// that synced everything found had found, under the remote's name.
fn clone_at(home: &Path, rel: &str) -> std::path::PathBuf {
    let repo = home.join(rel);
    std::fs::create_dir_all(&repo).unwrap();
    for args in [
        vec!["init", "-q"],
        vec![
            "remote",
            "add",
            "origin",
            "https://github.com/seed-drill/cordelia-node.git",
        ],
    ] {
        // Without git's own variables: `GIT_DIR`, where the caller has
        // it set, would make these act on the caller's repository.
        let mut git = std::process::Command::new("git");
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|name| name.starts_with("GIT_")) {
                git.env_remove(&name);
            }
        }
        let made = git.arg("-C").arg(&repo).args(&args).output().unwrap();
        assert!(made.status.success(), "git {args:?}: {made:?}");
    }
    repo
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// What holds on a node, each thing in a word, as `cordelia status
/// --json` lists it.
fn holds_of(status: &serde_json::Value) -> Vec<String> {
    let all = status["holds"].as_array().into_iter().flatten();
    all.filter_map(|holds| holds["what"].as_str().map(str::to_string))
        .collect()
}

/// With real processes (decision 2026-10-04 §10.1): only what is mapped
/// syncs, and a device whose folders stopped is told which.
///
/// Two devices. The laptop's database says that the scope was on,
/// written before its node starts, with a repository that was found, a
/// stored report that shows it syncing without a mapping, and a control
/// folder that is mapped. Its first start stores the notice. The desktop
/// maps the same two names.
///
/// - An edit in the repository does not reach the desktop; the control
///   folder's does.
/// - The laptop's status carries the notice and names the repository,
///   and its level is red: in `--json`, the line, the bar form and the
///   plain status; `cordelia sync status` says it first. It is still
///   there after a restart.
/// - A file is deleted in the repository, and the repository is mapped:
///   it merges. The file comes back, and is not deleted on the desktop;
///   the laptop's edit reaches the desktop. The notice no longer names
///   the repository, and `--seen` puts it away.
///
/// `scope` is what the laptop's database has stored as its scope. With
/// `before_mappings` its stored report is in the form from before
/// mappings, in which a folder has no directory: the notice then has no
/// command for it, and the list of what is found has.
fn folders_that_stopped_sync_again_once_they_are_mapped(
    scope: Option<&str>,
    before_mappings: bool,
) {
    use cordelia_storage::meta;
    use serde_json::json;
    let relay = relay_started();
    let desktop = device_started("desktop", &relay);
    let mut laptop = node("laptop", "personal", Some(relay.p2p));
    let home = laptop.home();
    let shown = |path: &Path| path.display().to_string();

    // On the laptop: the control folder, which is mapped, and the
    // repository, which was found. Each holds memory.
    let lab = std::path::PathBuf::from(lab_of(&laptop));
    std::fs::create_dir_all(&lab).unwrap();
    let lab_mem = claude_folder(&home, &lab);
    let repo = clone_at(&home, "work/tools");
    let repo_mem = claude_folder(&home, &repo);
    std::fs::write(repo_mem.join("shared.md"), "what both devices hold\n").unwrap();
    let repo_folder = shown(&claude_project(&home, &repo));
    {
        let conn = in_the_released_form(&laptop);
        match scope {
            Some(scope) => meta::set(&conn, meta::SYNC_CLAUDE_ALL, scope).unwrap(),
            None => {
                meta::remove(&conn, meta::SYNC_CLAUDE_ALL).unwrap();
            }
        }
        // The last cycle's report, as the version before stored it: the
        // control folder, and the repository, which synced unmapped.
        let folder = |dir: &Path, name: &str, mapped: bool| {
            let mut folder = json!({
                "channel_id": null, "conflict_files": [], "conflicts": 0, "error": null,
                "folder": shown(&claude_project(&home, dir)),
                "last_published_at": null, "last_pulled_at": null,
                "project": name, "published": 0, "pulled": 0, "skipped": [], "too_large": [],
                "waiting": false,
            });
            if !before_mappings {
                folder["cwd"] = shown(dir).into();
                folder["mapped"] = mapped.into();
            }
            folder
        };
        let report = json!({
            "at": "2026-10-05T09:12:44.512203817+00:00",
            "available": [], "errors": [], "excluded": [],
            "folders": [folder(&lab, "lab", true), folder(&repo, TOOLS, false)],
            "generation": 4, "unmapped": [], "unsynced": [],
        });
        meta::set(&conn, meta::SYNC_CLAUDE_REPORT, &report.to_string()).unwrap();
    }
    laptop.start();
    let all = [&relay, &desktop, &laptop];
    wait_for("laptop healthy", &all, 30, || healthy(&laptop));
    wait_for("laptop reaches its relay", &all, 60, || {
        has_hot_peer(&laptop)
    });

    // Its first start stored the notice, and the scope is off. It is not
    // added yet, and says that first: both are red.
    let named = |status: &serde_json::Value| -> serde_json::Value {
        let all = status["sync"]["notice"]["folders"].as_array().unwrap();
        let found = all
            .iter()
            .find(|folder| folder["folder"] == repo_folder.as_str());
        found
            .unwrap_or_else(|| panic!("the notice does not name the repository: {status}"))
            .clone()
    };
    let status = status_of(&laptop);
    assert_eq!(status["sync"]["all"], false, "{status}");
    assert_eq!(status["sync"]["notice"]["stopped"], 1, "{status}");
    assert_eq!(status["sync"]["notice"]["not_known"], false, "{status}");
    assert_eq!(named(&status)["name"], TOOLS);
    assert_eq!(status["level"], "red", "{status}");
    assert_eq!(status["summary"], "memory: not added yet", "{status}");
    assert_eq!(holds_of(&status), ["no_phrase", "stopped_syncing"]);

    // The two become one person's devices. The desktop maps its clone,
    // under the remote's name, and its control folder.
    pair(&desktop, &laptop, "laptop", &all);
    let d_home = desktop.home();
    let said = desktop.cli(&["sync", "claude", "--dir", &shown(&d_home.join(".claude"))]);
    assert!(said.starts_with("Sync turned on.\n"), "{said}");
    let d_repo = clone_at(&d_home, "code/tools");
    let d_repo_mem = claude_folder(&d_home, &d_repo);
    std::fs::write(d_repo_mem.join("shared.md"), "what both devices hold\n").unwrap();
    std::fs::write(
        d_repo_mem.join("from_desktop.md"),
        "written on the desktop\n",
    )
    .unwrap();
    let d_lab = d_home.join("lab");
    std::fs::create_dir_all(&d_lab).unwrap();
    let d_lab_mem = claude_folder(&d_home, &d_lab);
    desktop.cli(&["sync", "map", &shown(&d_repo)]);
    desktop.cli(&["sync", "map", &shown(&d_lab), "lab"]);
    let mapped: Vec<String> = status_of(&desktop)["sync"]["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|mapping| mapping["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(mapped, [TOOLS, "lab"]);

    // An edit in each folder on the laptop. The control folder's reaches
    // the desktop. The repository's does not: it is not mapped here.
    std::fs::write(repo_mem.join("decision.md"), "decided on the laptop\n").unwrap();
    std::fs::write(lab_mem.join("notes.md"), "noted on the laptop\n").unwrap();
    wait_for(
        "the control folder's edit reaches the desktop",
        &all,
        120,
        || (read(&d_lab_mem.join("notes.md"))?.as_str() == "noted on the laptop\n").then_some(()),
    );
    // Some cycles later still not, and nothing of the desktop's came
    // into the repository's folder here.
    std::thread::sleep(std::time::Duration::from_secs(12));
    assert_eq!(read(&d_repo_mem.join("decision.md")), None);
    assert_eq!(read(&repo_mem.join("from_desktop.md")), None);
    let seen = person_of(&laptop);
    let held: Vec<&str> = ["sent", "to_go"]
        .iter()
        .flat_map(|key| seen["names"][key].as_array().unwrap())
        .filter_map(|name| name.as_str())
        .collect();
    assert_eq!(held, ["lab"], "the laptop holds no name for the repository");

    // The laptop's status carries the notice, and is red: folders
    // stopped syncing.
    let status = wait_for("the laptop says what stopped", &all, 60, || {
        let status = status_of(&laptop);
        (status["summary"] == "memory: 1 folder stopped syncing").then_some(status)
    });
    assert_eq!(
        (&status["level"], &status["state"]),
        (&json!("red"), &json!("attention"))
    );
    assert!(holds_of(&status).contains(&"stopped_syncing".to_string()));
    assert_eq!(status["sync"]["notice"]["stopped"], 1, "{status}");
    let repository = named(&status);
    assert_eq!(repository["name"], TOOLS);
    let line = laptop.cli(&["status", "--line"]);
    assert!(
        line.contains("▲ memory: 1 folder stopped syncing"),
        "{line}"
    );
    let bar: serde_json::Value =
        serde_json::from_str(&laptop.cli(&["status", "--waybar"])).unwrap();
    assert_eq!(bar["class"], json!(["attention", "red", "active"]), "{bar}");
    let tooltip = bar["tooltip"].as_str().unwrap();
    assert!(tooltip.contains("Stopped syncing: "), "{tooltip}");
    // The tooltip and the plain status list everything that holds, and
    // not only what the line says: a device was added, and is not
    // cleared.
    assert_eq!(holds_of(&status), ["stopped_syncing", "added"]);
    let also = "To know: 1 device added, not yet cleared";
    assert!(tooltip.contains(also), "{tooltip}");
    let plain = laptop.cli(&["status"]);
    assert!(
        plain.contains("Memory:    memory: 1 folder stopped syncing"),
        "{plain}"
    );
    assert!(plain.contains(&format!("    also:     {also}")), "{plain}");
    assert!(plain.contains("    stopped:  "), "{plain}");
    // `cordelia sync status` says it first, with the command that maps
    // the repository under the name it synced under; or, from a report
    // of before mappings, that its directory is not known, with the
    // command in the list of what is found.
    let said = laptop.cli(&["sync", "status"]);
    assert!(
        said.starts_with("1 folder stopped syncing on this device"),
        "{said}"
    );
    let by_the_notice = format!("cordelia sync map ~/work/tools {TOOLS}");
    match before_mappings {
        false => {
            assert_eq!(repository["mappable"], true, "{repository}");
            assert_eq!(repository["cwd"], shown(&repo).as_str());
            assert!(
                tooltip.contains(&format!("~/work/tools ({TOOLS})")),
                "{tooltip}"
            );
            assert!(said.contains(&by_the_notice), "{said}");
        }
        true => {
            assert_eq!(repository["why_not"], "no_directory", "{repository}");
            assert!(repository["cwd"].is_null(), "{repository}");
            assert!(said.contains("its directory is not known"), "{said}");
            assert!(!said.contains(&by_the_notice), "{said}");
            let found = said.split("Found on this machine, not syncing:").nth(1);
            let found = found.unwrap_or_else(|| panic!("{said}"));
            assert!(found.contains("cordelia sync map ~/work/tools\n"), "{said}");
        }
    }
    assert!(said.contains("cordelia sync status --seen"), "{said}");

    if !before_mappings {
        // The notice is still there after a restart.
        laptop.stop();
        laptop.start();
        let all = [&relay, &desktop, &laptop];
        wait_for("laptop healthy again", &all, 30, || healthy(&laptop));
        wait_for("the laptop is red again", &all, 60, || {
            let status = status_of(&laptop);
            (status["summary"] == "memory: 1 folder stopped syncing").then_some(())
        });

        // `map` checks when it is run. A memory tree laid out by hand
        // records a directory: `map` of that directory would sync
        // another folder, and is refused with the reason.
        let other = home.join("work/other");
        std::fs::create_dir_all(&other).unwrap();
        let tree = home.join(".claude/projects/workspace");
        std::fs::create_dir_all(tree.join("memory")).unwrap();
        std::fs::write(tree.join("memory/kept.md"), "kept by hand\n").unwrap();
        let line = format!("{{\"cwd\":{:?}}}\n", shown(&other));
        std::fs::write(tree.join("scope.jsonl"), line).unwrap();
        // And a folder that is no repository, which is found; a
        // repository then appears above it.
        let notes = home.join("deep/notes");
        std::fs::create_dir_all(&notes).unwrap();
        claude_folder(&home, &notes);
        let said = wait_for("the laptop lists both", &all, 60, || {
            let said = laptop.cli(&["sync", "status"]);
            let both = said.contains("this layout cannot be mapped")
                && said.contains("cordelia sync map ~/deep/notes <name>");
            both.then_some(said)
        });
        assert!(
            said.contains("~/.claude/projects/workspace/memory"),
            "{said}"
        );
        assert!(!said.contains("cordelia sync map ~/work/other"), "{said}");
        let refused = laptop.refused(&["sync", "map", &shown(&other), "other"]);
        assert!(
            refused.contains("this layout cannot be mapped"),
            "{refused}"
        );
        assert!(refused.contains("nothing was mapped"), "{refused}");
        // It says which folder is in the way, and what clears it.
        assert!(refused.contains("/.claude/projects/workspace"), "{refused}");
        assert!(refused.contains("which is not there"), "{refused}");
        assert!(
            refused.contains("To sync the memory in") && refused.contains("move it into"),
            "{refused}"
        );
        assert!(
            refused.contains("start a Claude Code session in"),
            "{refused}"
        );
        let above = home.join("deep");
        let made = std::process::Command::new("git")
            .arg("-C")
            .arg(&above)
            .args(["init", "-q"])
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let refused = laptop.refused(&["sync", "map", &shown(&notes), "notes"]);
        assert!(refused.contains("would sync another folder"), "{refused}");
        assert!(
            refused.contains("a git repository that contains it"),
            "{refused}"
        );
        let mappings = status_of(&laptop)["sync"]["mappings"].clone();
        assert_eq!(mappings.as_array().unwrap().len(), 1, "{mappings}");
    }
    let all = [&relay, &desktop, &laptop];

    // A file is deleted in the repository, and then the repository is
    // mapped: by the notice's command, or by the list's.
    std::fs::remove_file(repo_mem.join("shared.md")).unwrap();
    let said = match before_mappings {
        false => laptop.cli(&["sync", "map", &shown(&repo), TOOLS]),
        true => laptop.cli(&["sync", "map", &shown(&repo)]),
    };
    assert!(
        said.contains(&format!("Mapped ~/work/tools to {TOOLS}.")),
        "{said}"
    );
    // It merges: what each side wrote reaches the other, and the file
    // that was deleted here comes back, and is not deleted there.
    wait_for("the laptop's edit reaches the desktop", &all, 120, || {
        (read(&d_repo_mem.join("decision.md"))?.as_str() == "decided on the laptop\n").then_some(())
    });
    wait_for("the desktop's file reaches the laptop", &all, 120, || {
        (read(&repo_mem.join("from_desktop.md"))?.as_str() == "written on the desktop\n")
            .then_some(())
    });
    wait_for("the deleted file comes back", &all, 120, || {
        (read(&repo_mem.join("shared.md"))?.as_str() == "what both devices hold\n").then_some(())
    });
    std::thread::sleep(std::time::Duration::from_secs(12));
    assert_eq!(
        read(&d_repo_mem.join("shared.md")).as_deref(),
        Some("what both devices hold\n"),
        "it is not deleted on the desktop"
    );
    assert_eq!(
        read(&repo_mem.join("shared.md")).as_deref(),
        Some("what both devices hold\n")
    );

    // The notice no longer names the repository: nothing of it is red.
    let status = wait_for("the notice names nothing that stopped", &all, 60, || {
        let status = status_of(&laptop);
        (status["sync"]["notice"]["stopped"] == 0 && status["level"] != "red").then_some(status)
    });
    assert_eq!(named(&status)["mapped"], true, "{status}");
    assert!(!holds_of(&status).contains(&"stopped_syncing".to_string()));
    let said = laptop.cli(&["sync", "status"]);
    assert!(
        said.starts_with("Every folder that stopped syncing on this device is mapped again."),
        "{said}"
    );
    // Seen: the notice is shown once more, and then put away, and the
    // status carries none.
    let said = laptop.cli(&["sync", "status", "--seen"]);
    assert!(
        said.starts_with(
            "Every folder that stopped syncing on this device is mapped again.\n\nThe notice \
             of the folders that stopped syncing is put away."
        ),
        "{said}"
    );
    assert!(!said.contains("--seen"), "{said}");
    let status = status_of(&laptop);
    assert!(status["sync"]["notice"].is_null(), "{status}");
    assert!(!laptop.cli(&["sync", "status"]).contains("stopped syncing"));
    let conn = database_of(&laptop);
    assert!(first_start::notices(&conn).unwrap().is_empty());

    // The node notes each report that it stores: it says for how long it
    // has stored none, and that is counted from the last one, and not
    // from its start. It has run for a while by now, and a cycle stores
    // a report every few seconds: so it has stored none for less than
    // half the time that it has run.
    wait_for(
        "the laptop says when it last stored a report",
        &all,
        120,
        || {
            let run_for = status_of(&laptop)["uptime_secs"].as_f64()?;
            let sync = laptop.post("/api/v1/sync/status", json!({}));
            let none_for = sync["no_report_secs"].as_u64()? as f64;
            (run_for >= 20.0 && none_for * 2.0 < run_for).then_some(())
        },
    );

    if !before_mappings {
        // The tree laid out by hand stands in the way of its directory
        // only while Claude Code's own folder for that directory is not
        // there. A session is started in the directory: the same command
        // now maps that folder, which is what was asked, and nothing
        // that the tree holds leaves the machine.
        let other = home.join("work/other");
        let own_mem = claude_folder(&home, &other);
        std::fs::write(own_mem.join("own.md"), "of the directory itself\n").unwrap();
        let said = wait_for("the laptop lists the own folder", &all, 60, || {
            let said = laptop.cli(&["sync", "status"]);
            said.contains("cordelia sync map ~/work/other <name>")
                .then_some(said)
        });
        assert!(said.contains("this layout cannot be mapped"), "{said}");
        let said = laptop.cli(&["sync", "map", &shown(&other), "other"]);
        assert!(said.contains("Mapped ~/work/other to other."), "{said}");
        let d_other = d_home.join("work/other");
        std::fs::create_dir_all(&d_other).unwrap();
        let d_other_mem = claude_folder(&d_home, &d_other);
        desktop.cli(&["sync", "map", &shown(&d_other), "other"]);
        wait_for(
            "the own folder's file reaches the desktop",
            &all,
            120,
            || {
                (read(&d_other_mem.join("own.md"))?.as_str() == "of the directory itself\n")
                    .then_some(())
            },
        );
        assert_eq!(read(&d_other_mem.join("kept.md")), None);
        let tree = home.join(".claude/projects/workspace/memory/kept.md");
        assert_eq!(read(&tree).as_deref(), Some("kept by hand\n"));
    }
}

#[test]
fn folders_that_synced_unmapped_stop_and_sync_again_once_they_are_mapped() {
    folders_that_stopped_sync_again_once_they_are_mapped(Some("on"), false);
}

/// The same from data where no scope is stored, with a directory set,
/// and a stored report in the form from before mappings.
#[test]
fn folders_of_an_install_from_before_mappings_stop_and_sync_again_once_mapped() {
    folders_that_stopped_sync_again_once_they_are_mapped(None, true);
}
