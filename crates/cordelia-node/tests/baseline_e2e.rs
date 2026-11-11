//! alpha.19's schema as this build's baseline, and the takeover of what
//! alpha.19 left (decision 2026-11-10 (older kind), rules 4, 5 and 10,
//! tests (b) and (c)).
//!
//! Each runs the binary of alpha.19 (`CORDELIA_TEST_BINARY_BEFORE`):
//! without it, each passes without running, but in CI.

mod common;

use std::path::Path;

use common::*;
use rusqlite::Connection;

/// The tables of the older kind of channel, which step 34 drops.
const OLDER_TABLES: [&str; 10] = [
    "channel_members",
    "channel_keys",
    "dm_peers",
    "items",
    "search_content",
    "search_fts",
    "invites",
    "state_offers",
    "trusted_keys",
    "channels",
];

fn path(p: &Path) -> String {
    p.display().to_string()
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

/// The database at `file`, opened for reading only.
fn reading(file: &Path) -> Connection {
    let conn =
        Connection::open_with_flags(file, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    conn.busy_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    conn
}

fn version(conn: &Connection) -> u32 {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}

/// Each definition a database holds, as its type, name, table and text,
/// sorted: the schema as a set.
fn definitions(conn: &Connection) -> Vec<String> {
    let mut found: Vec<String> = conn
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master")
        .unwrap()
        .query_map([], |row| {
            Ok(format!(
                "{}|{}|{}|{}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?.unwrap_or_default()
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    found.sort();
    found
}

/// Every row of every table a database holds, the tables SQLite keeps for
/// itself and for the search index among them, as text, by table: but
/// the random mark of `person_clear_mark`, which is given by its length.
fn rows(conn: &Connection) -> Vec<String> {
    let tables: Vec<String> = conn
        .prepare(
            "SELECT name FROM pragma_table_list WHERE schema = 'main' \
             AND type IN ('table', 'shadow') \
             AND name NOT IN ('sqlite_schema', 'sqlite_temp_schema') ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut found = Vec::new();
    for table in tables {
        let mut of_table: Vec<String> = conn
            .prepare(&format!("SELECT * FROM \"{table}\""))
            .unwrap()
            .query_map([], |row| {
                use rusqlite::types::ValueRef;
                let mut cells = Vec::new();
                for at in 0..row.as_ref().column_count() {
                    let cell = row.get_ref(at)?;
                    cells.push(match (table.as_str(), at, cell) {
                        ("person_clear_mark", 1, ValueRef::Blob(mark)) => {
                            format!("a mark of {} bytes", mark.len())
                        }
                        (_, _, ValueRef::Text(text)) => {
                            format!("{:?}", String::from_utf8_lossy(text))
                        }
                        (_, _, other) => format!("{other:?}"),
                    });
                }
                Ok(format!("{table}: {}", cells.join(", ")))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        of_table.sort();
        found.extend(of_table);
    }
    found
}

/// The tables of the older kind that a database holds, by name.
fn older_tables(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .filter(|name| OLDER_TABLES.contains(&name.as_str()) || name.starts_with("search_fts"))
        .collect()
}

/// A value of `node_meta`, where it is there.
fn meta_of(conn: &Connection, key: &str) -> Option<String> {
    use rusqlite::OptionalExtension;
    conn.query_row("SELECT value FROM node_meta WHERE key = ?1", [key], |row| {
        row.get(0)
    })
    .optional()
    .unwrap()
}

/// Test (b). alpha.19's own `init` makes a database; this build's
/// baseline, before step 34, makes the same: the same definitions, as a
/// set, text for text, with what `ALTER TABLE` left; the same schema
/// version; and the same rows, but the random mark (decision 2026-11-10
/// (older kind), rule 5).
#[test]
fn a_new_database_is_alpha_19s_before_step_34() {
    let Some(before) = binary_before() else {
        return;
    };
    // Its `init` made the database.
    let older = relay_made_by(before);
    let theirs = reading(&older.data_dir().join("cordelia.db"));

    let dir = tempfile::tempdir().unwrap();
    let ours = Connection::open(dir.path().join("cordelia.db")).unwrap();
    cordelia_storage::schema::init_db_as_alpha_19(&ours).unwrap();

    assert_eq!(definitions(&ours), definitions(&theirs));
    assert_eq!(
        (version(&ours), version(&theirs)),
        (
            cordelia_storage::schema::ALPHA_19_VERSION,
            cordelia_storage::schema::ALPHA_19_VERSION
        )
    );
    assert_eq!(rows(&ours), rows(&theirs));
    assert!(rows(&ours).contains(&"person_clear_mark: Integer(1), a mark of 16 bytes".into()));
}

/// Test (c). A device and a relay that ran alpha.19 are taken over by this
/// build (decision 2026-11-10 (older kind), rules 4, 5 and 10). The relay
/// holds items of the older kind in channels of its own, made through its
/// own API. The device, a laptop added to a person's desktop of this
/// build, synced a file each way, and holds rows of the older kind in
/// every table of that kind, put in once the guard of its first start is
/// dropped. The laptop and the relay are stopped, and started on this
/// build: no table of the older kind is left in either, the laptop keeps
/// `sync.claude.activity` and `sync.claude.last_change` as they were, and
/// a file goes each way again. How long step 34 takes on the relay's
/// database is said, as the node logs it and as it takes on a copy.
#[test]
fn a_device_and_a_relay_of_alpha_19_are_taken_over_and_sync_on() {
    const NOTES: &str = "lab";
    const CHANNELS: usize = 10;
    const ITEMS_EACH: usize = 50;
    let Some(before) = binary_before() else {
        return;
    };
    let mut relay = relay_made_by(before.clone());
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut laptop = node_run_by(before, "laptop", relay.p2p);
    let mut desktop = node("desktop", "personal", Some(relay.p2p));
    laptop.start();
    desktop.start();
    for n in [&laptop, &desktop] {
        wait_for("device healthy", &[&relay, n], 30, || healthy(n));
        wait_for("the device reaches its relay", &[&relay, n], 60, || {
            has_hot_peer(n)
        });
    }

    // Items of the older kind at the relay, through its own API.
    for n in 0..CHANNELS {
        let channel = format!("older-{n:02}");
        let made = relay.post(
            "/api/v1/channels/subscribe",
            serde_json::json!({ "channel": channel }),
        );
        assert_eq!(made["is_new"], true, "{made}");
        for i in 0..ITEMS_EACH {
            let published = relay.post(
                "/api/v1/channels/publish",
                serde_json::json!({
                    "channel": channel,
                    "content": { "text": format!("item {i} of the older kind") },
                }),
            );
            assert!(published["item_id"].is_string(), "{published}");
        }
    }
    let items = (CHANNELS * ITEMS_EACH) as i64;
    assert_eq!(older_items_held(&relay), items);

    // One person's two devices, each with its notes folder mapped under
    // one name, and a file each way.
    makes_a_phrase(&desktop, "desktop");
    adds(&desktop, &laptop, "laptop");
    has_applied(&laptop, 1, &[&relay, &laptop, &desktop]);
    let memory_of = |n: &Node| {
        let notes = n.home().join("notes");
        std::fs::create_dir_all(&notes).unwrap();
        n.cli(&["sync", "claude", "--dir", &path(&n.home().join(".claude"))]);
        n.cli(&["sync", "map", &path(&notes), NOTES]);
        claude_folder(&n.home(), &notes)
    };
    let (laptop_memory, desktop_memory) = (memory_of(&laptop), memory_of(&desktop));
    let a_file_each_way = |all: &[&Node], round: &str| {
        for (from, to, file) in [
            (&laptop_memory, &desktop_memory, "from-the-laptop"),
            (&desktop_memory, &laptop_memory, "from-the-desktop"),
        ] {
            let file = format!("{file}-{round}.md");
            let text = format!("{file}: a thought.\n");
            std::fs::write(from.join(&file), &text).unwrap();
            wait_for("the file reaches the other device", all, 180, || {
                (read(&to.join(&file))? == text).then_some(())
            });
        }
    };
    a_file_each_way(&[&relay, &laptop, &desktop], "alpha-19");

    // The laptop and the relay stop. The laptop holds rows of the older
    // kind in each of its tables, put in once the guard is dropped.
    laptop.stop();
    relay.stop();
    let laptop_db = laptop.data_dir().join("cordelia.db");
    let kept_by_the_laptop = {
        let db = Connection::open(&laptop_db).unwrap();
        assert_eq!(version(&db), cordelia_storage::schema::ALPHA_19_VERSION);
        db.execute_batch(
            "DROP TRIGGER moved_on_takes_no_channel;
             INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                   created_at, updated_at)
                 VALUES ('grp_older', 'group', 'batch', 'open', zeroblob(32), 't', 't');
             INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
                 VALUES ('grp_older', zeroblob(32), 'owner', 't');
             INSERT INTO channel_keys (channel_id, encrypted_psk)
                 VALUES ('grp_older', zeroblob(48));
             INSERT INTO dm_peers (channel_id, peer_key) VALUES ('grp_older', zeroblob(32));
             INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length)
                 VALUES ('ci_one', 'grp_older', zeroblob(32), 'memory', 't', zeroblob(32),
                         zeroblob(64), zeroblob(40), 40);
             INSERT INTO search_content (item_id, channel_id, item_type, published_at, name)
                 VALUES ('ci_one', 'grp_older', 'memory', 't', 'a word');
             INSERT INTO invites (item_id, inviter, channel_id, status, received_at)
                 VALUES ('ci_two', zeroblob(32), 'grp_older', 'pending', 't');
             INSERT INTO state_offers (channel_id, member, epoch, item_id, sent_at,
                                       last_offered_at)
                 VALUES ('grp_older', zeroblob(32), 1, 'ci_three', 1, 1);
             INSERT INTO trusted_keys (entity_key, kind, added_at)
                 VALUES (zeroblob(32), 'device', 't');
             INSERT INTO node_meta (key, value) VALUES ('personal_channel_id', 'grp_older');",
        )
        .unwrap();
        let kept = ["sync.claude.activity", "sync.claude.last_change"].map(|key| {
            let value = meta_of(&db, key);
            assert!(value.is_some(), "{key}");
            (key, value)
        });
        assert_eq!(older_tables(&db).len(), OLDER_TABLES.len() + 4);
        kept
    };

    // How long step 34 takes on a copy of the relay's database.
    let relay_db = relay.data_dir().join("cordelia.db");
    let copy = tempfile::tempdir().unwrap();
    for ending in ["", "-wal", "-shm"] {
        let file = format!("cordelia.db{ending}");
        if relay.data_dir().join(&file).exists() {
            std::fs::copy(relay.data_dir().join(&file), copy.path().join(&file)).unwrap();
        }
    }
    let bytes = std::fs::metadata(copy.path().join("cordelia.db"))
        .unwrap()
        .len();
    let began = std::time::Instant::now();
    drop(cordelia_storage::db::open_as(&copy.path().join("cordelia.db"), false).unwrap());
    eprintln!(
        "step 34 on a copy of the relay's database ({items} items of the older kind, {bytes} \
         bytes): {} ms",
        began.elapsed().as_millis()
    );

    // Each starts on this build.
    relay.bin = None;
    laptop.bin = None;
    relay.start();
    wait_for("relay healthy on this build", &[&relay], 30, || {
        healthy(&relay)
    });
    laptop.start();
    wait_for(
        "laptop healthy on this build",
        &[&relay, &laptop],
        30,
        || healthy(&laptop),
    );
    for (n, file) in [(&relay, &relay_db), (&laptop, &laptop_db)] {
        let db = reading(file);
        assert_eq!(
            version(&db),
            cordelia_storage::schema::SCHEMA_VERSION,
            "{}",
            n.name
        );
        assert_eq!(older_tables(&db), Vec::<String>::new(), "{}", n.name);
        assert_eq!(meta_of(&db, "personal_channel_id"), None, "{}", n.name);
    }
    let db = reading(&laptop_db);
    for (key, value) in &kept_by_the_laptop {
        assert_eq!(&meta_of(&db, key), value, "{key}");
    }
    drop(db);
    let log = std::fs::read_to_string(relay.log()).unwrap();
    let said = log
        .lines()
        .find(|line| line.contains("applied schema step 34"))
        .unwrap_or_else(|| panic!("{}", relay.log_tail()));
    eprintln!("the relay's log: {said}");

    // They sync on.
    wait_for(
        "the laptop reaches its relay again",
        &[&relay, &laptop],
        60,
        || has_hot_peer(&laptop),
    );
    a_file_each_way(&[&relay, &laptop, &desktop], "this-build");
}
