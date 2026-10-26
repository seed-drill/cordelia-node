//! A removal fails safe (decision 2026-10-24 (removal)): real processes,
//! set up with the commands a person types, with a relay of the test's
//! own on this machine.
//!
//! This file grows with the record's build, slice by slice (its section
//! 14). Its first slice makes a device fail closed: it seals nothing under
//! a secret that a key it knows to be removed holds, and takes nothing that
//! such a key signs (rules 2 to 6).

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;

use cordelia_crypto::addition::Addition;
use cordelia_crypto::bech32::decode_public_key;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{Entry, Inside, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::statement::Device;

fn path(p: &Path) -> String {
    p.to_str().unwrap().to_string()
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

/// A folder `notes` in `n`'s home, with the memory folder that Claude
/// Code keeps for it.
fn notes_of(n: &Node) -> (PathBuf, PathBuf) {
    let notes = n.home().join("notes");
    std::fs::create_dir_all(&notes).unwrap();
    let memory = claude_folder(&n.home(), &notes);
    (notes, memory)
}

/// Turn sync on for `n`, and map its folder `notes` to the name `lab`.
fn syncs_lab(n: &Node, notes: &Path) {
    let out = n.cli(&["sync", "claude", "--dir", &path(&n.home().join(".claude"))]);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
    let out = n.cli(&["sync", "map", &path(notes), "lab"]);
    assert!(out.contains("Mapped ~/notes to lab."), "{out}");
}

fn key_bytes(n: &Node) -> [u8; 32] {
    decode_public_key(&key_of(n)).expect("a node prints its key")
}

/// A node's database, opened for reading while the node runs.
fn store_of(node: &Node) -> rusqlite::Connection {
    let db = rusqlite::Connection::open_with_flags(
        node.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db
}

/// The highest place in `relay`'s store of any entry that the key
/// `author` signed: an entry stored later has a higher one.
fn last_stored_by(relay: &Node, author: &[u8; 32]) -> i64 {
    store_of(relay)
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM entries WHERE author = ?1",
            [author.as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// What `n` says of where it stands, and why it cannot go on.
fn stands(n: &Node) -> (String, String) {
    let seen = person_of(n);
    (
        seen["state"].as_str().unwrap_or_default().to_string(),
        seen["cannot_go_on"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

/// On `adder`, which is stopped, write into its store a record of an
/// addition under the change it follows that adds the key `added`, as its
/// own entry in the personal channel: what `cordelia add-device` writes,
/// and refuses to write for a removed key. Only a key that counts writes
/// a record that another device keeps, so this stands for a device that
/// counts and does not keep the rules: a stolen one, before its removal is
/// known, or one of a branch that never heard of the removal (decision
/// 2026-10-24 (removal), section 4, case 3). Its node sends it as anything
/// of its own that waits.
fn writes_a_record_adding(adder: &Node, added: &[u8; 32], label: &str) {
    let db = cordelia_storage::db::open(&adder.data_dir().join("cordelia.db")).unwrap();
    let identity = NodeIdentity::from_file(&adder.data_dir().join("identity.key")).unwrap();
    let held = cordelia_api::person::held(&db).unwrap().unwrap();
    let statement = held.statement.statement;
    let secret = cordelia_storage::person::applied_secret(&db)
        .unwrap()
        .unwrap()
        .secret;
    let personal = derive::personal_secret(&secret).unwrap();
    let name = cordelia_api::person::added_name(added).unwrap();
    let channel = derive::channel_id(&personal).unwrap();
    let slot = slot_id(&derive::slot_key(&personal).unwrap(), &name);
    let own = cordelia_storage::entries::author_entry(&db, &channel, &slot, &identity.public_key())
        .unwrap()
        .map(|held| held.entry.rev);
    let rev = cordelia_core::revision::next_under(own, statement.number).unwrap();
    let now = chrono::Utc::now().timestamp();
    let record = Addition::under(
        &statement,
        Device::new(*added, label).unwrap(),
        identity.public_key(),
        now as u64,
    )
    .unwrap()
    .sign(&identity)
    .unwrap();
    let inside = Inside {
        name,
        value: Value::Other(record.to_bytes().unwrap()),
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&personal, &identity, rev, &inside)
        .unwrap()
        .check()
        .unwrap();
    cordelia_storage::entries::store(&db, &entry, now).unwrap();
}

/// A record of an addition that hands a removed key the secret of the
/// change that a device follows closes that device (decision 2026-10-24
/// (removal), section 4, case 3, its second variant; rules 3, 4, 5 and
/// 10). The laptop, the desktop and the tablet share relay A. The laptop
/// removes the tablet (change 2). The desktop then writes a record under
/// change 2 that adds the tablet's key again, as no command of this
/// version writes.
///
/// It asserts:
///
/// - (a) the laptop takes the record and is closed, with no person's act:
///   stored as `fork` by rule 8 (rules 3 and 10, slice 3), its status says
///   so, in red, and the change it follows is change 2 still;
/// - (b) a file that the laptop edits while it is closed stays in its
///   folder, and no entry that the laptop signs reaches the relay;
/// - (c) a change made with the phrase on the laptop (`cordelia renew`),
///   which lists no removed device, is the way on: the laptop applies it
///   and goes on, and the file it edited while closed reaches the desktop.
///
/// Taken out: rule 3's keys of records, both those kept apart and those of
/// the records kept (the laptop goes on: (a) fails); rule 4's gate in
/// `Standing::to_write` and `stands` (it publishes: (b) fails). The
/// holders kept apart alone, taken out, are not caught here: the laptop
/// keeps the one record, and reads its key from it. Only a record dropped
/// by the bound of 256 is read from the holders alone, and the unit test
/// `test_a_record_that_adds_a_removed_key_makes_the_change_not_clear_past_the_bound`
/// (`cordelia-api`, `person.rs`) takes the record past it.
#[test]
fn a_record_that_hands_a_removed_device_the_secret_closes_a_device() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let mut desktop = device_started("desktop", &relay);
    let tablet = device_started("tablet", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    adds(&laptop, &tablet, "tablet");
    let (l_notes, l_mem) = notes_of(&laptop);
    let (d_notes, d_mem) = notes_of(&desktop);
    std::fs::write(l_mem.join("first.md"), "what both hold\n").unwrap();
    syncs_lab(&laptop, &l_notes);
    syncs_lab(&desktop, &d_notes);
    let all = [&relay, &laptop, &desktop, &tablet];
    wait_for("the desktop has the laptop's file", &all, 120, || {
        (read(&d_mem.join("first.md"))?.as_str() == "what both hold\n").then_some(())
    });

    // The laptop removes the tablet: change 2.
    let mut at = removes(&laptop, &key_of(&tablet), &["stays"], &words);
    at.says("The change is made (change 2).");
    drop(at);
    has_applied(&desktop, 2, &all);
    wait_for("the tablet reads that it was removed", &all, 120, || {
        (stands(&tablet).0 == "removed").then_some(())
    });
    assert_eq!(stands(&laptop).0, "applied");

    // The desktop, stopped, has a record under change 2 that adds the
    // tablet again, and sends it once it starts.
    desktop.stop();
    writes_a_record_adding(&desktop, &key_bytes(&tablet), "tablet");
    desktop.start();

    // (a) The laptop takes it, and is closed.
    let all = [&relay, &laptop, &desktop];
    wait_for("the laptop is closed", &all, 120, || {
        (stands(&laptop).0 == "fork").then_some(())
    });
    let (_, why) = stands(&laptop);
    assert!(
        why.contains("a device that was removed holds the secret"),
        "{why}"
    );
    assert_eq!(person_of(&laptop)["change"].as_u64(), Some(2));
    let status = laptop.cli(&["status"]);
    assert!(
        status.contains("a removed device holds the secret this device follows")
            || status.contains("a removed device holds this change's secret"),
        "{status}"
    );

    // (b) What was on its way when it closed has had its ten seconds; from
    // here nothing the laptop signs reaches the relay.
    std::thread::sleep(Duration::from_secs(12));
    let laptop_key = key_bytes(&laptop);
    let closed_at = last_stored_by(&relay, &laptop_key);
    std::fs::write(l_mem.join("while-closed.md"), "written while closed\n").unwrap();
    // Several passes, and several cycles of the adapter.
    std::thread::sleep(Duration::from_secs(30));
    assert_eq!(
        last_stored_by(&relay, &laptop_key),
        closed_at,
        "an entry the laptop signed reached the relay while it was closed"
    );
    assert_eq!(stands(&laptop).0, "fork");
    assert_eq!(
        read(&l_mem.join("while-closed.md")).as_deref(),
        Some("written while closed\n"),
        "the folder keeps what was written there"
    );
    assert_eq!(read(&d_mem.join("while-closed.md")), None);

    // (c) A change made with the phrase is the way on.
    let mut at = renews(&laptop, &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    assert_eq!(stands(&laptop).0, "applied");
    has_applied(&desktop, 3, &all);
    wait_for(
        "the desktop has the file written while closed",
        &all,
        180,
        || {
            (read(&d_mem.join("while-closed.md"))?.as_str() == "written while closed\n")
                .then_some(())
        },
    );
    assert!(last_stored_by(&relay, &laptop_key) > closed_at);
}
