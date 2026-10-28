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

// ── Slice 5: a move (rule 9) ─────────────────────────────────────────

/// The secret of the change that `node` follows, as its database holds it.
fn applied_secret_of(node: &Node) -> [u8; 32] {
    store_of(node)
        .query_row(
            "SELECT secret FROM person_secrets WHERE left_at IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

/// Every secret that `node`'s database holds of its person: the one it
/// follows, and those it left and keeps.
fn secrets_of(node: &Node) -> Vec<[u8; 32]> {
    let db = store_of(node);
    let mut stmt = db.prepare("SELECT secret FROM person_secrets").unwrap();
    stmt.query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// The channels of the generation of `secret` that a device of this test
/// writes in: the personal channel, the messages channel, and the channel
/// of the name `lab`.
fn channels_of(secret: &[u8; 32]) -> Vec<[u8; 32]> {
    [
        derive::personal_secret(secret).unwrap(),
        derive::messages_secret(secret).unwrap(),
        derive::own_secret(secret, "lab").unwrap(),
    ]
    .iter()
    .map(|channel| derive::channel_id(channel).unwrap())
    .collect()
}

/// The channel of each entry in `relay`'s store that the key `author`
/// signed, stored after the place `after`.
fn channels_stored_by(relay: &Node, author: &[u8; 32], after: i64) -> Vec<[u8; 32]> {
    let db = store_of(relay);
    let mut stmt = db
        .prepare("SELECT channel_id FROM entries WHERE author = ?1 AND seq > ?2")
        .unwrap();
    stmt.query_map(rusqlite::params![author.as_slice(), after], |row| {
        row.get(0)
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

/// Set `node` up with the relay at `to` in place of the one at `from`, and
/// start it again.
fn moves_relay(node: &mut Node, from: &Node, to: &Node) {
    node.stop();
    let config = std::fs::read_to_string(node.config()).unwrap();
    let (was, is) = (
        format!("127.0.0.1:{}", from.p2p),
        format!("127.0.0.1:{}", to.p2p),
    );
    assert!(config.contains(&was), "{config}");
    std::fs::write(node.config(), config.replace(&was, &is)).unwrap();
    node.start();
    wait_for("the device reaches its relay", &[node, to], 60, || {
        has_hot_peer(node)
    });
}

/// Test 1 of decision 2026-10-24 (removal), section 7, but its point (b),
/// which needs relays that keep every head (slice 6): the fault, kept for
/// good. The laptop and the tablet use relay A; the desktop uses relay B;
/// the relays are not listed together; all three are on change 2. The
/// desktop removes the tablet (its change 3). The laptop renews (its own
/// change 3, made apart, which lists the tablet). The tablet applies the laptop's change. The laptop
/// is then set up with relay B too, and started again.
///
/// It asserts:
///
/// - (a) the laptop follows the desktop's change 3, by its ID, with its
///   own set aside, and no phrase was typed (rules 8 and 9);
/// - (c) the desktop's state is applied at every look through the test,
///   and it never says that two changes were made apart (rule 11);
/// - (d) a file that the laptop edits after (a) reaches the desktop;
/// - (e) every entry that the laptop pushed to either relay after (a) is
///   in a channel of the desktop's change 3, and none is in a channel of
///   any secret that the tablet's database holds;
/// - (f) no entry that the laptop signed reaches either relay in a channel
///   of its own change 3 after (a): at relay B, none ever.
///
/// Taken out: rule 9 (the laptop is closed: (a) and (d) fail); rule 4 or
/// 5 (it goes on under its own change: (e) and (f) fail); rule 11 (the
/// desktop stops: (c) fails).
#[test]
fn a_removal_made_apart_from_a_renewal_takes_effect_without_settle() {
    let relay_a = relay_started();
    let relay_b = relay_started();
    let mut laptop = device_started("laptop", &relay_a);
    let mut desktop = device_started("desktop", &relay_a);
    let tablet = device_started("tablet", &relay_a);
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    adds(&laptop, &tablet, "tablet");
    let (l_notes, l_mem) = notes_of(&laptop);
    let (d_notes, d_mem) = notes_of(&desktop);
    std::fs::write(l_mem.join("first.md"), "what both hold\n").unwrap();
    syncs_lab(&laptop, &l_notes);
    syncs_lab(&desktop, &d_notes);
    let all = [&relay_a, &relay_b, &laptop, &desktop, &tablet];
    wait_for("the desktop has the laptop's file", &all, 120, || {
        (read(&d_mem.join("first.md"))?.as_str() == "what both hold\n").then_some(())
    });
    // All three on change 2, which lists each.
    let mut at = renews(&laptop, &["stays", "stays"], &words);
    at.says("The change is made (change 2).");
    drop(at);
    has_applied(&desktop, 2, &all);
    has_applied(&tablet, 2, &all);

    // The desktop uses relay B alone from here.
    moves_relay(&mut desktop, &relay_a, &relay_b);
    let desktop_applied = |desktop: &Node| {
        let seen = person_of(desktop);
        assert_eq!(seen["state"], "applied", "(c): {seen}");
        assert_eq!(
            seen["set_aside"].as_array().map(Vec::len),
            Some(0),
            "(c): {seen}"
        );
        let status = desktop.cli(&["status"]);
        assert!(!status.contains("made apart"), "(c): {status}");
    };
    desktop_applied(&desktop);

    // The desktop removes the tablet: its change 3, through relay B.
    let mut at = removes(&desktop, &key_of(&tablet), &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    let removal = person_of(&desktop)["latest"].as_str().unwrap().to_string();
    desktop_applied(&desktop);

    // The laptop, which reaches relay A alone, renews: its own change 3,
    // made apart, which lists the tablet. The tablet applies it.
    let mut at = renews(&laptop, &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    let own_change = person_of(&laptop)["latest"].as_str().unwrap().to_string();
    assert_ne!(own_change, removal);
    let own_secret = applied_secret_of(&laptop);
    has_applied(
        &tablet,
        3,
        &[&relay_a, &relay_b, &laptop, &desktop, &tablet],
    );
    assert_eq!(
        person_of(&tablet)["latest"].as_str(),
        Some(own_change.as_str())
    );
    desktop_applied(&desktop);

    // The laptop is set up with relay B too, and started again.
    laptop.stop();
    laptop.add_relay(&format!("127.0.0.1:{}", relay_b.p2p), None);
    laptop.start();
    let all = [&relay_a, &relay_b, &laptop, &desktop, &tablet];
    wait_for("the laptop is healthy", &all, 30, || healthy(&laptop));

    // (a) It follows the desktop's change, by its ID, with its own set
    // aside: no phrase was typed.
    wait_for("the laptop follows the desktop's change", &all, 180, || {
        let seen = person_of(&laptop);
        (seen["latest"].as_str() == Some(removal.as_str())).then_some(())
    });
    let laptop_key = key_bytes(&laptop);
    let marks = (
        last_stored_by(&relay_a, &laptop_key),
        last_stored_by(&relay_b, &laptop_key),
    );
    let seen = person_of(&laptop);
    assert_eq!(seen["state"], "applied", "{seen}");
    assert_eq!(seen["change"].as_u64(), Some(3), "{seen}");
    let set_aside = seen["set_aside"].as_array().cloned().unwrap_or_default();
    assert_eq!(set_aside.len(), 1, "{seen}");
    assert_eq!(set_aside[0]["clear"], false, "{seen}");
    let moved_to = applied_secret_of(&laptop);
    assert_eq!(moved_to, applied_secret_of(&desktop));
    desktop_applied(&desktop);

    // (d) A file that the laptop edits now reaches the desktop.
    std::fs::write(l_mem.join("after.md"), "written after the move\n").unwrap();
    wait_for(
        "the desktop has the file written after the move",
        &all,
        180,
        || (read(&d_mem.join("after.md"))?.as_str() == "written after the move\n").then_some(()),
    );
    desktop_applied(&desktop);
    // A few passes more, for whatever the laptop has still to send.
    std::thread::sleep(Duration::from_secs(15));

    // (e) Every entry it pushed after (a) is in a channel of the desktop's
    // change 3, and none in a channel of the tablet's secrets.
    let desktop_channels = channels_of(&moved_to);
    let tablet_channels: Vec<[u8; 32]> = secrets_of(&tablet).iter().flat_map(channels_of).collect();
    let own_channels = channels_of(&own_secret);
    let pushed_a = channels_stored_by(&relay_a, &laptop_key, marks.0);
    let pushed_b = channels_stored_by(&relay_b, &laptop_key, marks.1);
    assert!(!pushed_b.is_empty(), "the laptop pushed nothing to relay B");
    for channel in pushed_a.iter().chain(&pushed_b) {
        assert!(
            desktop_channels.contains(channel),
            "(e): {}",
            hex::encode(channel)
        );
        assert!(
            !tablet_channels.contains(channel),
            "(e): {}",
            hex::encode(channel)
        );
    }
    // (f) None in a channel of its own change 3 after (a), at either
    // relay; at relay B, none ever.
    for channel in pushed_a
        .iter()
        .chain(&channels_stored_by(&relay_b, &laptop_key, 0))
    {
        assert!(
            !own_channels.contains(channel),
            "(f): {}",
            hex::encode(channel)
        );
    }
    desktop_applied(&desktop);
}
