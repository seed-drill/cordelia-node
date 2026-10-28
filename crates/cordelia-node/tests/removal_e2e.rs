//! A removal fails safe (decision 2026-10-24 (removal)): real processes,
//! set up with the commands a person types, with a relay of the test's
//! own on this machine.
//!
//! This file grows with the record's build, slice by slice (its section
//! 14). Its first slice makes a device fail closed: it seals nothing under
//! a secret that a key it knows to be removed holds, and takes nothing that
//! such a key signs (rules 2 to 6). Slice 5 moves a device to a clear
//! change (rule 9); slice 6 has relays keep every head, hand each before
//! they say "held", and pass each on until it is taken (rules 14 to 17).

mod common;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// The desktop is applied, and never says that two changes were made
/// apart (rule 11; test 1's point (c)). From slice 6 a relay keeps the
/// laptop's change 3 beside the removal and hands it to the desktop, which
/// sets it aside, as it is not clear, and goes on: its status line says so
/// in amber ("a change made apart is set aside"), and never says the words
/// of a closed device (rule 10). Every head it sets aside is not clear.
fn desktop_applied(desktop: &Node) {
    let seen = person_of(desktop);
    assert_eq!(seen["state"], "applied", "(c): {seen}");
    for head in seen["set_aside"].as_array().cloned().unwrap_or_default() {
        assert_eq!(head["clear"], false, "(c): {seen}");
    }
    let status = desktop.cli(&["status"]);
    assert!(
        !status.contains("two changes were made apart"),
        "(c): {status}"
    );
}

/// The change entries that `relay` holds, as their bytes on the wire: each
/// entry of a change entry's size.
fn change_entries_at(relay: &Node) -> Vec<Vec<u8>> {
    let db = store_of(relay);
    let mut stmt = db
        .prepare(
            "SELECT channel_id, slot, author, rev, is_delete, content, author_sig, channel_sig
             FROM entries WHERE length(content) = ?1 ORDER BY seq",
        )
        .unwrap();
    stmt.query_map(
        [cordelia_core::protocol::CHANGE_ENTRY_BYTES as i64],
        |row| {
            Ok(Entry {
                channel: row.get(0)?,
                slot: row.get(1)?,
                author: row.get(2)?,
                rev: row.get::<_, i64>(3)? as u64,
                delete: row.get(4)?,
                content: row.get(5)?,
                author_signature: row.get(6)?,
                channel_signature: row.get(7)?,
            }
            .to_wire())
        },
    )
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

/// Whether `relay` holds the change entry whose ID is `id`, as the node
/// says it (`person_of`'s `latest`): hex of the entry's ID.
fn holds_change(relay: &Node, id: &str) -> bool {
    change_entries_at(relay)
        .iter()
        .any(|bytes| hex::encode(Entry::from_wire(bytes).unwrap().id()) == id)
}

/// The signatures of the entries in `relay`'s store that the key `author`
/// signed, each with its channel and its place in the store's order.
fn signed_at(relay: &Node, author: &[u8; 32]) -> Vec<(Vec<u8>, [u8; 32], i64)> {
    let db = store_of(relay);
    let mut stmt = db
        .prepare("SELECT author_sig, channel_id, seq FROM entries WHERE author = ?1")
        .unwrap();
    stmt.query_map([author.as_slice()], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

/// The fault of the record's section 0, set up as test 1 sets it up, up to
/// where the laptop and the desktop have made their changes apart: the
/// laptop and the tablet use relay A; the desktop uses relay B; the relays
/// are not listed together; all three were on change 2. The desktop
/// removes the tablet (its change 3). The laptop, which reaches relay A
/// alone, renews `renewals` times (its own changes 3 and on, made apart,
/// which list the tablet), and the tablet applies the last.
struct Fault {
    relay_a: Node,
    relay_b: Node,
    laptop: Node,
    desktop: Node,
    tablet: Node,
    l_mem: PathBuf,
    d_mem: PathBuf,
    /// The ID of the desktop's change 3, which removes the tablet.
    removal: String,
    /// The secrets of the laptop's own changes.
    own_secrets: Vec<[u8; 32]>,
    /// Every change entry that relay A held along the way: each that the
    /// tablet was handed, change 2 and the laptop's own among them.
    handed: Vec<Vec<u8>>,
}

impl Fault {
    fn nodes(&self) -> [&Node; 5] {
        [
            &self.relay_a,
            &self.relay_b,
            &self.laptop,
            &self.desktop,
            &self.tablet,
        ]
    }
}

fn the_fault(renewals: u64) -> Fault {
    let relay_a = relay_started();
    let relay_b = relay_started();
    let laptop = device_started("laptop", &relay_a);
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
    let mut handed = change_entries_at(&relay_a);

    // The desktop uses relay B alone from here.
    moves_relay(&mut desktop, &relay_a, &relay_b);
    desktop_applied(&desktop);

    // The desktop removes the tablet: its change 3, through relay B.
    let mut at = removes(&desktop, &key_of(&tablet), &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    let removal = person_of(&desktop)["latest"].as_str().unwrap().to_string();
    desktop_applied(&desktop);

    // The laptop, which reaches relay A alone, renews: its own changes,
    // made apart, which list the tablet. The tablet applies each.
    let mut own_secrets = Vec::new();
    for n in 3..3 + renewals {
        let mut at = renews(&laptop, &[], &words);
        at.says(&format!("The change is made (change {n})."));
        drop(at);
        let own_change = person_of(&laptop)["latest"].as_str().unwrap().to_string();
        assert_ne!(own_change, removal);
        own_secrets.push(applied_secret_of(&laptop));
        has_applied(
            &tablet,
            n,
            &[&relay_a, &relay_b, &laptop, &desktop, &tablet],
        );
        assert_eq!(
            person_of(&tablet)["latest"].as_str(),
            Some(own_change.as_str())
        );
        handed.extend(change_entries_at(&relay_a));
    }
    desktop_applied(&desktop);
    assert!(!holds_change(&relay_a, &removal));
    Fault {
        relay_a,
        relay_b,
        laptop,
        desktop,
        tablet,
        l_mem,
        d_mem,
        removal,
        own_secrets,
        handed,
    }
}

/// (a) The laptop follows the desktop's change 3, by its ID, with its own
/// set aside, and no phrase was typed (rules 8 and 9). Returns the secret
/// it follows.
fn follows_the_removal(f: &Fault, within: u64) -> [u8; 32] {
    wait_for(
        "the laptop follows the desktop's change",
        &f.nodes(),
        within,
        || {
            let seen = person_of(&f.laptop);
            (seen["latest"].as_str() == Some(f.removal.as_str())).then_some(())
        },
    );
    let seen = person_of(&f.laptop);
    assert_eq!(seen["state"], "applied", "(a): {seen}");
    assert_eq!(seen["change"].as_u64(), Some(3), "(a): {seen}");
    let set_aside = seen["set_aside"].as_array().cloned().unwrap_or_default();
    assert_eq!(set_aside.len(), 1, "(a): {seen}");
    assert_eq!(set_aside[0]["clear"], false, "(a): {seen}");
    let moved_to = applied_secret_of(&f.laptop);
    assert_eq!(moved_to, applied_secret_of(&f.desktop), "(a)");
    desktop_applied(&f.desktop);
    moved_to
}

/// (b) The tablet's status says that it was removed, with no `settle`: it
/// was handed the desktop's change at relay A, which it reaches alone
/// (rules 8, step 3, and 14 to 16).
fn the_tablet_reads_its_removal(f: &Fault) {
    wait_for(
        "the tablet reads that it was removed",
        &f.nodes(),
        120,
        || (stands(&f.tablet).0 == "removed").then_some(()),
    );
    let status = f.tablet.cli(&["status"]);
    assert!(status.contains("this device was removed"), "(b): {status}");
}

/// Test 1 of decision 2026-10-24 (removal), section 7: the fault, kept for
/// good. As [`the_fault`], with one renewal; the laptop is then set up with
/// relay B too, and started again.
///
/// It asserts:
///
/// - (a) the laptop follows the desktop's change 3, by its ID, with its
///   own set aside, and no phrase was typed (rules 8 and 9);
/// - (b) the tablet's status says "this device was removed", with no
///   `settle`, once the laptop has shown the desktop's change at relay A
///   (rules 14 to 16, slice 6);
/// - (c) the desktop's state is applied at every look through the test,
///   and it never says that two changes were made apart (rule 11);
/// - (d) a file that the laptop edits after (a) reaches the desktop;
/// - (e) every entry that the laptop pushed to either relay after (a) is
///   in a channel of the desktop's change 3, and none is in a channel of
///   any secret that the tablet's database holds;
/// - (f) no entry that the laptop signed reaches either relay in a channel
///   of its own change 3 once it is started with relay B, before the move
///   as after it: at relay A from then, and at relay B, none ever.
///
/// Taken out: rule 9 (the laptop is closed: (a) and (d) fail); rule 4 or
/// 5 (it goes on under its own change: (e) and (f) fail); rules 14 to 16
/// (relay A never hands the desktop's change: (b) fails); rule 11 (the
/// desktop stops: (c) fails).
#[test]
fn a_removal_made_apart_from_a_renewal_takes_effect_without_settle() {
    let mut f = the_fault(1);
    let own_secret = f.own_secrets[0];

    // The laptop is set up with relay B too, and started again. What relay
    // A holds of it is marked while it is stopped: from its start to the
    // move, it learns of the removal, and rule 5's window is there.
    f.laptop.stop();
    let laptop_key = key_bytes(&f.laptop);
    let before_the_move = last_stored_by(&f.relay_a, &laptop_key);
    f.laptop
        .add_relay(&format!("127.0.0.1:{}", f.relay_b.p2p), None);
    f.laptop.start();
    wait_for("the laptop is healthy", &f.nodes(), 30, || {
        healthy(&f.laptop)
    });

    // (a)
    let moved_to = follows_the_removal(&f, 180);
    let marks = (
        last_stored_by(&f.relay_a, &laptop_key),
        last_stored_by(&f.relay_b, &laptop_key),
    );

    // (b) The laptop shows the desktop's change at relay A, which keeps it
    // beside the laptop's own and hands it to the tablet.
    the_tablet_reads_its_removal(&f);
    assert!(holds_change(&f.relay_a, &f.removal));
    desktop_applied(&f.desktop);

    // (d) A file that the laptop edits now reaches the desktop.
    std::fs::write(f.l_mem.join("after.md"), "written after the move\n").unwrap();
    wait_for(
        "the desktop has the file written after the move",
        &f.nodes(),
        180,
        || (read(&f.d_mem.join("after.md"))?.as_str() == "written after the move\n").then_some(()),
    );
    desktop_applied(&f.desktop);
    // A few passes more, for whatever the laptop has still to send.
    std::thread::sleep(Duration::from_secs(15));

    // (e) Every entry it pushed after (a) is in a channel of the desktop's
    // change 3, and none in a channel of the tablet's secrets.
    let desktop_channels = channels_of(&moved_to);
    let tablet_channels: Vec<[u8; 32]> =
        secrets_of(&f.tablet).iter().flat_map(channels_of).collect();
    let own_channels = channels_of(&own_secret);
    let pushed_a = channels_stored_by(&f.relay_a, &laptop_key, marks.0);
    let pushed_b = channels_stored_by(&f.relay_b, &laptop_key, marks.1);
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
    // (f) None in a channel of its own change 3 from when it was started
    // with relay B, at relay A, before the move as after it; at relay B,
    // none ever.
    for channel in channels_stored_by(&f.relay_a, &laptop_key, before_the_move)
        .iter()
        .chain(&channels_stored_by(&f.relay_b, &laptop_key, 0))
    {
        assert!(
            !own_channels.contains(channel),
            "(f): {}",
            hex::encode(channel)
        );
    }
    desktop_applied(&f.desktop);
}

/// List relays A and B together, each with the other's key, and start
/// them again: from then they pass entries between them (decision
/// 2026-10-04 §2.4 item 6).
fn lists_together(f: &mut Fault) {
    let (key_a, key_b) = (key_of(&f.relay_a), key_of(&f.relay_b));
    let (port_a, port_b) = (f.relay_a.p2p, f.relay_b.p2p);
    f.relay_a.stop();
    f.relay_b.stop();
    f.relay_a
        .add_relay(&format!("127.0.0.1:{port_b}"), Some(&key_b));
    f.relay_b
        .add_relay(&format!("127.0.0.1:{port_a}"), Some(&key_a));
    f.relay_a.start();
    f.relay_b.start();
    wait_for("both relays are healthy", &f.nodes(), 30, || {
        healthy(&f.relay_a)?;
        healthy(&f.relay_b)
    });
}

/// Test 2 of decision 2026-10-24 (removal), section 7: as test 1, with
/// relays A and B listed together and no device set up with both. The
/// relays are listed together once the tablet has applied the laptop's
/// change: listed from the start, they would pass the desktop's change to
/// relay A before the laptop renewed, and the laptop would apply it, with
/// no fault to show.
///
/// It asserts (a), (b), (e) and (f) of test 1: the laptop, which reaches
/// relay A alone, follows the desktop's change; the tablet reads that it
/// was removed; and nothing that the laptop signs after (a) is in a
/// channel but the desktop's change 3's, at either relay. What either
/// relay held of the laptop's own change 3 by then, the other may take
/// from it: (e) and (f) are of what neither held at (a), and a push
/// already on its way at (a) has its ten seconds first (rule 5).
///
/// Taken out: rule 14 (relay A does not keep the desktop's change beside
/// the laptop's: (a) times out). Rule 17 taken out alone is not caught
/// here: the relays' pull, which reads every channel a relay tells of after
/// a start, takes the head as well; the unit test
/// `a_head_is_offered_again_until_each_relay_it_works_with_has_answered_for_it`
/// (`relay_entries.rs`) catches it.
#[test]
fn relays_that_work_together_spread_a_removal_made_apart() {
    let mut f = the_fault(1);
    let own_secret = f.own_secrets[0];
    let laptop_key = key_bytes(&f.laptop);
    lists_together(&mut f);

    // (a), and relay A holds the desktop's change, which it was passed.
    let moved_to = follows_the_removal(&f, 180);
    assert!(holds_change(&f.relay_a, &f.removal));
    // Until it read the removal the laptop could send under its own change
    // 3 (section 8's window), and a push already on its way has its ten
    // seconds (rule 5; its reset is slice 7's). What either relay holds of
    // the laptop's then, the other may take from it: (e) and (f) are of
    // what neither held then.
    std::thread::sleep(Duration::from_secs(12));
    let held_before: HashSet<Vec<u8>> = signed_at(&f.relay_a, &laptop_key)
        .into_iter()
        .chain(signed_at(&f.relay_b, &laptop_key))
        .map(|(signature, _, _)| signature)
        .collect();
    let marks = (
        last_stored_by(&f.relay_a, &laptop_key),
        last_stored_by(&f.relay_b, &laptop_key),
    );
    // (b)
    the_tablet_reads_its_removal(&f);

    // What the laptop writes now reaches the desktop, through the relays.
    std::fs::write(f.l_mem.join("after.md"), "written after the move\n").unwrap();
    wait_for(
        "the desktop has the file written after the move",
        &f.nodes(),
        180,
        || (read(&f.d_mem.join("after.md"))?.as_str() == "written after the move\n").then_some(()),
    );
    std::thread::sleep(Duration::from_secs(15));

    // (e) Every entry it signed that either relay stored after (a), and
    // that neither held before they were listed together, is in a channel
    // of the desktop's change 3, and in none of the tablet's secrets.
    let desktop_channels = channels_of(&moved_to);
    let tablet_channels: Vec<[u8; 32]> =
        secrets_of(&f.tablet).iter().flat_map(channels_of).collect();
    let own_channels = channels_of(&own_secret);
    let new = |relay: &Node, after: i64| -> Vec<[u8; 32]> {
        signed_at(relay, &laptop_key)
            .into_iter()
            .filter(|(signature, _, seq)| *seq > after && !held_before.contains(signature))
            .map(|(_, channel, _)| channel)
            .collect()
    };
    let after_a = new(&f.relay_a, marks.0);
    assert!(!after_a.is_empty(), "the laptop pushed nothing to relay A");
    for channel in after_a.iter().chain(&new(&f.relay_b, marks.1)) {
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
    // (f) None that neither relay held before is in a channel of the
    // laptop's own change 3, at either relay, at any time.
    for channel in new(&f.relay_a, 0).iter().chain(&new(&f.relay_b, 0)) {
        assert!(
            !own_channels.contains(channel),
            "(f): {}",
            hex::encode(channel)
        );
    }
    desktop_applied(&f.desktop);
}

/// A client of a relay that is not a node: it connects as any node may,
/// with a key of its own, and shows what the test has it show.
struct Client {
    conn: quinn::Connection,
    _manager: cordelia_network::connection::ConnectionManager,
}

/// Where a relay listens on this machine, and the key it answers with.
struct RelayAt {
    p2p: u16,
    key: String,
}

impl Client {
    async fn to_relay(relay: &RelayAt) -> Result<Self, String> {
        let identity = Arc::new(NodeIdentity::generate().unwrap());
        let endpoint =
            cordelia_network::transport::create_endpoint(&identity, "127.0.0.1:0".parse().unwrap())
                .map_err(|e| e.to_string())?;
        let port = endpoint.local_addr().unwrap().port();
        let mut manager = cordelia_network::connection::ConnectionManager::new(
            identity,
            endpoint,
            vec![],
            vec!["personal".into()],
            port,
        );
        let relay_id = manager
            .connect_to(format!("127.0.0.1:{}", relay.p2p).parse().unwrap())
            .await
            .map_err(|e| e.to_string())?;
        if relay_id.0 != decode_public_key(&relay.key).map_err(|e| e.to_string())? {
            manager.shutdown();
            return Err("another key answered at the relay's port".into());
        }
        let conn = manager.get_connection(&relay_id).unwrap().clone();
        Ok(Self {
            conn,
            _manager: manager,
        })
    }

    /// Show `entry` whole, and read the answer.
    async fn show(&self, entry: &[u8]) -> Result<(), String> {
        use cordelia_network::messages::{EntryShow, Protocol, WireMessage};
        let (mut send, mut recv) = self.conn.open_bi().await.map_err(|e| e.to_string())?;
        let mut stream = tokio::io::join(&mut recv, &mut send);
        let request = WireMessage::EntryShow(EntryShow {
            entry: entry.to_vec(),
        });
        let answer =
            cordelia_network::codec::send_request(&mut stream, Protocol::EntryShow, &request)
                .await
                .map_err(|e| e.to_string());
        let _ = send.finish();
        answer.map(|_| ())
    }
}

/// Test 5 of decision 2026-10-24 (removal), section 7: a removed device
/// that shows old changes again pushes no head out. As test 2, but that the
/// laptop renews twice (its changes 3 and 4), so that the desktop's removal
/// is at a number below the laptop's branch: a relay that kept change
/// entries by their numbers would keep the laptop's change 4 and drop the
/// removal for it. Once relay A holds the desktop's change, a client of
/// the test's own shows relay A, again and again, every change entry that
/// the tablet was handed, change 2 and the laptop's own among them, while
/// the laptop is still to learn of the removal.
///
/// It asserts that the laptop still learns of the desktop's change (it
/// moves to it, at the lower number), and that relay A holds the desktop's
/// change throughout.
///
/// Taken out: rule 14's test of lineage (kept by number alone: the
/// desktop's change is behind the laptop's change 4 by its number, and
/// relay A never keeps it, or drops it: the second assertion fails, or the
/// wait for it).
#[test]
fn a_removed_device_that_shows_old_changes_pushes_no_head_out() {
    let mut f = the_fault(2);
    assert!(f.handed.len() >= 3, "{}", f.handed.len());
    // The laptop is stopped while relay A comes to hold the removal, so
    // that the client shows its old changes while the laptop is still to
    // learn of it.
    f.laptop.stop();
    lists_together(&mut f);
    wait_for(
        "relay A holds the desktop's change",
        &f.nodes(),
        120,
        || holds_change(&f.relay_a, &f.removal).then_some(()),
    );

    // The client shows every change entry the tablet was handed, a round
    // every few seconds: few enough that what it shows from 127.0.0.1,
    // which every node of the test shares, stays within an address's
    // allowance.
    let stop = Arc::new(AtomicBool::new(false));
    let rounds = {
        let (stop, handed, relay) = (stop.clone(), f.handed.clone(), f.relay_a.p2p);
        let relay_key = key_of(&f.relay_a);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                let relay = RelayAt {
                    p2p: relay,
                    key: relay_key,
                };
                let client = Client::to_relay(&relay).await.expect("the client connects");
                let mut rounds = 0;
                while !stop.load(Ordering::SeqCst) {
                    for entry in &handed {
                        let _ = client.show(entry).await;
                    }
                    rounds += 1;
                    tokio::time::sleep(Duration::from_secs(6)).await;
                }
                rounds
            })
        })
    };
    // A few rounds before the laptop is started, and relay A keeps the
    // removal through each.
    for _ in 0..4 {
        std::thread::sleep(Duration::from_secs(6));
        assert!(
            holds_change(&f.relay_a, &f.removal),
            "the removal was pushed out"
        );
    }
    f.laptop.start();
    wait_for("the laptop is healthy", &f.nodes(), 30, || {
        healthy(&f.laptop)
    });
    wait_for(
        "the laptop follows the desktop's change",
        &f.nodes(),
        180,
        || {
            assert!(
                holds_change(&f.relay_a, &f.removal),
                "the removal was pushed out"
            );
            let seen = person_of(&f.laptop);
            (seen["latest"].as_str() == Some(f.removal.as_str())).then_some(())
        },
    );
    assert_eq!(person_of(&f.laptop)["change"].as_u64(), Some(3));
    stop.store(true, Ordering::SeqCst);
    let rounds = rounds.join().unwrap();
    assert!(rounds >= 4, "the client showed {rounds} rounds");
    assert!(
        holds_change(&f.relay_a, &f.removal),
        "the removal was pushed out"
    );
    desktop_applied(&f.desktop);
}
