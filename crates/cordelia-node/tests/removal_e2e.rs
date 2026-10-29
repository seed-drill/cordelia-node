//! A removal fails safe (decision 2026-10-24 (removal)): real processes,
//! set up with the commands a person types, with a relay of the test's
//! own on this machine.
//!
//! This file grows with the record's build, slice by slice (its section
//! 14). Its first slice makes a device fail closed: it seals nothing under
//! a secret that a key it knows to be removed holds, and takes nothing that
//! such a key signs (rules 2 to 6). Slice 5 moves a device to a clear
//! change (rule 9); slice 6 has relays keep every head, hand each before
//! they say "held", and pass each on until it is taken (rules 14 to 17);
//! slice 7 has a device show every head at a relay that names the role
//! `heads`, and none above the change it follows at one that does not
//! (rule 18), and bounds the window before a device reads a removal
//! (rule 5, section 8).

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
    /// A phone on change 2, stopped, where the test has one.
    phone: Option<Node>,
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
    the_fault_with(renewals, false)
}

/// [`the_fault`], with a phone where `phone` says so: it uses relay A, is
/// on change 2 with the others, and is stopped before the desktop removes
/// the tablet.
fn the_fault_with(renewals: u64, phone: bool) -> Fault {
    let relay_a = relay_started();
    let relay_b = relay_started();
    let laptop = device_started("laptop", &relay_a);
    let mut desktop = device_started("desktop", &relay_a);
    let tablet = device_started("tablet", &relay_a);
    let mut phone = phone.then(|| device_started("phone", &relay_a));
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    adds(&laptop, &tablet, "tablet");
    if let Some(phone) = &phone {
        adds(&laptop, phone, "phone");
    }
    let (l_notes, l_mem) = notes_of(&laptop);
    let (d_notes, d_mem) = notes_of(&desktop);
    std::fs::write(l_mem.join("first.md"), "what both hold\n").unwrap();
    syncs_lab(&laptop, &l_notes);
    syncs_lab(&desktop, &d_notes);
    let all = [&relay_a, &relay_b, &laptop, &desktop, &tablet];
    wait_for("the desktop has the laptop's file", &all, 120, || {
        (read(&d_mem.join("first.md"))?.as_str() == "what both hold\n").then_some(())
    });
    // All on change 2, which lists each.
    let stays: &[&str] = match phone {
        Some(_) => &["stays", "stays", "stays"],
        None => &["stays", "stays"],
    };
    let mut at = renews(&laptop, stays, &words);
    at.says("The change is made (change 2).");
    drop(at);
    has_applied(&desktop, 2, &all);
    has_applied(&tablet, 2, &all);
    if let Some(phone) = &mut phone {
        has_applied(phone, 2, &all);
        phone.stop();
    }
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
        phone,
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

// ── Slice 7: a device shows every head (rule 18) ─────────────────────

/// Test 4 of decision 2026-10-24 (removal), section 7: a device that slept
/// through changes made apart follows the clear one. As test 2, with a
/// phone that uses relay A and is stopped on change 2. The laptop renews
/// twice (changes 3 and 4) while the desktop removes the tablet; the relays
/// are then listed together, and relay A comes to keep the desktop's change
/// beside the laptop's change 4. The phone is started.
///
/// It asserts: the phone follows the desktop's change 3, with the laptop's
/// change 4 set aside, not clear; and no entry that it signed reaches
/// either relay in a channel of the laptop's change 3 or 4.
///
/// Taken out: rule 16's order with rule 9 (it applies change 4, and is then
/// closed: the first assertion fails); rule 9's move to a lower number
/// (closed: the same).
#[test]
fn a_device_that_slept_through_changes_made_apart_follows_the_clear_one() {
    let mut f = the_fault_with(2, true);
    lists_together(&mut f);
    wait_for(
        "relay A holds the desktop's change",
        &f.nodes(),
        120,
        || holds_change(&f.relay_a, &f.removal).then_some(()),
    );
    let mut phone = f.phone.take().unwrap();
    let phone_key = key_bytes(&phone);
    phone.start();
    wait_for("the phone is healthy", &[&phone], 30, || healthy(&phone));
    // It is handed the lower first, applies it, and is then handed the
    // laptop's change 4, which it sets aside.
    wait_for(
        "the phone follows the desktop's change, with the laptop's set aside",
        &[&phone, &f.relay_a, &f.relay_b],
        180,
        || {
            let seen = person_of(&phone);
            let follows = seen["latest"].as_str() == Some(f.removal.as_str());
            let set_aside = seen["set_aside"]
                .as_array()
                .is_some_and(|heads| !heads.is_empty());
            (follows && set_aside).then_some(())
        },
    );
    let seen = person_of(&phone);
    assert_eq!(seen["state"], "applied", "{seen}");
    assert_eq!(seen["change"].as_u64(), Some(3), "{seen}");
    let set_aside = seen["set_aside"].as_array().cloned().unwrap_or_default();
    assert_eq!(set_aside.len(), 1, "{seen}");
    assert_eq!(set_aside[0]["number"].as_u64(), Some(4), "{seen}");
    assert_eq!(set_aside[0]["clear"], false, "{seen}");
    // A few passes more, for whatever the phone has to send.
    std::thread::sleep(Duration::from_secs(15));
    let laptops: Vec<[u8; 32]> = f.own_secrets.iter().flat_map(channels_of).collect();
    for relay in [&f.relay_a, &f.relay_b] {
        for channel in channels_stored_by(relay, &phone_key, 0) {
            assert!(!laptops.contains(&channel), "{}", hex::encode(channel));
        }
    }
    assert_eq!(
        person_of(&phone)["latest"].as_str(),
        Some(f.removal.as_str())
    );
}

/// A stand-in for a relay of the version before, at a port of this
/// machine: it says "relay" alone among its roles, and names no role
/// `heads` (decision 2026-10-24 (removal), rule 18). It answers each show
/// "held", and keeps what it was shown, each change entry by its ID; it
/// resets every other stream.
struct RelayBefore {
    shown: Arc<std::sync::Mutex<Vec<[u8; 32]>>>,
    _runtime: tokio::runtime::Runtime,
}

impl RelayBefore {
    fn at(port: u16) -> Self {
        use cordelia_network::messages::{EntryShown, ShowAnswer, WireMessage};
        use cordelia_network::{codec, connection, transport};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let shown = Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = shown.clone();
        runtime.block_on(async {
            let identity = Arc::new(NodeIdentity::generate().unwrap());
            let here: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let endpoint = transport::create_endpoint(&identity, here).unwrap();
            let manager = connection::ConnectionManager::new(
                identity,
                endpoint.clone(),
                vec![],
                vec!["relay".into()],
                port,
            );
            let ctx = manager.connect_context();
            tokio::spawn(async move {
                let _manager = manager;
                while let Some(incoming) = endpoint.accept().await {
                    let Ok(outcome) = connection::inbound_accept(&ctx, incoming).await else {
                        continue;
                    };
                    let (conn, kept) = (outcome.conn, kept.clone());
                    tokio::spawn(async move {
                        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                            let kept = kept.clone();
                            tokio::spawn(async move {
                                let Ok(protocol) = codec::read_protocol_byte(&mut recv).await
                                else {
                                    return;
                                };
                                let Ok(request) = codec::read_frame(&mut recv, protocol).await
                                else {
                                    return;
                                };
                                let id = match &request {
                                    WireMessage::EntryShow(show) => {
                                        Entry::from_wire(&show.entry).ok().map(|e| e.id())
                                    }
                                    WireMessage::EntryShowShort(show) => Some(show.id),
                                    _ => None,
                                };
                                let Some(id) = id else {
                                    let _ = send.reset(0u32.into());
                                    return;
                                };
                                kept.lock().unwrap().push(id);
                                let answer = WireMessage::EntryShown(EntryShown {
                                    answer: ShowAnswer::Held,
                                });
                                let _ = codec::write_frame(&mut send, &answer).await;
                                let _ = send.finish();
                            });
                        }
                    });
                }
            });
        });
        Self {
            shown,
            _runtime: runtime,
        }
    }

    /// The change entries it was shown, by their IDs, in their order.
    fn shown(&self) -> Vec<[u8; 32]> {
        self.shown.lock().unwrap().clone()
    }
}

/// The change entry's ID that `person_of` names as `latest`: hex.
fn id_of(hex_id: &str) -> [u8; 32] {
    hex::decode(hex_id).unwrap().try_into().unwrap()
}

/// Test 18 of decision 2026-10-24 (removal), section 7: a closed device
/// shows every head at a relay that keeps heads. The laptop uses relays A
/// and B; a work laptop uses relay A alone; the desktop uses relay B; the
/// relays are not listed together. The laptop removes the phone (its
/// change 3), while it reaches relay A alone; the desktop removes the
/// tablet (its change 3), and then renews (change 4). The laptop is then
/// set up with relay B too.
///
/// It asserts: the laptop is closed (each change lists a key the other
/// removes); the work laptop is handed the desktop's change 4 at relay A,
/// which the laptop showed there, and closes; no entry that the work laptop
/// signed reaches relay A after that. Then relay A is replaced by a
/// stand-in that names no role `heads`: the laptop shows it the change it
/// follows, and never the desktop's change 4, which is above it.
///
/// Taken out: rule 18's showing at a relay that names the role (the work
/// laptop is never handed change 4, and goes on: its close times out); its
/// bar at one that does not (the laptop shows the stand-in change 4: the
/// last assertion fails).
#[test]
fn a_closed_device_shows_every_head_at_a_relay_that_keeps_heads() {
    let relay_a = relay_started();
    let relay_b = relay_started();
    let mut laptop = device_started("laptop", &relay_a);
    let work = device_started("work", &relay_a);
    let mut desktop = device_started("desktop", &relay_a);
    let mut phone = device_started("phone", &relay_a);
    let mut tablet = device_started("tablet", &relay_a);
    let words = makes_a_phrase(&laptop, "laptop");
    for (device, label) in [
        (&work, "work-laptop"),
        (&desktop, "desktop"),
        (&phone, "phone"),
        (&tablet, "tablet"),
    ] {
        adds(&laptop, device, label);
    }
    // The nodes whose logs a wait prints, as they are when it waits.
    macro_rules! all {
        () => {
            [&relay_a, &relay_b, &laptop, &work, &desktop]
        };
    }
    let mut at = renews(&laptop, &["stays"; 4], &words);
    at.says("The change is made (change 2).");
    drop(at);
    for device in [&work, &desktop, &phone, &tablet] {
        has_applied(device, 2, &all!());
    }
    // The phone and the tablet are needed no more.
    phone.stop();
    tablet.stop();
    let (w_notes, w_mem) = notes_of(&work);
    syncs_lab(&work, &w_notes);

    // The desktop uses relay B alone from here, and the laptop relay A.
    moves_relay(&mut desktop, &relay_a, &relay_b);
    let mut at = removes(&laptop, &key_of(&phone), &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    has_applied(&work, 3, &all!());
    let mut at = removes(&desktop, &key_of(&tablet), &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    let mut at = renews(&desktop, &[], &words);
    at.says("The change is made (change 4).");
    drop(at);
    let change_4 = person_of(&desktop)["latest"].as_str().unwrap().to_string();
    let laptops_3 = person_of(&laptop)["latest"].as_str().unwrap().to_string();

    // The laptop is set up with relay B too: it is handed change 4 there,
    // and is closed.
    laptop.stop();
    laptop.add_relay(&format!("127.0.0.1:{}", relay_b.p2p), None);
    laptop.start();
    wait_for("the laptop is healthy", &all!(), 30, || healthy(&laptop));
    wait_for("the laptop is closed", &all!(), 120, || {
        (stands(&laptop).0 == "fork").then_some(())
    });
    assert_eq!(
        person_of(&laptop)["latest"].as_str(),
        Some(laptops_3.as_str())
    );

    // It shows change 4 at relay A, which keeps heads, and the work laptop
    // is handed it there, and closes.
    wait_for("relay A holds change 4", &all!(), 120, || {
        holds_change(&relay_a, &change_4).then_some(())
    });
    wait_for("the work laptop is closed", &all!(), 120, || {
        (stands(&work).0 == "fork").then_some(())
    });
    // What was on its way when it closed has had its ten seconds; from
    // here nothing the work laptop signs reaches relay A.
    std::thread::sleep(Duration::from_secs(12));
    let work_key = key_bytes(&work);
    let closed_at = last_stored_by(&relay_a, &work_key);
    std::fs::write(w_mem.join("while-closed.md"), "written while closed\n").unwrap();
    std::thread::sleep(Duration::from_secs(30));
    assert_eq!(
        last_stored_by(&relay_a, &work_key),
        closed_at,
        "an entry the work laptop signed reached relay A while it was closed"
    );

    // Relay A is replaced by a stand-in that names no role `heads`.
    let port_a = relay_a.p2p;
    let mut relay_a = relay_a;
    relay_a.stop();
    let before = RelayBefore::at(port_a);
    let (followed, above) = (id_of(&laptops_3), id_of(&change_4));
    wait_for(
        "the laptop shows the stand-in what it follows, a few times",
        &[&laptop, &relay_b],
        180,
        || {
            let shown = before.shown();
            (shown.iter().filter(|id| **id == followed).count() >= 3).then_some(())
        },
    );
    let shown = before.shown();
    assert!(
        !shown.contains(&above),
        "the laptop showed change 4 at a relay that does not keep heads"
    );
    assert_eq!(stands(&laptop).0, "fork");
}

// ── Slice 7: the window, bounded (section 8, rule 5) ─────────────────

/// How long the stand-in of test 6 holds back each stage of a stream: just
/// under STREAM_TIMEOUT_SECS, so that each stage runs near its limit and
/// none is given up.
const HELD_BACK: Duration = Duration::from_secs(cordelia_core::protocol::STREAM_TIMEOUT_SECS - 1);

/// What the stand-in of test 6 keeps.
#[derive(Default)]
struct Held {
    /// The removal's change entry, as it is on the wire.
    removal: Vec<u8>,
    /// From when it holds the removal: the time the test set.
    from: Option<std::time::Instant>,
    /// Each entry pushed to it, with when it arrived whole, and its channel.
    pushed: Vec<(std::time::Instant, [u8; 32])>,
}

/// A stand-in for relay A in test 6, at a port of this machine, that
/// answers as the test says (`relay.says`). It names the role `heads`.
/// Until the test says that it holds the removal, it answers each show
/// "held", a proof as one for a channel it does not hold, a pull with a
/// page of nothing, and each entry of a push "stored", keeping what was
/// pushed. From then it answers each show with the removal, whole, and
/// holds back each stage of each stream for just under the stream's
/// timeout ([`HELD_BACK`]): its opening, by stream credit (it takes one
/// stream at a time, and lets one go only that long after it answered);
/// its reading, where the request does not fit in the stream's window;
/// and its answer.
struct HeldBackRelay {
    held: Arc<std::sync::Mutex<Held>>,
    _runtime: tokio::runtime::Runtime,
}

impl HeldBackRelay {
    fn at(port: u16, removal: Vec<u8>) -> Self {
        use cordelia_network::messages::{
            ChannelProved, EntryPulled, EntryPushed, EntryShown, PushAnswer, ShowAnswer,
            WireMessage,
        };
        use cordelia_network::{codec, connection, transport};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let held = Arc::new(std::sync::Mutex::new(Held {
            removal,
            ..Held::default()
        }));
        let kept = held.clone();
        runtime.block_on(async {
            let identity = Arc::new(NodeIdentity::generate().unwrap());
            let here: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let endpoint = transport::create_endpoint(&identity, here).unwrap();
            // One stream at a time: the next waits for credit.
            let mut server = transport::server_config(&identity).unwrap();
            let mut limits = quinn::TransportConfig::default();
            limits.max_concurrent_bidi_streams(1u32.into());
            limits.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
            limits.keep_alive_interval(Some(Duration::from_secs(15)));
            server.transport_config(Arc::new(limits));
            endpoint.set_server_config(Some(server));
            let manager = connection::ConnectionManager::new(
                identity,
                endpoint.clone(),
                vec![],
                vec!["relay".into(), "heads".into()],
                port,
            );
            let ctx = manager.connect_context();
            tokio::spawn(async move {
                let _manager = manager;
                while let Some(incoming) = endpoint.accept().await {
                    let Ok(outcome) = connection::inbound_accept(&ctx, incoming).await else {
                        continue;
                    };
                    let (conn, kept) = (outcome.conn, kept.clone());
                    tokio::spawn(async move {
                        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                            let kept = kept.clone();
                            // One at a time: the stream is answered and
                            // held before the next is accepted.
                            let holding = kept.lock().unwrap().from.is_some();
                            let Ok(protocol) = codec::read_protocol_byte(&mut recv).await else {
                                continue;
                            };
                            let Ok(len) = codec::read_frame_len(&mut recv).await else {
                                continue;
                            };
                            // A request larger than the stream's window waits
                            // for its reading.
                            if holding && len > cordelia_core::protocol::QUIC_STREAM_RECEIVE_WINDOW
                            {
                                tokio::time::sleep(HELD_BACK).await;
                            }
                            let Ok(body) = codec::read_frame_body(&mut recv, len).await else {
                                continue;
                            };
                            let Ok(request) = codec::decode_message(protocol, &body) else {
                                let _ = send.reset(0u32.into());
                                continue;
                            };
                            let arrived = std::time::Instant::now();
                            let answer = {
                                let mut held = kept.lock().unwrap();
                                match request {
                                    WireMessage::EntryShow(_) | WireMessage::EntryShowShort(_) => {
                                        let answer = match held.from.is_some() {
                                            true => ShowAnswer::Another(held.removal.clone()),
                                            false => ShowAnswer::Held,
                                        };
                                        Some(WireMessage::EntryShown(EntryShown { answer }))
                                    }
                                    WireMessage::ChannelProve(_) => {
                                        Some(WireMessage::ChannelProved(ChannelProved {
                                            proved: false,
                                        }))
                                    }
                                    WireMessage::EntryPull(pull) => {
                                        Some(WireMessage::EntryPulled(EntryPulled {
                                            entries: Vec::new(),
                                            next: pull.after,
                                            mark: pull.mark,
                                        }))
                                    }
                                    WireMessage::EntryPush(push) => {
                                        for bytes in &push.entries {
                                            if let Ok(entry) = Entry::from_wire(bytes) {
                                                held.pushed.push((arrived, entry.channel));
                                            }
                                        }
                                        Some(WireMessage::EntryPushed(EntryPushed {
                                            answers: vec![PushAnswer::Stored; push.entries.len()],
                                        }))
                                    }
                                    _ => None,
                                }
                            };
                            if holding {
                                tokio::time::sleep(HELD_BACK).await;
                            }
                            match answer {
                                Some(answer) => {
                                    let _ = codec::write_frame(&mut send, &answer).await;
                                    let _ = send.finish();
                                }
                                None => {
                                    let _ = send.reset(0u32.into());
                                }
                            }
                            // The stream's credit comes back that long after.
                            if holding {
                                tokio::time::sleep(HELD_BACK).await;
                            }
                            drop((send, recv));
                        }
                    });
                }
            });
        });
        Self {
            held,
            _runtime: runtime,
        }
    }

    /// From now on it holds the removal, and holds back each stage.
    fn holds_the_removal(&self) -> std::time::Instant {
        let now = std::time::Instant::now();
        self.held.lock().unwrap().from = Some(now);
        now
    }

    /// Each entry pushed to it, with when it arrived and its channel.
    fn pushed(&self) -> Vec<(std::time::Instant, [u8; 32])> {
        self.held.lock().unwrap().pushed.clone()
    }
}

/// Test 6 of decision 2026-10-24 (removal), section 7: the window before a
/// device reads a removal is bounded. As test 1, but that the laptop uses a
/// stand-in for relay A that answers as the test says, and a third relay,
/// C; neither holds the removal at first, and the laptop's edits reach both
/// under the secret of its own change 3, which the tablet holds (the
/// window, shown). At a time the test sets, relay A comes to hold the
/// removal, and from then holds back each stage of each stream for just
/// under STREAM_TIMEOUT_SECS (its opening, by stream credit; its reading;
/// its answer), so that each stage of section 8 runs near its limit.
///
/// It asserts: the last entry that the laptop pushes under the old secret,
/// at either relay, arrives no more than 90 seconds after relay A first
/// holds the removal (section 8); and none reaches relay C more than 10
/// seconds after the laptop has read the removal (rule 5: only a push whose
/// last byte was already sent), when it is closed, or has moved.
///
/// Taken out, by hand (the slice's mutation check): none of the three that
/// the record names is caught here. A leave ten times SHOW_LEAVE_SECS long
/// is not, since every whole pass shows at each relay whatever its leave,
/// so the device reads the removal at its next pass all the same; nor is
/// rule 5's reset, since relay C answers a push at once, and none is open
/// at the commit. Rule 5's moment is held by slice 5's tests of a move that
/// waits for the cycle, and the reset by
/// `a_push_open_at_the_commit_that_closes_the_device_is_reset`
/// (`device_entries_e2e.rs`). What this test holds is the bound itself.
#[test]
#[ignore = "waits out the window of section 8, each stage held near its limit: some minutes"]
fn the_window_before_a_device_reads_a_removal_is_bounded() {
    let relay_c = relay_started();
    let relay_b = relay_started();
    let mut laptop = device_started("laptop", &relay_c);
    let mut desktop = device_started("desktop", &relay_c);
    let mut tablet = device_started("tablet", &relay_c);
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    adds(&laptop, &tablet, "tablet");
    let (l_notes, l_mem) = notes_of(&laptop);
    syncs_lab(&laptop, &l_notes);
    let mut at = renews(&laptop, &["stays", "stays"], &words);
    at.says("The change is made (change 2).");
    drop(at);
    has_applied(&desktop, 2, &[&relay_c, &laptop, &desktop, &tablet]);
    has_applied(&tablet, 2, &[&relay_c, &laptop, &desktop, &tablet]);
    tablet.stop();

    // The desktop removes the tablet through relay B: its change 3. The
    // laptop renews through relay C: its own change 3, which lists the
    // tablet.
    moves_relay(&mut desktop, &relay_c, &relay_b);
    let mut at = removes(&desktop, &key_of(&tablet), &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    let removal = person_of(&desktop)["latest"].as_str().unwrap().to_string();
    wait_for(
        "relay B holds the removal",
        &[&relay_b, &desktop],
        60,
        || holds_change(&relay_b, &removal).then_some(()),
    );
    let removal_bytes = change_entries_at(&relay_b)
        .into_iter()
        .find(|bytes| hex::encode(Entry::from_wire(bytes).unwrap().id()) == removal)
        .expect("relay B holds the removal");
    let mut at = renews(&laptop, &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    let old = channels_of(&applied_secret_of(&laptop));
    let laptop_key = key_bytes(&laptop);

    // The laptop is set up with relay A too, the stand-in.
    let port_a = free_port();
    let relay_a = HeldBackRelay::at(port_a, removal_bytes);
    laptop.stop();
    laptop.add_relay(&format!("127.0.0.1:{port_a}"), None);
    laptop.start();
    wait_for("the laptop is healthy", &[&laptop], 30, || healthy(&laptop));
    let nodes = [&relay_b, &relay_c, &laptop, &desktop];

    // It edits a file every two seconds, through the test.
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (stop, l_mem) = (stop.clone(), l_mem.clone());
        std::thread::spawn(move || {
            let mut n = 0;
            while !stop.load(Ordering::SeqCst) {
                n += 1;
                let _ = std::fs::write(l_mem.join("edited.md"), format!("edit {n}\n"));
                std::thread::sleep(Duration::from_secs(2));
            }
        })
    };
    // The window, shown: its edits reach both relays under the old secret.
    let mut seen_at_c: std::collections::BTreeMap<i64, std::time::Instant> = Default::default();
    let old_at_c = |seen: &mut std::collections::BTreeMap<i64, std::time::Instant>| {
        let now = std::time::Instant::now();
        let db = store_of(&relay_c);
        let mut stmt = db
            .prepare("SELECT seq, channel_id FROM entries WHERE author = ?1")
            .unwrap();
        let rows: Vec<(i64, [u8; 32])> = stmt
            .query_map([laptop_key.as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for (seq, channel) in rows {
            if old.contains(&channel) {
                seen.entry(seq).or_insert(now);
            }
        }
    };
    old_at_c(&mut seen_at_c);
    let before_window = seen_at_c.len();
    wait_for("the laptop's edits reach both relays", &nodes, 120, || {
        old_at_c(&mut seen_at_c);
        let at_a = relay_a
            .pushed()
            .iter()
            .any(|(_, channel)| old.contains(channel));
        (at_a && seen_at_c.len() > before_window).then_some(())
    });

    // Relay A comes to hold the removal.
    let held_from = relay_a.holds_the_removal();
    let mut read_at: Option<std::time::Instant> = None;
    let began = std::time::Instant::now();
    loop {
        assert!(
            began.elapsed() < Duration::from_secs(300),
            "the laptop never read the removal"
        );
        old_at_c(&mut seen_at_c);
        let seen = person_of(&laptop);
        let latest = seen["latest"].as_str() == Some(removal.as_str());
        if read_at.is_none() && (seen["state"] == "fork" || latest) {
            read_at = Some(std::time::Instant::now());
        }
        if latest && read_at.is_some_and(|at| at.elapsed() > Duration::from_secs(20)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    let read_at = read_at.unwrap();

    // The last entry under the old secret, at either relay, arrived within
    // 90 seconds of relay A's holding the removal.
    let last_at_a = relay_a
        .pushed()
        .into_iter()
        .filter(|(_, channel)| old.contains(channel))
        .map(|(at, _)| at)
        .max();
    let last_at_c = seen_at_c.values().copied().max();
    let last = last_at_a.into_iter().chain(last_at_c).max().unwrap();
    let after = last.saturating_duration_since(held_from);
    assert!(
        after <= Duration::from_secs(90),
        "the last entry under the old secret arrived {after:?} after relay A held the removal"
    );
    // None reached relay C more than 10 seconds after the laptop read it.
    for at in seen_at_c.values() {
        let after_read = at.saturating_duration_since(read_at);
        assert!(
            after_read <= Duration::from_secs(10),
            "an entry under the old secret reached relay C {after_read:?} after the laptop read the removal"
        );
    }
    eprintln!(
        "read the removal {:?} after relay A held it; last under the old secret {after:?} after",
        read_at.saturating_duration_since(held_from)
    );
}
