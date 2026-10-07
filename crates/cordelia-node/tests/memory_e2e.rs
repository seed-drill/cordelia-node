//! Memory syncing between a person's devices, in channels from the
//! person's secret (decision 2026-10-04 §5.2, §6, §7, §10): real
//! processes, set up with the commands a person types, with a relay of
//! the test's own on this machine.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use serde_json::{Value, json};

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
fn syncs_notes_as_lab(n: &Node, notes: &Path) {
    let out = n.cli(&["sync", "claude", "--dir", &path(&n.home().join(".claude"))]);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
    let out = n.cli(&["sync", "map", &path(notes), "lab"]);
    assert!(out.contains("Mapped ~/notes to lab."), "{out}");
}

/// The files of a memory folder, by name, with their texts: hidden files
/// are none of them.
fn files(memory: &Path) -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = std::fs::read_dir(memory)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(entry.path()).ok()?;
            (!name.starts_with('.')).then_some((name, text))
        })
        .collect();
    all.sort();
    all
}

/// The conflict files of a memory folder, by name.
fn conflict_files(memory: &Path) -> Vec<String> {
    files(memory)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name.contains(".conflict-"))
        .collect()
}

/// What `n` holds under the name `lab`, by key: each key's revision, and
/// its text (`None` for a key that is deleted).
fn held(n: &Node) -> Vec<(String, u64, Option<String>)> {
    let answer = n.post("/api/v1/channels/entries", json!({ "channel": "lab" }));
    answer["entries"]
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
        .collect()
}

fn state(n: &Node) -> Value {
    serde_json::from_str(&n.cli(&["status", "--json"])).unwrap()
}

/// Whether `n` has sent every name it holds to the relays it reaches,
/// and each of them holds the change it keeps.
fn has_sent_everything(n: &Node) -> Option<()> {
    let seen = person_of(n);
    let relays = seen["relays"].as_array()?;
    let sent = seen["names"]["to_go"].as_array()?.is_empty()
        && seen["waiting"]
            .as_array()?
            .iter()
            .all(|relay| relay["waits"] == 0);
    (!relays.is_empty() && relays.iter().all(|relay| relay["holds_latest"] == true) && sent)
        .then_some(())
}

/// A person's memory, end to end (decision 2026-10-04 §5.2, §6, §10):
///
/// - a device that follows no recovery phrase publishes nothing, and
///   says so: what is in its folders stays on the machine;
/// - `cordelia phrase` on it, and its folders are published;
/// - a second device is added with the two commands, and its folder
///   meets the name's channel as on any first sync, in each of the four
///   ways: a file with the same text on both is agreed, with nothing
///   kept; a file that differs takes the channel's text, and this
///   device's is kept beside it; a file only here is published; and the
///   index is merged;
/// - an edit on one then reaches the other, and so does a delete.
#[test]
fn a_phrase_is_made_its_folders_are_published_and_a_second_devices_folders_meet_them() {
    let relay = relay_started();
    let a = device_started("a", &relay);
    let b = device_started("b", &relay);
    let all = [&relay, &a, &b];

    let (a_notes, a_mem) = notes_of(&a);
    let (b_notes, b_mem) = notes_of(&b);
    for (name, text) in [
        ("same.md", "the same on both\n"),
        ("differs.md", "as the desktop has it\n"),
        ("only_a.md", "only on the desktop\n"),
        ("MEMORY.md", "- [same](same.md)\n- [a](only_a.md)\n"),
    ] {
        std::fs::write(a_mem.join(name), text).unwrap();
    }
    for (name, text) in [
        ("same.md", "the same on both\n"),
        ("differs.md", "as the laptop has it\n"),
        ("only_b.md", "only on the laptop\n"),
        ("MEMORY.md", "- [same](same.md)\n- [b](only_b.md)\n"),
    ] {
        std::fs::write(b_mem.join(name), text).unwrap();
    }

    // Before there is a phrase: sync can be turned on and a folder
    // mapped, and nothing is published. The status says why.
    syncs_notes_as_lab(&a, &a_notes);
    let said = wait_for("a says that nothing is sent", &all, 60, || {
        let out = a.cli(&["sync", "status"]);
        out.contains("Nothing is sent from this device")
            .then_some(out)
    });
    assert!(said.contains("no recovery phrase yet"), "{said}");
    assert!(said.contains("stays on this machine"), "{said}");
    // With no phrase the state asks for the person: nothing that the
    // device holds syncs until one is made (decision 2026-10-04 §10.1).
    let s = state(&a);
    assert_eq!(s["state"], "attention", "{s}");
    assert_eq!(
        s["summary"], "memory stays here: no recovery phrase yet",
        "{s}"
    );
    assert_eq!(s["sync"]["moved_on"], false, "{s}");
    // It holds no name, and its local API publishes nothing either.
    assert!(
        person_of(&a)["names"]["sent"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(files(&a_mem).len(), 4);

    // The phrase is made: the device's folders are published.
    let words = makes_a_phrase(&a, "desktop");
    assert_eq!(words.split_whitespace().count(), 12);
    wait_for("a has published its folder", &all, 90, || {
        (held(&a).len() == 4).then_some(())
    });
    wait_for("a has sent what it holds", &all, 90, || {
        has_sent_everything(&a)
    });
    let published = held(&a);
    assert!(
        published
            .iter()
            .all(|(_, rev, text)| *rev == 1 && text.is_some()),
        "{published:?}"
    );
    assert!(conflict_files(&a_mem).is_empty());

    // The second device maps the same name before it is added: nothing
    // of it is published. Then it is added, with the two commands.
    syncs_notes_as_lab(&b, &b_notes);
    adds(&a, &b, "laptop");
    has_applied(&b, 1, &all);

    // Its folder meets the channel as on any first sync.
    wait_for("the two folders hold the same files", &all, 120, || {
        let (on_a, on_b) = (files(&a_mem), files(&b_mem));
        (on_a.len() == 6 && on_a == on_b).then_some(())
    });
    let on_b = files(&b_mem);
    let text_of = |name: &str| {
        on_b.iter()
            .find(|(file, _)| file == name)
            .map(|(_, text)| text.as_str())
    };
    // The same on both: agreed.
    assert_eq!(text_of("same.md"), Some("the same on both\n"));
    // It differs: the file takes the channel's, and this device's text
    // is kept beside it, in one copy, which every device then has.
    assert_eq!(text_of("differs.md"), Some("as the desktop has it\n"));
    let copies = conflict_files(&b_mem);
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert!(copies[0].starts_with("differs.conflict-"), "{copies:?}");
    assert_eq!(text_of(&copies[0]), Some("as the laptop has it\n"));
    // Only here: published.
    assert_eq!(
        read(&a_mem.join("only_b.md")).as_deref(),
        Some("only on the laptop\n")
    );
    assert_eq!(text_of("only_a.md"), Some("only on the desktop\n"));
    // The index: merged.
    let index = text_of("MEMORY.md").unwrap();
    for line in ["- [same](same.md)", "- [a](only_a.md)", "- [b](only_b.md)"] {
        assert_eq!(index.lines().filter(|l| *l == line).count(), 1, "{index}");
    }
    // Nothing that both held the same was published a second time: the
    // file that was the same on both is still the first version of it.
    let same = held(&b).into_iter().find(|(key, _, _)| key == "same.md");
    assert_eq!(same.map(|(_, rev, _)| rev), Some(1));

    // An edit on one reaches the other, and nothing is kept beside it.
    std::fs::write(a_mem.join("same.md"), "edited on the desktop\n").unwrap();
    wait_for("the edit reaches b", &all, 90, || {
        (read(&b_mem.join("same.md")).as_deref() == Some("edited on the desktop\n")).then_some(())
    });
    // And one the other way.
    std::fs::write(b_mem.join("only_a.md"), "edited on the laptop\n").unwrap();
    wait_for("the edit reaches a", &all, 90, || {
        (read(&a_mem.join("only_a.md")).as_deref() == Some("edited on the laptop\n")).then_some(())
    });
    assert_eq!(conflict_files(&a_mem), copies);
    assert_eq!(conflict_files(&b_mem), copies);

    // A delete on one removes the file on the other.
    std::fs::remove_file(b_mem.join("only_b.md")).unwrap();
    wait_for("the delete reaches a", &all, 90, || {
        (!a_mem.join("only_b.md").exists()).then_some(())
    });
    wait_for(
        "the two folders hold the same files again",
        &all,
        90,
        || (files(&a_mem) == files(&b_mem)).then_some(()),
    );
    assert_eq!(files(&a_mem).len(), 5);

    // The status is of a device that syncs, and has one thing for the
    // person: the copy that was kept, to merge.
    for n in [&a, &b] {
        wait_for("the device says what it has to merge", &all, 90, || {
            let s = state(n);
            (s["summary"] == "memory: 1 conflict").then_some(())
        });
    }
    // With the copy merged away on one device, both are synced.
    std::fs::remove_file(a_mem.join(&copies[0])).unwrap();
    for n in [&a, &b] {
        wait_for("the device is synced", &all, 90, || {
            let s = state(n);
            (s["state"] == "synced" && s["summary"] == "memory synced").then_some(())
        });
    }
    assert_eq!(files(&a_mem), files(&b_mem));
    assert_eq!(files(&a_mem).len(), 4);
}

/// Three devices of one person, each syncing its folder `notes` under
/// the name `lab`, with the files of `texts` on the first: the first
/// makes the phrase and adds the two others. It comes back once the
/// three folders hold the same files. Returns the twelve words.
fn three_that_sync(
    nodes: [&Node; 3],
    memories: [&Path; 3],
    notes: [&Path; 3],
    texts: &[(&str, &str)],
    all: &[&Node],
) -> String {
    for (name, text) in texts {
        std::fs::write(memories[0].join(name), text).unwrap();
    }
    for (n, notes) in nodes.iter().zip(notes) {
        syncs_notes_as_lab(n, notes);
    }
    let words = makes_a_phrase(nodes[0], "desktop");
    adds(nodes[0], nodes[1], "laptop");
    adds(nodes[0], nodes[2], "tablet");
    for n in &nodes[1..] {
        has_applied(n, 1, all);
    }
    wait_for("the three folders hold the same files", all, 150, || {
        let first = files(memories[0]);
        (first.len() == texts.len() && memories.iter().all(|memory| files(memory) == first))
            .then_some(())
    });
    words
}

/// A removal (decision 2026-10-04 §7.1 to §7.4). What the removed device
/// wrote, and the others had taken, stays as it was on each of them:
/// every file is as it was. The removed device's later edit reaches
/// nobody, and nothing that the others write reaches it. The others go
/// on syncing. The command that made the change stays until every relay
/// holds it and the device has sent what it carried, by name, and
/// `cordelia devices` says of the device that remains that it has
/// applied the change and sent what it held.
#[test]
fn a_removed_devices_later_edit_reaches_nobody_and_the_others_go_on_syncing() {
    let relay = relay_started();
    let a = device_started("a", &relay);
    let b = device_started("b", &relay);
    let c = device_started("c", &relay);
    let all = [&relay, &a, &b, &c];
    let (a_notes, a_mem) = notes_of(&a);
    let (b_notes, b_mem) = notes_of(&b);
    let (c_notes, c_mem) = notes_of(&c);
    let words = three_that_sync(
        [&a, &b, &c],
        [&a_mem, &b_mem, &c_mem],
        [&a_notes, &b_notes, &c_notes],
        &[
            ("first.md", "the first, as the desktop wrote it\n"),
            ("second.md", "the second, as the desktop wrote it\n"),
            ("MEMORY.md", "- [first](first.md)\n- [second](second.md)\n"),
        ],
        &all,
    );

    // The tablet writes, and the others take it, before it is removed.
    let by_the_tablet = "the first, as the tablet wrote it before it was removed\n";
    std::fs::write(c_mem.join("first.md"), by_the_tablet).unwrap();
    for memory in [&a_mem, &b_mem] {
        wait_for("the tablet's edit reaches the others", &all, 90, || {
            (read(&memory.join("first.md")).as_deref() == Some(by_the_tablet)).then_some(())
        });
    }
    let before = files(&a_mem);
    assert_eq!(files(&b_mem), before);

    // The desktop removes the tablet, with the phrase. Of the laptop,
    // which was added since the phrase was made, it is asked whether it
    // stays.
    let mut at = removes(&a, &key_of(&c), &["stays"], &words);
    at.says("The change is made (change 2)");
    has_applied(&b, 2, &all);
    wait_for("the tablet hears that it was removed", &all, 90, || {
        (person_of(&c)["state"] == "removed").then_some(())
    });
    // The command stays until every relay holds the change and this
    // device has sent what it carried, and says so by name.
    let said = at.done();
    assert!(said.contains("1 name sent"), "{said}");
    assert!(said.contains("this machine may be closed"), "{said}");
    wait_for(
        "the laptop is said to have sent what it held",
        &all,
        120,
        || {
            let listed = a.cli(&["devices"]);
            listed
                .contains("has applied change 2, and has sent what it held")
                .then_some(())
        },
    );

    // Every file is as it was, on both that remain: what the removed
    // device wrote before is theirs, and nothing was kept beside it.
    assert_eq!(files(&a_mem), before);
    assert_eq!(files(&b_mem), before);

    // The removed device edits a file, and writes a new one.
    std::fs::write(
        c_mem.join("second.md"),
        "written on the tablet after it was removed\n",
    )
    .unwrap();
    std::fs::write(
        c_mem.join("late.md"),
        "new on the tablet after it was removed\n",
    )
    .unwrap();

    // The others go on syncing, in both directions.
    let by_the_desktop = "the first, as the desktop wrote it after the removal\n";
    std::fs::write(a_mem.join("first.md"), by_the_desktop).unwrap();
    wait_for("the desktop's edit reaches the laptop", &all, 90, || {
        (read(&b_mem.join("first.md")).as_deref() == Some(by_the_desktop)).then_some(())
    });
    std::fs::write(
        b_mem.join("new.md"),
        "new on the laptop after the removal\n",
    )
    .unwrap();
    wait_for(
        "the laptop's new file reaches the desktop",
        &all,
        90,
        || a_mem.join("new.md").exists().then_some(()),
    );
    wait_for("the two folders hold the same files", &all, 90, || {
        (files(&a_mem) == files(&b_mem)).then_some(())
    });

    // In all that time, what the removed device wrote since reached
    // nobody: each other file is as it was, and nothing is beside one.
    let after = files(&a_mem);
    let text_of = |name: &str| after.iter().find(|(file, _)| file == name).cloned();
    assert_eq!(
        text_of("second.md").map(|(_, text)| text).as_deref(),
        Some("the second, as the desktop wrote it\n")
    );
    assert_eq!(text_of("late.md"), None);
    assert!(conflict_files(&a_mem).is_empty() && conflict_files(&b_mem).is_empty());
    assert_eq!(after.len(), before.len() + 1);
    // And nothing that the others wrote since reached it: it reads
    // nothing in the channels they moved to.
    assert_eq!(
        read(&c_mem.join("first.md")).as_deref(),
        Some(by_the_tablet)
    );
    assert!(!c_mem.join("new.md").exists());
    // Its own files are as it left them: nothing of it is removed.
    assert!(c_mem.join("late.md").exists());
}

/// An edit made on a device after another device made a change, and
/// before this one heard of it (decision 2026-10-04 §7.3, §7.4): the
/// device carries the edit when it applies the change, as an edit of the
/// version it was made on. The other device takes it as that: one
/// revision above the version it carried, with nothing kept beside the
/// file on either.
#[test]
fn an_edit_made_before_a_device_heard_of_a_change_arrives_as_an_edit_of_the_carried_version() {
    let relay = relay_started();
    let a = device_started("a", &relay);
    let mut b = device_started("b", &relay);
    let (a_notes, a_mem) = notes_of(&a);
    let (b_notes, b_mem) = notes_of(&b);
    std::fs::write(a_mem.join("notes.md"), "as both had it\n").unwrap();
    syncs_notes_as_lab(&a, &a_notes);
    syncs_notes_as_lab(&b, &b_notes);
    let words = makes_a_phrase(&a, "desktop");
    adds(&a, &b, "laptop");
    has_applied(&b, 1, &[&relay, &a, &b]);
    wait_for(
        "the file reaches the laptop",
        &[&relay, &a, &b],
        120,
        || (read(&b_mem.join("notes.md")).as_deref() == Some("as both had it\n")).then_some(()),
    );
    wait_for(
        "the laptop has sent what it holds",
        &[&relay, &a, &b],
        90,
        || has_sent_everything(&b),
    );
    let rev_of = |n: &Node| {
        let held = held(n);
        let notes = held.iter().find(|(key, _, _)| key == "notes.md");
        notes.map(|(_, rev, text)| (*rev, text.clone()))
    };
    assert_eq!(rev_of(&a), Some((1, Some("as both had it\n".to_string()))));

    // The laptop is off while the desktop makes a change: a renewal, in
    // which the laptop stays.
    b.stop();
    let mut at = renews(&a, &["stays"], &words);
    at.says("The change is made (change 2)");
    let said = at.done();
    assert!(said.contains("this machine may be closed"), "{said}");
    // The desktop has carried the version: it is the same, at its
    // revision.
    assert_eq!(rev_of(&a), Some((1, Some("as both had it\n".to_string()))));

    // The laptop, which has not heard, is edited, and then comes back.
    let edited = "edited on the laptop before it heard of the change\n";
    std::fs::write(b_mem.join("notes.md"), edited).unwrap();
    b.start();
    let all = [&relay, &a, &b];
    wait_for("the laptop is healthy", &all, 30, || healthy(&b));
    has_applied(&b, 2, &all);

    // The edit arrives on the desktop as an edit of the version it
    // carried: one revision above it, and nothing is kept beside the
    // file, there or on the laptop.
    wait_for("the edit reaches the desktop", &all, 120, || {
        (read(&a_mem.join("notes.md")).as_deref() == Some(edited)).then_some(())
    });
    assert_eq!(rev_of(&a), Some((2, Some(edited.to_string()))));
    assert_eq!(read(&b_mem.join("notes.md")).as_deref(), Some(edited));
    assert!(conflict_files(&a_mem).is_empty(), "{:?}", files(&a_mem));
    assert!(conflict_files(&b_mem).is_empty(), "{:?}", files(&b_mem));
    assert_eq!(files(&a_mem), files(&b_mem));
}

/// A relay of the test's own, under a name of its own, started.
fn relay_named(name: &'static str) -> Node {
    let mut relay = node(name, "relay", None);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    relay
}

/// A device that is set up with each of `relays`, started, and connected
/// to each of them.
fn device_at(name: &'static str, relays: &[&Node]) -> Node {
    let at: Vec<(String, Option<String>)> = relays
        .iter()
        .map(|relay| (format!("127.0.0.1:{}", relay.p2p), None))
        .collect();
    let mut device = node_with_relays(name, "personal", &at);
    device.start();
    wait_for("device healthy", &[&device], 30, || healthy(&device));
    connected_to_each(&device, relays.len());
    device
}

/// Wait until `device` is connected to each of the `relays` relays that
/// it is set up with.
fn connected_to_each(device: &Node, relays: usize) {
    wait_for("the device reaches its relays", &[device], 90, || {
        let set_up = relays_of(device);
        (set_up.len() == relays && set_up.iter().all(|relay| relay["state"] == "connected"))
            .then_some(())
    });
}

/// Whether the store of `relay` holds the change entry numbered `number`
/// of the phrase that `device` follows: the two databases are read
/// beside their nodes. The change entry is the one entry of the phrase's
/// channel, and its revision is the statement's number (decision
/// 2026-10-04 §4.6).
fn holds_the_change(relay: &Node, device: &Node, number: u64) -> bool {
    let beside = |node: &Node| {
        let conn = rusqlite::Connection::open_with_flags(
            node.data_dir().join("cordelia.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        conn
    };
    let channel: Vec<u8> = beside(device)
        .query_row("SELECT phrase_channel FROM person", [], |row| row.get(0))
        .unwrap();
    beside(relay)
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM entries WHERE channel_id = ?1 AND rev = ?2)",
            rusqlite::params![channel, number as i64],
            |row| row.get(0),
        )
        .unwrap()
}

/// What a remaining device, a removed device and two relays are before
/// the remaining device comes back (decision 2026-10-04 §4.6, §7.4).
struct LateWrite {
    /// The relay that holds the change, and the relay that the change
    /// has not reached: it holds what the removed device wrote since.
    has: Node,
    lacks: Node,
    /// The device that made the removal, stopped; the one that remains,
    /// stopped since before the removal; and the removed one, running,
    /// which has not heard.
    desktop: Node,
    laptop: Node,
    tablet: Node,
    desktop_memory: PathBuf,
    laptop_memory: PathBuf,
    /// The files that the devices held when they were last in step.
    before: Vec<(String, String)>,
}

/// What the removed device wrote after its removal: an edit of a file
/// that every device has, and a new file.
const LATE_EDIT: &str = "the second, as the tablet wrote it after it was removed\n";
const LATE_FILE: &str = "new on the tablet after it was removed\n";
const AS_THE_DESKTOP_WROTE_IT: &str = "the second, as the desktop wrote it\n";

/// Three devices of one person sync the name `lab`. The desktop and the
/// laptop are set up with two relays, and the tablet with one of them.
/// The laptop is turned off. The tablet's relay is stopped, and the
/// desktop removes the tablet: the change reaches the other relay, and
/// the desktop is then turned off, so that it tells the tablet's relay
/// nothing. That relay comes back. The tablet, which has not heard and
/// cannot, edits a file and writes a new one, in the channel that the
/// desktop has left, and its relay holds both.
fn a_removed_device_writes_late_while_another_is_off() -> LateWrite {
    let has = relay_named("has");
    let mut lacks = relay_named("lacks");
    let mut desktop = device_at("a", &[&has, &lacks]);
    let mut laptop = device_at("b", &[&has, &lacks]);
    let tablet = device_at("c", &[&lacks]);
    let (a_notes, a_mem) = notes_of(&desktop);
    let (b_notes, b_mem) = notes_of(&laptop);
    let (c_notes, c_mem) = notes_of(&tablet);
    let words = {
        let all = [&has, &lacks, &desktop, &laptop, &tablet];
        let words = three_that_sync(
            [&desktop, &laptop, &tablet],
            [&a_mem, &b_mem, &c_mem],
            [&a_notes, &b_notes, &c_notes],
            &[
                ("first.md", "the first, as the desktop wrote it\n"),
                ("second.md", AS_THE_DESKTOP_WROTE_IT),
                ("MEMORY.md", "- [first](first.md)\n- [second](second.md)\n"),
            ],
            &all,
        );
        for device in [&desktop, &laptop, &tablet] {
            wait_for("each device has sent what it holds", &all, 120, || {
                has_sent_everything(device)
            });
        }
        words
    };
    let before = files(&a_mem);

    // The laptop is off, and the tablet's relay is down, while the
    // desktop removes the tablet: the change reaches one relay.
    laptop.stop();
    lacks.stop();
    {
        let mut at = removes(&desktop, &key_of(&tablet), &["stays"], &words);
        at.says("The change is made (change 2)");
        // The relay's own store is asked, and not the desktop's status:
        // what a device says of a relay is what the relay last answered,
        // and the desktop is turned off as soon as the relay holds it.
        wait_for("the relay holds the change", &[&has, &desktop], 90, || {
            holds_the_change(&has, &desktop, 2).then_some(())
        });
    }
    desktop.stop();

    // The tablet's relay is back, and has not heard of the change. Nor
    // has the tablet: it writes on, in the channel that was left.
    lacks.start();
    wait_for("relay healthy", &[&lacks], 30, || healthy(&lacks));
    connected_to_each(&tablet, 1);
    std::fs::write(c_mem.join("second.md"), LATE_EDIT).unwrap();
    std::fs::write(c_mem.join("late.md"), LATE_FILE).unwrap();
    let all = [&lacks, &tablet];
    wait_for("the tablet has published what it wrote", &all, 90, || {
        let held = held(&tablet);
        let late = held.iter().any(|(key, _, _)| key == "late.md");
        let edit = held
            .iter()
            .any(|(key, _, text)| key == "second.md" && text.as_deref() == Some(LATE_EDIT));
        (late && edit).then_some(())
    });
    wait_for("the tablet has sent what it wrote", &all, 90, || {
        has_sent_everything(&tablet)
    });
    assert_eq!(person_of(&tablet)["state"], "applied");
    LateWrite {
        has,
        lacks,
        desktop,
        laptop,
        tablet,
        desktop_memory: a_mem,
        laptop_memory: b_mem,
        before,
    }
}

/// A device that was off during a removal comes back, and reaches a relay
/// that holds the change and a relay that holds what the removed device
/// wrote since, in the channel that was left (decision 2026-10-04 §4.6).
/// Its first act at each relay is the show, and it takes nothing until
/// each has answered: so it applies the change, and never takes what the
/// removed device wrote late. Its files are as they were, and nothing is
/// beside them.
#[test]
fn a_device_that_was_off_during_a_removal_applies_it_before_it_takes_a_late_write() {
    let LateWrite {
        has,
        lacks,
        mut desktop,
        mut laptop,
        tablet,
        desktop_memory,
        laptop_memory,
        before,
    } = a_removed_device_writes_late_while_another_is_off();

    laptop.start();
    let all = [&has, &lacks, &laptop, &tablet];
    wait_for("the laptop is healthy", &all, 30, || healthy(&laptop));
    has_applied(&laptop, 2, &all);
    // It shows the change to the other relay, which hands it to the
    // tablet: the tablet hears that it was removed. So the laptop has
    // been at the relay that holds what the tablet wrote late.
    wait_for("the tablet hears that it was removed", &all, 120, || {
        (person_of(&tablet)["state"] == "removed").then_some(())
    });
    wait_for("the laptop has sent what it holds", &all, 120, || {
        has_sent_everything(&laptop)
    });
    assert_eq!(files(&laptop_memory), before);

    // The desktop comes back, and the two go on syncing. In all that
    // time nothing of what the tablet wrote late has reached either.
    desktop.start();
    let all = [&has, &lacks, &desktop, &laptop, &tablet];
    wait_for("the desktop is healthy", &all, 30, || healthy(&desktop));
    std::fs::write(
        desktop_memory.join("after.md"),
        "new on the desktop after the removal\n",
    )
    .unwrap();
    wait_for(
        "the desktop's new file reaches the laptop",
        &all,
        120,
        || laptop_memory.join("after.md").exists().then_some(()),
    );
    for memory in [&desktop_memory, &laptop_memory] {
        let now = files(memory);
        assert_eq!(now.len(), before.len() + 1, "{now:?}");
        assert!(!memory.join("late.md").exists());
        assert_eq!(
            read(&memory.join("second.md")).as_deref(),
            Some(AS_THE_DESKTOP_WROTE_IT)
        );
        assert!(conflict_files(memory).is_empty(), "{now:?}");
    }
}

/// The same device, where the only relay it reaches when it comes back is
/// one that the change has not reached (decision 2026-10-04 §7.4, and
/// property 2): it cannot tell "nothing has changed" from "this relay
/// has not been told". It takes what the removed device wrote late, as
/// it takes any device's. When it hears of the removal it keeps that: it
/// carries each version as its own. A device that had applied the removal
/// takes each from there, and where a version differs from what its own
/// file held, its own text is kept beside the file.
#[test]
fn a_device_that_reaches_only_a_relay_without_the_change_takes_a_late_write_and_keeps_it() {
    let LateWrite {
        mut has,
        lacks,
        mut desktop,
        mut laptop,
        tablet,
        desktop_memory,
        laptop_memory,
        before,
    } = a_removed_device_writes_late_while_another_is_off();

    // The relay that holds the change is out of reach when the laptop
    // comes back. Once it has waited for that relay as long as a device
    // that wakes waits, it goes on at the other, and takes what is there.
    has.stop();
    laptop.start();
    {
        let all = [&lacks, &laptop, &tablet];
        wait_for("the laptop is healthy", &all, 30, || healthy(&laptop));
        wait_for(
            "the laptop takes what the tablet wrote late",
            &all,
            180,
            || {
                let edit = read(&laptop_memory.join("second.md"));
                let late = read(&laptop_memory.join("late.md"));
                (edit.as_deref() == Some(LATE_EDIT) && late.as_deref() == Some(LATE_FILE))
                    .then_some(())
            },
        );
        assert_eq!(person_of(&laptop)["change"], 1);
        // It took each as an edit of what it held: nothing is beside it.
        assert!(conflict_files(&laptop_memory).is_empty());
    }

    // The other relay is back: the laptop hears of the removal, applies
    // it, and keeps what it took.
    has.start();
    {
        let all = [&has, &lacks, &laptop, &tablet];
        wait_for("relay healthy", &all, 30, || healthy(&has));
        has_applied(&laptop, 2, &all);
        wait_for("the laptop has sent what it carried", &all, 150, || {
            has_sent_everything(&laptop)
        });
    }
    let carried = held(&laptop);
    let text_of = |name: &str| {
        let entry = carried.iter().find(|(key, _, _)| key == name);
        entry.and_then(|(_, _, text)| text.clone())
    };
    assert_eq!(text_of("second.md").as_deref(), Some(LATE_EDIT));
    assert_eq!(text_of("late.md").as_deref(), Some(LATE_FILE));
    assert_eq!(
        read(&laptop_memory.join("second.md")).as_deref(),
        Some(LATE_EDIT)
    );
    assert!(conflict_files(&laptop_memory).is_empty());

    // The desktop, which had applied the removal and never took what the
    // tablet wrote late, takes each version from the laptop's carry: the
    // new file as a new file, and the edit with its own text beside it.
    desktop.start();
    let all = [&has, &lacks, &desktop, &laptop, &tablet];
    wait_for("the desktop is healthy", &all, 30, || healthy(&desktop));
    wait_for(
        "the desktop takes what the laptop carried",
        &all,
        180,
        || {
            let edit = read(&desktop_memory.join("second.md"));
            let late = read(&desktop_memory.join("late.md"));
            (edit.as_deref() == Some(LATE_EDIT) && late.as_deref() == Some(LATE_FILE)).then_some(())
        },
    );
    let copies = conflict_files(&desktop_memory);
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert!(copies[0].starts_with("second.conflict-"), "{copies:?}");
    assert_eq!(
        read(&desktop_memory.join(&copies[0])).as_deref(),
        Some(AS_THE_DESKTOP_WROTE_IT)
    );
    // The copy is a file like any other, and reaches the laptop: the two
    // folders hold the same files, and one more than before but for it.
    wait_for("the two folders hold the same files", &all, 150, || {
        (files(&desktop_memory) == files(&laptop_memory)).then_some(())
    });
    assert_eq!(files(&desktop_memory).len(), before.len() + 2);
}

/// After a change, the command says that this machine may be closed only
/// once the device's own word says that it has sent what it carried, and
/// every relay it is set up with is connected and holds the change
/// (decision 2026-10-04 §7.1, step 4; §8).
///
/// Here a device carries more than it sends one relay in a minute. A
/// device is removed: the relay takes the change, and is stopped before
/// the names have gone. The command does not say that the machine may be
/// closed, and says what is missing.
#[test]
fn a_relay_lost_before_the_names_went_does_not_end_the_wait_after_a_change() {
    use cordelia_core::protocol::OUTBOX_BYTES_PER_MINUTE;
    let mut relay = relay_started();
    let a = device_started("a", &relay);
    let b = device_started("b", &relay);
    let words = pair(&a, &b, "laptop", &[&relay, &a, &b]).unwrap();

    // More than a device sends one relay in a minute: each file's entry
    // is counted at more than its text.
    let (notes, memory) = notes_of(&a);
    let files = 40;
    let text = "a memory that is kept. ".repeat(2000);
    assert!((files * text.len()) as u64 > OUTBOX_BYTES_PER_MINUTE);
    for n in 0..files {
        std::fs::write(
            memory.join(format!("note-{n:02}.md")),
            format!("{n}\n{text}"),
        )
        .unwrap();
    }
    syncs_notes_as_lab(&a, &notes);
    wait_for("a has published its folder", &[&relay, &a], 90, || {
        (held(&a).len() == files).then_some(())
    });

    // The laptop is removed. The relay takes the change, which is shown
    // to it before anything else; of what the device carried, the names
    // have not gone.
    let mut at = removes(&a, &key_of(&b), &[], &words);
    at.says("The change is made (change 2)");
    wait_for("the relay holds the change", &[&relay, &a], 30, || {
        let seen = person_of(&a);
        let relays = seen["relays"].as_array()?;
        (seen["change"] == 2 && relays.iter().all(|relay| relay["holds_latest"] == true))
            .then_some(())
    });
    let seen = person_of(&a);
    assert_eq!(seen["names"]["to_go"], json!(["lab"]), "{seen}");
    relay.stop();

    // The node sees that the relay is gone, and no row says any more
    // what waits there. The command stays, and says what is missing.
    wait_for("the device sees that its relay is gone", &[&a], 60, || {
        let seen = person_of(&a);
        (seen["not_reached"].as_array()?.len() == 1 && seen["waiting"].as_array()?.is_empty())
            .then_some(())
    });
    let said = at.hears_for(std::time::Duration::from_secs(8)).to_string();
    assert!(!said.contains("this machine may be closed"), "{said}");
    // Nor that a name is sent: with the relay gone, that is not known.
    assert!(!said.contains("1 name sent"), "{said}");
    assert!(
        said.contains("is not connected, and what is still to send there is not known until it is"),
        "{said}"
    );
    assert!(
        said.contains(
            "keep this machine on: this device has not yet sent every relay what it carried"
        ),
        "{said}"
    );
}
