//! A carry that a person asks for (decision 2026-10-04 §7.3): real
//! processes, set up with the commands a person types, with a relay of
//! the test's own on this machine.
//!
//! A device that applies a change carries what it holds, and reads the
//! channels it left no more. What a relay holds of a generation that was
//! left, beyond what the remaining devices had taken, comes in by a
//! command: `cordelia sync carry`, and `cordelia sync map` for a name
//! that the device comes to sync.

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

/// Turn sync on for `n`.
fn sync_is_turned_on(n: &Node) {
    let out = n.cli(&["sync", "claude", "--dir", &path(&n.home().join(".claude"))]);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
}

/// What `n` holds under the name `lab`, by key: each key's revision, and
/// its text (`None` for a key that is deleted).
fn held(n: &Node) -> Vec<(String, u64, Option<String>)> {
    let answer = n.post("/api/v1/channels/entries", json!({ "channel": "lab" }));
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

fn change_of(n: &Node) -> Value {
    person_of(n)["change"].clone()
}

/// What a device that never returned had sent to the relay, and that no
/// other device had taken before a change, is brought in by `cordelia
/// sync carry` (decision 2026-10-04 §7.3). The laptop is off while the
/// desktop writes and sends, and the desktop then never returns. The
/// laptop makes a change with no relay in reach, so that it carries what
/// it holds and nothing more: the desktop's last file is at the relay, in
/// the generation that was left, and reaches nobody by itself. The
/// command brings it in, as the laptop's own entry at the revision it
/// had; run again, it finds nothing more.
#[test]
fn what_a_device_that_never_returned_had_sent_is_carried_by_command() {
    let mut relay = relay_started();
    let mut laptop = device_started("laptop", &relay);
    let mut desktop = device_started("desktop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    let (l_notes, l_mem) = notes_of(&laptop);
    let (d_notes, d_mem) = notes_of(&desktop);
    std::fs::write(l_mem.join("first.md"), "what both hold\n").unwrap();
    for (n, notes) in [(&laptop, &l_notes), (&desktop, &d_notes)] {
        sync_is_turned_on(n);
        let out = n.cli(&["sync", "map", &path(notes), "lab"]);
        assert!(out.contains("Mapped ~/notes to lab."), "{out}");
    }
    wait_for(
        "the desktop has the laptop's file",
        &[&relay, &laptop, &desktop],
        120,
        || (read(&d_mem.join("first.md"))?.as_str() == "what both hold\n").then_some(()),
    );

    // The laptop is off. The desktop writes, the relay is sent it, and
    // the desktop never returns.
    laptop.stop();
    std::fs::write(d_mem.join("late.md"), "the desktop's last words\n").unwrap();
    wait_for(
        "the desktop has sent its last file",
        &[&relay, &desktop],
        120,
        || {
            let sent = held(&desktop).iter().any(|(key, _, _)| key == "late.md");
            (sent && has_sent_everything(&desktop).is_some()).then_some(())
        },
    );
    let at_the_desktop = held(&desktop);
    desktop.stop();

    // The laptop makes a change with no relay in reach: it carries what
    // it holds, which has nothing of the desktop's last file.
    relay.stop();
    laptop.start();
    wait_for("laptop healthy", &[&laptop], 30, || healthy(&laptop));
    let mut at = renews(&laptop, &["stays"], &words);
    at.says("The change is made (change 2).");
    drop(at);
    assert_eq!(change_of(&laptop), 2);
    relay.start();
    let all = [&relay, &laptop];
    wait_for("relay healthy again", &all, 30, || healthy(&relay));
    wait_for("the laptop has sent what it carried", &all, 180, || {
        has_sent_everything(&laptop)
    });
    assert_eq!(read(&l_mem.join("late.md")), None);
    assert!(
        !held(&laptop).iter().any(|(key, _, _)| key == "late.md"),
        "{:?}",
        held(&laptop)
    );

    // The carry by command: the desktop's file comes in, as the laptop's
    // own entry, at the revision that the desktop gave it.
    let said = laptop.cli(&["sync", "carry", "lab"]);
    println!("{said}");
    assert!(
        said.contains(
            "lab: 1 version brought in, each as this device's own entry at the revision it had."
        ),
        "{said}"
    );
    assert!(!said.contains("Could not read"), "{said}");
    assert!(!said.contains("now holds"), "{said}");
    assert_eq!(held(&laptop), at_the_desktop);
    wait_for("the file is in the laptop's folder", &all, 120, || {
        (read(&l_mem.join("late.md"))?.as_str() == "the desktop's last words\n").then_some(())
    });
    assert_eq!(
        read(&l_mem.join("first.md")).as_deref(),
        Some("what both hold\n")
    );
    // It is sent on, into the new channel.
    wait_for("the laptop has sent what it brought in", &all, 120, || {
        has_sent_everything(&laptop)
    });

    // Run again, with no name: every name that the device holds, and
    // nothing more to bring.
    let said = laptop.cli(&["sync", "carry"]);
    assert!(
        said.contains("lab: nothing to bring in from what was read."),
        "{said}"
    );
    assert_eq!(held(&laptop), at_the_desktop);
}

/// A device that comes to sync a name carries it first, by the command
/// that maps it (decision 2026-10-04 §7.3). Only the desktop synced the
/// name, and it never returns. After a change the name is in the new
/// generation on no device: `cordelia devices` on the laptop says so.
/// The laptop maps a folder to the name: what the desktop had sent is
/// carried before the folder's first cycle, the folder takes it, and
/// what the folder held is published beside it.
#[test]
fn a_device_that_comes_to_sync_a_name_carries_it_first() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let mut desktop = device_started("desktop", &relay);
    let all = [&relay, &laptop];
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    let (d_notes, d_mem) = notes_of(&desktop);
    std::fs::write(d_mem.join("a.md"), "written on the desktop\n").unwrap();
    std::fs::write(d_mem.join("b.md"), "and this\n").unwrap();
    sync_is_turned_on(&desktop);
    let out = desktop.cli(&["sync", "map", &path(&d_notes), "lab"]);
    assert!(out.contains("Mapped ~/notes to lab."), "{out}");
    wait_for(
        "the desktop has sent its files",
        &[&relay, &desktop],
        120,
        || {
            let sent = held(&desktop)
                .into_iter()
                .filter(|(_, _, text)| text.is_some());
            (sent.count() >= 2 && has_sent_everything(&desktop).is_some()).then_some(())
        },
    );
    wait_for(
        "the laptop hears that the name is listed",
        &all,
        120,
        || {
            // What a command that makes a change is handed of the names
            // that the personal channel lists, as the laptop holds it.
            let handed = laptop.post("/api/v1/change/prepare", json!({}));
            let names = handed["names"].as_array()?;
            names.iter().any(|name| name["name"] == "lab").then_some(())
        },
    );
    let at_the_desktop = held(&desktop);
    desktop.stop();

    // A change, on the laptop, which does not sync the name.
    sync_is_turned_on(&laptop);
    let mut at = renews(&laptop, &["stays"], &words);
    at.says("The change is made (change 2).");
    drop(at);
    wait_for("the relay holds the change", &all, 120, || {
        has_sent_everything(&laptop)
    });
    let listed = laptop.cli(&["devices"]);
    assert!(
        listed.contains("lab"),
        "the name is listed by no device yet: {listed}"
    );

    // The laptop maps a folder to the name, with a file of its own.
    let (l_notes, l_mem) = notes_of(&laptop);
    std::fs::write(l_mem.join("mine.md"), "written on the laptop\n").unwrap();
    let out = laptop.cli(&["sync", "map", &path(&l_notes), "lab"]);
    println!("{out}");
    assert!(out.contains("Mapped ~/notes to lab."), "{out}");
    assert!(
        out.contains(
            "lab: 2 versions brought in, each as this device's own entry at the revision it had."
        ),
        "{out}"
    );
    // What was carried is there at the revisions that the desktop gave.
    for carried in at_the_desktop.iter().filter(|(_, _, text)| text.is_some()) {
        assert!(
            held(&laptop).contains(carried),
            "{carried:?}: {:?}",
            held(&laptop)
        );
    }
    // The folder takes what was carried, and publishes what it held.
    wait_for("the folder has what was carried", &all, 120, || {
        let a = read(&l_mem.join("a.md"))?;
        let b = read(&l_mem.join("b.md"))?;
        (a == "written on the desktop\n" && b == "and this\n").then_some(())
    });
    wait_for("the laptop's own file is published", &all, 120, || {
        held(&laptop)
            .iter()
            .any(|(key, _, _)| key == "mine.md")
            .then_some(())
    });
    assert_eq!(
        read(&l_mem.join("mine.md")).as_deref(),
        Some("written on the laptop\n")
    );
    // Nothing was kept beside a file: each was taken as it was carried.
    let beside: Vec<String> = std::fs::read_dir(&l_mem)
        .unwrap()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.contains(".conflict-"))
        .collect();
    assert!(beside.is_empty(), "{beside:?}");
}
