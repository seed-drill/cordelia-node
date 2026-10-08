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

/// The first six words of the fingerprint of `n`'s key: what names a
/// removed key at `--from`.
fn six_words_of(n: &Node) -> String {
    let key = cordelia_crypto::bech32::decode_public_key(&key_of(n)).unwrap();
    cordelia_api::carry::naming_words(&key)
}

/// The names that `n` holds, as `cordelia devices` is told them: those
/// it has sent, and those still to go.
fn names_held(n: &Node) -> Vec<String> {
    let seen = person_of(n);
    let of = |field: &str| seen["names"][field].as_array().cloned().unwrap_or_default();
    let mut names: Vec<String> = of("sent")
        .iter()
        .chain(&of("to_go"))
        .filter_map(|name| name.as_str().map(str::to_string))
        .collect();
    names.sort();
    names
}

/// **`--from` holds a name only once something is taken** (decision
/// 2026-10-04 §7.3). The desktop alone syncs `lab`, and is removed. The
/// laptop, which never held the name, looks at what the removed key
/// signed there: the command says what it found, and after a no the
/// laptop holds no name, and nothing was done. With a yes and the phrase
/// the files come in, and the laptop holds the name and lists it, with no
/// folder mapped to it.
///
/// **Such a name can be let go:** `cordelia sync unmap lab` lets go of
/// it, and says so. Asked again, the word names nothing here.
#[test]
fn from_holds_a_name_only_once_something_is_taken_and_unmap_lets_go_of_it() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let mut desktop = device_started("desktop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    let (d_notes, d_mem) = notes_of(&desktop);
    std::fs::write(
        d_mem.join("one.md"),
        "written on the desktop
",
    )
    .unwrap();
    std::fs::write(
        d_mem.join("two.md"),
        "and this
",
    )
    .unwrap();
    sync_is_turned_on(&desktop);
    let out = desktop.cli(&["sync", "map", &path(&d_notes), "lab"]);
    assert!(out.contains("Mapped ~/notes to lab."), "{out}");
    wait_for(
        "the desktop has sent its files",
        &[&relay, &desktop],
        120,
        || (held(&desktop).len() == 2 && has_sent_everything(&desktop).is_some()).then_some(()),
    );
    let desktop_key = key_of(&desktop);
    desktop.stop();

    // The desktop is removed, on the laptop, which holds no name.
    let all = [&relay, &laptop];
    let mut at = removes(&laptop, &desktop_key, &[], &words);
    at.says("The change is made (change 2).");
    drop(at);
    wait_for("the relay holds the change", &all, 180, || {
        has_sent_everything(&laptop)
    });
    assert!(names_held(&laptop).is_empty());

    // What the removed key signed is said, and a no takes nothing: the
    // laptop holds no name for having looked.
    let mut at = laptop.at_terminal(&["sync", "carry", "lab", "--from", "desktop"]);
    at.says("What this removed key signed in lab:")
        .says("2 versions would go into slots where the new channel holds nothing.")
        .says("Bring in 2 versions into slots where the new channel holds nothing?")
        .types("no");
    let said = at.done();
    assert!(
        said.contains("That was not a yes. Nothing was done."),
        "{said}"
    );
    assert!(names_held(&laptop).is_empty(), "{:?}", names_held(&laptop));
    // Nor is there anything to let go of: the laptop syncs nothing.
    let unmapped = laptop.refused(&["sync", "unmap", "lab"]);
    assert!(unmapped.contains("Sync is off."), "{unmapped}");

    // With a yes and the phrase the files come in, and the laptop holds
    // the name and lists it.
    let mut at = laptop.at_terminal(&["sync", "carry", "lab", "--from", "desktop"]);
    at.says("Bring in 2 versions into slots").types("yes");
    at.says("The recovery phrase, twelve words").types(&words);
    let said = at.done();
    println!("{said}");
    assert!(said.contains("lab: 2 versions brought in"), "{said}");
    assert!(
        said.contains("This device now holds lab and lists it, with no folder mapped to it"),
        "{said}"
    );
    assert!(
        said.contains("To let go of it: cordelia sync unmap lab"),
        "{said}"
    );
    assert_eq!(names_held(&laptop), ["lab"]);
    let texts: Vec<Option<String>> = held(&laptop).into_iter().map(|(_, _, text)| text).collect();
    assert_eq!(
        texts,
        [
            Some("written on the desktop\n".to_string()),
            Some("and this\n".to_string())
        ]
    );
    wait_for("the laptop has sent what it carried", &all, 180, || {
        has_sent_everything(&laptop)
    });

    // A folder is mapped to the name, and unmapped again: the name is
    // still held, as it was before the folder, and the command says so,
    // and what lets go of it (decision 2026-10-04 §16).
    sync_is_turned_on(&laptop);
    let (l_notes, _) = notes_of(&laptop);
    let out = laptop.cli(&["sync", "map", &path(&l_notes), "lab"]);
    assert!(out.contains("Mapped ~/notes to lab."), "{out}");
    let said = laptop.cli(&["sync", "unmap", &path(&l_notes)]);
    assert!(
        said.contains("No longer synced from this device: ~/notes (lab)."),
        "{said}"
    );
    assert!(
        said.contains(
            "This device still holds lab, since a carry or a recovery brought it: `cordelia \
             sync unmap lab` lets it go, once nothing of it waits to be sent."
        ),
        "{said}"
    );
    assert_eq!(names_held(&laptop), ["lab"]);
    let off = laptop.cli(&["sync", "off"]);
    assert!(off.contains("Sync is off."), "{off}");
    assert_eq!(names_held(&laptop), ["lab"]);
    wait_for("the laptop has nothing more to send", &all, 180, || {
        has_sent_everything(&laptop)
    });

    // The name has no folder to unmap: unmapping its name lets go of it.
    let said = laptop.cli(&["sync", "unmap", "lab"]);
    assert!(
        said.starts_with("This device holds lab no longer. It held it by a carry"),
        "{said}"
    );
    assert!(names_held(&laptop).is_empty(), "{:?}", names_held(&laptop));
    let again = laptop.refused(&["sync", "unmap", "lab"]);
    assert!(again.contains("Sync is off."), "{again}");
}

/// The copies that a folder keeps beside its files.
fn kept_beside(memory: &Path) -> Vec<String> {
    let mut beside: Vec<String> = std::fs::read_dir(memory)
        .unwrap()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.contains(".conflict-"))
        .collect();
    beside.sort();
    beside
}

/// What a removed device wrote, and no remaining device had taken, comes
/// in only by `cordelia sync carry <name> --from`, at a terminal, with
/// the recovery phrase (decision 2026-10-04 §7.3). The desktop writes a
/// new file and writes over one that the laptop holds, the relay is sent
/// both, and the desktop is removed with no relay in reach.
///
/// - The plain command takes nothing of it, and says how much other keys
///   signed.
/// - `--from` with no key lists the removed key by the first six words of
///   its fingerprint, and takes nothing.
/// - With the key named it refuses without a terminal; at one, it says
///   what it found before it asks for anything, and a phrase that is
///   not this device's takes nothing.
/// - With the phrase, the new file comes in, into its empty slot. The
///   version that stands above the laptop's comes in only on the second
///   yes, and the laptop's text is then kept beside the file.
#[test]
fn what_a_removed_device_wrote_comes_in_only_by_from_with_the_phrase() {
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

    // The laptop is off. The desktop writes a new file, and writes over
    // the one that both hold; the relay is sent both.
    laptop.stop();
    std::fs::write(d_mem.join("late.md"), "the desktop's last words\n").unwrap();
    std::fs::write(d_mem.join("first.md"), "edited on the desktop\n").unwrap();
    wait_for(
        "the desktop has sent what it wrote",
        &[&relay, &desktop],
        120,
        || {
            let held = held(&desktop);
            let late = held.iter().any(|(key, _, _)| key == "late.md");
            let edited = held
                .iter()
                .any(|(key, rev, _)| key == "first.md" && *rev == 2);
            (late && edited && has_sent_everything(&desktop).is_some()).then_some(())
        },
    );
    let desktop_key = key_of(&desktop);
    let six_words = six_words_of(&desktop);
    desktop.stop();

    // The desktop is removed, on the laptop, with no relay in reach: the
    // laptop carries what it holds, and nothing of what the desktop
    // wrote since.
    relay.stop();
    laptop.start();
    wait_for("laptop healthy", &[&laptop], 30, || healthy(&laptop));
    let mut at = removes(&laptop, &desktop_key, &[], &words);
    at.says("The change is made (change 2).");
    drop(at);
    relay.start();
    let all = [&relay, &laptop];
    wait_for("relay healthy again", &all, 30, || healthy(&relay));
    wait_for("the laptop has sent what it carried", &all, 180, || {
        has_sent_everything(&laptop)
    });
    let before = held(&laptop);
    assert_eq!(before.len(), 1, "{before:?}");

    // The plain command takes nothing that the removed key signed.
    let said = laptop.cli(&["sync", "carry", "lab"]);
    assert!(said.contains("lab: nothing to bring in"), "{said}");
    assert!(
        said.contains("2 entries that other keys signed were left behind"),
        "{said}"
    );
    assert!(said.contains("cordelia sync carry lab --from"), "{said}");
    assert_eq!(held(&laptop), before);

    // With no key: the removed key that signed there, by its six words
    // and the label that this device knew it by, and nothing is taken.
    let listed = laptop.cli(&["sync", "carry", "lab", "--from"]);
    println!("{listed}");
    assert!(
        listed.contains("Removed keys that signed in lab"),
        "{listed}"
    );
    assert!(
        listed.contains(&format!("({six_words}) \"desktop\": 2 entries")),
        "{listed}"
    );
    assert!(listed.contains("Nothing was taken."), "{listed}");
    assert_eq!(held(&laptop), before);

    // With the key named, it asks for the phrase: not without a
    // terminal, and a name is needed.
    let no_terminal = laptop.refused(&["sync", "carry", "lab", "--from", "desktop"]);
    assert!(no_terminal.contains("terminal"), "{no_terminal}");
    let no_name = laptop.refused(&["sync", "carry", "--phrase"]);
    assert!(no_name.contains("is for one name"), "{no_name}");
    let both = laptop.refused(&["sync", "carry", "lab", "--from", "desktop", "--phrase"]);
    assert!(both.contains("are two carries"), "{both}");
    // A label that names no removed key.
    let nobody = laptop
        .at_terminal(&["sync", "carry", "lab", "--from", "phone"])
        .refused();
    assert!(nobody.contains("names no removed key"), "{nobody}");
    assert!(nobody.contains("Nothing was taken."), "{nobody}");

    // What it found is said before anything is asked. A phrase that is
    // not this device's takes nothing.
    let another = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let mut at = laptop.at_terminal(&["sync", "carry", "lab", "--from", "desktop"]);
    at.says("What this removed key signed in lab:")
        .says(&format!("({six_words}) \"desktop\""))
        .says("1 version would go into a slot where the new channel holds nothing.")
        .says("1 version stands above a version that the new channel holds: first.md.")
        .says("Those come in only on a second yes, which names them.")
        .says("A device in someone else's hands may have written any of these since")
        .says("say no unless you know it was not.")
        .says("Bring in 1 version into the slot where the new channel holds nothing?")
        .types("yes");
    at.says("Also bring in 1 version above the version that the new channel holds?")
        .says("first.md")
        .types("no");
    at.says("Those stay where they are.")
        .says("The recovery phrase, twelve words")
        .types(another);
    let refused = at.refused();
    assert!(
        refused.contains("it is not the one that this device follows: nothing was taken."),
        "{refused}"
    );
    assert_eq!(held(&laptop), before);

    // The removed device is named by its key, written whole, too.
    let mut at = laptop.at_terminal(&["sync", "carry", "lab", "--from", &desktop_key]);
    at.says("What this removed key signed in lab:")
        .says(&format!("({six_words}) \"desktop\""))
        .says("Bring in 1 version into the slot")
        .types("no");
    let said = at.done();
    assert!(
        said.contains("That was not a yes. Nothing was done."),
        "{said}"
    );

    // Anything but a yes takes nothing, and asks for no phrase.
    let mut at = laptop.at_terminal(&["sync", "carry", "lab", "--from", "desktop"]);
    at.says("Bring in 1 version into the slot").types("y");
    let said = at.done();
    assert!(
        said.contains("That was not a yes. Nothing was done."),
        "{said}"
    );
    assert!(
        !said.contains("The recovery phrase, twelve words"),
        "{said}"
    );
    assert_eq!(held(&laptop), before);

    // With the phrase: the new file comes in, into its empty slot. The
    // version above the laptop's stays where it is without the second
    // yes. (What the node is sent is passed on by this test, and kept.)
    let through = PassesOn::to(laptop.http);
    let mut at =
        laptop.at_terminal_through(through.port, &["sync", "carry", "lab", "--from", "desktop"]);
    at.says("Bring in 1 version into the slot").types("yes");
    at.says("Also bring in 1 version above").types("no");
    at.says("The recovery phrase, twelve words").types(&words);
    let said = at.done();
    println!("{said}");
    assert!(
        said.contains(
            "lab: 1 version brought in, each as this device's own entry at the revision it had."
        ),
        "{said}"
    );
    assert!(
        said.contains("1 version left: it stands above a version that the new channel holds"),
        "{said}"
    );
    wait_for("the new file is in the laptop's folder", &all, 120, || {
        (read(&l_mem.join("late.md"))?.as_str() == "the desktop's last words\n").then_some(())
    });
    assert_eq!(
        read(&l_mem.join("first.md")).as_deref(),
        Some("what both hold\n")
    );
    assert!(kept_beside(&l_mem).is_empty());

    // **A word is taken once** (§16): a program that saw the word cross
    // to the node posts the same request again, within the word's ten
    // minutes, and is refused.
    let seen = through.bodies("/api/v1/carry/from");
    assert_eq!(seen.len(), 1, "{seen:?}");
    let held_now = held(&laptop);
    let (status, refused) = laptop.post_told("/api/v1/carry/from", &seen[0]);
    assert_eq!(status, 400, "{refused}");
    assert!(
        refused
            .to_string()
            .contains("was taken before: a word is taken once"),
        "{refused}"
    );
    assert_eq!(held(&laptop), held_now);

    // Named by its six words, with the second yes: the version comes in
    // above the laptop's, and the laptop's text is kept beside the file.
    let mut at = laptop.at_terminal(&["sync", "carry", "lab", "--from", &six_words]);
    at.says("0 versions would go into slots where the new channel holds nothing.")
        .says("Also bring in 1 version above the version that the new channel holds?")
        .types("yes");
    at.says("The recovery phrase, twelve words").types(&words);
    let said = at.done();
    assert!(said.contains("lab: 1 version brought in"), "{said}");
    wait_for("the folder takes the version", &all, 120, || {
        (read(&l_mem.join("first.md"))?.as_str() == "edited on the desktop\n").then_some(())
    });
    let beside = kept_beside(&l_mem);
    assert_eq!(beside.len(), 1, "{beside:?}");
    assert_eq!(
        read(&l_mem.join(&beside[0])).as_deref(),
        Some("what both hold\n")
    );

    // Run again, there is nothing more of that key's to bring.
    let mut at = laptop.at_terminal(&["sync", "carry", "lab", "--from", "desktop"]);
    at.says("0 versions would go into slots where the new channel holds nothing.");
    let said = at.done();
    assert!(said.contains("Nothing was taken."), "{said}");
    assert!(
        !said.contains("The recovery phrase, twelve words"),
        "{said}"
    );
}

/// A generation whose secret a device never held is read with the
/// recovery phrase (decision 2026-10-04 §7.3). The desktop is off
/// through two changes. Between them the phone, which still counts,
/// writes a file that only the relay is sent, and never returns. The
/// desktop applies the second change directly: it left the first
/// generation, and never held the secret of the one between. `cordelia
/// sync carry lab` reads only the generation it left, and finds
/// nothing. With `--phrase`, the command opens the part of the change
/// entry that is for the phrase, reads the generation between, and the
/// phone's file comes in.
#[test]
fn a_generation_that_a_device_never_held_is_read_with_the_phrase() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let mut desktop = device_started("desktop", &relay);
    let mut phone = device_started("phone", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    adds(&laptop, &phone, "phone");
    let (d_notes, d_mem) = notes_of(&desktop);
    let (p_notes, p_mem) = notes_of(&phone);
    std::fs::write(d_mem.join("first.md"), "what both hold\n").unwrap();
    for (n, notes) in [(&desktop, &d_notes), (&phone, &p_notes)] {
        sync_is_turned_on(n);
        let out = n.cli(&["sync", "map", &path(notes), "lab"]);
        assert!(out.contains("Mapped ~/notes to lab."), "{out}");
    }
    wait_for(
        "the phone has the desktop's file",
        &[&relay, &desktop, &phone],
        120,
        || (read(&p_mem.join("first.md"))?.as_str() == "what both hold\n").then_some(()),
    );

    // The desktop is off. A change is made, and the phone applies it.
    desktop.stop();
    let mut at = renews(&laptop, &["stays", "stays"], &words);
    at.says("The change is made (change 2).");
    drop(at);
    wait_for(
        "the phone applies change 2",
        &[&relay, &laptop, &phone],
        120,
        || (change_of(&phone) == 2).then_some(()),
    );
    // The phone writes under it, the relay is sent it, and the phone
    // never returns.
    std::fs::write(p_mem.join("late.md"), "the phone's last words\n").unwrap();
    wait_for(
        "the phone has sent its last file",
        &[&relay, &phone],
        120,
        || {
            let sent = held(&phone).iter().any(|(key, _, _)| key == "late.md");
            (sent && has_sent_everything(&phone).is_some()).then_some(())
        },
    );
    phone.stop();

    // A second change, and the desktop returns: it applies it directly.
    let mut at = renews(&laptop, &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    wait_for("the relay holds change 3", &[&relay, &laptop], 120, || {
        has_sent_everything(&laptop)
    });
    desktop.start();
    let all = [&relay, &laptop, &desktop];
    wait_for("desktop healthy", &all, 30, || healthy(&desktop));
    wait_for("the desktop applies change 3", &all, 120, || {
        (change_of(&desktop) == 3).then_some(())
    });
    wait_for("the desktop has sent what it carried", &all, 180, || {
        has_sent_everything(&desktop)
    });
    assert_eq!(read(&d_mem.join("late.md")), None);

    // The plain command reads the generation that the desktop left: the
    // phone's file is not there.
    let said = desktop.cli(&["sync", "carry", "lab"]);
    assert!(said.contains("lab: nothing to bring in"), "{said}");

    // With the phrase: not without a terminal, and not with another's.
    let no_terminal = desktop.refused(&["sync", "carry", "lab", "--phrase"]);
    assert!(no_terminal.contains("terminal"), "{no_terminal}");
    let another = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let mut at = desktop.at_terminal(&["sync", "carry", "lab", "--phrase"]);
    at.says("the generations whose secret this device never held")
        .says("Read those generations of lab")
        .types("yes");
    at.says("The recovery phrase, twelve words").types(another);
    let refused = at.refused();
    assert!(
        refused.contains("it is not the one that this device follows: nothing was taken."),
        "{refused}"
    );
    assert_eq!(read(&d_mem.join("late.md")), None);

    // With the phrase, the generation between is read, and the phone's
    // file comes in. (What the node is sent is passed on by this test,
    // and kept.)
    let through = PassesOn::to(desktop.http);
    let mut at = desktop.at_terminal_through(through.port, &["sync", "carry", "lab", "--phrase"]);
    at.says("Read those generations of lab").types("yes");
    at.says("The recovery phrase, twelve words").types(&words);
    let said = at.done();
    println!("{said}");
    assert!(
        said.contains(
            "lab: 1 version brought in, each as this device's own entry at the revision it had."
        ),
        "{said}"
    );
    // Only the generation that the desktop never held is read so: the
    // ones whose secret the node holds are the plain command's.
    assert!(!said.contains("Could not read"), "{said}");
    wait_for("the file is in the desktop's folder", &all, 120, || {
        (read(&d_mem.join("late.md"))?.as_str() == "the phone's last words\n").then_some(())
    });

    // **What is handed on the phrase's word is bound to that word**
    // (§16). A program that saw the word and its batch cross to the node
    // posts the batch again: it was taken once. It posts versions of its
    // own under the word, as the same batch and as another: the key of
    // the run signed neither.
    let seen = through.bodies("/api/v1/carry/handed");
    assert_eq!(seen.len(), 1, "{seen:?}");
    let held_now = held(&desktop);
    let (status, again) = desktop.post_told("/api/v1/carry/handed", &seen[0]);
    assert_eq!(status, 400, "{again}");
    assert!(
        again
            .to_string()
            .contains("was taken before under this word"),
        "{again}"
    );
    let mut its_own = seen[0].clone();
    its_own["versions"][0]["text"] = "what somebody else wrote".into();
    its_own["versions"][0]["rev"] = 9.into();
    let mut another = its_own.clone();
    another["number"] = 1.into();
    for forged in [&its_own, &another] {
        let (status, refused) = desktop.post_told("/api/v1/carry/handed", forged);
        assert_eq!(status, 400, "{refused}");
        assert!(
            refused
                .to_string()
                .contains("is not signed by the key that the word"),
            "{refused}"
        );
    }
    assert_eq!(held(&desktop), held_now);

    // Run again, the new channel holds it.
    let mut at = desktop.at_terminal(&["sync", "carry", "lab", "--phrase"]);
    at.says("Read those generations of lab").types("yes");
    at.says("The recovery phrase, twelve words").types(&words);
    let said = at.done();
    assert!(said.contains("lab: nothing to bring in"), "{said}");
}
