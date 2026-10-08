//! Recovery (decision 2026-10-04 §9): real processes, set up with the
//! commands a person types, each at a pseudo-terminal, with relays of
//! the test's own on this machine.
//!
//! A person who has no device left that they trust types their recovery
//! phrase on a new machine: `cordelia recover`. The tests here go through
//! what §9 says of it: both devices lost; one that may be in someone
//! else's hands; one that the person still has; a relay that is stopped
//! while the look is made; a recovery that is cut short, and the one
//! after it; two changes made apart, found at a recovery; and that no
//! word of the phrase reaches the node.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// Turn sync on for `n`, and map its folder `notes` to `lab`.
fn syncs_lab(n: &Node) -> PathBuf {
    let (notes, memory) = notes_of(n);
    let out = n.cli(&["sync", "claude", "--dir", &path(&n.home().join(".claude"))]);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
    let out = n.cli(&["sync", "map", &path(&notes), "lab"]);
    assert!(out.contains("Mapped ~/notes to lab."), "{out}");
    memory
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

/// The text that `n` holds under `file` in `lab`.
fn text_of(n: &Node, file: &str) -> Option<String> {
    let all = held(n);
    let of_it = all.into_iter().find(|(key, _, _)| key == file)?;
    of_it.2
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
    wait_for("the device reaches its relays", &[&device], 90, || {
        let set_up = relays_of(&device);
        (set_up.len() == relays.len() && set_up.iter().all(|relay| relay["state"] == "connected"))
            .then_some(())
    });
    device
}

/// A node's database, read beside the node.
fn store_of(node: &Node) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_with_flags(
        node.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    conn
}

/// Whether the store of `relay` holds the change entry numbered `number`
/// of the phrase that `device` follows. The change entry is the one
/// entry of the phrase's channel, and its revision is the statement's
/// number (decision 2026-10-04 §4.6).
fn holds_the_change(relay: &Node, device: &Node, number: u64) -> bool {
    let channel: Option<Vec<u8>> = store_of(device)
        .query_row("SELECT phrase_channel FROM person", [], |row| row.get(0))
        .ok();
    let Some(channel) = channel else {
        return false;
    };
    store_of(relay)
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM entries WHERE channel_id = ?1 AND rev = ?2)",
            rusqlite::params![channel, number as i64],
            |row| row.get(0),
        )
        .unwrap_or(false)
}

/// The first six words of the fingerprint of the key `key`, as a
/// device's key is written: what names a removed key at `--from`.
fn six_words(key: &str) -> String {
    let key = cordelia_crypto::bech32::decode_public_key(key).unwrap();
    cordelia_api::carry::naming_words(&key)
}

/// The copies that a folder keeps beside its files.
fn kept_beside(memory: &Path) -> Vec<String> {
    std::fs::read_dir(memory)
        .unwrap()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.contains(".conflict-"))
        .collect()
}

/// A person's two devices, each set up with `relays`, which sync `lab`:
/// the laptop wrote `a.md` and the desktop wrote `b.md`, each has the
/// other's, and the relays were sent everything. With the words of their
/// recovery phrase, which was made on the laptop with `words` where
/// those are given.
struct Two {
    laptop: Node,
    desktop: Node,
    words: String,
    laptop_memory: PathBuf,
    desktop_memory: PathBuf,
}

const ON_THE_LAPTOP: &str = "written on the laptop\n";
const ON_THE_DESKTOP: &str = "written on the desktop\n";

fn two_devices(relays: &[&Node], words: Option<String>) -> Two {
    let laptop = device_at("laptop", relays);
    let desktop = device_at("desktop", relays);
    let words = match words {
        None => makes_a_phrase(&laptop, "laptop"),
        // A phrase whose words the test chose: the first statement is
        // made here with it, as the command makes it.
        Some(words) => {
            let phrase = cordelia_crypto::phrase::Phrase::parse(&words).unwrap();
            let key = cordelia_crypto::bech32::decode_public_key(&key_of(&laptop)).unwrap();
            let made = cordelia_api::person::first_entry(&phrase, &key, "laptop").unwrap();
            laptop.post(
                "/api/v1/phrase/make",
                json!({
                    "entry": hex::encode(made.entry.to_wire()),
                    "statement_key": hex::encode(made.statement_key),
                    "from": "no_phrase",
                }),
            );
            words
        }
    };
    adds(&laptop, &desktop, "desktop");
    let laptop_memory = syncs_lab(&laptop);
    let desktop_memory = syncs_lab(&desktop);
    std::fs::write(laptop_memory.join("a.md"), ON_THE_LAPTOP).unwrap();
    std::fs::write(desktop_memory.join("b.md"), ON_THE_DESKTOP).unwrap();
    let mut all: Vec<&Node> = relays.to_vec();
    all.extend([&laptop, &desktop]);
    wait_for("each device has the other's file", &all, 180, || {
        let there = read(&desktop_memory.join("a.md"))? == ON_THE_LAPTOP
            && read(&laptop_memory.join("b.md"))? == ON_THE_DESKTOP;
        there.then_some(())
    });
    wait_for("the relays were sent everything", &all, 180, || {
        has_sent_everything(&laptop).and(has_sent_everything(&desktop))
    });
    Two {
        laptop,
        desktop,
        words,
        laptop_memory,
        desktop_memory,
    }
}

/// `cordelia recover` on `new`, at a terminal, reached at `port` where
/// one is given: the phrase `words`; of each device, in the order it is
/// asked about, the answer in `answers`; and the yes. Returns the
/// command, still running, after the yes was typed.
fn recovers(new: &Node, port: Option<u16>, words: &str, answers: &[&str]) -> AtTerminal {
    let args = ["recover", "--name", new.name];
    let mut at = match port {
        Some(port) => new.at_terminal_through(port, &args),
        None => new.at_terminal(&args),
    };
    // It says first that a removal is the better way, and whose words
    // these are, and then asks for the phrase.
    at.says("Recovery is for when you have no device left that you trust.")
        .says("remove the device that is gone from it")
        .says("never type a wallet's words")
        .says("The recovery phrase, twelve words")
        .types(words);
    answers_and_yes(&mut at, answers);
    at
}

fn answers_and_yes(at: &mut AtTerminal, answers: &[&str]) {
    answers_and(at, answers, "yes");
}

/// Answer of each device, in the order it is asked about, and then type
/// `yes` at the command's yes. No answer is suggested: at the first
/// device Enter is pressed first, which answers nothing.
fn answers_and(at: &mut AtTerminal, answers: &[&str], yes: &str) {
    for (n, answer) in answers.iter().enumerate() {
        at.says("Type `have`, `lost` or `hands`: ");
        if n == 0 {
            at.types("")
                .says("That is none of the answers. No answer is suggested: type one.")
                .says("Type `have`, `lost` or `hands`: ");
        }
        at.types(answer);
    }
    at.says("The change that the recovery phrase will sign")
        .says("Recover on this machine?")
        .says("Type yes to go on")
        .types(yes);
}

/// A person with two devices loses both, and recovers on a third
/// machine, with the answer "lost or broken" for each (decision
/// 2026-10-04 §9): the new machine has every file that either had sent,
/// at the revision it had. The command says first that a removal is the
/// better way, shows each device with its words and how much it signed,
/// shows the statement that the phrase will sign, and says at the end
/// what the look found and whether anything is still to send.
///
/// **No word of the phrase, and nothing that only the phrase gives,
/// reaches the node, a log or a file**: what the node was sent is passed
/// on by this test and kept, and it, every log and every file of every
/// node are searched. The one thing that the phrase opened and the node
/// is handed is the secret of the generation recovered from, which the
/// machine keeps.
///
/// Afterwards: `recover` is refused on the machine, which follows a
/// phrase now; a folder mapped there has the files; after a restart the
/// machine goes on; and a device that was gone hears, when it comes
/// back, that it was removed.
#[test]
fn a_person_who_lost_both_devices_recovers_what_either_had_sent() {
    use cordelia_crypto::phrase::Phrase;
    let relay = relay_started();
    let words = a_phrase_of_words_that_nothing_else_says();
    let mut two = two_devices(&[&relay], Some(words.clone()));
    let at_the_laptop = held(&two.laptop);
    assert_eq!(at_the_laptop.len(), 2, "{at_the_laptop:?}");
    // The secret of the generation that will be recovered from.
    let first_secret: Vec<u8> = store_of(&two.laptop)
        .query_row("SELECT secret FROM person_secrets", [], |row| row.get(0))
        .unwrap();
    two.laptop.stop();
    two.desktop.stop();

    let mut new = device_started("new", &relay);
    // It asks for the phrase: not without a terminal.
    let no_terminal = new.refused(&["recover"]);
    assert!(no_terminal.contains("terminal"), "{no_terminal}");

    let through = PassesOn::to(new.http);
    let mut at = recovers(&new, Some(through.port), &words, &["lost", "lost"]);
    at.says("The change is made (change 2)")
        .says("It is shown to every relay first, before anything is carried.")
        .says("The look is made: 1 name read, and 2 versions carried, in 1 name.");
    let said = at.done();
    println!("{said}");
    // Each device, with whether the statement lists it or who added it,
    // and how much it signed.
    assert!(said.contains("Recovering from change 1."), "{said}");
    assert!(
        said.contains("\"laptop\", a device of change 1. It signed "),
        "{said}"
    );
    assert!(
        said.contains("\"desktop\", added since change 1, from ("),
        "{said}"
    );
    // The device that added it is named, by its words and its label.
    let added = said
        .split("\"desktop\", added since change 1, from (")
        .nth(1)
        .unwrap();
    let by = added.split(" at ").next().unwrap();
    assert!(by.ends_with(") \"laptop\""), "{by}: {said}");
    assert!(
        said.contains("No answer is suggested: each is typed."),
        "{said}"
    );
    // The statement, from the bytes that the phrase signs.
    for shown in [
        "(change 2):",
        "devices (1):",
        "\"new\"  (this machine)",
        "removed keys (2):",
        "The look takes what these wrote, as the relays hold it now:",
        "1 name is carried: lab.",
        "Every other device of yours stops when it hears of this change.",
    ] {
        assert!(said.contains(shown), "{shown}: {said}");
    }
    // What is still to send, as it stood when the look ended: the name;
    // or, with the name sent, the machine's personal channel, in which
    // it then writes that it has sent what it carried; or nothing.
    assert!(
        said.contains("keep this machine on: 1 name still to send")
            || said.contains(
                "keep this machine on: its personal channel, which lists the names, is still \
                 to send"
            )
            || said.contains("Nothing is waiting to be sent to a relay that is connected."),
        "{said}"
    );
    assert!(!said.contains("was cut short"), "{said}");

    // It has every file that either had sent, at the revision it had.
    assert_eq!(held(&new), at_the_laptop);
    let seen = person_of(&new);
    assert_eq!(seen["change"], 2);
    assert_eq!(seen["among"], "alone");
    assert_eq!(seen["devices"].as_array().unwrap().len(), 1);
    let removed: Vec<&str> = seen["removed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|key| key["label"].as_str())
        .collect();
    assert_eq!(removed.len(), 2);
    assert!(
        removed.contains(&"laptop") && removed.contains(&"desktop"),
        "{removed:?}"
    );
    wait_for(
        "the new machine has sent what it carried",
        &[&relay, &new],
        180,
        || has_sent_everything(&new),
    );

    // The phrase: no word of it, and nothing that only it gives, in what
    // the node was sent, in what the terminal showed, in a log or a file.
    let sent = through.sent();
    let sent_text = String::from_utf8_lossy(&sent).to_string();
    for asked in [
        "POST /api/v1/recover/look",
        "POST /api/v1/carry/read",
        "POST /api/v1/recover/make",
        "POST /api/v1/recover/progress",
    ] {
        assert!(sent_text.contains(asked), "{asked}: {sent_text}");
    }
    let phrase_words: Vec<&str> = words.split(' ').collect();
    let only_the_phrases: Vec<[u8; 32]> = {
        let phrase = Phrase::parse(&words).unwrap();
        vec![
            *phrase.signing_key().unwrap().seed(),
            *phrase.channel_secret().unwrap(),
            *phrase.seal_key().unwrap(),
        ]
    };
    let mut searched: Vec<(String, Vec<u8>)> = vec![
        ("what the node was sent".into(), sent.clone()),
        ("what the terminal showed".into(), said.clone().into_bytes()),
    ];
    for node in [&relay, &new, &two.laptop, &two.desktop] {
        searched.push((
            format!("the log of {}", node.name),
            std::fs::read(node.log()).unwrap(),
        ));
        for (path, bytes) in files_under(&node.data_dir()) {
            searched.push((format!("{} of {}", path.display(), node.name), bytes));
        }
    }
    let mut bytes_searched = 0;
    for (what, bytes) in &searched {
        bytes_searched += bytes.len();
        // The terminal shows the first words of keys' fingerprints,
        // which are from the list that a phrase's words are from: one
        // of them can be a word of the phrase by chance, and two in a
        // row cannot.
        if what == "what the terminal showed" {
            let two = two_words_in_a_row(bytes, &phrase_words);
            assert_eq!(two, None, "two words of the phrase are in {what}");
        } else {
            let found = words_in(bytes);
            for word in &phrase_words {
                assert!(!found.contains(*word), "the word {word:?} is in {what}");
            }
        }
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);
        for secret in &only_the_phrases {
            assert!(!has(secret), "what only the phrase gives is in {what}");
            assert!(
                !has(hex::encode(secret).as_bytes()),
                "what only the phrase gives is in {what}, in hex"
            );
        }
    }
    assert!(bytes_searched > 100_000, "{bytes_searched}");
    // What the machine keeps, and the node was handed for that: the
    // secret of the generation recovered from. It is in the request that
    // made the recovery, and in the machine's database, as a secret that
    // was left.
    assert!(
        sent_text.contains(&hex::encode(&first_secret)),
        "the secret of the generation recovered from is handed to the node"
    );
    let kept: Vec<(i64, Vec<u8>, Option<i64>)> = store_of(&new)
        .prepare("SELECT number, secret, left_at FROM person_secrets ORDER BY number")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(kept.len(), 2, "{kept:?}");
    assert_eq!((kept[0].0, &kept[0].1), (1, &first_secret));
    assert!(kept[0].2.is_some() && kept[1].2.is_none(), "{kept:?}");

    // It follows a phrase now: a recovery is refused on it.
    let again = new.at_terminal(&["recover"]).refused();
    assert!(
        again.contains("this device already follows a recovery phrase"),
        "{again}"
    );
    assert!(
        !again.contains("The recovery phrase, twelve words"),
        "{again}"
    );

    // A folder that is mapped to the name there has the files.
    let memory = syncs_lab(&new);
    wait_for("the folder has both files", &[&relay, &new], 120, || {
        let there = read(&memory.join("a.md"))? == ON_THE_LAPTOP
            && read(&memory.join("b.md"))? == ON_THE_DESKTOP;
        there.then_some(())
    });
    assert!(kept_beside(&memory).is_empty());

    // After a restart it goes on, with what it held.
    new.stop();
    new.start();
    let all = [&relay, &new];
    wait_for("the new machine is up again", &all, 30, || healthy(&new));
    assert_eq!(held(&new), at_the_laptop);
    wait_for("it has sent everything", &all, 180, || {
        has_sent_everything(&new)
    });
    // The look is not taken up again by itself.
    assert!(new.post("/api/v1/recover/progress", json!({}))["look"].is_null());
    // What the command had gone on to says so, and ends, where it finds
    // that the node was started again before the look had ended.
    let (ended, waited) = new
        .at_terminal(&["recover-made", "2"])
        .ends_within(Duration::from_secs(60));
    assert!(ended, "{waited}");
    assert!(
        waited.contains("The look was interrupted")
            && waited.contains("It is not taken up again by itself."),
        "{waited}"
    );

    // A device that was gone comes back: it is answered with the change,
    // and says that it was removed.
    two.laptop.start();
    let with_it = [&relay, &new, &two.laptop];
    wait_for("the laptop is up again", &with_it, 30, || {
        healthy(&two.laptop)
    });
    wait_for(
        "the laptop hears that it was removed",
        &with_it,
        120,
        || (person_of(&two.laptop)["state"] == "removed").then_some(()),
    );
    let says = person_of(&two.laptop)["cannot_go_on"].to_string();
    assert!(says.contains("this device was removed"), "{says}");
    let _ = (&two.laptop_memory, &two.desktop_memory);
}

/// One of the two devices may be in someone else's hands (decision
/// 2026-10-04 §9, step 3): the look takes nothing that it signed. The
/// command says so before its yes, and at the end says how much that key
/// signed that the new channels lack, and names the command that brings
/// it. What is carried of a file that it had written over is the other
/// device's version. `cordelia sync carry lab --from`, with the phrase,
/// then brings in what it wrote only into the slot where the new channel
/// holds nothing: the version that stands above another stays where it
/// is, since the name has no folder on the new machine.
#[test]
fn nothing_of_a_device_in_someone_elses_hands_comes_in_but_by_from() {
    let relay = relay_started();
    let mut two = two_devices(&[&relay], None);
    // The desktop also writes over the laptop's file.
    std::fs::write(
        two.desktop_memory.join("a.md"),
        "written over it on the desktop\n",
    )
    .unwrap();
    wait_for(
        "the desktop has sent its edit",
        &[&relay, &two.desktop],
        120,
        || {
            let edited = held(&two.desktop)
                .iter()
                .any(|(key, rev, _)| key == "a.md" && *rev == 2);
            (edited && has_sent_everything(&two.desktop).is_some()).then_some(())
        },
    );
    let desktop_words = six_words(&key_of(&two.desktop));
    two.laptop.stop();
    two.desktop.stop();

    let new = device_started("new", &relay);
    // Anything but a yes makes nothing: the machine follows no phrase.
    let mut at = new.at_terminal(&["recover", "--name", "new"]);
    at.says("The recovery phrase, twelve words")
        .types(&two.words);
    answers_and(&mut at, &["lost", "hands"], "y");
    let said = at.done();
    assert!(
        said.contains("That was not a yes. Nothing was done."),
        "{said}"
    );
    assert_eq!(person_of(&new)["state"], "no_phrase");

    let mut at = recovers(&new, None, &two.words, &["lost", "hands"]);
    at.says("The change is made (change 2)")
        .says("The look is made: 1 name read, and 1 version carried, in 1 name.");
    let said = at.done();
    println!("{said}");
    // Said before the yes: from whom nothing is taken, and how what it
    // wrote comes in.
    assert!(said.contains("It takes nothing from: "), "{said}");
    assert!(
        said.contains(
            "What they wrote comes in only by `cordelia sync carry <name> --from <device>`."
        ),
        "{said}"
    );
    assert!(
        said.contains(
            "a version of another device's that one of them had written over is what is carried"
        ),
        "{said}"
    );
    assert!(said.contains("removed keys (2):"), "{said}");
    // Said at the end: how much that key signed that the new channels
    // lack, and the command that brings it.
    assert!(
        said.contains(&format!(
            "({desktop_words}) \"desktop\" signed 2 versions that the new channels lack, in: lab."
        )),
        "{said}"
    );
    assert!(
        said.contains(&format!(
            "cordelia sync carry <name> --from \"{desktop_words}\""
        )),
        "{said}"
    );
    // Nothing of the desktop's came in: the laptop's version of the file
    // that the desktop had written over is what was carried.
    assert_eq!(
        held(&new),
        [("a.md".to_string(), 1, Some(ON_THE_LAPTOP.to_string()))]
    );

    // The command that names the key, with the phrase: what it found,
    // and that the version above another is not brought in where the
    // name has no folder.
    let mut at = new.at_terminal(&["sync", "carry", "lab", "--from", "desktop"]);
    at.says("1 version would go into a slot where the new channel holds nothing.")
        .says("1 version stands above a version that the new channel holds: a.md.")
        .says("Those are not brought in: no folder of this device's is mapped to lab")
        .says("say no unless you know it was not.")
        .says("Bring in 1 version into the slot where the new channel holds nothing?")
        .types("yes");
    at.says("The recovery phrase, twelve words")
        .types(&two.words);
    let said = at.done();
    assert!(said.contains("lab: 1 version brought in"), "{said}");
    assert!(!said.contains("Also bring in"), "{said}");
    assert_eq!(text_of(&new, "b.md").as_deref(), Some(ON_THE_DESKTOP));
    assert_eq!(text_of(&new, "a.md").as_deref(), Some(ON_THE_LAPTOP));
}

/// A device that the person still has (decision 2026-10-04 §9, steps 3,
/// 4 and 6), with two relays. The desktop is off, with an edit that it
/// has not sent. The recovery's statement lists it in neither list, and
/// the look takes what it had sent.
///
/// **The change entry reaches every relay before anything is carried:**
/// one relay is stopped as soon as the change is made, while the command
/// still waits for the look, and that relay's store holds the change.
/// The desktop then comes back with only that relay in reach: it is
/// answered with the change, stops, and says that it is not in a change
/// made on the new machine and is to be added again from there. The new
/// machine shows it as not in the last change. Added again by the two
/// commands, it carries what it holds, and its unsent edit arrives.
#[test]
fn a_device_that_the_person_still_has_stops_and_is_added_again() {
    let mut first = relay_named("relay-one");
    let mut second = relay_named("relay-two");
    let mut two = two_devices(&[&first, &second], None);
    two.laptop.stop();
    two.desktop.stop();
    std::fs::write(two.desktop_memory.join("late.md"), "not sent yet\n").unwrap();

    let new = device_at("new", &[&first, &second]);
    let mut at = recovers(&new, None, &two.words, &["lost", "have"]);
    at.says("The change is made (change 2)");
    // The second relay is stopped while the command waits for the look.
    wait_for(
        "the second relay holds the change",
        &[&second, &new],
        60,
        || holds_the_change(&second, &new, 2).then_some(()),
    );
    second.stop();
    at.says("The look is made: 1 name read, and 2 versions carried, in 1 name.");
    let said = at.done();
    println!("{said}");
    assert!(said.contains("removed keys (1):"), "{said}");
    assert!(
        said.contains("Each device that you still have has stopped, and is added again by hand"),
        "{said}"
    );
    assert!(
        said.contains(&format!("cordelia accept {}", key_of(&new))),
        "{said}"
    );
    assert!(holds_the_change(&first, &new, 2));
    assert!(holds_the_change(&second, &new, 2));
    assert_eq!(held(&new).len(), 2);

    // `cordelia devices` on the new machine: the device that the person
    // still has is not in the last change, by its label.
    let listed = new.cli(&["devices"]);
    assert!(
        listed.contains("Not in the last change (each holds what your devices held before it):"),
        "{listed}"
    );
    assert!(
        listed.contains("\"desktop\": add it again, or it was meant to go."),
        "{listed}"
    );
    let seen = person_of(&new);
    assert_eq!(seen["left_out"][0]["label"], "desktop");
    assert_eq!(seen["removed"].as_array().unwrap().len(), 1);
    assert_eq!(seen["removed"][0]["label"], "laptop");

    // The desktop comes back, with only the relay in reach that was
    // stopped during the look: it is answered with the change.
    first.stop();
    second.start();
    wait_for("the second relay is up again", &[&second], 30, || {
        healthy(&second)
    });
    two.desktop.start();
    let with_it = [&second, &two.desktop];
    wait_for("the desktop is up again", &with_it, 30, || {
        healthy(&two.desktop)
    });
    wait_for(
        "the desktop hears that it is in no list",
        &with_it,
        120,
        || (person_of(&two.desktop)["state"] == "not_listed").then_some(()),
    );
    let seen = person_of(&two.desktop);
    let says = seen["cannot_go_on"].as_str().unwrap_or_default();
    assert!(
        says.contains("this device is not in a change made on ("),
        "{says}"
    );
    assert!(says.contains("\"new\": if it is yours"), "{says}");
    assert!(
        says.contains("add it again from a device that is"),
        "{says}"
    );
    // It has stopped: its edit is not sent.
    assert_eq!(
        read(&two.desktop_memory.join("late.md")).as_deref(),
        Some("not sent yet\n")
    );

    // Added again by the two commands, it carries what it holds.
    first.start();
    wait_for("the first relay is up again", &[&first], 30, || {
        healthy(&first)
    });
    let all = [&first, &second, &new, &two.desktop];
    adds(&new, &two.desktop, "desktop");
    wait_for("the desktop has applied the change", &all, 120, || {
        let seen = person_of(&two.desktop);
        (seen["state"] == "applied" && seen["change"] == 2).then_some(())
    });
    wait_for(
        "the desktop's unsent edit reaches the new machine",
        &all,
        180,
        || (text_of(&new, "late.md")? == "not sent yet\n").then_some(()),
    );
    assert_eq!(text_of(&new, "a.md").as_deref(), Some(ON_THE_LAPTOP));
    assert_eq!(text_of(&new, "b.md").as_deref(), Some(ON_THE_DESKTOP));
}

/// Put in the store of `device`, which is stopped, `count` records of
/// additions that it signed under the statement it has applied, each of
/// a key that is nobody's: when it is started it sends them to its
/// relays, as it sends anything it wrote in its personal channel.
/// Returns the device's key.
fn signs_records(device: &Node, count: u16) -> [u8; 32] {
    use cordelia_crypto::addition::Addition;
    use cordelia_crypto::entry::{Entry, Inside, Value};
    use cordelia_crypto::identity::NodeIdentity;
    use cordelia_crypto::statement::{Device, SignedStatement};
    let identity = NodeIdentity::from_file(&device.data_dir().join("identity.key")).unwrap();
    let conn = rusqlite::Connection::open(device.data_dir().join("cordelia.db")).unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    let statement: Vec<u8> = conn
        .query_row("SELECT statement FROM person", [], |row| row.get(0))
        .unwrap();
    let statement = SignedStatement::from_bytes(&statement).unwrap().statement;
    let secret: Vec<u8> = conn
        .query_row(
            "SELECT secret FROM person_secrets WHERE left_at IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let secret: [u8; 32] = secret.try_into().unwrap();
    let personal = cordelia_crypto::derive::personal_secret(&secret).unwrap();
    let rev = (statement.number << cordelia_core::protocol::REV_COUNT_BITS) + 1;
    let now = chrono::Utc::now().timestamp();
    for n in 0..count {
        let mut seed = [0x5a; 32];
        seed[..2].copy_from_slice(&n.to_be_bytes());
        let key = NodeIdentity::from_seed(seed).unwrap().public_key();
        let added = Device::new(key, &format!("added {n}")).unwrap();
        let record = Addition::under(&statement, added, identity.public_key(), now as u64)
            .unwrap()
            .sign(&identity)
            .unwrap();
        let inside = Inside {
            name: cordelia_api::person::added_name(&key).unwrap(),
            value: Value::Other(record.to_bytes().unwrap()),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&personal, &identity, rev, &inside)
            .unwrap()
            .check()
            .unwrap();
        cordelia_storage::entries::store(&conn, &entry, now).unwrap();
    }
    identity.public_key()
}

/// **One device that counts cannot push the person's other devices out
/// of a recovery by what it signs** (decision 2026-10-04 §9, step 3). A
/// change lists the laptop and the desktop. The laptop, which is first in
/// its list, then signs 300 records of additions: 62 of them count, and
/// the others do not. The desktop is shown all the same, straight after
/// the laptop, and asked about: what it wrote comes back.
///
/// A record that does not count is shown as that, and nothing is asked
/// of it: its key is not made a removed key. What could not be shown
/// beyond the 256 rows is kept as left out on the new machine, and
/// `cordelia devices` shows each with its key.
#[test]
fn a_device_that_signs_hundreds_of_records_pushes_no_device_out_of_a_recovery() {
    let relay = relay_started();
    let mut two = two_devices(&[&relay], None);
    // A change that lists both, the laptop first.
    let mut at = renews(&two.laptop, &["stays"], &two.words);
    at.says("The change is made (change 2).");
    drop(at);
    let all = [&relay, &two.laptop, &two.desktop];
    wait_for("the desktop applies change 2", &all, 120, || {
        (person_of(&two.desktop)["change"] == 2).then_some(())
    });
    // The desktop writes a file under that change.
    const SINCE: &str = "written on the desktop since\n";
    std::fs::write(two.desktop_memory.join("c.md"), SINCE).unwrap();
    wait_for("the relay was sent everything", &all, 180, || {
        let there = text_of(&two.desktop, "c.md")? == SINCE;
        there
            .then_some(())
            .and(has_sent_everything(&two.laptop))
            .and(has_sent_everything(&two.desktop))
    });
    two.desktop.stop();

    // The laptop signs 300 records, and the relay is sent each.
    two.laptop.stop();
    let laptop_key = signs_records(&two.laptop, 300);
    two.laptop.start();
    wait_for("the laptop is up again", &[&relay, &two.laptop], 30, || {
        healthy(&two.laptop)
    });
    wait_for(
        "the relay holds the records",
        &[&relay, &two.laptop],
        180,
        || {
            let held: i64 = store_of(&relay)
                .query_row(
                    "SELECT COUNT(*) FROM entries WHERE author = ?1",
                    rusqlite::params![laptop_key.as_slice()],
                    |row| row.get(0),
                )
                .ok()?;
            (held >= 300).then_some(())
        },
    );
    two.laptop.stop();

    // The laptop may be in someone else's hands, and so may each key
    // that it added and that counts: 62 of them. The desktop is lost.
    let new = device_started("new", &relay);
    let mut answers = vec!["hands", "lost"];
    answers.extend(std::iter::repeat_n("hands", 62));
    let mut at = recovers(&new, None, &two.words, &answers);
    at.says("The change is made (change 3)")
        .says("The look is made: 1 name read, and ");
    let said = at.done();
    println!("{said}");
    assert!(said.contains("Recovering from change 2."), "{said}");
    assert!(
        said.contains("\"desktop\", a device of change 2. It signed "),
        "{said}"
    );
    // Each record that does not count is shown as that, and is asked
    // nothing: 256 rows in all, of which 64 count.
    assert_eq!(
        said.matches("by a record that does not count").count(),
        192,
        "{said}"
    );
    assert_eq!(
        said.matches("It is no device: nothing is asked of it")
            .count(),
        192,
        "{said}"
    );
    assert!(
        said.contains("46 more records beyond the 256 that are shown: nothing is asked of those."),
        "{said}"
    );
    assert!(
        said.contains(
            "this machine keeps each as left out: `cordelia devices` shows it with its key"
        ),
        "{said}"
    );
    // The devices that count are removed, and no other key.
    assert!(said.contains("removed keys (64):"), "{said}");
    assert!(!said.contains("Not every answer could be kept"), "{said}");

    // What the desktop wrote comes back.
    assert_eq!(text_of(&new, "b.md").as_deref(), Some(ON_THE_DESKTOP));
    assert_eq!(text_of(&new, "c.md").as_deref(), Some(SINCE));
    let seen = person_of(&new);
    assert_eq!(seen["change"], 3);
    assert_eq!(seen["removed"].as_array().unwrap().len(), 64);
    let left_out = seen["left_out"].as_array().unwrap();
    assert_eq!(left_out.len(), 46, "{left_out:?}");
    assert!(
        left_out.iter().all(|kept| kept["key"].is_string()),
        "{left_out:?}"
    );
    let listed = new.cli(&["devices"]);
    let first = left_out[0]["key"].as_str().unwrap();
    assert!(
        listed.contains(&format!(
            "{first}: the recovery could not show it, and asked nothing of it."
        )),
        "{listed}"
    );
}

/// **No device pushes another out of a recovery by filling the 64**
/// (decision 2026-10-04 §9, step 3). A change lists the laptop and the
/// desktop. The desktop then adds a phone, which syncs `lab` and writes
/// a file there. The laptop signs 62 records of additions, which a
/// recovery reads first: with them 64 devices count, and the phone's
/// record finds no room.
///
/// The laptop may be in someone else's hands, and the desktop is lost.
/// The phone is shown with the reason that it does not count, and is
/// asked about all the same, since the desktop added it. Said to be
/// lost, its key is removed, and the look takes nothing from it: what it
/// wrote comes in by `cordelia sync carry lab --from`, with the phrase.
#[test]
fn a_device_added_since_is_asked_about_where_only_the_bound_of_64_kept_it_out() {
    let relay = relay_started();
    let mut two = two_devices(&[&relay], None);
    // A change that lists both, the laptop first.
    let mut at = renews(&two.laptop, &["stays"], &two.words);
    at.says("The change is made (change 2).");
    drop(at);
    let all = [&relay, &two.laptop, &two.desktop];
    wait_for("the desktop applies change 2", &all, 120, || {
        (person_of(&two.desktop)["change"] == 2).then_some(())
    });
    wait_for("the relay was sent everything", &all, 180, || {
        has_sent_everything(&two.laptop).and(has_sent_everything(&two.desktop))
    });
    // The desktop adds a phone, which syncs `lab` and writes a file.
    let mut phone = device_started("phone", &relay);
    adds(&two.desktop, &phone, "phone");
    let phone_memory = syncs_lab(&phone);
    const ON_THE_PHONE: &str = "written on the phone\n";
    std::fs::write(phone_memory.join("p.md"), ON_THE_PHONE).unwrap();
    let all = [&relay, &two.laptop, &two.desktop, &phone];
    wait_for("the relay was sent the phone's file", &all, 180, || {
        let there = text_of(&phone, "p.md")? == ON_THE_PHONE;
        there
            .then_some(())
            .and(has_sent_everything(&phone))
            .and(has_sent_everything(&two.desktop))
    });
    phone.stop();
    two.desktop.stop();

    // The laptop signs 62 records, and the relay is sent each.
    let laptop_key = cordelia_crypto::bech32::decode_public_key(&key_of(&two.laptop)).unwrap();
    two.laptop.stop();
    let held_of_the_laptop = || -> Option<i64> {
        store_of(&relay)
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE author = ?1",
                rusqlite::params![laptop_key.as_slice()],
                |row| row.get(0),
            )
            .ok()
    };
    let before = held_of_the_laptop().unwrap();
    assert_eq!(signs_records(&two.laptop, 62), laptop_key);
    two.laptop.start();
    wait_for("the laptop is up again", &[&relay, &two.laptop], 30, || {
        healthy(&two.laptop)
    });
    wait_for(
        "the relay holds the records",
        &[&relay, &two.laptop],
        180,
        || {
            let held = held_of_the_laptop()? >= before + 62;
            held.then_some(()).and(has_sent_everything(&two.laptop))
        },
    );
    two.laptop.stop();

    // The laptop may be in someone else's hands, and so may each of the
    // 62 keys that it added, which count. The desktop is lost, and so is
    // the phone, which is asked about last.
    let new = device_started("new", &relay);
    let mut answers = vec!["hands", "lost"];
    answers.extend(std::iter::repeat_n("hands", 62));
    answers.push("lost");
    let mut at = recovers(&new, None, &two.words, &answers);
    at.says("The change is made (change 3)")
        .says("The look is made: 1 name read, and ");
    let said = at.done();
    println!("{said}");
    assert!(said.contains("Recovering from change 2."), "{said}");
    // The phone, with the device that added it and the reason that it
    // does not count: and what each answer does for it.
    let of_the_phone = said
        .split("\"phone\", added since change 2, from (")
        .nth(1)
        .unwrap_or_else(|| panic!("{said}"));
    let by = of_the_phone.split(" at ").next().unwrap();
    assert!(by.ends_with(") \"desktop\""), "{by}: {said}");
    assert!(
        of_the_phone
            .contains(", by a record that does not count: 64 devices counted already. It signed "),
        "{said}"
    );
    assert!(
        of_the_phone.contains(
            "That is the one thing its record fails for, so it is asked about all the same."
        ),
        "{said}"
    );
    assert!(
        !said.contains("It is no device: nothing is asked of it"),
        "{said}"
    );
    // The room for removed keys was worked out with it: nothing is said,
    // since each answer could be kept.
    assert!(!said.contains("Not every answer could be kept"), "{said}");
    // It is removed, with the 64 that count.
    assert!(said.contains("removed keys (65):"), "{said}");
    let nothing = said
        .split("It takes nothing from: ")
        .nth(1)
        .unwrap_or_else(|| panic!("{said}"));
    let nothing = nothing.split(". What they wrote").next().unwrap();
    assert!(nothing.contains("\"phone\""), "{said}");

    // The look took what the desktop wrote, and nothing of the phone: it
    // says how much the phone signed that the new channels lack.
    assert_eq!(text_of(&new, "b.md").as_deref(), Some(ON_THE_DESKTOP));
    assert_eq!(text_of(&new, "p.md"), None);
    assert!(
        said.contains("\"phone\" signed 1 version that the new channels lack, in: lab."),
        "{said}"
    );
    assert_eq!(person_of(&new)["removed"].as_array().unwrap().len(), 65);

    // Its key is a removed key: what it wrote comes in by the command
    // that names it, with the phrase.
    let mut at = new.at_terminal(&["sync", "carry", "lab", "--from", "phone"]);
    at.says("What this removed key signed in lab:")
        .says("1 version would go into a slot where the new channel holds nothing.")
        .says("Bring in 1 version into the slot where the new channel holds nothing?")
        .types("yes");
    at.says("The recovery phrase, twelve words")
        .types(&two.words);
    let said = at.done();
    assert!(said.contains("lab: 1 version brought in"), "{said}");
    assert_eq!(text_of(&new, "p.md").as_deref(), Some(ON_THE_PHONE));
}

/// What `n` holds under the name `name`, by key, with its text.
fn held_under(n: &Node, name: &str) -> Vec<(String, Option<String>)> {
    let answer = n.post("/api/v1/channels/entries", json!({ "channel": name }));
    let mut held: Vec<(String, Option<String>)> = answer["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            (
                entry["key"].as_str().unwrap_or_default().to_string(),
                entry["content"].as_str().map(str::to_string),
            )
        })
        .collect();
    held.sort();
    held
}

/// **A recovery reads more channels than one connection has places for**
/// (decision 2026-10-04 §16). The relay here remembers the proofs of 16
/// channels for one connection, and the new machine goes by the same
/// number. The person has five names, in two generations: the look reads
/// ten channels of generations that were left, after the command has
/// read three, while the machine comes to hold six channels of its own.
///
/// The read counts each proof that it sends, and keeps a place back for
/// each channel of the machine's own. Where a connection has no room
/// left, it is made again, and the look goes on from the name it was at:
/// every name is read, and every file comes back. And the machine's own
/// channels have their places: what it carried is sent.
#[test]
fn a_recovery_reads_more_names_than_one_connection_has_places_for() {
    const NAMES: [&str; 5] = ["five", "four", "one", "three", "two"];
    let mut relay = node("relay", "relay", None);
    relay.proofs_on_a_connection(16);
    relay.start();
    wait_for("relay healthy", &[&relay], 30, || healthy(&relay));
    let mut laptop = device_started("laptop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    let out = laptop.cli(&[
        "sync",
        "claude",
        "--dir",
        &path(&laptop.home().join(".claude")),
    ]);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
    for name in NAMES {
        let folder = laptop.home().join(format!("notes-{name}"));
        std::fs::create_dir_all(&folder).unwrap();
        let memory = claude_folder(&laptop.home(), &folder);
        std::fs::write(memory.join("a.md"), format!("written under {name}\n")).unwrap();
        let out = laptop.cli(&["sync", "map", &path(&folder), name]);
        assert!(out.contains(&format!("to {name}.")), "{out}");
    }
    let all = [&relay, &laptop];
    let each_is_held = |n: &Node| {
        NAMES.iter().try_for_each(|name| {
            let said = format!("written under {name}\n");
            (held_under(n, name) == [("a.md".to_string(), Some(said))]).then_some(())
        })
    };
    wait_for("the relay was sent each name", &all, 180, || {
        each_is_held(&laptop).and(has_sent_everything(&laptop))
    });
    // A change: each name is in two generations at the relay.
    let mut at = renews(&laptop, &[], &words);
    at.says("The change is made (change 2).");
    drop(at);
    wait_for("the relay was sent what was carried", &all, 180, || {
        let applied = person_of(&laptop)["change"] == 2;
        (applied && person_of(&laptop)["devices"][0]["sent"] == true)
            .then_some(())
            .and(has_sent_everything(&laptop))
    });
    laptop.stop();

    let mut new = node("new", "personal", Some(relay.p2p));
    new.proofs_on_a_connection(16);
    new.start();
    wait_for("new machine healthy", &[&new], 30, || healthy(&new));
    wait_for("it reaches its relay", &[&new, &relay], 60, || {
        has_hot_peer(&new)
    });
    let mut at = recovers(&new, None, &words, &["lost"]);
    at.says("The change is made (change 3)")
        .says("The look is made: 5 names read, and 5 versions carried, in 5 names.");
    let said = at.done();
    println!("{said}");
    assert!(!said.contains("Could not read"), "{said}");
    // Every file came back, under each name.
    assert_eq!(each_is_held(&new), Some(()));
    // The connection had no room left, and was made again.
    let log = std::fs::read_to_string(new.log()).unwrap();
    assert!(
        log.contains("the connection to a relay is made again"),
        "{}",
        new.log_tail()
    );
    // And the machine's own channels have their places on the
    // connection there is now: what it carried is sent.
    wait_for(
        "the new machine has sent what it carried",
        &[&relay, &new],
        180,
        || has_sent_everything(&new),
    );
}

/// **A proof goes with the session it was made over** (decision
/// 2026-10-04 §16). The command is told the session of each relay's
/// connection before it asks for the phrase. Here the relay is stopped
/// and started while the command waits for the phrase, so the connection
/// that the machine has when the words are typed is another one.
///
/// The node does not send a proof on a connection that it was not made
/// for: it says that the connection changed. The command asks for the
/// sessions again, makes its proofs again, and reads: the recovery goes
/// on, and every file comes back. A relay is never said to hold nothing
/// of the phrase for this.
#[test]
fn a_recovery_reads_at_a_connection_that_changed_after_its_session_was_said() {
    let mut relay = relay_started();
    let mut laptop = device_started("laptop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    let memory = syncs_lab(&laptop);
    std::fs::write(memory.join("a.md"), ON_THE_LAPTOP).unwrap();
    wait_for(
        "the relay was sent the file",
        &[&relay, &laptop],
        180,
        || {
            (text_of(&laptop, "a.md")? == ON_THE_LAPTOP)
                .then_some(())
                .and(has_sent_everything(&laptop))
        },
    );
    laptop.stop();

    let new = device_started("new", &relay);
    let session_now = |n: &Node| -> Option<String> {
        let said = n.post("/api/v1/carry/sessions", json!({}));
        assert_eq!(said["sessions"].as_array().unwrap().len(), 1, "{said}");
        said["sessions"][0]["session"].as_str().map(str::to_string)
    };
    let through = PassesOn::to(new.http);
    let mut at = new.at_terminal_through(through.port, &["recover", "--name", "new"]);
    at.says("The recovery phrase, twelve words");
    // The command was told the session of the connection there is now.
    let before = session_now(&new).expect("the relay is connected");

    // The relay goes and comes back: the machine has another connection
    // to it, with a session of its own.
    relay.stop();
    relay.start();
    wait_for("relay healthy again", &[&relay], 30, || healthy(&relay));
    let after = wait_for("the connection is another", &[&new, &relay], 90, || {
        session_now(&new).filter(|session| *session != before)
    });

    at.types(&words);
    answers_and_yes(&mut at, &["lost"]);
    at.says("The change is made (change 2)")
        .says("The look is made: 1 name read, and 1 version carried, in 1 name.");
    let said = at.done();
    println!("{said}");
    assert!(!said.contains("Could not read"), "{said}");
    assert!(!said.contains("holds a change"), "{said}");
    assert_eq!(text_of(&new, "a.md").as_deref(), Some(ON_THE_LAPTOP));

    // What crossed to the node: the first proof was made over the
    // session from before, and said so; the sessions were asked for
    // again; and the proofs after that were made over the new one.
    let made_over: Vec<String> = through
        .bodies("/api/v1/carry/read")
        .iter()
        .map(|body| {
            let proofs = body["proofs"].as_array().unwrap();
            assert_eq!(proofs.len(), 1, "{body}");
            proofs[0]["session"].as_str().unwrap().to_string()
        })
        .collect();
    assert!(made_over.len() >= 2, "{made_over:?}");
    assert_eq!(made_over[0], before);
    assert!(
        made_over[1..].iter().all(|session| *session == after),
        "{made_over:?} {after}"
    );
    assert_eq!(through.bodies("/api/v1/carry/sessions").len(), 1);
}

/// A recovery that is cut short, and the one after it (decision
/// 2026-10-04 §9). The relay has no room for a new channel: it takes the
/// first machine's change entry, which needs none, and nothing that the
/// machine carried. The machine is then lost.
///
/// The next recovery starts from the first machine's statement, under
/// which that machine alone counts. Its personal channel is at no relay,
/// so the names are read in the generation before, where the keys that
/// the statement removed had listed them. It says that the earlier
/// recovery was cut short, and, for each removed key, how much that key
/// signed that the new channels lack. What the two devices wrote comes
/// in by `cordelia sync carry lab --from`, with both keys named in one
/// run, each by the first six words of its fingerprint: the second
/// machine never knew either by a label.
///
/// **The command never ends its look saying less than "keep this machine
/// on" while what it carried is unsent.** What is still to send is asked
/// of the relays that the node is connected to, and the node says which
/// those are from the moment a relay is reached: the first machine here
/// would otherwise be told, for as long as its governor has not ticked,
/// that no relay is connected and so that nothing waits.
#[test]
fn a_recovery_that_was_cut_short_is_recovered_from_and_the_rest_comes_by_from() {
    let mut relay = relay_started();
    let mut two = two_devices(&[&relay], None);
    let (laptop_words, desktop_words) = (
        six_words(&key_of(&two.laptop)),
        six_words(&key_of(&two.desktop)),
    );
    two.laptop.stop();
    two.desktop.stop();

    // The relay may hold what it holds now, and no more: a new channel
    // is refused, and a newer change entry is taken.
    relay.stop();
    let used = cordelia_storage::relay::used_bytes(&store_of(&relay)).unwrap();
    relay.max_storage_bytes(used);
    relay.start();
    wait_for("relay healthy again", &[&relay], 30, || healthy(&relay));

    // The first machine's governor ticks only every half minute: what
    // the command says at its end is what the node knows from when its
    // relay was reached, and not from a tick that came before that.
    let mut first = node("first", "personal", Some(relay.p2p));
    first.governor_tick_secs(30);
    first.start();
    wait_for("device healthy", &[&first], 30, || healthy(&first));
    wait_for("device reaches its relay", &[&first, &relay], 60, || {
        has_hot_peer(&first)
    });
    let mut at = recovers(&first, None, &two.words, &["lost", "lost"]);
    at.says("The change is made (change 2)")
        .says("The look is made: 1 name read, and 2 versions carried, in 1 name.");
    let said = at.done();
    // What it carried cannot be sent: the relay has no room for a new
    // channel.
    assert!(
        said.contains("keep this machine on: 1 name still to send"),
        "{said}"
    );
    wait_for(
        "the relay holds the first machine's change",
        &[&relay, &first],
        60,
        || holds_the_change(&relay, &first, 2).then_some(()),
    );
    assert_eq!(held(&first).len(), 2);
    // What a status goes by for that: the name is held by the recovery,
    // with no folder mapped to it, and waits whatever sync says. The
    // machine maps nothing, and sync is off on it.
    let names = person_of(&first)["names"].clone();
    assert_eq!(names["to_go"], json!(["lab"]), "{names}");
    assert_eq!(names["carried_to_go"], json!(["lab"]), "{names}");
    assert!(names["carried_to_go_since"].is_i64(), "{names}");
    first.stop();

    // The second machine.
    let second = device_started("second", &relay);
    let mut at = recovers(&second, None, &two.words, &["lost"]);
    at.says("The change is made (change 3)")
        .says("The look is made: 1 name read, and 0 versions carried, in 0 names.");
    let said = at.done();
    println!("{said}");
    assert!(said.contains("Recovering from change 2."), "{said}");
    assert!(said.contains("\"first\", a device of change 2."), "{said}");
    assert!(said.contains("1 name is carried: lab."), "{said}");
    assert!(said.contains("removed keys (3):"), "{said}");
    for words in [&laptop_words, &desktop_words] {
        assert!(
            said.contains(&format!(
                "the device ({words}) signed 1 version that the new channels lack, in: lab."
            )),
            "{words}: {said}"
        );
    }
    assert!(
        said.contains("never wrote that it had sent what it carried"),
        "{said}"
    );
    assert!(said.contains("was cut short"), "{said}");
    assert!(held(&second).is_empty(), "{:?}", held(&second));

    // It never knew either device by a label: a label names none.
    let by_label = second
        .at_terminal(&["sync", "carry", "lab", "--from", "laptop"])
        .refused();
    assert!(by_label.contains("names no removed key"), "{by_label}");
    // With no key, each removed key that signed there is listed.
    let listed = second.cli(&["sync", "carry", "lab", "--from"]);
    assert!(
        listed.contains(&format!("the device ({laptop_words}): 1 entry")),
        "{listed}"
    );
    assert!(
        listed.contains(&format!("the device ({desktop_words}): 1 entry")),
        "{listed}"
    );

    // Both keys in one run.
    let mut at = second.at_terminal(&[
        "sync",
        "carry",
        "lab",
        "--from",
        &laptop_words,
        "--from",
        &desktop_words,
    ]);
    at.says("What these removed keys signed in lab (of each file, the newest version among them):")
        .says("2 versions would go into slots where the new channel holds nothing.")
        .says("If one of them was in someone else's hands")
        .says("Bring in 2 versions into slots where the new channel holds nothing?")
        .types("yes");
    at.says("The recovery phrase, twelve words")
        .types(&two.words);
    let said = at.done();
    assert!(said.contains("lab: 2 versions brought in"), "{said}");
    assert_eq!(text_of(&second, "a.md").as_deref(), Some(ON_THE_LAPTOP));
    assert_eq!(text_of(&second, "b.md").as_deref(), Some(ON_THE_DESKTOP));
}

/// **A recovery says at which relay the personal channel was not read**
/// (decision 2026-10-04 §9, step 3; §16). A person's two devices are set
/// up with two relays, make a second change, and are both lost. One
/// relay is down when the new machine recovers: the personal channel of
/// the change recovered from is read to its end at the other, and the
/// command goes on. Before its yes it says at which relay the channel
/// could not be read, and that devices added since and names may be
/// missing. **It says the same of the personal channel of the generation
/// before, which is read for names,** by that change's number.
#[test]
fn a_recovery_says_at_which_relay_the_personal_channel_was_not_read() {
    let first = relay_named("relay-one");
    let mut second = relay_named("relay-two");
    let mut two = two_devices(&[&first, &second], None);
    // A second change, which lists both: the first is a generation
    // before, whose personal channel a recovery reads for names.
    let mut at = renews(&two.laptop, &["stays"], &two.words);
    at.says("The change is made (change 2).");
    drop(at);
    let all = [&first, &second, &two.laptop, &two.desktop];
    wait_for("the desktop applies change 2", &all, 120, || {
        (person_of(&two.desktop)["change"] == 2).then_some(())
    });
    wait_for("the relays were sent everything", &all, 180, || {
        has_sent_everything(&two.laptop).and(has_sent_everything(&two.desktop))
    });
    two.laptop.stop();
    two.desktop.stop();
    let new = device_at("new", &[&first, &second]);
    let down = format!("127.0.0.1:{}", second.p2p);
    second.stop();
    wait_for(
        "the new machine has lost the second relay",
        &[&first, &new],
        120,
        || {
            let lost = |relay: &Value| relay["state"] != "connected";
            relays_of(&new).iter().any(lost).then_some(())
        },
    );

    let mut at = recovers(&new, None, &two.words, &["lost", "lost"]);
    at.says("The change is made (change 3)")
        .says("The look is made");
    let said = at.done();
    println!("{said}");
    assert!(said.contains("Recovering from change 2."), "{said}");
    assert!(
        said.contains(&format!(
            "Could not read the personal channel at {down} to its end (not reached)."
        )),
        "{said}"
    );
    let missing = format!(
        "The personal channel of the change recovered from could not be read to its end at \
         {down}: devices added since that change, and names, may be missing here."
    );
    let warned = said.find(&missing).unwrap_or_else(|| panic!("{said}"));
    let asked = said.find("Recover on this machine?").unwrap();
    assert!(warned < asked, "{said}");
    // The generation before, by its change's number.
    let before = format!(
        "The personal channel of change 1, which is read for names, could not be read to its \
         end at {down}: names that are listed only there may be missing."
    );
    let warned = said.find(&before).unwrap_or_else(|| panic!("{said}"));
    assert!(warned < asked, "{said}");
    // It was read to its end at one relay: what a read in part costs is
    // not said.
    assert!(!said.contains("A device that is missing"), "{said}");
    // What was read is carried.
    assert!(said.contains("1 name is carried: lab."), "{said}");
    assert_eq!(text_of(&new, "a.md").as_deref(), Some(ON_THE_LAPTOP));
    assert_eq!(text_of(&new, "b.md").as_deref(), Some(ON_THE_DESKTOP));
}

/// Two changes that were made apart are found at a recovery (decision
/// 2026-10-04 §9, step 2). The laptop makes a change that only the first
/// relay is shown, and the desktop one that only the second is shown:
/// each relay holds an entry that is not on the other's chain. The
/// command shows both lists and asks which to recover from, and the
/// statement it makes settles the two: each device, on either branch, is
/// answered with it and says that it was removed, and neither says that
/// two changes were made apart.
#[test]
fn two_changes_made_apart_are_found_and_settled_at_a_recovery() {
    let mut first = relay_named("relay-one");
    let mut second = relay_named("relay-two");
    let mut laptop = device_at("laptop", &[&first, &second]);
    let mut desktop = device_at("desktop", &[&first, &second]);
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    // A change that lists both, which both apply.
    let mut at = renews(&laptop, &["stays"], &words);
    at.says("The change is made (change 2).");
    drop(at);
    let all = [&first, &second, &laptop, &desktop];
    wait_for("the desktop applies change 2", &all, 120, || {
        (person_of(&desktop)["change"] == 2).then_some(())
    });
    wait_for("both relays hold change 2", &all, 120, || {
        (holds_the_change(&first, &laptop, 2) && holds_the_change(&second, &laptop, 2))
            .then_some(())
    });

    // The laptop makes a change that only the first relay is shown.
    desktop.stop();
    second.stop();
    let mut at = renews(&laptop, &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    wait_for(
        "the first relay holds the laptop's change",
        &[&first, &laptop],
        120,
        || holds_the_change(&first, &laptop, 3).then_some(()),
    );
    laptop.stop();

    // The desktop makes one that only the second relay is shown.
    first.stop();
    second.start();
    wait_for("the second relay is up again", &[&second], 30, || {
        healthy(&second)
    });
    desktop.start();
    wait_for("the desktop is up again", &[&second, &desktop], 30, || {
        healthy(&desktop)
    });
    wait_for(
        "the desktop reaches the second relay",
        &[&second, &desktop],
        90,
        || {
            relays_of(&desktop)
                .iter()
                .any(|relay| relay["state"] == "connected")
                .then_some(())
        },
    );
    let mut at = renews(&desktop, &[], &words);
    at.says("The change is made (change 3).");
    drop(at);
    wait_for(
        "the second relay holds the desktop's change",
        &[&second, &desktop],
        120,
        || holds_the_change(&second, &desktop, 3).then_some(()),
    );
    desktop.stop();
    first.start();
    wait_for("the first relay is up again", &[&first], 30, || {
        healthy(&first)
    });

    // The new machine reaches both relays, and finds both changes.
    let new = device_at("new", &[&first, &second]);

    // **Where no relay handed an entry of the personal channel of the
    // change recovered from, and none said that it holds none of it, the
    // recovery is refused before anything is asked** (§9, step 3; §16).
    // The phrase's channel is read; then, while the command asks which
    // change to recover from, both relays go down. It names each relay
    // at which nothing was read, says to run the command again, and
    // makes nothing.
    let mut at = new.at_terminal(&["recover", "--name", "new"]);
    at.says("The recovery phrase, twelve words").types(&words);
    at.says("Two changes were made apart")
        .says("Type `1` or `2`, the one to recover from: ");
    first.stop();
    second.stop();
    at.types("1");
    let refused = at.refused();
    assert!(
        refused.contains("nothing of the personal channel of change 3 was read at any relay: "),
        "{refused}"
    );
    for relay in [&first, &second] {
        assert!(
            refused.contains(&format!("127.0.0.1:{}", relay.p2p)),
            "{refused}"
        );
    }
    assert!(
        refused.contains(
            "No relay handed an entry of it, and none said that it holds none of it: which \
             devices were added since that change, and which names they sync, is not known."
        ),
        "{refused}"
    );
    assert!(
        refused.contains("Run `cordelia recover` again. Nothing was done."),
        "{refused}"
    );
    assert!(
        !refused.contains("Type `have`, `lost` or `hands`"),
        "{refused}"
    );
    assert_eq!(person_of(&new)["state"], "no_phrase", "{}", person_of(&new));
    first.start();
    second.start();
    let relays = [&first, &second, &new];
    for relay in [&first, &second] {
        wait_for("the relay is up again", &relays, 30, || healthy(relay));
    }
    wait_for(
        "the new machine reaches both relays again",
        &relays,
        120,
        || {
            // As the command is told: each relay with the session of
            // its connection.
            let told = new.post("/api/v1/recover/look", json!({}));
            let sessions = told["sessions"].as_array()?;
            let reached = |relay: &Value| relay["session"].is_string();
            (sessions.len() == 2 && sessions.iter().all(reached)).then_some(())
        },
    );

    let mut at = new.at_terminal(&["recover", "--name", "new"]);
    at.says("The recovery phrase, twelve words").types(&words);
    at.says("Two changes were made apart")
        .says("1. Change 3:")
        .says("2. Change 3:")
        .says("the change it makes settles the two")
        .says("comes back only by adding them again.")
        .says("Type `1` or `2`, the one to recover from: ")
        .types("3");
    at.says("That is neither.")
        .says("Type `1` or `2`, the one to recover from: ")
        .types("1");
    answers_and_yes(&mut at, &["lost", "lost"]);
    at.says("The change is made (change 4)")
        .says("The look is made");
    let said = at.done();
    println!("{said}");
    assert!(said.contains("Recovering from change 3."), "{said}");
    assert!(said.contains("(change 4):"), "{said}");
    assert_eq!(person_of(&new)["change"], 4);
    assert_eq!(person_of(&new)["state"], "applied");

    // Each device, on either branch, is answered with the statement that
    // settles them, and says that it was removed.
    laptop.start();
    desktop.start();
    let all = [&first, &second, &new, &laptop, &desktop];
    for device in [&laptop, &desktop] {
        wait_for("the device is up again", &all, 30, || healthy(device));
        wait_for("the device hears that it was removed", &all, 180, || {
            (person_of(device)["state"] == "removed").then_some(())
        });
    }
    let _: Value = person_of(&new);
}
