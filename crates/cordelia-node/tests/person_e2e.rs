//! End to end: the commands a person types for the devices under a
//! recovery phrase (decision 2026-10-04 §5 to §8), each run as a person
//! runs it, at a terminal.
//!
//! Every node is a process of its own, started through the harness on
//! this machine, with a relay of the test's own. Each command is the
//! binary, run at a pseudo-terminal whose other end the test holds: it
//! reads what the command says, and types what a person would.

mod common;

use serde_json::{Value, json};

use common::*;

// ── Nodes ────────────────────────────────────────────────────────────

/// What the node says of its device and its person.
fn look(node: &Node) -> Value {
    node.post("/api/v1/devices/list", json!({}))
}

/// Ask the node's API as a program that holds its token does, with no
/// command and no terminal: the status of the answer, and what it says.
fn asks(node: &Node, path: &str, body: Value) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .proxy(None)
        .http_status_as_error(false)
        .build()
        .into();
    let mut answer = agent
        .post(format!("http://127.0.0.1:{}{path}", node.http))
        .header("Authorization", &format!("Bearer {}", node.token()))
        .send_json(&body)
        .unwrap();
    let status = answer.status().as_u16();
    let said: Value = answer.body_mut().read_json().unwrap_or(Value::Null);
    let message = said["error"]["message"].as_str().map(str::to_string);
    (status, message.unwrap_or_else(|| said.to_string()))
}

/// What the node says that its device holds of its person: [`look`],
/// without what it says of its relays, which changes as it reaches them.
fn holds(node: &Node) -> Value {
    let mut seen = look(node);
    for of_its_relays in ["relays", "waiting", "not_reached", "says"] {
        seen.as_object_mut().unwrap().remove(of_its_relays);
    }
    seen
}

/// Wait until `node` shows every device of the last change as having
/// sent what it carried. Each device says so by itself, a pass or two
/// after it applies a change (decision 2026-10-04 §8): what a device
/// shows is set against what it showed before only once that is said.
fn all_have_sent(node: &Node, all: &[&Node]) {
    wait_for(
        "every device says that it has sent what it carried",
        all,
        60,
        || {
            let seen = look(node);
            let devices = seen["devices"].as_array()?;
            (!devices.is_empty() && devices.iter().all(|device| device["sent"] == true))
                .then_some(())
        },
    );
}

/// What `cordelia accept` sends for the key `key` once its yes is said
/// on `node`: the key, and the row of 5.1 that the device stands in, by
/// which the yes went. A device that takes no key in any row names the
/// third.
fn typed_on(node: &Node, key: &str) -> Value {
    let seen = look(node);
    let row = match (text(&seen, "state"), text(&seen, "among")) {
        ("no_phrase", _) => "no_phrase",
        ("not_listed" | "not_opened", _) => "not_listed",
        (_, "alone") => "alone",
        _ => "several",
    };
    json!({ "key": key, "row": row })
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap_or_default()
}

/// Whether `relay`, by its one name in `node`'s look, holds the latest
/// change that the device keeps.
fn relay_holds_latest(node: &Node) -> Option<()> {
    let seen = look(node);
    let relays = seen["relays"].as_array()?;
    (!relays.is_empty() && relays.iter().all(|relay| relay["holds_latest"] == true)).then_some(())
}

// ── cordelia phrase ──────────────────────────────────────────────────

/// A new install follows no phrase, and says so, in the words of §5.2
/// and §5.1, in `status`, in `status --json` and in `devices`. `cordelia
/// phrase` makes one at a terminal: the words are shown once, typed back
/// whole, and the command says first what a phrase is for and that it
/// is no wallet's. The device then follows it, alone, and its relay is
/// shown the change entry and holds it.
#[test]
fn a_phrase_is_made_at_a_terminal_and_the_relay_holds_its_first_change() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let all = [&relay, &laptop];

    // Before there is a phrase.
    let status = laptop.cli(&["status"]);
    assert!(
        status.contains("Devices:   no recovery phrase yet"),
        "{status}"
    );
    // Where it stands, and then the three ways on, each on a line of
    // its own and in this order: a person who has lost every device is
    // pointed to `cordelia recover`, and told to make no new phrase
    // first.
    assert!(
        status.contains(
            "    no recovery phrase yet: memory stays on this machine.\n      \
             - This is your first machine: make a phrase here (`cordelia phrase`).\n      \
             - Another machine has the phrase: add this one from it (`cordelia add-device` \
             there, `cordelia accept` here).\n      \
             - Every device that has the phrase is lost: recover here with it (`cordelia \
             recover`). Do not make a new phrase first.\n"
        ),
        "{status}"
    );
    let json: Value = serde_json::from_str(&laptop.cli(&["status", "--json"])).unwrap();
    assert_eq!(json["person"]["state"], "no_phrase");
    assert_eq!(json["person"]["short"], "no recovery phrase yet");
    // It is a new install: it took this version with nothing that an
    // earlier one held.
    assert_eq!(json["sync"]["moved_on"], false, "{json}");
    let says = json["person"]["says"][0].as_str().unwrap();
    assert!(says.starts_with("no recovery phrase yet:"), "{json}");
    assert_eq!(
        json["person"]["says"].as_array().unwrap().len(),
        4,
        "{json}"
    );
    let devices = laptop.cli(&["devices"]);
    assert!(devices.contains("no recovery phrase yet:"), "{devices}");
    assert!(
        devices.contains("\n  - Every device that has the phrase is lost: recover here"),
        "{devices}"
    );

    // The phrase, made at a terminal.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    let words = words_shown(&at.said);
    at.types("");
    let rows = rows_shown(&at.said).to_string();
    at.says("Now type the words back");
    at.types(&words);
    let said = at.done();
    println!("{said}");
    // What a phrase is for, who has it, and that it is no wallet's:
    // before anything is shown.
    let before_anything = "Your recovery phrase is twelve words.\r\n\r\n  \
         - You need it to remove a device, or to recover on a new machine.\r\n    \
         (You can add a device without it.)\r\n  \
         - Nobody else has it, and this device does not keep it. It is shown once, now.\r\n  \
         - It is not a wallet phrase. Never type it into a wallet, and never type a wallet's \
         words here.\r\n";
    assert!(said.starts_with(before_anything), "{said:?}");
    // On a machine that follows no phrase: a person who has a phrase
    // already, and has lost every device, is pointed to `cordelia
    // recover` before any word of a new phrase is shown.
    let has_one_already = "\r\nIf you have a recovery phrase already and every device is lost, \
         do not make a new one.\r\nPress Ctrl-C, and recover with the phrase you have:\r\n  \
         cordelia recover\r\n";
    let pointed_at = said.find(has_one_already).expect("the way to recover");
    assert!(
        pointed_at < said.find("Your recovery phrase (shown once):").unwrap(),
        "{said:?}"
    );
    for says in [
        "Your recovery phrase (shown once):\r\n\r\n   1. ",
        "Write the twelve words down, in order. Keep them where only you can read them.\r\n\
         Press Enter when you have. The words are then cleared from the screen. ",
        "\r\nAll twelve match.\r\n",
        "It is listed as (",
    ] {
        assert!(
            said.contains(says),
            "the command did not say {says:?}:\n{said}"
        );
    }
    // The words are shown once. And they are shown on the terminal's
    // other screen, which is put away once they are written down.
    assert_eq!(said.matches(&rows).count(), 1, "{said}");
    let shown_at = said.find(&rows).unwrap();
    let (other_screen, put_away) = (
        said.find("\u{1b}[?1049h").expect("the other screen"),
        said.find("\u{1b}[?1049l")
            .expect("the other screen is put away"),
    );
    assert!(other_screen < shown_at && shown_at < put_away, "{said}");
    assert_eq!(words.split(' ').count(), 12);
    // What was typed back is not shown: after the screen is put away
    // the terminal shows the line that asks, each number with its tick,
    // and no letter, star or count of what was typed.
    let typed_back = format!(
        "\u{1b}[?1049l{ASKS_THE_WORDS_BACK}\r\n\r\n{}\r\nAll twelve match.\r\n",
        ticks(1, 12)
    );
    assert!(said[put_away..].starts_with(&typed_back), "{said:?}");

    // It follows the phrase, alone, and has applied change 1.
    let seen = look(&laptop);
    assert_eq!(
        (text(&seen, "state"), text(&seen, "among"), &seen["change"]),
        ("applied", "alone", &json!(1))
    );
    assert_eq!(seen["devices"].as_array().unwrap().len(), 1);
    assert_eq!(seen["devices"][0]["label"], "laptop");
    assert_eq!(seen["devices"][0]["this_device"], true);
    // The relay is shown the change, and holds it.
    wait_for("the relay holds the first change", &all, 60, || {
        relay_holds_latest(&laptop)
    });
    let devices = laptop.cli(&["devices"]);
    assert!(devices.contains("change 1"), "{devices}");
    assert!(devices.contains("this device"), "{devices}");
    assert!(devices.contains("holds the latest change"), "{devices}");
    let status = laptop.cli(&["status"]);
    assert!(
        status.contains("Devices:   this device alone, under a recovery phrase (change 1)"),
        "{status}"
    );
    // The node was handed no word of it: nothing it logged has the
    // phrase.
    let log = std::fs::read_to_string(laptop.log()).unwrap();
    assert!(!log.contains(&words));
}

/// A relay that a device is set up with and whose name does not resolve
/// is one of its relays all the same (decision 2026-10-04 §4.6). The
/// device cannot tell what that relay holds: a change made while it was
/// off may be there, and nowhere else.
///
/// - When the device wakes it shows its change entry to the relay that
///   answers, and then neither sends to a channel of its own nor takes
///   from one until the 30 seconds have gone by. Then it goes on with the
///   relay that answers.
/// - Its status, and `cordelia devices`, name the relay it has not heard
///   from.
/// - A command that makes a change says of that relay that it could not
///   be fetched from, and that it does not hold the change: it never says
///   that the machine may be closed.
#[test]
fn a_relay_whose_name_does_not_resolve_is_waited_for_and_named() {
    use std::time::{Duration, Instant};
    let relay = relay_started();
    let reached = format!("127.0.0.1:{}", relay.p2p);
    let mut laptop = node_with_relays(
        "laptop",
        "personal",
        &[(reached.clone(), None), (NO_SUCH_NAME.to_string(), None)],
    );
    assert_eq!(laptop.will_dial(), [reached.as_str(), NO_SUCH_NAME]);
    laptop.start();
    let all = [&relay, &laptop];
    wait_for("device healthy", &all, 30, || healthy(&laptop));
    wait_for("device reaches its relay", &all, 60, || {
        has_hot_peer(&laptop)
    });
    // What the device says of one of its relays, by the relay's name.
    let of = |name: &str| -> Option<Value> {
        let seen = look(&laptop);
        let relays = seen["relays"].as_array()?;
        relays.iter().find(|relay| relay["relay"] == name).cloned()
    };
    // How many of its channels have something that waits to be sent to
    // the relay it reaches.
    let waits = || -> Option<u64> {
        let seen = look(&laptop);
        let waiting = seen["waiting"].as_array()?;
        waiting.first()?["waits"].as_u64()
    };

    // The device wakes when it first has a change entry to show: the
    // relay that answers is shown it, and holds it.
    let words = makes_a_phrase(&laptop, "laptop");
    let woke = Instant::now();
    wait_for("the relay that answers holds the change", &all, 20, || {
        (of(&reached)?["holds_latest"] == true).then_some(())
    });
    let named = of(NO_SUCH_NAME).expect("the relay whose name does not resolve is listed");
    assert_eq!(named["heard_since_woke"], false, "{named}");
    assert_eq!(named["holds_latest"], Value::Null, "{named}");
    // `cordelia peers`, and the status that a panel reads, list it too,
    // with why it is not reached.
    let unresolved = |relays: &[Value]| -> Option<()> {
        let named = relays.iter().find(|relay| relay["host"] == NO_SUCH_NAME)?;
        (named["state"] == "unreachable" && named["error"] == "its name does not resolve")
            .then_some(())
    };
    wait_for("the relay that cannot be found is listed", &all, 20, || {
        unresolved(&relays_of(&laptop))
    });
    let status: Value = serde_json::from_str(&laptop.cli(&["status", "--json"])).unwrap();
    let listed = status["peers"]["relays"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(listed.len(), 2, "{status}");
    assert!(unresolved(&listed).is_some(), "{status}");
    let peers = laptop.cli(&["peers"]);
    assert!(
        peers.contains(&format!(
            "{NO_SUCH_NAME}  unreachable (its name does not resolve)"
        )),
        "{peers}"
    );

    // While it wakes it sends nothing in a channel of its own: half of
    // the wait on, what it wrote in its personal channel still waits.
    std::thread::sleep(Duration::from_secs(15).saturating_sub(woke.elapsed()));
    assert!(
        woke.elapsed() < Duration::from_secs(25),
        "the test was slow"
    );
    assert_eq!(waits(), Some(1), "{}", look(&laptop));
    // The status, and `cordelia devices`, name the relay not heard from.
    let not_heard = format!(
        "has not heard from {NO_SUCH_NAME} since it woke: a change made while it was off may \
         not have reached it"
    );
    let status = laptop.cli(&["status"]);
    assert!(status.contains(&not_heard), "{status}");
    let devices = laptop.cli(&["devices"]);
    assert!(
        devices.contains(&format!(
            "{NO_SUCH_NAME}: has not answered since this device woke"
        )),
        "{devices}"
    );
    assert!(
        devices.contains(&format!("{reached}: holds the latest change")),
        "{devices}"
    );

    // Once the 30 seconds have gone by it goes on with the other relay.
    wait_for("the device sends what waits", &all, 60, || {
        (waits()? == 0).then_some(())
    });
    assert!(
        woke.elapsed() >= Duration::from_secs(25),
        "the device did not wait for the relay it had not heard from: it sent after {:?}",
        woke.elapsed()
    );

    // A command that makes a change says what it could not fetch, and
    // which relay does not hold the change. It goes on saying so.
    let mut at = renews(&laptop, &[], &words);
    at.says("The change is made (change 2).");
    assert!(
        at.said
            .contains(&format!("Could not fetch: {NO_SUCH_NAME} did not answer.")),
        "{}",
        at.said
    );
    at.says(&format!("{reached} holds the change"));
    let said = at.hears_for(Duration::from_secs(5)).to_string();
    assert!(
        said.contains(&format!(
            "keep this machine on: {NO_SUCH_NAME} does not hold the change yet"
        )),
        "{said}"
    );
    assert!(!said.contains("Every relay holds the change"), "{said}");
}

// ── cordelia add-device, cordelia accept, cordelia devices ───────────

/// The notices that a device shows, by what each says.
fn notices(node: &Node) -> Vec<String> {
    look(node)["notices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|notice| text(notice, "says").to_string())
        .collect()
}

/// A device is added by two commands, each at a terminal with its yes:
/// `add-device` on a device that is in, which says what it hands over
/// and shows the new key's words, and `accept` on the new one, which
/// says what will happen to it. The new device then follows the phrase,
/// and both list both. Every device shows the addition until a person
/// clears it there, at a terminal: clearing on one clears nothing on the
/// other.
#[test]
fn a_device_is_added_by_two_commands_and_each_device_shows_it_until_it_is_cleared() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let desktop = device_started("desktop", &relay);
    let all = [&relay, &laptop, &desktop];
    makes_a_phrase(&laptop, "laptop");
    wait_for("the relay holds the first change", &all, 60, || {
        relay_holds_latest(&laptop)
    });
    let (laptop_key, desktop_key) = (key_of(&laptop), key_of(&desktop));
    let words_of = |key: &str| {
        let key = cordelia_crypto::bech32::decode_public_key(key).unwrap();
        cordelia_crypto::fingerprint::shown(&key)
    };

    // Without its yes nothing is added.
    let mut at = laptop.at_terminal(&["add-device", &desktop_key, "--name", "desktop"]);
    at.says("Type yes to go on").types("");
    assert!(at.done().contains("That was not a yes. Nothing was done."));
    assert!(look(&laptop)["added"].as_array().unwrap().is_empty());
    assert!(notices(&laptop).is_empty());

    // `add-device`: what it hands over, the words of the key beside the
    // label, its yes, and what to run on the other device.
    let mut at = laptop.at_terminal(&["add-device", &desktop_key, "--name", "desktop"]);
    at.says(&format!(
        "This gives ({}) \"desktop\" every name's memory, and the means to read what your devices \
         write from now on.",
        words_of(&desktop_key)
    ));
    at.says("Type yes to go on").types("yes");
    let added = at.done();
    println!("{added}");
    assert!(
        added.contains(&format!("cordelia accept {laptop_key}")),
        "{added}"
    );
    assert!(added.contains(&words_of(&laptop_key)), "{added}");
    assert!(added.contains("within the hour"), "{added}");

    // `accept`, on a device that follows no phrase: what will happen,
    // with the words of the key that was typed, and its yes.
    let mut at = desktop.at_terminal(&["accept", &laptop_key]);
    at.says(&format!(
        "This device, and the 0 folders it maps, will join the devices of the device ({}): what \
         is in those folders will be sent to them.",
        words_of(&laptop_key)
    ));
    at.says("Type yes to go on").types("n");
    assert!(at.done().contains("That was not a yes. Nothing was done."));
    assert!(look(&desktop)["accepting"].as_array().unwrap().is_empty());
    let mut at = desktop.at_terminal(&["accept", &laptop_key]);
    at.says("Type yes to go on").types("yes");
    let accepted = at.done();
    println!("{accepted}");
    assert!(
        accepted.contains("this device has joined") && accepted.contains("applied change 1"),
        "{accepted}"
    );

    // Both list both, and the new one has applied the change.
    let seen = look(&desktop);
    assert_eq!(
        (text(&seen, "state"), text(&seen, "among")),
        ("applied", "several")
    );
    assert_eq!(seen["added"][0]["label"], "desktop");
    assert_eq!(seen["added"][0]["this_device"], true);
    assert_eq!(seen["added"][0]["by"]["label"], "laptop");
    wait_for(
        "the laptop hears that the desktop applied",
        &all,
        90,
        || {
            let seen = look(&laptop);
            (seen["added"][0]["applied"] == 1).then_some(())
        },
    );
    for device in [&laptop, &desktop] {
        let listed = device.cli(&["devices"]);
        println!("{listed}");
        for says in [
            format!("({}) \"laptop\"", words_of(&laptop_key)),
            format!("({}) \"desktop\", added from (", words_of(&desktop_key)),
            laptop_key.clone(),
            desktop_key.clone(),
            "holds the latest change".to_string(),
        ] {
            assert!(
                listed.contains(&says),
                "{}: {says:?}\n{listed}",
                device.name
            );
        }
    }
    let listed = laptop.cli(&["devices"]);
    assert!(
        listed.contains("\"desktop\", added from (") && listed.contains("has applied change 1"),
        "{listed}"
    );

    // The notice, on each device, in its status too, until a person
    // clears it there.
    let told = format!(
        "new device: ({}) \"desktop\", added from ({}) \"laptop\"",
        words_of(&desktop_key),
        words_of(&laptop_key)
    );
    assert_eq!(notices(&laptop), std::slice::from_ref(&told));
    assert_eq!(
        notices(&desktop),
        [format!(
            "this device was added from ({}) \"laptop\"",
            words_of(&laptop_key)
        )]
    );
    assert!(laptop.cli(&["status"]).contains(&told));
    let json: Value = serde_json::from_str(&laptop.cli(&["status", "--json"])).unwrap();
    assert_eq!(json["person"]["notices"][0]["says"], told.as_str());
    assert_eq!(json["person"]["notices"][0]["kind"], "added");
    // Not cleared without a yes.
    let mut at = laptop.at_terminal(&["devices", "--clear"]);
    at.says(&told).says("Type yes to go on").types("no");
    assert!(at.done().contains("It stays."));
    assert_eq!(notices(&laptop), std::slice::from_ref(&told));
    // Cleared with one, on that device and on no other.
    let mut at = laptop.at_terminal(&["devices", "--clear"]);
    at.says(&told).says("Type yes to go on").types("yes");
    assert!(at.done().contains("Cleared on this device."));
    assert!(notices(&laptop).is_empty());
    assert!(!laptop.cli(&["status"]).contains("new device:"));
    assert_eq!(notices(&desktop).len(), 1);
    // The device still counts: clearing changes what is shown, and
    // nothing else.
    assert_eq!(look(&laptop)["added"][0]["counted"], true);
    let at = laptop.at_terminal(&["devices", "--clear"]);
    assert!(at.done().contains("nothing to clear"));
}

// ── A command without a terminal, and a phrase typed back wrongly ────

/// Every command that asks refuses where its input is no terminal, says
/// so, and changes nothing: a yes stops a command that is run by a
/// script that has none (decision 2026-10-04 §5). The commands that only
/// read are not refused. A phrase whose words are typed back wrongly
/// three times makes nothing, and nor does a yes that is not given.
#[test]
fn a_command_without_a_terminal_refuses_and_a_phrase_typed_back_wrongly_makes_nothing() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let other = key_of(&relay);
    let before = holds(&laptop);
    let key_before = key_of(&laptop);

    let commands: [&[&str]; 9] = [
        &["phrase"],
        &["phrase", "--name", "laptop"],
        &["add-device", &other],
        &["accept", &other],
        &["remove-device", &other],
        &["renew"],
        &["settle"],
        &["devices", "--clear"],
        &["init", "--new-key"],
    ];
    for args in commands {
        let said = laptop.refused(args);
        assert!(
            said.contains("it asks at a terminal: its input is not one. Nothing was done."),
            "cordelia {args:?}: {said}"
        );
    }
    assert_eq!(holds(&laptop), before);
    assert_eq!(key_of(&laptop), key_before);
    assert_eq!(text(&before, "state"), "no_phrase");
    // It refuses before it asks or does anything: on a device whose
    // node is not running, each says that it has no terminal, and not
    // that it could not reach the node. It never asked it.
    let idle = node("idle", "personal", None);
    for args in commands {
        let out = idle.command(args);
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "cordelia {args:?}");
        assert!(
            said.contains("it asks at a terminal: its input is not one. Nothing was done."),
            "cordelia {args:?}: {said}"
        );
        assert!(
            out.stdout.is_empty(),
            "cordelia {args:?} said something first"
        );
    }
    // What only reads asks nothing, and is not refused.
    laptop.cli(&["devices"]);
    laptop.cli(&["status"]);
    // The commands are in the help. Those of the older kind of device
    // are gone with it (decision 2026-10-04 §10): no command has their
    // names.
    let help = laptop.cli(&["--help"]);
    for command in [
        "phrase",
        "add-device",
        "accept",
        "remove-device",
        "renew",
        "settle",
    ] {
        assert!(
            help.contains(&format!("\n  {command} ")),
            "{command}: {help}"
        );
    }
    assert!(!help.contains("old-"), "{help}");
    for gone in [
        "old-devices",
        "old-add-device",
        "old-accept",
        "old-remove-device",
        "old-invites",
    ] {
        let said = laptop.refused(&[gone]);
        assert!(said.contains("unrecognized subcommand"), "{gone}: {said}");
    }

    // On a device that follows no phrase, nothing can be added: the
    // refusal says the way on.
    let said = laptop.at_terminal(&["add-device", &other]).refused();
    assert!(
        said.contains("this device follows no recovery phrase yet.\r\n  - This is your first"),
        "{said}"
    );
    assert!(
        said.contains("recover here with it (`cordelia recover`). Do not make a new phrase first."),
        "{said}"
    );
    // Nor removed, renewed or settled.
    for args in [&["renew"][..], &["remove-device", &other], &["settle"]] {
        let said = laptop.at_terminal(args).refused();
        assert!(said.contains("follows no recovery phrase yet"), "{said}");
    }

    // The routes behind the commands refuse what the commands refuse,
    // whoever asks: a program that holds the node's token gets no
    // further than a person does.
    for (path, body) in [
        ("/api/v1/change/prepare", json!({})),
        ("/api/v1/change/prepare", json!({ "settle": true })),
        ("/api/v1/devices/add/look", json!({ "device": other })),
        (
            "/api/v1/devices/add",
            json!({ "device": other, "would": "add" }),
        ),
    ] {
        let (status, said) = asks(&laptop, path, body);
        assert_eq!(status, 400, "{path}: {said}");
        assert!(
            said.contains("follows no recovery phrase yet"),
            "{path}: {said}"
        );
    }
    // A key that is this device's own has no pair channel with it, and
    // is not kept; nor is one that is no key.
    for key in [key_before.as_str(), "cordelia_pk1nothing"] {
        let (status, said) = asks(&laptop, "/api/v1/devices/accept", typed_on(&laptop, key));
        assert_eq!(status, 400, "{said}");
    }
    assert!(look(&laptop)["accepting"].as_array().unwrap().is_empty());
    // A notice that the device does not show is not cleared, and what
    // is no name of a notice is refused.
    let (status, _) = asks(
        &laptop,
        "/api/v1/devices/clear",
        json!({ "notice": hex::encode([7u8; 32]) }),
    );
    assert_eq!(status, 404);
    let (status, _) = asks(&laptop, "/api/v1/devices/clear", json!({ "notice": "07" }));
    assert_eq!(status, 400);
    // What is no change entry makes no phrase, and nor does a change
    // entry that is said to be from where the device does not stand.
    let made = {
        let phrase = cordelia_crypto::phrase::Phrase::generate().unwrap();
        let key = cordelia_crypto::bech32::decode_public_key(&key_before).unwrap();
        cordelia_api::person::first_entry(&phrase, &key, "laptop").unwrap()
    };
    let entry = hex::encode(made.entry.to_wire());
    let statement_key = hex::encode(made.statement_key);
    for (body, refused_as) in [
        (
            json!({ "entry": "zz", "statement_key": statement_key, "from": "no_phrase" }),
            400,
        ),
        (
            json!({ "entry": entry, "statement_key": "00", "from": "no_phrase" }),
            400,
        ),
        (
            json!({ "entry": entry, "statement_key": statement_key, "from": "nowhere" }),
            400,
        ),
        (
            json!({ "entry": entry, "statement_key": hex::encode([9u8; 32]), "from": "no_phrase" }),
            400,
        ),
        (
            json!({ "entry": entry, "statement_key": statement_key, "from": "alone" }),
            409,
        ),
        (
            json!({ "entry": entry, "statement_key": statement_key, "from": "several" }),
            409,
        ),
    ] {
        let (status, said) = asks(&laptop, "/api/v1/phrase/make", body.clone());
        assert_eq!(status, refused_as, "{body}: {said}");
    }
    assert_eq!(holds(&laptop), before);
    // Without the node's token nothing is asked at all.
    let unasked = direct()
        .post(format!(
            "http://127.0.0.1:{}/api/v1/devices/list",
            laptop.http
        ))
        .send_json(json!({}));
    assert!(unasked.is_err());

    // Three words typed back that are not the words shown: nothing is
    // made.
    let soon = std::time::Duration::from_secs(60);
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    let words = words_shown(&at.said);
    at.types("");
    at.says("Now type the words back");
    let another = another_word_than(words.split(' ').next().unwrap());
    for _ in 0..2 {
        at.types(another);
        // It is said, and the number is asked again.
        at.says("That does not match word 1. Check what you wrote, and type it again.\r\n   1. ");
    }
    at.types(another);
    let said = at.refused_within(soon);
    assert!(
        said.contains(
            "Three tries did not match. Nothing was made, and the words you were shown are not a \
             recovery phrase: do not keep them. Run `cordelia phrase` again."
        ),
        "{said}"
    );
    assert!(!said.contains("All twelve match."), "{said}");
    assert_eq!(holds(&laptop), before);
    // Words that are no words of the list are asked for again, and the
    // command is ended there: nothing either.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have").types("");
    at.says("Now type the words back")
        .types("these are not twelve words");
    at.says("That is not a word from the list. Type word 1 again.\r\n   1. ")
        .ends_the_input();
    let said = at.refused_within(soon);
    // The input ended: what a command says of that anywhere, and that
    // the words that were shown are no phrase.
    assert!(
        said.ends_with(
            "   1. \r\nError: nothing was typed. Nothing was made, and the words you were shown \
             are not a recovery phrase: do not keep them.\r\n"
        ),
        "{said:?}"
    );
    assert_eq!(holds(&laptop), before);

    // A phrase is made, and then: a yes that is not given replaces
    // nothing.
    let words = makes_a_phrase(&laptop, "laptop");
    all_have_sent(&laptop, &[&relay, &laptop]);
    let made = look(&laptop);
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says(
        "This replaces the recovery phrase that this device follows: the old one stops working \
         here, and what the relays hold under it is left behind.",
    );
    at.says("Type yes to go on").types("y");
    let said = at.done();
    assert!(
        said.contains("That was not a yes. Nothing was done."),
        "{said}"
    );
    assert!(
        !said.contains("Your recovery phrase (shown once):"),
        "{said}"
    );
    let now = look(&laptop);
    assert_eq!(now["devices"], made["devices"]);
    assert_eq!(now["change"], made["change"]);

    // With its yes it replaces it: the device follows a new phrase,
    // alone, at change 1 again, and the old words are another phrase.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Type yes to go on").types("yes");
    at.says("Press Enter when you have");
    let new_words = words_shown(&at.said);
    at.types("");
    at.says("Now type the words back").types(&new_words);
    at.done();
    assert_ne!(new_words, words);
    let now = look(&laptop);
    assert_eq!((text(&now, "among"), &now["change"]), ("alone", &json!(1)));
    // The old phrase signs nothing here any more.
    let mut at = laptop.at_terminal(&["renew"]);
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    let said = at.refused();
    assert!(
        said.contains(
            "that is a recovery phrase, and it is not the one that this device follows: nothing \
             was made."
        ),
        "{said}"
    );
    assert_eq!(look(&laptop)["change"], 1);

    // The node's half of a change, asked without a command: what is no
    // entry, an entry that is no change the device can apply, and a
    // change that is said to be made over another entry than the one
    // the device keeps, make nothing.
    let handed = laptop.post("/api/v1/change/prepare", json!({}));
    let (over, kept) = (text(&handed, "over"), text(&handed, "entry"));
    for (body, refused_as) in [
        (json!({ "entry": "zz", "over": over }), 400),
        (json!({ "entry": kept, "over": "00" }), 400),
        (
            json!({ "entry": kept, "over": hex::encode([3u8; 32]) }),
            409,
        ),
        (json!({ "entry": entry, "over": over }), 400),
        (json!({ "entry": kept, "over": over, "apart": over }), 409),
    ] {
        let (status, said) = asks(&laptop, "/api/v1/change/make", body.clone());
        assert_eq!(status, refused_as, "{body}: {said}");
    }
    let (status, said) = asks(&laptop, "/api/v1/change/prepare", json!({ "settle": true }));
    assert_eq!(status, 400, "{said}");
    assert!(said.contains("nothing to settle"), "{said}");
    assert_eq!(look(&laptop)["change"], 1);
    // Alone under a phrase, with sync on: a key is not kept.
    let claude = laptop.home().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    laptop.cli(&["sync", "claude", "--dir", claude.to_str().unwrap()]);
    let typed = typed_on(&laptop, &other);
    let (status, said) = asks(&laptop, "/api/v1/devices/accept", typed.clone());
    assert_eq!(status, 400, "{said}");
    assert!(said.contains("`cordelia sync off` first"), "{said}");
    assert!(look(&laptop)["accepting"].as_array().unwrap().is_empty());
    laptop.cli(&["sync", "off"]);
    // With the yes for another row than the device stands in, nothing is
    // kept: the command asks again.
    let elsewhere = json!({ "key": other, "row": "no_phrase" });
    let (status, said) = asks(&laptop, "/api/v1/devices/accept", elsewhere);
    assert_eq!(status, 409, "{said}");
    assert!(look(&laptop)["accepting"].as_array().unwrap().is_empty());
    let (status, said) = asks(&laptop, "/api/v1/devices/accept", typed);
    assert_eq!(status, 200, "{said}");
    assert_eq!(look(&laptop)["accepting"].as_array().unwrap().len(), 1);
}

// ── What a device serves ─────────────────────────────────────────────

/// A device serves none of the Channels API of the older kind (decision
/// 2026-10-04 §10): it carries no channel of that kind, so there is
/// nothing to subscribe to, no group, no direct channel and no key to
/// rotate, before it follows a phrase and after. A relay serves each of
/// those paths as it did. What a device serves under the same scope is
/// the local API for the names it holds.
#[test]
fn a_device_serves_none_of_the_channels_api_of_the_older_kind() {
    const OLDER: [&str; 14] = [
        "subscribe",
        "listen",
        "list",
        "info",
        "unsubscribe",
        "dm",
        "list-dms",
        "group",
        "group/invite",
        "group/remove",
        "list-groups",
        "rotate-psk",
        "delete-item",
        "search",
    ];
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    // An empty request: a path that is served answers it, if only to
    // refuse it, and a path that is not served is not found.
    let served = |node: &Node, path: &str| {
        asks(node, &format!("/api/v1/channels/{path}"), json!({})).0 != 404
    };
    for path in OLDER {
        assert!(!served(&laptop, path), "{path}, with no phrase");
        assert!(served(&relay, path), "{path}, on the relay");
    }
    makes_a_phrase(&laptop, "laptop");
    for path in OLDER {
        assert!(!served(&laptop, path), "{path}, with a phrase");
    }
    for path in ["publish", "entries", "delete-key", "identity"] {
        assert!(served(&laptop, path), "{path}");
    }
}

// ── cordelia remove-device ───────────────────────────────────────────

/// Wait until `device` has applied change `number`.
fn applies(device: &Node, number: u64, all: &[&Node]) {
    wait_for(
        &format!("{} applies change {number}", device.name),
        all,
        120,
        || (look(device)["change"] == number).then_some(()),
    );
}

/// The first four words of the fingerprint of a key, as it is written.
fn words_of(key: &str) -> String {
    let key = cordelia_crypto::bech32::decode_public_key(key).unwrap();
    cordelia_crypto::fingerprint::shown(&key)
}

/// A removal, as a person makes it: `remove-device` shows the device to
/// be removed and asks of each device added since whether it stays, with
/// no answer suggested for one that the device being removed added; it
/// shows the lists that the phrase will sign, asks its yes and then the
/// phrase, and stays until the relay holds the change. A mistyped phrase
/// is told from a wrong one, and neither makes anything: and no word of
/// either is told from another before the twelfth is typed. The removed
/// device stops and says why, the others apply, `devices` shows who has
/// applied, and the removed key is refused when it is added again. A
/// device that was added by a device added since may not add.
#[test]
fn a_device_is_removed_with_the_phrase_and_stops_and_the_others_apply() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let desktop = device_started("desktop", &relay);
    let tablet = device_started("tablet", &relay);
    let all = [&relay, &laptop, &desktop, &tablet];
    let words = makes_a_phrase(&laptop, "laptop");
    let (laptop_key, desktop_key, tablet_key) =
        (key_of(&laptop), key_of(&desktop), key_of(&tablet));
    // The laptop adds the desktop, and the desktop adds the tablet.
    adds(&laptop, &desktop, "desktop");
    adds(&desktop, &tablet, "tablet");
    wait_for("the laptop hears of the tablet", &all, 120, || {
        (look(&laptop)["added"].as_array()?.len() == 2).then_some(())
    });

    // A chain is two long at most: the tablet may not add.
    let said = tablet
        .at_terminal(&["add-device", &key_of(&relay)])
        .refused();
    assert!(
        said.contains(
            "this device may not add another yet: it was itself added, since the last change, \
             by a device added since"
        ),
        "{said}"
    );
    // The device that makes a change is always among its devices.
    let said = laptop
        .at_terminal(&["remove-device", &laptop_key])
        .refused();
    assert!(said.contains("that is this device's own key"), "{said}");
    // A key that is nobody's device: the command says so, and asks a
    // typed answer before anything else. No answer is suggested: Enter
    // answers nothing, and nothing is made.
    let mut at = laptop.at_terminal(&["remove-device", &key_of(&relay)]);
    at.says("is no device of yours that this device knows of");
    at.says("Type `refuse` to refuse this key for good, or anything else to stop")
        .types("");
    let said = at.refused();
    assert!(
        said.contains("That was not `refuse`. Nothing was done."),
        "{said}"
    );
    assert!(!said.contains("Make this change?"), "{said}");
    assert_eq!(look(&laptop)["change"], 1);

    // A wrong phrase: one that is a phrase, and not this device's.
    let other_phrase =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let removes = |phrases: &[&str]| {
        let mut at = laptop.at_terminal(&["remove-device", &desktop_key]);
        at.says(&format!(
            "To be removed: ({}) \"desktop\".",
            words_of(&desktop_key)
        ));
        // The tablet was added by the device that is being removed: it
        // is shown as that. No answer is suggested for it, or for any
        // device added since: pressing Enter answers nothing.
        at.says(&format!(
            "({}) \"tablet\", added since the last change, from ({}) \"desktop\"",
            words_of(&tablet_key),
            words_of(&desktop_key)
        ));
        at.says("It was added by the device that is being removed");
        at.says("Type `stays` or `removed`").types("");
        at.says("That is none of the answers. No answer is suggested: type one.");
        at.says("Type `stays` or `removed`").types("stays");
        // The lists, from the bytes that will be signed.
        at.says("The change that the recovery phrase will sign (change 2):");
        at.says(&format!("made on ({}) \"laptop\"", words_of(&laptop_key)));
        at.says("devices (2):");
        at.says(&format!(
            "({}) \"laptop\"  (this device)",
            words_of(&laptop_key)
        ));
        at.says(&format!("({}) \"tablet\"", words_of(&tablet_key)));
        at.says("removed keys (1):");
        at.says(&format!(
            "({}), known here as \"desktop\"",
            words_of(&desktop_key)
        ));
        at.says("Make this change?")
            .says("Type yes to go on")
            .types("yes");
        for phrase in phrases {
            at.says(ASKS_THE_PHRASE).types(phrase);
        }
        at
    };
    // Without its yes nothing is made, and the phrase is not asked for.
    let mut at = laptop.at_terminal(&["remove-device", &desktop_key]);
    at.says("Type `stays` or `removed`").types("stays");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("no");
    let said = at.done();
    assert!(
        said.contains("That was not a yes. Nothing was done."),
        "{said}"
    );
    assert!(
        !said.contains("Type your recovery phrase, one word at a time"),
        "{said}"
    );
    assert_eq!(look(&laptop)["change"], 1);

    let said = removes(&[other_phrase]).refused();
    assert!(
        said.contains(
            "that is a recovery phrase, and it is not the one that this device follows: nothing \
             was made."
        ),
        "{said}"
    );
    assert_eq!(look(&laptop)["change"], 1);
    // The words are never shown as they are typed: each of the twelve
    // got a tick, as the words of the device's own phrase would, and
    // nothing else was shown of them.
    let typed = format!("{ASKS_THE_PHRASE}\r\n\r\n{}", ticks(1, 12));
    assert!(said.contains(&typed), "{said:?}");
    let other_words: Vec<&str> = other_phrase.split(' ').collect();
    assert_eq!(two_words_in_a_row(said.as_bytes(), &other_words), None);

    // A mistyped phrase is told from a wrong one, and is typed again:
    // a word changed for another of the list. It may be typed three
    // times in all: here twice mistyped, and the third time as it is,
    // which is taken. And a word that is none is asked for again by its
    // number, and is no try: the third try is still to come after it.
    let (first, second) = (mistyped(&words, 3), mistyped(&words, 8));
    assert_ne!(first, second);
    let mut at = removes(&[&first, &second, "xyzzy"]);
    at.says("That is not a word from the list. Type word 1 again.\r\n   1. ")
        .types(&words);
    at.says("The change is made (change 2).");
    at.says(
        "It must not be made again on another device, even if this command is stopped now: two \
         changes made apart have to be settled with the phrase.",
    );
    at.says(
        "This machine may be closed only when every relay holds the change and this device has \
         sent what it holds.",
    );
    let said = at.done();
    println!("{said}");
    assert!(
        said.contains("these words are not a recovery phrase") && said.contains("It was mistyped"),
        "{said}"
    );
    // Each mistyped phrase got its twelve ticks before anything was
    // said of it, and so did the phrase itself, after the word that is
    // none: three times the phrase was asked for.
    let mistyped_says = format!(
        "{typed}these words are not a recovery phrase: at least one of them is not the word it \
         was. It was mistyped: nothing was made. Type it again.\r\n"
    );
    assert_eq!(said.matches(&mistyped_says).count(), 2, "{said:?}");
    assert_eq!(said.matches(ASKS_THE_PHRASE).count(), 3, "{said:?}");
    assert!(
        said.contains(&format!(
            "{ASKS_THE_PHRASE}\r\n\r\n   1. \u{2717}  That is not a word from the list. Type \
             word 1 again.\r\n{}",
            ticks(1, 12)
        )),
        "{said:?}"
    );
    assert!(said.contains("holds the change"), "{said}");
    assert!(said.contains("this machine may be closed."), "{said}");
    let own_words: Vec<&str> = words.split(' ').collect();
    assert_eq!(
        two_words_in_a_row(said.as_bytes(), &own_words),
        None,
        "the phrase is not shown as it is typed"
    );

    // The laptop has applied its own change, and the tablet applies it.
    assert_eq!(look(&laptop)["change"], 2);
    applies(&tablet, 2, &all);
    wait_for(
        "the laptop hears that the tablet applied",
        &all,
        120,
        || {
            let seen = look(&laptop);
            let tablet = seen["devices"]
                .as_array()?
                .iter()
                .find(|device| device["label"] == "tablet")?;
            (tablet["applied"] == 2).then_some(())
        },
    );
    let listed = laptop.cli(&["devices"]);
    println!("{listed}");
    assert!(
        listed.contains(&format!(
            "({}) \"tablet\": has applied change 2",
            words_of(&tablet_key)
        )),
        "{listed}"
    );
    assert!(listed.contains("Removed keys:"), "{listed}");
    // A statement lists a removed key bare: it is shown by the label
    // that this device knew it by.
    assert!(
        listed.contains(&format!(
            "  ({}) \"desktop\"  {desktop_key}",
            words_of(&desktop_key)
        )),
        "{listed}"
    );

    // The removed device stops, and says why.
    wait_for("the desktop learns that it was removed", &all, 120, || {
        (text(&look(&desktop), "state") == "removed").then_some(())
    });
    let status = desktop.cli(&["status"]);
    assert!(
        status.contains("Devices:   this device was removed"),
        "{status}"
    );
    assert!(
        status.contains(
            "this device was removed. `cordelia init --new-key` gives it a new key; it is then \
             added as a new device"
        ),
        "{status}"
    );
    assert!(
        desktop
            .cli(&["devices"])
            .contains("This device cannot go on: this device was removed")
    );
    // It adds nothing, removes nothing, and is handed nothing.
    let said = desktop.at_terminal(&["add-device", &tablet_key]).refused();
    assert!(said.contains("this device was removed"), "{said}");
    let said = desktop.at_terminal(&["accept", &laptop_key]).refused();
    assert!(
        said.contains("this device was removed: `cordelia init --new-key` first"),
        "{said}"
    );
    let said = desktop.at_terminal(&["renew"]).refused();
    assert!(said.contains("this device was removed"), "{said}");
    // It makes no phrase of its own: no words are shown.
    let said = desktop
        .at_terminal(&["phrase", "--name", "desktop"])
        .refused();
    assert!(
        said.contains("A device that has stopped makes no phrase of its own"),
        "{said}"
    );
    assert!(
        !said.contains("Your recovery phrase (shown once):"),
        "{said}"
    );
    assert_eq!(text(&look(&desktop), "state"), "removed");
    // The route keeps no key for it either, whoever asks.
    let (status, said) = asks(
        &desktop,
        "/api/v1/devices/accept",
        typed_on(&desktop, &laptop_key),
    );
    assert_eq!(status, 400, "{said}");
    assert!(said.contains("this device was removed"), "{said}");
    assert!(
        look(&desktop)["accepting"]
            .as_array()
            .unwrap()
            .iter()
            .all(|typed| typed["key"] != laptop_key.as_str() || typed["taken"] == true)
    );

    // Its key is refused when it is added again.
    let said = laptop
        .at_terminal(&["add-device", &desktop_key, "--name", "desktop"])
        .refused();
    assert!(
        said.contains("that key was removed, and a removed key is not added again"),
        "{said}"
    );
    // And when it is removed again.
    let said = laptop
        .at_terminal(&["remove-device", &desktop_key])
        .refused();
    assert!(said.contains("that key was removed already"), "{said}");
}

/// A key that this device knows nothing of is removed by key (decision
/// 2026-10-04 §10): a key that is in no list is refused by nothing, and
/// the two commands would add it. `cordelia remove-device <key>` says that
/// this is no device it knows of, and that removing it refuses that key
/// for good, and asks a typed answer, with none suggested: a yes is not
/// the answer. It then goes on as any removal: the key is among the
/// removed keys that the phrase signs, every device of the person's
/// applies the change, and the key is added by none of them after it.
#[test]
fn a_key_that_no_device_knows_is_removed_by_key_and_refused_for_good() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let desktop = device_started("desktop", &relay);
    // A machine that was a device of the person's before every device
    // was added again, say: it has a key, and is in no list.
    let old = device_started("tablet", &relay);
    let all = [&relay, &laptop, &desktop, &old];
    let words = makes_a_phrase(&laptop, "laptop");
    let (laptop_key, desktop_key, old_key) = (key_of(&laptop), key_of(&desktop), key_of(&old));
    adds(&laptop, &desktop, "desktop");

    let asks_its_answer = |answer: &str| {
        let mut at = laptop.at_terminal(&["remove-device", &old_key]);
        at.says(&format!(
            "The key ({}) is no device of yours that this device knows of: it is in no list \
             of the last change, and was not added since",
            words_of(&old_key)
        ));
        at.says("Removing it refuses that key for good");
        at.says("Type `refuse` to refuse this key for good, or anything else to stop")
            .types(answer);
        at
    };
    // A yes is not the answer, and nor is the word that removes a device
    // which is known: nothing is made, and nothing more is asked.
    for not_it in ["yes", "removed"] {
        let said = asks_its_answer(not_it).refused();
        assert!(
            said.contains("That was not `refuse`. Nothing was done."),
            "{said}"
        );
        assert!(!said.contains("Type `stays` or `removed`"), "{said}");
        assert!(
            !said.contains("Type your recovery phrase, one word at a time"),
            "{said}"
        );
    }
    assert_eq!(look(&laptop)["change"], 1);

    // The answer, typed: it goes on as any removal. The desktop was added
    // since the last change, and is asked about; the lists that the
    // phrase will sign have the key among the removed, by its words, with
    // no label, for this device knew none.
    let mut at = asks_its_answer("refuse");
    at.says(&format!(
        "({}) \"desktop\", added since the last change",
        words_of(&desktop_key)
    ));
    at.says("Type `stays` or `removed`").types("stays");
    at.says("The change that the recovery phrase will sign (change 2):");
    at.says("devices (2):");
    at.says("removed keys (1):");
    at.says(&format!("({})", words_of(&old_key)));
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 2).");
    let said = at.done();
    assert!(
        !said.contains(&format!("({}), known here as", words_of(&old_key))),
        "{said}"
    );
    assert!(said.contains("this machine may be closed."), "{said}");

    // The statement that the laptop has applied lists the key as removed,
    // and the desktop applies it.
    assert_eq!(look(&laptop)["change"], 2);
    applies(&desktop, 2, &all);
    for device in [&laptop, &desktop] {
        let removed = look(device)["removed"].clone();
        assert_eq!(removed.as_array().unwrap().len(), 1, "{removed}");
        assert_eq!(removed[0]["key"], old_key.as_str(), "{removed}");
    }
    let listed = laptop.cli(&["devices"]);
    assert!(listed.contains("Removed keys:"), "{listed}");
    assert!(listed.contains(&old_key), "{listed}");

    // The key is refused for good: no device of the person's adds it.
    for device in [&laptop, &desktop] {
        let said = device
            .at_terminal(&["add-device", &old_key, "--name", "tablet"])
            .refused();
        assert!(
            said.contains("that key was removed, and a removed key is not added again"),
            "{said}"
        );
    }
    // And it is removed once: a second time says that it was.
    let said = laptop.at_terminal(&["remove-device", &old_key]).refused();
    assert!(said.contains("that key was removed already"), "{said}");
    // The machine of that key followed no phrase, and follows none.
    assert_eq!(text(&look(&old), "state"), "no_phrase");
    let _ = laptop_key;
}

// ── cordelia renew ───────────────────────────────────────────────────

/// A renewal: of each device added since the last change the person
/// says whether it stays, and one that stays is among the devices of the
/// next. A record of an addition that arrives after the prompt never has
/// the command ask again: its key is in no list. That device says that
/// it is not in the change, the device that made the change shows its
/// key as "not in the last change" until a person clears it, and
/// `add-device` shows the key as that before its yes. It is added again
/// by the same two commands: `accept`, on a device that is in no list,
/// takes the change that stopped it, by hand.
#[test]
fn a_renewal_lists_who_stays_and_a_record_that_arrives_after_the_prompt_restarts_nothing() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let desktop = device_started("desktop", &relay);
    let tablet = device_started("tablet", &relay);
    let all = [&relay, &laptop, &desktop, &tablet];
    let words = makes_a_phrase(&laptop, "laptop");
    let (laptop_key, desktop_key, tablet_key) =
        (key_of(&laptop), key_of(&desktop), key_of(&tablet));
    adds(&laptop, &desktop, "desktop");

    // The prompt: the desktop was added since, from this device, and an
    // answer is suggested for it. The lists are then shown.
    let mut at = laptop.at_terminal(&["renew"]);
    at.says(&format!(
        "({}) \"desktop\", added since the last change, from ({}) \"laptop\"",
        words_of(&desktop_key),
        words_of(&laptop_key)
    ));
    // No answer is suggested for a device added since, whoever added it
    // (decision 2026-10-04 §6): pressing Enter answers nothing.
    at.says("Type `stays` or `removed`").types("");
    at.says("That is none of the answers. No answer is suggested: type one.");
    at.says("Type `stays` or `removed`").types("stays");
    at.says("The change that the recovery phrase will sign (change 2):");
    at.says("devices (2):");
    at.says("Make this change?").says("Type yes to go on");

    // While the prompt stands, the desktop adds the tablet, and the
    // record reaches the laptop.
    adds(&desktop, &tablet, "tablet");
    wait_for("the laptop hears of the tablet", &all, 120, || {
        (look(&laptop)["added"].as_array()?.len() == 2).then_some(())
    });
    at.types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 2).");
    let said = at.done();
    assert!(!said.contains("This asks again"), "{said}");
    assert!(
        !said.contains("tablet"),
        "the tablet was never asked about:\n{said}"
    );

    // The desktop is among the devices of the change, and applies it.
    applies(&desktop, 2, &all);
    let seen = look(&laptop);
    let labels: Vec<&str> = seen["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|device| text(device, "label"))
        .collect();
    assert_eq!(labels, ["laptop", "desktop"]);
    assert!(seen["added"].as_array().unwrap().is_empty());

    // The tablet is in no list: it says so, and adds nothing.
    wait_for("the tablet learns that it is in no list", &all, 120, || {
        (text(&look(&tablet), "state") == "not_listed").then_some(())
    });
    let status = tablet.cli(&["status"]);
    assert!(
        status.contains(&format!(
            "this device is not in a change made on ({}) \"laptop\": if it is yours, add it again \
             from a device that is",
            words_of(&laptop_key)
        )),
        "{status}"
    );
    let said = tablet.at_terminal(&["add-device", &desktop_key]).refused();
    assert!(
        said.contains("this device is not in the last change: add it again from a device that is"),
        "{said}"
    );

    // The laptop counted it before the change: it shows it as not in
    // the last change, by its label and its words and never by its key.
    let not_in = format!(
        "({}) \"tablet\" is not in the last change: add it again, or it was meant to go",
        words_of(&tablet_key)
    );
    assert_eq!(notices(&laptop), std::slice::from_ref(&not_in));
    let listed = laptop.cli(&["devices"]);
    assert!(listed.contains("Not in the last change"), "{listed}");
    assert!(!listed.contains(&tablet_key), "{listed}");

    // It is added again, by the same two commands. `add-device` shows
    // the key as not in the last change before its yes.
    let mut at = laptop.at_terminal(&["add-device", &tablet_key, "--name", "tablet"]);
    at.says("This key was not in the last change. This device knew it as \"tablet\"");
    at.says("Type yes to go on").types("yes");
    at.done();
    let mut at = tablet.at_terminal(&["accept", &laptop_key]);
    at.says(&format!(
        "This device takes, within the hour, only what the device ({}) hands over under the \
         recovery phrase that it already follows, with the change that stopped it or one made \
         after that. It keeps its folders, and carries what it holds.",
        words_of(&laptop_key)
    ));
    at.says("Type yes to go on").types("yes");
    // The command stays a minute: where the hand-over is read later than
    // that, the node says what became of the key.
    let said = became_of_the_key(&tablet, &laptop_key, at.done());
    assert!(
        said.contains("this device has applied change 2, which it was handed"),
        "{said}"
    );
    let seen = look(&tablet);
    assert_eq!(
        (text(&seen, "state"), &seen["change"]),
        ("applied", &json!(2))
    );
    // It is told that it was added, and nothing of itself as a key
    // that a change left out.
    assert_eq!(
        notices(&tablet),
        [format!(
            "this device was added from ({}) \"laptop\"",
            words_of(&laptop_key)
        )]
    );

    // The key is still shown as not in the last change until a person
    // clears it there: and the addition beside it.
    let told = notices(&laptop);
    assert_eq!(told.len(), 2, "{told:?}");
    assert!(told.contains(&not_in), "{told:?}");
    let mut at = laptop.at_terminal(&["devices", "--clear"]);
    for _ in 0..2 {
        at.says("Type yes to go on").types("yes");
    }
    at.done();
    assert!(notices(&laptop).is_empty());
    assert!(!laptop.cli(&["devices"]).contains("Not in the last change"));

    // At the next change the tablet, added since, is asked about, and
    // the person says that it is removed: it is among the removed keys
    // of the change, which the lists show before the yes, and it stops.
    let mut at = laptop.at_terminal(&["renew"]);
    at.says(&format!(
        "({}) \"tablet\", added since the last change",
        words_of(&tablet_key)
    ));
    at.says("Type `stays` or `removed`").types("removed");
    at.says("The change that the recovery phrase will sign (change 3):");
    at.says("devices (2):");
    at.says("removed keys (1):");
    at.says(&format!(
        "({}), known here as \"tablet\"",
        words_of(&tablet_key)
    ));
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 3).");
    at.done();
    wait_for("the tablet learns that it was removed", &all, 120, || {
        (text(&look(&tablet), "state") == "removed").then_some(())
    });
    applies(&desktop, 3, &all);
    assert_eq!(look(&laptop)["removed"][0]["key"], tablet_key.as_str());
}

/// A statement that arrives between the prompt and the phrase: nothing
/// is made, and the command asks again, with what the device holds then.
/// And a device that is one of several takes nothing that is handed over
/// under another phrase: it says so, and nothing moves.
#[test]
fn a_change_that_arrives_between_the_prompt_and_the_phrase_has_the_command_ask_again() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let desktop = device_started("desktop", &relay);
    let other = device_started("other", &relay);
    let all = [&relay, &laptop, &desktop, &other];
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");

    // The laptop's command stands at its phrase prompt.
    let mut at = laptop.at_terminal(&["renew"]);
    at.says("Type `stays` or `removed`").types("stays");
    at.says("The change that the recovery phrase will sign (change 2):");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time");

    // Meanwhile the desktop makes a change, and the laptop applies it.
    // The desktop was added since the last change. Before a change lists
    // it, the command shows it as an addition, from the record of its
    // own addition, and its listing is confirmed by a typed answer
    // (decision 2026-10-04 §16).
    let mut not_confirmed = desktop.at_terminal(&["renew"]);
    not_confirmed
        .says("Type `stays` to list this device")
        .types("yes");
    let said = not_confirmed.refused();
    assert!(
        said.contains("That was not `stays`. Nothing was done."),
        "{said}"
    );
    assert!(!said.contains("Make this change?"), "{said}");
    let mut on_desktop = desktop.at_terminal(&["renew"]);
    on_desktop
        .says("This device is not in the last change: it was added since, as ")
        .says("desktop")
        .says("from ")
        .says("laptop")
        .says("this change lists it under that label")
        .says("Type `stays` to list this device")
        .types("stays");
    on_desktop
        .says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    on_desktop
        .says("Type your recovery phrase, one word at a time")
        .types(&words);
    on_desktop.done();
    assert_eq!(look(&desktop)["change"], 2);
    applies(&laptop, 2, &all);

    // The phrase is typed: nothing is made over what the prompt showed,
    // and the command asks again, with what the device holds now.
    at.types(&words);
    at.says("A change reached this device while you were answering.");
    at.says("This asks again");
    at.says("The change that the recovery phrase will sign (change 3):");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 3).");
    let said = at.done();
    // What is typed is shown again once the phrase has been read: each
    // of the two yeses is on the terminal, and the phrase never is.
    assert_eq!(
        said.matches("anything else to stop: yes").count(),
        2,
        "{said}"
    );
    assert!(!said.contains(&words), "{said}");
    assert_eq!(look(&laptop)["change"], 3);
    applies(&desktop, 3, &all);
    // One change was made by each command, and no two apart.
    for device in [&laptop, &desktop] {
        assert_eq!(text(&look(device), "state"), "applied");
    }

    // A key that the last change lists is handed that change again by
    // the same two commands, with no record: `add-device` says that it
    // is one of the person's devices already. The desktop has applied
    // the change: what it is handed brings none, and nothing is done.
    let mut at = laptop.at_terminal(&["add-device", &key_of(&desktop), "--name", "another"]);
    at.says(&format!(
        "({}) \"desktop\" is one of your devices already: this hands it the last change again, and \
         adds nothing.",
        words_of(&key_of(&desktop))
    ));
    at.says("Type yes to go on").types("yes");
    let said = at.done();
    assert!(
        said.contains("The last change is handed to it again."),
        "{said}"
    );
    assert!(notices(&laptop).is_empty(), "no record was made");
    let mut at = desktop.at_terminal(&["accept", &key_of(&laptop)]);
    at.says("This device is one of several.");
    at.says("Type yes to go on").types("yes");
    at.says(
        "So far: what was handed over brings no change that this device has not applied: \
         nothing was done.",
    );
    drop(at);
    assert_eq!(look(&desktop)["change"], 3);

    // Another person's device, under a phrase of its own, hands the
    // desktop what it would hand a device of its own. The desktop is one
    // of several: its yes says that it takes only a change under the
    // phrase it follows, and nothing moves.
    makes_a_phrase(&other, "other");
    all_have_sent(&desktop, &all);
    let before = holds(&desktop);
    let mut at = other.at_terminal(&["add-device", &key_of(&desktop), "--name", "desktop"]);
    at.says("Type yes to go on").types("yes");
    at.done();
    let mut at = desktop.at_terminal(&["accept", &key_of(&other)]);
    at.says("This device is one of several. It takes, within the hour, only what the device (");
    at.says("Anything else moves nothing.");
    at.says("Type yes to go on").types("yes");
    at.says(
        "So far: what was handed over is under another recovery phrase than the one this device \
         follows, and this device is one of several: nothing moved.",
    );
    drop(at);
    let mut now = holds(&desktop);
    // What is new is the key that was typed, and what became of it.
    let typed: Vec<&Value> = now["accepting"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|typed| typed["key"] == key_of(&other).as_str())
        .collect();
    assert_eq!(typed.len(), 1);
    assert_eq!(typed[0]["taken"], false);
    now["accepting"] = before["accepting"].clone();
    assert_eq!(now, before);
}

// ── Leaving: cordelia phrase on one of several, cordelia init --new-key ──

/// A device that is one of several and makes a phrase of its own leaves
/// the others, and says so: each device it left shows that it left until
/// a person clears it there. A device that is alone under a phrase is not
/// moved by `accept` while sync is on, and with sync off its yes says
/// that its phrase stops working there. `cordelia init --new-key` gives a
/// device a new key: it says that it has left, keeps what sync was set
/// to, follows no phrase, and is added as a new device.
#[test]
fn a_device_that_leaves_says_so_and_a_new_key_starts_it_afresh() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let desktop = device_started("desktop", &relay);
    let mut tablet = device_started("tablet", &relay);
    makes_a_phrase(&laptop, "laptop");
    let (laptop_key, desktop_key, tablet_key) =
        (key_of(&laptop), key_of(&desktop), key_of(&tablet));
    adds(&laptop, &desktop, "desktop");
    adds(&laptop, &tablet, "tablet");
    wait_for(
        "the desktop hears of the tablet",
        &[&relay, &laptop, &desktop],
        120,
        || {
            (text(&look(&desktop), "among") == "several" && look(&desktop)["others"] == 2)
                .then_some(())
        },
    );

    // `cordelia phrase` on one of several: it asks first.
    let mut at = desktop.at_terminal(&["phrase", "--name", "desktop"]);
    at.says(
        "This device leaves the 2 devices it is with and starts again alone, under a new phrase.",
    );
    at.says("Type yes to go on").types("yes");
    at.says("Press Enter when you have");
    let new_words = words_shown(&at.said);
    at.types("");
    at.says("Now type the words back").types(&new_words);
    at.done();
    let seen = look(&desktop);
    assert_eq!(
        (
            text(&seen, "among"),
            &seen["change"],
            seen["devices"].as_array().unwrap().len()
        ),
        ("alone", &json!(1), 1)
    );

    // Each device it left shows that it left, until a person clears it
    // there.
    let left = format!(
        "({}) \"desktop\" left, and started again under another phrase. It still holds the secret \
         it had, and is still listed: removing it, with the phrase, is what cuts it off \
         (`cordelia remove-device`)",
        words_of(&desktop_key)
    );
    for device in [&laptop, &tablet] {
        wait_for(
            "a device it left shows that it left",
            &[&relay, device, &desktop],
            120,
            || notices(device).contains(&left).then_some(()),
        );
        assert!(device.cli(&["status"]).contains(&left));
    }
    let listed = laptop.cli(&["devices"]);
    assert!(listed.contains("has said that it left"), "{listed}");
    // The laptop is told three things: the two additions, and this. A
    // person clears the last there, and it is shown there no more.
    assert_eq!(notices(&laptop).len(), 3);
    let mut at = laptop.at_terminal(&["devices", "--clear"]);
    at.says("new device: (")
        .says(") \"desktop\", added from")
        .says("Type yes to go on")
        .types("no");
    at.says("new device: (")
        .says(") \"tablet\", added from")
        .says("Type yes to go on")
        .types("no");
    at.says("left, and started again")
        .says("Type yes to go on")
        .types("yes");
    at.done();
    assert_eq!(notices(&laptop).len(), 2);
    assert!(!notices(&laptop).contains(&left));
    assert!(notices(&tablet).contains(&left));

    // The desktop is alone under a phrase. The laptop hands it what it
    // holds again: it still counts there.
    let mut at = laptop.at_terminal(&["add-device", &desktop_key, "--name", "desktop"]);
    at.says("This key counts as one of your devices already");
    at.says("Type yes to go on").types("yes");
    at.done();
    // While sync is on there, `accept` is refused: sending its folders
    // to another set of devices takes two acts.
    let claude = desktop.home().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    desktop.cli(&["sync", "claude", "--dir", claude.to_str().unwrap()]);
    let said = desktop.at_terminal(&["accept", &laptop_key]).refused();
    assert!(
        said.contains(
            "sync is on here, and this device is alone under a recovery phrase: `cordelia sync \
             off` first, so that sending its folders to another set of devices takes two acts."
        ),
        "{said}"
    );
    assert_eq!(text(&look(&desktop), "among"), "alone");
    desktop.cli(&["sync", "off"]);
    let mut at = desktop.at_terminal(&["accept", &laptop_key]);
    at.says("The recovery phrase that this device follows stops working here");
    at.says("Type yes to go on").types("yes");
    let said = at.done();
    assert!(
        said.contains("this device has left the recovery phrase it followed alone, and has joined"),
        "{said}"
    );
    assert_eq!(text(&look(&desktop), "among"), "several");

    // `cordelia init --new-key` on the tablet, with sync on there.
    let claude = tablet.home().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    tablet.cli(&["sync", "claude", "--dir", claude.to_str().unwrap()]);
    let sync_before = tablet.post("/api/v1/sync/status", json!({}));
    assert_eq!(sync_before["enabled"], true);
    // Without its yes nothing is done: it has the key it had, and
    // follows the phrase it followed.
    let mut at = tablet.at_terminal(&["init", "--new-key"]);
    at.says("Type yes to go on").types("");
    assert!(at.done().contains("That was not a yes. Nothing was done."));
    assert_eq!(key_of(&tablet), tablet_key);
    assert_eq!(text(&look(&tablet), "among"), "several");
    assert!(
        notices(&laptop)
            .iter()
            .all(|says| !says.starts_with("tablet"))
    );

    let mut at = tablet.at_terminal(&["init", "--new-key"]);
    at.says("This gives this device a new key. It leaves the 2 devices it is with");
    at.says("It keeps its memory folders and their mappings");
    at.says("Type yes to go on").types("yes");
    let said = at.done();
    // It waited for its relay to be sent what it leaves behind, before
    // the key that could send it was gone.
    assert!(
        said.contains("Telling the relays what this device leaves behind..."),
        "{said}"
    );
    assert!(!said.contains("Could not send it"), "{said}");
    assert!(said.contains("This device has a new key:"), "{said}");
    let new_key = key_of(&tablet);
    assert_ne!(new_key, tablet_key);
    assert!(said.contains(&new_key), "{said}");
    // It ends with the command that restarts the node as the service on
    // this system, on a line of its own, and `cordelia status` after it.
    let restart = cordelia_api::commands::restart_command(std::env::consts::OS);
    assert!(
        said.contains(&format!(
            "The node still runs under the old key. Before anything else, restart the \
             node:\r\n  {restart}\r\nThen run `cordelia status`.\r\n"
        )),
        "{said}"
    );
    assert!(!said.contains("cordelia start"), "{said}");
    // Until the node is started again it makes nothing for a command,
    // under a key that is the device's no longer: and says the same.
    let said = tablet.refused(&["devices"]);
    assert!(
        said.contains(&format!(
            "this device was given a new key, and the node still runs under the old one. \
             Restart the node:\n  {restart}\nThen run `cordelia status`.\n"
        )),
        "{said}"
    );
    assert!(!said.contains("cordelia start"), "{said}");
    // So does `cordelia accept`, which is what a person runs next.
    let said = tablet.at_terminal(&["accept", &laptop_key]).refused();
    assert!(
        said.contains(&format!("Restart the node:\r\n  {restart}\r\n")),
        "{said}"
    );
    tablet.stop();
    tablet.start();
    wait_for("the tablet is up under its new key", &[&tablet], 60, || {
        healthy(&tablet)
    });
    // It follows no phrase, under its new key, and sync is set as it was.
    let seen = look(&tablet);
    assert_eq!(text(&seen, "state"), "no_phrase");
    assert_eq!(text(&seen, "this_device"), new_key);
    assert!(tablet.cli(&["status"]).contains("no recovery phrase yet"));
    // Nothing that it held under the phrase is in its store: no entry
    // of any channel, its own word that it left among them, which is
    // not sent in the name of a key that the device has no more.
    {
        let db = rusqlite::Connection::open_with_flags(
            tablet.data_dir().join("cordelia.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let held: i64 = db
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(held, 0);
    }
    let sync_after = tablet.post("/api/v1/sync/status", json!({}));
    assert_eq!(sync_after["enabled"], true);
    assert_eq!(sync_after["dir"], sync_before["dir"]);
    assert_eq!(sync_after["mappings"], sync_before["mappings"]);
    // The devices it left show that it left, under the key they knew.
    let left = format!(
        "({}) \"tablet\" left, and started again under another phrase.",
        words_of(&tablet_key)
    );
    wait_for(
        "the laptop shows that the tablet left",
        &[&relay, &laptop, &tablet],
        120,
        || {
            notices(&laptop)
                .iter()
                .any(|says| says.starts_with(&left))
                .then_some(())
        },
    );
    // It is added as a new device.
    wait_for(
        "the tablet reaches its relay",
        &[&relay, &tablet],
        60,
        || has_hot_peer(&tablet),
    );
    adds(&laptop, &tablet, "tablet-2");
    let seen = look(&tablet);
    assert_eq!(
        (text(&seen, "state"), text(&seen, "among")),
        ("applied", "several")
    );
}

// ── Two changes made apart, and cordelia settle ──────────────────────

/// Two devices each make a change while neither can hear the other: the
/// relay comes to hold one, and the device that made the other sees both.
/// It is in a fork: it says so, with both lists, adds nothing and accepts
/// nothing. `cordelia settle`, there, shows both statements, asks of the
/// other device whether it stays, and makes the settlement with the
/// phrase. Both devices apply it.
#[test]
fn two_changes_made_apart_are_settled_with_the_phrase() {
    let mut relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let desktop = device_started("desktop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");
    // A change that lists both.
    renews(&laptop, &["stays"], &words).done();
    applies(&desktop, 2, &[&relay, &laptop, &desktop]);
    // On a device that has seen no two changes made apart there is
    // nothing to settle.
    let said = laptop.at_terminal(&["settle"]).refused();
    assert!(
        said.contains("this device has seen no two changes made apart: there is nothing to settle"),
        "{said}"
    );

    // The relay is out of reach, and each makes a change.
    relay.stop();
    for device in [&laptop, &desktop] {
        let mut at = renews(device, &[], &words);
        at.says("The change is made (change 3).");
        at.says("keep this machine on:");
        // It stays, and does not say that the machine may be closed:
        // no relay holds the change.
        let said = at.hears_for(std::time::Duration::from_secs(3));
        assert!(!said.contains("this machine may be closed."), "{said}");
        drop(at);
        assert_eq!(look(device)["change"], 3);
    }
    relay.start();
    wait_for("relay healthy again", &[&relay], 30, || healthy(&relay));
    let all = [&relay, &laptop, &desktop];

    // One of the two sees both.
    let in_a_fork = |device: &Node| text(&look(device), "state") == "fork";
    wait_for("one device sees both changes", &all, 180, || {
        (in_a_fork(&laptop) || in_a_fork(&desktop)).then_some(())
    });
    let (forked, other) = match in_a_fork(&laptop) {
        true => (&laptop, &desktop),
        false => (&desktop, &laptop),
    };
    assert!(!in_a_fork(other), "the relay holds one of the two");
    let fork = "two changes were made apart: settle it with the phrase (`cordelia settle`)";
    let status = forked.cli(&["status"]);
    assert!(
        status.contains("Devices:   two changes were made apart"),
        "{status}"
    );
    assert!(status.contains(fork), "{status}");
    let listed = forked.cli(&["devices"]);
    assert!(listed.contains(fork), "{listed}");
    assert!(
        listed.contains("The change made apart (change 3, made on"),
        "{listed}"
    );
    // In a fork a device adds nothing, is handed nothing, and makes no
    // change but the settlement.
    let said = forked
        .at_terminal(&["add-device", &key_of(&relay)])
        .refused();
    assert!(said.contains("two changes were made apart"), "{said}");
    // (It asks nothing, and so ends at once.)
    let said = forked
        .at_terminal(&["accept", &key_of(other)])
        .refused_within(std::time::Duration::from_secs(60));
    assert!(said.contains("the fork is settled"), "{said}");
    let said = forked.at_terminal(&["renew"]).refused();
    assert!(said.contains("two changes were made apart"), "{said}");
    // The routes refuse the same, whoever asks.
    let (status, said) = asks(
        forked,
        "/api/v1/devices/accept",
        typed_on(forked, &key_of(other)),
    );
    assert_eq!(status, 400, "{said}");
    assert!(said.contains("two changes were made apart"), "{said}");
    let (status, _) = asks(forked, "/api/v1/change/prepare", json!({}));
    assert_eq!(status, 400);

    // The settlement.
    let mut at = forked.at_terminal(&["settle"]);
    at.says("Two changes were made apart. Each is shown from its signed bytes.");
    at.says("Change 3 (this device had applied):");
    at.says("Change 3 (made apart):");
    at.says("It undoes no removal");
    at.says(&format!(
        "({}) {:?}, a device of both changes:",
        words_of(&key_of(other)),
        other.name
    ));
    at.says(
        "Type `stays` or `removed`, or `neither` (it is in no list, and is added again by hand)",
    )
    .types("stays");
    at.says("The change that the recovery phrase will sign (change 4):");
    at.says("devices (2):");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 4).");
    at.done();
    let seen = look(forked);
    assert_eq!(
        (text(&seen, "state"), &seen["change"]),
        ("applied", &json!(4))
    );
    assert!(seen["apart"].is_null());
    applies(other, 4, &all);
    assert_eq!(text(&look(other), "state"), "applied");
}

// ── The phrase stays in the command's process ────────────────────────

/// The recovery phrase never leaves the command's process (decision
/// 2026-10-04 §5). Through a removal, with the phrase typed at the
/// terminal: nothing that the node was sent on its API has a word of the
/// phrase, and nor has anything that it logged, or anything in any file
/// of its directory afterwards, or what the terminal showed. The same is
/// so of the other device and of the relay, which were sent what the
/// node made of it.
#[test]
fn no_word_of_the_phrase_reaches_the_node_its_log_or_its_files_at_a_removal() {
    use cordelia_crypto::phrase::Phrase;
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let desktop = device_started("desktop", &relay);
    let all = [&relay, &laptop, &desktop];

    // A phrase whose words this test chose. The first statement is made
    // here with it, as the command makes it, and the node is handed the
    // entry and the statement key.
    let words = a_phrase_of_words_that_nothing_else_says();
    {
        let phrase = Phrase::parse(&words).unwrap();
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
    }
    adds(&laptop, &desktop, "desktop");

    // The removal, with everything that the command sends the node
    // passed on by this test, and kept.
    let through = PassesOn::to(laptop.http);
    let mut at = laptop.at_terminal_through(through.port, &["remove-device", &key_of(&desktop)]);
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 2).");
    let shown = at.done();
    wait_for("the desktop learns that it was removed", &all, 120, || {
        (text(&look(&desktop), "state") == "removed").then_some(())
    });

    // The node was asked through this test: what it was sent is here.
    let sent = through.sent();
    let sent_text = String::from_utf8_lossy(&sent);
    assert!(
        sent_text.contains("POST /api/v1/change/prepare"),
        "{sent_text}"
    );
    assert!(
        sent_text.contains("POST /api/v1/change/make"),
        "{sent_text}"
    );
    assert!(sent_text.contains("\"entry\""), "{sent_text}");

    // No word of the phrase, anywhere.
    let phrase_words: Vec<&str> = words.split(' ').collect();
    // Nor what only the phrase gives, and no device is given: the seed
    // of its signing key, the secret of its channel, and the key that
    // seals the part of a change entry that is for it.
    let only_the_phrases: Vec<[u8; 32]> = {
        let phrase = Phrase::parse(&words).unwrap();
        vec![
            *phrase.signing_key().unwrap().seed(),
            *phrase.channel_secret().unwrap(),
            *phrase.seal_key().unwrap(),
        ]
    };
    let mut searched: Vec<(String, Vec<u8>)> = vec![
        ("what the node was sent".into(), sent),
        ("what the terminal showed".into(), shown.into_bytes()),
    ];
    for node in all {
        searched.push((
            format!("the log of {}", node.name),
            std::fs::read(node.log()).unwrap(),
        ));
        for (path, bytes) in files_under(&node.data_dir()) {
            searched.push((format!("{} of {}", path.display(), node.name), bytes));
        }
    }
    assert!(searched.len() > 8, "{}", searched.len());
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
    // The search finds what is there: the label of a device, which the
    // node was sent, logged and wrote.
    assert!(bytes_searched > 100_000, "{bytes_searched}");
    assert!(words_in(&searched[0].1).contains("entry"));
    let in_files = searched
        .iter()
        .filter(|(what, _)| what.contains("cordelia.db"))
        .any(|(_, bytes)| words_in(bytes).contains("laptop"));
    assert!(in_files, "the search reads the node's database");
}

// ── Where a phrase is shown ──────────────────────────────────────────

/// A recovery phrase is shown only where what the command writes to is
/// a terminal too, and is cleared from it before the words are typed
/// back (decision 2026-10-04 §16). With a terminal for its input and a
/// pipe for what it writes, as `cordelia phrase | tee log` runs it, each
/// command that shows or reads a phrase refuses before it reads
/// anything, and nothing of a phrase is in the pipe. At a terminal, the
/// screen is cleared, with what scrolled off it, before the other screen
/// is put away and the words are asked for.
#[test]
fn a_phrase_is_shown_only_on_a_terminal_and_is_cleared_from_it() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    let other = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let other = cordelia_crypto::bech32::encode_public_key(&other.public_key()).unwrap();

    for args in [
        &["phrase", "--name", "laptop"][..],
        &["renew"],
        &["remove-device", &other],
        &["settle"],
    ] {
        let (ended, out, err) = laptop.at_terminal_into_a_pipe(args);
        assert_eq!(ended, Some(false), "{args:?}: it wrote {out:?} and {err:?}");
        assert!(
            err.contains("what it writes to is not a terminal"),
            "{args:?}: {err}"
        );
        assert!(err.contains("Nothing was done."), "{args:?}: {err}");
        // Nothing of a phrase is in the pipe: no line that is one, and
        // nothing at all.
        for line in out.lines().chain(err.lines()) {
            let a_phrase = cordelia_crypto::phrase::Phrase::parse(line).is_ok();
            assert!(!a_phrase, "{args:?} wrote a phrase into the pipe");
        }
        assert_eq!(out, "", "{args:?}");
    }
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");

    // At a terminal: the words are shown on the other screen, which is
    // cleared, with what scrolled off, before it is put away.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    let words = words_shown(&at.said);
    let rows = rows_shown(&at.said).to_string();
    at.types("");
    at.says("Now type the words back").types(&words);
    let said = at.done();
    let shown = said.find(&rows).expect("the words were shown");
    let cleared_and_left = "\x1b[H\x1b[2J\x1b[3J\x1b[?1049l";
    let cleared = said[shown..]
        .find(cleared_and_left)
        .map(|at| shown + at)
        .unwrap_or_else(|| panic!("the screen was not cleared before it was left: {said:?}"));
    let asked = said.find("Now type the words back").unwrap();
    assert!(shown < cleared && cleared < asked, "{said:?}");
    // They were shown once, and on the other screen.
    assert_eq!(said.matches(&rows).count(), 1);
    assert!(said[..shown].contains("\x1b[?1049h"), "{said:?}");
}

/// `cordelia phrase` shows nothing on a terminal that is known to keep
/// what is shown (decision 2026-10-04 §16). The words are taken away by
/// the terminal's other screen and by the clearing of what scrolled off
/// it, and GNU `screen` honours neither as it is set up by itself: what
/// was shown stays in its scrollback. Where the environment says that
/// the command runs inside it (`STY` is set), the command stops before
/// anything is shown or made, and says where to run it.
///
/// A command that only reads the phrase shows no word, and is not
/// stopped there: here `cordelia renew`.
#[test]
fn a_phrase_is_not_shown_inside_a_terminal_that_keeps_what_is_shown() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let inside_screen = [("STY", "4242.pts-1.laptop")];

    let mut at = laptop.at_terminal_given(&inside_screen, &["phrase", "--name", "laptop"]);
    let stopped = at.says_one_of(&["outside `screen`", "Press Enter when you have"]);
    assert_eq!(stopped, 0, "{}", at.said);
    let said = at.refused_within(std::time::Duration::from_secs(60));
    assert_eq!(
        said,
        "Error: this terminal can keep what is shown in its scrollback.\r\nRun `cordelia phrase` \
         in a terminal outside `screen`. Nothing was made.\r\n"
    );
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");

    // Outside it, a phrase is made. And inside it, a command that reads
    // the phrase asks for it as anywhere.
    let words = makes_a_phrase(&laptop, "laptop");
    let mut at = laptop.at_terminal_given(&inside_screen, &["renew"]);
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says(ASKS_THE_PHRASE).types(&words);
    at.says("The change is made (change 2).");
    drop(at);
    assert_eq!(look(&laptop)["change"], 2);
}

/// **On a terminal narrower than a row of four words, the words are
/// shown one to a line** (decision 2026-10-04 §5), each after its
/// number: no row is broken over two lines, and no number parted from
/// its word. A row of four can take 59 columns. On a terminal of 58 the
/// twelve words are on twelve lines, and are typed back as shown; on
/// one of 59 they are in three rows.
#[test]
fn on_a_terminal_narrower_than_the_rows_the_words_are_shown_one_to_a_line() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));

    let mut at = laptop.at_terminal_of(58, 19, &["phrase", "--name", "laptop"]);
    let shown = at.says_one_of(&["Press Enter when you have", "too small"]);
    assert_eq!(shown, 0, "{}", at.said);
    let rows = rows_shown(&at.said).to_string();
    let words = words_shown(&at.said);
    let each: Vec<&str> = words.split(' ').collect();
    let lines: Vec<&str> = rows.split("\r\n").collect();
    assert_eq!(lines.len(), 12, "{rows:?}");
    for (at_line, line) in lines.iter().enumerate() {
        assert_eq!(*line, format!("  {:>2}. {}", at_line + 1, each[at_line]));
    }
    at.types("");
    at.says(ASKS_THE_WORDS_BACK).types(&words);
    let said = at.done();
    assert!(said.contains("All twelve match."), "{said}");
    assert_eq!(look(&laptop)["change"], 1);

    // A column more: three rows of four.
    let mut at = laptop.at_terminal_of(59, 10, &["phrase", "--name", "laptop"]);
    at.says("Type yes to go on").types("yes");
    let shown = at.says_one_of(&["Press Enter when you have", "too small"]);
    assert_eq!(shown, 0, "{}", at.said);
    let rows = rows_shown(&at.said).to_string();
    assert_eq!(rows.split("\r\n").count(), 3, "{rows:?}");
    assert!(
        rows.starts_with("   1. ") && rows.contains("   4. "),
        "{rows:?}"
    );
}

/// **On a terminal too small for the twelve words, nothing is shown and
/// nothing is made** (decision 2026-10-04 §5): what does not fit would
/// scroll off the top of a screen that keeps no lines. The command stops
/// before there is a phrase, and says the size that the terminal has and
/// the size that the words need:
///
/// - wide enough for the rows of four, and a line too short for them;
/// - narrower than a row, and a line too short for twelve lines of one
///   word each;
/// - narrower than one word with its number, however many lines it has.
///
/// With the line that was missing, the words are shown.
#[test]
fn on_a_terminal_too_small_for_the_twelve_words_nothing_is_shown_or_made() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    let soon = std::time::Duration::from_secs(60);

    for (has, needs) in [
        ((80, 7), (80, 8)),
        ((58, 18), (58, 19)),
        ((13, 200), (14, 29)),
    ] {
        let mut at = laptop.at_terminal_of(has.0, has.1, &["phrase", "--name", "laptop"]);
        let stopped = at.says_one_of(&["too small", "Press Enter when you have"]);
        assert_eq!(stopped, 0, "{has:?}:\n{}", at.said);
        let said = at.refused_within(soon);
        let too_small = format!(
            "Error: this terminal is too small to show the twelve words: it has {} columns and {} \
             lines.\r\nThey need {} columns and {} lines. Nothing was made.\r\n",
            has.0, has.1, needs.0, needs.1
        );
        assert!(said.ends_with(&too_small), "{has:?}:\n{said:?}");
        for never in ["(shown once)", "\x1b[?1049h", "Now type the words back"] {
            assert!(!said.contains(never), "{has:?}: {never:?} in\n{said:?}");
        }
        assert_eq!(text(&look(&laptop), "state"), "no_phrase", "{has:?}");
    }

    // With the eighth line, the rows of four are shown.
    let mut at = laptop.at_terminal_of(80, 8, &["phrase", "--name", "laptop"]);
    let shown = at.says_one_of(&["Press Enter when you have", "too small"]);
    assert_eq!(shown, 0, "{}", at.said);
    let words = words_shown(&at.said);
    assert_eq!(rows_shown(&at.said).split("\r\n").count(), 3);
    at.types("");
    at.says(ASKS_THE_WORDS_BACK).types(&words);
    at.done();
    assert_eq!(look(&laptop)["change"], 1);
}

// ── A new key that is stopped ────────────────────────────────────────

/// `cordelia init --new-key` on a device that is one of several, with no
/// relay in reach (decision 2026-10-04 §5.2, §16). It says that it has
/// left, cannot send that, and asks whether to go on without having told
/// the others. Stopped there, the device keeps its key and leaves nobody:
/// its word that it left is taken back, by a delete in its place, so that
/// no relay is sent the word. Gone on with, the new key takes the place
/// of the old one whole: the key file is another file, the device's alone
/// to read, and nothing is left beside it.
#[test]
fn a_new_key_that_is_stopped_takes_back_the_word_that_the_device_left() {
    let mut relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let tablet = device_started("tablet", &relay);
    makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &tablet, "tablet");
    has_applied(&tablet, 1, &[&relay, &laptop, &tablet]);
    relay.stop();

    let key_file = tablet.data_dir().join("identity.key");
    let key_before = std::fs::read(&key_file).unwrap();
    let own = cordelia_crypto::bech32::decode_public_key(&key_of(&tablet)).unwrap();
    // The entries of its own in its store: how many stand, and how many
    // are deletes.
    let own_entries = || -> (i64, i64) {
        store_of(&tablet)
            .query_row(
                "SELECT COALESCE(SUM(is_delete = 0), 0), COALESCE(SUM(is_delete = 1), 0)
                 FROM entries WHERE author = ?1",
                [own.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    };
    let (stood, deleted) = own_entries();
    assert_eq!(deleted, 0);

    // Stopped at the second yes.
    let mut at = tablet.at_terminal(&["init", "--new-key"]);
    at.says("This gives this device a new key")
        .says("Type yes to go on")
        .types("yes");
    at.says("Telling the relays what this device leaves behind");
    assert_eq!(own_entries(), (stood + 1, 0), "its word that it left");
    at.says("Go on without having told them?")
        .says("Type yes to go on")
        .types("no");
    at.says("Stopped. This device keeps its key and what it holds, and has taken back its word");
    at.done();
    assert_eq!(std::fs::read(&key_file).unwrap(), key_before);
    assert_eq!(
        own_entries(),
        (stood, 1),
        "a delete stands in the word's place"
    );
    assert_eq!(text(&look(&tablet), "state"), "applied");
    assert_eq!(key_of(&tablet), text(&look(&tablet), "this_device"));

    // Gone on with: the key file is replaced whole.
    let mut at = tablet.at_terminal(&["init", "--new-key"]);
    at.says("Type yes to go on").types("yes");
    at.says("Go on without having told them?")
        .says("Type yes to go on")
        .types("yes");
    at.says("This device has a new key");
    at.done();
    let key_after = std::fs::read(&key_file).unwrap();
    assert_eq!(key_after.len(), 32);
    assert_ne!(key_after, key_before);
    assert!(!tablet.data_dir().join("identity.key.new").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

// ── Keys at a prompt ─────────────────────────────────────────────────

/// Ctrl-C at a prompt that hides what is typed, or while the other screen
/// is up, is read as a key (decision 2026-10-04 §16): the terminal is put
/// back as it was, with the other screen cleared and put away, and the
/// command ends with nothing made. And what was typed ahead of a prompt
/// is dropped: an Enter pressed twice at a yes does not take away the
/// screen that shows a new phrase.
#[test]
fn ctrl_c_is_read_as_a_key_and_what_was_typed_ahead_answers_nothing() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    let ctrl_c = [0x03u8];

    // While the screen that shows a new phrase is up.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    assert_eq!(at.is_as_it_was(), (false, false), "each key is read");
    let shown = rows_shown(&at.said).to_string();
    at.presses(&ctrl_c);
    at.says("Interrupted: the terminal is as it was, and nothing was made.");
    assert_eq!(at.is_as_it_was(), (true, true));
    let said = at.refused();
    let cleared_and_left = "\x1b[H\x1b[2J\x1b[3J\x1b[?1049l";
    let after_the_words = &said[said.find(&shown).unwrap()..];
    assert!(after_the_words.contains(cleared_and_left), "{said:?}");
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");

    // While what is typed is hidden: at the words typed back, in the
    // middle of a word, and at the phrase of a change.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have").types("");
    at.says("Now type the words back");
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(at.is_as_it_was(), (false, false), "hidden, and signals off");
    at.presses(b"lega").presses(&ctrl_c);
    at.says("Interrupted: the terminal is as it was, and nothing was made.");
    assert_eq!(at.is_as_it_was(), (true, true));
    let said = at.refused();
    // Nothing of what was typed was shown, and the number's line was
    // ended before the command said that it was interrupted. (What the
    // terminal showed before the words were asked for is not looked at:
    // one of the words that were shown may hold these letters.)
    let from_the_asking = format!(
        "{ASKS_THE_WORDS_BACK}\r\n\r\n   1. \r\nError: Interrupted: the terminal is as it was, \
         and nothing was made.\r\n"
    );
    assert!(said.ends_with(&from_the_asking), "{said:?}");
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");

    // The keys that take back what was typed are acted on, where each
    // key is read as it is pressed, for the word that is being typed: a
    // letter, and the word by either of the keys that take back a word
    // or a line. The words are typed back with all three, and are the
    // phrase: no word got a cross.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    let words = words_shown(&at.said);
    at.types("");
    at.says("Now type the words back");
    let shown: Vec<&str> = words.split(' ').collect();
    // No word of the list ends in a q.
    at.presses(format!("{}q\x7f ", shown[0]).as_bytes());
    at.presses(format!("mistaken\x15{} ", shown[1]).as_bytes());
    at.presses(format!("mistaken\x17{}\n", shown[2]).as_bytes());
    at.types(&shown[3..].join(" "));
    let typed_back = at.says_one_of(&["All twelve match.", "\u{2717}"]);
    assert_eq!(typed_back, 0, "a word got a cross:\n{}", at.said);
    let said = at.done();
    assert!(said.contains("follows the new recovery phrase"), "{said}");
    assert!(
        said.contains(&format!("{ASKS_THE_WORDS_BACK}\r\n\r\n{}", ticks(1, 12))),
        "{said:?}"
    );
    assert!(!said.contains("mistaken"), "{said}");

    let mut at = laptop.at_terminal(&["renew"]);
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time");
    at.presses(&ctrl_c);
    at.says("Interrupted: the terminal is as it was, and nothing was made.");
    assert_eq!(at.is_as_it_was(), (true, true));
    at.refused();
    assert_eq!(look(&laptop)["change"], 1);

    // An Enter pressed twice at the yes: the second is dropped before the
    // screen that shows the new phrase goes up, and the screen stays.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("This replaces the recovery phrase that this device follows")
        .says("Type yes to go on")
        .presses(b"yes\n\n");
    at.says("Press Enter when you have");
    let said = at
        .hears_for(std::time::Duration::from_millis(1500))
        .to_string();
    assert!(!said.contains("Now type the words back"), "{said:?}");
    let _ = words;
}

// ── The phrase, a word at a time ─────────────────────────────────────

/// What a terminal showed from the `nth` time (the first is 0) that a
/// command said `asks` there, to the end of the line of the twelfth
/// number: where a phrase is proved, everything that is said of it
/// before it is judged.
fn to_the_twelfth<'a>(said: &'a str, asks: &str, nth: usize) -> &'a str {
    let (from, _) = said
        .match_indices(asks)
        .nth(nth)
        .unwrap_or_else(|| panic!("{asks:?} was not said {} times:\n{said}", nth + 1));
    let twelfth = said[from..]
        .find("\r\n  12. ")
        .unwrap_or_else(|| panic!("no twelfth word was asked for:\n{said}"));
    let line = from + twelfth + 2;
    let end = said[line..]
        .find("\r\n")
        .map_or(said.len(), |end| line + end + 2);
    &said[from..end]
}

/// What a terminal shows where what was typed for word `number` is not
/// in the list: the number, a cross and a few words, on one line.
fn not_in_the_list(number: usize) -> String {
    format!(
        "  {number:>2}. \u{2717}  That is not a word from the list. Type word {number} again.\r\n"
    )
}

/// What it shows, at `cordelia phrase`, where what was typed back for
/// word `number` is a word of the list and not the word that was shown.
fn does_not_match(number: usize) -> String {
    format!(
        "  {number:>2}. \u{2717}  That does not match word {number}. Check what you wrote, and \
         type it again.\r\n"
    )
}

/// `cordelia renew` on `device`, run to where it asks for the phrase.
fn renews_to_the_phrase(device: &Node) -> AtTerminal {
    let mut at = device.at_terminal(&["renew"]);
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says(ASKS_THE_PHRASE);
    at
}

/// A `cordelia phrase` that is about to show its words, run to where it
/// asks for them to be typed back: the command, and the words that it
/// showed.
fn makes_a_phrase_to_the_typing_back(mut at: AtTerminal) -> (AtTerminal, String) {
    at.says("Press Enter when you have");
    let words = words_shown(&at.said);
    at.types("");
    at.says(ASKS_THE_WORDS_BACK);
    (at, words)
}

/// Wherever a command reads the recovery phrase, it asks for the twelve
/// words by number, one at a time, and nothing that is typed is shown
/// (decision 2026-10-04 §5, §16): no letter, no star, no count of
/// letters. After each word its number has a tick beside it, on that
/// line, and the next number is asked for.
///
/// That is so where the words are typed back at `cordelia phrase`, and
/// where a phrase is proved, here at `cordelia renew`. Before each word
/// is typed, everything that the terminal has shown since the line that
/// asks is a tick for each word so far and the number that is asked for.
#[test]
fn each_word_of_the_list_gets_a_tick_and_nothing_that_is_typed_is_shown() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    // Type `words` one at a time where a command has said `asks`, each
    // when its number is asked for.
    let types_each = |at: &mut AtTerminal, asks: &str, words: &str| {
        for (typed, word) in words.split(' ').enumerate() {
            let number = format!("  {:>2}. ", typed + 1);
            at.says(&number);
            let so_far = format!("{asks}\r\n\r\n{}{number}", ticks(1, typed));
            assert!(
                at.said.ends_with(&so_far),
                "before word {} was typed, the terminal showed:\n{:?}",
                typed + 1,
                at.said
            );
            at.types(word);
        }
    };

    let at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    types_each(&mut at, ASKS_THE_WORDS_BACK, &words);
    let said = at.done();
    let typed_back = format!(
        "{ASKS_THE_WORDS_BACK}\r\n\r\n{}\r\nAll twelve match.\r\n",
        ticks(1, 12)
    );
    assert!(said.contains(&typed_back), "{said:?}");
    assert_eq!(look(&laptop)["change"], 1);

    let mut at = renews_to_the_phrase(&laptop);
    types_each(&mut at, ASKS_THE_PHRASE, &words);
    at.says("The change is made (change 2).");
    let said = at.said.clone();
    drop(at);
    let typed = format!(
        "{ASKS_THE_PHRASE}\r\n\r\n{}\r\nThe change is made (change 2).",
        ticks(1, 12)
    );
    assert!(said.contains(&typed), "{said:?}");
    assert_eq!(look(&laptop)["change"], 2);
}

/// A word ends at a space or at Enter, so twelve words typed or pasted
/// on one line are taken in their order, each to the next number
/// (decision 2026-10-04 §5): with more than one space between them, a
/// tab, space before the first, and upper case, which is taken as lower.
/// Typed last first, the same twelve are other words at each number:
/// they get their ticks, and are not the phrase.
#[test]
fn twelve_words_on_one_line_are_taken_in_their_order() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let all_ticks = |asks: &str| format!("{asks}\r\n\r\n{}", ticks(1, 12));

    let at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    let shown: Vec<&str> = words.split(' ').collect();
    let one_line = format!(
        "  {}  {}{}\t{}",
        shown[0].to_uppercase(),
        shown[1][..1].to_uppercase(),
        &shown[1][1..],
        shown[2..].join("   ")
    );
    assert_ne!(one_line.to_lowercase(), words);
    at.types(&one_line);
    let typed_back = at.says_one_of(&["All twelve match.", "\u{2717}"]);
    assert_eq!(typed_back, 0, "a word got a cross:\n{}", at.said);
    let said = at.done();
    assert!(
        said.contains(&format!(
            "{}\r\nAll twelve match.",
            all_ticks(ASKS_THE_WORDS_BACK)
        )),
        "{said:?}"
    );

    // Where a phrase is proved. Last first, they are twelve words of
    // the list, and another twelve than the phrase: nothing is made.
    let last_first: Vec<&str> = shown.iter().rev().copied().collect();
    assert_ne!(last_first, shown);
    let mut at = renews_to_the_phrase(&laptop);
    at.types(&last_first.join(" "));
    let judged = at.says_one_of(&[
        "It was mistyped: nothing was made.",
        "it is not the one that this device follows: nothing was made.",
        "The change is made",
        "\u{2717}",
    ]);
    assert!(judged < 2, "{}", at.said);
    assert_eq!(
        to_the_twelfth(&at.said, ASKS_THE_PHRASE, 0),
        all_ticks(ASKS_THE_PHRASE)
    );
    drop(at);
    assert_eq!(look(&laptop)["change"], 1);

    // In their order, on the one line: the phrase.
    let mut at = renews_to_the_phrase(&laptop);
    at.types(&one_line);
    let judged = at.says_one_of(&[
        "The change is made (change 2).",
        "It was mistyped",
        "it is not the one that this device follows",
        "\u{2717}",
    ]);
    assert_eq!(judged, 0, "{}", at.said);
    assert_eq!(
        to_the_twelfth(&at.said, ASKS_THE_PHRASE, 0),
        all_ticks(ASKS_THE_PHRASE)
    );
    drop(at);
    assert_eq!(look(&laptop)["change"], 2);
}

/// A word that is not in the list is no guess at a word (decision
/// 2026-10-04 §16): it gets a cross and a few plain words, the same
/// number is asked again, and that has no bound.
///
/// - **It is no miss.** At `cordelia phrase`, four words that are no
///   words of the list are typed back among two words that are, and are
///   not the word shown: the third miss would stop the command, and
///   none of the four is one. The phrase is made.
/// - **What was typed ahead of it is dropped.** Where a phrase is
///   proved, a line of twelve whose third is no word of the list gets
///   two ticks and a cross, and the third number is asked again: the
///   nine words after it were not taken for the third and the ones
///   after. Typed from the third on, the words are the phrase.
#[test]
fn a_word_that_is_not_in_the_list_is_asked_again_and_is_no_miss() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);

    let at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    let shown: Vec<&str> = words.split(' ').collect();
    let another = another_word_than(shown[0]);
    let mut crosses = String::new();
    for (typed, is_of_the_list) in [
        ("xyzzy", false),
        (another, true),
        ("abandon,", false),
        ("zo", false),
        (another, true),
        ("12345", false),
    ] {
        at.types(typed);
        // Either cross ends so, and the first number is asked again.
        let asked_again = at.says_one_of(&["again.\r\n   1. ", "Three tries did not match"]);
        assert_eq!(asked_again, 0, "after {typed:?}:\n{}", at.said);
        crosses.push_str(&match is_of_the_list {
            true => does_not_match(1),
            false => not_in_the_list(1),
        });
        let so_far = format!("{ASKS_THE_WORDS_BACK}\r\n\r\n{crosses}   1. ");
        assert!(
            at.said.ends_with(&so_far),
            "after {typed:?}:\n{:?}",
            at.said
        );
    }
    at.types(&words);
    let typed_back = at.says_one_of(&["All twelve match.", "Three tries did not match"]);
    assert_eq!(typed_back, 0, "{}", at.said);
    let said = at.done();
    assert!(
        said.contains(&format!(
            "{ASKS_THE_WORDS_BACK}\r\n\r\n{crosses}{}\r\nAll twelve match.",
            ticks(1, 12)
        )),
        "{said:?}"
    );
    assert_eq!(look(&laptop)["change"], 1);

    // Where a phrase is proved: the third word of a line is none.
    let mut at = renews_to_the_phrase(&laptop);
    at.types(&format!(
        "{} {} xyzzy {}",
        shown[0],
        shown[1],
        shown[3..].join(" ")
    ));
    at.says(&not_in_the_list(3)).says("   3. ");
    at.types(&shown[2..].join(" "));
    let judged = at.says_one_of(&[
        "The change is made (change 2).",
        "It was mistyped",
        "it is not the one that this device follows",
        "Type word",
    ]);
    assert_eq!(judged, 0, "{}", at.said);
    let typed = format!(
        "{ASKS_THE_PHRASE}\r\n\r\n{}{}{}\r\nThe change is made (change 2).",
        ticks(1, 2),
        not_in_the_list(3),
        ticks(3, 12)
    );
    assert!(at.said.contains(&typed), "{:?}", at.said);
    drop(at);
    assert_eq!(look(&laptop)["change"], 2);
}

/// **Where a phrase is proved, the command never says whether a word is
/// the right one** (decision 2026-10-04 §16): a tick says that a word is
/// a word of the list, and nothing more. Here at `cordelia renew`:
///
/// - a phrase whose fourth word is another word of the list, of another
///   length, is typed one word at a time: the wrong word gets its tick
///   when it is typed, as the three before it did, and the fifth number
///   is asked for. Nothing is said of the twelve until the twelfth is
///   typed;
/// - what the terminal shows for that phrase, from the line that asks to
///   the end of the twelfth word, is byte for byte what it shows for the
///   device's own phrase, and for another person's phrase, of which
///   every word is wrong;
/// - the transcripts of two runs of the command, one with another
///   person's phrase and one with the device's own, are the same from
///   their first byte to the end of the twelfth word;
/// - nothing waits here, as a miss does where words are typed back: of
///   the twelve words of another person's phrase, typed one at a time,
///   the quickest gets its tick in less than that pause.
///
/// Only after the twelfth word do they differ: by what is said of a
/// phrase once it is whole.
#[test]
fn where_a_phrase_is_proved_a_wrong_word_of_the_list_gets_the_tick_of_the_right_one() {
    use cordelia_core::protocol::PHRASE_MISS_PAUSE_SECS;
    use cordelia_crypto::phrase::Phrase;
    use std::time::{Duration, Instant};
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    let own: Vec<&str> = words.split(' ').collect();
    let all_ticks = format!("{ASKS_THE_PHRASE}\r\n\r\n{}", ticks(1, 12));
    wait_for(
        "the relay holds the first change",
        &[&relay, &laptop],
        60,
        || relay_holds_latest(&laptop),
    );

    // Another person's phrase: every word of it is a wrong one.
    let anothers = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    // And the device's own, with another word of the list as its fourth,
    // of another length: no phrase at all.
    let mistyped = [
        "zoo", "wrong", "able", "about", "above", "absent", "abandon",
    ]
    .iter()
    .filter(|other| other.len() != own[3].len())
    .map(|other| {
        let mut mistyped = own.clone();
        mistyped[3] = other;
        mistyped.join(" ")
    })
    .find(|mistyped| Phrase::parse(mistyped).is_err())
    .expect("one of these words in the place of another fails the checksum");

    // Another person's phrase, a word at a time, in a run of its own:
    // nothing is made. Each word of it is a wrong one, and none waits
    // for its tick.
    let mut at = renews_to_the_phrase(&laptop);
    let mut quickest = Duration::MAX;
    for word in anothers.split(' ') {
        let typed = Instant::now();
        at.types(word);
        at.says("\u{2713}\r\n");
        quickest = quickest.min(typed.elapsed());
    }
    assert!(
        quickest < Duration::from_secs(PHRASE_MISS_PAUSE_SECS),
        "a wrong word of the list waited {quickest:?} for its tick"
    );
    let with_anothers = at.refused_within(Duration::from_secs(60));
    assert!(
        with_anothers.contains(&format!(
            "{all_ticks}Error: that is a recovery phrase, and it is not the one that this device \
             follows: nothing was made."
        )),
        "{with_anothers:?}"
    );
    assert_eq!(look(&laptop)["change"], 1);

    // The mistyped phrase, a word at a time.
    let mut at = renews_to_the_phrase(&laptop);
    for (typed, word) in mistyped.split(' ').enumerate() {
        let number = format!("  {:>2}. ", typed + 1);
        at.says(&number);
        let so_far = format!("{ASKS_THE_PHRASE}\r\n\r\n{}{number}", ticks(1, typed));
        assert!(
            at.said.ends_with(&so_far),
            "before word {} was typed, the terminal showed:\n{:?}",
            typed + 1,
            at.said
        );
        at.types(word);
    }
    at.says(
        "these words are not a recovery phrase: at least one of them is not the word it was. It \
         was mistyped: nothing was made. Type it again.",
    );
    // And then the device's own, at the same command.
    at.says(ASKS_THE_PHRASE).types(&words);
    at.says("The change is made (change 2).");
    let with_its_own = at.said.clone();
    drop(at);

    // From the line that asks to the end of the twelfth word: the same
    // bytes for the three phrases, a tick for each word.
    let for_the_mistyped = to_the_twelfth(&with_its_own, ASKS_THE_PHRASE, 0);
    let for_its_own = to_the_twelfth(&with_its_own, ASKS_THE_PHRASE, 1);
    let for_anothers = to_the_twelfth(&with_anothers, ASKS_THE_PHRASE, 0);
    assert_eq!(for_its_own, all_ticks);
    assert_eq!(for_the_mistyped, for_its_own);
    assert_eq!(for_anothers, for_its_own);
    // Only what follows the twelfth word differs.
    assert!(
        with_its_own.contains(&format!("{all_ticks}these words are not a recovery phrase")),
        "{with_its_own:?}"
    );
    assert!(
        with_its_own.contains(&format!("{all_ticks}\r\nThe change is made (change 2).")),
        "{with_its_own:?}"
    );

    // Two runs of the command, each with one phrase typed on a line:
    // another person's, and the device's own. Their transcripts are the
    // same from their first byte to the end of the twelfth word, but for
    // the number of the change that each would make. (What a command
    // could not fetch is of the relay's moment, and not of a phrase
    // that was not asked for yet: a run that says so is held against the
    // other from the line that asks.)
    let mut at = renews_to_the_phrase(&laptop);
    at.types(&words);
    at.says("The change is made (change 3).");
    let with_the_right = at.said.clone();
    drop(at);
    assert_eq!(
        to_the_twelfth(&with_anothers, ASKS_THE_PHRASE, 0),
        to_the_twelfth(&with_the_right, ASKS_THE_PHRASE, 0)
    );
    let to_its_twelfth = |said: &str, change: &str| {
        let asked = said.find(ASKS_THE_PHRASE).expect("the phrase is asked for");
        let to = asked + to_the_twelfth(said, ASKS_THE_PHRASE, 0).len();
        said[..to].replace(change, "(change N)")
    };
    let fetched = |said: &str| !said.contains("Could not fetch");
    if fetched(&with_anothers) && fetched(&with_the_right) {
        assert_eq!(
            to_its_twelfth(&with_anothers, "(change 2)"),
            to_its_twelfth(&with_the_right, "(change 3)")
        );
    }
    assert_eq!(look(&laptop)["change"], 3);
}

/// **Only at `cordelia phrase`, where the words were shown a moment ago
/// and are typed back, is each word held against the word that was shown
/// at its number** (decision 2026-10-04 §5, §16). A word of the list
/// that is not that word gets a cross and plain words, and the same
/// number is asked again. The third such miss, over the whole typing
/// back and not for each word, stops the command: nothing is made, and
/// the node was asked to make nothing. Two misses followed by the right
/// words make the phrase.
#[test]
fn a_word_typed_back_that_is_not_the_word_shown_is_said_and_the_third_stops_the_command() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    // What the command asks of the node is passed on by this test, and
    // kept.
    let through = Answers::in_the_place_of(&laptop, |_, _| {});
    let asked_to_make = || {
        let asked = through.asked();
        asked
            .iter()
            .filter(|(path, _)| path == "/api/v1/phrase/make")
            .count()
    };
    // Type the words back to the ninth: the first as it was shown, the
    // second and the fifth first as another word of the list and then
    // as they were shown, and the rest as they were shown. What the
    // terminal then shows of it.
    let two_misses = |at: &mut AtTerminal, shown: &[&str]| -> String {
        at.types(shown[0]);
        let first = at.says_one_of(&["\u{2713}\r\n   2. ", "\u{2717}"]);
        assert_eq!(first, 0, "at word 1:\n{}", at.said);
        for (missed, then) in [(1, 4), (4, 8)] {
            let number = missed + 1;
            at.types(another_word_than(shown[missed]));
            // It is said, and the same number is asked again.
            let said = at.says_one_of(&[
                &format!(
                    "That does not match word {number}. Check what you wrote, and type it \
                     again.\r\n  {number:>2}. "
                ),
                "\u{2713}",
                "Three tries did not match",
            ]);
            assert_eq!(said, 0, "at word {number}:\n{}", at.said);
            // The word as it was shown, and the ones after it: each
            // gets its tick, and the next number is asked for.
            at.types(&shown[missed..then].join(" "));
            let next = format!("\u{2713}\r\n  {:>2}. ", then + 1);
            let ticked = at.says_one_of(&[&next, "\u{2717}"]);
            assert_eq!(ticked, 0, "after word {number}:\n{}", at.said);
        }
        format!(
            "{ASKS_THE_WORDS_BACK}\r\n\r\n{}{}{}{}{}",
            ticks(1, 1),
            does_not_match(2),
            ticks(2, 4),
            does_not_match(5),
            ticks(5, 8)
        )
    };

    // The third miss, at a third word: the command stops.
    let at = laptop.at_terminal_through(through.port, &["phrase", "--name", "laptop"]);
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    let shown: Vec<&str> = words.split(' ').collect();
    let to_the_ninth = two_misses(&mut at, &shown);
    at.types(another_word_than(shown[8]));
    let stopped = at.says_one_of(&[
        "Three tries did not match.",
        "That does not match word 9.",
        "\u{2713}",
    ]);
    assert_eq!(stopped, 0, "{}", at.said);
    let said = at.refused_within(std::time::Duration::from_secs(60));
    assert!(
        said.contains(&format!(
            "{to_the_ninth}   9. \u{2717}\r\nError: Three tries did not match. Nothing was made, \
             and the words you were shown are not a recovery phrase: do not keep them. Run \
             `cordelia phrase` again."
        )),
        "{said:?}"
    );
    assert!(!said.contains("All twelve match."), "{said}");
    assert!(!said.contains("follows the new recovery phrase"), "{said}");
    // Nothing was made, and the node was asked to make nothing.
    assert_eq!(asked_to_make(), 0);
    assert!(
        through
            .asked()
            .iter()
            .any(|(path, _)| path == "/api/v1/devices/list"),
        "the command asked the node through this test"
    );
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");

    // Two misses, and then each word as it was shown: the phrase.
    let at = laptop.at_terminal_through(through.port, &["phrase", "--name", "laptop"]);
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    let shown: Vec<&str> = words.split(' ').collect();
    let to_the_ninth = two_misses(&mut at, &shown);
    at.types(&shown[8..].join(" "));
    let typed_back = at.says_one_of(&["All twelve match.", "Three tries did not match"]);
    assert_eq!(typed_back, 0, "{}", at.said);
    let said = at.done();
    assert!(
        said.contains(&format!(
            "{to_the_ninth}{}\r\nAll twelve match.\r\n",
            ticks(9, 12)
        )),
        "{said:?}"
    );
    assert!(said.contains("follows the new recovery phrase"), "{said}");
    assert_eq!(asked_to_make(), 1);
    let seen = look(&laptop);
    assert_eq!(
        (text(&seen, "state"), &seen["change"]),
        ("applied", &json!(1))
    );
}

/// **A miss is said after a pause** (decision 2026-10-04 §16), at
/// `cordelia phrase` and nowhere else: two seconds before the first is
/// said, four before the second, and none before the third, which ends
/// the command. Measured here, from when each word is sent to when the
/// terminal shows what is said of it:
///
/// - a word that is the word shown, and a word that is not in the list,
///   are answered with no pause: of three of each, the quickest is
///   answered in less than the pause;
/// - the first miss is said no sooner than the pause after it was sent,
///   and nothing is shown for the whole of the pause, less a margin;
/// - the second is said no sooner than twice the pause, with nothing
///   shown meanwhile;
/// - the third is said at once: in less than the pause.
#[test]
fn a_miss_is_said_after_its_pause_and_any_other_word_is_answered_at_once() {
    use cordelia_core::protocol::PHRASE_MISS_PAUSE_SECS;
    use std::time::{Duration, Instant};
    let pause = Duration::from_secs(PHRASE_MISS_PAUSE_SECS);
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));

    let at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    let shown: Vec<&str> = words.split(' ').collect();
    let line = |word: &str| format!("{word}\n").into_bytes();
    // What follows a cross: its words, and then the same number asked
    // again. (The number before the cross is not in these: it was said,
    // and waited for, before its word was sent.)
    let no_word_says = "That is not a word from the list. Type word 1 again.\r\n";
    let a_miss_says = "That does not match word 4. Check what you wrote, and type it again.\r\n";
    // Hear the terminal out to a quarter of a second before `long` has
    // gone by since `sent`: nothing was shown by then, and it shows what
    // it showed when the word was sent, which ends with `asked`. (Where
    // the test itself was held up to the end of the pause, this says
    // nothing: the miss may have been said by then.)
    let nothing_is_shown = |at: &mut AtTerminal, sent: Instant, long: Duration, asked: &str| {
        let margin = Duration::from_millis(250);
        let until = sent + long - margin;
        let meanwhile = at
            .hears_for(until.saturating_duration_since(Instant::now()))
            .to_string();
        if sent.elapsed() < long {
            assert!(
                meanwhile.ends_with(asked),
                "{:?} after the word was sent, the terminal showed:\n{meanwhile:?}",
                sent.elapsed()
            );
        }
    };

    // No pause: a word that is not in the list, and the word shown.
    let mut quickest = Duration::MAX;
    for no_word in ["xyzzy", "legul", "qqq"] {
        at.says("   1. ");
        let sent = at.sends(&line(no_word));
        at.says(no_word_says);
        quickest = quickest.min(sent.elapsed());
    }
    assert!(
        quickest < pause,
        "a word that is not in the list waited {quickest:?}"
    );
    let mut quickest = Duration::MAX;
    for (typed_so_far, word) in shown[..3].iter().enumerate() {
        at.says(&format!("  {:>2}. ", typed_so_far + 1));
        let sent = at.sends(&line(word));
        at.says("\u{2713}\r\n");
        quickest = quickest.min(sent.elapsed());
    }
    assert!(quickest < pause, "the word shown waited {quickest:?}");

    // The first miss: nothing is shown for the pause, and then that it
    // does not match.
    let another = another_word_than(shown[3]);
    at.says("   4. ");
    let sent = at.sends(&line(another));
    nothing_is_shown(&mut at, sent, pause, &format!("{}   4. ", ticks(3, 3)));
    at.says(a_miss_says);
    let waited = sent.elapsed();
    assert!(waited >= pause, "the first miss was said after {waited:?}");

    // The second: twice as long.
    at.says("   4. ");
    let sent = at.sends(&line(another));
    let asked_again = format!("{}   4. ", does_not_match(4));
    nothing_is_shown(&mut at, sent, 2 * pause, &asked_again);
    at.says(a_miss_says);
    let waited = sent.elapsed();
    assert!(
        waited >= 2 * pause,
        "the second miss was said after {waited:?}"
    );

    // The third: at once, and the command ends.
    at.says("   4. ");
    let sent = at.sends(&line(another));
    let stopped = at.says_one_of(&["Three tries did not match.", a_miss_says]);
    let waited = sent.elapsed();
    assert_eq!(stopped, 0, "{}", at.said);
    assert!(waited < pause, "the third miss was said after {waited:?}");
    let said = at.refused_within(Duration::from_secs(60));
    let all = format!(
        "{ASKS_THE_WORDS_BACK}\r\n\r\n{}{}{}   4. \u{2717}\r\nError: Three tries did not match. \
         Nothing was made, and the words you were shown are not a recovery phrase: do not keep \
         them. Run `cordelia phrase` again.\r\n",
        not_in_the_list(1).repeat(3),
        ticks(1, 3),
        does_not_match(4).repeat(2),
    );
    assert!(said.ends_with(&all), "{said:?}");
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");
}

/// **What is typed while a miss waits is not taken as the next word**
/// (decision 2026-10-04 §16): it is dropped before the same number is
/// asked again, so that neither a key held down nor a line that was
/// pasted spends every miss at once.
///
/// - While the second miss waits, which is the longer wait, three things
///   are typed, each with its Enter: a word that is no word of the list,
///   the word that was shown, and the ten words after it on one line.
///   None is answered: the miss is said, the same number is asked again,
///   and the words typed then, from that number on, are the phrase.
/// - Ctrl-C while a miss waits ends the command then, and not when the
///   wait is over, with the terminal put back as it was.
#[test]
fn what_is_typed_while_a_miss_waits_is_not_taken_as_the_next_word() {
    use cordelia_core::protocol::PHRASE_MISS_PAUSE_SECS;
    use std::time::Duration;
    let pause = Duration::from_secs(PHRASE_MISS_PAUSE_SECS);
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    let line = |words: &str| format!("{words}\n").into_bytes();
    let a_moment = Duration::from_millis(100);
    // What follows a miss at word `number`: its words, and the same
    // number asked again.
    let a_miss_says = |number: usize| {
        format!(
            "That does not match word {number}. Check what you wrote, and type it again.\r\n  \
             {number:>2}. "
        )
    };

    let at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    let shown: Vec<&str> = words.split(' ').collect();
    let another = another_word_than(shown[1]);
    at.types(shown[0]);
    at.says("\u{2713}\r\n   2. ");
    at.types(another);
    at.says(&a_miss_says(2));
    // The second miss, and what is typed while it waits.
    let sent = at.sends(&line(another));
    for typed_meanwhile in ["xyzzy", shown[1], &shown[2..].join(" ")] {
        std::thread::sleep(a_moment);
        at.sends(&line(typed_meanwhile));
    }
    assert!(sent.elapsed() < 2 * pause, "the test was slow");
    at.says(&a_miss_says(2));
    assert!(sent.elapsed() >= 2 * pause, "{:?}", sent.elapsed());
    // Each word from the second on, as it was shown.
    at.types(&shown[1..].join(" "));
    let typed_back = at.says_one_of(&[
        "All twelve match.",
        "Three tries did not match",
        "That is not a word from the list. Type word 2 again.",
        "That does not match word",
    ]);
    assert_eq!(typed_back, 0, "{}", at.said);
    let said = at.done();
    // Of what was typed while the miss waited, nothing was answered:
    // no cross for the word that is none, and no tick before the miss
    // was said.
    let all = format!(
        "{ASKS_THE_WORDS_BACK}\r\n\r\n{}{}{}\r\nAll twelve match.\r\n",
        ticks(1, 1),
        does_not_match(2).repeat(2),
        ticks(2, 12),
    );
    assert!(said.contains(&all), "{said:?}");
    assert_eq!(look(&laptop)["change"], 1);

    // Ctrl-C while a miss waits: the command ends then, and not when
    // the pause is over. It is pressed while the second miss waits.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Type yes to go on").types("yes");
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    let another = another_word_than(words.split(' ').next().unwrap());
    at.types(another);
    at.says(&a_miss_says(1));
    let sent = at.sends(&line(another));
    std::thread::sleep(3 * a_moment);
    at.sends(&[0x03]);
    let ended = at.says_one_of(&[
        "Interrupted: the terminal is as it was, and nothing was made.",
        "That does not match word 1.",
    ]);
    let waited = sent.elapsed();
    assert_eq!(ended, 0, "{}", at.said);
    assert!(waited < 2 * pause, "Ctrl-C was acted on after {waited:?}");
    assert_eq!(at.is_as_it_was(), (true, true));
    let said = at.refused();
    assert!(said.contains("   1. \r\nError: Interrupted"), "{said:?}");
    // The phrase that the device follows is the one made before.
    assert_eq!(look(&laptop)["change"], 1);
    let key = cordelia_crypto::phrase::Phrase::parse(&words)
        .unwrap()
        .public_key()
        .unwrap();
    assert_ne!(
        text(&look(&laptop), "phrase_words"),
        cordelia_crypto::fingerprint::shown(&key)
    );
}

/// **A phrase that is mistyped may be typed three times in all, and no
/// more** (decision 2026-10-04 §5). Where a phrase is proved, here at
/// `cordelia renew`, twelve words of the list that are no recovery
/// phrase are told from a wrong phrase by its checksum, and are asked
/// for again: twice. After the third the command says the same of them,
/// asks no more, and ends: nothing is made.
#[test]
fn a_phrase_mistyped_three_times_is_refused_and_nothing_is_made() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    let no_phrase = mistyped(&words, 3);
    let says = "these words are not a recovery phrase: at least one of them is not the word it was. \
                It was mistyped: nothing was made.";

    let mut at = renews_to_the_phrase(&laptop);
    for _ in 0..2 {
        at.types(&no_phrase);
        // Said, and asked for again.
        let again = at.says_one_of(&[
            &format!("{says} Type it again.\r\n"),
            &format!("{says}\r\n"),
        ]);
        assert_eq!(again, 0, "{}", at.said);
        at.says(ASKS_THE_PHRASE);
    }
    at.types(&no_phrase);
    let again = at.says_one_of(&[
        &format!("Error: {says}\r\n"),
        &format!("{says} Type it again."),
    ]);
    assert_eq!(again, 0, "{}", at.said);
    let said = at.refused_within(std::time::Duration::from_secs(60));
    // Three times it was asked for, each time with its twelve ticks,
    // and the third was the last.
    assert_eq!(said.matches(ASKS_THE_PHRASE).count(), 3, "{said:?}");
    let all_ticks = format!("{ASKS_THE_PHRASE}\r\n\r\n{}", ticks(1, 12));
    assert_eq!(said.matches(&all_ticks).count(), 3, "{said:?}");
    assert!(
        said.ends_with(&format!("{all_ticks}Error: {says}\r\n")),
        "{said:?}"
    );
    assert_eq!(look(&laptop)["change"], 1);
}

/// **Where a phrase is proved, a right word and a wrong word of the list
/// get their ticks alike in time** (decision 2026-10-04 §16): nothing
/// waits for some words and not for others. Here at `cordelia renew`
/// another person's phrase, of which every word is a wrong one, and
/// then the device's own are typed one word at a time, and the time
/// from when each word is sent to when its tick is shown is taken. At
/// each of the twelve numbers the two times are within three quarters
/// of the pause that a miss has where words are typed back.
///
/// The bound is a wide one: it is there to catch a wait that is added
/// after some words, and not to measure the looking up of a word.
#[test]
fn where_a_phrase_is_proved_a_right_word_and_a_wrong_one_are_ticked_alike_in_time() {
    use cordelia_core::protocol::PHRASE_MISS_PAUSE_SECS;
    use std::time::Duration;
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    let anothers = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    // Type `words` one at a time: how long each took to get its tick.
    let ticked_in = |at: &mut AtTerminal, words: &str| -> Vec<Duration> {
        let mut each = Vec::new();
        for (typed, word) in words.split(' ').enumerate() {
            at.says(&format!("  {:>2}. ", typed + 1));
            let sent = at.sends(format!("{word}\n").as_bytes());
            at.says("\u{2713}\r\n");
            each.push(sent.elapsed());
        }
        each
    };

    let mut at = renews_to_the_phrase(&laptop);
    let wrong = ticked_in(&mut at, anothers);
    let said = at.refused_within(Duration::from_secs(60));
    assert!(
        said.contains("it is not the one that this device follows: nothing was made."),
        "{said}"
    );
    let mut at = renews_to_the_phrase(&laptop);
    let right = ticked_in(&mut at, &words);
    at.says("The change is made (change 2).");
    drop(at);

    let bound = Duration::from_secs(PHRASE_MISS_PAUSE_SECS) * 3 / 4;
    assert_eq!((right.len(), wrong.len()), (12, 12));
    for (number, (right, wrong)) in right.iter().zip(&wrong).enumerate() {
        assert!(
            right.abs_diff(*wrong) < bound,
            "word {}: a right word got its tick in {right:?}, and a wrong one in {wrong:?}",
            number + 1
        );
    }
}

/// At `cordelia phrase` the words are shown numbered, in rows of four
/// with the columns lined up, so that the numbers a person writes down
/// are the numbers that the words are asked for by (decision 2026-10-04
/// §5). They are shown once, on the other screen, and are gone from the
/// terminal afterwards: the screen is cleared, with what scrolled off
/// it, before it is put away, and nothing that the command says after
/// that has the rows, or two of the words one after the other.
#[test]
fn the_words_are_shown_numbered_and_are_gone_from_the_screen_afterwards() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));

    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    let rows = rows_shown(&at.said).to_string();
    let words = words_shown(&at.said);
    let shown: Vec<&str> = words.split(' ').collect();
    assert!(
        cordelia_crypto::phrase::Phrase::parse(&words).is_ok(),
        "the words shown are a phrase"
    );
    // Three rows of four. A word is at most eight letters: each column
    // is as wide as that, its number before it, right-aligned, and
    // three spaces after it. No row ends in a space.
    let lines: Vec<&str> = rows.split("\r\n").collect();
    assert_eq!(lines.len(), 3, "{rows:?}");
    for (row, line) in lines.iter().enumerate() {
        let mut is = String::from("  ");
        for column in 0..4 {
            let number = row * 4 + column + 1;
            let word = shown[number - 1];
            match column {
                3 => is.push_str(&format!("{number:>2}. {word}")),
                _ => is.push_str(&format!("{number:>2}. {word:<8}   ")),
            }
        }
        assert_eq!(*line, is);
    }
    // What is said around them.
    assert!(
        at.said.ends_with(&format!(
            "\x1b[?1049h\x1b[H\x1b[2J\x1b[3JYour recovery phrase (shown once):\r\n\r\n{rows}\r\n\r\n\
             Write the twelve words down, in order. Keep them where only you can read them.\r\n\
             Press Enter when you have. The words are then cleared from the screen. "
        )),
        "{:?}",
        at.said
    );

    // The word at each number is the word that is asked for by it.
    at.types("");
    at.says(ASKS_THE_WORDS_BACK);
    for (typed, word) in shown.iter().enumerate() {
        at.says(&format!("  {:>2}. ", typed + 1)).types(word);
    }
    let typed_back = at.says_one_of(&["All twelve match.", "\u{2717}"]);
    assert_eq!(typed_back, 0, "{}", at.said);
    let said = at.done();

    // Shown once, on the other screen, which is cleared before it is
    // put away: and gone afterwards.
    assert_eq!(said.matches(&rows).count(), 1, "{said:?}");
    let put_away = said.find("\x1b[?1049l").expect("the screen is put away");
    assert!(
        said[..put_away].ends_with("screen. \x1b[H\x1b[2J\x1b[3J"),
        "{said:?}"
    );
    let afterwards = &said[put_away..];
    assert!(!afterwards.contains(&rows), "{afterwards:?}");
    assert_eq!(two_words_in_a_row(afterwards.as_bytes(), &shown), None);
    assert!(
        afterwards.contains(&format!(
            "{ASKS_THE_WORDS_BACK}\r\n\r\n{}\r\nAll twelve match.",
            ticks(1, 12)
        )),
        "{afterwards:?}"
    );
}

/// **After a cross, the command waits for the person to stop typing**
/// (decision 2026-10-04 §16): what is typed is dropped until nothing has
/// been typed for a second, and only then is the same number asked
/// again. A person who types the words from paper without looking goes
/// on typing after a slip, and the words they go on with are not taken
/// for the number that is asked again.
///
/// Here, at `cordelia phrase`, the third word typed back is another word
/// of the list, and the words that were shown for the fourth, fifth and
/// sixth follow it with no waiting: the fourth while the miss waits to
/// be said, and the others once it is said. One miss is spent, and not
/// three: nothing is answered, the third number is asked again no
/// sooner than a second after the last of them was typed, and the words
/// typed then, from the third on, are the phrase.
#[test]
fn a_person_who_goes_on_typing_after_a_miss_spends_one_miss_and_not_three() {
    use cordelia_core::protocol::PHRASE_QUIET_AFTER_CROSS_SECS;
    use std::time::{Duration, Instant};
    let quiet = Duration::from_secs(PHRASE_QUIET_AFTER_CROSS_SECS);
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));

    let at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    let shown: Vec<&str> = words.split(' ').collect();
    let line = |word: &str| format!("{word}\n").into_bytes();
    at.types(&shown[..2].join(" "));
    at.says("\u{2713}\r\n   3. ");
    // The slip, and the next word at once.
    at.sends(&line(another_word_than(shown[2])));
    at.sends(&line(shown[3]));
    // The miss is said: and the person types on.
    at.says("That does not match word 3. Check what you wrote, and type it again.\r\n");
    at.sends(&line(shown[4]));
    std::thread::sleep(Duration::from_millis(300));
    let last = at.sends(&line(shown[5]));
    // The third number is asked again, a second after they stopped.
    at.says("   3. ");
    let asked_again = Instant::now();
    assert!(
        asked_again.duration_since(last) >= quiet,
        "the number was asked again {:?} after the last word was typed",
        asked_again.duration_since(last)
    );
    let so_far = format!(
        "{ASKS_THE_WORDS_BACK}\r\n\r\n{}{}   3. ",
        ticks(1, 2),
        does_not_match(3)
    );
    assert!(at.said.ends_with(&so_far), "{:?}", at.said);
    // Each word from the third on, as it was shown.
    at.types(&shown[2..].join(" "));
    let typed_back = at.says_one_of(&[
        "All twelve match.",
        "Three tries did not match",
        "That does not match word",
    ]);
    assert_eq!(typed_back, 0, "{}", at.said);
    let said = at.done();
    let all = format!(
        "{ASKS_THE_WORDS_BACK}\r\n\r\n{}{}{}\r\nAll twelve match.\r\n",
        ticks(1, 2),
        does_not_match(3),
        ticks(3, 12),
    );
    assert!(said.contains(&all), "{said:?}");
    assert_eq!(look(&laptop)["change"], 1);
}

/// The same where a phrase is proved, after the one cross that is said
/// there, which is for a word that is not in the list and says nothing
/// of right or wrong (decision 2026-10-04 §16). Here at `cordelia
/// renew` the third word is no word of the list, and the device's own
/// fourth, fifth and sixth words follow the cross with no waiting. None
/// is taken for the third: it is asked again no sooner than a second
/// after the last of them was typed, and the words typed then, from the
/// third on, are the phrase.
#[test]
fn where_a_phrase_is_proved_what_is_typed_on_after_a_cross_is_not_taken_for_the_word() {
    use cordelia_core::protocol::PHRASE_QUIET_AFTER_CROSS_SECS;
    use std::time::{Duration, Instant};
    let quiet = Duration::from_secs(PHRASE_QUIET_AFTER_CROSS_SECS);
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    let own: Vec<&str> = words.split(' ').collect();
    let line = |word: &str| format!("{word}\n").into_bytes();

    let mut at = renews_to_the_phrase(&laptop);
    at.types(&own[..2].join(" "));
    at.says("\u{2713}\r\n   3. ");
    at.sends(&line("xyzzy"));
    at.says("That is not a word from the list. Type word 3 again.\r\n");
    at.sends(&line(own[3]));
    std::thread::sleep(Duration::from_millis(300));
    at.sends(&line(own[4]));
    std::thread::sleep(Duration::from_millis(300));
    let last = at.sends(&line(own[5]));
    at.says("   3. ");
    let asked_again = Instant::now();
    assert!(
        asked_again.duration_since(last) >= quiet,
        "the number was asked again {:?} after the last word was typed",
        asked_again.duration_since(last)
    );
    let so_far = format!(
        "{ASKS_THE_PHRASE}\r\n\r\n{}{}   3. ",
        ticks(1, 2),
        not_in_the_list(3)
    );
    assert!(at.said.ends_with(&so_far), "{:?}", at.said);
    at.types(&own[2..].join(" "));
    let judged = at.says_one_of(&[
        "The change is made (change 2).",
        "It was mistyped",
        "it is not the one that this device follows",
        "Type word",
    ]);
    assert_eq!(judged, 0, "{}", at.said);
    let all = format!(
        "{ASKS_THE_PHRASE}\r\n\r\n{}{}{}\r\nThe change is made (change 2).",
        ticks(1, 2),
        not_in_the_list(3),
        ticks(3, 12)
    );
    assert!(at.said.contains(&all), "{:?}", at.said);
    drop(at);
    assert_eq!(look(&laptop)["change"], 2);
}

/// **A prompt for the phrase ends with the line that the twelfth word
/// is on** (decision 2026-10-04 §16): once that word is taken the
/// command reads on, with what is typed still hidden, to the Enter, and
/// drops whatever else is on the line. So a thirteenth word (a word
/// typed twice, or one split into two words of the list) is never
/// shown, and never reaches the shell. At both prompts:
///
/// - thirteen words on one line: twelve ticks, and nothing else;
/// - twelve words and a space, with no Enter: the twelfth has its tick,
///   and the command waits for the line's end, saying nothing more. A
///   thirteenth word typed then, with its Enter, is not shown.
///
/// Each time the terminal is read once the command has ended, as a
/// shell would read it: nothing is there.
#[test]
fn the_prompt_ends_with_the_line_that_the_twelfth_word_is_on() {
    use std::time::Duration;
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    // The twelve words and a space are sent, and no Enter: the twelfth
    // gets its tick, and nothing follows it while the line is not ended.
    let twelve_and_a_space = |at: &mut AtTerminal, words: &str| {
        at.sends(format!("{words} ").as_bytes());
        at.says(&ticks(12, 12));
        let so_far = at.hears_for(Duration::from_millis(700)).to_string();
        assert!(
            so_far.ends_with(&ticks(1, 12)),
            "the command did not wait for the end of the line:\n{so_far:?}"
        );
    };

    // The words typed back. Thirteen on one line.
    let at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    at.sends(format!("{words} thirteenth\n").as_bytes());
    let (made, said, left) = at.ends_and_leaves();
    assert!(made, "{said}");
    let typed_back = format!(
        "{ASKS_THE_WORDS_BACK}\r\n\r\n{}\r\nAll twelve match.\r\n",
        ticks(1, 12)
    );
    assert!(said.contains(&typed_back), "{said:?}");
    assert!(!said.contains("thirteenth"), "{said}");
    assert_eq!(left, "", "after thirteen words on a line");
    // A thirteenth after the twelfth's space.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Type yes to go on").types("yes");
    let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
    twelve_and_a_space(&mut at, &words);
    at.types("thirteenth");
    let (made, said, left) = at.ends_and_leaves();
    assert!(made, "{said}");
    assert!(said.contains(&typed_back), "{said:?}");
    assert!(!said.contains("thirteenth"), "{said}");
    assert_eq!(left, "", "after a thirteenth word on the twelfth's line");
    assert_eq!(look(&laptop)["change"], 1);

    // Where a phrase is proved. Thirteen on one line.
    let mut at = renews_to_the_phrase(&laptop);
    at.sends(format!("{words} thirteenth\n").as_bytes());
    let (made, said, left) = at.ends_and_leaves();
    assert!(made, "{said}");
    let typed = |change: u64| {
        format!(
            "{ASKS_THE_PHRASE}\r\n\r\n{}\r\nThe change is made (change {change}).",
            ticks(1, 12)
        )
    };
    assert!(said.contains(&typed(2)), "{said:?}");
    assert!(!said.contains("thirteenth"), "{said}");
    assert_eq!(left, "", "after thirteen words on a line");
    // A thirteenth after the twelfth's space: the phrase is not judged
    // before the line is ended.
    let mut at = renews_to_the_phrase(&laptop);
    twelve_and_a_space(&mut at, &words);
    at.types("thirteenth");
    let (made, said, left) = at.ends_and_leaves();
    assert!(made, "{said}");
    assert!(said.contains(&typed(3)), "{said:?}");
    assert!(!said.contains("thirteenth"), "{said}");
    assert_eq!(left, "", "after a thirteenth word on the twelfth's line");
    assert_eq!(look(&laptop)["change"], 3);
}

/// **Every way out of a prompt for the phrase drops what was typed
/// ahead** (decision 2026-10-04 §16), before the terminal is put back:
/// the rest of a line that was pasted is words of a phrase, and is not
/// handed to the shell. Here the terminal is read once the command has
/// ended, as a shell would read it, and nothing is there:
///
/// - after Ctrl-C in the middle of a pasted line;
/// - after a word that is too long, which the command says is a word;
/// - where the input is ended, with a line typed after that.
#[test]
fn every_way_out_of_the_prompt_drops_what_was_typed_ahead() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    // `cordelia phrase`, run to where the words are typed back; then
    // `typed` is sent at once, as a line that is pasted is. What the
    // command said from the line that asks, and what it left.
    let typed_back = |typed: &dyn Fn(&[&str]) -> Vec<u8>| -> (String, String) {
        let at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
        let (mut at, words) = makes_a_phrase_to_the_typing_back(at);
        let shown: Vec<&str> = words.split(' ').collect();
        at.says("   1. ");
        at.sends(&typed(&shown));
        let (success, said, left) = at.ends_and_leaves();
        assert!(!success, "{said}");
        let asked = said
            .find(ASKS_THE_WORDS_BACK)
            .expect("the words are asked for");
        (said[asked..].to_string(), left)
    };

    // Ctrl-C after the second word of a pasted line.
    let (said, left) = typed_back(&|shown| {
        format!("{} {} \x03{}\n", shown[0], shown[1], shown[2..].join(" ")).into_bytes()
    });
    assert_eq!(
        said,
        format!(
            "{ASKS_THE_WORDS_BACK}\r\n\r\n{}   3. \r\nError: Interrupted: the terminal is as it \
             was, and nothing was made.\r\n",
            ticks(1, 2)
        )
    );
    assert_eq!(left, "", "after Ctrl-C");

    // A word that is longer than any line this command asks for, and a
    // line after it.
    let (said, left) = typed_back(&|shown| {
        format!(
            "{} {}\n{}\n",
            shown[0],
            "a".repeat(2000),
            shown[2..].join(" ")
        )
        .into_bytes()
    });
    assert_eq!(
        said,
        format!(
            "{ASKS_THE_WORDS_BACK}\r\n\r\n{}   2. \r\nError: that word is longer than anything \
             this command asks for\r\n",
            ticks(1, 1)
        )
    );
    assert_eq!(left, "", "after a word that is too long");

    // The input is ended before anything is typed, and a line is typed
    // after that.
    let (said, left) = typed_back(&|shown| format!("\x04{}\n", shown.join(" ")).into_bytes());
    assert!(
        said.starts_with(&format!(
            "{ASKS_THE_WORDS_BACK}\r\n\r\n   1. \r\nError: nothing was typed"
        )),
        "{said:?}"
    );
    assert_eq!(left, "", "after the end of the input");
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");
}

// ── A chain of two, at a removal ─────────────────────────────────────

/// A chain of two at a removal (decision 2026-10-04 §6, §16). The desktop
/// makes the phrase, and adds the laptop and the tablet; the tablet adds
/// the phone. On the laptop, which the last change does not list, the
/// desktop is removed.
///
/// - The laptop is shown its own addition, and its listing is confirmed
///   by a typed answer.
/// - The tablet, which the device being removed added, is asked about
///   before the phone, which the tablet added.
/// - No answer is suggested for either: pressing Enter answers nothing,
///   and where the input ends at a question the command is refused, with
///   nothing made.
#[test]
fn a_chain_of_two_is_asked_about_in_its_order_and_no_answer_is_suggested() {
    let relay = relay_started();
    let desktop = device_started("desktop", &relay);
    let laptop = device_started("laptop", &relay);
    let tablet = device_started("tablet", &relay);
    let phone = device_started("phone", &relay);
    let all = [&relay, &desktop, &laptop, &tablet, &phone];
    let words = makes_a_phrase(&desktop, "desktop");
    for (adder, new) in [(&desktop, &laptop), (&desktop, &tablet), (&tablet, &phone)] {
        adds(adder, new, new.name);
        has_applied(new, 1, &all);
    }
    wait_for("the laptop counts each device added", &all, 120, || {
        let seen = look(&laptop);
        let counted = seen["added"]
            .as_array()?
            .iter()
            .filter(|added| added["counted"] == true)
            .count();
        (counted == 3).then_some(())
    });
    let desktop_key = key_of(&desktop);

    // The input ends at the first question: nothing is made.
    let mut at = laptop.at_terminal(&["remove-device", &desktop_key]);
    at.says("Type `stays` to list this device").types("stays");
    at.says("No answer is suggested for any of them: each is typed.");
    at.says("Type `stays` or `removed`").ends_the_input();
    let said = at.refused_within(std::time::Duration::from_secs(60));
    assert!(
        said.contains("the input ended before an answer was typed. Nothing was made."),
        "{said}"
    );
    assert!(!said.contains("Make this change?"), "{said}");
    assert_eq!(look(&laptop)["change"], 1);

    let mut at = laptop.at_terminal(&["remove-device", &desktop_key]);
    at.says("To be removed:");
    at.says("This device is not in the last change: it was added since")
        .says("Type `stays` to list this device")
        .types("stays");
    at.says("No answer is suggested for any of them: each is typed.");
    // The tablet first: the device that is being removed added it.
    at.says("tablet")
        .says("added since the last change, from")
        .says("desktop")
        .says("It was added by the device that is being removed");
    at.says("Type `stays` or `removed`").types("");
    at.says("That is none of the answers. No answer is suggested: type one.");
    at.says("Type `stays` or `removed`").types("removed");
    // Then the phone, which the tablet added: Enter keeps it no more
    // than it keeps the tablet.
    at.says("phone")
        .says("added since the last change, from")
        .says("tablet");
    at.says("Type `stays` or `removed`").types("");
    at.says("That is none of the answers. No answer is suggested: type one.");
    at.says("Type `stays` or `removed`").types("removed");
    at.says("The change that the recovery phrase will sign (change 2):");
    at.says("devices (1):");
    at.says("(this device)");
    at.says("removed keys (3):");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 2).");
    let said = at.done();
    // Each of the two was asked about, and asked again where Enter was
    // pressed: no third device was.
    assert_eq!(said.matches("added since the last change, from").count(), 4);
    let seen = look(&laptop);
    assert_eq!(seen["change"], 2, "{seen}");
    assert_eq!(seen["devices"].as_array().unwrap().len(), 1, "{seen}");
    assert_eq!(seen["devices"][0]["key"], key_of(&laptop), "{seen}");
    assert_eq!(seen["removed"].as_array().unwrap().len(), 3, "{seen}");
}

// ── A word that outlives a change ────────────────────────────────────

/// A device's word that it left outlives the next change, for as long as
/// its key is listed and nobody has cleared it (decision 2026-10-04
/// §5.2, §7.1). The tablet leaves, and the laptop and the desktop are
/// told. The laptop is then off while the desktop makes a change that
/// still lists the tablet: its prompt asks about the tablet as a device
/// that has said that it left. Afterwards the desktop still shows that
/// the tablet left, and so does the laptop once it has applied the
/// change, though the word itself is in a channel that neither reads
/// again. At the change after that the tablet, which the last change
/// lists, is asked about as that, with no answer suggested.
#[test]
fn a_devices_word_that_it_left_outlives_the_next_change() {
    let relay = relay_started();
    let mut laptop = device_started("laptop", &relay);
    let tablet = device_started("tablet", &relay);
    let desktop = device_started("desktop", &relay);
    let words = makes_a_phrase(&laptop, "laptop");
    for new in [&tablet, &desktop] {
        adds(&laptop, new, new.name);
        has_applied(new, 1, &[&relay, &laptop, &tablet, &desktop]);
    }

    // The tablet leaves, by a person's own command there.
    let mut at = tablet.at_terminal(&["phrase", "--name", "tablet"]);
    at.says("This device leaves the ")
        .says("Type yes to go on")
        .types("yes");
    at.says("Press Enter when you have");
    let its_own = words_shown(&at.said);
    at.types("");
    at.says("Now type the words back").types(&its_own);
    at.done();
    let told_it_left = |node: &Node| -> Option<()> {
        notices(node)
            .iter()
            .any(|says| says.contains("tablet") && says.contains("left, and started again"))
            .then_some(())
    };
    wait_for(
        "the laptop and the desktop are told that the tablet left",
        &[&relay, &laptop, &tablet, &desktop],
        120,
        || told_it_left(&laptop).and(told_it_left(&desktop)),
    );

    // The laptop is off while the desktop makes a change. The desktop
    // was added since the last change, and so was the tablet: the tablet
    // is asked about, and that it has said it left is said.
    laptop.stop();
    let mut at = desktop.at_terminal(&["renew"]);
    at.says("Type `stays` to list this device").types("stays");
    at.says("tablet")
        .says("added since the last change, from")
        .says("It has said that it left, and started again under another phrase");
    at.says("Type `stays` or `removed`").types("stays");
    at.says("devices (3):");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 2).");
    drop(at);
    assert_eq!(look(&desktop)["change"], 2);
    // The notice is still on the desktop afterwards.
    assert!(told_it_left(&desktop).is_some(), "{}", look(&desktop));

    // The laptop comes back, and applies the change: the word is still
    // shown there.
    laptop.start();
    wait_for("the laptop is up again", &[&laptop], 30, || {
        healthy(&laptop)
    });
    has_applied(&laptop, 2, &[&relay, &laptop, &desktop]);
    assert!(told_it_left(&laptop).is_some(), "{}", look(&laptop));
    for node in [&laptop, &desktop] {
        let seen = look(node);
        let listed = seen["devices"].as_array().unwrap();
        let of_the_tablet = listed
            .iter()
            .find(|device| device["label"] == "tablet")
            .unwrap_or_else(|| panic!("the tablet is not listed: {seen}"));
        assert_eq!(of_the_tablet["left"], true, "{}: {seen}", node.name);
    }

    // At the next change the tablet is a device of the last change, and
    // is asked about as one that has said that it left: no answer is
    // suggested.
    let mut at = desktop.at_terminal(&["renew"]);
    at.says("tablet")
        .says("a device of the last change. It has said that it left");
    at.says("Type `stays` or `removed`").types("");
    at.says("That is none of the answers. No answer is suggested: type one.");
    at.says("Type `stays` or `removed`").types("removed");
    at.says("devices (2):");
    at.says("removed keys (1):");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 3).");
    drop(at);
    has_applied(&laptop, 3, &[&relay, &laptop, &desktop]);
    // The word goes with the device.
    for node in [&laptop, &desktop] {
        assert!(told_it_left(node).is_none(), "{}", look(node));
    }
}

// ── The process that holds the phrase ────────────────────────────────

/// The command line that the system says process `pid` runs.
fn command_line(pid: u32) -> String {
    let out = std::process::Command::new("ps")
        .args(["-o", "args=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Whether the system says that process `pid` cannot be dumped or traced
/// by its user, and the most that it may leave as a core file. What the
/// system keeps of a process that can be dumped belongs to its user, as
/// what it keeps of this test does; of one that cannot, it does not.
#[cfg(target_os = "linux")]
fn guarded(pid: u32) -> (bool, String) {
    use std::os::unix::fs::MetadataExt;
    let owner = |pid: &str| {
        std::fs::metadata(format!("/proc/{pid}/stat"))
            .unwrap()
            .uid()
    };
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .unwrap_or_default();
    let core: Vec<&str> = core.split_whitespace().skip(4).take(2).collect();
    (owner(&pid.to_string()) != owner("self"), core.join(" "))
}

/// A process that makes or reads a recovery phrase cannot be dumped or
/// traced, from before it reads anything, and the wait that follows a
/// change runs in a new image of the program, which never held the phrase
/// (decision 2026-10-04 §16). Read back from the system: the flag and the
/// size of a core file, for `cordelia phrase` and `cordelia renew`, and
/// not for a command that reads no phrase; and the command line of the
/// process that waits, which is another than the one that signed, in the
/// same process.
#[test]
fn a_process_that_holds_the_phrase_cannot_be_dumped_and_the_wait_is_in_another_image() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);

    // The control: a command that reads no phrase is as any process is.
    let other = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let other = cordelia_crypto::bech32::encode_public_key(&other.public_key()).unwrap();
    let mut at = laptop.at_terminal(&["accept", &other]);
    at.says("Type yes to go on");
    #[cfg(target_os = "linux")]
    assert!(!guarded(at.pid()).0, "a command that reads no phrase");
    drop(at);

    // `cordelia phrase`, while the words are on the screen.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    #[cfg(target_os = "linux")]
    assert_eq!(guarded(at.pid()), (true, "0 0".to_string()));
    let words = words_shown(&at.said);
    at.types("");
    at.says("Now type the words back").types(&words);
    at.done();

    // `cordelia renew`, from before its yes.
    let mut at = laptop.at_terminal(&["renew"]);
    at.says("Make this change?").says("Type yes to go on");
    let pid = at.pid();
    let signs = command_line(pid);
    assert!(signs.ends_with(" renew"), "{signs}");
    #[cfg(target_os = "linux")]
    assert_eq!(guarded(pid), (true, "0 0".to_string()));
    at.types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The change is made (change 2).");

    // The wait: the same process, and another image of the program in
    // it, which was given the change's number and nothing else.
    let began = std::time::Instant::now();
    let waits = loop {
        let line = command_line(pid);
        if line.contains("change-made") || began.elapsed() > std::time::Duration::from_secs(20) {
            break line;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert!(
        waits.ends_with(" change-made 2"),
        "{waits:?} after {signs:?}"
    );
    assert!(!waits.contains("renew"), "{waits}");
    // A new image can be dumped as any process can: it holds no phrase.
    // (It may have ended by now: then there is nothing to read.)
    #[cfg(target_os = "linux")]
    if std::path::Path::new(&format!("/proc/{pid}/stat")).exists() {
        let unguarded = !guarded(pid).0;
        if command_line(pid).contains("change-made") {
            assert!(unguarded, "the image that waits");
        }
    }
    at.says("This machine may be closed only when");
    let said = at.done();
    assert!(said.contains("this machine may be closed."), "{said}");
}

// ── What answers at the node's address ───────────────────────────────

/// A stand-in at a port of this machine for the node at `port`: each
/// request is passed on to the node, and the node's answer is handed back
/// as `changed` leaves it. It is what a program that answers at the
/// node's address could say to a command.
struct Answers {
    port: u16,
    /// Each request that a command made here, in their order.
    asked: std::sync::Arc<std::sync::Mutex<Vec<Asked>>>,
}

/// A request that a command made: its path, and its body.
type Asked = (String, Vec<u8>);

impl Answers {
    fn in_the_place_of(
        node: &Node,
        changed: impl Fn(&str, &mut Value) + Send + Sync + 'static,
    ) -> Self {
        Self::losing(node, changed, |_| None)
    }

    /// [`Self::in_the_place_of`], where the answer to some requests is
    /// lost: `lost` says of a request's path whether its answer is lost
    /// once the node has done what was asked (`Some(true)`), or the
    /// request is lost before it reaches the node (`Some(false)`). The
    /// command is then answered nothing, and its connection is closed.
    fn losing(
        node: &Node,
        changed: impl Fn(&str, &mut Value) + Send + Sync + 'static,
        lost: impl Fn(&str) -> Option<bool> + Send + Sync + 'static,
    ) -> Self {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap().port();
        let (node_port, token) = (node.http, node.token());
        let changed = std::sync::Arc::new(changed);
        let lost = std::sync::Arc::new(lost);
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = asked.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let (changed, token) = (changed.clone(), token.clone());
                let (lost, kept) = (lost.clone(), kept.clone());
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }
                    let mut parts = line.split_whitespace();
                    let method = parts.next().unwrap_or_default().to_string();
                    let path = parts.next().unwrap_or_default().to_string();
                    let mut length = 0usize;
                    loop {
                        let mut header = String::new();
                        let read = reader.read_line(&mut header).unwrap_or(0);
                        if read == 0 || header == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = header.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            length = value.trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0u8; length];
                    if reader.read_exact(&mut body).is_err() {
                        return;
                    }
                    kept.lock().unwrap().push((path.clone(), body.clone()));
                    let loses = lost(&path);
                    if loses == Some(false) {
                        return;
                    }
                    let url = format!("http://127.0.0.1:{node_port}{path}");
                    let agent: ureq::Agent = ureq::Agent::config_builder()
                        .proxy(None)
                        .http_status_as_error(false)
                        .build()
                        .into();
                    let auth = format!("Bearer {token}");
                    let answered = match method.as_str() {
                        "GET" => agent.get(&url).header("Authorization", &auth).call(),
                        _ => agent
                            .post(&url)
                            .header("Authorization", &auth)
                            .header("Content-Type", "application/json")
                            .send(&body[..]),
                    };
                    let Ok(mut answered) = answered else {
                        return;
                    };
                    if loses == Some(true) {
                        return;
                    }
                    let status = answered.status().as_u16();
                    let mut answer: Value = answered.body_mut().read_json().unwrap_or(Value::Null);
                    changed(&path, &mut answer);
                    let out = answer.to_string();
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{out}",
                        out.len()
                    );
                });
            }
        });
        Self { port: at, asked }
    }

    /// Every request that a command has made here: its path, and its
    /// body.
    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }
}

/// No word of a new phrase reaches the node (decision 2026-10-04 §5).
/// `cordelia phrase` makes the words in its own process, and hands the
/// node the change entry of the first statement, the statement key, and
/// where the device stood: those three, and nothing else. Nothing that
/// only the phrase gives is in what the node was asked, in its log, or
/// in any file of its directory afterwards, and nor are three of the
/// words in a row. (One word of a new phrase may be a word that the
/// program says anyway: the words are from a list of common ones.)
#[test]
fn no_word_of_a_new_phrase_reaches_the_node() {
    use cordelia_crypto::entry::Entry;
    use cordelia_crypto::phrase::Phrase;
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));

    let through = Answers::in_the_place_of(&laptop, |_, _| {});
    let mut at = laptop.at_terminal_through(through.port, &["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    let words = words_shown(&at.said);
    at.types("");
    at.says("Now type the words back").types(&words);
    at.done();
    assert_eq!(look(&laptop)["change"], 1);
    let phrase = Phrase::parse(&words).unwrap();

    // What the command asked of the node to make the phrase: three
    // things, each of a form that holds no word.
    let asked = through.asked();
    let made: Vec<&Asked> = asked
        .iter()
        .filter(|(path, _)| path == "/api/v1/phrase/make")
        .collect();
    assert_eq!(
        made.len(),
        1,
        "{:?}",
        asked.iter().map(|a| &a.0).collect::<Vec<_>>()
    );
    let body: Value = serde_json::from_slice(&made[0].1).unwrap();
    let mut fields: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["entry", "from", "statement_key"]);
    assert_eq!(body["from"], "no_phrase");
    // The statement key, which every device that follows the phrase is
    // given.
    assert_eq!(
        body["statement_key"],
        hex::encode(*phrase.statement_key().unwrap())
    );
    // The change entry: what every relay is shown. Its author is the
    // phrase's public key, and its content is sealed.
    let entry = Entry::from_wire(&hex::decode(text(&body, "entry")).unwrap())
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(entry.author, phrase.public_key().unwrap());

    // What only the phrase gives, and no device is given.
    let only_the_phrases: Vec<[u8; 32]> = vec![
        *phrase.signing_key().unwrap().seed(),
        *phrase.channel_secret().unwrap(),
        *phrase.seal_key().unwrap(),
    ];
    let mut searched: Vec<(String, Vec<u8>)> = asked
        .iter()
        .map(|(path, body)| (format!("what the node was asked at {path}"), body.clone()))
        .collect();
    searched.push((
        "the node's log".into(),
        std::fs::read(laptop.log()).unwrap(),
    ));
    for (path, bytes) in files_under(&laptop.data_dir()) {
        searched.push((path.display().to_string(), bytes));
    }
    let in_a_row: Vec<&str> = words.split(' ').collect();
    for (what, bytes) in &searched {
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);
        for secret in &only_the_phrases {
            assert!(!has(secret), "what only the phrase gives is in {what}");
            assert!(
                !has(hex::encode(secret).as_bytes()),
                "what only the phrase gives is in {what}, in hex"
            );
        }
        // Every run of letters, in its order.
        let said: Vec<String> = bytes
            .split(|byte| !byte.is_ascii_alphabetic())
            .filter(|word| !word.is_empty())
            .map(|word| String::from_utf8_lossy(word).to_lowercase())
            .collect();
        for three in in_a_row.windows(3) {
            assert!(
                !said.windows(3).any(|run| run == three),
                "three words of the phrase are in {what}"
            );
        }
    }
    // The search reads what is there: the device's label, which the
    // phrase's first statement lists, is in the node's database.
    assert!(searched.len() > 4, "{}", searched.len());
    let in_the_database = searched
        .iter()
        .filter(|(what, _)| what.contains("cordelia.db"))
        .any(|(_, bytes)| words_in(bytes).contains("laptop"));
    assert!(in_the_database, "the search reads the node's database");
}

/// What a command shows as this device, signs for and prints is its own
/// reading of the key file, never the node's word (decision 2026-10-04
/// §16). Whatever answers at the node's address names a key of its own
/// as this device, with a record of an addition for it, which the node
/// itself signed: any program that holds the node's token can have it
/// sign one. `cordelia renew` refuses before it asks anything, and the
/// phrase is never asked for; `cordelia phrase` shows no word; and
/// `cordelia add-device` asks no yes and prints no key to type.
#[test]
fn a_command_refuses_what_names_another_key_as_this_device() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    makes_a_phrase(&laptop, "laptop");

    // A key of the stand-in's own, and the record that adds it.
    let its_own = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let its_key = cordelia_crypto::bech32::encode_public_key(&its_own.public_key()).unwrap();
    laptop.post(
        "/api/v1/devices/add",
        json!({ "device": its_key, "label": "laptop", "would": "add" }),
    );
    let named = its_key.clone();
    let stand_in = Answers::in_the_place_of(&laptop, move |_, answer| {
        if answer.get("this_device").is_some() {
            answer["this_device"] = named.clone().into();
        }
    });
    // The control: a stand-in that changes nothing is a way to the node,
    // and through it the record is among what a change asks about.
    let passes_on = Answers::in_the_place_of(&laptop, |_, _| {});
    let said = laptop
        .at_terminal_through(passes_on.port, &["devices"])
        .done();
    assert!(said.contains("Added since:"), "{said}");
    let mut at = laptop.at_terminal_through(passes_on.port, &["renew"]);
    at.says("added since the last change")
        .says("Type `stays` or `removed`");
    drop(at);

    // A command that is refused here asks nothing first: it ends by
    // itself, and is not waited for where it asks.
    let soon = std::time::Duration::from_secs(60);
    let refusal = "does not name this device's key";
    let said = laptop
        .at_terminal_through(stand_in.port, &["renew"])
        .refused_within(soon);
    assert!(said.contains(refusal), "{said}");
    for never in [
        "Type your recovery phrase, one word at a time",
        "Make this change?",
        "Type `stays`",
        "(this device)",
    ] {
        assert!(!said.contains(never), "{never:?} in:\n{said}");
    }

    let said = laptop
        .at_terminal_through(stand_in.port, &["phrase", "--name", "laptop"])
        .refused_within(soon);
    assert!(said.contains(refusal), "{said}");
    assert!(!said.contains("shown once"), "{said}");

    let other = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let other = cordelia_crypto::bech32::encode_public_key(&other.public_key()).unwrap();
    let said = laptop
        .at_terminal_through(stand_in.port, &["add-device", &other, "--name", "desktop"])
        .refused_within(soon);
    assert!(said.contains(refusal), "{said}");
    assert!(!said.contains("Type yes to go on"), "{said}");
    assert!(!said.contains("cordelia accept"), "{said}");
    // And `cordelia devices`, which only shows.
    let said = laptop
        .at_terminal_through(stand_in.port, &["devices"])
        .refused_within(soon);
    assert!(said.contains(refusal), "{said}");

    // Where only the answer to the adding itself names another key, the
    // yes was asked by then: the command prints no key to type on the
    // other device, neither that one nor its own.
    let named = its_key.clone();
    let at_the_add = Answers::in_the_place_of(&laptop, move |path, answer| {
        if path == "/api/v1/devices/add" && answer.get("this_device").is_some() {
            answer["this_device"] = named.clone().into();
        }
    });
    let mut at = laptop.at_terminal_through(
        at_the_add.port,
        &["add-device", &other, "--name", "desktop"],
    );
    at.says("Type yes to go on").types("yes");
    let said = at.refused_within(soon);
    assert!(said.contains(refusal), "{said}");
    assert!(!said.contains("cordelia accept"), "{said}");

    // Nothing was made of any of it: the device is where it was.
    let seen = look(&laptop);
    assert_eq!(seen["change"], 1, "{seen}");
    assert_eq!(seen["this_device"], key_of(&laptop), "{seen}");
}

/// Where a command cannot learn whether the node made what it was
/// handed, because the answer was lost, it asks the node again before it
/// says anything (decision 2026-10-04 §16). A phrase whose answer was
/// lost after the node made it is said to be made; so is a change. Where
/// the node still does not say that it made a new phrase, the command
/// says that it is not known, and that the words are to be KEPT until
/// `cordelia devices` shows which phrase the device follows: it does not
/// say that nothing was made.
#[test]
fn a_command_whose_answer_was_lost_asks_the_node_again_before_it_says_anything() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let phrase_words = |node: &Node| text(&look(node), "phrase_words").to_string();

    // The request for a new phrase never reaches the node: the node
    // does not follow it, and the command cannot know that it never
    // will.
    let never = Answers::losing(
        &laptop,
        |_, _| {},
        |path| (path == "/api/v1/phrase/make").then_some(false),
    );
    let mut at = laptop.at_terminal_through(never.port, &["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    let words = words_shown(&at.said);
    at.types("");
    at.says("Now type the words back").types(&words);
    at.says("The node's answer was lost. Asking it again...");
    let said = at.refused();
    assert!(
        said.contains("it is not known whether the node made the new phrase"),
        "{said}"
    );
    assert!(
        said.contains("KEEP the twelve words until `cordelia devices` shows"),
        "{said}"
    );
    assert!(!said.contains("do not keep them"), "{said}");
    assert!(!said.contains("Nothing was made"), "{said}");
    // It names the words that the new phrase's key is told by.
    let key = cordelia_crypto::phrase::Phrase::parse(&words)
        .unwrap()
        .public_key()
        .unwrap();
    let told_by = cordelia_crypto::fingerprint::shown(&key);
    assert!(
        said.contains(&format!("shown there as ({told_by})")),
        "{said}"
    );
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");

    // The answer is lost once the node has made the phrase: the command
    // asks again, and says that it is made.
    let after = Answers::losing(
        &laptop,
        |_, _| {},
        |path| (path == "/api/v1/phrase/make").then_some(true),
    );
    let mut at = laptop.at_terminal_through(after.port, &["phrase", "--name", "laptop"]);
    at.says("Press Enter when you have");
    let words = words_shown(&at.said);
    at.types("");
    at.says("Now type the words back").types(&words);
    at.says("The node's answer was lost. Asking it again...");
    let said = at.done();
    assert!(said.contains("follows the new recovery phrase"), "{said}");
    assert!(!said.contains("it is not known"), "{said}");
    let key = cordelia_crypto::phrase::Phrase::parse(&words)
        .unwrap()
        .public_key()
        .unwrap();
    assert_eq!(
        phrase_words(&laptop),
        cordelia_crypto::fingerprint::shown(&key)
    );
    // `cordelia devices` shows which phrase it is.
    let listed = laptop.cli(&["devices"]);
    assert!(
        listed.contains(&format!(
            "The recovery phrase it follows: ({}).",
            phrase_words(&laptop)
        )),
        "{listed}"
    );

    // A change whose answer is lost once the node has made it.
    let after = Answers::losing(
        &laptop,
        |_, _| {},
        |path| (path == "/api/v1/change/make").then_some(true),
    );
    let mut at = laptop.at_terminal_through(after.port, &["renew"]);
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The node's answer was lost. Asking it again...");
    at.says("The change is made (change 2).");
    drop(at);
    assert_eq!(look(&laptop)["change"], 2);

    // And one whose request never reached the node: it is not known,
    // and it is not to be made again until `cordelia devices` shows.
    let never = Answers::losing(
        &laptop,
        |_, _| {},
        |path| (path == "/api/v1/change/make").then_some(false),
    );
    let mut at = laptop.at_terminal_through(never.port, &["renew"]);
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("Type your recovery phrase, one word at a time")
        .types(&words);
    at.says("The node's answer was lost. Asking it again...");
    let said = at.refused();
    assert!(
        said.contains("it is not known whether the node made the change"),
        "{said}"
    );
    assert!(said.contains("Do not make it again"), "{said}");
    assert!(!said.contains("Nothing was made"), "{said}");
    assert_eq!(look(&laptop)["change"], 2);
}

// ── A node of another version ────────────────────────────────────────

/// A command that changes anything is refused where the node's version
/// could not be learned, and sends the node nothing (decision 2026-10-04
/// §10.1, rule 6): here the node's status is answered by nobody. Turning
/// sync off is sent all the same, and what only shows is answered.
#[test]
fn a_command_that_changes_anything_refuses_a_node_whose_version_it_cannot_learn() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    let claude = laptop.home().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    laptop.cli(&["sync", "claude", "--dir", claude.to_str().unwrap()]);
    let silent = Answers::losing(
        &laptop,
        |_, _| {},
        |path| (path == "/api/v1/status").then_some(false),
    );
    let other = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let other = cordelia_crypto::bech32::encode_public_key(&other.public_key()).unwrap();
    let home = laptop.home();
    let folder = home.to_str().unwrap();
    let soon = std::time::Duration::from_secs(60);

    let changes: [&[&str]; 12] = [
        &["sync", "claude"],
        &["sync", "map", folder, "notes"],
        &["sync", "home", "off"],
        &["restore", "an-id"],
        &["history", "drop", "--all"],
        &["init", "--new-key"],
        &["phrase", "--name", "laptop"],
        &["add-device", &other],
        &["accept", &other],
        &["devices", "--clear"],
        &["remove-device", &other],
        &["renew"],
    ];
    for args in changes {
        let before = silent.asked().len();
        let said = laptop
            .at_terminal_through(silent.port, args)
            .refused_within(soon);
        assert!(
            said.contains("The running node's version could not be learned."),
            "{args:?}: {said}"
        );
        assert!(said.contains("nothing was done."), "{args:?}: {said}");
        assert!(
            said.contains("cannot reach the local node at"),
            "{args:?}: {said}"
        );
        let asked = silent.asked();
        assert!(asked.len() > before, "{args:?} did not ask the node");
        for (path, _) in &asked[before..] {
            assert_eq!(path, "/api/v1/status", "{args:?} asked the node for more");
        }
    }
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");
    let settings = laptop.post("/api/v1/sync/status", json!({}));
    assert_eq!(settings["enabled"], true, "{settings}");
    assert_eq!(settings["mappings"], json!([]), "{settings}");

    // What only shows is answered, and turning sync off is sent.
    let said = laptop.at_terminal_through(silent.port, &["devices"]).done();
    assert!(said.contains("This device: "), "{said}");
    let said = laptop
        .at_terminal_through(silent.port, &["sync", "off"])
        .done();
    assert!(said.contains("Sync is off."), "{said}");
    let settings = laptop.post("/api/v1/sync/status", json!({}));
    assert_eq!(settings["enabled"], false, "{settings}");
}

/// A command that makes or asks for a recovery phrase asks how the node
/// stands first, and shows no word and asks for none where the node is
/// held up (decision 2026-10-04 §10.1): it says why the node is, and has
/// asked the node for nothing but how it stands. Here the node is behind
/// a stand-in that says it is held up for its first start.
#[test]
fn a_command_of_a_phrase_shows_no_word_where_the_node_is_held_up() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    let why = "the first start on this version is not done: no room for the copy";
    let held = Answers::in_the_place_of(&laptop, move |path, answer| {
        if path == "/api/v1/status" {
            answer["held"] = json!({ "by": "first_start", "why": why });
        }
    });
    let other = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let other = cordelia_crypto::bech32::encode_public_key(&other.public_key()).unwrap();
    let soon = std::time::Duration::from_secs(60);
    let of_a_phrase: [&[&str]; 4] = [
        &["phrase", "--name", "laptop"],
        &["remove-device", &other],
        &["renew"],
        &["settle"],
    ];
    for args in of_a_phrase {
        let before = held.asked().len();
        let said = laptop
            .at_terminal_through(held.port, args)
            .refused_within(soon);
        assert!(said.contains(why), "{args:?}: {said}");
        assert!(
            said.contains("no recovery phrase was shown or asked for, and nothing was done."),
            "{args:?}: {said}"
        );
        for shown in [
            "Your recovery phrase is twelve words",
            "Your recovery phrase (shown once)",
            "Now type the words back",
            "Type your recovery phrase, one word at a time",
        ] {
            assert!(!said.contains(shown), "{args:?}: {said}");
        }
        let asked = held.asked();
        assert!(asked.len() > before, "{args:?} did not ask the node");
        for (path, _) in &asked[before..] {
            assert_eq!(path, "/api/v1/status", "{args:?} asked the node for more");
        }
    }
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");

    // The control: the node itself is not held up, and a phrase is made.
    makes_a_phrase(&laptop, "laptop");
    assert_eq!(look(&laptop)["change"], 1);
}

/// A command that changes anything refuses a node of another version
/// than its own, with the note that says how to restart it, and sends it
/// nothing (decision 2026-10-04 §10.1, rule 6; §16): every `sync`
/// command but `status` and `off`, `restore`, `history drop`, `init
/// --new-key`, and each command of a person's devices but `devices` with
/// no act. Turning sync off is sent to any node. `cordelia status`,
/// `cordelia sync status` (its `--seen` included), `cordelia devices`
/// and `cordelia history` still answer beside such a node, with the
/// note. And a look that says
/// nothing of where the device stands is no look of this version: it is
/// refused.
///
/// The node here is of this version, behind a stand-in that says it is
/// of another.
#[test]
fn a_command_that_changes_anything_refuses_a_node_of_another_version() {
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    let claude = laptop.home().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    laptop.cli(&["sync", "claude", "--dir", claude.to_str().unwrap()]);
    let another = Answers::in_the_place_of(&laptop, |path, answer| {
        if path == "/api/v1/status" {
            answer["version"] = "0.0.0-another".into();
        }
    });
    let other = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
    let other = cordelia_crypto::bech32::encode_public_key(&other.public_key()).unwrap();
    let home = laptop.home();
    let folder = home.to_str().unwrap();
    let note = "The running node is version 0.0.0-another and this command is version";
    let soon = std::time::Duration::from_secs(60);

    // Each command that changes something: refused, with the note, and
    // the node is asked for nothing but its version.
    let changes: [&[&str]; 15] = [
        &["sync", "claude"],
        &["sync", "claude", "--mapped-only"],
        &["sync", "map", folder, "notes"],
        &["sync", "unmap", "notes"],
        &["sync", "home", "on"],
        &["sync", "home", "off"],
        &["restore", "an-id"],
        &["history", "drop", "--all"],
        &["init", "--new-key"],
        &["phrase", "--name", "laptop"],
        &["add-device", &other],
        &["accept", &other],
        &["devices", "--clear"],
        &["remove-device", &other],
        &["renew"],
    ];
    for args in changes.iter().copied().chain([&["settle"][..]]) {
        let before = another.asked().len();
        let said = laptop
            .at_terminal_through(another.port, args)
            .refused_within(soon);
        assert!(said.contains(note), "{args:?}: {said}");
        assert!(
            said.contains("is not sent to a node of another version: nothing was done."),
            "{args:?}: {said}"
        );
        assert!(said.contains("restart"), "{args:?}: {said}");
        let asked = another.asked();
        for (path, _) in &asked[before..] {
            assert_eq!(path, "/api/v1/status", "{args:?} asked the node for more");
        }
        assert!(
            asked.len() > before,
            "{args:?} did not ask the node its version"
        );
    }
    assert_eq!(text(&look(&laptop), "state"), "no_phrase");
    let settings = laptop.post("/api/v1/sync/status", json!({}));
    assert_eq!(settings["enabled"], true, "{settings}");

    // What is no more is refused before the node is asked anything at
    // all, its version included (decision 2026-10-04 §10.1): whatever
    // version the node is, nothing is sent to it.
    let no_more: [&[&str]; 4] = [
        &["sync", "claude", "--all"],
        &[
            "sync",
            "claude",
            "--exclude",
            "github.com/someone/something",
        ],
        &["sync", "exclude", "github.com/someone/something"],
        &["sync", "include", "github.com/someone/something"],
    ];
    for args in no_more {
        let before = another.asked().len();
        let said = laptop
            .at_terminal_through(another.port, args)
            .refused_within(soon);
        assert!(
            said.contains("only mapped folders sync"),
            "{args:?}: {said}"
        );
        assert!(said.contains("nothing was changed"), "{args:?}: {said}");
        assert!(!said.contains(note), "{args:?}: {said}");
        assert_eq!(another.asked().len(), before, "{args:?} asked the node");
    }

    // What only shows is answered, with the note: `cordelia sync
    // status` with the act that puts its notice away among them.
    let shows: [&[&str]; 6] = [
        &["status"],
        &["sync", "status"],
        &["sync", "status", "--seen"],
        &["devices"],
        &["history"],
        &["history", "notes"],
    ];
    for args in shows {
        let (ended, said) = laptop
            .at_terminal_through(another.port, args)
            .ends_within(soon);
        assert!(said.contains(note), "{args:?}: {said}");
        assert!(!said.contains("is not sent to a node"), "{args:?}: {said}");
        // `cordelia history` of a name that keeps nothing says so, and
        // is not refused for the node's version.
        if args != ["history", "notes"] {
            assert!(ended, "{args:?}: {said}");
        }
    }
    let said = laptop
        .at_terminal_through(another.port, &["devices"])
        .done();
    assert!(said.contains("This device: "), "{said}");

    // Turning sync off is sent to any node.
    let before = another.asked().len();
    let said = laptop
        .at_terminal_through(another.port, &["sync", "off"])
        .done();
    assert!(said.contains(note), "{said}");
    assert!(said.contains("Sync is off."), "{said}");
    let asked = another.asked();
    assert!(
        asked[before..]
            .iter()
            .any(|(path, body)| path == "/api/v1/sync/claude"
                && serde_json::from_slice::<Value>(body)
                    .is_ok_and(|sent| sent["enabled"] == false)),
        "{:?}",
        asked[before..]
            .iter()
            .map(|(path, body)| (path, String::from_utf8_lossy(body)))
            .collect::<Vec<_>>()
    );
    let settings = laptop.post("/api/v1/sync/status", json!({}));
    assert_eq!(settings["enabled"], false, "{settings}");

    // The control: against the node itself, of this version, a command
    // that changes something is sent, and nothing of a version is said.
    let said = laptop.cli(&["sync", "claude", "--dir", claude.to_str().unwrap()]);
    assert!(!said.contains("The running node is version"), "{said}");
    let settings = laptop.post("/api/v1/sync/status", json!({}));
    assert_eq!(settings["enabled"], true, "{settings}");
    // `--mapped-only` is sent, as the only scope there is: `all: false`
    // (decision 2026-10-04 §10.1). Seen at a stand-in that changes
    // nothing of what the node answers.
    let same = Answers::in_the_place_of(&laptop, |_, _| {});
    let said = laptop
        .at_terminal_through(same.port, &["sync", "claude", "--mapped-only"])
        .done();
    assert!(
        said.contains("Only mapped folders sync: that is the only scope there is."),
        "{said}"
    );
    let sent: Vec<Value> = same
        .asked()
        .iter()
        .filter(|(path, _)| path == "/api/v1/sync/claude")
        .filter_map(|(_, body)| serde_json::from_slice(body).ok())
        .collect();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        (&sent[0]["enabled"], &sent[0]["all"]),
        (&json!(true), &json!(false))
    );

    // A node of another version is one of the things that a status
    // holds, where something is mapped and a cycle has reported: only
    // the command knows of it, and so the level is the command's
    // (decision 2026-10-04 §10.1). Beside the node as it is, it is not.
    let notes = home.join("notes");
    std::fs::create_dir_all(&notes).unwrap();
    laptop.cli(&["sync", "map", notes.to_str().unwrap(), "notes"]);
    let status_through = |port: u16| -> Value {
        let said = laptop
            .at_terminal_through(port, &["status", "--json"])
            .done();
        let from = said.find('{').unwrap_or_else(|| panic!("{said}"));
        serde_json::from_str(&said[from..]).unwrap_or_else(|e| panic!("{e}: {said}"))
    };
    let whats = |status: &Value| -> Vec<String> {
        let all = status["holds"].as_array().into_iter().flatten();
        all.filter_map(|holds| holds["what"].as_str().map(str::to_string))
            .collect()
    };
    wait_for("a cycle has reported the folder", &[&laptop], 60, || {
        (status_through(same.port)["sync"]["folders"] == 1).then_some(())
    });
    assert_eq!(whats(&status_through(same.port)), ["no_phrase"]);
    // A status asks the node what it holds of its person, and asks for
    // no count of what the device has sent to no relay: the node works
    // that out only where a request asks for it (decision 2026-10-04
    // §16).
    let looks_asked = |of: &Answers, from: usize| -> Vec<Value> {
        let asked = of.asked();
        let looks = asked[from..]
            .iter()
            .filter(|(path, _)| path == "/api/v1/devices/list");
        looks
            .filter_map(|(_, body)| serde_json::from_slice(body).ok())
            .collect()
    };
    let by_a_status = looks_asked(&same, 0);
    assert!(!by_a_status.is_empty(), "a status asks for the look");
    for sent in &by_a_status {
        assert!(sent.get("sent_to_no_relay").is_none(), "{by_a_status:?}");
    }
    let beside_another = status_through(another.port);
    assert_eq!(whats(&beside_another), ["no_phrase", "other_version"]);
    assert_eq!(beside_another["level"], "red", "{beside_another}");
    assert_eq!(beside_another["node_version"], "0.0.0-another");
    laptop.cli(&["sync", "unmap", "notes"]);

    // A look that says nothing of where the device stands: refused, by
    // a command that only shows as by one that acts.
    let no_state = Answers::in_the_place_of(&laptop, |path, answer| {
        if path == "/api/v1/devices/list"
            && let Some(look) = answer.as_object_mut()
        {
            look.remove("state");
        }
    });
    //
    // **Each command that has the device begin again asks the look for
    // how much the device has sent to no relay,** which it says before
    // its yes: `accept`, `phrase` and `init --new-key`. A command that
    // only shows does not ask.
    for (args, asks) in [
        (&["devices"][..], false),
        (&["accept", &other][..], true),
        (&["phrase"][..], true),
        (&["init", "--new-key"][..], true),
    ] {
        let before = no_state.asked().len();
        let said = laptop
            .at_terminal_through(no_state.port, args)
            .refused_within(soon);
        assert!(
            said.contains("says nothing of where this device stands"),
            "{args:?}: {said}"
        );
        assert!(!said.contains("Type yes to go on"), "{args:?}: {said}");
        assert!(!said.contains("shown once"), "{args:?}: {said}");
        let looks = looks_asked(&no_state, before);
        assert_eq!(looks.len(), 1, "{args:?}: {looks:?}");
        assert_eq!(
            looks[0].get("sent_to_no_relay"),
            asks.then_some(&json!(true)),
            "{args:?}: {looks:?}"
        );
    }
}

/// A command that opens the node's database itself does not open it
/// beside a running node of another version than its own (decision
/// 2026-10-04 §10.1, rule 6): opening runs the schema's steps, and a
/// later command would step the database under an earlier node. `cordelia
/// stats`, `cordelia channels` and `cordelia init --force` say the note
/// that names the restart, end in failure, and open nothing: the
/// database stays at its schema version, byte for byte. `cordelia
/// status` still answers: it says the note, and that the database was
/// not read. **Where no node answers, each goes on as it did,** and the
/// database is stepped as any opening steps it.
///
/// The node here is of this version, behind a stand-in that says it is
/// of another. The database is one of the test's own, in the released
/// version's form, in a directory beside the node's with a key and a
/// token: no command here opens the database that the node runs on.
#[test]
fn a_command_that_opens_the_database_opens_none_beside_a_node_of_another_version() {
    use cordelia_storage::schema::{RELEASED_SCHEMA_VERSION, SCHEMA_VERSION};
    let mut laptop = node("laptop", "personal", None);
    laptop.start();
    wait_for("the laptop is up", &[&laptop], 30, || healthy(&laptop));
    let another = Answers::in_the_place_of(&laptop, |path, answer| {
        if path == "/api/v1/status" {
            answer["version"] = "0.0.0-another".into();
        }
    });

    // A data directory as the released version left one.
    let beside = laptop.dir.path().join("beside");
    std::fs::create_dir(&beside).unwrap();
    for file in ["identity.key", "node-token"] {
        std::fs::copy(laptop.data_dir().join(file), beside.join(file)).unwrap();
    }
    let database = beside.join("cordelia.db");
    drop(cordelia_storage::first_start::released::database(&database).unwrap());
    let schema_version = || -> u32 {
        let db = rusqlite::Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        db.pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap()
    };
    assert_eq!(schema_version(), RELEASED_SCHEMA_VERSION);
    const { assert!(RELEASED_SCHEMA_VERSION < SCHEMA_VERSION) };
    let as_it_was = std::fs::read(&database).unwrap();
    let key = std::fs::read(beside.join("identity.key")).unwrap();

    // Beside the node that says it is of another version.
    let port = another.port.to_string();
    let directory = beside.to_str().unwrap();
    let through = [
        ("CORDELIA_DATA_DIR", directory),
        ("CORDELIA_HTTP_PORT", port.as_str()),
    ];
    let note = "The running node is version 0.0.0-another and this command is version";
    let restart = cordelia_api::commands::restart_command(std::env::consts::OS);
    let opens: [&[&str]; 4] = [
        &["stats"],
        &["stats", "--json"],
        &["channels"],
        &["init", "--force"],
    ];
    for args in opens {
        let before = another.asked().len();
        let out = laptop.command_given(&through, args);
        let said = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(!out.status.success(), "{args:?}: {said}");
        assert!(said.contains(note), "{args:?}: {said}");
        assert!(said.contains(restart), "{args:?}: {said}");
        assert!(
            said.contains("does not open it beside a node of another version: nothing was opened."),
            "{args:?}: {said}"
        );
        assert_eq!(schema_version(), RELEASED_SCHEMA_VERSION, "{args:?}");
        assert_eq!(std::fs::read(&database).unwrap(), as_it_was, "{args:?}");
        // The node was asked its version, and nothing else.
        let asked = another.asked();
        assert!(asked.len() > before, "{args:?} did not ask the node");
        for (path, _) in &asked[before..] {
            assert_eq!(path, "/api/v1/status", "{args:?} asked the node for more");
        }
    }
    // `init --force` wrote no new key either.
    assert_eq!(std::fs::read(beside.join("identity.key")).unwrap(), key);

    // `cordelia status` still answers, and reads nothing of the database.
    let out = laptop.command_given(&through, &["status"]);
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains(
            "Storage:\n  Not read:  a node of another version is running, and its database \
             is not opened beside it."
        ),
        "{said}"
    );
    assert!(said.contains(note), "{said}");
    assert!(!said.contains("DB size:"), "{said}");
    assert_eq!(schema_version(), RELEASED_SCHEMA_VERSION);
    assert_eq!(std::fs::read(&database).unwrap(), as_it_was);

    // The control: where no node answers, each goes on as it did, and
    // the opening steps the database.
    let nobody = {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        free.local_addr().unwrap().port().to_string()
    };
    let alone = [
        ("CORDELIA_DATA_DIR", directory),
        ("CORDELIA_HTTP_PORT", nobody.as_str()),
    ];
    let out = laptop.command_given(&alone, &["stats"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(said.contains("Database:"), "{said}");
    assert_eq!(schema_version(), SCHEMA_VERSION);
}

// ── A change made while a pass is in flight ──────────────────────────

/// A node's database, opened for reading while the node runs.
fn store_of(node: &Node) -> rusqlite::Connection {
    let db = rusqlite::Connection::open_with_flags(
        node.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(std::time::Duration::from_secs(10)).unwrap();
    db
}

/// A command that changes the change entry which a device keeps is run
/// while the node's passes are in flight, one after another without a
/// gap. Nothing that a pass asked under the entry before is written down
/// after the change: when it is over, the device keeps nothing of a relay
/// for a channel that it holds no more, every device has applied the last
/// change, and none is in a fork.
#[test]
fn changes_made_while_passes_are_in_flight_leave_nothing_of_a_channel_left() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let desktop = device_started("desktop", &relay);
    let all = [&relay, &laptop, &desktop];
    let words = makes_a_phrase(&laptop, "laptop");
    adds(&laptop, &desktop, "desktop");

    // Whole passes on the laptop, back to back: each asking for a
    // change to be prepared has the node make one, and waits for it.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let passes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (url, token) = (
        format!("http://127.0.0.1:{}/api/v1/change/prepare", laptop.http),
        laptop.token(),
    );
    let asking = {
        let (stop, passes) = (stop.clone(), passes.clone());
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            while !stop.load(Ordering::SeqCst) {
                let asked = direct()
                    .post(&url)
                    .header("Authorization", &format!("Bearer {token}"))
                    .send_json(json!({ "settle": false }));
                if asked.is_ok() {
                    passes.fetch_add(1, Ordering::SeqCst);
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
        })
    };

    // Three changes, one after another, each made while that goes on.
    renews(&laptop, &["stays"], &words).done();
    for number in [3, 4] {
        let mut at = renews(&laptop, &[], &words);
        at.says(&format!("The change is made (change {number})."));
        at.done();
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    asking.join().unwrap();
    assert!(
        passes.load(std::sync::atomic::Ordering::SeqCst) >= 10,
        "passes were in flight all the while"
    );

    // Every device has applied the last change, and none is in a fork.
    applies(&desktop, 4, &all);
    for device in [&laptop, &desktop] {
        let seen = look(device);
        assert_eq!(
            (text(&seen, "state"), &seen["change"]),
            ("applied", &json!(4))
        );
        wait_for("the relay holds the last change", &all, 60, || {
            relay_holds_latest(device)
        });
    }
    // Nothing is kept of a relay for a channel that the device holds no
    // more: no pass wrote down, after a change, what it had asked before
    // it.
    for device in [&laptop, &desktop] {
        let db = store_of(device);
        for table in ["at_relays", "at_relays_refused"] {
            let left: i64 = db
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {table}
                         WHERE channel NOT IN (SELECT channel_id FROM entries)"
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(left, 0, "{}: {table}", device.name);
        }
        let kept: i64 = db
            .query_row("SELECT COUNT(*) FROM at_relays", [], |row| row.get(0))
            .unwrap();
        assert!(kept >= 1, "{}", device.name);
    }
    // And the relay took no breach of its limits from either.
    let log = std::fs::read_to_string(relay.log()).unwrap();
    assert!(!log.contains("breach"), "the relay counted a breach");
}

/// What another device wrote as a name and is none is never printed
/// (decision 2026-10-04 §16): not at the prompt of a removal, just before
/// the yes and the phrase, and not by `cordelia devices` or `cordelia
/// status`, with `--json` or without. It is counted, and said as a number.
///
/// The laptop's words are written here as only a device that does not run
/// this code would write them: under its own key, in the personal channel,
/// with an escape sequence, a new line, a great length, and another
/// spelling.
#[test]
fn a_word_that_is_no_name_is_printed_by_no_command() {
    use cordelia_crypto::entry::{Entry, Inside, Value as Held};
    let relay = relay_started();
    let desktop = device_started("desktop", &relay);
    let laptop = device_started("laptop", &relay);
    let all = [&relay, &desktop, &laptop];
    let words = pair(&desktop, &laptop, "laptop", &all).unwrap();

    // The laptop's words, in the desktop's own store, as if the desktop
    // had been given them.
    let no_names = [
        "\x1b[2J\x1b[31mNOT-A-NAME-escape".to_string(),
        "NOT-A-NAME-two\nlines".to_string(),
        format!("NOT-A-NAME-long-{}", "x".repeat(50_000)),
        "NOT-A-NAME-In-Capitals".to_string(),
        "not-a-name-NOT-A-NAME.git".to_string(),
    ];
    {
        let store = rusqlite::Connection::open(desktop.data_dir().join("cordelia.db")).unwrap();
        store
            .busy_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let secret: [u8; 32] = store
            .query_row(
                "SELECT secret FROM person_secrets WHERE left_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let personal = cordelia_crypto::derive::personal_secret(&secret).unwrap();
        let by = cordelia_crypto::identity::NodeIdentity::from_file(
            &laptop.data_dir().join("identity.key"),
        )
        .unwrap();
        for no_name in &no_names {
            let inside = Inside {
                name: format!("{}{no_name}", cordelia_core::protocol::PERSONAL_NAME_PREFIX),
                value: Held::Text(String::new()),
                chain: Some(Vec::new()),
            };
            let word = Entry::seal(&personal, &by, 1, &inside)
                .unwrap()
                .check()
                .unwrap();
            cordelia_storage::entries::store(&store, &word, 1_790_000_000).unwrap();
        }
    }
    let counted = format!(
        "{} names that cannot be shown are listed by a device",
        no_names.len()
    );
    let shows_none = |said: &str| {
        assert!(!said.to_uppercase().contains("NOT-A-NAME"), "{said}");
        assert!(!said.contains('\x1b'), "{said:?}");
        assert!(said.len() < 20_000, "{}", said.len());
    };

    let devices = desktop.cli(&["devices"]);
    assert!(devices.contains(&counted), "{devices}");
    shows_none(&devices);
    let status = desktop.cli(&["status"]);
    assert!(status.contains(&counted), "{status}");
    shows_none(&status);
    let as_json = desktop.cli(&["status", "--json"]);
    shows_none(&as_json);
    let seen: Value = serde_json::from_str(&as_json).unwrap();
    assert_eq!(seen["person"]["names_not_shown"], no_names.len(), "{seen}");

    // The prompt of a removal: the number, and nothing of what they hold.
    let mut at = desktop.at_terminal(&["remove-device", &key_of(&laptop)]);
    at.says("Make this change?").says("Type yes to go on");
    let said = at.said.clone();
    assert!(
        said.contains(&format!(
            "{} names that cannot be shown stay behind too",
            no_names.len()
        )),
        "{said}"
    );
    assert!(!said.to_uppercase().contains("NOT-A-NAME"), "{said}");
    assert!(said.len() < 20_000, "{}", said.len());
    at.types("no");
    let said = at.done();
    assert!(!said.to_uppercase().contains("NOT-A-NAME"), "{said}");
    let _ = words;
}
