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
    for of_its_relays in ["relays", "waiting", "says"] {
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
/// whole, and the prompts say whose words they are. The device then
/// follows it, alone, and its relay is shown the change entry and holds
/// it.
#[test]
fn a_phrase_is_made_at_a_terminal_and_the_relay_holds_its_first_change() {
    let relay = relay_started();
    let laptop = device_started("laptop", &relay);
    let all = [&relay, &laptop];

    // Before there is a phrase.
    let status = laptop.cli(&["status"]);
    assert!(status.contains("Devices:   not added yet"), "{status}");
    assert!(
        status.contains(
            "no recovery phrase yet: memory stays on this machine. Make one here (`cordelia \
             phrase`), or add this machine from one that has one."
        ),
        "{status}"
    );
    let json: Value = serde_json::from_str(&laptop.cli(&["status", "--json"])).unwrap();
    assert_eq!(json["person"]["state"], "no_phrase");
    assert_eq!(json["person"]["short"], "not added yet");
    let says = json["person"]["says"][0].as_str().unwrap();
    assert!(says.starts_with("no recovery phrase yet:"), "{json}");
    let devices = laptop.cli(&["devices"]);
    assert!(devices.contains("no recovery phrase yet:"), "{devices}");

    // The phrase, made at a terminal.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when they are written down");
    let words = words_shown(&at.said);
    at.types("");
    at.says("Type the twelve words back");
    at.types(&words);
    let said = at.done();
    // Whose words these are, and what they are for.
    for says in [
        "They are Cordelia's recovery phrase for your devices.",
        "from the list that a wallet's seed phrase uses",
        "never\r\ntype these into a wallet, and never type a wallet's words here",
        "Without the phrase a device can be added, and none can ever be removed or recovered.",
        "It is listed as laptop (",
    ] {
        assert!(
            said.contains(says),
            "the command did not say {says:?}:\n{said}"
        );
    }
    // The words are shown once: what was typed back is not shown. And
    // they are shown on the terminal's other screen, which is put away
    // once they are written down.
    assert_eq!(said.matches(&words).count(), 1, "{said}");
    let shown_at = said.find(&words).unwrap();
    let (other_screen, put_away) = (
        said.find("\u{1b}[?1049h").expect("the other screen"),
        said.find("\u{1b}[?1049l")
            .expect("the other screen is put away"),
    );
    assert!(other_screen < shown_at && shown_at < put_away, "{said}");
    assert!(put_away < said.find("Type the twelve words back").unwrap());
    assert_eq!(words.split(' ').count(), 12);

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
        "This gives desktop ({}) every name's memory, and the means to read what your devices \
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
            format!("laptop ({})", words_of(&laptop_key)),
            format!("desktop ({}), added from laptop", words_of(&desktop_key)),
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
        listed.contains("added from laptop") && listed.contains("has applied change 1"),
        "{listed}"
    );

    // The notice, on each device, in its status too, until a person
    // clears it there.
    let told = format!(
        "new device: desktop ({}), added from laptop ({})",
        words_of(&desktop_key),
        words_of(&laptop_key)
    );
    assert_eq!(notices(&laptop), std::slice::from_ref(&told));
    assert_eq!(
        notices(&desktop),
        [format!(
            "this device was added from laptop ({})",
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
/// makes nothing, and nor does a yes that is not given.
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
        said.contains("this device follows no recovery phrase yet. Make one here"),
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
        ("/api/v1/devices/add", json!({ "device": other })),
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

    // The words typed back are not the words shown: nothing is made.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when they are written down");
    let words = words_shown(&at.said);
    at.types("");
    at.says("Type the twelve words back");
    let mut wrong: Vec<&str> = words.split(' ').collect();
    wrong.swap(0, 11);
    assert_ne!(wrong.join(" "), words);
    at.types(&wrong.join(" "));
    let said = at.refused();
    assert!(
        said.contains("the words typed are not the words that were shown. Nothing was made"),
        "{said}"
    );
    assert_eq!(holds(&laptop), before);
    // Words that are no phrase at all, typed back: nothing either.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Press Enter when they are written down").types("");
    at.says("Type the twelve words back")
        .types("these are not twelve words");
    assert!(at.refused().contains("Nothing was made"));
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
    assert!(!said.contains("The recovery phrase, shown once:"), "{said}");
    let now = look(&laptop);
    assert_eq!(now["devices"], made["devices"]);
    assert_eq!(now["change"], made["change"]);

    // With its yes it replaces it: the device follows a new phrase,
    // alone, at change 1 again, and the old words are another phrase.
    let mut at = laptop.at_terminal(&["phrase", "--name", "laptop"]);
    at.says("Type yes to go on").types("yes");
    at.says("Press Enter when they are written down");
    let new_words = words_shown(&at.said);
    at.types("");
    at.says("Type the twelve words back").types(&new_words);
    at.done();
    assert_ne!(new_words, words);
    let now = look(&laptop);
    assert_eq!((text(&now, "among"), &now["change"]), ("alone", &json!(1)));
    // The old phrase signs nothing here any more.
    let mut at = laptop.at_terminal(&["renew"]);
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("The recovery phrase, twelve words").types(&words);
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
/// is told from a wrong one, and neither makes anything. The removed
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
    // A key that is nobody's device.
    let said = laptop
        .at_terminal(&["remove-device", &key_of(&relay)])
        .refused();
    assert!(said.contains("no device of yours"), "{said}");

    // A wrong phrase: one that is a phrase, and not this device's.
    let other_phrase =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let removes = |phrases: &[&str]| {
        let mut at = laptop.at_terminal(&["remove-device", &desktop_key]);
        at.says(&format!(
            "To be removed: desktop ({}).",
            words_of(&desktop_key)
        ));
        // The tablet was added by the device that is being removed: it
        // is shown as that, and no answer is suggested for it.
        at.says(&format!(
            "tablet ({}), added since the last change, from desktop ({})",
            words_of(&tablet_key),
            words_of(&desktop_key)
        ));
        at.says("It was added by the device that is being removed");
        at.says("[no answer is suggested]").types("");
        at.says("That is none of the answers.");
        at.says("Type `stays` or `removed`").types("stays");
        // The lists, from the bytes that will be signed.
        at.says("The change that the recovery phrase will sign (change 2):");
        at.says(&format!("made on laptop ({})", words_of(&laptop_key)));
        at.says("devices (2):");
        at.says(&format!(
            "laptop ({})  (this device)",
            words_of(&laptop_key)
        ));
        at.says(&format!("tablet ({})", words_of(&tablet_key)));
        at.says("removed keys (1):");
        at.says(&format!(
            "({}), known here as desktop",
            words_of(&desktop_key)
        ));
        at.says("Make this change?")
            .says("Type yes to go on")
            .types("yes");
        for phrase in phrases {
            at.says("The recovery phrase, twelve words").types(phrase);
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
        !said.contains("The recovery phrase, twelve words"),
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
    // The words are never shown as they are typed.
    assert!(!said.contains("legal winner"), "{said}");

    // A mistyped phrase is told from a wrong one, and is typed again:
    // a word changed for another of the list, and a word that is none.
    let mistyped = ["zoo", "wrong", "able", "about", "above", "absent"]
        .iter()
        .map(|other| {
            let mut mistyped: Vec<&str> = words.split(' ').collect();
            mistyped[3] = other;
            mistyped.join(" ")
        })
        .find(|mistyped| cordelia_crypto::phrase::Phrase::parse(mistyped).is_err())
        .expect("one of six words in the place of another fails the checksum");
    let no_word = format!("xyzzy {}", words.split_once(' ').unwrap().1);
    let mut at = removes(&[&mistyped, &no_word, &words]);
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
    assert!(
        said.contains("is not a word that a recovery phrase can have"),
        "{said}"
    );
    assert!(said.contains("holds the change"), "{said}");
    assert!(said.contains("this machine may be closed."), "{said}");
    assert!(
        !said.contains(&words),
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
            "tablet ({}): has applied change 2",
            words_of(&tablet_key)
        )),
        "{listed}"
    );
    assert!(listed.contains("Removed keys:"), "{listed}");
    assert!(listed.contains(&desktop_key), "{listed}");

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
    assert!(!said.contains("The recovery phrase, shown once:"), "{said}");
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
        "desktop ({}), added since the last change, from laptop ({})",
        words_of(&desktop_key),
        words_of(&laptop_key)
    ));
    at.says("Type `stays` or `removed` [Enter: stays]")
        .types("");
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
    at.says("The recovery phrase, twelve words").types(&words);
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
            "this device is not in a change made on laptop ({}): if it is yours, add it again \
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
        "tablet ({}) is not in the last change: add it again, or it was meant to go",
        words_of(&tablet_key)
    );
    assert_eq!(notices(&laptop), std::slice::from_ref(&not_in));
    let listed = laptop.cli(&["devices"]);
    assert!(listed.contains("Not in the last change"), "{listed}");
    assert!(!listed.contains(&tablet_key), "{listed}");

    // It is added again, by the same two commands. `add-device` shows
    // the key as not in the last change before its yes.
    let mut at = laptop.at_terminal(&["add-device", &tablet_key, "--name", "tablet"]);
    at.says("This key was not in the last change. This device knew it as tablet");
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
    let said = at.done();
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
            "this device was added from laptop ({})",
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
        "tablet ({}), added since the last change",
        words_of(&tablet_key)
    ));
    at.says("Type `stays` or `removed` [Enter: stays]")
        .types("removed");
    at.says("The change that the recovery phrase will sign (change 3):");
    at.says("devices (2):");
    at.says("removed keys (1):");
    at.says(&format!(
        "({}), known here as tablet",
        words_of(&tablet_key)
    ));
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("The recovery phrase, twelve words").types(&words);
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
    at.says("Type `stays` or `removed` [Enter: stays]")
        .types("");
    at.says("The change that the recovery phrase will sign (change 2):");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("The recovery phrase, twelve words");

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
        .says("The recovery phrase, twelve words")
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
    at.says("The recovery phrase, twelve words").types(&words);
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
        "desktop ({}) is one of your devices already: this hands it the last change again, and \
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
    at.says("Press Enter when they are written down");
    let new_words = words_shown(&at.said);
    at.types("");
    at.says("Type the twelve words back").types(&new_words);
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
        "desktop ({}) left, and started again under another phrase. It still holds the secret \
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
    at.says("new device: desktop")
        .says("Type yes to go on")
        .types("no");
    at.says("new device: tablet")
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
    // Until the node is started again it makes nothing for a command,
    // under a key that is the device's no longer.
    let said = tablet.refused(&["devices"]);
    assert!(
        said.contains("this device was given a new key, and the node still runs under the old one"),
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
        "tablet ({}) left, and started again under another phrase.",
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
    renews(&laptop, &[""], &words).done();
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
    let said = forked.at_terminal(&["accept", &key_of(other)]).refused();
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
        "{} ({}), a device of both changes:",
        other.name,
        words_of(&key_of(other))
    ));
    at.says(
        "Type `stays` or `removed`, or `neither` (it is in no list, and is added again by hand)",
    );
    at.says("[no answer is suggested]").types("stays");
    at.says("The change that the recovery phrase will sign (change 4):");
    at.says("devices (2):");
    at.says("Make this change?")
        .says("Type yes to go on")
        .types("yes");
    at.says("The recovery phrase, twelve words").types(&words);
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

/// A phrase of twelve words that are words of nothing this program
/// says, so that a search for any one of them finds only the phrase.
fn a_phrase_of_words_that_nothing_else_says() -> String {
    let first = [
        "giraffe", "kangaroo", "squirrel", "dolphin", "elephant", "lobster", "mushroom", "pumpkin",
        "sausage", "walnut", "banana",
    ];
    let last = [
        "cactus", "coconut", "dinosaur", "gorilla", "hamster", "lizard", "monkey", "oyster",
        "pelican", "pigeon", "rabbit", "raccoon", "salmon", "spider", "turkey", "turtle", "tomato",
        "potato", "peanut", "pepper", "noodle", "muffin", "garlic", "ginger", "cherry", "cereal",
        "butter", "bamboo", "avocado", "tornado", "volcano", "umbrella", "trumpet", "violin",
        "guitar",
    ];
    // The last word carries the checksum: one in sixteen fits.
    last.iter()
        .map(|last| format!("{} {last}", first.join(" ")))
        .find(|words| cordelia_crypto::phrase::Phrase::parse(words).is_ok())
        .expect("one of these words ends a phrase that begins with those")
}

/// Everything that is sent to a port on this machine is passed on to
/// another, and kept: for a test that reads what a node was sent.
struct PassesOn {
    port: u16,
    sent: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl PassesOn {
    fn to(port: u16) -> Self {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let at = listener.local_addr().unwrap().port();
        let kept = sent.clone();
        std::thread::spawn(move || {
            for from in listener.incoming().flatten() {
                let Ok(to) = TcpStream::connect(("127.0.0.1", port)) else {
                    continue;
                };
                let (mut asks, mut node) = (from.try_clone().unwrap(), to.try_clone().unwrap());
                let kept = kept.clone();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 16 * 1024];
                    while let Ok(n) = asks.read(&mut buf) {
                        if n == 0 || node.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        kept.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                    let _ = node.shutdown(Shutdown::Write);
                });
                let (mut node, mut asks) = (to, from);
                std::thread::spawn(move || {
                    let mut buf = [0u8; 16 * 1024];
                    while let Ok(n) = node.read(&mut buf) {
                        if n == 0 || asks.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = asks.shutdown(Shutdown::Write);
                });
            }
        });
        Self { port: at, sent }
    }

    fn sent(&self) -> Vec<u8> {
        self.sent.lock().unwrap().clone()
    }
}

/// Every file under `dir`, with its bytes.
fn files_under(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            found.push((path, bytes));
        }
    }
    found
}

/// The words in `bytes`: each run of letters, in lower case.
fn words_in(bytes: &[u8]) -> std::collections::HashSet<String> {
    bytes
        .split(|byte| !byte.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8_lossy(word).to_lowercase())
        .collect()
}

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
    at.says("The recovery phrase, twelve words").types(&words);
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
        let found = words_in(bytes);
        for word in &phrase_words {
            assert!(!found.contains(*word), "the word {word:?} is in {what}");
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
    at.says("Press Enter when they are written down");
    #[cfg(target_os = "linux")]
    assert_eq!(guarded(at.pid()), (true, "0 0".to_string()));
    let words = words_shown(&at.said);
    at.types("");
    at.says("Type the twelve words back").types(&words);
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
    at.says("The recovery phrase, twelve words").types(&words);
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
    for word in words.split(' ') {
        let after = said
            .split("The recovery phrase, twelve words")
            .nth(1)
            .unwrap();
        assert!(
            !words_in(after.as_bytes()).contains(word),
            "{word} in:\n{after}"
        );
    }
}

// ── What answers at the node's address ───────────────────────────────

/// A stand-in at a port of this machine for the node at `port`: each
/// request is passed on to the node, and the node's answer is handed back
/// as `changed` leaves it. It is what a program that answers at the
/// node's address could say to a command.
struct Answers {
    port: u16,
}

impl Answers {
    fn in_the_place_of(
        node: &Node,
        changed: impl Fn(&str, &mut Value) + Send + Sync + 'static,
    ) -> Self {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap().port();
        let (node_port, token) = (node.http, node.token());
        let changed = std::sync::Arc::new(changed);
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let (changed, token) = (changed.clone(), token.clone());
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
        Self { port: at }
    }
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
        json!({ "device": its_key, "label": "laptop" }),
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
        "The recovery phrase, twelve words",
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
    renews(&laptop, &[""], &words).done();
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
