//! Making, sharing and taking a shared channel (decision 2026-10-10, slice
//! 6): `cordelia shared new`, `share`, `accept <key> --channel <name>`,
//! `label`, `shared list`, `shared drop` and `id --words`, run as a person
//! runs them, at a terminal, against devices that are real processes and
//! relays of the test's own on this machine. Two people's devices are set
//! up with the same relay, each knowing it by its key (§8.2).

mod common;

use std::path::Path;
use std::time::Duration;

use common::*;
use cordelia_crypto::derive;
use cordelia_crypto::entry::{Entry, Inside, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::share::{Card, Relays, Share, share_name};
use serde_json::json;

/// What a command says where its input is not a terminal.
const NOT_A_TERMINAL: &str = "this command asks before it does anything";
/// What a command says where it was not given a yes.
const NOT_A_YES: &str = "That was not a yes. Nothing was done.";

fn path(p: &Path) -> String {
    p.to_str().unwrap().to_string()
}

/// Sync on for `n`, with nothing mapped.
fn sync_on(n: &Node) {
    let out = n.cli(&["sync", "claude", "--dir", &path(&n.home().join(".claude"))]);
    assert!(out.starts_with("Sync turned on.\n"), "{out}");
}

/// A person's one device, `name`, which knows `relay` by its key, follows
/// a phrase of its own and has sync on.
fn person(name: &'static str, relay: &Node) -> Node {
    let device = device_started_with_its_relays_key(name, relay);
    makes_a_phrase(&device, name);
    sync_on(&device);
    device
}

/// What `n` says of its shared channels (`POST /api/v1/shared/list`).
fn listed(n: &Node) -> serde_json::Value {
    n.post("/api/v1/shared/list", json!({ "keys": true }))
}

/// The channel `name` as `n` lists it, where it does.
fn channel_of(n: &Node, name: &str) -> Option<serde_json::Value> {
    listed(n)["channels"]
        .as_array()?
        .iter()
        .find(|channel| channel["name"] == name)
        .cloned()
}

/// `cordelia shared new <name>` on `n`, at a terminal, with its yes, and
/// `extra` arguments. Returns the channel's four words.
fn makes(n: &Node, name: &str, extra: &[&str]) -> String {
    let mut at = n.at_terminal(&[&["shared", "new", name], extra].concat());
    at.says("This makes a channel shared between people")
        .says("Type yes to go on")
        .types("yes");
    let said = at.done();
    let words = said
        .split(&format!("Made \"{name}\": channel "))
        .nth(1)
        .and_then(|rest| rest.split('.').next())
        .unwrap_or_else(|| panic!("{}: no channel made:\n{said}", n.name))
        .to_string();
    assert_eq!(words.split(' ').count(), 4, "{said}");
    words
}

/// `cordelia share <name> <key>` on `n`, with its yes: what it said. The
/// six words of the key are shown before the yes.
fn shares(n: &Node, name: &str, key: &str) -> String {
    let six = six_words_of(key);
    let mut at = n.at_terminal(&["share", name, key]);
    at.says(&format!("They must be these: {six}."))
        .says("Type yes to go on")
        .types("yes");
    let said = at.done();
    assert!(
        said.contains("Handed over. On the other device, within the hour, run:"),
        "{said}"
    );
    said
}

/// The six words of the fingerprint of the key `key`, as `id --words`
/// prints them on its device.
fn six_words_of(key: &str) -> String {
    let key = cordelia_crypto::bech32::decode_public_key(key).unwrap();
    cordelia_crypto::fingerprint::words(&key, 6)
}

/// `cordelia accept <key> --channel <name>` on `n`, with its yes, still
/// running: it stays up to a minute.
fn accepting(n: &Node, key: &str, name: &str) -> AtTerminal {
    let mut at = n.at_terminal(&["accept", key, "--channel", name]);
    at.says(&format!("They must be these: {}.", six_words_of(key)))
        .says("Type yes to go on")
        .types("yes");
    at.says("Asking your relays for what");
    at
}

/// Wait until `n` holds the channel `name`, taken with the key typed:
/// what the command said, where it ended with nothing taken yet, is
/// followed by what the node says.
fn holds_in_the_end(all: &[&Node], n: &Node, name: &str) -> serde_json::Value {
    wait_for("the shared channel is held", all, 300, || {
        channel_of(n, name)
    })
}

/// What `node` holds of `channel`, read from its database.
fn held_at(node: &Node, channel: &[u8; 32]) -> usize {
    let db = rusqlite::Connection::open_with_flags(
        node.data_dir().join("cordelia.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db.query_row(
        "SELECT COUNT(*) FROM entries WHERE channel_id = ?1",
        [&channel[..]],
        |row| row.get::<_, i64>(0),
    )
    .unwrap() as usize
}

/// The identity of `node`, read from its key file.
fn identity_of(node: &Node) -> NodeIdentity {
    NodeIdentity::from_file(&node.data_dir().join("identity.key")).unwrap()
}

fn id_of(channel: &serde_json::Value) -> [u8; 32] {
    hex::decode(channel["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// A share in either order, through a relay of the test's own (decision
/// 2026-10-10 §3.1 to §3.3): Alice's laptop makes a channel, Bob's desktop
/// prints its key and six words, Alice shares the channel to that key, and
/// Bob takes it with `accept --channel`, which prints the channel's words
/// that Alice's command printed; each then holds the other's key in the
/// channel, from the empty anew record each wrote there. Then the other
/// order: Bob types Alice's key for a second channel first, and Alice makes
/// and shares it within the hour.
#[test]
fn a_share_and_an_accept_in_either_order() {
    let relay = relay_started();
    let alice = person("laptop", &relay);
    let bob = person("desktop", &relay);
    let all = [&relay, &alice, &bob];
    let (alice_key, bob_key) = (key_of(&alice), key_of(&bob));

    // `id --words`: the key, and its six words, and nothing else.
    let id = bob.cli(&["id", "--words"]);
    let lines: Vec<&str> = id.lines().collect();
    assert_eq!(
        lines,
        [bob_key.as_str(), six_words_of(&bob_key).as_str()],
        "{id}"
    );

    let words = makes(&alice, "design-review", &[]);
    let said = shares(&alice, "design-review", &bob_key);
    assert!(
        said.contains(&format!(
            "  cordelia accept {alice_key} --channel <a name of their choosing>"
        )),
        "{said}"
    );
    assert!(
        said.contains(&format!(
            "It prints these words for the channel once it has taken it: {words}."
        )),
        "{said}"
    );
    let said = accepting(&bob, &alice_key, "review-with-alice").ends().1;
    if !said.contains("Nothing was taken yet") {
        assert!(
            said.contains(&format!(
                "Taken: \"review-with-alice\" is channel {words}, at 127.0.0.1:"
            )),
            "{said}"
        );
        assert!(
            said.contains("Keys that wrote here, in \"review-with-alice\""),
            "{said}"
        );
    }
    let taken = holds_in_the_end(&all, &bob, "review-with-alice");
    assert_eq!(taken["words"], words.as_str());
    assert_eq!(taken["reached"], true);
    assert!(
        taken["came"]["taken_from"]
            .as_str()
            .unwrap()
            .contains(&six_words_of(&alice_key))
    );
    // Each comes to hold the other's key there, from its empty anew record.
    wait_for("each holds the other's key", &all, 300, || {
        let a = channel_of(&alice, "design-review")?;
        let b = channel_of(&bob, "review-with-alice")?;
        (a["keys"] == 1 && b["keys"] == 1).then_some(())
    });
    let shared = listed(&alice)["shares"][0].clone();
    assert_eq!(shared["taken"], true, "{shared}");

    // The other order: the key typed first.
    let at = accepting(&bob, &alice_key, "second");
    let second = makes(&alice, "second", &[]);
    shares(&alice, "second", &bob_key);
    let said = at.ends().1;
    let held = holds_in_the_end(&all, &bob, "second");
    assert_eq!(held["words"], second.as_str(), "{said}");
    assert_ne!(second, words);
}

/// A device that a person adds later holds every shared channel that
/// person holds, with no act of anyone else in the channel (decision
/// 2026-10-10 property 19, T23); it writes its empty anew record there, so
/// the other person's device comes to hold its key.
#[test]
fn a_device_added_later_holds_the_shared_channels() {
    let relay = relay_started();
    let alice = person("laptop", &relay);
    let bob = person("desktop", &relay);
    makes(&alice, "design-review", &[]);
    shares(&alice, "design-review", &key_of(&bob));
    accepting(&bob, &key_of(&alice), "review").ends();
    holds_in_the_end(&[&relay, &alice, &bob], &bob, "review");

    let tablet = device_started_with_its_relays_key("tablet", &relay);
    let all = [&relay, &alice, &bob, &tablet];
    adds(&alice, &tablet, "tablet");
    has_applied(&tablet, 1, &all);
    sync_on(&tablet);
    let held = holds_in_the_end(&all, &tablet, "design-review");
    assert_eq!(held["reached"], true);
    wait_for("Bob holds the tablet's key", &all, 300, || {
        (channel_of(&bob, "review")?["keys"] == 2).then_some(())
    });
    wait_for("the tablet holds Bob's key", &all, 300, || {
        (channel_of(&tablet, "design-review")?["keys"].as_u64()? >= 2).then_some(())
    });
}

/// `accept <key> --channel` never reads a pair channel, takes a hand-over
/// or moves the device; `accept <key>` without it never takes a share
/// (decision 2026-10-10 §3.2, T13).
#[test]
fn accept_with_channel_never_moves_the_device_and_accept_without_never_takes_a_share() {
    let relay = relay_started();
    let alice = person("laptop", &relay);
    let bob = person("desktop", &relay);
    let carol = device_started_with_its_relays_key("phone", &relay);
    let all = [&relay, &alice, &bob, &carol];
    makes(&alice, "design-review", &[]);

    // Bob, under his phrase: --channel moves nothing, and types no key to
    // join devices.
    let before = person_of(&bob);
    let said = accepting(&bob, &key_of(&alice), "review").ends().1;
    assert!(said.contains("Nothing was taken yet"), "{said}");
    let after = person_of(&bob);
    assert_eq!(after["change"], before["change"]);
    assert_eq!(after["state"], before["state"]);
    assert_eq!(after["among"], before["among"]);
    assert!(
        after["accepting"]
            .as_array()
            .is_none_or(|keys| keys.is_empty()),
        "{after}"
    );
    assert_eq!(listed(&bob)["typed"].as_array().unwrap().len(), 1);

    // Carol's device, under no phrase: a share waits for its key, and the
    // device accept takes none of it.
    shares(&alice, "design-review", &key_of(&carol));
    let mut at = carol.at_terminal(&["accept", &key_of(&alice)]);
    at.says("Type yes to go on").types("yes");
    let said = at.done();
    assert!(said.contains("Nothing was taken yet"), "{said}");
    let seen = person_of(&carol);
    assert_eq!(seen["state"], "no_phrase", "{seen}");
    let shared = listed(&carol);
    assert!(
        shared["channels"].as_array().unwrap().is_empty(),
        "{shared}"
    );
    assert!(shared["typed"].as_array().unwrap().is_empty(), "{shared}");
    let _ = all;
}

/// Nothing of the person's own is handed out (decision 2026-10-10 §2.2,
/// T10): `share` of a name of the person's own is refused with `own_name`,
/// and of a channel of the person's own by its ID with `no_such_channel`;
/// no share pair channel is written at the relay.
#[test]
fn share_refuses_a_name_of_your_own() {
    let relay = relay_started();
    let alice = person("laptop", &relay);
    let bob = key_of(&relay_started_device_key());
    let dir = alice.home().join("repo");
    std::fs::create_dir_all(&dir).unwrap();
    alice.cli(&["sync", "map", &path(&dir), "github.com/owner/repo"]);

    let (ended, out, err) =
        alice.at_terminal_into_a_pipe(&["share", "github.com/owner/repo", &bob]);
    assert_eq!(ended, Some(false), "{out}{err}");
    assert!(
        err.contains(
            "\"github.com/owner/repo\" is a name of your own. Nothing of your own is ever shared"
        ),
        "{err}"
    );
    // Each channel of the person's own that the device holds, by its ID.
    let own: Vec<[u8; 32]> = {
        let db = rusqlite::Connection::open_with_flags(
            alice.data_dir().join("cordelia.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut rows = db
            .prepare("SELECT DISTINCT channel_id FROM entries")
            .unwrap();
        rows.query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert!(!own.is_empty());
    for channel in &own {
        let (ended, _, err) =
            alice.at_terminal_into_a_pipe(&["share", &hex::encode(channel), &bob]);
        assert_eq!(ended, Some(false));
        assert!(err.contains("No shared channel of yours is named"), "{err}");
    }
    assert!(listed(&alice)["shares"].as_array().unwrap().is_empty());
    let bob_key = cordelia_crypto::bech32::decode_public_key(&bob).unwrap();
    let pair =
        derive::channel_id(&derive::share_pair_secret(&identity_of(&alice), &bob_key).unwrap())
            .unwrap();
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(held_at(&relay, &pair), 0);
}

/// A key of a device that is no one's here: another person's key, made for
/// a test.
fn relay_started_device_key() -> Node {
    let mut node = node("other", "personal", None);
    node.start();
    wait_for("the other device answers", &[&node], 30, || healthy(&node));
    node
}

/// A name is never both a name of the person's own and a shared channel's
/// on one device (decision 2026-10-10 §2.2): `shared new` with a name that
/// is mapped is refused with `name_taken`, and `sync map` with a shared
/// channel's name is refused.
#[test]
fn a_name_is_never_both_on_one_device() {
    let relay = relay_started();
    let alice = person("laptop", &relay);
    let dir = alice.home().join("notes");
    std::fs::create_dir_all(&dir).unwrap();
    alice.cli(&["sync", "map", &path(&dir), "notes"]);
    let (ended, _, err) = alice.at_terminal_into_a_pipe(&["shared", "new", "notes"]);
    assert_eq!(ended, Some(false));
    assert!(
        err.contains("\"notes\" is already a name of yours: give the shared channel another."),
        "{err}"
    );
    makes(&alice, "design-review", &[]);
    let other = alice.home().join("other");
    std::fs::create_dir_all(&other).unwrap();
    let refused = alice.refused(&["sync", "map", &path(&other), "design-review"]);
    assert!(refused.contains("design-review"), "{refused}");
}

/// Every command of this slice that takes something in asks a yes at a
/// terminal, and says what it is for (decision 2026-10-10 property 18):
/// with no terminal each refuses and does nothing; with anything but yes
/// it prints that nothing was done, on standard output, and exits 0.
#[test]
fn each_command_that_takes_something_in_asks_at_a_terminal() {
    let relay = relay_started();
    let alice = person("laptop", &relay);
    makes(&alice, "design-review", &[]);
    let other = key_of(&relay_started_device_key());
    let commands: [Vec<&str>; 5] = [
        vec!["shared", "new", "review"],
        vec!["share", "design-review", &other],
        vec!["accept", &other, "--channel", "taken"],
        vec!["label", &other, "bob"],
        vec!["shared", "drop", "design-review"],
    ];
    let before = listed(&alice);
    for args in &commands {
        let said = alice.command(args);
        assert_eq!(said.status.code(), Some(1), "{args:?}");
        let err = String::from_utf8_lossy(&said.stderr);
        assert!(err.contains(NOT_A_TERMINAL), "{args:?}: {err}");
        let mut at = alice.at_terminal(args);
        at.says("Type yes to go on").types("no");
        let (success, said) = at.ends();
        assert!(success, "{args:?}: {said}");
        assert!(said.contains(NOT_A_YES), "{args:?}: {said}");
    }
    let after = listed(&alice);
    assert_eq!(after["channels"], before["channels"]);
    assert_eq!(after["shares"], before["shares"]);
    assert_eq!(after["typed"], before["typed"]);
}

/// The refusals go where §5.5 says (decision 2026-10-10 §5.5): each on
/// standard error with exit 1, but `accept --channel` that takes nothing
/// within its wait, which says so on standard output and exits 0.
#[test]
fn the_refusals_go_where_the_table_says() {
    let relay = relay_started();
    let alice = person("laptop", &relay);
    let bob = person("desktop", &relay);
    let (alice_key, bob_key) = (key_of(&alice), key_of(&bob));
    makes(&alice, "design-review", &[]);

    // `accept --channel` with the device's own key.
    let (ended, out, err) =
        bob.at_terminal_into_a_pipe(&["accept", &bob_key, "--channel", "review"]);
    assert_eq!(ended, Some(false), "{out}");
    assert!(
        err.contains("this device is one of your devices: a shared channel is handed to you by another person's device."),
        "{err}"
    );
    // A key that is no key.
    let (ended, _, err) = bob.at_terminal_into_a_pipe(&["label", "cordelia_pk1nope", "bob"]);
    assert_eq!(ended, Some(false));
    assert!(
        err.contains(
            "cordelia_pk1nope is not a device's key: give the whole key, as cordelia id prints it."
        ),
        "{err}"
    );
    // A label of more than 64 bytes.
    let long = "x".repeat(65);
    let (ended, _, err) = bob.at_terminal_into_a_pipe(&["label", &alice_key, &long]);
    assert_eq!(ended, Some(false));
    assert!(err.contains("A label is 1 to 64 bytes of text."), "{err}");
    // `label --none` of a key with no label: said on standard output.
    let (ended, out, _) = bob.at_terminal_into_a_pipe(&["label", &alice_key, "--none"]);
    assert_eq!(ended, Some(true));
    assert!(out.contains(") has no label of yours."), "{out}");

    // Nothing taken within its wait: standard output, and exit 0.
    let (success, said) = accepting(&bob, &alice_key, "review").ends();
    assert!(success, "{said}");
    assert!(
        said.contains("Nothing was taken yet. This device goes on asking until"),
        "{said}"
    );
    // Taken, and then a channel held already.
    shares(&alice, "design-review", &bob_key);
    holds_in_the_end(&[&relay, &alice, &bob], &bob, "review");
    shares(&alice, "design-review", &bob_key);
    let (success, said) = accepting(&bob, &alice_key, "again").ends();
    assert!(!success, "{said}");
    assert!(
        said.contains("Your devices hold this channel already, as \"review\": nothing was taken."),
        "{said}"
    );

    // A device of Alice's whose relay has no key: it holds the channel,
    // not reached from it, and refuses to share it, and to make one.
    let desktop = device_started("tablet", &relay);
    let all = [&relay, &alice, &bob, &desktop];
    adds(&alice, &desktop, "tablet");
    has_applied(&desktop, 1, &all);
    sync_on(&desktop);
    let held = holds_in_the_end(&all, &desktop, "design-review");
    assert_eq!(held["reached"], false);
    let lines = desktop.cli(&["shared", "list"]);
    assert!(
        lines.contains("held, not reached from this device"),
        "{lines}"
    );
    let (ended, _, err) = desktop.at_terminal_into_a_pipe(&["share", "design-review", &bob_key]);
    assert_eq!(ended, Some(false));
    assert!(
        err.contains("\"design-review\" is held on this device but not reached from it"),
        "{err}"
    );
    let (ended, _, err) = desktop.at_terminal_into_a_pipe(&["shared", "new", "mine"]);
    assert_eq!(ended, Some(false));
    assert!(
        err.contains("None of your relays is set up with its key"),
        "{err}"
    );
}

/// A shared channel lives only at relays that are, by key, the device's
/// own (decision 2026-10-10 §8.2, T19): with two relays known by key, a
/// channel made at the first is written, with its share, there and not at
/// the second; and `shared new` naming a relay the configuration does not
/// know by its key is refused with `not_own_relay`.
#[test]
fn a_shared_channel_lives_only_at_its_relays_that_are_your_own() {
    let one = relay_started();
    let two = relay_started();
    let mut alice = node("laptop", "personal", Some(one.p2p));
    alice.add_relay(&format!("127.0.0.1:{}", one.p2p), Some(&key_of(&one)));
    alice.add_relay(&format!("127.0.0.1:{}", two.p2p), Some(&key_of(&two)));
    alice.start();
    wait_for("the device answers", &[&alice], 30, || healthy(&alice));
    wait_for(
        "the device reaches its relays",
        &[&alice, &one, &two],
        60,
        || has_hot_peer(&alice),
    );
    makes_a_phrase(&alice, "laptop");
    sync_on(&alice);
    let bob = person("desktop", &one);
    let all = [&one, &two, &alice, &bob];

    let at_one = format!("127.0.0.1:{}", one.p2p);
    makes(&alice, "review", &["--relay", &at_one]);
    shares(&alice, "review", &key_of(&bob));
    accepting(&bob, &key_of(&alice), "review").ends();
    let held = holds_in_the_end(&all, &bob, "review");
    let channel = id_of(&held);
    let pair = derive::channel_id(
        &derive::share_pair_secret(
            &identity_of(&alice),
            &cordelia_crypto::bech32::decode_public_key(&key_of(&bob)).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    wait_for(
        "the first relay holds both devices' records",
        &all,
        120,
        || (held_at(&one, &channel) >= 2).then_some(()),
    );
    assert!(held_at(&one, &pair) >= 1);
    assert_eq!(held_at(&two, &channel), 0);
    assert_eq!(held_at(&two, &pair), 0);

    let (ended, _, err) =
        alice.at_terminal_into_a_pipe(&["shared", "new", "elsewhere", "--relay", "127.0.0.1:9"]);
    assert_eq!(ended, Some(false));
    assert!(
        err.contains("127.0.0.1:9 is not one of your relays known by its key, and a shared channel lives only at those: nothing was done."),
        "{err}"
    );
}

/// Where the relay holds two shares from the typed key for this device,
/// `accept --channel` takes none, says so and exits 1; once the other is
/// written over, `accept` again takes the one (decision 2026-10-10 §3.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn more_than_one_waiting_share_takes_none() {
    let stand_in = stand_in_relay();
    let stand_key = cordelia_crypto::bech32::decode_public_key(&stand_in.key).unwrap();
    let (stand_port, stand_text) = (stand_in.port, stand_in.key.clone());
    let alice = NodeIdentity::generate().unwrap();
    let alice_key = cordelia_crypto::bech32::encode_public_key(&alice.public_key()).unwrap();

    let bob = tokio::task::spawn_blocking(move || {
        let mut bob = node("desktop", "personal", Some(stand_port));
        bob.add_relay(&format!("127.0.0.1:{stand_port}"), Some(&stand_text));
        bob.start();
        wait_for("the device answers", &[&bob], 30, || healthy(&bob));
        wait_for("the device reaches the stand-in", &[&bob], 60, || {
            has_hot_peer(&bob)
        });
        makes_a_phrase(&bob, "desktop");
        sync_on(&bob);
        bob
    })
    .await
    .unwrap();
    let bob_key = cordelia_crypto::bech32::decode_public_key(&key_of(&bob)).unwrap();
    let pair_secret = derive::share_pair_secret(&alice, &bob_key).unwrap();
    let pair = derive::channel_id(&pair_secret).unwrap();
    let card = |seed: u8| {
        let mut bytes = vec![seed; 32];
        bytes.extend_from_slice(&Relays::new(&[stand_key]).unwrap().to_bytes());
        Card::from_bytes(&bytes).unwrap()
    };
    let now = chrono::Utc::now().timestamp() as u64;
    let share = |card: &Card, rev: u64, delete: bool| {
        let value = match delete {
            true => Value::Delete,
            false => Value::Other(
                Share {
                    made: now,
                    for_key: bob_key,
                    card: card.clone(),
                }
                .to_value(),
            ),
        };
        let inside = Inside {
            name: share_name(&card.channel_id().unwrap()),
            value,
            chain: Some(Vec::new()),
        };
        Entry::seal(&pair_secret, &alice, rev, &inside).unwrap()
    };
    let (one, two) = (card(1), card(2));
    stand_in.serves(pair, &[share(&one, now, false), share(&two, now, false)]);

    let typed = alice_key.clone();
    let bob = tokio::task::spawn_blocking(move || {
        let (success, said) = accepting(&bob, &typed, "review").ends();
        assert!(!success, "{said}");
        assert!(
            said.contains("has 2 shares waiting for this device: nothing was taken. Ask them to share the one channel again"),
            "{said}"
        );
        assert!(listed(&bob)["channels"].as_array().unwrap().is_empty());
        bob
    })
    .await
    .unwrap();

    // Alice shares the second again, which writes over the first.
    stand_in.serves(
        pair,
        &[share(&one, now + 1, true), share(&two, now + 1, false)],
    );
    let words = cordelia_crypto::fingerprint::shown(&two.channel_id().unwrap());
    tokio::task::spawn_blocking(move || {
        let said = accepting(&bob, &alice_key, "review").ends().1;
        let held = holds_in_the_end(&[&bob], &bob, "review");
        assert_eq!(held["words"], words.as_str(), "{said}");
    })
    .await
    .unwrap();
}
