//! The test of the commands' words (decision 2026-10-10 §13, "The
//! commands' words"): the texts of §5.2 to §5.5 that the node words, byte
//! for byte. Each text is written here as the record writes it, with its
//! placeholders in angle brackets; the test checks that the record says
//! each line of it, and that the node says it, filled in. A text the record
//! changes, or the node, fails here until the other follows. The command's
//! own lines (the summary, `accept`'s wait, `shared anew`'s question and
//! the help of `cordelia channels`) are tested beside the command
//! (`cordelia-node/src/shared_cmd.rs`).

use super::*;
use crate::several::Several;
use crate::shared::tests::{bob, member};
use crate::shared_routes::{UnsubscribeRequest, subscribe_plan, unsubscribe_of};
use cordelia_storage::meta;
use serde_json::json;

/// The record, as it is in the repository.
const RECORD: &str =
    include_str!("../../../../docs/decisions/2026-10-10-a-shared-channel-for-messages.md");

/// The relay of the record's examples, known by its key.
const AT: [u8; 32] = [3; 32];

fn relays() -> Vec<OwnRelay> {
    vec![OwnRelay {
        name: "relay.example.org:9474".into(),
        key: AT,
    }]
}

/// `template`, a text as the record writes it, with each placeholder in
/// angle brackets filled by `values` in turn: a value that is the
/// placeholder itself leaves it as it is, as the node prints it. Each line
/// of the template must be in the record.
fn says(template: &str, values: &[&str]) -> String {
    for line in template.lines() {
        assert!(RECORD.contains(line), "the record does not say: {line}");
    }
    let mut out = String::new();
    let mut rest = template;
    let mut values = values.iter();
    while let Some(at) = rest.find('<') {
        let Some(end) = rest[at..].find('>') else {
            break;
        };
        out.push_str(&rest[..at]);
        let value = values
            .next()
            .unwrap_or_else(|| panic!("no value for {} in {template}", &rest[at..at + end + 1]));
        out.push_str(value);
        rest = &rest[at + end + 1..];
    }
    out.push_str(rest);
    assert!(values.next().is_none(), "a value too many for {template}");
    out
}

/// The line of a refusal.
fn line_of<T: std::fmt::Debug>(out: Out<T>) -> (&'static str, String) {
    match out {
        Err(Failed::Refused(refusal)) => (refusal.word, refusal.line),
        other => panic!("not refused: {other:?}"),
    }
}

/// One of Bob's devices, with sync on, mapping `github.com/owner/repo`
/// from `/home/bob/repo`.
fn device() -> Several {
    let s = bob(1);
    let conn = &s[0].conn;
    crate::names::say(conn, &s[0].identity, "github.com/owner/repo", s.now).unwrap();
    let mapped = json!([{ "folder": "/home/bob/repo", "name": "github.com/owner/repo" }]);
    meta::set(conn, meta::SYNC_CLAUDE_MAPPINGS, &mapped.to_string()).unwrap();
    s
}

/// The texts of §5.2 to §5.5 that the node words, byte for byte.
#[test]
fn the_shared_commands_say_what_this_record_says() {
    let s = device();
    let now = s.now + 10;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let own = encode_public_key(&s.key(0)).unwrap();
    let alice = member(1);
    let alice_key = encode_public_key(&alice.public_key()).unwrap();
    let alice_six = six_words(&alice.public_key());
    let relay_words = fingerprint::shown(&AT);

    // §5.2, `shared new design-review`, before its yes and after it.
    let plan = new_plan(conn, &relays(), "design-review", &[]).unwrap();
    assert_eq!(
        plan.asks,
        says(
            "This makes a channel shared between people, filed on your devices as \
             \"design-review\".\n\
             It carries messages between your agents and other people's agents, and nothing \
             else: never memory.\n\
             It lives at:\n  relay.example.org:9474 (<four words>)\n\
             Whoever you share it with holds it as fully as you do, and can share it on. Nobody \
             is taken out of it except by making it anew.",
            &[&relay_words]
        )
    );
    let made = make_new(conn, identity, &plan.what, now).unwrap();
    let channel = filed(conn).unwrap()[0].channel;
    let words = channel_words(&channel);
    assert_eq!(
        made,
        says(
            "Made \"design-review\": channel <four words>. No folder subscribes to it: in a \
             folder, run cordelia subscribe design-review",
            &[&words]
        )
    );

    // `share design-review <key>`, before its yes and after it.
    let plan = share_plan(
        conn,
        identity,
        &relays(),
        "design-review",
        &alice_key,
        None,
        now,
    )
    .unwrap();
    assert_eq!(
        plan.asks,
        says(
            "This hands the shared channel \"design-review\" (channel <four words>) to the \
             device (<six words>) <\"label\", or no label of yours>.\n\
             Before you go on, have the person whose device it is read you the six words that \
             cordelia id --words prints there, by another way than the one the key came by: a \
             call, or in person. They must be these: <six words>. If they are not, someone has \
             put their own key in its place: stop here.\n\
             Whoever holds that device reads every message written there from now on, and can \
             write there and hand it on, until the channel is made anew without them.\n\
             Nothing of your own goes with it: no memory, no name of yours, and no other \
             channel.",
            &[&words, &alice_six, "no label of yours", &alice_six]
        )
    );
    let lines = make_share(conn, identity, &relays(), &plan.what, now).unwrap();
    assert_eq!(
        lines[..4].join("\n"),
        says(
            "Handed over. On the other device, within the hour, run:\n  cordelia accept <this \
             device's key> --channel <a name of their choosing>\n\
             It lives at relay.example.org:9474 (<four words>). The other device takes it only \
             where that relay, by its key, is one of its own.\n\
             It prints these words for the channel once it has taken it: <four words>. They are \
             its name, and prove nothing.",
            &[&own, "<a name of their choosing>", &relay_words, &words]
        )
    );
    // §5.4, the lines after it: nobody else wrote there yet.
    assert_eq!(
        lines[4],
        says(
            "Keys that wrote here, in \"<name>\": unchanged since <date>: <n> keys, <m> of them \
             labelled by you. Anyone a member handed the channel to reads it too, unseen.",
            &["design-review", &date_of(now), "0", "0"]
        )
    );

    // `accept <key> --channel review-with-alice`, before its yes.
    let plan = accept_plan(
        conn,
        identity,
        &relays(),
        &alice_key,
        "review-with-alice",
        now,
    )
    .unwrap();
    assert_eq!(
        plan.asks,
        says(
            "This device will take, within the hour, one shared channel that the device (<six \
             words>) <\"label\", or no label of yours> hands it, and file it as \
             \"review-with-alice\" on every device of yours.\n\
             Before you go on, have the person whose device it is read you the six words that \
             cordelia id --words prints there, by another way than the one the key came by: a \
             call, or in person. They must be these: <six words>. If they are not, someone has \
             put their own key in its place: stop here.\n\
             It is asked for at your relays that have a key, and taken only where it lives at \
             them:\n  relay.example.org:9474 (<four words>)\n\
             It carries messages from other people's agents, and never memory. No agent of yours \
             is shown anything from it until you subscribe a folder: cordelia subscribe \
             review-with-alice",
            &[&alice_six, "no label of yours", &alice_six, &relay_words]
        )
    );

    // `label <key> bob`, before its yes and after it.
    let Ok(plan) = label_plan(conn, identity, &alice_key, Some("bob"), now).unwrap() else {
        panic!("no plan");
    };
    assert_eq!(
        plan.asks,
        says(
            "Your devices will show the device (<six words>) as \"bob\" in every shared \
             channel, show its messages before those of keys you have not labelled, and keep \
             room for them.\n\
             Label a key only once its person has read you these six words by another way than \
             the one the key came by.",
            &[&alice_six]
        )
    );
    assert_eq!(
        make_label(conn, identity, &plan.what, now).unwrap(),
        says(
            "Labelled (<six words>) \"bob\" on every device of yours.",
            &[&alice_six]
        )
    );

    // `subscribe review-with-alice`, in the folder of github.com/owner/repo,
    // with the channel filed under the record's name.
    rename(
        conn,
        identity,
        "design-review",
        "review-with-alice",
        None,
        now,
    )
    .unwrap();
    let Ok(plan) =
        subscribe_plan(conn, identity, "/home/bob/repo", "review-with-alice", None).unwrap()
    else {
        panic!("no plan");
    };
    assert_eq!(
        plan.asks,
        says(
            "The agent of this folder, github.com/owner/repo, will be shown a count of the \
             messages in the shared channel \"review-with-alice\", on every device of yours \
             where github.com/owner/repo is mapped. It can read them, and write there with \
             --channel review-with-alice.\n\
             They come from other people's agents: <n> keys wrote there, <m> of them labelled \
             by you. Anyone a member handed the channel to reads it too, unseen.",
            &["0", "0"]
        )
    );
    act(
        conn,
        identity,
        &standing(conn).unwrap(),
        Do::Subscribe(plan.what.clone()),
        now,
    )
    .unwrap();
    let Err(already) =
        subscribe_plan(conn, identity, "/home/bob/repo", "review-with-alice", None).unwrap()
    else {
        panic!("subscribed twice");
    };
    assert_eq!(
        already,
        says(
            "<agent> subscribes to \"<name>\" already.",
            &["github.com/owner/repo", "review-with-alice"]
        )
    );
    let unsubscribing = UnsubscribeRequest {
        folder: Some("/home/bob/repo".into()),
        agent: None,
        name: "review-with-alice".into(),
        words: None,
    };
    assert_eq!(
        unsubscribe_of(conn, identity, &unsubscribing, now).unwrap(),
        says(
            "Unsubscribed: github.com/owner/repo from \"review-with-alice\". This agent is \
             shown nothing from it from now on, on every device of yours.",
            &[]
        )
    );
    assert_eq!(
        unsubscribe_of(conn, identity, &unsubscribing, now).unwrap(),
        says(
            "<agent> does not subscribe to \"<name>\".",
            &["github.com/owner/repo", "review-with-alice"]
        )
    );

    // `shared drop review-with-alice`, before its yes.
    assert_eq!(
        drop_plan(conn, identity, "review-with-alice", None, now)
            .unwrap()
            .asks,
        says(
            "This stops every device of yours holding the shared channel \"review-with-alice\". \
             Its other members are not told, and still hold it. What it held is taken off your \
             devices.",
            &[]
        )
    );

    // §5.5, the refusals the node words, each with its word.
    let refusal =
        |word: &str, template: &str, values: &[&str]| (word.to_string(), says(template, values));
    let got = |(word, line): (&'static str, String)| (word.to_string(), line);
    assert_eq!(
        got(line_of(new_plan(conn, &relays(), "review-with-alice", &[]))),
        refusal(
            "name_taken",
            "\"<name>\" is already a name of yours: give the shared channel another.",
            &["review-with-alice"]
        )
    );
    assert_eq!(
        got(line_of(new_plan(conn, &relays(), "Not A Name!", &[]))),
        refusal(
            "not_a_name",
            "\"<name>\" is not a name: use letters, digits and / . _ - only.",
            &["Not A Name!"]
        )
    );
    assert_eq!(
        got(line_of(new_plan(
            conn,
            &relays(),
            "other",
            &["relay.other.org:9474".into()]
        ))),
        refusal(
            "not_own_relay",
            "<relay> is not one of your relays known by its key, and a shared channel lives \
             only at those: nothing was done.",
            &["relay.other.org:9474"]
        )
    );
    assert_eq!(
        got(line_of(new_plan(conn, &[], "other", &[]))),
        refusal(
            "no_keyed_relay",
            "None of your relays is set up with its key, and a shared channel lives only at \
             relays known by their key: add a relay's key to your configuration.",
            &[]
        )
    );
    let twice = vec!["relay.example.org:9474".to_string(); 2];
    assert_eq!(
        got(line_of(new_plan(conn, &relays(), "other", &twice))),
        refusal(
            "",
            "A shared channel lives at one or two of your relays, each once.",
            &[]
        )
    );
    assert_eq!(
        got(line_of(share_plan(
            conn,
            identity,
            &relays(),
            "github.com/owner/repo",
            &alice_key,
            None,
            now
        ))),
        refusal(
            "own_name",
            "\"<name>\" is a name of your own. Nothing of your own is ever shared: only a \
             channel made with cordelia shared new, or taken with cordelia accept --channel, \
             is.",
            &["github.com/owner/repo"]
        )
    );
    assert_eq!(
        got(line_of(share_plan(
            conn,
            identity,
            &relays(),
            "nothing",
            &alice_key,
            None,
            now
        ))),
        refusal(
            "no_such_channel",
            "No shared channel of yours is named \"<name>\".",
            &["nothing"]
        )
    );
    assert_eq!(
        got(line_of(share_plan(
            conn,
            identity,
            &relays(),
            "review-with-alice",
            &alice_key,
            Some("a b c d"),
            now
        ))),
        refusal(
            "no_such_channel",
            "No shared channel of yours named \"<name>\" has the words <words>.",
            &["review-with-alice", "a b c d"]
        )
    );
    let share_own = share_plan(
        conn,
        identity,
        &relays(),
        "review-with-alice",
        &own,
        None,
        now,
    );
    assert_eq!(
        got(line_of(share_own)),
        refusal(
            "own_device",
            "<sender form> is one of your devices, and holds every shared channel of yours \
             already.",
            &["this device"]
        )
    );
    let label_own = label_plan(conn, identity, &own, Some("me"), now).map(|plan| plan.map(|_| ()));
    assert_eq!(
        got(line_of(label_own)),
        refusal(
            "own_device",
            "<sender form> is one of your devices: it has the label you gave it as a device, \
             and is not labelled here.",
            &["this device"]
        )
    );
    let accept_own = accept_plan(conn, identity, &relays(), &own, "taken", now);
    assert_eq!(
        got(line_of(accept_own)),
        refusal(
            "own_device",
            "<sender form> is one of your devices: a shared channel is handed to you by \
             another person's device.",
            &["this device"]
        )
    );
    assert_eq!(
        got(line_of(accept_plan(
            conn,
            identity,
            &relays(),
            "cordelia_pk1xyz",
            "taken",
            now
        ))),
        refusal(
            "",
            "<key> is not a device's key: give the whole key, as cordelia id prints it.",
            &["cordelia_pk1xyz"]
        )
    );
    let long = "x".repeat(65);
    let bad = label_plan(conn, identity, &alice_key, Some(&long), now).map(|plan| plan.map(|_| ()));
    assert_eq!(
        got(line_of(bad)),
        refusal("bad_label", "A label is 1 to 64 bytes of text.", &[])
    );
    // `label --none` of a key with no label: its words alone stand for the
    // sender form, which would say "no label of yours" twice.
    let carol = member(2);
    let carol_key = encode_public_key(&carol.public_key()).unwrap();
    let Err(no_label) = label_plan(conn, identity, &carol_key, None, now).unwrap() else {
        panic!("a plan");
    };
    assert_eq!(
        no_label,
        says(
            "<sender form> has no label of yours.",
            &[&format!("({})", six_words(&carol.public_key()))]
        )
    );
    // Not reached: no relay of the card is one of the device's own now.
    assert_eq!(
        got(line_of(share_plan(
            conn,
            identity,
            &[],
            "review-with-alice",
            &alice_key,
            None,
            now
        ))),
        refusal(
            "not_reached",
            "\"<name>\" is held on this device but not reached from it: write there from a \
             device of yours that reaches its relays.",
            &["review-with-alice"]
        )
    );
    // Eight shares waiting: a ninth is refused.
    for n in 10..17 {
        let key = encode_public_key(&member(n).public_key()).unwrap();
        let plan = share_plan(
            conn,
            identity,
            &relays(),
            "review-with-alice",
            &key,
            None,
            now,
        )
        .unwrap();
        make_share(conn, identity, &relays(), &plan.what, now).unwrap();
    }
    let ninth = encode_public_key(&member(20).public_key()).unwrap();
    assert_eq!(
        got(line_of(share_plan(
            conn,
            identity,
            &relays(),
            "review-with-alice",
            &ninth,
            None,
            now
        ))),
        refusal(
            "too_many_shares",
            "This device has 8 shares waiting to be taken, which is the most: wait for one to be \
             taken, or for its two hours to end.",
            &[]
        )
    );
    // Eight keys typed for channels: a ninth is refused.
    for n in 30..38 {
        let typed = TypeFor {
            key: member(n).public_key(),
            name: format!("typed-{n}"),
        };
        type_for_a_channel(conn, &typed, now).unwrap();
    }
    assert_eq!(
        got(line_of(accept_plan(
            conn,
            identity,
            &relays(),
            &ninth,
            "ninth",
            now
        ))),
        refusal(
            "too_many_typed",
            "This device is asking for 8 shared channels already: wait for one, or for its hour \
             to end.",
            &[]
        )
    );
    // Sixteen channels held: a seventeenth is refused.
    for n in 1..16 {
        let plan = new_plan(conn, &relays(), &format!("c{n}"), &[]).unwrap();
        make_new(conn, identity, &plan.what, now).unwrap();
    }
    assert_eq!(
        got(line_of(new_plan(conn, &relays(), "c16", &[]))),
        refusal(
            "too_many_channels",
            "Your devices hold 16 shared channels, which is the most: drop one first with \
             cordelia shared drop <name>.",
            &["<name>"]
        )
    );
    // A channel not yet clean (decision 2026-10-24, rule 25).
    assert_eq!(
        crate::shared_anew::not_clean_line("review-with-alice"),
        says(
            "\"<name>\" was held by a device that was removed: make it anew with cordelia \
             shared anew <name>",
            &["review-with-alice", "review-with-alice"]
        )
    );
    // `shared anew` on a channel past a bound (§3.4, §7).
    assert_eq!(
        crate::shared_anew::past_a_bound_line("review-with-alice", 3),
        says(
            "You could not list <n> keys of \"<name>\", nor anyone who wrote there after it went \
             past a bound: share the new channel with them again.",
            &["3", "review-with-alice"]
        )
    );
    // With sync off, every command is refused so.
    meta::remove(conn, meta::SYNC_CLAUDE_DIR).unwrap();
    assert_eq!(line_of(new_plan(conn, &relays(), "x", &[])).0, "sync_off");
}

/// A removed key (§5.5, `removed_key`): its words alone stand for the
/// sender form, since it is no device of another person's and none of the
/// person's own.
#[test]
fn a_removed_key_is_refused_in_the_records_words() {
    let mut s = bob(2);
    s.change(0, &[0], &[1]);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    meta::set(conn, meta::SYNC_CLAUDE_DIR, "/home/bob/.claude").unwrap();
    let removed = encode_public_key(&s.key(1)).unwrap();
    let (word, line) = line_of(accept_plan(
        conn,
        identity,
        &relays(),
        &removed,
        "taken",
        now,
    ));
    assert_eq!(word, "removed_key");
    assert_eq!(
        line,
        says(
            "<sender form> is a device you removed: nothing is handed to it, taken from it or \
             labelled.",
            &[&format!("({})", six_words(&s.key(1)))]
        )
    );
}
