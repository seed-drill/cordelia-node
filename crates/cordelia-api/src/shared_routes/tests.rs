//! Tests of subscribing and of messages in a shared channel (decision
//! 2026-10-10 §4, §5.3 to §5.6, §6.1, §6.2, §6.4), in-process.

use super::*;
use crate::lists::Do;
use crate::several::Several;
use crate::shared::tests::{Shared, acts, bob, given, holds, member, message, out, says};
use crate::shared_pass::Usable;
use cordelia_crypto::entry::Value as EntryValue;
use cordelia_crypto::message::{To, message_name, message_rev};
use cordelia_storage::meta;

/// The names each device of these tests syncs, each mapped from a folder of
/// its own.
const NAMES: [&str; 2] = ["notes", "work"];

/// The relay of every channel of these tests: the device knows it by key.
const AT: [u8; 32] = [3; 32];

fn folder(name: &str) -> String {
    format!("/home/bob/{name}")
}

/// `count` devices of Bob's, each with sync on, syncing and mapping each of
/// [`NAMES`], each having been given what every other holds; device 0 holds
/// the shared channel of seed 7 as `review`, and every other takes it from
/// its list.
fn devices(count: u16) -> (Several, Shared) {
    let mut s = bob(count);
    for n in 0..usize::from(count) {
        let conn = &s[n].conn;
        for name in NAMES {
            crate::names::say(conn, &s[n].identity, name, s.now).unwrap();
        }
        let mapped: Vec<Value> = NAMES
            .iter()
            .map(|name| json!({ "folder": folder(name), "name": name }))
            .collect();
        meta::set(
            conn,
            meta::SYNC_CLAUDE_MAPPINGS,
            &Value::from(mapped).to_string(),
        )
        .unwrap();
    }
    let now = s.now;
    let channel = holds(&s, 0, 7, "review", now);
    let all: Vec<usize> = (0..usize::from(count)).collect();
    s.meet(&all);
    follow_all(&s, now);
    (s, channel)
}

/// Each device works its lists out again, as at a whole fetch.
fn follow_all(s: &Several, now: i64) {
    for n in 0..s.machines.len() {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(s, n, now);
    }
}

/// Device `n` subscribes the agent `agent` to `channel`, or ends it.
fn subscribes(s: &Several, n: usize, channel: &Shared, agent: &str, on: bool, now: i64) {
    let subscription = Subscription {
        channel: channel.id,
        agent: agent.into(),
        subscribed: on,
    };
    acts(s, n, Do::Subscribe(subscription), now);
}

fn at(now: i64) -> SendAt {
    SendAt {
        now,
        no_place: false,
        per_folder_per_hour: 20,
        own_relays: vec![OwnRelay {
            name: "relay.example.org:9474".into(),
            key: AT,
        }],
    }
}

fn asking(from: &str, channel: &str, body: &str) -> SendRequest {
    SendRequest {
        folder: folder(from),
        channel: channel.into(),
        words: None,
        reply: None,
        asks: true,
        link: None,
        body: body.into(),
    }
}

/// Device `n` sends `request` at `now`, as a channel fetched since the start.
fn sends(
    s: &Several,
    n: usize,
    request: &SendRequest,
    now: i64,
) -> Result<(String, String, Vec<String>), NotSentHere> {
    send_of(&s[n].conn, &s[n].identity, request, &at(now), |_, _| true)
}

/// The word device `n` refuses `request` with.
fn refused(s: &Several, n: usize, request: &SendRequest, now: i64) -> &'static str {
    match sends(s, n, request, now) {
        Err(NotSentHere::Refused(why, _)) => why.word(),
        Err(NotSentHere::Failed(Failed::Refused(refusal))) => refusal.word,
        other => panic!("{other:?}"),
    }
}

/// The IDs device `n` shows unread to `agent` at `now`.
fn unread(s: &Several, n: usize, agent: &str, now: i64) -> Vec<String> {
    seen::unread(&s[n].conn, &s[n].identity, agent, now)
        .unwrap()
        .into_iter()
        .map(|seen| hex::encode(seen.id))
        .collect()
}

/// `read <id>` of the agent of `agent` on device `n`.
fn reads(s: &Several, n: usize, agent: &str, id: &str, now: i64) -> Result<Value, NotShown> {
    let asked = ReadRequest {
        folder: folder(agent),
        id: Some(id.into()),
        next: false,
    };
    read_of(&s[n].conn, &s[n].identity, &asked, now, true).map(|read| read.unwrap())
}

/// The ID of the message of `author` at `number` saying `body`, as device
/// `n` holds it in `channel`.
fn id_given(
    s: &Several,
    n: usize,
    channel: &Shared,
    entry_number: u64,
    body: &str,
    now: i64,
) -> String {
    let entry = message(&member(1), channel, entry_number, body, now);
    given(s, n, &entry, now);
    let value = says(body, now).to_value().unwrap();
    hex::encode(cordelia_crypto::message::message_id(
        &member(1).public_key(),
        &value,
    ))
}

/// A shared channel filed as `review`, and no name `review` (decision
/// 2026-10-10 §2.2, §4.2): a publish under `review` is refused and writes
/// nothing, and the one function that sends, given `Address::Own` with the
/// name `review`, refuses it as no name: `--to` looks among the person's
/// own names alone.
#[test]
fn a_shared_channels_name_is_no_name_to_publish_or_to_send() {
    let (s, _) = devices(1);
    let now = s.now + 10;
    let before = s[0].stored().len();
    let write = crate::publish::Write {
        name: "review",
        file: "a.md",
        value: EntryValue::Text("x".into()),
        planned: crate::publish::PlannedAgainst::NoVersion,
        merge: None,
    };
    assert!(crate::publish::publish(&s[0].conn, &s[0].identity, &write, now).is_err());
    assert_eq!(s[0].stored().len(), before);
    let request = Request {
        from: "notes".into(),
        address: Address::Own(To::Name("review".into())),
        asks: false,
        link: None,
        body: "x".into(),
        thread: [0; 16],
        answers: [0; 16],
    };
    let sends_at = At {
        now,
        fetched: true,
        no_place: false,
        mapped: true,
        per_folder_per_hour: 20,
        shared_fetched: true,
        shared_reached: true,
    };
    match sender::send(
        &s[0].conn,
        &s[0].identity,
        &sends_at,
        &request,
        sender::no_reply,
    ) {
        Err(NotSent::Refused(Refused::NoSuchName(name))) => assert_eq!(name, "review"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s[0].stored().len(), before);
}

/// Each route makes only its own kind of address (decision 2026-10-10
/// §4.2, §5.6): the messages record's route given a `channel` field passes
/// it over and sends to the person's own name it also names, and nothing
/// reaches the shared channel; this record's route given `to` refuses the
/// body.
#[test]
fn each_route_makes_only_its_own_kind_of_address() {
    let (s, channel) = devices(1);
    let now = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, now);
    let own: crate::messages::SendRequest = serde_json::from_value(json!({
        "folder": folder("notes"),
        "to": "work",
        "channel": "review",
        "body": "to work",
        "link": null,
        "reply": null,
    }))
    .unwrap();
    let at_own = crate::messages::SendAt {
        now,
        fetched: true,
        no_place: false,
        per_folder_per_hour: 20,
    };
    let before = s[0].stored_in(&channel.secret);
    let sent =
        crate::messages::send_of(&s[0].conn, &s[0].identity, &own, &at_own, |_| false).unwrap();
    assert_eq!(sent.to.as_deref(), Some("work"));
    // Nothing reached the shared channel.
    assert_eq!(s[0].stored_in(&channel.secret), before);
    let shared: Result<SendRequest, _> = serde_json::from_value(json!({
        "folder": folder("notes"),
        "channel": "review",
        "to": "work",
        "body": "to work",
    }));
    assert!(
        shared.is_err(),
        "a shared send body that says `to` is refused"
    );
}

/// No command makes a subscription item but `subscribe` and `unsubscribe`
/// (decision 2026-10-10 §4.1): not `shared new`, not a label, a rename, a
/// drop, a send or a read.
#[test]
fn only_subscribe_subscribes() {
    let (s, channel) = devices(1);
    let now = s.now + 10;
    let count = |s: &Several| crate::lists::holds(&s[0].conn).unwrap().subscriptions.len();
    let identity = &s[0].identity;
    let conn = &s[0].conn;
    let new = sharing::New {
        name: "design".into(),
        relays: at(now).own_relays,
    };
    sharing::make_new(conn, identity, &new, now).unwrap();
    sharing::rename(conn, identity, "design", "design-2", None, now + 1).unwrap();
    let labelling = sharing::Labelling {
        key: member(1).public_key(),
        label: Some("alice".into()),
    };
    sharing::make_label(conn, identity, &labelling, now + 2).unwrap();
    assert_eq!(
        refused(&s, 0, &asking("notes", "review", "x"), now + 3),
        "not_subscribed"
    );
    assert_eq!(count(&s), 0);
    let plan = subscribe_plan(conn, identity, &folder("notes"), "review", None)
        .unwrap()
        .unwrap();
    assert_eq!(plan.what.agent, "notes");
    assert_eq!(count(&s), 0, "the look subscribes nothing");
    subscribes(&s, 0, &channel, "notes", true, now + 4);
    assert_eq!(count(&s), 1);
    let ended = UnsubscribeRequest {
        folder: None,
        agent: Some("notes".into()),
        name: "review".into(),
        words: None,
    };
    let said = unsubscribe_of(conn, identity, &ended, now + 5).unwrap();
    assert!(
        said.starts_with("Unsubscribed: notes from \"review\"."),
        "{said}"
    );
    let holds = crate::lists::holds(conn).unwrap();
    assert_eq!(holds.subscriptions.len(), 1);
    assert!(!holds.subscriptions[0].0.item.subscribed);
    let again = unsubscribe_of(conn, identity, &ended, now + 6).unwrap();
    assert_eq!(again, "notes does not subscribe to \"review\".");
    let dropped = sharing::drop_plan(conn, identity, "design-2", None, now + 7).unwrap();
    sharing::make_drop(conn, identity, &dropped.what, "design-2", now + 7).unwrap();
    assert_eq!(crate::lists::holds(conn).unwrap().subscriptions.len(), 1);
}

/// A subscription starts when this device first takes it (decision
/// 2026-10-10 §4.1): what was written before, and what came while the
/// folder did not subscribe, is in `log` only; what comes after is shown.
#[test]
fn a_subscription_starts_when_this_device_first_takes_it() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    let before = id_given(&s, 0, &channel, 1, "before", t);
    subscribes(&s, 0, &channel, "notes", true, t + 1);
    assert!(unread(&s, 0, "notes", t + 2).is_empty());
    let after = id_given(&s, 0, &channel, 2, "after", t + 3);
    assert_eq!(unread(&s, 0, "notes", t + 4), std::slice::from_ref(&after));
    // The start is kept while the subscription stays.
    follow_all(&s, t + 5);
    assert_eq!(unread(&s, 0, "notes", t + 6), std::slice::from_ref(&after));
    subscribes(&s, 0, &channel, "notes", false, t + 7);
    let between = id_given(&s, 0, &channel, 3, "between", t + 8);
    subscribes(&s, 0, &channel, "notes", true, t + 9);
    assert!(unread(&s, 0, "notes", t + 10).is_empty());
    assert!(matches!(
        reads(&s, 0, "notes", &between, t + 10),
        Err(NotShown::Refused(Refused::NoSuchMessage(_)))
    ));
    // `log` at a terminal lists all three.
    let asked = LogRequest {
        folder: None,
        terminal: true,
        mark: Vec::new(),
    };
    let log = log_of(
        &s[0].conn,
        &s[0].identity,
        &asked,
        &at(t).own_relays,
        t + 10,
    )
    .unwrap();
    let listed: Vec<&str> = log["channels"][0]["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["id"].as_str().unwrap())
        .collect();
    for id in [&before, &after, &between] {
        assert!(listed.contains(&id.as_str()), "{listed:?}");
    }
    // Away from a terminal, nothing it says.
    id_given(&s, 0, &channel, 4, "later", t + 11);
    let asked = LogRequest {
        folder: Some(folder("notes")),
        terminal: false,
        mark: Vec::new(),
    };
    let log = log_of(
        &s[0].conn,
        &s[0].identity,
        &asked,
        &at(t).own_relays,
        t + 10,
    )
    .unwrap();
    let messages = log["channels"][0]["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1, "{log}");
    assert!(messages.iter().all(|message| message["body"].is_null()));
}

/// The marks of shared messages are in a list of their own, `sread/`, in
/// the person's messages channel, and cross a statement (decision
/// 2026-10-10 §6.1): one device's agent reads, its list is written and the
/// other device takes it, so its agent of that name is not shown the
/// message; the `read/` list holds no such mark; after a statement the list
/// is written again in the new generation from the table.
#[test]
fn shared_marks_have_a_list_of_their_own_and_cross_a_statement() {
    let (mut s, channel) = devices(3);
    let t = s.now + 10;
    for n in 0..3 {
        subscribes(&s, n, &channel, "notes", true, t);
    }
    follow_all(&s, t);
    let id = {
        let entry = message(&member(1), &channel, 1, "shared", t + 1);
        for n in 0..3 {
            given(&s, n, &entry, t + 1);
        }
        let value = says("shared", t + 1).to_value().unwrap();
        hex::encode(cordelia_crypto::message::message_id(
            &member(1).public_key(),
            &value,
        ))
    };
    assert_eq!(unread(&s, 1, "notes", t + 2), std::slice::from_ref(&id));
    reads(&s, 0, "notes", &id, t + 2).unwrap();
    assert!(unread(&s, 0, "notes", t + 3).is_empty());
    assert_eq!(unread(&s, 1, "notes", t + 3), std::slice::from_ref(&id));
    // Its list is written, in `sread/`; its `read/` list is not.
    assert!(
        seen::write_list(&s[0].conn, &s[0].identity, t + 3, true)
            .unwrap()
            .is_none()
    );
    s.pass(0, 1);
    assert!(unread(&s, 1, "notes", t + 4).is_empty());
    let read_lists: i64 = s[1]
        .conn
        .query_row("SELECT COUNT(*) FROM message_lists", [], |row| row.get(0))
        .unwrap();
    assert_eq!(read_lists, 0);
    // A statement: device 0's list is written again in the new generation,
    // from its table, and device 2 takes it there.
    s.change(0, &[0, 1, 2], &[]);
    s.meet(&[0, 1, 2]);
    let written = seen::write_list(&s[0].conn, &s[0].identity, t + 5, true).unwrap();
    assert!(written.is_some());
    s.pass(0, 2);
    assert!(unread(&s, 2, "notes", t + 6).is_empty());
}

/// The hold of a shared channel is the loop the agent is in (decision
/// 2026-10-10 §6.4): ten messages that others write among themselves hold
/// nothing; ten that answer its message, or are in a thread it wrote in,
/// hold it, until a person here reads them.
#[test]
fn the_hold_counts_only_the_loop_this_agent_is_in() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    // Both agents subscribe from the start, so that both are shown every
    // message here.
    subscribes(&s, 0, &channel, "notes", true, t);
    subscribes(&s, 0, &channel, "work", true, t);
    for n in 1..=10 {
        id_given(&s, 0, &channel, n, &format!("among themselves {n}"), t + 1);
    }
    let (mine, _, _) = sends(&s, 0, &asking("notes", "review", "mine"), t + 2).unwrap();
    let mine: [u8; 16] = hex::decode(&mine).unwrap().try_into().unwrap();
    for n in 11..=19 {
        let mut answer = says(&format!("answer {n}"), t + 3);
        answer.answers = mine;
        answer.thread = mine;
        let name = message_name(&member(1).public_key(), n).unwrap();
        let entry = crate::several::entry_by(
            &member(1),
            &channel.secret,
            message_rev(n).unwrap(),
            &name,
            EntryValue::Other(answer.to_value().unwrap()),
            &[],
        );
        given(&s, 0, &entry, t + 3);
    }
    // Its own and nine answers: ten.
    assert_eq!(
        refused(&s, 0, &asking("notes", "review", "more"), t + 4),
        "pair_held"
    );
    // Another agent is not in that loop: the hold is of the agent, not of
    // the channel.
    assert!(sends(&s, 0, &asking("work", "review", "not held"), t + 5).is_ok());
    assert_eq!(
        refused(&s, 0, &asking("notes", "review", "more"), t + 5),
        "pair_held"
    );
    // A person reads them, here: the loop is free.
    let row = kept::channel(&s[0].conn, &channel.id).unwrap().unwrap();
    for shown in crate::shared::shown(&s[0].conn, &s[0].identity, &channel.id, t + 6).unwrap() {
        rows::mark_read_by_a_person(&s[0].conn, row.id, &id_of(&shown.id).unwrap()).unwrap();
    }
    assert!(sends(&s, 0, &asking("notes", "review", "more"), t + 6).is_ok());
}

/// Sending again in a shared channel costs that channel alone (decision
/// 2026-10-10 §6.4): a relay that answers that it holds another entry at
/// the revision of a message's newest number has it written again under
/// the next, counted in the channel's hour and never in the folder's or
/// the device's; at 60 numbers in the channel's hour it waits, and the
/// device's own messages still go.
#[test]
fn sending_again_in_a_shared_channel_costs_that_channel_alone() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, t);
    let conn = &s[0].conn;
    let (id, _, _) = sends(&s, 0, &asking("notes", "review", "once"), t + 1).unwrap();
    let row = kept::channel(conn, &channel.id).unwrap().unwrap();
    let usable = crate::shared_pass::usable(conn, &channel.id, &AT)
        .unwrap()
        .unwrap();
    let again = |now: i64| {
        let mine: Vec<_> = crate::shared_pass::to_send(
            conn,
            &s[0].identity,
            &usable,
            &AT,
            crate::at_relays::Most {
                entries: 100,
                bytes: usize::MAX,
            },
        )
        .unwrap();
        let answers: Vec<_> = mine
            .iter()
            .map(|_| crate::at_relays::Pushed::HoldsAnother)
            .collect();
        crate::shared_pass::pushed(conn, &s[0].identity, &usable, &AT, &mine, &answers, now)
            .unwrap();
        crate::shared_sender::write_again(conn, &s[0].identity, now, &|_| true).unwrap()
    };
    // The anew record and the message are answered "another": each is
    // written again above.
    assert_eq!(again(t + 2), 1);
    let kept_now = rows::kept(conn).unwrap();
    assert_eq!(kept_now.len(), 1);
    assert_eq!(hex::encode(kept_now[0].id), id);
    assert_eq!(kept_now[0].numbers, [1, 2]);
    let (sends_in_channel, again_in_channel) = rows::sends_lately(conn, row.id, t + 2).unwrap();
    assert_eq!((sends_in_channel.len(), again_in_channel.len()), (1, 1));
    let lately = cordelia_storage::messages::sent_lately(conn, "notes", t + 2).unwrap();
    assert_eq!((lately.sends.len(), lately.again.len()), (1, 0));
    // The channel's hour fills with sends again: 60 numbers in all.
    for k in 0..58 {
        rows::record_send(conn, row.id, t + 3 + k, true).unwrap();
    }
    assert_eq!(
        again(t + 70),
        0,
        "it waits where the channel's hour is full"
    );
    assert_eq!(
        refused(&s, 0, &asking("notes", "review", "x"), t + 70),
        "channel_rate"
    );
    // The device's own messages still go.
    let own: crate::messages::SendRequest = serde_json::from_value(json!({
        "folder": folder("notes"), "to": "work", "body": "own", "link": null, "reply": null,
    }))
    .unwrap();
    let at_own = crate::messages::SendAt {
        now: t + 70,
        fetched: true,
        no_place: false,
        per_folder_per_hour: 20,
    };
    assert!(crate::messages::send_of(conn, &s[0].identity, &own, &at_own, |_| false).is_ok());
}

/// A shared message is written under four numbers at most (decision
/// 2026-10-10 §6.1, `AGENT_MESSAGE_SENDS_MAX`): written again three times,
/// each answered "another" by the relay, it is under four; answered so
/// once more, its kept value goes and nothing more is written.
#[test]
fn past_four_numbers_the_kept_value_of_a_shared_message_goes() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, t);
    let conn = &s[0].conn;
    let (id, _, _) = sends(&s, 0, &asking("notes", "review", "once"), t + 1).unwrap();
    let usable = crate::shared_pass::usable(conn, &channel.id, &AT)
        .unwrap()
        .unwrap();
    let again = |now: i64| {
        let mine: Vec<_> = crate::shared_pass::to_send(
            conn,
            &s[0].identity,
            &usable,
            &AT,
            crate::at_relays::Most {
                entries: 100,
                bytes: usize::MAX,
            },
        )
        .unwrap();
        let answers: Vec<_> = mine
            .iter()
            .map(|_| crate::at_relays::Pushed::HoldsAnother)
            .collect();
        crate::shared_pass::pushed(conn, &s[0].identity, &usable, &AT, &mine, &answers, now)
            .unwrap();
        crate::shared_sender::write_again(conn, &s[0].identity, now, &|_| true).unwrap()
    };
    for (k, numbers) in [vec![1, 2], vec![1, 2, 3], vec![1, 2, 3, 4]]
        .into_iter()
        .enumerate()
    {
        assert_eq!(again(t + 2 + k as i64), 1);
        let kept_now = rows::kept(conn).unwrap();
        assert_eq!(kept_now.len(), 1);
        assert_eq!(hex::encode(kept_now[0].id), id);
        assert_eq!(kept_now[0].numbers, numbers);
    }
    assert_eq!(again(t + 5), 0, "a fifth number is never written");
    assert!(rows::kept(conn).unwrap().is_empty());
}

/// A subscription's start is kept only while its channel is held (decision
/// 2026-10-10 §4.1): `notes` subscribes; the channel is dropped; a member
/// writes while it is dropped; it is filed again, and that message is
/// first held after. The agent is not shown it, since its subscription
/// starts again when the channel is held again; what is written after is
/// shown.
#[test]
fn a_channel_taken_again_after_a_drop_starts_its_subscriptions_again() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, t);
    assert_eq!(
        seen::start_of(&s[0].conn, &channel.id, "notes").unwrap(),
        Some(t)
    );
    acts(&s, 0, Do::Drop(channel.id), t + 100);
    assert_eq!(
        seen::start_of(&s[0].conn, &channel.id, "notes").unwrap(),
        None
    );
    // The subscription stays in force through the drop.
    assert!(
        seen::in_force(&s[0].conn)
            .unwrap()
            .contains(&(channel.id, "notes".into()))
    );
    let gap = message(&member(1), &channel, 1, "while dropped", t + 200);
    acts(
        &s,
        0,
        Do::File(crate::lists::tests::filing(7, "review")),
        t + 5000,
    );
    assert_eq!(
        kept::channel(&s[0].conn, &channel.id)
            .unwrap()
            .unwrap()
            .state,
        State::Held
    );
    assert_eq!(
        seen::start_of(&s[0].conn, &channel.id, "notes").unwrap(),
        Some(t + 5000)
    );
    given(&s, 0, &gap, t + 5001);
    assert!(unread(&s, 0, "notes", t + 5002).is_empty());
    let after = id_given(&s, 0, &channel, 2, "after", t + 5003);
    assert_eq!(
        unread(&s, 0, "notes", t + 5004),
        std::slice::from_ref(&after)
    );
}

/// One value written in two channels is two messages (decision 2026-10-10
/// §4.2): the index holds two rows, a reply with `--channel` finds the one
/// in that channel, `read <id>` is refused with `more_than_one`, and an
/// agent that reads it in one channel is shown it as unread in the other.
#[test]
fn one_id_in_two_channels_is_two_messages() {
    let (s, one) = devices(1);
    let t = s.now + 10;
    let two = holds(&s, 0, 8, "other", t);
    subscribes(&s, 0, &one, "notes", true, t);
    subscribes(&s, 0, &two, "notes", true, t);
    let mut asks = says("in both", t + 1);
    asks.asks = true;
    let value = asks.to_value().unwrap();
    for channel in [&one, &two] {
        let name = message_name(&member(1).public_key(), 1).unwrap();
        let entry = crate::several::entry_by(
            &member(1),
            &channel.secret,
            message_rev(1).unwrap(),
            &name,
            EntryValue::Other(value.clone()),
            &[],
        );
        given(&s, 0, &entry, t + 1);
    }
    let id = hex::encode(cordelia_crypto::message::message_id(
        &member(1).public_key(),
        &value,
    ));
    assert_eq!(unread(&s, 0, "notes", t + 2), vec![id.clone(); 2]);
    match reads(&s, 0, "notes", &id[..8], t + 2) {
        Err(NotShown::Refused(Refused::MoreThanOne { ids, .. })) => assert_eq!(ids.len(), 2),
        other => panic!("{other:?}"),
    }
    let mut reply = asking("notes", "review", "answer");
    reply.reply = Some(id[..8].into());
    assert!(sends(&s, 0, &reply, t + 3).is_ok());
    // Read in one channel, through the mark that binds it: unread in the
    // other.
    seen::mark(
        &s[0].conn,
        &shared_read_mark(
            &one.id,
            &id_of(&hex::decode(&id).unwrap()).unwrap(),
            "notes",
        ),
        t + 4,
    )
    .unwrap();
    let left = seen::unread(&s[0].conn, &s[0].identity, "notes", t + 4).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].row.channel, two.id);
}

/// A reply goes only where its message came from (decision 2026-10-10
/// §4.2): to a shared message without `--channel`, or with another, it is
/// refused with `reply_elsewhere`; to a message of the person's own with
/// `--channel`, likewise.
#[test]
fn a_reply_goes_only_where_its_message_came_from() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    let other = holds(&s, 0, 8, "other", t);
    subscribes(&s, 0, &channel, "notes", true, t);
    subscribes(&s, 0, &other, "notes", true, t);
    let mut asks = says("asks", t + 1);
    asks.asks = true;
    let name = message_name(&member(1).public_key(), 1).unwrap();
    let entry = crate::several::entry_by(
        &member(1),
        &channel.secret,
        message_rev(1).unwrap(),
        &name,
        EntryValue::Other(asks.to_value().unwrap()),
        &[],
    );
    given(&s, 0, &entry, t + 1);
    let id = hex::encode(cordelia_crypto::message::message_id(
        &member(1).public_key(),
        &asks.to_value().unwrap(),
    ));
    // Without --channel: the messages record's route.
    let own: crate::messages::SendRequest = serde_json::from_value(json!({
        "folder": folder("notes"), "to": null, "reply": &id[..8], "body": "x", "link": null,
    }))
    .unwrap();
    let at_own = crate::messages::SendAt {
        now: t + 2,
        fetched: true,
        no_place: false,
        per_folder_per_hour: 20,
    };
    match crate::messages::send_of(&s[0].conn, &s[0].identity, &own, &at_own, |_| false) {
        Err(crate::messages::NotSentHere::Refused(Refused::ReplyElsewhere {
            channel: Some(of),
            ..
        })) => assert_eq!(of, channel.id),
        other => panic!("{other:?}"),
    }
    // With another channel.
    let mut wrong = asking("notes", "other", "x");
    wrong.reply = Some(id[..8].into());
    assert_eq!(refused(&s, 0, &wrong, t + 2), "reply_elsewhere");
    // With its own channel.
    let mut right = asking("notes", "review", "x");
    right.reply = Some(id[..8].into());
    assert!(sends(&s, 0, &right, t + 2).is_ok());
    // A message of the person's own, answered with --channel.
    let own_message: crate::messages::SendRequest = serde_json::from_value(json!({
        "folder": folder("work"), "to": "notes", "body": "own", "link": null, "reply": null,
    }))
    .unwrap();
    let mut own_asks = own_message;
    own_asks.asks = true;
    let sent = crate::messages::send_of(&s[0].conn, &s[0].identity, &own_asks, &at_own, |_| false)
        .unwrap();
    let mut across = asking("notes", "review", "x");
    across.reply = Some(hex::encode(sent.id)[..8].into());
    match sends(&s, 0, &across, t + 3) {
        Err(NotSentHere::Refused(Refused::ReplyElsewhere { channel: None, .. }, _)) => {}
        other => panic!("{other:?}"),
    }
}

/// The `sread/` lists that the store held before step 25 are read once
/// (decision 2026-10-10 §14): an `sread/` list that a device stored while
/// it was of the version before, counted then among its signer's entries
/// that were not messages, is read through the reader at the first start
/// after the step, and that signer's count is 0, and no other's.
#[test]
fn sread_lists_held_before_the_upgrade_are_read_after_it() {
    let (s, channel) = devices(2);
    let t = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, t);
    subscribes(&s, 1, &channel, "notes", true, t);
    let id = id_given(&s, 0, &channel, 1, "x", t + 1);
    given(&s, 1, &message(&member(1), &channel, 1, "x", t + 1), t + 1);
    reads(&s, 0, "notes", &id, t + 2).unwrap();
    seen::write_list(&s[0].conn, &s[0].identity, t + 2, true).unwrap();
    // Device 1 stores device 0's list past the door, as the version before
    // did, and counts it as no message.
    let list = s[0].stored().into_iter().find(|entry| {
        entry.author == s.key(0)
            && entry.rev == 1
            && entry.content.len() == 2048
            && !s[0].stored_in(&channel.secret).contains(entry)
    });
    let list = list.expect("device 0's sread list");
    cordelia_storage::entries::store(&s[1].conn, &list, t + 2).unwrap();
    // Device 1 counted it as no message of device 0's; and another
    // signer's count of its own stays.
    s[1].conn
        .execute(
            "INSERT OR IGNORE INTO message_generations (id, channel, statement, first_held)
             VALUES (99, zeroblob(32), 1, 0)",
            [],
        )
        .unwrap();
    for signer in [s.key(0), member(1).public_key()] {
        s[1].conn
            .execute(
                "INSERT INTO message_signers (signer, generation, highest, not_messages)
                 VALUES (?1, 99, 0, 1)",
                [&signer[..]],
            )
            .unwrap();
    }
    assert_eq!(unread(&s, 1, "notes", t + 3), std::slice::from_ref(&id));
    assert!(crate::reader::read_held_shared_lists(&s[1].conn, &s[1].identity, t + 3).unwrap());
    assert!(unread(&s, 1, "notes", t + 4).is_empty());
    // Only the count of the signer whose list it read is 0: another
    // signer's stays.
    let counts: Vec<([u8; 32], i64)> = s[1]
        .conn
        .prepare("SELECT signer, not_messages FROM message_signers")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(counts.len() >= 2, "{counts:?}");
    for (signer, count) in counts {
        assert_eq!(count, i64::from(signer != s.key(0)), "{signer:?}");
    }
    // Once.
    assert!(!crate::reader::read_held_shared_lists(&s[1].conn, &s[1].identity, t + 5).unwrap());
}

/// The summary's count (decision 2026-10-10 §5.3): only of channels the
/// folder's agent subscribes to, of what is unread, and none where sync is
/// off; an agent is never counted what an agent of its name sent.
#[test]
fn the_summary_counts_only_what_waits_for_a_subscribed_agent() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    id_given(&s, 0, &channel, 1, "before", t);
    assert_eq!(
        summary_of(&s[0].conn, &s[0].identity, &folder("notes"), t).unwrap(),
        None
    );
    subscribes(&s, 0, &channel, "notes", true, t + 1);
    subscribes(&s, 0, &channel, "work", true, t + 1);
    id_given(&s, 0, &channel, 2, "after", t + 2);
    sends(&s, 0, &asking("notes", "review", "mine"), t + 3).unwrap();
    let count =
        |name: &str, now| summary_of(&s[0].conn, &s[0].identity, &folder(name), now).unwrap();
    assert_eq!(count("notes", t + 4), Some(1));
    // Another agent of the person's is shown it, as its own device's.
    assert_eq!(count("work", t + 4), Some(2));
    meta::remove(&s[0].conn, meta::SYNC_CLAUDE_DIR).unwrap();
    assert_eq!(count("notes", t + 4), None);
    let _: Option<Usable> = None;
}

/// Nothing is written in a shared channel before it is fetched since the
/// node started, at the relays of its card that the device reaches
/// (decision 2026-10-10 §6.1, `not_fetched`), nor where none of them is
/// the device's own (§8.3, `not_reached`).
#[test]
fn nothing_is_written_in_a_shared_channel_before_it_is_fetched() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, t);
    let before = s[0].stored_in(&channel.secret);
    let not_yet = |_: &[u8; 32], _: usize| false;
    match send_of(
        &s[0].conn,
        &s[0].identity,
        &asking("notes", "review", "x"),
        &at(t),
        not_yet,
    ) {
        Err(NotSentHere::Refused(why, _)) => assert_eq!(why.word(), "not_fetched"),
        other => panic!("{other:?}"),
    }
    let mut elsewhere = at(t);
    elsewhere.own_relays.clear();
    match send_of(
        &s[0].conn,
        &s[0].identity,
        &asking("notes", "review", "x"),
        &elsewhere,
        |_, _| true,
    ) {
        Err(NotSentHere::Refused(why, _)) => assert_eq!(why.word(), "not_reached"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s[0].stored_in(&channel.secret), before);
}

/// `send --channel` says which keys came since this folder last wrote
/// there, not since this device did (decision 2026-10-10 §5.4): `notes`
/// writes; a key is first held; `work` writes and is told of it; `notes`
/// writes again and is told of it too.
#[test]
fn send_says_what_came_since_this_folder_last_wrote() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, t);
    subscribes(&s, 0, &channel, "work", true, t);
    let (_, _, first) = sends(&s, 0, &asking("notes", "review", "one"), t + 1).unwrap();
    assert!(first[0].contains("unchanged since"), "{first:?}");
    given(
        &s,
        0,
        &message(&member(2), &channel, 1, "new here", t + 2),
        t + 2,
    );
    let new_key = |lines: &[String]| lines.iter().any(|line| line.starts_with("  new: "));
    let (_, _, work) = sends(&s, 0, &asking("work", "review", "two"), t + 3).unwrap();
    assert!(new_key(&work), "{work:?}");
    let (_, _, notes) = sends(&s, 0, &asking("notes", "review", "three"), t + 4).unwrap();
    assert!(new_key(&notes), "{notes:?}");
    // And once it has written since, it is not told again.
    let (_, _, again) = sends(&s, 0, &asking("notes", "review", "four"), t + 5).unwrap();
    assert!(!new_key(&again), "{again:?}");
}

/// A send waits where the channel is not yet clean, or paused by an offer
/// (decision 2026-10-24, rules 23, 25 and 26; decision 2026-10-10 §5.5):
/// `not_clean` while it is marked so; `paused` once an offer that seals to
/// Bob and leaves out Carol is read, until Bob stays; and, once Bob has
/// moved, a reply to a message of the old channel is `moved`.
#[test]
fn a_send_waits_where_the_channel_is_not_clean_or_paused() {
    use crate::shared::tests::{anew, anew_of};
    use cordelia_crypto::shared::{Anew, Offer};
    let (s, channel) = devices(1);
    let t = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, t);
    let (alice, carol) = (member(1), member(2));
    for member in [&alice, &carol] {
        given(&s, 0, &anew(member, &channel, 1), t);
    }
    let old_id = id_given(&s, 0, &channel, 1, "before it was made anew", t);
    assert!(sends(&s, 0, &asking("notes", "review", "clean"), t + 1).is_ok());

    // Not clean: nothing is sent.
    let conn = &s[0].conn;
    cordelia_storage::shared_anew::not_clean(conn, &channel.id, t, false).unwrap();
    assert_eq!(
        refused(&s, 0, &asking("notes", "review", "x"), t + 2),
        "not_clean"
    );
    match sends(&s, 0, &asking("notes", "review", "x"), t + 2) {
        Err(NotSentHere::Refused(why, name)) => {
            let answer = refusal_of(conn, &why, &name).unwrap();
            assert_eq!(answer.status(), 409);
        }
        other => panic!("{other:?}"),
    }
    cordelia_storage::shared_anew::clean(conn, &channel.id).unwrap();

    // Alice's offer, sealed to Bob and not to Carol: paused.
    let card = crate::lists::tests::filing(30, "x").card;
    let offer = Offer::make(
        (t + 3) as u64,
        &channel.id,
        &card,
        &[alice.public_key(), s.key(0)],
    )
    .unwrap();
    given(
        &s,
        0,
        &anew_of(&alice, &channel, 2, Anew::Offer(offer).to_value().unwrap()),
        t + 3,
    );
    assert_eq!(
        refused(&s, 0, &asking("notes", "review", "x"), t + 4),
        "paused"
    );
    // Bob stays: it is sent again.
    crate::shared_anew::make_stay(conn, &channel.id, "review").unwrap();
    assert!(sends(&s, 0, &asking("notes", "review", "stayed"), t + 5).is_ok());

    // Bob moves: a reply to the old channel's message is `moved`, and the
    // subscription is in the new channel.
    let plan = crate::shared_anew::move_plan(
        conn,
        &s[0].identity,
        &at(t).own_relays,
        "review",
        None,
        None,
        t + 6,
    )
    .unwrap();
    crate::shared_anew::make_move(conn, &s[0].identity, &plan.what, t + 6).unwrap();
    out(&s, 0, t + 6);
    let mut reply = asking("notes", "review", "an answer");
    reply.reply = Some(old_id[..8].to_string());
    assert_eq!(refused(&s, 0, &reply, t + 7), "moved");
    assert!(
        sends(
            &s,
            0,
            &asking("notes", "review", "in the new channel"),
            t + 7
        )
        .is_ok()
    );
}

/// The status's `unread_by_an_agent` counts, for each subscribed folder,
/// the messages unread by its agent (decision 2026-10-10 §9, section 19
/// item 83), as the `messages` object counts its own: a message neither of
/// two subscribed folders has read counts twice; read by one, once.
#[test]
fn unread_by_an_agent_counts_for_each_subscribed_folder() {
    let (s, channel) = devices(1);
    let t = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, t + 1);
    subscribes(&s, 0, &channel, "work", true, t + 1);
    let id = id_given(&s, 0, &channel, 1, "to both", t + 2);
    assert_eq!(unread(&s, 0, "notes", t + 3), std::slice::from_ref(&id));
    assert_eq!(unread(&s, 0, "work", t + 3), std::slice::from_ref(&id));
    let unread_by_an_agent = |now: i64| {
        let own = at(now).own_relays;
        let said = crate::state::SharedSaid::default();
        let beside = crate::shared_status::Beside {
            own_relays: &own,
            connected: &[AT],
            said: &said,
        };
        crate::shared_status::status_of(&s[0].conn, &s[0].identity, &beside, now)
            .unwrap()
            .unwrap()["channels"][0]["unread_by_an_agent"]
            .clone()
    };
    assert_eq!(unread_by_an_agent(t + 3), 2);
    reads(&s, 0, "notes", &id, t + 4).unwrap();
    assert!(unread(&s, 0, "notes", t + 5).is_empty());
    assert_eq!(unread_by_an_agent(t + 5), 1);
}

// ── A device's room ──────────────────────────────────────────────────

/// A relay of a test, as its store takes what a device pushes in a shared
/// channel: every entry is taken as a relay takes it, and what it holds of
/// one author is counted as a relay counts it.
struct RelayStore {
    conn: rusqlite::Connection,
    room: cordelia_storage::relay::Room,
    /// The size each slot was first written at.
    sizes: std::collections::HashMap<[u8; 32], usize>,
    /// The most it held of the device at any push.
    most: u64,
}

impl RelayStore {
    fn new() -> Self {
        Self {
            conn: cordelia_storage::db::open_in_memory().unwrap(),
            room: cordelia_storage::relay::Room::new(u64::MAX),
            sizes: std::collections::HashMap::new(),
            most: 0,
        }
    }

    /// The bytes it holds of `author` in `channel`, each entry counted as
    /// a relay counts it.
    fn held_of(&self, channel: &[u8; 32], author: &[u8; 32]) -> u64 {
        let mut rows = self
            .conn
            .prepare("SELECT length(content) FROM entries WHERE channel_id = ?1 AND author = ?2")
            .unwrap();
        rows.query_map(rusqlite::params![&channel[..], &author[..]], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
        .map(|len| cordelia_core::protocol::entry_cost(usize::try_from(len.unwrap()).unwrap()))
        .sum()
    }

    /// Device 0 of `s` pushes what waits for the relay in `channel_id`,
    /// every entry taken by this store; where `another`, the relay answers
    /// that it holds another entry at each message's revision, as a relay
    /// of somebody else's choosing may. Each entry is of one of the two
    /// sizes, and of its slot's first size; what the store holds of the
    /// device is within its room after each. Returns how many it pushed.
    fn pushed(&mut self, s: &Several, channel_id: &[u8; 32], another: bool, now: i64) -> usize {
        use crate::at_relays::Pushed;
        use cordelia_core::protocol::{AGENT_MESSAGE_CONTENT_BYTES, SHARED_ANEW_CONTENT_BYTES};
        use cordelia_storage::relay::{self, Taken};
        let (conn, identity, own) = (&s[0].conn, &s[0].identity, s.key(0));
        let usable = crate::shared_pass::usable(conn, channel_id, &AT)
            .unwrap()
            .unwrap();
        let batch = crate::shared_pass::to_send(
            conn,
            identity,
            &usable,
            &AT,
            crate::at_relays::Most {
                entries: 1_000,
                bytes: usize::MAX,
            },
        )
        .unwrap();
        let asker = relay::Asker::Address("127.0.0.1".parse().unwrap());
        let mut answers = Vec::new();
        for entry in &batch {
            assert_eq!(entry.author, own);
            let size = entry.content.len();
            assert!(
                size == AGENT_MESSAGE_CONTENT_BYTES || size == SHARED_ANEW_CONTENT_BYTES,
                "an entry of {size} bytes"
            );
            let first = *self.sizes.entry(entry.slot).or_insert(size);
            assert_eq!(size, first, "a slot written again at another size");
            let said = match relay::take(&self.conn, &mut self.room, entry, &asker, now).unwrap() {
                Taken::Stored | Taken::AlreadyHeld => Pushed::Holds,
                Taken::OlderThanHeld => Pushed::HoldsLater,
                Taken::HeldAnother => Pushed::HoldsAnother,
                other => panic!("{other:?}"),
            };
            let is_a_message = size == AGENT_MESSAGE_CONTENT_BYTES;
            answers.push(match another && is_a_message {
                true => Pushed::HoldsAnother,
                false => said,
            });
            let held = self.held_of(channel_id, &own);
            assert!(held <= ROOM, "the relay holds {held} bytes of the device");
            self.most = self.most.max(held);
        }
        crate::shared_pass::pushed(conn, identity, &usable, &AT, &batch, &answers, now).unwrap();
        batch.len()
    }
}

/// The room of one device in a shared channel, as a relay counts it: 64
/// messages and one anew record (decision 2026-10-10 §6.3).
const ROOM: u64 = 214_016;

/// A device never has more than its room in a shared channel (decision
/// 2026-10-10 §1, property 21; §6.3; T23): whatever it sends, every entry
/// it writes there is of its slot's one size, 2,048 bytes in `msg/` and
/// 16,384 in `anew/`, a slot written again is never larger, and a relay
/// that takes everything it pushes holds of its key at most 64 × 3,072 +
/// 17,408 = 214,016 bytes as counted, at every push. It sends more
/// messages than its ring holds, from two agents over many hours; a relay
/// answers that it holds another entry at a third of them, so each is
/// written again under the next number; at 30 days it clears what it sent;
/// and it makes the channel anew with 63 keys of others and its own, an
/// offer at its largest, over its empty anew record. Its room is whole from
/// its first message on.
#[test]
fn a_device_never_has_more_than_its_room_in_a_shared_channel() {
    use cordelia_core::protocol::{
        AGENT_MESSAGE_CONTENT_BYTES, AGENT_MESSAGE_RING, SHARED_ANEW_CONTENT_BYTES, entry_cost,
    };
    assert_eq!(
        AGENT_MESSAGE_RING as u64 * entry_cost(AGENT_MESSAGE_CONTENT_BYTES)
            + entry_cost(SHARED_ANEW_CONTENT_BYTES),
        ROOM
    );
    let (s, channel) = devices(1);
    let identity = &s[0].identity;
    let conn = &s[0].conn;
    let own = s.key(0);
    let mut t = s.now + 10;
    subscribes(&s, 0, &channel, "notes", true, t);
    subscribes(&s, 0, &channel, "work", true, t);
    assert_eq!(
        sharing::write_empty_anew_records(conn, identity, t).unwrap(),
        1
    );
    let mut relay = RelayStore::new();
    assert_eq!(relay.pushed(&s, &channel.id, false, t), 1);
    assert_eq!(
        relay.held_of(&channel.id, &own),
        entry_cost(SHARED_ANEW_CONTENT_BYTES)
    );

    // More messages than the ring holds, two agents, many hours; a third
    // of the pushes answered "another", and each such message written
    // again under the next number.
    let mut sent = 0;
    let mut pushes = 0;
    let mut again = 0;
    while sent < 3 * AGENT_MESSAGE_RING {
        t += 60;
        let from = ["notes", "work"][sent % 2];
        match sends(
            &s,
            0,
            &asking(from, "review", &format!("message {sent}")),
            t,
        ) {
            Ok(_) => sent += 1,
            Err(NotSentHere::Refused(why, _)) if why.word() == "pair_held" => {
                // A person reads what waits here, which frees the loop.
                let row = kept::channel(conn, &channel.id).unwrap().unwrap();
                for shown in crate::shared::shown(conn, identity, &channel.id, t).unwrap() {
                    rows::mark_read_by_a_person(conn, row.id, &id_of(&shown.id).unwrap()).unwrap();
                }
                for kept_value in rows::kept(conn).unwrap() {
                    rows::mark_read_by_a_person(conn, row.id, &kept_value.id).unwrap();
                }
                continue;
            }
            Err(_) => {
                // An hour is full: the next.
                t += 60 * 60;
                continue;
            }
        }
        pushes += 1;
        relay.pushed(&s, &channel.id, pushes % 3 == 0, t);
        again += crate::shared_sender::write_again(conn, identity, t, &|_| true).unwrap();
        relay.pushed(&s, &channel.id, false, t);
    }
    assert!(again >= AGENT_MESSAGE_RING / 2, "written again: {again}");
    let highest: i64 = relay
        .conn
        .query_row(
            "SELECT MAX(rev) FROM entries WHERE channel_id = ?1 AND author = ?2",
            rusqlite::params![&channel.id[..], &own[..]],
            |row| row.get(0),
        )
        .unwrap();
    let past = message_rev(3 * AGENT_MESSAGE_RING as u64).unwrap();
    assert!(
        u64::try_from(highest).unwrap() >= past,
        "the ring went round more than twice: {highest}"
    );
    assert_eq!(relay.most, ROOM, "the ring was written whole");

    // At 30 days, what it sent is cleared, in the same slots.
    t += 31 * 24 * 60 * 60;
    assert!(crate::shared_sender::clear_expired(conn, identity, t, &|_| true).unwrap() > 0);
    relay.pushed(&s, &channel.id, false, t);

    // Made anew with 63 other keys staying: its offer at its largest, over
    // its empty anew record.
    for k in 0..63 {
        given(
            &s,
            0,
            &crate::shared::tests::anew(&member(10 + k), &channel, 1),
            t,
        );
    }
    let own_relays = at(t).own_relays;
    let (listing, _) =
        crate::shared_anew::anew_plan(conn, identity, &own_relays, "review", None, &[], None, t)
            .unwrap();
    let listed: Vec<String> = listing
        .asked
        .iter()
        .map(|key| encode_public_key(key).unwrap())
        .collect();
    assert_eq!(listed.len(), 63);
    let (_, plan) = crate::shared_anew::anew_plan(
        conn,
        identity,
        &own_relays,
        "review",
        None,
        &[],
        Some((&listed, &listed)),
        t,
    )
    .unwrap();
    let plan = plan.unwrap();
    assert_eq!(plan.what.stay.len(), 64);
    crate::shared_anew::make_anew(conn, identity, &own_relays, &plan.what, t).unwrap();
    assert_eq!(relay.pushed(&s, &channel.id, false, t + 1), 1, "the offer");
    assert!(relay.held_of(&channel.id, &own) <= ROOM);
    assert_eq!(relay.held_of(&channel.id, &own), ROOM);
}

// ── A name that is both ──────────────────────────────────────────────

/// A name that is both, across two devices, goes nowhere wrong (decision
/// 2026-10-10 §2.2, §4.2; T10): the laptop syncs `review`, a name of the
/// person's own, while the desktop, apart, files a shared channel as
/// `review`; once they meet, each holds both. On each, `--to review` and a
/// publish under `review` look among the names alone, and write nothing in
/// the shared channel; `--channel review`, `share` and `subscribe` look
/// among the shared alone, and `share` hands the shared channel and is not
/// refused as a name of the person's own; `msg send --channel review`
/// writes in the shared channel and in no channel of the person's own; and
/// `shared list` says that the name is also a name the person syncs.
#[test]
fn a_name_that_is_both_across_two_devices_goes_nowhere_wrong() {
    let mut s = crate::shared::tests::bob(2);
    let (laptop, desktop) = (0, 1);
    let now = s.now + 10;
    for n in [laptop, desktop] {
        crate::names::say(&s[n].conn, &s[n].identity, "notes", now).unwrap();
    }
    // Apart: the laptop syncs `review`, the desktop files a shared channel
    // under that name.
    crate::names::say(&s[laptop].conn, &s[laptop].identity, "review", now).unwrap();
    let channel = holds(&s, desktop, 7, "review", now);
    for n in [laptop, desktop] {
        let mapped: Vec<Value> = ["notes", "review"]
            .iter()
            .map(|name| json!({ "folder": folder(name), "name": name }))
            .collect();
        meta::set(
            &s[n].conn,
            meta::SYNC_CLAUDE_MAPPINGS,
            &Value::from(mapped).to_string(),
        )
        .unwrap();
    }
    s.meet(&[laptop, desktop]);
    // Each syncs the name: a folder of each is mapped to it.
    s.hold(&[laptop, desktop], "review");
    follow_all(&s, now + 1);
    let t = s.now + 2;
    let others = |n: usize| -> Vec<cordelia_crypto::entry::CheckedEntry> {
        s[n].stored()
            .into_iter()
            .filter(|entry| entry.channel != channel.id)
            .collect()
    };
    for n in [laptop, desktop] {
        let conn = &s[n].conn;
        let identity = &s[n].identity;
        let names: Vec<String> = crate::names::listed(conn)
            .unwrap()
            .into_iter()
            .map(|listed| listed.name)
            .collect();
        assert!(
            names.contains(&"review".to_string()),
            "device {n}: {names:?}"
        );
        assert!(crate::lists::is_filed_under(conn, "review").unwrap());
        let filing = sharing::find(conn, "review", None, None).unwrap();
        assert_eq!(filing.channel, channel.id, "device {n}");
        let listed = sharing::list(conn, identity, &at(t).own_relays, false, t).unwrap();
        assert_eq!(listed["channels"][0]["name"], "review", "device {n}");
        assert_eq!(listed["channels"][0]["also_a_name"], true, "device {n}");

        // `--to review`: a name of the person's own, and nothing in the
        // shared channel.
        let in_shared = s[n].stored_in(&channel.secret);
        let own_before = others(n).len();
        let request = Request {
            from: "notes".into(),
            address: Address::Own(To::Name("review".into())),
            asks: false,
            link: None,
            body: format!("to the name, on device {n}"),
            thread: [0; 16],
            answers: [0; 16],
        };
        let sends_at = At {
            now: t,
            fetched: true,
            no_place: false,
            mapped: true,
            per_folder_per_hour: 20,
            shared_fetched: true,
            shared_reached: true,
        };
        sender::send(conn, identity, &sends_at, &request, sender::no_reply)
            .unwrap_or_else(|e| panic!("device {n}: {e:?}"));
        assert_eq!(others(n).len(), own_before + 1, "device {n}");
        assert_eq!(s[n].stored_in(&channel.secret), in_shared, "device {n}");

        // A publish under `review`: the name's channel, and nothing in the
        // shared channel.
        let write = crate::publish::Write {
            name: "review",
            file: &format!("from-{n}.md"),
            value: EntryValue::Text("memory".into()),
            planned: crate::publish::PlannedAgainst::NoVersion,
            merge: None,
        };
        let own_before = others(n).len();
        crate::publish::publish(conn, identity, &write, t).unwrap();
        assert_eq!(others(n).len(), own_before + 1, "device {n}");
        assert_eq!(s[n].stored_in(&channel.secret), in_shared, "device {n}");

        // `share review <key>`: the shared channel, not refused as a name
        // of the person's own.
        let to = encode_public_key(&member(1).public_key()).unwrap();
        let plan = sharing::share_plan(conn, identity, &at(t).own_relays, "review", &to, None, t)
            .unwrap_or_else(|e| panic!("device {n}: {e:?}"));
        assert_eq!(plan.what.filing.channel, channel.id, "device {n}");

        // `subscribe review`, in the folder of `notes`: the shared channel.
        let plan = subscribe_plan(conn, identity, &folder("notes"), "review", None)
            .unwrap()
            .unwrap();
        assert_eq!(plan.what.channel, channel.id, "device {n}");
    }
    // Subscribed, on the laptop, `send --channel review` writes in the
    // shared channel, and in no channel of the person's own.
    subscribes(&s, laptop, &channel, "notes", true, t + 1);
    let before = others(laptop);
    let in_shared = s[laptop].stored_in(&channel.secret).len();
    sends(
        &s,
        laptop,
        &asking("notes", "review", "into the channel"),
        t + 2,
    )
    .unwrap();
    assert_eq!(others(laptop), before);
    assert!(s[laptop].stored_in(&channel.secret).len() > in_shared);
    // And `--to review` there is still the name's.
    let request = Request {
        from: "notes".into(),
        address: Address::Own(To::Name("review".into())),
        asks: false,
        link: None,
        body: "to the name again".into(),
        thread: [0; 16],
        answers: [0; 16],
    };
    let sends_at = At {
        now: t + 3,
        fetched: true,
        no_place: false,
        mapped: true,
        per_folder_per_hour: 20,
        shared_fetched: true,
        shared_reached: true,
    };
    let in_shared = s[laptop].stored_in(&channel.secret);
    let own_before = others(laptop).len();
    sender::send(
        &s[laptop].conn,
        &s[laptop].identity,
        &sends_at,
        &request,
        sender::no_reply,
    )
    .unwrap();
    assert_eq!(others(laptop).len(), own_before + 1);
    assert_eq!(s[laptop].stored_in(&channel.secret), in_shared);
}
