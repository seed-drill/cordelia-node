//! Tests of making, sharing and taking a shared channel (decision
//! 2026-10-10 §3.1, §3.2, §5.2, §5.5), in-process.

use super::*;
use crate::several::{Several, entry_by};
use crate::shared::tests::{DAY, HOUR, bob, member};
use crate::shared::{Judged, NotAShare, accept_typed};
use cordelia_storage::meta;
use serde_json::json;

/// The relay a device of these tests knows by its key.
const AT: [u8; 32] = [3; 32];
/// A relay that no device of these tests knows.
const ELSEWHERE: [u8; 32] = [4; 32];

fn relays() -> Vec<OwnRelay> {
    vec![OwnRelay {
        name: "relay.example.org:9474".into(),
        key: AT,
    }]
}

/// The card of the seed `seed` at the relays `keys`.
fn card(seed: u8, keys: &[[u8; 32]]) -> Card {
    let mut bytes = vec![seed; 32];
    bytes.extend_from_slice(&Relays::new(keys).unwrap().to_bytes());
    Card::from_bytes(&bytes).unwrap()
}

/// A share by `from` of `card` for `to`, made at `made`, in their share
/// pair channel, at revision `rev`, under the name `name` (the share's own
/// where `None`).
fn share_by(
    from: &NodeIdentity,
    to: &[u8; 32],
    card: &Card,
    made: i64,
    name: Option<&str>,
) -> CheckedEntry {
    let (_, secret) = share_pair(from, to).unwrap();
    let share = Share {
        made: u64::try_from(made).unwrap(),
        for_key: *to,
        card: card.clone(),
    };
    let name = name
        .map(str::to_string)
        .unwrap_or_else(|| share_name(&card.channel_id().unwrap()));
    entry_by(from, &secret, 1, &name, Value::Other(share.to_value()), &[])
}

/// Bob's device `n` types Alice's key for a channel as `name` at `now`.
fn typed(s: &Several, n: usize, key: &[u8; 32], name: &str, now: i64) -> TypedForChannel {
    let to = TypeFor {
        key: *key,
        name: name.into(),
    };
    type_for_a_channel(&s[n].conn, &to, now).unwrap();
    rows::typed_key(&s[n].conn, key).unwrap().unwrap()
}

fn judge(
    s: &Several,
    n: usize,
    typed: &TypedForChannel,
    entry: &CheckedEntry,
    now: i64,
) -> Option<Judged> {
    accept_typed(
        &s[n].conn,
        &s[n].identity,
        &typed.key,
        typed.typed_at,
        entry,
        now,
    )
    .unwrap()
}

fn taken(
    s: &Several,
    n: usize,
    typed: &TypedForChannel,
    found: &[CheckedEntry],
    now: i64,
) -> Became {
    take_share(&s[n].conn, &s[n].identity, typed, found, &relays(), now).unwrap()
}

/// `accept --channel` takes only the share of the typed key, made within
/// the hour of its typing, for this device, of the ID its name says, at
/// this device's own relays, and only one (decision 2026-10-10 §3.2): each
/// rule, broken alone, takes nothing; the typed key is used up by one take.
#[test]
fn accept_takes_only_the_typed_keys_share_for_this_device_within_the_hour_at_its_own_relays() {
    let s = bob(1);
    let now = s.now + 10;
    let (alice, carol) = (member(1), member(2));
    let bob_key = s.key(0);
    let good_card = card(7, &[AT]);
    let good = share_by(&alice, &bob_key, &good_card, now, None);
    let typing = typed(&s, 0, &alice.public_key(), "review", now);
    assert!(matches!(
        judge(&s, 0, &typing, &good, now),
        Some(Judged::Share(_))
    ));

    // Rule 1: not typed at that time, or its hour gone.
    let mut other_time = typing.clone();
    other_time.typed_at += 1;
    assert_eq!(judge(&s, 0, &other_time, &good, now), None);
    assert_eq!(judge(&s, 0, &typing, &good, now + HOUR), None);
    assert_eq!(
        taken(&s, 0, &typing, std::slice::from_ref(&good), now + HOUR),
        Became::NotNow
    );
    // Rule 2: another pair channel.
    let elsewhere = share_by(&alice, &carol.public_key(), &good_card, now, None);
    assert_eq!(
        judge(&s, 0, &typing, &elsewhere, now),
        Some(Judged::Not(NotAShare::NotThePairChannel))
    );
    // Rule 3: another key signed it, in the pair channel of the typed key.
    let (_, secret) = share_pair(&alice, &bob_key).unwrap();
    let share = Share {
        made: u64::try_from(now).unwrap(),
        for_key: bob_key,
        card: good_card.clone(),
    };
    let name = share_name(&good_card.channel_id().unwrap());
    let by_carol = entry_by(
        &carol,
        &secret,
        1,
        &name,
        Value::Other(share.to_value()),
        &[],
    );
    assert_eq!(
        judge(&s, 0, &typing, &by_carol, now),
        Some(Judged::Not(NotAShare::SignedByAnotherKey))
    );
    // Rule 4: another name, a value that is no share, a delete.
    let named = share_by(&alice, &bob_key, &good_card, now, Some("hand-over"));
    let no_share = entry_by(&alice, &secret, 1, &name, Value::Other(vec![1; 407]), &[]);
    let delete = entry_by(&alice, &secret, 2, &name, Value::Delete, &[]);
    for entry in [&named, &no_share, &delete] {
        assert_eq!(
            judge(&s, 0, &typing, entry, now),
            Some(Judged::Not(NotAShare::NotAShare))
        );
    }
    // Rule 5: made an hour or more before or after the typing.
    for made in [now - HOUR, now + HOUR] {
        let old = share_by(&alice, &bob_key, &good_card, made, None);
        assert_eq!(
            judge(&s, 0, &typing, &old, now),
            Some(Judged::Not(NotAShare::NotMadeWithinTheHour))
        );
    }
    // Rule 6: for another device.
    let for_carol = Share {
        for_key: carol.public_key(),
        ..share.clone()
    };
    let not_ours = entry_by(
        &alice,
        &secret,
        1,
        &name,
        Value::Other(for_carol.to_value()),
        &[],
    );
    assert_eq!(
        judge(&s, 0, &typing, &not_ours, now),
        Some(Judged::Not(NotAShare::NotForThisDevice))
    );
    // Rule 8: a card of another ID than its name says.
    let other_id = share_name(&card(8, &[AT]).channel_id().unwrap());
    let misnamed = share_by(&alice, &bob_key, &good_card, now, Some(&other_id));
    assert_eq!(
        judge(&s, 0, &typing, &misnamed, now),
        Some(Judged::Not(NotAShare::AnotherChannel))
    );

    // More than one share: none is taken, and why is kept. The same share
    // from two relays is one.
    let second = share_by(&alice, &bob_key, &card(9, &[AT]), now, None);
    assert_eq!(
        taken(&s, 0, &typing, &[good.clone(), second], now),
        Became::Refused("more_than_one_share")
    );
    let kept = rows::typed_key(&s[0].conn, &alice.public_key())
        .unwrap()
        .unwrap();
    assert!(kept.detail.unwrap().contains("has 2 shares waiting"));
    // Rule 11: a relay of the card that is not one of the device's own.
    let far = share_by(&alice, &bob_key, &card(10, &[ELSEWHERE]), now, None);
    assert_eq!(
        taken(&s, 0, &typing, &[far], now),
        Became::Refused("not_own_relay")
    );
    let both = share_by(&alice, &bob_key, &card(10, &[AT, ELSEWHERE]), now, None);
    assert_eq!(
        taken(&s, 0, &typing, &[both], now),
        Became::Refused("not_own_relay")
    );
    // Rule 10: sync off.
    meta::remove(&s[0].conn, meta::SYNC_CLAUDE_DIR).unwrap();
    assert_eq!(
        taken(&s, 0, &typing, std::slice::from_ref(&good), now),
        Became::Refused("sync_off")
    );
    meta::set(&s[0].conn, meta::SYNC_CLAUDE_DIR, "/home/bob/.claude").unwrap();
    assert!(filed(&s[0].conn).unwrap().is_empty());

    // All hold: it is taken, filed as taken from the key, and its empty
    // anew record written; the typing is used up.
    assert_eq!(
        taken(&s, 0, &typing, &[good.clone(), good.clone()], now),
        Became::Taken(good_card.channel_id().unwrap())
    );
    let filings = filed(&s[0].conn).unwrap();
    assert_eq!(filings.len(), 1);
    assert_eq!(filings[0].name, "review");
    assert_eq!(filings[0].came, Came::Taken(alice.public_key()));
    let anew_slot = slot_id(
        &derive::slot_key(&good_card.secret().unwrap()).unwrap(),
        &anew_name(&bob_key).unwrap(),
    );
    let anew = entries::author_entry(
        &s[0].conn,
        &good_card.channel_id().unwrap(),
        &anew_slot,
        &bob_key,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        anew.entry.content.len(),
        cordelia_core::protocol::SHARED_ANEW_CONTENT_BYTES
    );
    assert_eq!(judge(&s, 0, &typing, &good, now), None);
    assert_eq!(
        taken(&s, 0, &typing, std::slice::from_ref(&good), now),
        Became::NotNow
    );

    // Rule 9: a channel the person holds already, typed again.
    let again = typed(&s, 0, &alice.public_key(), "review-again", now + 1);
    assert_eq!(
        taken(&s, 0, &again, std::slice::from_ref(&good), now + 1),
        Became::Refused("already_held")
    );
    assert!(
        rows::typed_key(&s[0].conn, &alice.public_key())
            .unwrap()
            .unwrap()
            .detail
            .unwrap()
            .contains("as \"review\"")
    );
}

/// The 16 channels of rule 9: a share of a 17th is not taken.
#[test]
fn a_share_past_sixteen_channels_is_not_taken() {
    let s = bob(1);
    let now = s.now + 10;
    for seed in 0..16u8 {
        crate::shared::tests::holds(&s, 0, 100 + seed, &format!("c{seed}"), now);
    }
    let alice = member(1);
    let typing = typed(&s, 0, &alice.public_key(), "review", now);
    let good = share_by(&alice, &s.key(0), &card(7, &[AT]), now, None);
    assert_eq!(
        taken(&s, 0, &typing, &[good], now),
        Became::Refused("too_many_channels")
    );
}

/// `shared new` makes a channel at the device's own relays known by key,
/// files it as made here, and writes its empty anew record; and refuses as
/// §5.5 says (decision 2026-10-10 §5.1, §5.5).
#[test]
fn shared_new_makes_a_channel_at_your_relays_and_refuses_as_the_table_says() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let word = |out: Out<Plan<New>>| match out {
        Err(Failed::Refused(refusal)) => refusal.word,
        other => panic!("{:?}", other.map(|plan| plan.asks)),
    };
    assert_eq!(word(new_plan(conn, &[], "review", &[])), "no_keyed_relay");
    assert_eq!(
        word(new_plan(
            conn,
            &relays(),
            "review",
            &["relay.other.org:9474".into()]
        )),
        "not_own_relay"
    );
    let three = vec!["a".to_string(), "b".into(), "c".into()];
    assert_eq!(word(new_plan(conn, &relays(), "review", &three)), "");
    let twice = vec!["relay.example.org:9474".to_string(); 2];
    assert_eq!(word(new_plan(conn, &relays(), "review", &twice)), "");
    assert_eq!(
        word(new_plan(conn, &relays(), "Not A Name!", &[])),
        "not_a_name"
    );

    let plan = new_plan(conn, &relays(), "review", &[]).unwrap();
    assert!(
        plan.asks.contains("filed on your devices as \"review\""),
        "{}",
        plan.asks
    );
    assert!(
        plan.asks.contains("  relay.example.org:9474 ("),
        "{}",
        plan.asks
    );
    let said = make_new(conn, &s[0].identity, &plan.what, now).unwrap();
    assert!(said.starts_with("Made \"review\": channel "), "{said}");
    let filing = &filed(conn).unwrap()[0];
    assert_eq!(filing.came, Came::Made);
    assert_eq!(filing.card.relays().keys(), &[AT]);
    let own = s.key(0);
    let slot = slot_id(
        &derive::slot_key(&filing.card.secret().unwrap()).unwrap(),
        &anew_name(&own).unwrap(),
    );
    assert!(
        entries::author_entry(conn, &filing.channel, &slot, &own)
            .unwrap()
            .is_some()
    );
    // Written once: a channel already holding it is written nothing more.
    assert_eq!(
        write_empty_anew_records(conn, &s[0].identity, now).unwrap(),
        0
    );
    // The name is taken now.
    assert_eq!(word(new_plan(conn, &relays(), "review", &[])), "name_taken");
    // Sync off: refused.
    meta::remove(conn, meta::SYNC_CLAUDE_DIR).unwrap();
    assert_eq!(word(new_plan(conn, &relays(), "other", &[])), "sync_off");
}

/// `share` writes one share for one key at a time, in the share pair
/// channel, kept two hours and then written over (decision 2026-10-10
/// §3.1), and refuses as §5.5 says.
#[test]
fn a_share_waits_for_one_key_at_a_time_and_goes_after_two_hours() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let made = |name: &str| {
        let plan = new_plan(conn, &relays(), name, &[]).unwrap();
        make_new(conn, identity, &plan.what, now).unwrap();
    };
    made("review");
    made("design");
    let alice = member(1).public_key();
    let alice_typed = encode_public_key(&alice).unwrap();
    let word = |out: Out<Plan<ShareTo>>| match out {
        Err(Failed::Refused(refusal)) => refusal.word,
        Ok(_) => "ok",
        Err(Failed::Error(e)) => panic!("{e}"),
    };
    let plan = |name: &str, key: &str, at: &[OwnRelay]| {
        share_plan(conn, identity, at, name, key, None, now)
    };
    assert_eq!(
        word(plan("nothing", &alice_typed, &relays())),
        "no_such_channel"
    );
    assert_eq!(word(plan("review", "cordelia_pk1nope", &relays())), "");
    let own_typed = encode_public_key(&s.key(0)).unwrap();
    assert_eq!(word(plan("review", &own_typed, &relays())), "own_device");
    assert_eq!(word(plan("review", &alice_typed, &[])), "not_reached");

    let to = plan("review", &alice_typed, &relays()).unwrap();
    assert!(to.asks.contains("no label of yours"), "{}", to.asks);
    assert!(to.asks.contains(&six_words(&alice)), "{}", to.asks);
    let said = make_share(conn, identity, &relays(), &to.what, now).unwrap();
    assert!(
        said[1].starts_with("  cordelia accept cordelia_pk1"),
        "{said:?}"
    );
    assert!(
        said[1].ends_with("--channel <a name of their choosing>"),
        "{said:?}"
    );
    assert!(
        said[4].starts_with("Keys that wrote here, in \"review\": unchanged since"),
        "{said:?}"
    );
    let (pair, secret) = share_pair(identity, &alice).unwrap();
    let review = to.what.filing.channel;
    let slot_of =
        |channel: &[u8; 32]| slot_id(&derive::slot_key(&secret).unwrap(), &share_name(channel));
    let held = entries::author_entry(conn, &pair, &slot_of(&review), &s.key(0))
        .unwrap()
        .unwrap();
    let opened = held.entry.check().unwrap().open(&secret).unwrap();
    assert_eq!(Share::from_value(&opened.value).unwrap().for_key, alice);

    // Another channel to the same key: the first is written over.
    let design = plan("design", &alice_typed, &relays()).unwrap();
    make_share(conn, identity, &relays(), &design.what, now + 1).unwrap();
    let first = entries::author_entry(conn, &pair, &slot_of(&review), &s.key(0))
        .unwrap()
        .unwrap();
    assert!(first.entry.check().unwrap().delete);
    assert_eq!(waiting(conn, now + 1).unwrap().len(), 1);

    // Eight keys wait: a ninth is refused, a key that waits is not.
    for n in 2..9 {
        let key = encode_public_key(&member(n).public_key()).unwrap();
        let to = plan("review", &key, &relays()).unwrap();
        make_share(conn, identity, &relays(), &to.what, now + 2).unwrap();
    }
    let ninth = encode_public_key(&member(9).public_key()).unwrap();
    assert_eq!(word(plan("review", &ninth, &relays())), "too_many_shares");
    assert_eq!(word(plan("review", &alice_typed, &relays())), "ok");

    // Two hours on, each is written over.
    assert_eq!(
        drop_old_shares(conn, identity, now + 2 * HOUR + 2).unwrap(),
        8
    );
    let second = entries::author_entry(
        conn,
        &pair,
        &slot_of(&design.what.filing.channel),
        &s.key(0),
    )
    .unwrap()
    .unwrap();
    assert!(second.entry.check().unwrap().delete);
    assert_eq!(word(plan("review", &ninth, &relays())), "ok");
    // And a day on, what is kept of them goes.
    drop_old_shares(conn, identity, now + DAY + 3).unwrap();
    assert!(rows::shares(conn).unwrap().is_empty());
}

/// `label` refuses a key of the person's own, a key that is not one, and a
/// label that is not 1 to 64 bytes once cleaned; `--none` of a key with no
/// label says so and does nothing (decision 2026-10-10 §5.2, §5.5).
#[test]
fn a_label_is_given_and_taken_away_as_the_table_says() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let carol = encode_public_key(&member(2).public_key()).unwrap();
    let word = |out: Out<Result<Plan<Labelling>, String>>| match out {
        Err(Failed::Refused(refusal)) => refusal.word.to_string(),
        Ok(Ok(_)) => "asks".into(),
        Ok(Err(line)) => line,
        Err(Failed::Error(e)) => panic!("{e}"),
    };
    let own = encode_public_key(&s.key(0)).unwrap();
    assert_eq!(
        word(label_plan(conn, identity, &own, Some("me"), now)),
        "own_device"
    );
    assert_eq!(
        word(label_plan(conn, identity, "nope", Some("me"), now)),
        ""
    );
    assert_eq!(
        word(label_plan(
            conn,
            identity,
            &carol,
            Some(&"x".repeat(65)),
            now
        )),
        "bad_label"
    );
    assert_eq!(
        word(label_plan(
            conn,
            identity,
            &carol,
            Some("\u{200b}\u{7}"),
            now
        )),
        "bad_label"
    );
    assert_eq!(
        word(label_plan(conn, identity, &carol, None, now)),
        format!(
            "({}) has no label of yours.",
            six_words(&member(2).public_key())
        )
    );
    let plan = label_plan(conn, identity, &carol, Some("carol"), now)
        .unwrap()
        .unwrap();
    assert!(
        plan.asks.starts_with("Your devices will show the device ("),
        "{}",
        plan.asks
    );
    let said = make_label(conn, identity, &plan.what, now).unwrap();
    assert!(
        said.ends_with("\"carol\" on every device of yours."),
        "{said}"
    );
    assert_eq!(
        label_given(conn, &member(2).public_key())
            .unwrap()
            .as_deref(),
        Some("carol")
    );
    let none = label_plan(conn, identity, &carol, None, now)
        .unwrap()
        .unwrap();
    make_label(conn, identity, &none.what, now + 1).unwrap();
    assert_eq!(label_given(conn, &member(2).public_key()).unwrap(), None);
}

/// `shared rename` files a channel under another name, and `shared drop`
/// stops every device of the person's holding it (decision 2026-10-10
/// §3.4); two filings in force under one name are told apart by their
/// words.
#[test]
fn a_channel_is_renamed_dropped_and_told_apart_by_its_words() {
    let mut s = bob(2);
    let now = s.now + 10;
    for n in 0..2 {
        let conn = &s[n].conn;
        let plan = new_plan(conn, &relays(), "review", &[]).unwrap();
        make_new(conn, &s[n].identity, &plan.what, now).unwrap();
    }
    s.meet(&[0, 1]);
    let now = s.now + 10;
    lists::follow(&s[0].conn, &s[0].identity, now).unwrap();
    let conn = &s[0].conn;
    let both = filed(conn).unwrap();
    assert_eq!(both.len(), 2, "{both:?}");
    let refused_word = |out: Out<String>| match out {
        Err(Failed::Refused(refusal)) => refusal.word,
        Ok(said) => panic!("{said}"),
        Err(Failed::Error(e)) => panic!("{e}"),
    };
    assert_eq!(
        refused_word(rename(conn, &s[0].identity, "review", "other", None, now)),
        "two_channels"
    );
    assert_eq!(
        refused_word(rename(
            conn,
            &s[0].identity,
            "review",
            "other",
            Some("no such words"),
            now
        )),
        "no_such_channel"
    );
    let words = channel_words(&both[1].channel);
    let said = rename(conn, &s[0].identity, "review", "other", Some(&words), now).unwrap();
    assert!(said.starts_with("Renamed \"review\""), "{said}");
    let names: Vec<String> = filed(conn).unwrap().into_iter().map(|f| f.name).collect();
    assert!(names.contains(&"other".to_string()) && names.contains(&"review".to_string()));
    assert_eq!(
        refused_word(rename(
            conn,
            &s[0].identity,
            "review",
            "other",
            None,
            now + 1
        )),
        "name_taken"
    );
    let plan = drop_plan(conn, &s[0].identity, "other", None, now + 2).unwrap();
    assert!(plan.asks.contains("\"other\""));
    make_drop(conn, &s[0].identity, &plan.what, "other", now + 2).unwrap();
    let names: Vec<String> = filed(conn).unwrap().into_iter().map(|f| f.name).collect();
    assert_eq!(names, ["review"]);
    assert_eq!(
        drop_plan(conn, &s[0].identity, "other", None, now + 2)
            .err()
            .map(|failed| match failed {
                Failed::Refused(refusal) => refusal.word,
                Failed::Error(e) => panic!("{e}"),
            }),
        Some("no_such_channel")
    );
}

/// `add-device`'s yes names each shared channel the person holds with the
/// keys that wrote there (decision 2026-10-10 §5.2): what its look gives.
#[test]
fn add_device_counts_the_keys_of_each_channel() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    assert!(held_with_keys(conn, &s.key(0)).unwrap().is_empty());
    let channel = crate::shared::tests::holds(&s, 0, 7, "review", now);
    crate::shared::tests::holds(&s, 0, 8, "design", now);
    let sorted = || {
        let mut held = held_with_keys(conn, &s.key(0)).unwrap();
        held.sort();
        held
    };
    assert_eq!(
        sorted(),
        [("design".to_string(), 0), ("review".to_string(), 0)]
    );
    for n in 1..4 {
        let entry = crate::shared::tests::message(&member(n), &channel, 1, "hello", now);
        crate::take::take(conn, &s[0].identity, &entry, now).unwrap();
    }
    assert_eq!(
        sorted(),
        [("design".to_string(), 0), ("review".to_string(), 3)]
    );
    // This device's own empty anew record is not counted, as `shared list`
    // does not count it.
    let plan = new_plan(conn, &relays(), "made", &[]).unwrap();
    make_new(conn, &s[0].identity, &plan.what, now).unwrap();
    let made = sorted().into_iter().find(|(name, _)| name == "made");
    assert_eq!(made, Some(("made".to_string(), 0)));
    let listed = list(conn, &s[0].identity, &relays(), false, now).unwrap();
    let in_list = listed["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|channel| channel["name"] == "made")
        .map(|channel| channel["keys"].clone());
    assert_eq!(in_list, Some(json!(0)));
}

/// The list says each channel by its words and its relays by the
/// configuration's address, whether it is reached, the keys typed for a
/// channel and the shares waiting (decision 2026-10-10 §5.1, §8.1, §8.3).
#[test]
fn the_list_says_each_channel_its_relays_and_what_waits() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let plan = new_plan(conn, &relays(), "review", &[]).unwrap();
    make_new(conn, identity, &plan.what, now).unwrap();
    let alice = encode_public_key(&member(1).public_key()).unwrap();
    let to = share_plan(conn, identity, &relays(), "review", &alice, None, now).unwrap();
    make_share(conn, identity, &relays(), &to.what, now).unwrap();
    typed(&s, 0, &member(2).public_key(), "design", now);
    let listed = list(conn, identity, &relays(), true, now).unwrap();
    let channel = &listed["channels"][0];
    assert_eq!(channel["name"], "review");
    assert_eq!(channel["reached"], true);
    assert_eq!(channel["relays"][0]["relay"], "relay.example.org:9474");
    assert_eq!(listed["shares"][0]["waiting"], true);
    assert_eq!(listed["shares"][0]["taken"], false);
    assert_eq!(listed["typed"][0]["name"], "design");
    assert_eq!(listed["typed"][0]["asking"], true);
    // Not reached from a device whose relays lack the card's.
    let elsewhere = list(conn, identity, &[], false, now).unwrap();
    assert_eq!(elsewhere["channels"][0]["reached"], false);
    assert!(elsewhere["channels"][0]["relays"][0]["relay"].is_null());
}

/// The routes of making, sharing and taking (decision 2026-10-10 §5.6):
/// each needs the node's token, is a personal node's, refuses a field it
/// does not know, says with `look` what the yes is for and does nothing,
/// and does it only where the yes was for the text it would ask now; a
/// relay is the configuration's that has a key.
#[actix_web::test]
async fn the_routes_ask_their_yes_and_refuse_a_field_they_do_not_know() {
    use actix_web::{App, test};
    let s = bob(1);
    let state = actix_web::web::Data::new(crate::several::state_of(
        s.machines.into_iter().next().unwrap(),
    ));
    *state.relays.write().unwrap() = vec![
        crate::state::RelaySnapshot {
            host: "relay.example.org:9474".into(),
            key: Some(encode_public_key(&AT).unwrap()),
            state: "connected".into(),
            unreachable_secs: None,
            last_tried_secs: None,
            error: None,
            tried: Default::default(),
            connection: None,
        },
        crate::state::RelaySnapshot {
            host: "nokey.example.org:9474".into(),
            key: None,
            state: "connected".into(),
            unreachable_secs: None,
            last_tried_secs: None,
            error: None,
            tried: Default::default(),
            connection: None,
        },
    ];
    let personal = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(crate::configure_device_routes),
    )
    .await;
    let call = |body: serde_json::Value, token: bool| {
        let mut request = test::TestRequest::post()
            .uri("/api/v1/shared/new")
            .set_json(body);
        if token {
            request = request.insert_header(("Authorization", "Bearer t"));
        }
        request.to_request()
    };
    let status = test::call_service(
        &personal,
        call(json!({ "name": "review", "look": true }), false),
    )
    .await
    .status();
    assert_eq!(status.as_u16(), 401);
    let status = test::call_service(
        &personal,
        call(
            json!({ "name": "review", "look": true, "to": "notes" }),
            true,
        ),
    )
    .await
    .status();
    assert_eq!(status.as_u16(), 400);
    let looked: serde_json::Value = test::call_and_read_body_json(
        &personal,
        call(json!({ "name": "review", "look": true }), true),
    )
    .await;
    let asks = looked["asks"].as_str().unwrap().to_string();
    assert!(asks.contains("  relay.example.org:9474 ("), "{asks}");
    assert!(!asks.contains("nokey.example.org"), "{asks}");
    assert!(filed(&state.db.lock().unwrap()).unwrap().is_empty());
    // A yes to another text does nothing.
    let changed = test::call_service(
        &personal,
        call(
            json!({ "name": "review", "said_yes_to": format!("{asks} ") }),
            true,
        ),
    )
    .await;
    assert_eq!(changed.status().as_u16(), 409);
    assert!(filed(&state.db.lock().unwrap()).unwrap().is_empty());
    let made: serde_json::Value = test::call_and_read_body_json(
        &personal,
        call(json!({ "name": "review", "said_yes_to": asks }), true),
    )
    .await;
    assert!(
        made["said"][0]
            .as_str()
            .unwrap()
            .starts_with("Made \"review\"")
    );
    assert_eq!(filed(&state.db.lock().unwrap()).unwrap().len(), 1);
    // A refusal is a conflict whose code is its word.
    let refused = test::call_service(
        &personal,
        call(json!({ "name": "review", "look": true }), true),
    )
    .await;
    assert_eq!(refused.status().as_u16(), 409);
    let said: serde_json::Value = test::read_body_json(refused).await;
    assert_eq!(said["error"]["code"], "name_taken");
    // Not served by a node of another role.
    let relay = test::init_service(
        App::new()
            .app_data(state.clone())
            .configure(crate::configure_routes),
    )
    .await;
    let status = test::call_service(&relay, call(json!({ "name": "x", "look": true }), true))
        .await
        .status();
    assert_eq!(status.as_u16(), 404);
}

/// A key the person's statement lists as removed is handed nothing, taken
/// from in nothing and labelled nothing (decision 2026-10-10 §5.5,
/// `removed_key`).
#[test]
fn a_removed_key_is_handed_nothing_taken_from_or_labelled() {
    let mut s = bob(2);
    s.change(0, &[0], &[1]);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    meta::set(conn, meta::SYNC_CLAUDE_DIR, "/home/bob/.claude").unwrap();
    let plan = new_plan(conn, &relays(), "review", &[]).unwrap();
    make_new(conn, identity, &plan.what, now).unwrap();
    let removed = encode_public_key(&s.key(1)).unwrap();
    let word = |failed: Failed| match failed {
        Failed::Refused(refusal) => refusal.word,
        Failed::Error(e) => panic!("{e}"),
    };
    let shared = share_plan(conn, identity, &relays(), "review", &removed, None, now);
    assert_eq!(word(shared.err().unwrap()), "removed_key");
    let accepted = accept_plan(conn, identity, &relays(), &removed, "taken", now);
    assert_eq!(word(accepted.err().unwrap()), "removed_key");
    let labelled = label_plan(conn, identity, &removed, Some("old"), now);
    assert_eq!(word(labelled.err().unwrap()), "removed_key");
}

/// A device that leaves its person keeps no share it wrote, whose card
/// holds the seed, and no key typed for a channel, which would take a
/// share into the list of the person it joins next (decision 2026-10-10
/// §3.1, §3.2; the record of 2026-10-04, §5.2).
#[test]
fn a_device_that_leaves_keeps_no_share_and_no_typed_key() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let plan = new_plan(conn, &relays(), "review", &[]).unwrap();
    make_new(conn, identity, &plan.what, now).unwrap();
    let alice = member(1).public_key();
    let typed_key = encode_public_key(&alice).unwrap();
    let to = share_plan(conn, identity, &relays(), "review", &typed_key, None, now).unwrap();
    make_share(conn, identity, &relays(), &to.what, now).unwrap();
    typed(&s, 0, &member(2).public_key(), "design", now);
    let (pair, _) = share_pair(identity, &alice).unwrap();
    assert_eq!(
        entries::author_entries(conn, &pair, &s.key(0))
            .unwrap()
            .len(),
        1
    );

    assert!(crate::leaving::forget(conn, identity, true, now + 1).unwrap());
    assert!(
        entries::author_entries(conn, &pair, &s.key(0))
            .unwrap()
            .is_empty()
    );
    assert!(rows::shares(conn).unwrap().is_empty());
    assert!(rows::typed_keys(conn).unwrap().is_empty());
}

/// A filing and a label past a bound are still acted on (decision
/// 2026-10-10 §3.4: "an item in force past a bound can be undone", and a
/// rename of a filing past it is never refused): `shared drop`, `shared
/// rename` and `label --none` find them, as `shared list` names them.
#[test]
fn a_filing_and_a_label_past_a_bound_are_still_acted_on() {
    let mut s = bob(2);
    let now = s.now + 10;
    // Device 1 files 16 and labels 64; device 0 then files 16 and labels
    // 64 that are newer, which push device 1's past the bounds on device
    // 0. Device 1's own list still carries them.
    for (n, at) in [(1, now), (0, now + 100)] {
        let conn = &s[n].conn;
        for i in 0..SHARED_MAX_CHANNELS {
            let plan = new_plan(conn, &relays(), &format!("d{n}-{i}"), &[]).unwrap();
            make_new(conn, &s[n].identity, &plan.what, at).unwrap();
        }
        for i in 0..64u32 {
            let key = member(1000 * (n as u32 + 1) + i).public_key();
            crate::shared::tests::labels(&s, n, &key, Some("someone"), at);
        }
    }
    s.meet(&[0, 1]);
    let now = s.now + 200;
    lists::follow(&s[0].conn, &s[0].identity, now).unwrap();
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let listed = list(conn, identity, &relays(), false, now).unwrap();
    assert!(
        listed["past_a_bound"]
            .as_array()
            .unwrap()
            .contains(&json!("d1-0")),
        "{}",
        listed["past_a_bound"]
    );
    assert!(
        filed(conn)
            .unwrap()
            .iter()
            .all(|f| f.name.starts_with("d0-"))
    );

    let plan = drop_plan(conn, identity, "d1-0", None, now).unwrap();
    make_drop(conn, identity, &plan.what, "d1-0", now).unwrap();
    let said = rename(conn, identity, "d1-1", "renamed", None, now + 1).unwrap();
    assert!(said.starts_with("Renamed \"d1-1\""), "{said}");
    let key = encode_public_key(&member(2000).public_key()).unwrap();
    let none = label_plan(conn, identity, &key, None, now + 2).unwrap();
    let none = none.unwrap_or_else(|line| panic!("{line}"));
    make_label(conn, identity, &none.what, now + 2).unwrap();
}

/// `shared list` calls a share taken only where its key came to write in
/// the channel since the share was made, by this device's clock (decision
/// 2026-10-10 §19, item 41): a key that wrote there within the hour before
/// it does not make it taken.
#[test]
fn a_share_is_taken_only_by_what_its_key_wrote_since() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let plan = new_plan(conn, &relays(), "review", &[]).unwrap();
    make_new(conn, identity, &plan.what, now).unwrap();
    let channel = plan_channel(conn, "review");
    let alice = member(1);
    let shared = crate::shared::tests::Shared {
        secret: channel.card.secret().unwrap(),
        id: channel.channel,
    };
    let before = crate::shared::tests::message(&alice, &shared, 1, "hello", now);
    crate::take::take(conn, identity, &before, now).unwrap();
    let typed_key = encode_public_key(&alice.public_key()).unwrap();
    let to = share_plan(
        conn,
        identity,
        &relays(),
        "review",
        &typed_key,
        None,
        now + 60,
    )
    .unwrap();
    make_share(conn, identity, &relays(), &to.what, now + 60).unwrap();
    let listed = list(conn, identity, &relays(), false, now + 61).unwrap();
    assert_eq!(listed["shares"][0]["taken"], false, "{listed}");
}

/// The filing in force named `name`.
fn plan_channel(conn: &Connection, name: &str) -> Filing {
    filed(conn)
        .unwrap()
        .into_iter()
        .find(|filing| filing.name == name)
        .unwrap()
}
