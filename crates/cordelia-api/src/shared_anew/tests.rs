//! Tests of making a shared channel anew, moving, a removal and a recovery
//! (decision 2026-10-10 §3.5, §7; decision 2026-10-24, rules 23 to 26),
//! in-process.

use super::*;
use crate::lists::tests::filing;
use crate::several::{Several, Twin};
use crate::shared::Read;
use crate::shared::tests::{
    FULL, Shared, acts, anew, anew_of, bob, fill_to, holds, labels, member, out, row, stores,
};
use cordelia_crypto::acts::{Label, Subscription};
use cordelia_crypto::shared::{Anew, Offer, Seal};

/// The relay of these tests' channels, known by its key.
const AT: [u8; 32] = [3; 32];

fn relays() -> Vec<OwnRelay> {
    vec![OwnRelay {
        name: "relay.example.org:9474".into(),
        key: AT,
    }]
}

/// The card of a new channel, made from `seed`, at the relay of these
/// tests.
fn new_card(seed: u8) -> Card {
    filing(seed, "x").card
}

/// The offer of `maker` that makes `old` anew as the card of `seed`, sealed
/// to `keys`, at revision `rev`.
fn offer_by(
    maker: &NodeIdentity,
    old: &Shared,
    seed: u8,
    keys: &[[u8; 32]],
    made: i64,
    rev: u64,
) -> CheckedEntry {
    let offer = Offer::make(made as u64, &old.id, &new_card(seed), keys).unwrap();
    anew_of(maker, old, rev, Anew::Offer(offer).to_value().unwrap())
}

use cordelia_crypto::entry::CheckedEntry;

/// Each member of `members` writes its empty anew record in `channel`, and
/// device `n` stores it: the device then shows each key.
pub(crate) fn written_by(
    s: &Several,
    n: usize,
    channel: &Shared,
    members: &[&NodeIdentity],
    now: i64,
) {
    for member in members {
        stores(s, n, &anew(member, channel, 1), now);
    }
}

/// What device `n` makes of each offer in `channel`, by maker.
fn what_is(s: &Several, n: usize, channel: &Shared, now: i64) -> Vec<([u8; 32], OfferIs)> {
    judged(&s[n].conn, &s[n].identity, &row(s, n, channel), Some(now))
        .unwrap()
        .into_iter()
        .map(|judged| (judged.offer.maker, judged.is))
        .collect()
}

/// The keys `shared anew` lists and asks about in the channel named `name`
/// on the device of `identity`, each as `cordelia id` writes it.
fn asked_of(conn: &Connection, identity: &NodeIdentity, name: &str, now: i64) -> Vec<String> {
    let (listing, _) = anew_plan(conn, identity, &relays(), name, None, &[], None, now).unwrap();
    listing
        .asked
        .iter()
        .map(|key| encode_public_key(key).unwrap())
        .collect()
}

fn refusal_word<T: std::fmt::Debug>(done: Out<T>) -> &'static str {
    match done {
        Err(Failed::Refused(refusal)) => refusal.word,
        other => panic!("{other:?}"),
    }
}

/// An offer leaves out, or is a fault, by its seals and the reader's own
/// statement alone (decision 2026-10-10 §7): one that seals to no device of
/// Bob's is "without you"; one whose seal for Bob's device does not open,
/// and one by a key Bob's statement removed, are faults naming their maker,
/// and `shared move` then refuses with `no_offer`; an offer of the old
/// channel itself, of another channel Bob holds, and of a channel Bob
/// dropped whose drop is kept, are each the fault `held`, also where they
/// seal to no device of Bob's, and none is "without you"; one that seals to
/// Bob's desktop and not his laptop is refused on the laptop with
/// `sealed_elsewhere`.
#[test]
fn an_offer_leaves_out_or_is_a_fault_by_its_seals_and_your_statement_alone() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let other = holds(&s, 0, 8, "other", now);
    let dropped = holds(&s, 0, 9, "gone", now);
    acts(&s, 0, Do::Drop(dropped.id), now);
    let laptop = s.key(0);
    let desktop = s.key(1);
    // The tablet offers, sealed to the laptop, and is then removed by Bob's
    // statement: its offer is a fault.
    let tablet = crate::several::identity_of(2);
    stores(&s, 0, &anew(&tablet, &channel, 1), now);
    stores(
        &s,
        0,
        &offer_by(&tablet, &channel, 22, &[laptop], now, 2),
        now,
    );
    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    let (alice, carol, broken, same, held, was_dropped) = (
        member(1),
        member(2),
        member(3),
        member(5),
        member(6),
        member(7),
    );
    written_by(
        &s,
        0,
        &channel,
        &[&alice, &carol, &broken, &same, &held, &was_dropped],
        now,
    );

    // Without you: sealed to Alice and Carol alone.
    stores(
        &s,
        0,
        &offer_by(
            &carol,
            &channel,
            20,
            &[carol.public_key(), alice.public_key()],
            now,
            2,
        ),
        now,
    );
    // A seal for the laptop that does not open.
    let mut offer = Offer::make(now as u64, &channel.id, &new_card(21), &[laptop]).unwrap();
    offer.seals[0].sealed[40] ^= 1;
    stores(
        &s,
        0,
        &anew_of(&broken, &channel, 2, Anew::Offer(offer).to_value().unwrap()),
        now,
    );
    // Of the old channel itself, of another channel held, of one dropped:
    // each sealed to nobody of Bob's.
    let into = |new_channel: [u8; 32]| {
        Anew::Offer(Offer {
            made: now as u64,
            new_channel,
            relays: Relays::new(&[AT]).unwrap(),
            seals: vec![Seal {
                key: alice.public_key(),
                sealed: [1; SEALED_SECRET_BYTES],
            }],
        })
        .to_value()
        .unwrap()
    };
    stores(&s, 0, &anew_of(&same, &channel, 2, into(channel.id)), now);
    stores(&s, 0, &anew_of(&held, &channel, 2, into(other.id)), now);
    stores(
        &s,
        0,
        &anew_of(&was_dropped, &channel, 2, into(dropped.id)),
        now,
    );

    let is = what_is(&s, 0, &channel, now);
    let of = |key: [u8; 32]| {
        is.iter()
            .find(|(maker, _)| *maker == key)
            .map(|(_, is)| is.clone())
            .unwrap_or_else(|| panic!("no offer of that key: {is:?}"))
    };
    assert_eq!(of(carol.public_key()), OfferIs::WithoutYou);
    assert_eq!(of(broken.public_key()), OfferIs::Fault(Fault::DidNotOpen));
    assert_eq!(of(tablet.public_key()), OfferIs::Fault(Fault::MakerRemoved));
    for key in [same, held, was_dropped].map(|m| m.public_key()) {
        assert_eq!(of(key), OfferIs::Fault(Fault::Held));
    }
    // Each is listed with its maker.
    let lines = offer_lines(
        &s[0].conn,
        &s[0].identity,
        &judged(&s[0].conn, &s[0].identity, &row(&s, 0, &channel), Some(now)).unwrap(),
    )
    .unwrap();
    assert_eq!(lines.len(), 6, "{lines:?}");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("into a channel you hold or held: a fault, not a move"))
            .count(),
        3,
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.ends_with("without you")),
        "{lines:?}"
    );
    // The channel is not clean on the laptop, which applied the removal of
    // the tablet: `shared move` is refused there (rule 25).
    let refused = move_plan(
        &s[0].conn,
        &s[0].identity,
        &relays(),
        "review",
        None,
        None,
        now,
    );
    assert_eq!(refusal_word(refused), "not_clean");
    st(rows::clean(&s[0].conn, &channel.id)).unwrap();
    // None of them is an offer to move to.
    let refused = move_plan(
        &s[0].conn,
        &s[0].identity,
        &relays(),
        "review",
        None,
        None,
        now,
    );
    assert_eq!(refusal_word(refused), "no_offer");

    // Sealed to the desktop and not the laptop: on the laptop, run it
    // there. Made here after the removal, so clean here (rule 23).
    let second = made_new(&s, 0, "second", now);
    written_by(&s, 0, &second, &[&alice], now);
    stores(
        &s,
        0,
        &offer_by(&alice, &second, 23, &[alice.public_key(), desktop], now, 2),
        now,
    );
    assert!(matches!(
        what_is(&s, 0, &second, now)[..],
        [(_, OfferIs::SealedElsewhere(key))] if key == desktop
    ));
    let refused = move_plan(
        &s[0].conn,
        &s[0].identity,
        &relays(),
        "second",
        None,
        None,
        now,
    );
    assert_eq!(refusal_word(refused), "sealed_elsewhere");
}

/// A move lists the mover's own devices as following (decision 2026-10-10
/// §7): an offer that seals to Bob's desktop and not to his phone; the
/// desktop's `shared move` names the phone among the devices that follow
/// the move, and not among the keys left out.
#[test]
fn a_move_lists_your_own_devices_as_following() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    let (alice, carol) = (member(1), member(2));
    written_by(&s, 1, &channel, &[&alice, &carol], now);
    let phone = s.key(2);
    for device in [phone, s.key(0)] {
        stores(
            &s,
            1,
            &anew(
                &s[if device == phone { 2 } else { 0 }].identity,
                &channel,
                1,
            ),
            now,
        );
    }
    stores(
        &s,
        1,
        &offer_by(
            &alice,
            &channel,
            20,
            &[alice.public_key(), s.key(1)],
            now,
            2,
        ),
        now,
    );
    let plan = move_plan(
        &s[1].conn,
        &s[1].identity,
        &relays(),
        "review",
        None,
        None,
        now,
    )
    .unwrap();
    let held = crate::person::held(&s[1].conn).unwrap().unwrap();
    let phone_form = sender_form(&s[1].conn, &held, &s.key(1), &phone).unwrap();
    let carol_form = sender_form(&s[1].conn, &held, &s.key(1), &carol.public_key()).unwrap();
    let follow = plan
        .asks
        .lines()
        .find(|line| line.starts_with("Your own devices follow your move: "))
        .unwrap_or_else(|| panic!("{}", plan.asks));
    assert!(follow.contains(&phone_form), "{}", plan.asks);
    let left = plan
        .asks
        .lines()
        .find(|line| line.starts_with("These are left out: "))
        .unwrap_or_else(|| panic!("{}", plan.asks));
    assert!(!left.contains(&phone_form), "{}", plan.asks);
    assert!(left.contains(&carol_form), "{}", plan.asks);
    assert!(plan.asks.contains("No agent of yours subscribes to it."));
    assert!(
        plan.asks
            .contains("Offers from keys this device shows: 1, of them faults: 0."),
        "{}",
        plan.asks
    );
    // The offer's line says the one key it leaves out with its noun (§5.2).
    let lines = offer_lines(
        &s[1].conn,
        &s[1].identity,
        &judged(&s[1].conn, &s[1].identity, &row(&s, 1, &channel), Some(now)).unwrap(),
    )
    .unwrap();
    assert!(
        lines.iter().any(|line| line.ends_with(", without 1 key")),
        "{lines:?}"
    );
}

/// A channel full at the device's room can still be made anew (decision
/// 2026-10-10 §6.3, T3): with the room of the keys Bob does not know full, a
/// member already there writes its offer over its empty anew record, at no
/// larger size, and it is taken and read.
#[test]
fn a_full_channel_can_still_be_made_anew() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    fill_to(&s, 0, &channel, FULL, now);
    let member = member(100_001);
    let offer = offer_by(
        &member,
        &channel,
        20,
        &[member.public_key(), s.key(0)],
        now,
        2,
    );
    assert!(matches!(
        stores(&s, 0, &offer, now),
        Some(Read::Anew(Anew::Offer(_)))
    ));
    assert!(matches!(
        what_is(&s, 0, &channel, now)[..],
        [(maker, OfferIs::ForThisDevice(_))] if maker == member.public_key()
    ));
}

/// What `shared anew` lists before it asks (decision 2026-10-10 §7): every
/// key of the table, a member's 100 keys and Dave's after them among them;
/// the person's own devices as staying and not asked about; a key Bob's
/// statement removed as left out and not asked about; the rows the table
/// let go, counted; and the line on labels. Of the answers, a `keep` past
/// 64 is refused, and the offer seals to exactly the keys answered `keep`
/// and Bob's own devices.
#[test]
fn out_for_the_rest_comes_only_after_the_whole_list() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    let tablet = crate::several::identity_of(2);
    stores(&s, 0, &anew(&tablet, &channel, 1), now);
    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    let members: Vec<NodeIdentity> = (0..100).map(|k| member(1_000 + k)).collect();
    let refs: Vec<&NodeIdentity> = members.iter().collect();
    written_by(&s, 0, &channel, &refs, now);
    let dave = member(9);
    written_by(&s, 0, &channel, &[&dave], now);
    let conn = &s[0].conn;
    conn.execute(
        "UPDATE shared_channels SET let_go = 3 WHERE channel = ?1",
        [&channel.id[..]],
    )
    .unwrap();

    let (listing, plan) = anew_plan(
        conn,
        &s[0].identity,
        &relays(),
        "review",
        None,
        &[],
        None,
        now,
    )
    .unwrap();
    assert!(plan.is_none(), "nothing is asked before the list is shown");
    let held = crate::person::held(conn).unwrap().unwrap();
    let form = |key: &[u8; 32]| sender_form(conn, &held, &s.key(0), key).unwrap();
    // Every key is in the list, Dave's among them, and asked about.
    assert_eq!(listing.asked.len(), 101, "{:?}", listing.lines);
    assert!(listing.asked.contains(&dave.public_key()));
    let dave_form = form(&dave.public_key());
    assert!(
        listing
            .lines
            .iter()
            .any(|line| line.starts_with(&format!("  {dave_form}: first held"))),
        "{:?}",
        listing.lines
    );
    // Bob's own devices stay and are not asked; the tablet is left out.
    assert_eq!(
        listing.own_devices.keys().copied().collect::<Vec<_>>(),
        vec![s.key(0), s.key(1)]
    );
    assert!(!listing.asked.contains(&s.key(1)));
    assert!(
        listing.lines.iter().any(|line| line
            == &format!(
                "  {}: left out, a device you removed",
                form(&tablet.public_key())
            )),
        "{:?}",
        listing.lines
    );
    assert!(!listing.asked.contains(&tablet.public_key()));
    assert!(
        listing
            .lines
            .contains(&"  no longer known on this device, so left out: up to 3 keys".to_string())
    );
    assert_eq!(listing.lines.last().unwrap(), LABEL_FIRST);

    let listed: Vec<String> = listing
        .asked
        .iter()
        .map(|key| encode_public_key(key).unwrap())
        .collect();
    // A key it did not ask about is no answer: the tablet's, removed.
    let unasked = vec![encode_public_key(&tablet.public_key()).unwrap()];
    let refused = anew_plan(
        conn,
        &s[0].identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&unasked, &listed)),
        now,
    );
    assert_eq!(
        refusal_word(refused.map(|(_, plan)| plan.map(|p| p.asks))),
        ""
    );
    // A keep past 64 staying is refused.
    let too_many: Vec<String> = listing.asked[..63]
        .iter()
        .map(|key| encode_public_key(key).unwrap())
        .collect();
    let refused = anew_plan(
        conn,
        &s[0].identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&too_many, &listed)),
        now,
    );
    assert_eq!(
        refusal_word(refused.map(|(_, plan)| plan.map(|p| p.asks))),
        ""
    );
    // Dave kept, every other out: the offer seals to Dave and Bob's own
    // devices, and to nobody else.
    let keep = vec![encode_public_key(&dave.public_key()).unwrap()];
    let (_, plan) = anew_plan(
        conn,
        &s[0].identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&keep, &listed)),
        now,
    )
    .unwrap();
    let plan = plan.unwrap();
    assert!(
        plan.asks
            .ends_with("Staying: 3 keys, your own devices among them. Left out: up to 104 keys."),
        "{}",
        plan.asks
    );
    assert!(plan.asks.starts_with(A_PERSONS_DEVICES));
    make_anew(conn, &s[0].identity, &relays(), &plan.what, now).unwrap();
    let mine = st(rows::offer_from(conn, &channel.id, &s.key(0)))
        .unwrap()
        .unwrap();
    let mut sealed = mine.sealed_to.clone();
    sealed.sort();
    let mut expected = vec![s.key(0), s.key(1), dave.public_key()];
    expected.sort();
    assert_eq!(sealed, expected);
}

/// A removal makes each shared channel anew without the removed key
/// (decision 2026-10-24, rules 23 and 24; decision 2026-10-10 §3.5, §7):
/// on the device that makes it, with no question, sealed to its own
/// devices and to Alice, whom the laptop labelled, and its subscription
/// moved with its start; the old channel's entries stay until its offer is at each relay
/// of its card, and then go. The other device follows the filing, and its
/// old channel is moved from: neither is left not clean.
#[test]
fn a_removal_makes_each_shared_channel_anew_without_the_removed_key() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let subscription = Subscription {
        channel: channel.id,
        agent: "github.com/owner/repo".into(),
        subscribed: true,
    };
    acts(&s, 0, Do::Subscribe(subscription), now);
    labels(&s, 0, &member(1).public_key(), Some("alice"), now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    let start = crate::shared_messages::start_of(&s[0].conn, &channel.id, "github.com/owner/repo")
        .unwrap()
        .unwrap();
    let alice = member(1);
    written_by(&s, 0, &channel, &[&alice], now);
    let tablet = crate::several::identity_of(2);
    stores(&s, 0, &anew(&tablet, &channel, 1), now);
    // A message of the laptop's own there, not yet at the relay: after the
    // removal it is never sent there (rule 23).
    stores(
        &s,
        0,
        &crate::shared::tests::message(&s[0].identity, &channel, 1, "before", now),
        now,
    );

    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    assert!(is_not_clean(conn, &channel.id).unwrap(), "rule 23");
    let said = anew_at_removal(conn, &s[0].identity, &relays(), now).unwrap();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].starts_with("\"review\" is made anew without the device removed"));
    assert!(!is_not_clean(conn, &channel.id).unwrap());
    assert!(
        st(rows::not_clean_of(conn, &channel.id)).unwrap().is_none(),
        "its mark goes"
    );
    let offer = st(rows::offer_from(conn, &channel.id, &s.key(0)))
        .unwrap()
        .unwrap();
    assert!(offer.sealed_to.contains(&alice.public_key()));
    assert!(offer.sealed_to.contains(&s.key(1)));
    assert!(!offer.sealed_to.contains(&tablet.public_key()), "rule 24");
    let new = sharing::filed(conn).unwrap();
    assert_eq!(new.len(), 1);
    assert_eq!(
        (new[0].name.as_str(), new[0].channel),
        ("review", offer.new_channel)
    );
    // The subscription moved, with its start.
    assert_eq!(
        crate::shared_messages::start_of(conn, &offer.new_channel, "github.com/owner/repo")
            .unwrap(),
        Some(start)
    );
    // The old channel's entries wait for the offer.
    let old_row = row(&s, 0, &channel);
    assert_eq!(old_row.state, State::Moved);
    out(&s, 0, now);
    assert!(!s[0].stored_in(&channel.secret).is_empty());
    let usable = crate::shared_pass::usable(conn, &channel.id, &AT)
        .unwrap()
        .unwrap();
    let most = crate::at_relays::Most {
        entries: 100,
        bytes: 1 << 20,
    };
    let batch = crate::shared_pass::to_send(conn, &s[0].identity, &usable, &AT, most).unwrap();
    assert_eq!(batch.len(), 1, "the offer alone");
    assert_eq!(batch[0].rev, offer.rev);
    let answers = vec![crate::at_relays::Pushed::Holds];
    crate::shared_pass::pushed(conn, &s[0].identity, &usable, &AT, &batch, &answers, now).unwrap();
    out(&s, 0, now);
    assert!(
        s[0].stored_in(&channel.secret).is_empty(),
        "its entries went"
    );

    // The desktop applies the change and takes the filing: it moves too.
    s.pass(0, 1);
    let now = s.now + 30;
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    out(&s, 1, now);
    assert_eq!(row(&s, 1, &channel).state, State::Moved);
    assert!(!is_not_clean(&s[1].conn, &channel.id).unwrap());
    let held_new = st(kept::channel(&s[1].conn, &offer.new_channel))
        .unwrap()
        .unwrap();
    assert_eq!(held_new.state, State::Held);
}

/// A channel not yet clean is written in by nobody (decision 2026-10-24,
/// rules 23 and 25): the device that made the removal is lost before its
/// offer; the desktop applies the removal, writes nothing of its own there,
/// names the channel in `cordelia devices` and in the status's
/// `removed_device_holds`, the fact the amber is read from (the amber
/// itself, from the node to the command, is checked in `shared_e2e.rs`,
/// `no_move_goes_into_a_channel_a_removed_key_reads`); `shared anew` there
/// goes through and ends both.
#[test]
fn a_channel_not_yet_clean_is_written_in_by_nobody() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    // The laptop removes the tablet, and is lost before its offer.
    s.change(0, &[0, 1], &[2]);
    s.pass(0, 1);
    let now = s.now + 20;
    let conn = &s[1].conn;
    let identity = &s[1].identity;
    assert!(is_not_clean(conn, &channel.id).unwrap());
    let held_row = row(&s, 1, &channel);
    assert!(!writes_there(conn, identity, &held_row).unwrap());
    // Its empty anew record is not written there, nor anything sent.
    let anew_slot = slot_id(
        &derive::slot_key(&channel.secret).unwrap(),
        &anew_name(&s.key(1)).unwrap(),
    );
    entries::remove_slot(conn, &channel.id, &anew_slot).unwrap();
    assert_eq!(
        sharing::write_empty_anew_records(conn, identity, now).unwrap(),
        0
    );
    let usable = crate::shared_pass::usable(conn, &channel.id, &AT)
        .unwrap()
        .unwrap();
    let most = crate::at_relays::Most {
        entries: 100,
        bytes: 1 << 20,
    };
    assert!(
        crate::shared_pass::to_send(conn, identity, &usable, &AT, most)
            .unwrap()
            .is_empty()
    );
    // The status says it as held by the removed device.
    assert_eq!(
        removed_device_holds(&s, 1, now),
        serde_json::json!([["review"]])
    );
    // `cordelia devices` names it, with the removed device that still
    // has it, by its words and name, and the command (decision 2026-11-11
    // (plain words), rules 2 to 4).
    let seen = crate::look::look(conn, identity, &Default::default(), now).unwrap();
    let tablet =
        crate::look::named_device("device 2", &cordelia_crypto::fingerprint::shown(&s.key(2)));
    let line = not_clean_named_line("review", std::slice::from_ref(&tablet));
    assert_eq!(
        line,
        format!(
            "\"review\": {tablet}, which you removed, can still read new messages there, and \
             this device sends nothing there until you reset it. To stop that: cordelia shared \
             reset review"
        )
    );
    let notice = seen
        .notices
        .iter()
        .find(|notice| notice.says == line)
        .unwrap_or_else(|| panic!("{:?}", seen.notices));
    // Cleared, it is named no more, and a statement after does not bring
    // it back (§3.5: clearing ends the naming).
    let id: [u8; 32] = hex::decode(&notice.id).unwrap().try_into().unwrap();
    crate::look::clear(conn, identity, &id, now)
        .unwrap()
        .unwrap();
    s.change(1, &[0, 1], &[]);
    let conn = &s[1].conn;
    let identity = &s[1].identity;
    let seen = crate::look::look(conn, identity, &Default::default(), now).unwrap();
    assert!(
        !seen.notices.iter().any(|notice| notice.says == line),
        "{:?}",
        seen.notices
    );
    assert!(is_not_clean(conn, &channel.id).unwrap());
    // `shared anew` goes through, and ends it.
    let listed = asked_of(conn, identity, "review", now);
    let (_, plan) = anew_plan(
        conn,
        identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&[], &listed)),
        now,
    )
    .unwrap();
    make_anew(conn, identity, &relays(), &plan.unwrap().what, now).unwrap();
    assert!(!is_not_clean(conn, &channel.id).unwrap());
    assert_eq!(removed_device_holds(&s, 1, now), serde_json::json!([]));
}

/// The channels of each group of the status's `removed_device_holds` on
/// device `n` of `s` at `now`.
fn removed_device_holds(s: &Several, n: usize, now: i64) -> serde_json::Value {
    let own = relays();
    let said = crate::state::SharedSaid::default();
    let beside = crate::shared_status::Beside {
        own_relays: &own,
        connected: &[AT],
        said: &said,
        next_read: None,
    };
    let shared = crate::shared_status::status_of(&s[n].conn, &s[n].identity, &beside, now)
        .unwrap()
        .unwrap();
    shared["removed_device_holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["channels"].clone())
        .collect()
}

/// A recovery takes and names the acts of a device in someone else's hands
/// (decision 2026-10-10 §3.5, T23): the laptop files a channel, subscribes
/// an agent and labels a key, and the desktop holds a copy; told the laptop
/// is in someone else's hands and the desktop still had, the recovery names
/// each of the laptop's acts with its undoing, passes over the desktop's,
/// and the new machine takes the laptop's; the desktop, once added again,
/// holds the same items in force.
#[test]
fn a_recovery_takes_and_names_the_acts_of_a_device_in_someone_elses_hands() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    acts(
        &s,
        0,
        Do::Subscribe(Subscription {
            channel: channel.id,
            agent: "github.com/owner/repo".into(),
            subscribed: true,
        }),
        now,
    );
    let alice = member(1);
    acts(
        &s,
        0,
        Do::Label(Label {
            key: alice.public_key(),
            label: Some("alice".into()),
        }),
        now,
    );
    // The desktop files a channel of its own.
    holds(&s, 1, 8, "desk", now);
    s.meet(&[0, 1]);
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    let personal = s[0].personal();
    let handed: Vec<CheckedEntry> = s[0].stored().into_iter().chain(s[1].stored()).collect();
    let lists = crate::lists::lists_in(&handed, &personal, &[s.key(0), s.key(1)]).unwrap();
    assert_eq!(lists.len(), 2);
    let gone = vec![(s.key(0), "laptop".to_string())];
    let have = vec![(s.key(1), "desktop".to_string())];
    let lines = recovery_lines(&lists, &gone, &have).unwrap();
    let all = lines.join("\n");
    for named in [
        "\"review\" filed (channel",
        "github.com/owner/repo subscribed to \"review\"",
        "labelled \"alice\"",
        "undo it with cordelia shared drop review",
        "undo it with cordelia unsubscribe review --agent github.com/owner/repo",
        "--none, or cordelia label",
    ] {
        assert!(all.contains(named), "{named}: {all}");
    }
    assert!(
        all.contains("is passed over until each is added again"),
        "{all}"
    );
    assert!(all.contains("\"desk\" filed"), "{all}");
    // Passed over, it is neither brought back nor named with its undoing.
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("\"desk\" filed") && line.contains("undo it with")),
        "{all}"
    );
    // The new machine takes the laptop's acts, and not the desktop's.
    let (written, _) = lists::recovered(&lists, |key| (*key == s.key(0)).then_some(Maker::Removed));
    let filed: Vec<String> = lists::acts_of(&written)
        .iter()
        .filter_map(|act| match act {
            AnyAct::Filing(filing) => Some(filing.item.name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(filed, ["review"]);
    // Once the desktop is added again, its own list brings its acts back:
    // the two hold the same.
    let (both, _) = lists::recovered(&lists, |key| match *key == s.key(0) {
        true => Some(Maker::Removed),
        false => Some(Maker::Counts),
    });
    let mut names: Vec<String> = lists::acts_of(&both)
        .iter()
        .filter_map(|act| match act {
            AnyAct::Filing(filing) => Some(filing.item.name.clone()),
            _ => None,
        })
        .collect();
    names.sort();
    assert_eq!(names, ["desk", "review"]);
}

/// Another person's device pauses after an offer that seals to its person
/// and leaves out a key, until its person moves or stays (decision
/// 2026-10-24, rule 26): its own entries wait, and a stay ends the pause on
/// this device; an offer that leaves Bob out changes nothing.
#[test]
fn another_persons_offer_pauses_this_device_until_it_moves_or_stays() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    written_by(&s, 0, &channel, &[&alice, &carol], now);
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    // Without Bob: nothing pauses.
    stores(
        &s,
        0,
        &offer_by(&carol, &channel, 20, &[carol.public_key()], now, 2),
        now,
    );
    assert!(
        pause_of(conn, identity, &row(&s, 0, &channel))
            .unwrap()
            .is_none()
    );
    // Sealed to Bob, without Carol: paused.
    stores(
        &s,
        0,
        &offer_by(
            &alice,
            &channel,
            21,
            &[alice.public_key(), s.key(0), dave.public_key()],
            now,
            2,
        ),
        now,
    );
    let pause = pause_of(conn, identity, &row(&s, 0, &channel))
        .unwrap()
        .unwrap();
    assert_eq!(pause.offer.maker, alice.public_key());
    assert_eq!(pause.left_out, vec![carol.public_key()]);
    assert!(!writes_there(conn, identity, &row(&s, 0, &channel)).unwrap());
    // The lines of §5.4 say it was made anew and Bob has not moved.
    let held = crate::person::held(conn).unwrap().unwrap();
    let said = sharing::who_wrote(conn, &held, &s.key(0), &channel.id, "review", None).unwrap();
    assert!(
        said.iter()
            .any(|line| line.starts_with("This channel was made anew by")
                && line.contains("without 1 key. You have not moved")),
        "{said:?}"
    );
    // A stay ends it here.
    let plan = stay_plan(conn, identity, "review", None).unwrap().unwrap();
    assert!(
        plan.asks
            .contains("without 1 key. Your devices send nothing more")
    );
    make_stay(conn, &channel.id, "review").unwrap();
    assert!(
        pause_of(conn, identity, &row(&s, 0, &channel))
            .unwrap()
            .is_none()
    );
    assert!(writes_there(conn, identity, &row(&s, 0, &channel)).unwrap());
    // Bob moves. Alice's offer counts among the keys not moved yet only
    // once she, its maker, has written in the new channel: until then the
    // new channel lists nobody as not moved yet (#291's reviews).
    let plan = move_plan(conn, identity, &relays(), "review", None, None, now).unwrap();
    let said = make_move(conn, identity, &plan.what, now).unwrap();
    assert!(
        said[0].starts_with("Moved \"review\" to channel "),
        "{said:?}"
    );
    assert!(
        !said.iter().any(|line| line.contains("not moved yet")),
        "{said:?}"
    );
    let new_channel = plan.what.to.channel;
    assert!(
        not_moved_yet(conn, &s.key(0), &new_channel)
            .unwrap()
            .is_empty()
    );
    let new = Shared {
        secret: plan.what.to.card.secret().unwrap(),
        id: new_channel,
    };
    // Alice writes there: Dave, sealed to and not yet there, is not moved
    // yet, until he writes there too.
    stores(&s, 0, &anew(&alice, &new, 1), now);
    assert_eq!(
        not_moved_yet(conn, &s.key(0), &new_channel).unwrap(),
        vec![dave.public_key()]
    );
    // A command that writes there says so, on a line of its own (§5.4).
    let dave_form = sender_form(conn, &held, &s.key(0), &dave.public_key()).unwrap();
    assert_eq!(
        after_who_wrote(conn, &held, &s.key(0), &new_channel, "review").unwrap(),
        [format!("not moved yet: {dave_form}")]
    );
    stores(&s, 0, &anew(&dave, &new, 1), now);
    assert!(
        not_moved_yet(conn, &s.key(0), &new_channel)
            .unwrap()
            .is_empty()
    );
}

/// Alice makes "review" anew without Carol, sealed to herself, Bob and
/// Dave, writes in the new channel, and Bob moves. Dave has not written
/// there yet: no table row holds him, and `shared anew` lists and asks
/// about him like any other key (#291). Kept, he is sealed to. A removal,
/// which keeps the table alone (rule 24), does not keep him.
#[test]
fn shared_anew_asks_about_a_key_not_moved_yet() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    written_by(&s, 0, &channel, &[&alice, &carol], now);
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    stores(
        &s,
        0,
        &offer_by(
            &alice,
            &channel,
            21,
            &[alice.public_key(), s.key(0), dave.public_key()],
            now,
            2,
        ),
        now,
    );
    let plan = move_plan(conn, identity, &relays(), "review", None, None, now).unwrap();
    make_move(conn, identity, &plan.what, now).unwrap();
    let new = Shared {
        secret: plan.what.to.card.secret().unwrap(),
        id: plan.what.to.channel,
    };
    stores(&s, 0, &anew(&alice, &new, 1), now);
    assert_eq!(
        not_moved_yet(conn, &s.key(0), &new.id).unwrap(),
        vec![dave.public_key()]
    );
    let (alice_key, dave_key) = (
        encode_public_key(&alice.public_key()).unwrap(),
        encode_public_key(&dave.public_key()).unwrap(),
    );
    let asked = asked_of(conn, identity, "review", now);
    assert_eq!(asked, vec![alice_key.clone(), dave_key.clone()]);
    let keep = [alice_key, dave_key];
    let (listing, plan) = anew_plan(
        conn,
        identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&keep, &asked)),
        now,
    )
    .unwrap();
    assert!(
        listing
            .lines
            .iter()
            .any(|line| line == "Sealed to when \"review\" was made anew, and not moved here yet:"),
        "{:?}",
        listing.lines
    );
    assert_eq!(listing.not_moved, vec![dave.public_key()]);
    let what = plan.unwrap().what;
    assert!(what.stay.contains(&dave.public_key()), "{:?}", what.stay);
    assert_eq!(what.left_out, 0);
    // A removal keeps a key labelled by a device that counts, Dave, though
    // he has not moved, and not Alice, whom no label names, though she
    // wrote there (rule 24).
    labels(&s, 0, &dave.public_key(), Some("dave"), now);
    let held = crate::person::held(conn).unwrap().unwrap();
    let (stay, ..) =
        staying_with_no_question(conn, &held, &s.key(0), &row(&s, 0, &new), true).unwrap();
    assert_eq!(stay, vec![s.key(0), dave.public_key()]);
}

/// An offer whose maker has not written in the channel it names counts for
/// nothing among its keys not moved yet (#291's reviews). Mallory, left
/// out, still holds the old channel, and writes there an offer that names
/// Alice's new channel, sealed to herself and Eve. Its seals are never
/// looked at, so one copied from another offer would change nothing:
/// Mallory has not written in the new channel and cannot, and only Dave,
/// from Alice's offer, is not moved yet.
#[test]
fn an_offer_whose_maker_is_not_in_the_channel_counts_for_nothing() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, mallory, eve, dave) = (member(1), member(2), member(3), member(4));
    written_by(&s, 0, &channel, &[&alice, &mallory], now);
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let genuine = Offer::make(
        now as u64,
        &channel.id,
        &new_card(21),
        &[alice.public_key(), s.key(0), dave.public_key()],
    )
    .unwrap();
    let forged = Offer {
        made: genuine.made,
        new_channel: genuine.new_channel,
        relays: genuine.relays.clone(),
        seals: vec![
            Seal {
                key: mallory.public_key(),
                sealed: [7; SEALED_SECRET_BYTES],
            },
            Seal {
                key: eve.public_key(),
                sealed: [9; SEALED_SECRET_BYTES],
            },
        ],
    };
    stores(
        &s,
        0,
        &anew_of(
            &mallory,
            &channel,
            2,
            Anew::Offer(forged).to_value().unwrap(),
        ),
        now,
    );
    stores(
        &s,
        0,
        &anew_of(
            &alice,
            &channel,
            2,
            Anew::Offer(genuine).to_value().unwrap(),
        ),
        now,
    );
    let plan = move_plan(conn, identity, &relays(), "review", None, None, now).unwrap();
    make_move(conn, identity, &plan.what, now).unwrap();
    let new = Shared {
        secret: plan.what.to.card.secret().unwrap(),
        id: plan.what.to.channel,
    };
    stores(&s, 0, &anew(&alice, &new, 1), now);
    assert_eq!(
        not_moved_yet(conn, &s.key(0), &new.id).unwrap(),
        vec![dave.public_key()]
    );
    assert_eq!(
        asked_of(conn, identity, "review", now),
        vec![
            encode_public_key(&alice.public_key()).unwrap(),
            encode_public_key(&dave.public_key()).unwrap()
        ]
    );
}

/// A removed device of the person's that an offer sealed to and that has
/// not moved yet is listed as left out, is not asked about, and is counted
/// among those left out (#291's review). Bob's laptop moves by Alice's
/// offer, which seals to his tablet too, and to the tablet's twin. The
/// tablet has not written in the new channel when the laptop removes it.
#[test]
fn a_removed_device_not_moved_yet_is_left_out_and_counted() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let alice = member(1);
    written_by(&s, 0, &channel, &[&alice], now);
    let tablet = s.key(2);
    let twin = Twin::of(&crate::several::identity_of(2)).key;
    stores(
        &s,
        0,
        &offer_by(
            &alice,
            &channel,
            21,
            &[alice.public_key(), s.key(0), tablet, twin],
            now,
            2,
        ),
        now,
    );
    {
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        let plan = move_plan(conn, identity, &relays(), "review", None, None, now).unwrap();
        make_move(conn, identity, &plan.what, now).unwrap();
        let new = Shared {
            secret: plan.what.to.card.secret().unwrap(),
            id: plan.what.to.channel,
        };
        stores(&s, 0, &anew(&alice, &new, 1), now);
        assert!(
            not_moved_yet(conn, &s.key(0), &new.id)
                .unwrap()
                .contains(&tablet)
        );
    }
    s.change(0, &[0, 1], &[2]);
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let tablet_key = encode_public_key(&tablet).unwrap();
    let alice_key = encode_public_key(&alice.public_key()).unwrap();
    let asked = asked_of(conn, identity, "review", now);
    assert!(!asked.contains(&tablet_key), "{asked:?}");
    assert!(
        !asked.contains(&encode_public_key(&twin).unwrap()),
        "{asked:?}"
    );
    let keep = [alice_key];
    let (listing, plan) = anew_plan(
        conn,
        identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&keep, &asked)),
        now,
    )
    .unwrap();
    assert_eq!(listing.removed, 2, "{:?}", listing.lines);
    assert!(
        listing
            .lines
            .iter()
            .any(|line| line.ends_with(": left out, a device you removed")),
        "{:?}",
        listing.lines
    );
    let what = plan.unwrap().what;
    assert!(!what.stay.contains(&tablet), "{:?}", what.stay);
}

// ── The fix round of slice 8 ─────────────────────────────────────────

/// The channel that device `n` files as `name` now, as a `Shared`.
/// Device `n` makes the shared channel `name` with `shared new`, at the
/// relay of these tests.
fn made_new(s: &Several, n: usize, name: &str, now: i64) -> Shared {
    let new = sharing::New {
        name: name.into(),
        relays: relays(),
    };
    sharing::make_new(&s[n].conn, &s[n].identity, &new, now).unwrap();
    filed_as(s, n, name)
}

/// Device `n` makes the channel filed as `name` anew with `shared anew`,
/// keeping every key it is asked about, and returns the new channel.
fn made_anew_on(s: &Several, n: usize, name: &str, now: i64) -> Shared {
    let (conn, identity) = (&s[n].conn, &s[n].identity);
    let listed = asked_of(conn, identity, name, now);
    let (_, plan) = anew_plan(
        conn,
        identity,
        &relays(),
        name,
        None,
        &[],
        Some((&[], &listed)),
        now,
    )
    .unwrap();
    make_anew(conn, identity, &relays(), &plan.unwrap().what, now).unwrap();
    out(s, n, now);
    filed_as(s, n, name)
}

/// Device `to` is given what device `from` holds, follows the lists and
/// ends the take-outs it began, at `now`.
fn follows(s: &mut Several, from: usize, to: usize, now: i64) {
    s.pass(from, to);
    crate::lists::follow(&s[to].conn, &s[to].identity, now).unwrap();
    out(s, to, now);
}

pub(crate) fn filed_as(s: &Several, n: usize, name: &str) -> Shared {
    let filing = sharing::filed(&s[n].conn)
        .unwrap()
        .into_iter()
        .find(|filing| filing.name == name)
        .unwrap();
    Shared {
        secret: filing.card.secret().unwrap(),
        id: filing.channel,
    }
}

/// Bob's three devices hold "review", each following the others' lists,
/// with Alice's key shown on device `n`; and the laptop then removes the
/// tablet. Returns the channel and Alice.
fn removed_the_tablet(s: &mut Several, n: usize) -> (Shared, NodeIdentity) {
    let now = s.now + 10;
    let channel = holds(s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for k in 0..3 {
        crate::lists::follow(&s[k].conn, &s[k].identity, now).unwrap();
        out(s, k, now);
    }
    let alice = member(1);
    written_by(s, n, &channel, &[&alice], now);
    let tablet = crate::several::identity_of(2);
    stores(s, n, &anew(&tablet, &channel, 1), now);
    s.change(0, &[0, 1], &[2]);
    (channel, alice)
}

/// A move never takes a device into a channel that a key its statement
/// removed reads (the review of slice 8, high 1; decision 2026-10-24,
/// rules 4 and 23): Bob's laptop removes his tablet and the channel is
/// made anew at the removal; Alice, who does not know of the removal, makes
/// the new channel anew sealed to the tablet as well as to the laptop. On
/// the laptop her offer is the fault `seals_removed`, named with its maker,
/// and `shared move` is refused `no_offer`; Carol's offer, which seals to
/// no removed key, is one to move to.
#[test]
fn a_move_never_takes_a_device_into_a_channel_that_a_removed_key_reads() {
    let mut s = bob(3);
    let (_, alice) = removed_the_tablet(&mut s, 0);
    let now = s.now + 20;
    let tablet = crate::several::identity_of(2);
    anew_at_removal(&s[0].conn, &s[0].identity, &relays(), now).unwrap();
    let new = filed_as(&s, 0, "review");
    let carol = member(2);
    written_by(&s, 0, &new, &[&alice, &carol], now);
    stores(
        &s,
        0,
        &offer_by(
            &alice,
            &new,
            30,
            &[alice.public_key(), s.key(0), tablet.public_key()],
            now,
            2,
        ),
        now,
    );
    assert_eq!(
        what_is(&s, 0, &new, now),
        vec![(alice.public_key(), OfferIs::Fault(Fault::SealsRemoved))]
    );
    let lines = offer_lines(
        &s[0].conn,
        &s[0].identity,
        &judged(&s[0].conn, &s[0].identity, &row(&s, 0, &new), Some(now)).unwrap(),
    )
    .unwrap();
    assert!(
        lines[0].ends_with("sealed to a device you removed: a fault, not a move"),
        "{lines:?}"
    );
    let refused = move_plan(
        &s[0].conn,
        &s[0].identity,
        &relays(),
        "review",
        None,
        None,
        now,
    );
    assert_eq!(refusal_word(refused), "no_offer");
    // And a command that writes there does not tell Bob to move to it.
    let held = crate::person::held(&s[0].conn).unwrap().unwrap();
    let said = after_who_wrote(&s[0].conn, &held, &s.key(0), &new.id, "review").unwrap();
    assert!(
        !said.iter().any(|line| line.contains("was made anew by")),
        "{said:?}"
    );
    // An offer that seals to no removed key is one to move to.
    stores(
        &s,
        0,
        &offer_by(&carol, &new, 31, &[carol.public_key(), s.key(0)], now, 2),
        now,
    );
    let plan = move_plan(
        &s[0].conn,
        &s[0].identity,
        &relays(),
        "review",
        None,
        None,
        now,
    )
    .unwrap();
    assert!(
        plan.asks.contains("faults: 1 (seals_removed)"),
        "{}",
        plan.asks
    );
}

/// `shared move` is refused in a channel not yet clean (the review of
/// slice 8, high 1; decision 2026-10-24, rule 25): the laptop removes the
/// tablet and is lost before its offer; the desktop applies the removal,
/// and reads Alice's offer, which seals to no removed key; its `shared
/// move` is refused `not_clean`, the offer listed above the line that
/// names the command that makes the channel anew.
#[test]
fn shared_move_is_refused_in_a_channel_not_yet_clean() {
    let mut s = bob(3);
    let (channel, alice) = removed_the_tablet(&mut s, 1);
    s.pass(0, 1);
    let now = s.now + 20;
    assert!(is_not_clean(&s[1].conn, &channel.id).unwrap());
    stores(
        &s,
        1,
        &offer_by(
            &alice,
            &channel,
            30,
            &[alice.public_key(), s.key(1)],
            now,
            2,
        ),
        now,
    );
    assert!(matches!(
        what_is(&s, 1, &channel, now)[..],
        [(_, OfferIs::ForThisDevice(_))]
    ));
    match move_plan(
        &s[1].conn,
        &s[1].identity,
        &relays(),
        "review",
        None,
        None,
        now,
    ) {
        Err(Failed::Refused(refusal)) => {
            assert_eq!(refusal.word, "not_clean");
            let lines: Vec<&str> = refusal.line.lines().collect();
            assert_eq!(lines.len(), 2, "{}", refusal.line);
            assert!(lines[0].contains("made anew by"), "{}", refusal.line);
            assert_eq!(lines[1], not_clean_line("review"));
        }
        other => panic!("{other:?}"),
    }
}

/// A refused `shared anew` writes and sends nothing, at a removal too (the
/// review of slice 8, medium 2): the desktop, which counts, holds the
/// filing of "review" at the time bound with the highest count; the laptop
/// removes the tablet, and the channel could not be made anew: no offer is
/// stored, no row of what was made is kept, the channel stays filed and not
/// clean, and the pass has nothing of the laptop's to push there; `shared
/// anew` after it is refused `held_at_bound` the same way.
#[test]
fn a_refused_anew_writes_and_sends_nothing() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for k in 0..3 {
        crate::lists::follow(&s[k].conn, &s[k].identity, now).unwrap();
        out(&s, k, now);
    }
    crate::lists::held_at_the_bound(&s[1].conn, &s[1].identity, filing(7, "review"), now).unwrap();
    s.meet(&[0, 1]);
    crate::lists::follow(&s[0].conn, &s[0].identity, now).unwrap();
    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let slot = slot_id(
        &derive::slot_key(&channel.secret).unwrap(),
        &anew_name(&s.key(0)).unwrap(),
    );
    let rev_of = || {
        entries::author_entry(conn, &channel.id, &slot, &s.key(0))
            .unwrap()
            .map(|held| held.entry.rev)
    };
    let before = rev_of();
    let nothing_written = || {
        assert_eq!(rev_of(), before, "no offer is stored");
        assert!(
            st(rows::offer_from(conn, &channel.id, &s.key(0)))
                .unwrap()
                .is_none()
        );
        assert!(
            st(rows::made_of_channel(conn, &channel.id))
                .unwrap()
                .is_none()
        );
        assert_eq!(sharing::filed(conn).unwrap()[0].channel, channel.id);
        assert!(is_not_clean(conn, &channel.id).unwrap());
        let usable = crate::shared_pass::usable(conn, &channel.id, &AT)
            .unwrap()
            .unwrap();
        let most = crate::at_relays::Most {
            entries: 100,
            bytes: 1 << 20,
        };
        assert!(
            crate::shared_pass::to_send(conn, identity, &usable, &AT, most)
                .unwrap()
                .iter()
                .all(|entry| entry.slot != slot),
            "nothing of the laptop's to push"
        );
    };
    let said = anew_at_removal(conn, identity, &relays(), now).unwrap();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].starts_with("\"review\" could not be made anew: "),
        "{said:?}"
    );
    nothing_written();
    let listed = asked_of(conn, identity, "review", now);
    let (_, plan) = anew_plan(
        conn,
        identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&[], &listed)),
        now,
    )
    .unwrap();
    let refused = make_anew(conn, identity, &relays(), &plan.unwrap().what, now);
    assert_eq!(refusal_word(refused), "held_at_bound");
    nothing_written();
}

/// A removal leaves a channel it does not reach not clean, and names it,
/// rather than making it anew (the review of slice 8, medium 3; decision
/// 2026-10-24, rules 24 and 25): the laptop, whose relays are not the
/// channel's, removes the tablet; nothing is written in the channel, it
/// stays filed and not clean, and `cordelia devices` names it with the
/// command to run on a device that reaches its relays.
#[test]
fn a_removal_leaves_a_channel_it_does_not_reach_not_clean() {
    let mut s = bob(3);
    let (channel, _) = removed_the_tablet(&mut s, 0);
    let now = s.now + 20;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let elsewhere = vec![OwnRelay {
        name: "elsewhere.example.org:9474".into(),
        key: [9; 32],
    }];
    let said = anew_at_removal(conn, identity, &elsewhere, now).unwrap();
    assert_eq!(said, vec![unreached_line("review")]);
    let tablet =
        crate::look::named_device("device 2", &cordelia_crypto::fingerprint::shown(&s.key(2)));
    assert!(is_not_clean(conn, &channel.id).unwrap());
    assert_eq!(sharing::filed(conn).unwrap()[0].channel, channel.id);
    assert!(
        st(rows::offer_from(conn, &channel.id, &s.key(0)))
            .unwrap()
            .is_none()
    );
    assert!(
        st(rows::made_of_channel(conn, &channel.id))
            .unwrap()
            .is_none()
    );
    let seen = crate::look::look(conn, identity, &Default::default(), now).unwrap();
    assert!(
        seen.notices
            .iter()
            .any(|notice| notice.says
                == unreached_named_line("review", std::slice::from_ref(&tablet))),
        "{:?}",
        seen.notices
    );
    assert!(
        unreached_line("review")
            .ends_with("run cordelia shared reset review on a device of yours that reaches them")
    );
}

/// The subscriptions a move moves do not fill the room of the old ones
/// (the review of slice 8, medium 4; decision 2026-10-10 §3.4, §7): 17
/// agents subscribe to "review", and Bob makes it anew; the 17 move with
/// it, and an 18th agent's subscribe to the new channel is made, not
/// refused for room.
#[test]
fn moved_subscriptions_leave_room_for_a_new_one() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    for k in 0..17 {
        let subscription = Subscription {
            channel: channel.id,
            agent: format!("github.com/owner/repo{k}"),
            subscribed: true,
        };
        acts(&s, 0, Do::Subscribe(subscription), now + 1 + k);
    }
    let now = now + 100;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let listed = asked_of(conn, identity, "review", now);
    let (_, plan) = anew_plan(
        conn,
        identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&[], &listed)),
        now,
    )
    .unwrap();
    make_anew(conn, identity, &relays(), &plan.unwrap().what, now).unwrap();
    let new = filed_as(&s, 0, "review");
    let in_new = || {
        crate::shared_messages::in_force(conn)
            .unwrap()
            .into_iter()
            .filter(|(channel, _)| *channel == new.id)
            .count()
    };
    assert_eq!(in_new(), 17);
    let one_more = Subscription {
        channel: new.id,
        agent: "github.com/owner/another".into(),
        subscribed: true,
    };
    acts(&s, 0, Do::Subscribe(one_more), now + 1);
    assert_eq!(in_new(), 18);
}

/// The line of a removal says how many keys the cap and the rows let go
/// left out (the review of slice 8, medium 5; decision 2026-10-10,
/// property 7): with 100 keys of members, 63 of them labelled, and 3 rows
/// let go, the laptop's removal of the tablet keeps its two devices and 62
/// labelled keys, and leaves out the other labelled one past the 64 that
/// stay, and 3 no longer known; `remove-device` says so at its end. (With
/// 64 labelled, the laptop would show none of its own devices there.)
#[test]
fn a_removal_says_how_many_keys_the_cap_and_the_rows_let_go_left_out() {
    let mut s = bob(3);
    let (channel, _) = removed_the_tablet(&mut s, 0);
    let now = s.now + 20;
    let members: Vec<NodeIdentity> = (0..99).map(|k| member(1_000 + k)).collect();
    let refs: Vec<&NodeIdentity> = members.iter().collect();
    written_by(&s, 0, &channel, &refs, now);
    for member in &members[..SHARED_MAX_KEYS - 1] {
        labels(&s, 0, &member.public_key(), Some("a member"), now);
    }
    let conn = &s[0].conn;
    conn.execute(
        "UPDATE shared_channels SET let_go = 3 WHERE channel = ?1",
        [&channel.id[..]],
    )
    .unwrap();
    let said = anew_at_removal(conn, &s[0].identity, &relays(), now).unwrap();
    let besides = "Left out besides: 1 key past the 64 that stay, and up to 3 keys no longer \
                   known on this device.";
    assert!(said[0].ends_with(besides), "{said:?}");
    let at_the_end = made_at_the_last_removal(conn, Some(0)).unwrap();
    assert_eq!(at_the_end, said);
    let offer = st(rows::offer_from(conn, &channel.id, &s.key(0)))
        .unwrap()
        .unwrap();
    assert_eq!(offer.sealed_to.len(), SHARED_MAX_KEYS);
}

/// The asked keys of `shared anew` are those it listed (the review of
/// slice 8, low 8; property 7): Dave writes in the channel after the
/// listing, and the answers to the keys listed are refused, with nothing
/// done, rather than leaving Dave out unasked.
#[test]
fn shared_anew_refuses_where_a_key_came_after_the_listing() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let alice = member(1);
    written_by(&s, 0, &channel, &[&alice], now);
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let listed = asked_of(conn, identity, "review", now);
    assert_eq!(listed.len(), 1);
    let dave = member(9);
    written_by(&s, 0, &channel, &[&dave], now);
    match anew_plan(
        conn,
        identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&listed, &listed)),
        now,
    ) {
        Err(Failed::Refused(refusal)) => assert_eq!(refusal.line, sharing::CHANGED_KEYS),
        other => panic!("{:?}", other.map(|(_, plan)| plan.map(|plan| plan.asks))),
    }
    assert_eq!(sharing::filed(conn).unwrap()[0].channel, channel.id);
}

/// A relay that holds another entry at the offer's revision does not hold
/// the offer (the review of slice 8, low 6; §7): the old channel's entries
/// stay until a relay holds the record written again above it.
#[test]
fn an_offer_is_delivered_only_where_a_relay_holds_it() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let listed = asked_of(conn, identity, "review", now);
    let (_, plan) = anew_plan(
        conn,
        identity,
        &relays(),
        "review",
        None,
        &[],
        Some((&[], &listed)),
        now,
    )
    .unwrap();
    make_anew(conn, identity, &relays(), &plan.unwrap().what, now).unwrap();
    out(&s, 0, now);
    let usable = crate::shared_pass::usable(conn, &channel.id, &AT)
        .unwrap()
        .unwrap();
    let most = crate::at_relays::Most {
        entries: 100,
        bytes: 1 << 20,
    };
    let batch = crate::shared_pass::to_send(conn, identity, &usable, &AT, most).unwrap();
    assert_eq!(batch.len(), 1, "the offer alone");
    let another = vec![crate::at_relays::Pushed::HoldsAnother];
    crate::shared_pass::pushed(conn, identity, &usable, &AT, &batch, &another, now).unwrap();
    out(&s, 0, now);
    assert!(
        !s[0].stored_in(&channel.secret).is_empty(),
        "its entries wait for the offer"
    );
    let batch = crate::shared_pass::to_send(conn, identity, &usable, &AT, most).unwrap();
    assert_eq!(batch.len(), 1, "the record written again");
    let holds = vec![crate::at_relays::Pushed::Holds];
    crate::shared_pass::pushed(conn, identity, &usable, &AT, &batch, &holds, now).unwrap();
    out(&s, 0, now);
    assert!(
        s[0].stored_in(&channel.secret).is_empty(),
        "its entries went"
    );
}

/// A notice of a channel not yet clean is named again at a later removal
/// (the review of slice 8, low 9; §3.5): the desktop clears it, a second
/// removal comes while the channel is still not clean, and `cordelia
/// devices` names it again.
#[test]
fn a_notice_of_a_channel_not_clean_is_named_again_at_a_later_removal() {
    let mut s = bob(4);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2, 3]);
    for k in 0..4 {
        crate::lists::follow(&s[k].conn, &s[k].identity, now).unwrap();
        out(&s, k, now);
    }
    s.change(0, &[0, 1, 3], &[2]);
    s.pass(0, 1);
    let now = s.now + 20;
    assert!(is_not_clean(&s[1].conn, &channel.id).unwrap());
    let named = |s: &Several| {
        crate::look::look(&s[1].conn, &s[1].identity, &Default::default(), now)
            .unwrap()
            .notices
            .into_iter()
            .find(|notice| notice.kind == "not_clean" && notice.says.starts_with("\"review\""))
    };
    let notice = named(&s).unwrap();
    let id: [u8; 32] = hex::decode(&notice.id).unwrap().try_into().unwrap();
    crate::look::clear(&s[1].conn, &s[1].identity, &id, now)
        .unwrap()
        .unwrap();
    assert!(named(&s).is_none());
    s.change(0, &[0, 1], &[3]);
    s.pass(0, 1);
    assert!(is_not_clean(&s[1].conn, &channel.id).unwrap());
    assert!(named(&s).is_some(), "named again at the second removal");
}

/// An older revision of an offer is ignored (decision 2026-10-10 §7): the
/// reader keeps the offer at revision 3, and one read after it at revision
/// 2 changes nothing.
#[test]
fn an_older_revision_of_an_offer_is_ignored() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let conn = &s[0].conn;
    let alice = member(1);
    let offer = |seed: u8| {
        Anew::Offer(Offer::make(now as u64, &channel.id, &new_card(seed), &[s.key(0)]).unwrap())
    };
    let held = row(&s, 0, &channel);
    read(
        conn,
        &s.key(0),
        &held,
        &alice.public_key(),
        3,
        &offer(20),
        now,
    )
    .unwrap();
    read(
        conn,
        &s.key(0),
        &held,
        &alice.public_key(),
        2,
        &offer(21),
        now,
    )
    .unwrap();
    let kept = st(rows::offer_from(conn, &channel.id, &alice.public_key()))
        .unwrap()
        .unwrap();
    assert_eq!(kept.rev, 3);
    assert_eq!(kept.new_channel, new_card(20).channel_id().unwrap());
}

/// The machine of a recovery makes a channel anew only once it has read
/// it since it started (decision 2026-10-10 §3.5; §19 item 67).
#[test]
fn a_recovery_makes_a_channel_anew_only_once_it_has_read_it() {
    let mut s = bob(2);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.change(0, &[0], &[1]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    recovered(conn, &[], now).unwrap();
    assert_eq!(make_owed(conn, &s[0].identity, now, &|_| false).unwrap(), 0);
    assert!(
        st(rows::made_of_channel(conn, &channel.id))
            .unwrap()
            .is_none()
    );
    assert!(is_not_clean(conn, &channel.id).unwrap());
    assert_eq!(make_owed(conn, &s[0].identity, now, &|_| true).unwrap(), 1);
    assert!(
        st(rows::made_of_channel(conn, &channel.id))
            .unwrap()
            .is_some()
    );
}

/// A device that comes to know of a removal before it applies it, on any
/// branch, sends nothing in a shared channel from that moment, and leaves
/// the removed key out of a channel it makes anew (decision 2026-10-24
/// (removal), rules 2, 23 and 24): the laptop is shown a change that
/// removes the tablet, and keeps the key as removed without applying the
/// change. Each shared channel it holds is then not clean, and the key is
/// no key that stays in the listing of `shared anew`, though the statement
/// the laptop applies does not list it.
#[test]
fn a_removal_known_before_it_is_applied_makes_each_shared_channel_not_clean() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for k in 0..3 {
        crate::lists::follow(&s[k].conn, &s[k].identity, now).unwrap();
        out(&s, k, now);
    }
    let tablet = crate::several::identity_of(2);
    stores(&s, 0, &anew(&tablet, &channel, 1), now);
    let conn = &s[0].conn;
    let own = s[0].identity.public_key();
    let held = crate::person::held(conn).unwrap().unwrap();
    // The keys that stay with no question: the person's own devices, and
    // those asked of.
    let listed = |conn: &Connection| {
        let held = crate::person::held(conn).unwrap().unwrap();
        let listing = listing_of(conn, &held, &own, &row(&s, 0, &channel)).unwrap();
        [listing.own_devices.keys().copied().collect(), listing.asked].concat()
    };
    assert!(!is_not_clean(conn, &channel.id).unwrap());
    assert!(listed(conn).contains(&tablet.public_key()));

    // A change made apart that removes the tablet, shown and not applied.
    let mut apart = held.statement.statement.clone();
    apart.removed.push(tablet.public_key());
    crate::person::know_removed(conn, &apart, &own, now + 1, false).unwrap();
    assert!(
        !crate::person::held(conn)
            .unwrap()
            .unwrap()
            .statement
            .statement
            .removes(&tablet.public_key()),
        "the statement applied does not list it"
    );
    assert!(is_not_clean(conn, &channel.id).unwrap(), "rule 23");
    assert!(
        !listed(conn).contains(&tablet.public_key()),
        "rule 24: a key known to be removed does not stay"
    );
    assert_eq!(
        removed_at(conn, now + 1).unwrap(),
        Some(vec![tablet.public_key()])
    );
}

// ── The fix round of the removal build, joined (#277) ────────────────

/// A channel that a device first holds while it knows of a removal is not
/// clean (the review of #277, high 1; decision 2026-10-24, rule 23, as the
/// person ruled on 2 November): the desktop removes the tablet; before the
/// laptop hears of it, the laptop files "notes" under the change before,
/// which the tablet reads and holds; the laptop applies the removal, and
/// the desktop then reads the laptop's list. The desktop holds "notes" not
/// clean, and sends nothing there. A channel the desktop files itself is
/// not clean either; one it makes with `shared new` is. The laptop makes
/// "notes" anew: the new channel is clean on the laptop and not on the
/// desktop, where "notes" was not; once the desktop makes it anew too, it
/// is clean on both.
#[test]
fn a_channel_first_held_while_a_removal_is_known_is_not_clean() {
    let mut s = bob(3);
    let now = s.now + 10;
    s.meet(&[0, 1, 2]);
    s.change(1, &[0, 1], &[2]);
    let channel = holds(&s, 0, 9, "notes", now);
    s.pass(0, 2);
    crate::lists::follow(&s[2].conn, &s[2].identity, now).unwrap();
    assert_eq!(
        row(&s, 2, &channel).state,
        State::Held,
        "the tablet holds it"
    );

    s.pass(1, 0);
    let now = s.now + 20;
    crate::lists::follow(&s[0].conn, &s[0].identity, now).unwrap();
    out(&s, 0, now);
    assert!(is_not_clean(&s[0].conn, &channel.id).unwrap(), "rule 23");
    follows(&mut s, 0, 1, now);
    let desktop = row(&s, 1, &channel);
    assert_eq!(desktop.state, State::Held);
    assert!(is_not_clean(&s[1].conn, &channel.id).unwrap(), "rule 23");
    assert!(!writes_there(&s[1].conn, &s[1].identity, &desktop).unwrap());

    // A channel the desktop files itself is not clean: its own filing
    // shows nothing of where the card was before. One it makes is.
    let own = holds(&s, 1, 11, "own", now);
    assert!(is_not_clean(&s[1].conn, &own.id).unwrap(), "own filing");
    let made = made_new(&s, 1, "made", now);
    assert!(!is_not_clean(&s[1].conn, &made.id).unwrap(), "made here");

    // The laptop makes "notes" anew: clean there, and not on the desktop.
    let new = made_anew_on(&s, 0, "notes", now);
    assert!(
        !is_not_clean(&s[0].conn, &new.id).unwrap(),
        "made anew here"
    );
    follows(&mut s, 0, 1, now);
    assert_eq!(row(&s, 1, &new).state, State::Held);
    assert!(is_not_clean(&s[1].conn, &new.id).unwrap(), "made elsewhere");
    assert!(
        !is_not_clean(&s[1].conn, &channel.id).unwrap(),
        "moved from"
    );

    // The desktop makes it anew: clean there, and on the laptop, where the
    // channel it was made out of is clean.
    let newer = made_anew_on(&s, 1, "notes", now);
    assert!(!is_not_clean(&s[1].conn, &newer.id).unwrap());
    follows(&mut s, 1, 0, now);
    assert_eq!(row(&s, 0, &newer).state, State::Held);
    assert!(!is_not_clean(&s[0].conn, &newer.id).unwrap());
    assert!(writes_there(&s[0].conn, &s[0].identity, &row(&s, 0, &newer)).unwrap());
}

// ── The person's ruling of 2 November: made anew once, no exemptions ─

/// A channel moved to before a removal is not clean on a device that
/// first holds it after one (the short review of #277, its high): the
/// laptop makes "notes" anew before the removal, and the tablet holds the
/// new channel; the desktop removes the tablet, and nobody makes "notes"
/// anew. The laptop holds it not clean, and so does the phone, which
/// follows the lists for the first time after the removal.
#[test]
fn a_channel_moved_to_before_a_removal_is_not_clean_where_it_is_first_held() {
    let mut s = bob(4);
    let now = s.now + 10;
    holds(&s, 0, 9, "notes", now);
    let new = made_anew_on(&s, 0, "notes", now);
    follows(&mut s, 0, 2, now);
    assert_eq!(row(&s, 2, &new).state, State::Held, "the tablet holds it");

    s.change(1, &[0, 1, 3], &[2]);
    let now = s.now + 20;
    follows(&mut s, 1, 0, now);
    assert!(is_not_clean(&s[0].conn, &new.id).unwrap(), "rule 23");
    follows(&mut s, 0, 3, now);
    let phone = row(&s, 3, &new);
    assert_eq!(phone.state, State::Held);
    assert!(
        is_not_clean(&s[3].conn, &new.id).unwrap(),
        "moved, but before"
    );
    assert!(!writes_there(&s[3].conn, &s[3].identity, &phone).unwrap());
}

/// A channel taken again after a removal is not clean (the short review
/// of #277, its medium): the laptop holds "notes" when the desktop removes
/// the tablet, makes it anew and moves from it; someone else stays in the
/// old channel and shares it again, and the laptop's filing of it, as a
/// take files it, is its own. It is not clean, and nothing is sent there.
#[test]
fn a_channel_taken_again_after_a_removal_is_not_clean() {
    let mut s = bob(3);
    let now = s.now + 10;
    let old = holds(&s, 0, 9, "notes", now);
    s.change(1, &[0, 1], &[2]);
    follows(&mut s, 1, 0, now);
    let new = made_anew_on(&s, 0, "notes", now);
    assert!(!is_not_clean(&s[0].conn, &new.id).unwrap());
    assert_eq!(row(&s, 0, &old).state, State::Moved);

    let mut again = filing(9, "notes-again");
    again.came = Came::Taken(member(1).public_key());
    acts(&s, 0, Do::File(again), now + 1);
    let laptop = row(&s, 0, &old);
    assert_eq!(laptop.state, State::Held);
    assert!(is_not_clean(&s[0].conn, &old.id).unwrap(), "taken again");
    assert!(!writes_there(&s[0].conn, &s[0].identity, &laptop).unwrap());
}

/// A channel made anew by a device that had not heard of the removal is
/// not clean on the devices that follow it (the gap the first fix round of
/// #277 stated): the desktop removes the tablet and makes nothing anew;
/// the laptop, not knowing, makes "notes" anew under the change before,
/// which the tablet reads. The desktop held "notes" when it applied the
/// removal, so the channel made anew out of it is not clean there; nor on
/// the laptop, once it hears.
#[test]
fn a_channel_made_anew_by_a_device_that_had_not_heard_is_not_clean() {
    let mut s = bob(3);
    let now = s.now + 10;
    holds(&s, 0, 9, "notes", now);
    s.meet(&[0, 1, 2]);
    for n in 1..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
    }
    s.change(1, &[0, 1], &[2]);
    let new = made_anew_on(&s, 0, "notes", now);
    follows(&mut s, 0, 2, now);
    assert_eq!(row(&s, 2, &new).state, State::Held, "the tablet holds it");

    let now = s.now + 20;
    follows(&mut s, 1, 0, now);
    assert!(is_not_clean(&s[0].conn, &new.id).unwrap(), "rule 23");
    follows(&mut s, 0, 1, now);
    let desktop = row(&s, 1, &new);
    assert_eq!(desktop.state, State::Held);
    assert!(
        is_not_clean(&s[1].conn, &new.id).unwrap(),
        "made by one not knowing"
    );
    assert!(!writes_there(&s[1].conn, &s[1].identity, &desktop).unwrap());
}

/// A second channel made anew out of one this device moved from is not
/// clean, though the mark of the one moved from is gone: the desktop
/// removes the tablet and makes "notes" anew itself; the laptop, not
/// knowing, makes "notes" anew too, under the change before, which the
/// tablet reads. The desktop then holds the laptop's channel, and holds it
/// not clean.
#[test]
fn a_second_channel_made_anew_out_of_one_moved_from_is_not_clean() {
    let mut s = bob(3);
    let now = s.now + 10;
    let old = holds(&s, 0, 9, "notes", now);
    s.meet(&[0, 1, 2]);
    for n in 1..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
    }
    s.change(1, &[0, 1], &[2]);
    let desktops = made_anew_on(&s, 1, "notes", now);
    assert_eq!(row(&s, 1, &old).state, State::Moved);
    assert!(!is_not_clean(&s[1].conn, &desktops.id).unwrap());
    let laptops = made_anew_on(&s, 0, "notes", now);
    assert_ne!(laptops.id, desktops.id);

    let now = s.now + 20;
    follows(&mut s, 1, 0, now);
    follows(&mut s, 0, 1, now);
    let desktop = row(&s, 1, &laptops);
    assert_eq!(desktop.state, State::Held, "the desktop holds it");
    assert!(
        is_not_clean(&s[1].conn, &laptops.id).unwrap(),
        "made out of one moved from"
    );
    assert!(!writes_there(&s[1].conn, &s[1].identity, &desktop).unwrap());
}

/// `shared anew` after a removal makes a channel clean on the devices that
/// hold clean the channel it was made out of, and on no other: the
/// desktop removes the tablet, and makes "notes" anew as a removal does;
/// it is clean on the desktop and not on the laptop or the phone. The
/// laptop makes it anew: the desktop holds that clean, and the phone, on
/// which the one before was not clean, does not, until it makes it anew
/// itself; then all three hold it clean.
#[test]
fn shared_anew_after_a_removal_is_clean_where_the_one_before_was() {
    let mut s = bob(4);
    let now = s.now + 10;
    let old = holds(&s, 0, 9, "notes", now);
    s.meet(&[0, 1, 2, 3]);
    for n in 1..4 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        assert_eq!(row(&s, n, &old).state, State::Held);
    }
    s.change(1, &[0, 1, 3], &[2]);
    let said = anew_at_removal(&s[1].conn, &s[1].identity, &relays(), now).unwrap();
    assert_eq!(said.len(), 1, "{said:?}");
    out(&s, 1, now);
    let first = filed_as(&s, 1, "notes");
    assert!(
        !is_not_clean(&s[1].conn, &first.id).unwrap(),
        "made at the removal"
    );
    for n in [0, 3] {
        follows(&mut s, 1, n, now);
        assert_eq!(row(&s, n, &first).state, State::Held);
        assert!(is_not_clean(&s[n].conn, &first.id).unwrap(), "device {n}");
    }

    let second = made_anew_on(&s, 0, "notes", now);
    for n in [1, 3] {
        follows(&mut s, 0, n, now);
        assert_eq!(row(&s, n, &second).state, State::Held);
    }
    assert!(
        !is_not_clean(&s[1].conn, &second.id).unwrap(),
        "the desktop"
    );
    assert!(is_not_clean(&s[3].conn, &second.id).unwrap(), "the phone");

    let third = made_anew_on(&s, 3, "notes", now);
    for n in [0, 1] {
        follows(&mut s, 3, n, now);
    }
    for n in [0, 1, 3] {
        let held = row(&s, n, &third);
        assert_eq!(held.state, State::Held, "device {n}");
        assert!(
            writes_there(&s[n].conn, &s[n].identity, &held).unwrap(),
            "device {n}"
        );
    }
}

/// A recovery takes by the person's word the acts of the devices the
/// person named at the terminal alone, and seals without every key it
/// removes (the review of #277, high 2; decision 2026-10-24 (removal),
/// rules 6, 22 and 24): the laptop, said to be lost, files "review"; the
/// tablet, which another change removed, files "thief" after its removal.
/// The recovered machine holds "review", not clean and owed its making
/// anew, and nothing of the tablet's: its acts are passed over.
#[test]
fn a_recovery_takes_no_act_of_a_device_another_change_removed() {
    let mut s = bob(3);
    let now = s.now + 10;
    let review = holds(&s, 1, 7, "review", now);
    let thief = holds(&s, 2, 9, "thief", now);
    let personal = s[1].personal();
    let handed: Vec<CheckedEntry> = s[1].stored().into_iter().chain(s[2].stored()).collect();
    let lists = crate::lists::lists_in(&handed, &personal, &[s.key(1), s.key(2)]).unwrap();
    assert_eq!(lists.len(), 2);
    s.change(0, &[0], &[1, 2]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    let shown = crate::recover::Shown {
        gone: vec![(s.key(1), "laptop".into())],
        removed_apart: vec![(s.key(2), "tablet".into())],
        ..Default::default()
    };
    in_one(conn, || {
        crate::recover::shared_recovered(conn, &s[0].identity, &lists, &shown, now)
    })
    .unwrap();
    let filed: Vec<String> = sharing::filed(conn)
        .unwrap()
        .into_iter()
        .map(|filing| filing.name)
        .collect();
    assert_eq!(filed, ["review"], "the tablet's acts are passed over");
    assert!(st(kept::channel(conn, &thief.id)).unwrap().is_none());
    assert!(is_not_clean(conn, &review.id).unwrap(), "rule 24");
    assert!(
        st(rows::not_clean_of(conn, &review.id))
            .unwrap()
            .unwrap()
            .owed
    );
}

/// A device that does not follow a clear change works its lists out
/// again, closed or not yet closed (the review of #277, low 3; decision
/// 2026-10-24 (removal), rules 4 and 10): it writes no list, and the table
/// of shared channels still follows the lists it holds, as on a device
/// that is stopped. The laptop drops "review", and the desktop stores its
/// list; the desktop then knows the tablet, which its change lists, to be
/// removed, and works its lists out before it is closed (`NotClear`): it
/// holds "review" no more. Closed (`Stopped`), it does the same.
#[test]
fn a_device_on_a_change_not_clear_follows_the_lists_and_writes_none() {
    for closed in [false, true] {
        let mut s = bob(3);
        let now = s.now + 10;
        let channel = holds(&s, 0, 7, "review", now);
        s.meet(&[0, 1]);
        crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
        assert_eq!(row(&s, 1, &channel).state, State::Held);
        acts(&s, 0, Do::Drop(channel.id), now);
        s.pass(0, 1);
        assert_eq!(row(&s, 1, &channel).state, State::Held, "not yet followed");
        let conn = &s[1].conn;
        cordelia_storage::person::keep_removed(conn, &[s.key(2)], now).unwrap();
        assert!(!crate::person::follows_a_clear_change(conn).unwrap());
        if closed {
            cordelia_storage::person::set_state(conn, cordelia_storage::person::State::Fork)
                .unwrap();
        }
        let wrote = crate::lists::follow(conn, &s[1].identity, now).unwrap();
        assert!(!wrote, "it writes no list");
        out(&s, 1, now);
        assert_ne!(row(&s, 1, &channel).state, State::Held, "closed: {closed}");
    }
}

/// An act is stamped as taken no earlier than the newest time of taking
/// kept (the review of #277, low 2; decision 2026-10-24 (removal), rule 7,
/// as an arrival is): the desktop takes the laptop's act; its clock is then
/// stepped back an hour, and the act it makes then is kept as taken no
/// earlier than the laptop's.
#[test]
fn an_act_taken_on_a_clock_stepped_back_is_taken_no_earlier_than_the_last() {
    let mut s = bob(2);
    let now = s.now + 10;
    holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1]);
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    let first = cordelia_storage::shared_lists::taken(&s[1].conn).unwrap();
    let newest = first
        .iter()
        .map(|(_, row)| row.taken.taken_at)
        .max()
        .unwrap();
    let back = newest - 3600;
    let done = crate::lists::act(
        &s[1].conn,
        &s[1].identity,
        Do::File(filing(8, "desk")),
        back,
    )
    .unwrap();
    let crate::lists::Done::Made(made) = done else {
        panic!("{done:?}")
    };
    let kept = cordelia_storage::shared_lists::taken(&s[1].conn).unwrap();
    let (_, own) = kept
        .iter()
        .find(|(taking, _)| *taking == made[0].taking())
        .unwrap();
    assert_eq!(own.taken.taken_at, newest, "not {back}");
}

// ── The review of #281 ───────────────────────────────────────────────

/// What `share` says of the channel named `name` on device `n` for Alice:
/// the word of its refusal, or "ok".
fn share_word(s: &Several, n: usize, name: &str, now: i64) -> &'static str {
    let alice = encode_public_key(&member(1).public_key()).unwrap();
    match sharing::share_plan(
        &s[n].conn,
        &s[n].identity,
        &relays(),
        name,
        &alice,
        None,
        now,
    ) {
        Ok(_) => "ok",
        Err(Failed::Refused(refusal)) => refusal.word,
        Err(Failed::Error(e)) => panic!("{e}"),
    }
}

/// `share` hands out no channel a removed key may read (the review of
/// #281, high 2; §5.5): after the laptop removes the tablet, the desktop
/// refuses to share "review" (`not_clean`), a share planned before the
/// removal and made after it is refused where it is written, and a share
/// made before the removal that waits to be sent is not sent. Once the
/// desktop makes the channel anew, the new one is shared.
#[test]
fn share_hands_out_no_channel_that_is_not_clean() {
    let mut s = bob(3);
    let now = s.now + 10;
    holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    // Before the removal, the desktop makes a share, and plans another.
    let alice = encode_public_key(&member(1).public_key()).unwrap();
    let (conn, identity) = (&s[1].conn, &s[1].identity);
    let to = sharing::share_plan(conn, identity, &relays(), "review", &alice, None, now).unwrap();
    sharing::make_share(conn, identity, &relays(), &to.what, false, now).unwrap();
    assert_eq!(
        sharing::shares_to_push(conn, identity, &AT).unwrap().len(),
        1
    );
    let carol = encode_public_key(&member(2).public_key()).unwrap();
    let later =
        sharing::share_plan(conn, identity, &relays(), "review", &carol, None, now).unwrap();

    s.change(0, &[0, 1], &[2]);
    s.pass(0, 1);
    let now = s.now + 20;
    let (conn, identity) = (&s[1].conn, &s[1].identity);
    assert_eq!(share_word(&s, 1, "review", now), "not_clean");
    assert_eq!(
        refusal_word(sharing::make_share(
            conn,
            identity,
            &relays(),
            &later.what,
            false,
            now
        )),
        "not_clean"
    );
    assert!(
        sharing::shares_to_push(conn, identity, &AT)
            .unwrap()
            .is_empty()
    );
    // Made anew here, the new channel is shared.
    made_anew_on(&s, 1, "review", now);
    assert_eq!(share_word(&s, 1, "review", now), "ok");
}

/// `share` hands out no channel paused by an offer (the review of #281,
/// high 2; §5.5): Alice makes "review" anew without Carol, sealed to Bob;
/// Bob's device refuses to share it (`paused`) until he stays.
#[test]
fn share_hands_out_no_channel_that_is_paused() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    written_by(&s, 0, &channel, &[&alice, &carol], now);
    assert_eq!(share_word(&s, 0, "review", now), "ok");
    stores(
        &s,
        0,
        &offer_by(
            &alice,
            &channel,
            21,
            &[alice.public_key(), s.key(0)],
            now,
            2,
        ),
        now,
    );
    assert_eq!(share_word(&s, 0, "review", now), "paused");
    make_stay(&s[0].conn, &channel.id, "review").unwrap();
    assert_eq!(share_word(&s, 0, "review", now), "ok");
}

/// The signers of what device `n` shows in `channel` at `now`.
fn shown_signers(s: &Several, n: usize, channel: &Shared, now: i64) -> Vec<[u8; 32]> {
    crate::shared::shown(&s[n].conn, &s[n].identity, &channel.id, now)
        .unwrap()
        .into_iter()
        .map(|shown| shown.signer)
        .collect()
}

/// While an offer pauses a device, it shows nothing of the keys the offer
/// leaves out, and after a move nothing of those the offer moved to leaves
/// out (the review of #281, medium 1): Alice makes "review" anew without
/// Carol (a device Carol removed, say), sealed to Bob. Carol's messages,
/// before the offer and after it, are not shown on Bob's device; `shared
/// stay` brings them back. A later offer without Carol pauses it again,
/// and once Bob moves to it, the old channel shows nothing of Carol's.
#[test]
fn a_paused_device_shows_nothing_of_a_key_its_offer_leaves_out() {
    use crate::shared::tests::message;
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    written_by(&s, 0, &channel, &[&alice, &carol], now);
    stores(&s, 0, &message(&carol, &channel, 1, "before", now), now);
    stores(&s, 0, &message(&alice, &channel, 1, "hello", now), now);
    let both = vec![alice.public_key(), carol.public_key()];
    let mut seen = shown_signers(&s, 0, &channel, now);
    seen.sort();
    let mut want = both.clone();
    want.sort();
    assert_eq!(seen, want);
    let without_carol = |seed: u8, rev: u64| {
        offer_by(
            &alice,
            &channel,
            seed,
            &[alice.public_key(), s.key(0)],
            now,
            rev,
        )
    };
    stores(&s, 0, &without_carol(21, 2), now);
    stores(
        &s,
        0,
        &message(&carol, &channel, 2, "after", now + 1),
        now + 1,
    );
    assert_eq!(
        shown_signers(&s, 0, &channel, now + 1),
        vec![alice.public_key()]
    );
    make_stay(&s[0].conn, &channel.id, "review").unwrap();
    let shown = shown_signers(&s, 0, &channel, now + 1);
    assert_eq!(
        shown
            .iter()
            .filter(|key| **key == carol.public_key())
            .count(),
        2
    );
    // A later offer pauses it again; Bob moves to it.
    stores(&s, 0, &without_carol(22, 3), now + 2);
    assert_eq!(
        shown_signers(&s, 0, &channel, now + 2),
        vec![alice.public_key()]
    );
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let plan = move_plan(conn, identity, &relays(), "review", None, None, now + 2).unwrap();
    make_move(conn, identity, &plan.what, now + 2).unwrap();
    assert_eq!(row(&s, 0, &channel).state, State::Moved);
    assert_eq!(
        shown_signers(&s, 0, &channel, now + 2),
        vec![alice.public_key()]
    );
}

/// A closed device's door takes nothing in a shared channel (the review of
/// #281, low 1; decision 2026-10-24 (removal), rule 10): the device keeps
/// a key as removed that holds its change's secret, and Alice's message is
/// refused as `Closed`, not stored.
#[test]
fn a_closed_device_takes_nothing_in_a_shared_channel() {
    use crate::shared::tests::{given, message};
    use crate::take::{NotTaken, Taken};
    let s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let alice = member(1);
    written_by(&s, 0, &channel, &[&alice], now);
    let conn = &s[0].conn;
    cordelia_storage::person::keep_removed(conn, &[s.key(2)], now).unwrap();
    assert!(!crate::person::follows_a_clear_change(conn).unwrap());
    assert_eq!(
        given(&s, 0, &message(&alice, &channel, 1, "hello", now), now),
        Taken::Refused(NotTaken::Closed)
    );
}

/// `shared move` checks again after its yes (the review of #281, low 3):
/// the desktop plans a move to Alice's offer before it has read the
/// laptop's removal of the tablet; it reads the removal before the yes,
/// and the move is refused `not_clean`.
#[test]
fn shared_move_checks_again_after_its_yes() {
    let mut s = bob(3);
    let (channel, alice) = removed_the_tablet(&mut s, 1);
    let now = s.now + 20;
    stores(
        &s,
        1,
        &offer_by(
            &alice,
            &channel,
            30,
            &[alice.public_key(), s.key(1)],
            now,
            2,
        ),
        now,
    );
    let plan = move_plan(
        &s[1].conn,
        &s[1].identity,
        &relays(),
        "review",
        None,
        None,
        now,
    )
    .unwrap();
    s.pass(0, 1);
    assert!(is_not_clean(&s[1].conn, &channel.id).unwrap());
    assert_eq!(
        refusal_word(make_move(&s[1].conn, &s[1].identity, &plan.what, now)),
        "not_clean"
    );
    assert_eq!(row(&s, 1, &channel).state, State::Held);
}

/// The status names no device for a channel first held after a removal
/// (issue #279, its first part): the laptop removes the tablet, holding no
/// shared channel; an hour on it files one, which is not clean, and the
/// status's `removed_device_holds` lists it with no `device` field.
#[test]
fn the_status_names_no_device_for_a_channel_first_held_after_a_removal() {
    let mut s = bob(3);
    s.meet(&[0, 1, 2]);
    s.change(0, &[0, 1], &[2]);
    let now = s.now + HOUR_SECS;
    let channel = holds(&s, 0, 9, "later", now);
    assert!(is_not_clean(&s[0].conn, &channel.id).unwrap());
    let own = relays();
    let said = crate::state::SharedSaid::default();
    let beside = crate::shared_status::Beside {
        own_relays: &own,
        connected: &[AT],
        said: &said,
        next_read: None,
    };
    let shared = crate::shared_status::status_of(&s[0].conn, &s[0].identity, &beside, now)
        .unwrap()
        .unwrap();
    let groups = shared["removed_device_holds"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0]["channels"], serde_json::json!(["later"]));
    assert!(groups[0].get("device").is_none(), "{groups:?}");
    assert_eq!(groups[0]["devices"], serde_json::json!([]), "{groups:?}");
}

const HOUR_SECS: i64 = 3600;

/// A paused device hides the keys every offer that pauses it leaves out,
/// not the first offer's alone (the review of #282, medium 2): Alice
/// removes her tablet and makes "review" anew without it; later Carol
/// removes hers and makes it anew without hers. Bob stays on neither:
/// what either tablet sends is shown on Bob's device no more.
#[test]
fn a_paused_device_hides_what_every_offer_that_pauses_it_leaves_out() {
    use crate::shared::tests::message;
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    let (alice_tablet, carol_tablet) = (member(3), member(4));
    let all = [&alice, &carol, &alice_tablet, &carol_tablet];
    written_by(&s, 0, &channel, &all, now);
    for (n, key) in all.iter().enumerate() {
        stores(&s, 0, &message(key, &channel, 1, "before", now), now);
        assert_eq!(shown_signers(&s, 0, &channel, now).len(), n + 1);
    }
    let without = |maker: &NodeIdentity, left_out: &NodeIdentity, seed: u8, at: i64| {
        let keys: Vec<[u8; 32]> = all
            .iter()
            .map(|key| key.public_key())
            .filter(|key| *key != left_out.public_key())
            .chain([s.key(0)])
            .collect();
        offer_by(maker, &channel, seed, &keys, at, 2)
    };
    stores(&s, 0, &without(&alice, &alice_tablet, 21, now), now);
    stores(&s, 0, &without(&carol, &carol_tablet, 22, now + 1), now + 1);
    stores(
        &s,
        0,
        &message(&carol_tablet, &channel, 2, "after", now + 2),
        now + 2,
    );
    let mut seen = shown_signers(&s, 0, &channel, now + 2);
    seen.sort();
    let mut want = vec![alice.public_key(), carol.public_key()];
    want.sort();
    assert_eq!(seen, want);
}

// ── The review of #282 ───────────────────────────────────────────────

/// Device `n` shares "review" with `to` at `now`.
fn shares_review(s: &Several, n: usize, to: &NodeIdentity, now: i64) {
    let to = encode_public_key(&to.public_key()).unwrap();
    let (conn, identity) = (&s[n].conn, &s[n].identity);
    let plan = sharing::share_plan(conn, identity, &relays(), "review", &to, None, now).unwrap();
    sharing::make_share(conn, identity, &relays(), &plan.what, false, now).unwrap();
}

/// Device `n`'s pass writes over the shares it does not send, and then
/// sends only deletes: one for each share of `shares`.
fn writes_over_its_shares(s: &Several, n: usize, shares: usize, now: i64) {
    let (conn, identity) = (&s[n].conn, &s[n].identity);
    assert_eq!(
        sharing::drop_old_shares(conn, identity, now).unwrap(),
        shares
    );
    let pushed = sharing::shares_to_push(conn, identity, &AT).unwrap();
    assert_eq!(pushed.len(), shares);
    assert!(pushed.iter().all(|(_, _, entry)| entry.delete));
}

/// A share waiting when its channel becomes not clean is written over
/// with a delete, which is sent (the review of #282, low 2): the desktop
/// shares "review" with Alice, the laptop removes the tablet, and the
/// desktop's next pass deletes the share at its relays, though its two
/// hours have not ended, so a removed device's channel is not taken.
#[test]
fn a_share_waiting_at_a_removal_is_written_over() {
    let mut s = bob(3);
    let now = s.now + 10;
    holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    shares_review(&s, 1, &member(1), now);
    let (conn, identity) = (&s[1].conn, &s[1].identity);
    assert_eq!(sharing::drop_old_shares(conn, identity, now).unwrap(), 0);
    s.change(0, &[0, 1], &[2]);
    s.pass(0, 1);
    writes_over_its_shares(&s, 1, 1, s.now + 20);
}

/// A share waiting when an offer pauses its channel is written over with
/// a delete, which is sent (the review of #282, low 2): Bob shares
/// "review" with Dave; Alice makes it anew without Carol, sealed to Bob.
#[test]
fn a_share_waiting_at_a_pause_is_written_over() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    written_by(&s, 0, &channel, &[&alice, &carol], now);
    shares_review(&s, 0, &member(3), now);
    let without_carol = &[alice.public_key(), s.key(0)];
    stores(
        &s,
        0,
        &offer_by(&alice, &channel, 21, without_carol, now, 2),
        now,
    );
    writes_over_its_shares(&s, 0, 1, now);
}

/// **An offer made past the bound is no offer, and stops nothing** (the
/// read of #281 for the shared gate, high): Carol's offer says it was made
/// at u64::MAX. Before, the door stored it as a negative time, which the
/// store's check refused: the take failed, the shared pass stopped at that
/// relay before its pushes, and every later pass failed there the same
/// way. Now the reader refuses it as no anew record: the entry is stored
/// and counted, nothing is kept of it as an offer, and the door takes what
/// follows.
#[test]
fn an_offer_made_past_the_bound_is_no_offer_and_stops_nothing() {
    use crate::shared::tests::{given, message};
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let carol = member(2);
    stores(&s, 0, &anew(&carol, &channel, 1), now);
    let mut value =
        Anew::Offer(Offer::make(9, &channel.id, &new_card(20), &[carol.public_key()]).unwrap())
            .to_value()
            .unwrap();
    value[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
    let late = anew_of(&carol, &channel, 2, value);
    let taken = given(&s, 0, &late, now);
    assert!(
        matches!(
            taken,
            crate::take::Taken::Shared {
                stored: cordelia_storage::entries::Outcome::Stored,
                read: Some(Read::NotAMessage(_)),
            }
        ),
        "{taken:?}"
    );
    assert!(
        st(rows::offers_in(&s[0].conn, &channel.id))
            .unwrap()
            .is_empty()
    );
    let after = message(&carol, &channel, 1, "after", now);
    assert!(stores(&s, 0, &after, now).is_some());
}

/// **A share picked before a removal is not pushed after it** (the read of
/// #281 for the shared gate, medium): the desktop's pass picks its share of
/// "review" for Alice to push; before the push, another relay's turn
/// applies the laptop's removal of the tablet. The check the push makes
/// under the lock, and again once its stream is open, now refuses the
/// share; the delete written over it is still pushed.
#[test]
fn a_share_picked_before_a_removal_is_not_pushed_after_it() {
    let mut s = bob(3);
    let now = s.now + 10;
    holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    let alice = member(1).public_key();
    shares_review(&s, 1, &member(1), now);
    let picked = sharing::shares_to_push(&s[1].conn, &s[1].identity, &AT).unwrap();
    let [(key, channel, share)] = &picked[..] else {
        panic!("{picked:?}");
    };
    assert_eq!(*key, alice);
    assert!(!share.delete);
    let may = |s: &Several, entry: &CheckedEntry| {
        sharing::may_push_share(&s[1].conn, &s[1].identity, key, channel, entry).unwrap()
    };
    assert!(may(&s, share));
    // Not for another channel than the one it hands.
    let elsewhere = [9; 32];
    assert!(!sharing::may_push_share(&s[1].conn, &s[1].identity, key, &elsewhere, share).unwrap());

    s.change(0, &[0, 1], &[2]);
    s.pass(0, 1);
    assert!(is_not_clean(&s[1].conn, channel).unwrap());
    assert!(!may(&s, share));
    // The delete over it, at the next pass, is pushed.
    writes_over_its_shares(&s, 1, 1, s.now + 20);
    let pushed = sharing::shares_to_push(&s[1].conn, &s[1].identity, &AT).unwrap();
    let [(_, _, delete)] = &pushed[..] else {
        panic!("{pushed:?}");
    };
    assert!(may(&s, delete));
}

/// **A shared push picked before a removal is not sent after it** (the
/// read of #281 for the shared gate, low 2): the desktop's pass picks what
/// waits of its own in "review"; before the push's stream is open, another
/// relay's turn applies the laptop's removal of the tablet. The check made
/// once the stream is open (`still_sends`) now refuses the batch.
#[test]
fn a_shared_push_picked_before_a_removal_is_not_sent_after_it() {
    use crate::shared_pass::{still_sends, to_send, usable};
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    let most = crate::at_relays::Most {
        entries: 100,
        bytes: 1 << 20,
    };
    let (conn, identity) = (&s[1].conn, &s[1].identity);
    let here = usable(conn, &channel.id, &AT).unwrap().unwrap();
    crate::take::take(conn, identity, &anew(identity, &channel, 1), now).unwrap();
    let batch = to_send(conn, identity, &here, &AT, most).unwrap();
    assert!(!batch.is_empty());
    assert!(still_sends(conn, identity, &channel.id, &AT, &batch).unwrap());
    s.change(0, &[0, 1], &[2]);
    s.pass(0, 1);
    let (conn, identity) = (&s[1].conn, &s[1].identity);
    assert!(is_not_clean(conn, &channel.id).unwrap());
    assert!(!still_sends(conn, identity, &channel.id, &AT, &batch).unwrap());
    assert!(
        to_send(conn, identity, &here, &AT, most)
            .unwrap()
            .is_empty()
    );
}

// ── The new channel line (decision 2026-11-06 (joining), rule 5) ─────

/// The relay of the channels of these tests whose new channel line is
/// printed: a key that can be used, as a relay's is, since a line names
/// only such a key. [`AT`] is not one, so its channels print no line.
pub(crate) fn line_at() -> [u8; 32] {
    NodeIdentity::from_seed([0x52; 32]).unwrap().public_key()
}

pub(crate) fn line_relays() -> Vec<OwnRelay> {
    vec![OwnRelay {
        name: "relay.example.org:9474".into(),
        key: line_at(),
    }]
}

/// The card made from `seed`, at [`line_at`].
pub(crate) fn card_at_line_at(seed: u8) -> Card {
    let mut bytes = vec![seed; 32];
    bytes.extend_from_slice(&Relays::new(&[line_at()]).unwrap().to_bytes());
    Card::from_bytes(&bytes).unwrap()
}

/// `key` with its top bit flipped: another key to Ed25519, the same to
/// X25519.
fn twin(key: [u8; 32]) -> [u8; 32] {
    let mut twin = key;
    twin[31] ^= 0x80;
    twin
}

/// Device `n` files the channel of the card made from `seed`, at
/// [`line_at`], as `name`.
pub(crate) fn holds_at_line_at(s: &Several, n: usize, seed: u8, name: &str, now: i64) -> Shared {
    let card = card_at_line_at(seed);
    let filing = Filing {
        channel: card.channel_id().unwrap(),
        card: card.clone(),
        name: name.into(),
        came: Came::Made,
    };
    acts(s, n, Do::File(filing), now);
    Shared {
        secret: card.secret().unwrap(),
        id: card.channel_id().unwrap(),
    }
}

/// Device `n` follows `repository`, whose list read at `at` has the
/// channel line of `channel` with `without`, and a line for each of
/// `devices`.
pub(crate) fn follows_a_list(
    s: &Several,
    n: usize,
    repository: &str,
    channel: &[u8; 32],
    without: &[[u8; 32]],
    devices: &[[u8; 32]],
    at: i64,
) {
    let mut list = ChannelLine {
        channel: *channel,
        relays: vec![line_at()],
        without: without.to_vec(),
    }
    .to_line()
    .unwrap();
    list.push('\n');
    for (k, key) in devices.iter().enumerate() {
        list.push_str(&format!("{}   d{k}\n", encode_public_key(key).unwrap()));
    }
    let conn = &s[n].conn;
    follows::follow(conn, repository, "origin", "/home/bob/Work/project", at).unwrap();
    let read = follows::LastRead {
        commit: "c".repeat(40),
        at,
        from_clone: true,
    };
    follows::read_done(conn, repository, &read, list.as_bytes(), None).unwrap();
}

/// Device `n` makes the channel `name` anew with `shared anew`, keeping the
/// keys of `keep` and leaving out every other key it is asked about.
/// Returns what it said, and the keys it left out in the order asked.
pub(crate) fn anew_keeping(
    s: &Several,
    n: usize,
    name: &str,
    keep: &[[u8; 32]],
    now: i64,
) -> (Vec<String>, Vec<[u8; 32]>) {
    let (conn, identity) = (&s[n].conn, &s[n].identity);
    let as_typed = |keys: &[[u8; 32]]| -> Vec<String> {
        keys.iter()
            .map(|key| encode_public_key(key).unwrap())
            .collect()
    };
    let (listing, _) =
        anew_plan(conn, identity, &line_relays(), name, None, &[], None, now).unwrap();
    let listed = as_typed(&listing.asked);
    let typed = as_typed(keep);
    let (listing, plan) = anew_plan(
        conn,
        identity,
        &line_relays(),
        name,
        None,
        &[],
        Some((&typed, &listed)),
        now,
    )
    .unwrap();
    let said = make_anew(conn, identity, &line_relays(), &plan.unwrap().what, now).unwrap();
    out(s, n, now);
    let left = listing
        .asked
        .into_iter()
        .filter(|key| !keep.contains(key))
        .collect();
    (said, left)
}

/// The new channel line said in `said`: the line after [`PUT_THE_LINE`],
/// read as a list reads it.
pub(crate) fn line_in(said: &[String]) -> (String, ChannelLine) {
    let at = said
        .iter()
        .position(|line| line == PUT_THE_LINE)
        .unwrap_or_else(|| panic!("no new channel line in {said:?}"));
    let line = said[at + 1].clone();
    let read = crate::members::read(line.as_bytes()).unwrap();
    assert!(read.devices.is_empty(), "{line}");
    (line, read.channel.unwrap())
}

/// What device `n` kept of its making anew of `channel`.
pub(crate) fn kept_of(s: &Several, n: usize, channel: &Shared) -> follows::MadeLine {
    follows::made_lines(&s[n].conn)
        .unwrap()
        .into_iter()
        .find(|made| made.channel == channel.id)
        .unwrap()
}

/// `shared anew` on a channel a follow's list names (rule 5): its line
/// names after `without` the keys it left out that the list names, Carol's
/// and not Dave's, which the list does not name; and carries over the
/// current line's `without` keys that the list still names, Erin's,
/// whose line is still there, and not Frank's, whose line went. Alice
/// stays and is named nowhere. The line is printed after the line that
/// says where to put it, reads back as the same channel line, and is kept
/// with every key left out.
#[test]
fn shared_anew_names_the_listed_keys_it_left_out_and_carries_the_current_ones() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    let (erin, frank) = (member(4).public_key(), member(5).public_key());
    written_by(&s, 0, &channel, &[&alice, &carol, &dave], now);
    let listed = [s.key(0), alice.public_key(), carol.public_key(), erin];
    follows_a_list(
        &s,
        0,
        "example.org/team/project",
        &channel.id,
        &[erin, frank],
        &listed,
        now,
    );
    // Another follow's list, of another channel, changes nothing here.
    let other = Shared::of(9).id;
    let dave_key = dave.public_key();
    follows_a_list(
        &s,
        0,
        "example.org/team/other",
        &other,
        &[dave_key],
        &[dave_key],
        now,
    );

    let (said, left) = anew_keeping(&s, 0, "review", &[alice.public_key()], now);
    let new = filed_as(&s, 0, "review");
    let (line, read) = line_in(&said);
    assert!(said[0].starts_with("Made \"review\" anew"), "{said:?}");
    assert_eq!(said[1], PUT_THE_LINE);
    assert_eq!(
        read,
        ChannelLine {
            channel: new.id,
            relays: vec![line_at()],
            without: vec![erin, carol.public_key()],
        }
    );
    assert_eq!(read.to_line().unwrap(), line);
    // Kept, with every key it left out.
    let kept = kept_of(&s, 0, &channel);
    assert_eq!(kept.new_channel, new.id);
    assert_eq!(kept.line.as_deref(), Some(line.as_str()));
    assert_eq!(kept.left_out, left);
    let mut out = left.clone();
    out.sort();
    let mut expected = vec![carol.public_key(), dave_key];
    expected.sort();
    assert_eq!(out, expected);
}

/// `shared anew` on a channel no follow's list names (rule 5): its line
/// names every key it left out, as listed, and nothing else: a follow of
/// another repository, whose list names another channel, neither cuts it
/// nor adds to it.
#[test]
fn shared_anew_where_no_list_names_the_channel_names_every_key_left_out() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    written_by(&s, 0, &channel, &[&alice, &carol, &dave], now);
    let other = Shared::of(9).id;
    let erin = member(4).public_key();
    follows_a_list(
        &s,
        0,
        "example.org/team/other",
        &other,
        &[erin],
        &[erin, alice.public_key()],
        now,
    );

    let (said, left) = anew_keeping(&s, 0, "review", &[alice.public_key()], now);
    let (line, read) = line_in(&said);
    assert_eq!(left.len(), 2);
    assert_eq!(read.without, left, "{line}");
    assert_eq!(read.channel, filed_as(&s, 0, "review").id);
    assert_eq!(
        kept_of(&s, 0, &channel).line.as_deref(),
        Some(line.as_str())
    );
}

/// A twin counts as its key (rule 5): the current line names Carol's twin
/// after `without`, and `shared anew` leaves Carol out again, so the new
/// line names her once; it names Alice's twin, and Alice stays, so the new
/// line does not name her at all.
#[test]
fn a_twin_is_named_once() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    written_by(&s, 0, &channel, &[&alice, &carol], now);
    let (alice_key, carol_key) = (alice.public_key(), carol.public_key());
    let without = [twin(carol_key), twin(alice_key)];
    let listed = [s.key(0), alice_key, carol_key];
    follows_a_list(
        &s,
        0,
        "example.org/team/project",
        &channel.id,
        &without,
        &listed,
        now,
    );

    let (said, left) = anew_keeping(&s, 0, "review", &[alice_key], now);
    assert_eq!(left, [carol_key]);
    let (line, read) = line_in(&said);
    assert_eq!(read.without, [twin(carol_key)], "{line}");
    assert_eq!(kept_of(&s, 0, &channel).left_out, [carol_key]);
}

/// A key and its twin left out are one key, kept and named once (rule 5):
/// Bob's laptop moves by Alice's offer, which seals to Carol and to her
/// twin, neither of which has moved yet; `shared anew` there asks about
/// both, and leaves both out.
#[test]
fn a_key_and_its_twin_left_out_are_kept_once() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2).public_key());
    written_by(&s, 0, &channel, &[&alice], now);
    let card = card_at_line_at(21);
    let sealed_to = [alice.public_key(), s.key(0), carol, twin(carol)];
    let offer = Offer::make(now as u64, &channel.id, &card, &sealed_to).unwrap();
    let value = Anew::Offer(offer).to_value().unwrap();
    stores(&s, 0, &anew_of(&alice, &channel, 2, value), now);
    {
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        let plan = move_plan(conn, identity, &line_relays(), "review", None, None, now).unwrap();
        make_move(conn, identity, &plan.what, now).unwrap();
    }
    let new = Shared {
        secret: card.secret().unwrap(),
        id: card.channel_id().unwrap(),
    };
    stores(&s, 0, &anew(&alice, &new, 1), now);

    let (said, left) = anew_keeping(&s, 0, "review", &[alice.public_key()], now);
    assert_eq!(left, [carol, twin(carol)], "both are asked about");
    let (line, read) = line_in(&said);
    assert_eq!(read.without, [carol], "{line}");
    assert_eq!(kept_of(&s, 0, &new).left_out, [carol]);
}

/// A removal's making anew names the removed device after `without` (rule
/// 5), whether or not it wrote in the channel, as it held every seed of the
/// person's; and whatever the list says, so that a line that later lists
/// it again does not let it in. The tablet wrote in `review` and not in
/// `design`; Bob's laptop follows a list naming `review` that still lists
/// the tablet, and one naming `notes` that does not; no list names
/// `design`. The removal says each line, after the line it says of each
/// channel, and the end of the removal says the same, from what was kept.
#[test]
fn a_removal_names_the_device_it_removed_after_without() {
    let mut s = bob(3);
    let now = s.now + 10;
    let review = holds_at_line_at(&s, 0, 7, "review", now);
    let design = holds_at_line_at(&s, 0, 8, "design", now);
    let notes = holds_at_line_at(&s, 0, 9, "notes", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    let alice = member(1);
    for channel in [&review, &design, &notes] {
        written_by(&s, 0, channel, &[&alice], now);
    }
    let tablet = crate::several::identity_of(2).public_key();
    stores(
        &s,
        0,
        &anew(&crate::several::identity_of(2), &review, 1),
        now,
    );
    let mut listed = vec![s.key(0), s.key(1), alice.public_key()];
    follows_a_list(
        &s,
        0,
        "example.org/team/notes",
        &notes.id,
        &[],
        &listed,
        now,
    );
    listed.push(tablet);
    follows_a_list(
        &s,
        0,
        "example.org/team/project",
        &review.id,
        &[],
        &listed,
        now,
    );

    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    let said = anew_at_removal(conn, &s[0].identity, &line_relays(), now).unwrap();
    for (channel, name, named) in [
        (&review, "review", vec![tablet]),
        (&design, "design", vec![tablet]),
        (&notes, "notes", vec![tablet]),
    ] {
        let at = said
            .iter()
            .position(|line| line.starts_with(&format!("\"{name}\" is made anew")))
            .unwrap_or_else(|| panic!("{said:?}"));
        assert_eq!(said[at + 1], PUT_THE_LINE, "{said:?}");
        let (line, read) = line_in(&said[at..]);
        assert_eq!(read.without, named, "{name}: {line}");
        assert_eq!(read.channel, filed_as(&s, 0, name).id);
        let kept = kept_of(&s, 0, channel);
        assert_eq!(kept.line.as_deref(), Some(line.as_str()));
        assert_eq!(kept.left_out, named);
    }
    let mut at_the_end = made_at_the_last_removal(conn, Some(0)).unwrap();
    let mut said = said;
    at_the_end.sort();
    said.sort();
    assert_eq!(at_the_end, said);
}

/// After a recovery, a channel made anew in the background keeps its new
/// channel line, for the status to show (rule 5): nothing hears it at a
/// terminal. It names the device the recovery removed.
#[test]
fn a_channel_made_anew_after_a_recovery_keeps_its_line() {
    let mut s = bob(2);
    let now = s.now + 10;
    let channel = holds_at_line_at(&s, 0, 7, "review", now);
    s.change(0, &[0], &[1]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    recovered(conn, &[s.key(1)], now).unwrap();
    assert_eq!(make_owed(conn, &s[0].identity, now, &|_| true).unwrap(), 1);
    let kept = kept_of(&s, 0, &channel);
    let new = filed_as(&s, 0, "review");
    assert_eq!(kept.new_channel, new.id);
    assert_eq!(kept.left_out, [s.key(1)]);
    let line = kept.line.unwrap();
    let read = crate::members::read(line.as_bytes())
        .unwrap()
        .channel
        .unwrap();
    assert_eq!(
        read,
        ChannelLine {
            channel: new.id,
            relays: vec![line_at()],
            without: vec![s.key(1)],
        }
    );
}

// ── The fix round of slice 6 ─────────────────────────────────────────

/// Bob's three devices hold `review` at [`line_at`], each following the
/// others' lists, with Alice's key shown and labelled on the laptop, and
/// the laptop removes the tablet and makes `review` anew (decision
/// 2026-10-24, rule 24). Returns the channel made anew, C1, and Alice; the
/// laptop then holds C2 as `review`.
fn removed_at_line_at(s: &mut Several) -> (Shared, NodeIdentity) {
    let now = s.now + 10;
    let c1 = holds_at_line_at(s, 0, 7, "review", now);
    labels(s, 0, &member(1).public_key(), Some("alice"), now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(s, n, now);
    }
    let alice = member(1);
    written_by(s, 0, &c1, &[&alice], now);
    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    anew_at_removal(&s[0].conn, &s[0].identity, &line_relays(), now).unwrap();
    out(s, 0, now);
    (c1, alice)
}

/// A later making anew still names a removed device that the list names
/// (the review of slice 6, high 1, probe A; §12: "a removed device that is
/// still listed is never handed the new channel"): the laptop removes the
/// tablet, which never wrote in `review`, and makes C1 into C2. The desktop
/// follows the filing, holds C2 not clean, and makes it anew itself (rule
/// 23), while the list still names C1 and lists the tablet. Its line names
/// the tablet.
#[test]
fn a_making_anew_on_another_device_after_a_removal_names_the_removed_device() {
    let mut s = bob(3);
    let (c1, alice) = removed_at_line_at(&mut s);
    let tablet = s.key(2);
    let now = s.now + 30;
    follows(&mut s, 0, 1, now);
    let c2 = filed_as(&s, 1, "review");
    assert_ne!(c2.id, c1.id);
    assert!(is_not_clean(&s[1].conn, &c2.id).unwrap(), "rule 23");
    let listed = [s.key(0), s.key(1), tablet, alice.public_key()];
    follows_a_list(&s, 1, "example.org/team/project", &c1.id, &[], &listed, now);

    let (said, _) = anew_keeping(&s, 1, "review", &[], now);
    let (line, read) = line_in(&said);
    assert_eq!(read.without, [tablet], "{line}");
    assert_eq!(kept_of(&s, 1, &c2).left_out, [tablet]);
}

/// A second `shared anew` before the removal's line is merged names the
/// removed device again (the review of slice 6, high 1, probe B): the list
/// still names C1, and lists the tablet and Carol; the laptop makes C2 anew
/// and leaves Carol out. Its line names both.
#[test]
fn a_second_making_anew_before_the_removals_line_is_merged_names_the_removed_device() {
    let mut s = bob(3);
    let (c1, alice) = removed_at_line_at(&mut s);
    let tablet = s.key(2);
    let now = s.now + 30;
    let c2 = filed_as(&s, 0, "review");
    let carol = member(2);
    written_by(&s, 0, &c2, &[&alice, &carol], now);
    let listed = [
        s.key(0),
        s.key(1),
        tablet,
        alice.public_key(),
        carol.public_key(),
    ];
    follows_a_list(&s, 0, "example.org/team/project", &c1.id, &[], &listed, now);

    let (said, left) = anew_keeping(&s, 0, "review", &[alice.public_key()], now);
    assert_eq!(left, [carol.public_key()]);
    let (line, read) = line_in(&said);
    assert_eq!(read.without, [tablet, carol.public_key()], "{line}");
    assert_eq!(kept_of(&s, 0, &c2).left_out, [tablet, carol.public_key()]);
}

/// A key removed at an earlier removal is named by a later making anew only
/// where the list names it (rule 5): after the laptop removed the tablet,
/// it makes C2 anew with `shared anew`, under a list naming C1 that does
/// not list the tablet. Its line does not name it.
#[test]
fn a_later_making_anew_names_an_earlier_removed_key_only_where_listed() {
    let mut s = bob(3);
    let (c1, alice) = removed_at_line_at(&mut s);
    let now = s.now + 30;
    let listed = [s.key(0), s.key(1), alice.public_key()];
    follows_a_list(&s, 0, "example.org/team/project", &c1.id, &[], &listed, now);

    let (said, _) = anew_keeping(&s, 0, "review", &[alice.public_key()], now);
    let (line, read) = line_in(&said);
    assert!(read.without.is_empty(), "{line}");
}

/// A key the list names stays at a removal though it has not moved, and is
/// not named (the review of slice 6, medium 1; decision 2026-10-24, rule
/// 24, as the person ruled on 7 November): Bob keeps Carol when he makes C0
/// into C1, and removes the tablet before Carol moves. The list, which
/// lists Carol, keeps her in C2, and the line names the tablet alone, so
/// the list is not held back by her.
#[test]
fn a_key_a_removal_leaves_out_only_as_not_moved_is_not_named() {
    let mut s = bob(3);
    let now = s.now + 10;
    let c0 = holds_at_line_at(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    let carol = member(2).public_key();
    written_by(&s, 0, &c0, &[&member(2)], now);
    let tablet = s.key(2);
    let listed = [s.key(0), s.key(1), tablet, carol];
    follows_a_list(&s, 0, "example.org/team/project", &c0.id, &[], &listed, now);
    anew_keeping(&s, 0, "review", &[carol], now);
    let c1 = filed_as(&s, 0, "review");
    assert!(
        not_moved_yet(&s[0].conn, &s.key(0), &c1.id)
            .unwrap()
            .contains(&carol)
    );

    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    let said = anew_at_removal(conn, &s[0].identity, &line_relays(), now).unwrap();
    let offer = st(rows::offer_from(conn, &c1.id, &s.key(0)))
        .unwrap()
        .unwrap();
    assert!(
        offer.sealed_to.contains(&carol),
        "rule 24 keeps the keys the list names"
    );
    let (line, read) = line_in(&said);
    assert_eq!(read.without, [tablet], "{line}");
    assert_eq!(kept_of(&s, 0, &c1).left_out, [tablet]);
}

/// A chain of makings anew carries the keys left out on purpose (the review
/// of slice 6, medium 2): the list names C0, with Frank after `without`,
/// and still lists Erin and Frank. Bob leaves Erin out of C1, then makes C1
/// and C2 anew again, each before the line of the one before is merged.
/// Each line names Frank, from the list's line, and Erin, from what this
/// device left out back along the moves.
#[test]
fn a_chain_of_makings_anew_carries_the_keys_left_out_along_it() {
    let s = bob(1);
    let now = s.now + 10;
    let c0 = holds_at_line_at(&s, 0, 7, "review", now);
    let (dave, erin) = (member(3), member(4));
    let frank = member(5).public_key();
    written_by(&s, 0, &c0, &[&dave, &erin], now);
    let listed = [s.key(0), dave.public_key(), erin.public_key(), frank];
    follows_a_list(
        &s,
        0,
        "example.org/team/project",
        &c0.id,
        &[frank],
        &listed,
        now,
    );

    let (said, left) = anew_keeping(&s, 0, "review", &[dave.public_key()], now);
    assert_eq!(left, [erin.public_key()]);
    assert_eq!(line_in(&said).1.without, [frank, erin.public_key()]);
    for _ in 0..2 {
        let (said, left) = anew_keeping(&s, 0, "review", &[dave.public_key()], now);
        assert!(left.is_empty(), "{left:?}");
        let (line, read) = line_in(&said);
        assert_eq!(read.without, [frank, erin.public_key()], "{line}");
    }
}

/// A line longer than a list holds is cut, and says so (the review of slice
/// 6, low 1): with 300 keys left out and no list, the line names as many as
/// fit in 16 KiB, and says how many it does not.
#[test]
fn a_line_longer_than_a_list_is_cut_and_says_so() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds_at_line_at(&s, 0, 7, "review", now);
    let members: Vec<NodeIdentity> = (0..300).map(|k| member(1_000 + k)).collect();
    let refs: Vec<&NodeIdentity> = members.iter().collect();
    written_by(&s, 0, &channel, &refs, now);

    let (said, left) = anew_keeping(&s, 0, "review", &[], now);
    assert_eq!(left.len(), 300);
    let (line, read) = line_in(&said);
    assert!(line.len() <= MEMBERS_FILE_MAX_BYTES, "{}", line.len());
    assert!(line.len() + 71 > MEMBERS_FILE_MAX_BYTES, "as many as fit");
    let cut = 300 - read.without.len();
    assert!(cut > 0);
    assert_eq!(read.without, left[..read.without.len()]);
    let at = said.iter().position(|said| *said == line).unwrap();
    assert_eq!(
        said[at + 1],
        format!("The line is cut: {cut} keys left out are not on it.")
    );
    let kept = kept_of(&s, 0, &channel);
    assert_eq!((kept.cut, kept.left_out.len()), (cut as u64, 300));
}

// ── A removed key's twin, and a key a thief made ─────────────────────

/// Whether a seal of the offer that device `n` wrote in `channel` opens
/// with the X25519 secret of `holder`, whatever key the seal names: the
/// new channel's card where one does. A thief who holds that secret tries
/// each seal so.
fn a_seal_opens_for(
    s: &Several,
    n: usize,
    channel: &Shared,
    holder: &NodeIdentity,
) -> Option<Card> {
    let own = s.key(n);
    let slot = slot_id(
        &derive::slot_key(&channel.secret).unwrap(),
        &anew_name(&own).unwrap(),
    );
    let stored = entries::author_entry(&s[n].conn, &channel.id, &slot, &own)
        .unwrap()
        .unwrap();
    let inside = stored.entry.check().unwrap().open(&channel.secret).unwrap();
    let Anew::Offer(offer) = Anew::from_value(&inside.value).unwrap() else {
        panic!("no offer");
    };
    offer.seals.iter().find_map(|seal| {
        let one = Offer {
            made: offer.made,
            new_channel: offer.new_channel,
            relays: offer.relays.clone(),
            seals: vec![Seal {
                key: holder.public_key(),
                sealed: seal.sealed,
            }],
        };
        one.open(holder, &channel.id).ok()
    })
}

/// Message `number` of the twin `twin` in `channel`, saying `body`, as a
/// relay takes it from the wire: the relay's door checks it as every
/// entry is checked ([`Entry::check`]).
fn twin_says(twin: &Twin, channel: &Shared, number: u64, body: &str, sent: i64) -> CheckedEntry {
    let value = crate::shared::tests::says(body, sent).to_value().unwrap();
    let name = cordelia_crypto::message::message_name(&twin.key, number).unwrap();
    let rev = cordelia_crypto::message::message_rev(number).unwrap();
    let entry = twin.entry(&channel.secret, rev, &name, Value::Other(value));
    cordelia_storage::relay::check(&entry.to_wire()).unwrap()
}

/// Bob's three devices hold "review", each following the others' lists,
/// and Alice, whom the laptop labelled, and the tablet wrote there; then a
/// thief with the tablet writes there `wrote`, which device 0, the laptop,
/// stores, before it knows of any removal. Returns the channel.
fn a_thief_wrote(s: &mut Several, wrote: &dyn Fn(&Shared, i64) -> CheckedEntry) -> Shared {
    let now = s.now + 10;
    let channel = holds(s, 0, 7, "review", now);
    labels(s, 0, &member(1).public_key(), Some("alice"), now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(s, n, now);
    }
    written_by(s, 0, &channel, &[&member(1)], now);
    let tablet = crate::several::identity_of(2);
    stores(s, 0, &anew(&tablet, &channel, 1), now);
    stores(s, 0, &wrote(&channel, now), now);
    channel
}

/// The twin of a removed key is the removed key (decision 2026-10-24,
/// property 4 and rule 24; decision 2026-10-10 §2.4, §3.5): a thief with
/// Bob's tablet writes in "review" as the tablet's twin, the tablet's key
/// with its top bit flipped, signed with the tablet's secret negated. The
/// check that a relay and a device make takes it, and the door stores and
/// shows it as any key's; it is labelled. The laptop then removes
/// the tablet: it shows nothing of the twin, here or in the channel once
/// moved from, holds its label for nothing, lists it as a device removed
/// and asks nothing of it, and its making anew at the removal seals
/// nothing that the tablet's own X25519 secret opens.
#[test]
fn a_removal_leaves_out_the_twin_of_the_key_it_removes() {
    let mut s = bob(3);
    let tablet = crate::several::identity_of(2);
    let twin = Twin::of(&tablet);
    let channel = a_thief_wrote(&mut s, &|channel, now| {
        twin_says(&twin, channel, 1, "from the tablet's twin", now)
    });
    let shown = crate::shared::shown_keys(&s[0].conn, &channel.id).unwrap();
    assert!(shown.contains(&twin.key), "the door takes it as any key's");
    // It is labelled, as the stolen tablet could label it before its
    // removal.
    crate::shared::tests::labels(&s, 0, &twin.key, Some("alice"), s.now + 10);

    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let shown = crate::shared::shown_keys(conn, &channel.id).unwrap();
    assert!(!shown.contains(&twin.key), "shown nothing");
    assert!(!shown_signers(&s, 0, &channel, now).contains(&twin.key));
    let held = crate::person::held(conn).unwrap().unwrap();
    let knows = crate::shared::Knows::of(conn, &held).unwrap();
    assert!(!knows.knows(&twin.key), "its label counts for nothing");
    let said = log_lines(conn, identity, &row(&s, 0, &channel), now).unwrap();
    assert!(!said.iter().any(|line| line.contains("no longer shown")));
    let (listing, _) =
        anew_plan(conn, identity, &relays(), "review", None, &[], None, now).unwrap();
    assert!(!listing.asked.contains(&twin.key), "{:?}", listing.lines);
    assert_eq!(listing.removed, 2, "{:?}", listing.lines);
    anew_at_removal(conn, identity, &relays(), now).unwrap();
    let offer = st(rows::offer_from(conn, &channel.id, &s.key(0)))
        .unwrap()
        .unwrap();
    assert!(offer.sealed_to.contains(&member(1).public_key()));
    assert!(!offer.sealed_to.contains(&twin.key), "rule 24");
    assert!(
        a_seal_opens_for(&s, 0, &channel, &tablet).is_none(),
        "property 4"
    );
    // The channel moved from shows nothing of it either.
    assert_eq!(row(&s, 0, &channel).state, State::Moved);
    assert!(!shown_signers(&s, 0, &channel, now).contains(&twin.key));
}

/// An offer by a removed key's twin, and one that seals to it, are each a
/// fault, as they are of the removed key (decision 2026-10-10 §7): the
/// desktop reads the twin's offer, sealed to it, before it knows of the
/// laptop's removal of the tablet; once it applies the removal, that offer
/// is `maker_removed`, and Alice's, which seals to the twin, is
/// `seals_removed`.
#[test]
fn an_offer_by_or_to_a_removed_keys_twin_is_a_fault() {
    let mut s = bob(3);
    let (channel, alice) = removed_the_tablet(&mut s, 1);
    let now = s.now + 20;
    let twin = Twin::of(&crate::several::identity_of(2));
    let offer = Offer::make(now as u64, &channel.id, &new_card(30), &[s.key(1)]).unwrap();
    let value = Anew::Offer(offer).to_value().unwrap();
    let name = anew_name(&twin.key).unwrap();
    let by_twin = twin.entry(&channel.secret, 1, &name, Value::Other(value));
    stores(&s, 1, &by_twin.check().unwrap(), now);
    s.pass(0, 1);
    stores(
        &s,
        1,
        &offer_by(
            &alice,
            &channel,
            31,
            &[alice.public_key(), s.key(1), twin.key],
            now,
            2,
        ),
        now,
    );
    let mut is = what_is(&s, 1, &channel, now);
    is.sort_by_key(|(maker, _)| *maker != twin.key);
    assert_eq!(
        is,
        vec![
            (twin.key, OfferIs::Fault(Fault::MakerRemoved)),
            (alice.public_key(), OfferIs::Fault(Fault::SealsRemoved)),
        ]
    );
}

/// A key that a thief made with the stolen device's seed, before the
/// removal, does not stay at the removal's making anew (decision
/// 2026-10-24, rule 24, as the person ruled on 7 November): the thief
/// writes in "review" under a key of its own, which is in the laptop's
/// table, is no removed key and is not the person's. Who stays comes only
/// from what the removed device could not write, never from who wrote, so
/// the laptop's making anew seals nothing that key opens; Alice, whom the
/// laptop labelled, stays.
#[test]
fn a_removal_leaves_out_a_key_the_thief_made() {
    let mut s = bob(3);
    let made = NodeIdentity::from_seed([0x7e; 32]).unwrap();
    let channel = a_thief_wrote(&mut s, &|channel, now| {
        crate::shared::tests::message(&made, channel, 1, "from a key the thief made", now)
    });
    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    anew_at_removal(&s[0].conn, &s[0].identity, &relays(), now).unwrap();
    assert!(
        a_seal_opens_for(&s, 0, &channel, &made).is_none(),
        "the thief opens the new seed with the key it made"
    );
    assert!(a_seal_opens_for(&s, 0, &channel, &member(1)).is_some());
}

/// The keys that device `n`'s making anew of `channel` sealed to, in order.
fn sealed_to(s: &Several, n: usize, channel: &Shared) -> Vec<[u8; 32]> {
    st(rows::offer_from(&s[n].conn, &channel.id, &s.key(n)))
        .unwrap()
        .unwrap()
        .sealed_to
}

/// A channel shared by hand keeps, at a removal, the person's own devices
/// and the keys labelled by a device that counts, and no other key
/// (decision 2026-10-24, rule 24, as the person ruled on 7 November): Bob's
/// laptop labelled Alice and Erin, and his tablet labelled Dave, before the
/// laptop removes the tablet. Alice, Carol and Dave wrote in "review". The
/// making anew seals to the laptop, the desktop and Alice: not to Carol,
/// whom no label names; not to Dave, whose label the removed tablet made,
/// though it is in force; and not to Erin, labelled but never in the
/// channel as far as the laptop knows.
#[test]
fn a_removal_keeps_own_devices_and_keys_labelled_by_a_device_that_counts() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol, dave, erin) = (member(1), member(2), member(3), member(4));
    labels(&s, 0, &alice.public_key(), Some("alice"), now);
    labels(&s, 0, &erin.public_key(), Some("erin"), now);
    labels(&s, 2, &dave.public_key(), Some("dave"), now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    written_by(&s, 0, &channel, &[&alice, &carol, &dave], now);
    let dave_label = crate::lists::holds(&s[0].conn)
        .unwrap()
        .labels
        .into_iter()
        .find(|(act, _)| act.item.key == dave.public_key())
        .unwrap();
    assert_eq!(dave_label.0.maker, s.key(2), "the tablet labelled Dave");

    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    anew_at_removal(&s[0].conn, &s[0].identity, &relays(), now).unwrap();
    assert_eq!(
        sealed_to(&s, 0, &channel),
        vec![s.key(0), s.key(1), alice.public_key()]
    );
}

/// A channel that follows a repository keeps, at a removal, the person's
/// own devices and the keys its list names, and no other key (decision
/// 2026-10-24, rule 24, as the person ruled on 7 November): the laptop
/// follows a list that names "review", Alice and Dave, Erin, whom the
/// channel line names after `without`, and the tablet's twin, whose line is
/// not deleted yet. Alice and Carol wrote there, and a thief with
/// the tablet wrote under a key it made. Once the laptop removes the
/// tablet, its making anew seals to the laptop, the desktop, Alice and
/// Dave, who never wrote there: not to Carol, whom the list does not name,
/// though she wrote; not to Erin, left out before; and not to the tablet,
/// its twin or the thief's key.
#[test]
fn a_removal_keeps_the_keys_a_repositorys_list_names() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds_at_line_at(&s, 0, 7, "review", now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    let (alice, carol, dave, erin) = (member(1), member(2), member(3), member(4));
    let made = NodeIdentity::from_seed([0x7e; 32]).unwrap();
    written_by(&s, 0, &channel, &[&alice, &carol, &made], now);
    let tablet = s.key(2);
    let listed = [
        s.key(0),
        s.key(1),
        twin(tablet),
        alice.public_key(),
        dave.public_key(),
        erin.public_key(),
    ];
    follows_a_list(
        &s,
        0,
        "example.org/team/project",
        &channel.id,
        &[erin.public_key()],
        &listed,
        now,
    );

    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    anew_at_removal(&s[0].conn, &s[0].identity, &line_relays(), now).unwrap();
    assert_eq!(
        sealed_to(&s, 0, &channel),
        vec![s.key(0), s.key(1), alice.public_key(), dave.public_key()]
    );
}

/// A device that does not follow the repository a channel follows keeps,
/// at a removal, what a channel shared by hand keeps, and never the table
/// (decision 2026-10-24, rule 24, condition 2 of the person's ruling of 7
/// November): the desktop follows a list that names "review", Alice and
/// Carol, and the laptop does not. Both wrote there, and the laptop labelled
/// Alice. The laptop removes the tablet: its making anew seals to its own
/// devices and Alice, and not to Carol, whom only a list it does not
/// follow names.
#[test]
fn a_device_that_does_not_follow_keeps_what_a_channel_shared_by_hand_keeps() {
    let mut s = bob(3);
    let now = s.now + 10;
    let channel = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    labels(&s, 0, &alice.public_key(), Some("alice"), now);
    s.meet(&[0, 1, 2]);
    for n in 0..3 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    written_by(&s, 0, &channel, &[&alice, &carol], now);
    let listed = [s.key(0), s.key(1), alice.public_key(), carol.public_key()];
    follows_a_list(
        &s,
        1,
        "example.org/team/project",
        &channel.id,
        &[],
        &listed,
        now,
    );

    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    anew_at_removal(&s[0].conn, &s[0].identity, &line_relays(), now).unwrap();
    assert_eq!(
        sealed_to(&s, 0, &channel),
        vec![s.key(0), s.key(1), alice.public_key()]
    );
}

/// The machine of a recovery makes a channel anew with what a removal
/// keeps (decision 2026-10-24, rule 24): its own devices alone, where the
/// labeller no longer counts. Device 1 labelled Alice, and device 0, the
/// machine of the recovery, holds that label; the recovery removes device
/// 1, so its label keeps no one, and neither Alice nor Carol, who wrote
/// there, is sealed to. A label of device 0's own, Dave's, keeps him.
#[test]
fn a_recovery_makes_a_channel_anew_with_what_a_removal_keeps() {
    let mut s = bob(2);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    labels(&s, 1, &alice.public_key(), Some("alice"), now);
    labels(&s, 0, &dave.public_key(), Some("dave"), now);
    s.meet(&[0, 1]);
    for n in 0..2 {
        crate::lists::follow(&s[n].conn, &s[n].identity, now).unwrap();
        out(&s, n, now);
    }
    written_by(&s, 0, &channel, &[&alice, &carol, &dave], now);
    let alice_label = crate::lists::holds(&s[0].conn)
        .unwrap()
        .labels
        .into_iter()
        .find(|(act, _)| act.item.key == alice.public_key())
        .unwrap();
    assert_eq!(alice_label.0.maker, s.key(1), "device 1 labelled Alice");
    s.change(0, &[0], &[1]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    recovered(conn, &[s.key(1)], now).unwrap();
    assert_eq!(make_owed(conn, &s[0].identity, now, &|_| true).unwrap(), 1);
    assert_eq!(
        sealed_to(&s, 0, &channel),
        vec![s.key(0), dave.public_key()]
    );
}

// ── Decision 2026-10-24 (removal), rule 25, amended 13 November ─────

use cordelia_core::protocol::PERSONAL_MADE_PREFIX;
use cordelia_core::revision::next_under;
use cordelia_crypto::statement::Link as ChangeLink;

/// Bob's laptop (0), desktop (1) and tablet (2) meet; the desktop removes
/// the tablet (change 2), and the laptop follows that change. The time
/// after.
fn the_desktop_removed_the_tablet(s: &mut Several) -> i64 {
    s.meet(&[0, 1, 2]);
    s.change(1, &[0, 1], &[2]);
    s.pass(1, 0);
    assert_eq!(s[0].number(), 2, "the laptop follows the removal");
    s.now + 10
}

/// The change that device `n` follows.
fn followed(s: &Several, n: usize) -> ChangeLink {
    s[n].held().statement.statement.link().unwrap()
}

/// Each entry `made/` that device `n`'s store holds in the personal
/// channel of the change it follows, with what it holds.
fn made_entries(s: &Several, n: usize) -> Vec<(String, Value)> {
    let personal = s[n].personal();
    s[n].stored_in(&personal)
        .into_iter()
        .filter_map(|entry| entry.open(&personal).ok())
        .filter(|inside| inside.name.starts_with(PERSONAL_MADE_PREFIX))
        .map(|inside| (inside.name, inside.value))
        .collect()
}

/// Whether `entry`, of the personal channel whose secret is `personal`,
/// is an entry `made/`.
fn is_made(entry: &CheckedEntry, personal: &[u8; 32]) -> bool {
    entry
        .open(personal)
        .is_ok_and(|inside| inside.name.starts_with(PERSONAL_MADE_PREFIX))
}

/// The entry `made/<channel>` that `author` signs in the personal channel
/// of the change device `n` follows, naming `change`, put straight in
/// device `n`'s store.
fn writes_made(
    s: &Several,
    n: usize,
    author: &NodeIdentity,
    channel: &Shared,
    change: &ChangeLink,
    now: i64,
) {
    let entry = crate::several::entry_by(
        author,
        &s[n].personal(),
        next_under(None, s[n].number()).unwrap(),
        &crate::shared::made_name(&channel.id),
        Value::Other(crate::shared::made_value(change)),
        &[],
    );
    entries::store(&s[n].conn, &entry, now).unwrap();
}

/// A channel made after a removal is clean on each device that follows
/// the change it was made under (decision 2026-10-24 (removal), rule 25,
/// amended 13 November): the desktop removes the tablet, and the laptop,
/// on that change, makes "notes" with `shared new`, writing beside it the
/// entry `made/` that names change 2. The desktop first holds "notes"
/// clean, and writes there. No list that the tablet reads, of change 1,
/// files "notes", in what either device holds.
#[test]
fn a_channel_made_after_a_removal_is_clean_on_each_device_of_its_change() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    let notes = made_new(&s, 0, "notes", now);
    assert_eq!(
        made_entries(&s, 0),
        [(
            crate::shared::made_name(&notes.id),
            Value::Other(crate::shared::made_value(&followed(&s, 0)))
        )]
    );
    assert!(!is_not_clean(&s[0].conn, &notes.id).unwrap());
    follows(&mut s, 0, 1, now);
    let desktop = row(&s, 1, &notes);
    assert_eq!(desktop.state, State::Held);
    assert!(!is_not_clean(&s[1].conn, &notes.id).unwrap(), "rule 25");
    assert!(writes_there(&s[1].conn, &s[1].identity, &desktop).unwrap());
    let mut held = s[0].stored();
    held.extend(s[1].stored());
    let tablet_reads =
        crate::lists::lists_in(&held, &s[2].personal(), &[s.key(0), s.key(1), s.key(2)]).unwrap();
    assert!(
        !filings_of(&tablet_reads).contains(&notes.id),
        "the tablet reads no list that files it"
    );
}

/// A channel made before its maker read the removal is not clean where it
/// is first held after it (rule 25, amended 13 November): the laptop makes
/// "notes" with `shared new` before it is shown the desktop's removal of
/// the tablet, so it writes no entry `made/`, and the card is in a list of
/// change 1, which the tablet reads. Once the laptop applies the removal,
/// "notes" is not clean there, and the desktop holds it not clean.
#[test]
fn a_channel_made_before_its_maker_read_the_removal_is_not_clean() {
    let mut s = bob(3);
    s.meet(&[0, 1, 2]);
    s.change(1, &[0, 1], &[2]);
    let now = s.now + 10;
    let notes = made_new(&s, 0, "notes", now);
    assert!(made_entries(&s, 0).is_empty(), "it knows of no removal");
    s.pass(1, 0);
    assert_eq!(s[0].number(), 2);
    assert!(is_not_clean(&s[0].conn, &notes.id).unwrap(), "rule 23");
    follows(&mut s, 0, 1, now);
    assert_eq!(row(&s, 1, &notes).state, State::Held);
    assert!(is_not_clean(&s[1].conn, &notes.id).unwrap());
}

/// An entry `made/` counts only where it names the change this device
/// follows (rule 25, amended 13 November): after the removal the laptop
/// files three channels with no `shared new`, and writes for each an entry
/// `made/` of its own in the personal channel of change 2: one naming a
/// change made apart with the same number, one naming change 1, as a copy
/// carried from it would, and one naming change 2. The desktop holds the
/// third alone clean.
#[test]
fn an_entry_made_counts_only_where_it_names_the_change_followed() {
    let mut s = bob(3);
    let before = followed(&s, 0);
    let now = the_desktop_removed_the_tablet(&mut s);
    let change = followed(&s, 0);
    let apart = ChangeLink {
        number: change.number,
        hash: [0xab; 16],
    };
    let laptop = crate::several::identity_of(0);
    let mut channels = Vec::new();
    for (seed, name, names) in [
        (21, "apart", &apart),
        (22, "copied", &before),
        (23, "named", &change),
    ] {
        let channel = holds(&s, 0, seed, name, now);
        writes_made(&s, 0, &laptop, &channel, names, now);
        channels.push(channel);
    }
    follows(&mut s, 0, 1, now);
    let conn = &s[1].conn;
    assert!(is_not_clean(conn, &channels[0].id).unwrap(), "made apart");
    assert!(is_not_clean(conn, &channels[1].id).unwrap(), "carried");
    assert!(!is_not_clean(conn, &channels[2].id).unwrap(), "named");
}

/// The entry `made/` ends at the next change, and a channel made before a
/// renewal is not clean where it is first held after it (rule 25, amended
/// 13 November, a cost it states): the laptop makes "notes" under change
/// 2; the desktop renews before it reads the laptop's list, and the laptop
/// carries its list into change 3, and not its entry `made/`. The desktop
/// holds "notes" not clean; the laptop, which made it, clean.
#[test]
fn a_channel_made_before_a_renewal_is_not_clean_where_first_held_after_it() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    let notes = made_new(&s, 0, "notes", now);
    assert_eq!(made_entries(&s, 0).len(), 1);
    s.change(1, &[0, 1], &[2]);
    s.pass(1, 0);
    assert_eq!(s[0].number(), 3, "the laptop follows the renewal");
    assert!(made_entries(&s, 0).is_empty(), "not carried");
    assert!(!is_not_clean(&s[0].conn, &notes.id).unwrap(), "made here");
    follows(&mut s, 0, 1, now);
    assert_eq!(row(&s, 1, &notes).state, State::Held);
    assert!(is_not_clean(&s[1].conn, &notes.id).unwrap());
}

/// An entry `made/` counts only where a device that counts there signed
/// it, as this device asks when it judges the channel, and not only as the
/// door asked when it stored it (rule 25, amended 13 November): after the
/// removal the laptop files three channels with no `shared new`, and the
/// desktop's store is given an entry `made/` naming change 2 for each, as
/// no door of this version stores one: signed by the tablet, which the
/// desktop knows to be removed; by a key that was never a device of
/// Bob's; and by the laptop. The desktop holds the third alone clean.
#[test]
fn an_entry_made_by_a_key_that_does_not_count_holds_nothing_clean() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    let change = followed(&s, 1);
    let (tablet, stranger, laptop) = (
        crate::several::identity_of(2),
        member(1),
        crate::several::identity_of(0),
    );
    let mut channels = Vec::new();
    for (seed, name) in [(21, "tablets"), (22, "strangers"), (23, "laptops")] {
        channels.push(holds(&s, 0, seed, name, now));
    }
    s.pass(0, 1);
    for (channel, by) in channels.iter().zip([&tablet, &stranger, &laptop]) {
        writes_made(&s, 1, by, channel, &change, now);
    }
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    out(&s, 1, now);
    let conn = &s[1].conn;
    assert!(is_not_clean(conn, &channels[0].id).unwrap(), "the tablet");
    assert!(is_not_clean(conn, &channels[1].id).unwrap(), "a stranger");
    assert!(!is_not_clean(conn, &channels[2].id).unwrap(), "the laptop");
}

/// Only a filing made counts, and a rename keeps how a channel came (rule
/// 25, amended 13 November): after the removal the laptop makes "notes"
/// and "drafts" with `shared new`, each with its entry `made/`, and then
/// files "notes" again as taken from a key, as an accept does, and renames
/// it; and files "drafts" as moved to from a channel that is not held. The
/// desktop first holds each under a filing that is not made, and neither
/// is clean there.
#[test]
fn a_channel_taken_or_moved_to_is_not_clean_and_a_rename_does_not_make_it_so() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    let notes = made_new(&s, 0, "notes", now);
    let drafts = made_new(&s, 0, "drafts", now);
    assert_eq!(made_entries(&s, 0).len(), 2);
    let notes_filed = sharing::filed(&s[0].conn)
        .unwrap()
        .into_iter()
        .find(|filing| filing.name == "notes")
        .unwrap();
    let taken = Filing {
        came: Came::Taken(member(1).public_key()),
        ..notes_filed
    };
    acts(&s, 0, Do::File(taken), now + 1);
    sharing::rename(&s[0].conn, &s[0].identity, "notes", "design", None, now + 2).unwrap();
    let drafts_filed = sharing::filed(&s[0].conn)
        .unwrap()
        .into_iter()
        .find(|filing| filing.name == "drafts")
        .unwrap();
    let moved = Filing {
        came: Came::Moved([0x5e; 32]),
        ..drafts_filed
    };
    acts(&s, 0, Do::File(moved), now + 3);
    follows(&mut s, 0, 1, now + 3);
    let conn = &s[1].conn;
    assert_eq!(row(&s, 1, &notes).name, "design");
    assert!(
        is_not_clean(conn, &notes.id).unwrap(),
        "taken, then renamed"
    );
    assert!(is_not_clean(conn, &drafts.id).unwrap(), "moved to");
}

/// A channel held clean by the test is marked not clean once the filing in
/// force of it is no longer one made, and stays so (rule 25, amended 13
/// November): the desktop holds "notes" clean; the laptop then files it as
/// taken, as a take by a device that had not read the removal would be,
/// and the desktop marks it once it reads that list. A filing made again
/// does not clear it: only a making anew does.
#[test]
fn a_channel_held_clean_is_marked_once_its_filing_is_no_longer_made() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    let notes = made_new(&s, 0, "notes", now);
    follows(&mut s, 0, 1, now);
    assert!(!is_not_clean(&s[1].conn, &notes.id).unwrap());
    let filed = sharing::filed(&s[0].conn).unwrap().remove(0);
    let taken = Filing {
        came: Came::Taken(member(1).public_key()),
        ..filed.clone()
    };
    acts(&s, 0, Do::File(taken), now + 1);
    follows(&mut s, 0, 1, now + 1);
    assert!(is_not_clean(&s[1].conn, &notes.id).unwrap(), "taken now");
    acts(&s, 0, Do::File(filed), now + 2);
    follows(&mut s, 0, 1, now + 2);
    assert!(is_not_clean(&s[1].conn, &notes.id).unwrap(), "for good");
}

/// Where the list comes before the entry `made/`, the mark set at first
/// holding is cleared at the next read of the lists (rule 25, amended 13
/// November): the desktop is given the laptop's list of "notes" alone, and
/// holds "notes" not clean; then the entry `made/`, and once it reads the
/// lists again it holds "notes" clean, and writes there.
#[test]
fn a_list_that_comes_before_its_entry_made_is_cleared_at_the_next_read() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    let notes = made_new(&s, 0, "notes", now);
    let personal = s[0].personal();
    let (made, rest): (Vec<_>, Vec<_>) = s[0]
        .stored()
        .into_iter()
        .partition(|entry| is_made(entry, &personal));
    assert_eq!(made.len(), 1);
    for entry in &rest {
        crate::shared::tests::given(&s, 1, entry, now);
    }
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    out(&s, 1, now);
    assert_eq!(row(&s, 1, &notes).state, State::Held);
    assert!(is_not_clean(&s[1].conn, &notes.id).unwrap(), "no entry yet");
    crate::shared::tests::given(&s, 1, &made[0], now + 1);
    crate::lists::follow(&s[1].conn, &s[1].identity, now + 1).unwrap();
    out(&s, 1, now + 1);
    assert!(!is_not_clean(&s[1].conn, &notes.id).unwrap(), "cleared");
    assert!(writes_there(&s[1].conn, &s[1].identity, &row(&s, 1, &notes)).unwrap());
}

/// A new removal ends it (rule 25, amended 13 November; rule 23): the
/// desktop first holds "notes" before the laptop's entry `made/` comes,
/// and "drafts" whole, clean. It then comes to know of a removal on
/// another branch, of a key that holds nothing of change 2, so its change
/// is still clear: both are marked, and once the entry `made/` of "notes"
/// comes and the lists are read again, neither is cleared.
#[test]
fn a_removal_known_after_first_holding_is_not_undone_by_an_entry_made() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    let notes = made_new(&s, 0, "notes", now);
    let drafts = made_new(&s, 0, "drafts", now);
    let personal = s[0].personal();
    let notes_made = crate::shared::made_name(&notes.id);
    let (late, rest): (Vec<_>, Vec<_>) = s[0].stored().into_iter().partition(|entry| {
        entry
            .open(&personal)
            .is_ok_and(|inside| inside.name == notes_made)
    });
    assert_eq!(late.len(), 1);
    for entry in &rest {
        crate::shared::tests::given(&s, 1, entry, now);
    }
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    out(&s, 1, now);
    let conn = &s[1].conn;
    assert!(is_not_clean(conn, &notes.id).unwrap());
    assert!(!is_not_clean(conn, &drafts.id).unwrap());

    let held = crate::person::held(conn).unwrap().unwrap();
    let mut apart = held.statement.statement.clone();
    apart.removed.push(member(9).public_key());
    crate::person::know_removed(conn, &apart, &s.key(1), now + 1, false).unwrap();
    assert!(crate::person::follows_a_clear_change(conn).unwrap());
    assert!(is_not_clean(conn, &drafts.id).unwrap(), "rule 23");
    crate::shared::tests::given(&s, 1, &late[0], now + 2);
    crate::lists::follow(conn, &s[1].identity, now + 2).unwrap();
    out(&s, 1, now + 2);
    assert!(is_not_clean(conn, &notes.id).unwrap(), "not cleared");
    assert!(is_not_clean(conn, &drafts.id).unwrap());
}

/// A device whose change stops being clear, where a key it knows to be
/// removed comes to hold its secret, marks every shared channel it holds
/// not clean, whether it is closed at the door or moves or closes after
/// (rules 3 and 25, amended 13 November): the desktop holds "notes" clean.
/// An entry that the tablet signed, which opens under the secret of change
/// 2, shows that the tablet holds that secret, and closes the desktop at
/// the door. Or the tablet is kept as a holder of change 2 with no close,
/// as a device of the version before left it, and the desktop is closed at
/// its next move. Either way "notes" is not clean.
#[test]
fn a_device_whose_change_stops_being_clear_marks_each_channel_it_holds() {
    for at_the_door in [true, false] {
        let mut s = bob(3);
        let now = the_desktop_removed_the_tablet(&mut s);
        let notes = made_new(&s, 0, "notes", now);
        follows(&mut s, 0, 1, now);
        let conn = &s[1].conn;
        assert!(!is_not_clean(conn, &notes.id).unwrap());
        let tablet = crate::several::identity_of(2);
        if at_the_door {
            let entry = crate::several::entry_by(
                &tablet,
                &s[1].personal(),
                next_under(None, 2).unwrap(),
                "name/late",
                crate::several::text("late"),
                &[],
            );
            crate::take::take(conn, &s[1].identity, &entry, now + 1).unwrap();
        } else {
            let change = followed(&s, 1);
            cordelia_storage::person::keep_holder(
                conn,
                change.number,
                &change.hash,
                &tablet.public_key(),
            )
            .unwrap();
            crate::person::move_to_a_clear_change(conn, &s[1].identity, now + 1).unwrap();
        }
        assert!(!crate::person::follows_a_clear_change(conn).unwrap());
        assert!(
            is_not_clean(conn, &notes.id).unwrap(),
            "at the door: {at_the_door}"
        );
    }
}

/// A device that does not stand applied under a clear change holds no
/// channel clean by the test (rule 25, amended 13 November): the desktop
/// is given the laptop's list of "notes" and its entry `made/`, and then
/// keeps the tablet as a holder of change 2, or is closed, before it reads
/// the lists. It holds "notes" not clean.
#[test]
fn a_device_not_clear_or_closed_holds_no_channel_made_clean() {
    for closed in [false, true] {
        let mut s = bob(3);
        let now = the_desktop_removed_the_tablet(&mut s);
        let notes = made_new(&s, 0, "notes", now);
        s.pass(0, 1);
        let conn = &s[1].conn;
        if closed {
            cordelia_storage::person::set_state(conn, cordelia_storage::person::State::Fork)
                .unwrap();
        } else {
            let change = followed(&s, 1);
            let tablet = crate::several::identity_of(2).public_key();
            cordelia_storage::person::keep_holder(conn, change.number, &change.hash, &tablet)
                .unwrap();
        }
        crate::lists::follow(conn, &s[1].identity, now).unwrap();
        out(&s, 1, now);
        assert_eq!(row(&s, 1, &notes).state, State::Held);
        assert!(is_not_clean(conn, &notes.id).unwrap(), "closed: {closed}");
    }
}

/// A device of the version before stores an entry `made/` and reads
/// nothing of it (rule 25, amended 13 November): the door, which reads the
/// personal channel as that version does, stores the laptop's entry
/// `made/` as no record, and the desktop takes every act of the laptop's
/// list, as the laptop holds them.
#[test]
fn the_door_stores_an_entry_made_as_no_record_and_every_act_is_taken() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    made_new(&s, 0, "notes", now);
    labels(&s, 0, &member(1).public_key(), Some("alice"), now);
    let personal = s[0].personal();
    let mut made = 0;
    for entry in s[0].stored() {
        let taken = crate::take::take(&s[1].conn, &s[1].identity, &entry, now).unwrap();
        if is_made(&entry, &personal) {
            made += 1;
            assert!(
                matches!(
                    taken,
                    crate::take::Taken::Own {
                        stored: cordelia_storage::entries::Outcome::Stored,
                        record: None,
                        came_to_count: 0,
                        came_to_add: 0,
                    }
                ),
                "{taken:?}"
            );
        }
    }
    assert_eq!(made, 1);
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    out(&s, 1, now);
    let acts = |n: usize| {
        let holds = crate::lists::holds(&s[n].conn).unwrap();
        let filings: Vec<_> = holds.filings.into_iter().map(|(act, _)| act).collect();
        let labels: Vec<_> = holds.labels.into_iter().map(|(act, _)| act).collect();
        (filings, labels)
    };
    assert_eq!(acts(1), acts(0));
    assert_eq!(acts(1).0.len(), 1);
    assert_eq!(acts(1).1.len(), 1);
}

/// The test of a channel made clears no mark of a recovery (rule 25,
/// amended 13 November; decision 2026-10-10 §3.5): the machine of a
/// recovery brings back "review", and holds it not clean, owed its making
/// anew. An entry `made/` of its own that names the recovery's change
/// does not clear it at the next read of the lists.
#[test]
fn the_test_of_a_channel_made_clears_no_mark_of_a_recovery() {
    let mut s = bob(2);
    let now = s.now + 10;
    let review = holds(&s, 1, 7, "review", now);
    let personal = s[1].personal();
    let handed = s[1].stored();
    let lists = crate::lists::lists_in(&handed, &personal, &[s.key(1)]).unwrap();
    s.change(0, &[0], &[1]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    let shown = crate::recover::Shown {
        gone: vec![(s.key(1), "laptop".into())],
        ..Default::default()
    };
    in_one(conn, || {
        crate::recover::shared_recovered(conn, &s[0].identity, &lists, &shown, now)
    })
    .unwrap();
    assert!(is_not_clean(conn, &review.id).unwrap());
    let identity = crate::several::identity_of(0);
    writes_made(&s, 0, &identity, &review, &followed(&s, 0), now);
    crate::lists::follow(conn, &s[0].identity, now + 1).unwrap();
    out(&s, 0, now + 1);
    assert!(is_not_clean(conn, &review.id).unwrap(), "owed");
    assert!(
        st(rows::not_clean_of(conn, &review.id))
            .unwrap()
            .unwrap()
            .owed
    );
}

/// The test is asked again only while the device follows the change it
/// first held the channel under (rule 25, amended 13 November): the
/// desktop first holds "notes" before the laptop's entry `made/` comes,
/// and then renews. An entry `made/` that names the renewal, put in its
/// store, does not clear the mark set under change 2.
#[test]
fn a_mark_set_under_one_change_is_not_asked_again_under_the_next() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    let notes = made_new(&s, 0, "notes", now);
    let personal = s[0].personal();
    for entry in s[0].stored() {
        if !is_made(&entry, &personal) {
            crate::shared::tests::given(&s, 1, &entry, now);
        }
    }
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    out(&s, 1, now);
    assert!(is_not_clean(&s[1].conn, &notes.id).unwrap());
    s.change(1, &[0, 1], &[2]);
    assert_eq!(s[1].number(), 3);
    let laptop = crate::several::identity_of(0);
    writes_made(&s, 1, &laptop, &notes, &followed(&s, 1), now + 1);
    crate::lists::follow(&s[1].conn, &s[1].identity, now + 1).unwrap();
    out(&s, 1, now + 1);
    assert!(is_not_clean(&s[1].conn, &notes.id).unwrap());
}

/// The removed key's act, copied and carried, is not clean where it is
/// first held after the removal (rule 25, amended 13 November): the tablet
/// files "thief", and the laptop takes its list and copies the act into
/// its own; the desktop takes the tablet's list too, before the removal,
/// and does not read the lists. The desktop removes the tablet, and the
/// laptop carries its copy into change 2, with an entry `made/` of its own
/// that names change 1, as a copy carried from there would. The desktop
/// first holds "thief" under the tablet's filing, and holds it not clean.
#[test]
fn the_removed_keys_act_copied_and_carried_is_not_clean() {
    let mut s = bob(3);
    let now = s.now + 10;
    s.meet(&[0, 1, 2]);
    let thief = holds(&s, 2, 31, "thief", now);
    s.pass(2, 0);
    crate::lists::follow(&s[0].conn, &s[0].identity, now).unwrap();
    out(&s, 0, now);
    s.pass(2, 1);
    // Taken past the removal's margin before it, so the act stays
    // (decision 2026-10-24 (removal), rule 6).
    s.now += cordelia_core::protocol::REMOVAL_TAKEN_MARGIN_SECS as i64 + 1;
    let before = followed(&s, 0);
    s.change(1, &[0, 1], &[2]);
    s.pass(1, 0);
    assert_eq!(s[0].number(), 2);
    let now = s.now + 10;
    let laptop = crate::several::identity_of(0);
    writes_made(&s, 0, &laptop, &thief, &before, now);
    follows(&mut s, 0, 1, now);
    let desktop = row(&s, 1, &thief);
    assert_eq!(
        desktop.state,
        State::Held,
        "the act stays, taken before its cut"
    );
    assert!(is_not_clean(&s[1].conn, &thief.id).unwrap());
}

/// A filing that is not made is not cleared when its entry `made/` comes
/// after it (rule 25, amended 13 November): the laptop makes "notes" with
/// `shared new`, and then files it as taken from a key. The desktop is
/// given the laptop's list first, and holds "notes" not clean; then the
/// entry `made/`, and the test asked again does not clear it.
#[test]
fn a_channel_taken_is_not_cleared_when_its_entry_made_comes_after() {
    let mut s = bob(3);
    let now = the_desktop_removed_the_tablet(&mut s);
    let notes = made_new(&s, 0, "notes", now);
    let filed = sharing::filed(&s[0].conn).unwrap().remove(0);
    let taken = Filing {
        came: Came::Taken(member(1).public_key()),
        ..filed
    };
    acts(&s, 0, Do::File(taken), now + 1);
    let personal = s[0].personal();
    let (made, rest): (Vec<_>, Vec<_>) = s[0]
        .stored()
        .into_iter()
        .partition(|entry| is_made(entry, &personal));
    for entry in &rest {
        crate::shared::tests::given(&s, 1, entry, now + 1);
    }
    crate::lists::follow(&s[1].conn, &s[1].identity, now + 1).unwrap();
    out(&s, 1, now + 1);
    assert!(is_not_clean(&s[1].conn, &notes.id).unwrap());
    crate::shared::tests::given(&s, 1, &made[0], now + 2);
    crate::lists::follow(&s[1].conn, &s[1].identity, now + 2).unwrap();
    out(&s, 1, now + 2);
    assert!(is_not_clean(&s[1].conn, &notes.id).unwrap(), "taken");
}

// ── Rule 25, amended 13 November: the fix round after its review ────

/// Bob's laptop (0), desktop (1), tablet (2) and phone (3) meet; the
/// desktop removes the tablet (change 2), and the laptop follows that
/// change. The phone is off, on change 1. The time after.
fn the_desktop_removed_the_tablet_with_the_phone_off(s: &mut Several) -> i64 {
    s.meet(&[0, 1, 2, 3]);
    s.change(1, &[0, 1, 3], &[2]);
    s.pass(1, 0);
    assert_eq!(s[0].number(), 2, "the laptop follows the removal");
    assert_eq!(s[3].number(), 1, "the phone is off");
    s.now + 10
}

/// The phone, on change 1, takes the channel the laptop filed as `name`
/// from a share at `now`, so its card is in a list the tablet reads; it
/// then applies the removal, and carries its list into change 2.
fn the_phone_takes_before_it_reads_the_removal(s: &mut Several, name: &str, now: i64) {
    let filed = sharing::filed(&s[0].conn)
        .unwrap()
        .into_iter()
        .find(|filing| filing.name == name)
        .unwrap();
    let channel = filed.channel;
    let taken = Filing {
        came: Came::Taken(member(1).public_key()),
        ..filed
    };
    acts(s, 3, Do::File(taken), now);
    let tablet_reads =
        crate::lists::lists_in(&s[3].stored(), &s[2].personal(), &[s.key(3)]).unwrap();
    assert!(
        filings_of(&tablet_reads).contains(&channel),
        "the window: the tablet reads the phone's list"
    );
    s.pass(1, 3);
    assert_eq!(s[3].number(), 2, "the phone applies the removal");
}

/// The channels that the filings of `lists` name.
fn filings_of(lists: &[([u8; 32], cordelia_crypto::acts::SharedList)]) -> Vec<[u8; 32]> {
    lists
        .iter()
        .flat_map(|(_, list)| crate::lists::acts_of(list))
        .filter_map(|act| match act {
            crate::lists::AnyAct::Filing(filing) => Some(filing.item.channel),
            _ => None,
        })
        .collect()
}

/// A mark set where the filing in force is not one made is kept, though a
/// newer filing made comes after it (rule 25, amended 13 November, as its
/// review found): the laptop makes "notes" after the removal; the phone,
/// which has not read it, takes "notes" from a share, and its card is in a
/// list the tablet reads. The phone applies the removal and carries its
/// list, and the desktop first holds "notes" under the phone's filing, and
/// marks it. The laptop, which has not read the phone's list, renames
/// "notes": a newer filing made, with its entry `made/`. The desktop keeps
/// the mark, as a device that first held "notes" clean and then saw the
/// take does. So it does where it first held "notes" under the laptop's
/// filing, before its entry `made/` came, and then read the take.
#[test]
fn a_mark_set_under_a_take_is_kept_though_a_filing_made_comes_after() {
    for made_first in [false, true] {
        let mut s = bob(4);
        let now = the_desktop_removed_the_tablet_with_the_phone_off(&mut s);
        let notes = made_new(&s, 0, "notes", now);
        if made_first {
            let personal = s[0].personal();
            for entry in s[0].stored() {
                if !is_made(&entry, &personal) {
                    crate::shared::tests::given(&s, 1, &entry, now);
                }
            }
            crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
            out(&s, 1, now);
            assert_eq!(row(&s, 1, &notes).state, State::Held);
            assert!(is_not_clean(&s[1].conn, &notes.id).unwrap(), "no entry");
        }
        the_phone_takes_before_it_reads_the_removal(&mut s, "notes", now + 1);
        follows(&mut s, 3, 1, now + 1);
        assert_eq!(row(&s, 1, &notes).state, State::Held);
        assert!(is_not_clean(&s[1].conn, &notes.id).unwrap(), "taken");
        sharing::rename(&s[0].conn, &s[0].identity, "notes", "design", None, now + 2).unwrap();
        follows(&mut s, 0, 1, now + 2);
        let desktop = row(&s, 1, &notes);
        assert_eq!(desktop.name, "design", "the filing made is in force");
        assert!(
            is_not_clean(&s[1].conn, &notes.id).unwrap(),
            "kept; made first: {made_first}"
        );
        assert!(!writes_there(&s[1].conn, &s[1].identity, &desktop).unwrap());
    }
}

/// The maker too marks a channel it made once the filing in force of it is
/// no longer one made (rule 25, amended 13 November, as its review found):
/// the laptop makes "notes" after the removal, and holds it clean at its
/// next read of the lists. The phone, which has not read the removal,
/// takes "notes", and carries its list into change 2 once it applies the
/// removal. The laptop reads that list, marks "notes" not clean, and
/// writes nothing there.
#[test]
fn the_maker_marks_a_channel_it_made_once_its_filing_is_no_longer_made() {
    let mut s = bob(4);
    let now = the_desktop_removed_the_tablet_with_the_phone_off(&mut s);
    let notes = made_new(&s, 0, "notes", now);
    crate::lists::follow(&s[0].conn, &s[0].identity, now).unwrap();
    out(&s, 0, now);
    assert!(!is_not_clean(&s[0].conn, &notes.id).unwrap(), "made here");
    the_phone_takes_before_it_reads_the_removal(&mut s, "notes", now + 1);
    follows(&mut s, 3, 0, now + 1);
    let laptop = row(&s, 0, &notes);
    assert_eq!(laptop.state, State::Held);
    assert!(is_not_clean(&s[0].conn, &notes.id).unwrap(), "taken");
    assert!(!writes_there(&s[0].conn, &s[0].identity, &laptop).unwrap());
}

/// An act of the removed key's taken inside the removal's margin counts
/// for nothing, and the channel it filed, held later by a rename from a
/// device that took the act earlier, is not clean (rule 25, amended 13
/// November; rule 6): the tablet files "thief". The laptop takes its list
/// and copies the act; the desktop takes it inside the ten minutes before
/// the removal, which then cuts it there. The desktop does not hold
/// "thief" until the laptop renames it, and then holds it not clean.
#[test]
fn an_act_inside_the_margin_held_later_by_a_rename_is_not_clean() {
    let mut s = bob(3);
    let now = s.now + 10;
    s.meet(&[0, 1, 2]);
    let thief = holds(&s, 2, 31, "thief", now);
    s.pass(2, 0);
    crate::lists::follow(&s[0].conn, &s[0].identity, now).unwrap();
    out(&s, 0, now);
    s.now += cordelia_core::protocol::REMOVAL_TAKEN_MARGIN_SECS as i64 + 1;
    s.pass(2, 1);
    s.change(1, &[0, 1], &[2]);
    s.pass(1, 0);
    assert_eq!(s[0].number(), 2);
    let now = s.now + 10;
    assert_eq!(
        row(&s, 0, &thief).state,
        State::Held,
        "taken before its cut"
    );
    follows(&mut s, 0, 1, now);
    assert!(
        kept::channel(&s[1].conn, &thief.id)
            .unwrap()
            .is_none_or(|row| row.state != State::Held),
        "cut on the desktop"
    );
    sharing::rename(&s[0].conn, &s[0].identity, "thief", "loot", None, now + 1).unwrap();
    follows(&mut s, 0, 1, now + 1);
    let desktop = row(&s, 1, &thief);
    assert_eq!(desktop.state, State::Held, "held by the rename");
    assert!(is_not_clean(&s[1].conn, &thief.id).unwrap());
    assert!(!writes_there(&s[1].conn, &s[1].identity, &desktop).unwrap());
}
