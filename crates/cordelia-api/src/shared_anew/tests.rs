//! Tests of making a shared channel anew, moving, a removal and a recovery
//! (decision 2026-10-10 §3.5, §7; decision 2026-10-24, rules 23 to 26),
//! in-process.

use super::*;
use crate::lists::tests::filing;
use crate::several::Several;
use crate::shared::Read;
use crate::shared::tests::{
    FULL, Shared, acts, anew, anew_of, bob, fill_to, holds, member, out, row, stores,
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
fn written_by(s: &Several, n: usize, channel: &Shared, members: &[&NodeIdentity], now: i64) {
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
    // there.
    let second = holds(&s, 0, 10, "second", now);
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
    assert_eq!(listing.own_devices, vec![s.key(0), s.key(1)]);
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
/// on the device that makes it, with no question, sealed to every key of
/// its table but the removed one, and its subscription moved with its
/// start; the old channel's entries stay until its offer is at each relay
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
    // `cordelia devices` names it.
    let seen = crate::look::look(conn, identity, &Default::default(), now).unwrap();
    let line = not_clean_line("review");
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
    let (alice, carol) = (member(1), member(2));
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
            &[alice.public_key(), s.key(0)],
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
    // Bob moves: the new channel lists Alice as not moved yet until she
    // writes there.
    let plan = move_plan(conn, identity, &relays(), "review", None, None, now).unwrap();
    let said = make_move(conn, identity, &plan.what, now).unwrap();
    assert!(
        said[0].starts_with("Moved \"review\" to channel "),
        "{said:?}"
    );
    let alice_form = sender_form(conn, &held, &s.key(0), &alice.public_key()).unwrap();
    assert!(
        said.contains(&format!("  not moved yet: {alice_form}")),
        "{said:?}"
    );
    let new_channel = plan.what.to.channel;
    assert_eq!(
        not_moved_yet(conn, &s.key(0), &new_channel).unwrap(),
        vec![alice.public_key()]
    );
    let new = Shared {
        secret: plan.what.to.card.secret().unwrap(),
        id: new_channel,
    };
    stores(&s, 0, &anew(&alice, &new, 1), now);
    assert!(
        not_moved_yet(conn, &s.key(0), &new_channel)
            .unwrap()
            .is_empty()
    );
}

// ── The fix round of slice 8 ─────────────────────────────────────────

/// The channel that device `n` files as `name` now, as a `Shared`.
fn filed_as(s: &Several, n: usize, name: &str) -> Shared {
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
            .any(|notice| notice.says == unreached_line("review")),
        "{:?}",
        seen.notices
    );
    assert!(unreached_line("review").ends_with(
        "make it anew with cordelia shared anew review on a device of yours that reaches its \
         relays"
    ));
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
/// property 7): with a member's 100 keys and 3 rows let go, the laptop's
/// removal of the tablet leaves out 38 keys past the 64 that stay, and 3
/// no longer known; `remove-device` says so at its end.
#[test]
fn a_removal_says_how_many_keys_the_cap_and_the_rows_let_go_left_out() {
    let mut s = bob(3);
    let (channel, _) = removed_the_tablet(&mut s, 0);
    let now = s.now + 20;
    let members: Vec<NodeIdentity> = (0..99).map(|k| member(1_000 + k)).collect();
    let refs: Vec<&NodeIdentity> = members.iter().collect();
    written_by(&s, 0, &channel, &refs, now);
    let conn = &s[0].conn;
    conn.execute(
        "UPDATE shared_channels SET let_go = 3 WHERE channel = ?1",
        [&channel.id[..]],
    )
    .unwrap();
    let said = anew_at_removal(conn, &s[0].identity, &relays(), now).unwrap();
    let besides = "Left out besides: 38 keys past the 64 that stay, and up to 3 keys no longer \
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
    let line = not_clean_line("review");
    let named = |s: &Several| {
        crate::look::look(&s[1].conn, &s[1].identity, &Default::default(), now)
            .unwrap()
            .notices
            .into_iter()
            .find(|notice| notice.says == line)
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
        [listing.own_devices, listing.asked].concat()
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
/// clean (the review of #277, high 1; decision 2026-10-24, rule 23): the
/// desktop removes the tablet; before the laptop hears of it, the laptop
/// files "notes" under the change before, which the tablet reads and
/// holds; the laptop applies the removal, and the desktop then reads the
/// laptop's list. The desktop holds "notes" not clean, and sends nothing
/// there. A channel the desktop files itself is clean, and so is "notes"
/// once the laptop makes it anew.
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
    s.pass(0, 1);
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    out(&s, 1, now);
    let desktop = row(&s, 1, &channel);
    assert_eq!(desktop.state, State::Held);
    assert!(is_not_clean(&s[1].conn, &channel.id).unwrap(), "rule 23");
    assert!(!writes_there(&s[1].conn, &s[1].identity, &desktop).unwrap());

    // A channel the desktop files itself, knowing, is clean.
    let own = holds(&s, 1, 11, "own", now);
    assert!(!is_not_clean(&s[1].conn, &own.id).unwrap());

    // The laptop makes "notes" anew; the desktop follows, and the new
    // channel is clean.
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let listed = asked_of(conn, identity, "notes", now);
    let (_, plan) = anew_plan(
        conn,
        identity,
        &relays(),
        "notes",
        None,
        &[],
        Some((&[], &listed)),
        now,
    )
    .unwrap();
    make_anew(conn, identity, &relays(), &plan.unwrap().what, now).unwrap();
    let new = filed_as(&s, 0, "notes");
    s.pass(0, 1);
    crate::lists::follow(&s[1].conn, &s[1].identity, now).unwrap();
    out(&s, 1, now);
    assert_eq!(row(&s, 1, &new).state, State::Held);
    assert!(!is_not_clean(&s[1].conn, &new.id).unwrap());
    assert!(
        !is_not_clean(&s[1].conn, &channel.id).unwrap(),
        "moved from"
    );
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
