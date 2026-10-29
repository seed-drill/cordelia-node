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
            .contains(&"  no longer known on this device, so left out: 3".to_string())
    );
    assert_eq!(listing.lines.last().unwrap(), LABEL_FIRST);

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
        Some(&too_many),
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
        Some(&keep),
        now,
    )
    .unwrap();
    let plan = plan.unwrap();
    assert!(
        plan.asks
            .ends_with("3 keys stay, your own devices among them, and 104 are left out."),
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

    s.change(0, &[0, 1], &[2]);
    let now = s.now + 20;
    let conn = &s[0].conn;
    assert!(is_not_clean(conn, &channel.id).unwrap(), "rule 23");
    let said = anew_at_removal(conn, &s[0].identity, now).unwrap();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].starts_with("\"review\" is made anew without the device removed"));
    assert!(!is_not_clean(conn, &channel.id).unwrap());
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
/// names the channel in `cordelia devices`; `shared anew` there goes
/// through and ends both.
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
    // `cordelia devices` names it.
    let seen = crate::look::look(conn, identity, &Default::default(), now).unwrap();
    let line = not_clean_line("review");
    assert!(
        seen.notices.iter().any(|notice| notice.says == line),
        "{:?}",
        seen.notices
    );
    // `shared anew` goes through, and ends both.
    let (_, plan) = anew_plan(
        conn,
        identity,
        &relays(),
        "review",
        None,
        &[],
        Some(&[]),
        now,
    )
    .unwrap();
    make_anew(conn, identity, &relays(), &plan.unwrap().what, now).unwrap();
    assert!(!is_not_clean(conn, &channel.id).unwrap());
    let seen = crate::look::look(conn, identity, &Default::default(), now).unwrap();
    assert!(!seen.notices.iter().any(|notice| notice.says == line));
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
                && line.contains("without 1 keys. You have not moved")),
        "{said:?}"
    );
    // A stay ends it here.
    let plan = stay_plan(conn, identity, "review", None).unwrap().unwrap();
    assert!(
        plan.asks
            .contains("without 1 keys. Your devices send nothing more")
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
