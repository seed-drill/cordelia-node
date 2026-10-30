//! The tests of the person's lists (decision 2026-10-10 §3.4, §13 under
//! properties 9, 25 and 26, and §20, item 10).
//!
//! The units work the lists out with [`compute`], which reads only the
//! lists, the makers and, for the removal's cut, when each act was taken;
//! the in-process tests run devices of one person with [`Several`], each
//! with its own database, handed what the others hold.

use super::*;
use crate::several::Several;
use crate::take::take;
use cordelia_crypto::acts::Came;
use cordelia_crypto::share::{Card, Relays};
use cordelia_storage::person::{self as held_rows, Kept as KeptEntry};

const DAY: i64 = 24 * 60 * 60;

// ── Items, acts and makers, for the units ────────────────────────────────

/// A filing of the channel of the card made from `seed`, under `name`.
pub(crate) fn filing(seed: u8, name: &str) -> Filing {
    let mut bytes = vec![seed; 32];
    bytes.extend_from_slice(&Relays::new(&[[3; 32]]).unwrap().to_bytes());
    let card = Card::from_bytes(&bytes).unwrap();
    Filing {
        channel: card.channel_id().unwrap(),
        card,
        name: name.into(),
        came: Came::Made,
    }
}

/// A filing as [`filing`] makes it, of a card at the relay of `relay`.
fn filing_at(seed: u8, name: &str, relay: [u8; 32]) -> Filing {
    let mut bytes = vec![seed; 32];
    bytes.extend_from_slice(&Relays::new(&[relay]).unwrap().to_bytes());
    let card = Card::from_bytes(&bytes).unwrap();
    Filing {
        channel: card.channel_id().unwrap(),
        card,
        name: name.into(),
        came: Came::Made,
    }
}

/// The ID of the channel of the card made from `seed`.
fn channel(seed: u8) -> [u8; 32] {
    filing(seed, "x").channel
}

fn subscription(seed: u8, agent: &str, subscribed: bool) -> Subscription {
    Subscription {
        channel: channel(seed),
        agent: agent.into(),
        subscribed,
    }
}

fn label(key: u8, label: Option<&str>) -> Label {
    Label {
        key: [key; 32],
        label: label.map(str::to_string),
    }
}

/// The device of `seed`.
fn device(seed: u8) -> NodeIdentity {
    NodeIdentity::from_seed([seed; 32]).unwrap()
}

/// An act on an item, by `by`, at `time` with `count`.
trait Made {
    fn by(self, by: &NodeIdentity, time: u64, count: u64) -> AnyAct;
}

impl Made for Filing {
    fn by(self, by: &NodeIdentity, time: u64, count: u64) -> AnyAct {
        AnyAct::Filing(Act::make(self, time, count, by, is_a_name).unwrap())
    }
}

impl Made for Dropped {
    fn by(self, by: &NodeIdentity, time: u64, count: u64) -> AnyAct {
        AnyAct::Drop(Act::make(self, time, count, by, is_a_name).unwrap())
    }
}

impl Made for Subscription {
    fn by(self, by: &NodeIdentity, time: u64, count: u64) -> AnyAct {
        AnyAct::Subscription(Act::make(self, time, count, by, is_a_name).unwrap())
    }
}

impl Made for Label {
    fn by(self, by: &NodeIdentity, time: u64, count: u64) -> AnyAct {
        AnyAct::Label(Act::make(self, time, count, by, is_a_name).unwrap())
    }
}

fn dropped(seed: u8) -> Dropped {
    Dropped {
        channel: channel(seed),
    }
}

/// Subscribed or not, the agent `a` to the channel of `seed`, by `by` at
/// `time`.
fn sub(seed: u8, on: bool, by: &NodeIdentity, time: u64) -> AnyAct {
    subscription(seed, "a", on).by(by, time, 0)
}

/// The makers where `counting` count and `removed` are removed by the
/// statement alone.
fn makers(counting: &[&NodeIdentity], removed: &[&NodeIdentity]) -> Makers {
    let counting: Vec<[u8; 32]> = counting.iter().map(|d| d.public_key()).collect();
    let removed: Vec<[u8; 32]> = removed.iter().map(|d| d.public_key()).collect();
    Makers::new(
        Counting::of_devices(&counting),
        ByTheStatement::of(&removed),
    )
}

/// The lists, each `acts` written by `writer`.
fn lists(of: &[(&NodeIdentity, Vec<AnyAct>)]) -> Vec<([u8; 32], SharedList)> {
    of.iter()
        .map(|(writer, acts)| (writer.public_key(), list_of(acts.clone())))
        .collect()
}

/// What `of` comes to, under `makers`, within `bounds`.
fn work(of: &[([u8; 32], SharedList)], makers: &Makers, bounds: Bounds) -> Computed {
    compute(of, makers, &Takings::default(), bounds)
}

/// The acts written, in force or undoes, by their bytes.
fn written(computed: &Computed) -> BTreeSet<Vec<u8>> {
    computed.written.iter().map(AnyAct::written).collect()
}

/// The acts a bound left out, by their bytes.
fn past(computed: &Computed) -> BTreeSet<Vec<u8>> {
    computed.past_bound.iter().map(AnyAct::written).collect()
}

/// Whether `act`'s item is in force.
fn in_force_of(computed: &Computed, act: &AnyAct) -> bool {
    computed.in_force(&act.key())
}

/// The newest valid act on `act`'s item, by its bytes.
fn newest_of(computed: &Computed, act: &AnyAct) -> Option<Vec<u8>> {
    computed.newest(&act.key()).map(AnyAct::written)
}

/// Each device of `devices`, reading every list, writes what it works out
/// as its own list, round after round, until no list changes. Returns the
/// rounds it took; asserts that the acts across the lists only grew
/// fewer.
fn settle(
    lists: &mut Vec<([u8; 32], SharedList)>,
    devices: &[[u8; 32]],
    makers: &Makers,
    bounds: Bounds,
) -> usize {
    let carried = |lists: &Vec<([u8; 32], SharedList)>| -> BTreeSet<Vec<u8>> {
        lists
            .iter()
            .flat_map(|(_, list)| acts_of(list))
            .map(|act| act.written())
            .collect()
    };
    for round in 0..64 {
        let before = carried(lists);
        let mut changed = false;
        for device in devices {
            let computed = work(lists, makers, bounds);
            let new = list_of(computed.written);
            match lists.iter_mut().find(|(writer, _)| writer == device) {
                Some((_, list)) if *list == new => {}
                Some((_, list)) => {
                    *list = new;
                    changed = true;
                }
                None => {
                    lists.push((*device, new));
                    changed = true;
                }
            }
        }
        let after = carried(lists);
        assert!(
            after.is_subset(&before),
            "a list written holds only acts the lists carried"
        );
        if !changed {
            return round;
        }
    }
    panic!("the rounds did not end");
}

/// A small generator of numbers, the same on every run.
struct Numbers(u64);

impl Numbers {
    fn next(&mut self, below: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % below
    }
}

/// Every order of `items`.
fn orders<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut all = Vec::new();
    for at in 0..items.len() {
        let mut rest = items.to_vec();
        let first = rest.remove(at);
        for mut order in orders(&rest) {
            order.insert(0, first.clone());
            all.push(order);
        }
    }
    all
}

// ── Property 26: the same lists, the same items ──────────────────────────

/// Over histories made at random, with valid and passed-over acts on
/// every part, at and below the bound, undoes kept for something and of
/// nothing, a device that counts and has no list, a removed key and a key
/// never of the person's, and acts whose signatures fail (decision
/// 2026-10-10 property 26, §3.4): two devices that read the same lists in
/// every order, at different times and with different histories of what
/// they took, hold the same items in force, write the same list and
/// refuse the same acts; and once each holds the other's latest list, the
/// rounds that follow end, the acts across the lists only growing fewer,
/// and at their end every device holds the same.
#[test]
fn the_items_in_force_are_a_function_of_the_lists() {
    let (a, b, c, d) = (device(1), device(2), device(3), device(4));
    let (removed, stranger) = (device(5), device(6));
    let makers = makers(&[&a, &b, &c, &d], &[&removed]);
    let writers = [&a, &b, &c];
    let all = [&a, &b, &c, &d, &removed, &stranger];
    let mut numbers = Numbers(26);
    for history in 0..60 {
        // The acts of this history.
        let mut acts: Vec<AnyAct> = Vec::new();
        for _ in 0..40 {
            let by = all[numbers.next(all.len() as u64) as usize];
            let time = if numbers.next(10) == 0 {
                SHARED_ACT_TIME_MAX
            } else {
                1 + numbers.next(60)
            };
            let count = if time == SHARED_ACT_TIME_MAX {
                numbers.next(4)
            } else {
                0
            };
            let on = numbers.next(3) != 0;
            let seed = 1 + numbers.next(6) as u8;
            let mut act = match numbers.next(4) {
                0 => filing(seed, "c").by(by, time, count),
                1 => dropped(seed).by(by, time, count),
                2 => subscription(seed, if seed.is_multiple_of(2) { "a" } else { "b" }, on)
                    .by(by, time, count),
                _ => label(seed, on.then_some("k")).by(by, time, count),
            };
            if numbers.next(20) == 0 {
                // A signature that does not hold.
                if let AnyAct::Label(a) = &mut act {
                    a.signature = [7; 64];
                }
                if let AnyAct::Drop(a) = &mut act {
                    a.time += 1;
                }
            }
            acts.push(act);
        }
        // Each writer's list: one act on each item, its own first, then
        // copies at random.
        let mut of: Vec<([u8; 32], SharedList)> = Vec::new();
        for writer in writers {
            let mut chosen: BTreeMap<Key, AnyAct> = BTreeMap::new();
            for act in &acts {
                let own = act.maker() == writer.public_key();
                if (own || numbers.next(3) == 0) && !chosen.contains_key(&act.key()) {
                    chosen.insert(act.key(), act.clone());
                }
            }
            of.push((writer.public_key(), list_of(chosen.into_values())));
        }
        for bounds in [Bounds::of(2, 3, 2, 3), Bounds::OF_A_LIST] {
            let first = work(&of, &makers, bounds);
            // Two histories of what was taken: the cut reads them, and no
            // rule of order does.
            let mut earlier = Takings::now(Taken {
                generation: 1,
                taken_at: 10,
            });
            // One history took every other act long before.
            for act in acts.iter().step_by(2) {
                earlier.record(
                    act.signature(),
                    Taken {
                        generation: 1,
                        taken_at: 1,
                    },
                );
            }
            let later = Takings::now(Taken {
                generation: 2,
                taken_at: 1_000_000,
            });
            for order in orders(&of) {
                for takings in [&earlier, &later] {
                    let other = compute(&order, &makers, takings, bounds);
                    assert_eq!(written(&other), written(&first), "history {history}");
                    assert_eq!(past(&other), past(&first), "history {history}");
                    assert_eq!(other.passed_over, first.passed_over, "history {history}");
                    // The same refusals, and the same acts made.
                    for what in [
                        Do::File(filing(1, "c")),
                        Do::Drop(channel(2)),
                        Do::Subscribe(subscription(3, "b", true)),
                        Do::Subscribe(subscription(4, "a", false)),
                        Do::Label(label(5, Some("k"))),
                        Do::Label(label(6, None)),
                    ] {
                        assert_eq!(
                            decide(&other, &makers, &a, &what, 5),
                            decide(&first, &makers, &a, &what, 5),
                            "history {history}: {what:?}"
                        );
                    }
                }
            }
            // Rounds, every device reading every list: they end, and all
            // hold the same.
            let mut settling = of.clone();
            let devices: Vec<[u8; 32]> = writers.iter().map(|w| w.public_key()).collect();
            settle(&mut settling, &devices, &makers, bounds);
            let settled = work(&settling, &makers, bounds);
            for (writer, list) in &settling {
                assert_eq!(
                    list_of(settled.written.clone()),
                    *list,
                    "history {history}: {writer:?}"
                );
            }
        }
    }
}

// ── Which acts are valid, and from which list ────────────────────────────

/// The smallest case (decision 2026-10-10 §13, property 25), with a bound
/// of 3 subscriptions: P subscribes `c` at 1, unsubscribes it at 5, and
/// subscribes `a` at 6; T, which counts, writes a copy of P's subscribe of
/// `c`, and `t1` at 100 and `t2` at 101; then the copy, an unsubscribe of
/// `t1` at 102 and of `t2` at 103; P writes its list again. `c` is not in
/// force in any computation, before or after T's removal, since P's own
/// list carries the unsubscribe and the copy is not taken. The same for a
/// label `alice` on a key that the person had unlabelled.
#[test]
fn a_copy_brings_back_nothing_its_maker_undid() {
    let (p, t) = (device(1), device(2));
    let bounds = Bounds::of(16, 64, 3, 3);
    let on_c = sub(3, true, &p, 1);
    let off_c = sub(3, false, &p, 5);
    let on_a = sub(1, true, &p, 6);
    let alice = label(9, Some("alice")).by(&p, 1, 0);
    let unlabelled = label(9, None).by(&p, 5, 0);
    let labelled_a = label(1, Some("a")).by(&p, 6, 0);
    let p_list = vec![
        off_c.clone(),
        on_a.clone(),
        unlabelled.clone(),
        labelled_a.clone(),
    ];
    // T writes copies of P's subscribe of `c` and label of `alice`, and
    // `t1` at 100 and `t2` at 101; then the copies, and undoes of `t1` at
    // 102 and of `t2` at 103.
    let t_first = vec![
        on_c.clone(),
        sub(10, true, &t, 100),
        sub(11, true, &t, 101),
        alice.clone(),
        label(10, Some("t")).by(&t, 100, 0),
        label(11, Some("t")).by(&t, 101, 0),
    ];
    let t_then = vec![
        on_c.clone(),
        sub(10, false, &t, 102),
        sub(11, false, &t, 103),
        alice.clone(),
        label(10, None).by(&t, 102, 0),
        label(11, None).by(&t, 103, 0),
    ];
    let not_back = |computed: &Computed, when: &str| {
        assert!(!in_force_of(computed, &on_c), "{when}");
        assert!(!in_force_of(computed, &alice), "{when}");
        assert!(in_force_of(computed, &on_a), "{when}");
    };
    let counting = makers(&[&p, &t], &[]);
    let removed = makers(&[&p], &[&t]);

    // The first computation: P's undoes are of nothing below them, since
    // the copies are not taken, and fall past the bound.
    let mut of = lists(&[(&p, p_list.clone()), (&t, t_first)]);
    let first = work(&of, &counting, bounds);
    not_back(&first, "first");
    assert_eq!(newest_of(&first, &on_c), Some(off_c.written()));
    assert_eq!(newest_of(&first, &alice), Some(unlabelled.written()));
    // P writes its list again: it no longer carries its undoes.
    of[0].1 = list_of(first.written.clone());
    // T writes the copies and its own undoes.
    of[1].1 = list_of(t_then);
    for (makers, when) in [(&counting, "then"), (&removed, "after T's removal")] {
        let computed = work(&of, makers, bounds);
        not_back(&computed, when);
        // And in every round after, each writing what it worked out.
        let mut settling = of.clone();
        settle(
            &mut settling,
            &[p.public_key(), t.public_key()],
            makers,
            bounds,
        );
        not_back(&work(&settling, makers, bounds), when);
    }
}

/// What a copy still brings back (decision 2026-10-10 §3.4, the costs):
/// an act of a device removed before, in force as that device's; an act
/// of a device that has not applied the latest statement, taken from a
/// copy until that device has a list, then not; and, where a relay
/// withholds P's list from one reader, T's copy on that reader alone until
/// P's list arrives.
#[test]
fn what_a_copy_still_brings_back() {
    let (p, t, gone, away) = (device(1), device(2), device(3), device(4));
    let bounds = Bounds::OF_A_LIST;

    // A device removed before: its filing, copied in T's list.
    let theirs = filing(1, "theirs").by(&gone, 10, 0);
    let makers_now = makers(&[&p, &t], &[&gone]);
    let computed = work(
        &lists(&[(&p, vec![]), (&t, vec![theirs.clone()])]),
        &makers_now,
        bounds,
    );
    assert!(in_force_of(&computed, &theirs));
    assert_eq!(makers_now.maker(&gone.public_key()), Some(Maker::Removed));

    // A device that counts and has no list: its subscription, in T's
    // copy, is taken; once it writes its list, without it, it is not.
    let makers_now = makers(&[&p, &t, &away], &[]);
    let old = sub(2, true, &away, 10);
    let of = lists(&[(&p, vec![]), (&t, vec![old.clone()])]);
    assert!(in_force_of(&work(&of, &makers_now, bounds), &old));
    let mut of = of;
    of.push((away.public_key(), SharedList::default()));
    assert!(!in_force_of(&work(&of, &makers_now, bounds), &old));
    assert!(work(&of, &makers_now, bounds).newest(&old.key()).is_none());

    // A relay withholds P's list from one reader: that reader takes T's
    // copy of P's filing, which P has since dropped; the other does not.
    let makers_now = makers(&[&p, &t], &[]);
    let filed = filing(3, "review").by(&p, 10, 0);
    let drop = dropped(3).by(&p, 11, 0);
    let without_p = lists(&[(&t, vec![filed.clone()])]);
    let with_p = lists(&[(&p, vec![drop.clone()]), (&t, vec![filed.clone()])]);
    assert!(in_force_of(&work(&without_p, &makers_now, bounds), &filed));
    assert!(!in_force_of(&work(&with_p, &makers_now, bounds), &filed));
}

/// An act of a device that counts and has a list is taken from that list
/// and from no copy; with no list of that device among those read, it is
/// taken from a copy; an act of a removed device is taken from any list;
/// two devices that read the same lists in every order take the same
/// (decision 2026-10-10 §3.4, "Which acts are valid").
#[test]
fn an_act_is_taken_from_its_makers_own_list() {
    let (p, q, t) = (device(1), device(2), device(3));
    let bounds = Bounds::OF_A_LIST;
    let old = label(4, Some("old")).by(&p, 10, 0);
    let new = label(5, Some("new")).by(&p, 20, 0);
    // P's own list carries `new`; T's copy carries `old` on another item.
    let of = lists(&[(&p, vec![new.clone()]), (&t, vec![old.clone()])]);
    let counting = makers(&[&p, &t], &[]);
    let computed = work(&of, &counting, bounds);
    assert!(in_force_of(&computed, &new));
    assert!(!in_force_of(&computed, &old));
    assert!(computed.newest(&old.key()).is_none());
    // With no list of P's read, from the copy.
    let no_p = lists(&[(&t, vec![old.clone()])]);
    assert!(in_force_of(&work(&no_p, &counting, bounds), &old));
    // P's list there and empty: nothing from the copy.
    let empty_p = lists(&[(&p, vec![]), (&t, vec![old.clone()])]);
    assert!(!in_force_of(&work(&empty_p, &counting, bounds), &old));
    // P removed: from any list.
    let removed = makers(&[&t], &[&p]);
    let computed = work(&of, &removed, bounds);
    assert!(in_force_of(&computed, &old));
    assert!(in_force_of(&computed, &new));
    // A copy in Q's list of an act of T's, which T's own list no longer
    // carries: not taken, in every order.
    let ts = sub(6, true, &t, 30);
    let of = lists(&[
        (&p, vec![new.clone()]),
        (&q, vec![ts.clone()]),
        (&t, vec![]),
    ]);
    let counting = makers(&[&p, &q, &t], &[]);
    let first = work(&of, &counting, bounds);
    assert!(!in_force_of(&first, &ts));
    for order in orders(&of) {
        assert_eq!(written(&work(&order, &counting, bounds)), written(&first));
    }
}

/// A counting device's list holds acts whose signature does not hold,
/// whose maker is a key that was never a device of the person's, whose
/// maker is another device that never made it, and whose time or count is
/// above `SHARED_ACT_TIME_MAX`; none is taken, written or ordered: each
/// item is what the other acts on it give, in every order (decision
/// 2026-10-10 property 9, T23).
#[test]
fn an_act_whose_signature_fails_or_whose_maker_was_never_a_device_is_not_taken() {
    let (laptop, desktop, stranger) = (device(1), device(2), device(9));
    let counting = makers(&[&laptop, &desktop], &[]);
    let bounds = Bounds::OF_A_LIST;
    let honest = label(1, Some("bob")).by(&desktop, 10, 0);
    let mut forged = label(1, Some("eve")).by(&desktop, 20, 0);
    if let AnyAct::Label(a) = &mut forged {
        a.signature = [3; 64];
    }
    let strangers = label(1, Some("mallory")).by(&stranger, 30, 0);
    // Signed by the laptop, said to be the desktop's.
    let mut as_desktop = label(2, Some("dave")).by(&laptop, 40, 0);
    if let AnyAct::Label(a) = &mut as_desktop {
        a.maker = desktop.public_key();
    }
    let honest_2 = label(2, Some("carol")).by(&desktop, 5, 0);
    let past_bound = Act {
        item: label(3, Some("late")),
        time: SHARED_ACT_TIME_MAX + 1,
        count: 0,
        maker: laptop.public_key(),
        signature: [0; 64],
    };
    let past_bound = {
        let mut a = past_bound;
        a.signature = laptop.sign(&{
            let mut signed = cordelia_core::protocol::LABEL_SHARED_ACT.to_vec();
            signed.push(4);
            signed
        });
        AnyAct::Label(a)
    };
    let of = lists(&[
        (
            &laptop,
            vec![forged.clone(), as_desktop.clone(), past_bound.clone()],
        ),
        (&desktop, vec![honest.clone(), honest_2.clone()]),
    ]);
    let alt = lists(&[
        (&laptop, vec![strangers.clone()]),
        (&desktop, vec![honest.clone(), honest_2.clone()]),
    ]);
    for of in [of, alt] {
        let first = work(&of, &counting, bounds);
        for order in orders(&of) {
            let computed = work(&order, &counting, bounds);
            assert_eq!(written(&computed), written(&first));
            assert_eq!(
                newest_of(&computed, &honest),
                Some(honest.written()),
                "the honest label decides"
            );
            assert_eq!(newest_of(&computed, &honest_2), Some(honest_2.written()));
            assert!(computed.newest(&past_bound.key()).is_none());
            assert_eq!(computed.written.len(), 2);
        }
    }
    // The stranger is named as passed over; a forged act names nobody.
    let named = work(
        &lists(&[(&laptop, vec![strangers.clone()])]),
        &counting,
        bounds,
    );
    assert_eq!(
        named.passed_over.iter().collect::<Vec<_>>(),
        [&stranger.public_key()]
    );
    // Nothing is kept of when this device took a stranger's act.
    assert!(named.taken.is_empty());
}

// ── The cut of the removal record ────────────────────────────────────────

/// The removal record's cut on acts (decision 2026-10-24, rule 6;
/// decision 2026-10-10 property 9 and §20, item 7): an act of the removed
/// key taken before its cut time stays in force, named as the removed
/// key's; one taken at or after it, or in a generation made apart from the
/// removal, is passed over, on every device that took them alike. Today
/// the cut times are not built, and a key the statement removes is taken
/// by the statement alone ([`ByTheStatement`]): that is said here too.
#[test]
fn an_act_of_a_removed_key_after_its_cut_time_counts_for_nothing() {
    let (laptop, desktop, tablet) = (device(1), device(2), device(3));
    let before = label(4, Some("before")).by(&tablet, 10, 0);
    let after = label(5, Some("after")).by(&tablet, 20, 0);
    let apart = sub(6, true, &tablet, 30);
    let of = lists(&[
        (&laptop, vec![before.clone(), after.clone(), apart.clone()]),
        (&desktop, vec![]),
    ]);
    struct Removed(Cut);
    impl Removals for Removed {
        fn removal(&self, key: &[u8; 32]) -> Option<Cut> {
            (*key == device(3).public_key()).then(|| self.0.clone())
        }
    }
    let cut_at = 1_000;
    let makers = Makers::new(
        Counting::of_devices(&[laptop.public_key(), desktop.public_key()]),
        Removed(Cut::Times(vec![(3, Some(cut_at))])),
    );
    // Taken before the cut in generation 3, after it there, and in
    // generation 2, which the filler does not list: one made apart from
    // the removal, since it lists every generation of the removal's chain.
    let mut takings = Takings::now(Taken {
        generation: 3,
        taken_at: cut_at + 5,
    });
    takings.record(
        before.signature(),
        Taken {
            generation: 3,
            taken_at: cut_at - 1,
        },
    );
    takings.record(
        after.signature(),
        Taken {
            generation: 3,
            taken_at: cut_at,
        },
    );
    takings.record(
        apart.signature(),
        Taken {
            generation: 2,
            taken_at: 1,
        },
    );
    for order in orders(&of) {
        let computed = compute(&order, &makers, &takings, Bounds::OF_A_LIST);
        assert!(in_force_of(&computed, &before));
        assert!(!in_force_of(&computed, &after));
        assert!(!in_force_of(&computed, &apart));
        assert!(computed.newest(&after.key()).is_none());
        assert!(computed.passed_over.contains(&tablet.public_key()));
        let holds = Holds::of(&computed.written, &computed.past_bound, &makers);
        assert_eq!(holds.labels.len(), 1);
        assert_eq!(holds.labels[0].1, Maker::Removed);
    }
    // A cut where no change has a time cuts all the key's acts in that
    // generation.
    let none = Makers::new(
        Counting::of_devices(&[laptop.public_key()]),
        Removed(Cut::Times(vec![(3, None)])),
    );
    let computed = compute(&of, &none, &takings, Bounds::OF_A_LIST);
    assert!(computed.written.is_empty());
    // Listed as an earlier generation of the removal's chain, generation
    // 2 counts before its cut time.
    let chain = Makers::new(
        Counting::of_devices(&[laptop.public_key(), desktop.public_key()]),
        Removed(Cut::Times(vec![(2, Some(cut_at)), (3, Some(cut_at))])),
    );
    let computed = compute(&of, &chain, &takings, Bounds::OF_A_LIST);
    assert!(in_force_of(&computed, &apart));
    assert!(in_force_of(&computed, &before));
    assert!(!in_force_of(&computed, &after));
    // Today: by the statement alone, every act taken counts.
    let today = makers_by_statement(&laptop, &tablet);
    let computed = compute(&of, &today, &takings, Bounds::OF_A_LIST);
    for act in [&before, &after, &apart] {
        assert!(in_force_of(&computed, act));
    }
    assert!(!Cut::StatementAlone.cuts(Taken {
        generation: 0,
        taken_at: i64::MAX
    }));
}

/// What is kept of when each act was taken: every act the lists read
/// carry, as carried in the generation applied, a new one taken now; and
/// each act the latest generation before carried, until the lists of this
/// one carry it. An act this generation carried and no longer does goes,
/// and so does one of an older generation (decision 2026-10-10 property
/// 9; the review of slice 3 again, medium 2).
#[test]
fn what_is_kept_of_a_taking_outlives_one_generation() {
    let t = |generation, taken_at| Taken {
        generation,
        taken_at,
    };
    let mut takings = Takings::now(t(5, 500));
    for (signature, carried_in) in [([1; 64], 5), ([2; 64], 4), ([3; 64], 3), ([4; 64], 4)] {
        takings.known.insert(signature, t(1, 10));
        takings.carried_in.insert(signature, carried_in);
    }
    let carried = BTreeSet::from([[4; 64], [9; 64]]);
    let row = |taken, carried_in| TakenRow { taken, carried_in };
    assert_eq!(
        takings.rows(&carried),
        [
            ([2; 64], row(t(1, 10), 4)),
            ([4; 64], row(t(1, 10), 5)),
            ([9; 64], row(t(5, 500), 5)),
        ]
    );
}

fn makers_by_statement(counting: &NodeIdentity, removed: &NodeIdentity) -> Makers {
    makers(&[counting], &[removed])
}

// ── The order, the dating, and past a bound ──────────────────────────────

/// What orders two acts on one item (decision 2026-10-10 §3.4): the
/// time; then whether the maker counts; then, at `SHARED_ACT_TIME_MAX`
/// alone, the item's count; then the maker's key; and last the act's
/// bytes; the greater above at each.
#[test]
fn two_acts_on_one_item_are_ordered_by_time_maker_count_key_and_bytes() {
    let (one, two, gone) = (device(1), device(2), device(7));
    let (high, low) = if one.public_key() > two.public_key() {
        (one, two)
    } else {
        (two, one)
    };
    let makers = makers(&[&high, &low], &[&gone]);
    let order = |by: &NodeIdentity, subscribed: bool, time: u64, count: u64| {
        Order::of(
            &subscription(1, "notes", subscribed).by(by, time, count),
            &makers,
        )
    };
    let bound = SHARED_ACT_TIME_MAX;
    assert!(order(&low, true, 11, 0) > order(&high, true, 10, 0));
    assert!(order(&gone, true, 11, 0) > order(&high, true, 10, 0));
    // At one time, a maker that counts.
    assert!(order(&low, true, 10, 0) > order(&gone, true, 10, 0));
    assert!(order(&low, true, bound, 0) > order(&gone, true, bound, 9));
    // Below the bound the count orders nothing; at it, before the key.
    assert!(order(&high, true, 10, 0) > order(&low, true, 10, 5));
    assert!(order(&low, true, bound, 1) > order(&high, true, bound, 0));
    // Then the key; and last the bytes.
    assert!(order(&high, true, 10, 0) > order(&low, true, 10, 0));
    assert!(order(&high, true, 10, 0) > order(&high, false, 10, 0));
    assert_eq!(order(&high, true, 10, 0), order(&high, true, 10, 0));
}

/// Past a bound, in one pass (decision 2026-10-10 §3.4 and §13): the
/// smallest case; 25 and 10; no one acting, room opening; removed keys
/// whose acts are taken in a different order round after round; and
/// filings and drops, two parts with two bounds.
#[test]
fn past_a_bound_in_one_pass() {
    let (a, b, c, d, old) = (device(1), device(2), device(3), device(4), device(5));
    let counting = makers(&[&a, &b, &c, &d, &old], &[]);

    // The smallest case, with a bound of 3 subscriptions.
    let bounds = Bounds::of(16, 64, 3, 64);
    let p = sub(1, true, &old, 1);
    let q = sub(2, true, &a, 2);
    let x = sub(3, true, &b, 3);
    let r = sub(4, true, &a, 4);
    let off_x = sub(3, false, &a, 5);
    let of = lists(&[
        (&old, vec![p.clone()]),
        (&a, vec![q.clone(), off_x.clone(), r.clone()]),
        (&b, vec![x.clone()]),
    ]);
    let computed = work(&of, &counting, bounds);
    assert_eq!(
        written(&computed),
        [&q, &r, &off_x].map(AnyAct::written).into()
    );
    assert_eq!(past(&computed), [p.written()].into());
    assert!(in_force_of(&computed, &q) && in_force_of(&computed, &r));
    assert!(!in_force_of(&computed, &p) && !in_force_of(&computed, &x));
    // In the next, with A's list as it wrote it, `p` falls past again.
    let mut next = of.clone();
    next[1].1 = list_of(computed.written.clone());
    let again = work(&next, &counting, bounds);
    assert_eq!(past(&again), [p.written()].into());

    // 25 and 10, at the bound of 32: 25 subscriptions in force and 10
    // unsubscriptions kept for an old list, all of makers that count. The
    // 3 oldest of the 35 fall past.
    let bounds = Bounds::OF_A_LIST;
    let olds: Vec<AnyAct> = (0..10)
        .map(|n| sub(100 + n, true, &old, 1 + n as u64))
        .collect();
    let offs: Vec<AnyAct> = (0..10)
        .map(|n| sub(100 + n, false, &a, 20 + n as u64))
        .collect();
    let ons: Vec<AnyAct> = (0..25).map(|n| sub(n, true, &a, 100 + n as u64)).collect();
    let mut a_list = offs.clone();
    a_list.extend(ons.clone());
    let of = lists(&[(&old, olds.clone()), (&a, a_list)]);
    let computed = work(&of, &counting, bounds);
    assert_eq!(computed.written.len(), 32);
    assert_eq!(
        past(&computed),
        offs[..3].iter().map(AnyAct::written).collect()
    );
    // A writes its list: the subscriptions those three undid are newest
    // again, and in force where a computation has room. Here it has none:
    // they are the oldest.
    let mut next = of.clone();
    next[1].1 = list_of(computed.written.clone());
    let again = work(&next, &counting, bounds);
    for old in &olds[..3] {
        assert_eq!(newest_of(&again, old), Some(old.written()));
        assert!(!in_force_of(&again, old));
    }
    // Room opens: the old list is written again without the subscriptions
    // the newest seven unsubscriptions are kept for, so those become
    // undoes of nothing below them.
    next[0].1 = list_of(olds[..3].to_vec());
    let roomy = work(&next, &counting, bounds);
    for old in &olds[..3] {
        assert!(in_force_of(&roomy, old));
    }

    // No one acting, room opening, with a bound of 2.
    let bounds = Bounds::of(16, 64, 2, 64);
    let x1 = sub(1, true, &c, 1);
    let y2 = sub(2, true, &b, 2);
    let off_x3 = sub(1, false, &a, 3);
    let off_y4 = sub(2, false, &a, 4);
    let z5 = sub(3, true, &d, 5);
    let mut of = lists(&[
        (&c, vec![x1.clone()]),
        (&b, vec![y2.clone()]),
        (&a, vec![off_x3.clone(), off_y4.clone()]),
        (&d, vec![z5.clone()]),
    ]);
    let first = work(&of, &counting, bounds);
    assert_eq!(past(&first), [off_x3.written()].into());
    // A writes again: `x` at 1 is newest, and falls past.
    of[2].1 = list_of(first.written.clone());
    let second = work(&of, &counting, bounds);
    assert_eq!(past(&second), [x1.written()].into());
    // B writes again, without its `y`: the unsubscribe of `y` is an undo
    // of nothing below it, and C's `x` is in force, on every device.
    of[1].1 = list_of(second.written.clone());
    let third = work(&of, &counting, bounds);
    assert!(in_force_of(&third, &x1));
    for order in orders(&of) {
        assert!(in_force_of(&work(&order, &counting, bounds), &x1));
    }

    // Removed keys: a removed key's filings copied in one list, and the
    // filings of a device that counts and has no list, with no undo; the
    // rounds end.
    let gone = device(8);
    let drawer = device(9);
    let with_gone = makers(&[&a, &b, &drawer], &[&gone]);
    let bounds = Bounds::of(3, 4, 32, 64);
    let gones: Vec<AnyAct> = (0..4)
        .map(|n| filing(20 + n, "g").by(&gone, 10 + n as u64, 0))
        .collect();
    let drawers: Vec<AnyAct> = (0..4)
        .map(|n| filing(30 + n, "d").by(&drawer, 12 + n as u64, 0))
        .collect();
    let mut a_list = gones[..2].to_vec();
    a_list.extend(drawers[..1].to_vec());
    let mut b_list = gones[2..].to_vec();
    b_list.extend(drawers[1..].to_vec());
    let mut of = lists(&[(&a, a_list), (&b, b_list)]);
    let rounds = settle(
        &mut of,
        &[a.public_key(), b.public_key()],
        &with_gone,
        bounds,
    );
    assert!(rounds < 10, "{rounds}");
    let settled = work(&of, &with_gone, bounds);
    // The drawer device counts: its filings first.
    assert!(
        settled
            .written
            .iter()
            .all(|act| act.maker() == drawer.public_key())
    );

    // Filings and drops: two devices apart make 17 filings between them,
    // and the oldest falls past 16, on every device alike.
    let bounds = Bounds::OF_A_LIST;
    let a_files: Vec<AnyAct> = (0..9)
        .map(|n| filing(n, "a").by(&a, 10 + 2 * n as u64, 0))
        .collect();
    let b_files: Vec<AnyAct> = (9..17)
        .map(|n| filing(n, "b").by(&b, 11 + 2 * (n - 9) as u64, 0))
        .collect();
    let of = lists(&[(&a, a_files.clone()), (&b, b_files.clone())]);
    for order in orders(&of) {
        let computed = work(&order, &counting, bounds);
        assert_eq!(past(&computed), [a_files[0].written()].into());
    }

    // Five old lists carry 80 filings, and 65 drops are each kept for one
    // of them: the oldest drop falls past 64, and its filing comes back
    // into force where the 16 places have room, and past the bound where
    // they do not.
    let olds: Vec<NodeIdentity> = (40..45).map(device).collect();
    let mut five = makers_list(&olds);
    five.push(&a);
    let counting = makers(&five, &[]);
    let filed_of = |n: usize| filing(n as u8, "f").by(&olds[n / 16], 100 + n as u64, 0);
    let mut of: Vec<([u8; 32], SharedList)> = (0..5)
        .map(|l| {
            (
                olds[l].public_key(),
                list_of((16 * l..16 * l + 16).map(filed_of)),
            )
        })
        .collect();
    let drops: Vec<AnyAct> = (0..65)
        .map(|n| dropped(n as u8).by(&a, 1_000 + n as u64, 0))
        .collect();
    of.push((a.public_key(), list_of(drops.clone())));
    let computed = work(&of, &counting, bounds);
    let back = filed_of(0);
    // In that computation the oldest drop falls past 64, and its channel
    // is not in force: there is no second pass.
    assert_eq!(past(&computed), [drops[0].written()].into());
    assert!(!in_force_of(&computed, &back));
    // In the next, A's list no longer carries that drop: the filing is
    // the newest valid act on its item again, and the 15 filings no drop
    // reaches leave room for it among the 16.
    let mut next = of.clone();
    next.last_mut().unwrap().1 = list_of(computed.written.clone());
    let roomy = work(&next, &counting, bounds);
    assert_eq!(newest_of(&roomy, &back), Some(back.written()));
    assert!(in_force_of(&roomy, &back));
    // Without room: one more filing, newer, of another device.
    let one_more = device(46);
    let mut more = five.clone();
    more.push(&one_more);
    let counting = makers(&more, &[]);
    next.push((
        one_more.public_key(),
        list_of([filing(90, "f").by(&one_more, 500, 0)]),
    ));
    let full = work(&next, &counting, bounds);
    assert_eq!(newest_of(&full, &back), Some(back.written()));
    assert!(!in_force_of(&full, &back));
    assert!(past(&full).contains(&back.written()));
}

/// Past a bound, within each group, an act whose maker counts goes before
/// one whose maker is removed, whatever their times; then the newer goes
/// first (decision 2026-10-10 §3.4).
#[test]
fn past_a_bound_the_makers_that_count_come_first() {
    let (person, gone) = (device(1), device(2));
    let both = makers(&[&person], &[&gone]);
    let bounds = Bounds::of(16, 2, 2, 64);
    let mine = [sub(1, true, &person, 1), sub(2, true, &person, 2)];
    let theirs = [sub(3, true, &gone, 100), sub(4, true, &gone, 101)];
    let of = lists(&[(&person, mine.to_vec()), (&gone, theirs.to_vec())]);
    let computed = work(&of, &both, bounds);
    for act in &mine {
        assert!(in_force_of(&computed, act));
    }
    for act in &theirs {
        assert!(!in_force_of(&computed, act));
    }
    // Among undoes of nothing below them too: the person's drop goes
    // first, the removed key's newer drops past.
    let undoes = lists(&[
        (&person, vec![dropped(1).by(&person, 1, 0)]),
        (
            &gone,
            vec![dropped(2).by(&gone, 100, 0), dropped(3).by(&gone, 101, 0)],
        ),
    ]);
    let computed = work(&undoes, &both, bounds);
    assert!(written(&computed).contains(&dropped(1).by(&person, 1, 0).written()));
    assert_eq!(
        past(&computed),
        [dropped(2).by(&gone, 100, 0).written()].into()
    );
}

/// A new act is dated one above the greatest of the device's clock and
/// the newest valid act on its item, and never above the bound: an act on
/// another item lifts nothing, and an act that is not valid lifts nothing.
/// At the bound its count is one above the highest count among the valid
/// acts on the item at the bound whose makers count, or 1 where none does
/// (decision 2026-10-10 §3.4, §20, item 5).
#[test]
fn a_new_act_is_dated_above_the_newest_valid_act_on_its_item() {
    let (person, other, gone, stranger) = (device(1), device(2), device(3), device(9));
    let m = makers(&[&person, &other], &[&gone]);
    let key = |act: &AnyAct| act.key();
    let on_item = label(1, Some("a")).by(&other, 500, 0);
    let elsewhere = label(2, Some("b")).by(&other, 9_000, 0);
    let strangers = label(1, Some("c")).by(&stranger, 8_000, 0);
    let of = lists(&[(&other, vec![on_item.clone(), elsewhere.clone()])]);
    let with_stranger = lists(&[
        (&other, vec![on_item.clone(), elsewhere.clone()]),
        (&person, vec![strangers]),
    ]);
    for of in [of, with_stranger] {
        let computed = work(&of, &m, Bounds::OF_A_LIST);
        assert_eq!(computed.dated(&key(&on_item), &m, 100), Ok((501, 0)));
        assert_eq!(computed.dated(&key(&on_item), &m, 1_000), Ok((1_001, 0)));
        assert_eq!(computed.dated(&key(&elsewhere), &m, 100), Ok((9_001, 0)));
        assert_eq!(
            computed.dated(&(Part::Label, vec![7; 32]), &m, 100),
            Ok((101, 0))
        );
    }
    // A removed key's act on the item lifts it.
    let removed = label(1, Some("d")).by(&gone, 7_000, 0);
    let computed = work(&lists(&[(&other, vec![removed])]), &m, Bounds::OF_A_LIST);
    assert_eq!(computed.dated(&key(&on_item), &m, 100), Ok((7_001, 0)));
    // At the bound.
    let bound = SHARED_ACT_TIME_MAX;
    let at_bound = |by: &NodeIdentity, count: u64| label(1, Some("e")).by(by, bound, count);
    let computed = work(
        &lists(&[(&other, vec![at_bound(&gone, 9)])]),
        &m,
        Bounds::OF_A_LIST,
    );
    assert_eq!(computed.dated(&key(&on_item), &m, 100), Ok((bound, 1)));
    let computed = work(
        &lists(&[(&other, vec![at_bound(&other, 4)])]),
        &m,
        Bounds::OF_A_LIST,
    );
    assert_eq!(computed.dated(&key(&on_item), &m, 100), Ok((bound, 5)));
    assert_eq!(computed.dated(&key(&on_item), &m, i64::MAX), Ok((bound, 5)));
    let computed = work(
        &lists(&[(&other, vec![at_bound(&other, bound)])]),
        &m,
        Bounds::OF_A_LIST,
    );
    assert_eq!(
        computed.dated(&key(&on_item), &m, 100),
        Err(HeldAtBound(other.public_key()))
    );
}

/// Two acts on one item that agree in time, count, maker and whether it
/// counts are ordered by their bytes, the greater above: a filing and a
/// drop of one channel, both signed by the laptop at one time, one in the
/// desktop's list and one in the phone's, with no list of the laptop's
/// read, are taken alike by every device, in every order of the lists
/// (decision 2026-10-10 §3.4).
#[test]
fn two_acts_alike_but_for_their_bytes_are_ordered_by_them_on_every_device() {
    let (laptop, desktop, phone) = (device(1), device(2), device(3));
    let m = makers(&[&laptop, &desktop, &phone], &[]);
    let filed = filing(1, "review").by(&laptop, 50, 0);
    let drop = dropped(1).by(&laptop, 50, 0);
    let greater = std::cmp::max(filed.written(), drop.written());
    let of = lists(&[(&desktop, vec![filed]), (&phone, vec![drop])]);
    for order in orders(&of) {
        let computed = work(&order, &m, Bounds::OF_A_LIST);
        assert_eq!(
            computed
                .newest(&(Part::Channel, channel(1).to_vec()))
                .map(AnyAct::written),
            Some(greater.clone())
        );
    }
}

fn makers_list(of: &[NodeIdentity]) -> Vec<&NodeIdentity> {
    of.iter().collect()
}

/// A device in someone else's hands writes 32 unsubscriptions and 64
/// drops of items no list carries: they are undoes of nothing below them,
/// ranked last; none pushes out an item in force or an undo kept for
/// something; a subscribe and a filing still go through, past the thief's
/// undoes, which they push out (decision 2026-10-10 §3.4, T23).
#[test]
fn an_undo_of_nothing_never_pushes_out_what_is_in_force() {
    let (person, thief, old) = (device(1), device(2), device(3));
    let counting = makers(&[&person, &thief, &old], &[]);
    let bounds = Bounds::OF_A_LIST;
    let mut theirs: Vec<AnyAct> = (0..32)
        .map(|n| sub(100 + n, false, &thief, 5_000 + n as u64))
        .collect();
    theirs.extend((0..64).map(|n| dropped(100 + n).by(&thief, 5_000 + n as u64, 0)));
    let mine: Vec<AnyAct> = (0..20)
        .map(|n| sub(n, true, &person, 10 + n as u64))
        .chain((0..15).map(|n| filing(n, "c").by(&person, 10 + n as u64, 0)))
        .collect();
    // An undo kept for something: the old device's subscription, undone.
    let kept_for = sub(50, true, &old, 1);
    let undo = sub(50, false, &person, 2);
    let mut person_list = mine.clone();
    person_list.push(undo.clone());
    let of = lists(&[
        (&person, person_list),
        (&thief, theirs.clone()),
        (&old, vec![kept_for]),
    ]);
    let computed = work(&of, &counting, bounds);
    for act in &mine {
        assert!(in_force_of(&computed, act), "{act:?}");
    }
    assert!(written(&computed).contains(&undo.written()));
    assert_eq!(
        decide(
            &computed,
            &counting,
            &person,
            &Do::Subscribe(subscription(60, "a", true)),
            9_000
        )
        .map(|made| made.len()),
        Ok(1)
    );
    assert_eq!(
        decide(
            &computed,
            &counting,
            &person,
            &Do::File(filing(60, "new")),
            9_000
        )
        .map(|made| made.len()),
        Ok(1)
    );
    // Made, each is in force, and pushes out one of the thief's.
    let mut person_list = mine.clone();
    person_list.push(undo.clone());
    person_list.push(sub(60, true, &person, 9_001));
    let of = lists(&[
        (&person, person_list),
        (&thief, theirs),
        (&old, vec![sub(50, true, &old, 1)]),
    ]);
    let computed = work(&of, &counting, bounds);
    assert!(in_force_of(&computed, &sub(60, true, &person, 9_001)));
    assert_eq!(
        computed
            .past_bound
            .iter()
            .filter(|act| act.maker() == thief.public_key())
            .count(),
        // Of the 32 places, the person's 20 subscriptions, its undo kept
        // for something and its new subscription take 22, first.
        22
    );
    assert!(
        computed
            .past_bound
            .iter()
            .all(|act| act.maker() == thief.public_key())
    );
}

/// The filing of `shared move` is refused `held_at_bound` only where the
/// channel moved to is itself held at the time bound with the highest
/// count by a device that counts, never for another channel's filing so
/// held; it is dated above every other filing that can be gone above
/// (decision 2026-10-10 §3.4, §5.5; the review of slice 3 again, low 4).
#[test]
fn a_move_is_held_at_the_bound_only_by_its_own_channel() {
    let (person, thief) = (device(1), device(2));
    let makers = makers(&[&person, &thief], &[]);
    let max = SHARED_ACT_TIME_MAX;
    let x = filing(1, "x").by(&person, 10, 0);
    let y = filing(2, "y").by(&thief, max, max);
    let other = filing(3, "other").by(&person, 8_000, 0);
    let of = lists(&[(&person, vec![x, other]), (&thief, vec![y])]);
    let computed = work(&of, &makers, Bounds::OF_A_LIST);
    let moved = Do::Move {
        from: channel(1),
        to: Filing {
            came: Came::Moved(channel(1)),
            ..filing(4, "x")
        },
    };
    let made = decide(&computed, &makers, &person, &moved, 9_000).unwrap();
    assert_eq!((made[0].time(), made[0].count()), (9_001, 0));
    // Above the other filings that can be gone above, whatever the clock.
    let made = decide(&computed, &makers, &person, &moved, 5).unwrap();
    assert_eq!((made[0].time(), made[0].count()), (8_001, 0));
    // The channel moved to, held at the bound: refused, naming its holder.
    let held = dropped(4).by(&thief, max, max);
    let of = lists(&[
        (&person, vec![filing(1, "x").by(&person, 10, 0)]),
        (&thief, vec![held]),
    ]);
    let computed = work(&of, &makers, Bounds::OF_A_LIST);
    assert_eq!(
        decide(&computed, &makers, &person, &moved, 9_000),
        Err(Refused::HeldAtBound(thief.public_key()))
    );
}

/// An undo over an undo is an undo of nothing below it, whatever older
/// act of a kind in force is carried under both: it ranks in the second
/// group past a bound, below an older item in force (decision 2026-10-10
/// §3.4, "Past a bound, in one pass").
#[test]
fn an_undo_over_an_undo_is_an_undo_of_nothing() {
    let (person, desktop, phone, old) = (device(1), device(2), device(3), device(4));
    let makers = makers(&[&person, &desktop, &phone], &[&old]);
    // A removed key's acts are taken from any list: its subscribe and its
    // unsubscribe, each a copy, under the person's newer unsubscribe.
    let undo = sub(50, false, &person, 30);
    let older = sub(51, true, &person, 1);
    let of = lists(&[
        (&person, vec![undo.clone(), older.clone()]),
        (&desktop, vec![sub(50, false, &old, 20)]),
        (&phone, vec![sub(50, true, &old, 10)]),
    ]);
    for order in orders(&of) {
        let computed = work(&order, &makers, Bounds::of(16, 64, 1, 64));
        assert_eq!(newest_of(&computed, &undo), Some(undo.written()));
        assert!(in_force_of(&computed, &older));
        assert_eq!(past(&computed), BTreeSet::from([undo.written()]));
    }
}

/// A filing, a subscribe or a label takes a new place, and is refused
/// where its part is full, unless the newest valid act on its item is of
/// a kind in force or an undo kept for something written in that part
/// (decision 2026-10-10 §3.4, "What a new act is refused for"): so none
/// pushes out an item in force. A filing of a channel whose drop is kept
/// for something takes a new place, since the drop is kept among the
/// drops; so does a subscribe over an undo of nothing, and one over an
/// undo kept for something that a bound left out.
#[test]
fn an_act_on_an_item_that_holds_no_place_is_refused_for_room() {
    // A filing of a dropped channel, at the real bounds: the desktop's
    // filing of it is still carried, below the laptop's drop.
    let s = person(2, 2);
    let now = s.now + 10;
    on(&s, 1, Do::File(filing(50, "x")), now + 1);
    fetch_from(&s, &[1], 0, now + 2);
    on(&s, 0, Do::Drop(channel(50)), now + 3);
    for seed in 0..16 {
        on(&s, 0, Do::File(filing(seed, &format!("c{seed}"))), now + 4);
    }
    assert_eq!(
        refused(&s, 0, Do::File(filing(50, "x")), now + 5),
        Refused::Full {
            part: Part::Channel,
            devices: Vec::new()
        }
    );
    let names = filed(&s, 0);
    assert_eq!(names.len(), 16);
    assert!(names.iter().all(|name| name.starts_with('c')), "{names:?}");
    // Once a place is free it is filed, and pushes out nothing.
    on(&s, 0, Do::Drop(channel(0)), now + 6);
    on(&s, 0, Do::File(filing(50, "x")), now + 7);
    let names = filed(&s, 0);
    assert_eq!(names.len(), 16);
    assert!(names.contains(&"x".to_string()) && !names.contains(&"c0".to_string()));

    // A subscribe over an undo of nothing, at the real bound of 32.
    let (person, desktop, phone, old) = (device(1), device(2), device(3), device(4));
    let makers = makers(&[&person, &desktop, &phone], &[&old]);
    let full: Vec<AnyAct> = (0..32)
        .map(|n| sub(100 + n, true, &person, 100 + u64::from(n)))
        .collect();
    let mut person_list = full.clone();
    person_list.push(sub(50, false, &person, 30));
    let of = lists(&[
        (&person, person_list),
        (&desktop, vec![sub(50, false, &old, 20)]),
        (&phone, vec![sub(50, true, &old, 10)]),
    ]);
    let again = Do::Subscribe(subscription(50, "a", true));
    let computed = work(&of, &makers, Bounds::OF_A_LIST);
    assert_eq!(
        decide(&computed, &makers, &person, &again, 9_000),
        Err(Refused::Full {
            part: Part::Subscription,
            devices: Vec::new()
        })
    );
    // An undo kept for something, past the bound: the person's 32 newer
    // subscriptions rank above it, so it holds no place.
    let mut person_list = full.clone();
    person_list.push(sub(50, false, &person, 20));
    let of = lists(&[
        (&person, person_list),
        (&phone, vec![sub(50, true, &old, 10)]),
    ]);
    let computed = work(&of, &makers, Bounds::OF_A_LIST);
    assert!(
        computed
            .past_bound
            .iter()
            .any(|act| act.key() == again_key())
    );
    assert_eq!(
        decide(&computed, &makers, &person, &again, 9_000),
        Err(Refused::Full {
            part: Part::Subscription,
            devices: Vec::new()
        })
    );
    // Written, that undo's place is the subscribe's: it is made.
    let mut person_list: Vec<AnyAct> = full[1..].to_vec();
    person_list.push(sub(50, false, &person, 20));
    let of = lists(&[
        (&person, person_list),
        (&phone, vec![sub(50, true, &old, 10)]),
    ]);
    let computed = work(&of, &makers, Bounds::OF_A_LIST);
    assert!(decide(&computed, &makers, &person, &again, 9_000).is_ok());

    fn again_key() -> Key {
        (Part::Subscription, subscription(50, "a", true).item())
    }
}

/// With three lists over a bound of filings and drops, the drop a device
/// makes is written first among the drops kept for something, and its
/// channel is not in force in that computation or the next (decision
/// 2026-10-10 §3.4).
#[test]
fn the_newest_act_is_written() {
    let (a, b, c) = (device(1), device(2), device(3));
    let counting = makers(&[&a, &b, &c], &[]);
    let bounds = Bounds::of(3, 3, 32, 64);
    let b_files: Vec<AnyAct> = (0..3)
        .map(|n| filing(n, "b").by(&b, 10 + n as u64, 0))
        .collect();
    let c_files: Vec<AnyAct> = (3..6)
        .map(|n| filing(n, "c").by(&c, 10 + n as u64, 0))
        .collect();
    let a_drops: Vec<AnyAct> = (0..3)
        .map(|n| dropped(n).by(&a, 100 + n as u64, 0))
        .collect();
    let mut of = lists(&[
        (&a, a_drops.clone()),
        (&b, b_files.clone()),
        (&c, c_files.clone()),
    ]);
    let before = work(&of, &counting, bounds);
    // A drops channel 4, which C filed.
    let made = decide(&before, &counting, &a, &Do::Drop(channel(4)), 200).unwrap();
    let mut own = before.written.clone();
    own.retain(|act| act.key() != made[0].key());
    own.extend(made.clone());
    of[0].1 = list_of(own);
    let computed = work(&of, &counting, bounds);
    assert!(written(&computed).contains(&made[0].written()));
    assert!(past(&computed).contains(&a_drops[0].written()));
    assert!(!in_force_of(&computed, &c_files[1]));
    of[0].1 = list_of(computed.written.clone());
    let next = work(&of, &counting, bounds);
    assert!(written(&next).contains(&made[0].written()));
    assert!(!in_force_of(&next, &c_files[1]));
}

/// The remedies of a removal are never refused (decision 2026-10-10
/// §3.4, T23): with 64 drops kept for something, the filing of `shared
/// anew` and a 65th drop go through; the drop pushes out the oldest drop
/// kept for something, whose filing then falls past the bound of the
/// filings and is not in force. A device of the version before, which
/// writes no list, counts among them and changes nothing.
#[test]
fn the_remedies_of_a_removal_are_never_refused_where_every_part_is_full() {
    let olds: Vec<NodeIdentity> = (40..46).map(device).collect();
    let (desktop, before) = (device(1), device(2));
    let mut all = makers_list(&olds);
    all.push(&desktop);
    all.push(&before);
    let counting = makers(&all, &[]);
    let filed_of = |n: usize| filing(n as u8, "f").by(&olds[n / 16], 100 + n as u64, 0);
    let mut of: Vec<([u8; 32], SharedList)> = (0..5)
        .map(|l| {
            (
                olds[l].public_key(),
                list_of((16 * l..16 * l + 16).map(filed_of)),
            )
        })
        .collect();
    // A sixth list, with the channel the person drops at the removal.
    let review = filing(90, "review").by(&olds[5], 500, 0);
    of.push((olds[5].public_key(), list_of([review.clone()])));
    // 64 drops, each kept for one of the old filings; the version
    // before's device writes no list.
    let drops: Vec<AnyAct> = (0..64)
        .map(|n| dropped(n as u8).by(&desktop, 1_000 + n as u64, 0))
        .collect();
    of.push((desktop.public_key(), list_of(drops.clone())));
    let computed = work(&of, &counting, Bounds::OF_A_LIST);
    assert_eq!(computed.placed(1).0, 64);
    assert_eq!(computed.placed(0).0, 16);
    // `shared anew` from the channel, and a 65th drop of it.
    let moved = Do::Move {
        from: channel(90),
        to: Filing {
            came: Came::Moved(channel(90)),
            ..filing(200, "review")
        },
    };
    let anew = decide(&computed, &counting, &desktop, &moved, 100).unwrap();
    assert_eq!(anew.len(), 2);
    let newest_filing = computed
        .valid
        .values()
        .flatten()
        .filter(|act| matches!(act, AnyAct::Filing(_)))
        .map(AnyAct::time)
        .max()
        .unwrap();
    assert!(anew[0].time() > newest_filing);
    let made = decide(
        &computed,
        &counting,
        &desktop,
        &Do::Drop(channel(90)),
        2_000,
    )
    .unwrap();
    // The 65th drop written: the oldest drop kept for something falls
    // past in that computation.
    let mut own = computed.written.clone();
    own.retain(|act| act.key() != made[0].key());
    own.extend(made.clone());
    of.last_mut().unwrap().1 = list_of(own);
    let after = work(&of, &counting, Bounds::OF_A_LIST);
    assert!(written(&after).contains(&made[0].written()));
    assert!(past(&after).contains(&drops[0].written()));
    // In the next its filing is the newest valid act on its item, and
    // falls past the bound of the filings, which the 16 the drops do not
    // reach fill.
    of.last_mut().unwrap().1 = list_of(after.written.clone());
    let next = work(&of, &counting, Bounds::OF_A_LIST);
    let back = filed_of(0);
    assert_eq!(newest_of(&next, &back), Some(back.written()));
    assert!(!in_force_of(&next, &back));
    assert!(!in_force_of(&next, &review));
}

/// The refusals of a new act name the devices whose lists carry the acts
/// below the undoes that fill the part (decision 2026-10-10 §3.4, §5.5):
/// with a bound's worth of unsubscriptions kept for the old device's
/// subscriptions, a new subscribe is refused naming the old device; an
/// act on an item that has one of a kind in force takes its place; and an
/// item that a device that counts holds at the time bound with the highest
/// count is refused naming that device (`held_at_bound`).
#[test]
fn a_refusal_names_the_devices_that_hold_the_places() {
    let (person, old, thief) = (device(1), device(2), device(3));
    let counting = makers(&[&person, &old, &thief], &[]);
    let olds: Vec<AnyAct> = (0..32).map(|n| sub(n, true, &old, 1 + n as u64)).collect();
    let offs: Vec<AnyAct> = (0..32)
        .map(|n| sub(n, false, &person, 100 + n as u64))
        .collect();
    let of = lists(&[(&person, offs), (&old, olds)]);
    let computed = work(&of, &counting, Bounds::OF_A_LIST);
    assert_eq!(
        decide(
            &computed,
            &counting,
            &person,
            &Do::Subscribe(subscription(40, "a", true)),
            500
        ),
        Err(Refused::Full {
            part: Part::Subscription,
            devices: vec![old.public_key()],
        })
    );
    // Subscribed again, an item whose own undo is kept for something.
    assert!(
        decide(
            &computed,
            &counting,
            &person,
            &Do::Subscribe(subscription(3, "a", true)),
            500
        )
        .is_ok()
    );

    // At the bound, with the highest count, held by a device that counts.
    let held = subscription(9, "a", true).by(&thief, SHARED_ACT_TIME_MAX, SHARED_ACT_TIME_MAX);
    let of = lists(&[(&thief, vec![held]), (&person, vec![])]);
    let computed = work(&of, &counting, Bounds::OF_A_LIST);
    assert_eq!(
        decide(
            &computed,
            &counting,
            &person,
            &Do::Subscribe(subscription(9, "a", false)),
            500
        ),
        Err(Refused::HeldAtBound(thief.public_key()))
    );
    // Once that device is removed, the person's act goes above it.
    let removed = makers(&[&person, &old], &[&thief]);
    let computed = work(&of, &removed, Bounds::OF_A_LIST);
    let made = decide(
        &computed,
        &removed,
        &person,
        &Do::Subscribe(subscription(9, "a", false)),
        500,
    )
    .unwrap();
    assert_eq!((made[0].time(), made[0].count()), (SHARED_ACT_TIME_MAX, 1));
}

/// A recovery applies the rules of 3.4 to every list of the devices it
/// shows, whatever their age (decision 2026-10-10 §3.5): a device answered
/// `lost` or `hands` is a removed key, whose acts are taken from any list;
/// one answered `have` is in no list, and its acts are passed over until
/// it is added again; a key that was never a device is passed over.
#[test]
fn a_recovery_reads_every_list_it_shows_as_a_device_reads() {
    let (laptop, desktop, phone, stranger) = (device(1), device(2), device(3), device(9));
    let have = sub(1, true, &laptop, 10);
    let hands = label(4, Some("k")).by(&desktop, 5, 0);
    let lost = filing(1, "review").by(&phone, 1, 0);
    let strangers = dropped(1).by(&stranger, 50, 0);
    let of = lists(&[
        (&laptop, vec![have.clone(), lost.clone()]),
        (&desktop, vec![hands.clone()]),
        (&phone, vec![strangers.clone()]),
    ]);
    let maker = |key: &[u8; 32]| {
        if *key == desktop.public_key() || *key == phone.public_key() {
            Some(Maker::Removed)
        } else {
            None
        }
    };
    let (taken, left_out) = recovered(&of, maker);
    assert!(left_out == SharedList::default());
    assert!(taken.subscriptions.is_empty());
    assert_eq!(acts_of(&taken).len(), 2);
    assert!(acts_of(&taken).contains(&hands));
    assert!(acts_of(&taken).contains(&lost));
    assert_eq!(recovered(&[], maker).0, SharedList::default());
}

// ── Devices of one person, in-process ─────────────────────────────────────

/// `count` devices of one person, of whom the first `added` are added: the
/// phrase is made on device 0, which adds each of the others, and each
/// has been given what every other holds.
fn person(count: u16, added: usize) -> Several {
    let mut s = Several::new(count);
    s.make_phrase(0);
    for new in 1..added {
        s.add(0, new);
    }
    let all: Vec<usize> = (0..added).collect();
    s.meet(&all);
    s
}

/// Device `n` does `what` at `now`, and it is made.
fn on(s: &Several, n: usize, what: Do, now: i64) -> Vec<AnyAct> {
    match act(&s[n].conn, &s[n].identity, what, now).unwrap() {
        Done::Made(made) => made,
        other => panic!("{other:?}"),
    }
}

/// Device `n` does `what` at `now`, and it is refused.
fn refused(s: &Several, n: usize, what: Do, now: i64) -> Refused {
    match act(&s[n].conn, &s[n].identity, what, now).unwrap() {
        Done::Refused(refused) => refused,
        other => panic!("{other:?}"),
    }
}

/// Device `to` is given, at `now`, everything device `from` holds: the
/// change entry it keeps, and then every entry of its store.
fn give(s: &Several, from: usize, to: usize, now: i64) {
    let kept = held_rows::change_entry(&s[from].conn, KeptEntry::Latest).unwrap();
    let entries = kept.map(|entry| entry.check().unwrap()).into_iter();
    for entry in entries.chain(s[from].stored()) {
        take(&s[to].conn, &s[to].identity, &entry, now).unwrap();
    }
}

/// Device `n` makes a whole fetch at `now`. Returns whether it wrote its
/// list.
fn fetch(s: &Several, n: usize, now: i64) -> bool {
    fetched_whole(&s[n].conn, &s[n].identity, now).unwrap()
}

/// Device `to` is given what each of `from` holds, and makes a whole
/// fetch, at `now`.
fn fetch_from(s: &Several, from: &[usize], to: usize, now: i64) -> bool {
    for from in from {
        give(s, *from, to, now);
    }
    fetch(s, to, now)
}

/// Every device of `who` is given what each of them holds and fetches,
/// `rounds` times.
fn all_fetch(s: &Several, who: &[usize], now: i64, rounds: usize) {
    for round in 0..rounds {
        for n in who {
            fetch_from(s, who, *n, now + round as i64);
        }
    }
}

/// The list device `n` last wrote.
fn kept(s: &Several, n: usize) -> SharedList {
    kept_rows::kept(&s[n].conn)
        .unwrap()
        .map(|kept| SharedList::from_value(&Value::Other(kept.list), is_a_name).unwrap())
        .unwrap_or_default()
}

/// Every act in force on device `n`.
fn in_force(s: &Several, n: usize) -> Vec<AnyAct> {
    acts_of(&kept(s, n))
        .into_iter()
        .filter(|act| !act.undoes())
        .collect()
}

/// The names of the channels filed in force on device `n`, in order.
fn filed(s: &Several, n: usize) -> Vec<String> {
    let mut names: Vec<String> = in_force(s, n)
        .into_iter()
        .filter_map(|act| match act {
            AnyAct::Filing(filing) => Some(filing.item.name),
            _ => None,
        })
        .collect();
    names.sort();
    names
}

/// Whether `agent` subscribes to the channel of `seed` on device `n`:
/// `None` where no act on it is written there.
fn subscribes(s: &Several, n: usize, seed: u8, agent: &str) -> Option<bool> {
    acts_of(&kept(s, n)).into_iter().find_map(|act| match act {
        AnyAct::Subscription(a) if a.item.channel == channel(seed) && a.item.agent == agent => {
            Some(a.item.subscribed)
        }
        _ => None,
    })
}

/// The label written on device `n` for the key of `key` bytes.
fn labelled(s: &Several, n: usize, key: u8) -> Option<Option<String>> {
    acts_of(&kept(s, n)).into_iter().find_map(|act| match act {
        AnyAct::Label(a) if a.item.key == [key; 32] => Some(a.item.label),
        _ => None,
    })
}

/// Device `n` writes `acts` in the personal channel as its own list, by
/// hand, one revision above what it wrote there, at `now`.
fn write_by_hand(s: &Several, n: usize, acts: Vec<AnyAct>, now: i64) {
    let personal = s[n].personal();
    let id = derive::channel_id(&personal).unwrap();
    let name = list_name(&s.key(n)).unwrap();
    let slot = slot_id(&derive::slot_key(&personal).unwrap(), &name);
    let before = entries::author_entry(&s[n].conn, &id, &slot, &s.key(n))
        .unwrap()
        .map(|held| held.entry.rev);
    let rev = next_under(before, s[n].number()).unwrap();
    let inside = Inside {
        name,
        value: Value::Other(list_of(acts).to_value(is_a_name).unwrap()),
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&personal, &s[n].identity, rev, &inside)
        .unwrap()
        .check()
        .unwrap();
    entries::store(&s[n].conn, &entry, now).unwrap();
}

/// The entry of device `n`'s own list in the personal channel, as its
/// store holds it: its revision and its list.
fn written_entry(s: &Several, n: usize) -> Option<(u64, SharedList)> {
    let personal = s[n].personal();
    let id = derive::channel_id(&personal).unwrap();
    let name = list_name(&s.key(n)).unwrap();
    let slot = slot_id(&derive::slot_key(&personal).unwrap(), &name);
    let held = entries::author_entry(&s[n].conn, &id, &slot, &s.key(n)).unwrap()?;
    let rev = held.entry.rev;
    let inside = held.entry.check().unwrap().open(&personal).unwrap();
    Some((
        rev,
        SharedList::from_value(&inside.value, is_a_name).unwrap(),
    ))
}

/// The time an act says, as a number.
fn at(act: &AnyAct) -> i64 {
    i64::try_from(act.time()).unwrap()
}

/// An act made on the laptop and copied by the desktop and the phone
/// holds the laptop's key and signature in every list (decision
/// 2026-10-10 property 9, §3.4); and two acts on one item, made at one
/// time by two devices that count, are ordered by their makers' keys, the
/// greater above, alike on every device.
#[test]
fn every_act_names_its_maker_and_a_copy_keeps_it() {
    let s = person(3, 3);
    let now = s.now + 10;
    let made = on(&s, 0, Do::Label(label(9, Some("bob"))), now + 1);
    let AnyAct::Label(made) = &made[0] else {
        panic!("{made:?}");
    };
    assert_eq!(made.maker, s.key(0));
    for n in [1, 2] {
        assert!(fetch_from(&s, &[0], n, now + 2));
    }
    for n in 0..3 {
        let list = kept(&s, n);
        assert_eq!(list.labels.len(), 1, "device {n}");
        assert_eq!(list.labels[0], *made, "device {n}");
        let (_, entry) = written_entry(&s, n).unwrap();
        assert_eq!(entry.labels[0], *made, "device {n}");
    }

    let at_once = now + 100;
    let greater = if s.key(1) > s.key(2) { 1 } else { 2 };
    let text = |n: usize| if n == greater { "a" } else { "z" };
    for n in [1, 2] {
        on(&s, n, Do::Label(label(7, Some(text(n)))), at_once);
    }
    all_fetch(&s, &[0, 1, 2], at_once + 1, 2);
    for n in 0..3 {
        assert_eq!(
            labelled(&s, n, 7),
            Some(Some("a".to_string())),
            "device {n}"
        );
        let of_7 = kept(&s, n)
            .labels
            .into_iter()
            .find(|a| a.item.key == [7; 32])
            .unwrap();
        assert_eq!(of_7.maker, s.key(greater), "device {n}");
    }
}

/// Which makers are valid comes from the statement alone (decision
/// 2026-10-10 property 9, T23): the laptop and the desktop counted a phone
/// by a record of addition, and a settlement left the phone in no list; a
/// tablet is added afterwards. On all three the phone's acts are passed
/// over, the items they decided are what the newest valid act gives, the
/// same on all three, and `passed_over` names the phone's key while any
/// list the device reads carries its acts; an act signed by a key that was
/// never a device of the person's, carried in the laptop's list, is
/// passed over on all three alike, before and after the laptop's removal.
#[test]
fn which_makers_are_valid_comes_from_the_statement_alone() {
    let mut s = person(5, 3);
    let mut now = s.now + 10;
    // The desktop labels a key; the phone, later, labels it again and
    // subscribes an agent; the laptop takes the phone's list, and the
    // desktop has not.
    on(&s, 1, Do::Label(label(9, Some("carol"))), now);
    on(&s, 0, Do::Label(label(7, Some("bob"))), now);
    fetch_from(&s, &[1], 2, now);
    on(&s, 2, Do::Label(label(9, Some("alice"))), now + 1);
    on(
        &s,
        2,
        Do::Subscribe(subscription(1, "github.com/owner/repo", true)),
        now + 1,
    );
    fetch_from(&s, &[2], 0, now + 2);
    assert_eq!(labelled(&s, 0, 9), Some(Some("alice".into())));
    // The settlement lists the laptop and the desktop, and neither keeps
    // nor removes the phone.
    s.now = now + 3;
    s.change(0, &[0, 1], &[]);
    now = s.now + 1;
    give(&s, 0, 1, now);
    s.now = now;
    s.add(0, 3);
    now = s.now + 1;
    // A stranger's act, in the laptop's list.
    let stranger = device(0x55);
    let strangers = label(8, Some("mallory")).by(&stranger, u64::try_from(now).unwrap(), 0);
    let mut laptop_s = acts_of(&kept(&s, 0));
    laptop_s.push(strangers.clone());
    write_by_hand(&s, 0, laptop_s, now);
    for n in [0, 1, 3] {
        give(&s, 0, n, now);
        give(&s, 1, n, now);
        let holds = holds_worked_out(&s[n].conn, &s.key(n), now).unwrap();
        assert!(holds.passed_over.contains(&s.key(2)), "device {n}");
        assert!(
            holds.passed_over.contains(&stranger.public_key()),
            "device {n}"
        );
        // With how many acts of each the lists carry, each once (the
        // status's `passed_over`, decision 2026-10-10 §9).
        assert!(
            holds.passed_over_acts.contains(&(stranger.public_key(), 1)),
            "device {n}: {:?}",
            holds.passed_over_acts
        );
        assert!(
            holds
                .passed_over_acts
                .iter()
                .any(|(key, acts)| *key == s.key(2) && *acts > 0),
            "device {n}"
        );
        assert_eq!(holds.passed_over_acts.len(), holds.passed_over.len());
    }
    all_fetch(&s, &[0, 1, 3], now, 3);
    for n in [0, 1, 3] {
        // The desktop's label is the newest valid act on the key.
        assert_eq!(labelled(&s, n, 9), Some(Some("carol".into())), "device {n}");
        assert_eq!(labelled(&s, n, 7), Some(Some("bob".into())), "device {n}");
        assert_eq!(
            subscribes(&s, n, 1, "github.com/owner/repo"),
            None,
            "device {n}"
        );
        assert_eq!(labelled(&s, n, 8), None, "device {n}");
        // Every device has written its list again: no list it reads
        // carries the phone's acts.
        let holds = holds_worked_out(&s[n].conn, &s.key(n), now + 5).unwrap();
        assert!(!holds.passed_over.contains(&s.key(2)), "device {n}");
    }
    // The laptop is removed: the stranger's act, which no list carries
    // now, is passed over still.
    s.now = now + 10;
    s.change(1, &[1, 3], &[0]);
    now = s.now + 1;
    give(&s, 1, 3, now);
    all_fetch(&s, &[1, 3], now, 2);
    for n in [1, 3] {
        assert_eq!(labelled(&s, n, 8), None, "device {n}");
        assert_eq!(labelled(&s, n, 9), Some(Some("carol".into())), "device {n}");
        // The laptop's own label stays in force, as a removed key's.
        let holds = holds(&s[n].conn).unwrap();
        let of_7 = holds.labels.iter().find(|(a, _)| a.item.key == [7; 32]);
        assert_eq!(
            of_7.map(|(_, maker)| *maker),
            Some(Maker::Removed),
            "device {n}"
        );
    }
}

/// The sequences that opened each hole of slice 3's three reviews
/// (decision 2026-10-10 §13, property 26, T23): an act of a key never a
/// device of the person's, the newest on its item, is passed over and
/// leaves the honest act in force on every device; a phone's drop, newer
/// than a filing, left in no list by a settlement, with a tablet added
/// afterwards that fetched while a list still carried the filing: laptop,
/// desktop and tablet each hold the channel in force, the phone's drop
/// being passed over on all three; once the phone is added again, all
/// four hold it dropped; and a drop by a device that
/// counts, run past 90 days and past a year in both orders of fetching,
/// with a tablet added while a list still carried the filing and a
/// statement in the gap: all hold the same, and none holds the channel.
#[test]
fn three_reviews_of_slice_3_converge() {
    // The first: a stranger's act, newest on its item.
    {
        let s = person(2, 2);
        let now = s.now + 10;
        on(&s, 1, Do::File(filing(1, "review")), now);
        on(&s, 0, Do::Label(label(3, Some("bob"))), now + 1);
        fetch_from(&s, &[0], 1, now + 1);
        let stranger = device(0x66);
        // The stranger's undo of the laptop's label, newer, in the list
        // the desktop writes by hand.
        let stranger_undo = label(3, None).by(&stranger, u64::try_from(now).unwrap() + 100, 0);
        let mut by_hand = acts_of(&kept(&s, 1));
        by_hand.retain(|act| act.key() != stranger_undo.key());
        by_hand.push(stranger_undo);
        write_by_hand(&s, 1, by_hand, now + 2);
        all_fetch(&s, &[0, 1], now + 3, 3);
        for n in 0..2 {
            assert_eq!(labelled(&s, n, 3), Some(Some("bob".into())), "device {n}");
            assert_eq!(filed(&s, n), ["review"], "device {n}");
        }
    }

    // The second: the settlement, the phone's drop, and a tablet.
    {
        let mut s = person(4, 3);
        let mut now = s.now + 10;
        on(&s, 1, Do::File(filing(1, "review")), now + 1);
        for n in [0, 2] {
            fetch_from(&s, &[1], n, now + 2);
            assert_eq!(filed(&s, n), ["review"], "device {n}");
        }
        on(&s, 2, Do::Drop(channel(1)), now + 3);
        fetch_from(&s, &[2], 0, now + 4);
        assert!(filed(&s, 0).is_empty());
        s.now = now + 5;
        s.change(0, &[0, 1], &[]);
        now = s.now + 1;
        give(&s, 0, 1, now);
        s.now = now;
        s.add(0, 3);
        now = s.now + 1;
        // The tablet fetches while the desktop's list still carries the
        // filing.
        fetch_from(&s, &[1], 3, now);
        all_fetch(&s, &[0, 1, 3], now + 1, 3);
        for n in [0, 1, 3] {
            assert_eq!(filed(&s, n), ["review"], "device {n}");
        }
        // The phone is added again: its own list brings its drop back.
        s.now = now + 10;
        s.add(0, 2);
        now = s.now + 1;
        all_fetch(&s, &[0, 1, 2, 3], now, 3);
        for n in 0..4 {
            assert!(filed(&s, n).is_empty(), "device {n}");
            let holds = holds(&s[n].conn).unwrap();
            assert_eq!(holds.drops.len(), 1, "device {n}");
            assert_eq!(holds.drops[0].1, Maker::Counts, "device {n}");
        }
    }

    // The third: a drop past 90 days and past a year, in both orders.
    for laptop_first in [false, true] {
        for gap in [91 * DAY, 400 * DAY] {
            let mut s = person(4, 3);
            let mut now = s.now + 10;
            on(&s, 1, Do::File(filing(1, "review")), now + 1);
            all_fetch(&s, &[0, 1, 2], now + 2, 1);
            on(&s, 0, Do::Drop(channel(1)), now + 3);
            now += gap;
            // A statement in the gap, and a tablet added while the
            // desktop's list still carries the filing.
            s.now = now;
            s.change(0, &[0, 1, 2], &[]);
            now = s.now + 1;
            for n in [1, 2] {
                give(&s, 0, n, now);
            }
            s.now = now;
            s.add(1, 3);
            now = s.now + 1;
            fetch_from(&s, &[1], 3, now);
            let order: Vec<usize> = if laptop_first {
                vec![0, 1, 2, 3]
            } else {
                vec![3, 2, 1, 0]
            };
            all_fetch(&s, &order, now + 1, 3);
            for n in 0..4 {
                assert!(filed(&s, n).is_empty(), "device {n}, gap {gap}");
                assert_eq!(kept(&s, n), kept(&s, 0), "device {n}, gap {gap}");
            }
        }
    }
}

/// A subscription dated a day ahead of the desktop's clock is taken by
/// the desktop; an unsubscription the desktop makes at once is dated
/// above it, and wins on every device (decision 2026-10-10 §3.4): no act
/// is refused for a clock.
#[test]
fn a_word_dated_ahead_is_followed_by_the_next_act() {
    let s = person(3, 3);
    let now = s.now + 10;
    let ahead = now + DAY;
    let made = on(&s, 0, Do::Subscribe(subscription(1, "notes", true)), ahead);
    assert_eq!(at(&made[0]), ahead + 1);
    fetch_from(&s, &[0], 2, now + 1);
    fetch_from(&s, &[0], 1, now + 1);
    assert_eq!(subscribes(&s, 1, 1, "notes"), Some(true));
    let undone = on(
        &s,
        1,
        Do::Subscribe(subscription(1, "notes", false)),
        now + 2,
    );
    assert_eq!(at(&undone[0]), ahead + 2);
    all_fetch(&s, &[0, 1, 2], now + 3, 2);
    for n in 0..3 {
        assert_eq!(subscribes(&s, n, 1, "notes"), Some(false), "device {n}");
    }
}

/// The two devices that stay in [`undone_at_the_bound`], each with the
/// other.
const STAY: [(usize, usize); 2] = [(1, 3), (3, 1)];

/// The device removed in [`undone_at_the_bound`].
const THIEF: usize = 0;

/// Two devices of the person's, with the subscription that a third, in
/// someone else's hands, made at the bound undone after its removal by
/// device `undoer`: dated at the bound with a count of 1, since no act at
/// the bound there has a maker that counts. Returns when the undo was
/// made.
fn undone_at_the_bound(undoer: usize) -> (Several, i64) {
    let mut s = person(4, 4);
    let mut now = s.now + 10;
    let bound = i64::try_from(SHARED_ACT_TIME_MAX).unwrap();
    let made = on(
        &s,
        THIEF,
        Do::Subscribe(subscription(1, "notes", true)),
        bound,
    );
    assert_eq!((made[0].time(), made[0].count()), (SHARED_ACT_TIME_MAX, 1));
    for (n, _) in STAY {
        fetch_from(&s, &[THIEF], n, now + 1);
        assert_eq!(subscribes(&s, n, 1, "notes"), Some(true), "device {n}");
    }
    let before: Vec<SharedList> = STAY.iter().map(|(n, _)| kept(&s, *n)).collect();
    s.now = now + 2;
    s.change(1, &[1, 3], &[THIEF]);
    now = s.now + 1;
    give(&s, 1, 3, now);
    for (n, other) in STAY {
        give(&s, n, other, now);
    }
    // The statement carries each list as it is.
    for (at, (n, _)) in STAY.into_iter().enumerate() {
        assert_eq!(written_entry(&s, n).unwrap().1, before[at], "device {n}");
    }
    let other = if undoer == 1 { 3 } else { 1 };
    let made_at = now + 1;
    let undone = on(
        &s,
        undoer,
        Do::Subscribe(subscription(1, "notes", false)),
        made_at,
    );
    assert_eq!(
        (undone[0].time(), undone[0].count()),
        (SHARED_ACT_TIME_MAX, 1)
    );
    fetch_from(&s, &[undoer], other, made_at + 1);
    fetch_from(&s, &[other], undoer, made_at + 1);
    (s, made_at)
}

/// The phone subscribes a folder at `SHARED_ACT_TIME_MAX`, and the desktop
/// copies it; the phone is removed; the laptop's unsubscription goes above
/// it at the same time, since its maker counts, and is taken on every
/// device; the statement carries every list unchanged (decision
/// 2026-10-10 §3.4).
#[test]
fn an_act_at_the_bound_leaves_room_to_undo_it() {
    let (s, _) = undone_at_the_bound(1);
    for (n, _) in STAY {
        assert_eq!(subscribes(&s, n, 1, "notes"), Some(false), "device {n}");
        let held = kept(&s, n);
        let act = &held.subscriptions[0];
        assert_eq!(
            (act.time, act.count, act.maker),
            (SHARED_ACT_TIME_MAX, 1, s.key(1))
        );
    }
}

/// After that undo, the other device, whose key is the lower, subscribes
/// the folder at the bound with a count above the undo's; then the device
/// that undid it unsubscribes it, with a count above that. Each takes
/// effect on every device, by its count, and no other item's acts are
/// dated at the bound (decision 2026-10-10 §3.4).
#[test]
fn two_acts_after_an_undo_at_the_bound_each_take_effect() {
    let (higher, lower) = (1, 3);
    let (s, made_at) = undone_at_the_bound(higher);
    let later = made_at + 100 * DAY;
    let sub = on(
        &s,
        lower,
        Do::Subscribe(subscription(1, "notes", true)),
        later,
    );
    assert_eq!((sub[0].time(), sub[0].count()), (SHARED_ACT_TIME_MAX, 2));
    fetch_from(&s, &[lower], higher, later + 1);
    for n in [higher, lower] {
        assert_eq!(subscribes(&s, n, 1, "notes"), Some(true), "device {n}");
    }
    let unsub = on(
        &s,
        higher,
        Do::Subscribe(subscription(1, "notes", false)),
        later + 2,
    );
    assert_eq!(
        (unsub[0].time(), unsub[0].count()),
        (SHARED_ACT_TIME_MAX, 3)
    );
    fetch_from(&s, &[higher], lower, later + 3);
    for n in [higher, lower] {
        assert_eq!(subscribes(&s, n, 1, "notes"), Some(false), "device {n}");
    }
    let other = on(&s, lower, Do::Label(label(4, Some("bob"))), later + 4);
    assert!(other[0].time() < SHARED_ACT_TIME_MAX);
    assert_eq!(other[0].count(), 0);
}

/// An undo is kept while the bounds allow (decision 2026-10-10 §3.4): the
/// desktop files a channel, the phone takes the filing, and the laptop
/// drops the channel; the phone is shut for a year; the drop is in every
/// list all that time; the phone, opened, takes the drop; no device ever
/// holds the channel. The same with a statement that removes a lost
/// tablet in the gap, applied by the laptop and the desktop on day 200
/// and by the phone when it is opened.
#[test]
fn an_undo_is_kept_while_the_bounds_allow() {
    for with_statement in [false, true] {
        let mut s = person(4, 4);
        let mut now = s.now + 10;
        on(&s, 1, Do::File(filing(1, "review")), now);
        fetch_from(&s, &[1], 2, now + 1);
        assert_eq!(filed(&s, 2), ["review"]);
        fetch_from(&s, &[1], 0, now + 1);
        on(&s, 0, Do::Drop(channel(1)), now + 2);
        for day in [1, 100, 199] {
            all_fetch(&s, &[0, 1], now + day * DAY, 1);
            for n in [0, 1] {
                assert!(filed(&s, n).is_empty(), "device {n}, day {day}");
                assert_eq!(kept(&s, n).drops.len(), 1, "device {n}, day {day}");
            }
        }
        if with_statement {
            s.now = now + 200 * DAY;
            s.change(0, &[0, 1, 2], &[3]);
            now = s.now + 1;
            give(&s, 0, 1, now);
            all_fetch(&s, &[0, 1], now, 2);
        }
        let opened = now + 365 * DAY;
        all_fetch(&s, &[0, 1], opened, 1);
        fetch_from(&s, &[0, 1], 2, opened + 1);
        all_fetch(&s, &[0, 1, 2], opened + 2, 2);
        for n in 0..3 {
            assert!(filed(&s, n).is_empty(), "device {n}");
            assert_eq!(kept(&s, n).drops.len(), 1, "device {n}");
        }
    }
}

/// A device away brings nothing back (decision 2026-10-10 §3.4, T16), off
/// and running with no relay reached, which are one in-process: the
/// desktop holds a filing and a subscription; the laptop drops the channel
/// and unsubscribes; a year passes; the desktop, back, takes the undoes
/// from the laptop's list and holds neither. And Alice's one laptop, with
/// three shared channels, two subscriptions and four labels, shut for a
/// year: opened, it holds all of them.
#[test]
fn a_device_away_brings_nothing_back() {
    for running in [false, true] {
        let s = person(2, 2);
        let now = s.now + 10;
        on(&s, 1, Do::File(filing(1, "review")), now);
        on(
            &s,
            1,
            Do::Subscribe(subscription(1, "notes", true)),
            now + 1,
        );
        fetch_from(&s, &[1], 0, now + 2);
        on(&s, 0, Do::Drop(channel(1)), now + 3);
        on(
            &s,
            0,
            Do::Subscribe(subscription(1, "notes", false)),
            now + 3,
        );
        if running {
            // Running with no relay: its fetches find nothing new.
            for day in [30, 200, 300] {
                fetch(&s, 1, now + day * DAY);
            }
        }
        let back = now + 365 * DAY;
        fetch_from(&s, &[0], 1, back);
        fetch_from(&s, &[1], 0, back + 1);
        for n in 0..2 {
            assert!(filed(&s, n).is_empty(), "device {n}");
            assert_eq!(subscribes(&s, n, 1, "notes"), Some(false), "device {n}");
        }
    }
    let mut s = Several::new(1);
    s.make_phrase(0);
    let now = s.now + 10;
    for seed in 1..=3 {
        on(&s, 0, Do::File(filing(seed, &format!("c{seed}"))), now);
    }
    for seed in 1..=2 {
        on(&s, 0, Do::Subscribe(subscription(seed, "notes", true)), now);
    }
    for key in 1..=4 {
        on(&s, 0, Do::Label(label(key, Some("k"))), now);
    }
    assert!(!fetch(&s, 0, now + 365 * DAY));
    assert_eq!(filed(&s, 0).len(), 3);
    assert_eq!(in_force(&s, 0).len(), 9);
}

/// No list is passed over for a clock (decision 2026-10-10 §3.4): a
/// device whose clock reads 1970 labels a key, and later removes the
/// label; every other device takes both; a device whose clock is a year
/// ahead takes the others' acts and the others take its; no undo is let
/// go by any clock.
#[test]
fn no_list_is_passed_over_for_a_clock() {
    let s = person(3, 3);
    let now = s.now + 10;
    let labelled_at = on(&s, 0, Do::Label(label(1, Some("bob"))), 0);
    assert_eq!(at(&labelled_at[0]), 1);
    all_fetch(&s, &[0, 1, 2], now, 1);
    for n in 0..3 {
        assert_eq!(labelled(&s, n, 1), Some(Some("bob".into())), "device {n}");
    }
    on(&s, 0, Do::Label(label(1, None)), 5);
    all_fetch(&s, &[0, 1, 2], now + 1, 1);
    for n in 0..3 {
        assert_eq!(labelled(&s, n, 1), Some(None), "device {n}");
    }
    let year = 365 * DAY;
    on(&s, 2, Do::Label(label(2, Some("carol"))), now + year);
    on(&s, 1, Do::Label(label(3, Some("dave"))), now + 2);
    all_fetch(&s, &[0, 1, 2], now + 3, 2);
    for n in 0..3 {
        assert_eq!(labelled(&s, n, 2), Some(Some("carol".into())), "device {n}");
        assert_eq!(labelled(&s, n, 3), Some(Some("dave".into())), "device {n}");
        assert_eq!(labelled(&s, n, 1), Some(None), "device {n}");
    }
    // Years later, by any clock, the undo is still written.
    all_fetch(&s, &[0, 1, 2], now + 10 * year, 1);
    for n in 0..3 {
        assert_eq!(labelled(&s, n, 1), Some(None), "device {n}");
    }
}

/// The remedies of a removal are never refused, in-process (decision
/// 2026-10-10 §3.4, T23): with 64 drops of nothing below them held, the
/// person removes a stolen laptop from the desktop; the phone applies the
/// statement and the tablet is off; `shared anew review` and then `shared
/// drop` on the desktop go through.
#[test]
fn the_remedies_of_a_removal_are_never_refused() {
    let mut s = person(4, 4);
    let mut now = s.now + 10;
    // 64 drops of nothing below them: filed and dropped, 16 at a time.
    for round in 0..4u8 {
        for n in 0..16u8 {
            let seed = 100 + round * 16 + n;
            on(&s, 1, Do::File(filing(seed, &format!("c{seed}"))), now);
        }
        for n in 0..16u8 {
            on(&s, 1, Do::Drop(channel(100 + round * 16 + n)), now + 1);
        }
        now += 2;
    }
    assert_eq!(kept(&s, 1).drops.len(), 64);
    on(&s, 1, Do::File(filing(1, "review")), now);
    all_fetch(&s, &[0, 1, 2], now + 1, 1);
    s.now = now + 2;
    s.change(1, &[1, 2, 3], &[0]);
    now = s.now + 1;
    give(&s, 1, 2, now);
    fetch(&s, 1, now);
    let anew = Do::Move {
        from: channel(1),
        to: Filing {
            came: Came::Moved(channel(1)),
            ..filing(2, "review")
        },
    };
    let made = on(&s, 1, anew, now + 1);
    assert_eq!(made.len(), 2);
    assert_eq!(filed(&s, 1), ["review"]);
    on(&s, 1, Do::Drop(channel(2)), now + 2);
    assert!(filed(&s, 1).is_empty());
    assert_eq!(kept(&s, 1).drops.len(), 64);
    fetch_from(&s, &[1], 2, now + 3);
    assert!(filed(&s, 2).is_empty());
}

/// A drop and a move take no place (decision 2026-10-10 §3.4): with 16
/// channels filed a 17th is refused, a drop frees a place at once, and a
/// move goes through with 16 held. A stolen phone's 16 filings, newer
/// than the person's, push the person's past the bound on every device,
/// and no device writes them again, so they are lost (§3.4, the costs);
/// once the phone is removed its filings stay in force, named as a
/// removed key's, and the person drops one to file its own again.
#[test]
fn a_drop_and_a_move_take_no_place() {
    let mut s = person(3, 3);
    let mut now = s.now + 10;
    for seed in 0..16 {
        on(&s, 0, Do::File(filing(seed, &format!("c{seed}"))), now + 1);
    }
    assert_eq!(
        refused(&s, 0, Do::File(filing(16, "c16")), now + 2),
        Refused::Full {
            part: Part::Channel,
            devices: Vec::new()
        }
    );
    // Filed again under another name, a channel takes its own place.
    on(&s, 0, Do::File(filing(3, "renamed")), now + 2);
    on(&s, 0, Do::Drop(channel(0)), now + 3);
    on(&s, 0, Do::File(filing(16, "c16")), now + 3);
    assert_eq!(kept(&s, 0).filings.len(), 16);
    on(
        &s,
        0,
        Do::Move {
            from: channel(1),
            to: Filing {
                came: Came::Moved(channel(1)),
                ..filing(17, "c1")
            },
        },
        now + 4,
    );
    let held = kept(&s, 0);
    assert_eq!(held.filings.len(), 16);
    assert_eq!(held.drops.len(), 2);
    assert!(filed(&s, 0).contains(&"renamed".to_string()));
    let persons: Vec<String> = filed(&s, 0);

    fetch_from(&s, &[0], 1, now + 5);
    let at_ = u64::try_from(now + 1000).unwrap();
    let phones: Vec<AnyAct> = (100..116)
        .map(|seed| filing(seed, &format!("p{seed}")).by(&s[2].identity, at_, 0))
        .collect();
    write_by_hand(&s, 2, phones, now + 6);
    for n in [0, 1] {
        fetch_from(&s, &[2], n, now + 7);
        let names = filed(&s, n);
        assert!(names.iter().all(|name| name.starts_with('p')), "{names:?}");
        assert_eq!(names.len(), 16);
    }
    // The person's 16 filings were pushed past the bound and written by
    // no device: once each holds the other's latest list, no list carries
    // them, and they are lost (§3.4, the costs).
    all_fetch(&s, &[0, 1], now + 7, 1);
    for n in [0, 1] {
        let worked = holds_worked_out(&s[n].conn, &s.key(n), now + 7).unwrap();
        assert!(worked.left_out.is_empty(), "device {n}");
        assert!(
            worked.filings.iter().all(|(act, _)| act.maker == s.key(2)),
            "device {n}"
        );
    }
    s.now = now + 8;
    s.change(0, &[0, 1], &[2]);
    now = s.now + 1;
    give(&s, 0, 1, now);
    all_fetch(&s, &[0, 1], now, 2);
    // Removed, the phone's filings stay in force as its acts, named; the
    // person's are not back. A new filing is refused until one of the
    // phone's is dropped, which is never refused.
    for n in [0, 1] {
        let holds = holds(&s[n].conn).unwrap();
        assert_eq!(holds.filings.len(), 16, "device {n}");
        assert!(
            holds
                .filings
                .iter()
                .all(|(act, maker)| act.maker == s.key(2) && *maker == Maker::Removed)
        );
    }
    assert_eq!(
        refused(&s, 0, Do::File(filing(3, "renamed")), now + 3),
        Refused::Full {
            part: Part::Channel,
            devices: Vec::new()
        }
    );
    on(&s, 0, Do::Drop(channel(100)), now + 3);
    on(&s, 0, Do::File(filing(3, "renamed")), now + 4);
    fetch_from(&s, &[0], 1, now + 5);
    for n in [0, 1] {
        let names = filed(&s, n);
        assert!(names.contains(&"renamed".to_string()), "device {n}");
        assert_eq!(names.len(), 16, "device {n}");
    }
    let _ = persons;
}

/// An act is refused where its part is full and it would take a new
/// place, where it drops or moves from a channel not filed, moves to one
/// filed, or undoes what is not there, and where what it holds cannot be
/// written in a list. A device that does not stand applied makes nothing.
#[test]
fn an_act_is_refused_past_its_part_and_where_it_has_nothing_to_do() {
    let mut s = person(2, 2);
    let now = s.now + 10;
    assert_eq!(refused(&s, 0, Do::Drop(channel(1)), now), Refused::NotFiled);
    let moved = Do::Move {
        from: channel(1),
        to: filing(2, "two"),
    };
    assert_eq!(refused(&s, 0, moved, now), Refused::NotFiled);
    on(&s, 0, Do::File(filing(1, "one")), now);
    on(&s, 0, Do::File(filing(2, "two")), now);
    let moved = Do::Move {
        from: channel(1),
        to: filing(2, "two"),
    };
    assert_eq!(refused(&s, 0, moved, now), Refused::Filed);
    let none = Do::Subscribe(subscription(1, "notes", false));
    assert_eq!(refused(&s, 0, none, now), Refused::NothingToUndo);
    assert_eq!(
        refused(&s, 0, Do::Label(label(1, None)), now),
        Refused::NothingToUndo
    );
    for k in 0..32u8 {
        on(
            &s,
            0,
            Do::Subscribe(subscription(1, &format!("a{k}"), true)),
            now,
        );
    }
    let more = Do::Subscribe(subscription(1, "a32", true));
    assert_eq!(
        refused(&s, 0, more, now),
        Refused::Full {
            part: Part::Subscription,
            devices: Vec::new()
        }
    );
    // Undone, a subscription keeps its place: an undo of nothing below
    // it, here, so a new one fits.
    on(&s, 0, Do::Subscribe(subscription(1, "a0", false)), now);
    let again = Do::Subscribe(subscription(1, "a0", false));
    assert_eq!(refused(&s, 0, again, now), Refused::NothingToUndo);
    on(&s, 0, Do::Subscribe(subscription(1, "a32", true)), now);
    for k in 0..64u8 {
        on(&s, 0, Do::Label(label(k, Some("k"))), now);
    }
    let more = Do::Label(label(64, Some("k")));
    assert_eq!(
        refused(&s, 0, more, now),
        Refused::Full {
            part: Part::Label,
            devices: Vec::new()
        }
    );
    on(&s, 0, Do::Label(label(1, Some("again"))), now);
    let long = Do::Label(label(2, Some(&"l".repeat(65))));
    on(&s, 0, Do::Label(label(1, None)), now);
    let again = Do::Label(label(1, None));
    assert_eq!(refused(&s, 0, again, now), Refused::NothingToUndo);
    assert!(matches!(
        refused(&s, 0, long, now),
        Refused::NotWritten(ListError::Label)
    ));
    let not_a_name = Do::File(filing(3, "Not A Name"));
    assert!(matches!(
        refused(&s, 0, not_a_name, now),
        Refused::NotWritten(ListError::Name)
    ));

    // Removed, the desktop makes nothing.
    s.now = now + 1;
    s.change(0, &[0], &[1]);
    give(&s, 0, 1, now + 2);
    let made = act(
        &s[1].conn,
        &s[1].identity,
        Do::File(filing(3, "three")),
        now + 2,
    );
    assert!(matches!(made, Err(PersonError::Stopped(_))), "{made:?}");
}

/// A device writes its list at each act of its own, at once, and where
/// what it works out differs from the list it last wrote; never for its
/// age, and with nothing in it that says when it was fetched (decision
/// 2026-10-10 §3.4, §20, item 1). A device that holds nothing writes no
/// list. A device brought back from a copy of its data reads its own
/// entry where that is at a higher revision than the list it kept.
#[test]
fn a_device_writes_its_list_at_an_act_and_where_it_changes_only() {
    let s = person(2, 2);
    let now = s.now + 10;
    assert!(!fetch(&s, 0, now));
    assert_eq!(written_entry(&s, 0), None);
    on(&s, 0, Do::Label(label(1, Some("bob"))), now + 5);
    let (rev, list) = written_entry(&s, 0).unwrap();
    assert_eq!(list, kept(&s, 0));
    assert_eq!(kept_rows::kept(&s[0].conn).unwrap().unwrap().rev, rev);
    // Nothing changed: not written again, a year on or not.
    assert!(!fetch(&s, 0, now + 6));
    assert!(!fetch(&s, 0, now + 365 * DAY));
    assert_eq!(written_entry(&s, 0).unwrap().0, rev);
    // The desktop's act, taken: written.
    on(&s, 1, Do::Label(label(2, Some("carol"))), now + 7);
    assert!(fetch_from(&s, &[1], 0, now + 8));
    let (again, _) = written_entry(&s, 0).unwrap();
    assert!(again > rev);

    // Brought back from a copy: the kept list is older than its entry.
    let older = kept_rows::Kept {
        list: list_of(Vec::new()).to_value(is_a_name).unwrap(),
        rev,
    };
    kept_rows::keep(&s[0].conn, &older).unwrap();
    // Its own entry, at the higher revision, is read: what it wrote since
    // the copy stays, and the list is written again in its place.
    assert!(fetch(&s, 0, now + 9));
    assert_eq!(labelled(&s, 0, 1), Some(Some("bob".into())));
    assert_eq!(labelled(&s, 0, 2), Some(Some("carol".into())));
}

/// A list is read only from its writer's own entry under its own list's
/// name, in the generation applied (decision 2026-10-10 §3.4): one in a
/// band above the statement's, or a delete, is passed over.
#[test]
fn a_list_is_read_only_from_its_writers_own_entry_under_the_statement() {
    let s = person(2, 2);
    let now = s.now + 10;
    on(&s, 1, Do::Label(label(4, Some("bob"))), now + 1);
    give(&s, 1, 0, now + 2);
    let read = |s: &Several| {
        let standing = Standing::to_write(&s[0].conn).unwrap();
        lists_read(&s[0].conn, &standing, &s.key(0)).unwrap()
    };
    assert_eq!(read(&s).len(), 1);
    assert_eq!(read(&s)[0].1.labels.len(), 1);

    let personal = s[1].personal();
    let name = list_name(&s.key(1)).unwrap();
    let above = (s[1].number() + 1) << cordelia_core::protocol::REV_COUNT_BITS;
    let inside = Inside {
        name: name.clone(),
        value: Value::Other(list_of(Vec::new()).to_value(is_a_name).unwrap()),
        chain: Some(Vec::new()),
    };
    let entry = Entry::seal(&personal, &s[1].identity, above, &inside).unwrap();
    entries::store(&s[0].conn, &entry.check().unwrap(), now + 3).unwrap();
    assert!(read(&s).is_empty());
    let id = derive::channel_id(&personal).unwrap();
    let slot = slot_id(&derive::slot_key(&personal).unwrap(), &name);
    s[0].conn
        .execute(
            "DELETE FROM entries WHERE channel_id = ?1 AND slot = ?2",
            rusqlite::params![id.as_slice(), slot.as_slice()],
        )
        .unwrap();
    let deleted = Inside {
        value: Value::Delete,
        ..inside
    };
    let entry = Entry::seal(&personal, &s[1].identity, 5, &deleted).unwrap();
    entries::store(&s[0].conn, &entry.check().unwrap(), now + 4).unwrap();
    assert!(read(&s).is_empty());
    // A list of a device's in another device's slot is no list of it.
    write_by_hand(
        &s,
        0,
        vec![label(6, Some("x")).by(&s[0].identity, 1, 0)],
        now + 5,
    );
    assert_eq!(read(&s).len(), 1);
}

/// The lists a recovery reads of the entries handed are each shown
/// device's own newest entry under its own list's name (decision
/// 2026-10-10 §3.5): not another device's entry in its slot, not a delete,
/// and nothing of a device not shown.
#[test]
fn the_lists_a_recovery_reads_are_each_shown_devices_own() {
    let s = person(3, 3);
    let personal = s[0].personal();
    let entry = |n: usize, of: usize, rev: u64, value: Value| {
        let inside = Inside {
            name: list_name(&s.key(of)).unwrap(),
            value,
            chain: Some(Vec::new()),
        };
        Entry::seal(&personal, &s[n].identity, rev, &inside)
            .unwrap()
            .check()
            .unwrap()
    };
    let of = |key: u8| {
        Value::Other(
            list_of(vec![label(key, Some("k")).by(&device(1), 1, 0)])
                .to_value(is_a_name)
                .unwrap(),
        )
    };
    let handed = [
        entry(0, 0, 1, of(1)),
        entry(0, 0, 2, of(2)),
        entry(1, 0, 3, of(3)),
        entry(1, 1, 1, of(4)),
        entry(1, 1, 2, Value::Delete),
        entry(2, 2, 1, of(5)),
    ];
    let key_of = |list: &SharedList| list.labels[0].item.key[0];
    let read = lists_in(&handed, &personal, &[s.key(0), s.key(1)]).unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].0, s.key(0));
    assert_eq!(key_of(&read[0].1), 2);
    let read = lists_in(&handed, &personal, &[s.key(2)]).unwrap();
    assert_eq!(read.iter().map(|(_, l)| key_of(l)).collect::<Vec<_>>(), [5]);
    let other = derive::personal_secret(&[9; 32]).unwrap();
    assert!(lists_in(&handed, &other, &[s.key(2)]).unwrap().is_empty());
}

/// An act made while the device reached no relay survives (decision
/// 2026-10-10 §3.4, "A list that never reached a relay"): the laptop
/// labels a key with no relay, while the desktop drops a channel; when
/// they meet, each takes the other's act by the order, and neither is
/// lost.
#[test]
fn an_act_made_with_no_relay_survives() {
    let s = person(2, 2);
    let now = s.now + 10;
    on(&s, 1, Do::File(filing(1, "review")), now);
    fetch_from(&s, &[1], 0, now + 1);
    on(&s, 0, Do::Label(label(4, Some("bob"))), now + 100 * DAY);
    on(&s, 1, Do::Drop(channel(1)), now + 2);
    all_fetch(&s, &[0, 1], now + 101 * DAY, 2);
    for n in 0..2 {
        assert_eq!(labelled(&s, n, 4), Some(Some("bob".into())), "device {n}");
        assert!(filed(&s, n).is_empty(), "device {n}");
    }
}

/// An act made with no relay survives coming back (decision 2026-10-10
/// §3.4, property 25, §13, T16): the desktop files a channel on day 0, and
/// every device takes it; from then the laptop reaches no relay, and goes
/// on running, its fetches finding nothing new, while the desktop and the
/// phone go on fetching and the desktop labels a key on day 50; on day 95
/// the laptop subscribes a folder; on day 100 it reaches a relay. The
/// subscription is in force on every device, and so are the filing of day
/// 0 and the label of day 50: no act and no list is passed over for its
/// age, or for how long its writer was away.
#[test]
fn an_act_made_with_no_relay_survives_coming_back() {
    let s = person(3, 3);
    let (desktop, laptop, phone) = (0, 1, 2);
    let day_0 = s.now + 10;
    on(&s, desktop, Do::File(filing(1, "review")), day_0);
    all_fetch(&s, &[desktop, laptop, phone], day_0 + 1, 2);
    for n in [desktop, laptop, phone] {
        assert_eq!(filed(&s, n), ["review"], "device {n}, day 0");
    }
    // The laptop reaches no relay from day 0; the others meet.
    on(
        &s,
        desktop,
        Do::Label(label(4, Some("bob"))),
        day_0 + 50 * DAY,
    );
    for day in [30, 60, 90] {
        assert!(!fetch(&s, laptop, day_0 + day * DAY), "day {day}");
        all_fetch(&s, &[desktop, phone], day_0 + day * DAY, 1);
    }
    assert_eq!(labelled(&s, laptop, 4), None);
    on(
        &s,
        laptop,
        Do::Subscribe(subscription(1, "notes", true)),
        day_0 + 95 * DAY,
    );
    assert!(!fetch(&s, laptop, day_0 + 97 * DAY));
    assert_eq!(subscribes(&s, laptop, 1, "notes"), Some(true));
    for n in [desktop, phone] {
        assert_eq!(subscribes(&s, n, 1, "notes"), None, "device {n}");
    }

    // Day 100: the laptop reaches a relay.
    all_fetch(&s, &[desktop, laptop, phone], day_0 + 100 * DAY, 3);
    for n in [desktop, laptop, phone] {
        assert_eq!(
            subscribes(&s, n, 1, "notes"),
            Some(true),
            "device {n}, day 100"
        );
        assert_eq!(filed(&s, n), ["review"], "device {n}, day 100");
        assert_eq!(
            labelled(&s, n, 4),
            Some(Some("bob".into())),
            "device {n}, day 100"
        );
    }
    // A year on, nothing of it has gone.
    all_fetch(&s, &[desktop, laptop, phone], day_0 + 465 * DAY, 2);
    for n in [desktop, laptop, phone] {
        assert_eq!(subscribes(&s, n, 1, "notes"), Some(true), "device {n}");
        assert_eq!(filed(&s, n), ["review"], "device {n}");
    }
}

/// What a thief past a bound leaves after its removal (decision
/// 2026-10-10 §3.4, the costs, and §13, T23), alone and with a device it
/// added by a record of addition (T20): with 14 channels, 25
/// subscriptions and 60 labels of the person's, a stolen device that
/// counts writes 16 filings, 32 subscriptions and 64 labels of its own,
/// dated after them; on every device the person's items are pushed past
/// the bounds and let go; the person removes the stolen device; its own
/// items in force stay, named as a removed key's, and the person's acts go
/// above them: an undo of one of its items is never refused, and the
/// person's item subscribed and labelled again after it is in force on
/// every device. The person's items it pushed out are not named.
#[test]
fn what_a_thief_past_a_bound_leaves_after_its_removal() {
    for with_an_added_device in [false, true] {
        let mut s = person(4, 3);
        let mut now = s.now + 10;
        for seed in 0..14 {
            on(&s, 0, Do::File(filing(seed, &format!("c{seed}"))), now);
        }
        for seed in 0..25 {
            on(&s, 0, Do::Subscribe(subscription(seed, "mine", true)), now);
        }
        for key in 0..60 {
            on(&s, 0, Do::Label(label(key, Some("mine"))), now);
        }
        all_fetch(&s, &[0, 1, 2], now + 1, 1);
        let thief = 2;
        let mut writers = vec![thief];
        if with_an_added_device {
            s.now = now + 2;
            s.add(thief, 3);
            now = s.now + 1;
            all_fetch(&s, &[0, 1, 2, 3], now, 1);
            writers.push(3);
        }
        // The thief's items, dated after the person's.
        let at_ = u64::try_from(now + 1_000).unwrap();
        let by = |n: usize| &s[n].identity;
        let mut theirs: Vec<Vec<AnyAct>> = vec![Vec::new(); writers.len()];
        for (w, n) in writers.iter().enumerate() {
            let share = |count: usize| (w * count / writers.len(), (w + 1) * count / writers.len());
            let (a, b) = share(16);
            theirs[w].extend((a..b).map(|i| filing(100 + i as u8, "t").by(by(*n), at_, 0)));
            let (a, b) = share(32);
            theirs[w].extend(
                (a..b).map(|i| subscription(100 + i as u8, "theirs", true).by(by(*n), at_, 0)),
            );
            let (a, b) = share(64);
            theirs[w]
                .extend((a..b).map(|i| label(100 + i as u8, Some("theirs")).by(by(*n), at_, 0)));
        }
        for (w, n) in writers.iter().enumerate() {
            write_by_hand(&s, *n, theirs[w].clone(), now + 2);
        }
        let mut everyone = vec![0, 1];
        everyone.extend(writers.iter().copied());
        all_fetch(&s, &everyone, now + 3, 2);
        for n in [0, 1] {
            assert!(filed(&s, n).iter().all(|name| name == "t"), "device {n}");
            assert_eq!(subscribes(&s, n, 0, "mine"), None, "device {n}");
            assert_eq!(labelled(&s, n, 0), None, "device {n}");
        }
        // Removed: the thief, and the device it added.
        s.now = now + 10;
        s.change(0, &[0, 1], &writers);
        now = s.now + 1;
        give(&s, 0, 1, now);
        all_fetch(&s, &[0, 1], now, 2);
        for n in [0, 1] {
            let holds = holds(&s[n].conn).unwrap();
            assert_eq!(holds.filings.len(), 16, "device {n}");
            assert!(holds.filings.iter().all(|(_, m)| *m == Maker::Removed));
            assert_eq!(holds.subscriptions.len(), 32, "device {n}");
            assert!(
                holds
                    .subscriptions
                    .iter()
                    .all(|(_, m)| *m == Maker::Removed)
            );
            assert_eq!(holds.labels.len(), 64, "device {n}");
            // The person's own pushed out: not carried, not named.
            assert!(
                holds_worked_out(&s[n].conn, &s.key(n), now)
                    .unwrap()
                    .left_out
                    .is_empty()
            );
        }
        // The person undoes one of the thief's, never refused; while a
        // list still carries the act below that undo, it keeps a place,
        // and a new item is refused naming those devices. Once every
        // device has written its list, the undo is of nothing below it,
        // and the person's own goes in again; labels the same.
        on(
            &s,
            0,
            Do::Subscribe(subscription(100, "theirs", false)),
            now + 1,
        );
        on(&s, 0, Do::Label(label(100, None)), now + 1);
        assert!(matches!(
            refused(&s, 0, Do::Subscribe(subscription(0, "mine", true)), now + 1),
            Refused::Full {
                part: Part::Subscription,
                ..
            }
        ));
        all_fetch(&s, &[0, 1], now + 2, 2);
        on(&s, 0, Do::Subscribe(subscription(0, "mine", true)), now + 4);
        on(&s, 0, Do::Label(label(0, Some("mine"))), now + 4);
        all_fetch(&s, &[0, 1], now + 5, 2);
        for n in [0, 1] {
            assert_eq!(subscribes(&s, n, 0, "mine"), Some(true), "device {n}");
            assert_eq!(labelled(&s, n, 0), Some(Some("mine".into())), "device {n}");
            // The undo, now of nothing below it, ranks last and falls past
            // the 32: the item is not in force either way.
            assert_ne!(subscribes(&s, n, 100, "theirs"), Some(true), "device {n}");
        }
    }
}

/// A device writes its list again when it applies a statement, with no
/// fetch (decision 2026-10-10 §3.4, "What a device writes"): the phone's
/// label, copied by the laptop and the desktop, is passed over once a
/// settlement leaves the phone in no list, and the desktop, handed the
/// change at the door, writes a list without it at once.
#[test]
fn a_statement_applied_writes_the_list_again() {
    let mut s = person(3, 3);
    let mut now = s.now + 10;
    on(&s, 2, Do::Label(label(5, Some("theirs"))), now);
    on(&s, 0, Do::Label(label(6, Some("mine"))), now);
    all_fetch(&s, &[0, 1, 2], now + 1, 2);
    assert_eq!(labelled(&s, 1, 5), Some(Some("theirs".into())));
    let (before, _) = written_entry(&s, 1).unwrap();
    s.now = now + 3;
    s.change(0, &[0, 1], &[]);
    now = s.now + 1;
    give(&s, 0, 1, now);
    assert_eq!(labelled(&s, 1, 5), None);
    assert_eq!(labelled(&s, 1, 6), Some(Some("mine".into())));
    let (after, list) = written_entry(&s, 1).unwrap();
    assert!(after > before);
    assert_eq!(list, kept(&s, 1));
}

/// When this device took an act, by its signature.
fn taken_of(s: &Several, n: usize, act: &AnyAct) -> Option<Taken> {
    kept_rows::taken(&s[n].conn)
        .unwrap()
        .into_iter()
        .find_map(|(signature, taken)| (signature == act.signature()).then_some(taken.taken))
}

/// An act's time of taking is when the door first stored a list that
/// brings it, though the device worked nothing out then; and it keeps
/// that time when its maker is removed later, so that the removal's cut
/// reads it, and not the time the lists were worked out again (decision
/// 2026-10-10 property 9, §20 item 7; the review of slice 3 again,
/// medium 2).
#[test]
fn an_act_is_taken_when_the_door_first_stores_a_list_that_brings_it() {
    let mut s = person(3, 3);
    let now = s.now + 10;
    // The tablet's act, copied by the laptop, whose store the desktop is
    // given: the desktop stores the lists and works nothing out.
    let made = on(&s, 2, Do::Label(label(7, Some("tablet's"))), now + 1);
    fetch_from(&s, &[2], 0, now + 2);
    give(&s, 0, 1, now + 3);
    let first = Taken {
        generation: s[1].number(),
        taken_at: now + 3,
    };
    assert_eq!(taken_of(&s, 1, &made[0]), Some(first));
    // Given again later, it keeps its time.
    give(&s, 0, 1, now + 4);
    assert_eq!(taken_of(&s, 1, &made[0]), Some(first));
    // The tablet removed: the desktop applies the statement at its door
    // and works its lists out again; the act, from the laptop's copy,
    // keeps the time it was first held.
    s.now = now + 10;
    s.change(0, &[0, 1], &[2]);
    give(&s, 0, 1, s.now + 1);
    assert!(s[1].number() > first.generation);
    assert_eq!(taken_of(&s, 1, &made[0]), Some(first));
    // Worked out in the new generation, the act stays, named as the
    // removed tablet's, and keeps its time.
    fetch(&s, 1, s.now + 2);
    assert_eq!(labelled(&s, 1, 7), Some(Some("tablet's".into())));
    assert_eq!(taken_of(&s, 1, &made[0]), Some(first));
}

/// An error in the person's lists takes back nothing at the door: a list
/// kept that no longer reads does not stop a statement from being
/// applied (the review of slice 3 again, low 5).
#[test]
fn an_error_in_the_lists_takes_back_no_statement() {
    let mut s = person(2, 2);
    kept_rows::keep(
        &s[1].conn,
        &kept_rows::Kept {
            list: vec![9; 5],
            rev: 1,
        },
    )
    .unwrap();
    assert!(holds(&s[1].conn).is_err());
    let before = s[1].number();
    s.now += 10;
    s.change(0, &[0, 1], &[]);
    give(&s, 0, 1, s.now + 1);
    assert!(s[1].number() > before);
    assert_eq!(s[1].number(), s[0].number());
}

/// A whole fetch whose database cannot be read says so.
#[test]
fn a_whole_fetch_that_cannot_read_the_database_says_so() {
    let s = person(1, 1);
    s[0].conn.execute("DROP TABLE shared_lists", []).unwrap();
    assert!(fetched_whole(&s[0].conn, &s[0].identity, s.now + 1).is_err());
}

// ── A whole fetch that finds nothing new ─────────────────────────────────

/// A copy of `conn` in a file at `path`, opened as the node opens its
/// store: its commits go to a write-ahead log, whose frames can be counted.
fn on_disk(conn: &rusqlite::Connection, path: &std::path::Path) -> rusqlite::Connection {
    conn.execute("VACUUM INTO ?1", [path.to_str().unwrap()])
        .unwrap();
    cordelia_storage::db::open_as(path, true).unwrap()
}

/// How many pages `work` wrote to the write-ahead log of `conn`: a write
/// that changes no row, as a delete of every row of an empty table, is
/// counted as any other.
fn frames_written(conn: &rusqlite::Connection, work: impl FnOnce()) -> i64 {
    let truncate = "PRAGMA wal_checkpoint(TRUNCATE)";
    let busy: i64 = conn.query_row(truncate, [], |row| row.get(0)).unwrap();
    assert_eq!(busy, 0);
    work();
    let frames = "PRAGMA wal_checkpoint(PASSIVE)";
    conn.query_row(frames, [], |row| row.get(1)).unwrap()
}

/// A whole fetch that finds the lists as they were writes nothing (decision
/// 2026-10-10 §3.4, "what a device writes"): a device works its lists out
/// at every whole pass, and one that changed nothing commits no page under
/// the node's lock. Two devices of one person hold a channel filed and a
/// key labelled, with an act of each taken; each then fetches ten times
/// with nothing new. Neither the rows of when it took each act, nor the
/// keys labelled, nor the row of the channel it holds is written again;
/// nor, on a device whose person holds no shared channel, are the empty
/// tables of either.
#[test]
fn a_whole_fetch_that_finds_nothing_new_writes_nothing() {
    let alone = person(1, 1);
    let dir = tempfile::tempdir().unwrap();
    let conn = on_disk(&alone[0].conn, &dir.path().join("alone.db"));
    let written = frames_written(&conn, || {
        for pass in 0..10 {
            let wrote = fetched_whole(&conn, &alone[0].identity, alone.now + pass).unwrap();
            assert!(!wrote, "pass {pass}");
        }
    });
    assert_eq!(written, 0, "a device of a person with no shared channel");

    let s = person(2, 2);
    let now = s.now + 10;
    on(&s, 0, Do::File(filing(1, "review")), now + 1);
    on(&s, 0, Do::Label(label(9, Some("bob"))), now + 2);
    all_fetch(&s, &[0, 1], now + 3, 2);
    for n in 0..2 {
        let conn = on_disk(&s[n].conn, &dir.path().join(format!("{n}.db")));
        assert_eq!(kept_rows::taken(&conn).unwrap().len(), 2, "device {n}");
        let labelled = cordelia_storage::shared::labelled(&conn).unwrap();
        assert_eq!(labelled, [[9; 32]], "device {n}");
        let held = cordelia_storage::shared::channel(&conn, &channel(1)).unwrap();
        assert!(held.is_some(), "device {n}");
        let written = frames_written(&conn, || {
            for pass in 0..10 {
                let wrote = fetched_whole(&conn, &s[n].identity, now + 10 + pass).unwrap();
                assert!(!wrote, "device {n}, pass {pass}");
            }
        });
        assert_eq!(written, 0, "device {n}");
    }
}

// ── A channel that is not written ────────────────────────────────────────

/// Sync on, on each device of `s`: the door takes a shared channel's
/// entries only where it is.
fn sync_on(s: &Several) {
    for machine in &s.machines {
        cordelia_storage::meta::set(
            &machine.conn,
            cordelia_storage::meta::SYNC_CLAUDE_DIR,
            "/home/bob/.claude",
        )
        .unwrap();
    }
}

/// Device `n` makes a whole fetch at `now`, having been given what each of
/// `from` holds, and ends the take-outs it began, as its next pass does.
fn fetch_out(s: &Several, from: &[usize], n: usize, now: i64) {
    fetch_from(s, from, n, now);
    crate::shared::tests::out(s, n, now);
}

/// How many rows of first holding device `n` keeps of `channel`.
fn first_held_rows(s: &Several, n: usize, channel: &crate::shared::tests::Shared) -> i64 {
    rows_in(s, n, channel, "shared_first_held")
}

/// How many rows of `table` device `n` keeps of `channel`.
fn rows_in(s: &Several, n: usize, channel: &crate::shared::tests::Shared, table: &str) -> i64 {
    let id = crate::shared::tests::row(s, n, channel).id;
    s[n].conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE channel = ?1"),
            [id],
            |row| row.get(0),
        )
        .unwrap()
}

/// A channel that is not written keeps no entries (decision 2026-10-10
/// §3.4, property 22, §13 under property 25). The phone files `review`,
/// and every device holds it; a member writes there, and another key of
/// a member, quiet for 30 days, is let go, its row keeping its revisions;
/// the phone is shut, its list still carrying the filing. The laptop and
/// the desktop, apart, file sixteen more between them: the filing of
/// `review`, the oldest, is pushed past the bound on both. Each takes its
/// entries and index rows out of its store, and keeps its table of keys,
/// with the let-go key's revisions, and its rows of first holding, while
/// a list carries an act on it; it can be dropped. Back within the bound,
/// once the laptop drops a channel, it is read again from its start: the
/// let-go key's old entry is refused, a message shown before is shown
/// under its first holding and not as new, and what was fetched of it is
/// forgotten, so the first send there fetches first (`not_fetched`).
/// Pushed past the bound once more, `shared anew` on it writes its offer
/// there. A channel the laptop filed, pushed past the bound by its own
/// filings and carried by no list once each device wrote its list again,
/// keeps no entry and no row on any device.
///
/// **The drop path:** a drop that is the newest valid act empties the
/// channel's entries and index rows, and keeps its other rows while it is
/// written; with five old lists carrying 80 filings and 65 drops, the
/// oldest drop, the channel's, is let go, and its filing comes back where
/// the 16 have room. The device wrote an act on the channel throughout, so
/// its rows stayed (the person's ruling of 30 October): a message under 30
/// days old is shown under its first holding, not as new, and the empty
/// anew record is written again. The rows go only where no list carries an
/// act on the channel (`b`, above).
#[test]
fn a_channel_not_written_keeps_no_entries() {
    use crate::shared::tests::{
        Shared, given, hourly, indexed, key_row, key_rows, member, message, row, stores,
    };
    use crate::state::OwnChannels;
    use cordelia_storage::shared::State;
    use std::time::Instant;

    let s = person(3, 3);
    sync_on(&s);
    let (laptop, desktop, phone) = (0, 1, 2);
    let t0 = s.now + 10;
    on(&s, phone, Do::File(filing(1, "review")), t0);
    all_fetch(&s, &[laptop, desktop, phone], t0 + 1, 2);
    let review = Shared::of(1);
    for n in [laptop, desktop] {
        crate::shared::tests::out(&s, n, t0 + 1);
        assert_eq!(row(&s, n, &review).state, State::Held, "device {n}");
    }
    // A member's key writes, and goes quiet; another writes 31 days on.
    let (quiet, writer) = (member(2), member(1));
    let old = message(&quiet, &review, 1, "quiet", t0 + 2);
    let t1 = t0 + 31 * DAY;
    let fresh = message(&writer, &review, 1, "fresh", t1);
    let mut first_shown = 0;
    for n in [laptop, desktop] {
        stores(&s, n, &old, t0 + 2);
        stores(&s, n, &fresh, t1);
        hourly(&s[n].conn, &s.key(n), t1 + 1).unwrap();
        let kept = key_row(&s, n, &review, &quiet.public_key()).unwrap();
        assert!(kept.kept_message_rev.is_some(), "device {n}");
        let shown = crate::shared::shown(&s[n].conn, &s[n].identity, &review.id, t1 + 2).unwrap();
        assert_eq!(shown.len(), 1, "device {n}");
        assert_eq!(shown[0].body, "fresh");
        first_shown = shown[0].first_held;
    }
    assert_eq!(first_shown, t1);
    // The pass fetched it, and kept a place at its relay.
    let own_channels = OwnChannels::default();
    own_channels.fetched_from(&review.id, "relay.example.org:9474", Instant::now());
    assert!(own_channels.shared_fetch_done(&review.id, 1, Instant::now()));
    for n in [laptop, desktop] {
        let id = row(&s, n, &review).id;
        cordelia_storage::shared_pass::keep_place(&s[n].conn, id, &[3; 32], &[1; 8], 7).unwrap();
    }

    // The phone is shut. The laptop files `b`, then the laptop and the
    // desktop file eight each, apart.
    let t2 = t1 + 10;
    on(&s, laptop, Do::File(filing(2, "b")), t2);
    let b = Shared::of(2);
    crate::shared::tests::out(&s, laptop, t2);
    stores(&s, laptop, &message(&writer, &b, 1, "in b", t2), t2);
    for k in 0..8u8 {
        on(
            &s,
            laptop,
            Do::File(filing(10 + k, &format!("l{k}"))),
            t2 + 1 + i64::from(k),
        );
        on(
            &s,
            desktop,
            Do::File(filing(20 + k, &format!("d{k}"))),
            t2 + 1 + i64::from(k),
        );
    }
    // The laptop ends its take-outs as the node does, and forgets what it
    // fetched of each channel whose take-out ended.
    let fetch_out_at_laptop = |now: i64| {
        fetch_from(&s, &[desktop], laptop, now);
        let done = crate::shared::take_out_all(&s[laptop].conn, &s.key(laptop), now).unwrap();
        for channel in &done.ended {
            own_channels.forget_fetched(channel);
        }
        done.ended
    };
    let mut ended = Vec::new();
    for round in 0..3 {
        let now = t2 + 20 + round;
        ended.extend(fetch_out_at_laptop(now));
        fetch_out(&s, &[laptop], desktop, now);
    }
    assert!(ended.contains(&review.id), "the take-out of review ended");
    let t3 = t2 + 30;
    for n in [laptop, desktop] {
        assert!(!filed(&s, n).contains(&"review".to_string()), "device {n}");
        assert_eq!(filed(&s, n).len(), 16, "device {n}");
        assert_eq!(row(&s, n, &review).state, State::NotInForce, "device {n}");
        assert!(s[n].stored_in(&review.secret).is_empty(), "device {n}");
        assert_eq!(indexed(&s, n, &review), 0, "device {n}");
        // Its rows stay: the table of keys, the let-go key's revisions,
        // and the rows of first holding and of H.
        assert_eq!(key_rows(&s, n, &review).len(), 2, "device {n}");
        let kept = key_row(&s, n, &review, &quiet.public_key()).unwrap();
        assert!(kept.kept_message_rev.is_some(), "device {n}");
        assert!(first_held_rows(&s, n, &review) > 0, "device {n}");
        assert_eq!(rows_in(&s, n, &review, "shared_signers"), 2, "device {n}");
        assert_eq!(rows_in(&s, n, &review, "shared_numbers"), 0, "device {n}");
        assert!(
            crate::shared::shown(&s[n].conn, &s[n].identity, &review.id, t3)
                .unwrap()
                .is_empty()
        );
        // It can be dropped.
        assert!(
            crate::sharing::drop_plan(&s[n].conn, &s[n].identity, "review", None, t3).is_ok(),
            "device {n}"
        );
        // `b`, carried by no list, keeps no entry and no row: its row in
        // the table is gone, and with it every row keyed by it.
        assert!(
            cordelia_storage::shared::channel(&s[n].conn, &b.id)
                .unwrap()
                .is_none(),
            "device {n}"
        );
        for table in [
            "shared_keys",
            "shared_index",
            "shared_first_held",
            "shared_signers",
            "shared_places",
        ] {
            let left: i64 = s[n]
                .conn
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {table} WHERE channel NOT IN
                         (SELECT id FROM shared_channels)"
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(left, 0, "device {n}, {table}");
        }
        assert!(s[n].stored_in(&b.secret).is_empty(), "device {n}");
    }
    // What it fetched of the channel was forgotten where its take-out
    // ended.
    assert!(!own_channels.shared_fetch_done(&review.id, 1, Instant::now()));

    // Back within the bound: the laptop drops one of its own.
    on(&s, laptop, Do::Drop(channel(10)), t3 + 1);
    for round in 0..3 {
        let now = t3 + 2 + round;
        fetch_out(&s, &[desktop], laptop, now);
        fetch_out(&s, &[laptop], desktop, now);
    }
    let t4 = t3 + 10;
    for n in [laptop, desktop] {
        assert!(filed(&s, n).contains(&"review".to_string()), "device {n}");
        let held = row(&s, n, &review);
        assert_eq!(held.state, State::Held, "device {n}");
        // Read again from its start.
        assert!(
            cordelia_storage::shared_pass::place(&s[n].conn, held.id, &[3; 32])
                .unwrap()
                .is_none(),
            "device {n}"
        );
        // The let-go key's old entry is refused, with no new row.
        let before = key_row(&s, n, &review, &quiet.public_key());
        assert_eq!(
            given(&s, n, &old, t4),
            crate::take::Taken::Refused(crate::take::NotTaken::SharedFull),
            "device {n}"
        );
        assert_eq!(key_row(&s, n, &review, &quiet.public_key()), before);
        // A message shown before is shown under its first holding.
        stores(&s, n, &fresh, t4);
        let shown = crate::shared::shown(&s[n].conn, &s[n].identity, &review.id, t4).unwrap();
        assert_eq!(shown.len(), 1, "device {n}");
        assert_eq!(shown[0].body, "fresh");
        assert_eq!(shown[0].first_held, first_shown, "device {n}: shown as new");
    }
    // For sending it is as after a start: fetched again first.
    assert!(!own_channels.shared_fetch_done(&review.id, 1, Instant::now()));

    // Past the bound once more, `shared anew` on it writes its offer.
    on(&s, laptop, Do::Drop(channel(11)), t4 + 1);
    for round in 0..2 {
        let now = t4 + 2 + round;
        fetch_out(&s, &[desktop], laptop, now);
        fetch_out(&s, &[laptop], desktop, now);
    }
    on(&s, laptop, Do::File(filing(30, "x1")), t4 + 5);
    on(&s, desktop, Do::File(filing(31, "x2")), t4 + 5);
    for round in 0..3 {
        let now = t4 + 6 + round;
        fetch_out(&s, &[desktop], laptop, now);
        fetch_out(&s, &[laptop], desktop, now);
    }
    let t5 = t4 + 10;
    assert_eq!(row(&s, laptop, &review).state, State::NotInForce);
    let own_relays = vec![crate::sharing::OwnRelay {
        name: "relay.example.org:9474".into(),
        key: [3; 32],
    }];
    let conn = &s[laptop].conn;
    let identity = &s[laptop].identity;
    let (listing, _) =
        crate::shared_anew::anew_plan(conn, identity, &own_relays, "review", None, &[], None, t5)
            .unwrap();
    let asked: Vec<String> = listing
        .asked
        .iter()
        .map(|key| cordelia_crypto::bech32::encode_public_key(key).unwrap())
        .collect();
    let (_, plan) = crate::shared_anew::anew_plan(
        conn,
        identity,
        &own_relays,
        "review",
        None,
        &[],
        Some((&asked, &asked)),
        t5,
    )
    .unwrap();
    crate::shared_anew::make_anew(conn, identity, &own_relays, &plan.unwrap().what, t5).unwrap();
    let offers: Vec<_> = s[laptop]
        .stored_in(&review.secret)
        .into_iter()
        .filter(|entry| entry.author == s.key(laptop))
        .collect();
    assert_eq!(offers.len(), 1, "the offer, in the channel past the bound");
    let opened = offers[0].open(&review.secret).unwrap();
    assert!(matches!(
        cordelia_crypto::shared::Anew::from_value(&opened.value),
        Ok(cordelia_crypto::shared::Anew::Offer(_))
    ));

    drop_path();
}

/// The drop path of [`a_channel_not_written_keeps_no_entries`], as
/// `past_a_bound_in_one_pass` has it in its units: devices 1 to 5 are shut,
/// and their old lists, written by hand, carry 80 filings, sixteen each;
/// device 0 reads them and makes 65 drops, one of each of 65 of them, the
/// first that of the channel of seed 1, which it held and was written in.
fn drop_path() {
    use crate::shared::tests::{Shared, message, row, stores};
    use cordelia_storage::shared::State;

    let s = person(6, 6);
    sync_on(&s);
    let t = s.now + 10;
    let seeds = |k: usize| (16 * (k as u8 - 1) + 1)..=(16 * k as u8);
    let list_of_device = |k: usize| -> Vec<AnyAct> {
        seeds(k)
            .map(|seed| filing(seed, &format!("c{seed}")).by(&s[k].identity, t as u64, 0))
            .collect()
    };
    let d = Shared::of(1);
    let member = crate::shared::tests::member(1);
    let said = message(&member, &d, 1, "in d", t);

    // Device 1's list: the channel of seed 1 is held, and written in.
    write_by_hand(&s, 1, list_of_device(1), t);
    fetch_out(&s, &[1], 0, t + 1);
    assert!(filed(&s, 0).contains(&"c1".to_string()));
    stores(&s, 0, &said, t + 2);
    assert!(!s[0].stored_in(&d.secret).is_empty());

    // Its drop, the newest valid act on it, empties it, and keeps its
    // rows while it is written.
    on(&s, 0, Do::Drop(d.id), t + 3);
    crate::shared::tests::out(&s, 0, t + 3);
    assert_eq!(row(&s, 0, &d).state, State::Dropped);
    assert!(s[0].stored_in(&d.secret).is_empty());
    assert_eq!(crate::shared::tests::indexed(&s, 0, &d), 0);
    assert!(!crate::shared::tests::key_rows(&s, 0, &d).is_empty());
    assert!(first_held_rows(&s, 0, &d) > 0);

    // The other four lists, and 64 drops more: 65 in all, each kept for
    // something. The oldest, the channel's, is let go.
    for k in 2..=5 {
        write_by_hand(&s, k, list_of_device(k), t);
    }
    fetch_out(&s, &[2, 3, 4, 5], 0, t + 4);
    for seed in 17..=80u8 {
        on(&s, 0, Do::Drop(channel(seed)), t + 5 + i64::from(seed));
    }
    let now = t + 100;
    fetch_out(&s, &[1, 2, 3, 4, 5], 0, now);
    let written = kept(&s, 0);
    assert_eq!(written.drops.len(), 64);
    assert!(!written.drops.iter().any(|drop| drop.item.channel == d.id));
    assert_eq!(filed(&s, 0).len(), 16, "{:?}", filed(&s, 0));
    assert!(filed(&s, 0).contains(&"c1".to_string()));
    assert_eq!(row(&s, 0, &d).state, State::Held);
    // The device wrote an act on it throughout, the drop and then the
    // filing below it: its rows stayed, and its message, under 30 days
    // old, is shown under its first holding, not as new...
    assert!(!crate::shared::tests::key_rows(&s, 0, &d).is_empty());
    let later = t + 6 * DAY;
    stores(&s, 0, &said, later);
    let shown = crate::shared::shown(&s[0].conn, &s[0].identity, &d.id, later).unwrap();
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].first_held, t + 2, "shown as new");
    // ...and its empty anew record is written again.
    assert!(
        crate::sharing::write_empty_anew_records(&s[0].conn, &s[0].identity, later).unwrap() >= 1
    );
    assert!(
        s[0].stored_in(&d.secret)
            .iter()
            .any(|entry| entry.author == s.key(0))
    );
}

/// A drop that is the newest valid act keeps the channel's rows while it
/// is written (decision 2026-10-10 §3.4: "Its rows stay while the device
/// writes a valid act on the channel, a filing or a drop"; §6.3; §13
/// under property 25; the person's ruling of 30 October): its entries,
/// its index rows and its seed go; its table of keys stays.
#[test]
fn a_drop_keeps_its_channels_rows_while_it_is_written() {
    use crate::shared::tests::{Shared, indexed, key_rows, message, row, stores};

    let s = person(2, 2);
    sync_on(&s);
    let t = s.now + 10;
    on(&s, 1, Do::File(filing(1, "review")), t);
    fetch_out(&s, &[1], 0, t + 1);
    let channel = Shared::of(1);
    let member = crate::shared::tests::member(1);
    stores(&s, 0, &message(&member, &channel, 1, "one", t + 2), t + 2);
    on(&s, 0, Do::Drop(channel.id), t + 3);
    crate::shared::tests::out(&s, 0, t + 3);
    assert!(s[0].stored_in(&channel.secret).is_empty());
    assert_eq!(indexed(&s, 0, &channel), 0);
    assert!(!key_rows(&s, 0, &channel).is_empty());
    assert!(first_held_rows(&s, 0, &channel) > 0);
    assert_eq!(
        &row(&s, 0, &channel).card[..32],
        &[0; 32],
        "the seed is forgotten"
    );
}

/// A channel shared again while its drop is written shows nothing old as
/// new (decision 2026-10-10 §1, property 22; §3.4; the person's ruling of
/// 30 October): the desktop holds `review`, a member's message shown
/// there, and a quiet key let go, its row keeping its revisions; it drops
/// the channel, and files it again, as a member's share brings it back,
/// while the drop is still the act its list carried. Its card comes back
/// with the filing; the let-go key's old entry is refused; the message,
/// stored again from the relay, is shown under its first holding, not as
/// new.
#[test]
fn a_channel_shared_again_while_its_drop_is_written_shows_nothing_old_as_new() {
    use crate::shared::tests::{Shared, given, hourly, key_row, member, message, row, stores};
    use cordelia_storage::shared::State;

    let s = person(2, 2);
    sync_on(&s);
    let t = s.now + 10;
    on(&s, 1, Do::File(filing(1, "review")), t);
    fetch_out(&s, &[1], 0, t + 1);
    let review = Shared::of(1);
    let card = row(&s, 0, &review).card;
    let (quiet, writer) = (member(2), member(1));
    let old = message(&quiet, &review, 1, "quiet", t + 2);
    let t1 = t + 31 * DAY;
    let fresh = message(&writer, &review, 1, "fresh", t1);
    stores(&s, 0, &old, t + 2);
    stores(&s, 0, &fresh, t1);
    hourly(&s[0].conn, &s.key(0), t1 + 1).unwrap();
    assert!(
        key_row(&s, 0, &review, &quiet.public_key())
            .unwrap()
            .kept_message_rev
            .is_some()
    );
    let shown = crate::shared::shown(&s[0].conn, &s[0].identity, &review.id, t1 + 1).unwrap();
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].first_held, t1);

    on(&s, 0, Do::Drop(review.id), t1 + 2);
    crate::shared::tests::out(&s, 0, t1 + 2);
    assert_eq!(row(&s, 0, &review).state, State::Dropped);
    assert!(s[0].stored_in(&review.secret).is_empty());
    assert!(
        kept(&s, 0)
            .drops
            .iter()
            .any(|drop| drop.item.channel == review.id)
    );

    // Shared again: a filing above the drop.
    on(&s, 0, Do::File(filing(1, "review")), t1 + 3);
    crate::shared::tests::out(&s, 0, t1 + 3);
    let held = row(&s, 0, &review);
    assert_eq!(held.state, State::Held);
    assert_eq!(held.card, card, "the filing carries the card again");
    let before = key_row(&s, 0, &review, &quiet.public_key());
    assert_eq!(
        given(&s, 0, &old, t1 + 4),
        crate::take::Taken::Refused(crate::take::NotTaken::SharedFull)
    );
    assert_eq!(key_row(&s, 0, &review, &quiet.public_key()), before);
    stores(&s, 0, &fresh, t1 + 5);
    let shown = crate::shared::shown(&s[0].conn, &s[0].identity, &review.id, t1 + 5).unwrap();
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].body, "fresh");
    assert_eq!(shown[0].first_held, t1, "shown as new");
}

/// A channel past its bound, as the tests below find it on the laptop.
struct PastABound {
    review: crate::shared::tests::Shared,
    /// The member whose row the table let go.
    gone: NodeIdentity,
    /// The member whose row the table holds.
    kept: NodeIdentity,
    /// A member that wrote there after it went past the bound.
    dave: NodeIdentity,
    /// A time after all of it.
    t2: i64,
}

/// Devices 0, 1 and 2 of `s` (the laptop, the desktop and the phone):
/// the phone files `review` and is shut, its list still carrying the
/// filing, so that the channel's rows stay while a list carries an act on
/// it. Two members write there, and `while_held` runs on the laptop while
/// it still holds the channel; the laptop and the desktop then file eight
/// each, apart, and `review`, the oldest of 17, is past the bound. The
/// table lets go the row of the member that wrote first (by hand: see
/// below), and Dave writes there after the bound, of which the door takes
/// nothing. The desktop's last channel, `d7`, is at a relay of its own,
/// which the laptop does not reach.
fn past_a_bound(
    s: &Several,
    while_held: &dyn Fn(&Several, &crate::shared::tests::Shared, &NodeIdentity),
) -> PastABound {
    use crate::shared::tests::{Shared, anew, given, key_row, key_rows, member, row, stores};
    use cordelia_storage::shared::State;

    sync_on(s);
    let (laptop, desktop, phone) = (0, 1, 2);
    let t0 = s.now + 10;
    on(s, phone, Do::File(filing(1, "review")), t0);
    all_fetch(s, &[laptop, desktop, phone], t0 + 1, 2);
    let review = Shared::of(1);
    crate::shared::tests::out(s, laptop, t0 + 1);
    assert_eq!(row(s, laptop, &review).state, State::Held);
    // Two members write there: the first is let go below, the second held.
    let (gone, kept) = (member(2), member(1));
    stores(s, laptop, &anew(&gone, &review, 1), t0 + 2);
    stores(s, laptop, &anew(&kept, &review, 1), t0 + 3);
    while_held(s, &review, &kept);

    let t1 = t0 + 10;
    for k in 0..8u8 {
        let at = t1 + i64::from(k);
        on(s, laptop, Do::File(filing(10 + k, &format!("l{k}"))), at);
        let d = match k {
            7 => filing_at(20 + k, "d7", [4; 32]),
            _ => filing(20 + k, &format!("d{k}")),
        };
        on(s, desktop, Do::File(d), at);
    }
    for round in 0..3 {
        let now = t1 + 10 + round;
        fetch_out(s, &[desktop], laptop, now);
        fetch_out(s, &[laptop], desktop, now);
    }
    let t2 = t1 + 20;
    assert!(!filed(s, laptop).contains(&"review".to_string()));
    let id = row(s, laptop, &review).id;
    assert_eq!(row(s, laptop, &review).state, State::NotInForce);
    assert!(s[laptop].stored_in(&review.secret).is_empty());
    assert_eq!(key_rows(s, laptop, &review).len(), 2);
    // The table lets go the row of the key that wrote first. Nothing lets a
    // row go on a channel past a bound (the door, the one caller of
    // `keep_rows_within`, takes held channels only), so the row is let go
    // here by hand: it stands for a row the table let go while the channel
    // was held, before it went past the bound, which `let_go` still counts.
    assert_eq!(
        cordelia_storage::shared::keep_rows_within(&s[laptop].conn, id, 1).unwrap(),
        1
    );
    assert!(key_row(s, laptop, &review, &gone.public_key()).is_none());
    assert!(key_row(s, laptop, &review, &kept.public_key()).is_some());
    // Dave writes there after it went past the bound: the door takes
    // nothing of his, and the table has no row of him.
    let dave = member(9);
    assert!(!matches!(
        given(s, laptop, &anew(&dave, &review, 1), t2),
        crate::take::Taken::Shared {
            stored: cordelia_storage::entries::Outcome::Stored,
            ..
        }
    ));
    assert!(key_row(s, laptop, &review, &dave.public_key()).is_none());
    PastABound {
        review,
        gone,
        kept,
        dave,
        t2,
    }
}

/// `shared anew` on a channel past its bound (decision 2026-10-10 §3.4, the
/// person's ruling for R1): the device does not read the channel again, so
/// it lists and asks about only the keys of its table of keys. The phone
/// files `review` and is shut, and two members write there; the laptop and
/// the desktop then file eight each, apart, and `review` is pushed past the
/// bound. The table lets go the row of the member that wrote first (by
/// hand: see below), and a third member, Dave, comes to the channel after
/// it went past the bound: the door takes nothing of his. `shared anew`
/// lists and asks about the one key it holds, says in one line that you
/// could not list everyone, up to 1 key you no longer hold and anyone who
/// wrote there since, and that they need the channel shared with them
/// again; it takes no `keep` of a key it did not list; and the offer seals
/// to the person's three devices and the key it holds, and to no other.
#[test]
fn shared_anew_past_a_bound_lists_only_the_keys_it_holds() {
    use cordelia_crypto::bech32::encode_public_key;
    use cordelia_crypto::shared::Anew;

    let s = person(3, 3);
    let (laptop, desktop, phone) = (0, 1, 2);
    let PastABound {
        review,
        gone,
        kept,
        dave,
        t2,
    } = past_a_bound(&s, &|_, _, _| {});
    let conn = &s[laptop].conn;

    let own_relays = vec![crate::sharing::OwnRelay {
        name: "relay.example.org:9474".into(),
        key: [3; 32],
    }];
    let identity = &s[laptop].identity;
    let plan_of = |keep: &[String], asked: &[String]| {
        crate::shared_anew::anew_plan(
            conn,
            identity,
            &own_relays,
            "review",
            None,
            &[],
            Some((keep, asked)),
            t2,
        )
    };
    let (listing, _) =
        crate::shared_anew::anew_plan(conn, identity, &own_relays, "review", None, &[], None, t2)
            .unwrap();
    // It lists and asks about the one key it holds.
    assert_eq!(listing.asked, vec![kept.public_key()]);
    assert_eq!(
        listing.own_devices,
        vec![s.key(laptop), s.key(desktop), s.key(phone)]
    );
    // One line says how many it could not list, and what to do.
    let line = crate::shared_anew::past_a_bound_line("review", 1);
    assert_eq!(
        line,
        "You could not list everyone in \"review\" since it went past a bound: up to 1 key you \
         no longer hold, and anyone who wrote there since. Share the new channel with them again."
    );
    assert_eq!(
        listing
            .lines
            .iter()
            .filter(|said| said.contains("could not list"))
            .collect::<Vec<_>>(),
        vec![&line],
        "{:?}",
        listing.lines
    );
    assert!(
        !listing
            .lines
            .iter()
            .any(|said| said.contains("no longer known on this device")),
        "{:?}",
        listing.lines
    );
    let asked: Vec<String> = listing
        .asked
        .iter()
        .map(|key| encode_public_key(key).unwrap())
        .collect();
    // A `keep` of a key it did not list is taken for nobody: Dave's, and
    // the key the table let go.
    for not_listed in [&dave, &gone] {
        let keep = vec![encode_public_key(&not_listed.public_key()).unwrap()];
        match plan_of(&keep, &asked) {
            Err(crate::sharing::Failed::Refused(refusal)) => assert!(
                refusal.line.contains("is not a key that this asks about"),
                "{}",
                refusal.line
            ),
            other => panic!("taken: {other:?}"),
        }
    }
    // Every key kept: the offer seals to the person's own devices and the
    // key it holds, and to no other.
    let (_, plan) = plan_of(&asked, &asked).unwrap();
    let plan = plan.unwrap();
    assert!(
        plan.asks
            .ends_with("Staying: 4 keys, your own devices among them. Left out: up to 1 key."),
        "{}",
        plan.asks
    );
    crate::shared_anew::make_anew(conn, identity, &own_relays, &plan.what, t2).unwrap();
    let offers: Vec<_> = s[laptop]
        .stored_in(&review.secret)
        .into_iter()
        .filter(|entry| entry.author == s.key(laptop))
        .collect();
    assert_eq!(offers.len(), 1, "the offer, in the channel past the bound");
    let opened = offers[0].open(&review.secret).unwrap();
    let Ok(Anew::Offer(offer)) = Anew::from_value(&opened.value) else {
        panic!("no offer");
    };
    let mut sealed: Vec<[u8; 32]> = offer.seals.iter().map(|seal| seal.key).collect();
    sealed.sort();
    let mut expected = vec![
        s.key(laptop),
        s.key(desktop),
        s.key(phone),
        kept.public_key(),
    ];
    expected.sort();
    assert_eq!(sealed, expected);
}

/// `shared move` on a channel past its bound judges the offers this device
/// read before, from the keys it shows (decision 2026-10-10 §3.4, §7): it
/// does not read the channel again. Past a bound every entry is taken out,
/// so the device shows there only the person's own devices and the keys
/// the person labelled (`keys_held_in_order` lists only keys with bytes
/// stored). With the channel of `past_a_bound`, the member the table holds
/// made it anew, sealed to itself and to the laptop, while the laptop held
/// it; Dave's offer, written after the bound, is not taken. On the laptop
/// `shared move` refuses with `no_offer` while that member is not
/// labelled; once the person labels the key, it names the one offer it
/// read, and its maker, and the move goes through: the channel is moved
/// from.
#[test]
fn shared_move_past_a_bound_judges_the_offers_read_before() {
    use crate::shared::tests::{Shared, anew_of, given, row, stores};
    use cordelia_crypto::shared::{Anew, Offer};
    use cordelia_storage::shared::State;

    let s = person(3, 3);
    let laptop = 0;
    let own_relays = vec![crate::sharing::OwnRelay {
        name: "relay.example.org:9474".into(),
        key: [3; 32],
    }];
    let offer_of = |maker: &NodeIdentity, old: &Shared, seed: u8| {
        let card = filing(seed, "x").card;
        let keys = [maker.public_key(), s.key(laptop)];
        let offer = Offer::make(s.now as u64, &old.id, &card, &keys).unwrap();
        (
            card.channel_id().unwrap(),
            anew_of(maker, old, 2, Anew::Offer(offer).to_value().unwrap()),
        )
    };
    let PastABound {
        review,
        kept,
        dave,
        t2,
        ..
    } = past_a_bound(&s, &|s, review, kept| {
        stores(s, laptop, &offer_of(kept, review, 40).1, s.now + 14);
    });
    let (new_channel, _) = offer_of(&kept, &review, 40);
    // Dave's offer, after the bound, is not taken.
    assert!(!matches!(
        given(&s, laptop, &offer_of(&dave, &review, 41).1, t2),
        crate::take::Taken::Shared {
            stored: cordelia_storage::entries::Outcome::Stored,
            ..
        }
    ));
    let conn = &s[laptop].conn;
    let identity = &s[laptop].identity;
    let plan_at =
        |now| crate::shared_anew::move_plan(conn, identity, &own_relays, "review", None, None, now);
    // Not labelled, the member is not shown, and its offer is not judged.
    match plan_at(t2) {
        Err(crate::sharing::Failed::Refused(refusal)) => {
            assert_eq!(refusal.word, "no_offer", "{}", refusal.line)
        }
        other => panic!("{other:?}"),
    }
    let ana = Label {
        key: kept.public_key(),
        label: Some("Ana".into()),
    };
    on(&s, laptop, Do::Label(ana), t2 + 1);
    let plan = plan_at(t2 + 2).unwrap();
    let held = crate::person::held(conn).unwrap().unwrap();
    let by = crate::sharing::sender_form(conn, &held, &s.key(laptop), &kept.public_key()).unwrap();
    assert!(
        plan.asks
            .starts_with(&format!("\"review\" was made anew by {by} on ")),
        "{}",
        plan.asks
    );
    assert!(
        plan.asks
            .contains("Offers from keys this device shows: 1, of them faults: 0."),
        "{}",
        plan.asks
    );
    assert_eq!(plan.what.to.channel, new_channel);
    crate::shared_anew::make_move(conn, identity, &plan.what, t2 + 3).unwrap();
    assert_eq!(row(&s, laptop, &review).state, State::Moved);
}

/// A removal makes a channel past its bound anew (decision 2026-10-10 §3.5,
/// the person's ruling of 30 October; T23). With the channel of
/// `past_a_bound`, which only the phone's list carries and the laptop no
/// longer holds, and Dave writing there after the bound, the laptop removes
/// the phone, which holds the channel's seed. Before its yes the removal
/// names the channel among those past a bound. It is made anew under the
/// lists of the generation before, though channels held come before it and
/// after it in the order of the channels not clean: its offer seals to the
/// laptop, the desktop and the one member the table holds, so to no key the
/// laptop does not hold, and the phone's key cannot open the new seed; it
/// goes at revision 2, above the empty anew record the relays hold at 1;
/// and the line says how many keys it could not list, in the words of
/// `shared anew`. The new channel takes the old one's place past the bound:
/// the 15 channels held that the laptop reaches are made anew and filed,
/// `d7`, which it does not reach, stays as it was, and none goes past the
/// bound. A take-out that the bound began and that has not ended when the
/// removal comes ends there: the old channel is moved from, keeps its
/// offer, and the pass sends it there alone; the look and the status say
/// the line.
#[test]
fn a_removal_makes_a_channel_past_its_bound_anew() {
    use crate::shared::tests::row;
    use crate::shared_anew::{LeftOut, made_anew_past_a_bound_line, past_a_bound_line};
    use cordelia_crypto::shared::Anew;
    use cordelia_storage::shared::State;

    let mut s = person(3, 3);
    let (laptop, desktop, phone) = (0, 1, 2);
    let PastABound {
        review,
        gone,
        kept,
        dave,
        t2,
    } = past_a_bound(&s, &|_, _, _| {});
    // The take-out that the bound began has not ended yet.
    let id = row(&s, laptop, &review).id;
    cordelia_storage::shared_pass::begin_channel(
        &s[laptop].conn,
        id,
        cordelia_storage::shared_pass::ChannelOut::Dropped,
    )
    .unwrap();
    s.now = t2 + 10;
    s.change(laptop, &[laptop, desktop], &[phone]);
    let now = s.now + 1;
    let conn = &s[laptop].conn;
    let identity = &s[laptop].identity;
    const AT: [u8; 32] = [3; 32];
    let own_relays = vec![crate::sharing::OwnRelay {
        name: "relay.example.org:9474".into(),
        key: AT,
    }];

    // Before its yes, the removal names it among the channels past a bound.
    let (made_anew, _, past, _) = crate::shared_anew::at_a_removal(conn, &own_relays).unwrap();
    assert_eq!(past, ["review"]);
    assert_eq!(made_anew.len(), 15, "d7 is not reached");
    // Channels held come before it and after it among those not clean.
    let order: Vec<[u8; 32]> = cordelia_storage::shared_anew::not_clean_all(conn)
        .unwrap()
        .iter()
        .map(|mark| mark.channel)
        .collect();
    assert_eq!(order.len(), 17);
    let at = order.iter().position(|id| *id == review.id).unwrap();
    assert!(at > 0 && at + 1 < order.len(), "at {at}");

    let said = crate::shared_anew::anew_at_removal(conn, identity, &own_relays, now).unwrap();
    assert_eq!(said.len(), 17, "{said:?}");
    assert!(
        !said
            .iter()
            .any(|line| line.contains("could not be made anew")),
        "{said:?}"
    );
    assert!(
        said.contains(&crate::shared_anew::unreached_line("d7")),
        "{said:?}"
    );

    // The offer, in the old channel.
    let offers: Vec<_> = s[laptop]
        .stored_in(&review.secret)
        .into_iter()
        .filter(|entry| entry.author == s.key(laptop))
        .collect();
    assert_eq!(offers.len(), 1, "the offer");
    // A node writes its empty anew record at revision 1 in each channel it
    // holds (`sharing::write_empty_anew_records`), and its relays hold it.
    assert_eq!(offers[0].rev, 2, "above the empty record at 1");
    let opened = offers[0].open(&review.secret).unwrap();
    let Ok(Anew::Offer(offer)) = Anew::from_value(&opened.value) else {
        panic!("no offer");
    };
    let mut sealed: Vec<[u8; 32]> = offer.seals.iter().map(|seal| seal.key).collect();
    sealed.sort();
    let mut expected = vec![s.key(laptop), s.key(desktop), kept.public_key()];
    expected.sort();
    assert_eq!(sealed, expected, "only keys the laptop holds");
    assert!(offer.open(&s[phone].identity, &review.id).is_err());
    assert!(offer.open(&gone, &review.id).is_err());
    assert!(offer.open(&dave, &review.id).is_err());
    assert!(offer.open(&s[desktop].identity, &review.id).is_ok());

    // The line counts what it could not list.
    let line = made_anew_past_a_bound_line(
        "review",
        &offer.new_channel,
        LeftOut {
            past_64: 0,
            let_go: 1,
        },
    );
    assert!(said.contains(&line), "{said:?}");
    assert!(line.ends_with(&past_a_bound_line("review", 1)), "{line}");
    assert!(line.contains("up to 1 key you no longer hold"), "{line}");
    assert!(line.contains("your devices do not hold it"), "{line}");

    // No other channel goes past the bound: the 16 held are filed, anew.
    let filings = crate::sharing::filed(conn).unwrap();
    let mut names: Vec<String> = filings.iter().map(|filing| filing.name.clone()).collect();
    names.sort();
    let mut expected: Vec<String> = (0..8u8)
        .flat_map(|k| [format!("l{k}"), format!("d{k}")])
        .collect();
    expected.sort();
    assert_eq!(names, expected);
    // Each but d7 is made anew; d7 keeps its filing.
    for filing in &filings {
        assert_eq!(filing.came == Came::Made, filing.name == "d7", "{filing:?}");
    }
    let worked = holds_worked_out(conn, &s.key(laptop), now).unwrap();
    assert!(
        !worked
            .left_out
            .iter()
            .any(|(act, _)| matches!(act, AnyAct::Filing(_))),
        "{:?}",
        worked.left_out
    );
    assert!(
        worked
            .drops
            .iter()
            .any(|(drop, _)| drop.item.channel == review.id)
    );

    // The old channel is moved from, and its offer is sent there alone.
    crate::shared::tests::out(&s, laptop, now);
    assert_eq!(row(&s, laptop, &review).state, State::Moved);
    let usable = crate::shared_pass::usable(conn, &review.id, &AT)
        .unwrap()
        .unwrap();
    let most = crate::at_relays::Most {
        entries: 100,
        bytes: 1 << 20,
    };
    let batch = crate::shared_pass::to_send(conn, identity, &usable, &AT, most).unwrap();
    assert_eq!(batch.len(), 1, "the offer alone");
    assert_eq!(batch[0].rev, 2);

    // The look and the status say the line.
    let look = crate::shared_anew::made_at_the_last_removal(conn, Some(now)).unwrap();
    assert!(look.contains(&line), "{look:?}");
    let said = crate::state::SharedSaid::default();
    let beside = crate::shared_status::Beside {
        own_relays: &own_relays,
        connected: &[AT],
        said: &said,
    };
    let status = crate::shared_status::status_of(conn, identity, &beside, now)
        .unwrap()
        .unwrap();
    let made = status["made_anew_past_a_bound"].as_array().unwrap();
    assert_eq!(made.len(), 1, "{status}");
    assert_eq!(made[0]["name"], "review");
    assert_eq!(made[0]["said"], line.as_str());
    // Only d7, which it did not reach, is still held by the removed device.
    assert_eq!(
        status["removed_device_holds"][0]["channels"],
        serde_json::json!(["d7"])
    );
}

/// A recovery does not make a channel past its bound anew, and names it
/// (decision 2026-10-10 §3.5): the new machine never read it, and holds no
/// table of its keys to seal to. With the lists of `past_a_bound`, whose
/// phone carries the filing of `review` and the laptop and the desktop 16
/// newer ones, a recovery told every device is gone brings back the 16 and
/// not `review`, which it names, past a bound, with what to ask of the
/// others in it; told every device is still had, it removes nobody, and
/// says nothing of it.
#[test]
fn a_recovery_names_a_channel_past_its_bound_and_does_not_make_it_anew() {
    use cordelia_crypto::entry::CheckedEntry;

    let s = person(3, 3);
    let PastABound { review, .. } = past_a_bound(&s, &|_, _, _| {});
    let personal = s[0].personal();
    let handed: Vec<CheckedEntry> = (0..3).flat_map(|n| s[n].stored()).collect();
    let keys = [s.key(0), s.key(1), s.key(2)];
    let lists = lists_in(&handed, &personal, &keys).unwrap();
    assert_eq!(lists.len(), 3);
    let devices: Vec<([u8; 32], String)> = keys.iter().map(|key| (*key, String::new())).collect();

    let lines = crate::shared_anew::recovery_lines(&lists, &devices, &[]).unwrap();
    let all = lines.join("\n");
    assert!(
        all.contains(
            "Past a bound, so not brought back or made anew: \"review\". A device you said is \
             gone may still read what is written in each: ask someone in each to make it anew \
             without your old devices, and to share it with you again."
        ),
        "{all}"
    );
    let (written, past) = recovered(&lists, |key| keys.contains(key).then_some(Maker::Removed));
    let filed_in = |list: &SharedList| {
        acts_of(list)
            .iter()
            .filter_map(|act| match act {
                AnyAct::Filing(filing) => Some(filing.item.channel),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(filed_in(&written).len(), 16);
    assert!(!filed_in(&written).contains(&review.id));
    assert_eq!(filed_in(&past), [review.id]);

    let lines = crate::shared_anew::recovery_lines(&lists, &[], &devices).unwrap();
    assert!(
        !lines.iter().any(|line| line.contains("Past a bound")),
        "{lines:?}"
    );
}
