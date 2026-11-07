//! Tests of the node's read of each list it follows (decision 2026-11-06
//! (joining), rules 2.5, 3 and 4), in-process, with a set time and no
//! relay: the turns of rule 4.2, the shares that go, where nothing is
//! handed over, the notices, the stop of a channel dropped, and a read that
//! counts for nothing; and, last, the clones read with git, over a real
//! clone on the disk.

use super::*;
use crate::following::tests::OnDisk;
use crate::git_list::ListAt;
use crate::lists::Do;
use crate::lists::tests::filing;
use crate::several::Several;
use crate::shared::tests::{Shared, acts, anew, anew_of, bob, holds, member, stores};
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::shared::{Anew, Offer};

const REPOSITORY: &str = "example.org/team/project";
const FOLDER: &str = "/home/bob/Work/project";

/// A read's interval, as the node keeps it.
const READ: i64 = 600;

/// The relay of these tests' channels, known by its key: that of
/// [`filing`]'s card.
const AT: [u8; 32] = [3; 32];

fn own_relays() -> Vec<OwnRelay> {
    vec![OwnRelay {
        name: "relay.example.org:9474".into(),
        key: AT,
    }]
}

/// The key a channel line of these tests gives its relay: one that can be
/// used, as a relay's is. What a line says of its relays is not read here.
fn line_relay() -> [u8; 32] {
    NodeIdentity::from_seed([0x52; 32]).unwrap().public_key()
}

fn commit(c: char) -> String {
    c.to_string().repeat(40)
}

/// `key` with its top bit flipped: another key to Ed25519, the same to
/// X25519.
fn twin(key: &[u8; 32]) -> [u8; 32] {
    let mut twin = *key;
    twin[31] ^= 0x80;
    twin
}

/// A list: the channel line of `channel`, with `without`, where it has one;
/// then a line for each key, with its label.
fn list_of(channel: Option<(&[u8; 32], &[[u8; 32]])>, devices: &[([u8; 32], &str)]) -> String {
    let mut list = String::new();
    if let Some((channel, without)) = channel {
        let line = ChannelLine {
            channel: *channel,
            relays: vec![line_relay()],
            without: without.to_vec(),
        };
        list.push_str(&line.to_line().unwrap());
        list.push('\n');
    }
    for (key, label) in devices {
        list.push_str(&format!("{}   {label}\n", encode_public_key(key).unwrap()));
    }
    list
}

/// The keys of members `numbers`, each labelled `m<n>`.
fn listed(numbers: impl IntoIterator<Item = u32>) -> Vec<([u8; 32], String)> {
    numbers
        .into_iter()
        .map(|n| (member(n).public_key(), format!("m{n}")))
        .collect()
}

/// [`list_of`], of `devices` as [`listed`] gives them.
fn list_with(channel: Option<(&[u8; 32], &[[u8; 32]])>, devices: &[([u8; 32], String)]) -> String {
    let devices: Vec<([u8; 32], &str)> = devices
        .iter()
        .map(|(key, label)| (*key, label.as_str()))
        .collect();
    list_of(channel, &devices)
}

/// Device 0 follows the repository from `at`, with its list `list` at
/// `commit` read then: as `subscribe` in a clone leaves it.
fn follows_at(s: &Several, list: &str, commit: &str, at: i64) {
    let conn = &s[0].conn;
    follows::follow(conn, REPOSITORY, "origin", FOLDER, at).unwrap();
    let read = LastRead {
        commit: commit.into(),
        at,
        from_clone: true,
    };
    follows::read_done(conn, REPOSITORY, &read, list.as_bytes()).unwrap();
}

/// The follow on device 0.
fn row(s: &Several) -> Option<Follow> {
    follows::follow_of(&s[0].conn, REPOSITORY).unwrap()
}

/// What device 0 read of its clone: `list` at `commit`, for the follow as
/// it is now, with never-back's answer `comes_after`.
fn read_of(s: &Several, list: &str, commit: &str, comes_after: bool) -> CloneRead {
    CloneRead {
        follow: row(s).unwrap(),
        read: Ok(Read {
            list: ClonedList {
                at: ListAt {
                    commit: commit.into(),
                    file: Some(list.as_bytes().to_vec()),
                },
                branch: "main".into(),
                fetched: None,
            },
            comes_after,
        }),
    }
}

/// Device 0 does what `read` came to at `now`.
fn done(s: &Several, read: &CloneRead, now: i64) -> Done {
    after_read(&s[0].conn, &s[0].identity, &own_relays(), read, now).unwrap()
}

/// Device 0 reads `list` at `commit`, at `now`.
fn reads(s: &Several, list: &str, commit: &str, now: i64) -> Done {
    done(s, &read_of(s, list, commit, true), now)
}

/// The keys a read that was done handed the channel to.
fn handed(done: Done) -> Vec<[u8; 32]> {
    match done {
        Done::Read {
            handed,
            not_handing: None,
        } => handed,
        other => panic!("{other:?}"),
    }
}

/// Why a read that was done handed nothing over.
fn not_handing(done: Done) -> NotHanding {
    match done {
        Done::Read {
            handed,
            not_handing: Some(why),
        } if handed.is_empty() => why,
        other => panic!("{other:?}"),
    }
}

/// The node's shares waiting on device 0, each key with when it was made,
/// by key.
fn node_shares(s: &Several) -> Vec<([u8; 32], i64)> {
    let mut shares: Vec<([u8; 32], i64)> = follows::shares_by_node(&s[0].conn)
        .unwrap()
        .into_iter()
        .map(|share| (share.key, share.made))
        .collect();
    shares.sort();
    shares
}

/// The keys of the node's shares waiting on device 0, by key.
fn node_keys(s: &Several) -> Vec<[u8; 32]> {
    node_shares(s).into_iter().map(|(key, _)| key).collect()
}

/// The keys of the person's own shares waiting on device 0, by key.
fn hand_keys(s: &Several) -> Vec<[u8; 32]> {
    let mut keys: Vec<[u8; 32]> = share_rows::shares(&s[0].conn)
        .unwrap()
        .into_iter()
        .filter(|share| !share.gone && !share.by_node)
        .map(|share| share.key)
        .collect();
    keys.sort();
    keys
}

/// `keys`, by key.
fn sorted(keys: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut keys = keys.to_vec();
    keys.sort();
    keys
}

/// The person shares the channel filed as `name` with `key` by hand on
/// device 0, at `now`; or why not.
fn share_by_hand(s: &Several, name: &str, key: &[u8; 32], now: i64) -> Result<(), &'static str> {
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let typed = encode_public_key(key).unwrap();
    let plan = sharing::share_plan(conn, identity, &own_relays(), name, &typed, None, now);
    let plan = match plan {
        Ok(plan) => plan,
        Err(Failed::Refused(refusal)) => return Err(refusal.word),
        Err(Failed::Error(e)) => panic!("{e}"),
    };
    sharing::make_share(conn, identity, &own_relays(), &plan.what, false, now).unwrap();
    Ok(())
}

/// Each of `writers` writes its empty anew record in `channel`, and device
/// 0 stores it at `now`: each is then in the channel, first held at `now`.
fn write_in(s: &Several, channel: &Shared, writers: &[&NodeIdentity], now: i64) {
    for writer in writers {
        stores(s, 0, &anew(writer, channel, 1), now);
    }
}

/// The offer of `maker` that makes `old` anew as the card of `seed`,
/// sealed to `keys`, at revision `rev`.
fn offer_by(
    maker: &NodeIdentity,
    old: &Shared,
    seed: u8,
    keys: &[[u8; 32]],
    made: i64,
) -> CheckedEntry {
    let offer = Offer::make(made as u64, &old.id, &filing(seed, "x").card, keys).unwrap();
    anew_of(maker, old, 2, Anew::Offer(offer).to_value().unwrap())
}

/// The notices of the follow on device 0, as text: each kind, with its
/// key's label.
fn notices(s: &Several) -> Vec<String> {
    follows::notices(&s[0].conn, REPOSITORY)
        .unwrap()
        .into_iter()
        .map(|notice| match notice.of {
            NoticeOf::Joined { label, .. } => format!("joined {label} at {}", notice.commit),
            NoticeOf::Dropped { label, .. } => format!("dropped {label} at {}", notice.commit),
            NoticeOf::LineChanged => format!("line changed at {}", notice.commit),
        })
        .collect()
}

// ── The turns (rule 4.2) ─────────────────────────────────────────────

/// Nine new keys, with eight of them off (the record's §12): each read
/// hands the channel to the next four, in the list's order, starting after
/// the last one handed, and each share lives for two reads, so at most
/// eight of the node's wait at once: the ninth is handed it at the third
/// read, twenty minutes on, and the fourth's share has gone. Once the
/// ninth writes in the channel it is handed nothing more.
#[test]
fn nine_new_keys_with_eight_off_the_ninth_is_handed_the_channel_in_turn() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let devices = listed(1..=9);
    let k: Vec<[u8; 32]> = devices.iter().map(|(key, _)| *key).collect();
    let list = list_with(Some((&channel.id, &[])), &devices);
    follows_at(&s, &list, &commit('a'), now);

    let first = now + READ;
    assert_eq!(handed(reads(&s, &list, &commit('a'), first)), k[0..4]);
    assert_eq!(row(&s).unwrap().last_handed, Some(k[3]));
    let second = first + READ;
    // The same commit read again is a read: it hands to the next four.
    assert_eq!(handed(reads(&s, &list, &commit('a'), second)), k[4..8]);
    assert_eq!(node_keys(&s), sorted(&k[0..8]), "eight wait at once");
    let third = second + READ;
    assert_eq!(
        handed(reads(&s, &list, &commit('a'), third)),
        [k[8], k[0], k[1], k[2]],
        "the ninth, then the first again: their shares of two reads ago went"
    );
    let shares = node_shares(&s);
    assert_eq!(shares.len(), 8);
    assert!(
        !shares.iter().any(|(key, _)| *key == k[3]),
        "the fourth's went"
    );
    for (key, made) in shares {
        let at = match k[4..8].contains(&key) {
            true => second,
            false => third,
        };
        assert_eq!(made, at);
    }

    // The ninth wrote in the channel: it is in it, and handed nothing more.
    write_in(&s, &channel, &[&member(9)], third + 1);
    let fourth = third + READ;
    let turn = handed(reads(&s, &list, &commit('a'), fourth));
    assert!(!turn.contains(&k[8]), "{turn:?}");
    assert_eq!(
        turn,
        k[3..7],
        "after the third, whose shares of two reads ago went"
    );
}

/// A share of the node's lives for two reads, then is deleted: it is not
/// made again while it waits, and the read after next writes a delete over
/// it before it is made again, so the key holds one share at a time.
#[test]
fn a_nodes_share_lives_two_reads() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let alice = member(1).public_key();
    let list = list_of(Some((&channel.id, &[])), &[(alice, "alice")]);
    follows_at(&s, &list, &commit('a'), now);
    let (first, second, third) = (now + READ, now + 2 * READ, now + 3 * READ);
    assert_eq!(handed(reads(&s, &list, &commit('a'), first)), [alice]);
    let rev = |s: &Several| {
        share_rows::shares(&s[0].conn)
            .unwrap()
            .into_iter()
            .find(|share| share.key == alice)
            .map(|share| (share.rev, share.gone))
            .unwrap()
    };
    let made_first = rev(&s);
    assert!(handed(reads(&s, &list, &commit('a'), second)).is_empty());
    assert_eq!(rev(&s), made_first, "the share waits as it was");
    assert_eq!(node_shares(&s), [(alice, first)]);
    assert_eq!(handed(reads(&s, &list, &commit('a'), third)), [alice]);
    assert_eq!(node_shares(&s), [(alice, third)]);
    assert!(rev(&s).0 > made_first.0 + 1, "written over, then made anew");
}

/// A person's own share keeps its places (rule 4.2): a key that a share of
/// theirs waits for, of this channel or another, is passed over, so that
/// the node never writes over it; and the node's shares are counted apart,
/// so the person may still have eight of their own waiting.
#[test]
fn a_persons_own_share_keeps_its_places_and_is_passed_over() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    holds(&s, 0, 8, "design", now);
    let devices = listed(1..=6);
    let k: Vec<[u8; 32]> = devices.iter().map(|(key, _)| *key).collect();
    let list = list_with(Some((&channel.id, &[])), &devices);
    follows_at(&s, &list, &commit('a'), now);
    share_by_hand(&s, "design", &k[0], now).unwrap();
    share_by_hand(&s, "review", &k[1], now).unwrap();
    let first = now + READ;
    assert_eq!(handed(reads(&s, &list, &commit('a'), first)), k[2..6]);
    assert_eq!(hand_keys(&s), sorted(&k[0..2]), "the person's shares wait");
    // The person's eight places: six more of their own, then no ninth.
    for n in 11..17 {
        share_by_hand(&s, "review", &member(n).public_key(), first).unwrap();
    }
    assert_eq!(
        share_by_hand(&s, "review", &member(17).public_key(), first),
        Err("too_many_shares")
    );
    assert_eq!(node_keys(&s), sorted(&k[2..6]));
}

/// A key the list names after `without`, a key the person removed, and a
/// twin of a key in the channel, of one of the person's own devices or of
/// a key removed, are never handed the channel (rules 1 and 4.2): a twin
/// is the same key to X25519, from which a share's pair is derived.
#[test]
fn a_key_after_without_a_removed_key_and_a_twin_are_never_handed_the_channel() {
    let mut s = bob(2);
    let removed = s.key(1);
    s.change(0, &[0], &[1]);
    let now = s.now + 10;
    // Made after the removal, so clean here.
    let plan = sharing::new_plan(&s[0].conn, &own_relays(), "review", &[]).unwrap();
    sharing::make_new(&s[0].conn, &s[0].identity, &plan.what, now).unwrap();
    let id = sharing::filed(&s[0].conn).unwrap()[0].channel;
    let (alice, carol, dave) = (member(1), member(2), member(3));
    let kept_row = kept::channel(&s[0].conn, &id).unwrap().unwrap();
    let card = cordelia_crypto::share::Card::from_bytes(&kept_row.card).unwrap();
    let channel = Shared {
        secret: card.secret().unwrap(),
        id,
    };
    // Carol is left out of the channel line, and wrote there: she is in
    // the channel, so the gate lets the list name it.
    write_in(&s, &channel, &[&alice, &carol], now);
    // A key and its twin are one key, so a list names one of them.
    let list = |removed_or_twin: [u8; 32]| {
        list_of(
            Some((&id, &[carol.public_key()])),
            &[
                (twin(&alice.public_key()), "alice-twin"),
                (carol.public_key(), "carol"),
                (removed_or_twin, "bob-old"),
                (twin(&s.key(0)), "bob-twin"),
                (dave.public_key(), "dave"),
            ],
        )
    };
    follows_at(&s, &list(twin(&removed)), &commit('a'), now);
    assert_eq!(
        handed(reads(&s, &list(twin(&removed)), &commit('a'), now + READ)),
        [dave.public_key()]
    );
    assert!(handed(reads(&s, &list(removed), &commit('b'), now + 3 * READ)).is_empty());
    assert_eq!(node_keys(&s), [dave.public_key()]);
}

/// The shares to keys the list no longer names go (rule 4.3): the node's,
/// and a person's to a key the list kept named; a person's to a key the
/// list never named stays, as a member may hand the channel to one by hand
/// (rule 10).
#[test]
fn the_shares_to_keys_the_list_no_longer_names_go() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let devices = listed(1..=4);
    let k: Vec<[u8; 32]> = devices.iter().map(|(key, _)| *key).collect();
    let list = list_with(Some((&channel.id, &[])), &devices);
    follows_at(&s, &list, &commit('a'), now);
    share_by_hand(&s, "review", &k[3], now).unwrap();
    let stranger = member(9).public_key();
    share_by_hand(&s, "review", &stranger, now).unwrap();
    assert_eq!(handed(reads(&s, &list, &commit('a'), now + READ)), k[0..3]);
    // The first and the fourth are dropped from the list.
    let shorter = list_with(Some((&channel.id, &[])), &devices[1..3]);
    let done = reads(&s, &shorter, &commit('b'), now + 2 * READ);
    assert!(handed(done).is_empty());
    assert_eq!(node_keys(&s), sorted(&k[1..3]));
    assert_eq!(hand_keys(&s), [stranger]);
}

/// Behind rule 1's gate, the turn itself never hands the channel to a key
/// the channel line names after `without`, or to its twin: a second guard,
/// which no read reaches while the gate holds the list back.
#[test]
fn the_turn_passes_over_a_key_after_without_behind_the_gate() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let devices = listed(1..=3);
    let k: Vec<[u8; 32]> = devices.iter().map(|(key, _)| *key).collect();
    let list = list_with(Some((&channel.id, &[k[1], twin(&k[2])])), &devices);
    follows_at(&s, &list, &commit('a'), now);
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let list = members::read(list.as_bytes()).unwrap();
    assert_eq!(
        acts_in(conn, identity, &own_relays(), &list).unwrap().err(),
        Some(NotHanding::LeftOut(vec!["m2".into(), "m3".into()]))
    );
    let held = sharing::standing(conn).unwrap();
    let filing = sharing::filed(conn).unwrap().remove(0);
    let line = list.channel.as_ref().unwrap();
    let follow = row(&s).unwrap();
    let handed = hand_over(
        conn,
        identity,
        &held,
        &own_relays(),
        &follow,
        &list,
        line,
        &filing,
        now + 1,
    )
    .unwrap();
    assert_eq!(handed, [k[0]]);
}

// ── Where nothing is handed over (rule 4.1) ──────────────────────────

/// Nothing is handed over where the list names no channel, or the gate of
/// rule 1 holds it back, or the person does not hold the channel it
/// names, or it is not reached from this device; and each says why.
#[test]
fn nothing_is_handed_over_where_the_list_names_no_channel_or_one_not_held() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let devices = listed(1..=2);
    let list = list_with(None, &devices);
    follows_at(&s, &list, &commit('a'), now);
    assert_eq!(
        not_handing(reads(&s, &list, &commit('a'), now + 1)),
        NotHanding::NoChannel
    );
    // Rule 1's gate: m2 is left out of the line, and not in the channel.
    let gated = list_with(Some((&channel.id, &[devices[1].0])), &devices);
    assert_eq!(
        not_handing(reads(&s, &gated, &commit('a'), now + 2)),
        NotHanding::LeftOut(vec!["m2".into()])
    );
    let elsewhere = Shared::of(9);
    let other = list_with(Some((&elsewhere.id, &[])), &devices);
    assert_eq!(
        not_handing(reads(&s, &other, &commit('a'), now + 3)),
        NotHanding::NotHeld
    );
    let named = list_with(Some((&channel.id, &[])), &devices);
    let read = read_of(&s, &named, &commit('a'), true);
    let unreached = after_read(&s[0].conn, &s[0].identity, &[], &read, now + 4).unwrap();
    assert_eq!(not_handing(unreached), NotHanding::NotReached);
    assert!(node_keys(&s).is_empty());
    assert_eq!(handed(reads(&s, &named, &commit('a'), now + 5)).len(), 2);
}

/// Nothing is handed over in a channel that is not clean here, after a
/// removal (rule 4.1).
#[test]
fn nothing_is_handed_over_in_a_channel_not_clean() {
    let mut s = bob(2);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    s.change(0, &[0], &[1]);
    let list = list_with(Some((&channel.id, &[])), &listed(1..=2));
    follows_at(&s, &list, &commit('a'), now);
    assert_eq!(
        not_handing(reads(&s, &list, &commit('a'), s.now + 1)),
        NotHanding::NotClean
    );
    assert!(node_keys(&s).is_empty());
}

/// Nothing is handed over in a channel in which this device read an offer
/// that seals to the person and leaves out a key, whether the person is
/// paused, stayed or moved (rule 4.1); a channel moved from is not one
/// dropped, so the follow goes on (rule 6). An offer "without you" does
/// not count.
#[test]
fn nothing_is_handed_over_in_a_channel_made_anew_for_the_person_paused_stayed_or_moved() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let identity = &s[0].identity;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    write_in(&s, &channel, &[&alice, &carol, &dave], now);
    let list = list_with(Some((&channel.id, &[])), &listed(4..=5));
    follows_at(&s, &list, &commit('a'), now);
    // Without you: sealed to Carol and Dave, and not to Bob.
    let without_you = offer_by(
        &carol,
        &channel,
        20,
        &[carol.public_key(), dave.public_key()],
        now,
    );
    stores(&s, 0, &without_you, now);
    let turn = handed(reads(&s, &list, &commit('a'), now + 1));
    assert_eq!(turn.len(), 2, "an offer without you does not count");
    // Sealed to Bob and Alice, without Carol and Dave: Bob is paused.
    stores(
        &s,
        0,
        &offer_by(&alice, &channel, 21, &[alice.public_key(), s.key(0)], now),
        now,
    );
    let made_anew = NotHanding::MadeAnew {
        maker: alice.public_key(),
    };
    assert_eq!(
        not_handing(reads(&s, &list, &commit('a'), now + 2)),
        made_anew
    );
    // Bob stays: he writes there again, and still hands nothing over.
    crate::shared_anew::make_stay(conn, &channel.id, "review").unwrap();
    assert!(
        crate::shared_anew::writes_there(
            conn,
            identity,
            &kept::channel(conn, &channel.id).unwrap().unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        not_handing(reads(&s, &list, &commit('a'), now + 3)),
        made_anew
    );
    // Bob moves: the list names the channel he moved from, and the follow
    // goes on.
    let plan =
        crate::shared_anew::move_plan(conn, identity, &own_relays(), "review", None, None, now)
            .unwrap();
    crate::shared_anew::make_move(conn, identity, &plan.what, now).unwrap();
    assert_eq!(
        not_handing(reads(&s, &list, &commit('a'), now + 4)),
        NotHanding::MovedFrom
    );
    assert!(row(&s).is_some());
}

// ── The notices (rules 4.5, 4.6 and 6) ───────────────────────────────

/// A key the list names that first writes in the channel after the follow
/// shows as joined, once (rule 4.5): one there before the follow does not,
/// nor one the list does not name, nor a device of the person's own; and
/// once seen it does not come back.
#[test]
fn a_listed_key_that_first_writes_after_the_follow_joined_once() {
    let s = bob(2);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    write_in(&s, &channel, &[&alice], now);
    let list = list_of(
        Some((&channel.id, &[])),
        &[
            (alice.public_key(), "alice"),
            (carol.public_key(), "carol"),
            (s.key(1), "bob-desktop"),
        ],
    );
    follows_at(&s, &list, &commit('a'), now + 1);
    write_in(&s, &channel, &[&carol, &dave, &s[1].identity], now + 5);
    reads(&s, &list, &commit('b'), now + READ);
    assert_eq!(notices(&s), [format!("joined carol at {}", commit('b'))]);
    reads(&s, &list, &commit('b'), now + 2 * READ);
    assert_eq!(notices(&s).len(), 1, "once");
    assert_eq!(follows::seen(&s[0].conn, REPOSITORY).unwrap(), 1);
    reads(&s, &list, &commit('c'), now + 3 * READ);
    assert!(notices(&s).is_empty(), "seen, it does not come back");
}

/// A device that comes to hold the channel after it followed takes none of
/// the keys it then first holds for a join: they were there before it, as
/// far as it can tell. A key that first writes after that read is noticed.
#[test]
fn a_device_that_comes_to_hold_the_channel_notices_no_join_of_those_there_before() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = Shared::of(7);
    let (alice, carol) = (member(1), member(2));
    let list = list_of(
        Some((&channel.id, &[])),
        &[(alice.public_key(), "alice"), (carol.public_key(), "carol")],
    );
    follows_at(&s, &list, &commit('a'), now);
    let taken = now + READ / 2;
    holds(&s, 0, 7, "review", taken);
    write_in(&s, &channel, &[&alice], taken + 1);
    reads(&s, &list, &commit('a'), now + READ);
    assert!(notices(&s).is_empty(), "{:?}", notices(&s));
    write_in(&s, &channel, &[&carol], now + READ + 1);
    reads(&s, &list, &commit('a'), now + 2 * READ);
    assert_eq!(notices(&s), [format!("joined carol at {}", commit('a'))]);
}

/// A key in the channel that the list kept named and the latest does not
/// shows as dropped (rule 4.6), whatever the commit; it goes once the list
/// names it again, and comes back with the next drop. A key dropped that
/// is not in the channel shows nothing. A list whose line names another
/// channel shows that (rule 6), and the dropped key, not in that channel,
/// goes; a line changed only in its `without` names the same channel, and
/// a list with no line leaves the channel the one named before. A dropped
/// key's notice stays through `shared seen`.
#[test]
fn a_key_dropped_from_the_list_and_a_changed_line_are_noticed() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let other = holds(&s, 0, 8, "design", now);
    let (alice, carol) = (member(1), member(2));
    write_in(&s, &channel, &[&alice, &carol], now);
    let devices = [
        (alice.public_key(), "alice"),
        (carol.public_key(), "carol"),
        (member(3).public_key(), "dave"),
    ];
    let line = Some((&channel.id, &[][..]));
    let all = list_of(line, &devices);
    follows_at(&s, &all, &commit('a'), now);
    // The same commit, and another list: what changed is read from it.
    let alice_only = list_of(line, &devices[..1]);
    reads(&s, &alice_only, &commit('a'), now + 1);
    assert_eq!(notices(&s), [format!("dropped carol at {}", commit('a'))]);
    reads(&s, &all, &commit('b'), now + 2);
    assert!(notices(&s).is_empty(), "listed again");
    reads(&s, &alice_only, &commit('c'), now + 3);
    assert_eq!(notices(&s), [format!("dropped carol at {}", commit('c'))]);
    follows::seen(&s[0].conn, REPOSITORY).unwrap();
    assert_eq!(notices(&s).len(), 1, "a drop is not seen away");
    // The line names only another `without`: the same channel.
    let eve = member(5).public_key();
    let without = list_of(Some((&channel.id, &[eve][..])), &devices[..1]);
    reads(&s, &without, &commit('d'), now + 4);
    assert_eq!(notices(&s), [format!("dropped carol at {}", commit('c'))]);
    // A list with no channel line: the channel is still the one it named.
    let no_line = list_of(None, &devices[..1]);
    reads(&s, &no_line, &commit('e'), now + 5);
    assert_eq!(notices(&s), [format!("dropped carol at {}", commit('c'))]);
    // Another channel: Carol is not in it, so her notice goes.
    let moved_on = list_of(Some((&other.id, &[][..])), &devices[..1]);
    reads(&s, &moved_on, &commit('f'), now + 6);
    assert_eq!(notices(&s), [format!("line changed at {}", commit('f'))]);
}

// ── The follow stopped (rule 2.5) ────────────────────────────────────

/// A follow whose list names a channel the person dropped is stopped at
/// the next read, before anything else: a drop on this device, and one
/// carried from another device of the person's through their lists;
/// where the list kept names it, though the read failed, and where the
/// list read names it, though the list kept named another.
#[test]
fn a_drop_on_this_device_or_another_stops_the_follow() {
    let mut s = bob(2);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let list = list_with(Some((&channel.id, &[])), &listed(1..=2));
    follows_at(&s, &list, &commit('a'), now);
    s.pass(0, 1);
    let now = s.now + 10;
    acts(&s, 1, Do::Drop(channel.id), now);
    assert_eq!(handed(reads(&s, &list, &commit('a'), now)).len(), 2);
    // Device 0 takes device 1's list, as its next whole fetch does.
    s.pass(1, 0);
    crate::lists::follow(&s[0].conn, &s[0].identity, s.now).unwrap();
    let failed = CloneRead {
        follow: row(&s).unwrap(),
        read: Err(ListFailed::NoRemoteHead {
            remote: "origin".into(),
        }),
    };
    assert_eq!(done(&s, &failed, s.now + 1), Done::Stopped);
    assert!(row(&s).is_none());

    // And on this device.
    let other = holds(&s, 0, 8, "design", s.now + 2);
    let gone = holds(&s, 0, 9, "old", s.now + 2);
    acts(&s, 0, Do::Drop(gone.id), s.now + 3);
    let list = list_with(Some((&other.id, &[])), &listed(1..=2));
    follows_at(&s, &list, &commit('a'), s.now + 3);
    let names_gone = list_with(Some((&gone.id, &[])), &listed(1..=2));
    assert_eq!(
        reads(&s, &names_gone, &commit('b'), s.now + 4),
        Done::Stopped
    );
    assert!(row(&s).is_none());
}

// ── A read that counts for nothing (rules 1 and 3) ───────────────────

/// A clone behind the last commit read gives nothing: the last list
/// stands, and so does the last commit, and why is kept for the status. A
/// read that failed, and a list that does not parse, are the same; the
/// next read that counts clears why.
#[test]
fn a_clone_behind_a_failed_read_and_a_list_that_does_not_parse_leave_the_last_list() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let first = list_with(Some((&channel.id, &[])), &listed(1..=1));
    follows_at(&s, &first, &commit('a'), now);
    let later = list_with(Some((&channel.id, &[])), &listed(1..=4));
    let stands = |s: &Several, word: &str| {
        let row = row(s).unwrap();
        assert_eq!(row.list.as_deref(), Some(first.as_bytes()));
        assert_eq!(row.last.unwrap().commit, commit('a'));
        assert_eq!(row.not_read.unwrap().word, word);
        assert!(node_keys(s).is_empty());
    };

    let behind = done(&s, &read_of(&s, &later, &commit('b'), false), now + 1);
    let Done::NotRead(not) = behind else {
        panic!("{behind:?}")
    };
    assert_eq!(
        not.why,
        format!(
            "your clone is at commit {}, which does not come after commit {}, the last one read",
            commit('b'),
            commit('a')
        )
    );
    stands(&s, "behind");

    let failed = ListFailed::NoRemoteHead {
        remote: "origin".into(),
    };
    let read = CloneRead {
        follow: row(&s).unwrap(),
        read: Err(failed.clone()),
    };
    assert_eq!(
        done(&s, &read, now + 2),
        Done::NotRead(NotRead {
            word: "no_remote_head".into(),
            why: failed.says(),
        })
    );
    stands(&s, "no_remote_head");

    let not_a_list = format!("{later}not a key and a label\n");
    reads(&s, &not_a_list, &commit('b'), now + 3);
    stands(&s, "not_a_list");
    assert_eq!(
        row(&s).unwrap().not_read.unwrap().why,
        "line 6 of the list is not a key and a label"
    );

    assert_eq!(handed(reads(&s, &later, &commit('b'), now + 4)).len(), 4);
    let row = row(&s).unwrap();
    assert_eq!(
        (row.not_read, row.list.as_deref()),
        (None, Some(later.as_bytes()))
    );
}

/// A follow made again while its clone was read is not read against what
/// it was: nothing is done, and the next read does it.
#[test]
fn a_follow_made_again_while_its_clone_was_read_is_read_again_later() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let list = list_with(Some((&channel.id, &[])), &listed(1..=2));
    follows_at(&s, &list, &commit('a'), now);
    let read = read_of(&s, &list, &commit('b'), true);
    follows::follow(
        &s[0].conn,
        REPOSITORY,
        "origin",
        "/home/bob/Work/fork",
        now + 1,
    )
    .unwrap();
    assert_eq!(done(&s, &read, now + 2), Done::Nothing);
    assert!(node_keys(&s).is_empty());
    follows::unfollow(&s[0].conn, REPOSITORY).unwrap();
    assert_eq!(done(&s, &read, now + 3), Done::Nothing);
}

// ── The clones, read with git ────────────────────────────────────────

/// Over a real clone on the disk, and no server: each follow's clone is
/// read at its remote's default branch; a commit after the last one read
/// is read, and kept; a history rewritten, whose commit does not come
/// after it, gives nothing; and a clone that no longer says which branch
/// is its remote's default is a read that failed.
#[test]
fn a_clone_on_the_disk_is_read_and_never_back() {
    let tmp = tempfile::tempdir().unwrap();
    let clone = OnDisk::new(tmp.path());
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let channel = holds(&s, 0, 7, "review", now);
    let top = clone.top.display().to_string();
    let first_list = list_with(Some((&channel.id, &[])), &listed(1..=1));
    let first = clone.fetched(&first_list);
    follows::follow(conn, REPOSITORY, "origin", &top, now).unwrap();
    let read = LastRead {
        commit: first.clone(),
        at: now,
        from_clone: true,
    };
    follows::read_done(conn, REPOSITORY, &read, first_list.as_bytes()).unwrap();
    let git = Git::under(&tmp.path().join("node")).unwrap();
    let read_now = || read_clones(&git, follows::follows(conn).unwrap()).remove(0);

    let second_list = list_with(Some((&channel.id, &[])), &listed(1..=2));
    let second = clone.fetched(&second_list);
    let read = read_now();
    let got = read.read.as_ref().unwrap();
    assert_eq!(got.list.at.commit, second);
    assert_eq!(got.list.at.file.as_deref(), Some(second_list.as_bytes()));
    assert!(got.comes_after);
    assert_eq!(
        done(&s, &read, now + 1),
        Done::Read {
            handed: vec![member(1).public_key(), member(2).public_key()],
            not_handing: None,
        }
    );
    assert_eq!(row(&s).unwrap().last.unwrap().commit, second);

    let side = clone.rewritten(&first_list);
    let read = read_now();
    assert_eq!(read.read.as_ref().unwrap().list.at.commit, side);
    assert!(!read.read.as_ref().unwrap().comes_after);
    assert!(matches!(done(&s, &read, now + 2), Done::NotRead(not) if not.word == "behind"));
    assert_eq!(
        row(&s).unwrap().list.as_deref(),
        Some(second_list.as_bytes())
    );

    std::fs::remove_file(clone.top.join(".git/refs/remotes/origin/HEAD")).unwrap();
    let read = read_now();
    assert!(
        matches!(read.read, Err(ListFailed::NoRemoteHead { .. })),
        "{:?}",
        read.read
    );
    assert!(matches!(done(&s, &read, now + 3), Done::NotRead(not) if not.word == "no_remote_head"));
}
