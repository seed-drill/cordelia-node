//! Tests of the node's read of each list it follows (decision 2026-11-06
//! (joining), rules 2.5, 3 and 4), in-process, with a set time and no
//! relay: the turns of rule 4.2, the shares that go, where nothing is
//! handed over, the notices, the stop of a channel dropped, and a read that
//! counts for nothing; and, last, the clones read with git, over a real
//! clone on the disk.

use super::*;
use crate::following::tests::OnDisk;
use crate::git_list::ListAt;
use crate::lists::tests::filing;
use crate::several::{Several, entry_by};
use crate::shared::NotAShare;
use crate::shared::tests::{HOUR, Shared, acts, anew, anew_of, bob, holds, member, stores};
use cordelia_crypto::acts::Came;
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::entry::Value;
use cordelia_crypto::share::{Share, share_name};
use cordelia_crypto::shared::{Anew, Offer};
use cordelia_storage::meta;

pub(crate) const REPOSITORY: &str = "example.org/team/project";

/// Another repository the device follows.
pub(crate) const OTHER: &str = "example.org/team/other";
pub(crate) const FOLDER: &str = "/home/bob/Work/project";

/// A read's interval, as the node keeps it.
pub(crate) const READ: i64 = 600;

/// The relay of these tests' channels, known by its key: that of
/// [`filing`]'s card.
pub(crate) const AT: [u8; 32] = [3; 32];

/// The device's relays known by their keys: that of [`filing`]'s card,
/// where a channel lives, and that of a channel line ([`line_relay`]),
/// which a device that takes the channel reads (rule 4.4).
pub(crate) fn own_relays() -> Vec<OwnRelay> {
    vec![
        OwnRelay {
            name: "relay.example.org:9474".into(),
            key: AT,
        },
        OwnRelay {
            name: "line.example.org:9474".into(),
            key: line_relay(),
        },
    ]
}

/// The key a channel line of these tests gives its relay: one that can be
/// used, as a relay's is. Only a device that takes the channel reads it.
pub(crate) fn line_relay() -> [u8; 32] {
    NodeIdentity::from_seed([0x52; 32]).unwrap().public_key()
}

pub(crate) fn commit(c: char) -> String {
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
pub(crate) fn list_of(
    channel: Option<(&[u8; 32], &[[u8; 32]])>,
    devices: &[([u8; 32], &str)],
) -> String {
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
pub(crate) fn listed(numbers: impl IntoIterator<Item = u32>) -> Vec<([u8; 32], String)> {
    numbers
        .into_iter()
        .map(|n| (member(n).public_key(), format!("m{n}")))
        .collect()
}

/// [`list_of`], of `devices` as [`listed`] gives them.
pub(crate) fn list_with(
    channel: Option<(&[u8; 32], &[[u8; 32]])>,
    devices: &[([u8; 32], String)],
) -> String {
    let devices: Vec<([u8; 32], &str)> = devices
        .iter()
        .map(|(key, label)| (*key, label.as_str()))
        .collect();
    list_of(channel, &devices)
}

/// Device 0 follows the repository from `at`, with its list `list` at
/// `commit` read then: as `subscribe` in a clone leaves it.
pub(crate) fn follows_at(s: &Several, list: &str, commit: &str, at: i64) {
    follows_as(s, REPOSITORY, list, commit, at);
}

/// [`follows_at`], of the repository `repository`.
pub(crate) fn follows_as(s: &Several, repository: &str, list: &str, commit: &str, at: i64) {
    let conn = &s[0].conn;
    follows::follow(conn, repository, "origin", FOLDER, at).unwrap();
    let read = LastRead {
        commit: commit.into(),
        at,
        from_clone: true,
    };
    follows::read_done(conn, repository, &read, list.as_bytes(), None).unwrap();
}

/// The follow on device 0.
pub(crate) fn row(s: &Several) -> Option<Follow> {
    row_of(s, REPOSITORY)
}

/// The follow of `repository` on device 0.
pub(crate) fn row_of(s: &Several, repository: &str) -> Option<Follow> {
    follows::follow_of(&s[0].conn, repository).unwrap()
}

/// What device 0 read of its clone: `list` at `commit`, for the follow as
/// it is now, with never-back's answer `comes_after`.
pub(crate) fn read_of(s: &Several, list: &str, commit: &str, comes_after: bool) -> CloneRead {
    read_as(s, REPOSITORY, list, commit, comes_after)
}

/// [`read_of`], of the repository `repository`.
pub(crate) fn read_as(
    s: &Several,
    repository: &str,
    list: &str,
    commit: &str,
    comes_after: bool,
) -> CloneRead {
    CloneRead {
        follow: row_of(s, repository).unwrap(),
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
pub(crate) fn done(s: &Several, read: &CloneRead, now: i64) -> Done {
    after_read(&s[0].conn, &s[0].identity, &own_relays(), read, now).unwrap()
}

/// Device 0 reads `list` at `commit`, at `now`.
pub(crate) fn reads(s: &Several, list: &str, commit: &str, now: i64) -> Done {
    done(s, &read_of(s, list, commit, true), now)
}

/// Device 0 reads `list` of the repository `repository` at `commit`, at
/// `now`.
fn reads_as(s: &Several, repository: &str, list: &str, commit: &str, now: i64) -> Done {
    done(s, &read_as(s, repository, list, commit, true), now)
}

/// The node's shares waiting on device 0, each key with its channel.
fn node_shares_in(s: &Several) -> Vec<([u8; 32], [u8; 32])> {
    follows::shares_by_node(&s[0].conn)
        .unwrap()
        .into_iter()
        .map(|share| (share.key, share.channel))
        .collect()
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
pub(crate) fn node_shares(s: &Several) -> Vec<([u8; 32], i64)> {
    let mut shares: Vec<([u8; 32], i64)> = follows::shares_by_node(&s[0].conn)
        .unwrap()
        .into_iter()
        .map(|share| (share.key, share.made))
        .collect();
    shares.sort();
    shares
}

/// The keys of the node's shares waiting on device 0, by key.
pub(crate) fn node_keys(s: &Several) -> Vec<[u8; 32]> {
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
pub(crate) fn write_in(s: &Several, channel: &Shared, writers: &[&NodeIdentity], now: i64) {
    for writer in writers {
        stores(s, 0, &anew(writer, channel, 1), now);
    }
}

/// The offer of `maker` that makes `old` anew as the card of `seed`,
/// sealed to `keys`, at revision `rev`.
pub(crate) fn offer_by(
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
/// read, twenty minutes on, as the first four's shares go, and those four
/// wait for that read. Once the ninth writes in the channel it is handed
/// nothing more.
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
        [k[8]],
        "the ninth; the first four's shares went, and they wait for this read"
    );
    let mut waiting: Vec<([u8; 32], i64)> = k[4..8].iter().map(|key| (*key, second)).collect();
    waiting.push((k[8], third));
    waiting.sort();
    assert_eq!(node_shares(&s), waiting);

    // The ninth wrote in the channel: it is in it, and handed nothing more.
    write_in(&s, &channel, &[&member(9)], third + 1);
    let fourth = third + READ;
    let turn = handed(reads(&s, &list, &commit('a'), fourth));
    assert_eq!(turn, k[0..4], "after the ninth, the first four again");
    let fifth = fourth + READ;
    let turn = handed(reads(&s, &list, &commit('a'), fifth));
    assert!(!turn.contains(&k[8]), "{turn:?}");
}

/// A share of the node's lives for two reads, then is deleted: it is not
/// made again while it waits, the read after next writes a delete over it,
/// and the key waits for that read before it is handed the channel again.
#[test]
fn a_nodes_share_lives_two_reads() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let alice = member(1).public_key();
    let list = list_of(Some((&channel.id, &[])), &[(alice, "alice")]);
    follows_at(&s, &list, &commit('a'), now);
    let (first, second, third, fourth) =
        (now + READ, now + 2 * READ, now + 3 * READ, now + 4 * READ);
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
    assert!(handed(reads(&s, &list, &commit('a'), third)).is_empty());
    assert!(node_shares(&s).is_empty());
    assert!(rev(&s).1, "written over");
    assert_eq!(handed(reads(&s, &list, &commit('a'), fourth)), [alice]);
    assert_eq!(node_shares(&s), [(alice, fourth)]);
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

/// Two repositories whose lists name one key, each with its own channel:
/// a read passes over a key that a share of the other's waits for, so
/// neither writes over the other's share, and each has its turn (rule
/// 4.2; the review of slice 5a, M1).
#[test]
fn two_repositories_that_list_one_key_take_turns_with_it() {
    let s = bob(1);
    let now = s.now + 10;
    let review = holds(&s, 0, 7, "review", now);
    let design = holds(&s, 0, 8, "design", now);
    let alice = member(1).public_key();
    let a = list_of(Some((&review.id, &[])), &[(alice, "alice")]);
    let b = list_of(Some((&design.id, &[])), &[(alice, "alice")]);
    follows_as(&s, REPOSITORY, &a, &commit('a'), now);
    follows_as(&s, OTHER, &b, &commit('a'), now);
    let (first, second, third) = (now + READ, now + 2 * READ, now + 3 * READ);
    assert_eq!(
        handed(reads_as(&s, REPOSITORY, &a, &commit('a'), first)),
        [alice]
    );
    assert!(handed(reads_as(&s, OTHER, &b, &commit('a'), first + 1)).is_empty());
    assert_eq!(node_shares_in(&s), [(alice, review.id)], "not written over");
    assert!(handed(reads_as(&s, REPOSITORY, &a, &commit('a'), second)).is_empty());
    assert!(handed(reads_as(&s, OTHER, &b, &commit('a'), second + 1)).is_empty());
    assert_eq!(node_shares_in(&s), [(alice, review.id)]);
    // The first's share goes after its two reads, and the other's turn
    // comes.
    assert!(handed(reads_as(&s, REPOSITORY, &a, &commit('a'), third)).is_empty());
    assert_eq!(
        handed(reads_as(&s, OTHER, &b, &commit('a'), third + 1)),
        [alice]
    );
    assert_eq!(node_shares_in(&s), [(alice, design.id)]);
}

/// A share of the node's goes as soon as it is not of the channel the
/// list names: a line that names another channel takes the old channel's
/// shares at that read (the review of slice 5a, L3).
#[test]
fn a_nodes_share_of_a_channel_the_list_no_longer_names_goes_at_once() {
    let s = bob(1);
    let now = s.now + 10;
    let review = holds(&s, 0, 7, "review", now);
    let design = holds(&s, 0, 8, "design", now);
    let alice = member(1).public_key();
    let first = list_of(Some((&review.id, &[])), &[(alice, "alice")]);
    follows_at(&s, &first, &commit('a'), now);
    assert_eq!(handed(reads(&s, &first, &commit('a'), now + READ)), [alice]);
    let moved_on = list_of(Some((&design.id, &[])), &[(alice, "alice")]);
    assert!(handed(reads(&s, &moved_on, &commit('b'), now + 2 * READ)).is_empty());
    assert!(node_shares_in(&s).is_empty(), "{:?}", node_shares_in(&s));
    assert_eq!(
        handed(reads(&s, &moved_on, &commit('b'), now + 3 * READ)),
        [alice]
    );
    assert_eq!(node_shares_in(&s), [(alice, design.id)]);
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
    let turn = Turn {
        held: &held,
        own_relays: &own_relays(),
        follow: &follow,
        list: &list,
        line,
        filing: &filing,
        waiting: &[],
    };
    let handed = hand_over(conn, identity, &turn, now + 1).unwrap();
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
/// dropped, so the follow goes on (rule 6).
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
    let turn = handed(reads(&s, &list, &commit('a'), now + 1));
    assert_eq!(turn.len(), 2);
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

/// Nothing is handed over either in a channel in which this device read an
/// offer "without you", which leaves the person out (rule 4.1, as the
/// person ruled on 8 November): a device left out hands a newcomer nothing
/// that the channel's members are leaving. Only an offer that is a fault
/// does not count, as one into a channel the person holds.
#[test]
fn nothing_is_handed_over_in_a_channel_made_anew_without_the_person_and_a_fault_does_not_count() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    holds(&s, 0, 8, "design", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    write_in(&s, &channel, &[&alice, &carol, &dave], now);
    let list = list_with(Some((&channel.id, &[])), &listed(4..=5));
    follows_at(&s, &list, &commit('a'), now);
    // A fault: an offer into "design", which the person holds.
    let sealed = [carol.public_key(), dave.public_key()];
    stores(&s, 0, &offer_by(&dave, &channel, 8, &sealed, now), now);
    let turn = handed(reads(&s, &list, &commit('a'), now + 1));
    assert_eq!(turn.len(), 2, "an offer that is a fault does not count");
    // Without you: sealed to Carol and Dave, and not to Bob.
    stores(&s, 0, &offer_by(&carol, &channel, 20, &sealed, now), now);
    assert_eq!(
        not_handing(reads(&s, &list, &commit('a'), now + 2)),
        NotHanding::MadeAnew {
            maker: carol.public_key()
        }
    );
}

// ── The notices (rules 4.5, 4.6 and 6) ───────────────────────────────

/// The keys of device 0 that rule 4.5 names new on the list, as text: each
/// label with its commit, by label.
fn named_new(s: &Several) -> Vec<String> {
    let mut joins: Vec<String> = notices(s)
        .into_iter()
        .filter(|notice| notice.starts_with("joined "))
        .collect();
    joins.sort();
    joins
}

/// `label` new on the list at `commit`, as [`named_new`] says it.
fn joined_at(label: &str, commit: &str) -> String {
    format!("joined {label} at {commit}")
}

/// The person says yes on device 0 to follow the repository from its clone
/// with the list `list` at `commit`, at `now`: a first follow, or a follow
/// again (rule 2.5).
fn subscribes(s: &Several, list: &str, commit: &str, now: i64) {
    let following = crate::following::Following {
        identity: REPOSITORY.into(),
        remote: "origin".into(),
        clone: FOLDER.into(),
        commit: commit.into(),
        list: list.as_bytes().to_vec(),
        fetched_at: None,
        replaces: None,
        agent: "project".into(),
        then: crate::following::Then::Nothing,
    };
    crate::following::make(&s[0].conn, &s[0].identity, &following, now).unwrap();
}

/// A first follow names, at its yes, each key on the list but the person's
/// own: this device and their other device, each as itself or its twin. A
/// device of theirs that was removed is theirs no more, and is named. It
/// asks nothing of the channel, which this device does not hold here.
/// Following again names nothing; the node's next read names a key the
/// list adds. After `unsubscribe`, a new follow names every key again.
#[test]
fn a_first_follow_names_every_key_on_the_list_but_your_own() {
    let mut s = bob(3);
    s.change(0, &[0, 1], &[2]);
    let now = s.now + 10;
    let channel = Shared::of(7);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    let mut devices = vec![
        (alice.public_key(), "alice-laptop"),
        (s.key(0), "bob-laptop"),
        (twin(&s.key(1)), "bob-desktop"),
        (s.key(2), "bob-old"),
        (carol.public_key(), "carol-laptop"),
    ];
    let list = list_of(Some((&channel.id, &[])), &devices);
    subscribes(&s, &list, &commit('a'), now);
    let first = [
        joined_at("alice-laptop", &commit('a')),
        joined_at("bob-old", &commit('a')),
        joined_at("carol-laptop", &commit('a')),
    ];
    assert_eq!(named_new(&s), first);
    // The node's read just after it: the same list, nothing new.
    reads(&s, &list, &commit('a'), now + 1);
    assert_eq!(named_new(&s), first);

    // Following again, with Dave on the list: nothing at the yes, and Dave
    // at the node's next read, against the list kept.
    devices.push((dave.public_key(), "dave-laptop"));
    let with_dave = list_of(Some((&channel.id, &[])), &devices);
    subscribes(&s, &with_dave, &commit('b'), now + 2);
    assert_eq!(named_new(&s), first, "following again names nothing");
    reads(&s, &with_dave, &commit('b'), now + 3);
    assert!(named_new(&s).contains(&joined_at("dave-laptop", &commit('b'))));

    // `unsubscribe`, and a new follow: every key again, with the twin of
    // this device and the other device as itself.
    follows::unfollow(&s[0].conn, REPOSITORY).unwrap();
    let again = list_of(
        Some((&channel.id, &[])),
        &[
            (twin(&s.key(0)), "bob-laptop"),
            (s.key(1), "bob-desktop"),
            (alice.public_key(), "alice-laptop"),
            (dave.public_key(), "dave-laptop"),
        ],
    );
    subscribes(&s, &again, &commit('c'), now + 4);
    assert_eq!(
        named_new(&s),
        [
            joined_at("alice-laptop", &commit('c')),
            joined_at("dave-laptop", &commit('c')),
        ]
    );
    let kept = follows::notices(&s[0].conn, REPOSITORY).unwrap();
    assert!(kept.iter().any(|notice| notice.of
        == NoticeOf::Joined {
            key: alice.public_key(),
            label: "alice-laptop".into(),
            channel: channel.id,
        }));
}

/// A clone that lags: a key whose entries this device held before its list
/// named it is named at the read that first lists it. Who wrote in the
/// channel, and when, counts for nothing.
#[test]
fn a_key_held_before_the_list_named_it_is_named_when_it_is_listed() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    let first = list_of(Some((&channel.id, &[])), &[(alice.public_key(), "alice")]);
    follows_at(&s, &first, &commit('a'), now);
    write_in(&s, &channel, &[&alice, &carol], now + 5);
    reads(&s, &first, &commit('a'), now + READ);
    assert!(named_new(&s).is_empty(), "Alice was on the list kept");
    let both = list_of(
        Some((&channel.id, &[])),
        &[(alice.public_key(), "alice"), (carol.public_key(), "carol")],
    );
    reads(&s, &both, &commit('b'), now + 2 * READ);
    assert_eq!(named_new(&s), [joined_at("carol", &commit('b'))]);
}

/// A channel made anew, and moved to, between two reads: a list that names
/// the new channel with the same keys names none, and a key it lists for
/// the first time is named.
#[test]
fn a_channel_made_anew_names_only_a_key_new_on_the_list() {
    let s = bob(1);
    let now = s.now + 10;
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let old = holds(&s, 0, 7, "review", now);
    let (alice, carol, eve) = (member(1), member(2), member(4));
    write_in(&s, &old, &[&alice, &carol], now);
    let devices = [(alice.public_key(), "alice"), (carol.public_key(), "carol")];
    follows_at(
        &s,
        &list_of(Some((&old.id, &[])), &devices),
        &commit('a'),
        now,
    );
    let sealed = [alice.public_key(), carol.public_key(), s.key(0)];
    stores(&s, 0, &offer_by(&alice, &old, 21, &sealed, now), now);
    let plan =
        crate::shared_anew::move_plan(conn, identity, &own_relays(), "review", None, None, now)
            .unwrap();
    crate::shared_anew::make_move(conn, identity, &plan.what, now).unwrap();
    let new = Shared::of(21);
    assert_eq!(plan.what.to.channel, new.id);
    write_in(&s, &new, &[&alice, &carol, &eve], now + 5);
    let same = list_of(Some((&new.id, &[])), &devices);
    reads(&s, &same, &commit('b'), now + READ);
    assert!(named_new(&s).is_empty(), "{:?}", notices(&s));
    let with_eve = list_of(
        Some((&new.id, &[])),
        &[devices[0], devices[1], (eve.public_key(), "eve")],
    );
    reads(&s, &with_eve, &commit('c'), now + 2 * READ);
    assert_eq!(named_new(&s), [joined_at("eve", &commit('c'))]);
}

/// A key dropped from the list and then listed again is named again, at
/// the commit that lists it again: its notice not yet cleared takes that
/// commit.
#[test]
fn a_key_dropped_and_listed_again_is_named_again() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    let line = Some((&channel.id, &[][..]));
    let alice_only = list_of(line, &[(alice.public_key(), "alice")]);
    let both = list_of(
        line,
        &[(alice.public_key(), "alice"), (carol.public_key(), "carol")],
    );
    follows_at(&s, &alice_only, &commit('a'), now);
    reads(&s, &both, &commit('b'), now + 1);
    assert_eq!(named_new(&s), [joined_at("carol", &commit('b'))]);
    reads(&s, &alice_only, &commit('c'), now + 2);
    reads(&s, &both, &commit('d'), now + 3);
    assert_eq!(named_new(&s), [joined_at("carol", &commit('d'))]);
    assert_eq!(follows::seen(&s[0].conn, REPOSITORY).unwrap(), 1);
    reads(&s, &alice_only, &commit('e'), now + 4);
    reads(&s, &both, &commit('f'), now + 5);
    assert_eq!(named_new(&s), [joined_at("carol", &commit('f'))]);
}

/// A read that counts for nothing names nothing, whether it failed, was
/// behind, or its list did not parse: the next read that counts names the
/// key, against the list kept.
#[test]
fn a_read_that_counts_for_nothing_names_nothing() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let first = list_with(Some((&channel.id, &[])), &listed(1..=1));
    follows_at(&s, &first, &commit('a'), now);
    let later = list_with(Some((&channel.id, &[])), &listed(1..=2));
    let failed = CloneRead {
        follow: row(&s).unwrap(),
        read: Err(ListFailed::NoRemoteHead {
            remote: "origin".into(),
        }),
    };
    assert!(matches!(done(&s, &failed, now + 1), Done::NotRead(_)));
    let behind = read_of(&s, &later, &commit('b'), false);
    assert!(matches!(done(&s, &behind, now + 2), Done::NotRead(_)));
    let not_a_list = format!("{later}not a key and a label\n");
    assert!(matches!(
        reads(&s, &not_a_list, &commit('b'), now + 3),
        Done::NotRead(_)
    ));
    assert!(notices(&s).is_empty(), "{:?}", notices(&s));
    reads(&s, &later, &commit('b'), now + 4);
    assert_eq!(named_new(&s), [joined_at("m2", &commit('b'))]);
}

/// A list with no channel line names nothing; the first read whose list
/// has one names every key on it but the person's own, those listed
/// before included.
#[test]
fn the_first_list_with_a_channel_line_names_every_key() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = Shared::of(7);
    let (alice, carol) = (member(1), member(2));
    let no_line = list_of(
        None,
        &[(alice.public_key(), "alice"), (s.key(0), "bob-laptop")],
    );
    follows_at(&s, &no_line, &commit('a'), now);
    let with_carol = list_of(
        None,
        &[
            (alice.public_key(), "alice"),
            (s.key(0), "bob-laptop"),
            (carol.public_key(), "carol"),
        ],
    );
    reads(&s, &with_carol, &commit('b'), now + 1);
    assert!(named_new(&s).is_empty());
    let named = list_of(
        Some((&channel.id, &[])),
        &[
            (alice.public_key(), "alice"),
            (s.key(0), "bob-laptop"),
            (carol.public_key(), "carol"),
        ],
    );
    reads(&s, &named, &commit('c'), now + 2);
    assert_eq!(
        named_new(&s),
        [
            joined_at("alice", &commit('c')),
            joined_at("carol", &commit('c'))
        ]
    );
}

/// A key in the channel that the list kept named and the latest does not
/// shows as dropped (rule 4.6), whatever the commit; it goes once the list
/// names it again, and comes back with the next drop. A key dropped that
/// is not in the channel shows nothing. A list whose line names another
/// channel shows that (rule 6), and the dropped key, not in that channel,
/// goes; a line changed only in its `without` names the same channel, a
/// list with no line leaves the channel the one named before, and a line
/// after a list with none is no change, as after `subscribe --new`. A
/// dropped key's notice stays through `shared seen`. Beside these, rule
/// 4.5 names each key listed again, and every key of the first list with a
/// line after one with none.
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
    // The notices but rule 4.5's.
    let others = |s: &Several| -> Vec<String> {
        notices(s)
            .into_iter()
            .filter(|notice| !notice.starts_with("joined "))
            .collect()
    };
    let line = Some((&channel.id, &[][..]));
    let all = list_of(line, &devices);
    follows_at(&s, &all, &commit('a'), now);
    // The same commit, and another list: what changed is read from it.
    let alice_only = list_of(line, &devices[..1]);
    reads(&s, &alice_only, &commit('a'), now + 1);
    assert_eq!(notices(&s), [format!("dropped carol at {}", commit('a'))]);
    reads(&s, &all, &commit('b'), now + 2);
    assert!(others(&s).is_empty(), "listed again");
    assert_eq!(
        named_new(&s),
        [
            joined_at("carol", &commit('b')),
            joined_at("dave", &commit('b'))
        ]
    );
    reads(&s, &alice_only, &commit('c'), now + 3);
    assert_eq!(others(&s), [format!("dropped carol at {}", commit('c'))]);
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
    // A line again, after none: no change is noticed, and each key on the
    // list is new.
    reads(&s, &alice_only, &commit('f'), now + 6);
    assert_eq!(others(&s), [format!("dropped carol at {}", commit('c'))]);
    assert_eq!(named_new(&s), [joined_at("alice", &commit('f'))]);
    // Another channel: Carol is not in it, so her notice goes.
    let moved_on = list_of(Some((&other.id, &[][..])), &devices[..1]);
    reads(&s, &moved_on, &commit('g'), now + 7);
    assert_eq!(others(&s), [format!("line changed at {}", commit('g'))]);
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

/// A channel moved from twice, as after two makings anew before a list
/// names either, is moved from, not dropped: a read of a list that still
/// names it does not stop the follow, and the take says to put the new
/// line in the list (rules 2.5 and 6).
#[test]
fn a_channel_moved_from_twice_is_not_taken_for_one_dropped() {
    use crate::shared_anew::tests::{anew_keeping, filed_as, holds_at_line_at, written_by};
    let s = bob(1);
    let now = s.now + 10;
    let old = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    written_by(&s, 0, &old, &[&alice, &carol, &dave], now);
    let mut list = ChannelLine {
        channel: old.id,
        relays: vec![line_relay()],
        without: Vec::new(),
    }
    .to_line()
    .unwrap();
    list.push('\n');
    for (key, label) in [(alice.public_key(), "alice"), (carol.public_key(), "carol")] {
        list.push_str(&format!("{}   {label}\n", encode_public_key(&key).unwrap()));
    }
    follows_at(&s, &list, &commit('a'), now);
    let keep = [alice.public_key(), dave.public_key()];
    anew_keeping(&s, 0, "review", &keep, now + 1);
    let first = filed_as(&s, 0, "review");
    written_by(&s, 0, &first, &[&alice, &dave], now + 2);
    anew_keeping(&s, 0, "review", &keep[..1], now + 3);
    assert_eq!(
        crate::shared_anew::dropped_or_moved(&s[0].conn, &old.id).unwrap(),
        Some(crate::shared_anew::Gone::Moved)
    );
    reads(&s, &list, &commit('a'), now + 4);
    assert!(row(&s).is_some(), "a move is not a drop");
    assert_eq!(not_taking(&s).0, "moved");
}

// ── One follow for each channel (rule 2.5) ───────────────────────────

/// A list that names a channel another follow's list names counts for
/// nothing: the follow that named it first keeps it, and why is kept for
/// the status (the review of slice 5a, M2).
#[test]
fn a_list_that_names_a_channel_another_follow_names_counts_for_nothing() {
    let s = bob(1);
    let now = s.now + 10;
    let review = holds(&s, 0, 7, "review", now);
    let design = holds(&s, 0, 8, "design", now);
    let alice = member(1).public_key();
    let a = list_of(Some((&review.id, &[])), &[(alice, "alice")]);
    let b = list_of(Some((&design.id, &[])), &[(alice, "alice")]);
    follows_as(&s, REPOSITORY, &a, &commit('a'), now);
    follows_as(&s, OTHER, &b, &commit('a'), now);
    let names_review = list_of(
        Some((&review.id, &[])),
        &[(alice, "alice"), (member(2).public_key(), "carol")],
    );
    let not = NotRead {
        word: "followed_elsewhere".into(),
        why: format!(
            "The list of {OTHER} names \"review\", which this device follows from {REPOSITORY}: \
             run cordelia subscribe in a clone of the one it should follow."
        ),
    };
    let read = reads_as(&s, OTHER, &names_review, &commit('b'), now + READ);
    assert_eq!(read, Done::NotRead(not.clone()));
    let other = row_of(&s, OTHER).unwrap();
    assert_eq!(
        other.list.as_deref(),
        Some(b.as_bytes()),
        "the last list stands"
    );
    assert_eq!(other.last.unwrap().commit, commit('a'));
    assert_eq!(other.not_read, Some(not));
    assert!(node_shares_in(&s).is_empty());
    // The follow that named it first keeps it.
    assert_eq!(
        handed(reads_as(&s, REPOSITORY, &a, &commit('a'), now + READ + 1)),
        [alice]
    );
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
            &commit('b')[..12],
            &commit('a')[..12]
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

    // A read that counts keeps when the clone says it was fetched.
    let mut read = read_of(&s, &later, &commit('b'), true);
    let fetched = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_799_000_000);
    if let Ok(got) = &mut read.read {
        got.list.fetched = Some(fetched);
    }
    assert_eq!(handed(done(&s, &read, now + 4)).len(), 4);
    let row = row(&s).unwrap();
    assert_eq!(
        (row.not_read, row.list.as_deref(), row.fetched_at),
        (None, Some(later.as_bytes()), Some(1_799_000_000))
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

/// A second follow of the same clone, at a commit of a history rewritten,
/// made while a read of the clone ran, is not written over by that read:
/// the read was checked against the commit before (the review of slice
/// 5a, L2).
#[test]
fn a_follow_made_again_on_the_same_clone_is_not_written_over_by_a_stale_read() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let list = list_with(Some((&channel.id, &[])), &listed(1..=2));
    follows_at(&s, &list, &commit('a'), now);
    let stale = read_of(
        &s,
        &list_with(Some((&channel.id, &[])), &listed(1..=4)),
        &commit('b'),
        true,
    );
    let conn = &s[0].conn;
    follows::follow(conn, REPOSITORY, "origin", FOLDER, now + 1).unwrap();
    let rewritten = LastRead {
        commit: commit('c'),
        at: now,
        from_clone: true,
    };
    follows::set_last_read(conn, REPOSITORY, &rewritten).unwrap();
    assert_eq!(done(&s, &stale, now + 2), Done::Nothing);
    let row = row(&s).unwrap();
    assert_eq!(row.last, Some(rewritten));
    assert_eq!(row.list.as_deref(), Some(list.as_bytes()));
    assert!(node_keys(&s).is_empty());
}

// ── Taking (rule 4.4) ────────────────────────────────────────────────

/// The name a channel of [`REPOSITORY`] is filed under: its `owner/name`.
const NAME: &str = "team/project";

/// The agent of [`FOLDER`], the clone of the follow.
pub(crate) const AGENT: &str = "project";

/// Device 0 maps [`FOLDER`] to [`AGENT`].
pub(crate) fn maps_the_clone(s: &Several) {
    let mapped = serde_json::json!([{ "folder": FOLDER, "name": AGENT }]);
    meta::set(&s[0].conn, meta::SYNC_CLAUDE_MAPPINGS, &mapped.to_string()).unwrap();
}

/// The list of these tests' takes: the channel line of `channel`, with
/// `without`, and members `numbers` and every device of Bob's, each
/// labelled.
pub(crate) fn bobs_list(
    s: &Several,
    channel: &Shared,
    numbers: impl IntoIterator<Item = u32>,
    without: &[[u8; 32]],
) -> String {
    let mut devices = listed(numbers);
    for n in 0..s.machines.len() {
        devices.push((s.key(n), format!("bob-{n}")));
    }
    list_with(Some((&channel.id, without)), &devices)
}

/// Device 0 follows a list that names the channel of the card of `seed`,
/// Alice and Carol (members 1 and 2) and each device of Bob's, from `now`:
/// the channel and the list.
pub(crate) fn joins(s: &Several, seed: u8, now: i64) -> (Shared, String) {
    let channel = Shared::of(seed);
    let list = bobs_list(s, &channel, 1..=2, &[]);
    follows_at(s, &list, &commit('a'), now);
    (channel, list)
}

/// A share by `from` of the channel of the card of `seed`, for device 0,
/// made at `made`, in their share pair channel.
pub(crate) fn share_of(s: &Several, from: &NodeIdentity, seed: u8, made: i64) -> CheckedEntry {
    let card = filing(seed, "x").card;
    let to = s.key(0);
    let (_, secret) = crate::shared_pass::share_pair(from, &to).unwrap();
    let share = Share {
        made: u64::try_from(made).unwrap(),
        for_key: to,
        card: card.clone(),
    };
    let name = share_name(&card.channel_id().unwrap());
    entry_by(from, &secret, 1, &name, Value::Other(share.to_value()), &[])
}

/// The keys the node typed on device 0 for the follow, by key.
fn typed_keys(s: &Several) -> Vec<[u8; 32]> {
    follows::typed(&s[0].conn, REPOSITORY)
        .unwrap()
        .into_iter()
        .map(|typed| typed.key)
        .collect()
}

/// What became of the node's typing of `key` on device 0, and its line.
fn became_of(s: &Several, key: &[u8; 32]) -> (Option<String>, Option<String>) {
    let typed = follows::typed(&s[0].conn, REPOSITORY).unwrap();
    let typed = typed.into_iter().find(|typed| typed.key == *key).unwrap();
    (typed.became, typed.detail)
}

/// The keys device 0 asks its relays for at `now`, by key.
fn asked_for(s: &Several, now: i64) -> Vec<[u8; 32]> {
    let keys: Vec<[u8; 32]> = to_ask(&s[0].conn, now)
        .unwrap()
        .into_iter()
        .map(|typing| typing.key)
        .collect();
    sorted(&keys)
}

/// The node's typing of `from`'s key on device 0 that it asks its relays
/// for at `now`.
pub(crate) fn typing_of(s: &Several, from: &NodeIdentity, now: i64) -> Typing {
    let key = from.public_key();
    to_ask(&s[0].conn, now)
        .unwrap()
        .into_iter()
        .find(|typing| typing.key == key)
        .unwrap_or_else(|| panic!("no typing of the key to ask for"))
}

/// What device 0's pass does with `entries`, handed from the share pair
/// channel of `typing`'s key at `now`: each judged, and those that pass
/// given to the take.
pub(crate) fn handed_to(
    s: &Several,
    typing: &Typing,
    entries: &[CheckedEntry],
    now: i64,
) -> Became {
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let found: Vec<CheckedEntry> = entries
        .iter()
        .filter_map(
            |entry| match judge(conn, identity, typing, entry, now).unwrap() {
                Some(Judged::Share(entry)) => Some(*entry),
                _ => None,
            },
        )
        .collect();
    take(conn, identity, typing, &found, &own_relays(), now).unwrap()
}

/// Why device 0 takes nothing for its follow, with this list kept: its
/// word and line.
fn not_taking(s: &Several) -> (&'static str, String) {
    let follow = row(s).unwrap();
    let why = takes_in(&s[0].conn, &s[0].identity, &own_relays(), &follow)
        .unwrap()
        .unwrap_err();
    (why.word, why.line)
}

/// Device 0's filings, each channel with its name and where it came from.
fn filings_of(s: &Several, n: usize) -> Vec<([u8; 32], String, Came)> {
    sharing::filed(&s[n].conn)
        .unwrap()
        .into_iter()
        .map(|filing| (filing.channel, filing.name, filing.came))
        .collect()
}

/// A device on the list that does not hold the channel it names types each
/// listed key at each read, but its person's own devices', and asks its
/// relays for each once after the read (rule 4.4). The share of the named
/// channel from a listed key is taken as `accept --channel` takes one:
/// filed under the repository's `owner/name` on every device of the
/// person's, as taken from the key. What became of each typing is kept;
/// the agent of the clone is subscribed; and once the person holds the
/// channel, a read types nothing.
#[test]
fn the_named_channel_is_taken_from_a_listed_key_on_every_device() {
    let mut s = bob(2);
    let now = s.now + 10;
    maps_the_clone(&s);
    let (channel, list) = joins(&s, 7, now);
    let (alice, carol) = (member(1), member(2));
    let both = sorted(&[alice.public_key(), carol.public_key()]);
    assert!(typed_keys(&s).is_empty(), "nothing is typed before a read");
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    assert_eq!(typed_keys(&s), both, "not Bob's own devices");
    let at = read + 10;
    assert_eq!(asked_for(&s, at), both);

    // Carol has handed nothing: she is asked for once, until the next read.
    let typing = typing_of(&s, &carol, at);
    assert_eq!(handed_to(&s, &typing, &[], at), Became::Nothing);
    assert_eq!(
        became_of(&s, &carol.public_key()),
        (Some(ASKED.into()), None)
    );
    assert_eq!(asked_for(&s, at), [alice.public_key()]);
    // Alice handed it, a minute before the read.
    let typing = typing_of(&s, &alice, at);
    let share = share_of(&s, &alice, 7, read - 60);
    assert_eq!(
        handed_to(&s, &typing, &[share], at),
        Became::Taken(channel.id)
    );
    assert_eq!(
        filings_of(&s, 0),
        [(channel.id, NAME.into(), Came::Taken(alice.public_key()))]
    );
    assert_eq!(
        became_of(&s, &alice.public_key()),
        (Some(TAKEN.into()), None)
    );
    assert!(asked_for(&s, at).is_empty());
    let subscribed = crate::shared_messages::in_force(&s[0].conn).unwrap();
    assert_eq!(subscribed, [(channel.id, AGENT.to_string())]);

    // Bob's other device holds it too, from device 0's list.
    s.pass(0, 1);
    crate::lists::follow(&s[1].conn, &s[1].identity, s.now).unwrap();
    assert_eq!(
        filings_of(&s, 1),
        [(channel.id, NAME.into(), Came::Taken(alice.public_key()))]
    );
    // The next read: the person holds it, and nothing is typed.
    reads(&s, &list, &commit('a'), read + READ);
    assert!(typed_keys(&s).is_empty());
    assert_eq!(not_taking(&s).0, "held");
}

/// A share of another channel from a listed key is not taken, alone or
/// beside the share of the channel the list names, which is then taken
/// (rule 4.4): the take is told the one channel it may take.
#[test]
fn a_share_of_another_channel_from_a_listed_key_is_not_taken() {
    let s = bob(1);
    let now = s.now + 10;
    let (channel, list) = joins(&s, 7, now);
    let alice = member(1);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    let other = share_of(&s, &alice, 8, read);
    let typing = typing_of(&s, &alice, read + 1);
    assert_eq!(
        handed_to(&s, &typing, std::slice::from_ref(&other), read + 1),
        Became::Nothing
    );
    assert!(filings_of(&s, 0).is_empty());

    let next = read + READ;
    reads(&s, &list, &commit('a'), next);
    let typing = typing_of(&s, &alice, next + 1);
    let named = share_of(&s, &alice, 7, next);
    assert_eq!(
        handed_to(&s, &typing, &[other, named], next + 1),
        Became::Taken(channel.id)
    );
    assert_eq!(filings_of(&s, 0).len(), 1);
}

/// A share from a key the list does not name is not taken: the node types
/// no key it does not name, and the typing of a key goes at the read whose
/// list no longer names it (rule 4.4).
#[test]
fn a_share_from_an_unlisted_key_is_not_taken() {
    let s = bob(1);
    let now = s.now + 10;
    let (channel, list) = joins(&s, 7, now);
    let (alice, dave) = (member(1), member(9));
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    assert!(!typed_keys(&s).contains(&dave.public_key()));
    let never = Typing {
        of: REPOSITORY.into(),
        key: dave.public_key(),
        typed_at: read,
    };
    let from_dave = share_of(&s, &dave, 7, read);
    assert_eq!(
        handed_to(&s, &never, &[from_dave], read + 1),
        Became::NotNow
    );

    // Alice's line goes in the next commit: her typing goes with it.
    let typing = typing_of(&s, &alice, read + 1);
    let without_alice = bobs_list(&s, &channel, 2..=2, &[]);
    reads(&s, &without_alice, &commit('b'), read + 2);
    assert_eq!(typed_keys(&s), [member(2).public_key()]);
    let from_alice = share_of(&s, &alice, 7, read);
    assert_eq!(
        handed_to(&s, &typing, &[from_alice], read + 3),
        Became::NotNow
    );
    assert!(filings_of(&s, 0).is_empty());
}

/// A share made an hour or more from the latest read is not taken, though
/// it was made within the hour of an earlier one, and one made within the
/// hour of the latest read is (rule 4.4). A typing reads for the hour of
/// its read and no longer.
#[test]
fn a_share_older_than_the_hour_of_the_latest_read_is_not_taken() {
    let s = bob(1);
    let now = s.now + 10;
    let (channel, list) = joins(&s, 7, now);
    let alice = member(1);
    let first = now + READ;
    reads(&s, &list, &commit('a'), first);
    let old = share_of(&s, &alice, 7, first);
    let typing = typing_of(&s, &alice, first);
    assert_eq!(
        handed_to(&s, &typing, std::slice::from_ref(&old), first + HOUR),
        Became::NotNow,
        "past the hour of its read"
    );
    assert!(asked_for(&s, first + HOUR).is_empty());

    let latest = first + HOUR;
    reads(&s, &list, &commit('a'), latest);
    let typing = typing_of(&s, &alice, latest + 1);
    let judged = judge(&s[0].conn, &s[0].identity, &typing, &old, latest + 1).unwrap();
    assert_eq!(judged, Some(Judged::Not(NotAShare::NotMadeWithinTheHour)));
    assert_eq!(handed_to(&s, &typing, &[old], latest + 1), Became::Nothing);

    let next = latest + READ;
    reads(&s, &list, &commit('a'), next);
    let typing = typing_of(&s, &alice, next + 1);
    let fresh = share_of(&s, &alice, 7, latest + 30);
    assert_eq!(
        handed_to(&s, &typing, &[fresh], next + 1),
        Became::Taken(channel.id)
    );
}

/// Nothing is taken where the list names no channel, its channel line
/// names this device after `without`, the list does not name this
/// device's key, or names only its twin, or a relay of its line is not one
/// of this device's own: no key is typed, none is asked for, and each says
/// why, in rule 6's line (rule 4.4). A list that clears them all has each
/// key typed.
#[test]
fn nothing_is_taken_where_this_device_is_left_out_or_its_key_is_not_listed() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = Shared::of(7);
    let words = channel_words(&channel.id);
    let (bob_key, carol) = (s.key(0), member(2).public_key());
    let none = list_with(None, &listed(1..=2));
    follows_at(&s, &none, &commit('a'), now);
    let mut read = now;
    let mut not_typed = |list: &str, at: char| {
        read += 1;
        reads(&s, list, &commit(at), read);
        assert!(typed_keys(&s).is_empty());
        assert!(asked_for(&s, read).is_empty());
        not_taking(&s)
    };
    assert_eq!(
        not_typed(&none, 'a'),
        (
            "no_channel",
            format!("The list of {REPOSITORY} names no channel yet.")
        )
    );
    let mut devices = listed(1..=2);
    devices.push((twin(&bob_key), "bob-0".into()));
    let twin_only = list_with(Some((&channel.id, &[])), &devices);
    assert_eq!(
        not_typed(&twin_only, 'b'),
        (
            "twin_listed",
            format!(
                "The list of {REPOSITORY} names your key in another form: list it as cordelia id \
                 prints it, {}.",
                encode_public_key(&bob_key).unwrap()
            )
        )
    );
    let left_out = bobs_list(&s, &channel, 1..=2, &[bob_key]);
    assert_eq!(
        not_typed(&left_out, 'c'),
        (
            "left_out_of_it",
            format!(
                "The list of {REPOSITORY} at {} names channel {words}, which no device of yours \
                 holds or can move to.",
                &commit('c')[..12]
            )
        )
    );
    let not_listed = list_with(Some((&channel.id, &[])), &listed(1..=2));
    assert_eq!(
        not_typed(&not_listed, 'd'),
        (
            "not_listed",
            format!(
                "Your key is not on the list of {REPOSITORY} at {}.",
                &commit('d')[..12]
            )
        )
    );

    // A relay of the line that this device does not know by its key.
    let list = bobs_list(&s, &channel, 1..=2, &[]);
    let card_only = &own_relays()[..1];
    let unreached = after_read(
        &s[0].conn,
        &s[0].identity,
        card_only,
        &read_of(&s, &list, &commit('e'), true),
        read + 1,
    );
    assert!(matches!(unreached, Ok(Done::Read { .. })), "{unreached:?}");
    assert!(typed_keys(&s).is_empty());
    let why = takes_in(&s[0].conn, &s[0].identity, card_only, &row(&s).unwrap())
        .unwrap()
        .unwrap_err();
    assert_eq!(why.word, "not_own_relay");
    assert_eq!(
        why.line,
        format!(
            "Channel {words} is at ({}), which is not one of your relays: add it to your \
             configuration.",
            cordelia_crypto::fingerprint::shown(&line_relay())
        )
    );

    reads(&s, &list, &commit('e'), read + 2);
    let both = sorted(&[member(1).public_key(), carol]);
    assert_eq!(typed_keys(&s), both);
    assert_eq!(asked_for(&s, read + 2), both);
}

/// Rule 1's gate does not keep a joiner out (rules 1 and 4.4): a device
/// that does not hold the channel cannot see who is in it, so a listed key
/// after `without` looks out of it, though the members see it write and
/// hand the channel over. The joiner types every listed key, and takes
/// the channel the list names from one.
#[test]
fn rule_1s_gate_does_not_keep_a_joiner_out() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = Shared::of(7);
    let (alice, carol) = (member(1), member(2).public_key());
    let gated = bobs_list(&s, &channel, 1..=2, &[carol]);
    follows_at(&s, &gated, &commit('a'), now);
    let read = now + READ;
    reads(&s, &gated, &commit('a'), read);
    assert_eq!(typed_keys(&s), sorted(&[alice.public_key(), carol]));
    let typing = typing_of(&s, &alice, read + 1);
    let share = share_of(&s, &alice, 7, read);
    assert_eq!(
        handed_to(&s, &typing, &[share], read + 1),
        Became::Taken(channel.id)
    );
}

/// The relays are asked for at most [`MEMBERS_ASKED_PER_PASS`] of the
/// node's typings at a pass, across every follow (rule 4.4): the rest are
/// asked for at the passes after, each within the hour of its read.
#[test]
fn a_pass_asks_for_at_most_32_typings_across_every_follow() {
    let s = bob(1);
    let now = s.now + 10;
    let (review, design) = (Shared::of(7), Shared::of(8));
    let first = bobs_list(&s, &review, 1..=20, &[]);
    let second = bobs_list(&s, &design, 21..=40, &[]);
    follows_as(&s, REPOSITORY, &first, &commit('a'), now);
    follows_as(&s, OTHER, &second, &commit('a'), now);
    let read = now + READ;
    reads_as(&s, REPOSITORY, &first, &commit('a'), read);
    reads_as(&s, OTHER, &second, &commit('a'), read);
    let typed = |of: &str| follows::typed(&s[0].conn, of).unwrap().len();
    assert_eq!((typed(REPOSITORY), typed(OTHER)), (20, 20));
    let asked = to_ask(&s[0].conn, read + 1).unwrap();
    assert_eq!(asked.len(), MEMBERS_ASKED_PER_PASS);
    for typing in &asked {
        let (conn, identity) = (&s[0].conn, &s[0].identity);
        let became = take(conn, identity, typing, &[], &own_relays(), read + 1).unwrap();
        assert_eq!(became, Became::Nothing);
    }
    assert_eq!(to_ask(&s[0].conn, read + 2).unwrap().len(), 40 - 32);
}

/// A typing whose take failed is kept as failed, with the error, and not
/// asked for again until the next read types its key again (the review of
/// slice 5b): so a follow that comes first, whose takes fail at every
/// pass, does not keep a later follow's typings from being asked for.
#[test]
fn a_follow_whose_takes_fail_does_not_keep_a_later_follows_keys_from_being_asked() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    // The first follow by its identity, which is no repository's, so that
    // each of its takes fails.
    let broken = "aaaaa";
    let first = bobs_list(&s, &Shared::of(8), 1..=40, &[]);
    follows_as(&s, broken, &first, &commit('a'), now);
    let read = now + READ;
    for n in 1..=40 {
        follows::type_key(conn, broken, &member(n).public_key(), read).unwrap();
    }
    let (_, list) = joins(&s, 7, now);
    reads(&s, &list, &commit('a'), read);
    let later = sorted(&[member(1).public_key(), member(2).public_key()]);
    let of_later = |asked: &[Typing]| -> Vec<[u8; 32]> {
        let keys: Vec<[u8; 32]> = asked
            .iter()
            .filter(|typing| typing.of == REPOSITORY)
            .map(|typing| typing.key)
            .collect();
        sorted(&keys)
    };

    let asked = to_ask(conn, read + 1).unwrap();
    assert_eq!(asked.len(), MEMBERS_ASKED_PER_PASS);
    assert!(of_later(&asked).is_empty(), "the first follow's come first");
    for typing in &asked {
        let took = take(conn, &s[0].identity, typing, &[], &own_relays(), read + 1);
        assert!(took.is_err(), "{took:?}");
    }
    let failed: Vec<follows::Typed> = follows::typed(conn, broken)
        .unwrap()
        .into_iter()
        .filter(|typed| typed.became.as_deref() == Some(FAILED))
        .collect();
    assert_eq!(failed.len(), MEMBERS_ASKED_PER_PASS);
    assert!(
        failed[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("is no repository")
    );
    // The next pass asks for the first follow's eight left, and the later
    // follow's.
    let asked = to_ask(conn, read + 2).unwrap();
    assert_eq!(asked.len(), 40 - MEMBERS_ASKED_PER_PASS + 2);
    assert_eq!(of_later(&asked), later);
}

/// What became of a typing is kept, its line cut at a character to what
/// the row keeps, so that a long one does not undo the take (the review
/// of slice 5b, L4): here, the line that a clone with a long path is no
/// mapped folder.
#[test]
fn a_long_line_of_what_became_of_a_typing_is_cut_and_the_take_stands() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = Shared::of(7);
    let list = bobs_list(&s, &channel, 1..=1, &[]);
    let clone = format!("/home/bob/{}", "\u{e9}".repeat(600));
    let conn = &s[0].conn;
    follows::follow(conn, REPOSITORY, "origin", &clone, now).unwrap();
    let at = LastRead {
        commit: commit('a'),
        at: now,
        from_clone: true,
    };
    follows::read_done(conn, REPOSITORY, &at, list.as_bytes(), None).unwrap();
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    let alice = member(1);
    let typing = typing_of(&s, &alice, read + 1);
    let share = share_of(&s, &alice, 7, read);
    assert_eq!(
        handed_to(&s, &typing, &[share], read + 1),
        Became::Taken(channel.id)
    );
    assert_eq!(filings_of(&s, 0).len(), 1);
    let (became, detail) = became_of(&s, &alice.public_key());
    assert_eq!(became.as_deref(), Some(TAKEN));
    let detail = detail.unwrap();
    assert!(
        detail.len() <= 1024 && detail.len() > 1000,
        "{}",
        detail.len()
    );
    assert!(detail.starts_with("/home/bob/\u{e9}"));
}

/// Where a key the node typed at a read is asked for, and the person has
/// since dropped the channel, or moved from it, nothing is taken, and why
/// is kept with the typing (rules 2.5, 4.4 and 6). The next read types
/// nothing: a drop stops the follow, and a move says to put the new line
/// in the list.
#[test]
fn nothing_is_taken_of_a_channel_dropped_or_moved_from() {
    // Dropped.
    let s = bob(1);
    let now = s.now + 10;
    let (channel, list) = joins(&s, 7, now);
    let alice = member(1);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    let typing = typing_of(&s, &alice, read + 1);
    acts(&s, 0, Do::File(filing(7, "review")), read + 1);
    acts(&s, 0, Do::Drop(channel.id), read + 2);
    let share = share_of(&s, &alice, 7, read);
    assert_eq!(
        handed_to(&s, &typing, std::slice::from_ref(&share), read + 3),
        Became::Refused("dropped")
    );
    let words = channel_words(&channel.id);
    assert_eq!(
        became_of(&s, &alice.public_key()),
        (
            Some("dropped".into()),
            Some(format!(
                "You dropped channel {words}, and a dropped channel is not taken again."
            ))
        )
    );
    assert!(filings_of(&s, 0).is_empty());
    assert_eq!(reads(&s, &list, &commit('a'), read + READ), Done::Stopped);

    // Moved from: Bob held it, and moved to the channel Alice made it anew
    // as.
    let s = bob(1);
    let now = s.now + 10;
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let channel = holds(&s, 0, 7, "review", now);
    write_in(&s, &channel, &[&alice], now);
    stores(
        &s,
        0,
        &offer_by(&alice, &channel, 21, &[alice.public_key(), s.key(0)], now),
        now,
    );
    let plan =
        crate::shared_anew::move_plan(conn, identity, &own_relays(), "review", None, None, now)
            .unwrap();
    crate::shared_anew::make_move(conn, identity, &plan.what, now).unwrap();
    let list = bobs_list(&s, &channel, 1..=2, &[]);
    follows_at(&s, &list, &commit('a'), now);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    assert!(typed_keys(&s).is_empty());
    assert_eq!(
        not_taking(&s),
        ("moved", crate::following::MOVED_FROM.into())
    );
    // A typing kept from before, asked for now.
    follows::type_key(conn, REPOSITORY, &alice.public_key(), read).unwrap();
    let typing = typing_of(&s, &alice, read + 1);
    assert_eq!(
        handed_to(&s, &typing, &[share_of(&s, &alice, 7, read)], read + 1),
        Became::Refused("moved")
    );
    assert!(row(&s).is_some(), "a move does not stop the follow");
}

/// Nothing is taken where the person holds a channel the named one was
/// made anew from, by an offer that counts: they move to it (rules 4.4 and
/// 6). An offer "without you" leaves nothing to move to, and does not
/// count here.
#[test]
fn nothing_is_taken_where_a_channel_it_was_made_anew_from_is_held() {
    let s = bob(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let old = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    write_in(&s, &old, &[&alice, &carol], now);
    let new = Shared::of(21);
    let list = bobs_list(&s, &new, 1..=2, &[]);
    follows_at(&s, &list, &commit('a'), now);
    // Without you: Carol's, sealed to Alice and Carol, and not to Bob.
    let without_you = offer_by(
        &carol,
        &old,
        21,
        &[alice.public_key(), carol.public_key()],
        now,
    );
    stores(&s, 0, &without_you, now);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    assert_eq!(
        typed_keys(&s).len(),
        2,
        "an offer without you does not count"
    );
    let typing = typing_of(&s, &alice, read + 1);

    stores(
        &s,
        0,
        &offer_by(&alice, &old, 21, &[alice.public_key(), s.key(0)], now),
        now,
    );
    let share = share_of(&s, &alice, 21, read);
    assert_eq!(
        handed_to(&s, &typing, &[share], read + 1),
        Became::Refused("made_anew")
    );
    let move_line =
        "Run cordelia shared move review: the list names the channel it was made anew as.";
    assert_eq!(
        became_of(&s, &alice.public_key()),
        (Some("made_anew".into()), Some(move_line.into()))
    );
    reads(&s, &list, &commit('a'), read + READ);
    assert!(typed_keys(&s).is_empty());
    assert_eq!(not_taking(&s), ("made_anew", move_line.into()));
    assert_eq!(filings_of(&s, 0).len(), 1);
    assert!(
        crate::shared_anew::dropped_or_moved(conn, &new.id)
            .unwrap()
            .is_none()
    );
}

/// Nothing is taken where the latest read counted for nothing (rules 2.5,
/// 3 and 4.4): a key typed at an earlier read and asked for now is refused,
/// and why is kept with it; and no read that counts for nothing types a
/// key, as a list that names another follow's channel does not.
#[test]
fn nothing_is_taken_where_the_read_counted_for_nothing() {
    let s = bob(1);
    let now = s.now + 10;
    let (channel, list) = joins(&s, 7, now);
    let alice = member(1);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    let typing = typing_of(&s, &alice, read + 1);
    let behind = done(&s, &read_of(&s, &list, &commit('b'), false), read + 1);
    assert!(matches!(behind, Done::NotRead(_)), "{behind:?}");
    assert!(asked_for(&s, read + 1).is_empty(), "nothing is asked for");
    assert_eq!(
        handed_to(&s, &typing, &[share_of(&s, &alice, 7, read)], read + 2),
        Became::Refused("not_read")
    );
    let (became, why) = became_of(&s, &alice.public_key());
    assert_eq!(became.as_deref(), Some("not_read"));
    assert!(why.unwrap().starts_with("your clone is at commit"));
    assert!(filings_of(&s, 0).is_empty());

    // Another follow names the channel first: this list counts for
    // nothing, and types nothing.
    let s = bob(1);
    let now = s.now + 10;
    let other = bobs_list(&s, &channel, 1..=1, &[]);
    follows_as(&s, OTHER, &other, &commit('a'), now);
    follows_at(&s, &list_with(None, &listed(1..=1)), &commit('a'), now);
    let list = bobs_list(&s, &channel, 1..=2, &[]);
    let read = reads(&s, &list, &commit('b'), now + READ);
    assert!(matches!(&read, Done::NotRead(not) if not.word == "followed_elsewhere"));
    assert!(typed_keys(&s).is_empty());
    assert_eq!(not_taking(&s).0, "not_read");
}

/// The node's typings leave the person's own `accept --channel` its eight
/// places (rule 4.4): with nine listed keys typed by the node, the person
/// types eight of their own, and a ninth is refused as before; and the
/// node's are not among those the person's read.
#[test]
fn the_persons_own_typings_keep_their_eight_places() {
    let s = bob(1);
    let now = s.now + 10;
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let channel = Shared::of(7);
    let list = bobs_list(&s, &channel, 1..=9, &[]);
    follows_at(&s, &list, &commit('a'), now);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    assert_eq!(asked_for(&s, read).len(), 9);
    let accept = |n: u32| {
        let typed = encode_public_key(&member(n).public_key()).unwrap();
        sharing::accept_plan(
            conn,
            identity,
            &own_relays(),
            &typed,
            &format!("c{n}"),
            read,
        )
    };
    for n in 10..18 {
        let plan = accept(n).unwrap();
        sharing::type_for_a_channel(conn, &plan.what, read).unwrap();
    }
    match accept(18) {
        Err(Failed::Refused(refusal)) => assert_eq!(refusal.word, "too_many_typed"),
        other => panic!("{other:?}"),
    }
    let persons: Vec<[u8; 32]> = sharing::keys_that_read(conn, read)
        .unwrap()
        .into_iter()
        .map(|typed| typed.key)
        .collect();
    let own: Vec<[u8; 32]> = (10..18).map(|n| member(n).public_key()).collect();
    assert_eq!(sorted(&persons), sorted(&own));
    assert_eq!(asked_for(&s, read).len(), 9);
}

/// The agent of the follow's clone is subscribed to the channel taken,
/// once, as the yes to follow said: the person unsubscribes it, and no
/// later read subscribes it again. Where the clone is no mapped folder,
/// none is, and that is kept with the typing.
#[test]
fn the_agent_of_the_clone_is_subscribed_once() {
    let s = bob(1);
    let now = s.now + 10;
    maps_the_clone(&s);
    let (channel, list) = joins(&s, 7, now);
    let alice = member(1);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    let typing = typing_of(&s, &alice, read + 1);
    let share = share_of(&s, &alice, 7, read);
    assert_eq!(
        handed_to(&s, &typing, &[share], read + 1),
        Became::Taken(channel.id)
    );
    let subscribed = |s: &Several| crate::shared_messages::in_force(&s[0].conn).unwrap();
    assert_eq!(subscribed(&s), [(channel.id, AGENT.to_string())]);
    let unsubscribe = Subscription {
        channel: channel.id,
        agent: AGENT.into(),
        subscribed: false,
    };
    acts(&s, 0, Do::Subscribe(unsubscribe), read + 2);
    assert!(subscribed(&s).is_empty());
    for later in 1..=3 {
        reads(&s, &list, &commit('a'), read + later * READ);
        assert!(subscribed(&s).is_empty());
        assert!(typed_keys(&s).is_empty());
    }

    // A clone that is no mapped folder.
    let s = bob(1);
    let now = s.now + 10;
    let (channel, list) = joins(&s, 7, now);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    let typing = typing_of(&s, &alice, read + 1);
    let share = share_of(&s, &alice, 7, read);
    assert_eq!(
        handed_to(&s, &typing, &[share], read + 1),
        Became::Taken(channel.id)
    );
    assert!(subscribed(&s).is_empty());
    assert_eq!(
        became_of(&s, &alice.public_key()),
        (
            Some(TAKEN.into()),
            Some(format!(
                "{FOLDER} is no mapped folder now, so no agent was subscribed."
            ))
        )
    );
}

/// Where the person holds the 16 channels, or files another channel under
/// the repository's `owner/name`, or syncs a folder as it, nothing is
/// typed, and each says why in rule 6's line (rule 4.4). And the line of
/// the wait, while this device looks.
#[test]
fn nothing_is_taken_without_room_or_the_name() {
    let s = bob(1);
    let now = s.now + 10;
    let (_, list) = joins(&s, 7, now);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    assert_eq!(typed_keys(&s).len(), 2);
    assert!(
        takes_in(&s[0].conn, &s[0].identity, &own_relays(), &row(&s).unwrap())
            .unwrap()
            .is_ok()
    );
    assert_eq!(
        waiting_line(NAME, "2 minutes ago"),
        "Waiting for a member's device to hand you team/project. Your list was read 2 minutes \
         ago. A member's device hands it over once a member's clone has the merged list: a \
         member runs git pull there."
    );

    holds(&s, 0, 8, NAME, read);
    reads(&s, &list, &commit('a'), read + 1);
    assert!(typed_keys(&s).is_empty());
    assert_eq!(
        not_taking(&s),
        (
            "name_taken",
            "You file another channel as team/project: rename it with cordelia shared rename."
                .into()
        )
    );
    acts(&s, 0, Do::Drop(Shared::of(8).id), read + 2);

    let mapped = serde_json::json!([{ "folder": "/home/bob/Work/elsewhere", "name": NAME }]);
    meta::set(&s[0].conn, meta::SYNC_CLAUDE_MAPPINGS, &mapped.to_string()).unwrap();
    reads(&s, &list, &commit('a'), read + 3);
    assert!(typed_keys(&s).is_empty());
    assert_eq!(not_taking(&s).0, "name_taken");
    meta::remove(&s[0].conn, meta::SYNC_CLAUDE_MAPPINGS).unwrap();

    for seed in 0..16u8 {
        holds(&s, 0, 100 + seed, &format!("c{seed}"), read + 4);
    }
    reads(&s, &list, &commit('a'), read + 5);
    assert!(typed_keys(&s).is_empty());
    assert_eq!(
        not_taking(&s),
        (
            "too_many_channels",
            "You hold 16 shared channels, the most there can be.".into()
        )
    );
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
    follows::read_done(conn, REPOSITORY, &read, first_list.as_bytes(), None).unwrap();
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
