//! Tests of following a repository (decision 2026-11-06 (joining), rules
//! 2.3 to 2.5): the plan of `cordelia subscribe` in a clone for each case
//! of rule 2.3, `--new` and the labels it makes, leaving, and the route
//! over a real clone on the disk.

use super::*;
use crate::git_list::ListAt;
use crate::several::Several;
use crate::shared::tests::{Shared, bob, holds, member, message, stores};
use cordelia_storage::meta;
use serde_json::{Value, json};

/// The folder of every test here but the last, mapped as `project`.
const FOLDER: &str = "/home/bob/Work/project";

/// The repository's identity, as `https://example.org/team/project` names
/// it.
const REPOSITORY: &str = "example.org/team/project";

const FIRST: &str = "1111111111111111111111111111111111111111";
const SECOND: &str = "2222222222222222222222222222222222222222";

/// The key of the relay that the device knows by key, and that every
/// channel line of these tests names: a key that can be used, as a
/// relay's is.
fn relay() -> [u8; 32] {
    NodeIdentity::from_seed([0x52; 32]).unwrap().public_key()
}

/// The record's lines, as rules 2.3 and 6 give them.
const HANDS_YOU: &str = "This follows example.org/team/project. A member's device hands you its \
                         channel once it reads the list. cordelia status shows how it goes.";
const NO_CHANNEL_YET: &str = "The list of example.org/team/project names no channel yet.";

fn own_relays() -> Vec<OwnRelay> {
    vec![OwnRelay {
        name: "relay.example.org:9474".into(),
        key: relay(),
    }]
}

/// Device `n` maps each folder as its name.
fn map(s: &Several, n: usize, mapped: &[(&str, &str)]) {
    let mapped: Vec<Value> = mapped
        .iter()
        .map(|(folder, name)| json!({ "folder": folder, "name": name }))
        .collect();
    meta::set(
        &s[n].conn,
        meta::SYNC_CLAUDE_MAPPINGS,
        &Value::from(mapped).to_string(),
    )
    .unwrap();
}

/// `count` devices of Bob's, each with sync on and [`FOLDER`] mapped.
fn devices(count: u16) -> Several {
    let s = bob(count);
    for n in 0..usize::from(count) {
        map(&s, n, &[(FOLDER, "project")]);
    }
    s
}

/// A key as `cordelia id` prints it.
fn id(key: &[u8; 32]) -> String {
    encode_public_key(key).unwrap()
}

/// The channel line of `channel`, at [`relay`], with `without`.
fn channel_line(channel: &Shared, without: &[[u8; 32]]) -> String {
    ChannelLine {
        channel: channel.id,
        relays: vec![relay()],
        without: without.to_vec(),
    }
    .to_line()
    .unwrap()
}

/// What device 0 read of its clone at `commit`, with `list` (or none):
/// where it follows the repository, whether `commit` comes after the last
/// one read is `comes_after`.
fn read_on(s: &Several, list: Option<&str>, commit: &str, comes_after: bool) -> ClonedRead {
    ClonedRead {
        identity: Identity::from_address("https://example.org/team/project").unwrap(),
        remote: "origin".into(),
        top: PathBuf::from(FOLDER),
        list: ClonedList {
            at: ListAt {
                commit: commit.into(),
                file: list.map(|list| list.as_bytes().to_vec()),
            },
            branch: "main".into(),
            fetched: None,
        },
        after_last: follow_row(s)
            .and_then(|row| row.last)
            .map(|last| AfterLast {
                last: last.commit,
                comes_after,
            }),
    }
}

/// The plan of device 0 in [`FOLDER`], of what was read.
fn plan_of(s: &Several, read: &ClonedRead, new: bool) -> Out<Plan<Following>> {
    plan(&s[0].conn, &s[0].identity, &own_relays(), FOLDER, read, new)
}

/// The plan of device 0 in [`FOLDER`], with `list` at `commit`, which
/// comes after any commit it read last.
fn planned(s: &Several, list: Option<&str>, commit: &str, new: bool) -> Out<Plan<Following>> {
    plan_of(s, &read_on(s, list, commit, true), new)
}

/// The yes's first line, of the list at `commit` from the clone at
/// [`FOLDER`] through `origin`.
fn reads(commit: &str) -> String {
    format!(
        "This reads the list of {REPOSITORY} at commit {commit}, from your clone at {FOLDER}, \
         through its remote origin."
    )
}

/// The word and the line of a refusal.
fn refusal<T: std::fmt::Debug>(out: Out<T>) -> (&'static str, String) {
    match out {
        Err(Failed::Refused(refusal)) => (refusal.word, refusal.line),
        other => panic!("{other:?}"),
    }
}

/// The follow of [`REPOSITORY`] on device 0.
fn follow_row(s: &Several) -> Option<follows::Follow> {
    follows::follow_of(&s[0].conn, REPOSITORY).unwrap()
}

/// Whether the agent `project` subscribes to `channel` on device 0.
fn subscribed(s: &Several, channel: &Shared) -> bool {
    crate::shared_messages::in_force(&s[0].conn)
        .unwrap()
        .iter()
        .any(|(of, agent)| *of == channel.id && agent == "project")
}

/// Device 0 says yes to `planned`, at `now`.
fn yes(s: &Several, planned: &Plan<Following>, now: i64) -> Vec<String> {
    make(&s[0].conn, &s[0].identity, &planned.what, now).unwrap()
}

/// A list that names no channel, and this device, is followed, and the
/// device waits (rule 2.3): its yes shows the repository, the commit, that
/// the list names no channel yet (rule 6), and the key's label; on the
/// yes, the follow's row holds the clone, the commit read from it, and
/// the list. The plan alone writes nothing.
#[test]
fn a_list_that_names_this_device_and_no_channel_is_followed_and_waits() {
    let s = devices(1);
    let now = s.now + 10;
    let list = format!("# the team\n{}   bob-laptop\n", id(&s.key(0)));
    let planned = planned(&s, Some(&list), FIRST, false).unwrap();
    assert_eq!(
        planned.asks,
        [
            &reads(FIRST),
            NO_CHANNEL_YET,
            "Your key is on the list, as bob-laptop.",
            "This follows example.org/team/project. A member's device hands you its channel \
             once the list names one. cordelia status shows how it goes.",
        ]
        .join("\n")
    );
    assert!(follow_row(&s).is_none(), "a plan writes nothing");
    let said = yes(&s, &planned, now);
    assert_eq!(
        said,
        [format!(
            "Following {REPOSITORY}, from its list at commit {FIRST}. cordelia status shows how \
             it goes."
        )]
    );
    let row = follow_row(&s).unwrap();
    assert_eq!(
        (row.remote.as_str(), row.clone.as_str(), row.followed_at),
        ("origin", FOLDER, now)
    );
    assert_eq!(
        row.last,
        Some(LastRead {
            commit: FIRST.into(),
            at: now,
            from_clone: true
        })
    );
    assert_eq!(row.list.as_deref(), Some(list.as_bytes()));
}

/// A list that names a channel the person does not hold, and this device,
/// is followed, and the device waits to be handed it: the yes says rule
/// 2.3's line exactly, and shows the channel by its words.
#[test]
fn a_device_on_the_list_of_a_channel_it_does_not_hold_waits_to_be_handed_it() {
    let s = devices(1);
    let now = s.now + 10;
    let channel = Shared::of(9);
    let list = format!(
        "{}\n{} alice-laptop\n{} bob-laptop\n",
        channel_line(&channel, &[]),
        id(&member(1).public_key()),
        id(&s.key(0))
    );
    let planned = planned(&s, Some(&list), FIRST, false).unwrap();
    assert_eq!(
        planned.asks,
        [
            &reads(FIRST),
            &format!(
                "It names channel {}, which you do not hold.",
                channel_words(&channel.id)
            ),
            "Your key is on the list, as bob-laptop.",
            HANDS_YOU,
        ]
        .join("\n")
    );
    assert!(matches!(planned.what.then, Then::Nothing));
    yes(&s, &planned, now);
    assert_eq!(follow_row(&s).unwrap().last.unwrap().commit, FIRST);
    assert!(!subscribed(&s, &channel));
}

/// A device that the list does not name is refused with rule 2.3's line,
/// and nothing is done: whether the list names a channel or not, and a
/// clone with no list, which is a list of no devices.
#[test]
fn a_device_not_on_the_list_is_refused_and_nothing_is_done() {
    let s = devices(1);
    let channel = Shared::of(9);
    let alice = format!("{} alice-laptop\n", id(&member(1).public_key()));
    let line = format!(
        "Your key is not on the list of {REPOSITORY} at {FIRST}. Add it with a pull request, \
         then run this again."
    );
    for list in [
        Some(format!("{}\n{alice}", channel_line(&channel, &[]))),
        Some(alice.clone()),
        None,
    ] {
        let refused = refusal(planned(&s, list.as_deref(), FIRST, false));
        assert_eq!(refused, ("not_listed", line.clone()), "{list:?}");
    }
    assert!(follow_row(&s).is_none());
    assert!(follows::follows(&s[0].conn).unwrap().is_empty());
}

/// A twin of this device's key is this device's key (rule 1).
#[test]
fn a_twin_of_this_devices_key_is_on_the_list() {
    let s = devices(1);
    let mut twin = s.key(0);
    twin[31] ^= 0x80;
    let list = format!("{} bob-laptop\n", id(&twin));
    let planned = planned(&s, Some(&list), FIRST, false).unwrap();
    assert!(
        planned
            .asks
            .contains("Your key is on the list, as bob-laptop."),
        "{}",
        planned.asks
    );
}

/// A person who holds the channel the list names follows the repository,
/// and the folder's agent is subscribed to it, with the channel shown by
/// the person's name for it (rules 2.2 and 2.3). Where the agent
/// subscribes already, it still follows, and never-back starts over (rule
/// 2.5). A holder whose key is not on the list follows too.
#[test]
fn a_holder_follows_and_its_agent_is_subscribed() {
    let mut s = devices(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let list = format!(
        "{}\n{} bob-laptop\n",
        channel_line(&channel, &[]),
        id(&s.key(0))
    );
    let first = planned(&s, Some(&list), FIRST, false).unwrap();
    let words = channel_words(&channel.id);
    let head = [
        reads(FIRST),
        format!("It names the shared channel \"review\" (channel {words}), which you hold."),
        "Your key is on the list, as bob-laptop.".to_string(),
        format!("This follows {REPOSITORY}."),
        "The agent of this folder, project, will be shown a count of the messages in the shared \
         channel \"review\""
            .to_string(),
    ]
    .join("\n");
    assert!(first.asks.starts_with(&head), "{}", first.asks);
    assert!(!subscribed(&s, &channel));
    let said = yes(&s, &first, now + 1);
    assert!(
        said[0].starts_with("Subscribed: project to \"review\", from now on."),
        "{said:?}"
    );
    assert!(subscribed(&s, &channel));
    assert_eq!(follow_row(&s).unwrap().last.unwrap().commit, FIRST);

    // Subscribed already: it still follows. The yes says where this
    // device read last, and names the commit now read.
    let later = s.tick() + 10;
    let again = planned(&s, Some(&list), SECOND, false).unwrap();
    assert!(
        again.asks.contains(&format!(
            "\nThis device follows {REPOSITORY} already, from {FOLDER} at {FIRST}.\n"
        )),
        "{}",
        again.asks
    );
    assert!(
        again.asks.ends_with(
            "This follows example.org/team/project.\nproject subscribes to \"review\" already."
        ),
        "{}",
        again.asks
    );
    assert!(!again.asks.contains("does not come after"));
    assert_ne!(again.asks, first.asks, "the yes names the commit");
    yes(&s, &again, later);
    // Never-back starts over: the last commit read goes, and the list,
    // and when it was first followed, stay (rule 2.5).
    let row = follow_row(&s).unwrap();
    assert_eq!(
        (row.last, row.followed_at, row.list.as_deref()),
        (None, now + 1, Some(list.as_bytes()))
    );

    // A holder that the list does not name follows too, and says so.
    let others = format!(
        "{}\n{} alice-laptop\n",
        channel_line(&channel, &[]),
        id(&member(1).public_key())
    );
    let unlisted = planned(&s, Some(&others), FIRST, false).unwrap();
    assert!(
        unlisted
            .asks
            .contains("which you hold.\nYour key is not on the list.\n"),
        "{}",
        unlisted.asks
    );
}

/// A channel the person dropped, or moved from, is not taken again, as
/// `accept --channel` refuses it: each said as rules 2.3 and 6 say it,
/// and nothing is done.
#[test]
fn a_dropped_channel_is_refused() {
    let s = devices(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 8, "old", now);
    let identity = &s[0].identity;
    sharing::make_drop(&s[0].conn, identity, &channel.id, "old", now + 1).unwrap();
    let list = format!(
        "{}\n{} bob-laptop\n",
        channel_line(&channel, &[]),
        id(&s.key(0))
    );
    assert_eq!(
        refusal(planned(&s, Some(&list), FIRST, false)),
        (
            "dropped",
            format!(
                "You dropped channel {}, and a dropped channel is not taken again.",
                channel_words(&channel.id)
            )
        )
    );
    assert!(follow_row(&s).is_none());

    // A channel moved from is kept as a drop: rule 6 says what to do.
    let moved = holds(&s, 0, 9, "review", now + 2);
    let mut to = crate::lists::tests::filing(10, "review-2");
    to.came = Came::Moved(moved.id);
    crate::shared::tests::acts(&s, 0, Do::Move { from: moved.id, to }, now + 3);
    let list = format!(
        "{}\n{} bob-laptop\n",
        channel_line(&moved, &[]),
        id(&s.key(0))
    );
    assert_eq!(
        refusal(planned(&s, Some(&list), FIRST, false)),
        ("moved", MOVED_FROM.to_string())
    );
    assert!(follow_row(&s).is_none());
}

/// The gate line of rule 6, for `label` on the list of `name`.
fn gate_line(label: &str, name: &str) -> String {
    format!(
        "{label} is on the list of {name} but was left out of it: nothing is handed over until \
         its line goes, or it writes in the channel."
    )
}

/// A key left out of the channel and still listed holds the list back
/// (rule 1). A holder of the line's channel is still a holder (rule 2.3):
/// it follows, the yes says the gate line of rule 6 for each such key,
/// and that the folder's agent is subscribed once the list names the
/// channel; nothing promises a hand-over. Once that key writes in the
/// channel, the list names it again, and the agent is subscribed.
#[test]
fn a_key_left_out_and_still_listed_holds_the_list_back() {
    let s = devices(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let alice = member(1);
    let list = format!(
        "{}\n{} alice-laptop\n{} bob-laptop\n",
        channel_line(&channel, &[alice.public_key()]),
        id(&alice.public_key()),
        id(&s.key(0))
    );
    let held_back = planned(&s, Some(&list), FIRST, false).unwrap();
    let words = channel_words(&channel.id);
    assert_eq!(
        held_back.asks,
        [
            reads(FIRST),
            format!("It names the shared channel \"review\" (channel {words}), which you hold."),
            "Your key is on the list, as bob-laptop.".to_string(),
            gate_line("alice-laptop", "review"),
            format!("This follows {REPOSITORY}."),
            "The agent of this folder, project, is subscribed to it once the list names it."
                .to_string(),
        ]
        .join("\n")
    );
    assert!(matches!(held_back.what.then, Then::Nothing));
    yes(&s, &held_back, now + 1);
    assert!(!subscribed(&s, &channel));
    assert!(follow_row(&s).is_some());
    // Alice writes there: she is in the channel, and the list names it.
    stores(
        &s,
        0,
        &message(&alice, &channel, 1, "hello", now + 2),
        now + 2,
    );
    let named = planned(&s, Some(&list), FIRST, false).unwrap();
    assert!(
        matches!(named.what.then, Then::Subscribe { .. }),
        "{}",
        named.asks
    );
}

/// Rule 2.3's cases are taken on the list's channel line, whatever the gate
/// says: a channel dropped, or moved from, is refused though a key left
/// out holds the list back; and a device that does not hold the channel
/// follows and is told the gate line, by the channel's words, with no
/// hand-over promised.
#[test]
fn the_cases_of_rule_2_3_are_taken_on_the_line_whatever_the_gate_says() {
    let s = devices(1);
    let now = s.now + 10;
    let alice = member(1).public_key();
    let gated_list = |channel: &Shared| {
        format!(
            "{}\n{} alice-laptop\n{} bob-laptop\n",
            channel_line(channel, &[alice]),
            id(&alice),
            id(&s.key(0))
        )
    };
    let dropped = holds(&s, 0, 8, "old", now);
    sharing::make_drop(&s[0].conn, &s[0].identity, &dropped.id, "old", now + 1).unwrap();
    assert_eq!(
        refusal(planned(&s, Some(&gated_list(&dropped)), FIRST, false)).0,
        "dropped"
    );
    let moved = holds(&s, 0, 9, "review", now + 2);
    let mut to = crate::lists::tests::filing(10, "review-2");
    to.came = Came::Moved(moved.id);
    crate::shared::tests::acts(&s, 0, Do::Move { from: moved.id, to }, now + 3);
    assert_eq!(
        refusal(planned(&s, Some(&gated_list(&moved)), FIRST, false)).0,
        "moved"
    );
    assert!(follow_row(&s).is_none());
    // Not held: it follows, and says what holds the list back.
    let other = Shared::of(11);
    let planned = planned(&s, Some(&gated_list(&other)), FIRST, false).unwrap();
    let words = channel_words(&other.id);
    assert_eq!(
        planned.asks,
        [
            reads(FIRST),
            format!("It names channel {words}, which you do not hold."),
            "Your key is on the list, as bob-laptop.".to_string(),
            gate_line("alice-laptop", &format!("channel {words}")),
            format!("This follows {REPOSITORY}. cordelia status shows how it goes."),
        ]
        .join("\n")
    );
}

/// A person who holds the channel that the list's channel was made anew
/// from is told to move to it (rule 6), and follows; nothing promises a
/// hand-over.
#[test]
fn a_holder_of_the_channel_it_was_made_anew_from_is_told_to_move() {
    let s = devices(1);
    let now = s.now + 10;
    let old = holds(&s, 0, 7, "review", now);
    let new = Shared::of(12);
    let offer = kept_anew::OfferRow {
        channel: old.id,
        maker: member(1).public_key(),
        rev: 1,
        made: 0,
        new_channel: new.id,
        relays: cordelia_crypto::share::Relays::new(&[relay()])
            .unwrap()
            .to_bytes(),
        sealed_to: vec![s.key(0)],
        own_seal: None,
        first_held: now,
        stayed: false,
    };
    kept_anew::keep_offer(&s[0].conn, &offer).unwrap();
    let list = format!(
        "{}\n{} bob-laptop\n",
        channel_line(&new, &[]),
        id(&s.key(0))
    );
    let planned = planned(&s, Some(&list), FIRST, false).unwrap();
    assert_eq!(
        planned.asks,
        [
            reads(FIRST),
            format!(
                "It names channel {}, which you do not hold.",
                channel_words(&new.id)
            ),
            "Your key is on the list, as bob-laptop.".to_string(),
            "Run cordelia shared move review: the list names the channel it was made anew as."
                .to_string(),
            format!("This follows {REPOSITORY}."),
        ]
        .join("\n")
    );
    assert!(matches!(planned.what.then, Then::Nothing));
}

/// Following again, the yes says where this device read last; where the
/// clone's commit does not come after it, that the list would go back
/// (rules 2.5 and 3); and it names the clone and its remote, so that a yes
/// is good for no other. A follow read again while the clone was read is
/// refused as changed.
#[test]
fn following_again_says_where_it_read_last_and_whether_the_clone_goes_back() {
    let s = devices(1);
    let now = s.now + 10;
    let list = format!("{} bob-laptop\n", id(&s.key(0)));
    yes(&s, &planned(&s, Some(&list), SECOND, false).unwrap(), now);
    let back = plan_of(&s, &read_on(&s, Some(&list), FIRST, false), false).unwrap();
    let asks: Vec<&str> = back.asks.lines().collect();
    assert_eq!(
        asks[..3],
        [
            reads(FIRST).as_str(),
            &format!("This device follows {REPOSITORY} already, from {FOLDER} at {SECOND}."),
            &format!(
                "Your clone is at {FIRST}, which does not come after it: you would read an older \
                 list."
            ),
        ]
    );
    let on = planned(&s, Some(&list), FIRST, false).unwrap();
    assert!(!on.asks.contains("does not come after"), "{}", on.asks);
    // Another remote, or another clone, at the same commit: another yes.
    let mut upstream = read_on(&s, Some(&list), FIRST, true);
    upstream.remote = "upstream".into();
    assert_ne!(plan_of(&s, &upstream, false).unwrap().asks, on.asks);
    let mut elsewhere = read_on(&s, Some(&list), FIRST, true);
    elsewhere.top = PathBuf::from("/home/bob/Work/project-2");
    assert_ne!(plan_of(&s, &elsewhere, false).unwrap().asks, on.asks);
    // A read that checked another last commit than the follow now has.
    let mut stale = read_on(&s, Some(&list), FIRST, true);
    stale.after_last = None;
    assert_eq!(refusal(plan_of(&s, &stale, false)).0, "changed");
}

/// Following again keeps what the node's reads need (rule 2.5): the list
/// last read, the notices, the last key handed, and when it was first
/// followed. Only the last commit read goes.
#[test]
fn following_again_keeps_the_list_and_the_notices() {
    let s = devices(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let list = format!("{} bob-laptop\n", id(&s.key(0)));
    yes(&s, &planned(&s, Some(&list), FIRST, false).unwrap(), now);
    let dropped = follows::Notice {
        of: follows::NoticeOf::Dropped {
            key: member(1).public_key(),
            label: "alice-laptop".into(),
        },
        commit: FIRST.into(),
        at: now,
    };
    follows::notice(conn, REPOSITORY, &dropped).unwrap();
    follows::set_last_handed(conn, REPOSITORY, &member(2).public_key()).unwrap();
    let changed = format!("# the team\n{list}");
    yes(
        &s,
        &planned(&s, Some(&changed), SECOND, false).unwrap(),
        now + 5,
    );
    let row = follow_row(&s).unwrap();
    assert_eq!(row.last, None);
    assert_eq!(row.followed_at, now);
    assert_eq!(row.list.as_deref(), Some(list.as_bytes()));
    assert_eq!(row.last_handed, Some(member(2).public_key()));
    assert_eq!(follows::notices(conn, REPOSITORY).unwrap(), [dropped]);
}

/// A list that does not parse is refused, naming its line, and nothing is
/// done.
#[test]
fn a_list_that_does_not_parse_is_refused_naming_its_line() {
    let s = devices(1);
    let list = format!("{} bob-laptop\nnot a list\n", id(&s.key(0)));
    assert_eq!(
        refusal(planned(&s, Some(&list), FIRST, false)),
        (
            "not_a_list",
            format!(
                "The list of {REPOSITORY} at commit {FIRST} cannot be read: line 2 of the list \
                 is not a key and a label. Fix it in a pull request. Nothing was done."
            )
        )
    );
    assert!(follow_row(&s).is_none());
}

/// A folder that is not mapped is refused with today's line, before the
/// list is looked at.
#[test]
fn a_folder_that_is_not_mapped_is_refused() {
    let s = bob(1);
    let list = format!("{} bob-laptop\n", id(&s.key(0)));
    let (word, line) = refusal(planned(&s, Some(&list), FIRST, false));
    assert_eq!(word, "not_mapped");
    assert!(
        line.ends_with("Map it with: cordelia sync map /home/bob/Work/project <name>"),
        "{line}"
    );
}

/// `--new` (rule 2.4) makes the channel at the person's relays, filed as
/// the repository's `owner/name`; subscribes the folder's agent; follows
/// the repository; and says the record's lines to add: the channel line,
/// `without 0`, and a line for each device of the person's that the list
/// does not name yet, labelled from its own label. The lines, added to
/// the list, read as the list of that channel and those devices.
#[test]
fn new_makes_the_channel_follows_and_says_the_lines_to_add() {
    let s = devices(2);
    let now = s.now + 10;
    // The list names Bob's other device already, and Alice's.
    let list = format!(
        "{} bob-desktop\n{} alice-laptop\n",
        id(&s.key(1)),
        id(&member(1).public_key())
    );
    let planned = planned(&s, Some(&list), FIRST, true).unwrap();
    let asks: Vec<&str> = planned.asks.lines().collect();
    assert_eq!(asks[1], NO_CHANNEL_YET);
    assert_eq!(asks[2], "Your key is not on the list.");
    assert!(
        asks[3].starts_with(
            "This makes a channel shared between people, filed on your devices as \
             \"team/project\"."
        ),
        "{}",
        planned.asks
    );
    assert_eq!(
        asks.last().unwrap(),
        &"This follows example.org/team/project, and subscribes project, the agent of this \
          folder, to the new channel. Then it prints the lines to add to the list."
    );
    let said = yes(&s, &planned, now);
    let filing = sharing::filed(&s[0].conn)
        .unwrap()
        .into_iter()
        .find(|filing| filing.name == "team/project")
        .expect("the channel is filed as owner/name");
    let channel = Shared {
        secret: filing.card.secret().unwrap(),
        id: filing.channel,
    };
    assert!(subscribed(&s, &channel));
    assert_eq!(follow_row(&s).unwrap().last.unwrap().commit, FIRST);
    assert_eq!(
        said[0],
        format!(
            "Made \"team/project\": channel {}, and subscribed project to it.",
            channel_words(&channel.id)
        )
    );
    assert!(said[1].starts_with("Following example.org/team/project"));
    assert_eq!(
        said[2],
        "Add these lines to .cordelia/members in a pull request:"
    );
    assert_eq!(said[3], channel_line(&channel, &[]));
    assert!(said[3].ends_with(" without 0"), "{}", said[3]);
    // One line for this device, the one the list does not name.
    assert_eq!(said.len(), 5, "{said:?}");
    let own_label =
        crate::reader::label_of(&s[0].conn, &s[0].held().statement.statement, &s.key(0)).unwrap();
    let label = list_labels(&[own_label], &["bob-desktop".into(), "alice-laptop".into()]);
    assert_eq!(said[4], format!("{}   {}", id(&s.key(0)), label[0]));
    // Added to the list, the lines read as the list of the new channel.
    let added = format!("{list}{}\n{}\n", said[3], said[4]);
    let read = members::read(added.as_bytes()).unwrap();
    assert_eq!(read.channel.as_ref().unwrap().channel, channel.id);
    assert_eq!(read.devices.len(), 3);
    assert!(read.lists(&s.key(0)));
}

/// `--new` is refused where the list has a channel line already, held
/// back or not, and where another channel is filed as `owner/name`, with
/// rule 6's line; and nothing is done.
#[test]
fn new_is_refused_where_the_list_names_a_channel_or_the_name_is_taken() {
    let s = devices(1);
    let now = s.now + 10;
    let me = format!("{} bob-laptop\n", id(&s.key(0)));
    let channel = Shared::of(9);
    for line in [
        channel_line(&channel, &[]),
        channel_line(&channel, &[member(1).public_key()]),
    ] {
        let list = format!("{line}\n{me}");
        assert_eq!(
            refusal(planned(&s, Some(&list), FIRST, true)),
            (
                "names_a_channel",
                format!(
                    "The list of {REPOSITORY} at commit {FIRST} names a channel already, so \
                     --new makes none: run cordelia subscribe without --new."
                )
            )
        );
    }
    holds(&s, 0, 5, "team/project", now);
    let filed = sharing::filed(&s[0].conn).unwrap().len();
    assert_eq!(
        refusal(planned(&s, Some(&me), FIRST, true)),
        (
            "name_taken",
            "You file another channel as team/project: rename it with cordelia shared rename."
                .to_string()
        )
    );
    assert_eq!(sharing::filed(&s[0].conn).unwrap().len(), filed);
    assert!(follow_row(&s).is_none());
}

/// `--new` whose subscription is refused, the agents holding the most
/// subscriptions there may be, makes nothing: no channel is filed or held,
/// nothing is stored, and nothing is followed, as the channel it made is
/// undone with the refusal.
#[test]
fn new_whose_subscription_is_refused_makes_nothing() {
    use cordelia_core::protocol::SHARED_MAX_SUBSCRIPTIONS;
    let s = devices(1);
    let now = s.now + 10;
    let review = holds(&s, 0, 7, "review", now);
    for n in 0..SHARED_MAX_SUBSCRIPTIONS {
        let subscription = Subscription {
            channel: review.id,
            agent: format!("agent-{n}"),
            subscribed: true,
        };
        crate::shared::tests::acts(&s, 0, Do::Subscribe(subscription), now);
    }
    let me = format!("{} bob-laptop\n", id(&s.key(0)));
    let filed = sharing::filed(&s[0].conn).unwrap();
    let held = kept::channels(&s[0].conn).unwrap().len();
    let stored = s[0].stored().len();
    let planned = planned(&s, Some(&me), FIRST, true).unwrap();
    let refused = make(&s[0].conn, &s[0].identity, &planned.what, now + 1);
    assert_eq!(refusal(refused).0, "too_many_subscriptions");
    assert_eq!(sharing::filed(&s[0].conn).unwrap(), filed);
    assert_eq!(kept::channels(&s[0].conn).unwrap().len(), held);
    assert_eq!(s[0].stored().len(), stored);
    assert!(follow_row(&s).is_none());
}

/// `--new` is refused where the list, with the lines it would say to add,
/// would name more than 64 devices (rule 1); at 64 it is not.
#[test]
fn new_is_refused_where_the_list_would_pass_64_devices() {
    let s = devices(1);
    let others = |count: u32| -> String {
        (1..=count)
            .map(|n| format!("{} member-{n}\n", id(&member(n).public_key())))
            .collect()
    };
    assert!(planned(&s, Some(&others(63)), FIRST, true).is_ok());
    assert_eq!(
        refusal(planned(&s, Some(&others(64)), FIRST, true)),
        (
            "channel_full",
            format!(
                "With your devices, the list of {REPOSITORY} would name 65, and a list names 64 \
                 at most: delete some lines in a pull request first. Nothing was made."
            )
        )
    );
}

/// The whole read of a clone is given one deadline: past it, no step of git
/// begins, and it says so plainly (the route's twenty seconds).
#[test]
fn a_read_past_its_deadline_is_refused_plainly() {
    let tmp = tempfile::tempdir().unwrap();
    let git = Git::under(tmp.path()).unwrap();
    let past = Instant::now();
    assert_eq!(
        refusal(read_with(&git, tmp.path(), None, &[], past, 20)),
        (
            "late",
            "git did not answer in 20 seconds, so nothing was done.".to_string()
        )
    );
}

/// Where the subscription is refused after the channel is made, what was
/// made is undone with it: a refusal part of the way leaves nothing.
#[test]
fn a_refusal_part_of_the_way_undoes_what_was_made() {
    let s = devices(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    let filings = sharing::filed(conn).unwrap().len();
    let undone: Out<()> = in_one_or_none(conn, || {
        follows::follow(conn, REPOSITORY, "origin", FOLDER, now)?;
        sharing::refused("too_many_subscriptions", "refused".into())
    });
    assert_eq!(refusal(undone).0, "too_many_subscriptions");
    assert!(follow_row(&s).is_none(), "the follow was undone");
    assert_eq!(sharing::filed(conn).unwrap().len(), filings);
}

/// Labels for the list are made from each device's own label (rule 2.4):
/// lower case, every other character a `-`, runs and ends of `-` taken
/// off, cut to 32; one that ends up empty or the same as another, or one
/// the list has, gets `-2`, `-3` and so on. Each is a label the list
/// takes.
#[test]
fn labels_for_the_list_are_made_from_each_devices_label() {
    let given = |labels: &[&str], taken: &[&str]| -> Vec<String> {
        let labels: Vec<String> = labels.iter().map(|l| l.to_string()).collect();
        let taken: Vec<String> = taken.iter().map(|l| l.to_string()).collect();
        let made = list_labels(&labels, &taken);
        for label in &made {
            assert!(members::is_a_label(label), "{label:?}");
        }
        made
    };
    assert_eq!(
        given(
            &[
                "Bob's Laptop",
                "MacBook-Pro.local",
                "x--y__z..",
                "-lead-",
                "Ünïcode",
                "desk  top",
            ],
            &[]
        ),
        [
            "bob-s-laptop",
            "macbook-pro.local",
            "x-y__z..",
            "lead",
            "n-code",
            "desk-top"
        ]
    );
    // Cut to 32, and a `-` the cut leaves at the end taken off.
    let long = "a".repeat(40);
    let dash_at_32 = format!("{}-b", "a".repeat(31));
    assert_eq!(
        given(&[&long, &dash_at_32], &[]),
        ["a".repeat(32), "a".repeat(31)]
    );
    // The same twice, or one the list has: -2, then -3.
    assert_eq!(
        given(&["laptop", "Laptop", "LAPTOP"], &["laptop-2"]),
        ["laptop", "laptop-3", "laptop-4"]
    );
    // One cut to make room for its number.
    assert_eq!(
        given(&[&long, &long], &[]),
        ["a".repeat(32), format!("{}-2", "a".repeat(30))]
    );
    // Empty: a number alone.
    assert_eq!(given(&["", "笔记本", "!!"], &[]), ["-2", "-3", "-4"]);
}

/// A device that leaves its person follows nothing after (rule 2.5): every
/// follow goes, in the leave's write.
#[test]
fn leaving_deletes_every_follow() {
    let s = devices(1);
    let now = s.now + 10;
    let conn = &s[0].conn;
    for repository in ["example.org/team/a", "example.org/team/b"] {
        follows::follow(conn, repository, "origin", FOLDER, now).unwrap();
    }
    assert_eq!(follows::follows(conn).unwrap().len(), 2);
    assert!(crate::leaving::forget(conn, &s[0].identity, false, now).unwrap());
    assert!(follows::follows(conn).unwrap().is_empty());
}

// ── The route, over a real clone ─────────────────────────────────────

/// Git, as a test runs it, in `dir`, with nothing of the person's.
fn git(home: &Path, dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.org",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// A clone of `https://example.org/team/project` with no network: a
/// repository whose `origin` names it, and whose copy of the remote's
/// default branch, `refs/remotes/origin/main`, is the commit of the list.
pub(crate) struct OnDisk {
    home: PathBuf,
    pub(crate) top: PathBuf,
}

impl OnDisk {
    pub(crate) fn new(under: &Path) -> Self {
        let home = under.join("home");
        let top = under.join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(top.join(".cordelia")).unwrap();
        let top = top.canonicalize().unwrap();
        git(&home, &top, &["init", "--quiet"]);
        git(&home, &top, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        git(
            &home,
            &top,
            &[
                "remote",
                "add",
                "origin",
                "https://example.org/team/project",
            ],
        );
        Self { home, top }
    }

    /// Commit `list`, and make it the remote's default branch as a fetch
    /// would. Returns the commit.
    pub(crate) fn fetched(&self, list: &str) -> String {
        std::fs::write(self.top.join(".cordelia/members"), list).unwrap();
        git(&self.home, &self.top, &["add", "-A"]);
        git(&self.home, &self.top, &["commit", "--quiet", "-m", "list"]);
        let commit = git(&self.home, &self.top, &["rev-parse", "HEAD"]);
        git(
            &self.home,
            &self.top,
            &["update-ref", "refs/remotes/origin/main", &commit],
        );
        git(
            &self.home,
            &self.top,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ],
        );
        commit
    }

    /// Commit `list` on a branch with no history, and make it the remote's
    /// default branch: a commit that comes after no other. Returns it.
    pub(crate) fn rewritten(&self, list: &str) -> String {
        git(
            &self.home,
            &self.top,
            &["checkout", "--quiet", "--orphan", "side"],
        );
        self.fetched(list)
    }

    /// Make `commit` the remote's default branch.
    fn at(&self, commit: &str) {
        git(
            &self.home,
            &self.top,
            &["update-ref", "refs/remotes/origin/main", commit],
        );
    }
}

/// What the route answered: its status, and its body.
async fn asked(state: &actix_web::web::Data<crate::state::AppState>, body: Value) -> (u16, Value) {
    let req = actix_web::test::TestRequest::default()
        .insert_header(("authorization", "Bearer t"))
        .to_http_request();
    let body: crate::shared_routes::FollowRequest = serde_json::from_value(body).unwrap();
    let answered = crate::shared_routes::follow(req, state.clone(), actix_web::web::Json(body))
        .await
        .unwrap();
    let status = answered.status().as_u16();
    let bytes = actix_web::body::to_bytes(answered.into_body())
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// Whether the node was asked to read the lists it follows, since it was
/// last asked.
async fn read_asked(state: &crate::state::AppState) -> bool {
    tokio::time::timeout(
        std::time::Duration::from_millis(50),
        state.own_channels.wait_members_read(),
    )
    .await
    .is_ok()
}

/// The route, over a real clone on the disk and no server: it follows the
/// repository at the commit its yes named, from the clone and remote its
/// yes named, and asks the node to read the list; a second subscribe, at a
/// new commit, needs a new yes, and a yes to the old one is refused as
/// changed, with nothing done; its yes says where this device read last,
/// and that a commit that does not come after it would read an older list,
/// and, once given, starts never-back over and keeps the list; a mapped
/// folder below the clone's top follows the clone, by its top, and the
/// command itself sends the top from any folder of it; a folder that is
/// not mapped, and a mapped one in no repository, are refused.
#[actix_web::test]
async fn a_clone_on_the_disk_is_followed_through_the_route() {
    let tmp = tempfile::tempdir().unwrap();
    let clone = OnDisk::new(tmp.path());
    let mut s = devices(1);
    let top = clone.top.display().to_string();
    let docs = clone.top.join("docs");
    std::fs::create_dir_all(&docs).unwrap();
    let docs = docs.display().to_string();
    std::fs::create_dir_all(tmp.path().join("elsewhere")).unwrap();
    let elsewhere = tmp.path().join("elsewhere").canonicalize().unwrap();
    let elsewhere = elsewhere.display().to_string();
    map(
        &s,
        0,
        &[(&top, "project"), (&docs, "docs"), (&elsewhere, "notes")],
    );
    let me = format!("{} bob-laptop\n", id(&s.key(0)));
    let first = clone.fetched(&me);
    let mut state = crate::several::state_of(s.machines.remove(0));
    state.home_dir = tmp.path().join("node");
    let state = actix_web::web::Data::new(state);
    let row = |state: &crate::state::AppState| {
        let conn = state.db.lock().unwrap();
        follows::follow_of(&conn, REPOSITORY).unwrap()
    };

    let (status, looked) = asked(&state, json!({ "folder": top, "look": true })).await;
    assert_eq!(status, 200, "{looked}");
    let asks = looked["asks"].as_str().unwrap().to_string();
    assert!(
        asks.starts_with(&format!(
            "This reads the list of {REPOSITORY} at commit {first}, from your clone at {top}, \
             through its remote origin.\n"
        )),
        "{asks}"
    );
    assert!(row(&state).is_none(), "a look does nothing");
    assert!(!read_asked(&state).await);
    let (status, done) = asked(&state, json!({ "folder": top, "said_yes_to": asks })).await;
    assert_eq!(status, 200, "{done}");
    let followed = row(&state).unwrap();
    assert_eq!(followed.clone, top);
    assert_eq!(followed.remote, "origin");
    assert_eq!(followed.last.unwrap().commit, first);
    assert!(
        read_asked(&state).await,
        "the node is asked to read the list"
    );

    // A new commit: the yes to the old one is refused, and nothing done.
    let second = clone.fetched(&format!("# the team\n{me}"));
    let (status, refused) = asked(&state, json!({ "folder": top, "said_yes_to": asks })).await;
    assert_eq!(status, 409);
    assert_eq!(refused["error"]["code"], "changed", "{refused}");
    assert_eq!(row(&state).unwrap().last.unwrap().commit, first);
    assert!(!read_asked(&state).await);
    let (_, looked) = asked(&state, json!({ "folder": top, "look": true })).await;
    let again = looked["asks"].as_str().unwrap().to_string();
    let follows_already =
        format!("This device follows {REPOSITORY} already, from {top} at {first}.");
    assert!(again.contains(&second), "{again}");
    assert!(again.contains(&follows_already), "{again}");
    assert!(!again.contains("does not come after"), "{again}");
    // A history rewritten: its commit does not come after the last one
    // read, and the yes says so, as git in the clone finds it.
    let side = clone.rewritten(&format!("# rewritten\n{me}"));
    let (_, looked) = asked(&state, json!({ "folder": top, "look": true })).await;
    let back = looked["asks"].as_str().unwrap();
    assert!(
        back.contains(&format!(
            "{follows_already}\nYour clone is at {side}, which does not come after it: you \
             would read an older list."
        )),
        "{back}"
    );
    clone.at(&second);
    let (status, _) = asked(&state, json!({ "folder": top, "said_yes_to": again })).await;
    assert_eq!(status, 200);
    let again = row(&state).unwrap();
    assert_eq!(again.last, None, "never-back starts over");
    assert_eq!(again.followed_at, followed.followed_at);
    assert_eq!(again.list.as_deref(), Some(me.as_bytes()));

    // A mapped folder below the top follows the clone, by its top.
    {
        let conn = state.db.lock().unwrap();
        follows::unfollow(&conn, REPOSITORY).unwrap();
    }
    let (_, looked) = asked(&state, json!({ "folder": docs, "look": true })).await;
    let asks = looked["asks"].as_str().unwrap().to_string();
    let (status, done) = asked(&state, json!({ "folder": docs, "said_yes_to": asks })).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(row(&state).unwrap().clone, top);
    // And the command sends the top, from any folder of the clone.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    assert_eq!(
        crate::found::memory_root_by(Path::new(&docs), deadline),
        Some(clone.top.clone())
    );

    // A folder that is not mapped, and one in no repository.
    let unmapped = tmp.path().join("project/docs/unmapped");
    std::fs::create_dir_all(&unmapped).unwrap();
    let unmapped = unmapped.display().to_string();
    let (status, refused) = asked(&state, json!({ "folder": unmapped, "look": true })).await;
    assert_eq!(status, 409);
    assert_eq!(refused["error"]["code"], "not_mapped", "{refused}");
    let (status, refused) = asked(&state, json!({ "folder": elsewhere, "look": true })).await;
    assert_eq!(status, 409);
    assert_eq!(refused["error"]["code"], "not_a_repository", "{refused}");
    assert_eq!(refused["error"]["message"], NOT_IN_A_CLONE);
}
