//! Tests of what the status and `cordelia shared list` say of each
//! repository a device follows, and of `cordelia shared seen` (decision
//! 2026-11-06 (joining), rules 3 to 7), in-process, with a set time and no
//! relay: each line from the rows it is worked out from, a read that
//! counted for nothing first, the ambers and what ends each, and the view's
//! shape.

use super::*;
use crate::members::ChannelLine;
use crate::members_read::tests::{
    FOLDER, READ, REPOSITORY, commit, follows_as, follows_at, joins, list_of, list_with, listed,
    offer_by, own_relays, read_of, reads, row, write_in,
};
use crate::members_read::{CloneRead, Done, after_read};
use crate::several::Several;
use crate::shared::tests::{Shared, bob, holds, member, stores};
use crate::shared_anew::tests::{anew_keeping, filed_as, holds_at_line_at, written_by};
use cordelia_storage::shared_anew::MadeRow;

/// The record, as it is in the repository.
const RECORD: &str =
    include_str!("../../../../docs/decisions/2026-11-06-joining-by-pull-request.md");

/// The view on device 0 of the repository `repository` at `now`.
fn view_of(s: &Several, repository: &str, now: i64) -> Value {
    views(&s[0].conn, &s[0].identity, &own_relays(), None, now)
        .into_iter()
        .find(|view| view["identity"] == repository)
        .unwrap_or_else(|| panic!("no view of {repository}"))
}

/// The view on device 0 of [`REPOSITORY`] at `now`.
fn view_now(s: &Several, now: i64) -> Value {
    view_of(s, REPOSITORY, now)
}

/// The lines of `view`, each as its word and what it says, and whether it
/// is amber.
fn lines(view: &Value) -> Vec<(String, String, bool)> {
    view["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| {
            (
                line["word"].as_str().unwrap().to_string(),
                line["says"].as_str().unwrap().to_string(),
                line["amber"].as_bool().unwrap(),
            )
        })
        .collect()
}

/// The words of the lines of `view`.
fn words(view: &Value) -> Vec<String> {
    lines(view).into_iter().map(|(word, ..)| word).collect()
}

/// The words of the amber lines of `view`.
fn amber_words(view: &Value) -> Vec<String> {
    lines(view)
        .into_iter()
        .filter(|(_, _, amber)| *amber)
        .map(|(word, ..)| word)
        .collect()
}

/// What each amber line of `view` says.
fn ambers(view: &Value) -> Vec<String> {
    lines(view)
        .into_iter()
        .filter(|(_, _, amber)| *amber)
        .map(|(_, says, _)| says)
        .collect()
}

/// Each member of `view`, by its label, and whether it is in.
fn members_of(view: &Value) -> Vec<(String, Value)> {
    view["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| {
            (
                member["label"].as_str().unwrap().to_string(),
                member["in"].clone(),
            )
        })
        .collect()
}

/// `cordelia shared seen <name>` on device 0: what it says, or why not.
fn seen_on(s: &Several, name: &str) -> Result<Vec<String>, (&'static str, String)> {
    seen_of(s, name, None)
}

/// `cordelia shared seen <name> <label>` on device 0: what it says, or why
/// not.
fn seen_key(s: &Several, name: &str, label: &str) -> Vec<String> {
    seen_of(s, name, Some(label)).unwrap()
}

/// `cordelia shared seen` on device 0, of `name`, with `label` or none.
fn seen_of(
    s: &Several,
    name: &str,
    label: Option<&str>,
) -> Result<Vec<String>, (&'static str, String)> {
    match seen(&s[0].conn, &s[0].identity, name, label) {
        Ok(said) => Ok(said),
        Err(sharing::Failed::Refused(refusal)) => Err((refusal.word, refusal.line)),
        Err(sharing::Failed::Error(e)) => panic!("{e}"),
    }
}

/// `commit(c)` as a status shows it.
fn short_of(c: char) -> String {
    commit(c)[..12].to_string()
}

/// A list naming `channel`, with `without`, and `devices` by their labels.
fn list_named(channel: &[u8; 32], without: &[[u8; 32]], devices: &[([u8; 32], &str)]) -> String {
    list_of(Some((channel, without)), devices)
}

// ── The view (rule 7) ────────────────────────────────────────────────

/// A member's view says the repository, the name its channel is filed
/// under, its words, the list's read with its commit, the members by the
/// list's labels, each in the channel or not yet, what waits unread, and
/// each key its node handed the channel to that has not taken it.
#[test]
fn a_members_view_says_the_list_its_members_and_who_it_hands_the_channel_to() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    write_in(&s, &channel, &[&alice], now);
    let list = list_named(
        &channel.id,
        &[],
        &[
            (alice.public_key(), "alice-laptop"),
            (carol.public_key(), "carol-laptop"),
        ],
    );
    follows_at(&s, &list, &commit('a'), now);
    let read = now + READ;
    reads(&s, &list, &commit('a'), read);
    let view = view_now(&s, read + 120);
    assert_eq!(view["identity"], REPOSITORY, "{view}");
    assert_eq!(view["name"], "review");
    assert_eq!(view["held"], true);
    assert_eq!(view["channel"], hex::encode(channel.id));
    assert_eq!(view["words"], channel_words(&channel.id));
    assert_eq!(view["read"]["commit"], commit('a'));
    assert_eq!(view["read"]["from"], "clone");
    assert_eq!(view["read"]["fetched"], Value::Null);
    assert_eq!(
        view["read"]["says"],
        format!(
            "List of {REPOSITORY} read from your clone; your clone's last fetch is not known. \
             Read 2 minutes ago, at commit {}.",
            short_of('a')
        )
    );
    assert_eq!(
        members_of(&view),
        [
            ("alice-laptop".to_string(), json!(true)),
            ("carol-laptop".to_string(), json!(false)),
        ]
    );
    assert_eq!(
        view["members"][1]["key"],
        encode_public_key(&carol.public_key()).unwrap()
    );
    assert_eq!(view["members"][1]["words"], six_words(&carol.public_key()));
    assert_eq!(
        (
            view["unread_by_a_person"].as_u64(),
            view["unread_by_an_agent"].as_u64()
        ),
        (Some(0), Some(0))
    );
    assert_eq!(
        lines(&view),
        [(
            "handing".to_string(),
            "Handing review to carol-laptop: waiting for that device to take it.".to_string(),
            false
        )]
    );
    // Once Carol writes in the channel, she is in, and nothing waits.
    write_in(&s, &channel, &[&carol], read + 200);
    let view = view_now(&s, read + 300);
    assert_eq!(members_of(&view)[1].1, json!(true));
    assert!(lines(&view).is_empty(), "{view}");
}

/// The view's shape, in the status's `shared` object as in `shared list`:
/// each field, and no other.
#[test]
fn the_status_carries_each_repositorys_view_with_its_fields() {
    let s = bob(1);
    let now = s.now + 10;
    let (_, list) = joins(&s, 7, now);
    let own = own_relays();
    let said = crate::state::SharedSaid::default();
    let beside = crate::shared_status::Beside {
        own_relays: &own,
        connected: &[],
        said: &said,
    };
    let shared = crate::shared_status::status_of(&s[0].conn, &s[0].identity, &beside, now)
        .unwrap()
        .unwrap();
    let view = &shared["repositories"][0];
    let mut fields: Vec<&str> = view
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort();
    assert_eq!(
        fields,
        [
            "channel",
            "held",
            "identity",
            "lines",
            "members",
            "name",
            "read",
            "unread_by_a_person",
            "unread_by_an_agent",
            "words"
        ]
    );
    let mut read: Vec<&str> = view["read"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    read.sort();
    assert_eq!(read, ["at", "commit", "fetched", "from", "says"]);
    let mut member: Vec<&str> = view["members"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    member.sort();
    assert_eq!(member, ["in", "key", "label", "words"]);
    let mut line: Vec<&str> = view["lines"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    line.sort();
    assert_eq!(line, ["amber", "line", "says", "word"]);
    // A joiner does not hold the channel, so it cannot see who is in it.
    assert_eq!(view["held"], false);
    assert!(
        view["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|member| member["in"].is_null()),
        "{view}"
    );
    // Its name is the repository's `owner/name`, which it is filed under
    // once taken.
    assert_eq!(view["name"], "team/project");
    assert!(list.contains("channel "));
}

/// Rule 3's line says how old the clone's copy is where the clone says
/// when it fetched it, and that this is not known where it does not, as
/// with a person's `insteadOf`: it never says the list is stale.
#[test]
fn the_read_says_how_old_the_clones_copy_is_or_that_it_is_not_known() {
    let last = LastRead {
        commit: commit('a'),
        at: 1_000_000,
        from_clone: true,
    };
    let now = last.at + 300;
    assert_eq!(
        read_line(REPOSITORY, &last, Some(now - 2 * 3600 - 5), now),
        format!(
            "List of {REPOSITORY} read from your clone, fetched 2 hours ago. Read 5 minutes ago, \
             at commit {}.",
            short_of('a')
        )
    );
    let unknown = read_line(REPOSITORY, &last, None, now);
    assert_eq!(
        unknown,
        format!(
            "List of {REPOSITORY} read from your clone; your clone's last fetch is not known. \
             Read 5 minutes ago, at commit {}.",
            short_of('a')
        )
    );
    assert!(!unknown.contains("stale") && !unknown.contains("old"));
    // Rule 3's own words.
    assert!(RECORD.contains("list of <identity> read from your clone, fetched 2 hours ago"));

    // In the view, from the row a read kept.
    let s = bob(1);
    let at = s.now + 10;
    let channel = holds(&s, 0, 7, "review", at);
    let list = list_with(Some((&channel.id, &[])), &listed(1..=1));
    follows_at(&s, &list, &commit('a'), at);
    let mut read = read_of(&s, &list, &commit('b'), true);
    let fetched = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(at as u64);
    if let Ok(got) = &mut read.read {
        got.list.fetched = Some(fetched);
    }
    after_read(&s[0].conn, &s[0].identity, &own_relays(), &read, at + 60).unwrap();
    let view = view_now(&s, at + 3 * 3600);
    assert_eq!(view["read"]["fetched"], rfc3339(at));
    assert_eq!(
        view["read"]["says"],
        format!(
            "List of {REPOSITORY} read from your clone, fetched 3 hours ago. Read 2 hours ago, at \
             commit {}.",
            short_of('b')
        )
    );
}

// ── A read that counted for nothing, first ───────────────────────────

/// A read that counted for nothing says why first, and nothing of what the
/// list read before would hand over: the node handed nothing over at it. A
/// clone behind says so. The notices kept still show. The next read that
/// counts says what it hands again.
#[test]
fn a_read_that_counted_for_nothing_says_why_before_anything_else() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    write_in(&s, &channel, &[&alice], now);
    let devices = [
        (alice.public_key(), "alice-laptop"),
        (carol.public_key(), "carol-laptop"),
    ];
    let list = list_named(&channel.id, &[], &devices);
    follows_at(&s, &list, &commit('a'), now);
    reads(&s, &list, &commit('a'), now + READ);
    assert_eq!(words(&view_now(&s, now + READ)), ["handing"]);
    // Alice is dropped: a notice that stays through what follows.
    let carol_only = list_named(&channel.id, &[], &devices[1..]);
    reads(&s, &carol_only, &commit('b'), now + READ + 1);
    assert_eq!(
        words(&view_now(&s, now + READ + 1)),
        ["handing", "no_longer_listed"]
    );

    let behind = after_read(
        &s[0].conn,
        &s[0].identity,
        &own_relays(),
        &read_of(&s, &list, &commit('c'), false),
        now + 2 * READ,
    )
    .unwrap();
    assert!(matches!(behind, Done::NotRead(_)), "{behind:?}");
    let view = view_now(&s, now + 2 * READ);
    assert_eq!(words(&view), ["behind", "no_longer_listed"]);
    assert_eq!(
        lines(&view)[0].1,
        format!(
            "Your clone of {REPOSITORY} is behind: your clone is at commit {}, which does not come \
             after commit {}, the last one read. The last list read stands. Run git pull there; if \
             its history was rewritten, run cordelia subscribe there again.",
            short_of('c'),
            short_of('b')
        )
    );

    // A read that failed says the git's line, and that the last list
    // stands.
    let failed = crate::git_list::ListFailed::NoRemoteHead {
        remote: "origin".into(),
    };
    let read = CloneRead {
        follow: row(&s).unwrap(),
        read: Err(failed.clone()),
    };
    after_read(
        &s[0].conn,
        &s[0].identity,
        &own_relays(),
        &read,
        now + 3 * READ,
    )
    .unwrap();
    let view = view_now(&s, now + 3 * READ);
    assert_eq!(words(&view), ["no_remote_head", "no_longer_listed"]);
    assert_eq!(
        lines(&view)[0].1,
        format!(
            "The list of {REPOSITORY} was not read from your clone: {}. The last list read stands.",
            failed.says()
        )
    );
    // A list that does not parse names its line.
    let not_a_list = format!("{carol_only}not a key and a label\n");
    reads(&s, &not_a_list, &commit('d'), now + 4 * READ);
    assert_eq!(
        lines(&view_of(&s, REPOSITORY, now + 4 * READ))[0].1,
        format!(
            "The list of {REPOSITORY} in your clone cannot be read: line 3 of the list is not a \
             key and a label. Fix it in a pull request. The last list read stands."
        )
    );

    // Reads that count again: the node's share to Carol, two reads old,
    // goes at the first, and she waits out that read (rule 4.2); at the
    // next she is handed it again, and that is said.
    reads(&s, &carol_only, &commit('d'), now + 5 * READ);
    assert_eq!(
        words(&view_of(&s, REPOSITORY, now + 5 * READ)),
        ["no_longer_listed"]
    );
    reads(&s, &carol_only, &commit('d'), now + 6 * READ);
    assert_eq!(
        words(&view_of(&s, REPOSITORY, now + 6 * READ)),
        ["handing", "no_longer_listed"]
    );
}

/// A list that names a channel another follow names counts for nothing,
/// and says rule 6's line, whole.
#[test]
fn a_list_that_names_a_channel_another_follow_names_says_so() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let list = list_with(Some((&channel.id, &[])), &listed(1..=1));
    let other = "example.org/team/other";
    follows_as(&s, other, &list, &commit('a'), now);
    let first = list_with(None, &listed(1..=1));
    follows_at(&s, &first, &commit('a'), now);
    reads(&s, &list, &commit('b'), now + 1);
    assert_eq!(
        lines(&view_now(&s, now + 1)),
        [(
            "followed_elsewhere".to_string(),
            format!(
                "The list of {REPOSITORY} names \"review\", which this device follows from \
                 {other}: run cordelia subscribe in a clone of the one it should follow."
            ),
            false
        )]
    );
}

// ── A joiner's lines (rules 4.4 and 6) ───────────────────────────────

/// A device on the list that does not hold the channel says the wait; one
/// whose key is not on the list says so; a list that names no channel says
/// so; and one whose key is after `without` is amber, as rule 6 marks it.
/// Rule 1's gate is not said on a joiner: it cannot see who is in.
#[test]
fn a_joiners_lines_say_the_wait_or_why_it_takes_nothing() {
    let s = bob(1);
    let now = s.now + 10;
    let (channel, list) = joins(&s, 7, now);
    let view = view_now(&s, now + 120);
    assert_eq!(
        lines(&view),
        [(
            "waiting".to_string(),
            "Waiting for a member's device to hand you team/project. Your list was read 2 \
             minutes ago. A member's device hands it over once a member's clone has the merged \
             list: a member runs git pull there."
                .to_string(),
            false
        )]
    );

    let not_listed = list_with(Some((&channel.id, &[])), &listed(1..=2));
    reads(&s, &not_listed, &commit('b'), now + 1);
    assert_eq!(
        lines(&view_now(&s, now + 1)),
        [(
            "not_listed".to_string(),
            format!(
                "Your key is not on the list of {REPOSITORY} at {}.",
                short_of('b')
            ),
            false
        )]
    );

    let no_line = list_with(None, &listed(1..=2));
    reads(&s, &no_line, &commit('c'), now + 2);
    assert_eq!(
        lines(&view_now(&s, now + 2)),
        [(
            "no_channel".to_string(),
            format!("The list of {REPOSITORY} names no channel yet."),
            false
        )]
    );

    // Left out, and the line says so: amber. A gate key beside it is not
    // said on a joiner.
    let carol = member(2).public_key();
    let mut devices = listed(1..=2);
    devices.push((s.key(0), "bob-0".into()));
    let left_out = list_with(Some((&channel.id, &[s.key(0), carol])), &devices);
    reads(&s, &left_out, &commit('d'), now + 3);
    let view = view_now(&s, now + 3);
    assert_eq!(
        lines(&view),
        [(
            "left_out_of_it".to_string(),
            format!(
                "The list of {REPOSITORY} at {} names channel {}, which no device of yours holds \
                 or can move to.",
                short_of('d'),
                channel_words(&channel.id)
            ),
            true
        )]
    );
    assert!(list.contains("bob-0"));
}

// ── A member who cannot hand over (rules 4.1 and 6) ──────────────────

/// A member that read an offer that made the channel anew for the person
/// says who made it, by the list's label, and that nothing is handed over;
/// once the person moves, it says to put the new line in the list.
#[test]
fn a_member_says_why_it_hands_nothing_over() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    write_in(&s, &channel, &[&alice, &carol], now);
    let list = list_named(
        &channel.id,
        &[],
        &[
            (alice.public_key(), "alice-laptop"),
            (member(4).public_key(), "dave"),
        ],
    );
    follows_at(&s, &list, &commit('a'), now);
    stores(
        &s,
        0,
        &offer_by(&alice, &channel, 21, &[alice.public_key(), s.key(0)], now),
        now,
    );
    reads(&s, &list, &commit('a'), now + 1);
    assert_eq!(
        lines(&view_now(&s, now + 1)),
        [(
            "offer_read".to_string(),
            "review was made anew by alice-laptop: nothing is handed over until the list names \
             the new channel."
                .to_string(),
            false
        )]
    );
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let plan =
        crate::shared_anew::move_plan(conn, identity, &own_relays(), "review", None, None, now)
            .unwrap();
    crate::shared_anew::make_move(conn, identity, &plan.what, now).unwrap();
    reads(&s, &list, &commit('a'), now + 2);
    let view = view_now(&s, now + 2);
    assert_eq!(view["name"], "review", "the channel moved to");
    assert_eq!(view["held"], false);
    assert_eq!(
        lines(&view),
        [("moved".to_string(), MOVED_FROM.to_string(), false)]
    );
}

/// A channel none of whose relays is the device's own is not reached:
/// nothing is handed over until it is.
#[test]
fn a_member_whose_channel_is_not_reached_says_so() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let list = list_with(Some((&channel.id, &[])), &listed(1..=1));
    follows_at(&s, &list, &commit('a'), now);
    let only_the_lines = vec![own_relays()[1].clone()];
    let views = views(&s[0].conn, &s[0].identity, &only_the_lines, None, now);
    assert_eq!(
        lines(&views[0]),
        [(
            "not_reached".to_string(),
            "review is not reached at its relays: nothing is handed over until then.".to_string(),
            false
        )]
    );
}

/// Rule 1's gate, on a member, which sees who is in: each key the list
/// names, that its line names after `without`, and that is not in the
/// channel, amber, and nothing handed over. Once the key writes in the
/// channel, or its line goes, it is not said.
#[test]
fn rule_1s_gate_is_amber_on_a_member() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    write_in(&s, &channel, &[&alice], now);
    let devices = [
        (alice.public_key(), "alice-laptop"),
        (carol.public_key(), "carol-laptop"),
    ];
    let list = list_named(&channel.id, &[carol.public_key()], &devices);
    follows_at(&s, &list, &commit('a'), now);
    reads(&s, &list, &commit('a'), now + 1);
    let gate = "carol-laptop is on the list of review but was left out of it: delete its line in \
                a pull request, or wait for that device to write in the channel";
    assert_eq!(
        lines(&view_now(&s, now + 1)),
        [("left_out".to_string(), gate.to_string(), true)]
    );
    // Under a read that counted for nothing, the gate is not said: the
    // last list stands, and nothing was handed over at that read.
    let failed = CloneRead {
        follow: row(&s).unwrap(),
        read: Err(crate::git_list::ListFailed::NotAFile),
    };
    after_read(&s[0].conn, &s[0].identity, &own_relays(), &failed, now + 2).unwrap();
    assert_eq!(words(&view_now(&s, now + 2)), ["not_a_file"]);
    reads(&s, &list, &commit('a'), now + 3);
    assert_eq!(ambers(&view_now(&s, now + 3)), [gate]);
    write_in(&s, &channel, &[&carol], now + 4);
    assert!(ambers(&view_now(&s, now + 4)).is_empty());
}

// ── The notices (rules 4.5, 4.6 and 6), and `shared seen` ────────────

/// A join, a key dropped and a changed channel line are each amber, with
/// the record's words; `shared seen` clears the join and the changed line
/// on this device, and not the dropped key, which stays until it leaves
/// the channel; and nothing of another repository's.
#[test]
fn the_notices_are_amber_and_seen_clears_the_join_and_the_changed_line_alone() {
    let s = bob(1);
    let now = s.now + 10;
    let channel = holds(&s, 0, 7, "review", now);
    let other = holds(&s, 0, 8, "design", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    write_in(&s, &channel, &[&alice, &carol], now);
    let all = [
        (alice.public_key(), "alice-laptop"),
        (carol.public_key(), "carol-laptop"),
        (dave.public_key(), "dave-laptop"),
    ];
    follows_at(&s, &list_named(&channel.id, &[], &all), &commit('a'), now);
    // Another repository, whose list names "design", with a join.
    let elsewhere = "example.org/team/other";
    let theirs = list_named(&other.id, &[], &all[2..]);
    follows_as(&s, elsewhere, &theirs, &commit('a'), now);
    write_in(&s, &other, &[&dave], now + 5);
    let read_there =
        crate::members_read::tests::read_as(&s, elsewhere, &theirs, &commit('e'), true);
    after_read(
        &s[0].conn,
        &s[0].identity,
        &own_relays(),
        &read_there,
        now + READ,
    )
    .unwrap();
    assert_eq!(
        view_of(&s, elsewhere, now + READ)["lines"][0]["word"],
        "joined"
    );

    write_in(&s, &channel, &[&dave], now + 5);
    let without_carol = list_named(&channel.id, &[], &[all[0], all[2]]);
    reads(&s, &without_carol, &commit('b'), now + READ);
    let view = view_now(&s, now + READ);
    assert_eq!(amber_words(&view), ["joined", "no_longer_listed"]);
    assert_eq!(
        ambers(&view),
        [
            format!(
                "dave-laptop joined review from the list at {}",
                short_of('b')
            ),
            "carol-laptop is no longer on the list of review: make it anew with cordelia shared \
             anew review"
                .to_string(),
        ]
    );
    // The line names another channel, which Carol is in too, so her
    // notice stays.
    let notes = holds(&s, 0, 9, "notes", now);
    write_in(&s, &notes, &[&carol], now + 5);
    reads(
        &s,
        &list_named(&notes.id, &[], &all[..1]),
        &commit('c'),
        now + READ + 1,
    );
    let view = view_now(&s, now + READ + 1);
    assert_eq!(view["name"], "notes", "the channel the list names now");
    assert_eq!(
        amber_words(&view),
        ["joined", "no_longer_listed", "line_changed"]
    );
    assert_eq!(
        ambers(&view)[2],
        format!(
            "The list of {REPOSITORY} names a new channel for notes at {}.",
            short_of('c')
        )
    );

    // Each it clears is said, by label; the join is said against the
    // channel it joined.
    assert_eq!(
        seen_on(&s, "notes").unwrap(),
        [
            format!(
                "Cleared: dave-laptop joined review from the list at {}",
                short_of('b')
            ),
            format!(
                "Cleared: The list of {REPOSITORY} names a new channel for notes at {}.",
                short_of('c')
            ),
            DROPPED_STAYS.to_string(),
        ]
    );
    assert_eq!(
        amber_words(&view_now(&s, now + READ + 2)),
        ["no_longer_listed"]
    );
    assert_eq!(
        view_of(&s, elsewhere, now + READ + 2)["lines"][0]["word"],
        "joined",
        "another repository's notices stay"
    );
    // By its identity too; and a second time, nothing is left to clear.
    assert_eq!(
        seen_on(&s, REPOSITORY).unwrap()[0],
        "Nothing to clear for example.org/team/project on this device."
    );
}

/// `shared seen` of a name no repository this device follows names says
/// that this device does not read its list: another device's follows are
/// its own.
#[test]
fn seen_where_this_device_follows_no_list_of_the_name_says_so() {
    let s = bob(1);
    let now = s.now + 10;
    holds(&s, 0, 7, "review", now);
    assert_eq!(
        seen_on(&s, "review"),
        Err((
            "not_followed",
            "This device follows no repository whose channel is review.".to_string()
        ))
    );
}

// ── A making anew here (rule 5) ──────────────────────────────────────

/// Device 0 follows [`REPOSITORY`], whose list names `channel` with
/// `without` and `devices`, by their labels, read at `at`.
fn follows_line_at(
    s: &Several,
    channel: &[u8; 32],
    without: &[[u8; 32]],
    devices: &[([u8; 32], &str)],
    at: i64,
) -> String {
    let list = list_of_line_at(channel, without, devices);
    follows_at(s, &list, &commit('a'), at);
    list
}

/// A list whose channel line names `channel` at the relay of the channels
/// whose line is printed, with `without` and `devices`.
fn list_of_line_at(
    channel: &[u8; 32],
    without: &[[u8; 32]],
    devices: &[([u8; 32], &str)],
) -> String {
    let mut list = ChannelLine {
        channel: *channel,
        relays: vec![crate::shared_anew::tests::line_at()],
        without: without.to_vec(),
    }
    .to_line()
    .unwrap();
    list.push('\n');
    for (key, label) in devices {
        list.push_str(&format!("{}   {label}\n", encode_public_key(key).unwrap()));
    }
    list
}

/// The device that made a channel anew shows its new channel line, amber,
/// until the list names the new channel; the first read that names it is
/// kept (rule 5's "from then on"). From then on, a key it left out that
/// the list names and whose channel line does not name it after `without`
/// is amber; and `shared seen` ends that amber, for a key brought back on
/// purpose, and only that.
#[test]
fn a_making_anew_here_shows_its_line_and_then_each_key_left_out_the_line_does_not_name() {
    let s = bob(1);
    let now = s.now + 10;
    let old = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    written_by(&s, 0, &old, &[&alice, &carol, &dave], now);
    let devices = [
        (alice.public_key(), "alice-laptop"),
        (carol.public_key(), "carol-laptop"),
        (dave.public_key(), "dave-laptop"),
    ];
    let list = follows_line_at(&s, &old.id, &[], &devices, now);
    let (said, left) = anew_keeping(&s, 0, "review", &[alice.public_key()], now + 1);
    let mut left_sorted = left.clone();
    left_sorted.sort();
    let mut expected = vec![carol.public_key(), dave.public_key()];
    expected.sort();
    assert_eq!(left_sorted, expected);
    let new = filed_as(&s, 0, "review");
    let put = said
        .iter()
        .find(|line| line.starts_with(&format!("channel {}", hex::encode(new.id))))
        .unwrap()
        .clone();

    // The list names the old channel: the line, amber, and the "moved"
    // line is not said beside it.
    let view = view_now(&s, now + 2);
    assert_eq!(view["name"], "review");
    assert_eq!(
        lines(&view),
        [(
            "put_the_line".to_string(),
            "review was made anew here: put its new channel line in .cordelia/members, in a pull \
             request"
                .to_string(),
            true
        )]
    );
    assert_eq!(view["lines"][0]["line"], put.as_str());
    // A read of the same list keeps nothing of "from then on".
    reads(&s, &list, &commit('a'), now + 3);
    let named_at = || follows::made_lines(&s[0].conn).unwrap()[0].named_at;
    assert_eq!(named_at(), None);

    // The new line merged, with Carol's and Dave's lines deleted: the
    // first read that names the new channel is kept, and the line is no
    // longer said; the changed channel line is.
    let merged = list_of_line_at(
        &new.id,
        &[carol.public_key(), dave.public_key()],
        &devices[..1],
    );
    reads(&s, &merged, &commit('b'), now + 4);
    assert_eq!(named_at(), Some(now + 4));
    assert_eq!(amber_words(&view_now(&s, now + 5)), ["line_changed"]);
    reads(&s, &merged, &commit('b'), now + 6);
    assert_eq!(named_at(), Some(now + 4), "the first time stays");
    seen_on(&s, "review").unwrap();
    assert!(ambers(&view_now(&s, now + 6)).is_empty());

    // A pull request brings Dave back: his line, and off `without`. Amber,
    // and he is handed the channel.
    let back = list_of_line_at(&new.id, &[carol.public_key()], &[devices[0], devices[2]]);
    reads(&s, &back, &commit('c'), now + 7);
    let gone_amiss = "dave-laptop was left out of review, and its channel line does not say so: \
                      add it after without, or delete its line";
    let view = view_now(&s, now + 8);
    assert_eq!(ambers(&view), [gone_amiss]);
    assert_eq!(words(&view), ["handing", "not_said"]);
    // Carol listed again, and not after `without`: amber too. The line
    // that names her after `without` again ends hers.
    let both = list_of_line_at(&new.id, &[], &devices);
    reads(&s, &both, &commit('d'), now + 9);
    assert_eq!(
        amber_words(&view_now(&s, now + 10)),
        ["not_said", "not_said"]
    );
    let carol_out = list_of_line_at(&new.id, &[carol.public_key()], &devices);
    reads(&s, &carol_out, &commit('e'), now + 11);
    let view = view_now(&s, now + 11);
    assert_eq!(
        ambers(&view)[1..],
        [gone_amiss],
        "the gate holds Carol, and Dave's stays"
    );

    // `shared seen` alone does not end Dave's amber: it says it is still
    // shown, and how to clear it. Dave was brought back on purpose: `shared
    // seen review dave-laptop` ends it, and keeps him as left out no more.
    // Carol's line goes, and nothing is amber.
    assert_eq!(
        seen_on(&s, "review").unwrap(),
        [
            "Nothing to clear for review on this device.".to_string(),
            still_shown_line("dave-laptop", "review"),
        ]
    );
    assert_eq!(ambers(&view_now(&s, now + 11))[1..], [gone_amiss]);
    assert_eq!(
        seen_key(&s, "review", "carol-laptop"),
        ["Nothing to clear for carol-laptop in review on this device."]
    );
    assert_eq!(
        seen_key(&s, "review", "dave-laptop"),
        [format!("Cleared: {gone_amiss}")]
    );
    assert_eq!(
        follows::made_lines(&s[0].conn).unwrap()[0].left_out,
        [carol.public_key()]
    );
    let without_carol = list_of_line_at(&new.id, &[carol.public_key()], &[devices[0], devices[2]]);
    reads(&s, &without_carol, &commit('f'), now + 12);
    assert!(ambers(&view_now(&s, now + 12)).is_empty());
    // A key left out that the list no longer names, nor its line after
    // `without`, shows nothing: it is not listed.
    let gone = list_of_line_at(&new.id, &[], &devices[..1]);
    reads(&s, &gone, &commit('g'), now + 13);
    assert!(ambers(&view_now(&s, now + 13)).is_empty());
    // So `shared seen` has nothing of it to clear, and keeps it as left
    // out.
    assert_eq!(
        seen_on(&s, "review").unwrap(),
        ["Nothing to clear for review on this device."]
    );
    assert_eq!(
        follows::made_lines(&s[0].conn).unwrap()[0].left_out,
        [carol.public_key()]
    );
}

/// Rule 5's "from then on" starts at the node's first read whose line
/// names the new channel: a list kept by a follow before that read, as
/// `subscribe` keeps one, shows no key left out yet; the node's read does.
#[test]
fn rule_5s_amber_starts_at_the_nodes_first_read_that_names_the_new_channel() {
    let s = bob(1);
    let now = s.now + 10;
    let old = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    written_by(&s, 0, &old, &[&alice, &carol], now);
    let devices = [
        (alice.public_key(), "alice-laptop"),
        (carol.public_key(), "carol-laptop"),
    ];
    follows_line_at(&s, &old.id, &[], &devices, now);
    anew_keeping(&s, 0, "review", &[alice.public_key()], now + 1);
    let new = filed_as(&s, 0, "review");
    let named = list_of_line_at(&new.id, &[], &devices);
    follows_at(&s, &named, &commit('b'), now + 2);
    assert_eq!(follows::made_lines(&s[0].conn).unwrap()[0].named_at, None);
    assert!(ambers(&view_now(&s, now + 2)).is_empty());
    reads(&s, &named, &commit('b'), now + 3);
    assert_eq!(amber_words(&view_now(&s, now + 3)), ["not_said"]);
    // A list that names the old channel again, after it named the new one,
    // is neither this making anew nor a later one: neither its line nor a
    // key it left out is said, only that the line changed.
    let back = list_of_line_at(&old.id, &[], &devices);
    reads(&s, &back, &commit('c'), now + 4);
    assert_eq!(amber_words(&view_now(&s, now + 4)), ["line_changed"]);
}

/// Made anew twice before the first line is merged: only the later line
/// is said, which is the one to put.
#[test]
fn made_anew_twice_before_a_merge_says_the_later_line_alone() {
    let s = bob(1);
    let now = s.now + 10;
    let old = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol, dave) = (member(1), member(2), member(3));
    written_by(&s, 0, &old, &[&alice, &carol, &dave], now);
    let devices = [
        (alice.public_key(), "alice-laptop"),
        (carol.public_key(), "carol-laptop"),
        (dave.public_key(), "dave-laptop"),
    ];
    follows_line_at(&s, &old.id, &[], &devices, now);
    let keep = [alice.public_key(), dave.public_key()];
    anew_keeping(&s, 0, "review", &keep, now + 1);
    let first = filed_as(&s, 0, "review");
    written_by(&s, 0, &first, &[&alice, &dave], now + 2);
    let (said, _) = anew_keeping(&s, 0, "review", &keep[..1], now + 3);
    let later = filed_as(&s, 0, "review");
    let put = said
        .iter()
        .find(|line| line.starts_with(&format!("channel {}", hex::encode(later.id))))
        .unwrap()
        .clone();
    let view = view_now(&s, now + 4);
    assert_eq!(amber_words(&view), ["put_the_line"], "{view}");
    assert_eq!(view["lines"][0]["line"], put.as_str(), "{view}");
}

/// A key left out comes back in the list with a changed channel line, as
/// in the record's §10: `shared seen <name>` clears the changed line and
/// says each line it clears, and says that the key's amber is still
/// shown; `shared seen <name> <label>` clears that amber alone.
#[test]
fn seen_clears_a_changed_line_and_never_a_key_left_out_which_its_label_clears() {
    let s = bob(1);
    let now = s.now + 10;
    let old = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    written_by(&s, 0, &old, &[&alice, &carol], now);
    let devices = [
        (alice.public_key(), "alice-laptop"),
        (carol.public_key(), "carol-laptop"),
    ];
    follows_line_at(&s, &old.id, &[], &devices, now);
    anew_keeping(&s, 0, "review", &[alice.public_key()], now + 1);
    let new = filed_as(&s, 0, "review");
    let back = list_of_line_at(&new.id, &[], &devices);
    reads(&s, &back, &commit('b'), now + 2);
    let view = view_now(&s, now + 3);
    assert_eq!(amber_words(&view), ["line_changed", "not_said"], "{view}");
    let not_said = not_said_line("carol-laptop", "review");
    assert_eq!(
        seen_on(&s, "review").unwrap(),
        [
            format!(
                "Cleared: The list of {REPOSITORY} names a new channel for review at {}.",
                short_of('b')
            ),
            still_shown_line("carol-laptop", "review"),
        ]
    );
    assert_eq!(ambers(&view_now(&s, now + 4)), std::slice::from_ref(&not_said));
    assert_eq!(
        seen_key(&s, "review", "carol-laptop"),
        [format!("Cleared: {not_said}")]
    );
    assert!(ambers(&view_now(&s, now + 5)).is_empty());
    assert_eq!(
        seen_key(&s, "review", "carol-laptop"),
        ["Nothing to clear for carol-laptop in review on this device."]
    );
}

/// Rule 5's "from then on" holds for a channel made anew from this
/// device's new one: Alice makes it anew again, Bob's device moves to it,
/// the list names it, and Carol, left out by Bob's making anew, listed and
/// not after `without`, is amber.
#[test]
fn rule_5s_amber_holds_for_a_channel_made_anew_from_the_new_one() {
    let s = bob(1);
    let now = s.now + 10;
    let old = holds_at_line_at(&s, 0, 7, "review", now);
    let (alice, carol) = (member(1), member(2));
    written_by(&s, 0, &old, &[&alice, &carol], now);
    let devices = [
        (alice.public_key(), "alice-laptop"),
        (carol.public_key(), "carol-laptop"),
    ];
    follows_line_at(&s, &old.id, &[], &devices, now);
    anew_keeping(&s, 0, "review", &[alice.public_key()], now + 1);
    let ours = filed_as(&s, 0, "review");
    written_by(&s, 0, &ours, &[&alice], now + 2);
    let keys = [alice.public_key(), s.key(0)];
    stores(&s, 0, &offer_by(&alice, &ours, 30, &keys, now + 3), now + 3);
    let (conn, identity) = (&s[0].conn, &s[0].identity);
    let plan =
        crate::shared_anew::move_plan(conn, identity, &own_relays(), "review", None, None, now)
            .unwrap();
    crate::shared_anew::make_move(conn, identity, &plan.what, now + 3).unwrap();
    let later = filed_as(&s, 0, "review");
    assert_ne!(later.id, ours.id);
    let named = list_of_line_at(&later.id, &[], &devices);
    reads(&s, &named, &commit('b'), now + 4);
    assert_eq!(
        follows::made_lines(&s[0].conn).unwrap()[0].named_at,
        Some(now + 4)
    );
    assert!(
        amber_words(&view_now(&s, now + 5)).contains(&"not_said".to_string()),
        "{}",
        view_now(&s, now + 5)
    );
}

/// A channel past its bound that a removal made anew on this device is
/// dropped by the removal's own act: here that drop is a move, so the
/// follow goes on, and the removal's line shows until the list names the
/// new channel. On a device that did not make it anew, it is a drop, and
/// the follow stops (rule 2.5).
#[test]
fn a_removals_drop_past_a_bound_keeps_the_follow_on_its_device() {
    let s = bob(1);
    let now = s.now + 10;
    let old = holds_at_line_at(&s, 0, 7, "review", now);
    let alice = (member(1).public_key(), "alice-laptop");
    let list = follows_line_at(&s, &old.id, &[], &[alice], now);
    let new = Shared::of(9);
    crate::shared::tests::acts(&s, 0, crate::lists::Do::DropPastBound(vec![old.id]), now);
    let conn = &s[0].conn;
    anew_rows::made(
        conn,
        &MadeRow {
            channel: old.id,
            new_channel: new.id,
            rev: 2,
            made_at: now,
            at_removal: true,
            delivering: true,
            past_64: 0,
            let_go: 0,
            past_bound: true,
        },
    )
    .unwrap();
    let removed = member(5).public_key();
    let put = list_of_line_at(&new.id, &[removed], &[])
        .trim_end()
        .to_string();
    follows::made_line(conn, &old.id, &[removed], &put, 0).unwrap();
    let gone = || crate::shared_anew::dropped_or_moved(&s[0].conn, &old.id).unwrap();
    assert_eq!(gone(), Some(crate::shared_anew::Gone::Moved));
    reads(&s, &list, &commit('a'), now + 1);
    assert!(row(&s).is_some(), "the follow goes on");
    assert_eq!(
        amber_words(&view_now(&s, now + 2)),
        ["made_anew_at_removal"]
    );
    // Where the making anew is not kept, as on the person's other devices,
    // the drop stops the follow.
    anew_rows::forget_made(&s[0].conn, &old.id).unwrap();
    assert_eq!(gone(), Some(crate::shared_anew::Gone::Dropped));
    reads(&s, &list, &commit('a'), now + 3);
    assert!(row(&s).is_none());
}

/// A view that cannot be worked out is a line of that view, so that the
/// status and `shared list` still say the rest (L2 of slice 7's review).
#[test]
fn a_view_that_cannot_be_worked_out_says_so_in_a_line() {
    let s = bob(1);
    let now = s.now + 10;
    let (_, list) = joins(&s, 7, now);
    let view = not_worked_out(&row(&s).unwrap(), "a fault");
    assert_eq!(view["identity"], REPOSITORY);
    assert_eq!(
        lines(&view),
        [(
            "not_worked_out".to_string(),
            format!("This device could not work out how {REPOSITORY} stands: a fault."),
            false
        )]
    );
    assert!(!list.is_empty());
}

/// A making anew at a removal shows its own line, with its new channel
/// line, amber, until the list names the new channel, and then nothing.
/// The line of a making anew is shown only for the list that names the
/// channel it made anew, or one that channel was made anew from.
#[test]
fn a_making_anew_at_a_removal_shows_its_line_until_the_list_names_the_new_channel() {
    let s = bob(1);
    let now = s.now + 10;
    let old = holds_at_line_at(&s, 0, 7, "review", now);
    let new = Shared::of(9);
    let conn = &s[0].conn;
    anew_rows::made(
        conn,
        &MadeRow {
            channel: old.id,
            new_channel: new.id,
            rev: 2,
            made_at: now,
            at_removal: true,
            delivering: true,
            past_64: 0,
            let_go: 0,
            past_bound: false,
        },
    )
    .unwrap();
    let removed = member(5).public_key();
    let put = list_of_line_at(&new.id, &[removed], &[])
        .trim_end()
        .to_string();
    follows::made_line(conn, &old.id, &[removed], &put, 0).unwrap();
    let alice = (member(1).public_key(), "alice-laptop");
    // Another follow's list, of another channel, shows nothing of it.
    let elsewhere = "example.org/team/other";
    follows_as(
        &s,
        elsewhere,
        &list_of_line_at(&Shared::of(11).id, &[], &[alice]),
        &commit('a'),
        now,
    );
    assert!(ambers(&view_of(&s, elsewhere, now)).is_empty());

    let list = follows_line_at(&s, &old.id, &[], &[alice], now);
    let view = view_now(&s, now + 1);
    let amber: Vec<(String, String, bool)> = lines(&view)
        .into_iter()
        .filter(|(_, _, amber)| *amber)
        .collect();
    assert_eq!(
        amber,
        [(
            "made_anew_at_removal".to_string(),
            "review was made anew at a removal: put its new channel line in .cordelia/members"
                .to_string(),
            true
        )]
    );
    let shown = view["lines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|line| line["word"] == "made_anew_at_removal")
        .unwrap();
    assert_eq!(shown["line"], put.as_str());
    reads(&s, &list, &commit('a'), now + 2);
    assert_eq!(ambers(&view_now(&s, now + 2)).len(), 1);
    // `shared seen` does not end it: the list does.
    seen_on(&s, "review").unwrap();
    assert_eq!(ambers(&view_now(&s, now + 3)).len(), 1);
    // Merged: the list names the new channel, which says it changed, and
    // the line is said no more.
    let merged = list_of_line_at(&new.id, &[removed], &[alice]);
    reads(&s, &merged, &commit('b'), now + 4);
    assert_eq!(amber_words(&view_now(&s, now + 5)), ["line_changed"]);
    assert_eq!(
        follows::made_lines(&s[0].conn).unwrap()[0].named_at,
        Some(now + 4)
    );
}

// ── The words ────────────────────────────────────────────────────────

/// Each line of rules 4.5 to 4.7, 5 and 6 that is said here as the record
/// writes it, the record says.
#[test]
fn the_record_says_each_line() {
    let lines = [
        joined_line("<label>", "<name>", "<commit>"),
        dropped_line("<label>", "<name>").replace("'<name>'", "<name>"),
        gate_line("<label>", "<name>"),
        line_changed_line("<identity>", "<name>", "<commit>"),
        handing_line("<name>", "<label>"),
        put_the_line("<name>", true),
        not_said_line("<label>", "<name>"),
        not_followed_line("<name>"),
    ];
    for line in lines {
        assert!(RECORD.contains(&line), "the record does not say: {line}");
    }
    // The table's line of a member who cannot, in its parts.
    for part in [
        "not clean",
        "not reached at its relays",
        "full",
        "nothing is handed over until then.",
    ] {
        assert!(RECORD.contains(part), "{part}");
    }
    assert!(FOLDER.starts_with('/'));
}

// ── What it costs ────────────────────────────────────────────────────

/// What the views and the status's `shared` object cost under the lock,
/// with 16 follows, the most there can be, each of a held channel whose
/// list names 64 keys, half of them in it; and the object with the same
/// channels and no follow, to compare: printed, for a person to read. Run
/// by hand, in release: `cargo test --release -p cordelia-api --lib
/// the_cost_of_the_views -- --ignored --nocapture`.
#[test]
#[ignore = "a measure, run by hand in release"]
fn the_cost_of_the_views_of_16_follows_of_64_keys() {
    let s = bob(1);
    let now = s.now + 10;
    let mut lists = Vec::new();
    for n in 0..16u32 {
        let channel = holds(&s, 0, 20 + n as u8, &format!("c{n}"), now);
        let devices: Vec<([u8; 32], String)> = (0..64u32)
            .map(|k| (member(n * 100 + k).public_key(), format!("m{n}-{k}")))
            .collect();
        for k in 0..32 {
            stores(
                &s,
                0,
                &crate::shared::tests::anew(&member(n * 100 + k), &channel, 1),
                now,
            );
        }
        lists.push(list_with(Some((&channel.id, &[])), &devices));
    }
    let own = own_relays();
    let said = crate::state::SharedSaid::default();
    let beside = crate::shared_status::Beside {
        own_relays: &own,
        connected: &[],
        said: &said,
    };
    let time = |what: &dyn Fn()| {
        let mut took: Vec<u128> = (0..9)
            .map(|_| {
                let at = std::time::Instant::now();
                what();
                at.elapsed().as_micros()
            })
            .collect();
        took.sort();
        took[4]
    };
    let status = || {
        crate::shared_status::status_of(&s[0].conn, &s[0].identity, &beside, now)
            .unwrap()
            .unwrap();
    };
    let no_follow = time(&status);
    for (n, list) in lists.iter().enumerate() {
        follows_as(
            &s,
            &format!("example.org/team/p{n}"),
            list,
            &commit('a'),
            now,
        );
    }
    let views_took = time(&|| {
        assert_eq!(views(&s[0].conn, &s[0].identity, &own, None, now).len(), 16);
    });
    let with_follows = time(&status);
    println!(
        "median of 9: views alone {views_took} µs; status_of {with_follows} µs with the 16 \
         follows, {no_follow} µs without them"
    );
}
