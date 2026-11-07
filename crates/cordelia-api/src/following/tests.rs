//! Tests of following a repository (decision 2026-11-06 (joining), rules
//! 2.3 to 2.5): the plan of `cordelia subscribe` in a clone for each case
//! of rule 2.3, `--new` and the labels it makes, and the route over a real
//! clone on the disk.

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

/// What was read of a clone at `commit`, with `list` (or none).
fn read_at(list: Option<&str>, commit: &str) -> ClonedRead {
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
    }
}

/// The plan of device 0 in [`FOLDER`], with `list` at `commit`.
fn planned(s: &Several, list: Option<&str>, commit: &str, new: bool) -> Out<Plan<Following>> {
    plan(
        &s[0].conn,
        &s[0].identity,
        &own_relays(),
        FOLDER,
        &read_at(list, commit),
        new,
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
            &format!("This reads the list of {REPOSITORY} at commit {FIRST}, from your clone."),
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
            &format!("This reads the list of {REPOSITORY} at commit {FIRST}, from your clone."),
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
/// subscribes already, it still follows. Subscribing again starts the row
/// afresh at the commit read, whether or not it comes after the last one
/// (rule 2.5). A holder whose key is not on the list follows too.
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
        format!("This reads the list of {REPOSITORY} at commit {FIRST}, from your clone."),
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

    // Subscribed already: it still follows, at the commit now read.
    let later = s.tick() + 10;
    let again = planned(&s, Some(&list), SECOND, false).unwrap();
    assert!(
        again.asks.ends_with(
            "This follows example.org/team/project.\nproject subscribes to \"review\" already."
        ),
        "{}",
        again.asks
    );
    assert_ne!(again.asks, first.asks, "the yes names the commit");
    yes(&s, &again, later);
    let row = follow_row(&s).unwrap();
    assert_eq!(
        (row.last.unwrap().commit, row.followed_at),
        (SECOND.into(), later)
    );
    // Never back does not hold for a subscribe: the row starts afresh at
    // the commit read, here the earlier one.
    let back = planned(&s, Some(&list), FIRST, false).unwrap();
    yes(&s, &back, later + 1);
    assert_eq!(follow_row(&s).unwrap().last.unwrap().commit, FIRST);

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

/// A key left out of the channel and still listed holds the list back
/// (rule 1): the list names no channel, so the holder follows and waits,
/// and no agent is subscribed. Once that key writes in the channel, the
/// list names it again.
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
    assert!(
        held_back.asks.contains(NO_CHANNEL_YET),
        "{}",
        held_back.asks
    );
    assert!(matches!(held_back.what.then, Then::Nothing));
    yes(&s, &held_back, now + 1);
    assert!(!subscribed(&s, &channel));
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
/// back or not, and where the name `owner/name` is taken, with today's
/// refusal; and nothing is done.
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
    assert_eq!(refusal(planned(&s, Some(&me), FIRST, true)).0, "name_taken");
    assert_eq!(sharing::filed(&s[0].conn).unwrap().len(), filed);
    assert!(follow_row(&s).is_none());
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
struct OnDisk {
    home: PathBuf,
    top: PathBuf,
}

impl OnDisk {
    fn new(under: &Path) -> Self {
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
    fn fetched(&self, list: &str) -> String {
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
/// repository at the commit its yes named, and asks the node to read the
/// list; a second subscribe, at a new commit, needs a new yes, and a yes
/// to the old one is refused as changed, with nothing done; a mapped
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
            "This reads the list of {REPOSITORY} at commit {first}, from your clone."
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
    assert!(again.contains(&second), "{again}");
    let (status, _) = asked(&state, json!({ "folder": top, "said_yes_to": again })).await;
    assert_eq!(status, 200);
    assert_eq!(row(&state).unwrap().last.unwrap().commit, second);

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
