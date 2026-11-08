//! Tests of what a device keeps of the repositories it follows (decision
//! 2026-11-06 (joining), schema step 33).

use super::*;
use crate::schema::init_db;

const ID: &str = "example.org/team/project";

fn db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_db(&conn).unwrap();
    conn
}

fn commit(c: char) -> String {
    c.to_string().repeat(40)
}

#[test]
fn a_follow_is_kept_read_and_turned() {
    let conn = db();
    assert_eq!(follow_of(&conn, ID).unwrap(), None);
    follow(&conn, ID, "origin", "/work/project", 7).unwrap();
    let kept = follow_of(&conn, ID).unwrap().unwrap();
    assert_eq!(
        (kept.remote.as_str(), kept.clone.as_str(), kept.followed_at),
        ("origin", "/work/project", 7)
    );
    assert_eq!((kept.last, kept.list, kept.last_handed), (None, None, None));
    let read = LastRead {
        commit: commit('a'),
        at: 9,
        from_clone: true,
    };
    assert!(read_done(&conn, ID, &read, b"channel line", Some(8)).unwrap());
    set_last_handed(&conn, ID, &[5; 32]).unwrap();
    let kept = follow_of(&conn, ID).unwrap().unwrap();
    assert_eq!(kept.last, Some(read));
    assert_eq!(kept.list.as_deref(), Some(&b"channel line"[..]));
    assert_eq!(kept.last_handed, Some([5; 32]));
    assert_eq!(
        kept.fetched_at,
        Some(8),
        "when the clone said it was fetched"
    );
    assert_eq!(follows(&conn).unwrap(), vec![kept]);
    // A list read for a repository not followed changes nothing.
    let other = LastRead {
        commit: commit('b'),
        at: 9,
        from_clone: false,
    };
    assert!(!read_done(&conn, "example.org/o/other", &other, b"x", None).unwrap());
}

/// A read that counted for nothing is kept with its word and why, the
/// last list standing, until a read counts; a why longer than the row
/// keeps is cut at a character (rules 1 and 3).
#[test]
fn a_read_that_counted_for_nothing_is_kept_until_one_counts() {
    let conn = db();
    follow(&conn, ID, "origin", "/work/project", 7).unwrap();
    let read = LastRead {
        commit: commit('a'),
        at: 9,
        from_clone: true,
    };
    read_done(&conn, ID, &read, b"list", None).unwrap();
    assert_eq!(follow_of(&conn, ID).unwrap().unwrap().not_read, None);
    let behind = NotRead {
        word: "behind".into(),
        why: "your clone is behind".into(),
    };
    not_read(&conn, ID, &behind).unwrap();
    let kept = follow_of(&conn, ID).unwrap().unwrap();
    assert_eq!(kept.not_read, Some(behind));
    assert_eq!(
        (kept.last, kept.list.as_deref()),
        (Some(read.clone()), Some(&b"list"[..])),
        "the last list stands"
    );
    // Cut at a character: 1,023 bytes and a character of two do not fit.
    let long = NotRead {
        word: "git".into(),
        why: format!("{}é", "w".repeat(1023)),
    };
    not_read(&conn, ID, &long).unwrap();
    let kept = follow_of(&conn, ID).unwrap().unwrap().not_read.unwrap();
    assert_eq!(kept.why, "w".repeat(1023));
    read_done(&conn, ID, &read, b"list", None).unwrap();
    assert_eq!(follow_of(&conn, ID).unwrap().unwrap().not_read, None);
}

/// Following again starts never-back over, and keeps the rest; unfollowing
/// keeps nothing (rule 2.5). The list and the notices stay because the
/// next read is compared with the list last read (rule 4.6), and a notice
/// goes only as rules 4.5 and 4.6 say: a dropped key's stays until the key
/// leaves the channel. The first `followed_at` stays because no key's join
/// before it is noticed (rule 4.5).
#[test]
fn following_again_starts_never_back_over_and_unfollowing_keeps_nothing() {
    let conn = db();
    let key = [3; 32];
    let filled = |conn: &Connection| {
        follow(conn, ID, "origin", "/work/project", 7).unwrap();
        let read = LastRead {
            commit: commit('a'),
            at: 9,
            from_clone: false,
        };
        read_done(conn, ID, &read, b"list", None).unwrap();
        set_last_handed(conn, ID, &[2; 32]).unwrap();
        type_key(conn, ID, &key, 9).unwrap();
        notice(
            conn,
            ID,
            &Notice {
                of: NoticeOf::LineChanged,
                commit: commit('a'),
                at: 9,
            },
        )
        .unwrap();
    };
    filled(&conn);
    follow(&conn, ID, "upstream", "/work/fork", 11).unwrap();
    let kept = follow_of(&conn, ID).unwrap().unwrap();
    assert_eq!(
        (kept.remote.as_str(), kept.clone.as_str(), kept.followed_at),
        ("upstream", "/work/fork", 7)
    );
    assert_eq!(kept.last, None, "never-back starts over");
    assert_eq!(
        (kept.list.as_deref(), kept.last_handed),
        (Some(&b"list"[..]), Some([2; 32]))
    );
    assert_eq!(typed(&conn, ID).unwrap().len(), 1);
    assert_eq!(notices(&conn, ID).unwrap().len(), 1);
    // The yes's commit is where never-back starts over; the list stays.
    let yes_again = || LastRead {
        commit: commit('b'),
        at: 12,
        from_clone: true,
    };
    let yes = yes_again();
    assert!(set_last_read(&conn, ID, &yes).unwrap());
    let kept = follow_of(&conn, ID).unwrap().unwrap();
    assert_eq!(
        (kept.last, kept.list.as_deref()),
        (Some(yes), Some(&b"list"[..]))
    );
    // Nothing is done for a repository not followed.
    assert!(!set_last_read(&conn, "example.org/o/none", &yes_again()).unwrap());
    filled(&conn);
    unfollow(&conn, ID).unwrap();
    assert_eq!(follow_of(&conn, ID).unwrap(), None);
    assert!(typed(&conn, ID).unwrap().is_empty() && notices(&conn, ID).unwrap().is_empty());
    filled(&conn);
    follow(&conn, "example.org/o/other", "origin", "/o", 1).unwrap();
    unfollow_all(&conn).unwrap();
    assert!(follows(&conn).unwrap().is_empty());
    assert!(typed(&conn, ID).unwrap().is_empty() && notices(&conn, ID).unwrap().is_empty());
}

#[test]
fn the_nodes_typings_are_its_own_and_typed_again_start_again() {
    let conn = db();
    follow(&conn, ID, "origin", "/work/project", 7).unwrap();
    type_key(&conn, ID, &[2; 32], 9).unwrap();
    type_key(&conn, ID, &[1; 32], 9).unwrap();
    typed_became(&conn, ID, &[1; 32], "taken", Some("from alice-laptop")).unwrap();
    let kept = typed(&conn, ID).unwrap();
    assert_eq!(kept.len(), 2);
    assert_eq!(
        (
            kept[0].key,
            kept[0].became.as_deref(),
            kept[0].detail.as_deref()
        ),
        ([1; 32], Some("taken"), Some("from alice-laptop"))
    );
    type_key(&conn, ID, &[1; 32], 19).unwrap();
    let again = &typed(&conn, ID).unwrap()[0];
    assert_eq!((again.typed_at, again.became.as_deref()), (19, None));
    untype(&conn, ID, &[1; 32]).unwrap();
    assert_eq!(typed(&conn, ID).unwrap().len(), 1);
    // The person's own typings are another table.
    let persons: i64 = conn
        .query_row("SELECT COUNT(*) FROM shared_typed_keys", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(persons, 0);
}

#[test]
fn a_notice_is_kept_once_until_seen_and_a_dropped_key_until_it_leaves() {
    let conn = db();
    let joined = Notice {
        of: NoticeOf::Joined {
            key: [5; 32],
            label: "alice-laptop".into(),
            channel: [7; 32],
        },
        commit: commit('a'),
        at: 9,
    };
    let changed = |c: char, at: i64| Notice {
        of: NoticeOf::LineChanged,
        commit: commit(c),
        at,
    };
    let dropped = Notice {
        of: NoticeOf::Dropped {
            key: [6; 32],
            label: "bob".into(),
        },
        commit: commit('c'),
        at: 11,
    };
    assert!(notice(&conn, ID, &joined).unwrap());
    assert!(!notice(&conn, ID, &joined).unwrap(), "kept once");
    assert!(notice(&conn, ID, &changed('b', 10)).unwrap());
    assert!(notice(&conn, ID, &dropped).unwrap());
    // A second change of the line takes the place of the first, not yet seen.
    assert!(notice(&conn, ID, &changed('d', 12)).unwrap());
    assert!(!notice(&conn, ID, &changed('d', 12)).unwrap());
    assert_eq!(
        notices(&conn, ID).unwrap(),
        vec![joined, dropped.clone(), changed('d', 12)]
    );
    // `seen` clears the join and the line; the dropped key stays until it
    // leaves the channel.
    assert_eq!(seen(&conn, ID).unwrap(), 2);
    assert_eq!(notices(&conn, ID).unwrap(), vec![dropped]);
    clear_dropped(&conn, ID, &[6; 32]).unwrap();
    assert!(notices(&conn, ID).unwrap().is_empty());
}

/// A follow and an unfollow are one write inside a caller's transaction,
/// as a drop of the channel is (rule 2.5), and undo with it.
#[test]
fn following_runs_inside_a_callers_transaction() {
    let conn = db();
    conn.execute_batch("BEGIN").unwrap();
    follow(&conn, ID, "origin", "/work/project", 7).unwrap();
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(follow_of(&conn, ID).unwrap(), None, "undone with it");
    follow(&conn, ID, "origin", "/work/project", 7).unwrap();
    conn.execute_batch("BEGIN").unwrap();
    unfollow(&conn, ID).unwrap();
    unfollow_all(&conn).unwrap();
    conn.execute_batch("COMMIT").unwrap();
    assert!(follows(&conn).unwrap().is_empty());
}

#[test]
fn the_nodes_shares_and_what_a_making_anew_printed_are_kept() {
    let conn = db();
    conn.execute_batch(
        "INSERT INTO shared_shares (key, channel, pair, relays, rev, made, gone)
             VALUES (x'0101010101010101010101010101010101010101010101010101010101010101',
                     zeroblob(32), zeroblob(32), zeroblob(33), 1, 8, 0);
         INSERT INTO shared_shares (key, channel, pair, relays, rev, made, gone)
             VALUES (x'0202020202020202020202020202020202020202020202020202020202020202',
                     zeroblob(32), zeroblob(32), zeroblob(33), 1, 9, 0);
         INSERT INTO shared_anew_made (channel, new_channel, rev, made_at, at_removal, delivering)
             VALUES (zeroblob(32), x'0909090909090909090909090909090909090909090909090909090909090909',
                     1, 9, 1, 1);",
    )
    .unwrap();
    assert!(shares_by_node(&conn).unwrap().is_empty());
    by_node(&conn, &[2; 32], &[0; 32]).unwrap();
    assert_eq!(
        shares_by_node(&conn).unwrap(),
        vec![NodeShare {
            key: [2; 32],
            channel: [0; 32],
            made: 9
        }]
    );
    let made = made_lines(&conn).unwrap();
    assert_eq!((made[0].left_out.len(), made[0].line.as_deref()), (0, None));
    assert!(
        made_line(
            &conn,
            &[0; 32],
            &[[7; 32], [8; 32]],
            "channel 09 without 2 a b",
            3
        )
        .unwrap()
    );
    assert!(
        !made_line(&conn, &[4; 32], &[], "x", 0).unwrap(),
        "not made here"
    );
    let made = &made_lines(&conn).unwrap()[0];
    assert_eq!(made.new_channel, [9; 32]);
    assert_eq!(made.left_out, vec![[7; 32], [8; 32]]);
    assert_eq!(made.line.as_deref(), Some("channel 09 without 2 a b"));
    assert_eq!(made.cut, 3);
}

/// What a making anew printed is kept within the bounds of schema step 33,
/// so that keeping it never fails the making anew: the first 1,024 keys
/// left out, the rows a table keeps, and a line no longer than a list; a
/// longer line is not kept.
#[test]
fn what_a_making_anew_printed_is_kept_within_its_bounds() {
    let conn = db();
    conn.execute_batch(
        "INSERT INTO shared_anew_made (channel, new_channel, rev, made_at, at_removal, delivering)
             VALUES (zeroblob(32), zeroblob(32), 1, 9, 1, 1);",
    )
    .unwrap();
    let keys: Vec<[u8; 32]> = (0..=SHARED_KEYS_KEPT as u32)
        .map(|n| {
            let mut key = [0; 32];
            key[..4].copy_from_slice(&n.to_be_bytes());
            key
        })
        .collect();
    let longest = "c".repeat(MEMBERS_FILE_MAX_BYTES);
    assert!(made_line(&conn, &[0; 32], &keys, &longest, 0).unwrap());
    let made = &made_lines(&conn).unwrap()[0];
    assert_eq!(made.left_out, keys[..SHARED_KEYS_KEPT]);
    assert_eq!(made.line.as_deref(), Some(longest.as_str()));
    let longer = "c".repeat(MEMBERS_FILE_MAX_BYTES + 1);
    assert!(made_line(&conn, &[0; 32], &keys[..1], &longer, 0).unwrap());
    let made = &made_lines(&conn).unwrap()[0];
    assert_eq!((made.left_out.len(), made.line.as_deref()), (1, None));
}

/// When a list first named the new channel is kept once, and stays the
/// first time (rule 5's "from then on"); and the keys a person cleared the
/// amber of are kept as left out no more, the others staying, in their
/// order.
#[test]
fn when_a_list_first_named_the_new_channel_is_kept_and_cleared_keys_go() {
    let conn = db();
    conn.execute_batch(
        "INSERT INTO shared_anew_made (channel, new_channel, rev, made_at, at_removal, delivering)
             VALUES (zeroblob(32), zeroblob(32), 1, 9, 0, 1);",
    )
    .unwrap();
    assert_eq!(made_lines(&conn).unwrap()[0].named_at, None);
    assert!(!named(&conn, &[4; 32], 10).unwrap(), "not made here");
    assert!(named(&conn, &[0; 32], 10).unwrap());
    assert!(!named(&conn, &[0; 32], 11).unwrap(), "the first time stays");
    assert_eq!(made_lines(&conn).unwrap()[0].named_at, Some(10));

    assert_eq!(not_left_out(&conn, &[0; 32], &[[7; 32]]).unwrap(), 0);
    made_line(&conn, &[0; 32], &[[7; 32], [8; 32], [6; 32]], "x", 0).unwrap();
    assert_eq!(not_left_out(&conn, &[0; 32], &[[5; 32]]).unwrap(), 0);
    assert_eq!(
        not_left_out(&conn, &[0; 32], &[[8; 32], [7; 32]]).unwrap(),
        2
    );
    let made = &made_lines(&conn).unwrap()[0];
    assert_eq!(made.left_out, [[6; 32]]);
    assert_eq!((made.line.as_deref(), made.named_at), (Some("x"), Some(10)));
    assert_eq!(not_left_out(&conn, &[4; 32], &[[6; 32]]).unwrap(), 0);
}
