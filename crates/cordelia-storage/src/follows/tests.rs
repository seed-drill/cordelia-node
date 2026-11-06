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
    assert_eq!((kept.last, kept.list, kept.turn), (None, None, 0));
    let read = LastRead {
        commit: commit('a'),
        at: 9,
        from_clone: true,
    };
    assert!(read_done(&conn, ID, &read, b"channel line").unwrap());
    set_turn(&conn, ID, 5).unwrap();
    let kept = follow_of(&conn, ID).unwrap().unwrap();
    assert_eq!(kept.last, Some(read));
    assert_eq!(kept.list.as_deref(), Some(&b"channel line"[..]));
    assert_eq!(kept.turn, 5);
    assert_eq!(follows(&conn).unwrap(), vec![kept]);
    // A list read for a repository not followed changes nothing.
    let other = LastRead {
        commit: commit('b'),
        at: 9,
        from_clone: false,
    };
    assert!(!read_done(&conn, "example.org/o/other", &other, b"x").unwrap());
}

/// Following again starts afresh, and unfollowing keeps nothing (rule 2.5).
#[test]
fn following_again_starts_afresh_and_unfollowing_keeps_nothing() {
    let conn = db();
    let key = [3; 32];
    let filled = |conn: &Connection| {
        follow(conn, ID, "origin", "/work/project", 7).unwrap();
        let read = LastRead {
            commit: commit('a'),
            at: 9,
            from_clone: false,
        };
        read_done(conn, ID, &read, b"list").unwrap();
        set_turn(conn, ID, 2).unwrap();
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
    assert_eq!((kept.remote.as_str(), kept.followed_at), ("upstream", 11));
    assert_eq!((kept.last, kept.list, kept.turn), (None, None, 0));
    assert!(typed(&conn, ID).unwrap().is_empty());
    assert!(notices(&conn, ID).unwrap().is_empty());
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
fn a_notice_is_kept_once_until_seen() {
    let conn = db();
    let joined = Notice {
        of: NoticeOf::Joined([5; 32]),
        commit: commit('a'),
        at: 9,
    };
    let changed = Notice {
        of: NoticeOf::LineChanged,
        commit: commit('b'),
        at: 10,
    };
    assert!(notice(&conn, ID, &joined).unwrap());
    assert!(!notice(&conn, ID, &joined).unwrap(), "kept once");
    assert!(notice(&conn, ID, &changed).unwrap());
    assert_eq!(notices(&conn, ID).unwrap(), vec![joined, changed]);
    assert_eq!(seen(&conn, ID).unwrap(), 2);
    assert!(notices(&conn, ID).unwrap().is_empty());
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
            "channel 09 without 2 a b"
        )
        .unwrap()
    );
    assert!(
        !made_line(&conn, &[4; 32], &[], "x").unwrap(),
        "not made here"
    );
    let made = &made_lines(&conn).unwrap()[0];
    assert_eq!(made.new_channel, [9; 32]);
    assert_eq!(made.left_out, vec![[7; 32], [8; 32]]);
    assert_eq!(made.line.as_deref(), Some("channel 09 without 2 a b"));
}
