//! The index line of a memory that comes back (`claude::lines`): what a
//! cycle writes down, the minute of looking, the put-back and what stops
//! it, and when a record goes.

use super::*;
use crate::memory_md::INDEX_FILE as INDEX;
use cordelia_storage::index_lines;

/// The time the tests begin at, in seconds: any time will do.
const T0: i64 = 1_800_000_000;

/// Set this device's clock to `t` seconds after the beginning.
fn at(p: &Pair, t: i64) {
    p.st.sync_control.set_now(Some(T0 + t));
}

/// A cycle at `t`.
fn cycle_at(p: &Pair, t: i64) -> FolderReport {
    at(p, t);
    p.cycle()
}

/// The whole records of the folder, as (file, line, times put back).
fn records(p: &Pair) -> Vec<(String, String, u32)> {
    let db = p.st.db.lock().unwrap();
    let folder = p.mem.display().to_string();
    let now = p.st.sync_control.now();
    index_lines::whole(&db, &folder, &p.channel, now)
        .unwrap()
        .into_iter()
        .map(|r| (r.file, r.line, r.put_back))
        .collect()
}

/// Every row of the folder, whole or not: (file, has a line, has a
/// delete, whole).
fn rows(p: &Pair) -> Vec<(String, bool, bool, bool)> {
    let db = p.st.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT file, line_at IS NOT NULL, deleted_at IS NOT NULL, whole FROM index_lines
             WHERE folder = ?1 AND channel_id = ?2 ORDER BY file",
        )
        .unwrap();
    let folder = p.mem.display().to_string();
    stmt.query_map(rusqlite::params![folder, p.channel], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

const NOTES: &str = "- [Notes](notes.md) what was noted\n";
const OTHER_LINE: &str = "- [Other](other.md) the other one\n";

/// A folder with two memories and an index that lists both, agreed with
/// the channel at the beginning.
fn listed() -> Pair {
    let p = Pair::new();
    p.file("notes.md", "one\n");
    p.file("other.md", "x\n");
    p.file(INDEX, &format!("{NOTES}{OTHER_LINE}"));
    assert_eq!(cycle_at(&p, 0).published, 3);
    p
}

/// This device deletes `notes.md` and its line, in one cycle, at `t`.
fn deletes_with_its_line(p: &Pair, t: i64) {
    std::fs::remove_file(p.mem.join("notes.md")).unwrap();
    p.file(INDEX, OTHER_LINE);
    assert_eq!(cycle_at(p, t).published, 2);
}

/// The other device's edit of `notes.md`, made apart, beats the delete,
/// and this device takes it at `t`: the file is back, and its line is not.
fn comes_back(p: &Pair, t: i64) {
    p.other_writes("notes.md", Some("two\n"));
    let report = cycle_at(p, t);
    assert_eq!((report.pulled, report.published), (1, 0), "{report:?}");
    assert_eq!(p.read("notes.md").as_deref(), Some("two\n"));
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
}

/// A memory that this device deleted with its line comes back by another
/// device's edit. A minute of looks later, and not before, this device
/// puts the line back, at the end of the index, as an edit of its own.
/// Once the line has stayed for a minute the record goes, and a line that
/// someone removes after that is not put back.
#[test]
fn the_line_of_a_memory_that_comes_back_is_put_back() {
    let p = listed();
    deletes_with_its_line(&p, 10);
    assert_eq!(
        records(&p),
        [("notes.md".into(), NOTES.trim_end().into(), 0)]
    );
    comes_back(&p, 20);

    // Thirteen cycles five seconds apart: the line goes back at the last,
    // and at none before.
    for look in 1..13 {
        let report = cycle_at(&p, 20 + 5 * look);
        assert_eq!(report.published, 0, "look {look}: {report:?}");
        assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE), "look {look}");
    }
    let report = cycle_at(&p, 85);
    assert_eq!(report.published, 1, "{report:?}");
    let back = format!("{OTHER_LINE}{NOTES}");
    assert_eq!(p.read(INDEX).as_deref(), Some(back.as_str()));
    assert_eq!(p.held(INDEX).as_deref(), Some(back.as_str()));
    assert_eq!(
        records(&p),
        [("notes.md".into(), NOTES.trim_end().into(), 1)]
    );
    // It is this device's own edit, at rest from the next cycle.
    let report = cycle_at(&p, 90);
    assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");

    // The line has stayed through a minute of looking, of which the
    // cycle at 90 was the first: the record goes.
    for look in 1..12 {
        cycle_at(&p, 90 + 5 * look);
        assert_eq!(records(&p).len(), 1, "look {look}");
    }
    cycle_at(&p, 150);
    assert_eq!(records(&p), []);
    assert_eq!(rows(&p), []);

    // Someone removes the line later, and keeps the file: it is theirs to
    // unlist, and nothing answers it.
    p.file(INDEX, OTHER_LINE);
    assert_eq!(cycle_at(&p, 200).published, 1);
    for look in 1..20 {
        assert_eq!(cycle_at(&p, 200 + 5 * look).published, 0);
    }
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
}

/// What a cycle writes down, and what it does not. A line is written
/// down when this device publishes an edit of the index that drops it,
/// whether or not its file is there; a delete, when this device publishes
/// it. Nothing is written for a line that is a line for no file, for the
/// index's own delete or a conflict file's, for a merge, for an index or
/// a delete taken from the channel, or for a publish that is not made.
#[test]
fn what_this_device_publishes_is_written_down() {
    let p = Pair::new();
    let index = [
        "# Memory\n",
        NOTES,
        "- [Notes again](notes.md) a second line for it\n",
        "- [Gone](absent.md) no such file  \n",
        "plain words\n",
        "- [Site](https://example.org/notes.md) a link to elsewhere\n",
        "- [Below](./below.md) a path\n",
        "- [Index](MEMORY.md) the index itself\n",
        "- [Copy](notes.conflict-0a1b2c3d.md) a conflict file\n",
        OTHER_LINE,
    ]
    .concat();
    p.file("notes.md", "one\n");
    p.file("other.md", "x\n");
    p.file("notes.conflict-0a1b2c3d.md", "a copy\n");
    p.file(INDEX, &index);
    assert_eq!(cycle_at(&p, 0).published, 4);
    assert_eq!(rows(&p), []);

    // An edit of the index that keeps only the heading and one line. A
    // line is written down for each file that had one: the first of two
    // for `notes.md`, which is there, and the one for a file that is not.
    p.file(INDEX, &format!("# Memory\n{OTHER_LINE}"));
    assert_eq!(cycle_at(&p, 10).published, 1);
    assert_eq!(
        rows(&p),
        [
            ("absent.md".to_string(), true, false, false),
            ("notes.md".to_string(), true, false, false),
        ]
    );
    let line_of = |file: &str| -> String {
        let db = p.st.db.lock().unwrap();
        db.query_row(
            "SELECT line FROM index_lines WHERE file = ?1",
            [file],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(line_of("notes.md"), NOTES.trim_end());
    // Without the space at its end.
    assert_eq!(line_of("absent.md"), "- [Gone](absent.md) no such file");

    // The delete of a memory is written down, and the record is whole.
    // The delete of a conflict file is not.
    std::fs::remove_file(p.mem.join("notes.md")).unwrap();
    std::fs::remove_file(p.mem.join("notes.conflict-0a1b2c3d.md")).unwrap();
    assert_eq!(cycle_at(&p, 20).published, 2);
    assert_eq!(
        rows(&p),
        [
            ("absent.md".to_string(), true, false, false),
            ("notes.md".to_string(), true, true, true),
        ]
    );

    // A delete that arrives from another device is not this device's.
    p.other_writes("other.md", None);
    let report = cycle_at(&p, 30);
    assert_eq!((report.pulled, report.published), (1, 0), "{report:?}");
    assert_eq!(p.read("other.md"), None);
    assert_eq!(rows(&p).len(), 2);

    // Nor is an index taken from the channel, whatever lines it lacks...
    p.other_writes(INDEX, Some("# Memory\n"));
    let report = cycle_at(&p, 40);
    assert_eq!((report.pulled, report.published), (1, 0), "{report:?}");
    assert_eq!(rows(&p).len(), 2);

    // ...nor a merge, whatever it leaves out: the other device adds a
    // line while this one writes another index.
    p.file(INDEX, "# Memory\n- [A](a.md) here\n");
    p.file("a.md", "a\n");
    assert_eq!(cycle_at(&p, 50).published, 2);
    // The other device's index also has a line for `other.md`, which is
    // deleted in the channel: the merge leaves that line out.
    p.file(INDEX, "# Memory\n- [B](b.md) here\n");
    p.other_writes(
        INDEX,
        Some(&format!(
            "# Memory\n- [A](a.md) here\n- [C](c.md) there\n{OTHER_LINE}"
        )),
    );
    let report = cycle_at(&p, 60);
    assert_eq!(report.published, 1, "{report:?}");
    let merged = p.read(INDEX).unwrap();
    assert!(merged.contains("[C](c.md)") && merged.contains("[B](b.md)"));
    assert!(!merged.contains("other.md"), "{merged}");
    assert_eq!(rows(&p).len(), 2);

    // An edit that is not published, because the channel's version moved
    // after the cycle read it, writes nothing down.
    let before = p.read(INDEX).unwrap();
    p.file(INDEX, "# Memory\n");
    let report = cycle_with_at(&p, 70, &|| {
        p.other_writes(INDEX, Some("# Memory\n- [D](d.md)\n"))
    });
    assert_eq!(report.published, 0, "{report:?}");
    assert_eq!(rows(&p).len(), 2);
    let _ = before;

    // The index's own delete is written down for no file.
    std::fs::remove_file(p.mem.join(INDEX)).unwrap();
    p.other_writes("zzz.md", Some("z\n"));
    cycle_at(&p, 80);
    cycle_at(&p, 85);
    assert!(rows(&p).iter().all(|(file, ..)| file != INDEX));
}

/// A cycle at `t`, with `between` done once it has read the folder and
/// the channel.
fn cycle_with_at(p: &Pair, t: i64, between: &dyn Fn()) -> FolderReport {
    at(p, t);
    p.cycle_with(between)
}

/// A file that this device makes under the name of a memory it deleted is
/// its own to list: the record goes when the file is published. And a
/// half that waited more than an hour for the other is gone, so a line
/// removed and a memory deleted an hour and more apart make no record.
#[test]
fn a_record_is_of_a_memory_deleted_with_its_line() {
    let p = listed();
    deletes_with_its_line(&p, 10);
    assert_eq!(records(&p).len(), 1);
    // The person writes a new file under that name here: no text was
    // agreed for it. The record goes, and the line is theirs to add.
    p.file("notes.md", "written anew\n");
    assert_eq!(cycle_at(&p, 20).published, 1);
    assert_eq!(rows(&p), []);
    for look in 1..20 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));

    // An edit of a file that was agreed as a text keeps a record.
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    p.file("notes.md", "three\n");
    assert_eq!(cycle_at(&p, 25).published, 1);
    assert_eq!(records(&p).len(), 1);

    // The line goes, and the file an hour and a second later: no record.
    let p = listed();
    p.file(INDEX, OTHER_LINE);
    assert_eq!(cycle_at(&p, 10).published, 1);
    std::fs::remove_file(p.mem.join("notes.md")).unwrap();
    assert_eq!(cycle_at(&p, 10 + 3601).published, 1);
    assert_eq!(records(&p), []);
    comes_back(&p, 10 + 3700);
    for look in 1..20 {
        assert_eq!(cycle_at(&p, 3710 + 5 * look).published, 0);
    }
    // Within the hour, in either order, it is one.
    let p = listed();
    std::fs::remove_file(p.mem.join("notes.md")).unwrap();
    assert_eq!(cycle_at(&p, 10).published, 1);
    assert_eq!(records(&p), []);
    p.file(INDEX, OTHER_LINE);
    assert_eq!(cycle_at(&p, 3600).published, 1);
    assert_eq!(records(&p).len(), 1);
}

/// The minute of looking. The line is put back only once it has been due
/// at every look for a minute, the looks no more than 30 seconds apart.
/// The minute starts again after a gap, at a settings command, at a
/// restart, and when a cycle applies an action to the index or to the
/// file. A cycle that did not deal with every file is no look; one in
/// which another file failed is.
#[test]
fn the_minute_of_looking() {
    // One jump of the clock past the minute puts nothing back, and a look
    // 31 seconds after the one before starts the minute again.
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    assert_eq!(cycle_at(&p, 25).published, 0);
    assert_eq!(cycle_at(&p, 500).published, 0);
    assert_eq!(cycle_at(&p, 530).published, 0);
    assert_eq!(cycle_at(&p, 559).published, 0);
    // 31 seconds: the minute, which was a second from up, starts again.
    assert_eq!(cycle_at(&p, 590).published, 0);
    assert_eq!(cycle_at(&p, 620).published, 0);
    assert_eq!(cycle_at(&p, 649).published, 0);
    assert_eq!(cycle_at(&p, 650).published, 1);

    // The clock is set back in the middle of the minute: a time later
    // than now is read as now, so the minute runs from the earlier time,
    // and is not held up until the clock has caught up with itself.
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    for t in [25, 50] {
        assert_eq!(cycle_at(&p, t).published, 0);
    }
    for t in [15, 40, 65, 74] {
        assert_eq!(cycle_at(&p, t).published, 0, "{t}");
    }
    assert_eq!(cycle_at(&p, 75).published, 1);

    // A settings command starts it again.
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    for t in [25, 50, 75] {
        assert_eq!(cycle_at(&p, t).published, 0);
    }
    p.st.sync_control.changed(&p.st.db.lock().unwrap());
    assert_eq!(cycle_at(&p, 85).published, 0);
    assert_eq!(cycle_at(&p, 110).published, 0);
    assert_eq!(cycle_at(&p, 135).published, 0);
    assert_eq!(cycle_at(&p, 145).published, 1);

    // So does a restart: what the looks found is in the node's memory.
    let mut p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    for t in [25, 50, 75] {
        assert_eq!(cycle_at(&p, t).published, 0);
    }
    p.st.sync_control = Default::default();
    assert_eq!(cycle_at(&p, 90).published, 0);
    assert_eq!(cycle_at(&p, 120).published, 0);
    assert_eq!(cycle_at(&p, 149).published, 0);
    assert_eq!(cycle_at(&p, 150).published, 1);
    assert_eq!(records(&p).len(), 1, "a record is not lost at a restart");

    // An action on the file starts it again: the other device edits it.
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    for t in [25, 50, 75] {
        assert_eq!(cycle_at(&p, t).published, 0);
    }
    p.other_writes("notes.md", Some("three\n"));
    assert_eq!(cycle_at(&p, 80).pulled, 1);
    for t in [85, 110, 135, 144] {
        assert_eq!(cycle_at(&p, t).published, 0, "{t}");
    }
    assert_eq!(cycle_at(&p, 145).published, 1);

    // And an action on the index: the other device adds a line.
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    for t in [25, 50, 75] {
        assert_eq!(cycle_at(&p, t).published, 0);
    }
    let longer = format!("{OTHER_LINE}- [More](more.md) more\n");
    p.other_writes(INDEX, Some(&longer));
    assert_eq!(cycle_at(&p, 80).pulled, 1);
    for t in [85, 110, 135, 144] {
        assert_eq!(cycle_at(&p, t).published, 0, "{t}");
    }
    assert_eq!(cycle_at(&p, 145).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{longer}{NOTES}"));
}

/// A cycle that did not deal with every file of the folder asks nothing:
/// one that was stopped by a change of settings, and one ended by a
/// failure that is not a file's. A cycle in which a file failed did deal
/// with every file, and is a look.
#[test]
fn only_a_cycle_that_dealt_with_every_file_looks() {
    // Ended by a failure that is not a file's, at the moment the minute
    // is up: nothing is put back.
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    p.other_writes("z.md", Some("z\n"));
    let broken = cycle_with_at(&p, 85, &|| {
        let db = p.st.db.lock().unwrap();
        db.execute_batch("ALTER TABLE sync_files RENAME TO sync_files_away")
            .unwrap();
    });
    assert!(broken.error.is_some(), "{broken:?}");
    assert_eq!(broken.published, 0);
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    p.st.db
        .lock()
        .unwrap()
        .execute_batch("ALTER TABLE sync_files_away RENAME TO sync_files")
        .unwrap();

    // A cycle that takes a new text for the file, and is then ended by a
    // failure at a later file, has done something to the file: the minute
    // starts again at that moment, though that cycle makes no look.
    let p = back_unlisted();
    for look in 1..12 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    p.other_writes("notes.md", Some("three\n"));
    p.other_writes("zz.md", Some("z\n"));
    let flushed = |name: &str| {
        if name == "zz.md" {
            let db = p.st.db.lock().unwrap();
            db.execute_batch("ALTER TABLE sync_files RENAME TO sync_files_away")
                .unwrap();
        }
    };
    let broken = hooked_at(
        &p,
        80,
        &Hooks {
            flushed: &flushed,
            ..Hooks::NONE
        },
    );
    assert!(broken.error.is_some(), "{broken:?}");
    assert_eq!(p.read("notes.md").as_deref(), Some("three\n"));
    p.st.db
        .lock()
        .unwrap()
        .execute_batch("ALTER TABLE sync_files_away RENAME TO sync_files")
        .unwrap();
    // The next cycle is a look, a minute after the first one; and the
    // line is not due for its minute, which begins again with this look.
    let report = cycle_at(&p, 85);
    assert_eq!(report.published, 0, "{report:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    for look in 1..12 {
        assert_eq!(cycle_at(&p, 85 + 5 * look).published, 0, "look {look}");
    }
    assert_eq!(cycle_at(&p, 145).published, 1);

    // The same for the index: a cycle that takes a new index, and is then
    // ended by a failure at a later file, starts every record's minute
    // again.
    let p = back_unlisted();
    for look in 1..12 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    let theirs = format!("{OTHER_LINE}- [Extra](extra.md) listed there\n");
    p.other_writes(INDEX, Some(&theirs));
    p.other_writes("zz.md", Some("z\n"));
    let flushed = |name: &str| {
        if name == "zz.md" {
            let db = p.st.db.lock().unwrap();
            db.execute_batch("ALTER TABLE sync_files RENAME TO sync_files_away")
                .unwrap();
        }
    };
    let broken = hooked_at(
        &p,
        80,
        &Hooks {
            flushed: &flushed,
            ..Hooks::NONE
        },
    );
    assert!(broken.error.is_some(), "{broken:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(theirs.as_str()));
    p.st.db
        .lock()
        .unwrap()
        .execute_batch("ALTER TABLE sync_files_away RENAME TO sync_files")
        .unwrap();
    for look in 0..12 {
        let report = cycle_at(&p, 85 + 5 * look);
        assert_eq!(report.published, 0, "look {look}: {report:?}");
    }
    assert_eq!(cycle_at(&p, 145).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{theirs}{NOTES}"));

    // Stopped by a change of settings, likewise: here at the last file,
    // when every other has been dealt with, and at the moment the minute
    // is up. It makes no look, so the minute begins again with the next
    // cycle's, at 90, and not with one at 85.
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    p.other_writes("z.md", Some("z\n"));
    let changed = |name: &str| {
        if name == "z.md" {
            p.st.sync_control.changed(&p.st.db.lock().unwrap());
        }
    };
    let stopped = hooked_at(
        &p,
        85,
        &Hooks {
            flushed: &changed,
            ..Hooks::NONE
        },
    );
    assert!(stopped.stopped, "{stopped:?}");
    assert_eq!(stopped.published, 0);
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    for look in 0..12 {
        let report = cycle_at(&p, 90 + 5 * look);
        assert_eq!(report.published, 0, "look {look}: {report:?}");
    }
    assert_eq!(cycle_at(&p, 150).published, 1);

    // A file that fails in every cycle does not hold the line back: each
    // of those cycles is a look.
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    p.other_writes("stuck.md", Some("s\n"));
    std::fs::create_dir(p.mem.join(temporary_name("stuck.md"))).unwrap();
    for look in 1..13 {
        let report = cycle_at(&p, 20 + 5 * look);
        assert_eq!(
            (report.published, report.failed.len()),
            (0, 1),
            "{report:?}"
        );
    }
    let report = cycle_at(&p, 85);
    assert_eq!(
        (report.published, report.failed.len()),
        (1, 1),
        "{report:?}"
    );
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));
}

/// Thirteen looks, five seconds apart, from `first`: the reports of all
/// but the last, which is returned by itself. With a line due at every
/// one of them, the last is the look at which it goes back.
fn a_minute_from(p: &Pair, first: i64) -> FolderReport {
    for look in 0..12 {
        let report = cycle_at(p, first + 5 * look);
        assert_eq!(report.published, 0, "look {look}: {report:?}");
    }
    cycle_at(p, first + 60)
}

/// A memory deleted here with its line, and back by another device's
/// edit: the folder as it is when the looks begin, at 20.
fn back_unlisted() -> Pair {
    let p = listed();
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    p
}

/// What one rule alone holds back: a line that is already there; a
/// memory that is deleted in the channel again; a record that agrees in
/// text and not in revision; and an index that is not there.
#[test]
fn nothing_is_put_back_where_the_line_is_not_due() {
    // A line is there already: the other device listed the memory. The
    // record goes once the line has stayed, and nothing is published.
    let p = back_unlisted();
    let theirs = format!("{OTHER_LINE}- [Notes, again](notes.md) listed there\n");
    p.other_writes(INDEX, Some(&theirs));
    assert_eq!(cycle_at(&p, 25).pulled, 1);
    let last = a_minute_from(&p, 30);
    assert_eq!(last.published, 0, "{last:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(theirs.as_str()));
    assert_eq!(records(&p), []);

    // The line is there and the file is deleted again: the record stays
    // (a line that is there shows nothing of a memory that is gone).
    let p = back_unlisted();
    p.other_writes(INDEX, Some(&theirs));
    p.other_writes("notes.md", None);
    let report = cycle_at(&p, 25);
    assert_eq!(report.pulled, 2, "{report:?}");
    let last = a_minute_from(&p, 30);
    assert_eq!(last.published, 0, "{last:?}");
    assert_eq!(records(&p).len(), 1);

    // The memory is deleted in the channel again, with no line: nothing
    // is due.
    let p = back_unlisted();
    p.other_writes("notes.md", None);
    assert_eq!(cycle_at(&p, 25).pulled, 1);
    let last = a_minute_from(&p, 30);
    assert_eq!(last.published, 0, "{last:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));

    // The record of the file agrees in text and not in revision: the
    // other device published the same text again. That cycle records it,
    // which is an action on the file, and the minute starts again.
    let p = back_unlisted();
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    p.other_writes("notes.md", Some("two\n"));
    let report = cycle_at(&p, 85);
    assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");
    assert_eq!(a_minute_from(&p, 90).published, 1);

    // The index is not there: this device deleted it. Nothing is put
    // back while it is away.
    let p = back_unlisted();
    std::fs::remove_file(p.mem.join(INDEX)).unwrap();
    assert_eq!(cycle_at(&p, 25).published, 1);
    let last = a_minute_from(&p, 30);
    assert_eq!(last.published, 0, "{last:?}");
    assert_eq!(p.read(INDEX), None);
}

/// One cycle at `t` with `hooks`.
fn hooked_at(p: &Pair, t: i64, hooks: &Hooks) -> FolderReport {
    at(p, t);
    p.cycle_hooked(hooks).unwrap()
}

/// What the second look and the hold refuse: a line that is due for its
/// minute is not put back in a cycle in which the index or the file has
/// changed here since the cycle listed them, or in which the index's
/// entry, the file's entry or the settings have changed since the cycle
/// read them. The next looks decide again.
#[test]
fn nothing_is_put_back_over_what_changed_during_the_cycle() {
    let due = || {
        let p = back_unlisted();
        for look in 1..13 {
            assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
        }
        p
    };
    let not_put_back = |p: &Pair, report: &FolderReport| {
        assert_eq!(report.published, 0, "{report:?}");
        assert!(
            report.failed.is_empty() && report.error.is_none(),
            "{report:?}"
        );
        assert_eq!(
            records(p),
            [("notes.md".into(), NOTES.trim_end().into(), 0)]
        );
        assert!(!p.held(INDEX).unwrap().contains("notes.md"));
    };

    // The index changed here after the cycle listed it.
    let p = due();
    let report = cycle_with_at(&p, 85, &|| {
        p.file(INDEX, "- [Mine](mine.md) written meanwhile\n")
    });
    not_put_back(&p, &report);
    assert_eq!(
        p.read(INDEX).as_deref(),
        Some("- [Mine](mine.md) written meanwhile\n")
    );

    // The file changed here.
    let p = due();
    let report = cycle_with_at(&p, 85, &|| p.file("notes.md", "edited meanwhile\n"));
    not_put_back(&p, &report);

    // The file is gone here: an agent removed it while the cycle ran.
    let p = due();
    let report = cycle_with_at(&p, 85, &|| {
        std::fs::remove_file(p.mem.join("notes.md")).unwrap()
    });
    not_put_back(&p, &report);

    // The index's entry changed in the channel, between the cycle's read
    // and the hold.
    let p = due();
    let theirs = format!("{OTHER_LINE}- [More](more.md) more\n");
    let before_hold = || p.other_writes(INDEX, Some(&theirs));
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        },
    );
    not_put_back(&p, &report);
    assert_eq!(p.held(INDEX).as_deref(), Some(theirs.as_str()));

    // The file's entry changed in the channel there.
    let p = due();
    let before_hold = || p.other_writes("notes.md", Some("three\n"));
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        },
    );
    not_put_back(&p, &report);

    // The settings changed there.
    let p = due();
    let before_hold = || p.st.sync_control.changed(&p.st.db.lock().unwrap());
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        },
    );
    not_put_back(&p, &report);

    // With nothing in the way, the line goes back at that same look.
    let p = due();
    assert_eq!(cycle_at(&p, 85).published, 1);
}

/// An agent writes the index while its new text is being flushed: its
/// write is not overwritten, and the next cycle merges it.
#[test]
fn an_index_written_while_its_lines_are_put_back_is_merged() {
    let p = back_unlisted();
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    let agent = format!("{OTHER_LINE}- [Agent](agent.md) written meanwhile\n");
    let flushed = |name: &str| {
        if name == INDEX {
            p.file(INDEX, &agent);
        }
    };
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            flushed: &flushed,
            ..Hooks::NONE
        },
    );
    // Published, and the file is the agent's.
    assert_eq!(report.published, 1, "{report:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(agent.as_str()));
    assert_eq!(p.held(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));
    // The next cycle merges the two.
    let report = cycle_at(&p, 90);
    assert_eq!(report.published, 1, "{report:?}");
    let merged = p.read(INDEX).unwrap();
    assert!(
        merged.contains("[Agent](agent.md)") && merged.contains(NOTES.trim_end()),
        "{merged}"
    );
}

/// The channel's text is in a put-back byte for byte, with the lines
/// after it: an index with no line break at its end gets one before the
/// first line, an empty one gets none, and one whose lines end in
/// carriage returns keeps them.
#[test]
fn a_put_back_is_the_channels_text_with_lines_after_it() {
    for (index, expected) in [
        (
            "- [Other](other.md) x",
            format!("- [Other](other.md) x\n{NOTES}"),
        ),
        ("", NOTES.to_string()),
        (
            "# Memory\r\n- [Other](other.md) x\r\n",
            format!("# Memory\r\n- [Other](other.md) x\r\n{NOTES}"),
        ),
        ("\n\n", format!("\n\n{NOTES}")),
    ] {
        let p = listed();
        std::fs::remove_file(p.mem.join("notes.md")).unwrap();
        p.file(INDEX, index);
        assert_eq!(cycle_at(&p, 10).published, 2, "{index:?}");
        comes_back_to(&p, 20, index);
        assert_eq!(a_minute_from(&p, 25).published, 1, "{index:?}");
        assert_eq!(p.read(INDEX).unwrap(), expected, "{index:?}");
        assert_eq!(p.held(INDEX).unwrap(), expected, "{index:?}");
    }
}

/// As [`comes_back`], for an index that is `index` after the delete.
fn comes_back_to(p: &Pair, t: i64, index: &str) {
    p.other_writes("notes.md", Some("two\n"));
    let report = cycle_at(p, t);
    assert_eq!((report.pulled, report.published), (1, 0), "{report:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(index));
}

/// Two memories deleted with their lines, both back: their lines go back
/// in one publish, in the order of their files' names. Where one is due
/// and the other is not, the one goes back alone. Where both are due and
/// one's file has changed here before the second look, nothing is
/// published in that cycle.
#[test]
fn the_lines_that_are_due_go_back_in_one_publish() {
    let both_deleted = || {
        let p = listed();
        std::fs::remove_file(p.mem.join("notes.md")).unwrap();
        std::fs::remove_file(p.mem.join("other.md")).unwrap();
        p.file(INDEX, "# Memory\n");
        assert_eq!(cycle_at(&p, 10).published, 3);
        assert_eq!(records(&p).len(), 2);
        p
    };
    // Both back in one cycle: one publish, `notes.md` before `other.md`.
    let p = both_deleted();
    p.other_writes("notes.md", Some("two\n"));
    p.other_writes("other.md", Some("y\n"));
    assert_eq!(cycle_at(&p, 20).pulled, 2);
    let last = a_minute_from(&p, 25);
    assert_eq!(last.published, 1, "{last:?}");
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("# Memory\n{NOTES}{OTHER_LINE}")
    );
    assert_eq!(records(&p).iter().map(|r| r.2).collect::<Vec<_>>(), [1, 1]);

    // One back, the other still deleted: the one goes back alone.
    let p = both_deleted();
    p.other_writes("other.md", Some("y\n"));
    assert_eq!(cycle_at(&p, 20).pulled, 1);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("# Memory\n{OTHER_LINE}"));

    // One back half a minute after the other: the first goes back at its
    // minute, which is an action on the index, and the second a minute
    // of looks after that.
    let p = both_deleted();
    p.other_writes("notes.md", Some("two\n"));
    assert_eq!(cycle_at(&p, 20).pulled, 1);
    for look in 1..6 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    p.other_writes("other.md", Some("y\n"));
    assert_eq!(cycle_at(&p, 50).pulled, 1);
    for look in 1..7 {
        assert_eq!(cycle_at(&p, 50 + 5 * look).published, 0);
    }
    assert_eq!(cycle_at(&p, 85).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("# Memory\n{NOTES}"));
    assert_eq!(a_minute_from(&p, 90).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("# Memory\n{NOTES}{OTHER_LINE}")
    );

    // Both due, and one's file changes here before the second look:
    // nothing is published in that cycle.
    let p = both_deleted();
    p.other_writes("notes.md", Some("two\n"));
    p.other_writes("other.md", Some("y\n"));
    assert_eq!(cycle_at(&p, 20).pulled, 2);
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    let report = cycle_with_at(&p, 85, &|| p.file("other.md", "edited meanwhile\n"));
    assert_eq!(report.published, 0, "{report:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some("# Memory\n"));
}

/// A line that is put back and taken out again is put back again, up to
/// three times, and then no more: the record goes.
#[test]
fn a_line_is_put_back_three_times_and_no_more() {
    let p = back_unlisted();
    let mut t = 25;
    for time in 1..=3 {
        assert_eq!(a_minute_from(&p, t).published, 1, "time {time}");
        t += 65;
        assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));
        let count: Vec<u32> = records(&p).iter().map(|r| r.2).collect();
        assert_eq!(
            count,
            if time < 3 { vec![time] } else { vec![] },
            "time {time}"
        );
        // Another device's index, without the line, overtakes it within
        // the minute.
        p.other_writes(INDEX, Some(OTHER_LINE));
        assert_eq!(cycle_at(&p, t).pulled, 1);
        t += 5;
    }
    let last = a_minute_from(&p, t);
    assert_eq!(last.published, 0, "{last:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    assert_eq!(rows(&p), []);
}

/// An index that is too large to take the line back: nothing is
/// published, the record goes, and nothing is tried at the next cycle.
/// The same where it would fit only by saying less of what it was
/// written after.
#[test]
fn a_line_that_does_not_fit_is_not_put_back() {
    let limit = cordelia_core::protocol::MAX_ITEM_BYTES;
    // An index that fills an entry to within a few bytes, with no line
    // for the memory. (Each byte of it is one byte in the entry.) With 4
    // bytes of room the line does not fit. With 100 the line would, and
    // what the entry says it was written after would not go in with it.
    for short_by in [4, 100] {
        let p = listed();
        std::fs::remove_file(p.mem.join("notes.md")).unwrap();
        let mut index = OTHER_LINE.to_string();
        // Fill it until an entry with nothing said of what it was written
        // after would be `short_by` bytes under the limit.
        let fits = |text: &str| {
            entries::fits(
                INDEX,
                &Value::String(format!("{text}{}", "x".repeat(short_by))),
            )
        };
        let mut filler = limit;
        while filler > 0 {
            let candidate = format!("{index}{}\n", "y".repeat(filler));
            if fits(&candidate) {
                index = candidate;
            }
            filler /= 2;
        }
        p.file(INDEX, &index);
        let report = cycle_at(&p, 10);
        assert_eq!(report.published, 2, "{report:?}");
        comes_back_to(&p, 20, &index);
        let last = a_minute_from(&p, 25);
        assert_eq!(last.published, 0, "short by {short_by}: {last:?}");
        assert!(last.failed.is_empty() && last.error.is_none(), "{last:?}");
        assert_eq!(p.read(INDEX).unwrap(), index);
        assert_eq!(rows(&p), [], "short by {short_by}");
        // Nothing is tried again.
        assert_eq!(a_minute_from(&p, 90).published, 0);
    }
}

/// A new device of the same person in the pair's channel.
fn third(p: &Pair) -> AppState {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = p.mem.parent().unwrap().join(format!("third-{n}"));
    another_device(&p.st, &dir, &p.channel)
}

/// The hash by which a tie is decided, of the entry `id` as `st` holds it.
fn hash_of(st: &AppState, channel: &str, id: &str) -> Vec<u8> {
    let it = held(st, channel).into_iter().find(|it| it.item_id == id);
    it.unwrap().content_hash
}

/// Another device's version of `name`, with `text`, comes to stand beside
/// the channel's on this device: an entry at the channel's revision that
/// loses the tie. Returns that device.
fn stands_beside(p: &Pair, name: &str, text: &str) -> AppState {
    stands_beside_as(p, name, text, false)
}

/// [`stands_beside`], as a delete if `deleted`: one that carries `text`,
/// which no device that follows the code writes.
fn stands_beside_as(p: &Pair, name: &str, text: &str, deleted: bool) -> AppState {
    let (current, rev, _) = version(&p.st, &p.channel, name).unwrap();
    let counts = hash_of(&p.st, &p.channel, &current);
    loop {
        let device = third(p);
        let id = entry_at(&device, &p.channel, name, text, rev, deleted);
        if hash_of(&device, &p.channel, &id) < counts {
            deliver(&device, &p.st, &p.channel);
            assert_eq!(version(&p.st, &p.channel, name).unwrap().0, current);
            return device;
        }
    }
}

const EXTRA: &str = "- [Extra](extra.md) listed on another device\n";

/// A put-back overtakes every version of the index that stands beside the
/// channel's, so it takes their lines with it: each line that the text so
/// far lacks, after the channel's text and before the record's own line.
/// A version that has a line for the file, in whatever words, supplies
/// it, and the record's line is not added. A line for a file that is
/// deleted in the channel is not taken.
#[test]
fn a_put_back_takes_the_lines_of_the_versions_beside() {
    // A line that the channel's version lacks, and none for the file.
    let p = back_unlisted();
    // (With a blank line in it, which is no line to take.)
    stands_beside(&p, INDEX, &format!("{OTHER_LINE}\n{EXTRA}"));
    // The version has just come to stand there: the minute starts again.
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0, "look {look}");
    }
    assert_eq!(cycle_at(&p, 85).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("{OTHER_LINE}{EXTRA}{NOTES}")
    );
    assert_eq!(records(&p)[0].2, 1);

    // A version that comes to stand beside in the middle of a line's
    // minute starts the minute again.
    let p = back_unlisted();
    for look in 1..7 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    stands_beside(&p, INDEX, &format!("{OTHER_LINE}{EXTRA}"));
    for look in 7..19 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0, "look {look}");
    }
    assert_eq!(cycle_at(&p, 115).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("{OTHER_LINE}{EXTRA}{NOTES}")
    );

    // A line for the file in other words: that line goes in, and the
    // record's own does not. The record is counted all the same.
    let p = back_unlisted();
    let theirs = "- [Notes, renamed](notes.md) as the other device has it\n";
    stands_beside(&p, INDEX, &format!("{theirs}{OTHER_LINE}"));
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{theirs}"));
    assert_eq!(records(&p)[0].2, 1);

    // Two versions beside: their lines in the order of their writers'
    // keys, a line that both have once. Each has a line for the file,
    // and both are taken: the record counts one.
    let p = back_unlisted();
    let (first, second) = (
        "- [Notes, one](notes.md) on one device\n",
        "- [Notes, two](notes.md) on another\n",
    );
    let one = stands_beside(&p, INDEX, &format!("{first}{EXTRA}"));
    let two = stands_beside(&p, INDEX, &format!("{EXTRA}{second}"));
    assert_eq!(a_minute_from(&p, 25).published, 1);
    let (lower, higher) = match one.identity.public_key() < two.identity.public_key() {
        true => (format!("{first}{EXTRA}"), second.to_string()),
        false => (format!("{EXTRA}{second}"), first.to_string()),
    };
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("{OTHER_LINE}{lower}{higher}")
    );
    assert_eq!(records(&p)[0].2, 1);

    // A line that the text has is the same line with space at its end,
    // and a line that is taken is taken without it.
    let p = back_unlisted();
    let spaced = format!("{}  \n{}\t\n", OTHER_LINE.trim_end(), EXTRA.trim_end());
    stands_beside(&p, INDEX, &spaced);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("{OTHER_LINE}{EXTRA}{NOTES}")
    );

    // What stands beside as a delete has no lines, whatever it carries.
    let p = back_unlisted();
    stands_beside_as(&p, INDEX, &format!("{OTHER_LINE}{EXTRA}"), true);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));

    // A line of a version beside for a file that is deleted in the
    // channel is not taken; one for a file that is there is.
    let p = listed();
    p.other_writes("gone.md", Some("g\n"));
    p.other_writes("gone.md", None);
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    stands_beside(
        &p,
        INDEX,
        &format!("- [Gone](gone.md) deleted since\n{EXTRA}"),
    );
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("{OTHER_LINE}{EXTRA}{NOTES}")
    );

    // The same for a file whose delete arrives between the cycle's read
    // and the hold.
    let p = listed();
    p.other_writes("extra.md", Some("e\n"));
    assert_eq!(cycle_at(&p, 5).pulled, 1);
    deletes_with_its_line(&p, 10);
    comes_back(&p, 20);
    stands_beside(&p, INDEX, &format!("{OTHER_LINE}{EXTRA}"));
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    let before_hold = || p.other_writes("extra.md", None);
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        },
    );
    assert_eq!(report.published, 1, "{report:?}");
    assert_eq!(p.held(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));

    // A version that comes to stand beside between the cycle's read and
    // the hold: nothing is published in that cycle.
    let p = back_unlisted();
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    let before_hold = || {
        stands_beside(&p, INDEX, &format!("{OTHER_LINE}{EXTRA}"));
    };
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        },
    );
    assert_eq!(report.published, 0, "{report:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    assert_eq!(a_minute_from(&p, 90).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("{OTHER_LINE}{EXTRA}{NOTES}")
    );
}

/// The other device moves to a new key, which this one has not got yet.
/// Returns what gives this device the key.
fn other_moves_to_a_new_key(p: &Pair) -> impl Fn(&AppState) + '_ {
    use cordelia_storage::psk;
    let key = [7u8; 32];
    let other = p.other.identity.public_key();
    let now_at = move |st: &AppState| {
        psk::rotate_psk(&st.home_dir, &p.channel, &key, "2026-10-04T00:00:00Z").unwrap();
        let db = st.db.lock().unwrap();
        let hash = cordelia_crypto::sha256(&key);
        channels::set_state(&db, &p.channel, 2, &other, 2, &hash).unwrap();
    };
    now_at(&p.other);
    now_at
}

/// An entry of the index that this device cannot read (it waits for a
/// key) is passed over when the channel's version is worked out, and may
/// be above it. While the index's slot holds one, by a device that
/// counts, at the revision the cycle read or above it, nothing is put
/// back and the minute does not run. Once the key comes, the entry is
/// taken as it would have been.
#[test]
fn nothing_is_put_back_over_an_entry_that_cannot_be_read() {
    let theirs = format!("{OTHER_LINE}- [Theirs](theirs.md) under the new key\n");

    // Above the entry this device reads.
    let p = back_unlisted();
    let key_comes = other_moves_to_a_new_key(&p);
    p.other_writes(INDEX, Some(&theirs));
    assert_eq!(p.held(INDEX).as_deref(), Some(OTHER_LINE), "passed over");
    // The look finds neither, so nothing is tried: no put-back comes as
    // far as its hold, in any cycle.
    let tried = std::cell::Cell::new(0);
    let before_hold = || tried.set(tried.get() + 1);
    for look in 1..40 {
        let hooks = Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        };
        let report = hooked_at(&p, 20 + 5 * look, &hooks);
        assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");
    }
    assert_eq!(tried.get(), 0);
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    // The key comes: the entry is taken, with nothing put back over it,
    // and the minute starts from there.
    key_comes(&p.st);
    let report = cycle_at(&p, 220);
    assert_eq!((report.published, report.pulled), (0, 1), "{report:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(theirs.as_str()));
    assert_eq!(a_minute_from(&p, 225).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{theirs}{NOTES}"));

    // It arrives between the cycle's read and the hold, at the look at
    // which the line would go back: nothing is published.
    let p = back_unlisted();
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    let before_hold = || {
        let _key_comes = other_moves_to_a_new_key(&p);
        p.other_writes(INDEX, Some(&theirs));
    };
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        },
    );
    assert_eq!(report.published, 0, "{report:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    assert_eq!(a_minute_from(&p, 90).published, 0);

    // Below the revision this device reads: the line goes back. (The
    // other device's first entry for the index, at revision 1, under the
    // new key: this device reads its own, at 2.)
    let p = back_unlisted();
    let _key_comes = other_moves_to_a_new_key(&p);
    entry_at(&p.other, &p.channel, INDEX, &theirs, 1, false);
    deliver(&p.other, &p.st, &p.channel);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));

    // By a device that does not count (it is no member here): the line
    // goes back.
    let p = back_unlisted();
    let stranger = third(&p);
    {
        let db = p.st.db.lock().unwrap();
        let key = stranger.identity.public_key();
        channels::remove_member(&db, &p.channel, &key).unwrap();
    }
    cordelia_storage::psk::rotate_psk(
        &stranger.home_dir,
        &p.channel,
        &[9u8; 32],
        "2026-10-04T00:00:00Z",
    )
    .unwrap();
    entry_at(&stranger, &p.channel, INDEX, &theirs, 7, false);
    deliver(&stranger, &p.st, &p.channel);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));
}

/// An entry of the index's slot that a key this device holds opens, and
/// that is not an entry's content, is not one that cannot be read: it
/// counts for nothing, and the line goes back.
#[test]
fn an_entry_that_opens_and_is_no_entry_holds_nothing_back() {
    use cordelia_crypto::signing::ItemMetadata;
    use cordelia_crypto::slots::{item_aad, slot_id};
    use cordelia_storage::{items, psk};
    let p = back_unlisted();
    // By the other device, which counts, above the entry this device
    // reads, sealed under the key both hold: bytes that are no JSON.
    let st = &p.other;
    let author = st.identity.public_key();
    let slot = slot_id(
        &psk::read_slot_key(&st.home_dir, &p.channel).unwrap(),
        INDEX,
    );
    let rev = 9;
    let blob = cordelia_crypto::item_encrypt(
        &psk::read_psk(&st.home_dir, &p.channel).unwrap(),
        b"not an entry",
        &item_aad(&p.channel, Some(&slot), Some(rev)),
    )
    .unwrap();
    let content_hash = cordelia_crypto::sha256(&blob);
    {
        let db = st.db.lock().unwrap();
        let key_version = channels::get_by_id(&db, &p.channel).unwrap().key_version;
        let item_id = items::generate_item_id();
        let published_at = chrono::Utc::now().to_rfc3339();
        let signed = ItemMetadata {
            author_id: &author,
            channel_id: &p.channel,
            content_hash: &content_hash,
            is_tombstone: false,
            item_id: &item_id,
            key_version,
            published_at: &published_at,
            slot: Some(&slot),
            rev: Some(rev),
        }
        .encode()
        .unwrap();
        let stored = items::insert_item(
            &db,
            &items::NewItem {
                item_id: &item_id,
                channel_id: &p.channel,
                author_id: &author,
                item_type: ITEM_TYPE,
                published_at: &published_at,
                parent_id: None,
                key_version,
                content_hash: &content_hash,
                signature: &st.identity.sign(&signed),
                encrypted_blob: &blob,
                is_tombstone: false,
                slot: Some(&slot),
                rev: Some(rev),
            },
        )
        .unwrap();
        assert!(stored);
    }
    deliver(&p.other, &p.st, &p.channel);
    assert_eq!(p.held(INDEX).as_deref(), Some(OTHER_LINE));
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));
    // Above the entry that counts for nothing.
    assert_eq!(version(&p.st, &p.channel, INDEX).unwrap().1, rev + 1);
}
