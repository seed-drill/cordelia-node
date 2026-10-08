//! The index line of a memory that comes back (`claude::lines`): what a
//! cycle writes down, the minute of looking, the put-back and what stops
//! it, and when a record goes.

use super::*;
use crate::memory_md::INDEX_FILE as INDEX;
use cordelia_api::publish::Kind;
use cordelia_crypto::entry::EntryError;
use cordelia_crypto::version::Version;
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
/// The line of the memory that stays. Its words are chosen for the hash
/// of an index that is this line alone, which is above that of every
/// text these tests put beside such an index: a tie at one revision goes
/// to the higher hash of the text (decision 2026-10-04 §2.3), so each of
/// those loses it. [`stands_beside`] says where one does not.
const OTHER_LINE: &str = "- [Others](other.md) something else\n";

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
    p.file(INDEX, "# Memory\n");
    let report = cycle_with_at(&p, 70, &|| {
        p.other_writes(INDEX, Some("# Memory\n- [D](d.md)\n"))
    });
    assert_eq!(report.published, 0, "{report:?}");
    assert_eq!(rows(&p).len(), 2);

    // The index's own delete is written down for no file. (The cycle at
    // 75 merges the edit that was not published with what arrived, which
    // comes to what arrived: the folder and the channel agree an index
    // again.)
    let report = cycle_at(&p, 75);
    assert_eq!((report.published, report.pulled), (0, 1), "{report:?}");
    let agreed = p.held(INDEX);
    assert_eq!(agreed, p.read(INDEX));
    std::fs::remove_file(p.mem.join(INDEX)).unwrap();
    let report = cycle_at(&p, 80);
    assert_eq!(report.published, 1, "{report:?}");
    // (What the channel holds for the index is a delete.)
    assert_eq!(p.held(INDEX), None);
    assert!(is_deleted(&p, INDEX), "the delete was published");
    assert_eq!(p.read(INDEX), None);
    assert!(rows(&p).iter().all(|(file, ..)| file != INDEX));
    assert_eq!(rows(&p).len(), 2);
}

/// Whether the channel's version of `name`, as this device holds it, is a
/// delete.
fn is_deleted(p: &Pair, name: &str) -> bool {
    let db = p.st.db.lock().unwrap();
    let slot = publish::read(&db, NAME, name).unwrap().slot;
    slot.current
        .is_some_and(|version| version.value == Value::Delete)
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
/// read them. The index's version with one entry more held of it is not
/// what the cycle read either. The next looks decide again.
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

    // The index's version is held in one entry more there: another device
    // wrote the same index apart, at the same revision. It is the same
    // text, and it is not what the cycle read: a version is planned
    // against with every entry held of it (decision 2026-10-04 §2.3). The
    // next look decides again, and the line goes back.
    let p = due();
    let before_hold = || {
        let device = third(&p);
        entry_at(&device, NAME, INDEX, text(OTHER_LINE), 2, Some(Vec::new()));
        deliver(&device, &p.st, NAME);
    };
    let (read, ..) = version(&p.st, NAME, INDEX).unwrap();
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        },
    );
    not_put_back(&p, &report);
    let (now, rev, same) = version(&p.st, NAME, INDEX).unwrap();
    assert_eq!((rev, same.as_str()), (2, OTHER_LINE));
    assert_ne!(now, read);
    assert_eq!(cycle_at(&p, 90).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));

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
    // Both back in one cycle, where the index had listed them the other
    // way round, and the records were made that way round too: one
    // publish, `notes.md` before `other.md`, by their files' names.
    let p = Pair::new();
    p.file("notes.md", "one\n");
    p.file("other.md", "x\n");
    p.file(INDEX, &format!("{OTHER_LINE}{NOTES}"));
    assert_eq!(cycle_at(&p, 0).published, 3);
    p.file(INDEX, NOTES);
    std::fs::remove_file(p.mem.join("other.md")).unwrap();
    assert_eq!(cycle_at(&p, 5).published, 2);
    p.file(INDEX, "# Memory\n");
    std::fs::remove_file(p.mem.join("notes.md")).unwrap();
    assert_eq!(cycle_at(&p, 10).published, 2);
    p.other_writes("notes.md", Some("two\n"));
    p.other_writes("other.md", Some("y\n"));
    assert_eq!(cycle_at(&p, 20).pulled, 2);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("# Memory\n{NOTES}{OTHER_LINE}")
    );

    // Both back in one cycle: one publish.
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
/// published, the record goes, and nothing is tried at the next cycle. A
/// text and its name may be 60 KB together, and room for what an entry
/// says is kept in every entry (decision 2026-10-04 §2.3): an index that
/// fits with the line to the last byte takes it back, in an entry that
/// says all that it was written after.
#[test]
fn a_line_that_does_not_fit_is_not_put_back() {
    let bound = cordelia_core::protocol::MAX_ENTRY_NAME_AND_VALUE_BYTES;
    // An index with no line for the memory, which is `over` bytes over
    // the bound with its name once the line is after it.
    for over in [1, 0] {
        let p = listed();
        std::fs::remove_file(p.mem.join("notes.md")).unwrap();
        let filled = bound + over - INDEX.len() - NOTES.len() - OTHER_LINE.len() - 1;
        let index = format!("{OTHER_LINE}{}\n", "y".repeat(filled));
        assert_eq!(INDEX.len() + index.len() + NOTES.len(), bound + over);
        p.file(INDEX, &index);
        let report = cycle_at(&p, 10);
        assert_eq!(report.published, 2, "{report:?}");
        comes_back_to(&p, 20, &index);
        let last = a_minute_from(&p, 25);
        assert!(last.failed.is_empty() && last.error.is_none(), "{last:?}");
        if over > 0 {
            assert_eq!(last.published, 0, "{last:?}");
            assert_eq!(p.read(INDEX).unwrap(), index);
            assert_eq!(p.held(INDEX).unwrap(), index);
            assert_eq!(rows(&p), []);
            // Nothing is tried again.
            assert_eq!(a_minute_from(&p, 90).published, 0);
            continue;
        }
        // At the bound: the line goes back, and the entry says what it
        // was written over, and what that was written over.
        assert_eq!(last.published, 1, "{last:?}");
        let back = format!("{index}{NOTES}");
        assert_eq!(p.read(INDEX).unwrap(), back);
        assert_eq!(p.held(INDEX).unwrap(), back);
        assert_eq!(
            records(&p),
            [("notes.md".into(), NOTES.trim_end().into(), 1)]
        );
        let first = format!("{NOTES}{OTHER_LINE}");
        assert_eq!(
            said(&p.st, NAME, INDEX),
            Some(vec![link(Some(&index), &p.st), link(Some(&first), &p.st)])
        );
    }
}

/// A new device of the same person, which holds the pair's name: this
/// device adds it, as it added the other.
fn third(p: &Pair) -> AppState {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = p.mem.parent().unwrap().join(format!("third-{n}"));
    another_device(&p.st, &dir, NAME)
}

/// The versions that stand beside the channel's version of `name` on this
/// device: those that lost the tie at its revision.
fn lost(p: &Pair, name: &str) -> Vec<Version> {
    let db = p.st.db.lock().unwrap();
    publish::read(&db, NAME, name).unwrap().slot.lost
}

/// Another device's version of `name`, with `text`, comes to stand beside
/// the channel's on this device: an entry at the channel's revision that
/// loses the tie. A tie goes to the higher hash of the text, so `text` is
/// one whose hash is the lower. Returns that device.
fn stands_beside(p: &Pair, name: &str, text: &str) -> AppState {
    stands_beside_as(p, name, Value::Text(text.into()))
}

/// [`stands_beside`], for any value: a delete loses to every text, and
/// bytes that are no text rank by their hash, as a text does.
fn stands_beside_as(p: &Pair, name: &str, value: Value) -> AppState {
    let (current, rev, _) = version(&p.st, NAME, name).unwrap();
    let entries = |lost: &[Version]| lost.iter().map(|v| v.entries.len()).sum::<usize>();
    let before = entries(&lost(p, name));
    let device = third(p);
    entry_at(&device, NAME, name, value.clone(), rev, Some(Vec::new()));
    deliver(&device, &p.st, NAME);
    assert_eq!(
        version(&p.st, NAME, name).unwrap().0,
        current,
        "it won the tie: choose a text whose hash is the lower"
    );
    let now = lost(p, name);
    assert_eq!(entries(&now), before + 1);
    assert!(now.iter().any(|version| version.value == value));
    device
}

/// Another device's version of `name`, with `text`, takes the place of
/// the channel's on this device at a tie: an entry at the channel's
/// revision that wins it, the hash of `text` being the higher. What was
/// the channel's version then stands beside. Returns that device.
fn overtakes_at_a_tie(p: &Pair, name: &str, text: &str) -> AppState {
    let (_, rev, was) = version(&p.st, NAME, name).unwrap();
    let device = third(p);
    let value = Value::Text(text.into());
    entry_at(&device, NAME, name, value, rev, Some(Vec::new()));
    deliver(&device, &p.st, NAME);
    let (_, at, now) = version(&p.st, NAME, name).unwrap();
    assert_eq!(
        (at, now.as_str()),
        (rev, text),
        "it lost the tie: choose a text whose hash is the higher"
    );
    let was = Value::Text(was);
    assert!(lost(p, name).iter().any(|version| version.value == was));
    device
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
    let (first, second) = (
        "- [Notes, one](notes.md) on one device\n",
        "- [Notes, two](notes.md) on another\n",
    );
    // (Made until the slot gives the two in another order than that of
    // their writers' keys: it gives them by the hashes of their texts.
    // The order of the lines is then the rule's doing, and not the order
    // in which the two happen to be given.)
    let (p, one, two) = loop {
        let p = back_unlisted();
        let one = stands_beside(&p, INDEX, &format!("{first}{EXTRA}"));
        let two = stands_beside(&p, INDEX, &format!("{EXTRA}{second}"));
        let held: Vec<[u8; 32]> = lost(&p, INDEX)
            .iter()
            .map(|version| version.entries[0].author)
            .collect();
        assert_eq!(held.len(), 2);
        if held[0] > held[1] {
            break (p, one, two);
        }
    };
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

    // What stands beside as a delete has no lines, and nor has what is
    // no text, whatever bytes it holds.
    let p = back_unlisted();
    stands_beside_as(&p, INDEX, Value::Delete);
    let bytes = format!("{OTHER_LINE}{EXTRA}").into_bytes();
    stands_beside_as(&p, INDEX, Value::Other(bytes));
    assert_eq!(lost(&p, INDEX).len(), 2);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));

    // This device's own older version beside: its lines are taken like
    // any. It listed a memory that another device then deleted; a third
    // device's index, without that line, won the tie at its revision;
    // this device's merge was that index as it stood, so nothing was
    // published and its own version went on standing beside. The memory
    // has come back since, and its line is in that version alone.
    let p = Pair::new();
    p.file("notes.md", "one\n");
    p.file("other.md", "x\n");
    p.file("extra.md", "e\n");
    p.file(INDEX, &format!("{NOTES}{OTHER_LINE}{EXTRA}"));
    assert_eq!(cycle_at(&p, 0).published, 4);
    p.other_writes("extra.md", None);
    assert_eq!(cycle_at(&p, 5).pulled, 1);
    std::fs::remove_file(p.mem.join("notes.md")).unwrap();
    p.file(INDEX, &format!("{OTHER_LINE}{EXTRA}"));
    assert_eq!(cycle_at(&p, 10).published, 2);
    let PlannedAgainst::Version { entries: mine, .. } = version(&p.st, NAME, INDEX).unwrap().0
    else {
        panic!("the index has a version");
    };
    overtakes_at_a_tie(&p, INDEX, OTHER_LINE);
    let report = cycle_at(&p, 15);
    assert_eq!((report.published, report.conflicts), (0, 0), "{report:?}");
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    let beside: Vec<Vec<[u8; 32]>> = lost(&p, INDEX)
        .iter()
        .map(|version| version.entries.iter().map(|entry| entry.id).collect())
        .collect();
    assert_eq!(beside, [mine], "this device's own version stands beside");
    p.other_writes("notes.md", Some("two\n"));
    p.other_writes("extra.md", Some("again\n"));
    assert_eq!(cycle_at(&p, 20).pulled, 2);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("{OTHER_LINE}{EXTRA}{NOTES}")
    );

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

/// Two devices that wrote one text apart, at one revision, made one
/// version, whoever signed its entries (decision 2026-10-04 §2.3). Where
/// it stands beside the index's, its lines are taken once. And it is
/// another thing to stand there once a second entry of it arrives: the
/// minute starts again, and a put-back under whose hold it arrives is not
/// made.
#[test]
fn a_version_beside_that_two_devices_wrote_is_one_version() {
    let beside = format!("{OTHER_LINE}{EXTRA}");
    // The entries held of the versions beside the index's, for each.
    let held = |p: &Pair| -> Vec<usize> {
        let lost = lost(p, INDEX);
        lost.iter().map(|version| version.entries.len()).collect()
    };

    // The second entry arrives in the middle of the line's minute.
    let p = back_unlisted();
    stands_beside(&p, INDEX, &beside);
    for look in 1..7 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    stands_beside(&p, INDEX, &beside);
    assert_eq!(held(&p), [2]);
    for look in 7..19 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0, "look {look}");
    }
    assert_eq!(cycle_at(&p, 115).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("{OTHER_LINE}{EXTRA}{NOTES}")
    );

    // It arrives between the cycle's read and the hold, at the look at
    // which the line would go back: nothing is published in that cycle.
    let p = back_unlisted();
    stands_beside(&p, INDEX, &beside);
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    let before_hold = || {
        stands_beside(&p, INDEX, &beside);
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
    assert_eq!(held(&p), [2]);
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    assert_eq!(a_minute_from(&p, 90).published, 1);
    assert_eq!(
        p.read(INDEX).unwrap(),
        format!("{OTHER_LINE}{EXTRA}{NOTES}")
    );
}

/// This device of the pair is given `entry`, as from a relay, and stores
/// it.
fn arrives(p: &Pair, entry: &CheckedEntry) {
    let db = p.st.db.lock().unwrap();
    let taken = take::take(&db, &p.st.identity, entry, now()).unwrap();
    let stored = stored::Outcome::Stored;
    assert!(
        matches!(taken, take::Taken::Own { stored: s, .. } if s == stored),
        "{taken:?}"
    );
}

/// The secret of the pair's channel, and the slot of `file` in it.
fn secret_and_slot(p: &Pair, file: &str) -> ([u8; 32], [u8; 32]) {
    let secret = name_secret(&p.st, NAME);
    let slot = cordelia_crypto::slots::slot_id(&derive::slot_key(&secret).unwrap(), file);
    (secret, slot)
}

/// An entry under `file`'s name in the pair's channel, at `rev`, that `by`
/// and the channel signed, and that is no version: its content was sealed
/// under another secret, and does not open.
fn does_not_open(p: &Pair, by: &AppState, file: &str, rev: u64) -> CheckedEntry {
    let (secret, slot) = secret_and_slot(p, file);
    let inside = Inside {
        name: file.into(),
        value: text("sealed elsewhere\n"),
        chain: Some(Vec::new()),
    };
    let elsewhere = Entry::seal(&[7u8; 32], &by.identity, rev, &inside).unwrap();
    let entry = signed_in(&secret, &by.identity, slot, rev, elsewhere.content);
    assert_eq!(entry.open(&secret), Err(EntryError::DidNotOpen));
    entry
}

/// The same, for one that the channel's secret opens and that is not an
/// entry's content: it says a name that is no text.
fn no_entry_at(p: &Pair, by: &AppState, file: &str, rev: u64) -> CheckedEntry {
    use cordelia_core::protocol::{
        ITEM_SEAL_OVERHEAD_BYTES, LABEL_ENTRY_CONTENT, MIN_ENTRY_CONTENT_BYTES,
    };
    let (secret, slot) = secret_and_slot(p, file);
    // What a content says, filled up to the smallest size, and sealed as
    // an entry's is: under the channel's entry key, and bound to the
    // channel, the slot and the revision.
    let mut said = vec![0, 8, 0xff, 0xfe];
    said.resize(MIN_ENTRY_CONTENT_BYTES - ITEM_SEAL_OVERHEAD_BYTES, 0);
    let channel = derive::channel_id(&secret).unwrap();
    let bound = [LABEL_ENTRY_CONTENT, &channel, &slot, &rev.to_be_bytes()].concat();
    let key = derive::entry_key(&secret).unwrap();
    let content = cordelia_crypto::item_encrypt(&key, &said, &bound).unwrap();
    let entry = signed_in(&secret, &by.identity, slot, rev, content);
    assert_eq!(entry.open(&secret), Err(EntryError::NotThisForm));
    entry
}

/// How many entries the slot of `file` holds, on this device of the pair,
/// that it cannot read: see [`publish::not_read`].
fn not_read(p: &Pair, file: &str) -> usize {
    publish::not_read(&p.st.db.lock().unwrap(), NAME, file).unwrap()
}

/// The ID, as it is written, of the channel that `st` holds for the
/// pair's name now: after a statement it is another than before.
fn channel_of(st: &AppState) -> String {
    let db = st.db.lock().unwrap();
    let id = held_rows::channel_of_name(&db, NAME).unwrap().unwrap();
    encode_channel_id(&id).unwrap()
}

/// An entry of the index that this device cannot read (it is no version:
/// here it does not open) is passed over when the channel's version is
/// worked out, and may be above it. While the index's slot holds one, by
/// a key that counts, at the revision the cycle read or above it, nothing
/// is put back and the minute does not run. It stands there until its
/// writer writes the index again, the index is edited here, or a
/// statement moves the name to a new channel.
#[test]
fn nothing_is_put_back_over_an_entry_that_cannot_be_read() {
    let theirs = format!("{OTHER_LINE}- [Theirs](theirs.md) written again\n");
    // The look finds neither, so nothing is tried: no put-back comes as
    // far as its hold, in any of the cycles before the `looks`th.
    let none_tried = |p: &Pair, looks: i64| {
        let tried = std::cell::Cell::new(0);
        let before_hold = || tried.set(tried.get() + 1);
        for look in 1..looks {
            let hooks = Hooks {
                before_hold: &before_hold,
                ..Hooks::NONE
            };
            let report = hooked_at(p, 20 + 5 * look, &hooks);
            assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");
        }
        assert_eq!(tried.get(), 0);
        assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    };

    // Above the entry this device reads.
    let p = back_unlisted();
    arrives(&p, &does_not_open(&p, &p.other, INDEX, 3));
    assert_eq!(p.held(INDEX).as_deref(), Some(OTHER_LINE), "passed over");
    assert_eq!(not_read(&p, INDEX), 1);
    none_tried(&p, 40);
    // Its writer writes the index again, above it: that entry has the
    // place of the one that could not be read. It is taken, with nothing
    // put back over it, and the minute starts from there.
    p.other_writes(INDEX, Some(&theirs));
    assert_eq!(not_read(&p, INDEX), 0);
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
    let before_hold = || arrives(&p, &does_not_open(&p, &p.other, INDEX, 3));
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

    // At the revision this device reads, and not above it (this device
    // reads its own entry, at 2): the same. It is beside the version that
    // this device reads, and is no version to stand there.
    let p = back_unlisted();
    arrives(&p, &does_not_open(&p, &p.other, INDEX, 2));
    assert_eq!(p.held(INDEX).as_deref(), Some(OTHER_LINE), "passed over");
    assert_eq!(lost(&p, INDEX), []);
    assert_eq!(not_read(&p, INDEX), 1);
    // Here too the look finds neither, and no put-back comes as far as
    // its hold.
    none_tried(&p, 20);

    // And arriving at that revision between the cycle's read and the
    // hold: nothing is published.
    let p = back_unlisted();
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    let before_hold = || arrives(&p, &does_not_open(&p, &p.other, INDEX, 2));
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

    // By any key that counts: here a third device's, which this device
    // added, above the entry read.
    let p = back_unlisted();
    let another = third(&p);
    arrives(&p, &does_not_open(&p, &another, INDEX, 3));
    assert_eq!(p.held(INDEX).as_deref(), Some(OTHER_LINE), "passed over");
    for look in 1..20 {
        let report = cycle_at(&p, 20 + 5 * look);
        assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");
    }

    // Below the revision this device reads: the line goes back. (The
    // other device's entry for the index is at revision 1: this device
    // reads its own, at 2.)
    let p = back_unlisted();
    arrives(&p, &does_not_open(&p, &p.other, INDEX, 1));
    assert_eq!(not_read(&p, INDEX), 0);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));

    // By a key that does not count: it is refused where it arrives. One
    // that the store holds all the same counts for nothing: the line goes
    // back, and at the revision above the index's version, which is not
    // above that entry.
    let p = back_unlisted();
    let stranger = state(&p.mem.parent().unwrap().join("stranger"));
    let entry = does_not_open(&p, &stranger, INDEX, 7);
    {
        let db = p.st.db.lock().unwrap();
        let taken = take::take(&db, &p.st.identity, &entry, now()).unwrap();
        let refused = take::Taken::Refused(take::NotTaken::SignerDoesNotCount);
        assert_eq!(taken, refused);
        let put = stored::store(&db, &entry, now()).unwrap();
        assert_eq!(put, stored::Outcome::Stored);
    }
    assert_eq!(not_read(&p, INDEX), 0);
    assert_eq!(a_minute_from(&p, 25).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));
    assert_eq!(version(&p.st, NAME, INDEX).unwrap().1, 3);

    // The device that wrote it is removed. This device applies the
    // statement, and carries what it holds into the name's new channel:
    // the index's version, and the memory as the removed device last
    // wrote it, but nothing of an entry that is no version. The folder's
    // records move with them, and the line goes back there.
    let mut p = back_unlisted();
    arrives(&p, &does_not_open(&p, &p.other, INDEX, 3));
    none_tried(&p, 20);
    removes(&p.st, &p.phrase, &p.other.identity.public_key());
    let left = std::mem::replace(&mut p.channel, channel_of(&p.st));
    assert_ne!(p.channel, left);
    assert_eq!(not_read(&p, INDEX), 0);
    assert_eq!(
        records(&p),
        [("notes.md".into(), NOTES.trim_end().into(), 0)]
    );
    // (The first cycle there notes that the memory's version is this
    // device's own entry now, which is an action on the file.)
    let report = cycle_at(&p, 120);
    assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");
    let last = a_minute_from(&p, 125);
    assert_eq!(last.published, 1, "{last:?}");
    assert!(last.conflict_files.is_empty(), "{last:?}");
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));
    assert_eq!(p.held(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));
    assert_eq!(p.read("notes.md").as_deref(), Some("two\n"));
}

/// The question is asked of the index's slot, and not of the file's. An
/// entry of the file's slot that this device cannot read, above a text by
/// another device, holds nothing back: the file looks at rest, and the
/// line goes back. Where its writer then writes the memory again, as a
/// delete, the file goes, and the line stays, pointing at no file: the
/// cost that the decision record states.
#[test]
fn an_entry_of_the_files_slot_that_cannot_be_read_holds_nothing_back() {
    let p = back_unlisted();
    // A third device, which the other device knows too, edits the memory,
    // and this one takes that.
    let third = third(&p);
    deliver(&p.st, &third, NAME);
    deliver(&p.st, &p.other, NAME);
    let (_, rev, _) = version(&p.st, NAME, "notes.md").unwrap();
    write(&third, NAME, "notes.md", text("three\n"));
    deliver(&third, &p.st, NAME);
    deliver(&third, &p.other, NAME);
    assert_eq!(version(&p.st, NAME, "notes.md").unwrap().1, rev + 1);
    assert_eq!(cycle_at(&p, 25).pulled, 1);
    assert_eq!(p.read("notes.md").as_deref(), Some("three\n"));

    // An entry of the other device's arrives above the third device's
    // text, and does not open. This device passes that over: it reads the
    // third device's text.
    arrives(&p, &does_not_open(&p, &p.other, "notes.md", rev + 2));
    assert_eq!(
        p.held("notes.md").as_deref(),
        Some("three\n"),
        "passed over"
    );
    assert_eq!((not_read(&p, "notes.md"), not_read(&p, INDEX)), (1, 0));
    assert_eq!(a_minute_from(&p, 30).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));

    // The other device writes the memory again, above that entry, as a
    // delete: the file goes, and the line that was put back stays.
    p.other_writes("notes.md", None);
    let (_, deleted_at, _) = version(&p.st, NAME, "notes.md").unwrap();
    assert_eq!(deleted_at, rev + 3);
    assert!(is_deleted(&p, "notes.md"));
    let report = cycle_at(&p, 95);
    assert_eq!(report.published, 0, "{report:?}");
    assert_eq!(p.read("notes.md"), None);
    assert_eq!(p.read(INDEX).unwrap(), format!("{OTHER_LINE}{NOTES}"));
}

/// One cycle of a memory folder of the other device's, at `dir`.
fn other_cycle(p: &Pair, dir: &Path) -> FolderReport {
    let generation = p.other.sync_control.generation();
    let channel = channel_of(&p.other);
    sync_folder(&p.other, dir, &channel, NAME, "ef01", generation).unwrap()
}

/// A put-back is published as any edit of the index is (decision
/// 2026-10-04 §7.3): its chain is that of an entry written over the
/// index's version, as the cycle read it, and the folder's record is of
/// that entry. So a device whose index is that version takes the put-back
/// with nothing kept beside it.
#[test]
fn a_put_back_is_an_edit_of_the_indexes_version() {
    let p = back_unlisted();
    // The other device has the folder too, and lists a memory more there.
    let theirs = p.mem.parent().unwrap().join("the other's memory");
    std::fs::create_dir_all(&theirs).unwrap();
    deliver(&p.st, &p.other, NAME);
    assert_eq!(other_cycle(&p, &theirs).pulled, 3);
    let longer = format!("{OTHER_LINE}- [More](more.md) more\n");
    std::fs::write(theirs.join(INDEX), &longer).unwrap();
    assert_eq!(other_cycle(&p, &theirs).published, 1);
    deliver(&p.other, &p.st, NAME);
    assert_eq!(cycle_at(&p, 25).pulled, 1);

    // A minute of looks later this device puts the line back, over the
    // other device's version of the index.
    assert_eq!(a_minute_from(&p, 30).published, 1);
    let back = format!("{longer}{NOTES}");
    let first = format!("{NOTES}{OTHER_LINE}");
    let chain = vec![
        link(Some(&longer), &p.other),
        link(Some(OTHER_LINE), &p.st),
        link(Some(&first), &p.st),
    ];
    assert_eq!(version(&p.st, NAME, INDEX).unwrap().1, 4);
    assert_eq!(said(&p.st, NAME, INDEX), Some(chain.clone()));
    let recorded = {
        let db = p.st.db.lock().unwrap();
        let folder = p.mem.display().to_string();
        let mut all = sync_state::load(&db, &folder, &p.channel).unwrap();
        all.remove(INDEX)
    };
    let agreed = Agreed {
        hash: Some(Content::new(back.as_str()).hash),
        rev: 4,
        signer: Some(p.st.identity.public_key()),
        chain: Some(chain),
    };
    assert_eq!(recorded, Some(agreed));

    // The other device's index is the version that the put-back was
    // written over: it takes the put-back, and keeps nothing beside it.
    deliver(&p.st, &p.other, NAME);
    let report = other_cycle(&p, &theirs);
    assert_eq!(
        (report.pulled, report.conflicts, report.published),
        (1, 0, 0),
        "{report:?}"
    );
    assert!(report.conflict_files.is_empty(), "{report:?}");
    assert_eq!(std::fs::read_to_string(theirs.join(INDEX)).unwrap(), back);
}

/// A device is removed by a statement, and what it wrote does not go with
/// it: a device that applies the statement carries each version it holds
/// into the name's new channel, as its own entry (decision 2026-10-04
/// §7.3), and the folder's records move there, those of index lines among
/// them (§4.2). So a memory that came back by the removed device's edit
/// stays back, and its line is put back in the new channel, a minute of
/// looks after the move, as an edit of the index's version as this device
/// carried it. It is so where this device makes the statement, and where
/// it is shown one that another device made.
#[test]
fn after_a_statement_the_line_goes_back_in_the_names_new_channel() {
    let mut p = back_unlisted();
    for look in 1..7 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    removes(&p.st, &p.phrase, &p.other.identity.public_key());
    let left = std::mem::replace(&mut p.channel, channel_of(&p.st));
    assert_ne!(p.channel, left);

    // What this device holds of the name is in the new channel, and is
    // all its own: among it the memory as the removed device wrote it, in
    // an entry that says first which key signed that.
    let me = p.st.identity.public_key();
    assert!(held(&p.st, NAME).iter().all(|entry| entry.author == me));
    let (_, rev, text) = version(&p.st, NAME, "notes.md").unwrap();
    assert_eq!((rev, text.as_str()), (3, "two\n"));
    let carried = said(&p.st, NAME, "notes.md").unwrap();
    assert_eq!(carried[0], link(Some("two\n"), &p.other));
    // The record of the memory deleted with its line has moved too.
    assert_eq!(
        records(&p),
        [("notes.md".into(), NOTES.trim_end().into(), 0)]
    );

    // The first cycle there changes no file and publishes nothing: it
    // notes that the memory's version is this device's own entry now. The
    // minute of looking begins again after it.
    let report = cycle_at(&p, 50);
    assert_eq!(
        (report.published, report.pulled, report.conflicts),
        (0, 0, 0),
        "{report:?}"
    );
    assert_eq!(p.read("notes.md").as_deref(), Some("two\n"));
    let last = a_minute_from(&p, 55);
    assert_eq!(last.published, 1, "{last:?}");
    assert!(last.conflict_files.is_empty(), "{last:?}");
    let back = format!("{OTHER_LINE}{NOTES}");
    assert_eq!(p.read(INDEX).unwrap(), back);
    assert_eq!(p.held(INDEX).unwrap(), back);
    // It is an edit of the index's version, which was this device's own
    // and was carried with its chain.
    let first = format!("{NOTES}{OTHER_LINE}");
    assert_eq!(version(&p.st, NAME, INDEX).unwrap().1, 3);
    assert_eq!(
        said(&p.st, NAME, INDEX),
        Some(vec![
            link(Some(OTHER_LINE), &p.st),
            link(Some(&first), &p.st)
        ])
    );
    assert_eq!(
        records(&p),
        [("notes.md".into(), NOTES.trim_end().into(), 1)]
    );

    // The same where this device is shown a statement that another
    // device made: here the other device removes a third. Each of the two
    // that stay has carried what it held, so the index's version is held
    // in two entries, which are one version, and the line goes back over
    // it.
    let mut p = back_unlisted();
    let third = third(&p);
    deliver(&p.st, &p.other, NAME);
    for look in 1..7 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    let change = removes(&p.other, &p.phrase, &third.identity.public_key());
    {
        let db = p.st.db.lock().unwrap();
        let shown = take::take(&db, &p.st.identity, &change, now()).unwrap();
        let applied = matches!(shown, take::Taken::Shown(person::Shown::Applied(_)));
        assert!(applied, "{shown:?}");
    }
    let left = std::mem::replace(&mut p.channel, channel_of(&p.st));
    assert_ne!(p.channel, left);
    deliver(&p.other, &p.st, NAME);
    let PlannedAgainst::Version { rev, entries, .. } = version(&p.st, NAME, INDEX).unwrap().0
    else {
        panic!("the index has a version");
    };
    assert_eq!((rev, entries.len()), (2, 2));
    assert_eq!(lost(&p, INDEX), []);
    assert_eq!(
        records(&p),
        [("notes.md".into(), NOTES.trim_end().into(), 0)]
    );
    let report = cycle_at(&p, 50);
    assert_eq!(
        (report.published, report.pulled, report.conflicts),
        (0, 0, 0),
        "{report:?}"
    );
    let last = a_minute_from(&p, 55);
    assert_eq!(last.published, 1, "{last:?}");
    assert!(last.conflict_files.is_empty(), "{last:?}");
    assert_eq!(p.read(INDEX).unwrap(), back);
    assert_eq!(p.held(INDEX).unwrap(), back);
    assert_eq!(p.read("notes.md").as_deref(), Some("two\n"));
    // It is written from this device's own entry of that version.
    assert_eq!(
        said(&p.st, NAME, INDEX),
        Some(vec![
            link(Some(OTHER_LINE), &p.st),
            link(Some(&first), &p.st)
        ])
    );
}

/// An entry of the index's slot that the channel's secret opens, and that
/// is not an entry's content, is no version (decision 2026-10-04 §2.3),
/// and so one that this device cannot read, as one that does not open is.
/// While it stands at the revision read or above it, nothing is put back.
/// Once the index is written above it, the line goes back.
#[test]
fn an_entry_that_opens_and_is_no_entry_is_one_that_cannot_be_read() {
    let p = back_unlisted();
    // Above the entry this device reads.
    let rev = 9;
    arrives(&p, &no_entry_at(&p, &p.other, INDEX, rev));
    assert_eq!(p.held(INDEX).as_deref(), Some(OTHER_LINE), "passed over");
    assert_eq!(not_read(&p, INDEX), 1);
    // The look finds neither: no put-back comes as far as its hold.
    let tried = std::cell::Cell::new(0);
    let before_hold = || tried.set(tried.get() + 1);
    for look in 1..20 {
        let hooks = Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        };
        let report = hooked_at(&p, 20 + 5 * look, &hooks);
        assert_eq!((report.published, report.pulled), (0, 0), "{report:?}");
    }
    assert_eq!(tried.get(), 0);
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));

    // The index is edited here: the edit is published above the entry,
    // which counts for the next revision though it is no version.
    let edited = format!("{OTHER_LINE}- [Mine](mine.md) added here\n");
    p.file(INDEX, &edited);
    assert_eq!(cycle_at(&p, 120).published, 1);
    assert_eq!(version(&p.st, NAME, INDEX).unwrap().1, rev + 1);
    assert_eq!(not_read(&p, INDEX), 0);
    // A minute of looks later the line goes back, above that.
    assert_eq!(a_minute_from(&p, 125).published, 1);
    assert_eq!(p.read(INDEX).unwrap(), format!("{edited}{NOTES}"));
    assert_eq!(version(&p.st, NAME, INDEX).unwrap().1, rev + 2);
}

/// A file is not at rest where the channel has no version of it: what is
/// under its name there is neither a text nor a delete (bytes written
/// through the API). The plan has nothing to do for such a file, and it
/// is still no file that the channel and the folder agree. No line goes
/// back for it, and none goes back into an index that is in that state:
/// nothing is published, and nothing is even kept in local history for
/// a put-back that would then be refused.
#[test]
fn a_file_with_no_version_in_the_channel_is_not_at_rest() {
    for name in ["notes.md", INDEX] {
        let (p, store) = back_unlisted().with_history();
        write(&p.other, NAME, name, Value::Other(b"{\"a\":1}".to_vec()));
        deliver(&p.other, &p.st, NAME);
        let (planned, _, text) = version(&p.st, NAME, name).unwrap();
        let other = Kind::Other;
        assert!(
            matches!(planned, PlannedAgainst::Version { kind, .. } if kind == other),
            "{name}: {planned:?}"
        );
        assert_eq!(text, "", "{name}");
        for look in 1..20 {
            let report = cycle_at(&p, 20 + 5 * look);
            assert_eq!(
                (report.published, report.pulled, report.failed.len()),
                (0, 0, 0),
                "{name}, look {look}: {report:?}"
            );
        }
        assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE), "{name}");
        assert_eq!(kept_in(&store), [], "{name}");
        assert!(!p.st.home_dir.join("history").exists(), "{name}");
        assert_eq!(records(&p).len(), 1, "{name}");
    }
}

/// With local history on, as a node has it: the index as it was here goes
/// into history before its lines are put back, as at a merge, in a record
/// that names the put-back's revision. A put-back that is not made leaves
/// no record: one that is refused under the hold, and one for which an
/// entry arrives under the index's name after the text was kept.
#[test]
fn the_index_as_it_was_is_kept_before_its_lines_are_put_back() {
    use history::{Change, Replacement, Whose};
    let due = || {
        let (p, store) = back_unlisted().with_history();
        for look in 1..13 {
            assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
        }
        assert_eq!(kept_in(&store), []);
        (p, store)
    };

    let (p, store) = due();
    let me = Pair::shown(&p.st.identity.public_key());
    assert_eq!(cycle_at(&p, 85).published, 1);
    let kept = kept_in(&store);
    assert_eq!(briefly(&kept), [(INDEX, Change::Merged, Some(OTHER_LINE))]);
    let about = &kept[0].3;
    assert_eq!(
        about.kept.as_ref().unwrap().whose,
        Whose::Here { agreed: Some(2) }
    );
    let put_back = history::Entry { device: me, rev: 3 };
    assert_eq!(about.replaced_by, Replacement::Entry(put_back));
    assert_eq!(version(&p.st, NAME, INDEX).unwrap().1, 3);

    // Refused under the hold (the memory's entry changed in the channel
    // meanwhile): nothing is published, and no record stays.
    let (p, store) = due();
    let before_hold = || p.other_writes("notes.md", Some("three\n"));
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        },
    );
    assert_eq!(report.published, 0, "{report:?}");
    assert_eq!(kept_in(&store), []);

    // An entry arrives under the index's name after the text was kept,
    // one that this device passes over when it reads the channel (it
    // opens and is no entry), so that the channel's version does not
    // show it: the record names a revision that a put-back would no
    // longer have. Nothing is published, and no record stays.
    let (p, store) = due();
    let before_hold = || arrives(&p, &no_entry_at(&p, &p.other, INDEX, 9));
    let report = hooked_at(
        &p,
        85,
        &Hooks {
            before_hold: &before_hold,
            ..Hooks::NONE
        },
    );
    assert_eq!(report.published, 0, "{report:?}");
    assert_eq!(kept_in(&store), []);
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));
    // Nothing is put back while that entry stands above the index's
    // version, and nothing is kept for it.
    assert_eq!(cycle_at(&p, 90).published, 0);
    assert_eq!(kept_in(&store), []);
    // The index is edited here, above that entry. The put-back that
    // follows is made above the edit, and its record names the revision
    // it has.
    let edited = format!("{OTHER_LINE}- [Mine](mine.md) added here\n");
    p.file(INDEX, &edited);
    assert_eq!(cycle_at(&p, 95).published, 1);
    assert_eq!(version(&p.st, NAME, INDEX).unwrap().1, 10);
    assert_eq!(a_minute_from(&p, 100).published, 1);
    let kept = kept_in(&store);
    let merged: Vec<&Kept4> = kept.iter().filter(|r| r.1 == Change::Merged).collect();
    assert_eq!(merged.len(), 1, "{kept:?}");
    assert_eq!(merged[0].2.as_deref(), Some(edited.as_str()));
    let about = &merged[0].3;
    assert_eq!(
        about.kept.as_ref().unwrap().whose,
        Whose::Here { agreed: Some(10) }
    );
    let me = Pair::shown(&p.st.identity.public_key());
    let put_back = history::Entry {
        device: me,
        rev: 11,
    };
    assert_eq!(about.replaced_by, Replacement::Entry(put_back));
    assert_eq!(version(&p.st, NAME, INDEX).unwrap().1, 11);
}

/// A failure while lines are put back is the index's, reported as any
/// file's is, and leaves the folder's other files done: here a file that
/// arrives in the same cycle is taken. One that is not a file's (the
/// database cannot be read) is the folder's, and the files are done all
/// the same.
#[test]
fn a_failure_while_lines_are_put_back_leaves_the_other_files_done() {
    // The index cannot be kept in local history: something that is no
    // directory is where the history directory would be.
    let (p, _store) = back_unlisted().with_history();
    for look in 1..13 {
        assert_eq!(cycle_at(&p, 20 + 5 * look).published, 0);
    }
    std::fs::create_dir_all(&p.st.home_dir).unwrap();
    std::fs::write(p.st.home_dir.join("history"), "in the way").unwrap();
    p.other_writes("later.md", Some("l\n"));
    let report = cycle_at(&p, 85);
    assert_eq!((report.published, report.pulled), (0, 1), "{report:?}");
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert_eq!(report.failed[0].name, INDEX);
    assert!(report.error.is_none(), "{report:?}");
    assert_eq!(p.read("later.md").as_deref(), Some("l\n"));
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));

    // The table of records cannot be read when the cycle comes to look.
    let p = back_unlisted();
    p.other_writes("later.md", Some("l\n"));
    let away = |name: &str| {
        if name == "later.md" {
            let db = p.st.db.lock().unwrap();
            db.execute_batch("ALTER TABLE index_lines RENAME TO index_lines_away")
                .unwrap();
        }
    };
    let report = hooked_at(
        &p,
        25,
        &Hooks {
            flushed: &away,
            ..Hooks::NONE
        },
    );
    assert!(report.error.is_some(), "{report:?}");
    assert_eq!(report.pulled, 1, "{report:?}");
    assert_eq!(p.read("later.md").as_deref(), Some("l\n"));
}

/// A record needs both halves, and both from this device. A line taken
/// out here while the file is kept, where another device then deletes the
/// file and this device's text beats the delete: no delete was published
/// here, and nothing is put back. A file deleted here while its line is
/// kept, which then comes back: the line never went.
#[test]
fn a_record_needs_both_of_this_devices_acts() {
    // The line goes, the file stays; the other device deletes the file,
    // and this device's edit of it wins.
    let p = listed();
    p.file(INDEX, OTHER_LINE);
    assert_eq!(cycle_at(&p, 10).published, 1);
    p.file("notes.md", "edited here\n");
    p.other_writes("notes.md", None);
    let report = cycle_at(&p, 20);
    assert_eq!(report.published, 1, "{report:?}");
    assert_eq!(p.read("notes.md").as_deref(), Some("edited here\n"));
    assert_eq!(
        rows(&p),
        [("notes.md".to_string(), true, false, false)],
        "a line, and no delete of this device's"
    );
    assert_eq!(a_minute_from(&p, 25).published, 0);
    assert_eq!(p.read(INDEX).as_deref(), Some(OTHER_LINE));

    // The file goes, the line stays; the other device's edit brings the
    // file back.
    let p = listed();
    std::fs::remove_file(p.mem.join("notes.md")).unwrap();
    assert_eq!(cycle_at(&p, 10).published, 1);
    assert_eq!(rows(&p), [("notes.md".to_string(), false, true, false)]);
    comes_back_to(&p, 20, &format!("{NOTES}{OTHER_LINE}"));
    assert_eq!(a_minute_from(&p, 25).published, 0);
    assert_eq!(p.read(INDEX).unwrap(), format!("{NOTES}{OTHER_LINE}"));
}
