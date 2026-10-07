//! The sweep of old deletes in a device's own store (decision 2026-10-04
//! §2.3, §7.3; decision 2026-09-30 §4.4).
//!
//! A delete is a version: it is stored, sent and carried like a text, so
//! that a device which was away learns that a file was deleted. It is
//! held for 90 days (`KEYED_TOMBSTONE_RETENTION_DAYS`), counted from when
//! this device stored the entry, and then it goes ([`sweep_deletes`]). A
//! delete that is carried at a statement is a new entry, so its 90 days
//! start again there.
//!
//! **A slot goes whole, or not at all.** Were a delete to go alone, a
//! lower revision by another author would be the slot's version again,
//! and a file that was deleted would come back. Which slots go turns on
//! what the device can know of them:
//!
//! - **In the channel of a name it holds,** the device reads the slot as
//!   it reads it for a folder: with the name's secret, under the
//!   statement it has applied, and with its word on who counts. The slot
//!   goes where its current version is a delete, and the device has held
//!   every entry that is that delete for 90 days.
//!   - **It stays while a folder's record names a text there.** Such a
//!     folder has not taken the delete yet: with the slot gone, its file
//!     would meet the channel as a new file does, and be published again.
//!     Once every folder has agreed that the file is deleted, the slot
//!     goes, and those records go with it: no folder's record names a
//!     version that the store holds no more.
//! - **In any other channel of its own** (the personal channel, and the
//!   pair channel of a hand-over it made), an entry is one device's own
//!   word, whatever another key wrote in its slot. A slot goes there
//!   only where every entry in it is a delete that the device has held
//!   for 90 days, as a relay sweeps a slot.
//!
//! A device that follows no phrase holds no channel of its own, and one
//! that has stopped keeps what it holds until a person acts: neither
//! sweeps anything.
//!
//! **What a sweep costs.** A slot that has gone has no revision: the next
//! entry written there starts again at the first. A node that stored the
//! delete later than this device still holds it for as long, and to that
//! node a file that is made again under the same name in that time is
//! below the delete until its own 90 days have passed.

use std::collections::HashMap;

use rusqlite::Connection;

use cordelia_core::protocol::KEYED_TOMBSTONE_RETENTION_DAYS;
use cordelia_crypto::bech32::encode_channel_id;
use cordelia_crypto::derive;
use cordelia_crypto::entry::Value;
use cordelia_crypto::version;
use cordelia_storage::entries;
use cordelia_storage::person::{self as held_rows, State};
use cordelia_storage::sync_state;

use crate::person::{PersonError, in_one};
use crate::publish::Standing;

/// How long a delete is held, in seconds.
const DELETE_HELD_SECS: i64 = KEYED_TOMBSTONE_RETENTION_DAYS as i64 * 24 * 60 * 60;

/// What a sweep of old deletes did on a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Swept {
    /// How many slots went.
    pub slots: usize,
    /// How many entries went with them.
    pub entries: usize,
    /// How many slots stay, though their delete is old, because a
    /// folder's record names a text there.
    pub kept_for_a_folder: usize,
}

/// Drop from this device's store each slot whose delete it has held for
/// 90 days (see the module's documentation), at `now`, the device's time
/// in seconds. All of it happens, or none.
pub fn sweep_deletes(conn: &Connection, now: i64) -> Result<Swept, PersonError> {
    in_one(conn, || {
        let standing = match Standing::of(conn) {
            Ok(standing) if standing.held.state == State::Applied => standing,
            Ok(_) | Err(PersonError::FollowsNoPhrase) => return Ok(Swept::default()),
            Err(e) => return Err(e),
        };
        let by = now.saturating_sub(DELETE_HELD_SECS);
        // The channel of each name the device holds, with its secret.
        let mut names: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
        for held in held_rows::names(conn)? {
            let secret = derive::own_secret(&standing.secret, &held.name)?;
            names.insert(derive::channel_id(&secret)?, secret);
        }

        let mut swept = Swept::default();
        for (channel, slot) in entries::slots_with_a_delete_stored(conn, by)? {
            let goes = match names.get(&channel) {
                Some(secret) => match of_a_name(conn, &standing, &channel, &slot, secret, by)? {
                    Judged::Goes => true,
                    Judged::KeptForAFolder => {
                        swept.kept_for_a_folder += 1;
                        false
                    }
                    Judged::Stays => false,
                },
                None => entries::holds_only_deletes_stored(conn, &channel, &slot, by)?,
            };
            if goes {
                swept.entries += entries::remove_slot(conn, &channel, &slot)?;
                swept.slots += 1;
            }
        }
        Ok(swept)
    })
}

/// What a sweep makes of one slot in the channel of a name.
enum Judged {
    /// Its current version is a delete held for 90 days, and no folder's
    /// record names a text there: it goes, with each folder's record that
    /// the file is deleted.
    Goes,
    /// It would go, and a folder's record names a text there.
    KeptForAFolder,
    /// Its current version is no delete, or one that is not old yet.
    Stays,
}

/// Judge one slot of the channel of a name that the device holds, whose
/// secret is `secret`: `by` is the time at or before which a delete that
/// goes was stored. A slot that goes has its folders' records of the
/// delete forgotten here.
fn of_a_name(
    conn: &Connection,
    standing: &Standing,
    channel: &[u8; 32],
    slot: &[u8; 32],
    secret: &[u8; 32],
    by: i64,
) -> Result<Judged, PersonError> {
    let stored = entries::slot_stored(conn, channel, slot)?;
    let checked: Vec<_> = stored
        .iter()
        .filter_map(|held| held.entry.clone().check().ok())
        .collect();
    let read = version::current(&checked, secret, standing.number(), |key| {
        standing.counting.counts(key)
    })?;
    let Some(current) = read.current else {
        return Ok(Judged::Stays);
    };
    if current.value != Value::Delete {
        return Ok(Judged::Stays);
    }
    // The device has held the delete for 90 days in every entry that is
    // it: one that arrived since says that a device still wrote it then.
    let held_long = current.entries.iter().all(|one| {
        stored
            .iter()
            .any(|held| held.entry.id() == one.id && held.stored_at <= by)
    });
    if !held_long {
        return Ok(Judged::Stays);
    }
    let written = encode_channel_id(channel)?;
    if sync_state::names_a_text(conn, &written, &current.name)? {
        return Ok(Judged::KeptForAFolder);
    }
    sync_state::forget_deleted(conn, &written, &current.name)?;
    Ok(Judged::Goes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::{PlannedAgainst, Published, Write, publish};
    use crate::several::{Machine, Several};
    use cordelia_storage::sync_state::Agreed;

    const DAY: i64 = 24 * 60 * 60;

    /// Device `n` writes a delete under `file` in `name`, over what it
    /// reads there.
    fn deletes(s: &mut Several, n: usize, name: &str, file: &str) {
        let now = s.tick();
        let on = &s[n];
        let write = Write {
            name,
            file,
            value: Value::Delete,
            planned: PlannedAgainst::what_is_in(&on.slot(name, file)),
            merge: None,
        };
        let made = publish(&on.conn, &on.identity, &write, now).unwrap();
        assert!(matches!(made, Published::Made(_)), "{made:?}");
    }

    /// The channel of `name` on `on`, as a folder's record writes it.
    fn written(on: &Machine, name: &str) -> String {
        encode_channel_id(&derive::channel_id(&on.own(name)).unwrap()).unwrap()
    }

    /// A folder's record of `file` in `name`: a text where `said` is one,
    /// and that the file is deleted otherwise.
    fn records(on: &Machine, folder: &str, name: &str, file: &str, said: Option<&str>) {
        let agreed = Agreed {
            hash: said.map(|said| cordelia_crypto::sha256(said.as_bytes())),
            rev: 1,
            signer: Some(on.key()),
            chain: Some(Vec::new()),
        };
        sync_state::save(&on.conn, folder, &written(on, name), file, &agreed).unwrap();
    }

    fn recorded(on: &Machine, name: &str) -> Vec<(String, String)> {
        sync_state::files(&on.conn, &written(on, name)).unwrap()
    }

    /// How many entries the device holds of the channel of `name`.
    fn held_of(on: &Machine, name: &str) -> usize {
        on.stored_in(&on.own(name)).len()
    }

    /// In the channel of a name, a slot goes where its current version is
    /// a delete that the device has held for 90 days, and not a second
    /// before (decision 2026-10-04 §2.3, §7.3). It goes whole: the text
    /// that the delete was written over goes with it, and no file comes
    /// back. A slot whose current version is a text stays, however old a
    /// delete below it is.
    #[test]
    fn test_a_slot_whose_delete_was_held_for_90_days_goes_whole() {
        assert_eq!(KEYED_TOMBSTONE_RETENTION_DAYS, 90);
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "lab");
        // Device 0 writes two files. Device 1 deletes one: its delete
        // stands beside device 0's text in the slot.
        s.write(0, "lab", "gone.md", "a text that is deleted");
        s.write(0, "lab", "kept.md", "a text that stays");
        s.meet(&[0, 1]);
        deletes(&mut s, 1, "lab", "gone.md");
        // And it deletes another that device 0 then writes again, above
        // the delete: the slot's current version is a text.
        s.write(1, "lab", "back.md", "first");
        deletes(&mut s, 1, "lab", "back.md");
        // Device 0 stores the deletes after this moment.
        let not_yet_stored = s.now;
        s.meet(&[0, 1]);
        s.write(0, "lab", "back.md", "written again");
        s.meet(&[0, 1]);
        let stored = s.now;
        for n in 0..2 {
            assert_eq!(
                s[n].slot("lab", "gone.md").current.unwrap().value,
                Value::Delete
            );
            assert_eq!(held_of(&s[n], "lab"), 5, "device {n}");
        }

        // Short of 90 days from when this device stored the delete,
        // nothing goes.
        let on = &s[0];
        let none = sweep_deletes(&on.conn, not_yet_stored + 90 * DAY).unwrap();
        assert_eq!(none, Swept::default());
        assert_eq!(held_of(on, "lab"), 5);
        // At 90 days from when everything was stored: the slot of
        // `gone.md` goes, with device 0's text below the delete. The
        // others stay.
        let swept = sweep_deletes(&on.conn, stored + 90 * DAY).unwrap();
        assert_eq!(
            swept,
            Swept {
                slots: 1,
                entries: 2,
                kept_for_a_folder: 0
            }
        );
        assert!(on.slot("lab", "gone.md").current.is_none());
        assert_eq!(
            on.text("lab", "kept.md").as_deref(),
            Some("a text that stays")
        );
        assert_eq!(on.text("lab", "back.md").as_deref(), Some("written again"));
        assert_eq!(held_of(on, "lab"), 3);
        // Again, and long after: nothing more.
        let again = sweep_deletes(&on.conn, stored + 3650 * DAY).unwrap();
        assert_eq!(again, Swept::default());
        assert_eq!(held_of(on, "lab"), 3);
        // The other device is as it was until its own sweep.
        assert_eq!(held_of(&s[1], "lab"), 5);
    }

    /// A slot stays while a folder's record names a text there: that
    /// folder has not taken the delete, and with the slot gone its file
    /// would be published again. Once every folder has agreed that the
    /// file is deleted the slot goes, and those records go with it.
    #[test]
    fn test_a_delete_stays_while_a_folders_record_names_a_text_there() {
        let mut s = Several::of_one_person(1);
        s.hold(&[0], "lab");
        s.write(0, "lab", "gone.md", "a text");
        s.write(0, "lab", "other.md", "another");
        deletes(&mut s, 0, "lab", "gone.md");
        let long_after = s.now + 91 * DAY;
        let on = &s[0];
        // Two folders sync the name. One has agreed the delete, and the
        // other still has the text.
        records(on, "/home/sam/one", "lab", "gone.md", None);
        records(on, "/home/sam/two", "lab", "gone.md", Some("a text"));
        records(on, "/home/sam/two", "lab", "other.md", Some("another"));

        let swept = sweep_deletes(&on.conn, long_after).unwrap();
        assert_eq!(
            swept,
            Swept {
                slots: 0,
                entries: 0,
                kept_for_a_folder: 1
            }
        );
        assert_eq!(
            on.slot("lab", "gone.md").current.unwrap().value,
            Value::Delete
        );
        assert_eq!(recorded(on, "lab").len(), 3);

        // The second folder takes the delete: the slot goes, with both
        // folders' records that the file is deleted. A record of another
        // file stays, and so does that file.
        records(on, "/home/sam/two", "lab", "gone.md", None);
        let swept = sweep_deletes(&on.conn, long_after).unwrap();
        assert_eq!(
            (swept.slots, swept.entries, swept.kept_for_a_folder),
            (1, 1, 0)
        );
        assert!(on.slot("lab", "gone.md").current.is_none());
        assert_eq!(
            recorded(on, "lab"),
            [("/home/sam/two".to_string(), "other.md".to_string())]
        );
        assert_eq!(on.text("lab", "other.md").as_deref(), Some("another"));
    }

    /// A delete is held for 90 days from when this device stored the
    /// entry that is it. Where the device holds the delete in two
    /// entries (two devices wrote it), each has to be old: one that
    /// arrived since says that a device still wrote it then.
    #[test]
    fn test_a_delete_is_old_only_once_every_entry_of_it_is() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "lab");
        s.write(0, "lab", "gone.md", "a text");
        s.meet(&[0, 1]);
        // Each deletes it apart: one version, in two entries.
        deletes(&mut s, 0, "lab", "gone.md");
        deletes(&mut s, 1, "lab", "gone.md");
        let own_stored = s.now;
        // Device 1's delete reaches device 0 ten days later.
        s.now += 10 * DAY;
        s.pass(1, 0);
        let arrived = s.now;
        let on = &s[0];
        let current = on.slot("lab", "gone.md").current.unwrap();
        assert_eq!(
            (current.value.clone(), current.entries.len()),
            (Value::Delete, 2)
        );

        assert_eq!(
            sweep_deletes(&on.conn, own_stored + 90 * DAY).unwrap(),
            Swept::default()
        );
        assert_eq!(
            sweep_deletes(&on.conn, arrived + 90 * DAY - 1).unwrap(),
            Swept::default()
        );
        let swept = sweep_deletes(&on.conn, arrived + 90 * DAY).unwrap();
        assert_eq!((swept.slots, swept.entries), (1, 2));
    }

    /// In the personal channel an entry is one device's own word, whatever
    /// another key wrote in its slot: a slot goes only where every entry
    /// in it is a delete held for 90 days. A device's word that it syncs a
    /// name stays, though another device's delete in that slot is old and
    /// at a higher revision.
    #[test]
    fn test_in_the_personal_channel_a_slot_goes_only_where_every_word_is_an_old_delete() {
        use crate::names::{say, unsay};
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "lab");
        s.hold(&[0, 1], "old");
        let now = s.tick();
        for n in 0..2 {
            for name in ["lab", "old"] {
                assert!(say(&s[n].conn, &s[n].identity, name, now).unwrap());
            }
        }
        // Device 1 says, stops, says and stops again, so that its delete
        // is above device 0's word. Both stop syncing `old`.
        for step in 0..3 {
            let now = s.tick();
            let on = &s[1];
            match step % 2 {
                0 => assert!(unsay(&on.conn, &on.identity, "lab", now).unwrap()),
                _ => assert!(say(&on.conn, &on.identity, "lab", now).unwrap()),
            }
        }
        let now = s.tick();
        for n in 0..2 {
            assert!(unsay(&s[n].conn, &s[n].identity, "old", now).unwrap());
        }
        s.meet(&[0, 1]);
        let long_after = s.now + 91 * DAY;
        let on = &s[0];
        let listed = |on: &Machine| -> Vec<String> {
            crate::names::listed(&on.conn)
                .unwrap()
                .into_iter()
                .map(|listed| listed.name)
                .collect()
        };
        assert_eq!(listed(on), ["lab"]);
        let personal = on.stored_in(&on.personal()).len();

        let swept = sweep_deletes(&on.conn, long_after).unwrap();
        // The slot of `old` goes, with both devices' deletes. The slot
        // of `lab` stays whole: device 0's word is there.
        assert_eq!((swept.slots, swept.entries), (1, 2));
        assert_eq!(on.stored_in(&on.personal()).len(), personal - 2);
        assert_eq!(listed(on), ["lab"]);
    }

    /// A device that follows no phrase has nothing to sweep, and one that
    /// has stopped keeps what it holds until a person acts.
    #[test]
    fn test_a_device_that_has_stopped_sweeps_nothing() {
        let fresh = Several::new(1);
        assert_eq!(
            sweep_deletes(&fresh[0].conn, crate::several::START + 3650 * DAY).unwrap(),
            Swept::default()
        );

        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "lab");
        s.write(0, "lab", "gone.md", "a text");
        deletes(&mut s, 0, "lab", "gone.md");
        s.meet(&[0, 1]);
        let long_after = s.now + 91 * DAY;
        // Eighty days on device 1 is removed, and learns of it.
        s.now += 80 * DAY;
        let change = s.change(0, &[0], &[1]);
        let carried = s.now;
        let now = s.tick();
        let on = &s[1];
        crate::person::shown(&on.conn, &on.identity, &change, now).unwrap();
        assert_eq!(on.state(), State::Removed);
        let before = on.everything();
        assert_eq!(
            sweep_deletes(&on.conn, long_after).unwrap(),
            Swept::default()
        );
        assert_eq!(on.everything(), before);
        // The device that goes on carried the delete: it is a new entry
        // there, and its 90 days started again when it was carried.
        let on = &s[0];
        assert_eq!(
            on.slot("lab", "gone.md").current.unwrap().value,
            Value::Delete
        );
        assert_eq!(
            sweep_deletes(&on.conn, long_after).unwrap(),
            Swept::default()
        );
        assert_eq!(
            sweep_deletes(&on.conn, carried + 90 * DAY - 1).unwrap(),
            Swept::default()
        );
        let swept = sweep_deletes(&on.conn, carried + 90 * DAY).unwrap();
        assert_eq!((swept.slots, swept.entries), (1, 1));
    }
}
