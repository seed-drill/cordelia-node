//! The sweep of old deletes in a device's own store (decision 2026-10-04
//! §2.3, §7.3, §16; decision 2026-09-30 §4.4).
//!
//! A delete is a version: it is stored, sent and carried like a text, so
//! that a device which was away learns that a file was deleted. It is
//! held for 90 days (`KEYED_TOMBSTONE_RETENTION_DAYS`), counted from when
//! this device stored the entry, and then it goes ([`sweep_deletes`]). A
//! delete that is carried at a statement is a new entry, so its 90 days
//! start again there.
//!
//! **A sweep takes only deletes** (§16). An entry that is no delete
//! stays where it is, whatever goes around it. Which deletes go turns on
//! what the device can know of their slot:
//!
//! - **In the channel of a name it holds,** the device reads the slot as
//!   it reads it for a folder: with the name's secret, under the
//!   statement it has applied, and with its word on who counts. The
//!   slot's old deletes go where its current version is a delete, and the
//!   device has held every entry that is that delete for 90 days.
//!   - **They stay while the slot holds an entry that is no delete and
//!     that the store took before the delete.** Were the delete to go,
//!     that entry would be the slot's version again, and a file that was
//!     deleted would come back. (An entry that is no delete and that came
//!     after the delete is another thing: a file made again under the
//!     name, by a device whose own delete had gone already. It stays, and
//!     is the slot's version once the delete has gone.)
//!   - **They stay while a folder's record names a text there.** Such a
//!     folder has not taken the delete yet: with the delete gone, its
//!     file would meet the channel as a new file does, and be published
//!     again. Once every folder has agreed that the file is deleted, the
//!     delete goes, and those records go with it: no folder's record
//!     names a version that the store holds no more.
//! - **In any other channel of its own** (the personal channel, and the
//!   pair channel of a hand-over it made), an entry is one device's own
//!   word, whatever another key wrote in its slot. A slot's deletes go
//!   there only where every entry in it is a delete that the device has
//!   held for 90 days, as a relay sweeps a slot.
//!
//! **A channel that a sweep took anything of is read again from its
//! start, at every relay** (§16). A device whose delete went earlier may
//! have made the file again since, at the first revision. Where one
//! author wrote that entry and the delete, this device's store kept the
//! delete and nothing of the entry below it, and its place at each relay
//! is past the entry. So it forgets its places in the channel, and the
//! node's next pass reads the entry.
//!
//! A device that follows no phrase holds no channel of its own, and one
//! that has stopped keeps what it holds until a person acts: neither
//! sweeps anything.
//!
//! **What a sweep costs.** A slot of which nothing is left has no
//! revision: the next entry written there starts again at the first. A
//! node that stored the delete later than this device still holds it for
//! as long, and to that node a file that is made again under the same
//! name in that time is below the delete until its own 90 days have
//! passed. It has the file then: late, by as long as it was behind.

use std::collections::{BTreeSet, HashMap};

use rusqlite::Connection;

use cordelia_core::protocol::KEYED_TOMBSTONE_RETENTION_DAYS;
use cordelia_crypto::bech32::encode_channel_id;
use cordelia_crypto::derive;
use cordelia_crypto::entry::Value;
use cordelia_crypto::version;
use cordelia_storage::at_relays as places;
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
    /// How many slots it took deletes of.
    pub slots: usize,
    /// How many entries went: each of them a delete.
    pub entries: usize,
    /// How many slots keep their delete, though it is old, because a
    /// folder's record names a text there.
    pub kept_for_a_folder: usize,
    /// How many slots keep their delete, though it is old, because an
    /// entry that is no delete was stored there before it.
    pub kept_over_an_entry: usize,
    /// How many channels it took something of: each is read again from
    /// its start, at every relay.
    pub read_again: usize,
}

/// Drop from this device's store each delete that it has held for 90
/// days and that may go (see the module's documentation), at `now`, the
/// device's time in seconds, and forget the device's places in each
/// channel that something went from. All of it happens, or none.
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
        // The channels that something went from.
        let mut taken_of: BTreeSet<[u8; 32]> = BTreeSet::new();
        for (channel, slot) in entries::slots_with_a_delete_stored(conn, by)? {
            let goes = match names.get(&channel) {
                Some(secret) => match of_a_name(conn, &standing, &channel, &slot, secret, by)? {
                    Judged::Goes => true,
                    Judged::KeptForAFolder => {
                        swept.kept_for_a_folder += 1;
                        false
                    }
                    Judged::KeptOverAnEntry => {
                        swept.kept_over_an_entry += 1;
                        false
                    }
                    Judged::Stays => false,
                },
                None => entries::holds_only_deletes_stored(conn, &channel, &slot, by)?,
            };
            if goes {
                // The deletes, and nothing else: an entry that is no
                // delete stays.
                swept.entries += entries::remove_deletes_stored(conn, &channel, &slot, by)?;
                swept.slots += 1;
                taken_of.insert(channel);
            }
        }
        // Each channel that something went from is read again from its
        // start, at every relay: a file made again there since may lie
        // behind the place that the device has reached.
        for channel in &taken_of {
            places::forget_places_of(conn, channel)?;
        }
        swept.read_again = taken_of.len();
        Ok(swept)
    })
}

/// What a sweep makes of one slot in the channel of a name.
enum Judged {
    /// Its current version is a delete held for 90 days, no entry that is
    /// no delete came before it, and no folder's record names a text
    /// there: its old deletes go, with each folder's record that the file
    /// is deleted.
    Goes,
    /// They would go, and a folder's record names a text there.
    KeptForAFolder,
    /// Its current version is a delete held for 90 days, and the slot
    /// holds an entry that is no delete and that came before it: with the
    /// delete gone, that entry would be the file again.
    KeptOverAnEntry,
    /// Its current version is no delete, or one that is not old yet.
    Stays,
}

/// Judge one slot of the channel of a name that the device holds, whose
/// secret is `secret`: `by` is the time at or before which a delete that
/// goes was stored. A slot whose deletes go has its folders' records of
/// the delete forgotten here.
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
    let of_the_delete = |held: &&entries::StoredEntry| {
        let id = held.entry.id();
        current.entries.iter().any(|one| one.id == id)
    };
    let held_long = current.entries.iter().all(|one| {
        stored
            .iter()
            .any(|held| held.entry.id() == one.id && held.stored_at <= by)
    });
    if !held_long {
        return Ok(Judged::Stays);
    }
    // An entry that is no delete, and that the store took before the
    // last entry of the delete: whoever signed it, and whether or not it
    // is read today. The delete is what keeps it from being the file.
    let delete_came = stored
        .iter()
        .filter(of_the_delete)
        .map(|held| held.seq)
        .max();
    let under = stored
        .iter()
        .any(|held| !held.entry.delete && Some(held.seq) < delete_came);
    if under {
        return Ok(Judged::KeptOverAnEntry);
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
    const RELAY: [u8; 32] = [0xa1; 32];
    const OTHER_RELAY: [u8; 32] = [0xa2; 32];
    const MARK: [u8; 8] = [0x4d, 1, 2, 3, 4, 5, 6, 7];

    /// The place that `on` keeps at `relay` in `channel`.
    fn place_at(on: &Machine, relay: &[u8; 32], channel: &[u8; 32]) -> Option<([u8; 8], u64)> {
        places::kept(&on.conn, relay, channel).unwrap().place
    }

    /// The channel of `name` on `on`.
    fn channel_of(on: &Machine, name: &str) -> [u8; 32] {
        derive::channel_id(&on.own(name)).unwrap()
    }

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

    /// In the channel of a name, a slot's delete goes where it is the
    /// slot's current version and the device has held it for 90 days, and
    /// not a second before (decision 2026-10-04 §2.3, §7.3, §16). **Only
    /// deletes go.** A slot whose current version is a text stays,
    /// however old a delete below it is. And a delete stays while the
    /// slot holds an entry that is no delete and that came before it:
    /// that entry would be the file again, and no file comes back.
    ///
    /// The device forgets its places, at every relay, in a channel that
    /// the sweep took something of, and in no other; and none where the
    /// sweep took nothing.
    #[test]
    fn test_a_sweep_takes_the_deletes_held_for_90_days_and_nothing_else() {
        assert_eq!(KEYED_TOMBSTONE_RETENTION_DAYS, 90);
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "lab");
        s.write(0, "lab", "gone.md", "a text that its writer deletes");
        s.write(0, "lab", "under.md", "a text that another device deletes");
        s.write(0, "lab", "kept.md", "a text that stays");
        s.meet(&[0, 1]);
        // Device 0 deletes a file of its own: a store holds one entry for
        // an author in a slot, so the delete is all that the slot holds.
        deletes(&mut s, 0, "lab", "gone.md");
        let deleted = s.now;
        // Device 1 deletes another: its delete stands beside device 0's
        // text in the slot.
        deletes(&mut s, 1, "lab", "under.md");
        // And it deletes another that device 0 then writes again, above
        // the delete: the slot's current version is a text.
        s.write(1, "lab", "back.md", "first");
        deletes(&mut s, 1, "lab", "back.md");
        s.meet(&[0, 1]);
        s.write(0, "lab", "back.md", "written again");
        s.meet(&[0, 1]);
        let stored = s.now;
        for n in 0..2 {
            for file in ["gone.md", "under.md"] {
                assert_eq!(s[n].slot("lab", file).current.unwrap().value, Value::Delete);
            }
            assert_eq!(held_of(&s[n], "lab"), 6, "device {n}");
        }
        let on = &s[0];
        let (lab, personal) = (
            channel_of(on, "lab"),
            derive::channel_id(&on.personal()).unwrap(),
        );
        let reaches = |channel: &[u8; 32]| {
            for relay in [RELAY, OTHER_RELAY] {
                places::keep_place(&on.conn, &relay, channel, &MARK, 7).unwrap();
                places::sent(&on.conn, &relay, channel, 5).unwrap();
            }
        };
        reaches(&lab);
        reaches(&personal);
        let there = Some((MARK, 7));

        // A second short of 90 days from when this device stored its
        // delete, nothing goes, and no place is forgotten.
        let none = sweep_deletes(&on.conn, deleted + 90 * DAY - 1).unwrap();
        assert_eq!(none, Swept::default());
        assert_eq!(held_of(on, "lab"), 6);
        assert_eq!(place_at(on, &RELAY, &lab), there);
        // At 90 days the delete of `gone.md` goes: the slot holds
        // nothing. The delete that device 1 wrote is not old here yet.
        let swept = sweep_deletes(&on.conn, deleted + 90 * DAY).unwrap();
        assert_eq!(
            swept,
            Swept {
                slots: 1,
                entries: 1,
                read_again: 1,
                ..Swept::default()
            }
        );
        assert!(on.slot("lab", "gone.md").current.is_none());
        assert_eq!(held_of(on, "lab"), 5);
        // The name's channel is read again from its start, at each
        // relay: what was sent there is kept. A place in another channel
        // stays.
        for relay in [RELAY, OTHER_RELAY] {
            let kept = places::kept(&on.conn, &relay, &lab).unwrap();
            assert_eq!((kept.place, kept.sent_to), (None, 5));
            assert_eq!(place_at(on, &relay, &personal), there);
        }

        // Once everything is 90 days old: the delete of `under.md` stays,
        // over the text that came before it, and that text is not the
        // file again. The others stay. Nothing went, so no place is
        // forgotten.
        reaches(&lab);
        for long_after in [stored + 90 * DAY, stored + 3650 * DAY] {
            let swept = sweep_deletes(&on.conn, long_after).unwrap();
            assert_eq!(
                swept,
                Swept {
                    kept_over_an_entry: 1,
                    ..Swept::default()
                }
            );
        }
        assert_eq!(
            on.slot("lab", "under.md").current.unwrap().value,
            Value::Delete
        );
        assert_eq!(
            on.text("lab", "kept.md").as_deref(),
            Some("a text that stays")
        );
        assert_eq!(on.text("lab", "back.md").as_deref(), Some("written again"));
        assert_eq!(held_of(on, "lab"), 5);
        assert_eq!(place_at(on, &RELAY, &lab), there);
        // The other device is as it was until its own sweep.
        assert_eq!(held_of(&s[1], "lab"), 6);
    }

    /// **A file made again under a swept name reaches a device that
    /// swept later** (decision 2026-10-04 §16). Device 0 writes a file
    /// and deletes it, and device 1 stores that delete ten days after
    /// device 0 did. At its 90 days device 0's delete goes, and the file
    /// is made again there, at the first revision. To device 1 that entry
    /// is below the delete, and of the delete's own author: its store
    /// keeps nothing of it, and its place at a relay moves past it. When
    /// its own 90 days have passed, its delete goes too, and its place in
    /// the channel is forgotten: the channel is read again from its
    /// start, and the file is there.
    #[test]
    fn test_a_file_made_again_under_a_swept_name_reaches_a_device_that_swept_later() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "lab");
        let first = s.write(0, "lab", "again.md", "first");
        s.write(0, "lab", "other.md", "stays");
        deletes(&mut s, 0, "lab", "again.md");
        let early = s.now;
        s.now += 10 * DAY;
        s.pass(0, 1);
        let late = s.now;
        assert_eq!(held_of(&s[1], "lab"), 2);

        // Device 0's 90 days: its delete goes, and the slot holds
        // nothing. The file is made again there, at the first revision.
        let swept = sweep_deletes(&s[0].conn, early + 90 * DAY).unwrap();
        assert_eq!((swept.slots, swept.entries, swept.read_again), (1, 1, 1));
        assert!(s[0].slot("lab", "again.md").current.is_none());
        s.now = early + 91 * DAY;
        let again = s.write(0, "lab", "again.md", "made again");
        assert_eq!(again.rev, first.rev);

        // Device 1 is handed it, and keeps nothing of it: it holds the
        // delete, of that author, at a higher revision.
        s.pass(0, 1);
        let on = &s[1];
        assert_eq!(
            on.slot("lab", "again.md").current.unwrap().value,
            Value::Delete
        );
        let holds_it = |on: &Machine| {
            let held = on.stored_in(&on.own("lab"));
            held.iter().any(|held| held.id() == again.id())
        };
        assert!(!holds_it(on));
        // Its place at a relay is past the entry.
        let lab = channel_of(on, "lab");
        places::keep_place(&on.conn, &RELAY, &lab, &MARK, 4).unwrap();

        // A second short of its own 90 days nothing goes, and its place
        // is kept: read from there, the entry would never come.
        let none = sweep_deletes(&on.conn, late + 90 * DAY - 1).unwrap();
        assert_eq!(none, Swept::default());
        assert_eq!(place_at(on, &RELAY, &lab), Some((MARK, 4)));
        // At its 90 days the delete goes, and the place with it.
        let swept = sweep_deletes(&on.conn, late + 90 * DAY).unwrap();
        assert_eq!(
            swept,
            Swept {
                slots: 1,
                entries: 1,
                read_again: 1,
                ..Swept::default()
            }
        );
        assert_eq!(place_at(on, &RELAY, &lab), None);
        assert!(on.slot("lab", "again.md").current.is_none());

        // The channel is read again from its start: the file is there.
        s.now = late + 91 * DAY;
        s.pass(0, 1);
        assert!(holds_it(&s[1]));
        assert_eq!(s[1].text("lab", "again.md").as_deref(), Some("made again"));
        assert_eq!(s[1].text("lab", "other.md").as_deref(), Some("stays"));
    }

    /// **An entry that is no delete stays** (decision 2026-10-04 §16).
    /// Here another device than the delete's author makes the file
    /// again, once its own delete has gone. A device that still holds
    /// the delete keeps that entry, below the delete: it came after it.
    /// When this device's delete goes, the entry is what the slot holds,
    /// and the file is there at once.
    #[test]
    fn test_an_entry_that_came_after_the_delete_stays_when_the_delete_goes() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "lab");
        let first = s.write(0, "lab", "again.md", "first");
        deletes(&mut s, 0, "lab", "again.md");
        s.pass(0, 2);
        let early = s.now;
        s.now += 10 * DAY;
        s.pass(0, 1);
        let late = s.now;

        // Device 2's delete goes, and it makes the file again: an entry
        // of its own, at the first revision.
        let swept = sweep_deletes(&s[2].conn, early + 90 * DAY).unwrap();
        assert_eq!((swept.slots, swept.entries), (1, 1));
        s.now = early + 91 * DAY;
        let again = s.write(2, "lab", "again.md", "made again by another");
        assert_eq!(again.rev, first.rev);
        // Device 1 keeps it below the delete that it still holds.
        s.pass(2, 1);
        let on = &s[1];
        assert_eq!(held_of(on, "lab"), 2);
        assert_eq!(
            on.slot("lab", "again.md").current.unwrap().value,
            Value::Delete
        );

        // Its own 90 days: the delete goes, and the entry stays.
        let swept = sweep_deletes(&on.conn, late + 90 * DAY).unwrap();
        assert_eq!(
            swept,
            Swept {
                slots: 1,
                entries: 1,
                read_again: 1,
                ..Swept::default()
            }
        );
        assert_eq!(held_of(on, "lab"), 1);
        assert_eq!(
            on.text("lab", "again.md").as_deref(),
            Some("made again by another")
        );
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
                kept_for_a_folder: 1,
                ..Swept::default()
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
            swept,
            Swept {
                slots: 1,
                entries: 1,
                read_again: 1,
                ..Swept::default()
            }
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

    /// Where two devices wrote a delete apart, it is one version in two
    /// entries, and it came whole with the last of them. A text that the
    /// store took before that keeps the delete, though it came after the
    /// first entry of it: it was written by a device that had seen
    /// neither, and with the delete gone it would be the file.
    #[test]
    fn test_a_delete_stays_over_an_entry_that_came_before_the_last_entry_of_it() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "lab");
        // Devices 0 and 2 each write the file, apart. Device 1 sees
        // device 0's text, and each of the two deletes it.
        s.write(0, "lab", "apart.md", "of device 0");
        s.write(2, "lab", "apart.md", "of device 2");
        s.meet(&[0, 1]);
        deletes(&mut s, 0, "lab", "apart.md");
        deletes(&mut s, 1, "lab", "apart.md");
        // Device 0 is handed device 2's text, and then device 1's delete.
        s.pass(2, 0);
        s.pass(1, 0);
        let stored = s.now;
        let on = &s[0];
        let current = on.slot("lab", "apart.md").current.unwrap();
        assert_eq!(
            (current.value.clone(), current.entries.len()),
            (Value::Delete, 2)
        );
        assert_eq!(held_of(on, "lab"), 3);

        let swept = sweep_deletes(&on.conn, stored + 90 * DAY).unwrap();
        assert_eq!(
            swept,
            Swept {
                kept_over_an_entry: 1,
                ..Swept::default()
            }
        );
        assert_eq!(held_of(on, "lab"), 3);
        assert_eq!(
            on.slot("lab", "apart.md").current.unwrap().value,
            Value::Delete
        );
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
