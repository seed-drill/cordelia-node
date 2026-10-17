//! A read of a channel of the device's own with places of its own
//! (decision 2026-10-17 §4.2, items 1 to 3): what the device reads before
//! a carried name is let go.
//!
//! It is a pull of the channel at each relay that the device is set up
//! with, under leave, as a pass makes it, and each page is taken through
//! [`crate::at_relays::take_page`] and the one door. It differs from a
//! pass in three things:
//!
//! - **Its places are its own,** here, in memory, under the read's ID: at
//!   each relay it starts at the mark of no holding and the start, and it
//!   never writes the place that the device keeps there
//!   ([`crate::at_relays::Places::Own`]). The pass's place is left as it
//!   was.
//! - **It marks nothing as sent.** What it is handed is stored as any
//!   entry is, and how far each relay was sent the channel does not move
//!   for it.
//! - **It notes what each relay handed in each slot,** for the check
//!   before a let-go: each entry of the channel that the relay handed,
//!   whatever the door did with it.
//!
//! **The node reads, round by round, outside the database's lock**
//! (§4.2 item 3): it asks the relays for pages, within the budget of the
//! pass at each relay, and takes the database's lock only to take each
//! page, as a pass does. What it read is kept here between rounds, and a
//! command asks it to read on under the read's ID
//! ([`crate::state::OwnAsk`]). Nothing here opens a stream, and nothing
//! here knows a connection: a relay is the name that the device's
//! configuration gives it.
//!
//! **A round reads on only where a relay was read in part,** as a
//! recovery reads (§3.2): a relay that has handed the channel to its end,
//! that holds none of it, or that was not reached in a round, is not
//! asked again. Where the end of a relay's read is is what a carry's read
//! says it is (`read_left`): a page that holds nothing, or that leaves the
//! place where it was.
//!
//! **One read of a channel is kept at a time.** A read that begins
//! forgets any other of the same channel, so the reads that a node keeps
//! are at most as many as the channels of its own.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use cordelia_crypto::entry::CheckedEntry;
use cordelia_storage::relay::{Mark, NO_MARK};

use crate::person::PersonError;

/// What a read is named by: sixteen random bytes, so that a node that
/// was started again since a read was made knows no read by that ID.
pub type ReadId = [u8; 16];

/// Where a read stands at one relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAt {
    /// Read in part so far: the next round reads on from its place. A
    /// relay is so before the read's first round.
    Reading,
    /// It handed the channel to its end: a page that held nothing, or
    /// that left the place where it was.
    ToItsEnd,
    /// It holds none of the channel: it said so before it had handed
    /// anything of it.
    HoldsNone,
    /// Read in part, and not read on: it handed part of the channel and
    /// then said that it holds none of it, or handed a page of which
    /// nothing is the channel's, or was not reached in a round after it
    /// had handed something.
    InPart,
    /// It was not reached in a round before it had handed anything: not
    /// connected, no leave, or no answer. It is not asked again.
    NotReached,
}

impl ReadAt {
    /// Whether the next round reads on at the relay.
    pub fn reads_on(self) -> bool {
        self == Self::Reading
    }
}

/// What one page that a relay handed came to, as [`OwnAt::handed`] takes
/// it.
#[derive(Debug, Clone, Copy)]
pub enum Handed<'a> {
    /// A page of the channel, whose entries went through the one door.
    Page {
        /// Its entries, each of the channel.
        entries: &'a [CheckedEntry],
        /// What the relay handed, counted as it counts against its cap:
        /// each entry's content and ENTRY_OVERHEAD_BYTES.
        counted: u64,
        /// The mark of the holding that `next` is a place in.
        mark: Mark,
        /// The place to ask after next.
        next: u64,
    },
    /// What the relay handed is no page of the channel: something of it
    /// is no entry of the channel, or does not check. What it holds
    /// beyond is not known.
    NotThePage {
        /// What it handed, counted as for a page.
        counted: u64,
    },
}

/// What a read has of one relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnAt {
    /// The relay, by the name that the device's configuration gives it.
    pub relay: String,
    pub read: ReadAt,
    /// The mark of the relay's holding and the place to ask after next,
    /// as a pull keeps them. The read's own: no place that the device
    /// keeps is read or written for it.
    pub place: (Mark, u64),
    /// What the relay handed, counted as it counts against its cap.
    pub bytes: u64,
    /// Each entry of the channel that the relay handed, by its slot, once
    /// each, in the order handed: what the door did with it is not
    /// asked here.
    pub handed: BTreeMap<[u8; 32], Vec<CheckedEntry>>,
}

impl OwnAt {
    /// The relay called `relay`, before the read's first round: from the
    /// start, under the mark of no holding.
    pub fn new(relay: &str) -> Self {
        Self {
            relay: relay.to_string(),
            read: ReadAt::Reading,
            place: (NO_MARK, 0),
            bytes: 0,
            handed: BTreeMap::new(),
        }
    }

    /// Take what the relay handed to a pull asked from [`Self::place`].
    /// Returns whether the relay is asked for another page in this round.
    ///
    /// - The mark of no holding with nothing: the relay holds none of the
    ///   channel. Where it had handed part of it, the channel is read in
    ///   part there.
    /// - A page that holds nothing, or that leaves the place where it was,
    ///   is the channel's end there.
    /// - A page under another mark than the place was asked under is of
    ///   another holding: the relay dropped the channel and took it again,
    ///   and hands it from the start. What it handed before is kept.
    pub fn handed(&mut self, page: Handed) -> bool {
        let (entries, mark, next) = match page {
            Handed::NotThePage { counted } => {
                self.bytes += counted;
                self.read = ReadAt::InPart;
                return false;
            }
            Handed::Page {
                entries,
                counted,
                mark,
                next,
            } => {
                self.bytes += counted;
                (entries, mark, next)
            }
        };
        if mark == NO_MARK && entries.is_empty() {
            self.read = match self.handed.is_empty() {
                true => ReadAt::HoldsNone,
                false => ReadAt::InPart,
            };
            return false;
        }
        for entry in entries {
            let slot = self.handed.entry(entry.slot).or_default();
            if !slot.iter().any(|held| held.id() == entry.id()) {
                slot.push(entry.clone());
            }
        }
        if entries.is_empty() || (mark, next) == self.place {
            self.read = ReadAt::ToItsEnd;
            return false;
        }
        self.place = (mark, next);
        true
    }

    /// The relay was not reached in this round: it is not connected, there
    /// was no leave, or it did not answer. It is not asked again, and
    /// stays with what it handed.
    pub fn not_reached(&mut self) {
        self.read = match self.handed.is_empty() {
            true => ReadAt::NotReached,
            false => ReadAt::InPart,
        };
    }
}

/// A read of a channel of the device's own, as the node keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnRead {
    /// The channel's ID.
    pub channel: [u8; 32],
    /// What the change entry is named by that the device kept when the
    /// read began: the channel is one of that entry's statement, and
    /// nothing is asked of a relay for it under another.
    pub under: [u8; 32],
    /// Each relay that the device was set up with when the read began, in
    /// that order.
    pub at: Vec<OwnAt>,
    /// Whether a round of it is running.
    reading: bool,
}

impl OwnRead {
    /// What the read has of the relay called `relay`.
    pub fn at(&self, relay: &str) -> Option<&OwnAt> {
        self.at.iter().find(|at| at.relay == relay)
    }
}

/// The reads that the node keeps, each under its ID (see the module's
/// documentation).
#[derive(Debug, Default)]
pub struct OwnReads {
    reads: Mutex<HashMap<ReadId, OwnRead>>,
}

impl OwnReads {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ReadId, OwnRead>> {
        self.reads.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Begin a read of `channel`, which is of the statement of the change
    /// entry named `under`, at `relays`: each from the start, under the
    /// mark of no holding. A read of the same channel that is kept is
    /// forgotten. Returns the new read's ID: nothing is read until a
    /// round of it is taken ([`Self::to_read`]).
    pub fn begin(
        &self,
        channel: &[u8; 32],
        under: &[u8; 32],
        relays: &[String],
    ) -> Result<ReadId, PersonError> {
        let random = cordelia_crypto::generate_psk()?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&random[..16]);
        let read = OwnRead {
            channel: *channel,
            under: *under,
            at: relays.iter().map(|relay| OwnAt::new(relay)).collect(),
            reading: false,
        };
        let mut reads = self.lock();
        reads.retain(|_, kept| kept.channel != *channel);
        reads.insert(id, read);
        Ok(id)
    }

    /// Take a round of the read named `read`: the channel, the change
    /// entry it is read under, and what it has of each relay that is read
    /// on ([`ReadAt::reads_on`]). Each other relay stays as it was.
    /// `None` where the node keeps no such read, or a round of it is
    /// running.
    pub fn to_read(&self, read: &ReadId) -> Option<([u8; 32], [u8; 32], Vec<OwnAt>)> {
        let mut reads = self.lock();
        let kept = reads.get_mut(read).filter(|kept| !kept.reading)?;
        kept.reading = true;
        let on = kept
            .at
            .iter()
            .filter(|at| at.read.reads_on())
            .cloned()
            .collect();
        Some((kept.channel, kept.under, on))
    }

    /// A round of the read named `read` has ended, and `at` is what it
    /// read at each relay it asked. Where the read was forgotten in the
    /// meantime, nothing is kept of it.
    pub fn read(&self, read: &ReadId, at: Vec<OwnAt>) {
        let mut reads = self.lock();
        let Some(kept) = reads.get_mut(read) else {
            return;
        };
        for one in at {
            if let Some(was) = kept.at.iter_mut().find(|was| was.relay == one.relay) {
                *was = one;
            }
        }
        kept.reading = false;
    }

    /// The read named `read`, as it stands, where the node keeps it.
    pub fn get(&self, read: &ReadId) -> Option<OwnRead> {
        self.lock().get(read).cloned()
    }

    /// The read named `read` is kept no more.
    pub fn forget(&self, read: &ReadId) {
        self.lock().remove(read);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cordelia_crypto::entry::Value;

    use crate::several::{Several, entry_by, identity_of};

    const MARK: Mark = [0x4d, 1, 2, 3, 4, 5, 6, 7];
    const OTHER_MARK: Mark = [0x4e, 1, 2, 3, 4, 5, 6, 7];

    /// Entries of one channel: `n` of them, each in a slot of its own.
    fn entries(n: usize) -> Vec<CheckedEntry> {
        let by = identity_of(0);
        let channel = [0x5c; 32];
        (0..n)
            .map(|i| {
                let name = format!("{i}.md");
                entry_by(&by, &channel, 1, &name, Value::Text("a text".into()), &[])
            })
            .collect()
    }

    fn page(entries: &[CheckedEntry], mark: Mark, next: u64) -> Handed<'_> {
        Handed::Page {
            entries,
            counted: 10 * entries.len() as u64,
            mark,
            next,
        }
    }

    fn handed_ids(at: &OwnAt) -> Vec<[u8; 32]> {
        at.handed
            .values()
            .flatten()
            .map(|entry| entry.id())
            .collect()
    }

    /// A read starts at each relay from the start, under the mark of no
    /// holding, and goes on from the place that each page reaches. It
    /// counts what was handed.
    #[test]
    fn test_a_read_starts_from_the_start_and_goes_on_from_the_place_each_page_reaches() {
        let written = entries(4);
        let mut at = OwnAt::new("relay-one");
        assert_eq!(at.place, (NO_MARK, 0));
        assert_eq!(at.read, ReadAt::Reading);
        assert!(at.handed(page(&written[..2], MARK, 2)));
        assert_eq!(at.place, (MARK, 2));
        assert!(at.handed(page(&written[2..], MARK, 4)));
        assert_eq!(at.place, (MARK, 4));
        assert_eq!(at.read, ReadAt::Reading);
        assert_eq!(at.bytes, 40);
        assert_eq!(handed_ids(&at).len(), 4);
    }

    /// A page that holds nothing is the channel's end there, and so is one
    /// that leaves the place where it was. The place stays.
    #[test]
    fn test_a_relay_is_read_to_its_end_by_a_page_of_nothing_or_one_that_leaves_the_place() {
        let written = entries(3);
        let mut at = OwnAt::new("relay-one");
        assert!(at.handed(page(&written[..2], MARK, 2)));
        assert!(!at.handed(page(&[], MARK, 2)));
        assert_eq!(at.read, ReadAt::ToItsEnd);
        assert_eq!(at.place, (MARK, 2));

        // A page of nothing under another mark ends it too.
        let mut at = OwnAt::new("relay-one");
        assert!(at.handed(page(&written[..2], MARK, 2)));
        assert!(!at.handed(page(&[], OTHER_MARK, 0)));
        assert_eq!(at.read, ReadAt::ToItsEnd);

        let mut at = OwnAt::new("relay-one");
        assert!(at.handed(page(&written[..2], MARK, 2)));
        // The same place again, though it handed something.
        assert!(!at.handed(page(&written[2..], MARK, 2)));
        assert_eq!(at.read, ReadAt::ToItsEnd);
        assert_eq!(handed_ids(&at).len(), 3);
    }

    /// The mark of no holding with nothing: a relay that has handed
    /// nothing of the channel holds none of it. One that handed part of it
    /// and then says so leaves the channel read in part there.
    #[test]
    fn test_a_relay_that_holds_none_and_one_that_handed_part_and_then_holds_none() {
        let written = entries(2);
        let mut at = OwnAt::new("relay-one");
        assert!(!at.handed(page(&[], NO_MARK, 0)));
        assert_eq!(at.read, ReadAt::HoldsNone);

        let mut at = OwnAt::new("relay-one");
        assert!(at.handed(page(&written, MARK, 2)));
        assert!(!at.handed(page(&[], NO_MARK, 0)));
        assert_eq!(at.read, ReadAt::InPart);
        assert_eq!(handed_ids(&at).len(), 2);
    }

    /// A page under another mark than the place was asked under is of
    /// another holding, handed from the start: the read goes on from its
    /// place there, and keeps what was handed before.
    #[test]
    fn test_a_page_under_another_mark_is_read_on_and_what_was_handed_before_is_kept() {
        let written = entries(3);
        let mut at = OwnAt::new("relay-one");
        assert!(at.handed(page(&written[..2], MARK, 2)));
        assert!(at.handed(page(&written[2..], OTHER_MARK, 1)));
        assert_eq!(at.place, (OTHER_MARK, 1));
        assert_eq!(at.read, ReadAt::Reading);
        assert_eq!(handed_ids(&at).len(), 3);
    }

    /// A page of which something is not the channel's leaves the relay
    /// read in part, and it is not read on: what it holds beyond is not
    /// known. What it handed is counted.
    #[test]
    fn test_a_page_that_is_not_the_channels_leaves_the_relay_read_in_part() {
        let written = entries(2);
        let mut at = OwnAt::new("relay-one");
        assert!(at.handed(page(&written, MARK, 2)));
        assert!(!at.handed(Handed::NotThePage { counted: 7 }));
        assert_eq!(at.read, ReadAt::InPart);
        assert!(!at.read.reads_on());
        assert_eq!(at.bytes, 27);
        assert_eq!(at.place, (MARK, 2));
    }

    /// What a relay handed is noted in each slot, each entry once: two
    /// entries of one slot are both kept, and an entry handed again is
    /// not kept twice.
    #[test]
    fn test_what_each_relay_handed_is_noted_in_each_slot() {
        let mut s = Several::of_one_person(2);
        s.hold(&[0, 1], "notes");
        let first = s.write(0, "notes", "a.md", "by device 0");
        let second = s.write(1, "notes", "a.md", "by device 1");
        let other = s.write(0, "notes", "b.md", "by device 0");
        assert_eq!(first.slot, second.slot);
        let mut at = OwnAt::new("relay-one");
        let both = [first.clone(), other.clone()];
        assert!(at.handed(page(&both, MARK, 2)));
        assert!(at.handed(page(std::slice::from_ref(&second), MARK, 3)));
        // From the start under another holding: what it hands again is not
        // kept twice.
        assert!(at.handed(page(&both, OTHER_MARK, 2)));
        assert_eq!(at.handed.len(), 2);
        let ids = |slot: &[u8; 32]| -> Vec<[u8; 32]> {
            at.handed[slot].iter().map(|entry| entry.id()).collect()
        };
        assert_eq!(ids(&first.slot), [first.id(), second.id()]);
        assert_eq!(ids(&other.slot), [other.id()]);
    }

    /// A relay that was not reached in a round is not read on: with
    /// nothing handed it is not reached, and with something handed the
    /// channel is read in part there.
    #[test]
    fn test_a_relay_not_reached_in_a_round_is_not_read_on() {
        let written = entries(2);
        let mut at = OwnAt::new("relay-one");
        at.not_reached();
        assert_eq!(at.read, ReadAt::NotReached);
        assert!(!at.read.reads_on());

        let mut at = OwnAt::new("relay-one");
        assert!(at.handed(page(&written, MARK, 2)));
        at.not_reached();
        assert_eq!(at.read, ReadAt::InPart);
        assert_eq!(handed_ids(&at).len(), 2);
    }

    /// A read is kept under its ID, with its places: a round takes the
    /// relays that are read on, and no other, and gives them back. While a
    /// round runs no other is taken. A read that begins of the same
    /// channel takes the place of the one before, and another channel's
    /// read stays. A read that is forgotten, or was never made, is not
    /// known.
    #[test]
    fn test_a_read_is_kept_under_its_id_and_a_new_read_of_its_channel_takes_its_place() {
        let reads = OwnReads::default();
        let relays = ["relay-one".to_string(), "relay-two".to_string()];
        let (channel, other, under) = ([1; 32], [2; 32], [3; 32]);
        let id = reads.begin(&channel, &under, &relays).unwrap();
        let kept = reads.get(&id).unwrap();
        assert_eq!((kept.channel, kept.under), (channel, under));
        assert!(kept.at.iter().all(|at| *at == OwnAt::new(&at.relay)));

        let (read_channel, read_under, mut at) = reads.to_read(&id).unwrap();
        assert_eq!((read_channel, read_under), (channel, under));
        assert_eq!(at.len(), 2);
        assert_eq!(reads.to_read(&id), None);
        let written = entries(2);
        assert!(at[0].handed(page(&written, MARK, 2)));
        at[1].not_reached();
        reads.read(&id, at);

        // The next round reads on at the first relay alone, from its
        // place.
        let (_, _, at) = reads.to_read(&id).unwrap();
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].relay, "relay-one");
        assert_eq!(at[0].place, (MARK, 2));
        reads.read(&id, at);
        let kept = reads.get(&id).unwrap();
        assert_eq!(kept.at("relay-two").unwrap().read, ReadAt::NotReached);
        assert_eq!(kept.at("relay-one").unwrap().place, (MARK, 2));

        // Another channel's read stays; a new read of this channel takes
        // the place of the first.
        let of_other = reads.begin(&other, &under, &relays).unwrap();
        let again = reads.begin(&channel, &under, &relays).unwrap();
        assert_ne!(again, id);
        assert_eq!(reads.get(&id), None);
        assert_eq!(reads.to_read(&id), None);
        assert!(reads.get(&of_other).is_some());
        assert_eq!(
            reads.get(&again).unwrap().at("relay-one").unwrap().place,
            (NO_MARK, 0)
        );

        // What a round of a read that was forgotten read is not kept.
        let (_, _, at) = reads.to_read(&again).unwrap();
        reads.forget(&again);
        reads.read(&again, at);
        assert_eq!(reads.get(&again), None);
        assert_eq!(reads.get(&[9; 16]), None);
    }
}
