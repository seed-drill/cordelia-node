//! What a device took before it knew of a removal (decision 2026-10-24
//! (removal), rules 2, 6 and 7).
//!
//! Each removed key has a **cut time** (rule 2): for each change the device
//! noted that removes it, the time of the change on that change's chain
//! that first removes the key, where the device noted it and the change
//! before it; otherwise the time of the newest change on that chain that it
//! noted and that does not remove the key. Less `REMOVAL_TAKEN_MARGIN_SECS`.
//! Of several, the earliest. Where no such change has a time there is none,
//! and everything of the key's is cut. A key that rule 6 removed (a removed
//! key's record added it after that key's cut time) has its adder's cut.
//!
//! [`Cuts::cuts`] says whether what a removed key wrote, or added, and that
//! this device took at a time in a generation, is cut: where it came in a
//! generation that is no removal of the key and was made after none, and
//! 1. made apart from a change that removed the key; or
//! 2. that such a change was made after, at or after the key's cut time, or
//!    at any time where there is none.
//!
//! What it does not know fails safe: a generation whose chain it did not
//! note is taken as made apart, and a key that no noted change removes has
//! everything cut. A record taken before the cut time stays, and so does
//! what came in a generation made after the removal: the key was known to
//! be removed there.

use std::collections::BTreeMap;

use rusqlite::Connection;

use cordelia_core::protocol::REMOVAL_TAKEN_MARGIN_SECS;
use cordelia_crypto::entry::Link as EntryLink;
use cordelia_storage::person::{self as held_rows, NotedChange};

use crate::person::PersonError;

/// A change by its statement's number and hash.
pub(crate) type Change = (u64, [u8; 16]);

/// The cut of one removed key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyCut {
    pub(crate) key: [u8; 32],
    /// The first 16 bytes of the key, as a link names it.
    pub(crate) signer: [u8; 16],
    /// The cut time; `None`: everything of the key's is cut in a generation
    /// that a removal of it was made after.
    pub(crate) at: Option<i64>,
    /// Each noted change that removes the key, with its chain. Empty where
    /// none is noted: then everything of the key's is cut.
    removals: Vec<(Change, Vec<Change>)>,
}

/// The cut of every key a device knows to be removed, and the chain of
/// each change it noted.
#[derive(Debug, Clone, Default)]
pub(crate) struct Cuts {
    keys: Vec<KeyCut>,
    chains: BTreeMap<Change, Option<Vec<Change>>>,
    /// The keys each noted change lists as devices.
    devices: BTreeMap<Change, Vec<[u8; 32]>>,
}

impl Cuts {
    /// What this device knows, as its database holds it.
    pub(crate) fn read(conn: &Connection) -> Result<Self, PersonError> {
        let noted = held_rows::changes_noted(conn)?;
        let removed = held_rows::removed_with_adders(conn)?;
        Ok(Self::of(&noted, &removed))
    }

    /// The cuts of `removed`, each with the key whose record added it where
    /// rule 6 removed it, from the changes `noted`.
    pub(crate) fn of(noted: &[NotedChange], removed: &[([u8; 32], Option<[u8; 32]>)]) -> Self {
        let by_change: BTreeMap<Change, &NotedChange> = noted
            .iter()
            .map(|change| ((change.number, change.hash), change))
            .collect();
        let chains = noted
            .iter()
            .map(|change| ((change.number, change.hash), change.chain.clone()))
            .collect();
        let devices = noted
            .iter()
            .filter_map(|change| Some(((change.number, change.hash), change.devices.clone()?)))
            .collect();
        let own_cut = |key: &[u8; 32]| -> (Option<i64>, Vec<(Change, Vec<Change>)>) {
            let mut removals = Vec::new();
            let mut at: Option<Option<i64>> = None;
            for change in noted {
                let (Some(lists), Some(chain)) = (&change.removed, &change.chain) else {
                    continue;
                };
                if !lists.contains(key) {
                    continue;
                }
                let this = (change.number, change.hash);
                removals.push((this, chain.clone()));
                let time = time_of(&by_change, key, chain, this);
                at = Some(match (at, time) {
                    (None, time) => time,
                    (Some(None), _) | (Some(_), None) => None,
                    (Some(Some(kept)), Some(time)) => Some(kept.min(time)),
                });
            }
            let at = at
                .flatten()
                .map(|at| at.saturating_sub(REMOVAL_TAKEN_MARGIN_SECS as i64));
            (at, removals)
        };
        let adders: BTreeMap<[u8; 32], Option<[u8; 32]>> = removed.iter().copied().collect();
        let mut keys = Vec::new();
        for (key, _) in removed {
            // A key that rule 6 removed has the cut of the key whose record
            // added it, and so on back to a key a change removed. A loop
            // (which no honest database holds) cuts everything.
            let mut from = *key;
            let mut steps = 0;
            while let Some(Some(adder)) = adders.get(&from) {
                from = *adder;
                steps += 1;
                if steps > removed.len() {
                    break;
                }
            }
            let (at, removals) = match steps > removed.len() {
                true => (None, Vec::new()),
                false => own_cut(&from),
            };
            keys.push(KeyCut {
                key: *key,
                signer: EntryLink::signer_of(key),
                at,
                removals,
            });
        }
        Self {
            keys,
            chains,
            devices,
        }
    }

    /// Whether `key`, which the removed key `adder` added by a record, is
    /// listed as a device by a noted change that removes `adder`, or by one
    /// on the chain of such a change (rule 6): the person put it in the
    /// history that leads to the removal, with the phrase, and it is not a
    /// key that `adder` added alone. A key that only a change made apart
    /// from every removal lists is not.
    pub(crate) fn listed_toward_a_removal(&self, adder: &[u8; 32], key: &[u8; 32]) -> bool {
        let Some(cut) = self.of_key(adder) else {
            return false;
        };
        let lists = |change: &Change| {
            self.devices
                .get(change)
                .is_some_and(|devices| devices.contains(key))
        };
        cut.removals
            .iter()
            .any(|(removal, chain)| lists(removal) || chain.iter().any(lists))
    }

    /// The cut of `key`, where the device knows it to be removed.
    pub(crate) fn of_key(&self, key: &[u8; 32]) -> Option<&KeyCut> {
        self.keys.iter().find(|cut| cut.key == *key)
    }

    /// Every removed key's cut.
    pub(crate) fn keys(&self) -> &[KeyCut] {
        &self.keys
    }

    /// Whether what `cut`'s key wrote or added, taken by this device at
    /// `at` in the generation `generation`, is cut (rules 6 and 7).
    pub(crate) fn cuts(&self, cut: &KeyCut, generation: &Change, at: i64) -> bool {
        if cut.removals.is_empty() {
            return true;
        }
        let generation_chain = self.chains.get(generation).cloned().flatten();
        // A generation that is a removal of the key, or made after one,
        // knew it to be removed: nothing of it is cut there. Every later
        // change lists the key as removed (rule 20), so without this a
        // generation made after the first removal, which is on the chain of
        // the next, would be judged by time, and honest arrivals there cut
        // again at every later change.
        let after_a_removal = cut.removals.iter().any(|(removal, _)| {
            removal == generation
                || generation_chain
                    .as_ref()
                    .is_some_and(|chain| chain.contains(removal))
        });
        if after_a_removal {
            return false;
        }
        for (_, chain) in &cut.removals {
            if chain.contains(generation) {
                // A generation the removal was made after: by time.
                if cut.at.is_none_or(|from| at >= from) {
                    return true;
                }
                continue;
            }
            // Neither on its chain nor after it: made apart from the
            // removal, or not known. Cut.
            return true;
        }
        false
    }

    /// Whether what `key` wrote or added, taken at `at` in `generation`,
    /// is cut: `false` for a key this device does not know to be removed.
    pub(crate) fn cuts_key(&self, key: &[u8; 32], generation: &Change, at: i64) -> bool {
        self.of_key(key)
            .is_some_and(|cut| self.cuts(cut, generation, at))
    }
}

/// The time that the removal `removal`, whose chain is `chain`, gives
/// `key`'s cut (rule 2), before the margin: `None` where it gives none.
fn time_of(
    noted: &BTreeMap<Change, &NotedChange>,
    key: &[u8; 32],
    chain: &[Change],
    removal: Change,
) -> Option<i64> {
    let links: Vec<Change> = chain.iter().copied().chain([removal]).collect();
    // Whether the device noted the change and its lists, and they remove
    // the key.
    let removes = |change: &Change| -> Option<bool> {
        let noted = noted.get(change)?;
        Some(noted.removed.as_ref()?.contains(key))
    };
    let made_at = |change: &Change| noted.get(change).and_then(|noted| noted.made_at);
    let first = links
        .iter()
        .position(|change| removes(change) == Some(true))?;
    if first > 0
        && removes(&links[first - 1]) == Some(false)
        && let Some(time) = made_at(&links[first])
    {
        return Some(time);
    }
    links[..first]
        .iter()
        .filter(|change| removes(change) == Some(false))
        .filter_map(made_at)
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARGIN: i64 = REMOVAL_TAKEN_MARGIN_SECS as i64;

    fn change(number: u64, made_at: Option<i64>, removed: &[u8], chain: &[u64]) -> NotedChange {
        NotedChange {
            number,
            hash: [number as u8; 16],
            made_at,
            removed: Some(removed.iter().map(|k| [*k; 32]).collect()),
            chain: Some(chain.iter().map(|n| (*n, [*n as u8; 16])).collect()),
            devices: Some(Vec::new()),
        }
    }

    fn at(number: u64) -> Change {
        (number, [number as u8; 16])
    }

    /// The cut time is the time of the change that first removes the key,
    /// where it and the one before it are noted (decision 2026-10-24
    /// (removal), rule 2, unit test 12).
    #[test]
    fn the_cut_time_is_of_the_change_that_first_removes_the_key() {
        let noted = [
            change(2, Some(100), &[], &[1]),
            change(3, Some(5_000), &[9], &[1, 2]),
            change(4, Some(9_000), &[9], &[1, 2, 3]),
        ];
        let cuts = Cuts::of(&noted, &[([9; 32], None)]);
        assert_eq!(cuts.of_key(&[9; 32]).unwrap().at, Some(5_000 - MARGIN));
    }

    /// Where only a later change is noted, the cut is from the newest
    /// earlier change noted that does not remove the key.
    #[test]
    fn a_later_change_alone_cuts_from_an_earlier_one() {
        let noted = [
            change(2, Some(100), &[], &[1]),
            change(4, Some(9_000), &[9], &[1, 2, 3]),
        ];
        let cuts = Cuts::of(&noted, &[([9; 32], None)]);
        assert_eq!(cuts.of_key(&[9; 32]).unwrap().at, Some(100 - MARGIN));
    }

    /// Where no change on the chain has a time, there is none: everything
    /// of the key's in a generation the removal was made after is cut.
    #[test]
    fn no_time_on_the_chain_cuts_everything() {
        let noted = [change(2, None, &[], &[1]), change(3, None, &[9], &[1, 2])];
        let cuts = Cuts::of(&noted, &[([9; 32], None)]);
        let cut = cuts.of_key(&[9; 32]).unwrap();
        assert_eq!(cut.at, None);
        assert!(cuts.cuts(cut, &at(2), i64::MIN));
    }

    /// In a generation the removal was made after, an arrival one second
    /// before the cut time is kept and one at it is cut; in one made apart
    /// everything is cut; in one made after the removal nothing is.
    #[test]
    fn what_is_cut_goes_by_the_generation_and_the_time() {
        let mut apart = change(3, Some(4_000), &[], &[1, 2]);
        apart.hash = [0x33; 16];
        let noted = [
            change(2, Some(100), &[], &[1]),
            change(3, Some(5_000), &[9], &[1, 2]),
            apart,
            change(4, Some(6_000), &[9], &[1, 2, 3]),
        ];
        let cuts = Cuts::of(&noted, &[([9; 32], None), ([7; 32], Some([9; 32]))]);
        let cut = cuts.of_key(&[9; 32]).unwrap();
        let from = 5_000 - MARGIN;
        assert!(!cuts.cuts(cut, &at(2), from - 1));
        assert!(cuts.cuts(cut, &at(2), from));
        assert!(cuts.cuts(cut, &(3, [0x33; 16]), 0));
        assert!(!cuts.cuts(cut, &at(4), i64::MAX));
        // A key that the removed key added has its cut.
        let added = cuts.of_key(&[7; 32]).unwrap();
        assert_eq!(added.at, Some(from));
        assert!(cuts.cuts(added, &at(2), from));
        assert!(!cuts.cuts(added, &at(2), from - 1));
        // A key this device does not know to be removed is cut nowhere.
        assert!(!cuts.cuts_key(&[8; 32], &at(2), i64::MAX));
    }

    /// A generation that is a removal of the key, or made after one, cuts
    /// nothing of it, though a later change that lists the key again has
    /// that generation on its chain (rule 20): honest arrivals made after
    /// the first removal are not cut again at every later change.
    #[test]
    fn a_generation_after_a_removal_cuts_nothing_of_the_key() {
        let noted = [
            change(2, Some(100), &[], &[1]),
            change(3, Some(5_000), &[9], &[1, 2]),
            change(4, Some(9_000), &[9], &[1, 2, 3]),
            change(5, Some(9_500), &[9], &[1, 2, 3, 4]),
        ];
        let cuts = Cuts::of(&noted, &[([9; 32], None)]);
        let long_after = 1_000_000;
        assert!(!cuts.cuts_key(&[9; 32], &at(3), long_after));
        assert!(!cuts.cuts_key(&[9; 32], &at(4), long_after));
        // Before the first removal it is still cut by time.
        assert!(cuts.cuts_key(&[9; 32], &at(2), long_after));
        assert!(!cuts.cuts_key(&[9; 32], &at(2), 5_000 - MARGIN - 1));
    }

    /// A key that no noted change removes has everything cut.
    #[test]
    fn a_key_no_noted_change_removes_is_cut_everywhere() {
        let noted = [change(2, Some(100), &[], &[1])];
        let cuts = Cuts::of(&noted, &[([9; 32], None)]);
        assert!(cuts.cuts_key(&[9; 32], &at(2), 0));
    }
}
