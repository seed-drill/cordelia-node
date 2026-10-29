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
    /// Each noted change by its number and its statement's commitment to
    /// its secret, where that was noted.
    by_commitment: BTreeMap<(u64, [u8; 32]), Change>,
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
        let by_commitment = noted
            .iter()
            .filter_map(|change| {
                Some((
                    (change.number, change.commitment?),
                    (change.number, change.hash),
                ))
            })
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
            by_commitment,
        }
    }

    /// The change of the generation numbered `number` whose person secret
    /// is `secret`, where the device noted it with its commitment: `None`
    /// where it did not, and the generation is not known.
    pub(crate) fn generation_of(&self, number: u64, secret: &[u8; 32]) -> Option<Change> {
        let commitment = cordelia_crypto::statement::commitment(secret);
        self.by_commitment.get(&(number, commitment)).copied()
    }

    /// Whether a version read in `generation` of a channel left, by a
    /// carry that a command makes at `now`, is left out (the second read
    /// of slice 8, its second finding): a key that `signers` names, or that
    /// a link of `chains` names, is cut there at that time. What a command
    /// reads there has no time of arrival, so it is judged at its own: in a
    /// generation that a removal of the key was made after, everything of
    /// the key's is left out; in one that is a removal, or made after one,
    /// nothing; and in one made apart, or not known (`None`), everything.
    /// A key of `named` is not judged: the person named it, with the
    /// phrase, as one whose writing is theirs (a recovery's look takes what
    /// a device lost or broken wrote, decision 2026-10-04 §9).
    pub(crate) fn leaves_out(
        &self,
        signers: &[[u8; 32]],
        chains: &[&[EntryLink]],
        generation: Option<&Change>,
        now: i64,
        named: &[[u8; 32]],
    ) -> bool {
        let cut = |key: &KeyCut| {
            !named.contains(&key.key)
                && match generation {
                    Some(generation) => self.cuts(key, generation, now),
                    None => true,
                }
        };
        signers
            .iter()
            .filter_map(|signer| self.of_key(signer))
            .any(cut)
            || chains.iter().flat_map(|chain| chain.iter()).any(|link| {
                self.keys
                    .iter()
                    .filter(|key| key.signer == link.signer)
                    .any(cut)
            })
    }

    /// Whether `key`, which the removed key `adder` added by a record, is
    /// listed as a device by **every** noted change that removes `adder`
    /// (rule 6): the person kept it with the phrase in each change that
    /// removed its adder, and it is not a key that `adder` added alone. For
    /// a key that rule 6 removed, the changes are those that remove the key
    /// it goes back to. A key that only a change on such a change's chain
    /// lists, or a change made apart from every removal, is not: one the
    /// person dropped from the list, and the removed device added again,
    /// holds the secret by its record alone.
    ///
    /// **Every, and not any** (the second read of slice 8, its third
    /// finding). A removal can list a key only where the key existed when
    /// it was made, so a removal made before `adder` added `key` never
    /// lists it: a key that `adder` added after one of its removals is
    /// spared nowhere that removal is noted, whatever another removal made
    /// apart lists. One removal alone spares only a key that existed when
    /// it was made, and that the person kept there: `cordelia
    /// remove-device` asks of each key the device removed added, and says
    /// that the device being removed added it.
    pub(crate) fn listed_toward_a_removal(&self, adder: &[u8; 32], key: &[u8; 32]) -> bool {
        let Some(cut) = self.of_key(adder) else {
            return false;
        };
        !cut.removals.is_empty()
            && cut.removals.iter().all(|(removal, _)| {
                self.devices
                    .get(removal)
                    .is_some_and(|devices| devices.contains(key))
            })
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

/// What a device cuts now, in the generation it follows (rules 6 and 7),
/// for a reader that knows no time of arrival: the put-back of an index
/// line. It judges at `now`, the latest anything came, which fails safe. In
/// a generation that is a removal of a key, or made after one, nothing of
/// that key is cut (the key was known removed there, and its entries were
/// refused); before it, what such a key signed or a chain names is cut.
/// Where the device follows no change, every removed key is cut.
#[derive(Debug, Clone)]
pub struct CutNow {
    cuts: Cuts,
    generation: Option<Change>,
    now: i64,
}

impl CutNow {
    /// What the device whose database is `conn` cuts at `now`.
    pub fn read(conn: &Connection, now: i64) -> Result<Self, PersonError> {
        let generation = match crate::person::held(conn)? {
            Some(held) => {
                let link = held.statement.statement.link()?;
                Some((link.number, link.hash))
            }
            None => None,
        };
        Ok(Self {
            cuts: Cuts::read(conn)?,
            generation,
            now,
        })
    }

    /// Whether what `key` signed is cut.
    pub fn key(&self, key: &[u8; 32]) -> bool {
        self.cuts.of_key(key).is_some_and(|cut| self.cut(cut))
    }

    /// Whether what the key whose first 16 bytes are `signer` signed, as a
    /// link names it, is cut.
    pub fn signer(&self, signer: &[u8; 16]) -> bool {
        self.cuts
            .keys()
            .iter()
            .filter(|cut| cut.signer == *signer)
            .any(|cut| self.cut(cut))
    }

    fn cut(&self, cut: &KeyCut) -> bool {
        match &self.generation {
            Some(generation) => self.cuts.cuts(cut, generation, self.now),
            None => true,
        }
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
    // A change's time, by its maker's clock, no later than that of any
    // noted change made after it (the second read of slice 8, a low
    // finding): an honest change made on a fast clock does not move the
    // cut later than a change that followed it, the removal among them.
    let made_at = |change: &Change| -> Option<i64> {
        let own = noted.get(change)?.made_at?;
        let after = noted
            .values()
            .filter(|later| {
                later
                    .chain
                    .as_ref()
                    .is_some_and(|chain| chain.contains(change))
            })
            .filter_map(|later| later.made_at)
            .min();
        Some(after.map_or(own, |after| own.min(after)))
    };
    let first = links
        .iter()
        .position(|change| removes(change) == Some(true))?;
    if first > 0
        && removes(&links[first - 1]) == Some(false)
        && let Some(time) = made_at(&links[first])
    {
        return Some(time);
    }
    // The newest change on the chain, by the chain's order, that the
    // device noted with its time and that does not remove the key: not
    // the latest time of any, which a fast clock on an older change gives.
    links[..first]
        .iter()
        .rev()
        .filter(|change| removes(change) == Some(false))
        .find_map(made_at)
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
            commitment: None,
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

    /// The cut time goes by the chain's order, and no change's time is
    /// later than that of a noted change made after it (the second read of
    /// slice 8, a low finding): an honest change 2 made on a clock that is
    /// fast does not move the cut later than the removal, change 4; and of
    /// the changes before it, the newest gives the time, not the latest.
    #[test]
    fn the_cut_time_goes_by_the_chain_and_no_later_than_a_change_after() {
        let noted = [
            change(1, Some(100), &[], &[]),
            change(2, Some(90_000), &[], &[1]),
            change(4, Some(6_000), &[9], &[1, 2, 3]),
        ];
        let cuts = Cuts::of(&noted, &[([9; 32], None)]);
        assert_eq!(cuts.of_key(&[9; 32]).unwrap().at, Some(6_000 - MARGIN));
        let noted = [
            change(1, Some(5_000), &[], &[]),
            change(2, Some(4_000), &[], &[1]),
            change(4, Some(6_000), &[9], &[1, 2, 3]),
        ];
        let cuts = Cuts::of(&noted, &[([9; 32], None)]);
        assert_eq!(cuts.of_key(&[9; 32]).unwrap().at, Some(4_000 - MARGIN));
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

    /// Rule 6 spares a key that a removal of its adder lists, and not one
    /// that only a change on that removal's chain lists: one the person
    /// dropped from the list there, and the removed key added again.
    #[test]
    fn a_key_is_spared_only_where_a_removal_of_its_adder_lists_it() {
        let mut dropped_later = change(3, Some(4_000), &[], &[1, 2]);
        dropped_later.devices = Some(vec![[6; 32]]);
        let mut removal = change(4, Some(5_000), &[9], &[1, 2, 3]);
        removal.devices = Some(vec![[0; 32], [5; 32]]);
        let noted = [change(2, Some(100), &[], &[1]), dropped_later, removal];
        let cuts = Cuts::of(&noted, &[([9; 32], None), ([7; 32], Some([9; 32]))]);
        assert!(cuts.listed_toward_a_removal(&[9; 32], &[5; 32]));
        assert!(!cuts.listed_toward_a_removal(&[9; 32], &[6; 32]));
        // A key that rule 6 removed goes back to its adder's removals.
        assert!(cuts.listed_toward_a_removal(&[7; 32], &[5; 32]));
        assert!(!cuts.listed_toward_a_removal(&[8; 32], &[5; 32]));
    }

    /// Of two removals made apart, a key is spared only where both list it
    /// (the second read of slice 8, its third finding): one that lists the
    /// key does not spare it where the other, made before the key was
    /// added, cannot.
    #[test]
    fn a_key_is_spared_only_where_every_removal_of_its_adder_lists_it() {
        let mut here = change(3, Some(6_000), &[9], &[1, 2]);
        here.hash = [0x33; 16];
        here.devices = Some(vec![[0; 32], [5; 32]]);
        let mut apart = change(3, Some(5_000), &[9], &[1, 2]);
        apart.devices = Some(vec![[0; 32]]);
        let noted = [change(2, Some(100), &[], &[1]), here.clone()];
        let removed = [([9; 32], None)];
        assert!(Cuts::of(&noted, &removed).listed_toward_a_removal(&[9; 32], &[5; 32]));
        let noted = [change(2, Some(100), &[], &[1]), here, apart];
        assert!(!Cuts::of(&noted, &removed).listed_toward_a_removal(&[9; 32], &[5; 32]));
    }

    /// What the put-back of an index line judges by (`CutNow`): in a
    /// generation before the removal, what the key signed or a chain names
    /// is cut at the time now; in the removal's generation, or one made
    /// after it, nothing; where the device follows no change, everything.
    #[test]
    fn what_is_cut_now_goes_by_the_generation_followed() {
        let noted = [
            change(2, Some(100), &[], &[1]),
            change(3, Some(5_000), &[9], &[1, 2]),
            change(4, Some(9_000), &[9], &[1, 2, 3]),
        ];
        let cuts = Cuts::of(&noted, &[([9; 32], None)]);
        let now = |generation: Option<Change>| CutNow {
            cuts: cuts.clone(),
            generation,
            now: 1_000_000,
        };
        let signer = EntryLink::signer_of(&[9; 32]);
        for generation in [Some(at(2)), None] {
            assert!(now(generation).key(&[9; 32]));
            assert!(now(generation).signer(&signer));
        }
        for generation in [at(3), at(4)] {
            assert!(!now(Some(generation)).key(&[9; 32]));
            assert!(!now(Some(generation)).signer(&signer));
        }
        assert!(!now(Some(at(2))).key(&[8; 32]));
    }

    /// What a carry by command leaves out (the second read of slice 8, its
    /// second finding): a version read in a generation the removal was made
    /// after, whose signer or a link of whose chain is the removed key, at
    /// the command's own time; in the removal's generation, nothing; in a
    /// generation not known, everything of the key's. A generation is known
    /// by its statement's commitment to its secret.
    #[test]
    fn a_carry_by_command_judges_where_the_version_was_read() {
        let mut removal = change(3, Some(5_000), &[9], &[1, 2]);
        removal.commitment = Some(cordelia_crypto::statement::commitment(&[3; 32]));
        let mut before = change(2, Some(100), &[], &[1]);
        before.commitment = Some(cordelia_crypto::statement::commitment(&[2; 32]));
        let cuts = Cuts::of(&[before, removal], &[([9; 32], None)]);
        assert_eq!(cuts.generation_of(2, &[2; 32]), Some(at(2)));
        assert_eq!(cuts.generation_of(3, &[3; 32]), Some(at(3)));
        assert_eq!(cuts.generation_of(3, &[2; 32]), None);
        let named = [EntryLink {
            hash: [1; 16],
            signer: EntryLink::signer_of(&[9; 32]),
        }];
        let honest: [[u8; 32]; 1] = [[4; 32]];
        let now = 1_000_000;
        // Signed by it, or over it, in the generation before: left out.
        assert!(cuts.leaves_out(&[[9; 32]], &[], Some(&at(2)), now, &[]));
        assert!(cuts.leaves_out(&honest, &[&named], Some(&at(2)), now, &[]));
        // In the removal's generation: nothing.
        assert!(!cuts.leaves_out(&honest, &[&named], Some(&at(3)), now, &[]));
        // Not known: everything of the key's.
        assert!(cuts.leaves_out(&honest, &[&named], None, now, &[]));
        // What names no removed key is never left out.
        assert!(!cuts.leaves_out(&honest, &[], None, now, &[]));
        // Nor what the person named the key to take from.
        assert!(!cuts.leaves_out(&[[9; 32]], &[&named], None, now, &[[9; 32]]));
    }

    /// A key that no noted change removes has everything cut.
    #[test]
    fn a_key_no_noted_change_removes_is_cut_everywhere() {
        let noted = [change(2, Some(100), &[], &[1])];
        let cuts = Cuts::of(&noted, &[([9; 32], None)]);
        assert!(cuts.cuts_key(&[9; 32], &at(2), 0));
    }
}
