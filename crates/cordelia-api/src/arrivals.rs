//! The arrivals of each file, and the cut at a carry (decision 2026-10-24
//! (removal), rule 7).
//!
//! **At the door** ([`noted_at_the_door`]), an entry that another key signed
//! in the channel of a name makes arrivals: the version, with its signer,
//! and each link of its chain that stands there more times than in any
//! chain of the file stored before (a link is only a text's hash and its
//! signer, so a text written back stands again). Where its chain is full
//! (100 links), the other keys its links name are kept with it: a removed
//! key's link there is cut all the same. An entry whose chain may have
//! dropped links ([`crate::cut::may_have_dropped_links`]: missing, full,
//! or the index's) is marked, and judged as an arrival of every removed
//! key. With them are kept the generation
//! the device was in, when it stored the entry, and the version that was
//! current in the file before it. The device's own versions make none.
//!
//! **At a carry** ([`cut_of_channel`]), each file is judged by its
//! arrivals, by the cut of each removed key ([`crate::cut::Cuts`]). The
//! file goes back to the version that was current before its first arrival
//! that is cut, and that arrival and everything stored after it in the file
//! are left out: the carry carries the version gone back to, or nothing, and
//! a folder that holds the file takes that version back
//! (`cordelia_storage::sync_state::save_put_back`), with what it held kept
//! in local history alone. What the bound let go of a file is judged as an
//! arrival of every removed key at the newest time that went: where it is
//! cut, the file goes back to the version before the first event that went,
//! which is kept with it. A version gone back to that nothing kept brought
//! is judged at the cut's own time, by its signers and the keys its chain
//! names, and where one is cut the file goes back to none. The arrivals that
//! are not cut go with the file to the channel it is carried to.
//!
//! **What the device wrote itself** (rule 27, the person's ruling of 30
//! October). Each version it writes in the channel of a name is kept as an
//! event of its own ([`noted_own`]). At a carry, the window of each
//! removed key ([`windows`]) opens at the first arrival, in any name and
//! any generation, that the cut leaves out for that key, or at the first
//! message of the key's that the device held where it is cut, and closes
//! when the device first kept the key as removed. Every version of its own
//! stored in a window, in any generation, is set aside: the file goes back
//! to the version current before the first, as for an arrival cut.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::Connection;

use cordelia_core::protocol::MAX_ENTRY_LINKS;
use cordelia_crypto::entry::{CheckedEntry, Entry, Link, Value};
use cordelia_crypto::version::{self, Version, VersionEntry};
use cordelia_storage::arrivals::{self as kept, Arrival};
use cordelia_storage::entries;

use crate::cut::{Change, Cuts};
use crate::person::{Counting, PersonError};

/// A link by its hash and its signer.
type LinkOf = ([u8; 16], [u8; 16]);

/// What the door read of a file before it stored an entry there.
pub(crate) struct Before {
    /// The version current before, as one of its entries: this device's own
    /// where it holds one, and otherwise the first.
    current: Option<Entry>,
    /// The most times each link, by hash and signer, stands in a chain of a
    /// version the file holds.
    times: HashMap<LinkOf, u32>,
}

/// How many times each link stands in `chain`.
fn counted(chain: &[Link]) -> HashMap<LinkOf, u32> {
    let mut times = HashMap::new();
    for link in chain {
        *times.entry((link.hash, link.signer)).or_insert(0) += 1;
    }
    times
}

/// Read the file of `entry`'s slot as it is before the door stores
/// `entry`: the channel's secret is `secret`, the statement applied is
/// numbered `statement`, and `counting` says who counts.
pub(crate) fn before(
    conn: &Connection,
    own: &[u8; 32],
    entry: &CheckedEntry,
    secret: &[u8; 32],
    statement: u64,
    counting: &Counting,
) -> Result<Before, PersonError> {
    let held = entries::slot_entries(conn, &entry.channel, &entry.slot)?;
    let slot = version::current(&held, secret, statement, |key| counting.counts(key))?;
    let mut times: HashMap<LinkOf, u32> = HashMap::new();
    for version in slot.current.iter().chain(&slot.lost) {
        for one in &version.entries {
            for (link, count) in counted(one.chain.as_deref().unwrap_or_default()) {
                let kept = times.entry(link).or_insert(0);
                *kept = (*kept).max(count);
            }
        }
    }
    let current = slot.current.as_ref().and_then(|version| {
        let one = version
            .entries
            .iter()
            .find(|one| one.author == *own)
            .or(version.entries.first())?;
        held.iter()
            .find(|entry| entry.id() == one.id)
            .map(|entry| Entry::clone(entry))
    });
    Ok(Before { current, times })
}

/// Keep the arrivals that `entry`, which the door just stored in the file
/// of its slot, makes (rule 7), in the generation `generation`, at `now`.
/// `before` is what the door read of the file before it stored the entry,
/// and `secret` the channel's secret. The device's own entry makes none.
///
/// **The index rule.** Every entry of the index (`MEMORY.md`) that another
/// key signed is marked as one whose chain may have dropped links, edit or
/// merge, of any length, as a full chain's is: at a carry it is judged as
/// an arrival of every removed key, so each such version stored in a
/// removal's window is set aside, and the index goes back to the version
/// before. A link is only a hash and a signer, and records no time or
/// place: no chain can show that it was written straight over a version
/// held here and not over a removed key's late re-send of an old text (the
/// read of the index rule, two ways round the precise rule it replaces).
/// What it costs: an honest edit of the index by another device, taken in
/// the window, is set aside too, and goes to local history; what this
/// device wrote itself it carries, so its own lines reach the others again.
pub(crate) fn noted_at_the_door(
    conn: &Connection,
    own: &[u8; 32],
    entry: &CheckedEntry,
    secret: &[u8; 32],
    generation: &Change,
    before: &Before,
    now: i64,
) -> Result<(), PersonError> {
    if entry.author == *own {
        return Ok(());
    }
    let own_signer = Link::signer_of(own);
    let mut arrivals = vec![Arrival {
        signer: Link::signer_of(&entry.author),
        link: None,
        times: 1,
    }];
    let opened = entry.open(secret).ok();
    let name = opened.as_ref().map(|inside| inside.name.clone());
    let chain = opened.and_then(|inside| inside.chain);
    // A chain that may have dropped what it was written after
    // ([`crate::cut::may_have_dropped_links`]): one that is missing, one at
    // the most a chain keeps, and every chain of the index, edit or merge,
    // of any length (the index rule). Such an event is judged at a carry
    // as an arrival of every removed key.
    let unknown = crate::cut::may_have_dropped_links(name.as_deref(), chain.as_deref());
    let chain = chain.unwrap_or_default();
    let mut links: Vec<(LinkOf, u32)> = counted(&chain).into_iter().collect();
    links.sort();
    for ((hash, signer), count) in links {
        if signer == own_signer {
            continue;
        }
        let stood = before
            .times
            .get(&(hash, signer))
            .copied()
            .unwrap_or(0)
            .max(kept::link_times(
                conn,
                &entry.channel,
                &entry.slot,
                &hash,
                &signer,
            )?);
        if count > stood {
            arrivals.push(Arrival {
                signer,
                link: Some(hash),
                times: count,
            });
        }
    }
    let mut full: Vec<[u8; 16]> = Vec::new();
    if chain.len() >= MAX_ENTRY_LINKS {
        full = chain
            .iter()
            .map(|link| link.signer)
            .filter(|signer| *signer != own_signer)
            .collect();
        full.sort();
        full.dedup();
    }
    let place = kept::note(
        conn,
        &entry.channel,
        &entry.slot,
        generation.0,
        &generation.1,
        now,
        &full,
        before.current.as_ref(),
        Some(&entry.id()),
        &arrivals,
    )?;
    if unknown {
        kept::noted_unknown(conn, place)?;
    }
    Ok(())
}

/// When each window of rule 27 opens and closes, for each removed key:
/// the first arrival that the cut leaves out for that key, in any name and
/// any generation, or the first message of the key's that the device held
/// where it is cut; and when this device first kept the key as removed.
///
/// **A window is not of one generation** (the review of rule 27, its
/// high): a device that took late writing in one generation, and then
/// carried into another before it knew (a change made apart, a renewal of
/// its own), still writes from what it read. Every version of its own
/// stored after the window opens, in any generation, is set aside until
/// the device knew.
#[derive(Debug, Clone, Default)]
pub(crate) struct Windows {
    /// Where each opens by the place of an event: the place of its first
    /// arrival, or of the first event that went past the arrivals' bound in
    /// a generation where that is cut at any time (made apart from the
    /// removal), whose times are not kept. A version of the device's own
    /// stored after that place is in it. Places are given in the order the
    /// device stored its events, in every file, so no clock moves this.
    /// With the time of that event (`i64::MIN` where it went).
    after_place: BTreeMap<[u8; 32], (i64, i64)>,
    /// Where each opens by a time alone: a message's, which has no place
    /// among the events of files, and a cut time where what went past the
    /// bound is cut by time. A version of the device's own stamped at it
    /// or after is in it.
    from_at: BTreeMap<[u8; 32], i64>,
    /// When the device first kept each key as removed: stamped no earlier
    /// than any event kept then (`keep_removed`), so a version stored
    /// before it is never stamped after it. A version stamped in that
    /// second is in the window (fails safe).
    closes: BTreeMap<[u8; 32], i64>,
}

impl Windows {
    /// Whether the window of `key` is open for a version stored at `at` and
    /// `place`.
    fn opened(&self, key: &[u8; 32], at: i64, place: i64) -> bool {
        self.after_place
            .get(key)
            .is_some_and(|(after, _)| place > *after)
            || self.from_at.get(key).is_some_and(|from| at >= *from)
    }

    /// Whether a version stored at `at` was stored before the device knew
    /// of `key`'s removal, or in that second.
    fn before_close(&self, key: &[u8; 32], at: i64) -> bool {
        self.closes.get(key).is_none_or(|closes| at <= *closes)
    }

    /// The keys whose window opened.
    fn keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.after_place.keys().chain(self.from_at.keys())
    }

    /// Whether a version of the device's own, stored at `at` and `place`,
    /// in any generation, is in a window: stored after it opens for some
    /// removed key, and before the device knew of that key's removal.
    pub(crate) fn sets_aside(&self, at: i64, place: i64) -> bool {
        self.keys()
            .any(|key| self.opened(key, at, place) && self.before_close(key, at))
    }

    /// Whether a version of the device's own that went past the bound
    /// (`went`) may have been in a window: the newest that went was stored
    /// after one opened, and the oldest before the device knew of that
    /// key's removal. Which of those between went is not known, so that
    /// fails safe.
    fn may_have_set_aside(&self, went: &kept::OwnDropped) -> bool {
        self.keys().any(|key| {
            self.opened(key, went.newest_at, went.newest_place)
                && self.before_close(key, went.oldest_at)
        })
    }

    /// When the first window opens, by time: `i64::MIN` where one opens at
    /// the place of what went past the bound.
    fn opens_at(&self) -> Option<i64> {
        self.after_place
            .values()
            .map(|(_, at)| *at)
            .chain(self.from_at.values().copied())
            .min()
    }

    fn open_after(&mut self, key: [u8; 32], place: i64, at: i64) {
        let after = self.after_place.entry(key).or_insert((place, at));
        *after = (*after).min((place, at));
    }

    fn open_from(&mut self, key: [u8; 32], at: i64) {
        let from = self.from_at.entry(key).or_insert(at);
        *from = (*from).min(at);
    }
}

/// The windows of rule 27, from every file of the channels `channels` (the
/// channels of the names a carry leaves) and the messages the device
/// held, and the time each removed key was first kept: worked out before
/// any file is judged, since a late arrival in one name sets aside what
/// the device wrote in every name.
pub(crate) fn windows(
    conn: &Connection,
    channels: &[[u8; 32]],
    cuts: &Cuts,
) -> Result<Windows, PersonError> {
    let mut windows = Windows {
        after_place: BTreeMap::new(),
        from_at: BTreeMap::new(),
        closes: cordelia_storage::person::removed_seen(conn)?
            .into_iter()
            .collect(),
    };
    if cuts.keys().is_empty() {
        return Ok(windows);
    }
    for channel in channels {
        let mut slots = entries::channel_slots(conn, channel)?;
        slots.extend(kept::files_of_channel(conn, channel)?);
        slots.sort();
        slots.dedup();
        for slot in slots {
            let (events, dropped) = kept::of_file(conn, channel, &slot)?;
            for event in events.iter().filter(|event| !event.own) {
                let generation = (event.number, event.hash);
                for key in cuts.keys() {
                    let names_it = event.unknown
                        || event
                            .arrivals
                            .iter()
                            .map(|arrival| &arrival.signer)
                            .chain(&event.full_signers)
                            .any(|signer| *signer == key.signer);
                    if names_it && cuts.cuts(key, &generation, event.stored_at) {
                        windows.open_after(key.key, event.place, event.stored_at);
                    }
                }
            }
            // What went past the bound and is cut opens the window at the
            // earliest an arrival of the key could be cut there: its cut
            // time where it is cut by time, and otherwise just before the
            // first event of that generation that went (no version of the
            // device's own was at its place).
            for went in &dropped {
                let generation = (went.number, went.hash);
                for key in cuts.keys() {
                    if !cuts.cuts(key, &generation, went.newest_at) {
                        continue;
                    }
                    match (cuts.cuts(key, &generation, i64::MIN), key.at) {
                        (false, Some(at)) => windows.open_from(key.key, at),
                        _ => windows.open_after(key.key, went.first_place - 1, i64::MIN),
                    }
                }
            }
        }
    }
    // A message of a removed key's that the device held where it is cut
    // opens the window too (the review of rule 27, its messages): an agent
    // reads it, and may write it down. Its generation is known by its
    // statement's number alone, and is judged as each noted change of that
    // number, and as one made apart where none is noted (fails safe).
    for key in cuts.keys() {
        let held = cordelia_storage::messages::held_of(conn, &key.key).map_err(|e| {
            PersonError::Storage(cordelia_core::CordeliaError::Storage(e.to_string()))
        })?;
        for (number, at) in held.held {
            if cuts.cuts_numbered(key, number, at) {
                windows.open_from(key.key, at);
            }
        }
        // Where a message of the key's went past the ring, its time is not
        // kept: it was held after the generation was first held, and is
        // judged as held at the latest. Where that is cut, the window opens
        // at the earliest it could have been cut.
        for (number, first_held) in held.went {
            if !cuts.cuts_numbered(key, number, i64::MAX) {
                continue;
            }
            let opens = match cuts.cuts_numbered(key, number, first_held) {
                true => first_held,
                false => key.at.unwrap_or(first_held).max(first_held),
            };
            windows.open_from(key.key, opens);
        }
    }
    Ok(windows)
}

/// The version current in `file` of the channel whose secret is `channel`,
/// before this device writes its own entry over `current` (rule 27), as
/// one entry: its own where it holds one, and otherwise the first. Read
/// before the entry is stored, since the store keeps one entry of each
/// author in a slot.
pub(crate) fn own_before(
    conn: &Connection,
    own: &[u8; 32],
    channel: &[u8; 32],
    file: &str,
    current: Option<&Version>,
) -> Result<Option<Entry>, PersonError> {
    let Some(version) = current else {
        return Ok(None);
    };
    let Some(one) = version
        .entries
        .iter()
        .find(|one| one.author == *own)
        .or(version.entries.first())
    else {
        return Ok(None);
    };
    let id = cordelia_crypto::derive::channel_id(channel)?;
    let slot = cordelia_crypto::slots::slot_id(&cordelia_crypto::derive::slot_key(channel)?, file);
    Ok(entries::slot_entries(conn, &id, &slot)?
        .into_iter()
        .find(|entry| entry.id() == one.id)
        .map(|entry| Entry::clone(&entry)))
}

/// Keep `entry`, which this device just wrote itself in the channel whose
/// secret is `channel`, in the generation `generation`, at `now`, over the
/// version `before` ([`own_before`]): an event of its own (rule 27).
pub(crate) fn noted_own(
    conn: &Connection,
    entry: &CheckedEntry,
    generation: &Change,
    before: Option<&Entry>,
    now: i64,
) -> Result<(), PersonError> {
    kept::note_own(
        conn,
        &entry.channel,
        &entry.slot,
        generation.0,
        &generation.1,
        now,
        before,
        &entry.id(),
    )?;
    Ok(())
}

/// Whether a carry by command leaves out `version`, read in `generation`
/// (`None`: a generation not known), as what this device wrote itself in
/// a window (rule 27): where a carry set aside its own writing in that
/// generation (or in any, where the generation is not known), a version
/// that this device signed, or whose chain names its key, or whose chain
/// may have dropped links. What it sent there in its window is at the
/// relays.
pub(crate) fn own_window_leaves_out(
    conn: &Connection,
    own: &[u8; 32],
    generation: Option<&Change>,
    version: &Version,
) -> Result<bool, PersonError> {
    let set_aside = kept::own_set_aside(conn)?;
    let in_it = match generation {
        Some(generation) => set_aside.contains(generation),
        None => !set_aside.is_empty(),
    };
    if !in_it {
        return Ok(false);
    }
    let signer = Link::signer_of(own);
    Ok(version.entries.iter().any(|one| {
        one.author == *own
            || match one.chain.as_deref() {
                Some(links)
                    if !crate::cut::may_have_dropped_links(Some(&version.name), Some(links)) =>
                {
                    links.iter().any(|link| link.signer == signer)
                }
                _ => true,
            }
    }))
}

/// The first event of a file that the cut leaves out, or what went past
/// its bound.
struct First<'a> {
    /// Its place; `None` where what went past the bound is cut.
    place: Option<i64>,
    generation: Change,
    at: i64,
    /// The version current in the file before it.
    before: Option<&'a Entry>,
    /// The IDs of the entries that the events before it stored, of those
    /// kept and of the first of each generation that went and is not cut:
    /// a version gone back to that one of them stored was judged when it
    /// came.
    stored_before: Vec<[u8; 32]>,
    /// It is a version of the device's own in a window of rule 27, and no
    /// earlier event of the file is cut by rule 7.
    own: bool,
}

/// What the cut leaves of a file at a carry (rule 7).
#[derive(Debug, Clone)]
pub(crate) struct FileCut {
    /// The place of the first event that is cut: it and every one after
    /// it are left out.
    pub(crate) place: Option<i64>,
    /// When that event was stored, or the newest time that went past the
    /// bound where that is what was cut.
    pub(crate) at: i64,
    /// The version the file goes back to; `None` for none.
    pub(crate) target: Option<Version>,
    /// What is left out is the device's own writing in a window of rule 27,
    /// and nothing earlier of the file is cut by rule 7: what is said of it
    /// differs, and no command brings it back (the review of the whole
    /// build, its M4).
    pub(crate) own: bool,
}

/// Each file of the channel whose secret is `from`, under the statement
/// numbered `statement`, that the cut leaves out from somewhere, by its
/// slot (rule 7). A file that is not in it is carried as it is.
///
/// **And each file where a version of the device's own is in a window of
/// rule 27** (`windows`): it goes back to the version current before the
/// first such version, where no event earlier is cut; where one of its own
/// that went past the bound may have been in a window, it goes back to
/// none. Each generation where that set anything aside is added to
/// `set_aside_in`.
pub(crate) fn cut_of_channel(
    conn: &Connection,
    own: &[u8; 32],
    from: &[u8; 32],
    cuts: &Cuts,
    windows: &Windows,
    set_aside_in: &mut BTreeSet<Change>,
) -> Result<BTreeMap<[u8; 32], FileCut>, PersonError> {
    let channel = cordelia_crypto::derive::channel_id(from)?;
    let mut cut = BTreeMap::new();
    if cuts.keys().is_empty() {
        return Ok(cut);
    }
    // Every file that holds an entry, and every one that holds arrivals
    // and none: a conflict copy that is not yet published.
    let mut slots = entries::channel_slots(conn, &channel)?;
    slots.extend(kept::files_of_channel(conn, &channel)?);
    slots.sort();
    slots.dedup();
    for slot in slots {
        let (events, dropped) = kept::of_file(conn, &channel, &slot)?;
        let own_dropped = kept::own_dropped_of_file(conn, &channel, &slot)?;
        let any_key = |generation: &Change, at: i64| {
            cuts.keys().iter().any(|key| cuts.cuts(key, generation, at))
        };
        let of_signer = |signer: &[u8; 16], generation: &Change, at: i64| {
            cuts.keys()
                .iter()
                .filter(|key| key.signer == *signer)
                .any(|key| cuts.cuts(key, generation, at))
        };
        // What went past the bound is judged as an arrival of every removed
        // key, at the newest time that went. Where it is cut, the file goes
        // back to the version before the first event that went in the
        // first generation so cut: not to before the oldest event kept,
        // which may be a removed key's own version.
        let went = dropped
            .iter()
            .position(|went| any_key(&(went.number, went.hash), went.newest_at));
        // A version of the device's own that went past its bound in a
        // generation where a window opened at or before it: the version
        // before it is not kept, so the file goes back to none (rule 27).
        let own_went = own_dropped
            .iter()
            .find(|went| windows.may_have_set_aside(went));
        // The first version of the device's own in a window (rule 27).
        let own_first = events
            .iter()
            .position(|event| event.own && windows.sets_aside(event.stored_at, event.place));
        if let Some(index) = own_first {
            set_aside_in.insert((events[index].number, events[index].hash));
        }
        let first = match (own_went, went) {
            (Some(own_went), _) => {
                let generation = (own_went.number, own_went.hash);
                set_aside_in.insert(generation);
                Some(First {
                    place: None,
                    generation,
                    at: windows.opens_at().unwrap_or(own_went.newest_at),
                    before: None,
                    stored_before: Vec::new(),
                    own: true,
                })
            }
            (None, Some(at)) => {
                let went = &dropped[at];
                Some(First {
                    place: None,
                    generation: (went.number, went.hash),
                    at: went.newest_at,
                    before: went.before.as_ref(),
                    stored_before: dropped[..at]
                        .iter()
                        .filter_map(|went| went.first_stored_id)
                        .collect(),
                    own: false,
                })
            }
            (None, None) => {
                let by_rule_7 = events.iter().position(|event| {
                    let generation = (event.number, event.hash);
                    event
                        .arrivals
                        .iter()
                        .map(|arrival| &arrival.signer)
                        .chain(&event.full_signers)
                        .any(|signer| of_signer(signer, &generation, event.stored_at))
                        // A chain that may have dropped links names every
                        // removed key.
                        || (event.unknown && any_key(&generation, event.stored_at))
                });
                by_rule_7.into_iter().chain(own_first).min().map(|index| {
                    let event = &events[index];
                    let stored = events[..index].iter().map(|event| event.stored_id);
                    let went = dropped.iter().map(|went| went.first_stored_id);
                    First {
                        place: Some(event.place),
                        generation: (event.number, event.hash),
                        at: event.stored_at,
                        before: event.before.as_ref(),
                        stored_before: stored.chain(went).flatten().collect(),
                        own: by_rule_7.is_none_or(|first| first > index),
                    }
                })
            }
        };
        let Some(first) = first else {
            continue;
        };
        let target = match first.before {
            Some(before) => version_of(before, from)?,
            None => None,
        };
        // The version gone back to was judged when it came only where the
        // device wrote it itself, or a kept event stored exactly it (the
        // second read of slice 8, its medium finding). That an earlier
        // event was kept says nothing of it: an honest entry at a lower
        // revision makes an event and leaves the version current as it was,
        // which may be one taken before this version kept arrivals.
        let brought = first.before.is_some_and(|before| {
            first.stored_before.contains(&before.id())
                || target
                    .as_ref()
                    .is_some_and(|version| is_own_writing(version, own))
        });
        // Where nothing kept brought it, its arrival was never judged: its
        // signers, and every key its chains name, are judged at the cut's
        // own generation and time, and where one is cut the file goes back
        // to none. That fails safe.
        // A chain that may have dropped links (missing, at the most a chain
        // keeps, or the index's) names every removed key there.
        let target = target.filter(|version| {
            brought
                || !version.entries.iter().any(|one| {
                    cuts.cuts_key(&one.author, &first.generation, first.at)
                        || one
                            .chain
                            .iter()
                            .flatten()
                            .any(|link| of_signer(&link.signer, &first.generation, first.at))
                        || (crate::cut::may_have_dropped_links(
                            Some(&version.name),
                            one.chain.as_deref(),
                        ) && any_key(&first.generation, first.at))
                })
        });
        cut.insert(
            slot,
            FileCut {
                place: first.place,
                at: first.at,
                target,
                own: first.own,
            },
        );
    }
    Ok(cut)
}

/// Whether `version`, of one entry, is what the device whose key is `own`
/// wrote itself: it signed it, and it is no carry of another key's
/// version. A carry's chain begins with links whose hash is the value's,
/// one for each key it was carried from ([`crate::carry::later_by_its_author`]);
/// so it is the device's own writing where none of those is another key's.
pub(crate) fn is_own_writing(version: &Version, own: &[u8; 32]) -> bool {
    let signer = Link::signer_of(own);
    let hash = version.value.chain_hash();
    version.entries.iter().all(|one| {
        one.author == *own
            && one
                .chain
                .iter()
                .flatten()
                .take_while(|link| link.hash == hash)
                .all(|link| link.signer == signer)
    })
}

/// The version that `entry`, sealed under `secret`, is: `None` where it is
/// a delete, or does not open.
pub(crate) fn version_of(entry: &Entry, secret: &[u8; 32]) -> Result<Option<Version>, PersonError> {
    let Ok(checked) = entry.clone().check() else {
        return Ok(None);
    };
    if checked.delete {
        return Ok(None);
    }
    let Ok(inside) = checked.open(secret) else {
        return Ok(None);
    };
    if inside.value == Value::Delete {
        return Ok(None);
    }
    Ok(Some(Version {
        rev: checked.rev,
        name: inside.name,
        value: inside.value,
        entries: vec![VersionEntry {
            id: checked.id(),
            author: checked.author,
            chain: inside.chain,
        }],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::person::Shown;
    use crate::several::Several;
    use crate::take::Taken;
    use cordelia_core::protocol::{MAX_FILE_ARRIVALS, REMOVAL_TAKEN_MARGIN_SECS};

    const MARGIN: i64 = REMOVAL_TAKEN_MARGIN_SECS as i64;
    /// The name of a folder's index file.
    const INDEX: &str = "MEMORY.md";

    /// Every text the device's store holds of the name `notes`, in the
    /// generation it follows.
    fn texts(s: &Several, n: usize) -> Vec<String> {
        s[n].stored_in(&s[n].own("notes"))
            .iter()
            .filter_map(|entry| match entry.open(&s[n].own("notes")).ok()?.value {
                Value::Text(text) => Some(text),
                _ => None,
            })
            .collect()
    }

    /// Rule 7 at a carry (decision 2026-10-24 (removal), unit test 12): the
    /// desktop (0) removes the tablet (2). The laptop (1) does not know,
    /// takes the tablet's late edit of `y.md` under change 1, and renews
    /// (its change made apart), carrying it: its arrival goes with the file.
    /// The phone (3) takes a second late edit, of `x.md`, and carries it
    /// into the laptop's change when it applies it; the laptop takes only
    /// the phone's version. When the laptop moves to the desktop's change,
    /// neither is carried: `y.md` goes back to the laptop's own text, and
    /// `x.md`, which held nothing before, to none.
    #[test]
    fn each_arrival_that_rule_7_cuts_is_cut_whoever_carried_it() {
        let mut s = Several::of_one_person(4);
        s.hold(&[0, 1, 2, 3], "notes");
        s.write(1, "notes", "y.md", "y one");
        s.meet(&[0, 1, 2, 3]);
        s.now += MARGIN + 1;
        s.change(0, &[0, 1, 3], &[2]);

        // The tablet writes late, under change 1.
        s.write(2, "notes", "y.md", "y late");
        s.pass(2, 1);
        assert_eq!(s[1].text("notes", "y.md").as_deref(), Some("y late"));
        s.write(2, "notes", "x.md", "x late");
        s.pass(2, 3);
        // The laptop renews, apart from the removal, and carries y.md: its
        // arrival is kept across the carry.
        s.change(1, &[1, 0, 2, 3], &[]);
        assert_eq!(s[1].text("notes", "y.md").as_deref(), Some("y late"));
        let (events, _) = kept::of_file(
            &s[1].conn,
            &cordelia_crypto::derive::channel_id(&s[1].own("notes")).unwrap(),
            &s[1].slot_of("notes", "y.md"),
        )
        .unwrap();
        assert!(!events.is_empty(), "the arrival went with the file");
        // The phone applies the laptop's change, carrying x.md; the laptop
        // takes the phone's version alone.
        let taken = s.pass(1, 3);
        assert!(matches!(taken[0], Taken::Shown(Shown::Applied(_))));
        s.pass(3, 1);
        assert_eq!(s[1].text("notes", "x.md").as_deref(), Some("x late"));

        // The laptop is shown the removal, and moves.
        let taken = s.pass(0, 1);
        assert!(
            matches!(taken[0], Taken::Shown(Shown::Moved(_))),
            "{:?}",
            taken[0]
        );
        assert_eq!(s[1].text("notes", "y.md").as_deref(), Some("y one"));
        assert_eq!(s[1].text("notes", "x.md"), None);
        assert!(
            texts(&s, 1).iter().all(|text| !text.contains("late")),
            "{:?}",
            texts(&s, 1)
        );
        // The desktop is given what the laptop carried: none of it.
        s.pass(1, 0);
        assert!(texts(&s, 0).iter().all(|text| !text.contains("late")));
    }

    /// With the clock set (unit test 12): an arrival a second before the
    /// cut time is carried, and one at it is not.
    #[test]
    fn an_arrival_a_second_before_the_cut_time_is_carried_and_one_at_it_is_not() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        let cut = s.now + 10 * MARGIN;
        s.now = cut - 10;
        s.write(2, "notes", "before.md", "a second before");
        s.now = cut - 2;
        s.pass(2, 1);
        s.write(2, "notes", "at.md", "at the cut time");
        s.now = cut - 1;
        s.pass(2, 1);
        // The removal is made at the cut time and ten minutes.
        s.now = cut + MARGIN - 1;
        s.change(0, &[0, 1], &[2]);
        let taken = s.pass(0, 1);
        assert!(matches!(taken[0], Taken::Shown(Shown::Applied(_))));
        assert_eq!(
            s[1].text("notes", "before.md").as_deref(),
            Some("a second before")
        );
        assert_eq!(s[1].text("notes", "at.md"), None);
    }

    /// Past 1,024 arrivals a file (unit test 12): a cut time before the
    /// oldest kept takes the file back to before it, whoever signed what
    /// came after. With room, the honest version is carried as it is.
    #[test]
    fn past_the_bound_a_cut_time_before_the_oldest_kept_goes_back_before_it() {
        for over in [false, true] {
            let mut s = Several::of_one_person(3);
            s.hold(&[0, 1, 2], "notes");
            s.write(1, "notes", "w.md", "w kept");
            s.meet(&[0, 1, 2]);
            let made = s.now + 10 * MARGIN;
            // Device 0 is honest, and writes after the cut time; the laptop
            // takes it.
            s.now = made - MARGIN / 2;
            s.write(0, "notes", "w.md", "w later, by device 0");
            s.pass(0, 1);
            assert_eq!(
                s[1].text("notes", "w.md").as_deref(),
                Some("w later, by device 0")
            );
            if over {
                // More arrivals of the honest device than are kept: the
                // oldest go, the one above among them.
                let on = &s[1];
                let channel = cordelia_crypto::derive::channel_id(&on.own("notes")).unwrap();
                let slot = on.slot_of("notes", "w.md");
                let own = on
                    .stored_in(&on.own("notes"))
                    .into_iter()
                    .find(|entry| entry.slot == slot && entry.author == on.key())
                    .unwrap();
                let link = on.held().statement.statement.link().unwrap();
                let honest = Arrival {
                    signer: Link::signer_of(&s.key(0)),
                    link: None,
                    times: 1,
                };
                for i in 0..MAX_FILE_ARRIVALS {
                    kept::note(
                        &on.conn,
                        &channel,
                        &slot,
                        link.number,
                        &link.hash,
                        s.now + 1 + i as i64,
                        &[],
                        Some(&own),
                        None,
                        &[honest],
                    )
                    .unwrap();
                }
                let (events, dropped) = kept::of_file(&on.conn, &channel, &slot).unwrap();
                // The laptop's own version is an event of its own, counted
                // apart (rule 27).
                let arrivals = events.iter().filter(|event| !event.own).count();
                assert_eq!((arrivals, dropped.len()), (MAX_FILE_ARRIVALS, 1));
            }
            s.now = made - 1;
            let removal = s.change(0, &[0, 1], &[2]);
            // The laptop is shown the removal alone, and carries.
            let now = s.tick();
            let on = &s[1];
            let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
            assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
            let carried = s[1].text("notes", "w.md");
            match over {
                false => assert_eq!(carried.as_deref(), Some("w later, by device 0")),
                true => assert_eq!(carried.as_deref(), Some("w kept")),
            }
        }
    }

    /// A full chain (unit test 12): where a chain holds 100 links, and an
    /// earlier standing of a removed key's link may have fallen off its end,
    /// that link is cut all the same, though it stands no more times than
    /// in a chain the file held before. With room in the chain, the same
    /// link makes no arrival, and the honest version is carried. Since the
    /// fourth read of slice 8, every full chain is judged as an arrival of
    /// every removed key, so the keys it names are no longer what cuts it:
    /// its old end names the version device 1 holds, and that is not
    /// trusted either.
    #[test]
    fn in_a_full_chain_a_removed_keys_link_is_cut_all_the_same() {
        use crate::several::entry_by;
        use cordelia_core::protocol::MAX_ENTRY_LINKS;
        for full in [false, true] {
            let mut s = Several::of_one_person(3);
            s.hold(&[0, 1, 2], "notes");
            s.meet(&[0, 1, 2]);
            let channel = s[1].own("notes");
            let tablet_link = Link::of(&Value::Text("the tablet's\n".into()), s.key(2));
            let first_rev = cordelia_core::revision::next_under(None, 1).unwrap();
            // Long before the removal, device 0 writes over a text that the
            // tablet wrote: its link once.
            let first = entry_by(
                &s[0].identity,
                &channel,
                first_rev,
                "w.md",
                Value::Text("one\n".into()),
                &[tablet_link],
            );
            let now = s.tick();
            crate::take::take(&s[1].conn, &s[1].identity, &first, now).unwrap();
            // After the cut time, device 0 writes again, with the tablet's
            // link once in its chain, and 99 more where `full`.
            let made = s.now + 10 * MARGIN;
            let mut chain = vec![tablet_link];
            if full {
                chain.extend((0..MAX_ENTRY_LINKS - 1).map(|i| Link {
                    hash: [i as u8; 16],
                    signer: Link::signer_of(&s.key(0)),
                }));
                // Its old end names the version device 1 holds, which is no
                // sign that nothing fell off it (the fourth read of slice 8).
                chain[MAX_ENTRY_LINKS - 1] = Link::of(&Value::Text("one\n".into()), s.key(0));
            }
            let second = entry_by(
                &s[0].identity,
                &channel,
                first_rev + 1,
                "w.md",
                Value::Text("two, after the cut time\n".into()),
                &chain,
            );
            crate::take::take(&s[1].conn, &s[1].identity, &second, made - MARGIN / 2).unwrap();
            assert_eq!(
                s[1].text("notes", "w.md").as_deref(),
                Some("two, after the cut time\n")
            );
            s.now = made - 1;
            let removal = s.change(0, &[0, 1], &[2]);
            let now = s.tick();
            let taken = crate::take::take(&s[1].conn, &s[1].identity, &removal, now).unwrap();
            assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
            let carried = s[1].text("notes", "w.md");
            match full {
                false => assert_eq!(carried.as_deref(), Some("two, after the cut time\n")),
                true => assert_eq!(carried.as_deref(), Some("one\n")),
            }
        }
    }

    /// A full chain that may have dropped a removed key's link (the extra
    /// look of the third read of slice 8, and the fourth read's high): the
    /// tablet's late text reached device 0, which edited it a hundred times
    /// and more before it heard, so the tablet's link fell off the old end
    /// of its chain. Device 1 takes only device 0's newest version, after
    /// the cut time, and no link of it names the tablet. A full chain says
    /// nothing of what fell off its end, whatever version device 1 holds
    /// and whatever link of it names one: the event is judged as an arrival
    /// of every removed key, and the carry leaves it out. So with no version
    /// held (the file goes back to none); with the version held named at
    /// the chain's old end; with it named in the middle, where device 0
    /// went back to "one" among its last hundred edits (the fourth read's
    /// sequence); with a delete held, and a delete's link, whose hash is
    /// every delete's, in the middle (the file goes back to the delete);
    /// and the index's.
    #[test]
    fn a_full_chain_that_may_have_dropped_a_removed_keys_link_is_cut() {
        use crate::several::entry_by;
        use cordelia_core::protocol::MAX_ENTRY_LINKS;
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Held {
            Nothing,
            NamedAtTheOldEnd,
            NamedInTheMiddle,
            ADeleteNamedInTheMiddle,
            NamedInTheIndexsChain,
        }
        for held in [
            Held::Nothing,
            Held::NamedAtTheOldEnd,
            Held::NamedInTheMiddle,
            Held::ADeleteNamedInTheMiddle,
            Held::NamedInTheIndexsChain,
        ] {
            let file = match held {
                Held::NamedInTheIndexsChain => "MEMORY.md",
                _ => "w.md",
            };
            let mut s = Several::of_one_person(3);
            s.hold(&[0, 1, 2], "notes");
            s.meet(&[0, 1, 2]);
            let channel = s[1].own("notes");
            let first_rev = cordelia_core::revision::next_under(None, 1).unwrap();
            let one = match held {
                Held::ADeleteNamedInTheMiddle => Value::Delete,
                _ => Value::Text("one\n".into()),
            };
            if held != Held::Nothing {
                // Long before the removal, device 1 takes device 0's text,
                // or its delete.
                let first = entry_by(&s[0].identity, &channel, first_rev, file, one.clone(), &[]);
                let now = s.tick();
                crate::take::take(&s[1].conn, &s[1].identity, &first, now).unwrap();
            }
            // After the cut time, device 0's version: a full chain of its own
            // links, the tablet's gone from its end; where device 1 held a
            // version, a link of it stands at the old end or in the middle.
            let made = s.now + 10 * MARGIN;
            let mut chain: Vec<Link> = (0..MAX_ENTRY_LINKS)
                .map(|i| Link {
                    hash: [i as u8 + 1; 16],
                    signer: Link::signer_of(&s.key(0)),
                })
                .collect();
            match held {
                Held::Nothing => {}
                Held::NamedAtTheOldEnd | Held::NamedInTheIndexsChain => {
                    chain[MAX_ENTRY_LINKS - 1] = Link::of(&one, s.key(0));
                }
                Held::NamedInTheMiddle | Held::ADeleteNamedInTheMiddle => {
                    chain[MAX_ENTRY_LINKS / 2] = Link::of(&one, s.key(0));
                }
            }
            let late = entry_by(
                &s[0].identity,
                &channel,
                first_rev + 1,
                file,
                Value::Text("over the tablet's late text\n".into()),
                &chain,
            );
            crate::take::take(&s[1].conn, &s[1].identity, &late, made - MARGIN / 2).unwrap();
            assert_eq!(
                s[1].text("notes", file).as_deref(),
                Some("over the tablet's late text\n")
            );
            s.now = made - 1;
            let removal = s.change(0, &[0, 1], &[2]);
            let now = s.tick();
            let taken = crate::take::take(&s[1].conn, &s[1].identity, &removal, now).unwrap();
            assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
            let carried = s[1].text("notes", file);
            match held {
                Held::Nothing | Held::ADeleteNamedInTheMiddle => {
                    assert_eq!(carried, None, "{held:?}")
                }
                Held::NamedAtTheOldEnd | Held::NamedInTheMiddle | Held::NamedInTheIndexsChain => {
                    assert_eq!(carried.as_deref(), Some("one\n"), "{held:?}")
                }
            }
            assert!(
                texts(&s, 1).iter().all(|text| !text.contains("late")),
                "{held:?}: {:?}",
                texts(&s, 1)
            );
        }
    }

    /// The rev of the newest entry device `n` stores in `file` of `notes`.
    fn newest_rev(s: &Several, n: usize, file: &str) -> u64 {
        let slot = s[n].slot_of("notes", file);
        s[n].stored_in(&s[n].own("notes"))
            .iter()
            .filter(|entry| entry.slot == slot)
            .map(|entry| entry.rev)
            .max()
            .unwrap()
    }

    /// A flood past the bound (the review of slice 8, its first finding):
    /// the tablet writes twelve late versions of `w.md`, each with a chain
    /// of 100 links of its own, 101 arrivals each, so the first late ones
    /// go past the bound. The cut goes back to before the first event that
    /// went, the laptop's own `w kept`, and not to before the oldest kept,
    /// which is the tablet's own late version.
    #[test]
    fn a_flood_past_the_bound_never_carries_a_removed_devices_late_writing() {
        use crate::several::entry_by;
        // Where `renewed`, the laptop renews before it hears of the removal,
        // and carries the file with what went past its bound: the version
        // to go back to is sealed again there.
        for renewed in [false, true] {
            let mut s = Several::of_one_person(3);
            s.hold(&[0, 1, 2], "notes");
            s.write(1, "notes", "w.md", "w kept");
            s.meet(&[0, 1, 2]);
            let made = s.now + 10 * MARGIN;
            s.now = made - MARGIN / 2;
            let channel = s[1].own("notes");
            let rev = newest_rev(&s, 1, "w.md");
            for k in 1..=12u64 {
                let chain: Vec<Link> = (0..MAX_ENTRY_LINKS)
                    .map(|i| Link {
                        hash: {
                            let mut hash = [i as u8; 16];
                            hash[0] = k as u8;
                            hash
                        },
                        signer: Link::signer_of(&s.key(2)),
                    })
                    .collect();
                let late = entry_by(
                    &s[2].identity,
                    &channel,
                    rev + k,
                    "w.md",
                    Value::Text(format!("tablet late {k}")),
                    &chain,
                );
                let now = s.tick();
                crate::take::take(&s[1].conn, &s[1].identity, &late, now).unwrap();
            }
            assert_eq!(
                s[1].text("notes", "w.md").as_deref(),
                Some("tablet late 12")
            );
            if renewed {
                s.change(1, &[1, 0, 2], &[]);
            }
            let (events, dropped) = kept::of_file(
                &s[1].conn,
                &cordelia_crypto::derive::channel_id(&s[1].own("notes")).unwrap(),
                &s[1].slot_of("notes", "w.md"),
            )
            .unwrap();
            assert!(!dropped.is_empty());
            // The oldest event kept goes back to a late version of the
            // tablet's (sealed again as the laptop's own, after a carry).
            let oldest = events.iter().find(|event| !event.own).unwrap();
            let oldest = version_of(oldest.before.as_ref().unwrap(), &s[1].own("notes"))
                .unwrap()
                .unwrap();
            assert!(matches!(&oldest.value, Value::Text(text) if text.starts_with("tablet late")));

            s.now = made - 1;
            let removal = s.change(0, &[0, 1], &[2]);
            let now = s.tick();
            let on = &s[1];
            let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
            match renewed {
                false => assert!(matches!(taken, Taken::Shown(Shown::Applied(_)))),
                true => assert!(matches!(taken, Taken::Shown(Shown::Moved(_))), "{taken:?}"),
            }
            assert_eq!(s[1].text("notes", "w.md").as_deref(), Some("w kept"));
            assert!(texts(&s, 1).iter().all(|text| !text.contains("late")));
        }
    }

    /// A version gone back to that nothing kept brought (one taken before
    /// the arrivals were kept, as on a device stepped to this version) is
    /// judged at the cut's own time: where its signer is cut there, the
    /// file goes back to none. The rows are set so by hand.
    #[test]
    fn a_version_gone_back_to_that_nothing_kept_brought_is_judged_at_the_cut() {
        use crate::several::entry_by;
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        let made = s.now + 10 * MARGIN;
        s.now = made - MARGIN / 2;
        let channel = s[1].own("notes");
        let first_rev = cordelia_core::revision::next_under(None, 1).unwrap();
        let late = entry_by(
            &s[2].identity,
            &channel,
            first_rev,
            "z.md",
            Value::Text("z late".into()),
            &[],
        );
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &late, now).unwrap();
        // Its arrival is as if it was never kept: the event is gone.
        let id = cordelia_crypto::derive::channel_id(&channel).unwrap();
        let slot = s[1].slot_of("notes", "z.md");
        kept::drop_from(&s[1].conn, &id, &slot, i64::MIN).unwrap();
        // Device 0 writes over it, with the tablet's link: an arrival of
        // that link, after the cut time.
        let over = entry_by(
            &s[0].identity,
            &channel,
            first_rev + 1,
            "z.md",
            Value::Text("z over".into()),
            &[Link::of(&Value::Text("z late".into()), s.key(2))],
        );
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &over, now).unwrap();
        let (events, _) = kept::of_file(&s[1].conn, &id, &slot).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].before.as_ref().unwrap().author, s.key(2));

        s.now = made - 1;
        let removal = s.change(0, &[0, 1], &[2]);
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
        assert_eq!(s[1].text("notes", "z.md"), None);
    }

    /// A version gone back to that nothing kept brought, whose chain may
    /// have dropped links (the extra look of the third read of slice 8, and
    /// the fourth read's round): device 0 wrote it a hundred times over the
    /// tablet's late text, and the tablet's link fell off its end; or it is
    /// the index's, with a chain of one link, which a merge may have cut
    /// short. Its event is taken out by hand, as on a device stepped to this
    /// version. The tablet's next late version is cut, and goes back to it:
    /// no link of it names the tablet, but such a chain names every removed
    /// key, and the file goes back to none.
    #[test]
    fn a_version_gone_back_to_whose_chain_is_full_names_every_removed_key() {
        use crate::several::entry_by;
        use cordelia_core::protocol::MAX_ENTRY_LINKS;
        for file in ["z.md", INDEX] {
            let mut s = Several::of_one_person(3);
            s.hold(&[0, 1, 2], "notes");
            s.meet(&[0, 1, 2]);
            let made = s.now + 10 * MARGIN;
            s.now = made - MARGIN / 2;
            let channel = s[1].own("notes");
            let first_rev = cordelia_core::revision::next_under(None, 1).unwrap();
            let links = match file {
                INDEX => 1,
                _ => MAX_ENTRY_LINKS,
            };
            let chain: Vec<Link> = (0..links)
                .map(|i| Link {
                    hash: [i as u8 + 1; 16],
                    signer: Link::signer_of(&s.key(0)),
                })
                .collect();
            let busy_text = Value::Text("z, a hundred edits over the tablet's".into());
            let busy = entry_by(
                &s[0].identity,
                &channel,
                first_rev,
                file,
                busy_text.clone(),
                &chain,
            );
            let now = s.tick();
            crate::take::take(&s[1].conn, &s[1].identity, &busy, now).unwrap();
            let id = cordelia_crypto::derive::channel_id(&channel).unwrap();
            let slot = s[1].slot_of("notes", file);
            kept::drop_from(&s[1].conn, &id, &slot, i64::MIN).unwrap();
            let late = entry_by(
                &s[2].identity,
                &channel,
                first_rev + 1,
                file,
                Value::Text("z late".into()),
                &[Link::of(&busy_text, s.key(0))],
            );
            let now = s.tick();
            crate::take::take(&s[1].conn, &s[1].identity, &late, now).unwrap();
            let (events, _) = kept::of_file(&s[1].conn, &id, &slot).unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].before.as_ref().unwrap().author, s.key(0));

            s.now = made - 1;
            let removal = s.change(0, &[0, 1], &[2]);
            let now = s.tick();
            let on = &s[1];
            let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
            assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
            assert_eq!(s[1].text("notes", file), None, "{file}");
        }
    }

    /// A version gone back to counts as brought only where a kept event
    /// stored exactly it (the second read of slice 8, its medium finding).
    /// The laptop took the tablet's late `z late` before it kept arrivals
    /// (its event is taken out by hand, as on a device stepped to this
    /// version). Device 0 writes `z.md` at a lower revision: that makes an
    /// event, and `z late` stays current. The tablet's next late version
    /// is cut, and goes back to `z late`, which no kept event stored: it is
    /// judged at the cut, and the file goes back to none. Where device 0's
    /// entry is the one gone back to, the event that stored it brought it,
    /// and it is carried. Each way with the laptop's renewal between, which
    /// names anew the entry each event stored where it seals it again.
    #[test]
    fn a_version_gone_back_to_is_brought_only_where_a_kept_event_stored_it() {
        use crate::several::entry_by;
        for (over_honest, renewed) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut s = Several::of_one_person(3);
            s.hold(&[0, 1, 2], "notes");
            s.meet(&[0, 1, 2]);
            let made = s.now + 10 * MARGIN;
            s.now = made - MARGIN / 2;
            let channel = s[1].own("notes");
            let id = cordelia_crypto::derive::channel_id(&channel).unwrap();
            let rev = cordelia_core::revision::next_under(None, 1).unwrap();
            let take = |s: &mut Several, entry: &CheckedEntry| {
                let now = s.tick();
                crate::take::take(&s[1].conn, &s[1].identity, entry, now).unwrap();
            };
            let late = entry_by(
                &s[2].identity,
                &channel,
                rev + 5,
                "z.md",
                Value::Text("z late".into()),
                &[],
            );
            let honest = entry_by(
                &s[0].identity,
                &channel,
                match over_honest {
                    false => rev + 1,
                    true => rev + 6,
                },
                "z.md",
                Value::Text("z honest".into()),
                &[],
            );
            take(&mut s, &late);
            let slot = s[1].slot_of("notes", "z.md");
            kept::drop_from(&s[1].conn, &id, &slot, i64::MIN).unwrap();
            take(&mut s, &honest);
            let current = match over_honest {
                false => "z late",
                true => "z honest",
            };
            assert_eq!(s[1].text("notes", "z.md").as_deref(), Some(current));
            let later = entry_by(
                &s[2].identity,
                &channel,
                rev + 7,
                "z.md",
                Value::Text("z later".into()),
                &[],
            );
            take(&mut s, &later);
            let (events, _) = kept::of_file(&s[1].conn, &id, &slot).unwrap();
            assert_eq!(events.len(), 2);
            if renewed {
                s.change(1, &[1, 0, 2], &[]);
                // The event that stored the version carried names the entry
                // that carries it.
                let channel = s[1].own("notes");
                let id = cordelia_crypto::derive::channel_id(&channel).unwrap();
                let slot = s[1].slot_of("notes", "z.md");
                let carried = s[1]
                    .stored_in(&channel)
                    .into_iter()
                    .find(|entry| entry.slot == slot)
                    .unwrap();
                let (events, _) = kept::of_file(&s[1].conn, &id, &slot).unwrap();
                assert_eq!(events[1].stored_id, Some(carried.id()));
            }

            s.now = made - 1;
            let removal = s.change(0, &[0, 1], &[2]);
            let now = s.tick();
            let on = &s[1];
            let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
            assert!(
                matches!(taken, Taken::Shown(Shown::Applied(_) | Shown::Moved(_))),
                "{taken:?}"
            );
            match over_honest {
                false => assert_eq!(s[1].text("notes", "z.md"), None),
                true => assert_eq!(s[1].text("notes", "z.md").as_deref(), Some("z honest")),
            }
        }
    }

    /// A version gone back to that the device wrote itself counts as
    /// brought (the second read of slice 8, its medium finding): it is no
    /// arrival. The laptop writes `w.md` over the tablet's early text, so
    /// that its chain names the tablet; the tablet's late version is cut,
    /// and the file goes back to the laptop's own text, and not to none.
    #[test]
    fn a_version_gone_back_to_that_the_device_wrote_is_carried() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        s.write(2, "notes", "w.md", "the tablet's early text");
        s.pass(2, 1);
        s.write(1, "notes", "w.md", "the laptop's, over it");
        let made = s.now + 10 * MARGIN;
        s.now = made - MARGIN / 2;
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 1);
        assert_eq!(
            s[1].text("notes", "w.md").as_deref(),
            Some("the tablet's late text")
        );
        s.now = made - 1;
        let removal = s.change(0, &[0, 1], &[2]);
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
        assert_eq!(
            s[1].text("notes", "w.md").as_deref(),
            Some("the laptop's, over it")
        );
    }

    /// An index merge (the second read of slice 8, a low finding): the
    /// tablet writes `MEMORY.md` back to its own earlier text, the desktop
    /// merges that with an edit of its own, and the laptop stores only the
    /// desktop's merge. The merge's chain says the tablet's text one time
    /// more than any chain the laptop held: that is an arrival of the
    /// tablet's, and the cut leaves the merge out. Each way the tablet
    /// writes back: over the desktop's version, and over its own earlier
    /// one, not having seen the desktop's.
    #[test]
    fn a_merge_of_a_text_written_back_is_an_arrival_of_its_writer() {
        use crate::several::entry_by;
        use cordelia_crypto::chain;
        for over_its_own in [false, true] {
            let mut s = Several::of_one_person(3);
            s.hold(&[0, 1, 2], "notes");
            s.meet(&[0, 1, 2]);
            let channel = s[1].own("notes");
            let rev = cordelia_core::revision::next_under(None, 1).unwrap();
            let (t1, t2) = (Value::Text("- one\n".into()), Value::Text("- two\n".into()));
            let (k, b) = (s.key(2), s.key(0));
            let by = |s: &Several, n: usize, rev: u64, value: &Value, chain: &[Link]| {
                entry_by(&s[n].identity, &channel, rev, INDEX, value.clone(), chain)
            };
            // Long before the removal: the tablet's text, and the desktop's
            // over it, both taken by the laptop.
            let first = by(&s, 2, rev, &t1, &[]);
            let over_k = chain::written_over(&t1, &k, Some(&[]));
            let second = by(&s, 0, rev + 1, &t2, &over_k);
            for entry in [&first, &second] {
                let now = s.tick();
                crate::take::take(&s[1].conn, &s[1].identity, entry, now).unwrap();
            }
            // Late: the tablet writes its own text back, and the desktop
            // merges it with its own edit. The laptop stores the merge.
            let made = s.now + 10 * MARGIN;
            s.now = made - MARGIN / 2;
            let back = match over_its_own {
                false => chain::written_over(&t2, &b, Some(&over_k)),
                true => chain::written_over(&t1, &k, Some(&[])),
            };
            let other = Link::of(&t2, b);
            let merged = chain::merged(&t1, &k, Some(&back), &other, Some(&over_k));
            let merge = by(
                &s,
                0,
                rev + 3,
                &Value::Text("- one\n- mine\n".into()),
                &merged,
            );
            let now = s.tick();
            crate::take::take(&s[1].conn, &s[1].identity, &merge, now).unwrap();
            let id = cordelia_crypto::derive::channel_id(&channel).unwrap();
            let slot = s[1].slot_of("notes", INDEX);
            let (events, _) = kept::of_file(&s[1].conn, &id, &slot).unwrap();
            let last = events.last().unwrap();
            assert!(
                last.arrivals
                    .iter()
                    .any(|arrival| arrival.signer == Link::signer_of(&k)),
                "{over_its_own}: {:?}",
                last.arrivals
            );

            s.now = made - 1;
            let removal = s.change(0, &[0, 1], &[2]);
            let now = s.tick();
            let on = &s[1];
            let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
            assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
            assert_eq!(s[1].text("notes", INDEX).as_deref(), Some("- two\n"));
        }
    }

    /// An index merge that drops a removed key's link from a chain that is
    /// not full (the fourth read's round, its look for other paths). The
    /// tablet writes `MEMORY.md` late over device 0's `- one`; device 0
    /// writes `- one` back over it, and then a line of its own over the
    /// tablet's. Device 0 then merges that with a version whose chain names
    /// `- one` too: the merge stops the channel's chain at that hash, and
    /// what stood behind it, the tablet's link among it, is not said
    /// (`chain::merged`). The merge's chain holds three links, none the
    /// tablet's. The laptop stores only the merge: it is an index version
    /// another device wrote, taken in the window, so it may have dropped a
    /// link, and the carry leaves it out (the index rule).
    #[test]
    fn an_index_merge_that_drops_a_removed_keys_link_is_cut() {
        use crate::several::entry_by;
        use cordelia_crypto::chain;
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        let channel = s[1].own("notes");
        let rev = cordelia_core::revision::next_under(None, 1).unwrap();
        let (b, k) = (s.key(0), s.key(2));
        let one = Value::Text("- one\n".into());
        let first = entry_by(&s[0].identity, &channel, rev, INDEX, one.clone(), &[]);
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &first, now).unwrap();

        let made = s.now + 10 * MARGIN;
        s.now = made - MARGIN / 2;
        // Late: the tablet over `- one`; device 0's `- one` back over it;
        // device 0's own line over that, which keeps the tablet's.
        let late = Value::Text("- one\n- the tablet's late line\n".into());
        let over_one = chain::written_over(&one, &b, Some(&[]));
        let back = chain::written_over(&late, &k, Some(&over_one));
        let mine = Value::Text("- one\n- the tablet's late line\n- mine\n".into());
        let over_back = chain::written_over(&one, &b, Some(&back));
        assert!(
            over_back
                .iter()
                .any(|link| link.signer == Link::signer_of(&k))
        );
        // The other side: device 0's folder held `- two`, written over `- one`.
        let two = Value::Text("- one\n- two\n".into());
        let merged = chain::merged(
            &mine,
            &b,
            Some(&over_back),
            &Link::of(&two, b),
            Some(&over_one),
        );
        assert!(merged.len() < MAX_ENTRY_LINKS);
        assert!(
            merged.iter().all(|link| link.signer != Link::signer_of(&k)),
            "{merged:?}"
        );
        let merge = entry_by(
            &s[0].identity,
            &channel,
            rev + 4,
            INDEX,
            Value::Text("- one\n- the tablet's late line\n- mine\n- two\n".into()),
            &merged,
        );
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &merge, now).unwrap();
        assert!(
            s[1].text("notes", INDEX)
                .is_some_and(|text| text.contains("late"))
        );

        s.now = made - 1;
        let removal = s.change(0, &[0, 1], &[2]);
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
        assert_eq!(s[1].text("notes", INDEX).as_deref(), Some("- one\n"));
        assert!(texts(&s, 1).iter().all(|text| !text.contains("late")));
    }

    /// A merge whose other source's hash stands in the channel's chain
    /// (the read of the index rule, #252, its medium). The desktop (0)
    /// wrote `T`, then `U` without the line `- gone`. Late, the tablet (2)
    /// writes `T` back over `U`; the phone (3) takes it, so its folder
    /// agreed the tablet's `T`. The desktop, which has not taken it, writes
    /// `V` and then `C` over `U`. The phone takes them and merges its own
    /// edit with `C`, through `publish`: a union, so `- gone` comes back.
    /// `T`'s hash stands in `C`'s chain, by the desktop's link. The laptop
    /// (1) holds `C` and takes only the phone's merge, never the tablet's
    /// write-back. The merge's chain is exactly an edit's over `C`, and no
    /// arrival of the tablet's is in it: it is an index version another
    /// device wrote, taken in the window, and the carry leaves it out (the
    /// index rule). So are the desktop's `V` and `C`, taken in the window
    /// too: the index goes back to `U`, and the desktop carries its own.
    #[test]
    fn a_merge_over_a_chain_that_names_a_text_written_back_is_cut_at_a_third_device() {
        use crate::publish::{OtherSource, PlannedAgainst, Published, Write, publish, value_hash};
        let mut s = Several::of_one_person(4);
        s.hold(&[0, 1, 2, 3], "notes");
        let t = "- one\n- gone\n";
        s.write(0, "notes", INDEX, t);
        s.write(0, "notes", INDEX, "- one\n");
        s.meet(&[0, 1, 2, 3]);

        let made = s.now + 10 * MARGIN;
        s.now = made - MARGIN / 2;
        // Late: the tablet writes `T` back, and only the phone takes it.
        let back = s.write(2, "notes", INDEX, t);
        let now = s.tick();
        crate::take::take(&s[3].conn, &s[3].identity, &back, now).unwrap();
        let back_chain = back.open(&s[3].own("notes")).unwrap().chain;
        // The desktop goes on over `U`, and the phone and the laptop take
        // each version as it is written.
        let c = "- one\n- new\n";
        for said in ["- one\n- between\n", c] {
            s.write(0, "notes", INDEX, said);
            s.pass(0, 3);
            s.pass(0, 1);
        }
        assert_eq!(s[3].text("notes", INDEX).as_deref(), Some(c));
        assert_eq!(s[1].text("notes", INDEX).as_deref(), Some(c));
        let c_chain = s[3].slot("notes", INDEX).current.unwrap().entries[0]
            .chain
            .clone()
            .unwrap();
        assert!(
            c_chain
                .iter()
                .any(|link| link.hash == Link::of(&Value::Text(t.into()), [0; 32]).hash)
        );

        // The phone's folder agreed the tablet's `T`, and its agent added a
        // line: the plan merges, `C`'s lines and then its own not in `C`.
        let tablets = OtherSource {
            hash: value_hash(&Value::Text(t.into())),
            signer: s.key(2),
            chain: back_chain,
        };
        let now = s.tick();
        let on = &s[3];
        let write = Write {
            name: "notes",
            file: INDEX,
            value: Value::Text("- one\n- new\n- gone\n- mine\n".into()),
            planned: PlannedAgainst::what_is_in(&on.slot("notes", INDEX)),
            merge: Some(&tablets),
        };
        let Published::Made(merge) = publish(&on.conn, &on.identity, &write, now).unwrap() else {
            panic!("not made");
        };
        let merged_chain = merge.open(&s[3].own("notes")).unwrap().chain.unwrap();
        let mut as_an_edit = vec![Link::of(&Value::Text(c.into()), s.key(0))];
        as_an_edit.extend(c_chain.iter().copied());
        assert_eq!(merged_chain, as_an_edit);

        // The laptop takes the merge alone.
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &merge, now).unwrap();
        assert!(
            s[1].text("notes", INDEX)
                .is_some_and(|text| text.contains("gone"))
        );

        s.now = made - 1;
        let removal = s.change(0, &[0, 1, 3], &[2]);
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
        assert_eq!(s[1].text("notes", INDEX).as_deref(), Some("- one\n"));
        assert!(texts(&s, 1).iter().all(|text| !text.contains("gone")));
    }

    /// A merge whose weave makes exactly an edit's chain over the version
    /// held (the read of #271, its medium). The desktop (0) writes `T`, then
    /// `U` without `- gone`; everyone takes both. The tablet (2) writes `T`
    /// back over `U`; the desktop and the laptop (1) take it, the phone (3)
    /// does not. The desktop writes `C` over the tablet's `T`, and the
    /// laptop takes it. In the window, the tablet sends the phone its own
    /// old `T` entry again: nothing forged. The phone takes `C` and merges
    /// with the tablet's `T` as the other source, so `- gone` comes back.
    /// The merge's chain is `C`'s link and then `C`'s chain, and the
    /// tablet's link stands in it no more times than in `C`'s: no arrival
    /// of the tablet's is noted. The laptop takes the merge alone, and at
    /// the removal it goes back to `C`, by the index rule alone.
    #[test]
    fn a_merge_whose_weave_is_an_edits_chain_over_the_held_version_is_cut() {
        use crate::publish::{OtherSource, PlannedAgainst, Published, Write, publish, value_hash};
        let mut s = Several::of_one_person(4);
        s.hold(&[0, 1, 2, 3], "notes");
        let t = "- one\n- gone\n";
        s.write(0, "notes", INDEX, t);
        s.write(0, "notes", INDEX, "- one\n");
        s.meet(&[0, 1, 2, 3]);
        let back = s.write(2, "notes", INDEX, t);
        for on in [0, 1] {
            let now = s.tick();
            crate::take::take(&s[on].conn, &s[on].identity, &back, now).unwrap();
        }
        let back_chain = back.open(&s[1].own("notes")).unwrap().chain;
        let c = "- one\n- new\n";
        s.write(0, "notes", INDEX, c);
        s.pass(0, 1);
        assert_eq!(s[1].text("notes", INDEX).as_deref(), Some(c));
        let c_chain = s[1].slot("notes", INDEX).current.unwrap().entries[0]
            .chain
            .clone()
            .unwrap();
        assert_eq!(c_chain[0], Link::of(&Value::Text(t.into()), s.key(2)));

        let made = s.now + 10 * MARGIN;
        s.now = made - MARGIN / 2;
        // In the window: the tablet's old `T` again, at the phone, and then
        // the desktop's `C`.
        let now = s.tick();
        crate::take::take(&s[3].conn, &s[3].identity, &back, now).unwrap();
        s.pass(0, 3);
        assert_eq!(s[3].text("notes", INDEX).as_deref(), Some(c));
        let tablets = OtherSource {
            hash: value_hash(&Value::Text(t.into())),
            signer: s.key(2),
            chain: back_chain,
        };
        let now = s.tick();
        let on = &s[3];
        let write = Write {
            name: "notes",
            file: INDEX,
            value: Value::Text("- one\n- new\n- gone\n- mine\n".into()),
            planned: PlannedAgainst::what_is_in(&on.slot("notes", INDEX)),
            merge: Some(&tablets),
        };
        let Published::Made(merge) = publish(&on.conn, &on.identity, &write, now).unwrap() else {
            panic!("not made");
        };
        let merged_chain = merge.open(&s[3].own("notes")).unwrap().chain.unwrap();
        let mut as_an_edit = vec![Link::of(&Value::Text(c.into()), s.key(0))];
        as_an_edit.extend(c_chain.iter().copied());
        assert_eq!(merged_chain, as_an_edit);

        // The laptop takes the merge alone: no arrival of the tablet's.
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &merge, now).unwrap();
        assert!(
            s[1].text("notes", INDEX)
                .is_some_and(|text| text.contains("gone"))
        );
        let id = cordelia_crypto::derive::channel_id(&s[1].own("notes")).unwrap();
        let slot = s[1].slot_of("notes", INDEX);
        let (events, _) = kept::of_file(&s[1].conn, &id, &slot).unwrap();
        let last = events.last().unwrap();
        assert!(
            last.arrivals
                .iter()
                .all(|arrival| arrival.signer != Link::signer_of(&s.key(2))),
            "{:?}",
            last.arrivals
        );

        s.now = made - 1;
        let removal = s.change(0, &[0, 1, 3], &[2]);
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
        assert_eq!(s[1].text("notes", INDEX).as_deref(), Some(c));
        assert!(texts(&s, 1).iter().all(|text| !text.contains("gone")));
    }

    /// The index rule's cost, held so that it cannot change unseen. The
    /// desktop (0) edits the index straight over the version the laptop (1)
    /// holds, with a short chain, and the laptop takes it in the window: it
    /// is set aside at the removal all the same, as every index version
    /// another device wrote and this one took in the window is, and the
    /// index goes back to the version held. Also with one more link behind,
    /// which no edit over a held version would say. The desktop carries
    /// what it wrote itself, so the edit reaches the laptop again in the
    /// new generation.
    #[test]
    fn an_index_edit_by_another_device_over_the_version_held_is_set_aside_in_the_window() {
        use crate::several::entry_by;
        use cordelia_crypto::chain;
        for straight_over in [true, false] {
            let mut s = Several::of_one_person(3);
            s.hold(&[0, 1, 2], "notes");
            s.meet(&[0, 1, 2]);
            let channel = s[1].own("notes");
            let rev = cordelia_core::revision::next_under(None, 1).unwrap();
            let b = s.key(0);
            let zero = Value::Text("- zero\n".into());
            let one = Value::Text("- one\n".into());
            let first_chain = chain::written_over(&zero, &b, Some(&[]));
            let first = entry_by(
                &s[0].identity,
                &channel,
                rev,
                INDEX,
                one.clone(),
                &first_chain,
            );
            for on in [0, 1] {
                let now = s.tick();
                crate::take::take(&s[on].conn, &s[on].identity, &first, now).unwrap();
            }

            let made = s.now + 10 * MARGIN;
            s.now = made - MARGIN / 2;
            let edit = match straight_over {
                true => s.write(0, "notes", INDEX, "- one\n- two\n"),
                false => {
                    let mut chain = chain::written_over(&one, &b, Some(&first_chain));
                    chain.push(Link::of(&Value::Text("- older\n".into()), b));
                    entry_by(
                        &s[0].identity,
                        &channel,
                        rev + 1,
                        INDEX,
                        Value::Text("- one\n- two\n".into()),
                        &chain,
                    )
                }
            };
            let edit_chain = edit.open(&channel).unwrap().chain.unwrap();
            if straight_over {
                let mut as_an_edit = vec![Link::of(&one, b)];
                as_an_edit.extend(first_chain.iter().copied());
                assert_eq!(edit_chain, as_an_edit);
            }
            assert!(edit_chain.len() < MAX_ENTRY_LINKS);
            let now = s.tick();
            crate::take::take(&s[1].conn, &s[1].identity, &edit, now).unwrap();
            assert_eq!(s[1].text("notes", INDEX).as_deref(), Some("- one\n- two\n"));

            s.now = made - 1;
            let removal = s.change(0, &[0, 1], &[2]);
            let now = s.tick();
            let on = &s[1];
            let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
            assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
            assert_eq!(
                s[1].text("notes", INDEX).as_deref(),
                Some("- one\n"),
                "{straight_over}"
            );
            if straight_over {
                // The desktop's own edit, which it carried, comes back.
                s.pass(0, 1);
                assert_eq!(s[1].text("notes", INDEX).as_deref(), Some("- one\n- two\n"));
            }
        }
    }

    /// What a device wrote itself in the index in a removal's window is
    /// carried, as rule 7 says of its own versions: the laptop (1) edits
    /// the index in the window, before it takes anything late, and keeps
    /// it at the removal. When the desktop (0) then edits over the laptop's
    /// version and the laptop takes that in the window, the desktop's is
    /// set aside and the index goes back to the laptop's own.
    #[test]
    fn a_devices_own_index_version_in_the_window_is_carried() {
        for desktop_after in [false, true] {
            let mut s = Several::of_one_person(3);
            s.hold(&[0, 1, 2], "notes");
            s.write(0, "notes", INDEX, "- one\n");
            s.meet(&[0, 1, 2]);

            let made = s.now + 10 * MARGIN;
            s.now = made - MARGIN / 2;
            let mine = "- one\n- the laptop's\n";
            s.write(1, "notes", INDEX, mine);
            if desktop_after {
                s.pass(1, 0);
                s.write(
                    0,
                    "notes",
                    INDEX,
                    "- one\n- the laptop's\n- the desktop's\n",
                );
                s.pass(0, 1);
                assert!(
                    s[1].text("notes", INDEX)
                        .is_some_and(|text| text.contains("desktop"))
                );
            }

            s.now = made - 1;
            let removal = s.change(0, &[0, 1], &[2]);
            let now = s.tick();
            let on = &s[1];
            let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
            assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
            assert_eq!(
                s[1].text("notes", INDEX).as_deref(),
                Some(mine),
                "{desktop_after}"
            );
        }
    }

    /// An index edit over a held text that another key signed (the fourth
    /// read's round, kept under the simple index rule). The laptop
    /// holds device 0's `- one`, whose chain is `- zero`, and beside it at
    /// the same revision its own, whose chain names the tablet's `- one`
    /// twice. Device 0's version after the cut time is written, it says,
    /// over the tablet's `- one`, and then `- zero`: the text and the rest
    /// of the chain are those of the version held, but not the signer. The
    /// tablet's link stands there no more times than in a chain held, so it
    /// makes no arrival; it is an index version another device wrote,
    /// taken in the window, and the carry leaves it out (the index rule).
    #[test]
    fn an_index_edit_over_a_held_text_another_key_signed_is_cut() {
        use crate::several::entry_by;
        use cordelia_crypto::chain;
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        let channel = s[1].own("notes");
        let rev = cordelia_core::revision::next_under(None, 1).unwrap();
        let (b, k) = (s.key(0), s.key(2));
        let zero = Value::Text("- zero\n".into());
        let one = Value::Text("- one\n".into());
        let rest = chain::written_over(&zero, &b, Some(&[]));
        let tablets = Link::of(&one, k);
        let held = entry_by(&s[0].identity, &channel, rev, INDEX, one.clone(), &rest);
        let beside = entry_by(
            &s[1].identity,
            &channel,
            rev,
            INDEX,
            Value::Text("- one, the laptop's\n".into()),
            &[tablets, tablets],
        );
        for entry in [&held, &beside] {
            let now = s.tick();
            crate::take::take(&s[1].conn, &s[1].identity, entry, now).unwrap();
        }
        let before = s[1].text("notes", INDEX);

        let made = s.now + 10 * MARGIN;
        s.now = made - MARGIN / 2;
        let mut chain = vec![tablets];
        chain.extend(rest.iter().copied());
        let late = entry_by(
            &s[0].identity,
            &channel,
            rev + 1,
            INDEX,
            Value::Text("- one\n- over the tablet's late text\n".into()),
            &chain,
        );
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &late, now).unwrap();
        assert!(
            s[1].text("notes", INDEX)
                .is_some_and(|text| text.contains("late"))
        );

        s.now = made - 1;
        let removal = s.change(0, &[0, 1], &[2]);
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
        assert_eq!(s[1].text("notes", INDEX), before);
        assert!(texts(&s, 1).iter().all(|text| !text.contains("late")));
    }

    /// The generation device `n` follows, by its statement's number and
    /// hash.
    fn generation_of(s: &Several, n: usize) -> Change {
        let link = s[n].held().statement.statement.link().unwrap();
        (link.number, link.hash)
    }

    /// Rule 27, the sequence of section 8's limit (the person's ruling of 30
    /// October): the desktop (0) removes the tablet (2). Before the laptop
    /// (1) knows, it takes the tablet's late `w.md`, and then writes
    /// `notes.md`, a new file, as its agent would that read the late text,
    /// and edits `keep.md`, which it wrote long before. When it applies the
    /// removal, neither is carried: `notes.md` goes back to none and
    /// `keep.md` to its earlier text, with `w.md` by rule 7. What it wrote
    /// before the late text came (`early.md`, after the cut time) is kept.
    #[test]
    fn what_a_device_wrote_after_it_took_late_writing_is_set_aside() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.write(1, "notes", "keep.md", "keep, long before");
        s.meet(&[0, 1, 2]);
        s.now += MARGIN + 1;
        let removal = s.change(0, &[0, 1], &[2]);
        s.write(1, "notes", "early.md", "written before the late text came");
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 1);
        s.write(
            1,
            "notes",
            "notes.md",
            "the late text, as the agent wrote it down",
        );
        s.write(1, "notes", "keep.md", "keep, edited after the late text");
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(
            matches!(taken, Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        assert_eq!(s[1].text("notes", "w.md"), None);
        assert_eq!(s[1].text("notes", "notes.md"), None);
        assert_eq!(
            s[1].text("notes", "keep.md").as_deref(),
            Some("keep, long before")
        );
        assert_eq!(
            s[1].text("notes", "early.md").as_deref(),
            Some("written before the late text came")
        );
        assert!(
            texts(&s, 1)
                .iter()
                .all(|text| !text.contains("late text") || text.contains("before")),
            "{:?}",
            texts(&s, 1)
        );
        // The desktop is given what the laptop carried: none of it.
        s.pass(1, 0);
        assert_eq!(s[0].text("notes", "notes.md"), None);
        assert_eq!(
            s[0].text("notes", "keep.md").as_deref(),
            Some("keep, long before")
        );
    }

    /// The cut says which rule leaves each file out (the review of the
    /// whole build, its M4): the tablet's late `w.md` by rule 7, and what
    /// the laptop wrote itself after it took it (`notes.md`, `keep.md`) by
    /// rule 27, so that the status and the commands say each in its own
    /// words, and point to `--from` only for the first.
    ///
    /// Taken out: the mark (every file is said as rule 7's: the second
    /// fails).
    #[test]
    fn the_cut_tells_rule_27s_files_from_rule_7s() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.write(1, "notes", "keep.md", "keep, long before");
        s.meet(&[0, 1, 2]);
        s.now += MARGIN + 1;
        let removal = s.change(0, &[0, 1], &[2]);
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 1);
        s.write(
            1,
            "notes",
            "notes.md",
            "the late text, as the agent wrote it",
        );
        s.write(1, "notes", "keep.md", "keep, edited after the late text");
        let now = s.tick();
        let on = &s[1];
        crate::person::know_what_is_shown(&on.conn, &on.identity, &removal, now).unwrap();
        let secret = on.own("notes");
        let channel = cordelia_crypto::derive::channel_id(&secret).unwrap();
        let cuts = crate::cut::Cuts::read(&on.conn).unwrap();
        let windows = windows(&on.conn, &[channel], &cuts).unwrap();
        let cut = cut_of_channel(
            &on.conn,
            &on.key(),
            &secret,
            &cuts,
            &windows,
            &mut BTreeSet::new(),
        )
        .unwrap();
        let own_of = |file: &str| cut.get(&on.slot_of("notes", file)).map(|cut| cut.own);
        assert_eq!(own_of("w.md"), Some(false));
        assert_eq!(own_of("notes.md"), Some(true));
        assert_eq!(own_of("keep.md"), Some(true));
    }

    /// Rule 27: what a device wrote before the first late arrival it took
    /// is kept, though it came after the cut time; and a late arrival in
    /// one name sets aside what the device wrote in another name after it.
    #[test]
    fn what_a_device_wrote_before_the_first_late_arrival_is_kept() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.hold(&[0, 1, 2], "work");
        s.meet(&[0, 1, 2]);
        s.now += MARGIN + 1;
        let removal = s.change(0, &[0, 1], &[2]);
        s.now += 5;
        s.write(
            1,
            "work",
            "before.md",
            "after the cut time, before the late text",
        );
        s.write(1, "notes", "before.md", "also before the late text");
        s.now += 5;
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 1);
        s.write(1, "work", "after.md", "in another name, after it");
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(
            matches!(taken, Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        assert_eq!(
            s[1].text("work", "before.md").as_deref(),
            Some("after the cut time, before the late text")
        );
        assert_eq!(
            s[1].text("notes", "before.md").as_deref(),
            Some("also before the late text")
        );
        assert_eq!(s[1].text("work", "after.md"), None);
    }

    /// Rule 27, the index: an edit of `MEMORY.md` that the laptop makes
    /// after it took the tablet's late writing of another file goes back to
    /// the index it held before, as its other files do.
    #[test]
    fn an_index_written_after_late_writing_was_taken_is_set_aside() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.write(1, "notes", INDEX, "- one\n");
        s.meet(&[0, 1, 2]);
        s.now += MARGIN + 1;
        let removal = s.change(0, &[0, 1], &[2]);
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 1);
        s.write(1, "notes", INDEX, "- one\n- [w](w.md): the late text\n");
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(
            matches!(taken, Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        assert_eq!(s[1].text("notes", INDEX).as_deref(), Some("- one\n"));
    }

    /// Rule 27, across a carry made before the device knew: the tablet's
    /// late writing is a delete of `w.md`, which the laptop takes, and then
    /// the laptop writes `notes.md` and renews, apart from the removal. Its
    /// renewal carries the delete with its events: when it moves to the
    /// desktop's change, the late delete still opens the window, and
    /// `notes.md` goes back to none.
    #[test]
    fn a_late_delete_carried_before_the_device_knew_still_opens_the_window() {
        use crate::several::entry_by;
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.write(1, "notes", "w.md", "w, long before");
        s.meet(&[0, 1, 2]);
        s.now += MARGIN + 1;
        s.change(0, &[0, 1], &[2]);
        let rev = newest_rev(&s, 1, "w.md");
        let delete = entry_by(
            &s[2].identity,
            &s[1].own("notes"),
            rev + 1,
            "w.md",
            Value::Delete,
            &[Link::of(&Value::Text("w, long before".into()), s.key(1))],
        );
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &delete, now).unwrap();
        assert_eq!(s[1].text("notes", "w.md").as_deref(), Some("Delete"));
        s.write(1, "notes", "notes.md", "written after the late delete");
        s.change(1, &[1, 0, 2], &[]);
        assert_eq!(
            s[1].text("notes", "notes.md").as_deref(),
            Some("written after the late delete")
        );
        let taken = s.pass(0, 1);
        assert!(
            matches!(taken[0], Taken::Shown(Shown::Moved(_))),
            "{:?}",
            taken[0]
        );
        assert_eq!(s[1].text("notes", "notes.md"), None);
    }

    /// Rule 27, past the bound of the device's own versions: the laptop
    /// writes `notes.md` after it took the tablet's late text, and then more
    /// than `MAX_FILE_ARRIVALS` versions of its own follow in that file (set
    /// by hand), so the first goes past the bound with the version before
    /// it. Its time is inside the window: the file goes back to none, and
    /// not to the laptop's first version, which the events kept go back to.
    #[test]
    fn a_version_of_its_own_past_the_bound_in_a_window_goes_back_to_none() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        s.now += MARGIN + 1;
        let removal = s.change(0, &[0, 1], &[2]);
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 1);
        let first = s.write(1, "notes", "notes.md", "the late text, written down");
        let generation = generation_of(&s, 1);
        let on = &s[1];
        let channel = cordelia_crypto::derive::channel_id(&on.own("notes")).unwrap();
        let slot = on.slot_of("notes", "notes.md");
        for i in 0..MAX_FILE_ARRIVALS {
            kept::note_own(
                &on.conn,
                &channel,
                &slot,
                generation.0,
                &generation.1,
                s.now + 1 + i as i64,
                Some(&first),
                &first.id(),
            )
            .unwrap();
        }
        assert_eq!(
            kept::own_dropped_of_file(&on.conn, &channel, &slot)
                .unwrap()
                .len(),
            1
        );
        s.now += MAX_FILE_ARRIVALS as i64 + 2;
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(
            matches!(taken, Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        assert_eq!(s[1].text("notes", "notes.md"), None);
    }

    /// Rule 27, what went past the arrivals' bound in a change made apart
    /// from the removal: the laptop renews (its change 3, apart), writes
    /// `before.md` there, and then more than `MAX_FILE_ARRIVALS` arrivals of
    /// the tablet's come in `w.md` (set by hand), so the first go past the
    /// bound, and the laptop writes `notes.md` (and `between.md`, after the
    /// first, which went, and before those kept). Everything of the tablet's
    /// is cut there, at any time, and the times of what went are not kept
    /// but the newest: the window opens at any time, at the place of the
    /// first that went, so `notes.md` and `between.md` go back to none,
    /// though they were written long before the desktop's removal and its
    /// cut time. `before.md`, stored before any of them, is kept.
    #[test]
    fn what_went_past_the_bound_in_a_change_made_apart_opens_the_window_at_any_time() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.write(1, "notes", "w.md", "w, long before");
        s.meet(&[0, 1, 2]);
        s.change(1, &[1, 0, 2], &[]);
        s.write(1, "notes", "before.md", "written before the arrivals");
        let generation = generation_of(&s, 1);
        let channel = cordelia_crypto::derive::channel_id(&s[1].own("notes")).unwrap();
        let slot = s[1].slot_of("notes", "w.md");
        let tablet = Arrival {
            signer: Link::signer_of(&s.key(2)),
            link: None,
            times: 1,
        };
        let base = s.now;
        for i in 0..=MAX_FILE_ARRIVALS {
            kept::note(
                &s[1].conn,
                &channel,
                &slot,
                generation.0,
                &generation.1,
                base + 1 + i as i64,
                &[],
                None,
                None,
                &[tablet],
            )
            .unwrap();
            // Between the first arrival, which goes past the bound, and
            // those kept: only what went opens the window for it.
            if i == 0 {
                s.write(1, "notes", "between.md", "written after the first arrival");
            }
        }
        let on = &s[1];
        assert_eq!(kept::of_file(&on.conn, &channel, &slot).unwrap().1.len(), 1);
        s.now += MAX_FILE_ARRIVALS as i64 + 2;
        s.write(1, "notes", "notes.md", "written after the arrivals");
        // The desktop removes the tablet long after, from change 2.
        s.now += 10 * MARGIN + MAX_FILE_ARRIVALS as i64;
        let removal = s.change(0, &[0, 1], &[2]);
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(matches!(taken, Taken::Shown(Shown::Moved(_))), "{taken:?}");
        assert_eq!(s[1].text("notes", "notes.md"), None);
        assert_eq!(s[1].text("notes", "between.md"), None);
        assert_eq!(
            s[1].text("notes", "before.md").as_deref(),
            Some("written before the arrivals")
        );
    }

    /// Rule 27, the window closes when the device knew: a version of its
    /// own stored then, in that second, is set aside, and one stored after
    /// is not; one stored before it, after the first late arrival, is. An
    /// arrival opens it by its place, whatever the clock said; a message
    /// by its time. Of the device's own versions that went past their
    /// bound, the file goes back to none where the newest went after it
    /// opened and the oldest before it closed (the review of rule 27, its
    /// first low).
    #[test]
    fn a_window_closes_when_the_device_knew() {
        let key = [9; 32];
        let closes: BTreeMap<[u8; 32], i64> = [(key, 200)].into_iter().collect();
        let mut windows = Windows {
            closes: closes.clone(),
            ..Windows::default()
        };
        windows.open_after(key, 7, 120);
        windows.open_after(key, 5, 100);
        // Before its first arrival, by place, whatever the clock said.
        assert!(!windows.sets_aside(150, 4));
        assert!(!windows.sets_aside(150, 5));
        // After it, a clock stepped back does not take it out.
        assert!(windows.sets_aside(90, 6));
        assert!(windows.sets_aside(199, 9));
        // In the second the device knew, it is in (fails safe); after, not.
        assert!(windows.sets_aside(200, 9));
        assert!(!windows.sets_aside(201, 9));
        assert_eq!(windows.opens_at(), Some(100));

        let went = |oldest_at, newest_at, newest_place| kept::OwnDropped {
            number: 2,
            hash: [2; 16],
            newest_at,
            oldest_at,
            newest_place,
        };
        assert!(windows.may_have_set_aside(&went(50, 150, 6)));
        assert!(!windows.may_have_set_aside(&went(50, 150, 5)));
        // Every one that went was stored after the device knew: none was in
        // the window, and the file is judged by the events kept.
        assert!(windows.may_have_set_aside(&went(200, 300, 20)));
        assert!(!windows.may_have_set_aside(&went(201, 300, 20)));

        // A message opens it at its time.
        let mut by_time = Windows {
            closes,
            ..Windows::default()
        };
        by_time.open_from(key, 100);
        assert!(!by_time.sets_aside(99, 50));
        assert!(by_time.sets_aside(100, 1));
        assert!(!by_time.sets_aside(201, 60));
    }

    /// Rule 27 across a change made apart (the review of rule 27, its
    /// high): the desktop (0) removes the tablet (2). The laptop (1) takes
    /// the tablet's late `w.md` under change 2, then makes a change apart
    /// from the removal (its change 3) before it knows, and its agent
    /// writes `notes.md` there. When the laptop is shown the removal and
    /// moves, `notes.md` is set aside with `w.md`: the window opened in
    /// change 2 is not of change 2 alone. What it wrote in change 3 before
    /// it took the late text is kept.
    #[test]
    fn own_writing_in_a_later_generation_is_set_aside() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        s.now += MARGIN + 1;
        s.change(0, &[0, 1], &[2]);
        s.write(1, "notes", "early.md", "written before the late text came");
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 1);
        assert_eq!(
            s[1].text("notes", "w.md").as_deref(),
            Some("the tablet's late text")
        );
        s.change(1, &[1, 0, 2], &[]);
        s.write(
            1,
            "notes",
            "notes.md",
            "the late text, written down in change 3",
        );
        assert_eq!(
            s[1].text("notes", "notes.md").as_deref(),
            Some("the late text, written down in change 3")
        );
        let taken = s.pass(0, 1);
        assert!(
            matches!(taken[0], Taken::Shown(Shown::Moved(_))),
            "{:?}",
            taken[0]
        );
        assert_eq!(s[1].text("notes", "w.md"), None);
        assert_eq!(s[1].text("notes", "notes.md"), None);
        assert_eq!(
            s[1].text("notes", "early.md").as_deref(),
            Some("written before the late text came")
        );
        // The desktop is given what the laptop carried: none of it.
        s.pass(1, 0);
        assert_eq!(s[0].text("notes", "notes.md"), None);
    }

    /// Rule 27 with a clock that was once ahead (the review of rule 27, its
    /// clock): the laptop (1) stores `ahead.md` while its clock is an hour
    /// ahead, and the clock is put right. Within that hour it takes the
    /// tablet's late `w.md`, and writes `notes.md`, which is stamped no
    /// earlier than `ahead.md`; then it applies the removal. The window
    /// closes no earlier than the newest time stamped when the device knew,
    /// so `notes.md` is set aside; `ahead.md`, stored before the late
    /// arrival by its place, is kept.
    #[test]
    fn a_clock_once_ahead_does_not_empty_the_window() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        s.now += MARGIN + 1;
        let removal = s.change(0, &[0, 1], &[2]);
        s.now += 3600;
        s.write(1, "notes", "ahead.md", "stored with the clock ahead");
        s.now -= 3600;
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 1);
        s.write(
            1,
            "notes",
            "notes.md",
            "the late text, as the agent wrote it down",
        );
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(
            matches!(taken, Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        assert_eq!(s[1].text("notes", "w.md"), None);
        assert_eq!(s[1].text("notes", "notes.md"), None);
        assert_eq!(
            s[1].text("notes", "ahead.md").as_deref(),
            Some("stored with the clock ahead")
        );
    }

    /// Message `number` of device `from`, saying `body`, sent at `sent`, in
    /// the messages channel of the generation device `on` follows.
    fn message(s: &Several, on: usize, from: usize, number: u64, body: &str) -> CheckedEntry {
        use cordelia_core::protocol::AGENT_MESSAGE_ID_BYTES;
        use cordelia_crypto::message::{Message, To, message_name, message_rev};
        let said = Message {
            asks: false,
            sent: u64::try_from(s.now).unwrap(),
            nonce: [0; 16],
            thread: [0; AGENT_MESSAGE_ID_BYTES],
            answers: [0; AGENT_MESSAGE_ID_BYTES],
            from: "~".into(),
            to: To::Name("notes".into()),
            link: None,
            body: body.into(),
        };
        let messages = cordelia_crypto::derive::messages_secret(&s[on].secret()).unwrap();
        crate::several::entry_by(
            &s[from].identity,
            &messages,
            message_rev(number).unwrap(),
            &message_name(&s.key(from), number).unwrap(),
            Value::Other(said.to_value(crate::names::is_a_name).unwrap()),
            &[],
        )
    }

    /// Rule 27, a late message (the review of rule 27, its messages): the
    /// tablet (2) sent one message long before its removal, and one after
    /// it; the laptop (1) took both before it knew. The second opens the
    /// window though no file of the tablet's came late: `notes.md`, which
    /// the laptop wrote after it, is set aside. `before.md`, written after
    /// the first message and after the cut time, but before the late one,
    /// is kept.
    #[test]
    fn a_late_message_opens_the_window() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        let early = message(&s, 1, 2, 1, "an honest message");
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &early, now).unwrap();
        s.now += 2 * MARGIN;
        let removal = s.change(0, &[0, 1], &[2]);
        s.write(
            1,
            "notes",
            "before.md",
            "after the cut time, before the message",
        );
        let late = message(&s, 1, 2, 2, "the tablet's late message");
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &late, now).unwrap();
        let held = cordelia_storage::messages::held_of(&s[1].conn, &s.key(2)).unwrap();
        assert_eq!(held.held.len(), 2, "{held:?}");
        s.write(
            1,
            "notes",
            "notes.md",
            "the late message, as the agent wrote it down",
        );
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(
            matches!(taken, Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        assert_eq!(s[1].text("notes", "notes.md"), None);
        assert_eq!(
            s[1].text("notes", "before.md").as_deref(),
            Some("after the cut time, before the message")
        );
    }

    /// Rule 27, a late message whose record went past the ring before the
    /// carry (the removed device sent more than `AGENT_MESSAGE_RING`, or
    /// cleared it): its time is not kept, and the window opens at the
    /// earliest it could have been cut, so `notes.md`, written after it, is
    /// set aside.
    #[test]
    fn a_late_message_that_went_past_the_ring_still_opens_the_window() {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        s.now += MARGIN + 1;
        let removal = s.change(0, &[0, 1], &[2]);
        let late = message(&s, 1, 2, 1, "the tablet's late message");
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &late, now).unwrap();
        // As the ring drops a number that is no longer live.
        s[1].conn
            .execute(
                "DELETE FROM message_first_held WHERE signer = ?1",
                [&s.key(2)[..]],
            )
            .unwrap();
        let held = cordelia_storage::messages::held_of(&s[1].conn, &s.key(2)).unwrap();
        assert!(held.held.is_empty(), "{held:?}");
        assert_eq!(held.went.len(), 1, "{held:?}");
        s.write(
            1,
            "notes",
            "notes.md",
            "the late message, as the agent wrote it down",
        );
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(
            matches!(taken, Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        assert_eq!(s[1].text("notes", "notes.md"), None);
    }

    /// Rule 27, after the device knew: the laptop follows a change made
    /// apart from the removal that never listed the tablet (its change 3
    /// lists the desktop, the laptop and the phone), so it stays clear and
    /// the laptop goes on there once it knows (rule 11). The phone (3)
    /// carried the tablet's late text into it, and the laptop took that:
    /// a window opens there. What the laptop wrote before it knew is set
    /// aside at its next carry; what it wrote after it knew is kept.
    #[test]
    fn what_a_device_wrote_after_it_knew_is_kept() {
        let mut s = Several::of_one_person(4);
        s.hold(&[0, 1, 2, 3], "notes");
        s.meet(&[0, 1, 2, 3]);
        s.now += MARGIN + 1;
        let removal = s.change(0, &[0, 1, 3], &[2]);
        // Late, under change 2: the tablet writes, and the phone takes it.
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 3);
        // The laptop renews without the tablet, apart from the removal;
        // the phone applies it, carrying the late text.
        s.change(1, &[1, 0, 3], &[]);
        let taken = s.pass(1, 3);
        assert!(
            matches!(taken[0], Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        s.pass(3, 1);
        assert_eq!(
            s[1].text("notes", "w.md").as_deref(),
            Some("the tablet's late text")
        );
        s.write(1, "notes", "before.md", "before the laptop knew");
        // The laptop is shown the removal: its change is clear, and it
        // goes on.
        let now = s.tick();
        let on = &s[1];
        crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(held_rows_removed(&s, 1).contains(&s.key(2)));
        s.write(1, "notes", "after.md", "after the laptop knew");
        // A later change of the laptop's carries from its change 3.
        s.change(1, &[1, 0, 3], &[2]);
        assert_eq!(s[1].text("notes", "before.md"), None);
        assert_eq!(
            s[1].text("notes", "after.md").as_deref(),
            Some("after the laptop knew")
        );
        assert_eq!(s[1].text("notes", "w.md"), None);
    }

    /// The keys device `n` keeps as removed.
    fn held_rows_removed(s: &Several, n: usize) -> Vec<[u8; 32]> {
        cordelia_storage::person::removed_keys(&s[n].conn).unwrap()
    }

    /// Rule 27, where it does not hold (the limit, shown): the phone (3)
    /// took the laptop's `notes.md` from the laptop's window before either
    /// knew. The laptop sets it aside at its carry; the phone, which cannot
    /// see when the laptop's window opened, carries it as the laptop's
    /// version, and the laptop takes that carry back in the new generation.
    /// And a carry by command on the laptop leaves out what it wrote in its
    /// window, which the relays still hold in the old generation.
    #[test]
    fn another_device_that_took_the_window_writing_carries_it() {
        let mut s = Several::of_one_person(4);
        s.hold(&[0, 1, 2, 3], "notes");
        s.meet(&[0, 1, 2, 3]);
        s.now += MARGIN + 1;
        let removal = s.change(0, &[0, 1, 3], &[2]);
        s.write(2, "notes", "w.md", "the tablet's late text");
        s.pass(2, 1);
        let written = s.write(1, "notes", "notes.md", "the late text, written down");
        let old_secret = s[1].own("notes");
        let old_generation = generation_of(&s, 1);
        s.pass(1, 3);
        assert!(s[3].text("notes", "notes.md").is_some());
        let now = s.tick();
        let on = &s[1];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(
            matches!(taken, Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        assert_eq!(s[1].text("notes", "notes.md"), None);

        // A carry by command on the laptop, of what the relays hold of the
        // old generation, leaves its window writing out, as rule 27's own:
        // no command brings it in (the review of the whole build, its M4).
        let version = version_of(&written, &old_secret).unwrap().unwrap();
        let now = s.tick();
        let on = &s[1];
        let brought = crate::carry::bring(
            &on.conn,
            &on.identity,
            "notes",
            &version,
            crate::carry::Rule::Counts(Some(old_generation)),
            now,
        )
        .unwrap();
        assert_eq!(brought, crate::carry::Brought::CutOwn);

        // The phone applies the removal, and carries the laptop's version.
        let now = s.tick();
        let on = &s[3];
        let taken = crate::take::take(&on.conn, &on.identity, &removal, now).unwrap();
        assert!(
            matches!(taken, Taken::Shown(Shown::Applied(_))),
            "{taken:?}"
        );
        assert_eq!(
            s[3].text("notes", "notes.md").as_deref(),
            Some("the late text, written down")
        );
        s.pass(3, 1);
        assert_eq!(
            s[1].text("notes", "notes.md").as_deref(),
            Some("the late text, written down"),
            "the limit: it comes back from the phone's carry"
        );
    }

    /// After a removal, honest arrivals are not cut again at a later change
    /// (the review of slice 8, its second finding). The laptop applies the
    /// removal. Long after, device 0 writes `w.md` with a full chain that
    /// holds one old link of the tablet's. The desktop renews, listing the
    /// tablet as removed again (rule 20), and the laptop applies it: the
    /// generation of the removal is on the renewal's chain, and what came
    /// in it is not judged by time.
    #[test]
    fn an_honest_edit_after_a_removal_is_not_set_aside_at_a_later_change() {
        use crate::several::entry_by;
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], "notes");
        s.meet(&[0, 1, 2]);
        let tablet_link = Link::of(&Value::Text("the tablet's\n".into()), s.key(2));
        let first_rev = cordelia_core::revision::next_under(None, 1).unwrap();
        let first = entry_by(
            &s[0].identity,
            &s[1].own("notes"),
            first_rev,
            "w.md",
            Value::Text("one\n".into()),
            &[tablet_link],
        );
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &first, now).unwrap();
        s.now += 10 * MARGIN;
        let removal = s.change(0, &[0, 1], &[2]);
        let now = s.tick();
        let taken = crate::take::take(&s[1].conn, &s[1].identity, &removal, now).unwrap();
        assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
        assert_eq!(s[1].text("notes", "w.md").as_deref(), Some("one\n"));

        // Long after, an honest edit with a full chain.
        s.now += 100 * MARGIN;
        let mut chain = vec![tablet_link];
        chain.extend((0..MAX_ENTRY_LINKS - 1).map(|i| Link {
            hash: [i as u8; 16],
            signer: Link::signer_of(&s.key(0)),
        }));
        let rev = newest_rev(&s, 1, "w.md");
        let honest = entry_by(
            &s[0].identity,
            &s[1].own("notes"),
            rev + 1,
            "w.md",
            Value::Text("two, long after\n".into()),
            &chain,
        );
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &honest, now).unwrap();
        assert_eq!(
            s[1].text("notes", "w.md").as_deref(),
            Some("two, long after\n")
        );

        // The desktop renews, and the laptop applies the renewal.
        s.now += MARGIN;
        let renewal = s.change(0, &[0, 1], &[2]);
        let now = s.tick();
        let taken = crate::take::take(&s[1].conn, &s[1].identity, &renewal, now).unwrap();
        assert!(matches!(taken, Taken::Shown(Shown::Applied(_))));
        assert_eq!(
            s[1].text("notes", "w.md").as_deref(),
            Some("two, long after\n")
        );
    }
}
