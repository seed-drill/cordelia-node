//! The arrivals of each file, and the cut at a carry (decision 2026-10-24
//! (removal), rule 7).
//!
//! **At the door** ([`noted_at_the_door`]), an entry that another key signed
//! in the channel of a name makes arrivals: the version, with its signer,
//! and each link of its chain that stands there more times than in any
//! chain of the file stored before (a link is only a text's hash and its
//! signer, so a text written back stands again). Where its chain is full
//! (100 links), the other keys its links name are kept with it: a removed
//! key's link there is cut all the same. With them are kept the generation
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

use std::collections::{BTreeMap, HashMap};

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
    let chain = entry
        .open(secret)
        .ok()
        .and_then(|inside| inside.chain)
        .unwrap_or_default();
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
    kept::note(
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
    Ok(())
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
}

/// Each file of the channel whose secret is `from`, under the statement
/// numbered `statement`, that the cut leaves out from somewhere, by its
/// slot (rule 7). A file that is not in it is carried as it is.
pub(crate) fn cut_of_channel(
    conn: &Connection,
    own: &[u8; 32],
    from: &[u8; 32],
    cuts: &Cuts,
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
        let first = match went {
            Some(at) => {
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
                })
            }
            None => events
                .iter()
                .position(|event| {
                    let generation = (event.number, event.hash);
                    event
                        .arrivals
                        .iter()
                        .map(|arrival| &arrival.signer)
                        .chain(&event.full_signers)
                        .any(|signer| of_signer(signer, &generation, event.stored_at))
                })
                .map(|index| {
                    let event = &events[index];
                    let stored = events[..index].iter().map(|event| event.stored_id);
                    let went = dropped.iter().map(|went| went.first_stored_id);
                    First {
                        place: Some(event.place),
                        generation: (event.number, event.hash),
                        at: event.stored_at,
                        before: event.before.as_ref(),
                        stored_before: stored.chain(went).flatten().collect(),
                    }
                }),
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
        let target = target.filter(|version| {
            brought
                || !version.entries.iter().any(|one| {
                    cuts.cuts_key(&one.author, &first.generation, first.at)
                        || one
                            .chain
                            .iter()
                            .flatten()
                            .any(|link| of_signer(&link.signer, &first.generation, first.at))
                })
        });
        cut.insert(
            slot,
            FileCut {
                place: first.place,
                at: first.at,
                target,
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
                assert_eq!((events.len(), dropped.len()), (MAX_FILE_ARRIVALS, 1));
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
    /// link makes no arrival, and the honest version is carried.
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
            let oldest = version_of(events[0].before.as_ref().unwrap(), &s[1].own("notes"))
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
