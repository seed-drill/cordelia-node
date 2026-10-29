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
//! cut, the file goes back to before the oldest kept. The arrivals that are
//! not cut go with the file to the channel it is carried to.

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
        &arrivals,
    )?;
    Ok(())
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
    from: &[u8; 32],
    cuts: &Cuts,
) -> Result<BTreeMap<[u8; 32], FileCut>, PersonError> {
    let channel = cordelia_crypto::derive::channel_id(from)?;
    let mut cut = BTreeMap::new();
    if cuts.keys().is_empty() {
        return Ok(cut);
    }
    for slot in entries::channel_slots(conn, &channel)? {
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
        // key, at the newest time that went.
        let went = dropped
            .iter()
            .filter(|went| any_key(&(went.number, went.hash), went.newest_at))
            .map(|went| went.newest_at)
            .max();
        let first = match went {
            Some(at) => Some((events.first(), at)),
            None => events
                .iter()
                .find(|event| {
                    let generation = (event.number, event.hash);
                    event
                        .arrivals
                        .iter()
                        .map(|arrival| &arrival.signer)
                        .chain(&event.full_signers)
                        .any(|signer| of_signer(signer, &generation, event.stored_at))
                })
                .map(|event| (Some(event), event.stored_at)),
        };
        let Some((event, at)) = first else {
            continue;
        };
        let target = match event.and_then(|event| event.before.as_ref()) {
            Some(before) => version_of(before, from)?,
            None => None,
        };
        cut.insert(
            slot,
            FileCut {
                place: event.map(|event| event.place),
                at,
                target,
            },
        );
    }
    Ok(cut)
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
}
