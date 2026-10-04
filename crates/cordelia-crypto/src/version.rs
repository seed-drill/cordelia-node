//! A slot's current version (decision 2026-10-04 §2.3, §4.4, §7.3).
//!
//! A slot holds one entry for each author. A device reads it with the
//! channel's secret, the number of the statement it has applied, and its
//! word on which keys count:
//!
//! - Only an entry whose signer counts is looked at. An entry's writer
//!   is its author, so an entry that a key which does not count signed is
//!   nothing here.
//! - An entry is **no version** where it does not open, where it opens to
//!   something that is not an entry's content, where its name and value
//!   are over their bound, and where its revision may not be an entry's
//!   under the statement. It is passed over.
//! - The **current version** is the one at the highest revision among
//!   versions. At one revision a text beats a delete, and of two texts the
//!   one with the higher SHA-256 wins. Bytes that are not a text rank as a
//!   text does, by the hash of the bytes. The hash is of the text,
//!   whatever its ciphertext: an entry that is sealed again ranks where it
//!   did.
//! - Entries with one value at one revision **are one version**, whoever
//!   signed them: two devices carried it, or made the same edit apart.
//!   They are given together, each with its author and its chain, and
//!   none of them wins over another.
//! - The **next revision** is one above the highest that counts for it
//!   ([`cordelia_core::revision::next_under`]). Every entry of a signer
//!   that counts does, a version or not, so that a device's next edit is
//!   above what it cannot read: all but an entry in a band above the
//!   statement's, which counts for nothing.

use cordelia_core::revision::{band, may_be_under, next_under};

use crate::entry::{ChannelKeys, CheckedEntry, EntryError, Link, Value};

/// What a slot holds, as a device reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    /// The current version, where the slot holds a version at all.
    pub current: Option<Version>,
    /// The other versions at the current one's revision: those that lost
    /// the tie, the one that came nearest first.
    pub lost: Vec<Version>,
    /// The highest revision that counts for the next one.
    pub highest: Option<u64>,
    /// The next revision under the statement. `None` where there is none
    /// until the next statement.
    pub next: Option<u64>,
}

/// One version: a value at a revision, and every entry that is it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub rev: u64,
    /// The name its entries give, which is the slot's.
    pub name: String,
    pub value: Value,
    /// The entries that are this version, in order of their authors' keys.
    /// There is at least one.
    pub entries: Vec<VersionEntry>,
}

/// One of the entries that are a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionEntry {
    /// What the entry is named by ([`crate::entry::Entry::id`]).
    pub id: [u8; 32],
    /// The key that signed it, and so wrote it. It counts.
    pub author: [u8; 32],
    /// The entry's chain, or `None` where the entry lacks what it should
    /// say ([`crate::entry::Inside::chain`]).
    pub chain: Option<Vec<Link>>,
}

/// Read a slot: its current version, the versions that tie with it, and
/// the next revision.
///
/// `entries` is every entry that the device holds in the slot, `secret`
/// the channel's, `statement` the number of the statement that the device
/// has applied, and `counts` says whether a key counts (decision
/// 2026-10-04 §4.4).
///
/// Entries of another channel than the secret's, or of more than one
/// slot, are refused: there is no slot to read.
pub fn current(
    entries: &[CheckedEntry],
    secret: &[u8; 32],
    statement: u64,
    counts: impl Fn(&[u8; 32]) -> bool,
) -> Result<Slot, EntryError> {
    let keys = ChannelKeys::of(secret)?;
    if entries.iter().any(|entry| entry.channel != keys.id) {
        return Err(EntryError::AnotherChannel);
    }
    if entries.windows(2).any(|pair| pair[0].slot != pair[1].slot) {
        return Err(EntryError::NotOneSlot);
    }

    let looked_at: Vec<&CheckedEntry> = entries
        .iter()
        .filter(|entry| counts(&entry.author))
        .collect();
    let highest = looked_at
        .iter()
        .map(|entry| entry.rev)
        .filter(|rev| band(*rev) <= statement)
        .max();

    // The highest revision first. The first entry that is a version is at
    // the current revision, and only the versions at that revision tie
    // with it: nothing below it is opened.
    let mut may_be: Vec<&CheckedEntry> = looked_at
        .into_iter()
        .filter(|entry| may_be_under(entry.rev, statement))
        .collect();
    may_be.sort_by_key(|entry| std::cmp::Reverse(entry.rev));

    let mut tied: Vec<Version> = Vec::new();
    for entry in may_be {
        if tied.first().is_some_and(|found| entry.rev < found.rev) {
            break;
        }
        let Ok(inside) = entry.open_with(&keys) else {
            continue;
        };
        let one = VersionEntry {
            id: entry.id(),
            author: entry.author,
            chain: inside.chain,
        };
        // One value at one revision is one version, whoever signed it.
        match tied.iter_mut().find(|v| v.value == inside.value) {
            Some(version) => version.entries.push(one),
            None => tied.push(Version {
                rev: entry.rev,
                name: inside.name,
                value: inside.value,
                entries: vec![one],
            }),
        }
    }

    tied.sort_by_key(|version| std::cmp::Reverse(rank(&version.value)));
    for version in &mut tied {
        version.entries.sort_by_key(|one| (one.author, one.id));
        version.entries.dedup_by(|a, b| a.id == b.id);
    }
    let mut tied = tied.into_iter();
    Ok(Slot {
        current: tied.next(),
        lost: tied.collect(),
        highest,
        next: next_under(highest, statement),
    })
}

/// What decides a tie at one revision, the greater winning: the hash of
/// the text, or of the bytes that are not a text. A delete has none, which
/// is below every hash, so a text beats a delete. Then, of a text and
/// other bytes that are the same bytes, the text.
fn rank(value: &Value) -> (Option<[u8; 32]>, bool) {
    (value.hash(), matches!(value, Value::Text(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive;
    use crate::entry::testing::*;
    use crate::entry::{Entry, Inside, signed};
    use cordelia_core::protocol::{MAX_REV, REV_BAND_HALF, REV_BAND_SIZE, REV_COUNT_BITS};
    use cordelia_core::revision::lifted;

    const HALF: u64 = REV_BAND_HALF;
    const SIZE: u64 = REV_BAND_SIZE;
    const NAME: &str = "notes.md";

    /// The revision at `count` in `band`.
    fn at(band: u64, count: u64) -> u64 {
        (band << REV_COUNT_BITS) + count
    }

    fn everyone(_: &[u8; 32]) -> bool {
        true
    }

    /// Only the devices numbered so count.
    fn only(devices: &[u8]) -> impl Fn(&[u8; 32]) -> bool {
        let keys: Vec<[u8; 32]> = devices.iter().map(|n| key(*n)).collect();
        move |key| keys.contains(key)
    }

    /// The entry that device `n` made of the text `said` at `rev`.
    fn of_text(n: u8, rev: u64, said: &str) -> CheckedEntry {
        entry(n, rev, &text(NAME, said))
    }

    fn of_delete(n: u8, rev: u64) -> CheckedEntry {
        entry(n, rev, &holding(NAME, Value::Delete))
    }

    /// The slot as a device reads it under statement 1, where every key
    /// counts.
    fn read(entries: &[CheckedEntry]) -> Slot {
        current(entries, &SECRET, 1, everyone).unwrap()
    }

    /// The entries in each order they can be given in.
    fn in_every_order(entries: &[CheckedEntry]) -> Vec<Vec<CheckedEntry>> {
        if entries.len() <= 1 {
            return vec![entries.to_vec()];
        }
        let mut orders = Vec::new();
        for first in 0..entries.len() {
            let mut rest = entries.to_vec();
            let one = rest.remove(first);
            for mut order in in_every_order(&rest) {
                order.insert(0, one.clone());
                orders.push(order);
            }
        }
        orders
    }

    /// Who signed the entries of a version, in the order they are given.
    fn authors(version: &Version) -> Vec<[u8; 32]> {
        version.entries.iter().map(|one| one.author).collect()
    }

    fn text_value(said: &str) -> Value {
        Value::Text(said.to_string())
    }

    /// The two texts, the one with the higher SHA-256 first.
    fn by_hash<'a>(one: &'a str, other: &'a str) -> (&'a str, &'a str) {
        if crate::sha256(one.as_bytes()) > crate::sha256(other.as_bytes()) {
            (one, other)
        } else {
            (other, one)
        }
    }

    // ── Entries that are no version, each signed by device `n` at `rev`
    // and passing the check, which reads no content.

    /// Sealed under another channel's key: it does not open.
    fn does_not_open(n: u8, rev: u64) -> CheckedEntry {
        let other = Entry::seal(&OTHER_SECRET, &device(n), rev, &text(NAME, "t")).unwrap();
        signed(
            &channel_key(),
            &device(n),
            slot_of(NAME),
            rev,
            false,
            other.content,
        )
        .check()
        .unwrap()
    }

    /// It opens, and what it says is not an entry's content.
    fn not_this_form(n: u8, rev: u64) -> CheckedEntry {
        saying(n, rev, NAME, &[0, 8, 0xff, 0xfe], false)
    }

    /// Its name and value are one byte over their bound.
    fn over_the_bound(n: u8, rev: u64) -> CheckedEntry {
        let inside = holding(NAME, Value::Text("x".repeat(61_440 - NAME.len() + 1)));
        saying(n, rev, NAME, &inside.to_bytes(), false)
    }

    /// It names a file whose slot is another than the one it sits in.
    fn of_another_name(n: u8, rev: u64) -> CheckedEntry {
        saying(n, rev, NAME, &text("other.md", "t").to_bytes(), false)
    }

    // ── The current version ──────────────────────────────────────────

    #[test]
    fn the_current_version_is_at_the_highest_revision_among_versions() {
        let entries = [
            of_text(1, 3, "the oldest"),
            of_text(2, 5, "the newest"),
            of_delete(3, 4),
        ];
        for order in in_every_order(&entries) {
            let slot = read(&order);
            let version = slot.current.unwrap();
            assert_eq!(version.rev, 5);
            assert_eq!(version.name, NAME);
            assert_eq!(version.value, text_value("the newest"));
            assert_eq!(authors(&version), [key(2)]);
            // What is below the current revision ties with nothing.
            assert!(slot.lost.is_empty());
            assert_eq!((slot.highest, slot.next), (Some(5), Some(6)));
        }

        // A delete at the highest revision is the current version.
        let slot = read(&[of_text(1, 3, "a text"), of_delete(2, 4)]);
        let version = slot.current.unwrap();
        assert_eq!((version.rev, &version.value), (4, &Value::Delete));
        assert!(slot.lost.is_empty());
    }

    #[test]
    fn an_empty_slot_has_no_version_and_its_first_revision_is_1() {
        let slot = read(&[]);
        assert_eq!(
            slot,
            Slot {
                current: None,
                lost: Vec::new(),
                highest: None,
                next: Some(1),
            }
        );
    }

    /// Two devices carried one version, or made the same edit apart: one
    /// text at one revision, in two entries that differ in who signed
    /// them, in how they were sealed and in what they say.
    #[test]
    fn two_entries_with_one_text_at_one_revision_are_one_version_and_neither_wins() {
        let one = Inside {
            chain: Some(vec![link("before", 3)]),
            ..text(NAME, "the same text")
        };
        let other = Inside {
            chain: Some(vec![link("before", 4), link("first", 3)]),
            ..one.clone()
        };
        let (first, second) = if key(1) < key(2) { (1, 2) } else { (2, 1) };
        let entries = [entry(first, 5, &one), entry(second, 5, &other)];
        assert_ne!(entries[0].content, entries[1].content);

        for order in in_every_order(&entries) {
            let slot = read(&order);
            assert!(slot.lost.is_empty(), "neither lost");
            let version = slot.current.unwrap();
            assert_eq!((version.rev, &version.value), (5, &one.value));
            // Both are given, in order of their authors' keys, each with
            // its chain.
            assert_eq!(authors(&version), [key(first), key(second)]);
            assert_eq!(version.entries[0].id, entries[0].id());
            assert_eq!(version.entries[0].chain, one.chain);
            assert_eq!(version.entries[1].id, entries[1].id());
            assert_eq!(version.entries[1].chain, other.chain);
        }

        // Two deletes at one revision are one version too.
        let slot = read(&[of_delete(1, 5), of_delete(2, 5)]);
        assert!(slot.lost.is_empty());
        assert_eq!(slot.current.unwrap().entries.len(), 2);

        // Two texts are two versions, though one device wrote both names.
        let slot = read(&[of_text(1, 5, "one text"), of_text(2, 5, "another")]);
        assert_eq!(slot.current.unwrap().entries.len(), 1);
        assert_eq!(slot.lost.len(), 1);

        // An entry given twice is one entry of its version.
        let slot = read(&[entries[0].clone(), entries[0].clone()]);
        assert_eq!(slot.current.unwrap().entries.len(), 1);
    }

    #[test]
    fn a_text_beats_a_delete_at_a_tie() {
        for value in [
            text_value("a text"),
            // An empty text is a text.
            text_value(""),
            // Bytes that are not a text rank as a text does.
            Value::Other(vec![0xff, 0x00]),
            Value::Other(Vec::new()),
        ] {
            let entries = [of_delete(1, 5), entry(2, 5, &holding(NAME, value.clone()))];
            for order in in_every_order(&entries) {
                let slot = read(&order);
                let version = slot.current.unwrap();
                assert_eq!(version.value, value);
                assert_eq!(authors(&version), [key(2)]);
                // The delete lost the tie, and is given as that.
                assert_eq!(slot.lost.len(), 1);
                assert_eq!(slot.lost[0].value, Value::Delete);
                assert_eq!(
                    (slot.lost[0].rev, authors(&slot.lost[0])),
                    (5, vec![key(1)])
                );
            }
        }
        // Whoever signed which.
        let slot = read(&[of_text(1, 5, "a text"), of_delete(2, 5)]);
        assert_eq!(slot.current.unwrap().value, text_value("a text"));
        // A delete above a text is the current version: there is no tie.
        let slot = read(&[of_text(1, 5, "a text"), of_delete(2, 6)]);
        assert_eq!(slot.current.unwrap().value, Value::Delete);
        assert!(slot.lost.is_empty());
    }

    /// A tie between two texts goes to the higher hash of the text. The
    /// hash of a ciphertext changes whenever an entry is sealed again, and
    /// decides nothing: neither does who signed which, nor the order the
    /// entries are read in.
    #[test]
    fn of_two_texts_at_one_revision_the_higher_hash_of_the_text_wins() {
        let (higher, lower) = by_hash("the text of one device", "the text of another");
        assert!(crate::sha256(higher.as_bytes()) > crate::sha256(lower.as_bytes()));

        for (winner, loser) in [(1, 2), (2, 1)] {
            // Sealed several times over: the winner is the same.
            for _ in 0..4 {
                let entries = [of_text(winner, 5, higher), of_text(loser, 5, lower)];
                for order in in_every_order(&entries) {
                    let slot = read(&order);
                    let version = slot.current.unwrap();
                    assert_eq!(version.value, text_value(higher));
                    assert_eq!(authors(&version), [key(winner)]);
                    assert_eq!(slot.lost.len(), 1);
                    assert_eq!(slot.lost[0].value, text_value(lower));
                    assert_eq!(authors(&slot.lost[0]), [key(loser)]);
                    assert_eq!(slot.lost[0].name, NAME);
                }
            }
        }

        // Of three, those that lost are given the higher first, and a
        // delete last.
        let texts = ["one", "two", "three"];
        let mut ranked = texts.to_vec();
        ranked.sort_by_key(|said| std::cmp::Reverse(crate::sha256(said.as_bytes())));
        let entries = [
            of_text(1, 5, texts[0]),
            of_text(2, 5, texts[1]),
            of_text(3, 5, texts[2]),
            of_delete(4, 5),
        ];
        for order in in_every_order(&entries) {
            let slot = read(&order);
            assert_eq!(slot.current.unwrap().value, text_value(ranked[0]));
            let lost: Vec<&Value> = slot.lost.iter().map(|version| &version.value).collect();
            assert_eq!(
                lost,
                [
                    &text_value(ranked[1]),
                    &text_value(ranked[2]),
                    &Value::Delete
                ]
            );
        }
    }

    /// Bytes that are not a text rank as a text does, by the hash of the
    /// bytes. A text and other bytes are two values, also where the bytes
    /// are the same: then the text is the current one.
    #[test]
    fn bytes_that_are_not_a_text_rank_as_a_text_does() {
        let (higher, lower) = by_hash("some bytes", "a text");
        let other = |said: &str| Value::Other(said.as_bytes().to_vec());
        for (one, another) in [
            (other(higher), text_value(lower)),
            (text_value(higher), other(lower)),
            (other(higher), other(lower)),
        ] {
            let entries = [
                entry(1, 5, &holding(NAME, another.clone())),
                entry(2, 5, &holding(NAME, one.clone())),
            ];
            for order in in_every_order(&entries) {
                let slot = read(&order);
                assert_eq!(slot.current.unwrap().value, one);
                assert_eq!(slot.lost[0].value, another);
            }
        }

        let entries = [
            entry(1, 5, &holding(NAME, other("the same"))),
            entry(2, 5, &text(NAME, "the same")),
        ];
        for order in in_every_order(&entries) {
            let slot = read(&order);
            assert_eq!(slot.current.unwrap().value, text_value("the same"));
            assert_eq!(slot.lost.len(), 1);
            assert_eq!(slot.lost[0].value, other("the same"));
        }
    }

    // ── Who counts ───────────────────────────────────────────────────

    /// An entry that a key which does not count signed is not looked at:
    /// it is no version, it ties with nothing, it is not one of a
    /// version's entries, and the next revision is not above it.
    #[test]
    fn a_signer_that_does_not_count_is_not_looked_at() {
        // Device 9 does not count, and signs a late version.
        let late = of_text(9, 9, "late");
        let entries = [of_text(1, 5, "agreed"), late.clone()];
        for order in in_every_order(&entries) {
            let slot = current(&order, &SECRET, 1, only(&[1, 2])).unwrap();
            let version = slot.current.unwrap();
            assert_eq!((version.rev, &version.value), (5, &text_value("agreed")));
            assert_eq!(authors(&version), [key(1)]);
            assert!(slot.lost.is_empty());
            assert_eq!((slot.highest, slot.next), (Some(5), Some(6)));
        }

        // At the current revision it does not tie, and is not one of a
        // version's entries where its text is the same.
        for said in ["late", "agreed"] {
            let tying = of_text(9, 5, said);
            let slot = current(&[of_text(1, 5, "agreed"), tying], &SECRET, 1, only(&[1, 2]));
            let slot = slot.unwrap();
            assert_eq!(authors(&slot.current.unwrap()), [key(1)]);
            assert!(slot.lost.is_empty());
        }

        // Alone in the slot, it leaves the slot empty.
        let slot = current(std::slice::from_ref(&late), &SECRET, 1, only(&[1, 2])).unwrap();
        assert_eq!(
            (slot.current, slot.highest, slot.next),
            (None, None, Some(1))
        );

        // The control: where its signer counts, it is the current version,
        // and its author is who wrote it.
        let slot = current(&entries, &SECRET, 1, only(&[1, 9])).unwrap();
        let version = slot.current.unwrap();
        assert_eq!((version.rev, &version.value), (9, &text_value("late")));
        assert_eq!(authors(&version), [key(9)]);
        assert_eq!((slot.highest, slot.next), (Some(9), Some(10)));
    }

    // ── Entries that are no version ──────────────────────────────────

    /// An entry that does not open, one that is not in an entry's form,
    /// one over the bound and one that names another slot's file: each is
    /// passed over, and each still counts for the next revision, so that
    /// a device's next edit is above it.
    #[test]
    fn an_entry_that_is_no_version_is_passed_over_and_counts_for_the_next_revision() {
        type Maker = fn(u8, u64) -> CheckedEntry;
        let makers: [(&str, Maker); 4] = [
            ("does not open", does_not_open),
            ("not this form", not_this_form),
            ("over the bound", over_the_bound),
            ("another name", of_another_name),
        ];
        for (what, make) in makers {
            // The control: it is no version, and why.
            assert!(make(2, 9).open(&SECRET).is_err(), "{what}");

            // Alone: the slot holds no version, and the next revision is
            // above it.
            let slot = read(&[make(2, 9)]);
            assert_eq!(slot.current, None, "{what}");
            assert!(slot.lost.is_empty(), "{what}");
            assert_eq!((slot.highest, slot.next), (Some(9), Some(10)), "{what}");

            // Above a version: the version below it is current.
            for order in in_every_order(&[of_text(1, 5, "a text"), make(2, 9)]) {
                let slot = read(&order);
                let version = slot.current.unwrap();
                assert_eq!(
                    (version.rev, authors(&version)),
                    (5, vec![key(1)]),
                    "{what}"
                );
                assert!(slot.lost.is_empty(), "{what}");
                assert_eq!((slot.highest, slot.next), (Some(9), Some(10)), "{what}");
            }

            // At a version's revision: it does not tie.
            let slot = read(&[of_text(1, 5, "a text"), make(2, 5)]);
            assert_eq!(slot.current.unwrap().entries.len(), 1, "{what}");
            assert!(slot.lost.is_empty(), "{what}");

            // While its signer counts, and no longer.
            let slot = current(&[make(2, 9)], &SECRET, 1, only(&[1])).unwrap();
            assert_eq!((slot.highest, slot.next), (None, Some(1)), "{what}");
        }
        assert_eq!(
            does_not_open(2, 9).open(&SECRET),
            Err(EntryError::DidNotOpen)
        );
        assert_eq!(
            not_this_form(2, 9).open(&SECRET),
            Err(EntryError::NotThisForm)
        );
        assert_eq!(
            over_the_bound(2, 9).open(&SECRET),
            Err(EntryError::OverTheBound(61_441))
        );
        assert_eq!(
            of_another_name(2, 9).open(&SECRET),
            Err(EntryError::AnotherSlot)
        );
    }

    /// An entry whose revision may not be an entry's under the statement
    /// is no version, though it opens. In the top half of a lower band it
    /// still counts for the next revision, which is then moved as a move
    /// would move it.
    #[test]
    fn an_entry_whose_revision_may_not_be_under_the_statement_is_no_version() {
        // Under statement 2: the top half of band 0, and of band 1.
        for rev in [
            at(0, HALF),
            at(0, HALF + 3),
            at(1, HALF + 3),
            at(1, SIZE - 1),
        ] {
            let jumped = of_text(2, rev, "a jump");
            assert!(jumped.open(&SECRET).is_ok());
            for order in in_every_order(&[of_text(1, 5, "a text"), jumped.clone()]) {
                let slot = current(&order, &SECRET, 2, everyone).unwrap();
                let version = slot.current.unwrap();
                assert_eq!((version.rev, authors(&version)), (5, vec![key(1)]), "{rev}");
                assert!(slot.lost.is_empty());
                assert_eq!(slot.highest, Some(rev));
                assert_eq!(slot.next, Some(lifted(rev + 1)), "{rev}");
                assert!(slot.next.unwrap() > rev);
            }
        }
        // The control: in the bottom half of a lower band, and in the
        // statement's own band, in either half, it is the current version.
        for rev in [at(0, HALF - 1), at(1, 3), at(2, 0), at(2, HALF + 3)] {
            let slot = current(
                &[of_text(1, 5, "a text"), of_text(2, rev, "later")],
                &SECRET,
                2,
                everyone,
            );
            assert_eq!(slot.unwrap().current.unwrap().rev, rev, "{rev}");
        }
    }

    /// An entry in a band above the statement's counts for nothing: it is
    /// no version, and the next revision is not above it. Otherwise one
    /// entry there would put a name out of reach.
    #[test]
    fn an_entry_in_a_band_above_the_statements_counts_for_nothing() {
        for rev in [
            at(3, 0),
            at(3, 7),
            at(3, HALF + 1),
            at(4, 1),
            at(256, 0),
            MAX_REV,
        ] {
            let above = of_text(2, rev, "from a later statement");
            for order in in_every_order(&[of_text(1, 5, "a text"), above.clone()]) {
                let slot = current(&order, &SECRET, 2, everyone).unwrap();
                let version = slot.current.unwrap();
                assert_eq!((version.rev, authors(&version)), (5, vec![key(1)]), "{rev}");
                assert!(slot.lost.is_empty(), "{rev}");
                assert_eq!((slot.highest, slot.next), (Some(5), Some(6)), "{rev}");
            }
            // Alone, it leaves the slot as an empty one is.
            let slot = current(&[above], &SECRET, 2, everyone).unwrap();
            assert_eq!(
                (slot.current, slot.highest, slot.next),
                (None, None, Some(1))
            );
        }

        // One that does not open is no different: above the statement's
        // band it counts for nothing, and in or below it for the next
        // revision.
        let slot = current(&[does_not_open(2, at(3, 7))], &SECRET, 2, everyone).unwrap();
        assert_eq!((slot.highest, slot.next), (None, Some(1)));
        let slot = current(&[does_not_open(2, at(2, 7))], &SECRET, 2, everyone).unwrap();
        assert_eq!((slot.highest, slot.next), (Some(at(2, 7)), Some(at(2, 8))));

        // The control: under the statement whose band it is in, it is the
        // current version.
        let slot = current(
            &[of_text(1, 5, "a text"), of_text(2, at(3, 7), "later")],
            &SECRET,
            3,
            everyone,
        );
        let slot = slot.unwrap();
        assert_eq!(slot.current.unwrap().rev, at(3, 7));
        assert_eq!(slot.next, Some(at(3, 8)));
    }

    // ── The next revision ────────────────────────────────────────────

    #[test]
    fn the_next_revision_is_one_above_the_highest_that_counts() {
        // Above the current version, and above an entry that is none.
        let slot = read(&[of_text(1, 5, "a text"), of_text(2, 3, "an older")]);
        assert_eq!((slot.highest, slot.next), (Some(5), Some(6)));

        // From the last revision of a lower band's bottom half it is moved
        // to the first of the next band, under either statement above it.
        let entries = [of_text(1, at(1, HALF - 1), "a text")];
        for statement in [2, 3] {
            let slot = current(&entries, &SECRET, statement, everyone).unwrap();
            assert_eq!(slot.current.as_ref().unwrap().rev, at(1, HALF - 1));
            assert_eq!(slot.next, Some(at(2, 0)), "{statement}");
        }

        // At the top of the statement's band there is none until the next
        // statement, under which the version is no version until it is
        // moved, and the next revision is above where it is moved to.
        let top = at(2, SIZE - 1);
        let entries = [of_text(1, top, "out of reach")];
        let slot = current(&entries, &SECRET, 2, everyone).unwrap();
        assert_eq!(slot.current.as_ref().unwrap().rev, top);
        assert_eq!((slot.highest, slot.next), (Some(top), None));
        let slot = current(&entries, &SECRET, 3, everyone).unwrap();
        assert_eq!(slot.current, None);
        assert_eq!((slot.highest, slot.next), (Some(top), Some(at(3, 0))));
        assert_eq!(lifted(top), at(3, HALF - 1));
    }

    /// Under a number that no statement has, no revision is an entry's:
    /// the slot holds no version and has no next revision.
    #[test]
    fn under_a_number_no_statement_has_a_slot_holds_no_version() {
        let entries = [of_text(1, 5, "a text")];
        for not_a_statement in [0, 257, 511, u64::MAX] {
            let slot = current(&entries, &SECRET, not_a_statement, everyone).unwrap();
            assert_eq!(slot.current, None, "{not_a_statement}");
            assert_eq!(slot.next, None, "{not_a_statement}");
        }
        // The control: the first and the last number that a statement has.
        for statement in [1, 256] {
            let slot = current(&entries, &SECRET, statement, everyone).unwrap();
            assert_eq!(slot.current.unwrap().rev, 5);
            assert_eq!(slot.next, Some(6));
        }
    }

    // ── What is read ─────────────────────────────────────────────────

    /// Each entry of a version is given with its author and its chain: an
    /// empty one, one of several links, and none where the entry lacks
    /// what it should say, which is a version all the same.
    #[test]
    fn each_entry_of_a_version_is_given_with_its_author_and_its_chain() {
        let slot = read(&[of_text(2, 5, "a text")]);
        let version = slot.current.unwrap();
        assert_eq!(version.entries[0].author, key(2));
        assert_eq!(version.entries[0].chain, Some(Vec::new()));

        let chain = vec![link("before", 1), link("first", 3)];
        let inside = Inside {
            chain: Some(chain.clone()),
            ..text(NAME, "a text")
        };
        let slot = read(&[entry(2, 5, &inside)]);
        let version = slot.current.unwrap();
        assert_eq!(version.entries[0].author, key(2));
        assert_eq!(version.entries[0].chain, Some(chain.clone()));

        // One whose chain cannot be read: a byte that is no fill comes
        // after its last link.
        let mut and_more = inside.to_bytes();
        and_more.push(1);
        let lacking = saying(3, 5, NAME, &and_more, false);
        let slot = read(std::slice::from_ref(&lacking));
        let version = slot.current.unwrap();
        assert_eq!((version.rev, &version.value), (5, &text_value("a text")));
        assert_eq!(version.entries[0].author, key(3));
        assert_eq!(version.entries[0].chain, None);

        // With one that says its chain, it is one version of two entries.
        let slot = read(&[lacking, entry(2, 5, &inside)]);
        let version = slot.current.unwrap();
        assert!(slot.lost.is_empty());
        assert_eq!(version.entries.len(), 2);
        let chains: Vec<Option<Vec<Link>>> = version
            .entries
            .iter()
            .map(|one| one.chain.clone())
            .collect();
        assert!(chains.contains(&None) && chains.contains(&Some(chain)));
    }

    /// A slot is one slot of one channel. Entries of another channel than
    /// the secret's, or of two slots, are not read as one.
    #[test]
    fn entries_of_another_channel_or_of_two_slots_are_refused() {
        let here = of_text(1, 5, "a text");
        let elsewhere = entry(2, 5, &text("other.md", "a text"));
        assert_eq!(
            current(&[here.clone(), elsewhere.clone()], &SECRET, 1, everyone),
            Err(EntryError::NotOneSlot)
        );
        // Also where the signer of one of them does not count.
        assert_eq!(
            current(&[here.clone(), elsewhere], &SECRET, 1, only(&[1])),
            Err(EntryError::NotOneSlot)
        );

        let of_another = Entry::seal(&OTHER_SECRET, &device(1), 5, &text(NAME, "a text"))
            .unwrap()
            .check()
            .unwrap();
        assert_ne!(of_another.channel, derive::channel_id(&SECRET).unwrap());
        assert_eq!(
            current(&[here.clone(), of_another.clone()], &SECRET, 1, everyone),
            Err(EntryError::AnotherChannel)
        );
        assert_eq!(
            current(&[here], &OTHER_SECRET, 1, everyone),
            Err(EntryError::AnotherChannel)
        );
        assert!(current(&[of_another], &OTHER_SECRET, 1, everyone).is_ok());
    }
}
