//! A revision as a band and a count (decision 2026-10-04 §2.3).
//!
//! A revision is one number below 2^53, compared as one, and editing adds
//! one to it. Its top nine bits are its band and the 44 below them its
//! count. A band is a statement's number, from 0 to 256.
//!
//! Three rules, each one function of the numbers alone, so that every
//! device gives the same answer whatever it holds and however many
//! statements it was behind:
//!
//! - [`may_be_under`]: under statement n an entry's revision is in band n,
//!   or in the bottom half of a lower band. Any other is no version.
//! - [`next_under`]: the next revision is one above the highest; the first
//!   of band n where that would be in the top half of a lower band; and
//!   none at the top of band n.
//! - [`lifted`]: when a version crosses a statement, a revision in the top
//!   half of a band goes to the same place in the bottom half of the next
//!   band, and so does every such revision that speaks of it.
//!
//! Editing never reaches the top half of a band: it is 2^43 edits away. A
//! revision is up there because a device jumped, and at the top of band n
//! a name is out of reach until the next statement, which lifts it.

use crate::protocol::{MAX_STATEMENT_NUMBER, REV_BAND_HALF, REV_BAND_SIZE, REV_COUNT_BITS};

/// The band of `rev`: the bits above its count. A number over the bound on
/// a revision is in no band that a statement has.
pub const fn band(rev: u64) -> u64 {
    rev >> REV_COUNT_BITS
}

/// The count of `rev`: its place in its band.
pub const fn count(rev: u64) -> u64 {
    rev & (REV_BAND_SIZE - 1)
}

/// `rev` as it is once it has crossed a statement.
///
/// A revision in the top half of its band goes to the same place in the
/// bottom half of the next band. Any other is unchanged: one in a bottom
/// half, one in the last band, which has no next, and a number that is in
/// no statement's band at all.
///
/// Where it lands, nothing was written before the statement that moves it,
/// so it keeps the order of every two revisions that may be entries under
/// one statement. What it gives is in a bottom half, so lifting twice is
/// lifting once: a device that was two statements behind moves what it
/// holds to where the others moved it.
pub const fn lifted(rev: u64) -> u64 {
    if band(rev) < MAX_STATEMENT_NUMBER && count(rev) >= REV_BAND_HALF {
        rev + REV_BAND_HALF
    } else {
        rev
    }
}

/// Whether `rev` may be an entry's revision under statement `statement`:
/// it is in that statement's band, or in the bottom half of a lower one.
/// Under a number that no statement has, nothing may.
pub const fn may_be_under(rev: u64, statement: u64) -> bool {
    if !is_statement(statement) {
        return false;
    }
    let band = band(rev);
    band == statement || (band < statement && count(rev) < REV_BAND_HALF)
}

/// The next revision under statement `statement`, where `highest` is the
/// highest revision held for the name, of every entry that counts for it
/// (one that is no version among them), or `None` where there is none.
///
/// It is one above the highest. Where that would be in the top half of a
/// lower band, it is the first of the statement's band. `None` where
/// nothing can be written above the highest under this statement: at the
/// top of the statement's band, or above it.
pub const fn next_under(highest: Option<u64>, statement: u64) -> Option<u64> {
    if !is_statement(statement) {
        return None;
    }
    let above = match highest {
        None => 1,
        Some(highest) => match highest.checked_add(1) {
            Some(above) => above,
            None => return None,
        },
    };
    if may_be_under(above, statement) {
        Some(above)
    } else if band(above) < statement {
        Some(statement << REV_COUNT_BITS)
    } else {
        None
    }
}

/// Whether a statement can have the number `statement`: 1 to
/// MAX_STATEMENT_NUMBER.
const fn is_statement(statement: u64) -> bool {
    statement >= 1 && statement <= MAX_STATEMENT_NUMBER
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MAX_REV;

    const HALF: u64 = REV_BAND_HALF;
    const SIZE: u64 = REV_BAND_SIZE;

    /// The revision at `count` in `band`.
    fn at(band: u64, count: u64) -> u64 {
        (band << REV_COUNT_BITS) + count
    }

    /// Statements at each end of the range, and in the middle of it.
    const STATEMENTS: [u64; 9] = [1, 2, 3, 127, 128, 129, 254, 255, 256];

    /// Every edge of a band, in bands at each end of the range, beside it
    /// and beyond it, and numbers that are over the bound on a revision.
    fn edges() -> Vec<u64> {
        let mut out = Vec::new();
        for band in [0, 1, 2, 3, 4, 126, 127, 128, 129, 130] {
            out.extend(edges_of(band));
        }
        for band in [253, 254, 255, 256, 257, 258, 510, 511] {
            out.extend(edges_of(band));
        }
        out.extend([MAX_REV + 1, MAX_REV + HALF, u64::MAX - 1, u64::MAX]);
        out
    }

    fn edges_of(band: u64) -> Vec<u64> {
        [
            0,
            1,
            2,
            HALF - 2,
            HALF - 1,
            HALF,
            HALF + 1,
            SIZE - 2,
            SIZE - 1,
        ]
        .iter()
        .map(|count| at(band, *count))
        .collect()
    }

    #[test]
    fn test_a_revision_is_a_band_and_a_count() {
        for (rev, in_band, with_count) in [
            (0, 0, 0),
            (1, 0, 1),
            (HALF - 1, 0, HALF - 1),
            (HALF, 0, HALF),
            (SIZE - 1, 0, SIZE - 1),
            (SIZE, 1, 0),
            (SIZE + 1, 1, 1),
            (256 * SIZE, 256, 0),
            (257 * SIZE - 1, 256, SIZE - 1),
            (MAX_REV, 511, SIZE - 1),
        ] {
            assert_eq!(band(rev), in_band, "{rev}");
            assert_eq!(count(rev), with_count, "{rev}");
        }
        // The two are the whole of a revision, and its order is theirs.
        for rev in edges() {
            if rev <= MAX_REV {
                assert_eq!(at(band(rev), count(rev)), rev);
                assert!(count(rev) < SIZE);
            } else {
                assert!(band(rev) > MAX_STATEMENT_NUMBER, "{rev}");
            }
        }
        // Nine bits of band and 44 of count.
        assert_eq!(band(MAX_REV), (1 << 9) - 1);
        assert_eq!(count(MAX_REV), (1 << 44) - 1);
    }

    #[test]
    fn test_the_top_half_of_a_band_is_lifted_to_the_bottom_half_of_the_next() {
        for b in [0, 1, 2, 127, 128, 254, 255] {
            // The same place: as far into the bottom half of the next band
            // as it was into the top half of its own.
            for place in [0, 1, 2, HALF - 2, HALF - 1] {
                assert_eq!(lifted(at(b, HALF + place)), at(b + 1, place), "{b} {place}");
            }
            // The bottom half stays, to its last revision.
            for place in [0, 1, 2, HALF - 2, HALF - 1] {
                assert_eq!(lifted(at(b, place)), at(b, place), "{b} {place}");
            }
        }
    }

    /// The last band has no next band, a number above it is in no
    /// statement's band, and a number over the bound is no revision: each
    /// is left as it is, and nothing overflows.
    #[test]
    fn test_what_has_no_next_band_is_not_lifted() {
        for b in [256, 257, 258, 510, 511] {
            for rev in edges_of(b) {
                assert_eq!(lifted(rev), rev, "{rev}");
            }
        }
        for rev in [MAX_REV, MAX_REV + 1, MAX_REV + HALF, u64::MAX - 1, u64::MAX] {
            assert_eq!(lifted(rev), rev, "{rev}");
        }
        // The band before the last is lifted into the last, and no further.
        assert_eq!(lifted(at(255, SIZE - 1)), at(256, HALF - 1));
        // Nothing is ever lifted over the bound on a revision.
        for rev in edges() {
            assert!(rev > MAX_REV || lifted(rev) <= MAX_REV, "{rev}");
        }
    }

    #[test]
    fn test_lifting_keeps_the_order_of_every_two_revisions_that_may_be_entries() {
        for statement in STATEMENTS {
            let mut held: Vec<u64> = edges()
                .into_iter()
                .filter(|rev| may_be_under(*rev, statement))
                .collect();
            held.sort_unstable();
            held.dedup();
            // Some in the statement's own top half, which is what moves,
            // but under the last statement, whose band has no next.
            assert_eq!(
                held.iter().any(|rev| lifted(*rev) != *rev),
                statement < MAX_STATEMENT_NUMBER,
                "{statement}"
            );
            for (i, lower) in held.iter().enumerate() {
                for higher in &held[i + 1..] {
                    assert!(
                        lifted(*lower) < lifted(*higher),
                        "{statement}: {lower} {higher}"
                    );
                }
            }
        }
        // The control: two revisions that are not both entries under one
        // statement can change places. One in the top half of a band is
        // lifted over one at the bottom of the next band, which no
        // statement allows beside it.
        let (lower, higher) = (at(3, HALF + 5), at(4, 2));
        assert!(lower < higher && lifted(lower) > lifted(higher));
        for statement in STATEMENTS {
            assert!(!(may_be_under(lower, statement) && may_be_under(higher, statement)));
        }
    }

    #[test]
    fn test_lifting_twice_is_lifting_once() {
        for rev in edges() {
            assert_eq!(lifted(lifted(rev)), lifted(rev), "{rev}");
        }
        // And for one that may be an entry it is a revision that may be an
        // entry under the next statement, in a bottom half.
        for statement in STATEMENTS {
            for rev in edges() {
                if may_be_under(rev, statement) && statement < MAX_STATEMENT_NUMBER {
                    assert!(
                        may_be_under(lifted(rev), statement + 1),
                        "{statement} {rev}"
                    );
                    assert!(count(lifted(rev)) < HALF, "{statement} {rev}");
                }
            }
        }
    }

    /// A device that was one statement behind lifts what it holds once, at
    /// each of the next two statements: twice in all. One that was two
    /// behind applies the second statement directly, and lifts once. Both
    /// give a version the same revision, and it may be an entry under the
    /// statement they end at.
    #[test]
    fn test_a_device_two_statements_behind_gives_what_one_behind_gave() {
        for statement in STATEMENTS {
            if statement + 2 > MAX_STATEMENT_NUMBER {
                continue;
            }
            for rev in edges() {
                if !may_be_under(rev, statement) {
                    continue;
                }
                let at_the_first = lifted(rev);
                assert!(
                    may_be_under(at_the_first, statement + 1),
                    "{statement} {rev}"
                );
                let through_both = lifted(at_the_first);
                let straight_to_the_second = lifted(rev);
                assert_eq!(straight_to_the_second, through_both, "{statement} {rev}");
                assert!(
                    may_be_under(through_both, statement + 2),
                    "{statement} {rev}"
                );
            }
        }
        // What a device wrote in the top half of a band it then left is
        // lifted at the next statement, while what was lifted before stays.
        let jumped_under_5 = at(5, HALF + 9);
        let moved_to_6 = lifted(jumped_under_5);
        assert_eq!(moved_to_6, at(6, 9));
        let jumped_under_6 = at(6, HALF + 2);
        assert_eq!(lifted(moved_to_6), at(6, 9));
        assert_eq!(lifted(jumped_under_6), at(7, 2));
        assert!(lifted(moved_to_6) < lifted(jumped_under_6));
    }

    #[test]
    fn test_an_entry_is_in_its_statements_band_or_the_bottom_half_of_a_lower_one() {
        for n in STATEMENTS {
            // The whole of the statement's own band.
            for rev in edges_of(n) {
                assert!(may_be_under(rev, n), "{n} {rev}");
            }
            // The bottom half of each lower band, to its last revision, and
            // nothing of its top half, from its first.
            for lower in [0, n / 2, n - 1] {
                for place in [0, 1, 2, HALF - 2, HALF - 1] {
                    assert!(may_be_under(at(lower, place), n), "{n} {lower} {place}");
                }
                for place in [HALF, HALF + 1, SIZE - 2, SIZE - 1] {
                    assert!(!may_be_under(at(lower, place), n), "{n} {lower} {place}");
                }
            }
            // Nothing in a band above the statement's, in either half.
            for above in [n + 1, n + 2, 257, 511] {
                for rev in edges_of(above) {
                    assert!(!may_be_under(rev, n), "{n} {rev}");
                }
            }
            // Nor a number over the bound on a revision.
            for rev in [MAX_REV + 1, MAX_REV + HALF, u64::MAX - 1, u64::MAX] {
                assert!(!may_be_under(rev, n), "{n} {rev}");
            }
        }
        // Ordinary editing: the first revisions, under any statement.
        for n in STATEMENTS {
            assert!(may_be_under(1, n) && may_be_under(2, n));
        }
    }

    /// A statement's number is from 1 to 256. Under any other number no
    /// revision is an entry's, and there is no next revision.
    #[test]
    fn test_nothing_is_an_entry_under_a_number_no_statement_has() {
        for not_a_statement in [0, 257, 258, 511, 512, u64::MAX] {
            for rev in edges() {
                assert!(
                    !may_be_under(rev, not_a_statement),
                    "{not_a_statement} {rev}"
                );
                assert_eq!(next_under(Some(rev), not_a_statement), None);
            }
            assert_eq!(next_under(None, not_a_statement), None);
        }
        // The control: the first and the last number that a statement has.
        assert!(may_be_under(1, 1) && may_be_under(at(256, 0), 256));
        assert_eq!(next_under(None, 1), Some(1));
        assert_eq!(next_under(None, 256), Some(1));
    }

    #[test]
    fn test_the_next_revision_is_one_above_the_highest() {
        for n in STATEMENTS {
            // A name with no entry starts at 1, as it always has.
            assert_eq!(next_under(None, n), Some(1));
            assert_eq!(next_under(Some(0), n), Some(1));
            assert_eq!(next_under(Some(1), n), Some(2));
            // In the bottom half of a lower band, up to its last revision.
            for lower in [0, n / 2, n - 1] {
                assert_eq!(
                    next_under(Some(at(lower, HALF - 2)), n),
                    Some(at(lower, HALF - 1)),
                    "{n} {lower}"
                );
            }
            // In the statement's own band, in both halves, up to its last.
            for place in [0, 1, HALF - 2, HALF - 1, HALF, HALF + 1, SIZE - 3, SIZE - 2] {
                assert_eq!(
                    next_under(Some(at(n, place)), n),
                    Some(at(n, place + 1)),
                    "{n} {place}"
                );
            }
        }
    }

    /// One above the last revision of a lower band's bottom half would be
    /// in its top half, where no entry may be: the next is the first of the
    /// statement's band. So it is above an entry that is itself up there,
    /// which is no version and still counts.
    #[test]
    fn test_the_next_revision_is_the_first_of_the_statements_band() {
        for n in STATEMENTS {
            let first = at(n, 0);
            for lower in [0, n / 2, n - 1] {
                for place in [HALF - 1, HALF, HALF + 1, SIZE - 3, SIZE - 2] {
                    assert_eq!(
                        next_under(Some(at(lower, place)), n),
                        Some(first),
                        "{n} {lower} {place}"
                    );
                }
            }
            // From the very top of the band below, one above is the first
            // of the statement's band already.
            assert_eq!(next_under(Some(at(n - 1, SIZE - 1)), n), Some(first));
        }
        // From the very top of a band further down, one above is the first
        // of the band after it, in a bottom half, where an entry may be.
        assert_eq!(next_under(Some(at(3, SIZE - 1)), 9), Some(at(4, 0)));
    }

    /// At the top of the statement's band nothing can be written above the
    /// highest, and nor can it above a revision in a higher band. The name
    /// is out of reach until the next statement, which lifts the revision
    /// into its own bottom half.
    #[test]
    fn test_there_is_no_next_revision_at_the_top_of_the_statements_band() {
        for n in STATEMENTS {
            let top = at(n, SIZE - 1);
            assert_eq!(next_under(Some(top), n), None, "{n}");
            assert_eq!(next_under(Some(at(n, SIZE - 2)), n), Some(top), "{n}");
            for above in [n + 1, n + 2, 257, 511] {
                for rev in edges_of(above) {
                    assert_eq!(next_under(Some(rev), n), None, "{n} {rev}");
                }
            }
            for rev in [MAX_REV, MAX_REV + 1, u64::MAX - 1, u64::MAX] {
                assert_eq!(next_under(Some(rev), n), None, "{n} {rev}");
            }
            if n < MAX_STATEMENT_NUMBER {
                assert_eq!(lifted(top), at(n + 1, HALF - 1));
                assert_eq!(
                    next_under(Some(lifted(top)), n + 1),
                    Some(at(n + 1, HALF)),
                    "{n}"
                );
            }
        }
    }

    #[test]
    fn test_the_next_revision_is_above_the_highest_and_may_be_an_entry() {
        let mut some = 0;
        let mut none = 0;
        for n in STATEMENTS {
            for highest in edges() {
                match next_under(Some(highest), n) {
                    Some(next) => {
                        assert!(next > highest, "{n} {highest}");
                        assert!(may_be_under(next, n), "{n} {highest}");
                        some += 1;
                    }
                    // None only where no revision above the highest may be
                    // an entry: at the top of the statement's band or over.
                    None => {
                        assert!(highest >= at(n, SIZE - 1), "{n} {highest}");
                        none += 1;
                    }
                }
            }
        }
        assert!(some > 100 && none > 100, "{some} {none}");
    }
}
