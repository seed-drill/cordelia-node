//! What an entry says it was written after (decision
//! 2026-09-30-agent-memory-sync §4.5).
//!
//! A revision is a number: the highest its writer held for the file, plus
//! one. A higher one shows that the writer held more revisions, not that it
//! had seen the version another device holds. So each entry the adapter
//! publishes for a memory file also says what it was written over: the
//! entry the plan read, and through that entry the ones before it.
//!
//! It is read for one decision only, in [`crate::plan`]: whether a version
//! at a higher revision is known to have been written after the entry this
//! folder agreed. It can only make that decision keep more. An entry that
//! says nothing, or says something that cannot be read, is taken by its
//! revision as it was before.
//!
//! It is a member of the entry's sealed content, beside the text: a relay
//! sees only that the entry is larger.

use std::collections::BTreeMap;

use serde_json::Value;

/// The most devices an entry names. With more, those with the lowest
/// revisions are left out.
pub const MAX_NAMES: usize = 64;

/// What an entry says it was written after. Each part may be missing, and
/// a part that is missing shows nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct After {
    /// For each device whose entry this text descends from, by its key:
    /// the highest revision of its entries among them.
    pub of: BTreeMap<[u8; 32], u64>,
    /// The hash of the text of the entry this one was published over, if
    /// that entry was a text.
    pub over: Option<[u8; 32]>,
    /// Every entry at or below this revision is taken as followed. It is
    /// the revision of the newest entry in this text's history that said
    /// nothing of what it was written after: what came before that entry
    /// is not known, and is decided by revision as it always was.
    pub below: Option<u64>,
}

/// The entry that another is published over.
#[derive(Debug, Clone, Copy)]
pub struct Over<'a> {
    /// The device that wrote it.
    pub author: [u8; 32],
    pub rev: u64,
    /// The hash of its text; `None` if it is a delete.
    pub text: Option<[u8; 32]>,
    /// What it says it was written after, as [`After::read`] gives it.
    pub after: Option<&'a After>,
}

/// A device's key, or a text's hash, from 64 lower-case hex digits.
fn from_hex(text: &str) -> Option<[u8; 32]> {
    if !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    // Any other number of digits is not 32 bytes.
    hex::decode(text).ok()?.try_into().ok()
}

impl After {
    /// Read the `after` member of an entry at revision `rev`.
    ///
    /// `None` where the entry has none: nothing is known of what it was
    /// written after. Otherwise what it shows. Whatever is not as
    /// [`After::to_value`] writes it is ignored by itself and shows
    /// nothing: a member of another shape, a name or a hash that is not 64
    /// lower-case hex digits, a revision that an entry at `rev` cannot
    /// have been written after (its own or a higher one, or one past the
    /// limit), and every name where there are more than [`MAX_NAMES`]. So
    /// a member that is no object at all is read as one that shows
    /// nothing, which is not the same as there being none.
    pub fn read(member: Option<&Value>, rev: u64) -> Option<After> {
        let member = member.filter(|m| !m.is_null())?;
        let mut after = After::default();
        let Some(said) = member.as_object() else {
            return Some(after);
        };
        let earlier = |n: &Value| {
            n.as_u64()
                .filter(|n| *n < rev && *n <= cordelia_core::protocol::MAX_REV)
        };
        if let Some(of) = said.get("of").and_then(Value::as_object)
            && of.len() <= MAX_NAMES
        {
            for (name, n) in of {
                if let (Some(device), Some(n)) = (from_hex(name), earlier(n)) {
                    after.of.insert(device, n);
                }
            }
        }
        after.over = said.get("over").and_then(Value::as_str).and_then(from_hex);
        after.below = said.get("below").and_then(earlier);
        Some(after)
    }

    /// What an entry published over `over` says; over nothing (a new
    /// file), something that shows nothing.
    ///
    /// Its history is the history of the entry it is published over, with
    /// that entry joined in. If that entry said nothing, all that is known
    /// is the entry itself, and everything at or below it is left to its
    /// revision.
    pub fn written_over(over: Option<&Over>) -> After {
        let Some(over) = over else {
            return After::default();
        };
        let mut after = match over.after {
            Some(theirs) => After {
                of: theirs.of.clone(),
                over: None,
                below: theirs.below,
            },
            None => After {
                of: BTreeMap::new(),
                over: None,
                below: Some(over.rev),
            },
        };
        // Above any revision it was named at before: an entry's history
        // is of revisions below its own.
        after.of.insert(over.author, over.rev);
        after.over = over.text;
        while after.of.len() > MAX_NAMES {
            after.leave_one_out();
        }
        after
    }

    /// Leave out the name with the lowest revision (of names at one
    /// revision, the highest key). `false` if there was none to leave out.
    pub fn leave_one_out(&mut self) -> bool {
        let lowest = self
            .of
            .iter()
            .min_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
            .map(|(device, _)| *device);
        match lowest {
            Some(device) => self.of.remove(&device).is_some(),
            None => false,
        }
    }

    /// The member as it is written in an entry: an object, with only the
    /// parts that show something.
    pub fn to_value(&self) -> Value {
        let mut said = serde_json::Map::new();
        if !self.of.is_empty() {
            let of = self
                .of
                .iter()
                .map(|(device, rev)| (hex::encode(device), Value::from(*rev)))
                .collect();
            said.insert("of".into(), Value::Object(of));
        }
        if let Some(over) = self.over {
            said.insert("over".into(), Value::from(hex::encode(over)));
        }
        if let Some(below) = self.below {
            said.insert("below".into(), Value::from(below));
        }
        Value::Object(said)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: [u8; 32] = [0xa1; 32];
    const B: [u8; 32] = [0xb2; 32];
    const C: [u8; 32] = [0xc3; 32];
    const TEXT: [u8; 32] = [0x7e; 32];

    fn hex_of(bytes: [u8; 32]) -> String {
        hex::encode(bytes)
    }

    fn of(names: &[([u8; 32], u64)]) -> BTreeMap<[u8; 32], u64> {
        names.iter().copied().collect()
    }

    /// No member, and `null`, are an entry that says nothing. Anything
    /// else is an entry that says something, even where what it says shows
    /// nothing: the two are decided differently.
    #[test]
    fn none_and_null_say_nothing_and_anything_else_says_something() {
        assert_eq!(After::read(None, 5), None);
        assert_eq!(After::read(Some(&Value::Null), 5), None);
        for other in [
            json!({}),
            json!("text"),
            json!([1, 2]),
            json!(4),
            json!(true),
            json!(false),
        ] {
            assert_eq!(
                After::read(Some(&other), 5),
                Some(After::default()),
                "{other}"
            );
        }
    }

    #[test]
    fn what_is_written_is_read_back() {
        let after = After {
            of: of(&[(A, 3), (B, 4)]),
            over: Some(TEXT),
            below: Some(2),
        };
        let written = after.to_value();
        assert_eq!(
            written,
            json!({
                "of": { hex_of(A): 3, hex_of(B): 4 },
                "over": hex_of(TEXT),
                "below": 2,
            })
        );
        assert_eq!(After::read(Some(&written), 5), Some(after));
        // What shows nothing is not written.
        assert_eq!(After::default().to_value(), json!({}));
    }

    /// Each thing that is not as it is written is ignored by itself: the
    /// rest of the member is read.
    #[test]
    fn what_cannot_be_read_is_ignored_by_itself() {
        let good = json!({
            "of": { hex_of(A): 3, hex_of(B): 4 },
            "over": hex_of(TEXT),
            "below": 2,
        });
        let whole = After {
            of: of(&[(A, 3), (B, 4)]),
            over: Some(TEXT),
            below: Some(2),
        };
        let read = |change: &dyn Fn(&mut Value)| {
            let mut member = good.clone();
            change(&mut member);
            After::read(Some(&member), 5).unwrap()
        };
        assert_eq!(read(&|_| {}), whole);

        // A member of another shape.
        for other in [json!("x"), json!([]), json!(7), json!(true)] {
            let without_of = read(&|m| m["of"] = other.clone());
            assert_eq!(
                without_of,
                After {
                    of: of(&[]),
                    ..whole.clone()
                }
            );
        }
        for other in [json!({}), json!([]), json!(7), json!(true)] {
            let without_over = read(&|m| m["over"] = other.clone());
            assert_eq!(
                without_over,
                After {
                    over: None,
                    ..whole.clone()
                }
            );
        }
        for other in [json!("2"), json!({}), json!(-1), json!(2.5)] {
            let without_below = read(&|m| m["below"] = other.clone());
            assert_eq!(
                without_below,
                After {
                    below: None,
                    ..whole.clone()
                }
            );
        }

        // A name that is not 64 lower-case hex digits: too short, too
        // long, in upper case, not hex. The other name is read.
        let only_b = After {
            of: of(&[(B, 4)]),
            ..whole.clone()
        };
        for name in [
            hex_of(A)[..62].to_string(),
            format!("{}00", hex_of(A)),
            hex_of(A).to_uppercase(),
            "g".repeat(64),
        ] {
            let renamed = read(&|m| {
                let of = m["of"].as_object_mut().unwrap();
                let rev = of.remove(&hex_of(A)).unwrap();
                of.insert(name.clone(), rev);
            });
            assert_eq!(renamed, only_b, "{name}");
        }
        // A hash that is not: the same.
        let upper = read(&|m| m["over"] = json!(hex_of(TEXT).to_uppercase()));
        assert_eq!(upper.over, None);

        // A named revision that is no number.
        for rev in [json!("3"), json!(null), json!(-3), json!(3.5)] {
            let unnumbered = read(&|m| m["of"][hex_of(A)] = rev.clone());
            assert_eq!(unnumbered, only_b, "{rev}");
        }

        // A member this version does not know.
        let more = read(&|m| m["later"] = json!({ "x": 1 }));
        assert_eq!(more, whole);
    }

    /// An entry cannot have been written after its own revision or a
    /// higher one, or after a revision past the limit.
    #[test]
    fn a_revision_the_entry_cannot_follow_is_ignored() {
        let member = |named: u64, below: u64| json!({ "of": { hex_of(A): named, hex_of(B): 1 }, "below": below });
        let read = |named: u64, below: u64, rev: u64| {
            let after = After::read(Some(&member(named, below)), rev).unwrap();
            (after.of.get(&A).copied(), after.below)
        };
        // One below the entry's own is the highest that is read.
        assert_eq!(read(4, 4, 5), (Some(4), Some(4)));
        assert_eq!(read(5, 4, 5), (None, Some(4)));
        assert_eq!(read(4, 5, 5), (Some(4), None));
        assert_eq!(read(6, 9, 5), (None, None));
        // The other name is read all the same.
        let after = After::read(Some(&member(5, 5)), 5).unwrap();
        assert_eq!(after.of, of(&[(B, 1)]));

        // Past the limit, whatever the entry's own revision is said to be.
        let limit = cordelia_core::protocol::MAX_REV;
        assert_eq!(
            read(limit, limit, u64::MAX),
            (Some(limit), Some(limit)),
            "the limit itself is a revision"
        );
        assert_eq!(read(limit + 1, limit + 1, u64::MAX), (None, None));
    }

    /// More names than an entry may have: none of them is read. The rest
    /// of the member is.
    #[test]
    fn too_many_names_are_all_ignored() {
        let names = |n: usize| -> Value {
            let of: serde_json::Map<String, Value> = (0..n)
                .map(|i| {
                    let mut device = [0u8; 32];
                    device[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    (hex_of(device), json!(1))
                })
                .collect();
            json!({ "of": of, "below": 3 })
        };
        let at_most = After::read(Some(&names(MAX_NAMES)), 5).unwrap();
        assert_eq!((at_most.of.len(), at_most.below), (MAX_NAMES, Some(3)));
        let one_more = After::read(Some(&names(MAX_NAMES + 1)), 5).unwrap();
        assert_eq!((one_more.of.len(), one_more.below), (0, Some(3)));
    }

    /// Over nothing, an entry shows nothing. Over an entry that said
    /// nothing, it names that entry, and leaves everything at or below it
    /// to its revision.
    #[test]
    fn what_an_entry_says_over_nothing_and_over_an_entry_that_said_nothing() {
        assert_eq!(After::written_over(None), After::default());

        let text = Over {
            author: A,
            rev: 4,
            text: Some(TEXT),
            after: None,
        };
        assert_eq!(
            After::written_over(Some(&text)),
            After {
                of: of(&[(A, 4)]),
                over: Some(TEXT),
                below: Some(4),
            }
        );
        // Over a delete there is no text to name.
        let delete = Over { text: None, ..text };
        assert_eq!(After::written_over(Some(&delete)).over, None);
    }

    /// Over an entry that said something: its history is carried on, with
    /// the entry itself joined in at its own revision, which is higher
    /// than any it was named at before.
    #[test]
    fn what_an_entry_says_over_an_entry_that_said_something() {
        let theirs = After {
            of: of(&[(A, 2), (B, 3)]),
            over: Some([0x11; 32]),
            below: Some(1),
        };
        let by = |author: [u8; 32]| Over {
            author,
            rev: 5,
            text: Some(TEXT),
            after: Some(&theirs),
        };
        // By a device its history did not name.
        assert_eq!(
            After::written_over(Some(&by(C))),
            After {
                of: of(&[(A, 2), (B, 3), (C, 5)]),
                over: Some(TEXT),
                below: Some(1),
            }
        );
        // By a device it named, at a lower revision: the higher is kept.
        assert_eq!(After::written_over(Some(&by(A))).of, of(&[(A, 5), (B, 3)]));
        // What it was itself published over is not carried on: only the
        // hash of its own text.
        assert_eq!(After::written_over(Some(&by(A))).over, Some(TEXT));
        // One that showed nothing has no `below`, and gets none: it said
        // something, so nothing under it is left to its revision.
        let nothing = After::default();
        let over = Over {
            after: Some(&nothing),
            ..by(C)
        };
        assert_eq!(
            After::written_over(Some(&over)),
            After {
                of: of(&[(C, 5)]),
                over: Some(TEXT),
                below: None,
            }
        );
    }

    /// At most [`MAX_NAMES`] names. The lowest revisions are left out
    /// first, and of names at one revision the highest keys.
    #[test]
    fn the_names_with_the_lowest_revisions_are_left_out() {
        let device = |i: u8| [i; 32];
        // 64 names, at revisions 10 to 73, and one more writer at 100.
        let full = After {
            of: (0..MAX_NAMES as u8)
                .map(|i| (device(i), 10 + u64::from(i)))
                .collect(),
            over: None,
            below: None,
        };
        let over = Over {
            author: device(200),
            rev: 100,
            text: None,
            after: Some(&full),
        };
        let after = After::written_over(Some(&over));
        assert_eq!(after.of.len(), MAX_NAMES);
        assert!(!after.of.contains_key(&device(0)), "the lowest goes");
        assert_eq!(after.of.get(&device(1)), Some(&11));
        assert_eq!(after.of.get(&device(200)), Some(&100));

        // Of names at one revision, the highest key goes first.
        let mut tied = After {
            of: of(&[(A, 3), (B, 3), (C, 7)]),
            over: Some(TEXT),
            below: Some(1),
        };
        assert!(tied.leave_one_out());
        assert_eq!(tied.of, of(&[(A, 3), (C, 7)]));
        assert!(tied.leave_one_out());
        assert_eq!(tied.of, of(&[(C, 7)]));
        assert!(tied.leave_one_out());
        assert!(!tied.leave_one_out());
        // The rest of what it says is untouched.
        assert_eq!((tied.over, tied.below), (Some(TEXT), Some(1)));
    }
}
