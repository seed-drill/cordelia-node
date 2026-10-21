//! The value of a device's carried word (decision 2026-10-19 §4, rules 4
//! and 5): its entry under `reached/<its key>` in the personal channel,
//! which says that what it carried when it applied a statement is at the
//! relays it names, where the others are out of reach.
//!
//! Pure: what the value is byte for byte, and what a reader refuses.
//! Nothing here holds a store, and nothing here knows which key signed
//! the entry: whoever reads it asks that ([`CarriedWord::from_value`] is
//! only the form).
//!
//! ## The value
//!
//! A value of kind 2 ([`Value::Other`]), with four fields and nothing
//! after them. Every number is big-endian.
//!
//! ```text
//! number     8         the statement's number
//! keys       1 + 32 n  n from 1 to 8: the node keys of the relays at which
//!                      nothing that the device carried waits, in the
//!                      order of its configuration, each once
//! more       2         how many more such relays there are: 0 unless n is 8
//! not yet    2         how many relays it is set up with are neither named
//!                      nor counted in `more`: those at which something that
//!                      it carried may still wait
//! ```
//!
//! **The two sets never overlap:** a relay is named, or counted in `more`,
//! or counted in `not yet`, and never two of them. Each count is at most
//! 256 (REACHED_WORD_MAX_COUNT). No name and no address of a relay is in
//! the word: a relay is named in a configuration by its address, and every
//! device that ever holds the generation's secret reads this channel.

use cordelia_core::protocol::{REACHED_WORD_MAX_COUNT, REACHED_WORD_MAX_RELAYS};

use crate::entry::Value;
use crate::statement::Reader;

/// Why a value is no carried word (decision 2026-10-19, rule 5). A reader
/// reads any of these as no word.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotAWord {
    #[error("the carried word is a value of kind 2, and this is not")]
    Kind,

    #[error("the carried word ends before its four fields")]
    Short,

    #[error("the carried word has bytes after its four fields")]
    Long,

    #[error("the carried word names from 1 to 8 keys, and this names {0}")]
    Keys(usize),

    #[error("the carried word names a key twice")]
    Twice,

    #[error("the carried word counts more relays only where it names 8 keys")]
    MoreWithFewKeys,

    #[error("a count of the carried word is at most 256, and this is {0}")]
    Count(u64),
}

/// A device's carried word, as its value holds it (see the module's
/// documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarriedWord {
    /// The number of the statement under which the device carried.
    pub number: u64,
    /// The node keys of the relays at which nothing that it carried waits:
    /// one at least, at most eight, in the order of its configuration.
    pub keys: Vec<[u8; 32]>,
    /// How many more such relays there are: 0 unless there are eight keys.
    pub more: u64,
    /// How many relays it is set up with are neither named nor counted in
    /// `more`.
    pub not_yet: u64,
}

impl CarriedWord {
    /// The word's value. Refused, and never cut to fit, where a reader
    /// would refuse it: so a device writes only a word that reads back.
    pub fn to_value(&self) -> Result<Vec<u8>, NotAWord> {
        self.check()?;
        let mut out = Vec::with_capacity(8 + 1 + 32 * self.keys.len() + 2 + 2);
        out.extend_from_slice(&self.number.to_be_bytes());
        // At most eight keys, and each count at most 256 (checked above).
        out.push(self.keys.len() as u8);
        for key in &self.keys {
            out.extend_from_slice(key);
        }
        out.extend_from_slice(&(self.more as u16).to_be_bytes());
        out.extend_from_slice(&(self.not_yet as u16).to_be_bytes());
        Ok(out)
    }

    /// Read a word from an entry's value, as a reader does (decision
    /// 2026-10-19, rule 5): four fields, no more; one to eight keys of 32
    /// bytes, none twice; the third field 0 unless there are eight keys;
    /// each count at most 256. Anything else is no word.
    pub fn from_value(value: &Value) -> Result<Self, NotAWord> {
        let Value::Other(bytes) = value else {
            return Err(NotAWord::Kind);
        };
        let mut reader = Reader::new(bytes);
        let number = reader.u64().ok_or(NotAWord::Short)?;
        // How many keys follow: their bound is checked with the rest.
        let count = reader.array::<1>().ok_or(NotAWord::Short)?[0] as usize;
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            keys.push(reader.array::<32>().ok_or(NotAWord::Short)?);
        }
        let more = reader.count().ok_or(NotAWord::Short)? as u64;
        let not_yet = reader.count().ok_or(NotAWord::Short)? as u64;
        if !reader.is_empty() {
            return Err(NotAWord::Long);
        }
        let word = Self {
            number,
            keys,
            more,
            not_yet,
        };
        word.check()?;
        Ok(word)
    }

    /// What a reader refuses of the fields themselves.
    fn check(&self) -> Result<(), NotAWord> {
        if !(1..=REACHED_WORD_MAX_RELAYS).contains(&self.keys.len()) {
            return Err(NotAWord::Keys(self.keys.len()));
        }
        for (at, key) in self.keys.iter().enumerate() {
            if self.keys[..at].contains(key) {
                return Err(NotAWord::Twice);
            }
        }
        if self.more != 0 && self.keys.len() < REACHED_WORD_MAX_RELAYS {
            return Err(NotAWord::MoreWithFewKeys);
        }
        for count in [self.more, self.not_yet] {
            if count > REACHED_WORD_MAX_COUNT {
                return Err(NotAWord::Count(count));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn word(keys: usize, more: u64, not_yet: u64) -> CarriedWord {
        CarriedWord {
            number: 3,
            keys: (1..=keys as u8).map(key).collect(),
            more,
            not_yet,
        }
    }

    /// The value byte for byte (decision 2026-10-19, rule 4): the number,
    /// the count of keys and the keys, and the two counts, and nothing
    /// after.
    #[test]
    fn the_value_is_four_fields_byte_for_byte() {
        let value = word(2, 0, 1).to_value().unwrap();
        let mut expected = 3u64.to_be_bytes().to_vec();
        expected.push(2);
        expected.extend_from_slice(&key(1));
        expected.extend_from_slice(&key(2));
        expected.extend_from_slice(&[0, 0, 0, 1]);
        assert_eq!(value, expected);
        assert_eq!(
            CarriedWord::from_value(&Value::Other(value)).unwrap(),
            word(2, 0, 1)
        );
        // At the bound: eight keys, and both counts at 256.
        let full = word(REACHED_WORD_MAX_RELAYS, 256, 256);
        let value = full.to_value().unwrap();
        assert_eq!(value.len(), 8 + 1 + 32 * 8 + 2 + 2);
        assert_eq!(CarriedWord::from_value(&Value::Other(value)).unwrap(), full);
        // A fourth field of 0 is read: a relay out of reach that took
        // everything is named, and not counted (decision 2026-10-19 §13,
        // third review, finding 4).
        let all = word(2, 0, 0);
        let value = Value::Other(all.to_value().unwrap());
        assert_eq!(CarriedWord::from_value(&value).unwrap(), all);
    }

    /// What a reader refuses, each as no word (decision 2026-10-19, rule
    /// 5); and the writer refuses the same, so it never writes one.
    #[test]
    fn a_word_out_of_its_form_is_no_word() {
        let refused = |word: CarriedWord, why: NotAWord| {
            assert_eq!(word.to_value(), Err(why.clone()), "{word:?}");
            // The same bytes, put together by hand, are refused by the
            // reader.
            let mut bytes = word.number.to_be_bytes().to_vec();
            bytes.push(word.keys.len() as u8);
            for key in &word.keys {
                bytes.extend_from_slice(key);
            }
            bytes.extend_from_slice(&(word.more as u16).to_be_bytes());
            bytes.extend_from_slice(&(word.not_yet as u16).to_be_bytes());
            assert_eq!(CarriedWord::from_value(&Value::Other(bytes)), Err(why));
        };
        refused(word(0, 0, 2), NotAWord::Keys(0));
        refused(word(9, 0, 0), NotAWord::Keys(9));
        let mut twice = word(3, 0, 0);
        twice.keys[2] = twice.keys[0];
        refused(twice, NotAWord::Twice);
        refused(word(7, 1, 0), NotAWord::MoreWithFewKeys);
        refused(word(8, 257, 0), NotAWord::Count(257));
        refused(word(2, 0, 257), NotAWord::Count(257));

        let good = word(1, 0, 1).to_value().unwrap();
        // A byte more, or a byte less, is no word.
        let mut long = good.clone();
        long.push(0);
        assert_eq!(
            CarriedWord::from_value(&Value::Other(long)),
            Err(NotAWord::Long)
        );
        for cut in 0..good.len() {
            let short = Value::Other(good[..cut].to_vec());
            assert_eq!(CarriedWord::from_value(&short), Err(NotAWord::Short));
        }
        // A text, or a delete, is no word.
        let text = Value::Text(String::from_utf8_lossy(&good).into_owned());
        assert_eq!(CarriedWord::from_value(&text), Err(NotAWord::Kind));
        assert_eq!(CarriedWord::from_value(&Value::Delete), Err(NotAWord::Kind));
    }
}
