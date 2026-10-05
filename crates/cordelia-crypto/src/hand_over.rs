//! The hand-over: what a device is handed when it is added (decision
//! 2026-10-04 §6).
//!
//! The device that adds writes one entry in the pair channel it has with
//! the new device, under the name `hand-over`. This module makes and reads
//! that entry's value, and nothing else of it: when it was made, the
//! statement the adder has applied, the secret, the statement key, the
//! change entry it holds, the record of the addition, and, where the adder
//! was itself added since that statement, the record of its own addition.
//!
//! ## Form
//!
//! A length is two bytes and a time is eight, the higher byte first.
//!
//! ```text
//! made           8: when it was made, in seconds, in UTC, by the clock of
//!                the device that adds
//! statement      its length, then the signed statement
//! secret         32
//! statement key  32
//! change entry   channel's ID 32, slot 32, author's signature 64,
//!                channel's signature 64, content 32768
//! records        1: how many, from 0 to 2; then for each its length and
//!                the signed record
//! ```
//!
//! The change entry is carried whole, so that the new device can keep it
//! and show it to a relay as every device does (§4.6). Its author and its
//! revision are the statement's phrase key and number, and are not written
//! a second time. The first record is the record of the addition, and the
//! second the record of the adder's own addition.
//!
//! The time a hand-over was made is part of what it says, and the entry
//! that carries it signs it with the rest: whoever accepts it sets that
//! time beside the time a key was typed. The revision of that entry only
//! orders the hand-overs of one device to another, and can run ahead of
//! any clock.
//!
//! ## What is refused
//!
//! Reading is strict, and a hand-over that is read holds together. Bytes
//! after its end, a part that is missing or cut short, and each of these:
//!
//! - a statement that its phrase's key did not sign;
//! - a secret that the statement does not commit to;
//! - a change entry whose signatures do not hold, or that is not the entry
//!   of that statement: the phrase's key did not write it, it is not in
//!   the change entry's slot of its channel, the statement key does not
//!   open it, or it carries another statement;
//! - a record that its adder did not sign, or that is made under another
//!   statement than the one handed over;
//! - a record that adds a key the statement lists as removed, or one it
//!   already lists as a device: such a key is handed the change with no
//!   record;
//! - a record whose adder neither is a device of the statement nor comes
//!   with the record of its own addition by one: a chain is two long at
//!   most;
//! - a record of the adder's own addition that is not needed, or with no
//!   record of an addition before it.
//!
//! Making one refuses the same, so no hand-over is written that the device
//! it is for would refuse.

use std::fmt;

use cordelia_core::protocol::{CHANGE_ENTRY_BYTES, MAX_ADDITION_BYTES, MAX_HAND_OVER_RECORDS};

use crate::addition::{AdditionError, SignedAddition};
use crate::change_entry::{ChangeEntryError, open_statement};
use crate::entry::{Entry, EntryError};
use crate::statement::{Reader, SignedStatement, StatementError, put_count};

/// Why bytes are not a hand-over, or why one was not made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandOverError {
    #[error("the hand-over ends before it is whole")]
    Truncated,

    #[error("there are bytes after the hand-over's end")]
    TrailingBytes,

    #[error("the statement that is handed over is no statement: {0}")]
    Statement(#[from] StatementError),

    #[error("the secret is not the one that the statement commits to")]
    SecretNotCommitted,

    #[error("the change entry that is handed over is no entry: {0}")]
    Entry(#[from] EntryError),

    #[error("the change entry is not the entry of the statement that is handed over")]
    NotTheStatementsEntry,

    #[error("the change entry is not opened: {0}")]
    ChangeEntry(#[from] ChangeEntryError),

    #[error("a hand-over carries at most 2 records, and this carries {0}")]
    TooManyRecords(usize),

    #[error("a record is at most 226 bytes, and this is {0}")]
    RecordLength(usize),

    #[error("a record that is handed over is no record: {0}")]
    Record(#[from] AdditionError),

    #[error("a record is made under another statement than the one that is handed over")]
    RecordUnderAnotherStatement,

    #[error("a record adds a key that the statement lists as removed")]
    AddsARemovedKey,

    #[error("a record adds a key that the statement already lists as a device")]
    AddsAListedKey,

    #[error(
        "the device that adds is no device of the statement, and no record of its own addition comes with it"
    )]
    AdderNotKnown,

    #[error("the record of the adder's own addition is not of the device that adds")]
    NotTheAddersOwn,

    #[error(
        "the adder was itself added by a device that is no device of the statement: a chain is two long at most"
    )]
    ChainTooLong,

    #[error("the record of the adder's own addition is not needed: the statement lists the adder")]
    RecordNotNeeded,
}

/// What a device is handed when it is added (decision 2026-10-04 §6).
#[derive(Clone, PartialEq, Eq)]
pub struct HandOver {
    /// When the hand-over was made, by the clock of the device that adds:
    /// seconds, in UTC. Any time is in the form: whether it is near
    /// enough to now is for the device that accepts to say.
    pub made_at: u64,
    /// The statement the adder has applied.
    pub statement: SignedStatement,
    /// The person secret of that statement.
    pub secret: [u8; 32],
    /// The statement key of the phrase the adder follows (§4.6).
    pub statement_key: [u8; 32],
    /// The change entry of that statement, whole: the latest the adder
    /// holds.
    pub change_entry: Entry,
    /// The record of the addition. `None` where a key that the statement
    /// already lists is handed the change again.
    pub addition: Option<SignedAddition>,
    /// The record of the adder's own addition, where the adder was itself
    /// added since that statement.
    pub adders_own: Option<SignedAddition>,
}

impl HandOver {
    /// Whether the hand-over holds together: every rule of the module's
    /// documentation.
    pub fn validate(&self) -> Result<(), HandOverError> {
        self.statement.verify()?;
        let statement = &self.statement.statement;
        if !statement.commits_to(&self.secret) {
            return Err(HandOverError::SecretNotCommitted);
        }

        // The change entry is an entry, by the check that needs no key, and
        // it is this statement's. It is opened as a device opens one: the
        // phrase's key wrote it, in the change entry's slot of the channel
        // it names, and it is no delete. And the statement key opens it to
        // this very statement, whose number is its revision.
        let entry = self.change_entry.clone().check()?;
        let carried = open_statement(
            &entry,
            &statement.phrase_key,
            &entry.channel,
            &self.statement_key,
        )?;
        if carried != self.statement {
            return Err(HandOverError::NotTheStatementsEntry);
        }

        let under = statement.link()?;
        let Some(addition) = &self.addition else {
            // A record of the adder's own addition comes only with the
            // record it is for.
            return match self.adders_own {
                Some(_) => Err(HandOverError::RecordNotNeeded),
                None => Ok(()),
            };
        };
        addition.verify()?;
        let added = &addition.addition;
        if added.under != under {
            return Err(HandOverError::RecordUnderAnotherStatement);
        }
        if statement.removes(&added.device.key) {
            return Err(HandOverError::AddsARemovedKey);
        }
        if statement.lists(&added.device.key) {
            return Err(HandOverError::AddsAListedKey);
        }

        match (&self.adders_own, statement.lists(&added.adder)) {
            (None, true) => Ok(()),
            (Some(_), true) => Err(HandOverError::RecordNotNeeded),
            (None, false) => Err(HandOverError::AdderNotKnown),
            (Some(own), false) => {
                own.verify()?;
                let own = &own.addition;
                if own.under != under {
                    return Err(HandOverError::RecordUnderAnotherStatement);
                }
                if own.device.key != added.adder {
                    return Err(HandOverError::NotTheAddersOwn);
                }
                if statement.removes(&own.device.key) {
                    return Err(HandOverError::AddsARemovedKey);
                }
                // The adder was added by a device of the statement. One
                // that was added by a device added since may not add.
                if !statement.lists(&own.adder) {
                    return Err(HandOverError::ChainTooLong);
                }
                Ok(())
            }
        }
    }

    /// Whether the hand-over is for the device whose key is `device`: its
    /// record adds that key, or it has no record and its statement lists
    /// that key.
    pub fn is_for(&self, device: &[u8; 32]) -> bool {
        match &self.addition {
            Some(addition) => addition.addition.device.key == *device,
            None => self.statement.statement.lists(device),
        }
    }

    /// The hand-over as bytes (see the module's documentation). One that
    /// does not hold together has none.
    pub fn to_bytes(&self) -> Result<Vec<u8>, HandOverError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.made_at.to_be_bytes());
        let statement = self.statement.to_bytes()?;
        put_count(&mut out, statement.len());
        out.extend_from_slice(&statement);
        out.extend_from_slice(&self.secret);
        out.extend_from_slice(&self.statement_key);

        out.extend_from_slice(&self.change_entry.channel);
        out.extend_from_slice(&self.change_entry.slot);
        out.extend_from_slice(&self.change_entry.author_signature);
        out.extend_from_slice(&self.change_entry.channel_signature);
        out.extend_from_slice(&self.change_entry.content);

        let records: Vec<&SignedAddition> = self.addition.iter().chain(&self.adders_own).collect();
        out.push(records.len() as u8);
        for record in records {
            let record = record.to_bytes()?;
            put_count(&mut out, record.len());
            out.extend_from_slice(&record);
        }
        Ok(out)
    }

    /// Read a hand-over, strictly, and check that it holds together
    /// ([`HandOver::validate`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandOverError> {
        let short = || HandOverError::Truncated;
        let mut reader = Reader::new(bytes);

        let made_at = reader.u64().ok_or_else(short)?;
        let length = reader.count().ok_or_else(short)?;
        let statement = SignedStatement::from_bytes(reader.take(length).ok_or_else(short)?)?;
        let secret = reader.array().ok_or_else(short)?;
        let statement_key = reader.array().ok_or_else(short)?;

        let change_entry = Entry {
            channel: reader.array().ok_or_else(short)?,
            slot: reader.array().ok_or_else(short)?,
            author: statement.statement.phrase_key,
            rev: statement.statement.number,
            delete: false,
            author_signature: reader.array().ok_or_else(short)?,
            channel_signature: reader.array().ok_or_else(short)?,
            content: reader.take(CHANGE_ENTRY_BYTES).ok_or_else(short)?.to_vec(),
        };

        // The count is checked against its bound before a record is read.
        let count = usize::from(reader.array::<1>().ok_or_else(short)?[0]);
        if count > MAX_HAND_OVER_RECORDS {
            return Err(HandOverError::TooManyRecords(count));
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let length = reader.count().ok_or_else(short)?;
            if length > MAX_ADDITION_BYTES {
                return Err(HandOverError::RecordLength(length));
            }
            let record = reader.take(length).ok_or_else(short)?;
            records.push(SignedAddition::from_bytes(record)?);
        }
        if !reader.is_empty() {
            return Err(HandOverError::TrailingBytes);
        }

        let mut records = records.into_iter();
        let hand_over = Self {
            made_at,
            statement,
            secret,
            statement_key,
            change_entry,
            addition: records.next(),
            adders_own: records.next(),
        };
        hand_over.validate()?;
        Ok(hand_over)
    }
}

// A hand-over holds the person secret and the statement key. What is shown
// for debugging is when it was made, the statement's number and which
// records come with it.
impl fmt::Debug for HandOver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandOver")
            .field("made_at", &self.made_at)
            .field("statement", &self.statement.statement.number)
            .field("addition", &self.addition.is_some())
            .field("adders_own", &self.adders_own.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addition::Addition;
    use crate::addition::testing::added;
    use crate::change_entry::{ForPhrase, entry_of};
    use crate::phrase::Phrase;
    use crate::statement::testing::*;
    use crate::statement::{Device, Statement};
    use cordelia_core::protocol::{
        HAND_OVER_NAME, MAX_ENTRY_NAME_AND_VALUE_BYTES, MAX_HAND_OVER_BYTES,
    };

    /// When the hand-overs of these tests say they were made.
    const MADE_AT: u64 = 1_800_000_000;

    /// Statement 2 of the phrase, which lists devices 0 and 1 and removes
    /// device 2. It commits to secret 2.
    fn second(phrase: &Phrase) -> Statement {
        first(phrase)
            .next(key(0), &secret(2), devices(&[0, 1]), &[key(2)])
            .unwrap()
    }

    /// The change entry of `statement`, which commits to `secret`.
    fn change_entry(phrase: &Phrase, statement: &Statement, secret: [u8; 32]) -> Entry {
        entry_of(
            phrase,
            &signed(statement, phrase),
            &ForPhrase::first(secret),
        )
        .unwrap()
    }

    /// What device 0 hands device 7 under statement 2: the record of the
    /// addition, and no other.
    fn sample(phrase: &Phrase) -> HandOver {
        let statement = second(phrase);
        HandOver {
            made_at: MADE_AT,
            statement: signed(&statement, phrase),
            secret: secret(2),
            statement_key: phrase.statement_key().unwrap(),
            change_entry: change_entry(phrase, &statement, secret(2)),
            addition: Some(added(&statement, 0, 7)),
            adders_own: None,
        }
    }

    /// What device 7, which device 0 added, hands device 8.
    fn from_an_added_device(phrase: &Phrase) -> HandOver {
        let statement = second(phrase);
        HandOver {
            addition: Some(added(&statement, 7, 8)),
            adders_own: Some(added(&statement, 0, 7)),
            ..sample(phrase)
        }
    }

    /// Where the parts of [`sample`]'s bytes begin: the secret, the
    /// statement key, the change entry, and the count of records. The
    /// time is before them all, and the statement follows it.
    fn places(hand_over: &HandOver) -> (usize, usize, usize, usize) {
        let secret = 8 + 2 + hand_over.statement.to_bytes().unwrap().len();
        (secret, secret + 32, secret + 64, secret + 64 + 192 + 32_768)
    }

    #[test]
    fn a_hand_over_is_laid_out_as_documented() {
        let phrase = phrase();
        let hand_over = sample(&phrase);
        let bytes = hand_over.to_bytes().unwrap();

        let statement = hand_over.statement.to_bytes().unwrap();
        let (secret_at, key_at, entry_at, records_at) = places(&hand_over);
        assert_eq!(bytes[..8], MADE_AT.to_be_bytes());
        assert_eq!(bytes[8..10], (statement.len() as u16).to_be_bytes());
        assert_eq!(bytes[10..secret_at], statement);
        assert_eq!(bytes[secret_at..key_at], secret(2));
        assert_eq!(bytes[key_at..entry_at], phrase.statement_key().unwrap());

        let entry = &hand_over.change_entry;
        assert_eq!(bytes[entry_at..entry_at + 32], entry.channel);
        assert_eq!(bytes[entry_at + 32..entry_at + 64], entry.slot);
        assert_eq!(bytes[entry_at + 64..entry_at + 128], entry.author_signature);
        assert_eq!(
            bytes[entry_at + 128..entry_at + 192],
            entry.channel_signature
        );
        assert_eq!(bytes[entry_at + 192..records_at], entry.content);

        let record = hand_over.addition.as_ref().unwrap().to_bytes().unwrap();
        assert_eq!(bytes[records_at], 1);
        assert_eq!(
            bytes[records_at + 1..records_at + 3],
            (record.len() as u16).to_be_bytes()
        );
        assert_eq!(bytes[records_at + 3..], record);
    }

    /// A hand-over says when it was made, in its first eight bytes, and
    /// reads back with that time: any time is in the form.
    #[test]
    fn a_hand_over_says_when_it_was_made() {
        let phrase = phrase();
        let made = sample(&phrase);
        let at = |made_at: u64| HandOver {
            made_at,
            ..made.clone()
        };
        let bytes = at(MADE_AT).to_bytes().unwrap();
        for made_at in [0, 1, MADE_AT + 1, u64::MAX] {
            let other = at(made_at).to_bytes().unwrap();
            // Two that differ in their time differ in those bytes alone.
            assert_eq!(other[..8], made_at.to_be_bytes());
            assert!(other[8..] == bytes[8..], "{made_at}");
            let read = HandOver::from_bytes(&other).unwrap();
            assert_eq!(read.made_at, made_at);
            assert_eq!(read, at(made_at));
            assert_ne!(read, at(MADE_AT));
        }
    }

    #[test]
    fn a_hand_over_reads_back_as_it_was_made() {
        let phrase = phrase();
        let statement = second(&phrase);
        for hand_over in [
            sample(&phrase),
            from_an_added_device(&phrase),
            // A key that the statement lists is handed the change again,
            // with no record.
            HandOver {
                addition: None,
                ..sample(&phrase)
            },
        ] {
            let bytes = hand_over.to_bytes().unwrap();
            let read = HandOver::from_bytes(&bytes).unwrap();
            assert_eq!(read, hand_over);
            assert_eq!(read.to_bytes().unwrap(), bytes);
            // The change entry it carries is whole: it passes the check
            // that needs no key, as it must to be shown to a relay.
            let entry = read.change_entry.clone().check().unwrap();
            assert_eq!(entry.author, phrase.public_key().unwrap());
            assert_eq!(entry.rev, 2);
            assert_eq!(read.statement.statement, statement);
        }
    }

    #[test]
    fn a_hand_over_that_ends_early_or_goes_on_is_refused() {
        let phrase = phrase();
        for hand_over in [sample(&phrase), from_an_added_device(&phrase)] {
            let bytes = hand_over.to_bytes().unwrap();
            let (secret_at, key_at, entry_at, records_at) = places(&hand_over);
            // Cut within each part, at each part's end, and one byte short
            // of the whole.
            let mut cuts = vec![
                0,
                1,
                7,
                8,
                9,
                10,
                secret_at - 1,
                secret_at,
                key_at,
                entry_at,
            ];
            cuts.extend([entry_at + 32, entry_at + 64, entry_at + 128, entry_at + 192]);
            cuts.extend([records_at - 1, records_at, records_at + 1, records_at + 2]);
            cuts.extend([records_at + 3, bytes.len() - 65, bytes.len() - 1]);
            for cut in cuts {
                let refused = HandOver::from_bytes(&bytes[..cut]).unwrap_err();
                assert!(
                    matches!(
                        refused,
                        HandOverError::Truncated
                            | HandOverError::Statement(StatementError::Truncated)
                    ),
                    "{cut}: {refused:?}"
                );
            }
            for extra in [vec![0u8], vec![0xff], vec![0; 64]] {
                let mut longer = bytes.clone();
                longer.extend_from_slice(&extra);
                assert_eq!(
                    HandOver::from_bytes(&longer),
                    Err(HandOverError::TrailingBytes)
                );
            }
        }
    }

    /// A count of records over its bound, and a record over its length,
    /// are refused where they are read, before anything is read for them.
    #[test]
    fn a_count_or_a_length_over_its_bound_is_refused_where_it_is_read() {
        let phrase = phrase();
        let hand_over = sample(&phrase);
        let bytes = hand_over.to_bytes().unwrap();
        let (.., records_at) = places(&hand_over);

        for count in [3u8, 4, 255] {
            let mut claims = bytes[..=records_at].to_vec();
            claims[records_at] = count;
            assert_eq!(
                HandOver::from_bytes(&claims),
                Err(HandOverError::TooManyRecords(usize::from(count)))
            );
        }
        for length in [227u16, 1000, u16::MAX] {
            let mut claims = bytes[..records_at + 3].to_vec();
            claims[records_at + 1..].copy_from_slice(&length.to_be_bytes());
            assert_eq!(
                HandOver::from_bytes(&claims),
                Err(HandOverError::RecordLength(usize::from(length)))
            );
        }
        // A count that says more records than follow: a part is missing.
        let mut claims = bytes.clone();
        claims[records_at] = 2;
        assert_eq!(HandOver::from_bytes(&claims), Err(HandOverError::Truncated));
        // And one that says fewer: bytes are left over.
        let mut claims = bytes;
        claims[records_at] = 0;
        assert_eq!(
            HandOver::from_bytes(&claims),
            Err(HandOverError::TrailingBytes)
        );
    }

    #[test]
    fn a_statement_or_a_secret_that_does_not_hold_is_refused() {
        let phrase = phrase();
        let hand_over = sample(&phrase);
        let bytes = hand_over.to_bytes().unwrap();
        let (secret_at, ..) = places(&hand_over);

        // The statement's signature is changed.
        let mut forged = bytes.clone();
        forged[secret_at - 1] ^= 1;
        assert_eq!(
            HandOver::from_bytes(&forged),
            Err(HandOverError::Statement(StatementError::Signature))
        );
        // A statement that another phrase signed, with that phrase's own
        // entry: it holds together, and says whose it is. Whether a device
        // takes it is for the device to say.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let theirs = sample(&other);
        assert_eq!(theirs.validate(), Ok(()));
        assert_ne!(
            theirs.statement.statement.phrase_key,
            hand_over.statement.statement.phrase_key
        );

        // Another secret than the one the statement commits to.
        let mut another = bytes.clone();
        another[secret_at] ^= 1;
        assert_eq!(
            HandOver::from_bytes(&another),
            Err(HandOverError::SecretNotCommitted)
        );
        let made = HandOver {
            secret: secret(1),
            ..hand_over
        };
        assert_eq!(made.validate(), Err(HandOverError::SecretNotCommitted));
        assert_eq!(made.to_bytes(), Err(HandOverError::SecretNotCommitted));
    }

    #[test]
    fn a_change_entry_that_is_not_the_statements_is_refused() {
        let phrase = phrase();
        let hand_over = sample(&phrase);
        let bytes = hand_over.to_bytes().unwrap();
        let (_, key_at, entry_at, records_at) = places(&hand_over);

        // Each clear field and each signature changed: a signature does
        // not hold.
        for (place, refused) in [
            (entry_at, EntryError::AuthorSignature),
            (entry_at + 32, EntryError::AuthorSignature),
            (entry_at + 64, EntryError::AuthorSignature),
            (entry_at + 128, EntryError::ChannelSignature),
            (entry_at + 192, EntryError::AuthorSignature),
            (records_at - 1, EntryError::AuthorSignature),
        ] {
            let mut changed = bytes.clone();
            changed[place] ^= 1;
            let read = HandOver::from_bytes(&changed).unwrap_err();
            // A channel's ID that was changed may be no usable key at all.
            if place == entry_at {
                assert!(matches!(read, HandOverError::Entry(_)), "{read:?}");
            } else {
                assert_eq!(read, HandOverError::Entry(refused), "{place}");
            }
        }

        // The statement key does not open it.
        let mut another = bytes.clone();
        another[key_at] ^= 1;
        assert_eq!(
            HandOver::from_bytes(&another),
            Err(HandOverError::ChangeEntry(ChangeEntryError::DidNotOpen))
        );

        // The entry of another statement of the phrase: statement 1's,
        // which the phrase signed at another number.
        let one = first(&phrase);
        let earlier = HandOver {
            change_entry: change_entry(&phrase, &one, secret(1)),
            ..hand_over.clone()
        };
        assert_eq!(
            earlier.validate(),
            Err(HandOverError::NotTheStatementsEntry)
        );
        // Another statement at the same number: one made apart.
        let apart = first(&phrase)
            .next(key(0), &secret(2), devices(&[0, 3]), &[key(2)])
            .unwrap();
        let other = HandOver {
            change_entry: change_entry(&phrase, &apart, secret(2)),
            ..hand_over.clone()
        };
        assert_eq!(other.validate(), Err(HandOverError::NotTheStatementsEntry));
        // An entry that says it is a delete: one that was made to say so
        // after it was signed, and one that the phrase signed so.
        let mut deleted = hand_over.clone();
        deleted.change_entry.delete = true;
        assert!(matches!(
            deleted.validate(),
            Err(HandOverError::Entry(EntryError::AuthorSignature))
        ));
        let channel_key = crate::derive::signing_key(&phrase.channel_secret().unwrap()).unwrap();
        let by_the_phrase = |slot: [u8; 32], delete: bool| HandOver {
            change_entry: crate::entry::signed(
                &channel_key,
                &phrase.signing_key().unwrap(),
                slot,
                2,
                delete,
                hand_over.change_entry.content.clone(),
            ),
            ..hand_over.clone()
        };
        assert_eq!(
            by_the_phrase(hand_over.change_entry.slot, true).validate(),
            Err(HandOverError::ChangeEntry(ChangeEntryError::Delete))
        );
        // An entry that the phrase's key wrote in another slot of its
        // channel than the change entry's.
        assert_eq!(
            by_the_phrase([7u8; 32], false).validate(),
            Err(HandOverError::ChangeEntry(ChangeEntryError::AnotherSlot))
        );
        assert_eq!(
            by_the_phrase(hand_over.change_entry.slot, false).validate(),
            Ok(())
        );
        // An entry of the same content that another key wrote, in a
        // channel of its own: the phrase's key did not sign it.
        let secret_of_another = [0x44; 32];
        let stranger = identity(9);
        let mut theirs = crate::entry::signed(
            &crate::derive::signing_key(&secret_of_another).unwrap(),
            &stranger,
            hand_over.change_entry.slot,
            2,
            false,
            hand_over.change_entry.content.clone(),
        );
        assert!(theirs.clone().check().is_ok());
        let with_theirs = HandOver {
            change_entry: theirs.clone(),
            ..hand_over.clone()
        };
        assert_eq!(
            with_theirs.validate(),
            Err(HandOverError::ChangeEntry(ChangeEntryError::AnotherAuthor))
        );
        // Written out, its author is read as the phrase's key, under
        // which its signature does not hold.
        theirs.author = phrase.public_key().unwrap();
        let with_theirs = HandOver {
            change_entry: theirs,
            ..hand_over
        };
        assert_eq!(
            with_theirs.validate(),
            Err(HandOverError::Entry(EntryError::AuthorSignature))
        );
    }

    #[test]
    fn a_record_that_does_not_verify_is_refused() {
        let phrase = phrase();
        let hand_over = sample(&phrase);
        let bytes = hand_over.to_bytes().unwrap();

        // The record's signature is changed, and then each of its fields.
        let last = bytes.len() - 1;
        let mut forged = bytes.clone();
        forged[last] ^= 1;
        assert_eq!(
            HandOver::from_bytes(&forged),
            Err(HandOverError::Record(AdditionError::Signature))
        );
        let (.., records_at) = places(&hand_over);
        let mut renamed = bytes.clone();
        renamed[records_at + 3 + 34] ^= 1;
        assert_eq!(
            HandOver::from_bytes(&renamed),
            Err(HandOverError::Record(AdditionError::Signature))
        );

        // A record that another device signed in the adder's name.
        let statement = second(&phrase);
        let mut theirs = added(&statement, 1, 7);
        theirs.addition.adder = key(0);
        let made = HandOver {
            addition: Some(theirs),
            ..hand_over.clone()
        };
        assert_eq!(
            made.validate(),
            Err(HandOverError::Record(AdditionError::Signature))
        );

        // The record of the adder's own addition is held to the same.
        let chained = from_an_added_device(&phrase);
        let mut own = chained.adders_own.clone().unwrap();
        own.signature[0] ^= 1;
        let made = HandOver {
            adders_own: Some(own),
            ..chained
        };
        assert_eq!(
            made.validate(),
            Err(HandOverError::Record(AdditionError::Signature))
        );
    }

    /// A record counts only under the statement it names: one under
    /// another statement than the one handed over is refused.
    #[test]
    fn a_record_under_another_statement_is_refused() {
        let phrase = phrase();
        let one = first(&phrase);
        let hand_over = sample(&phrase);
        let made = HandOver {
            addition: Some(added(&one, 0, 7)),
            ..hand_over
        };
        assert_eq!(
            made.validate(),
            Err(HandOverError::RecordUnderAnotherStatement)
        );

        let chained = from_an_added_device(&phrase);
        let made = HandOver {
            adders_own: Some(added(&one, 0, 7)),
            ..chained
        };
        assert_eq!(
            made.validate(),
            Err(HandOverError::RecordUnderAnotherStatement)
        );
    }

    #[test]
    fn a_record_that_adds_a_removed_or_a_listed_key_is_refused() {
        let phrase = phrase();
        let statement = second(&phrase);
        let hand_over = sample(&phrase);

        // Device 2 is among the statement's removed keys.
        let made = HandOver {
            addition: Some(added(&statement, 0, 2)),
            ..hand_over.clone()
        };
        assert_eq!(made.validate(), Err(HandOverError::AddsARemovedKey));

        // Device 1 is among its devices: it is handed the change with no
        // record.
        let made = HandOver {
            addition: Some(added(&statement, 0, 1)),
            ..hand_over.clone()
        };
        assert_eq!(made.validate(), Err(HandOverError::AddsAListedKey));
        let made = HandOver {
            addition: None,
            ..hand_over.clone()
        };
        assert_eq!(made.validate(), Ok(()));
        assert!(made.is_for(&key(1)) && made.is_for(&key(0)));
        assert!(!made.is_for(&key(7)) && !made.is_for(&key(2)));

        // With a record it is for the key the record adds, and no other.
        assert!(hand_over.is_for(&key(7)));
        assert!(!hand_over.is_for(&key(0)) && !hand_over.is_for(&key(8)));

        // A removed key that added the adder: its record is refused too.
        let made = HandOver {
            addition: Some(added(&statement, 2, 8)),
            adders_own: Some(added(&statement, 0, 2)),
            ..hand_over
        };
        assert_eq!(made.validate(), Err(HandOverError::AddsARemovedKey));
    }

    /// A device that the statement lists may add, and so may a device that
    /// such a device added. A device added by one of those may not: a
    /// chain is two long at most.
    #[test]
    fn a_chain_of_additions_is_two_long_at_most() {
        let phrase = phrase();
        let statement = second(&phrase);
        let hand_over = sample(&phrase);

        // Device 7, which is no device of the statement, adds with no
        // record of its own addition.
        let made = HandOver {
            addition: Some(added(&statement, 7, 8)),
            ..hand_over.clone()
        };
        assert_eq!(made.validate(), Err(HandOverError::AdderNotKnown));

        // With it, where a device of the statement added it.
        assert_eq!(from_an_added_device(&phrase).validate(), Ok(()));

        // Device 8, which device 7 added, adds device 9: the record that
        // comes with it was signed by a device that was itself added.
        let made = HandOver {
            addition: Some(added(&statement, 8, 9)),
            adders_own: Some(added(&statement, 7, 8)),
            ..hand_over.clone()
        };
        assert_eq!(made.validate(), Err(HandOverError::ChainTooLong));

        // The record that comes with it is of another device than the
        // adder.
        let made = HandOver {
            addition: Some(added(&statement, 7, 8)),
            adders_own: Some(added(&statement, 0, 9)),
            ..hand_over.clone()
        };
        assert_eq!(made.validate(), Err(HandOverError::NotTheAddersOwn));

        // A record of the adder's own addition where the statement lists
        // the adder, and one with no record of an addition before it.
        let made = HandOver {
            adders_own: Some(added(&statement, 1, 0)),
            ..hand_over.clone()
        };
        assert_eq!(made.validate(), Err(HandOverError::RecordNotNeeded));
        let made = HandOver {
            addition: None,
            adders_own: Some(added(&statement, 0, 7)),
            ..hand_over
        };
        assert_eq!(made.validate(), Err(HandOverError::RecordNotNeeded));
    }

    /// At every bound together a hand-over is as large as its bound says,
    /// and with its name it fits one entry.
    #[test]
    fn at_every_bound_together_a_hand_over_fits_one_entry() {
        let phrase = phrase();
        let statement = at_every_bound(&phrase);
        let longest = |n: u16| Device::new(key(n), &"x".repeat(64)).unwrap();
        // Device 100 was added by device 0 of the statement, and adds 101.
        let own = Addition::under(&statement, longest(100), key(0), u64::MAX)
            .unwrap()
            .sign(&identity(0))
            .unwrap();
        let addition = Addition::under(&statement, longest(101), key(100), u64::MAX)
            .unwrap()
            .sign(&identity(100))
            .unwrap();
        let hand_over = HandOver {
            made_at: u64::MAX,
            statement: signed(&statement, &phrase),
            secret: secret(9),
            statement_key: phrase.statement_key().unwrap(),
            change_entry: change_entry(&phrase, &statement, secret(9)),
            addition: Some(addition),
            adders_own: Some(own),
        };
        let bytes = hand_over.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_HAND_OVER_BYTES);
        assert!(HAND_OVER_NAME.len() + bytes.len() <= MAX_ENTRY_NAME_AND_VALUE_BYTES);
        assert_eq!(HandOver::from_bytes(&bytes).unwrap(), hand_over);

        // It is the value of one entry of a pair channel, under its name.
        let pair = crate::derive::pair_secret(&identity(100), &key(101)).unwrap();
        let inside = crate::entry::Inside {
            name: HAND_OVER_NAME.to_string(),
            value: crate::entry::Value::Other(bytes.clone()),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&pair, &identity(100), 1, &inside)
            .unwrap()
            .check()
            .unwrap();
        // The new device derives the same channel, and reads it there.
        let theirs = crate::derive::pair_secret(&identity(101), &key(100)).unwrap();
        let read = entry.open(&theirs).unwrap();
        assert_eq!(read.name, "hand-over");
        assert_eq!(HandOver::from_bytes(read.value.bytes()).unwrap(), hand_over);
    }

    #[test]
    fn what_a_hand_over_holds_prints_no_secret() {
        let phrase = phrase();
        let mut hand_over = sample(&phrase);
        hand_over.secret = [0x9c; 32];
        hand_over.statement_key = [0x9d; 32];
        let printed = format!("{hand_over:?}");
        assert_eq!(
            printed,
            "HandOver { made_at: 1800000000, statement: 2, addition: true, adders_own: false, .. }"
        );
        assert!(!printed.contains("156") && !printed.contains("157"));
    }
}
