//! An entry on the wire (decision 2026-10-04 §2.3, §2.4): its bytes, to
//! and from, in one form.
//!
//! With a number as its bytes, the highest first:
//!
//! ```text
//! channel's ID   32
//! slot           32
//! author         32
//! revision       8
//! delete         1: 1 where the entry is a delete, and otherwise 0
//! length         4: the content's length
//! content        that many bytes
//! author's       64: the author's signature
//! channel's      64: the signature of the channel's signing key
//! ```
//!
//! The clear fields come in the order in which they are signed
//! ([`Entry::signed_bytes`]), with the content where its hash is signed,
//! and the two signatures after it.
//!
//! Reading is strict, so that an entry has one form and no other bytes are
//! read as it. Refused: bytes that end before the entry does, or go on
//! after it; a length that is not the length of the content that is there;
//! a content of a size that no entry's is; a delete that is neither 0 nor
//! 1; and a revision that no entry has.
//!
//! What is read is an [`Entry`], and nothing of it has been checked: its
//! signatures have not been looked at. Only [`Entry::check`] makes a
//! checked entry, here as everywhere.

use cordelia_core::protocol::{ENTRY_WIRE_OVERHEAD_BYTES, MAX_REV};

use crate::entry::{Entry, is_content_size};
use crate::statement::Reader;

/// Why bytes were not read as an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("the bytes end before an entry's clear fields do")]
    TooShort,

    #[error("an entry's content is a power of two from 256 to 65536 bytes, and this says {0}")]
    ContentSize(usize),

    #[error("an entry with that content is {said} bytes, and these are {given}")]
    Length { said: usize, given: usize },

    #[error("whether an entry is a delete is 0 or 1, and this is {0}")]
    Delete(u8),

    #[error("an entry's revision is from 1 to 2^53 - 1, and this is {0}")]
    Revision(u64),
}

impl Entry {
    /// The entry's bytes on the wire (see the module's documentation).
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENTRY_WIRE_OVERHEAD_BYTES + self.content.len());
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.slot);
        out.extend_from_slice(&self.author);
        out.extend_from_slice(&self.rev.to_be_bytes());
        out.push(u8::from(self.delete));
        // A content that four bytes cannot count is no entry's: its length
        // is written as the most they can say, which no reader takes.
        let length = u32::try_from(self.content.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.content);
        out.extend_from_slice(&self.author_signature);
        out.extend_from_slice(&self.channel_signature);
        out
    }

    /// Read an entry from its bytes on the wire, strictly. What is read
    /// has not been checked: [`Entry::check`] does that.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let short = || WireError::TooShort;
        let mut reader = Reader::new(bytes);
        let channel = reader.array().ok_or_else(short)?;
        let slot = reader.array().ok_or_else(short)?;
        let author = reader.array().ok_or_else(short)?;
        let rev = reader.u64().ok_or_else(short)?;
        let delete = reader.array::<1>().ok_or_else(short)?[0];
        let length = u32::from_be_bytes(reader.array().ok_or_else(short)?) as usize;

        // The length is looked at before anything is read by it: it is of
        // an allowed size, and the bytes are those of an entry with a
        // content of that size, no fewer and no more.
        if !is_content_size(length) {
            return Err(WireError::ContentSize(length));
        }
        let said = ENTRY_WIRE_OVERHEAD_BYTES + length;
        if bytes.len() != said {
            return Err(WireError::Length {
                said,
                given: bytes.len(),
            });
        }
        if delete > 1 {
            return Err(WireError::Delete(delete));
        }
        if !(1..=MAX_REV).contains(&rev) {
            return Err(WireError::Revision(rev));
        }

        let content = reader.take(length).ok_or_else(short)?.to_vec();
        let author_signature = reader.array().ok_or_else(short)?;
        let channel_signature = reader.array().ok_or_else(short)?;
        Ok(Self {
            channel,
            slot,
            author,
            rev,
            delete: delete == 1,
            content,
            author_signature,
            channel_signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive;
    use crate::entry::testing::*;
    use crate::entry::{EntryError, Value};
    use cordelia_core::protocol::{
        ENTRY_CLEAR_BYTES, MAX_ENTRY_NAME_AND_VALUE_BYTES, MAX_ENTRY_WIRE_BYTES, MAX_ITEM_BYTES,
        MIN_ENTRY_CONTENT_BYTES,
    };

    /// The entry that device 1 made of a small text at revision 5, as it
    /// travels.
    fn made() -> Entry {
        entry(1, 5, &text("notes.md", "what the file holds")).into_entry()
    }

    /// The bytes of [`made`], with the four bytes of its length saying
    /// `length`.
    fn saying_length(length: u32) -> Vec<u8> {
        let mut bytes = made().to_wire();
        bytes[105..109].copy_from_slice(&length.to_be_bytes());
        bytes
    }

    #[test]
    fn an_entry_is_read_from_its_bytes_as_it_was() {
        let long = "x".repeat(3000);
        let longest = "x".repeat(MAX_ENTRY_NAME_AND_VALUE_BYTES - 1);
        for (rev, inside) in [
            (5, text("notes.md", "what the file holds")),
            (1, text("n", "")),
            (MAX_REV, holding("notes.md", Value::Delete)),
            (7, holding("notes.md", Value::Other(vec![0x00, 0x9f, 0x92]))),
            (1 << 44, text("notes.md", &long)),
            (9, text("n", &longest)),
        ] {
            let checked = entry(2, rev, &inside);
            let bytes = checked.to_wire();
            assert_eq!(
                bytes.len(),
                ENTRY_WIRE_OVERHEAD_BYTES + checked.content.len()
            );

            let read = Entry::from_wire(&bytes).unwrap();
            assert_eq!(read, *checked, "{rev}");
            // And it is written again as the bytes it was read from.
            assert_eq!(read.to_wire(), bytes, "{rev}");
            // What was read passes the check, and opens to what was made.
            assert_eq!(read.check().unwrap().open(&SECRET).unwrap(), inside);
        }

        // The smallest entry and the largest, on the wire.
        let smallest = entry(1, 1, &text("n", "")).to_wire();
        assert_eq!(smallest.len(), 237 + MIN_ENTRY_CONTENT_BYTES);
        let largest = entry(1, 1, &text("n", &longest)).to_wire();
        assert_eq!(largest.len(), MAX_ENTRY_WIRE_BYTES);
        assert_eq!(largest.len(), 237 + MAX_ITEM_BYTES);
    }

    /// The form, byte by byte.
    #[test]
    fn an_entry_on_the_wire_is_laid_out_as_documented() {
        let entry = entry(2, (3 << 44) + 0x0102, &holding("notes.md", Value::Delete)).into_entry();
        let mut form = Vec::new();
        form.extend_from_slice(&derive::channel_id(&SECRET).unwrap());
        form.extend_from_slice(&slot_of("notes.md"));
        form.extend_from_slice(&key(2));
        form.extend_from_slice(&[0, 0, 0x30, 0, 0, 0, 0x01, 0x02]);
        form.push(1);
        form.extend_from_slice(&[0, 0, 1, 0]);
        form.extend_from_slice(&entry.content);
        form.extend_from_slice(&entry.author_signature);
        form.extend_from_slice(&entry.channel_signature);
        assert_eq!(entry.to_wire(), form);
        assert_eq!(entry.content.len(), 256);
        assert_eq!(form.len(), 32 + 32 + 32 + 8 + 1 + 4 + 256 + 64 + 64);

        // The clear fields are those that are signed, in their order, with
        // the content where its hash is signed.
        let signed = entry.signed_bytes();
        assert_eq!(form[..105], signed[..105]);
        assert_eq!(signed[105..], crate::sha256(&form[109..109 + 256]));
        // Beside the content: the clear fields and the two signatures, and
        // the four bytes of the length.
        assert_eq!(form.len() - 256, ENTRY_CLEAR_BYTES + 4);

        // One that is no delete says so with 0.
        let kept = made().to_wire();
        assert_eq!(kept[104], 0);
        assert_eq!(kept[96..104], [0, 0, 0, 0, 0, 0, 0, 5]);
    }

    /// Reading checks nothing but the form: an entry whose signatures do
    /// not hold is read, and only the check refuses it.
    #[test]
    fn what_is_read_from_the_wire_is_not_checked() {
        let mut unsigned = made();
        unsigned.author_signature = [0; 64];
        let read = Entry::from_wire(&unsigned.to_wire()).unwrap();
        assert_eq!(read, unsigned);
        assert_eq!(read.check(), Err(EntryError::AuthorSignature));

        let mut by_another = made();
        by_another.channel_signature = made().author_signature;
        let read = Entry::from_wire(&by_another.to_wire()).unwrap();
        assert_eq!(read.check(), Err(EntryError::ChannelSignature));

        // A content that was changed on the way is read as it came.
        let mut bytes = made().to_wire();
        bytes[200] ^= 1;
        let read = Entry::from_wire(&bytes).unwrap();
        assert_eq!(read.check(), Err(EntryError::AuthorSignature));
    }

    #[test]
    fn bytes_that_end_before_the_entry_does_are_refused() {
        let bytes = made().to_wire();
        assert_eq!(bytes.len(), 493);
        // Every beginning of an entry, and no bytes at all.
        for length in 0..bytes.len() {
            let refused = Entry::from_wire(&bytes[..length]).unwrap_err();
            let expected = if length < 109 {
                WireError::TooShort
            } else {
                WireError::Length {
                    said: 493,
                    given: length,
                }
            };
            assert_eq!(refused, expected, "{length}");
        }
        assert!(Entry::from_wire(&bytes).is_ok());
    }

    #[test]
    fn bytes_that_go_on_after_the_entry_are_refused() {
        let bytes = made().to_wire();
        for more in [&[0u8][..], &[0; 64], &[0xff; 256], &bytes] {
            let longer = [bytes.as_slice(), more].concat();
            assert_eq!(
                Entry::from_wire(&longer),
                Err(WireError::Length {
                    said: 493,
                    given: 493 + more.len(),
                }),
                "{}",
                more.len()
            );
        }
    }

    /// The length is the length of the content that is there. One that
    /// says another allowed size is refused, whether fewer bytes follow
    /// than it says or more.
    #[test]
    fn a_length_that_is_not_the_contents_is_refused() {
        // The control: the length as it was written.
        assert!(Entry::from_wire(&saying_length(256)).is_ok());
        for said in [512u32, 1024, 65_536] {
            assert_eq!(
                Entry::from_wire(&saying_length(said)),
                Err(WireError::Length {
                    said: 237 + said as usize,
                    given: 493,
                }),
                "{said}"
            );
        }
        // An entry of 512 bytes of content whose length says 256: what
        // follows the 256 is not read as signatures.
        let larger = entry(1, 5, &text("notes.md", &"x".repeat(300))).to_wire();
        assert_eq!(larger.len(), 237 + 512);
        let mut says_less = larger.clone();
        says_less[105..109].copy_from_slice(&256u32.to_be_bytes());
        assert_eq!(
            Entry::from_wire(&says_less),
            Err(WireError::Length {
                said: 493,
                given: 749,
            })
        );
        // And cut to what its length says, it is read, and is no entry
        // that anyone signed.
        let cut = Entry::from_wire(&says_less[..493]).unwrap();
        assert!(cut.check().is_err());
    }

    /// A content is a power of two from 256 bytes to 64 KB. A length that
    /// says another size is refused, also where that many bytes follow.
    #[test]
    fn a_content_of_a_size_that_is_not_allowed_is_refused() {
        for size in [0usize, 1, 128, 255, 257, 384, 1000, 65_535, 65_537, 131_072] {
            let mut entry = made();
            entry.content = vec![0x5a; size];
            let bytes = entry.to_wire();
            assert_eq!(bytes.len(), 237 + size);
            assert_eq!(
                Entry::from_wire(&bytes),
                Err(WireError::ContentSize(size)),
                "{size}"
            );
        }
        // A length that the bytes could never hold is refused as a size,
        // before anything is read by it.
        for said in [u32::MAX, 1 << 31, 0] {
            assert_eq!(
                Entry::from_wire(&saying_length(said)),
                Err(WireError::ContentSize(said as usize))
            );
        }
        // The control: each allowed size is read.
        for size in [256usize, 512, 4096, 65_536] {
            let mut entry = made();
            entry.content = vec![0x5a; size];
            assert_eq!(Entry::from_wire(&entry.to_wire()), Ok(entry), "{size}");
        }
    }

    /// A delete is written as 1 and anything else as 0. No other byte is
    /// read as either, or one entry would have many forms.
    #[test]
    fn a_delete_that_is_neither_0_nor_1_is_refused() {
        let bytes = made().to_wire();
        for byte in [2u8, 3, 0x80, 0xff] {
            let mut changed = bytes.clone();
            changed[104] = byte;
            assert_eq!(Entry::from_wire(&changed), Err(WireError::Delete(byte)));
        }
        let mut deleted = bytes.clone();
        deleted[104] = 1;
        assert!(Entry::from_wire(&deleted).unwrap().delete);
        assert!(!Entry::from_wire(&bytes).unwrap().delete);
    }

    #[test]
    fn a_revision_that_no_entry_has_is_refused() {
        for rev in [0, MAX_REV + 1, 1 << 53, u64::MAX] {
            let mut entry = made();
            entry.rev = rev;
            assert_eq!(
                Entry::from_wire(&entry.to_wire()),
                Err(WireError::Revision(rev)),
                "{rev}"
            );
        }
        for rev in [1, 2, MAX_REV] {
            let mut entry = made();
            entry.rev = rev;
            assert_eq!(Entry::from_wire(&entry.to_wire()).unwrap().rev, rev);
        }
    }

    /// No two byte strings are read as one entry: with any one bit of an
    /// entry's bytes changed, what is read, if anything is, is written
    /// again as the changed bytes, and is another entry.
    #[test]
    fn an_entry_has_one_form_on_the_wire() {
        let entry = made();
        let bytes = entry.to_wire();
        let mut read = 0;
        for place in 0..bytes.len() {
            for bit in [0x01u8, 0x80] {
                let mut changed = bytes.clone();
                changed[place] ^= bit;
                if let Ok(other) = Entry::from_wire(&changed) {
                    assert_eq!(other.to_wire(), changed, "{place}");
                    assert_ne!(other, entry, "{place}");
                    read += 1;
                }
            }
        }
        // All but twelve are read as some entry. Not read: a change to
        // the length (eight), one that takes the revision over its bound
        // (three), and one that makes the delete neither 0 nor 1.
        assert_eq!(read, 2 * 493 - 12);
    }
}
