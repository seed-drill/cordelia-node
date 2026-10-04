//! The record of an addition: one device's word that it added another
//! (decision 2026-10-04 §6).
//!
//! A device is added by a device that is in, with no phrase. The device
//! that adds says so in a record: the new device's key, the label the
//! person knows it by, the time, and the statement the record is made
//! under. It signs the record as itself, under a label of its own, hands
//! it to the new device, and writes it where every other device sees it.
//!
//! A record counts only under the statement it names. Whether its signer
//! may add, and whether there is room for one device more, is for the
//! device that reads it to say: a record says only who added whom.
//!
//! ## Canonical form
//!
//! The fields in a fixed order. A number is eight bytes and a length is
//! two, the higher byte first.
//!
//! ```text
//! key        32                  the new device's
//! label      its length, then the label
//! time       8                   when it was added, in seconds, in UTC
//! statement  number 8, hash 16   the statement it is made under
//! adder      32                  the device that adds, which signs
//! ```
//!
//! The adder's key is part of what is signed, so that a record can be
//! checked wherever it is found, and says who added. A signed record is
//! this form and then the signature's 64 bytes.
//!
//! Decoding refuses anything else: a record that ends early, bytes after
//! its end, a label that a statement could not carry, a key that is no
//! usable public key, a device that adds itself.

use cordelia_core::protocol::{LABEL_ADDITION, MAX_DEVICE_LABEL_BYTES, MAX_STATEMENT_NUMBER};

use crate::identity::{NodeIdentity, is_usable_public_key, verify_signature};
use crate::statement::{Device, Link, Reader, Statement, StatementError, put_count};

/// Why bytes are not a record of an addition, or why one was not made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdditionError {
    #[error("the record ends before it is whole")]
    Truncated,

    #[error("there are bytes after the record's end")]
    TrailingBytes,

    #[error("the new device's label is not one a statement may carry: {0}")]
    Label(StatementError),

    #[error("the new device's key is not a usable public key")]
    KeyNotUsable,

    #[error("a device does not add itself")]
    AddsItself,

    #[error("a record is made under a statement numbered from 1 to 256, and this is {0}")]
    Number(u64),

    #[error("the key given to sign with is not the key of the device that adds")]
    NotTheAdder,

    #[error("the key of the device that adds is not a usable public key")]
    AdderKeyNotUsable,

    #[error("the record is not signed by the device that adds")]
    Signature,

    #[error("the statement the record would be made under is no statement: {0}")]
    Statement(StatementError),
}

/// One record of an addition (decision 2026-10-04 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addition {
    /// The new device: its key, and the label the device that adds calls
    /// it by. The label is checked as a statement's is: it is what the next
    /// statement lists the device under.
    pub device: Device,
    /// When it was added, by the clock of the device that adds: seconds,
    /// in UTC.
    pub at: u64,
    /// The statement it is made under, by its number and its hash. A
    /// record counts under that statement and no other.
    pub under: Link,
    /// The key of the device that adds, which signs the record.
    pub adder: [u8; 32],
}

/// A record with the signature of the device that adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAddition {
    pub addition: Addition,
    pub signature: [u8; 64],
}

impl Addition {
    /// The record that the device `adder` adds `device` at `at`, under the
    /// statement `under`, which is the one the adder has applied.
    pub fn under(
        under: &Statement,
        device: Device,
        adder: [u8; 32],
        at: u64,
    ) -> Result<Self, AdditionError> {
        let addition = Self {
            device,
            at,
            under: under.link().map_err(AdditionError::Statement)?,
            adder,
        };
        addition.validate()?;
        Ok(addition)
    }

    /// Whether this is a record at all: every rule of its form.
    pub fn validate(&self) -> Result<(), AdditionError> {
        Device::new(self.device.key, &self.device.label).map_err(AdditionError::Label)?;
        if !is_usable_public_key(&self.device.key) {
            return Err(AdditionError::KeyNotUsable);
        }
        if self.device.key == self.adder {
            return Err(AdditionError::AddsItself);
        }
        if self.under.number < 1 || self.under.number > MAX_STATEMENT_NUMBER {
            return Err(AdditionError::Number(self.under.number));
        }
        Ok(())
    }

    /// The canonical form (see the module's documentation). A record that
    /// is not valid has none.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AdditionError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.device.key);
        put_count(&mut out, self.device.label.len());
        out.extend_from_slice(self.device.label.as_bytes());
        out.extend_from_slice(&self.at.to_be_bytes());
        out.extend_from_slice(&self.under.number.to_be_bytes());
        out.extend_from_slice(&self.under.hash);
        out.extend_from_slice(&self.adder);
        Ok(out)
    }

    /// Read a record from its canonical form, and from nothing else.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdditionError> {
        let short = || AdditionError::Truncated;
        let mut reader = Reader::new(bytes);

        let key = reader.array().ok_or_else(short)?;
        // The length is checked against its bound before the label is read.
        let length = reader.count().ok_or_else(short)?;
        if length > MAX_DEVICE_LABEL_BYTES {
            return Err(AdditionError::Label(StatementError::LabelLength(length)));
        }
        let label = reader.take(length).ok_or_else(short)?;
        let label = std::str::from_utf8(label)
            .map_err(|_| AdditionError::Label(StatementError::LabelNotPrintable))?;
        let at = reader.u64().ok_or_else(short)?;
        let under = Link {
            number: reader.u64().ok_or_else(short)?,
            hash: reader.array().ok_or_else(short)?,
        };
        let adder = reader.array().ok_or_else(short)?;
        if !reader.is_empty() {
            return Err(AdditionError::TrailingBytes);
        }

        let addition = Self {
            device: Device {
                key,
                label: label.to_string(),
            },
            at,
            under,
            adder,
        };
        addition.validate()?;
        Ok(addition)
    }

    /// Sign the record as the device that adds, under the record's label.
    /// A key that is not the adder's is refused.
    pub fn sign(self, adder: &NodeIdentity) -> Result<SignedAddition, AdditionError> {
        if adder.public_key() != self.adder {
            return Err(AdditionError::NotTheAdder);
        }
        let signature = adder.sign(&under_label(&self.to_bytes()?));
        Ok(SignedAddition {
            addition: self,
            signature,
        })
    }
}

impl SignedAddition {
    /// Whether the record is one, and the device that adds signed it.
    ///
    /// An adder's key that is not a usable public key is refused: under a
    /// point of small order anyone can make a signature that is accepted.
    pub fn verify(&self) -> Result<(), AdditionError> {
        let bytes = self.addition.to_bytes()?;
        if !is_usable_public_key(&self.addition.adder) {
            return Err(AdditionError::AdderKeyNotUsable);
        }
        if !verify_signature(&self.addition.adder, &under_label(&bytes), &self.signature) {
            return Err(AdditionError::Signature);
        }
        Ok(())
    }

    /// The record's canonical form, and then its signature.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AdditionError> {
        let mut out = self.addition.to_bytes()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Read a signed record. The signature is not checked here:
    /// [`SignedAddition::verify`] checks it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdditionError> {
        let Some(split) = bytes.len().checked_sub(64) else {
            return Err(AdditionError::Truncated);
        };
        let (addition, signature) = bytes.split_at(split);
        let mut signed = Self {
            addition: Addition::from_bytes(addition)?,
            signature: [0u8; 64],
        };
        signed.signature.copy_from_slice(signature);
        Ok(signed)
    }
}

/// What the device that adds signs: the record's label, and its canonical
/// form.
fn under_label(bytes: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(LABEL_ADDITION.len() + bytes.len());
    signed.extend_from_slice(LABEL_ADDITION);
    signed.extend_from_slice(bytes);
    signed
}

/// What the tests of this module and of the hand-over are made from.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::statement::testing::{device, identity, key};

    /// The record that device `adder` adds device `new` under `statement`,
    /// signed by the adder.
    pub(crate) fn added(statement: &Statement, adder: u16, new: u16) -> SignedAddition {
        Addition::under(statement, device(new), key(adder), 1_800_000_000)
            .unwrap()
            .sign(&identity(adder))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::statement::testing::*;
    use cordelia_core::protocol::MAX_ADDITION_BYTES;

    /// The record that device 0 adds device 7, under statement 1 of the
    /// phrase.
    fn sample() -> Addition {
        Addition::under(&first(&phrase()), device(7), key(0), 1_800_000_000).unwrap()
    }

    /// A record's form written field by field, so that a form that is not
    /// a record's can be written too.
    #[derive(Clone)]
    struct Raw {
        key: [u8; 32],
        label: Vec<u8>,
        at: u64,
        number: u64,
        hash: [u8; 16],
        adder: [u8; 32],
    }

    impl Raw {
        fn of(addition: &Addition) -> Self {
            Self {
                key: addition.device.key,
                label: addition.device.label.clone().into_bytes(),
                at: addition.at,
                number: addition.under.number,
                hash: addition.under.hash,
                adder: addition.adder,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&self.key);
            out.extend_from_slice(&(self.label.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.label);
            out.extend_from_slice(&self.at.to_be_bytes());
            out.extend_from_slice(&self.number.to_be_bytes());
            out.extend_from_slice(&self.hash);
            out.extend_from_slice(&self.adder);
            out
        }
    }

    #[test]
    fn a_record_has_one_canonical_form() {
        let addition = sample();
        let statement = first(&phrase());
        assert_eq!(addition.under.number, 1);
        assert_eq!(addition.under.hash, statement.hash().unwrap());

        // Field by field, as the module's documentation lays it out.
        let bytes = addition.to_bytes().unwrap();
        let mut expected = key(7).to_vec();
        expected.extend_from_slice(&[0, 8]);
        expected.extend_from_slice(b"device 7");
        expected.extend_from_slice(&1_800_000_000u64.to_be_bytes());
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&statement.hash().unwrap());
        expected.extend_from_slice(&key(0));
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 32 + 2 + 8 + 8 + 8 + 16 + 32);
        assert_eq!(Raw::of(&addition).bytes(), bytes);

        // It reads back as it was, and is written again as it was read.
        let read = Addition::from_bytes(&bytes).unwrap();
        assert_eq!(read, addition);
        assert_eq!(read.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn a_record_that_ends_early_or_goes_on_is_refused() {
        let bytes = sample().to_bytes().unwrap();
        for length in 0..bytes.len() {
            assert_eq!(
                Addition::from_bytes(&bytes[..length]),
                Err(AdditionError::Truncated),
                "{length}"
            );
        }
        for extra in [vec![0u8], vec![0xff], vec![0; 64]] {
            let mut longer = bytes.clone();
            longer.extend_from_slice(&extra);
            assert_eq!(
                Addition::from_bytes(&longer),
                Err(AdditionError::TrailingBytes)
            );
        }
    }

    /// The label is checked as a statement's label is: 1 to 64 bytes of
    /// printable ASCII, with no space at either end, kept as it was given.
    #[test]
    fn a_records_label_is_checked_as_a_statements_is() {
        let raw = Raw::of(&sample());
        let with = |label: &[u8]| {
            Addition::from_bytes(
                &Raw {
                    label: label.to_vec(),
                    ..raw.clone()
                }
                .bytes(),
            )
        };
        for kept in [&b"Kitchen laptop"[..], b"x", &[b'x'; 64]] {
            let read = with(kept).unwrap();
            assert_eq!(read.device.label.as_bytes(), kept);
        }
        assert_eq!(
            with(b""),
            Err(AdditionError::Label(StatementError::LabelLength(0)))
        );
        // A label over the bound is refused where its length is read,
        // before the label is: the bytes end long before it would.
        assert_eq!(
            with(&[b'x'; 65]),
            Err(AdditionError::Label(StatementError::LabelLength(65)))
        );
        let mut claims = raw.bytes();
        claims[32..34].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            Addition::from_bytes(&claims),
            Err(AdditionError::Label(StatementError::LabelLength(65_535)))
        );
        for not_printable in [
            &b"lap\ntop"[..],
            b"lap\x7ftop",
            "läptop".as_bytes(),
            b"\xff",
        ] {
            assert_eq!(
                with(not_printable),
                Err(AdditionError::Label(StatementError::LabelNotPrintable)),
                "{not_printable:?}"
            );
        }
        for spaced in [&b" laptop"[..], b"laptop ", b" "] {
            assert_eq!(
                with(spaced),
                Err(AdditionError::Label(StatementError::LabelSpaceAtAnEnd))
            );
        }

        // And where one is made: the same label is refused, not changed.
        let made = Addition {
            device: Device {
                key: key(7),
                label: " laptop".to_string(),
            },
            ..sample()
        };
        assert_eq!(
            made.validate(),
            Err(AdditionError::Label(StatementError::LabelSpaceAtAnEnd))
        );
        assert_eq!(
            made.to_bytes(),
            Err(AdditionError::Label(StatementError::LabelSpaceAtAnEnd))
        );
        assert!(Device::new(key(7), " laptop").is_err());
    }

    #[test]
    fn a_record_that_adds_no_device_is_refused() {
        let raw = Raw::of(&sample());
        // A key that anyone can sign for, and that nothing can be sealed
        // to: the point of order one.
        let mut small = [0u8; 32];
        small[0] = 1;
        assert_eq!(
            Addition::from_bytes(
                &Raw {
                    key: small,
                    ..raw.clone()
                }
                .bytes()
            ),
            Err(AdditionError::KeyNotUsable)
        );
        // A device that adds itself.
        assert_eq!(
            Addition::from_bytes(
                &Raw {
                    adder: key(7),
                    ..raw.clone()
                }
                .bytes()
            ),
            Err(AdditionError::AddsItself)
        );
        assert_eq!(
            Addition::under(&first(&phrase()), device(0), key(0), 1).unwrap_err(),
            AdditionError::AddsItself
        );
        // A number that no statement has.
        for number in [0, 257, u64::MAX] {
            assert_eq!(
                Addition::from_bytes(
                    &Raw {
                        number,
                        ..raw.clone()
                    }
                    .bytes()
                ),
                Err(AdditionError::Number(number))
            );
        }
        for number in [1, 256] {
            let read = Addition::from_bytes(
                &Raw {
                    number,
                    ..raw.clone()
                }
                .bytes(),
            );
            assert_eq!(read.unwrap().under.number, number);
        }
    }

    #[test]
    fn a_record_is_signed_by_the_device_that_adds_under_its_label() {
        let addition = sample();
        let bytes = addition.to_bytes().unwrap();
        let signed = addition.clone().sign(&identity(0)).unwrap();
        assert_eq!(signed.verify(), Ok(()));

        // What is signed is the label and the form, and nothing else.
        let mut labelled = b"cordelia v2 addition".to_vec();
        labelled.extend_from_slice(&bytes);
        assert!(verify_signature(&key(0), &labelled, &signed.signature));
        assert!(!verify_signature(&key(0), &bytes, &signed.signature));
        // A signature over the same bytes under a statement's label is not
        // a record's.
        let mut as_statement = b"cordelia v2 statement".to_vec();
        as_statement.extend_from_slice(&bytes);
        let other = SignedAddition {
            addition: addition.clone(),
            signature: identity(0).sign(&as_statement),
        };
        assert_eq!(other.verify(), Err(AdditionError::Signature));

        // Only the adder's key signs it.
        assert_eq!(
            addition.clone().sign(&identity(7)).unwrap_err(),
            AdditionError::NotTheAdder
        );
        assert_eq!(
            addition.sign(&identity(1)).unwrap_err(),
            AdditionError::NotTheAdder
        );
    }

    /// Each field is under the signature: a record changed after it was
    /// signed does not verify, and nor does one that names another adder.
    #[test]
    fn a_record_changed_after_it_was_signed_does_not_verify() {
        let signed = added(&first(&phrase()), 0, 7);
        assert_eq!(signed.verify(), Ok(()));

        let changes: [fn(&mut Addition); 6] = [
            |a| a.device.key = key(8),
            |a| a.device.label = "device 8".to_string(),
            |a| a.at += 1,
            |a| a.under.number = 2,
            |a| a.under.hash[0] ^= 1,
            // Another device is said to have added.
            |a| a.adder = key(1),
        ];
        for (place, change) in changes.iter().enumerate() {
            let mut other = signed.clone();
            change(&mut other.addition);
            assert_eq!(other.verify(), Err(AdditionError::Signature), "{place}");
        }
        let mut other = signed.clone();
        other.signature[0] ^= 1;
        assert_eq!(other.verify(), Err(AdditionError::Signature));
        let mut other = signed.clone();
        other.signature = [0u8; 64];
        assert_eq!(other.verify(), Err(AdditionError::Signature));

        // An adder's key that anyone can sign for is refused before any
        // signature is looked at.
        let mut small = [0u8; 32];
        small[0] = 1;
        let mut other = signed;
        other.addition.adder = small;
        assert_eq!(other.verify(), Err(AdditionError::AdderKeyNotUsable));
    }

    #[test]
    fn a_signed_record_is_its_form_and_then_its_signature() {
        let signed = added(&first(&phrase()), 0, 7);
        let bytes = signed.to_bytes().unwrap();
        let form = signed.addition.to_bytes().unwrap();
        assert_eq!(bytes.len(), form.len() + 64);
        assert_eq!(bytes[..form.len()], form);
        assert_eq!(bytes[form.len()..], signed.signature);

        let read = SignedAddition::from_bytes(&bytes).unwrap();
        assert_eq!(read, signed);
        assert_eq!(read.verify(), Ok(()));

        for length in [0, 1, 63] {
            assert_eq!(
                SignedAddition::from_bytes(&bytes[..length]),
                Err(AdditionError::Truncated)
            );
        }
        assert_eq!(
            SignedAddition::from_bytes(&bytes[..bytes.len() - 1]),
            Err(AdditionError::Truncated)
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            SignedAddition::from_bytes(&longer),
            Err(AdditionError::TrailingBytes)
        );
        // Reading checks no signature: one that was changed reads, and
        // does not verify.
        let mut changed = bytes;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        let read = SignedAddition::from_bytes(&changed).unwrap();
        assert_eq!(read.verify(), Err(AdditionError::Signature));
    }

    #[test]
    fn a_record_at_its_bound_is_as_large_as_the_bound_says() {
        let longest = Device::new(key(7), &"x".repeat(64)).unwrap();
        let signed = Addition::under(&first(&phrase()), longest, key(0), u64::MAX)
            .unwrap()
            .sign(&identity(0))
            .unwrap();
        assert_eq!(signed.to_bytes().unwrap().len(), MAX_ADDITION_BYTES);
        assert_eq!(MAX_ADDITION_BYTES, 226);
    }

    /// A record names the statement it is made under by that statement's
    /// own number and hash: a record under one statement is not a record
    /// under the next.
    #[test]
    fn a_record_names_the_statement_it_is_made_under() {
        let one = first(&phrase());
        let two = one.next(key(0), &secret(2), devices(&[0, 1]), &[]).unwrap();
        let under_one = added(&one, 0, 7);
        let under_two = added(&two, 0, 7);
        assert_eq!(under_one.addition.under, one.link().unwrap());
        assert_eq!(under_two.addition.under, two.link().unwrap());
        assert_ne!(under_one.addition.under, under_two.addition.under);
        assert_ne!(under_one.signature, under_two.signature);

        // A statement that is none gives no record.
        let mut not_one = one;
        not_one.number = 0;
        assert_eq!(
            Addition::under(&not_one, device(7), key(0), 1).unwrap_err(),
            AdditionError::Statement(StatementError::Number(0))
        );
    }
}
