//! The change entry: how a statement reaches a device (decision 2026-10-04
//! §4.6, §9).
//!
//! Each statement is published as one entry in the phrase's channel. This
//! module makes and opens that entry's content, which is always 32 KB. It
//! has two parts. Each is sealed with AES-256-GCM under a key of its own,
//! and bound to the statement's number and the phrase's public key, so
//! that a part is no part of another entry.
//!
//! - **For the devices**, under the statement key, which every device that
//!   follows the phrase holds: the statement, and, for each device it
//!   lists and in that order, the new secret sealed to that device's key
//!   as the node seals to a key ([`crate::ecies`]). So every device that
//!   follows the phrase can read the statement, and only a device it lists
//!   can open the secret.
//! - **For the phrase**, under a key that only the phrase gives: the new
//!   secret, and the secrets of the generations before it, as many as
//!   eight, the newest first, each with its statement's number. Nothing
//!   else.
//!
//! ## Layout
//!
//! ```text
//! the part for the devices   28672 bytes: nonce 12, ciphertext, tag 16
//! the part for the phrase     4096 bytes: nonce 12, ciphertext, tag 16
//! ```
//!
//! Each part is one size whatever it says: what it says is filled up with
//! zeros inside the encryption. So a relay holds 32 KB that say nothing,
//! not even how many devices there are. What a part says, with a count or
//! a length as two bytes and a number as eight, the higher byte first:
//!
//! ```text
//! for the devices   the signed statement's length, the signed statement,
//!                   a count, and for each device the sealed secret (92)
//! for the phrase    the secret (32), a count, and for each earlier
//!                   generation its number and its secret (32)
//! ```
//!
//! Building refuses what does not fit, and never cuts it. At every bound
//! together both parts fit, which `cordelia_core::protocol` checks when it
//! is compiled.

use std::fmt;

use cordelia_core::protocol::{
    CHANGE_ENTRY_BYTES, CHANGE_ENTRY_DEVICES_PART_BYTES, CHANGE_ENTRY_NAME,
    CHANGE_ENTRY_PHRASE_PART_BYTES, ITEM_SEAL_OVERHEAD_BYTES, LABEL_CHANGE_DEVICES,
    LABEL_CHANGE_PHRASE, MAX_EARLIER_SECRETS, SEALED_SECRET_BYTES,
};

use crate::aes_gcm::{item_decrypt, item_encrypt};
use crate::ecies::{EciesEnvelope, ecies_decrypt, ecies_encrypt};
use crate::identity::{NodeIdentity, x25519_pub_from_ed25519_pub};
use crate::statement::{Reader, SignedStatement, StatementError, put_count};

/// Why a change entry's content was not made, or not opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChangeEntryError {
    #[error("a change entry's content is 32768 bytes, and this is {0}")]
    Size(usize),

    #[error("a part of the change entry would say {needed} bytes, and has room for {room}")]
    DoesNotFit { needed: usize, room: usize },

    #[error("the part did not open: it is not under this key, or not of this entry")]
    DidNotOpen,

    #[error("what the part says is not in its form")]
    Malformed,

    #[error("the entry is for statement {entry}, and the statement in it is number {statement}")]
    Number { entry: u64, statement: u64 },

    #[error("the statement in the entry is under another phrase")]
    AnotherPhrase,

    #[error("the secret is not the one that the statement commits to")]
    SecretNotCommitted,

    #[error("the part for the phrase holds at most 8 earlier secrets, and this holds {0}")]
    TooManyEarlier(usize),

    #[error(
        "the earlier secrets are the newest first, each of a statement before this one, none twice"
    )]
    EarlierOrder,

    #[error("device {0} of the statement has a key that nothing can be sealed to")]
    DeviceKey(usize),

    #[error(transparent)]
    Statement(#[from] StatementError),

    #[error("sealing failed: {0}")]
    Crypto(String),
}

/// The secret of a generation before the entry's own, with the number of
/// its statement. Two generations have one number where two changes were
/// made apart.
#[derive(Clone, PartialEq, Eq)]
pub struct Earlier {
    pub number: u64,
    pub secret: [u8; 32],
}

/// What the part of a change entry for the phrase says (decision
/// 2026-10-04 §4.6, §9).
#[derive(Clone, PartialEq, Eq)]
pub struct ForPhrase {
    /// The statement's secret.
    pub secret: [u8; 32],
    /// The secrets of the generations before it, as many as eight, the
    /// newest first. They are for what the relays hold in a generation
    /// that was left and that nobody carried.
    pub earlier: Vec<Earlier>,
}

/// What a device reads in a change entry: the statement, which the phrase
/// signed, and what became of the secret sealed to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForDevice {
    pub statement: SignedStatement,
    pub secret: DeviceSecret,
}

/// What became of the secret that a change entry seals to a device.
#[derive(Clone, PartialEq, Eq)]
pub enum DeviceSecret {
    /// The statement lists the device, and the secret sealed to it opened
    /// to the statement's commitment (decision 2026-10-04 §4.2, rule 4).
    Opened([u8; 32]),
    /// The statement lists the device, and the secret that comes with it
    /// does not open, is not the one the statement commits to, or is not
    /// there. That is a fault in how the change was made (decision
    /// 2026-10-04 §4.5).
    DidNotOpen,
    /// The statement does not list the device: nothing is sealed to it.
    NotListed,
}

impl ForPhrase {
    /// What the part says in the entry of a first statement: its secret,
    /// and nothing before it.
    pub fn first(secret: [u8; 32]) -> Self {
        Self {
            secret,
            earlier: Vec::new(),
        }
    }

    /// What the part says in the entry of a statement made after others:
    /// its `secret`, and the secrets copied forward from the entries
    /// `before` it, each given with its statement's number (decision
    /// 2026-10-04 §9).
    ///
    /// One entry before for a statement made after one, and two for a
    /// settlement, which passes on the secrets of both branches. They are
    /// kept the newest first, each once, and only as many as eight. So a
    /// maker that never held a generation's secret passes it on all the
    /// same: it is read from the entry, with the phrase.
    pub fn following(secret: [u8; 32], before: &[(u64, &ForPhrase)]) -> Self {
        let mut earlier = Vec::new();
        for (number, entry) in before {
            earlier.push(Earlier {
                number: *number,
                secret: entry.secret,
            });
            earlier.extend(entry.earlier.iter().cloned());
        }
        earlier.sort_unstable_by(|a, b| by_age(b, a));
        earlier.dedup();
        earlier.truncate(MAX_EARLIER_SECRETS);
        Self { secret, earlier }
    }

    /// Whether this is what the part may say in the entry of statement
    /// `number`.
    pub fn validate(&self, number: u64) -> Result<(), ChangeEntryError> {
        if self.earlier.len() > MAX_EARLIER_SECRETS {
            return Err(ChangeEntryError::TooManyEarlier(self.earlier.len()));
        }
        let before_this = self
            .earlier
            .iter()
            .all(|earlier| earlier.number >= 1 && earlier.number < number);
        let in_order = self
            .earlier
            .windows(2)
            .all(|pair| by_age(&pair[0], &pair[1]).is_gt());
        if !before_this || !in_order {
            return Err(ChangeEntryError::EarlierOrder);
        }
        Ok(())
    }

    /// What the part says, as bytes.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.secret);
        put_count(&mut out, self.earlier.len());
        for earlier in &self.earlier {
            out.extend_from_slice(&earlier.number.to_be_bytes());
            out.extend_from_slice(&earlier.secret);
        }
        out
    }

    /// Read what the part says: its bytes, and then nothing but the zeros
    /// that fill the part.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ChangeEntryError> {
        let short = || ChangeEntryError::Malformed;
        let mut reader = Reader::new(bytes);
        let secret = reader.array().ok_or_else(short)?;

        let count = reader.count().ok_or_else(short)?;
        if count > MAX_EARLIER_SECRETS {
            return Err(ChangeEntryError::TooManyEarlier(count));
        }
        let mut earlier = Vec::with_capacity(count);
        for _ in 0..count {
            earlier.push(Earlier {
                number: reader.u64().ok_or_else(short)?,
                secret: reader.array().ok_or_else(short)?,
            });
        }

        if !only_zeros(reader.rest()) {
            return Err(ChangeEntryError::Malformed);
        }
        Ok(Self { secret, earlier })
    }
}

/// Make the content of the change entry of `statement`: exactly 32 KB.
///
/// `for_phrase` is what the part for the phrase says, and its secret is
/// the one sealed to each device that the statement lists. `statement_key`
/// and `seal_key` are the phrase's
/// ([`crate::phrase::Phrase::statement_key`],
/// [`crate::phrase::Phrase::seal_key`]).
///
/// Refused: a statement that its phrase's key did not sign; a secret that
/// the statement does not commit to; a device key that nothing can be
/// sealed to; and anything that would not fit. Nothing is ever left out to
/// make it fit.
pub fn build(
    statement: &SignedStatement,
    for_phrase: &ForPhrase,
    statement_key: &[u8; 32],
    seal_key: &[u8; 32],
) -> Result<Vec<u8>, ChangeEntryError> {
    statement.verify()?;
    let number = statement.statement.number;
    let phrase_key = &statement.statement.phrase_key;
    if !statement.statement.commits_to(&for_phrase.secret) {
        return Err(ChangeEntryError::SecretNotCommitted);
    }
    for_phrase.validate(number)?;

    let signed = statement.to_bytes()?;
    let mut said = Vec::new();
    put_count(&mut said, signed.len());
    said.extend_from_slice(&signed);
    put_count(&mut said, statement.statement.devices.len());
    for (place, device) in statement.statement.devices.iter().enumerate() {
        let to =
            x25519_pub_from_ed25519_pub(&device.key).ok_or(ChangeEntryError::DeviceKey(place))?;
        let sealed = ecies_encrypt(&to, &for_phrase.secret).map_err(crypto)?;
        said.extend_from_slice(&sealed.to_bytes());
    }

    let mut content = sealed_part(
        &said,
        CHANGE_ENTRY_DEVICES_PART_BYTES,
        statement_key,
        &bound_to(LABEL_CHANGE_DEVICES, number, phrase_key),
    )?;
    content.extend_from_slice(&sealed_part(
        &for_phrase.to_bytes(),
        CHANGE_ENTRY_PHRASE_PART_BYTES,
        seal_key,
        &bound_to(LABEL_CHANGE_PHRASE, number, phrase_key),
    )?);
    Ok(content)
}

/// The change entry of `statement`, as the entry of the phrase's channel
/// that carries it (decision 2026-10-04 §2.2, §4.6): its content is what
/// [`build`] makes, its author is the phrase's key, and its revision is
/// the statement's number. It is signed by the phrase's key and by the
/// key of the phrase's channel, as every entry is by its author and its
/// channel, so only what was given the phrase can make one.
///
/// The channel holds this one entry, in the slot of one name
/// (`CHANGE_ENTRY_NAME`): each statement's entry takes the place of the
/// one before it.
///
/// Refused: a statement under another phrase than `phrase`, and whatever
/// [`build`] refuses.
pub fn entry_of(
    phrase: &crate::phrase::Phrase,
    statement: &SignedStatement,
    for_phrase: &ForPhrase,
) -> Result<crate::entry::Entry, ChangeEntryError> {
    let author = phrase.signing_key().map_err(crypto)?;
    if statement.statement.phrase_key != author.public_key() {
        return Err(ChangeEntryError::AnotherPhrase);
    }
    let content = build(
        statement,
        for_phrase,
        &phrase.statement_key().map_err(crypto)?,
        &phrase.seal_key().map_err(crypto)?,
    )?;
    let channel = phrase.channel_secret().map_err(crypto)?;
    let channel_key = crate::derive::signing_key(&channel).map_err(crypto)?;
    let slot_key = crate::derive::slot_key(&channel).map_err(crypto)?;
    Ok(crate::entry::signed(
        &channel_key,
        &author,
        crate::slots::slot_id(&slot_key, CHANGE_ENTRY_NAME),
        statement.statement.number,
        false,
        content,
    ))
}

/// Open the part of a change entry for the devices as far as its
/// statement, which every device that follows the phrase can read, however
/// far behind it is.
///
/// `number` is the entry's revision and `phrase_key` its author, which is
/// the key the device follows. The statement that is returned is under
/// that phrase, has that number, and was signed by that key.
pub fn open_statement(
    content: &[u8],
    number: u64,
    phrase_key: &[u8; 32],
    statement_key: &[u8; 32],
) -> Result<SignedStatement, ChangeEntryError> {
    Ok(open_devices_part(content, number, phrase_key, statement_key)?.0)
}

/// Open a change entry as the device `device`: the statement, and the
/// secret where the statement lists the device and what was sealed to it
/// opens to the statement's commitment.
///
/// A fault in what comes with the statement is no error here: the
/// statement was read, and a device that it lists is told that its secret
/// did not open ([`DeviceSecret::DidNotOpen`]). What the statement is to
/// the device is [`crate::statement::judge`]'s to say.
pub fn open_for_device(
    content: &[u8],
    number: u64,
    phrase_key: &[u8; 32],
    statement_key: &[u8; 32],
    device: &NodeIdentity,
) -> Result<ForDevice, ChangeEntryError> {
    let (statement, sealed) = open_devices_part(content, number, phrase_key, statement_key)?;
    let listed = &statement.statement.devices;
    let own = device.public_key();
    let secret = match listed.iter().position(|one| one.key == own) {
        None => DeviceSecret::NotListed,
        Some(place) => {
            let opened = sealed_secrets(&sealed, listed.len())
                .and_then(|sealed| open_sealed(&sealed[place], device));
            match opened {
                Some(secret) if statement.statement.commits_to(&secret) => {
                    DeviceSecret::Opened(secret)
                }
                _ => DeviceSecret::DidNotOpen,
            }
        }
    };
    Ok(ForDevice { statement, secret })
}

/// Open the part of a change entry that is for the phrase, with the key
/// that only the phrase gives.
pub fn open_for_phrase(
    content: &[u8],
    number: u64,
    phrase_key: &[u8; 32],
    seal_key: &[u8; 32],
) -> Result<ForPhrase, ChangeEntryError> {
    let (_, part) = parts(content)?;
    let said = open_part(
        part,
        seal_key,
        &bound_to(LABEL_CHANGE_PHRASE, number, phrase_key),
    )?;
    let for_phrase = ForPhrase::from_bytes(&said)?;
    for_phrase.validate(number)?;
    Ok(for_phrase)
}

/// The statement of the part for the devices, checked, and what the part
/// says after it.
fn open_devices_part(
    content: &[u8],
    number: u64,
    phrase_key: &[u8; 32],
    statement_key: &[u8; 32],
) -> Result<(SignedStatement, Vec<u8>), ChangeEntryError> {
    let (part, _) = parts(content)?;
    let said = open_part(
        part,
        statement_key,
        &bound_to(LABEL_CHANGE_DEVICES, number, phrase_key),
    )?;
    let mut reader = Reader::new(&said);
    let length = reader.count().ok_or(ChangeEntryError::Malformed)?;
    let signed = reader.take(length).ok_or(ChangeEntryError::Malformed)?;
    let statement = SignedStatement::from_bytes(signed)?;
    // The part is bound to the entry's number and phrase. So is what it
    // says: the statement of another phrase, or of another number, is not
    // this entry's, whoever sealed it here.
    if statement.statement.phrase_key != *phrase_key {
        return Err(ChangeEntryError::AnotherPhrase);
    }
    statement.verify()?;
    if statement.statement.number != number {
        return Err(ChangeEntryError::Number {
            entry: number,
            statement: statement.statement.number,
        });
    }
    Ok((statement, reader.rest().to_vec()))
}

/// The secrets sealed to a statement's devices, one for each and in their
/// order. `None` where the part does not say exactly that after its
/// statement: a count that is not the number of devices, or anything after
/// the list but the zeros that fill the part.
fn sealed_secrets(said: &[u8], devices: usize) -> Option<Vec<[u8; SEALED_SECRET_BYTES]>> {
    let mut reader = Reader::new(said);
    if reader.count()? != devices {
        return None;
    }
    let mut sealed = Vec::with_capacity(devices);
    for _ in 0..devices {
        sealed.push(reader.array()?);
    }
    only_zeros(reader.rest()).then_some(sealed)
}

/// Open a secret that was sealed to `device`'s key, as the node opens what
/// is sealed to it.
fn open_sealed(sealed: &[u8; SEALED_SECRET_BYTES], device: &NodeIdentity) -> Option<[u8; 32]> {
    let envelope = EciesEnvelope::from_bytes(sealed, 32).ok()?;
    let secret = ecies_decrypt(&device.x25519_private_key(), &envelope).ok()?;
    secret.try_into().ok()
}

/// The two parts of a change entry's content, which is of its one size.
fn parts(content: &[u8]) -> Result<(&[u8], &[u8]), ChangeEntryError> {
    if content.len() != CHANGE_ENTRY_BYTES {
        return Err(ChangeEntryError::Size(content.len()));
    }
    Ok(content.split_at(CHANGE_ENTRY_DEVICES_PART_BYTES))
}

/// Seal what a part says as a part of `size` bytes: filled up with zeros,
/// under `key`, and bound to `bound_to`. What does not fit is refused, and
/// never cut.
fn sealed_part(
    said: &[u8],
    size: usize,
    key: &[u8; 32],
    bound_to: &[u8],
) -> Result<Vec<u8>, ChangeEntryError> {
    let room = size - ITEM_SEAL_OVERHEAD_BYTES;
    if said.len() > room {
        return Err(ChangeEntryError::DoesNotFit {
            needed: said.len(),
            room,
        });
    }
    let mut filled = said.to_vec();
    filled.resize(room, 0);
    item_encrypt(key, &filled, bound_to).map_err(crypto)
}

/// Open a part: what it says, with the zeros that fill it.
fn open_part(part: &[u8], key: &[u8; 32], bound_to: &[u8]) -> Result<Vec<u8>, ChangeEntryError> {
    item_decrypt(key, part, bound_to).map_err(|_| ChangeEntryError::DidNotOpen)
}

/// What a part's encryption is bound to: the part's label, the statement's
/// number, and the phrase's public key.
fn bound_to(label: &[u8], number: u64, phrase_key: &[u8; 32]) -> Vec<u8> {
    let mut bound = Vec::with_capacity(label.len() + 8 + 32);
    bound.extend_from_slice(label);
    bound.extend_from_slice(&number.to_be_bytes());
    bound.extend_from_slice(phrase_key);
    bound
}

/// The order of the earlier secrets: by number, and by the secret where
/// two generations have one number. The greater is the newer, and the
/// newer goes first.
fn by_age(a: &Earlier, b: &Earlier) -> std::cmp::Ordering {
    (a.number, &a.secret).cmp(&(b.number, &b.secret))
}

fn only_zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn crypto(e: crate::CryptoError) -> ChangeEntryError {
    ChangeEntryError::Crypto(e.to_string())
}

// A secret is not printed for debugging: what is shown is that there is
// one, and of which statement.

impl fmt::Debug for Earlier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Earlier({})", self.number)
    }
}

impl fmt::Debug for ForPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForPhrase")
            .field("earlier", &self.earlier)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DeviceSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Opened(_) => "Opened(..)",
            Self::DidNotOpen => "DidNotOpen",
            Self::NotListed => "NotListed",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive;
    use crate::phrase::Phrase;
    use crate::statement::testing::*;
    use crate::statement::{Device, Judgement, Statement, judge};

    /// What an entry of one phrase is made and opened with.
    struct Keys {
        phrase_key: [u8; 32],
        statement_key: [u8; 32],
        seal_key: [u8; 32],
    }

    fn keys(phrase: &Phrase) -> Keys {
        Keys {
            phrase_key: phrase.public_key().unwrap(),
            statement_key: phrase.statement_key().unwrap(),
            seal_key: phrase.seal_key().unwrap(),
        }
    }

    /// The content of the entry of `statement`, as the phrase makes it.
    fn entry(phrase: &Phrase, statement: &Statement, for_phrase: &ForPhrase) -> Vec<u8> {
        let keys = keys(phrase);
        build(
            &signed(statement, phrase),
            for_phrase,
            &keys.statement_key,
            &keys.seal_key,
        )
        .unwrap()
    }

    /// Statements 1 to 5 of one phrase. Statement n commits to secret n.
    ///
    /// 2 lists devices 0, 1 and 2. 3 removes device 2. 4 is made on device
    /// 1 and adds device 3. 5 renews.
    fn statements(phrase: &Phrase) -> [Statement; 5] {
        let one = first(phrase);
        let two = one
            .next(key(0), &secret(2), devices(&[0, 1, 2]), &[])
            .unwrap();
        let three = two
            .next(key(0), &secret(3), devices(&[0, 1]), &[key(2)])
            .unwrap();
        let four = three
            .next(key(1), &secret(4), devices(&[1, 0, 3]), &[])
            .unwrap();
        let five = four
            .next(key(1), &secret(5), devices(&[1, 0, 3]), &[])
            .unwrap();
        [one, two, three, four, five]
    }

    /// What the part for the phrase says in the entry of statement
    /// `number` of [`statements`]: each entry made from the one before.
    fn for_phrase_of(number: u8) -> ForPhrase {
        let mut said = ForPhrase::first(secret(1));
        for n in 2..=number {
            said = ForPhrase::following(secret(n), &[(u64::from(n) - 1, &said)]);
        }
        said
    }

    /// The content of an entry whose part for the devices says `said`: made
    /// as an entry of statement `number` is made, but saying anything.
    fn content_saying(said: &[u8], number: u64, keys: &Keys) -> Vec<u8> {
        let mut content = sealed_part(
            said,
            CHANGE_ENTRY_DEVICES_PART_BYTES,
            &keys.statement_key,
            &bound_to(LABEL_CHANGE_DEVICES, number, &keys.phrase_key),
        )
        .unwrap();
        content.extend_from_slice(&phrase_part_saying(
            &ForPhrase::first(secret(0)).to_bytes(),
            number,
            keys,
        ));
        content
    }

    /// A part for the phrase that says `said`, for statement `number`.
    fn phrase_part_saying(said: &[u8], number: u64, keys: &Keys) -> Vec<u8> {
        sealed_part(
            said,
            CHANGE_ENTRY_PHRASE_PART_BYTES,
            &keys.seal_key,
            &bound_to(LABEL_CHANGE_PHRASE, number, &keys.phrase_key),
        )
        .unwrap()
    }

    /// What the part for the devices says: the statement behind its
    /// length, and then `after` it.
    fn statement_and(statement: &SignedStatement, after: &[u8]) -> Vec<u8> {
        let signed = statement.to_bytes().unwrap();
        let mut said = Vec::new();
        put_count(&mut said, signed.len());
        said.extend_from_slice(&signed);
        said.extend_from_slice(after);
        said
    }

    /// `secret` sealed to device `n`, as the node seals to a key.
    fn sealed_to(n: u16, secret: &[u8; 32]) -> Vec<u8> {
        let to = x25519_pub_from_ed25519_pub(&key(n)).unwrap();
        ecies_encrypt(&to, secret).unwrap().to_bytes()
    }

    /// A count, and the sealed secrets after it.
    fn counted(count: usize, sealed: &[Vec<u8>]) -> Vec<u8> {
        let mut said = Vec::new();
        put_count(&mut said, count);
        for one in sealed {
            said.extend_from_slice(one);
        }
        said
    }

    fn opened_by(content: &[u8], number: u64, keys: &Keys, n: u16) -> ForDevice {
        open_for_device(
            content,
            number,
            &keys.phrase_key,
            &keys.statement_key,
            &identity(n),
        )
        .unwrap()
    }

    // ── What an entry is ─────────────────────────────────────────────

    #[test]
    fn a_change_entry_is_always_32_kb() {
        let phrase = phrase();
        let [one, two, ..] = statements(&phrase);
        let first_entry = entry(&phrase, &one, &for_phrase_of(1));
        let second_entry = entry(&phrase, &two, &for_phrase_of(2));
        assert_eq!(first_entry.len(), 32 * 1024);
        assert_eq!(second_entry.len(), first_entry.len());
        assert_eq!(
            CHANGE_ENTRY_DEVICES_PART_BYTES + CHANGE_ENTRY_PHRASE_PART_BYTES,
            first_entry.len()
        );

        // Made again, it is sealed afresh: the same size, and nothing of
        // one content is in the other.
        let again = entry(&phrase, &one, &for_phrase_of(1));
        assert_eq!(again.len(), first_entry.len());
        let same = first_entry
            .iter()
            .zip(&again)
            .filter(|(a, b)| a == b)
            .count();
        assert!(same < 400, "{same} bytes of 32768 are the same");

        // Content of any other size is no change entry.
        let keys = keys(&phrase);
        for length in [0, 1, 4096, 28_672, 32_767, 32_769, 65_536] {
            let mut other = first_entry.clone();
            other.resize(length, 0);
            assert_eq!(
                open_statement(&other, 1, &keys.phrase_key, &keys.statement_key),
                Err(ChangeEntryError::Size(length))
            );
            assert_eq!(
                open_for_phrase(&other, 1, &keys.phrase_key, &keys.seal_key),
                Err(ChangeEntryError::Size(length))
            );
        }
    }

    /// What each part says, byte by byte, before it is filled and sealed.
    #[test]
    fn each_part_says_what_its_layout_says() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [_, two, ..] = statements(&phrase);
        let content = entry(&phrase, &two, &for_phrase_of(2));
        let (devices_part, phrase_part) = parts(&content).unwrap();
        assert_eq!(devices_part.len(), 28_672);
        assert_eq!(phrase_part.len(), 4096);

        // For the devices: the statement's length, the statement with its
        // signature, a count, a sealed secret of 92 bytes for each device,
        // and zeros to the end.
        let said = open_part(
            devices_part,
            &keys.statement_key,
            &bound_to(b"cordelia v2 change devices", 2, &keys.phrase_key),
        )
        .unwrap();
        assert_eq!(said.len(), 28_672 - 12 - 16);
        let signed = signed(&two, &phrase).to_bytes().unwrap();
        let length = (signed.len() as u16).to_be_bytes();
        assert_eq!(said[..2], length);
        assert_eq!(said[2..2 + signed.len()], signed);
        let after = 2 + signed.len();
        assert_eq!(said[after..after + 2], [0, 3]);
        let end = after + 2 + 3 * 92;
        assert!(only_zeros(&said[end..]));
        assert!(!only_zeros(&said[end - 92..end]));

        // For the phrase: the secret, and a count and each earlier secret
        // behind its statement's number. Nothing else: zeros to the end.
        let said = open_part(
            phrase_part,
            &keys.seal_key,
            &bound_to(b"cordelia v2 change phrase", 2, &keys.phrase_key),
        )
        .unwrap();
        assert_eq!(said.len(), 4096 - 12 - 16);
        let mut expected = secret(2).to_vec();
        expected.extend_from_slice(&[0, 1]);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&secret(1));
        assert_eq!(said[..expected.len()], expected);
        assert!(only_zeros(&said[expected.len()..]));
        assert_eq!(for_phrase_of(2).to_bytes(), expected);
    }

    // ── Opening for a device ─────────────────────────────────────────

    #[test]
    fn a_listed_device_reads_the_statement_and_opens_the_secret() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [_, two, _, four, _] = statements(&phrase);
        let content = entry(&phrase, &two, &for_phrase_of(2));
        for n in [0, 1, 2] {
            let opened = opened_by(&content, 2, &keys, n);
            assert_eq!(opened.statement, signed(&two, &phrase));
            assert_eq!(opened.statement.verify(), Ok(()));
            assert_eq!(opened.secret, DeviceSecret::Opened(secret(2)));
        }
        assert_eq!(
            open_statement(&content, 2, &keys.phrase_key, &keys.statement_key).unwrap(),
            signed(&two, &phrase)
        );

        // The sealed secrets follow the order of the statement's devices,
        // which is their maker's: 1, 0, 3.
        let content = entry(&phrase, &four, &for_phrase_of(4));
        for n in [1, 0, 3] {
            assert_eq!(
                opened_by(&content, 4, &keys, n).secret,
                DeviceSecret::Opened(secret(4)),
                "{n}"
            );
        }
    }

    /// A device that is answered with a later entry has all it needs: the
    /// statement applies and the secret is with it, whether the device was
    /// one change behind, or two, or three.
    #[test]
    fn a_device_applies_a_later_entry_in_one_step_however_far_behind() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let all = statements(&phrase);
        let applied = &all[1];
        for (shown, number) in [(&all[2], 3u8), (&all[3], 4), (&all[4], 5)] {
            let content = entry(&phrase, shown, &for_phrase_of(number));
            for n in [0, 1] {
                let opened = opened_by(&content, u64::from(number), &keys, n);
                assert_eq!(
                    judge(&opened.statement, applied, &key(n), &keys.phrase_key),
                    Ok(Judgement::Applies),
                    "{number} on device {n}"
                );
                assert_eq!(opened.secret, DeviceSecret::Opened(secret(number)));
                assert!(opened.statement.statement.commits_to(&secret(number)));
            }
        }
        // An earlier entry shown to a device: it is read, and nothing is
        // done with it. And the entry it has applied, likewise.
        for (shown, number) in [(&all[0], 1u8), (&all[1], 2), (&all[2], 3)] {
            let content = entry(&phrase, shown, &for_phrase_of(number));
            let opened = opened_by(&content, u64::from(number), &keys, 0);
            assert_eq!(
                judge(&opened.statement, &all[2], &key(0), &keys.phrase_key),
                Ok(Judgement::Behind)
            );
        }
    }

    /// Two entries at one number: a device that has applied one and is
    /// shown the other reads both lists, and is in a fork.
    #[test]
    fn two_entries_at_one_number_are_a_fork() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [_, two, three, ..] = statements(&phrase);
        let apart = two
            .next(key(1), &secret(0xb3), devices(&[1, 2]), &[key(0)])
            .unwrap();
        let content = entry(
            &phrase,
            &apart,
            &ForPhrase::following(secret(0xb3), &[(2, &for_phrase_of(2))]),
        );
        for n in [0, 1] {
            let opened = opened_by(&content, 3, &keys, n);
            assert_eq!(
                judge(&opened.statement, &three, &key(n), &keys.phrase_key),
                Ok(Judgement::Fork)
            );
            // Both lists can be read: the one it applied, and this one.
            assert_eq!(opened.statement.statement.devices, devices(&[1, 2]));
            assert_eq!(opened.statement.statement.removed, vec![key(0)]);
        }
    }

    /// A device that the statement does not list reads that it was
    /// removed, or is in no list, and opens no secret: none is sealed to
    /// it.
    #[test]
    fn a_device_that_is_not_listed_reads_the_statement_and_no_secret() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [_, two, three, ..] = statements(&phrase);
        let content = entry(&phrase, &three, &for_phrase_of(3));

        let removed = opened_by(&content, 3, &keys, 2);
        assert_eq!(removed.secret, DeviceSecret::NotListed);
        assert_eq!(removed.statement, signed(&three, &phrase));
        assert_eq!(
            judge(&removed.statement, &two, &key(2), &keys.phrase_key),
            Ok(Judgement::Removed)
        );
        let unknown = opened_by(&content, 3, &keys, 7);
        assert_eq!(unknown.secret, DeviceSecret::NotListed);
        assert_eq!(
            judge(&unknown.statement, &two, &key(7), &keys.phrase_key),
            Ok(Judgement::NotListed)
        );

        // It holds the statement key, and still opens nothing that is
        // sealed in the entry: not with its own key, in any place.
        let (statement, after) =
            open_devices_part(&content, 3, &keys.phrase_key, &keys.statement_key).unwrap();
        let sealed = sealed_secrets(&after, statement.statement.devices.len()).unwrap();
        assert_eq!(sealed.len(), 2);
        for one in &sealed {
            assert_eq!(open_sealed(one, &identity(2)), None);
            assert_eq!(open_sealed(one, &identity(7)), None);
        }
        // The control: each opens for the device in its place.
        assert_eq!(open_sealed(&sealed[0], &identity(0)), Some(secret(3)));
        assert_eq!(open_sealed(&sealed[1], &identity(1)), Some(secret(3)));
    }

    /// A statement that lists this device, with a secret that does not
    /// open, is not the committed one, or is not there. The statement is
    /// read all the same, and the device is told that its secret did not
    /// open: a fault in how the change was made.
    #[test]
    fn a_listed_device_whose_secret_does_not_open_is_told_so() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [_, two, ..] = statements(&phrase);
        let signed_two = signed(&two, &phrase);
        let right = |n: u16| sealed_to(n, &secret(2));
        let secrets_of = |after: &[u8]| -> Vec<DeviceSecret> {
            let content = content_saying(&statement_and(&signed_two, after), 2, &keys);
            [0, 1, 2, 7]
                .iter()
                .map(|n| {
                    let opened = opened_by(&content, 2, &keys, *n);
                    assert_eq!(opened.statement, signed_two);
                    opened.secret
                })
                .collect()
        };
        let opened = DeviceSecret::Opened(secret(2));
        let not = DeviceSecret::DidNotOpen;
        let stranger = DeviceSecret::NotListed;

        // The control: made by hand as `build` makes it.
        assert_eq!(
            secrets_of(&counted(3, &[right(0), right(1), right(2)])),
            [
                opened.clone(),
                opened.clone(),
                opened.clone(),
                stranger.clone()
            ]
        );
        // In device 1's place, the secret sealed to another device.
        assert_eq!(
            secrets_of(&counted(3, &[right(0), right(2), right(2)])),
            [
                opened.clone(),
                not.clone(),
                opened.clone(),
                stranger.clone()
            ]
        );
        // In device 1's place, another secret than the statement commits
        // to: it opens, and it is not the secret.
        assert_eq!(
            secrets_of(&counted(3, &[right(0), sealed_to(1, &secret(7)), right(2)])),
            [
                opened.clone(),
                not.clone(),
                opened.clone(),
                stranger.clone()
            ]
        );
        // In device 1's place, bytes that are no sealed secret.
        assert_eq!(
            secrets_of(&counted(3, &[right(0), vec![0x55; 92], right(2)])),
            [
                opened.clone(),
                not.clone(),
                opened.clone(),
                stranger.clone()
            ]
        );
        // The secrets in another order than the devices.
        assert_eq!(
            secrets_of(&counted(3, &[right(1), right(0), right(2)])),
            [not.clone(), not.clone(), opened.clone(), stranger.clone()]
        );

        // A secret for each device but the last: where the last should
        // be, there are the zeros that fill the part.
        assert_eq!(
            secrets_of(&counted(3, &[right(0), right(1)])),
            [
                opened.clone(),
                opened.clone(),
                not.clone(),
                stranger.clone()
            ]
        );

        // Not there: nothing after the statement, or a list for fewer
        // devices than the statement has.
        let none = [not.clone(), not.clone(), not.clone(), stranger.clone()];
        assert_eq!(secrets_of(&[]), none);
        assert_eq!(secrets_of(&counted(0, &[])), none);
        assert_eq!(secrets_of(&counted(2, &[right(0), right(1)])), none);
        // A count that is not the number of devices, with a secret for
        // each device after it.
        assert_eq!(
            secrets_of(&counted(4, &[right(0), right(1), right(2)])),
            none
        );
        assert_eq!(
            secrets_of(&counted(2, &[right(0), right(1), right(2)])),
            none
        );
        // More than the list after it: a fourth secret, and one byte.
        assert_eq!(
            secrets_of(&counted(3, &[right(0), right(1), right(2), right(2)])),
            none
        );
        let mut and_a_byte = counted(3, &[right(0), right(1), right(2)]);
        and_a_byte.extend_from_slice(&[0, 0, 0, 1]);
        assert_eq!(secrets_of(&and_a_byte), none);
    }

    // ── What an entry is bound to, and who can open it ───────────────

    /// The part for the devices opens under the statement key and no
    /// other, and the part for the phrase under the key that only the
    /// phrase gives. A relay has neither, and a device has only the first.
    #[test]
    fn each_part_opens_under_its_own_key_and_no_other() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let [_, two, ..] = statements(&phrase);
        let said = for_phrase_of(2);
        let content = entry(&phrase, &two, &said);

        assert!(open_statement(&content, 2, &keys.phrase_key, &keys.statement_key).is_ok());
        assert_eq!(
            open_for_phrase(&content, 2, &keys.phrase_key, &keys.seal_key).unwrap(),
            said
        );

        // What a relay holds of the phrase's channel, what a device holds,
        // and what another phrase gives.
        let channel = phrase.channel_secret().unwrap();
        let not_the_statement_key = [
            keys.seal_key,
            keys.phrase_key,
            channel,
            derive::entry_key(&channel).unwrap(),
            derive::slot_key(&channel).unwrap(),
            derive::channel_id(&channel).unwrap(),
            other.statement_key().unwrap(),
            secret(2),
            [0u8; 32],
        ];
        for wrong in not_the_statement_key {
            assert_eq!(
                open_statement(&content, 2, &keys.phrase_key, &wrong),
                Err(ChangeEntryError::DidNotOpen)
            );
            assert_eq!(
                open_for_device(&content, 2, &keys.phrase_key, &wrong, &identity(0)),
                Err(ChangeEntryError::DidNotOpen)
            );
        }
        let not_the_seal_key = [
            keys.statement_key,
            keys.phrase_key,
            channel,
            derive::entry_key(&channel).unwrap(),
            other.seal_key().unwrap(),
            secret(2),
            identity(0).x25519_private_key(),
            [0u8; 32],
        ];
        for wrong in not_the_seal_key {
            assert_eq!(
                open_for_phrase(&content, 2, &keys.phrase_key, &wrong),
                Err(ChangeEntryError::DidNotOpen)
            );
        }

        // And nothing of what it says is in the content as it travels: no
        // device's key, no label, and not the phrase's key.
        let found = |needle: &[u8]| content.windows(needle.len()).any(|window| window == needle);
        for n in [0, 1, 2] {
            assert!(!found(&key(n)));
        }
        assert!(!found(b"device 0"));
        assert!(!found(&keys.phrase_key));
        assert!(!found(&two.commitment));
        assert!(!found(&secret(2)));
    }

    /// Each part's encryption is bound to the statement's number and the
    /// phrase's public key: a part is no part of an entry at another
    /// number, or of another phrase's.
    #[test]
    fn each_part_is_bound_to_the_number_and_the_phrases_key() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let [_, two, three, ..] = statements(&phrase);
        let content = entry(&phrase, &two, &for_phrase_of(2));

        for number in [0, 1, 3, 258, u64::MAX] {
            assert_eq!(
                open_statement(&content, number, &keys.phrase_key, &keys.statement_key),
                Err(ChangeEntryError::DidNotOpen),
                "{number}"
            );
            assert_eq!(
                open_for_phrase(&content, number, &keys.phrase_key, &keys.seal_key),
                Err(ChangeEntryError::DidNotOpen),
                "{number}"
            );
        }
        for not_the_phrase in [other.public_key().unwrap(), key(0), [0u8; 32]] {
            assert_eq!(
                open_statement(&content, 2, &not_the_phrase, &keys.statement_key),
                Err(ChangeEntryError::DidNotOpen)
            );
            assert_eq!(
                open_for_phrase(&content, 2, &not_the_phrase, &keys.seal_key),
                Err(ChangeEntryError::DidNotOpen)
            );
        }

        // The parts of two entries do not make a third: each opens only at
        // its own number.
        let next = entry(&phrase, &three, &for_phrase_of(3));
        let mut mixed = parts(&content).unwrap().0.to_vec();
        mixed.extend_from_slice(parts(&next).unwrap().1);
        assert!(open_statement(&mixed, 2, &keys.phrase_key, &keys.statement_key).is_ok());
        assert_eq!(
            open_for_phrase(&mixed, 2, &keys.phrase_key, &keys.seal_key),
            Err(ChangeEntryError::DidNotOpen)
        );
        assert_eq!(
            open_statement(&mixed, 3, &keys.phrase_key, &keys.statement_key),
            Err(ChangeEntryError::DidNotOpen)
        );
        // Nor does a part open as the other part.
        let mut swapped = vec![0u8; CHANGE_ENTRY_BYTES];
        swapped[..4096].copy_from_slice(parts(&content).unwrap().1);
        assert_eq!(
            open_statement(&swapped, 2, &keys.phrase_key, &keys.statement_key),
            Err(ChangeEntryError::DidNotOpen)
        );
    }

    /// What the part says is held to the same binding as its encryption. A
    /// statement of another number, or under another phrase, is not this
    /// entry's, though it was sealed under this entry's key and number.
    #[test]
    fn the_statement_in_an_entry_is_the_entrys_own() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let [_, _, three, ..] = statements(&phrase);
        let after = counted(2, &[sealed_to(0, &secret(3)), sealed_to(1, &secret(3))]);

        // Statement 3, in an entry that is sealed as statement 2's.
        let content = content_saying(&statement_and(&signed(&three, &phrase), &after), 2, &keys);
        let number = ChangeEntryError::Number {
            entry: 2,
            statement: 3,
        };
        assert_eq!(
            open_statement(&content, 2, &keys.phrase_key, &keys.statement_key),
            Err(number.clone())
        );
        assert_eq!(
            open_for_device(
                &content,
                2,
                &keys.phrase_key,
                &keys.statement_key,
                &identity(0)
            ),
            Err(number)
        );
        // The control: sealed as its own, it opens.
        let content = content_saying(&statement_and(&signed(&three, &phrase), &after), 3, &keys);
        assert_eq!(
            opened_by(&content, 3, &keys, 0).secret,
            DeviceSecret::Opened(secret(3))
        );

        // Another phrase's statement, well signed by that phrase.
        let theirs = signed(&first(&other), &other);
        assert_eq!(theirs.verify(), Ok(()));
        let content = content_saying(&statement_and(&theirs, &[]), 1, &keys);
        assert_eq!(
            open_statement(&content, 1, &keys.phrase_key, &keys.statement_key),
            Err(ChangeEntryError::AnotherPhrase)
        );
    }

    /// An entry whose statement another key than the phrase's signed, or
    /// whose statement is none, is refused: by a device, and where it is
    /// made.
    #[test]
    fn an_entry_whose_statement_the_phrase_did_not_sign_is_refused() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let [_, two, ..] = statements(&phrase);

        // It names this phrase, and the other phrase's key signed it.
        let mut forged = signed(&two, &phrase);
        let mut theirs = two.clone();
        theirs.phrase_key = other.public_key().unwrap();
        forged.signature = signed(&theirs, &other).signature;
        let unsigned = ChangeEntryError::Statement(StatementError::Signature);
        let content = content_saying(&statement_and(&forged, &[]), 2, &keys);
        assert_eq!(
            open_statement(&content, 2, &keys.phrase_key, &keys.statement_key),
            Err(unsigned.clone())
        );
        assert_eq!(
            open_for_device(
                &content,
                2,
                &keys.phrase_key,
                &keys.statement_key,
                &identity(0)
            ),
            Err(unsigned.clone())
        );
        // And no entry is made around it.
        assert_eq!(
            build(
                &forged,
                &for_phrase_of(2),
                &keys.statement_key,
                &keys.seal_key
            ),
            Err(unsigned)
        );

        // Bytes that are no statement, where the statement should be.
        let open = |said: &[u8]| {
            open_statement(
                &content_saying(said, 2, &keys),
                2,
                &keys.phrase_key,
                &keys.statement_key,
            )
        };
        let truncated = ChangeEntryError::Statement(StatementError::Truncated);
        assert_eq!(open(&[]), Err(truncated.clone()));
        assert_eq!(open(&counted(10, &[vec![0xab; 10]])), Err(truncated));
        let mut cut = statement_and(&signed(&two, &phrase), &[]);
        cut.truncate(cut.len() - 1);
        cut[..2].copy_from_slice(&[0xff, 0xff]);
        assert_eq!(open(&cut), Err(ChangeEntryError::Malformed));
        assert_eq!(open(&[0x70]), Err(ChangeEntryError::Malformed));
        let mut longer = signed(&two, &phrase).to_bytes().unwrap();
        longer.push(0);
        assert_eq!(
            open(&counted(longer.len(), &[longer])),
            Err(ChangeEntryError::Statement(StatementError::TrailingBytes))
        );
    }

    /// One changed bit anywhere in a part, and the part does not open. The
    /// other part is not touched by it.
    #[test]
    fn a_damaged_part_does_not_open() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [_, two, ..] = statements(&phrase);
        let said = for_phrase_of(2);
        let content = entry(&phrase, &two, &said);
        let devices_end = CHANGE_ENTRY_DEVICES_PART_BYTES;

        for at in [0, 11, 12, 1000, 20_000, devices_end - 17, devices_end - 1] {
            let mut damaged = content.clone();
            damaged[at] ^= 0x04;
            assert_eq!(
                open_statement(&damaged, 2, &keys.phrase_key, &keys.statement_key),
                Err(ChangeEntryError::DidNotOpen),
                "{at}"
            );
            assert_eq!(
                open_for_phrase(&damaged, 2, &keys.phrase_key, &keys.seal_key).unwrap(),
                said
            );
        }
        for at in [
            devices_end,
            devices_end + 12,
            devices_end + 2000,
            CHANGE_ENTRY_BYTES - 1,
        ] {
            let mut damaged = content.clone();
            damaged[at] ^= 0x04;
            assert_eq!(
                open_for_phrase(&damaged, 2, &keys.phrase_key, &keys.seal_key),
                Err(ChangeEntryError::DidNotOpen),
                "{at}"
            );
            assert_eq!(
                opened_by(&damaged, 2, &keys, 1).secret,
                DeviceSecret::Opened(secret(2))
            );
        }
    }

    // ── Making an entry ──────────────────────────────────────────────

    /// The secret in an entry is the one its statement commits to, and it
    /// is sealed to keys that can be sealed to. Anything else is a change
    /// that no device could open, and is not made.
    #[test]
    fn an_entry_is_not_made_that_no_device_could_open() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [_, two, ..] = statements(&phrase);
        let make = |statement: &Statement, said: &ForPhrase| {
            build(
                &signed(statement, &phrase),
                said,
                &keys.statement_key,
                &keys.seal_key,
            )
        };
        assert!(make(&two, &for_phrase_of(2)).is_ok());

        // Another secret than the statement commits to.
        let other_secret = ForPhrase {
            secret: secret(7),
            ..for_phrase_of(2)
        };
        assert_eq!(
            make(&two, &other_secret),
            Err(ChangeEntryError::SecretNotCommitted)
        );
        assert_eq!(
            make(&two, &for_phrase_of(1)),
            Err(ChangeEntryError::SecretNotCommitted)
        );

        // A device whose key is a point of small order: what is sealed to
        // it, anyone could open.
        let mut small = [0u8; 32];
        small[0] = 1;
        let mut listing = two.clone();
        listing.devices[1] = Device::new(small, "nobody").unwrap();
        assert_eq!(listing.validate(), Ok(()));
        assert_eq!(
            make(&listing, &for_phrase_of(2)),
            Err(ChangeEntryError::DeviceKey(1))
        );
        // A statement that is none.
        let mut not_one = signed(&two, &phrase);
        not_one.statement.removed.push(key(1));
        assert_eq!(
            build(
                &not_one,
                &for_phrase_of(2),
                &keys.statement_key,
                &keys.seal_key
            ),
            Err(ChangeEntryError::Statement(StatementError::InBothLists))
        );
    }

    /// A part that would say more than it has room for is refused, and
    /// never cut to fit.
    #[test]
    fn a_part_that_would_not_fit_is_refused_and_never_cut() {
        let key = [7u8; 32];
        for size in [
            CHANGE_ENTRY_DEVICES_PART_BYTES,
            CHANGE_ENTRY_PHRASE_PART_BYTES,
        ] {
            let room = size - 12 - 16;
            // What fills the part exactly comes back whole.
            let said: Vec<u8> = (0..room).map(|i| (i % 251) as u8 + 1).collect();
            let part = sealed_part(&said, size, &key, b"bound").unwrap();
            assert_eq!(part.len(), size);
            assert_eq!(open_part(&part, &key, b"bound").unwrap(), said);
            // And less is filled up with zeros, to the same size.
            let part = sealed_part(&said[..100], size, &key, b"bound").unwrap();
            assert_eq!(part.len(), size);
            let opened = open_part(&part, &key, b"bound").unwrap();
            assert_eq!(opened[..100], said[..100]);
            assert!(only_zeros(&opened[100..]) && opened.len() == room);

            // One byte more, and more than that.
            for over in [1, 2, 4096] {
                let mut more = said.clone();
                more.resize(room + over, 9);
                assert_eq!(
                    sealed_part(&more, size, &key, b"bound"),
                    Err(ChangeEntryError::DoesNotFit {
                        needed: room + over,
                        room
                    })
                );
            }
        }
    }

    /// At every bound together, the entry fits its 32 KB: 64 devices with
    /// labels of 64 bytes, 256 removed keys, a chain of 256, and nine
    /// secrets. Every device opens its secret, and the phrase reads its
    /// part whole.
    #[test]
    fn at_every_bound_together_the_entry_fits_its_32_kb() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let full = at_every_bound(&phrase);
        let signed_full = signed(&full, &phrase);
        let said = ForPhrase {
            secret: secret(9),
            earlier: (0..8u8)
                .map(|n| Earlier {
                    number: 255 - u64::from(n),
                    secret: secret(100 + n),
                })
                .collect(),
        };
        assert_eq!(said.earlier.len(), MAX_EARLIER_SECRETS);
        assert_eq!(said.validate(256), Ok(()));

        let content = build(&signed_full, &said, &keys.statement_key, &keys.seal_key).unwrap();
        assert_eq!(content.len(), 32_768);

        // What each part says, of the room it has.
        let statement_bytes = signed_full.to_bytes().unwrap().len();
        assert_eq!(statement_bytes, 20_784);
        let devices_say = 2 + statement_bytes + 2 + 64 * 92;
        assert_eq!(devices_say, 26_676);
        assert_eq!(CHANGE_ENTRY_DEVICES_PART_BYTES - 12 - 16, 28_644);
        let phrase_says = said.to_bytes().len();
        assert_eq!(phrase_says, 32 + 2 + 8 * 40);
        assert_eq!(phrase_says, 354);
        assert_eq!(CHANGE_ENTRY_PHRASE_PART_BYTES - 12 - 16, 4068);

        let (devices_part, _) = parts(&content).unwrap();
        let opened = open_part(
            devices_part,
            &keys.statement_key,
            &bound_to(LABEL_CHANGE_DEVICES, 256, &keys.phrase_key),
        )
        .unwrap();
        assert!(only_zeros(&opened[devices_say..]));
        assert!(!only_zeros(&opened[devices_say - 92..devices_say]));

        for n in 0..64 {
            let opened = opened_by(&content, 256, &keys, n);
            assert_eq!(opened.secret, DeviceSecret::Opened(secret(9)), "{n}");
            assert_eq!(opened.statement, signed_full);
        }
        assert_eq!(
            opened_by(&content, 256, &keys, 64).secret,
            DeviceSecret::NotListed
        );
        assert_eq!(
            open_for_phrase(&content, 256, &keys.phrase_key, &keys.seal_key).unwrap(),
            said
        );
    }

    // ── The part for the phrase ──────────────────────────────────────

    /// The part for the phrase holds the statement's secret, and the
    /// secrets of the generations before it, the newest first, each with
    /// its statement's number. Nothing else.
    #[test]
    fn the_part_for_the_phrase_holds_the_secrets_and_nothing_else() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [.., five] = statements(&phrase);
        let said = for_phrase_of(5);
        let content = entry(&phrase, &five, &said);
        let read = open_for_phrase(&content, 5, &keys.phrase_key, &keys.seal_key).unwrap();
        assert_eq!(read, said);
        assert_eq!(read.secret, secret(5));
        assert!(five.commits_to(&read.secret));
        let numbers: Vec<u64> = read.earlier.iter().map(|earlier| earlier.number).collect();
        assert_eq!(numbers, [4, 3, 2, 1]);
        for earlier in &read.earlier {
            assert_eq!(earlier.secret, secret(earlier.number as u8));
        }
        // That is all of it: the secret, a count, four numbered secrets.
        assert_eq!(said.to_bytes().len(), 32 + 2 + 4 * (8 + 32));

        // The first statement's entry holds its secret alone.
        let [one, ..] = statements(&phrase);
        let alone = entry(&phrase, &one, &ForPhrase::first(secret(1)));
        let read = open_for_phrase(&alone, 1, &keys.phrase_key, &keys.seal_key).unwrap();
        assert_eq!(read, ForPhrase::first(secret(1)));
        assert!(read.earlier.is_empty());
    }

    /// The command that has the phrase opens the part of the entry before,
    /// and copies its secrets forward: the newest first, and as many as
    /// eight. A maker that never held a generation's secret passes it on.
    #[test]
    fn the_earlier_secrets_are_copied_forward_from_the_entry_before() {
        assert!(ForPhrase::first(secret(1)).earlier.is_empty());

        let mut said = ForPhrase::first(secret(1));
        for n in 2..=12u8 {
            // Only the entry before is read: no secret but the new one is
            // given.
            said = ForPhrase::following(secret(n), &[(u64::from(n) - 1, &said)]);
            assert_eq!(said.secret, secret(n));
            assert_eq!(said.earlier.len(), usize::from(n - 1).min(8));
            for (place, earlier) in said.earlier.iter().enumerate() {
                let number = n - 1 - place as u8;
                assert_eq!(earlier.number, u64::from(number));
                assert_eq!(earlier.secret, secret(number));
            }
            assert_eq!(said.validate(u64::from(n)), Ok(()));
        }
        // After eight, the oldest is let go: the entry of statement 12
        // holds the secrets of 11 down to 4.
        assert_eq!(said.earlier.first().unwrap().number, 11);
        assert_eq!(said.earlier.last().unwrap().number, 4);
    }

    /// A settlement passes on the secrets of both branches: each once, the
    /// newest first, and as many as eight.
    #[test]
    fn a_settlement_passes_on_the_secrets_of_both_branches() {
        // Two branches from statement 2: one statement on one side, and
        // two on the other.
        let two = for_phrase_of(2);
        let a3 = ForPhrase::following(secret(0xa3), &[(2, &two)]);
        let b3 = ForPhrase::following(secret(0xb3), &[(2, &two)]);
        let b4 = ForPhrase::following(secret(0xb4), &[(3, &b3)]);

        let settled = ForPhrase::following(secret(5), &[(3, &a3), (4, &b4)]);
        assert_eq!(settled.secret, secret(5));
        let held: Vec<(u64, [u8; 32])> = settled
            .earlier
            .iter()
            .map(|earlier| (earlier.number, earlier.secret))
            .collect();
        assert_eq!(
            held,
            [
                (4, secret(0xb4)),
                (3, secret(0xb3)),
                (3, secret(0xa3)),
                (2, secret(2)),
                (1, secret(1)),
            ]
        );
        assert_eq!(settled.validate(5), Ok(()));
        // Either way round it is the same.
        assert_eq!(
            ForPhrase::following(secret(5), &[(4, &b4), (3, &a3)]),
            settled
        );

        // Two long branches: the eight newest of both.
        let branch = |salt: u8| {
            let mut said = two.clone();
            for n in 3..=9u8 {
                said = ForPhrase::following(secret(salt + n), &[(u64::from(n) - 1, &said)]);
            }
            said
        };
        let settled = ForPhrase::following(secret(10), &[(9, &branch(0x40)), (9, &branch(0x80))]);
        let held: Vec<(u64, [u8; 32])> = settled
            .earlier
            .iter()
            .map(|earlier| (earlier.number, earlier.secret))
            .collect();
        assert_eq!(
            held,
            [
                (9, secret(0x89)),
                (9, secret(0x49)),
                (8, secret(0x88)),
                (8, secret(0x48)),
                (7, secret(0x87)),
                (7, secret(0x47)),
                (6, secret(0x86)),
                (6, secret(0x46)),
            ]
        );
        assert_eq!(settled.validate(10), Ok(()));
    }

    /// What the part for the phrase may say: at most eight earlier
    /// secrets, the newest first, each of a statement before this one and
    /// none twice. Anything else is refused where an entry is made and
    /// where one is opened.
    #[test]
    fn the_part_for_the_phrase_is_held_to_its_bounds_and_its_order() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [.., five] = statements(&phrase);
        let good = for_phrase_of(5);
        let earlier = |numbers: &[u64]| -> Vec<Earlier> {
            numbers
                .iter()
                .map(|number| Earlier {
                    number: *number,
                    secret: secret(*number as u8),
                })
                .collect()
        };
        // Each is refused as it is, where an entry is made around it, and
        // where a part that says it is opened.
        let refused = |said: ForPhrase, number: u64, why: ChangeEntryError| {
            assert_eq!(said.validate(number), Err(why.clone()));
            if number == 5 {
                let made = build(
                    &signed(&five, &phrase),
                    &said,
                    &keys.statement_key,
                    &keys.seal_key,
                );
                assert_eq!(made, Err(why.clone()));
            }
            let mut content = vec![0u8; CHANGE_ENTRY_DEVICES_PART_BYTES];
            content.extend_from_slice(&phrase_part_saying(&said.to_bytes(), number, &keys));
            assert_eq!(
                open_for_phrase(&content, number, &keys.phrase_key, &keys.seal_key),
                Err(why)
            );
        };

        assert_eq!(good.validate(5), Ok(()));
        // A ninth earlier secret.
        let nine = ForPhrase {
            secret: secret(11),
            earlier: earlier(&[10, 9, 8, 7, 6, 5, 4, 3, 2]),
        };
        refused(nine, 11, ChangeEntryError::TooManyEarlier(9));

        for numbers in [
            // Not the newest first.
            &[1, 2, 3, 4][..],
            &[4, 3, 1, 2],
            // One twice.
            &[4, 3, 3, 2],
            // Of this statement, or of one after it: not before it.
            &[5, 4, 3],
            &[6, 4],
            // Number 0 is no statement's.
            &[2, 1, 0],
        ] {
            let said = ForPhrase {
                earlier: earlier(numbers),
                ..good.clone()
            };
            refused(said, 5, ChangeEntryError::EarlierOrder);
        }
        // Two branches at one number are both kept, in the order of their
        // secrets, and not in the other order.
        let mut branches = earlier(&[4, 3, 3]);
        branches[1].secret = secret(0xb3);
        branches[2].secret = secret(0xa3);
        let said = ForPhrase {
            earlier: branches.clone(),
            ..good.clone()
        };
        assert_eq!(said.validate(5), Ok(()));
        branches.swap(1, 2);
        let said = ForPhrase {
            earlier: branches,
            ..good.clone()
        };
        refused(said, 5, ChangeEntryError::EarlierOrder);
    }

    /// A part for the phrase that says more than its form, or less, is not
    /// read.
    #[test]
    fn a_part_for_the_phrase_that_is_not_in_its_form_is_refused() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let open = |said: &[u8]| {
            let mut content = vec![0u8; CHANGE_ENTRY_DEVICES_PART_BYTES];
            content.extend_from_slice(&phrase_part_saying(said, 5, &keys));
            open_for_phrase(&content, 5, &keys.phrase_key, &keys.seal_key)
        };
        let good = for_phrase_of(5);
        let said = good.to_bytes();
        assert_eq!(open(&said), Ok(good));

        // Anything after it but zeros.
        let mut more = said.clone();
        more.push(1);
        assert_eq!(open(&more), Err(ChangeEntryError::Malformed));
        let mut more = said.clone();
        more.extend_from_slice(&[0, 0, 0, 7]);
        assert_eq!(open(&more), Err(ChangeEntryError::Malformed));
        // A list of keys after the secrets is such a thing: the part holds
        // the secrets, and nothing else.
        let mut more = said.clone();
        more.extend_from_slice(&[0, 1]);
        more.extend_from_slice(&key(0));
        assert_eq!(open(&more), Err(ChangeEntryError::Malformed));

        // A count over its bound is refused where it is read, before
        // anything is read for what it counts: 9 earlier secrets, with
        // nothing after the count.
        let mut nine = secret(5).to_vec();
        nine.extend_from_slice(&[0, 9]);
        assert_eq!(open(&nine), Err(ChangeEntryError::TooManyEarlier(9)));
        assert_eq!(
            ForPhrase::from_bytes(&nine),
            Err(ChangeEntryError::TooManyEarlier(9))
        );
        // At the bound, the count is read on, and the part ends early.
        nine[33] = 8;
        assert_eq!(
            ForPhrase::from_bytes(&nine),
            Err(ChangeEntryError::Malformed)
        );

        // A part that ends before what it counts: read alone, with no
        // zeros after it to stand for what is missing.
        let short = ChangeEntryError::Malformed;
        assert_eq!(said.len(), 32 + 2 + 4 * 40);
        for length in [0, 31, 33, 35, 74, said.len() - 1] {
            assert_eq!(
                ForPhrase::from_bytes(&said[..length]),
                Err(short.clone()),
                "{length}"
            );
        }
    }

    /// A secret is not printed for debugging.
    #[test]
    fn what_an_entry_holds_prints_no_secret() {
        let said = ForPhrase {
            secret: [0x9c; 32],
            earlier: vec![Earlier {
                number: 3,
                secret: [0x9d; 32],
            }],
        };
        assert_eq!(
            format!("{said:?}"),
            "ForPhrase { earlier: [Earlier(3)], .. }"
        );
        assert_eq!(
            format!(
                "{:?} {:?} {:?}",
                DeviceSecret::Opened([0x9c; 32]),
                DeviceSecret::DidNotOpen,
                DeviceSecret::NotListed
            ),
            "Opened(..) DidNotOpen NotListed"
        );
        // What a device read is printed with its statement, which is no
        // secret, and without the secret.
        let phrase = phrase();
        let read = ForDevice {
            statement: signed(&first(&phrase), &phrase),
            secret: DeviceSecret::Opened([0x9c; 32]),
        };
        let printed = format!("{read:?}");
        assert!(printed.contains("secret: Opened(..)"), "{printed}");
        assert!(!printed.contains("156, 156, 156"), "{printed}");
    }

    // ── The entry that carries it ────────────────────────────────────

    /// The change entry is an entry of the phrase's channel: its author is
    /// the phrase's key, its revision the statement's number, and both of
    /// its signatures hold, so that a relay stores it with no key.
    #[test]
    fn the_change_entry_is_an_entry_of_the_phrases_channel() {
        let phrase = phrase();
        let keys = keys(&phrase);
        let [one, two, ..] = statements(&phrase);
        let channel = phrase.channel_secret().unwrap();

        let made = entry_of(&phrase, &signed(&two, &phrase), &for_phrase_of(2)).unwrap();
        assert_eq!(made.channel, derive::channel_id(&channel).unwrap());
        assert_eq!(made.author, keys.phrase_key);
        assert_eq!(made.rev, 2);
        assert!(!made.delete);
        assert_eq!(made.content.len(), CHANGE_ENTRY_BYTES);
        // Its slot is the slot of its one name, under the channel's slot
        // key.
        assert_eq!(
            made.slot,
            crate::slots::slot_id(&derive::slot_key(&channel).unwrap(), "change")
        );

        // It passes the check that needs no key, and a device that the
        // statement lists opens it.
        let checked = made.clone().check().unwrap();
        let opened = opened_by(&checked.content, checked.rev, &keys, 1);
        assert_eq!(opened.statement, signed(&two, &phrase));
        assert_eq!(opened.secret, DeviceSecret::Opened(secret(2)));
        // The phrase opens its part.
        let said = open_for_phrase(&checked.content, 2, &keys.phrase_key, &keys.seal_key).unwrap();
        assert_eq!(said, for_phrase_of(2));

        // Each statement's entry is in the one slot of the one channel, at
        // its statement's number: it takes the place of the one before.
        let before = entry_of(&phrase, &signed(&one, &phrase), &for_phrase_of(1)).unwrap();
        assert_eq!((before.channel, before.slot), (made.channel, made.slot));
        assert_eq!((before.author, before.rev), (made.author, 1));
        assert!(before.check().is_ok());

        // Another phrase's entry is in another channel, by another author.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let theirs = entry_of(&other, &signed(&first(&other), &other), &for_phrase_of(1)).unwrap();
        assert_ne!(theirs.channel, made.channel);
        assert_ne!(theirs.author, made.author);
        assert_ne!(theirs.slot, made.slot);
    }

    /// Only the phrase that signed a statement makes its entry: a
    /// statement under another phrase is refused, and so is whatever no
    /// content is made from.
    #[test]
    fn a_change_entry_is_not_made_for_another_phrases_statement() {
        let phrase = phrase();
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let theirs = signed(&first(&other), &other);
        assert_eq!(
            entry_of(&phrase, &theirs, &for_phrase_of(1)),
            Err(ChangeEntryError::AnotherPhrase)
        );
        // A secret that the statement does not commit to.
        let ours = signed(&first(&phrase), &phrase);
        assert_eq!(
            entry_of(&phrase, &ours, &ForPhrase::first(secret(2))),
            Err(ChangeEntryError::SecretNotCommitted)
        );
        // A statement that its phrase's key did not sign.
        let mut forged = ours.clone();
        forged.signature[0] ^= 1;
        assert_eq!(
            entry_of(&phrase, &forged, &for_phrase_of(1)),
            Err(ChangeEntryError::Statement(StatementError::Signature))
        );
        assert!(entry_of(&phrase, &ours, &for_phrase_of(1)).is_ok());
    }
}
