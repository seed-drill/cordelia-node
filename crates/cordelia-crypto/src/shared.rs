//! The entries of a shared channel (decision 2026-10-10 §2.3, §6.1, §7):
//! a message of form 3, the entry that clears one (form 0), and a device's
//! anew record (form 5), with the seal of a new seed to each key that stays.
//!
//! Everything here is pure, as [`crate::message`] is: what each value is
//! byte for byte, the name of each slot, and what a reader takes from an
//! entry. Every length is big-endian.
//!
//! ## The slots
//!
//! ```text
//! msg/<the signer's key>/<n>   a message of form 3, or its clearing: 2,048 bytes
//! anew/<the signer's key>      the device's anew record, an offer or empty: 16,384
//! ```
//!
//! A message's slot and revisions are the messages record's
//! ([`crate::message::message_name`], [`crate::message::message_rev`]). A
//! reader takes from a slot only what the key in its name signed.
//!
//! ## A message (form 3)
//!
//! The messages record's form 1 without `from`, `to` and the kind of `to`:
//! it names no agent of the sender's, and no recipient. Of kind 2 and of
//! exactly `AGENT_MESSAGE_VALUE_BYTES` (1,936) bytes, so that it seals at
//! 2,048 through [`crate::entry::Entry::seal`] as it is.
//!
//! ```text
//! form       1    3
//! flags      1    bit 0: it asks for an answer; every other bit 0
//! sent       8    seconds since 1970, by the sender's clock
//! nonce      16   random
//! thread     16   the ID of the message that began the thread, or zeros
//! answers    16   the ID of the message it answers, or zeros
//! link       1 + 0 to 151     `owner/repo#n`, or nothing
//! body       2 + 1 to 1,024   UTF-8
//! fill       the rest, zeros
//! ```
//!
//! ## An anew record (form 5)
//!
//! Of kind 2 and of exactly `SHARED_ANEW_VALUE_BYTES` (16,274) bytes, so
//! that it seals at 16,384. Empty, it is the byte 5 and zeros. An offer:
//!
//! ```text
//! form       1    5
//! made       8    seconds since 1970, by the maker's clock
//! new        32   the new channel's ID
//! relays     1 + 32 or 64     the new card's relays, as a card holds them
//! seals      1    a count, 1 to 64; then for each key that stays: the key,
//!                 32, and the new seed sealed to it, 92
//! fill       the rest, zeros
//! ```
//!
//! A seed is sealed to a key's X25519 form under `cordelia v2 anew seal`,
//! the old channel's ID and the new one's ([`seal_info`]), as a change
//! entry seals a secret to each device. At 64 keys the record's fields are
//! 8,043 bytes.

use cordelia_core::protocol::{
    AGENT_MESSAGE_BODY_MAX_BYTES, AGENT_MESSAGE_ID_BYTES, AGENT_MESSAGE_LINK_MAX_BYTES,
    AGENT_MESSAGE_VALUE_BYTES, LABEL_ANEW_SEAL, SEALED_SECRET_BYTES, SHARED_ANEW_PREFIX,
    SHARED_ANEW_VALUE_BYTES, SHARED_MAX_KEYS,
};

use crate::CryptoError;
use crate::bech32::encode_public_key;
use crate::ecies::{EciesEnvelope, ecies_decrypt_for, ecies_encrypt_for};
use crate::entry::Value;
use crate::identity::{NodeIdentity, is_usable_public_key, x25519_pub_from_ed25519_pub};
use crate::message::{
    FLAG_ASKS, NotAMessage, Place, byte, filled, is_a_link, is_clearing, place_of, whole,
};
use crate::share::{Card, Relays, ShareError};
use crate::statement::{Reader, put_count};

/// The first byte of each form of value that a shared channel holds.
const FORM_CLEARING: u8 = 0;
const FORM_MESSAGE: u8 = 3;
const FORM_ANEW: u8 = 5;

/// A message of a shared channel, as its value holds it (decision
/// 2026-10-10 §6.1): no agent and no recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedMessage {
    /// Whether it asks for an answer: bit 0 of the flags.
    pub asks: bool,
    /// When it was sent, in seconds since 1970, by the sender's clock.
    pub sent: u64,
    /// Random, so that two messages with the same words are two messages.
    pub nonce: [u8; 16],
    /// The ID of the message that began the thread, or zeros.
    pub thread: [u8; AGENT_MESSAGE_ID_BYTES],
    /// The ID of the message it answers, or zeros.
    pub answers: [u8; AGENT_MESSAGE_ID_BYTES],
    /// `owner/repo#n`, the sender's text.
    pub link: Option<String>,
    pub body: String,
}

impl SharedMessage {
    /// The message's value, filled with zeros to its one length. Refused,
    /// and never cut to fit, where a reader would refuse it.
    pub fn to_value(&self) -> Result<Vec<u8>, NotAMessage> {
        let link = self.link.as_deref().unwrap_or("");
        // A link given as nothing is no link: it would read back as none.
        if self.link.as_deref() == Some("") {
            return Err(NotAMessage::Link);
        }
        if link.len() > AGENT_MESSAGE_LINK_MAX_BYTES {
            return Err(NotAMessage::Field);
        }
        if self.body.len() > AGENT_MESSAGE_BODY_MAX_BYTES {
            return Err(NotAMessage::BodyTooLong(self.body.len()));
        }
        let mut out = Vec::with_capacity(AGENT_MESSAGE_VALUE_BYTES);
        out.push(FORM_MESSAGE);
        out.push(if self.asks { FLAG_ASKS } else { 0 });
        out.extend_from_slice(&self.sent.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.thread);
        out.extend_from_slice(&self.answers);
        out.push(link.len() as u8);
        out.extend_from_slice(link.as_bytes());
        put_count(&mut out, self.body.len());
        out.extend_from_slice(self.body.as_bytes());
        out.resize(AGENT_MESSAGE_VALUE_BYTES, 0);

        if Self::from_value(&Value::Other(out.clone()))? != *self {
            return Err(NotAMessage::Field);
        }
        Ok(out)
    }

    /// Read a message from an entry's value of a shared channel, as a
    /// reader does (decision 2026-10-10 §2.3). A value of the messages
    /// channel's forms, 1 and 2, is no message here, nor one of form 4.
    pub fn from_value(value: &Value) -> Result<Self, NotAMessage> {
        let mut reader = Reader::new(whole(value)?);
        let form = byte(&mut reader)?;
        if form != FORM_MESSAGE {
            return Err(form_refused(form));
        }
        let flags = byte(&mut reader)?;
        if flags & !FLAG_ASKS != 0 {
            return Err(NotAMessage::Flags(flags));
        }
        let sent = reader.u64().ok_or(NotAMessage::Field)?;
        let nonce = reader.array().ok_or(NotAMessage::Field)?;
        let thread = reader.array().ok_or(NotAMessage::Field)?;
        let answers = reader.array().ok_or(NotAMessage::Field)?;

        let length = usize::from(byte(&mut reader)?);
        if length > AGENT_MESSAGE_LINK_MAX_BYTES {
            return Err(NotAMessage::Field);
        }
        let link = match reader.take(length).ok_or(NotAMessage::Field)? {
            [] => None,
            link => {
                let link = std::str::from_utf8(link).map_err(|_| NotAMessage::Link)?;
                if !is_a_link(link) {
                    return Err(NotAMessage::Link);
                }
                Some(link.to_string())
            }
        };

        let length = reader.count().ok_or(NotAMessage::Field)?;
        if length == 0 {
            return Err(NotAMessage::BodyEmpty);
        }
        if length > AGENT_MESSAGE_BODY_MAX_BYTES {
            return Err(NotAMessage::BodyTooLong(length));
        }
        let body = reader.take(length).ok_or(NotAMessage::Field)?;
        let body = String::from_utf8(body.to_vec()).map_err(|_| NotAMessage::BodyNotText)?;

        filled(&reader)?;
        Ok(Self {
            asks: flags & FLAG_ASKS != 0,
            sent,
            nonce,
            thread,
            answers,
            link,
            body,
        })
    }

    /// The subject: the body up to its first line feed (decision
    /// 2026-10-09 §2.2).
    pub fn subject(&self) -> &str {
        self.body.split('\n').next().unwrap_or("")
    }
}

/// A form that a shared channel holds, at a place of another, or one it
/// does not hold.
fn form_refused(form: u8) -> NotAMessage {
    match form {
        FORM_CLEARING | FORM_MESSAGE | FORM_ANEW => NotAMessage::AnotherForm(form),
        other => NotAMessage::Form(other),
    }
}

/// Why an anew record is none, or was not made, or does not open.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnewError {
    #[error("an anew record holds a value that is not of kind 2")]
    Kind,

    #[error("an anew record's value is 16274 bytes, and this is {0}")]
    Length(usize),

    #[error("an anew record is of form 5, and this is of form {0}")]
    Form(u8),

    #[error("an anew record's fields run past its value")]
    Field,

    #[error("an offer's relays are not a card's: {0}")]
    Relays(ShareError),

    #[error("an offer seals the new seed to one key at least")]
    NoKey,

    #[error("an offer seals the new seed to 64 keys at most, and this to {0}")]
    TooManyKeys(usize),

    #[error("an offer seals to one key twice")]
    KeyTwice,

    #[error("a key that stays is not a usable public key")]
    KeyNotUsable,

    #[error("what follows an anew record's fields is not all zeros")]
    Fill,

    #[error("the offer seals nothing to this device's key")]
    NotSealedToThisKey,

    #[error("the seal for this device's key does not open as this offer's seed")]
    DidNotOpen,

    #[error("the seed sealed to this device gives another channel than the offer's")]
    AnotherChannel,

    #[error("the offer's new channel is the channel it makes anew")]
    SameChannel,

    #[error("sealing failed: {0}")]
    Crypto(String),
}

fn crypto(error: CryptoError) -> AnewError {
    AnewError::Crypto(error.to_string())
}

/// A device's anew record in a shared channel (decision 2026-10-10 §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anew {
    /// What each device writes when it comes to hold the channel, at the
    /// record's full size.
    Empty,
    /// The channel made anew: a new channel, and its seed for each key
    /// that stays.
    Offer(Offer),
}

/// The new seed sealed to one key that stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seal {
    pub key: [u8; 32],
    pub sealed: [u8; SEALED_SECRET_BYTES],
}

/// An offer: the channel made anew, by its maker (decision 2026-10-10 §7).
/// Who it keeps is the keys it seals to; nothing else in it says who stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// When it was made, in seconds since 1970, by the maker's clock.
    pub made: u64,
    /// The new channel's ID.
    pub new_channel: [u8; 32],
    /// The new card's relays.
    pub relays: Relays,
    /// For each key that stays, in the order the maker gave them.
    pub seals: Vec<Seal>,
}

impl Offer {
    /// The offer that makes the channel `old_channel` anew as `card`, with
    /// the new seed sealed to each of `keys` (decision 2026-10-10 §7, step
    /// 2). At least one key, at most 64, each once and each usable; and a
    /// card of another channel than the old one.
    pub fn make(
        made: u64,
        old_channel: &[u8; 32],
        card: &Card,
        keys: &[[u8; 32]],
    ) -> Result<Self, AnewError> {
        check_keys(keys.iter())?;
        let new_channel = card.channel_id().map_err(crypto)?;
        if new_channel == *old_channel {
            return Err(AnewError::SameChannel);
        }
        let info = seal_info(old_channel, &new_channel);
        let seals = keys
            .iter()
            .map(|key| {
                let to = x25519_pub_from_ed25519_pub(key).ok_or(AnewError::KeyNotUsable)?;
                let envelope = ecies_encrypt_for(&to, card.seed(), &info).map_err(crypto)?;
                let sealed = envelope
                    .to_bytes()
                    .try_into()
                    .map_err(|_| AnewError::Crypto("a seal of another length".into()))?;
                Ok(Seal { key: *key, sealed })
            })
            .collect::<Result<_, AnewError>>()?;
        Ok(Self {
            made,
            new_channel,
            relays: card.relays().clone(),
            seals,
        })
    }

    /// Whether the offer seals the new seed to `key`.
    pub fn seals_to(&self, key: &[u8; 32]) -> bool {
        self.seals.iter().any(|seal| seal.key == *key)
    }

    /// Open the seal for `device`, in the offer that makes `old_channel`
    /// anew: the new channel's card, where the seal opens to a seed whose
    /// card gives the offer's new ID (decision 2026-10-10 §7). Anything
    /// else is a fault, and says which. An offer whose new channel is the
    /// old one is a fault: any member holds the old seed and can seal it,
    /// and a move to it would file the channel beside its own drop.
    pub fn open(&self, device: &NodeIdentity, old_channel: &[u8; 32]) -> Result<Card, AnewError> {
        if self.new_channel == *old_channel {
            return Err(AnewError::SameChannel);
        }
        let key = device.public_key();
        let seal = self
            .seals
            .iter()
            .find(|seal| seal.key == key)
            .ok_or(AnewError::NotSealedToThisKey)?;
        let envelope =
            EciesEnvelope::from_bytes(&seal.sealed, 32).map_err(|_| AnewError::DidNotOpen)?;
        let seed: [u8; 32] = ecies_decrypt_for(
            &device.x25519_private_key(),
            &envelope,
            &seal_info(old_channel, &self.new_channel),
        )
        .map_err(|_| AnewError::DidNotOpen)?
        .try_into()
        .map_err(|_| AnewError::DidNotOpen)?;
        let card = Card::of(seed, self.relays.clone());
        if card.channel_id().map_err(crypto)? != self.new_channel {
            return Err(AnewError::AnotherChannel);
        }
        Ok(card)
    }
}

impl Anew {
    /// The record's value, filled with zeros to its one length.
    pub fn to_value(&self) -> Result<Vec<u8>, AnewError> {
        let mut out = Vec::with_capacity(SHARED_ANEW_VALUE_BYTES);
        out.push(FORM_ANEW);
        if let Self::Offer(offer) = self {
            check_keys(offer.seals.iter().map(|seal| &seal.key))?;
            out.extend_from_slice(&offer.made.to_be_bytes());
            out.extend_from_slice(&offer.new_channel);
            out.extend_from_slice(&offer.relays.to_bytes());
            out.push(offer.seals.len() as u8);
            for seal in &offer.seals {
                out.extend_from_slice(&seal.key);
                out.extend_from_slice(&seal.sealed);
            }
        }
        out.resize(SHARED_ANEW_VALUE_BYTES, 0);
        Ok(out)
    }

    /// Read a record from an entry's value, as a reader does (decision
    /// 2026-10-10 §2.3): of kind 2, of its one length and form; empty, or
    /// an offer whose relays are a card's and whose seals are 1 to 64, each
    /// for another key; and a fill of zeros.
    pub fn from_value(value: &Value) -> Result<Self, AnewError> {
        let Value::Other(bytes) = value else {
            return Err(AnewError::Kind);
        };
        if bytes.len() != SHARED_ANEW_VALUE_BYTES {
            return Err(AnewError::Length(bytes.len()));
        }
        let mut reader = Reader::new(bytes);
        let form = reader.array::<1>().ok_or(AnewError::Field)?[0];
        if form != FORM_ANEW {
            return Err(AnewError::Form(form));
        }
        if reader.rest().iter().all(|byte| *byte == 0) {
            return Ok(Self::Empty);
        }
        let made = reader.u64().ok_or(AnewError::Field)?;
        let new_channel = reader.array().ok_or(AnewError::Field)?;
        let relays = Relays::read(&mut reader).map_err(AnewError::Relays)?;
        let count = usize::from(reader.array::<1>().ok_or(AnewError::Field)?[0]);
        let seals: Vec<Seal> = (0..count)
            .map(|_| {
                Ok(Seal {
                    key: reader.array().ok_or(AnewError::Field)?,
                    sealed: reader.array().ok_or(AnewError::Field)?,
                })
            })
            .collect::<Result<_, AnewError>>()?;
        check_keys(seals.iter().map(|seal| &seal.key))?;
        if reader.rest().iter().any(|byte| *byte != 0) {
            return Err(AnewError::Fill);
        }
        Ok(Self::Offer(Offer {
            made,
            new_channel,
            relays,
            seals,
        }))
    }
}

/// The keys an offer seals to: 1 to 64, each once, and each a usable
/// public key, made or read: a key of no device is no one who stays.
fn check_keys<'a>(keys: impl ExactSizeIterator<Item = &'a [u8; 32]>) -> Result<(), AnewError> {
    let count = keys.len();
    if count == 0 {
        return Err(AnewError::NoKey);
    }
    if count > SHARED_MAX_KEYS {
        return Err(AnewError::TooManyKeys(count));
    }
    let mut seen: Vec<&[u8; 32]> = keys.collect();
    seen.sort_unstable();
    if seen.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AnewError::KeyTwice);
    }
    // Last, since it is the one check that costs a point's decompression
    // for each key.
    if !seen.iter().all(|key| is_usable_public_key(key)) {
        return Err(AnewError::KeyNotUsable);
    }
    Ok(())
}

/// What a new seed is sealed under (decision 2026-10-10 §7): its label, the
/// old channel's ID and the new channel's. A seal moved to another offer,
/// or to another channel's, does not open.
pub fn seal_info(old_channel: &[u8; 32], new_channel: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(LABEL_ANEW_SEAL.len() + 64);
    info.extend_from_slice(LABEL_ANEW_SEAL);
    info.extend_from_slice(old_channel);
    info.extend_from_slice(new_channel);
    info
}

/// The name of a device's anew record: `anew/` and the device's key as it
/// is written (decision 2026-10-10 §2.3).
pub fn anew_name(signer: &[u8; 32]) -> Result<String, CryptoError> {
    Ok(format!(
        "{SHARED_ANEW_PREFIX}{}",
        encode_public_key(signer)?
    ))
}

/// What an entry of a shared channel is, once its place and its value
/// agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedTaken {
    /// A message, at its number.
    Message { number: u64, message: SharedMessage },
    /// The entry that clears the message of that number.
    Clearing { number: u64 },
    /// The signer's anew record.
    Anew(Anew),
}

/// Why an entry of a shared channel is taken as nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotShared {
    #[error("the entry is in none of its signer's slots")]
    NotInItsSlots,

    #[error(transparent)]
    Message(#[from] NotAMessage),

    #[error(transparent)]
    Anew(#[from] AnewError),
}

/// What a reader takes from the entry of a shared channel named `name`,
/// signed by `signer`, at revision `rev`, that holds `value` (decision
/// 2026-10-10 §2.3): an entry in a slot of one of the two kinds named for
/// its signer, a message at its place in the ring, and a value of its
/// kind's length and form. Anything else is taken as nothing: an entry in
/// a slot named for another key among them, and a list of the messages
/// channel.
pub fn take(
    name: &str,
    signer: &[u8; 32],
    rev: u64,
    value: &Value,
) -> Result<SharedTaken, NotShared> {
    if name == anew_name(signer).map_err(|_| NotShared::NotInItsSlots)? {
        return Ok(SharedTaken::Anew(Anew::from_value(value)?));
    }
    match place_of(name, signer, rev) {
        Some(Place::Message(number)) => Ok(SharedTaken::Message {
            number,
            message: SharedMessage::from_value(value)?,
        }),
        Some(Place::Clearing(number)) => {
            is_clearing(value)?;
            Ok(SharedTaken::Clearing { number })
        }
        Some(Place::List) | None => Err(NotShared::NotInItsSlots),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecies::ecies_decrypt;
    use crate::entry::{Entry, Inside};
    use crate::message::{
        Message, ReadMarks, To, clearing_rev, clearing_value, message_name, message_rev, read_name,
    };
    use cordelia_core::protocol::{AGENT_MESSAGE_CONTENT_BYTES, SHARED_ANEW_CONTENT_BYTES};

    const SECRET: [u8; 32] = [0x6b; 32];
    const OLD: [u8; 32] = [0x01; 32];

    fn device(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32]).unwrap()
    }

    fn card(relays: &[[u8; 32]]) -> Card {
        Card::make(Relays::new(relays).unwrap()).unwrap()
    }

    fn smallest() -> SharedMessage {
        SharedMessage {
            asks: false,
            sent: 0,
            nonce: [0; 16],
            thread: [0; 16],
            answers: [0; 16],
            link: None,
            body: "x".into(),
        }
    }

    fn largest() -> SharedMessage {
        SharedMessage {
            asks: true,
            sent: u64::MAX,
            nonce: [0xff; 16],
            thread: [0xee; 16],
            answers: [0xdd; 16],
            link: Some(format!(
                "{}/{}#{}",
                "o".repeat(39),
                "r".repeat(100),
                "9".repeat(10)
            )),
            body: "b".repeat(1024),
        }
    }

    /// An offer from the maker to 64 keys: what the largest record holds.
    fn full_offer(card: &Card) -> Offer {
        let keys: Vec<[u8; 32]> = (0..64u8).map(|n| device(100 + n).public_key()).collect();
        Offer::make(u64::MAX, &OLD, card, &keys).unwrap()
    }

    fn sealed(signer: &NodeIdentity, name: String, rev: u64, value: Vec<u8>) -> Entry {
        let inside = Inside {
            name,
            value: Value::Other(value),
            chain: Some(Vec::new()),
        };
        Entry::seal(&SECRET, signer, rev, &inside).unwrap()
    }

    /// Every entry an honest node writes in a shared channel is of one of
    /// its two sizes (decision 2026-10-10 §1, property 21): the smallest
    /// and the largest message and the clearing, in slot 0 and in slot 63,
    /// at 2,048 bytes with a value of 1,936; and the empty anew record and
    /// an offer to 64 keys at two relays, at 16,384 with a value of 16,274.
    /// Each opens to what it was given, and is taken as what it is.
    #[test]
    fn every_entry_of_a_shared_channel_is_of_its_one_size() {
        let laptop = device(1);
        let key = laptop.public_key();
        let mut written = Vec::new();
        for number in [63, 64] {
            let name = message_name(&key, number).unwrap();
            for message in [smallest(), largest()] {
                let value = message.to_value().unwrap();
                written.push((name.clone(), message_rev(number).unwrap(), value));
            }
            written.push((name, clearing_rev(number).unwrap(), clearing_value()));
        }
        for (name, rev, value) in written {
            assert_eq!(value.len(), AGENT_MESSAGE_VALUE_BYTES);
            assert_eq!(value.len(), 1_936);
            let entry = sealed(&laptop, name.clone(), rev, value.clone());
            assert_eq!(entry.content.len(), AGENT_MESSAGE_CONTENT_BYTES, "{name}");
            assert_eq!(entry.content.len(), 2_048);
            let opened = entry.check().unwrap().open(&SECRET).unwrap();
            assert_eq!(opened.value, Value::Other(value));
            assert!(take(&name, &key, rev, &opened.value).is_ok(), "{name}");
        }

        let card = card(&[[3; 32], [4; 32]]);
        for record in [Anew::Empty, Anew::Offer(full_offer(&card))] {
            let value = record.to_value().unwrap();
            assert_eq!(value.len(), SHARED_ANEW_VALUE_BYTES);
            assert_eq!(value.len(), 16_274);
            let name = anew_name(&key).unwrap();
            let entry = sealed(&laptop, name.clone(), 1, value);
            assert_eq!(entry.content.len(), SHARED_ANEW_CONTENT_BYTES);
            assert_eq!(entry.content.len(), 16_384);
            let opened = entry.check().unwrap().open(&SECRET).unwrap();
            assert_eq!(
                take(&name, &key, 1, &opened.value),
                Ok(SharedTaken::Anew(record))
            );
        }

        // A body of 1,025 bytes is refused before it is sealed.
        let over = SharedMessage {
            body: "b".repeat(1025),
            ..largest()
        };
        assert_eq!(over.to_value(), Err(NotAMessage::BodyTooLong(1025)));
    }

    /// A message of form 3, byte for byte: no agent, no recipient.
    #[test]
    fn a_shared_messages_value_is_its_fields_in_their_places() {
        let message = SharedMessage {
            asks: true,
            sent: 0x0102_0304_0506_0708,
            nonce: [0xa1; 16],
            thread: [0xb2; 16],
            answers: [0xc3; 16],
            link: Some("o/r#5".into()),
            body: "hi\nthere".into(),
        };
        let value = message.to_value().unwrap();
        let mut expected = vec![3, 1, 1, 2, 3, 4, 5, 6, 7, 8];
        expected.extend_from_slice(&[0xa1; 16]);
        expected.extend_from_slice(&[0xb2; 16]);
        expected.extend_from_slice(&[0xc3; 16]);
        expected.push(5);
        expected.extend_from_slice(b"o/r#5");
        expected.extend_from_slice(&[0, 8]);
        expected.extend_from_slice(b"hi\nthere");
        assert_eq!(&value[..expected.len()], &expected[..]);
        assert!(value[expected.len()..].iter().all(|byte| *byte == 0));
        assert_eq!(
            SharedMessage::from_value(&Value::Other(value)).unwrap(),
            message
        );
        assert_eq!(message.subject(), "hi");

        // Not asking: flags 0; no link: a length of 0.
        let plain = SharedMessage {
            asks: false,
            link: None,
            ..message
        };
        let value = plain.to_value().unwrap();
        assert_eq!(value[1], 0);
        assert_eq!(&value[58..61], &[0, 0, 8]);
        // A message at every bound is 1,236 bytes, and the smallest 62.
        let fixed = 1 + 1 + 8 + 16 + 16 + 16;
        assert_eq!(fixed + (1 + 151) + (2 + 1024), 1_236);
        assert_eq!(fixed + 1 + (2 + 1), 62);
        let largest = largest().to_value().unwrap();
        assert!(largest[1_236..].iter().all(|byte| *byte == 0));
        assert_ne!(largest[1_235], 0);
    }

    /// A reader of a shared channel refuses each value that is not a
    /// message of form 3: the messages channel's forms, form 4, a flag but
    /// bit 0, a link that is none, a body empty, too long or not text, and
    /// a fill that is not zeros. The sender refuses the same.
    #[test]
    fn a_reader_refuses_each_shared_message_that_is_not_one() {
        let value = largest().to_value().unwrap();
        let read = |value: Vec<u8>| SharedMessage::from_value(&Value::Other(value));
        assert!(read(value.clone()).is_ok());
        assert_eq!(
            SharedMessage::from_value(&Value::Text("a".repeat(1_936))),
            Err(NotAMessage::Kind)
        );
        for length in [1_935, 1_937] {
            let mut changed = value.clone();
            changed.resize(length, 0);
            assert_eq!(read(changed), Err(NotAMessage::Length(length)));
        }
        // The messages channel's message, list and clearing, form 4, and
        // the anew record's form.
        let names = |name: &str| !name.is_empty();
        let own = Message {
            asks: false,
            sent: 0,
            nonce: [0; 16],
            thread: [0; 16],
            answers: [0; 16],
            from: "~".into(),
            to: To::All,
            link: None,
            body: "x".into(),
        }
        .to_value(names)
        .unwrap();
        assert_eq!(read(own), Err(NotAMessage::Form(1)));
        let list = ReadMarks::default().to_value().unwrap();
        assert_eq!(read(list), Err(NotAMessage::Form(2)));
        assert_eq!(read(clearing_value()), Err(NotAMessage::AnotherForm(0)));
        for form in [4, 5, 6, 0xff] {
            let mut changed = value.clone();
            changed[0] = form;
            let refused = read(changed).unwrap_err();
            assert!(
                matches!(refused, NotAMessage::Form(_) | NotAMessage::AnotherForm(_)),
                "{form}"
            );
        }
        // And a shared message is no message of the messages channel.
        assert_eq!(
            Message::from_value(&Value::Other(value.clone()), names),
            Err(NotAMessage::Form(3))
        );

        for flags in [0b10, 0b11, 0x80] {
            let mut changed = value.clone();
            changed[1] = flags;
            assert_eq!(read(changed), Err(NotAMessage::Flags(flags)));
        }
        // The link's length at 58: past its bound, and a link that is none.
        let mut changed = value.clone();
        changed[58] = 152;
        assert_eq!(read(changed), Err(NotAMessage::Field));
        let mut changed = value.clone();
        changed[59] = b'#';
        assert_eq!(read(changed), Err(NotAMessage::Link));
        // The body's length at 210: none, and past its bound.
        let at = 59 + 151;
        let mut changed = value.clone();
        changed[at..at + 2].copy_from_slice(&[0, 0]);
        assert_eq!(read(changed), Err(NotAMessage::BodyEmpty));
        let mut changed = value.clone();
        changed[at..at + 2].copy_from_slice(&1025u16.to_be_bytes());
        assert_eq!(read(changed), Err(NotAMessage::BodyTooLong(1025)));
        let mut changed = value.clone();
        changed[at + 2] = 0xff;
        assert_eq!(read(changed), Err(NotAMessage::BodyNotText));
        for at in [1_236, 1_935] {
            let mut changed = value.clone();
            changed[at] = 1;
            assert_eq!(read(changed), Err(NotAMessage::Fill), "{at}");
        }

        // The sender refuses what a reader would.
        let refused = |message: SharedMessage| message.to_value();
        for link in ["", "owner/repo", &"1".repeat(152)] {
            assert!(
                refused(SharedMessage {
                    link: Some(link.to_string()),
                    ..smallest()
                })
                .is_err(),
                "{link}"
            );
        }
        assert_eq!(
            refused(SharedMessage {
                body: String::new(),
                ..smallest()
            }),
            Err(NotAMessage::BodyEmpty)
        );
    }

    /// An anew record seals the new seed and nothing else (decision
    /// 2026-10-10 §1, property 1, and §7): its bytes are its form, its
    /// time, the new ID, the relays, a count and, for each key that stays,
    /// the key and a seal that opens, for that key and under the label and
    /// both IDs, to the new seed; its fields at 64 keys are 8,043 bytes.
    #[test]
    fn an_anew_record_seals_only_the_new_seed() {
        let card = card(&[[3; 32], [4; 32]]);
        let new = card.channel_id().unwrap();
        let offer = full_offer(&card);
        let value = Anew::Offer(offer.clone()).to_value().unwrap();

        let mut expected = vec![5];
        expected.extend_from_slice(&u64::MAX.to_be_bytes());
        expected.extend_from_slice(&new);
        expected.push(2);
        expected.extend_from_slice(&[3; 32]);
        expected.extend_from_slice(&[4; 32]);
        expected.push(64);
        assert_eq!(&value[..expected.len()], &expected[..]);
        let fields = expected.len() + 64 * (32 + SEALED_SECRET_BYTES);
        assert_eq!(fields, 8_043);
        assert!(value[fields..].iter().all(|byte| *byte == 0));

        let info = seal_info(&OLD, &new);
        let mut label = b"cordelia v2 anew seal".to_vec();
        label.extend_from_slice(&OLD);
        label.extend_from_slice(&new);
        assert_eq!(info, label);
        for (n, at) in (0..64u8).zip((expected.len()..fields).step_by(124)) {
            let device = device(100 + n);
            assert_eq!(value[at..at + 32], device.public_key());
            let envelope = EciesEnvelope::from_bytes(&value[at + 32..at + 124], 32).unwrap();
            let private = device.x25519_private_key();
            assert_eq!(
                ecies_decrypt_for(&private, &envelope, &info).unwrap(),
                card.seed().to_vec()
            );
            // Under no other purpose, and for no other key.
            assert!(ecies_decrypt(&private, &envelope).is_err());
            assert!(ecies_decrypt_for(&private, &envelope, &seal_info(&new, &OLD)).is_err());
            let other = self::device(99).x25519_private_key();
            assert!(ecies_decrypt_for(&other, &envelope, &info).is_err());
            assert_eq!(offer.open(&device, &OLD).unwrap(), card);
        }
        assert_eq!(
            Anew::from_value(&Value::Other(value)).unwrap(),
            Anew::Offer(offer)
        );
        // The empty record is its form and zeros.
        let empty = Anew::Empty.to_value().unwrap();
        assert_eq!(empty[0], 5);
        assert!(empty[1..].iter().all(|byte| *byte == 0));
    }

    /// An offer opens only for a key it seals to, in the offer of the old
    /// channel it names, to a seed whose card gives its new ID: a seal of
    /// another seed, a seal that is not one, and a seal read for another
    /// old channel are each a fault, and say which.
    #[test]
    fn an_offer_opens_only_for_a_key_it_seals_to_and_to_its_new_channel() {
        let (laptop, desktop, phone) = (device(1), device(2), device(3));
        let card = card(&[[3; 32]]);
        let offer =
            Offer::make(9, &OLD, &card, &[laptop.public_key(), desktop.public_key()]).unwrap();
        assert!(offer.seals_to(&laptop.public_key()));
        assert!(!offer.seals_to(&phone.public_key()));
        assert_eq!(offer.open(&laptop, &OLD).unwrap(), card);
        assert_eq!(offer.open(&desktop, &OLD).unwrap(), card);
        assert_eq!(offer.open(&phone, &OLD), Err(AnewError::NotSealedToThisKey));
        assert_eq!(offer.open(&laptop, &[2; 32]), Err(AnewError::DidNotOpen));

        // An offer of the old channel itself, which any member can seal
        // with the old seed: it is not made, and one written by hand opens
        // to the channel it makes anew, and is a fault.
        let old = card.channel_id().unwrap();
        assert_eq!(
            Offer::make(9, &old, &card, &[laptop.public_key()]),
            Err(AnewError::SameChannel)
        );
        let to = x25519_pub_from_ed25519_pub(&laptop.public_key()).unwrap();
        let same = Offer {
            new_channel: old,
            seals: vec![Seal {
                key: laptop.public_key(),
                sealed: ecies_encrypt_for(&to, card.seed(), &seal_info(&old, &old))
                    .unwrap()
                    .to_bytes()
                    .try_into()
                    .unwrap(),
            }],
            ..offer.clone()
        };
        assert_eq!(same.open(&laptop, &old), Err(AnewError::SameChannel));
        // Read in another old channel, its seal, bound to the old one, does
        // not open.
        assert_eq!(same.open(&laptop, &OLD), Err(AnewError::DidNotOpen));

        // The seal of another card's seed, under this offer's IDs.
        let other = self::card(&[[3; 32]]);
        let mut forged = offer.clone();
        let to = x25519_pub_from_ed25519_pub(&laptop.public_key()).unwrap();
        let info = seal_info(&OLD, &offer.new_channel);
        forged.seals[0].sealed = ecies_encrypt_for(&to, other.seed(), &info)
            .unwrap()
            .to_bytes()
            .try_into()
            .unwrap();
        assert_eq!(forged.open(&laptop, &OLD), Err(AnewError::AnotherChannel));
        // Bytes that are no seal.
        forged.seals[0].sealed = [7; SEALED_SECRET_BYTES];
        assert_eq!(forged.open(&laptop, &OLD), Err(AnewError::DidNotOpen));
        // The other relays: the seed is the same, the channel another.
        let mut moved = offer.clone();
        moved.relays = Relays::new(&[[4; 32]]).unwrap();
        assert_eq!(moved.open(&laptop, &OLD), Err(AnewError::AnotherChannel));

        // What may not be made: no key, a key twice, more than 64, a key
        // that is not usable.
        assert_eq!(Offer::make(9, &OLD, &card, &[]), Err(AnewError::NoKey));
        assert_eq!(
            Offer::make(9, &OLD, &card, &[laptop.public_key(); 2]),
            Err(AnewError::KeyTwice)
        );
        let many: Vec<[u8; 32]> = (0..65u8).map(|n| device(100 + n).public_key()).collect();
        assert_eq!(
            Offer::make(9, &OLD, &card, &many),
            Err(AnewError::TooManyKeys(65))
        );
        assert!(Offer::make(9, &OLD, &card, &many[..64]).is_ok());
        assert_eq!(
            Offer::make(9, &OLD, &card, &[[0; 32]]),
            Err(AnewError::KeyNotUsable)
        );
    }

    /// A reader refuses an anew record of another kind, length or form,
    /// with relays that are not a card's, with no seal, more than 64 or a
    /// key twice, or with a fill that is not zeros.
    #[test]
    fn a_reader_refuses_each_anew_record_that_is_not_one() {
        let card = card(&[[3; 32], [4; 32]]);
        let offer = Offer::make(
            9,
            &OLD,
            &card,
            &[device(1).public_key(), device(2).public_key()],
        )
        .unwrap();
        let value = Anew::Offer(offer).to_value().unwrap();
        let read = |value: Vec<u8>| Anew::from_value(&Value::Other(value));
        assert!(read(value.clone()).is_ok());
        assert_eq!(
            Anew::from_value(&Value::Text("a".repeat(16_274))),
            Err(AnewError::Kind)
        );
        for length in [16_273, 16_275, 1_936] {
            let mut changed = value.clone();
            changed.resize(length, 0);
            assert_eq!(read(changed), Err(AnewError::Length(length)));
        }
        for form in [0, 3, 4] {
            let mut changed = value.clone();
            changed[0] = form;
            assert_eq!(read(changed), Err(AnewError::Form(form)));
        }
        // The relays' count at 41: three, and none.
        let mut changed = value.clone();
        changed[41] = 3;
        assert_eq!(
            read(changed),
            Err(AnewError::Relays(ShareError::TooManyRelays(3)))
        );
        let mut changed = value.clone();
        changed[41] = 0;
        assert_eq!(read(changed), Err(AnewError::Relays(ShareError::NoRelay)));
        // The seals' count at 106: none, and more than 64.
        let mut changed = value.clone();
        changed[106] = 0;
        assert_eq!(read(changed), Err(AnewError::NoKey));
        let mut changed = value.clone();
        changed[106] = 65;
        assert_eq!(read(changed), Err(AnewError::TooManyKeys(65)));
        // The second seal's key the first's.
        let mut changed = value.clone();
        let first = changed[107..139].to_vec();
        changed[231..263].copy_from_slice(&first);
        assert_eq!(read(changed), Err(AnewError::KeyTwice));
        for at in [355, 16_273] {
            let mut changed = value.clone();
            changed[at] = 1;
            assert_eq!(read(changed), Err(AnewError::Fill), "{at}");
        }
        // The second seal's key one of small order, and bytes that are no
        // point.
        for key in [[0; 32], [0xff; 32]] {
            let mut changed = value.clone();
            changed[231..263].copy_from_slice(&key);
            assert_eq!(read(changed), Err(AnewError::KeyNotUsable), "{key:?}");
        }
        // An empty record whose fill is not all zeros is read as an offer,
        // and refused as one.
        let mut empty = Anew::Empty.to_value().unwrap();
        empty[16_273] = 1;
        assert!(read(empty).is_err());
    }

    /// A message, a clearing and an anew record in a slot named for another
    /// key than the one that signed it are taken as nothing; so is a list
    /// of the messages channel, and a message out of its place in the ring.
    #[test]
    fn a_message_or_an_anew_record_in_another_keys_slot_is_not_taken() {
        let (laptop, desktop) = (device(1).public_key(), device(2).public_key());
        let message = Value::Other(smallest().to_value().unwrap());
        let clearing = Value::Other(clearing_value());
        let anew = Value::Other(Anew::Empty.to_value().unwrap());
        let theirs = message_name(&desktop, 0).unwrap();
        let their_anew = anew_name(&desktop).unwrap();
        assert_eq!(
            take(&theirs, &laptop, 128, &message),
            Err(NotShared::NotInItsSlots)
        );
        assert_eq!(
            take(&theirs, &laptop, 129, &clearing),
            Err(NotShared::NotInItsSlots)
        );
        assert_eq!(
            take(&their_anew, &laptop, 1, &anew),
            Err(NotShared::NotInItsSlots)
        );
        // In the signer's own slots each is taken.
        assert_eq!(
            take(&theirs, &desktop, 128, &message),
            Ok(SharedTaken::Message {
                number: 64,
                message: smallest()
            })
        );
        assert_eq!(
            take(&theirs, &desktop, 129, &clearing),
            Ok(SharedTaken::Clearing { number: 64 })
        );
        assert_eq!(
            take(&their_anew, &desktop, 1, &anew),
            Ok(SharedTaken::Anew(Anew::Empty))
        );
        // A list of the messages channel is no slot of a shared channel.
        let list = Value::Other(ReadMarks::default().to_value().unwrap());
        assert_eq!(
            take(&read_name(&desktop).unwrap(), &desktop, 1, &list),
            Err(NotShared::NotInItsSlots)
        );
        // Number 65 in slot 0.
        assert_eq!(
            take(&theirs, &desktop, 130, &message),
            Err(NotShared::NotInItsSlots)
        );
        // A value of the other kind in each slot.
        assert!(matches!(
            take(&theirs, &desktop, 128, &anew),
            Err(NotShared::Message(_))
        ));
        assert!(matches!(
            take(&theirs, &desktop, 129, &message),
            Err(NotShared::Message(_))
        ));
        assert!(matches!(
            take(&their_anew, &desktop, 1, &message),
            Err(NotShared::Anew(AnewError::Length(1_936)))
        ));
        // The name: `anew/` and the key as it is written, 75 bytes.
        assert_eq!(
            their_anew,
            format!("anew/{}", encode_public_key(&desktop).unwrap())
        );
        assert_eq!(their_anew.len(), 75);
    }
}
