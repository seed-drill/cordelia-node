//! A shared channel's card, and the share that hands it to another
//! person's device (decision 2026-10-10 §2.1, §3.1).
//!
//! ## The card
//!
//! A shared channel is made from a seed of 32 bytes from the operating
//! system's random source, and lives at one or two relays. Its card is the
//! two together: what a device needs to hold the channel. A relay is named
//! by its key alone, and a card holds no host. Every length is big-endian.
//!
//! ```text
//! seed     32
//! relays   a count of one byte, 1 or 2; then each relay's key, 32 bytes,
//!          sorted, each once
//! ```
//!
//! A card of two relays is 97 bytes. The channel's secret is derived from
//! the seed under `cordelia v2 shared` and the hash of the relays
//! ([`crate::derive`]), so a card with other relays is another channel.
//! Only a card gives that secret, and a card is made only by [`Card::make`]
//! or read from bytes: never from the person secret, a name or a channel's
//! ID. What writes a share, and what seals a seed when a channel is made
//! anew ([`crate::shared`]), take a card.
//!
//! ## The share
//!
//! One entry in the share pair channel of the sharer and the taker
//! ([`crate::derive::share_pair_secret`]), under the name `share/` and the
//! channel's ID in hex. Its value, of kind 2 and of exactly
//! `SHARE_VALUE_BYTES` (407) bytes, seals at 512:
//!
//! ```text
//! form     1    1
//! made     8    seconds since 1970, by the sharer's clock
//! for      32   the taker's key
//! card     65 or 97
//! fill     the rest, zeros
//! ```
//!
//! Nothing else: no name of the sharer's for the channel, no label, no list
//! of members, and nothing of the sharer's own.

use std::fmt;

use cordelia_core::protocol::{
    LABEL_SHARED_RELAYS, SHARE_PREFIX, SHARE_VALUE_BYTES, SHARED_MAX_RELAYS, SHARED_SEED_BYTES,
};
use ring::rand::{SecureRandom, SystemRandom};

use crate::CryptoError;
use crate::derive;
use crate::entry::Value;
use crate::statement::Reader;

/// The first byte of a share's value.
const FORM_SHARE: u8 = 1;

/// Why bytes are no card or no share, or why one was not made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    #[error("a shared channel lives at one relay at least")]
    NoRelay,

    #[error("a shared channel lives at two relays at most, and this names {0}")]
    TooManyRelays(usize),

    #[error("a card names one relay twice")]
    RelayTwice,

    #[error("a card's relays are not in their one order")]
    RelaysNotInOrder,

    #[error("a card ends before it is whole, or has bytes after its end")]
    CardLength,

    #[error("a share holds a value that is not of kind 2")]
    Kind,

    #[error("a share's value is 407 bytes, and this is {0}")]
    Length(usize),

    #[error("a share's value is of form 1, and this is of form {0}")]
    Form(u8),

    #[error("a share's fields run past its value")]
    Field,

    #[error("what follows a share's fields is not all zeros")]
    Fill,

    #[error("a seed was not made: {0}")]
    Crypto(String),
}

/// The relays a shared channel lives at, by key alone, in their one form:
/// one or two, sorted, each once (decision 2026-10-10 §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relays(Vec<[u8; 32]>);

impl Relays {
    /// The relays of these keys, in their one order. A key given twice, no
    /// key, and more than two are refused.
    pub fn new(keys: &[[u8; 32]]) -> Result<Self, ShareError> {
        if keys.is_empty() {
            return Err(ShareError::NoRelay);
        }
        if keys.len() > SHARED_MAX_RELAYS {
            return Err(ShareError::TooManyRelays(keys.len()));
        }
        let mut sorted = keys.to_vec();
        sorted.sort_unstable();
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ShareError::RelayTwice);
        }
        Ok(Self(sorted))
    }

    /// The relays' keys, sorted.
    pub fn keys(&self) -> &[[u8; 32]] {
        &self.0
    }

    /// The list in its one form: a count of one byte, and each key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 * self.0.len());
        out.push(self.0.len() as u8);
        for key in &self.0 {
            out.extend_from_slice(key);
        }
        out
    }

    /// What the channel's secret is derived under, beside its label:
    /// SHA-256 of the relays' label and the list in its one form.
    pub fn hash(&self) -> [u8; 32] {
        let mut hashed = LABEL_SHARED_RELAYS.to_vec();
        hashed.extend_from_slice(&self.to_bytes());
        crate::sha256(&hashed)
    }

    /// Read a list in its one form from the front of `reader`, and nothing
    /// else: a count that is not 1 or 2, a key twice, and keys out of their
    /// order are refused. Another order would be another channel.
    pub(crate) fn read(reader: &mut Reader) -> Result<Self, ShareError> {
        let count = usize::from(reader.array::<1>().ok_or(ShareError::CardLength)?[0]);
        if count == 0 {
            return Err(ShareError::NoRelay);
        }
        if count > SHARED_MAX_RELAYS {
            return Err(ShareError::TooManyRelays(count));
        }
        let keys = (0..count)
            .map(|_| reader.array().ok_or(ShareError::CardLength))
            .collect::<Result<Vec<[u8; 32]>, _>>()?;
        for pair in keys.windows(2) {
            if pair[0] == pair[1] {
                return Err(ShareError::RelayTwice);
            }
            if pair[0] > pair[1] {
                return Err(ShareError::RelaysNotInOrder);
            }
        }
        Ok(Self(keys))
    }

    /// Read a list from its one form, and from nothing else.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShareError> {
        let mut reader = Reader::new(bytes);
        let relays = Self::read(&mut reader)?;
        if !reader.is_empty() {
            return Err(ShareError::CardLength);
        }
        Ok(relays)
    }
}

/// What a device needs to hold a shared channel: its seed and its relays
/// (decision 2026-10-10 §2.1). It is the one thing that a share hands, and
/// that an anew record seals.
#[derive(Clone, PartialEq, Eq)]
pub struct Card {
    seed: [u8; SHARED_SEED_BYTES],
    relays: Relays,
}

// A card is not printed for debugging: its seed is the channel.
impl fmt::Debug for Card {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Card")
            .field("relays", &self.relays)
            .finish_non_exhaustive()
    }
}

impl Card {
    /// A new shared channel at `relays`: a seed from the operating system's
    /// random source (decision 2026-10-10 §2.1). Nothing derives a seed.
    pub fn make(relays: Relays) -> Result<Self, ShareError> {
        let mut seed = [0u8; SHARED_SEED_BYTES];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| ShareError::Crypto("RNG failure".into()))?;
        Ok(Self { seed, relays })
    }

    /// The card of a seed that was sealed in an anew record, at the relays
    /// the record names: the new channel that the record offers.
    pub(crate) fn of(seed: [u8; SHARED_SEED_BYTES], relays: Relays) -> Self {
        Self { seed, relays }
    }

    /// The seed, for the one thing that seals it: an anew record.
    pub(crate) fn seed(&self) -> &[u8; SHARED_SEED_BYTES] {
        &self.seed
    }

    pub fn relays(&self) -> &Relays {
        &self.relays
    }

    /// The channel's secret (decision 2026-10-10 §2.1). From it come the
    /// channel's entry key, slot key, signing key and ID, as from every
    /// channel's secret.
    pub fn secret(&self) -> Result<[u8; 32], CryptoError> {
        derive::shared_secret(&self.seed, &self.relays)
    }

    /// The channel's ID: the public half of the signing key its secret
    /// gives.
    pub fn channel_id(&self) -> Result<[u8; 32], CryptoError> {
        derive::channel_id(&self.secret()?)
    }

    /// The card in its one form: the seed, then the relays.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.seed.to_vec();
        out.extend_from_slice(&self.relays.to_bytes());
        out
    }

    /// Read a card from the front of `reader`.
    pub(crate) fn read(reader: &mut Reader) -> Result<Self, ShareError> {
        let seed = reader.array().ok_or(ShareError::CardLength)?;
        let relays = Relays::read(reader)?;
        Ok(Self { seed, relays })
    }

    /// Read a card from its one form, and from nothing else: what a filing
    /// in a person's list holds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShareError> {
        let mut reader = Reader::new(bytes);
        let card = Self::read(&mut reader)?;
        if !reader.is_empty() {
            return Err(ShareError::CardLength);
        }
        Ok(card)
    }
}

/// A share: a card for one key, made at a time (decision 2026-10-10 §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// When it was made, in seconds since 1970, by the sharer's clock.
    pub made: u64,
    /// The key of the device it is for: the taker's.
    pub for_key: [u8; 32],
    pub card: Card,
}

impl Share {
    /// The share's value, filled with zeros to its one length.
    pub fn to_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SHARE_VALUE_BYTES);
        out.push(FORM_SHARE);
        out.extend_from_slice(&self.made.to_be_bytes());
        out.extend_from_slice(&self.for_key);
        out.extend_from_slice(&self.card.to_bytes());
        out.resize(SHARE_VALUE_BYTES, 0);
        out
    }

    /// Read a share from an entry's value, as a taker does (decision
    /// 2026-10-10 §3.2, rule 4): of kind 2, of its one length and form,
    /// with a card of its form and a fill of zeros.
    pub fn from_value(value: &Value) -> Result<Self, ShareError> {
        let Value::Other(bytes) = value else {
            return Err(ShareError::Kind);
        };
        if bytes.len() != SHARE_VALUE_BYTES {
            return Err(ShareError::Length(bytes.len()));
        }
        let mut reader = Reader::new(bytes);
        let form = reader.array::<1>().ok_or(ShareError::Field)?[0];
        if form != FORM_SHARE {
            return Err(ShareError::Form(form));
        }
        let made = reader.u64().ok_or(ShareError::Field)?;
        let for_key = reader.array().ok_or(ShareError::Field)?;
        let card = Card::read(&mut reader)?;
        if reader.rest().iter().any(|byte| *byte != 0) {
            return Err(ShareError::Fill);
        }
        Ok(Self {
            made,
            for_key,
            card,
        })
    }
}

/// The name of the share of the channel `channel`: `share/` and the
/// channel's ID in hex (decision 2026-10-10 §3.1).
pub fn share_name(channel: &[u8; 32]) -> String {
    format!("{SHARE_PREFIX}{}", hex::encode(channel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Entry, Inside};
    use crate::identity::NodeIdentity;
    use cordelia_core::protocol::{LABEL_SHARED, LABELS};
    use serde_json::Value as Json;

    fn relay(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn card(seed: u8, relays: &[[u8; 32]]) -> Card {
        Card::of([seed; 32], Relays::new(relays).unwrap())
    }

    fn device(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32]).unwrap()
    }

    /// A card is the seed and the relays by key, sorted, behind their
    /// count: 65 bytes at one relay and 97 at two, whatever order the keys
    /// are given in. It reads back as it was written.
    #[test]
    fn a_card_names_its_relays_by_key_alone_in_one_form() {
        let one = card(7, &[relay(2)]);
        let mut expected = vec![7; 32];
        expected.push(1);
        expected.extend_from_slice(&relay(2));
        assert_eq!(one.to_bytes(), expected);
        assert_eq!(one.to_bytes().len(), 65);

        let two = card(7, &[relay(9), relay(2)]);
        assert_eq!(two, card(7, &[relay(2), relay(9)]));
        let mut expected = vec![7; 32];
        expected.push(2);
        expected.extend_from_slice(&relay(2));
        expected.extend_from_slice(&relay(9));
        assert_eq!(two.to_bytes(), expected);
        assert_eq!(two.to_bytes().len(), 97);
        assert_eq!(two.relays().keys(), &[relay(2), relay(9)]);

        for card in [one, two] {
            assert_eq!(Card::from_bytes(&card.to_bytes()).unwrap(), card);
            let relays = card.relays().to_bytes();
            assert_eq!(Relays::from_bytes(&relays).unwrap(), *card.relays());
        }
        // A card prints no seed.
        assert!(!format!("{:?}", card(0xab, &[relay(1)])).contains("171"));
    }

    /// A card is made from a seed of the operating system's random source:
    /// two cards made at the same relays are two channels, and neither seed
    /// is zeros.
    #[test]
    fn a_card_is_made_from_a_random_seed() {
        let relays = Relays::new(&[relay(1)]).unwrap();
        let (one, two) = (
            Card::make(relays.clone()).unwrap(),
            Card::make(relays).unwrap(),
        );
        assert_ne!(one.seed(), two.seed());
        assert_ne!(one.channel_id().unwrap(), two.channel_id().unwrap());
        assert_ne!(one.seed(), &[0; 32]);
        assert_eq!(one.relays(), two.relays());
    }

    /// A card in which one key is named twice, of no relay, or of more than
    /// two, is refused, made or read; so is a list out of its order, and a
    /// card that ends early or runs on.
    #[test]
    fn a_card_with_a_key_twice_or_of_more_than_two_relays_is_refused() {
        assert_eq!(
            Relays::new(&[relay(1), relay(1)]),
            Err(ShareError::RelayTwice)
        );
        assert_eq!(Relays::new(&[]), Err(ShareError::NoRelay));
        assert_eq!(
            Relays::new(&[relay(1), relay(2), relay(3)]),
            Err(ShareError::TooManyRelays(3))
        );

        let read = |count: u8, keys: &[[u8; 32]]| {
            let mut bytes = vec![5; 32];
            bytes.push(count);
            for key in keys {
                bytes.extend_from_slice(key);
            }
            Card::from_bytes(&bytes)
        };
        assert_eq!(read(2, &[relay(1), relay(1)]), Err(ShareError::RelayTwice));
        assert_eq!(read(0, &[]), Err(ShareError::NoRelay));
        assert_eq!(
            read(3, &[relay(1), relay(2), relay(3)]),
            Err(ShareError::TooManyRelays(3))
        );
        assert_eq!(
            read(2, &[relay(2), relay(1)]),
            Err(ShareError::RelaysNotInOrder)
        );
        assert_eq!(read(2, &[relay(1)]), Err(ShareError::CardLength));
        assert_eq!(read(1, &[relay(1), relay(2)]), Err(ShareError::CardLength));
        assert_eq!(Card::from_bytes(&[5; 31]), Err(ShareError::CardLength));
        let mut longer = card(5, &[relay(1)]).to_bytes();
        longer.push(0);
        assert_eq!(Card::from_bytes(&longer), Err(ShareError::CardLength));
        assert_eq!(
            Relays::from_bytes(&longer[32..]),
            Err(ShareError::CardLength)
        );
        // The control: in its one form, each reads.
        assert!(read(1, &[relay(1)]).is_ok());
        assert!(read(2, &[relay(1), relay(2)]).is_ok());
    }

    /// The secret of a shared channel is HKDF of its seed under `cordelia
    /// v2 shared` and the hash of its relays (decision 2026-10-10 §2.1):
    /// the seed and relays of the published vector give its ID, another
    /// list of relays gives another, and the label begins no other in
    /// `LABELS`, and none begins it.
    #[test]
    fn a_shared_channel_is_derived_under_its_own_label_and_its_relays() {
        let file: Json = serde_json::from_str(crate::vectors::published()).unwrap();
        let shared = &file["kinds"]["shared"];
        let key = |value: &Json| -> [u8; 32] {
            hex::decode(value.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let seed = key(&shared["seed"]);
        let keys: Vec<[u8; 32]> = shared["relays"]
            .as_array()
            .unwrap()
            .iter()
            .map(key)
            .collect();
        let card = Card::of(seed, Relays::new(&keys).unwrap());
        assert_eq!(card.channel_id().unwrap(), key(&shared["id"]));
        assert_eq!(card.secret().unwrap(), key(&shared["secret"]));

        // What it is, worked out by hand.
        let mut list = vec![keys.len() as u8];
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        for relay in &sorted {
            list.extend_from_slice(relay);
        }
        let mut hashed = b"cordelia v2 relays".to_vec();
        hashed.extend_from_slice(&list);
        let mut info = b"cordelia v2 shared".to_vec();
        info.extend_from_slice(&crate::sha256(&hashed));
        assert_eq!(
            card.secret().unwrap(),
            crate::ecies::hkdf_sha256(&seed, &[], &info).unwrap()
        );

        // Another list of relays is another channel: one of the two, or
        // another key.
        let one = Card::of(seed, Relays::new(&keys[..1]).unwrap());
        let other = Card::of(seed, Relays::new(&[keys[0], [0x99; 32]]).unwrap());
        let ids = [
            card.channel_id().unwrap(),
            one.channel_id().unwrap(),
            other.channel_id().unwrap(),
        ];
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            3
        );
        assert_eq!(
            hex::encode(one.channel_id().unwrap()),
            shared["one_relay_id"].as_str().unwrap()
        );

        // The seed taken as a person secret gives none of the person's own
        // channels this one is.
        for own in [
            derive::personal_secret(&seed).unwrap(),
            derive::messages_secret(&seed).unwrap(),
            derive::own_secret(&seed, "~").unwrap(),
        ] {
            assert_ne!(own, card.secret().unwrap());
        }

        // The label begins no other, and none begins it.
        assert_eq!(LABEL_SHARED, b"cordelia v2 shared");
        for other in LABELS.iter().filter(|other| **other != LABEL_SHARED) {
            assert!(!other.starts_with(LABEL_SHARED), "{other:?}");
            assert!(!LABEL_SHARED.starts_with(other), "{other:?}");
        }
    }

    /// A share opened is its form, its time, the key it is for, the seed
    /// and the relays, and zeros: no 32 bytes of it are the person secret
    /// of the published vectors, or any secret or key derived from it.
    #[test]
    fn a_share_entry_holds_only_a_seed_and_relays() {
        let (alice, bob) = (device(1), device(2));
        let card = Card::make(Relays::new(&[relay(3), relay(4)]).unwrap()).unwrap();
        let share = Share {
            made: 1_800_000_000,
            for_key: bob.public_key(),
            card: card.clone(),
        };
        let pair = derive::share_pair_secret(&alice, &bob.public_key()).unwrap();
        let name = share_name(&card.channel_id().unwrap());
        let inside = Inside {
            name: name.clone(),
            value: Value::Other(share.to_value()),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&pair, &alice, 1_800_000_000, &inside).unwrap();
        let opened = entry.check().unwrap().open(&pair).unwrap();
        assert_eq!(opened.name, name);
        let bytes = opened.value.bytes().to_vec();

        let mut expected = vec![1];
        expected.extend_from_slice(&1_800_000_000u64.to_be_bytes());
        expected.extend_from_slice(&bob.public_key());
        expected.extend_from_slice(card.seed());
        expected.extend_from_slice(&[2]);
        expected.extend_from_slice(&relay(3));
        expected.extend_from_slice(&relay(4));
        assert_eq!(expected.len(), 138);
        assert_eq!(&bytes[..138], &expected[..]);
        assert!(bytes[138..].iter().all(|byte| *byte == 0));
        assert_eq!(Share::from_value(&opened.value).unwrap(), share);

        // Nothing of the person's own, over the published vectors.
        let file: Json = serde_json::from_str(crate::vectors::published()).unwrap();
        let person: [u8; 32] = hex::decode(file["kinds"]["person_secret"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut secrets = vec![
            person,
            derive::personal_secret(&person).unwrap(),
            derive::messages_secret(&person).unwrap(),
            derive::own_secret(&person, "~").unwrap(),
            derive::own_secret(&person, "github.com/owner/repo").unwrap(),
        ];
        for secret in secrets.clone() {
            secrets.push(derive::entry_key(&secret).unwrap());
            secrets.push(derive::slot_key(&secret).unwrap());
            secrets.push(*derive::signing_key(&secret).unwrap().seed());
        }
        assert_eq!(secrets.len(), 20);
        for window in bytes.windows(32) {
            assert!(!secrets.iter().any(|secret| secret == window));
        }
    }

    /// A share's value is 407 bytes, and seals at 512 through `Entry::seal`
    /// as it is, at one relay and at two.
    #[test]
    fn a_share_is_407_bytes_and_seals_at_512() {
        let (alice, bob) = (device(1), device(2));
        let pair = derive::share_pair_secret(&alice, &bob.public_key()).unwrap();
        for relays in [&[relay(3)][..], &[relay(3), relay(4)]] {
            let card = card(9, relays);
            let value = Share {
                made: u64::MAX,
                for_key: bob.public_key(),
                card: card.clone(),
            }
            .to_value();
            assert_eq!(value.len(), SHARE_VALUE_BYTES);
            assert_eq!(value.len(), 407);
            let inside = Inside {
                name: share_name(&card.channel_id().unwrap()),
                value: Value::Other(value),
                chain: Some(Vec::new()),
            };
            let entry = Entry::seal(&pair, &alice, 1, &inside).unwrap();
            assert_eq!(entry.content.len(), 512);
        }
    }

    /// A taker refuses a share of another kind, length or form, with a
    /// card that is not of its form, or a fill that is not zeros.
    #[test]
    fn a_reader_refuses_a_share_that_is_not_one() {
        let share = Share {
            made: 5,
            for_key: [8; 32],
            card: card(9, &[relay(3), relay(4)]),
        };
        let value = share.to_value();
        assert_eq!(
            Share::from_value(&Value::Other(value.clone())).unwrap(),
            share
        );
        assert_eq!(
            Share::from_value(&Value::Text("a".repeat(407))),
            Err(ShareError::Kind)
        );
        for length in [406, 408] {
            let mut changed = value.clone();
            changed.resize(length, 0);
            assert_eq!(
                Share::from_value(&Value::Other(changed)),
                Err(ShareError::Length(length))
            );
        }
        for form in [0, 2, 5] {
            let mut changed = value.clone();
            changed[0] = form;
            assert_eq!(
                Share::from_value(&Value::Other(changed)),
                Err(ShareError::Form(form))
            );
        }
        // The card's count, at 41 + 32: three relays, and none.
        for (count, refused) in [(3, ShareError::TooManyRelays(3)), (0, ShareError::NoRelay)] {
            let mut changed = value.clone();
            changed[73] = count;
            assert_eq!(Share::from_value(&Value::Other(changed)), Err(refused));
        }
        // The two relays the other way round.
        let mut changed = value.clone();
        changed[74..106].copy_from_slice(&relay(4));
        changed[106..138].copy_from_slice(&relay(3));
        assert_eq!(
            Share::from_value(&Value::Other(changed)),
            Err(ShareError::RelaysNotInOrder)
        );
        for at in [138, 406] {
            let mut changed = value.clone();
            changed[at] = 1;
            assert_eq!(
                Share::from_value(&Value::Other(changed)),
                Err(ShareError::Fill),
                "{at}"
            );
        }
    }

    /// A share's name is `share/` and the channel's ID in hex: 70 bytes.
    #[test]
    fn a_shares_name_is_its_channels_id_in_hex() {
        let id = card(9, &[relay(3)]).channel_id().unwrap();
        let name = share_name(&id);
        assert_eq!(name, format!("share/{}", hex::encode(id)));
        assert_eq!(name.len(), 70);
    }
}
