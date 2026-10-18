//! A device's list in the personal channel: the shared channels the person
//! holds, the drops, the subscriptions and the labels, each act signed by
//! the device that made it (decision 2026-10-10 §3.4).
//!
//! Each device writes one list, under `shared/` and its key, sealed under
//! the personal channel's entry key, of kind 2. A reader takes from that
//! slot only the entry its key signed. What is here is the list's form,
//! byte for byte, and an act's signature; which act a device takes, and
//! when, is the node's to say.
//!
//! ## The form
//!
//! Every length is big-endian. A count of a part is one byte.
//!
//! ```text
//! form            1    1
//! fetched         8    the device's last whole fetch of the personal channel
//! filings         a count, 0 to 16; then each: the channel's ID 32; the
//!                 card, 65 or 97; the name the person files it under,
//!                 behind a length of one byte; how it came, a byte (0 made
//!                 here; 1 taken from a key, and the key, 32; 2 moved to
//!                 from a channel, and its ID, 32); and its act
//! drops           a count, 0 to 64; then each: a channel's ID 32; its act
//! subscriptions   a count, 0 to 32; then each: the channel's ID 32; the
//!                 agent's name, behind a length of one byte; its state, a
//!                 byte (1 subscribed, 0 not); and its act
//! labels          a count, 0 to 64; then each: a key 32; its label, behind
//!                 a length of two bytes as a statement writes a label, of
//!                 no bytes where there is none; and its act
//! ```
//!
//! An act is the item's time 8, its count 8, its maker's key 32, and its
//! maker's signature 64. The maker signs, under its device key, `cordelia
//! v2 act`, the item's kind (1 a filing, 2 a drop, 3 a subscription, 4 a
//! label) and every other field of the item, as they are written here up to
//! the signature. A copy keeps both, so a list holds acts made on other
//! devices exactly as they were made. At every bound a list is 41,341
//! bytes, which seals at 65,536.
//!
//! An item is a channel (a filing or a drop), a channel and an agent (a
//! subscription), or a key (a label): a list holds one act on each.

use cordelia_core::protocol::{
    AGENT_MESSAGE_NAME_MAX_BYTES, LABEL_SHARED_ACT, PERSONAL_SHARED_PREFIX, SHARED_ACT_TIME_MAX,
    SHARED_LABEL_MAX_BYTES, SHARED_LIST_MAX_VALUE_BYTES, SHARED_MAX_CHANNELS, SHARED_MAX_DROPPED,
    SHARED_MAX_LABELS, SHARED_MAX_SUBSCRIPTIONS,
};

use crate::CryptoError;
use crate::bech32::encode_public_key;
use crate::entry::Value;
use crate::identity::{NodeIdentity, is_usable_public_key, verify_signature};
use crate::share::{Card, ShareError};
use crate::statement::{Reader, put_count};

/// The first byte of a list's value.
const FORM_LIST: u8 = 1;

/// The kinds of item, which an act's signature binds.
const KIND_FILING: u8 = 1;
const KIND_DROP: u8 = 2;
const KIND_SUBSCRIPTION: u8 = 3;
const KIND_LABEL: u8 = 4;

/// How a channel came to be filed.
const CAME_MADE: u8 = 0;
const CAME_TAKEN: u8 = 1;
const CAME_MOVED: u8 = 2;

/// The states of a subscription.
const SUBSCRIBED: u8 = 1;
const NOT_SUBSCRIBED: u8 = 0;

/// Why a list is none, or was not written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    #[error("a list holds a value that is not of kind 2")]
    Kind,

    #[error("a list is of form 1, and this is of form {0}")]
    Form(u8),

    #[error("a list ends before it is whole")]
    Truncated,

    #[error("there are bytes after the list's end")]
    TrailingBytes,

    #[error("a list holds at most {most} {part}, and this holds {count}")]
    TooMany {
        part: &'static str,
        most: usize,
        count: usize,
    },

    #[error("a list holds two acts on one item")]
    ItemTwice,

    #[error("a channel's name or an agent's in a list is not a name")]
    Name,

    #[error("a label is at most 64 bytes of text, or none")]
    Label,

    #[error("a filing came in one of three ways, and this says {0}")]
    Came(u8),

    #[error("a subscription is held or not, and this says {0}")]
    State(u8),

    #[error("a filing's card is not a card: {0}")]
    Card(ShareError),

    #[error("a list is at most 41341 bytes, and this is {0}")]
    TooLong(usize),

    #[error("a list's fetched time is at most 2^40, and this is {0}")]
    FetchedPastTheBound(u64),
}

/// How a channel came to be filed (decision 2026-10-10 §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Came {
    /// Made on a device of the person's, by `shared new` or `shared anew`.
    Made,
    /// Taken from the share of this key.
    Taken([u8; 32]),
    /// Moved to from the channel of this ID, made anew.
    Moved([u8; 32]),
}

/// A channel the person holds, under the name the person files it under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filing {
    pub channel: [u8; 32],
    pub card: Card,
    pub name: String,
    pub came: Came,
}

/// A channel the person dropped or moved from: it takes no place among the
/// filings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    pub channel: [u8; 32],
}

/// An agent of the person's, subscribed to a channel or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub channel: [u8; 32],
    pub agent: String,
    pub subscribed: bool,
}

/// The label the person gives a key, or none where it was removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub key: [u8; 32],
    pub label: Option<String>,
}

/// What each kind of item is written as: a filing, a drop, a subscription
/// or a label.
pub trait Item: Sized {
    /// The byte its maker's signature binds.
    const KIND: u8;

    /// Its fields, as a list writes them before its act. Refused where a
    /// reader would refuse them.
    fn write(&self, out: &mut Vec<u8>, is_a_name: &dyn Fn(&str) -> bool) -> Result<(), ListError>;

    /// What the item is about: two acts on one item stand for one.
    fn item(&self) -> Vec<u8>;

    /// Whether its fields agree with each other. A filing's ID is its
    /// card's.
    fn agrees(&self) -> bool {
        true
    }
}

/// How each kind of item's fields are read from the front of a list.
type ReadItem<T> = fn(&mut Reader, &dyn Fn(&str) -> bool) -> Result<T, ListError>;

impl Item for Filing {
    const KIND: u8 = KIND_FILING;

    fn write(&self, out: &mut Vec<u8>, is_a_name: &dyn Fn(&str) -> bool) -> Result<(), ListError> {
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.card.to_bytes());
        put_name(out, &self.name, is_a_name)?;
        match self.came {
            Came::Made => out.push(CAME_MADE),
            Came::Taken(key) => {
                out.push(CAME_TAKEN);
                out.extend_from_slice(&key);
            }
            Came::Moved(channel) => {
                out.push(CAME_MOVED);
                out.extend_from_slice(&channel);
            }
        }
        Ok(())
    }

    fn item(&self) -> Vec<u8> {
        self.channel.to_vec()
    }

    fn agrees(&self) -> bool {
        self.card.channel_id().ok() == Some(self.channel)
    }
}

impl Filing {
    fn read(reader: &mut Reader, is_a_name: &dyn Fn(&str) -> bool) -> Result<Self, ListError> {
        let channel = reader.array().ok_or(ListError::Truncated)?;
        let card = Card::read(reader).map_err(|error| match error {
            ShareError::CardLength => ListError::Truncated,
            other => ListError::Card(other),
        })?;
        let name = name_in(reader, is_a_name)?;
        let came = match byte(reader)? {
            CAME_MADE => Came::Made,
            CAME_TAKEN => Came::Taken(reader.array().ok_or(ListError::Truncated)?),
            CAME_MOVED => Came::Moved(reader.array().ok_or(ListError::Truncated)?),
            other => return Err(ListError::Came(other)),
        };
        Ok(Self {
            channel,
            card,
            name,
            came,
        })
    }
}

impl Item for Dropped {
    const KIND: u8 = KIND_DROP;

    fn write(&self, out: &mut Vec<u8>, _: &dyn Fn(&str) -> bool) -> Result<(), ListError> {
        out.extend_from_slice(&self.channel);
        Ok(())
    }

    fn item(&self) -> Vec<u8> {
        self.channel.to_vec()
    }
}

impl Dropped {
    fn read(reader: &mut Reader, _: &dyn Fn(&str) -> bool) -> Result<Self, ListError> {
        Ok(Self {
            channel: reader.array().ok_or(ListError::Truncated)?,
        })
    }
}

impl Item for Subscription {
    const KIND: u8 = KIND_SUBSCRIPTION;

    fn write(&self, out: &mut Vec<u8>, is_a_name: &dyn Fn(&str) -> bool) -> Result<(), ListError> {
        out.extend_from_slice(&self.channel);
        put_name(out, &self.agent, is_a_name)?;
        out.push(if self.subscribed {
            SUBSCRIBED
        } else {
            NOT_SUBSCRIBED
        });
        Ok(())
    }

    fn item(&self) -> Vec<u8> {
        let mut item = self.channel.to_vec();
        item.extend_from_slice(self.agent.as_bytes());
        item
    }
}

impl Subscription {
    fn read(reader: &mut Reader, is_a_name: &dyn Fn(&str) -> bool) -> Result<Self, ListError> {
        let channel = reader.array().ok_or(ListError::Truncated)?;
        let agent = name_in(reader, is_a_name)?;
        let subscribed = match byte(reader)? {
            SUBSCRIBED => true,
            NOT_SUBSCRIBED => false,
            other => return Err(ListError::State(other)),
        };
        Ok(Self {
            channel,
            agent,
            subscribed,
        })
    }
}

impl Item for Label {
    const KIND: u8 = KIND_LABEL;

    fn write(&self, out: &mut Vec<u8>, _: &dyn Fn(&str) -> bool) -> Result<(), ListError> {
        let label = self.label.as_deref().unwrap_or("");
        // A label of no bytes would read back as none.
        if self.label.as_deref() == Some("") || label.len() > SHARED_LABEL_MAX_BYTES {
            return Err(ListError::Label);
        }
        out.extend_from_slice(&self.key);
        put_count(out, label.len());
        out.extend_from_slice(label.as_bytes());
        Ok(())
    }

    fn item(&self) -> Vec<u8> {
        self.key.to_vec()
    }
}

impl Label {
    fn read(reader: &mut Reader, _: &dyn Fn(&str) -> bool) -> Result<Self, ListError> {
        let key = reader.array().ok_or(ListError::Truncated)?;
        let length = reader.count().ok_or(ListError::Truncated)?;
        if length > SHARED_LABEL_MAX_BYTES {
            return Err(ListError::Label);
        }
        let label = match reader.take(length).ok_or(ListError::Truncated)? {
            [] => None,
            label => Some(
                std::str::from_utf8(label)
                    .map_err(|_| ListError::Label)?
                    .to_string(),
            ),
        };
        Ok(Self { key, label })
    }
}

/// An item, with its time, its count, its maker's key and its maker's
/// signature (decision 2026-10-10 §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Act<T> {
    pub item: T,
    /// When the act was made, in seconds since 1970, as its maker dated it.
    pub time: u64,
    /// The item's count: 0 below the time bound, and what orders acts at
    /// it.
    pub count: u64,
    /// The key of the device that made it.
    pub maker: [u8; 32],
    /// The maker's signature, under its device key.
    pub signature: [u8; 64],
}

impl<T: Item> Act<T> {
    /// The act that `maker` makes on `item`, dated `time` with `count`,
    /// signed by it.
    pub fn make(
        item: T,
        time: u64,
        count: u64,
        maker: &NodeIdentity,
        is_a_name: impl Fn(&str) -> bool,
    ) -> Result<Self, ListError> {
        let mut act = Self {
            item,
            time,
            count,
            maker: maker.public_key(),
            signature: [0u8; 64],
        };
        act.signature = maker.sign(&act.signed(&is_a_name)?);
        Ok(act)
    }

    /// What the maker signs: the label, the item's kind, and the item's
    /// fields with its time, its count and its maker's key, as a list
    /// writes them.
    fn signed(&self, is_a_name: &dyn Fn(&str) -> bool) -> Result<Vec<u8>, ListError> {
        let mut signed = LABEL_SHARED_ACT.to_vec();
        signed.push(T::KIND);
        self.write_unsigned(&mut signed, is_a_name)?;
        Ok(signed)
    }

    fn write_unsigned(
        &self,
        out: &mut Vec<u8>,
        is_a_name: &dyn Fn(&str) -> bool,
    ) -> Result<(), ListError> {
        self.item.write(out, is_a_name)?;
        out.extend_from_slice(&self.time.to_be_bytes());
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.maker);
        Ok(())
    }

    fn write(&self, out: &mut Vec<u8>, is_a_name: &dyn Fn(&str) -> bool) -> Result<(), ListError> {
        self.write_unsigned(out, is_a_name)?;
        out.extend_from_slice(&self.signature);
        Ok(())
    }

    /// The act as a list writes it: its item's fields, its time, its
    /// count, its maker's key and its signature. Two acts on one item that
    /// agree in all else are ordered by these bytes (decision 2026-10-10
    /// §3.4), so that every device orders them alike.
    pub fn written(&self) -> Result<Vec<u8>, ListError> {
        let mut out = Vec::new();
        self.write(&mut out, &|_| true)?;
        Ok(out)
    }

    fn read(
        reader: &mut Reader,
        read_item: ReadItem<T>,
        is_a_name: &dyn Fn(&str) -> bool,
    ) -> Result<Self, ListError> {
        let item = read_item(reader, is_a_name)?;
        Ok(Self {
            item,
            time: reader.u64().ok_or(ListError::Truncated)?,
            count: reader.u64().ok_or(ListError::Truncated)?,
            maker: reader.array().ok_or(ListError::Truncated)?,
            signature: reader.array().ok_or(ListError::Truncated)?,
        })
    }

    /// Whether the act's signature holds under its maker's key, over its
    /// label, its kind and its fields (decision 2026-10-10 §3.4). A maker's
    /// key that is not a usable public key is refused: under a point of
    /// small order anyone can make a signature that is accepted.
    pub fn signed_by_its_maker(&self) -> bool {
        let names = |_: &str| true;
        is_usable_public_key(&self.maker)
            && self
                .signed(&names)
                .is_ok_and(|signed| verify_signature(&self.maker, &signed, &self.signature))
    }

    /// Whether the act may be taken for what it says, before it is asked
    /// whose its maker is: its signature holds, its time and its count are
    /// each at most `SHARED_ACT_TIME_MAX`, and its fields agree (decision
    /// 2026-10-10 §3.4). Whether its maker counts, or is a removed key, is
    /// the node's to say with the statement and the records of addition.
    pub fn holds(&self) -> bool {
        self.time <= SHARED_ACT_TIME_MAX
            && self.count <= SHARED_ACT_TIME_MAX
            && self.item.agrees()
            && self.signed_by_its_maker()
    }
}

/// A device's list (decision 2026-10-10 §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SharedList {
    /// The time of the device's last whole fetch of the personal channel,
    /// by its clock.
    pub fetched: u64,
    pub filings: Vec<Act<Filing>>,
    pub drops: Vec<Act<Dropped>>,
    pub subscriptions: Vec<Act<Subscription>>,
    pub labels: Vec<Act<Label>>,
}

impl SharedList {
    /// The list's value. Refused where a reader would refuse it: a part
    /// past its bound, two acts on one item, a field that is not of its
    /// form.
    pub fn to_value(&self, is_a_name: impl Fn(&str) -> bool) -> Result<Vec<u8>, ListError> {
        self.check()?;
        let mut out = vec![FORM_LIST];
        out.extend_from_slice(&self.fetched.to_be_bytes());
        write_part(&mut out, &self.filings, &is_a_name)?;
        write_part(&mut out, &self.drops, &is_a_name)?;
        write_part(&mut out, &self.subscriptions, &is_a_name)?;
        write_part(&mut out, &self.labels, &is_a_name)?;
        if out.len() > SHARED_LIST_MAX_VALUE_BYTES {
            return Err(ListError::TooLong(out.len()));
        }
        Ok(out)
    }

    /// Read a list from an entry's value, as a reader does. `is_a_name`
    /// says whether a name is a name in its one spelling
    /// (`names::is_a_name` on a device). Whether each act holds is asked of
    /// it apart ([`Act::holds`]).
    pub fn from_value(value: &Value, is_a_name: impl Fn(&str) -> bool) -> Result<Self, ListError> {
        let Value::Other(bytes) = value else {
            return Err(ListError::Kind);
        };
        if bytes.len() > SHARED_LIST_MAX_VALUE_BYTES {
            return Err(ListError::TooLong(bytes.len()));
        }
        let mut reader = Reader::new(bytes);
        let form = byte(&mut reader)?;
        if form != FORM_LIST {
            return Err(ListError::Form(form));
        }
        let list = Self {
            fetched: reader.u64().ok_or(ListError::Truncated)?,
            filings: read_part(
                &mut reader,
                ("filings", SHARED_MAX_CHANNELS),
                Filing::read,
                &is_a_name,
            )?,
            drops: read_part(
                &mut reader,
                ("drops", SHARED_MAX_DROPPED),
                Dropped::read,
                &is_a_name,
            )?,
            subscriptions: read_part(
                &mut reader,
                ("subscriptions", SHARED_MAX_SUBSCRIPTIONS),
                Subscription::read,
                &is_a_name,
            )?,
            labels: read_part(
                &mut reader,
                ("labels", SHARED_MAX_LABELS),
                Label::read,
                &is_a_name,
            )?,
        };
        if !reader.is_empty() {
            return Err(ListError::TrailingBytes);
        }
        list.check()?;
        Ok(list)
    }

    /// The fetched time within its bound, each part within its bound, and
    /// one act on each item: a filing and a drop of one channel are one
    /// item.
    fn check(&self) -> Result<(), ListError> {
        if self.fetched > SHARED_ACT_TIME_MAX {
            return Err(ListError::FetchedPastTheBound(self.fetched));
        }
        for (part, most, count) in [
            ("filings", SHARED_MAX_CHANNELS, self.filings.len()),
            ("drops", SHARED_MAX_DROPPED, self.drops.len()),
            (
                "subscriptions",
                SHARED_MAX_SUBSCRIPTIONS,
                self.subscriptions.len(),
            ),
            ("labels", SHARED_MAX_LABELS, self.labels.len()),
        ] {
            if count > most {
                return Err(ListError::TooMany { part, most, count });
            }
        }
        let channels = self
            .filings
            .iter()
            .map(|act| act.item.item())
            .chain(self.drops.iter().map(|act| act.item.item()));
        once_each(channels)?;
        once_each(self.subscriptions.iter().map(|act| act.item.item()))?;
        once_each(self.labels.iter().map(|act| act.item.item()))
    }
}

/// The name of a device's list: `shared/` and the device's key as it is
/// written (decision 2026-10-10 §3.4).
pub fn list_name(device: &[u8; 32]) -> Result<String, CryptoError> {
    Ok(format!(
        "{PERSONAL_SHARED_PREFIX}{}",
        encode_public_key(device)?
    ))
}

fn write_part<T: Item>(
    out: &mut Vec<u8>,
    acts: &[Act<T>],
    is_a_name: &dyn Fn(&str) -> bool,
) -> Result<(), ListError> {
    out.push(acts.len() as u8);
    for act in acts {
        act.write(out, is_a_name)?;
    }
    Ok(())
}

/// A part of a list: its count, checked against its bound before anything
/// is read, and its acts.
fn read_part<T: Item>(
    reader: &mut Reader,
    (part, most): (&'static str, usize),
    read_item: ReadItem<T>,
    is_a_name: &dyn Fn(&str) -> bool,
) -> Result<Vec<Act<T>>, ListError> {
    let count = usize::from(byte(reader)?);
    if count > most {
        return Err(ListError::TooMany { part, most, count });
    }
    (0..count)
        .map(|_| Act::read(reader, read_item, is_a_name))
        .collect()
}

/// Every item once.
fn once_each(items: impl Iterator<Item = Vec<u8>>) -> Result<(), ListError> {
    let mut items: Vec<Vec<u8>> = items.collect();
    items.sort_unstable();
    if items.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ListError::ItemTwice);
    }
    Ok(())
}

fn byte(reader: &mut Reader) -> Result<u8, ListError> {
    Ok(reader.array::<1>().ok_or(ListError::Truncated)?[0])
}

/// A name behind a length of one byte: of 1 to 200 bytes, and a name.
fn put_name(
    out: &mut Vec<u8>,
    name: &str,
    is_a_name: &dyn Fn(&str) -> bool,
) -> Result<(), ListError> {
    if name.is_empty() || name.len() > AGENT_MESSAGE_NAME_MAX_BYTES || !is_a_name(name) {
        return Err(ListError::Name);
    }
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    Ok(())
}

fn name_in(reader: &mut Reader, is_a_name: &dyn Fn(&str) -> bool) -> Result<String, ListError> {
    let length = usize::from(byte(reader)?);
    if length > AGENT_MESSAGE_NAME_MAX_BYTES {
        return Err(ListError::Name);
    }
    let name = reader.take(length).ok_or(ListError::Truncated)?;
    match std::str::from_utf8(name) {
        Ok(name) if !name.is_empty() && is_a_name(name) => Ok(name.to_string()),
        _ => Err(ListError::Name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive;
    use crate::entry::{Entry, Inside};
    use crate::share::Relays;
    use cordelia_core::protocol::{MAX_ITEM_BYTES, entry_cost};

    /// A stand-in for `names::is_a_name`, which is the node's: a name of
    /// lower-case letters, digits and `~./-`, of any length, so that the
    /// list's own bounds are what refuse a long one.
    fn names(name: &str) -> bool {
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"~./-".contains(&b))
    }

    fn device(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32]).unwrap()
    }

    fn card(seed: u8) -> Card {
        Card::of([seed; 32], Relays::new(&[[3; 32], [4; 32]]).unwrap())
    }

    fn filing(seed: u8, name: &str) -> Filing {
        let card = card(seed);
        Filing {
            channel: card.channel_id().unwrap(),
            card,
            name: name.into(),
            came: Came::Taken([seed; 32]),
        }
    }

    fn act<T: Item>(item: T, maker: &NodeIdentity) -> Act<T> {
        Act::make(item, 1_800_000_000, 0, maker, names).unwrap()
    }

    /// A list at every bound: 16 filings, 64 drops, 32 subscriptions and
    /// 64 labels, each field at its longest, made on two devices.
    fn at_every_bound() -> SharedList {
        let (laptop, desktop) = (device(1), device(2));
        let long = |n: usize, at: usize| format!("{n:0>at$}");
        SharedList {
            fetched: SHARED_ACT_TIME_MAX,
            filings: (0..16)
                .map(|n| act(filing(n as u8, &long(n, 200)), &laptop))
                .collect(),
            drops: (0..64u8)
                .map(|n| {
                    act(
                        Dropped {
                            channel: [100 + n; 32],
                        },
                        &desktop,
                    )
                })
                .collect(),
            subscriptions: (0..32)
                .map(|n| {
                    act(
                        Subscription {
                            channel: [7; 32],
                            agent: long(n, 200),
                            subscribed: n % 2 == 0,
                        },
                        &laptop,
                    )
                })
                .collect(),
            labels: (0..64u8)
                .map(|n| {
                    act(
                        Label {
                            key: [n; 32],
                            label: Some(format!("{:x<64}", n)),
                        },
                        &desktop,
                    )
                })
                .collect(),
        }
    }

    /// At every bound a list is 41,341 bytes, which seal at 65,536 with
    /// its name through `Entry::seal` as it is, and 64 lists are 4,259,840
    /// bytes as a relay counts them. A filing at its longest is 475 bytes,
    /// a drop 144, a subscription 346 and a label 210.
    #[test]
    fn the_personal_channel_holds_this_records_lists_at_the_limits() {
        let list = at_every_bound();
        let value = list.to_value(names).unwrap();
        assert_eq!(value.len(), SHARED_LIST_MAX_VALUE_BYTES);
        assert_eq!(value.len(), 41_341);
        assert_eq!(
            SharedList::from_value(&Value::Other(value.clone()), names).unwrap(),
            list
        );

        let laptop = device(1);
        let name = list_name(&laptop.public_key()).unwrap();
        assert_eq!(name.len(), 77);
        let secret = derive::personal_secret(&[0x22; 32]).unwrap();
        let inside = Inside {
            name,
            value: Value::Other(value),
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&secret, &laptop, 1, &inside).unwrap();
        assert_eq!(entry.content.len(), MAX_ITEM_BYTES);
        assert_eq!(entry.content.len(), 65_536);
        assert_eq!(entry_cost(entry.content.len()), 66_560);
        assert_eq!(64 * entry_cost(entry.content.len()), 4_259_840);

        // Each item at its longest, as one more of it adds to a list.
        let empty = SharedList::default().to_value(names).unwrap().len();
        assert_eq!(empty, 1 + 8 + 4);
        let one = |list: SharedList| list.to_value(names).unwrap().len() - empty;
        let sizes = [
            one(SharedList {
                filings: list.filings[..1].to_vec(),
                ..SharedList::default()
            }),
            one(SharedList {
                drops: list.drops[..1].to_vec(),
                ..SharedList::default()
            }),
            one(SharedList {
                subscriptions: list.subscriptions[..1].to_vec(),
                ..SharedList::default()
            }),
            one(SharedList {
                labels: list.labels[..1].to_vec(),
                ..SharedList::default()
            }),
        ];
        assert_eq!(sizes, [475, 144, 346, 210]);
    }

    /// A list, byte for byte: the form, the fetched time, and each part's
    /// count and items, each with its act.
    #[test]
    fn a_list_is_its_parts_in_their_places() {
        let laptop = device(1);
        let filing = act(
            Filing {
                came: Came::Made,
                ..filing(9, "review")
            },
            &laptop,
        );
        let label = act(
            Label {
                key: [5; 32],
                label: None,
            },
            &laptop,
        );
        let list = SharedList {
            fetched: 0x00ff_0102_0304,
            filings: vec![filing.clone()],
            labels: vec![label.clone()],
            ..SharedList::default()
        };
        let value = list.to_value(names).unwrap();

        let mut expected = vec![1, 0, 0, 0, 0xff, 1, 2, 3, 4, 1];
        expected.extend_from_slice(&filing.item.channel);
        expected.extend_from_slice(&card(9).to_bytes());
        expected.push(6);
        expected.extend_from_slice(b"review");
        expected.push(0);
        expected.extend_from_slice(&1_800_000_000u64.to_be_bytes());
        expected.extend_from_slice(&0u64.to_be_bytes());
        expected.extend_from_slice(&laptop.public_key());
        expected.extend_from_slice(&filing.signature);
        expected.extend_from_slice(&[0, 0, 1]);
        expected.extend_from_slice(&[5; 32]);
        expected.extend_from_slice(&[0, 0]);
        expected.extend_from_slice(&1_800_000_000u64.to_be_bytes());
        expected.extend_from_slice(&0u64.to_be_bytes());
        expected.extend_from_slice(&laptop.public_key());
        expected.extend_from_slice(&label.signature);
        assert_eq!(value, expected);

        // A filing taken from a key, and one moved to from a channel; a
        // subscription held, and not.
        for came in [Came::Taken([6; 32]), Came::Moved([8; 32])] {
            let mut out = Vec::new();
            Filing {
                came,
                ..filing.item.clone()
            }
            .write(&mut out, &names)
            .unwrap();
            let (byte, of) = match came {
                Came::Taken(key) => (1, key),
                Came::Moved(id) => (2, id),
                Came::Made => unreachable!(),
            };
            assert_eq!(out[out.len() - 33], byte);
            assert_eq!(out[out.len() - 32..], of);
        }
        for (subscribed, state) in [(true, 1), (false, 0)] {
            let mut out = Vec::new();
            Subscription {
                channel: [7; 32],
                agent: "~".into(),
                subscribed,
            }
            .write(&mut out, &names)
            .unwrap();
            assert_eq!(out[32..], [1, b'~', state]);
        }
        assert_eq!(
            list_name(&laptop.public_key()).unwrap(),
            format!(
                "shared/{}",
                encode_public_key(&laptop.public_key()).unwrap()
            )
        );
    }

    /// An act's signature is its maker's, under its device key, over
    /// `cordelia v2 act`, the item's kind and every other field: a change
    /// to its time, its count, its maker, or a field of its item, and it no
    /// longer holds; nor does an act of one kind read as another's.
    #[test]
    fn an_acts_signature_is_its_makers_over_its_label_kind_and_fields() {
        let laptop = device(1);
        let made = act(
            Subscription {
                channel: [7; 32],
                agent: "github.com/owner/repo".into(),
                subscribed: true,
            },
            &laptop,
        );
        let mut signed = b"cordelia v2 act".to_vec();
        signed.push(3);
        signed.extend_from_slice(&[7; 32]);
        signed.push(21);
        signed.extend_from_slice(b"github.com/owner/repo");
        signed.push(1);
        signed.extend_from_slice(&1_800_000_000u64.to_be_bytes());
        signed.extend_from_slice(&0u64.to_be_bytes());
        signed.extend_from_slice(&laptop.public_key());
        assert!(verify_signature(
            &laptop.public_key(),
            &signed,
            &made.signature
        ));
        assert!(made.signed_by_its_maker());
        assert!(made.holds());

        let changed = [
            Act {
                time: made.time + 1,
                ..made.clone()
            },
            Act {
                count: 1,
                ..made.clone()
            },
            Act {
                maker: device(2).public_key(),
                ..made.clone()
            },
            Act {
                item: Subscription {
                    subscribed: false,
                    ..made.item.clone()
                },
                ..made.clone()
            },
            Act {
                item: Subscription {
                    channel: [8; 32],
                    ..made.item.clone()
                },
                ..made.clone()
            },
            Act {
                item: Subscription {
                    agent: "~".into(),
                    ..made.item.clone()
                },
                ..made.clone()
            },
        ];
        for act in changed {
            assert!(!act.signed_by_its_maker(), "{act:?}");
            assert!(!act.holds(), "{act:?}");
        }
        // A drop and a filing of one channel, a label and a drop of the
        // same 32 bytes: each kind's signature is its own.
        let dropped = act(Dropped { channel: [5; 32] }, &laptop);
        let as_a_label = Act {
            item: Label {
                key: [5; 32],
                label: None,
            },
            time: dropped.time,
            count: dropped.count,
            maker: dropped.maker,
            signature: dropped.signature,
        };
        assert!(dropped.holds());
        assert!(!as_a_label.signed_by_its_maker());
        assert_eq!(LABEL_SHARED_ACT, b"cordelia v2 act");
    }

    /// An act holds only where its signature holds under a usable key of
    /// its maker, its time and its count are each at most 2^40, and a
    /// filing's ID is its card's.
    #[test]
    fn an_act_holds_only_with_its_makers_signature_and_within_the_bound() {
        let laptop = device(1);
        let at = |time: u64, count: u64| {
            Act::make(Dropped { channel: [5; 32] }, time, count, &laptop, names).unwrap()
        };
        assert!(at(SHARED_ACT_TIME_MAX, SHARED_ACT_TIME_MAX).holds());
        assert!(!at(SHARED_ACT_TIME_MAX + 1, 0).holds());
        assert!(!at(0, SHARED_ACT_TIME_MAX + 1).holds());
        assert!(!at(u64::MAX, u64::MAX).holds());
        // Each is signed: what fails is the bound alone.
        assert!(at(SHARED_ACT_TIME_MAX + 1, 0).signed_by_its_maker());

        // A signature that is another device's, and a maker of small order.
        let mut forged = at(1, 0);
        forged.signature = device(2).sign(b"anything");
        assert!(!forged.holds());
        // The identity point, for which a signature of the identity and a
        // scalar of zero holds over anything: refused for its key.
        let mut small = at(1, 0);
        small.maker = [0; 32];
        small.maker[0] = 1;
        small.signature = [0; 64];
        small.signature[0] = 1;
        let names = |_: &str| true;
        assert!(verify_signature(
            &small.maker,
            &small.signed(&names).unwrap(),
            &small.signature
        ));
        assert!(!small.signed_by_its_maker());
        assert!(!small.holds());

        // A filing whose ID is another card's.
        let mut other = filing(9, "review");
        other.channel = card(10).channel_id().unwrap();
        let wrong = act(other, &laptop);
        assert!(wrong.signed_by_its_maker());
        assert!(!wrong.holds());
        assert!(act(filing(9, "review"), &laptop).holds());
    }

    /// An act's bytes are those a list writes for it, after the part's
    /// count: its item's fields, its time, its count, its maker and its
    /// signature.
    #[test]
    fn an_acts_bytes_are_those_a_list_writes_for_it() {
        let laptop = device(1);
        let made = act(
            Label {
                key: [9; 32],
                label: Some("bob".into()),
            },
            &laptop,
        );
        let value = SharedList {
            labels: vec![made.clone()],
            ..SharedList::default()
        }
        .to_value(names)
        .unwrap();
        let written = made.written().unwrap();
        assert_eq!(written, value[13..]);
        assert_eq!(written.len(), 32 + 2 + 3 + 8 + 8 + 32 + 64);
        assert_eq!(written[written.len() - 64..], made.signature);
    }

    /// A list copied by other devices keeps each act's maker and signature:
    /// the laptop's act, in the desktop's list and the phone's, each sealed
    /// by its own device, reads back with the laptop's key and signature,
    /// and holds.
    #[test]
    fn a_copied_act_keeps_its_makers_key_and_signature() {
        let (laptop, desktop, phone) = (device(1), device(2), device(3));
        let made = act(
            Label {
                key: [9; 32],
                label: Some("bob".into()),
            },
            &laptop,
        );
        let secret = derive::personal_secret(&[0x22; 32]).unwrap();
        for writer in [&laptop, &desktop, &phone] {
            let list = SharedList {
                fetched: 7,
                labels: vec![made.clone()],
                ..SharedList::default()
            };
            let inside = Inside {
                name: list_name(&writer.public_key()).unwrap(),
                value: Value::Other(list.to_value(names).unwrap()),
                chain: Some(Vec::new()),
            };
            let entry = Entry::seal(&secret, writer, 1, &inside).unwrap();
            assert_eq!(entry.author, writer.public_key());
            let opened = entry.check().unwrap().open(&secret).unwrap();
            let read = SharedList::from_value(&opened.value, names).unwrap();
            assert_eq!(read.labels[0].maker, laptop.public_key());
            assert_eq!(read.labels[0].signature, made.signature);
            assert!(read.labels[0].holds());
        }
    }

    /// A reader refuses a list of another kind or form, a part past its
    /// bound, two acts on one item, a name that is not one, a label of more
    /// than 64 bytes or not text, a way of coming or a state there is not,
    /// a card that is not one, and a list that ends early or runs on. The
    /// writer refuses the same.
    #[test]
    fn a_reader_refuses_a_list_that_is_not_one() {
        let laptop = device(1);
        let read = |bytes: Vec<u8>| SharedList::from_value(&Value::Other(bytes), names);
        assert_eq!(
            SharedList::from_value(&Value::Text("x".into()), names),
            Err(ListError::Kind)
        );
        let empty = SharedList::default().to_value(names).unwrap();
        assert!(read(empty.clone()).is_ok());
        let mut changed = empty.clone();
        changed[0] = 2;
        assert_eq!(read(changed), Err(ListError::Form(2)));
        assert_eq!(read(empty[..12].to_vec()), Err(ListError::Truncated));
        let mut longer = empty.clone();
        longer.push(0);
        assert_eq!(read(longer), Err(ListError::TrailingBytes));

        // A fetched time past 2^40, written and read; at it, a list.
        let past = SharedList {
            fetched: SHARED_ACT_TIME_MAX + 1,
            ..SharedList::default()
        };
        assert_eq!(
            past.to_value(names),
            Err(ListError::FetchedPastTheBound(SHARED_ACT_TIME_MAX + 1))
        );
        let mut changed = empty.clone();
        changed[1..9].copy_from_slice(&(SHARED_ACT_TIME_MAX + 1).to_be_bytes());
        assert_eq!(
            read(changed),
            Err(ListError::FetchedPastTheBound(SHARED_ACT_TIME_MAX + 1))
        );
        let mut changed = empty.clone();
        changed[1..9].copy_from_slice(&SHARED_ACT_TIME_MAX.to_be_bytes());
        assert_eq!(read(changed).unwrap().fetched, SHARED_ACT_TIME_MAX);

        // Each part's count past its bound, read and written.
        for (at, part, most) in [
            (9, "filings", 16),
            (10, "drops", 64),
            (11, "subscriptions", 32),
            (12, "labels", 64),
        ] {
            let mut changed = empty.clone();
            changed[at] = most as u8 + 1;
            assert_eq!(
                read(changed),
                Err(ListError::TooMany {
                    part,
                    most,
                    count: most + 1
                })
            );
        }
        let full = at_every_bound();
        let over = |list: SharedList| list.to_value(names);
        let mut more = full.clone();
        more.filings.push(act(filing(99, "x"), &laptop));
        assert!(matches!(
            over(more),
            Err(ListError::TooMany {
                part: "filings",
                ..
            })
        ));
        let mut more = full.clone();
        more.drops.push(act(Dropped { channel: [1; 32] }, &laptop));
        assert!(matches!(
            over(more),
            Err(ListError::TooMany { part: "drops", .. })
        ));
        let mut more = full.clone();
        more.subscriptions.push(full.subscriptions[0].clone());
        assert!(matches!(
            over(more),
            Err(ListError::TooMany {
                part: "subscriptions",
                ..
            })
        ));
        let mut more = full.clone();
        more.labels.push(full.labels[0].clone());
        assert!(matches!(
            over(more),
            Err(ListError::TooMany { part: "labels", .. })
        ));

        // Two acts on one item: a filing and a drop of one channel, one
        // agent's subscription twice, one key's label twice.
        let filed = act(filing(9, "review"), &laptop);
        let twice = [
            SharedList {
                filings: vec![filed.clone()],
                drops: vec![act(
                    Dropped {
                        channel: filed.item.channel,
                    },
                    &laptop,
                )],
                ..SharedList::default()
            },
            SharedList {
                subscriptions: vec![full.subscriptions[0].clone(); 2],
                ..SharedList::default()
            },
            SharedList {
                labels: vec![full.labels[0].clone(); 2],
                ..SharedList::default()
            },
        ];
        for list in twice {
            assert_eq!(list.to_value(names), Err(ListError::ItemTwice));
            let mut written = vec![1];
            written.extend_from_slice(&0u64.to_be_bytes());
            write_part(&mut written, &list.filings, &names).unwrap();
            write_part(&mut written, &list.drops, &names).unwrap();
            write_part(&mut written, &list.subscriptions, &names).unwrap();
            write_part(&mut written, &list.labels, &names).unwrap();
            assert_eq!(read(written), Err(ListError::ItemTwice));
        }
        // One agent in two channels, and two agents in one, are two items.
        let two = SharedList {
            subscriptions: vec![
                full.subscriptions[0].clone(),
                act(
                    Subscription {
                        channel: [8; 32],
                        ..full.subscriptions[0].item.clone()
                    },
                    &laptop,
                ),
                full.subscriptions[1].clone(),
            ],
            ..SharedList::default()
        };
        assert!(two.to_value(names).is_ok());

        // The fields of one filing, written as given.
        let one = SharedList {
            filings: vec![filed.clone()],
            ..SharedList::default()
        }
        .to_value(names)
        .unwrap();
        // The name's length at 10 + 32 + 97, and how it came after it.
        let name_at = 10 + 32 + 97;
        let mut changed = one.clone();
        changed[name_at + 1] = b'R';
        assert_eq!(read(changed), Err(ListError::Name));
        let mut changed = one.clone();
        changed[name_at] = 0;
        assert!(read(changed).is_err());
        // A length past 200, with as many bytes of a name behind it.
        let mut changed = one[..name_at].to_vec();
        changed.push(201);
        changed.extend_from_slice(&[b'n'; 201]);
        changed.extend_from_slice(&one[name_at + 7..]);
        assert_eq!(read(changed), Err(ListError::Name));
        let mut changed = one.clone();
        changed[name_at + 7] = 3;
        assert_eq!(read(changed), Err(ListError::Came(3)));
        // The card's count of relays: three.
        let mut changed = one.clone();
        changed[10 + 32 + 32] = 3;
        assert_eq!(
            read(changed),
            Err(ListError::Card(ShareError::TooManyRelays(3)))
        );
        // A name of 201 bytes is refused, written or read.
        assert_eq!(
            Act::make(filing(9, &"n".repeat(201)), 1, 0, &laptop, names),
            Err(ListError::Name)
        );
        assert_eq!(
            Act::make(filing(9, "Review"), 1, 0, &laptop, names),
            Err(ListError::Name)
        );

        // A subscription's state, at its end before its act.
        let subscribed = SharedList {
            subscriptions: vec![full.subscriptions[0].clone()],
            ..SharedList::default()
        }
        .to_value(names)
        .unwrap();
        let state_at = 12 + 32 + 1 + 200;
        assert_eq!(subscribed[state_at], 1);
        let mut changed = subscribed.clone();
        changed[state_at] = 2;
        assert_eq!(read(changed), Err(ListError::State(2)));

        // A label: of 65 bytes, not text, and of no bytes as a label.
        let labelled = SharedList {
            labels: vec![full.labels[0].clone()],
            ..SharedList::default()
        }
        .to_value(names)
        .unwrap();
        let length_at = 13 + 32;
        let mut changed = labelled.clone();
        changed[length_at..length_at + 2].copy_from_slice(&65u16.to_be_bytes());
        assert_eq!(read(changed), Err(ListError::Label));
        let mut changed = labelled.clone();
        changed[length_at + 2] = 0xff;
        assert_eq!(read(changed), Err(ListError::Label));
        for label in [String::new(), "l".repeat(65)] {
            assert_eq!(
                Act::make(
                    Label {
                        key: [1; 32],
                        label: Some(label),
                    },
                    1,
                    0,
                    &laptop,
                    names
                ),
                Err(ListError::Label)
            );
        }
        // A list over its most is refused before it is read.
        assert_eq!(
            read(vec![1; SHARED_LIST_MAX_VALUE_BYTES + 1]),
            Err(ListError::TooLong(SHARED_LIST_MAX_VALUE_BYTES + 1))
        );
    }
}
