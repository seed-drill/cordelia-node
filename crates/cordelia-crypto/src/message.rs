//! The value of a message between a person's own agents, and where it
//! stands in the messages channel (decision 2026-10-09 §2.2, §2.3, §2.5).
//!
//! Everything here is pure: what a message's value is byte for byte, its
//! ID, the mark of a message read by a name, the name of each slot, the
//! check that an entry stands where its signer's ring puts it, and the
//! revisions of a message and of its clearing. Nothing here holds a store
//! or a clock.
//!
//! ## The value
//!
//! Every entry of the messages channel holds a value of kind 2
//! ([`Value::Other`]) of exactly `AGENT_MESSAGE_VALUE_BYTES` (1,936)
//! bytes, with an empty chain, so that each seals at 2,048 bytes through
//! [`crate::entry::Entry::seal`] as it is. Every length is big-endian.
//!
//! A message (form 1):
//!
//! ```text
//! form       1    1
//! flags      1    bit 0: it asks for an answer; every other bit 0
//! sent       8    seconds since 1970, by the sender's clock
//! nonce      16   random
//! thread     16   the ID of the message that began the thread, or zeros
//! answers    16   the ID of the message it answers, or zeros
//! from       2 + 1 to 200     a name, in its one spelling
//! to, kind   1    1: one name; 2: every name
//! to         2 + 0 to 200     the name for kind 1; nothing for kind 2
//! link       1 + 0 to 151     `owner/repo#n`, or nothing
//! body       2 + 1 to 1,024   UTF-8
//! fill       the rest, zeros
//! ```
//!
//! The entry that clears a message (form 0) is the byte 0 and zeros. A
//! device's list of what its agents read (form 2) is the byte 2, a count
//! of two bytes from 0 to 120, that many marks of 16 bytes, the newest
//! first, and zeros.
//!
//! A reader refuses anything else as no message ([`NotAMessage`]), and the
//! node that sends checks the same before it seals: a value is written
//! only where it reads back.
//!
//! ## The ring
//!
//! A device's message number k goes in the slot `msg/<its key>/<k mod
//! 64>` at revision 2k, and the entry that clears it in the same slot at
//! 2k + 1. Its list is in `read/<its key>`. A reader takes from those slots
//! only what the key in the name signed, at a number that the slot's
//! place agrees with ([`place_of`]).

use cordelia_core::protocol::{
    AGENT_MESSAGE_BODY_MAX_BYTES, AGENT_MESSAGE_ID_BYTES, AGENT_MESSAGE_LINK_MAX_BYTES,
    AGENT_MESSAGE_LINK_NUMBER_MAX_DIGITS, AGENT_MESSAGE_LINK_OWNER_MAX_BYTES,
    AGENT_MESSAGE_LINK_REPO_MAX_BYTES, AGENT_MESSAGE_NAME_MAX_BYTES, AGENT_MESSAGE_NUMBER_MAX,
    AGENT_MESSAGE_PREFIX, AGENT_MESSAGE_READ_MARK_BYTES, AGENT_MESSAGE_READ_MARKS_MAX,
    AGENT_MESSAGE_READ_PREFIX, AGENT_MESSAGE_RING, AGENT_MESSAGE_VALUE_BYTES,
    LABEL_AGENT_MESSAGE_ID, LABEL_AGENT_MESSAGE_READ,
};

use crate::CryptoError;
use crate::bech32::encode_public_key;
use crate::entry::{Inside, Value};
use crate::statement::{Reader, put_count};

/// The first byte of each form of value.
const FORM_CLEARING: u8 = 0;
const FORM_MESSAGE: u8 = 1;
const FORM_LIST: u8 = 2;

/// The one flag: the message asks for an answer.
const FLAG_ASKS: u8 = 0b0000_0001;

/// The kinds of `to`.
const TO_ONE: u8 = 1;
const TO_ALL: u8 = 2;

/// Why what an entry of the messages channel holds is no message, no
/// clearing and no list (decision 2026-10-09 §2.2, §2.3). A reader counts
/// each as "not a message", and shows none.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotAMessage {
    #[error("an entry of the messages channel holds a value that is not of kind 2")]
    Kind,

    #[error("a value of the messages channel is 1936 bytes, and this is {0}")]
    Length(usize),

    #[error("a value of form {0} is of no form that there is")]
    Form(u8),

    #[error("a value of form {0} does not stand at a revision of its form")]
    AnotherForm(u8),

    #[error("a message's flags are bit 0 alone, and these are {0:#04x}")]
    Flags(u8),

    #[error("a length in the value runs past its field's bound, or past the value")]
    Field,

    #[error("what follows the fields is not all zeros")]
    Fill,

    #[error("a name in the message is not a name")]
    Name,

    #[error("a message is to one name (1) or to every name (2), and this says {0}")]
    ToKind(u8),

    #[error("a message to every name names a name")]
    ToWithAll,

    #[error("a message's body is at least one byte")]
    BodyEmpty,

    #[error("a message's body is at most 1024 bytes, and this is {0}")]
    BodyTooLong(usize),

    #[error("a message's body is not UTF-8")]
    BodyNotText,

    #[error("a message's link is not of the form owner/repo#number")]
    Link,

    #[error("a list holds at most 120 marks, and this says {0}")]
    Marks(usize),

    #[error("the entry is not in its signer's ring")]
    NotInRing,
}

/// Whom a message is addressed to (decision 2026-10-09 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum To {
    /// One name of the person's, in its one spelling.
    Name(String),
    /// Every name of the person's.
    All,
}

/// A message, as its value holds it (decision 2026-10-09 §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Whether it asks for an answer: bit 0 of the flags.
    pub asks: bool,
    /// When it was sent, in seconds since 1970, by the sender's clock.
    pub sent: u64,
    /// Random, so that two messages with the same words are two messages.
    pub nonce: [u8; 16],
    /// The ID of the message that began the thread, or zeros where this
    /// one begins it.
    pub thread: [u8; AGENT_MESSAGE_ID_BYTES],
    /// The ID of the message it answers, or zeros where it answers none.
    pub answers: [u8; AGENT_MESSAGE_ID_BYTES],
    /// The agent on the sending device: a name in its one spelling.
    pub from: String,
    pub to: To,
    /// `owner/repo#n`, the sender's text.
    pub link: Option<String>,
    pub body: String,
}

impl Message {
    /// The message's value, filled with zeros to its one length.
    ///
    /// Refused, and never cut to fit, where a reader would refuse it: a
    /// length past its field's bound, a name that `is_a_name` does not
    /// take, an empty body, a link not of its form. So the node that sends
    /// checks what every reader checks, before it seals.
    pub fn to_value(&self, is_a_name: impl Fn(&str) -> bool) -> Result<Vec<u8>, NotAMessage> {
        let to = match &self.to {
            To::Name(name) => name.as_str(),
            To::All => "",
        };
        let link = self.link.as_deref().unwrap_or("");
        // A link given as nothing is no link: it would read back as none.
        if self.link.as_deref() == Some("") {
            return Err(NotAMessage::Link);
        }
        // Each length first, so that none is written that its own field
        // cannot count: a length that wrapped would read back as another
        // message.
        if self.from.len() > AGENT_MESSAGE_NAME_MAX_BYTES
            || to.len() > AGENT_MESSAGE_NAME_MAX_BYTES
            || link.len() > AGENT_MESSAGE_LINK_MAX_BYTES
        {
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
        put_count(&mut out, self.from.len());
        out.extend_from_slice(self.from.as_bytes());
        out.push(match self.to {
            To::Name(_) => TO_ONE,
            To::All => TO_ALL,
        });
        put_count(&mut out, to.len());
        out.extend_from_slice(to.as_bytes());
        out.push(link.len() as u8);
        out.extend_from_slice(link.as_bytes());
        put_count(&mut out, self.body.len());
        out.extend_from_slice(self.body.as_bytes());
        out.resize(AGENT_MESSAGE_VALUE_BYTES, 0);

        if Self::from_value(&Value::Other(out.clone()), is_a_name)? != *self {
            return Err(NotAMessage::Field);
        }
        Ok(out)
    }

    /// Read a message from an entry's value, as a reader does (decision
    /// 2026-10-09 §2.2). `is_a_name` says whether a name is a name of the
    /// person's in its one spelling (`names::is_a_name` on a device).
    pub fn from_value(
        value: &Value,
        is_a_name: impl Fn(&str) -> bool,
    ) -> Result<Self, NotAMessage> {
        let bytes = whole(value)?;
        let mut reader = Reader::new(bytes);
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

        let from = field(&mut reader, AGENT_MESSAGE_NAME_MAX_BYTES)?;
        let from = name_in(from, &is_a_name)?;

        let kind = byte(&mut reader)?;
        let to = field(&mut reader, AGENT_MESSAGE_NAME_MAX_BYTES)?;
        let to = match kind {
            TO_ONE => To::Name(name_in(to, &is_a_name)?),
            TO_ALL if to.is_empty() => To::All,
            TO_ALL => return Err(NotAMessage::ToWithAll),
            other => return Err(NotAMessage::ToKind(other)),
        };

        let length = usize::from(byte(&mut reader)?);
        if length > AGENT_MESSAGE_LINK_MAX_BYTES {
            return Err(NotAMessage::Field);
        }
        let link = reader.take(length).ok_or(NotAMessage::Field)?;
        let link = match link {
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
            from,
            to,
            link,
            body,
        })
    }

    /// The subject: the body up to its first line feed, or the whole body
    /// where it has none (decision 2026-10-09 §2.2). It is not a field of
    /// its own, so it cannot say another thing than the first line.
    pub fn subject(&self) -> &str {
        self.body.split('\n').next().unwrap_or("")
    }
}

/// The value of the entry that clears a message (decision 2026-10-09
/// §2.2): form 0, and zeros. It is the size of a message, so the slot is
/// never written smaller.
pub fn clearing_value() -> Vec<u8> {
    let mut value = vec![0; AGENT_MESSAGE_VALUE_BYTES];
    value[0] = FORM_CLEARING;
    value
}

/// Whether `value` is the value of an entry that clears a message.
pub fn is_clearing(value: &Value) -> Result<(), NotAMessage> {
    let mut reader = Reader::new(whole(value)?);
    let form = byte(&mut reader)?;
    if form != FORM_CLEARING {
        return Err(form_refused(form));
    }
    filled(&reader)
}

/// A device's list of what its agents read (decision 2026-10-09 §2.4):
/// the marks of what they read, the newest first, at most 120.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadMarks {
    pub marks: Vec<[u8; AGENT_MESSAGE_READ_MARK_BYTES]>,
}

impl ReadMarks {
    /// The list's value. A list of more than 120 marks is refused: the
    /// device writes its newest 120.
    pub fn to_value(&self) -> Result<Vec<u8>, NotAMessage> {
        if self.marks.len() > AGENT_MESSAGE_READ_MARKS_MAX {
            return Err(NotAMessage::Marks(self.marks.len()));
        }
        let mut out = Vec::with_capacity(AGENT_MESSAGE_VALUE_BYTES);
        out.push(FORM_LIST);
        put_count(&mut out, self.marks.len());
        for mark in &self.marks {
            out.extend_from_slice(mark);
        }
        out.resize(AGENT_MESSAGE_VALUE_BYTES, 0);
        Ok(out)
    }

    /// Read a list from an entry's value, as a reader does.
    pub fn from_value(value: &Value) -> Result<Self, NotAMessage> {
        let mut reader = Reader::new(whole(value)?);
        let form = byte(&mut reader)?;
        if form != FORM_LIST {
            return Err(form_refused(form));
        }
        let count = reader.count().ok_or(NotAMessage::Field)?;
        if count > AGENT_MESSAGE_READ_MARKS_MAX {
            return Err(NotAMessage::Marks(count));
        }
        let marks = (0..count)
            .map(|_| reader.array().ok_or(NotAMessage::Field))
            .collect::<Result<_, _>>()?;
        filled(&reader)?;
        Ok(Self { marks })
    }
}

/// What an entry of the messages channel is, once its place and its
/// value agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// A message, at its number.
    Message { number: u64, message: Message },
    /// The entry that clears the message of that number.
    Clearing { number: u64 },
    /// The signer's list of what its agents read.
    List(ReadMarks),
}

/// Where an entry stands in its signer's slots, by its name and revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Message(u64),
    Clearing(u64),
    List,
}

/// Where the entry named `name`, signed by `signer`, at revision `rev`,
/// stands in that signer's slots (decision 2026-10-09 §2.3, C3). `None`
/// where it stands in none, however it was signed:
///
/// - a message is in the slot `msg/<signer>/<n>`, with n its number
///   modulo 64 written with no leading zero, at an even revision whose
///   half is its number, from 1 to the highest;
/// - a clearing is in the same slot at an odd revision, whose half,
///   rounded down, is the number it clears;
/// - a list is in `read/<signer>`, at any revision.
///
/// Whether the number is live is the reader's to say, with what it holds
/// ([`is_live`]).
pub fn place_of(name: &str, signer: &[u8; 32], rev: u64) -> Option<Place> {
    if name == read_name(signer).ok()? {
        return Some(Place::List);
    }
    let number = number_of(rev);
    if !is_a_number(number) || name != message_name(signer, number).ok()? {
        return None;
    }
    Some(if is_clearing_rev(rev) {
        Place::Clearing(number)
    } else {
        Place::Message(number)
    })
}

/// What a reader takes from the entry named `name`, signed by `signer`,
/// at revision `rev`, that holds `value` (decision 2026-10-09 §2.2, §2.3):
/// the entry stands in its signer's ring, and its value is of the form of
/// its place. Anything else is no message.
pub fn take(
    name: &str,
    signer: &[u8; 32],
    rev: u64,
    value: &Value,
    is_a_name: impl Fn(&str) -> bool,
) -> Result<Taken, NotAMessage> {
    match place_of(name, signer, rev).ok_or(NotAMessage::NotInRing)? {
        Place::Message(number) => Ok(Taken::Message {
            number,
            message: Message::from_value(value, is_a_name)?,
        }),
        Place::Clearing(number) => {
            is_clearing(value)?;
            Ok(Taken::Clearing { number })
        }
        Place::List => Ok(Taken::List(ReadMarks::from_value(value)?)),
    }
}

/// What an entry of the messages channel holds: its name and value, with
/// an empty chain (decision 2026-10-09 §2.2).
pub fn inside(name: String, value: Vec<u8>) -> Inside {
    Inside {
        name,
        value: Value::Other(value),
        chain: Some(Vec::new()),
    }
}

/// The name of the slot that a device's message `number`, and its
/// clearing, are in: `msg/`, the device's key as it is written, `/`, and
/// the number modulo 64 in decimal (decision 2026-10-09 §2.2).
pub fn message_name(signer: &[u8; 32], number: u64) -> Result<String, CryptoError> {
    Ok(format!(
        "{AGENT_MESSAGE_PREFIX}{}/{}",
        encode_public_key(signer)?,
        number % AGENT_MESSAGE_RING as u64
    ))
}

/// The name of a device's list of what its agents read: `read/` and the
/// device's key as it is written (decision 2026-10-09 §2.2).
pub fn read_name(signer: &[u8; 32]) -> Result<String, CryptoError> {
    Ok(format!(
        "{AGENT_MESSAGE_READ_PREFIX}{}",
        encode_public_key(signer)?
    ))
}

/// The revision of message `number`: twice it (decision 2026-10-09 §2.3).
/// `None` for a number that no message has: 0, or one above the highest.
pub fn message_rev(number: u64) -> Option<u64> {
    is_a_number(number).then(|| 2 * number)
}

/// The revision of the entry that clears message `number`: one above the
/// message's, so it is above the message in the slot and takes no number
/// of its own.
pub fn clearing_rev(number: u64) -> Option<u64> {
    is_a_number(number).then(|| 2 * number + 1)
}

/// The number of the message, or of the message cleared, at revision
/// `rev`: the revision halved, and rounded down.
pub fn number_of(rev: u64) -> u64 {
    rev / 2
}

/// Whether the entry at revision `rev` is a clearing: its revision is odd.
/// A message's is even, and that is all that a relay can tell of the two.
pub fn is_clearing_rev(rev: u64) -> bool {
    rev % 2 == 1
}

/// The number after `highest`, the highest number a device holds in its
/// own ring: `None` once that would be above the highest a message can
/// have, until the next statement starts the ring again (decision
/// 2026-10-09 §2.3).
pub fn next_number(highest: u64) -> Option<u64> {
    highest.checked_add(1).filter(|next| is_a_number(*next))
}

/// Whether `number` is live at a reader whose highest number of that
/// signer is `highest`: above `highest` less the ring (decision 2026-10-09
/// §2.5). An entry at a number that is not live is overwritten.
pub fn is_live(number: u64, highest: u64) -> bool {
    number > highest.saturating_sub(AGENT_MESSAGE_RING as u64)
}

/// A message's ID: the first 16 bytes of SHA-256 of its label, the
/// signer's key and the value with its fill (decision 2026-10-09 §2.2).
/// It binds the sender, and is the same under every number the message is
/// sent under.
pub fn message_id(signer: &[u8; 32], value: &[u8]) -> [u8; AGENT_MESSAGE_ID_BYTES] {
    let mut hashed = Vec::with_capacity(LABEL_AGENT_MESSAGE_ID.len() + 32 + value.len());
    hashed.extend_from_slice(LABEL_AGENT_MESSAGE_ID);
    hashed.extend_from_slice(signer);
    hashed.extend_from_slice(value);
    first(&crate::sha256(&hashed))
}

/// The mark that message `id` was read by the agent of `name`: the first
/// 16 bytes of SHA-256 of its label, the ID and the name (decision
/// 2026-10-09 §2.2). It is never the ID, so a message to every name read
/// by one agent is not read for another.
pub fn read_mark(
    id: &[u8; AGENT_MESSAGE_ID_BYTES],
    name: &str,
) -> [u8; AGENT_MESSAGE_READ_MARK_BYTES] {
    let mut hashed = Vec::with_capacity(LABEL_AGENT_MESSAGE_READ.len() + id.len() + name.len());
    hashed.extend_from_slice(LABEL_AGENT_MESSAGE_READ);
    hashed.extend_from_slice(id);
    hashed.extend_from_slice(name.as_bytes());
    first(&crate::sha256(&hashed))
}

/// Whether `link` is a link (decision 2026-10-09 §2.2): an owner of 1 to
/// 39 ASCII letters, digits and `-`, `/`, a repository of 1 to 100 ASCII
/// letters, digits, `.`, `_` and `-`, `#`, and a number of 1 to 10 digits
/// with no leading zero. It is text, and is never read as a number.
pub fn is_a_link(link: &str) -> bool {
    let Some((owner, rest)) = link.split_once('/') else {
        return false;
    };
    let Some((repo, number)) = rest.split_once('#') else {
        return false;
    };
    let of = |part: &str, most: usize, also: &[u8]| {
        (1..=most).contains(&part.len())
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || also.contains(&b))
    };
    of(owner, AGENT_MESSAGE_LINK_OWNER_MAX_BYTES, b"-")
        && of(repo, AGENT_MESSAGE_LINK_REPO_MAX_BYTES, b"._-")
        && (1..=AGENT_MESSAGE_LINK_NUMBER_MAX_DIGITS).contains(&number.len())
        && number.bytes().all(|b| b.is_ascii_digit())
        && !number.starts_with('0')
}

/// Whether a message can have the number `number`: from 1 to the highest.
fn is_a_number(number: u64) -> bool {
    (1..=AGENT_MESSAGE_NUMBER_MAX).contains(&number)
}

/// The bytes of a value of the messages channel: of kind 2, and of its
/// one length.
fn whole(value: &Value) -> Result<&[u8], NotAMessage> {
    let Value::Other(bytes) = value else {
        return Err(NotAMessage::Kind);
    };
    if bytes.len() != AGENT_MESSAGE_VALUE_BYTES {
        return Err(NotAMessage::Length(bytes.len()));
    }
    Ok(bytes)
}

/// A form that is known, at a place of another, or one that is not.
fn form_refused(form: u8) -> NotAMessage {
    match form {
        FORM_CLEARING | FORM_MESSAGE | FORM_LIST => NotAMessage::AnotherForm(form),
        other => NotAMessage::Form(other),
    }
}

fn byte(reader: &mut Reader) -> Result<u8, NotAMessage> {
    Ok(reader.array::<1>().ok_or(NotAMessage::Field)?[0])
}

/// A field behind a length of two bytes, of at most `most` bytes.
fn field<'a>(reader: &mut Reader<'a>, most: usize) -> Result<&'a [u8], NotAMessage> {
    let length = reader.count().ok_or(NotAMessage::Field)?;
    if length > most {
        return Err(NotAMessage::Field);
    }
    reader.take(length).ok_or(NotAMessage::Field)
}

/// A name of a message: UTF-8, and a name that `is_a_name` takes.
fn name_in(bytes: &[u8], is_a_name: impl Fn(&str) -> bool) -> Result<String, NotAMessage> {
    match std::str::from_utf8(bytes) {
        Ok(name) if !name.is_empty() && is_a_name(name) => Ok(name.to_string()),
        _ => Err(NotAMessage::Name),
    }
}

/// What is left after the fields is the fill: zeros, all of it.
fn filled(reader: &Reader) -> Result<(), NotAMessage> {
    if reader.rest().iter().any(|byte| *byte != 0) {
        return Err(NotAMessage::Fill);
    }
    Ok(())
}

fn first<const N: usize>(hash: &[u8; 32]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&hash[..N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Entry;
    use crate::identity::NodeIdentity;
    use cordelia_core::protocol::{AGENT_MESSAGE_CONTENT_BYTES, REV_BAND_HALF};

    const SECRET: [u8; 32] = [0x5a; 32];

    fn device(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32]).unwrap()
    }

    /// A stand-in for `names::is_a_name`, which is the node's: a name of
    /// lower-case letters, digits and `~./-`. It takes a name of any
    /// length, so that the value's own bounds are what refuse a long one.
    fn names(name: &str) -> bool {
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"~./-".contains(&b))
    }

    fn smallest() -> Message {
        Message {
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
    }

    fn largest() -> Message {
        Message {
            asks: true,
            sent: u64::MAX,
            nonce: [0xff; 16],
            thread: [0xee; 16],
            answers: [0xdd; 16],
            from: "f".repeat(200),
            to: To::Name("t".repeat(200)),
            link: Some(format!(
                "{}/{}#{}",
                "o".repeat(39),
                "r".repeat(100),
                "9".repeat(10)
            )),
            body: "b".repeat(1024),
        }
    }

    /// Write a message's fields as given, with no check, and fill to
    /// `length`: what a holder of a device's key could write.
    struct Forged {
        form: u8,
        flags: u8,
        from: Vec<u8>,
        kind: u8,
        to: Vec<u8>,
        link: Vec<u8>,
        body: Vec<u8>,
        length: usize,
    }

    impl Forged {
        fn new() -> Self {
            Self {
                form: 1,
                flags: 0,
                from: b"laptop-agent".to_vec(),
                kind: 1,
                to: b"github.com/owner/repo".to_vec(),
                link: b"owner/repo#12".to_vec(),
                body: b"a branch to look at\nmore".to_vec(),
                length: AGENT_MESSAGE_VALUE_BYTES,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            let mut out = vec![self.form, self.flags];
            out.extend_from_slice(&7u64.to_be_bytes());
            out.extend_from_slice(&[1; 48]);
            out.extend_from_slice(&(self.from.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.from);
            out.push(self.kind);
            out.extend_from_slice(&(self.to.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.to);
            out.push(self.link.len() as u8);
            out.extend_from_slice(&self.link);
            out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.body);
            out.resize(self.length, 0);
            out
        }

        fn read(&self) -> Result<Message, NotAMessage> {
            Message::from_value(&Value::Other(self.bytes()), names)
        }
    }

    /// Each entry of the messages channel, sealed by `Entry::seal` as it
    /// is, has a content of 2,048 bytes: the smallest and the largest
    /// message and the clearing, each in slot 0 and in slot 63, and a full
    /// list. Each opens to the value it was given. One byte of body over
    /// the bound is refused before anything is sealed.
    #[test]
    fn the_clearing_entry_and_the_smallest_and_largest_message_each_have_a_content_of_2048_through_entry_seal()
     {
        let laptop = device(1);
        let key = laptop.public_key();
        let list = ReadMarks {
            marks: (0..120u8).map(|i| [i; 16]).collect(),
        }
        .to_value()
        .unwrap();
        assert_eq!(&list[..3], &[2, 0, 120]);

        let mut sealed = Vec::new();
        // Slot 63 is number 63, and slot 0 is number 64.
        for number in [63, 64] {
            let name = message_name(&key, number).unwrap();
            for message in [smallest(), largest()] {
                sealed.push((name.clone(), message_rev(number).unwrap(), {
                    message.to_value(names).unwrap()
                }));
            }
            sealed.push((name, clearing_rev(number).unwrap(), clearing_value()));
        }
        sealed.push((read_name(&key).unwrap(), 1, list));
        assert_eq!(sealed.len(), 7);

        for (name, rev, value) in sealed {
            assert_eq!(value.len(), 1_936);
            let entry =
                Entry::seal(&SECRET, &laptop, rev, &inside(name.clone(), value.clone())).unwrap();
            assert_eq!(entry.content.len(), AGENT_MESSAGE_CONTENT_BYTES, "{name}");
            assert_eq!(entry.content.len(), 2_048);
            let opened = entry.check().unwrap().open(&SECRET).unwrap();
            assert_eq!(opened, inside(name.clone(), value.clone()), "{name}");
            assert!(
                take(&name, &key, rev, &opened.value, names).is_ok(),
                "{name}"
            );
        }

        // The two messages read back as they were written.
        for message in [smallest(), largest()] {
            let value = message.to_value(names).unwrap();
            assert_eq!(
                Message::from_value(&Value::Other(value), names).unwrap(),
                message
            );
        }

        // A body of 1,025 bytes is refused before it is sealed.
        let over = Message {
            body: "b".repeat(1025),
            ..largest()
        };
        assert_eq!(over.to_value(names), Err(NotAMessage::BodyTooLong(1025)));
        let over = Message {
            body: "b".repeat(1025),
            ..smallest()
        };
        assert_eq!(over.to_value(names), Err(NotAMessage::BodyTooLong(1025)));
    }

    /// The fill of a message, of a clearing and of a list is zeros, every
    /// byte of it: one byte that is not, anywhere in it, and it is no
    /// message.
    #[test]
    fn a_fill_that_is_not_all_zeros_is_no_message() {
        let message = largest().to_value(names).unwrap();
        let list = ReadMarks {
            marks: vec![[3; 16]; 2],
        }
        .to_value()
        .unwrap();
        // Where the fill of each starts: after 1,641, after 1, after 35.
        for (value, start) in [(message, 1_641), (clearing_value(), 1), (list, 35)] {
            for at in [start, start + 1, AGENT_MESSAGE_VALUE_BYTES - 1] {
                let mut changed = value.clone();
                changed[at] = 1;
                let read = match value[0] {
                    1 => Message::from_value(&Value::Other(changed), names).map(|_| ()),
                    0 => is_clearing(&Value::Other(changed)),
                    _ => ReadMarks::from_value(&Value::Other(changed)).map(|_| ()),
                };
                assert_eq!(read, Err(NotAMessage::Fill), "form {} at {at}", value[0]);
            }
            // The control: as it was written, it reads.
            let read = match value[0] {
                1 => Message::from_value(&Value::Other(value.clone()), names).map(|_| ()),
                0 => is_clearing(&Value::Other(value.clone())),
                _ => ReadMarks::from_value(&Value::Other(value.clone())).map(|_| ()),
            };
            assert_eq!(read, Ok(()));
        }
        // The clearing is the byte of its form, 0, and the fill.
        assert!(clearing_value().iter().all(|byte| *byte == 0));
    }

    /// A field longer than its length can count is refused before it is
    /// written: written, its length would wrap, and the value would read
    /// back as another message, here one from `a`, to every name, that
    /// says `z`.
    #[test]
    fn the_sender_writes_no_value_that_reads_back_as_another_message() {
        let wrapped = |head: &str, at: usize| format!("{head}{}", "\0".repeat(at - head.len()));
        // A from of 65,537 bytes counts as 1: `a`, then every name, no
        // link, and a body of one byte.
        let from = Message {
            from: wrapped("a\u{2}\0\0\0\0\u{1}z", 65_537),
            ..smallest()
        };
        assert_eq!(from.to_value(names), Err(NotAMessage::Field));
        // A to of 65,537 counts as 1: `t`, no link, and a body `z`.
        let to = Message {
            to: To::Name(wrapped("t\0\0\u{1}z", 65_537)),
            ..smallest()
        };
        assert_eq!(to.to_value(names), Err(NotAMessage::Field));
        // A link of 2,053 counts as 5: `o/r#1`, and a body `z`; the rest
        // is past the value's end.
        let link = Message {
            link: Some(wrapped("o/r#1\0\u{1}z", 2_053)),
            ..smallest()
        };
        assert_eq!(link.to_value(names), Err(NotAMessage::Field));
        // A body of 65,537 counts as 1: `z`.
        let body = Message {
            body: wrapped("z", 65_537),
            ..smallest()
        };
        assert_eq!(body.to_value(names), Err(NotAMessage::BodyTooLong(65_537)));
    }

    /// What a relay sees of a message and of its clearing: the same
    /// channel, slot, author, delete and size of content, and two
    /// revisions, the message's even and the clearing's odd, one above.
    #[test]
    fn a_relay_tells_a_clearing_from_a_message_by_parity_alone() {
        let laptop = device(1);
        let name = message_name(&laptop.public_key(), 5).unwrap();
        let value = largest().to_value(names).unwrap();
        let message = Entry::seal(
            &SECRET,
            &laptop,
            message_rev(5).unwrap(),
            &inside(name.clone(), value),
        )
        .unwrap();
        let clearing = Entry::seal(
            &SECRET,
            &laptop,
            clearing_rev(5).unwrap(),
            &inside(name, clearing_value()),
        )
        .unwrap();
        assert_eq!(message.channel, clearing.channel);
        assert_eq!(message.slot, clearing.slot);
        assert_eq!(message.author, clearing.author);
        assert_eq!(message.delete, clearing.delete);
        assert!(!message.delete);
        assert_eq!(message.content.len(), clearing.content.len());
        assert_eq!((message.rev, clearing.rev), (10, 11));
        assert!(!is_clearing_rev(message.rev));
        assert!(is_clearing_rev(clearing.rev));
        assert_eq!(number_of(message.rev), number_of(clearing.rev));
        assert!(message.check().is_ok());
        assert!(clearing.check().is_ok());
    }

    /// An entry in a slot named for another key than the one that signed
    /// it is no message, no clearing and no list, whatever it holds.
    #[test]
    fn a_message_in_a_slot_named_for_another_key_is_no_message() {
        let (laptop, desktop) = (device(1).public_key(), device(2).public_key());
        let value = Value::Other(smallest().to_value(names).unwrap());
        let name = message_name(&desktop, 0).unwrap();
        assert!(name.ends_with("/0"));
        assert_eq!(place_of(&name, &laptop, 128), None);
        assert_eq!(
            take(&name, &laptop, 128, &value, names),
            Err(NotAMessage::NotInRing)
        );
        let list = Value::Other(ReadMarks::default().to_value().unwrap());
        let other_list = read_name(&desktop).unwrap();
        assert_eq!(
            take(&other_list, &laptop, 1, &list, names),
            Err(NotAMessage::NotInRing)
        );
        let clearing = Value::Other(clearing_value());
        assert_eq!(
            take(&name, &laptop, 129, &clearing, names),
            Err(NotAMessage::NotInRing)
        );
        // The control: in the slots named for the key that signed, each
        // is taken.
        assert_eq!(
            take(&name, &desktop, 128, &value, names),
            Ok(Taken::Message {
                number: 64,
                message: smallest()
            })
        );
        assert_eq!(
            take(&other_list, &desktop, 1, &list, names),
            Ok(Taken::List(ReadMarks::default()))
        );
        assert_eq!(
            take(&name, &desktop, 129, &clearing, names),
            Ok(Taken::Clearing { number: 64 })
        );
    }

    /// The number must be in its slot's place, the slot's place written as
    /// the ring writes it, and the value of the form of its revision.
    #[test]
    fn an_entry_whose_number_is_not_in_its_slots_place_is_no_message() {
        let laptop = device(1).public_key();
        let message = Value::Other(smallest().to_value(names).unwrap());
        let key = encode_public_key(&laptop).unwrap();
        let slot = |place: &str| format!("msg/{key}/{place}");

        // Number 65 in slot 0, and in slot 1 where it belongs.
        assert_eq!(
            take(&slot("0"), &laptop, 130, &message, names),
            Err(NotAMessage::NotInRing)
        );
        assert!(take(&slot("1"), &laptop, 130, &message, names).is_ok());
        // An odd revision with a message's value is the place of a
        // clearing, and a message is no clearing.
        assert_eq!(
            take(&slot("1"), &laptop, 131, &message, names),
            Err(NotAMessage::AnotherForm(1))
        );
        // A clearing's value at a message's revision.
        assert_eq!(
            take(
                &slot("1"),
                &laptop,
                130,
                &Value::Other(clearing_value()),
                names
            ),
            Err(NotAMessage::AnotherForm(0))
        );
        // A list's value in a message's slot, and a message in a list's.
        let list = Value::Other(ReadMarks::default().to_value().unwrap());
        assert_eq!(
            take(&slot("1"), &laptop, 130, &list, names),
            Err(NotAMessage::AnotherForm(2))
        );
        assert_eq!(
            take(&read_name(&laptop).unwrap(), &laptop, 130, &message, names),
            Err(NotAMessage::AnotherForm(1))
        );
        // A leading zero, a place past the ring, and the number itself
        // where its place is not it.
        for (place, rev) in [("07", 14), ("64", 128), ("65", 130), ("", 128), ("+7", 14)] {
            assert_eq!(place_of(&slot(place), &laptop, rev), None, "{place}");
        }
        assert_eq!(place_of(&slot("7"), &laptop, 14), Some(Place::Message(7)));
        // Number 0 is no message's, and its clearing none.
        for rev in [0, 1] {
            assert_eq!(place_of(&slot("0"), &laptop, rev), None, "{rev}");
        }
        assert_eq!(place_of(&slot("0"), &laptop, 128), Some(Place::Message(64)));
        assert_eq!(
            place_of(&slot("0"), &laptop, 129),
            Some(Place::Clearing(64))
        );
        // A number past the highest is in slot 0 here, and is no message's
        // and no clearing's: 2^42, one past the highest, at revision 2^43,
        // and 2^43, at 2^44, the first revision of band 1.
        let clearing = Value::Other(clearing_value());
        for rev in [1 << 43, 1 << 44] {
            assert_eq!(message_name(&laptop, number_of(rev)).unwrap(), slot("0"));
            for (rev, value) in [(rev, &message), (rev + 1, &clearing)] {
                assert_eq!(place_of(&slot("0"), &laptop, rev), None, "{rev}");
                assert_eq!(
                    take(&slot("0"), &laptop, rev, value, names),
                    Err(NotAMessage::NotInRing),
                    "{rev}"
                );
            }
        }
        // The control: the highest, in its slot, is a message's and a
        // clearing's.
        let highest = slot(&(AGENT_MESSAGE_NUMBER_MAX % 64).to_string());
        let rev = message_rev(AGENT_MESSAGE_NUMBER_MAX).unwrap();
        assert_eq!(
            take(&highest, &laptop, rev, &message, names),
            Ok(Taken::Message {
                number: AGENT_MESSAGE_NUMBER_MAX,
                message: smallest()
            })
        );
        assert_eq!(
            take(&highest, &laptop, rev + 1, &clearing, names),
            Ok(Taken::Clearing {
                number: AGENT_MESSAGE_NUMBER_MAX
            })
        );
        // Another prefix, or none.
        assert_eq!(place_of(&format!("msgs/{key}/7"), &laptop, 14), None);
        assert_eq!(place_of(&format!("{key}/7"), &laptop, 14), None);
    }

    /// A slot's name is its prefix, the signer's key as a device's key is
    /// written, and for a message its place in the ring: 75, 76 and 77
    /// bytes.
    #[test]
    fn a_slots_name_is_its_signers_key_and_its_place_in_the_ring() {
        let laptop = device(1).public_key();
        let key = encode_public_key(&laptop).unwrap();
        assert_eq!(key.len(), 70);
        assert!(key.starts_with("cordelia_pk1"));
        assert_eq!(read_name(&laptop).unwrap(), format!("read/{key}"));
        assert_eq!(read_name(&laptop).unwrap().len(), 75);
        for (number, place) in [
            (1, "1"),
            (9, "9"),
            (10, "10"),
            (63, "63"),
            (64, "0"),
            (65, "1"),
            (130, "2"),
        ] {
            assert_eq!(
                message_name(&laptop, number).unwrap(),
                format!("msg/{key}/{place}"),
                "{number}"
            );
        }
        assert_eq!(message_name(&laptop, 9).unwrap().len(), 76);
        assert_eq!(message_name(&laptop, 63).unwrap().len(), 77);
        assert_ne!(
            message_name(&laptop, 1).unwrap(),
            message_name(&device(2).public_key(), 1).unwrap()
        );
    }

    /// A message's revision is twice its number, and its clearing's one
    /// more: from number 1 to 2^42 - 1, whose clearing is the last revision
    /// in the bottom half of band 0. Back from either, the number.
    #[test]
    fn the_revision_of_a_message_is_twice_its_number_and_its_clearings_one_more() {
        for number in [1, 2, 63, 64, 1_000, AGENT_MESSAGE_NUMBER_MAX] {
            let message = message_rev(number).unwrap();
            let clearing = clearing_rev(number).unwrap();
            assert_eq!(message, 2 * number);
            assert_eq!(clearing, message + 1);
            assert_eq!(message % 2, 0);
            assert!(!is_clearing_rev(message));
            assert!(is_clearing_rev(clearing));
            assert_eq!(number_of(message), number);
            assert_eq!(number_of(clearing), number);
        }
        assert_eq!(AGENT_MESSAGE_NUMBER_MAX, (1 << 42) - 1);
        assert_eq!(
            clearing_rev(AGENT_MESSAGE_NUMBER_MAX),
            Some(REV_BAND_HALF - 1)
        );
        for none in [0, AGENT_MESSAGE_NUMBER_MAX + 1, u64::MAX / 2] {
            assert_eq!(message_rev(none), None, "{none}");
            assert_eq!(clearing_rev(none), None, "{none}");
        }
    }

    /// The next number is one above the highest a device holds, and there
    /// is none past the highest a message can have.
    #[test]
    fn the_next_number_stops_at_the_highest() {
        assert_eq!(next_number(0), Some(1));
        assert_eq!(next_number(69), Some(70));
        assert_eq!(
            next_number(AGENT_MESSAGE_NUMBER_MAX - 1),
            Some(AGENT_MESSAGE_NUMBER_MAX)
        );
        assert_eq!(next_number(AGENT_MESSAGE_NUMBER_MAX), None);
        // The highest is 2^42 - 1, whose clearing is 2^43 - 1.
        assert_eq!(next_number((1 << 42) - 2), Some((1 << 42) - 1));
        assert_eq!(next_number((1 << 42) - 1), None);
        assert_eq!(next_number(u64::MAX), None);
    }

    /// A number is live above the highest number held less the ring: with
    /// the highest at 200, 136 is overwritten and 137 is live.
    #[test]
    fn a_number_is_live_only_above_the_highest_less_the_ring() {
        assert!(!is_live(136, 200));
        assert!(is_live(137, 200));
        assert!(is_live(200, 200));
        assert!(is_live(1, 64));
        assert!(!is_live(1, 65));
        // Above the highest is live too: it is about to be the highest.
        assert!(is_live(201, 200));
        // At the top nothing overflows: a number less the ring is never
        // added up past u64.
        let live = |number, highest| std::panic::catch_unwind(|| is_live(number, highest));
        assert_eq!(live(u64::MAX, 0).ok(), Some(true));
        assert_eq!(live(u64::MAX, 100).ok(), Some(true));
        assert_eq!(live(u64::MAX, u64::MAX).ok(), Some(true));
        assert_eq!(live(u64::MAX - 64, u64::MAX).ok(), Some(false));
        assert_eq!(live(u64::MAX - 63, u64::MAX).ok(), Some(true));
    }

    /// The value's fields, byte for byte, in their places.
    #[test]
    fn a_messages_value_is_its_fields_in_their_places() {
        let message = Message {
            asks: true,
            sent: 0x0102_0304_0506_0708,
            nonce: [0xa1; 16],
            thread: [0xb2; 16],
            answers: [0xc3; 16],
            from: "~".into(),
            to: To::Name("ab".into()),
            link: Some("o/r#5".into()),
            body: "hi\nthere".into(),
        };
        let value = message.to_value(names).unwrap();
        assert_eq!(
            Message::from_value(&Value::Other(value.clone()), names).unwrap(),
            message
        );
        let mut expected = vec![1, 1, 1, 2, 3, 4, 5, 6, 7, 8];
        expected.extend_from_slice(&[0xa1; 16]);
        expected.extend_from_slice(&[0xb2; 16]);
        expected.extend_from_slice(&[0xc3; 16]);
        expected.extend_from_slice(&[0, 1, b'~', 1, 0, 2, b'a', b'b', 5]);
        expected.extend_from_slice(b"o/r#5");
        expected.extend_from_slice(&[0, 8]);
        expected.extend_from_slice(b"hi\nthere");
        assert_eq!(&value[..expected.len()], &expected[..]);
        assert!(value[expected.len()..].iter().all(|byte| *byte == 0));
        assert_eq!(value.len(), 1_936);

        // To every name: kind 2, and a `to` of no bytes; no link: a
        // length of 0; not asking: flags 0.
        let all = Message {
            asks: false,
            to: To::All,
            link: None,
            ..message.clone()
        };
        let value = all.to_value(names).unwrap();
        assert_eq!(value[1], 0);
        assert_eq!(&value[58..65], &[0, 1, b'~', 2, 0, 0, 0]);
        assert_eq!(&value[65..67], &[0, 8]);
        assert_eq!(
            Message::from_value(&Value::Other(value), names).unwrap(),
            all
        );
        assert_eq!(message.subject(), "hi");
    }

    /// Every check a reader makes of a message, each one past its bound:
    /// and each refused by the sender too where it can be written.
    #[test]
    fn a_reader_refuses_each_message_that_is_not_one() {
        let read = |forged: Forged| forged.read();
        // The control.
        assert!(read(Forged::new()).is_ok());

        // Another kind, or another length.
        let value = largest().to_value(names).unwrap();
        let text = Value::Text(String::from_utf8(vec![b'a'; 1_936]).unwrap());
        assert_eq!(Message::from_value(&text, names), Err(NotAMessage::Kind));
        assert_eq!(
            NotAMessage::Kind.to_string(),
            "an entry of the messages channel holds a value that is not of kind 2"
        );
        for length in [1_935, 1_937] {
            let mut changed = value.clone();
            changed.resize(length, 0);
            assert_eq!(
                Message::from_value(&Value::Other(changed), names),
                Err(NotAMessage::Length(length))
            );
        }
        assert_eq!(
            read(Forged {
                length: 2_048,
                ..Forged::new()
            }),
            Err(NotAMessage::Length(2_048))
        );

        // A form there is not, and a flag bit but bit 0.
        assert_eq!(
            read(Forged {
                form: 3,
                ..Forged::new()
            }),
            Err(NotAMessage::Form(3))
        );
        for flags in [0b10, 0b11, 0x80] {
            assert_eq!(
                read(Forged {
                    flags,
                    ..Forged::new()
                }),
                Err(NotAMessage::Flags(flags))
            );
        }
        assert!(
            read(Forged {
                flags: 1,
                ..Forged::new()
            })
            .unwrap()
            .asks
        );

        // A name past its bound, of no bytes, or that is not a name.
        for (from, to) in [(201, 3), (3, 201)] {
            assert_eq!(
                read(Forged {
                    from: vec![b'a'; from],
                    to: vec![b'a'; to],
                    ..Forged::new()
                }),
                Err(NotAMessage::Field),
                "{from} {to}"
            );
        }
        assert!(
            read(Forged {
                from: vec![b'a'; 200],
                to: vec![b'a'; 200],
                ..Forged::new()
            })
            .is_ok()
        );
        for name in [&b""[..], b"Laptop", b"a b", &[0xff, 0xfe]] {
            assert_eq!(
                read(Forged {
                    from: name.to_vec(),
                    ..Forged::new()
                }),
                Err(NotAMessage::Name),
                "{name:?}"
            );
            assert_eq!(
                read(Forged {
                    to: name.to_vec(),
                    ..Forged::new()
                }),
                Err(NotAMessage::Name),
                "{name:?}"
            );
        }

        // A kind of `to` there is not, and every name with a name.
        for kind in [0, 3, 0xff] {
            assert_eq!(
                read(Forged {
                    kind,
                    ..Forged::new()
                }),
                Err(NotAMessage::ToKind(kind))
            );
        }
        assert_eq!(
            read(Forged {
                kind: 2,
                ..Forged::new()
            }),
            Err(NotAMessage::ToWithAll)
        );
        assert_eq!(
            read(Forged {
                kind: 2,
                to: Vec::new(),
                ..Forged::new()
            })
            .unwrap()
            .to,
            To::All
        );

        // A link past its bound, or not a link.
        assert_eq!(
            read(Forged {
                link: vec![b'1'; 152],
                ..Forged::new()
            }),
            Err(NotAMessage::Field)
        );
        for link in [
            &b"owner/repo"[..],
            b"owner/repo#0",
            b"owner/repo#01",
            &[0xff],
        ] {
            assert_eq!(
                read(Forged {
                    link: link.to_vec(),
                    ..Forged::new()
                }),
                Err(NotAMessage::Link),
                "{link:?}"
            );
        }
        assert_eq!(
            read(Forged {
                link: Vec::new(),
                ..Forged::new()
            })
            .unwrap()
            .link,
            None
        );

        // A body empty, past its bound, or not UTF-8.
        assert_eq!(
            read(Forged {
                body: Vec::new(),
                ..Forged::new()
            }),
            Err(NotAMessage::BodyEmpty)
        );
        assert_eq!(
            read(Forged {
                body: vec![b'b'; 1_025],
                ..Forged::new()
            }),
            Err(NotAMessage::BodyTooLong(1_025))
        );
        assert!(
            read(Forged {
                body: vec![b'b'; 1_024],
                ..Forged::new()
            })
            .is_ok()
        );
        assert_eq!(
            read(Forged {
                body: vec![b'a', 0xff],
                ..Forged::new()
            }),
            Err(NotAMessage::BodyNotText)
        );

        // The sender refuses the same before it seals.
        let refused = |message: Message| message.to_value(names);
        assert_eq!(
            refused(Message {
                from: "f".repeat(201),
                ..smallest()
            }),
            Err(NotAMessage::Field)
        );
        assert_eq!(
            refused(Message {
                to: To::Name("t".repeat(201)),
                ..smallest()
            }),
            Err(NotAMessage::Field)
        );
        assert_eq!(
            refused(Message {
                from: "Laptop".into(),
                ..smallest()
            }),
            Err(NotAMessage::Name)
        );
        assert_eq!(
            refused(Message {
                to: To::Name(String::new()),
                ..smallest()
            }),
            Err(NotAMessage::Name)
        );
        assert_eq!(
            refused(Message {
                body: String::new(),
                ..smallest()
            }),
            Err(NotAMessage::BodyEmpty)
        );
        for link in ["", "owner/repo", "o/r#1x", &"1".repeat(152)] {
            assert!(
                refused(Message {
                    link: Some(link.to_string()),
                    ..smallest()
                })
                .is_err(),
                "{link}"
            );
        }
    }

    /// A link is an owner, a repository and a number, each within its
    /// bound and of its characters, the number with no leading zero.
    #[test]
    fn a_link_is_an_owner_a_repository_and_a_number() {
        let owner = "o".repeat(39);
        let repo = "r".repeat(100);
        let longest = format!("{owner}/{repo}#{}", "9".repeat(10));
        assert_eq!(longest.len(), AGENT_MESSAGE_LINK_MAX_BYTES);
        for link in [
            "owner/repo#1",
            "seed-drill/cordelia-node#4096",
            "O-1/r.e_p-o#10",
            "a/b#4294967296",
            longest.as_str(),
        ] {
            assert!(is_a_link(link), "{link}");
        }
        let long_owner = format!("{}/repo#1", "o".repeat(40));
        let long_repo = format!("owner/{}#1", "r".repeat(101));
        let long_number = format!("owner/repo#{}", "1".repeat(11));
        for link in [
            "",
            "owner",
            "owner/repo",
            "owner/repo#",
            "/repo#1",
            "owner/#1",
            "owner/repo#0",
            "owner/repo#012",
            "owner/repo#1a",
            "owner/repo#-1",
            "own_er/repo#1",
            "own.er/repo#1",
            "owner/re/po#1",
            "owner/repo#1#2",
            "owner/rep o#1",
            "owner/répo#1",
            "https://github.com/owner/repo#1",
            long_owner.as_str(),
            long_repo.as_str(),
            long_number.as_str(),
        ] {
            assert!(!is_a_link(link), "{link}");
        }
    }

    /// A message's ID is the first 16 bytes of SHA-256 of its label, the
    /// signer's key and the whole value: two signers of one value, or one
    /// signer of two values, give two IDs.
    #[test]
    fn a_messages_id_binds_its_signer_and_its_value() {
        let (laptop, desktop) = (device(1).public_key(), device(2).public_key());
        let value = smallest().to_value(names).unwrap();
        let mut hashed = b"cordelia v2 message id".to_vec();
        hashed.extend_from_slice(&laptop);
        hashed.extend_from_slice(&value);
        let id = message_id(&laptop, &value);
        assert_eq!(id[..], crate::sha256(&hashed)[..16]);
        assert_ne!(id, message_id(&desktop, &value));
        let other = Message {
            nonce: [1; 16],
            ..smallest()
        }
        .to_value(names)
        .unwrap();
        assert_ne!(id, message_id(&laptop, &other));
        // The fill is part of what is hashed.
        assert_ne!(id, message_id(&laptop, &value[..68]));
    }

    /// A mark is of a message and a name: the first 16 bytes of SHA-256 of
    /// its label, the ID and the name. It is never the ID, and one name's
    /// mark is not another's.
    #[test]
    fn a_read_mark_is_of_an_id_and_a_name_and_is_never_the_id() {
        let id = message_id(&device(1).public_key(), &clearing_value());
        let mut hashed = b"cordelia v2 message read".to_vec();
        hashed.extend_from_slice(&id);
        hashed.extend_from_slice(b"github.com/owner/repo");
        let mark = read_mark(&id, "github.com/owner/repo");
        assert_eq!(mark[..], crate::sha256(&hashed)[..16]);
        assert_ne!(mark, id);
        assert_ne!(mark, read_mark(&id, "~"));
        assert_ne!(mark, read_mark(&[0; 16], "github.com/owner/repo"));
    }

    /// A list holds at most 120 marks, the newest first, as it was given;
    /// a list that says more is no list.
    #[test]
    fn a_list_of_read_marks_holds_at_most_120() {
        let full = ReadMarks {
            marks: (0..120u8).map(|i| [i; 16]).collect(),
        };
        let value = full.to_value().unwrap();
        assert_eq!(&value[..3], &[2, 0, 120]);
        assert_eq!(&value[3..19], &[0; 16]);
        assert_eq!(&value[19..35], &[1; 16]);
        assert_eq!(
            ReadMarks::from_value(&Value::Other(value.clone())).unwrap(),
            full
        );
        let over = ReadMarks {
            marks: vec![[9; 16]; 121],
        };
        assert_eq!(over.to_value(), Err(NotAMessage::Marks(121)));
        let mut said = value;
        said[2] = 121;
        assert_eq!(
            ReadMarks::from_value(&Value::Other(said)),
            Err(NotAMessage::Marks(121))
        );
        let empty = ReadMarks::default().to_value().unwrap();
        assert_eq!(&empty[..3], &[2, 0, 0]);
        assert!(
            ReadMarks::from_value(&Value::Other(empty))
                .unwrap()
                .marks
                .is_empty()
        );
    }

    /// The subject is the body up to its first line feed, or all of it.
    #[test]
    fn the_subject_is_the_bodys_first_line() {
        let with = |body: &str| Message {
            body: body.into(),
            ..smallest()
        };
        assert_eq!(with("one\ntwo\nthree").subject(), "one");
        assert_eq!(with("only").subject(), "only");
        assert_eq!(with("\nsecond").subject(), "");
        assert_eq!(with("a\r\nb").subject(), "a\r");
    }
}
