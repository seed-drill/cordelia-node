//! An entry of a channel from its secret (decision 2026-10-04 §2.3), and
//! what is checked of one without any key (§2.4).
//!
//! ## In clear
//!
//! So that every hop can check it, an entry carries in clear: the
//! channel's ID, its slot, its author's key, its revision, whether it is a
//! delete, and its content. An entry's writer is its author, always. Two
//! signatures are over one thing, each under a label of its own: the
//! author's, and the channel's signing key's
//! ([`crate::derive::signing_key`]). What is signed, with a number as
//! eight bytes, the highest first:
//!
//! ```text
//! channel's ID   32
//! slot           32
//! author         32
//! revision       8
//! delete         1: 1 where the entry is a delete, and otherwise 0
//! content        32: SHA-256 of the content
//! ```
//!
//! An entry is named by the hash of what is signed ([`Entry::id`]): an
//! author can sign two entries at one revision, and they have two names.
//!
//! ## The content
//!
//! A nonce, a ciphertext and a tag, as [`crate::aes_gcm`] makes them,
//! under the channel's entry key, and bound to the channel's ID, the slot
//! and the revision: content that is moved to another channel, slot or
//! revision does not open. Its length is a power of two from 256 bytes to
//! 64 KB. What it says is filled up with zeros inside the encryption to
//! the smallest of those sizes that holds it, so a relay sees a size class
//! and no length. What it says, with a count or a length as two bytes, the
//! higher first:
//!
//! ```text
//! name     its length, then the name: text, of at least one byte
//! value    1: 0 nothing (a delete), 1 a text, 2 other bytes; and for a
//!          text and for other bytes its length, then the bytes
//! chain    a count, from 0 to 100, then for each link: the first 16
//!          bytes of the hash of a version's value, which are zeros for
//!          a delete, and the first 16 bytes of the key that signed the
//!          entry it was taken from
//! ```
//!
//! The chain is what the entry says it was written after ([`Link`]): the
//! versions it descends from, the newest first. Room is kept for it in
//! every entry: a name and a value may together be 60 KB, and at that
//! bound, with 100 links, the content is within 64 KB
//! (`cordelia_core::protocol` checks it when it is compiled). So what an
//! entry says always fits, whatever its value.
//!
//! The chain is read strictly. A count over 100, a link that is there
//! twice, or anything left over after the last link but the zeros that
//! fill the content to its size, and the entry lacks what it should say:
//! it is a version all the same, and shows nothing. [`known_to_follow`] is
//! the one question that a chain answers.
//!
//! ## Three things that are done with one
//!
//! - [`Entry::seal`] makes one, and refuses what may not be made.
//! - [`Entry::check`] is what a relay does, and what a device does first
//!   with what it is sent: both signatures hold, the content is of an
//!   allowed size, the revision is within its bound. It needs no key, and
//!   only it makes a [`CheckedEntry`], which is all that the store takes.
//! - [`CheckedEntry::open`] reads the content with the channel's secret.
//!   An entry that does not open, that opens to something else than the
//!   form above, or whose name and value are over their bound, is no
//!   version: the error says which.

use std::fmt;
use std::ops::Deref;

use cordelia_core::protocol::{
    ENTRY_LINK_HASH_BYTES, ENTRY_LINK_SIGNER_BYTES, ITEM_SEAL_OVERHEAD_BYTES, LABEL_ENTRY_AUTHOR,
    LABEL_ENTRY_CHANNEL, LABEL_ENTRY_CONTENT, MAX_ENTRY_LINKS, MAX_ENTRY_NAME_AND_VALUE_BYTES,
    MAX_ITEM_BYTES, MAX_REV, MIN_ENTRY_CONTENT_BYTES,
};

use crate::aes_gcm::{item_decrypt, item_encrypt};
use crate::derive;
use crate::identity::{NodeIdentity, is_usable_public_key, verify_signature};
use crate::slots::slot_id;
use crate::statement::{Reader, put_count};

/// Why an entry was not made, did not pass the check, or is no version.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntryError {
    #[error("an entry's revision is from 1 to 2^53 - 1, and this is {0}")]
    Revision(u64),

    #[error("an entry's name is at least one byte")]
    NameEmpty,

    #[error("an entry's name and value are at most 61440 bytes together, and these are {0}")]
    OverTheBound(usize),

    #[error("an entry that is made says its chain")]
    NoChain,

    #[error("an entry's chain has at most 100 links, and this has {0}")]
    TooManyLinks(usize),

    #[error("a link is in an entry's chain once")]
    LinkTwice,

    #[error("an entry's content is a power of two from 256 to 65536 bytes, and this is {0}")]
    ContentSize(usize),

    #[error("the author's key is not a usable public key")]
    AuthorKeyNotUsable,

    #[error("the channel's ID is not a usable public key")]
    ChannelNotUsable,

    #[error("the entry is not signed by its author")]
    AuthorSignature,

    #[error("the entry is not signed by its channel")]
    ChannelSignature,

    #[error("the entry is of another channel than this secret's")]
    AnotherChannel,

    #[error(
        "the content did not open: it is not under this channel's key, or not of this channel, \
         slot and revision"
    )]
    DidNotOpen,

    #[error("what the content says is not in an entry's form")]
    NotThisForm,

    #[error("the entry's slot is not the slot of its name")]
    AnotherSlot,

    #[error("the entry is a delete in clear and not in its content, or the other way round")]
    DeleteNotAsSigned,

    #[error("the entries are not all of one slot")]
    NotOneSlot,

    #[error("sealing failed: {0}")]
    Crypto(String),
}

/// What an entry holds for its name.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// A text: what a file holds.
    Text(String),
    /// Nothing: the name was deleted.
    Delete,
    /// Bytes that are not a text: what the local API writes that is not
    /// one. They are tagged so, and a text is never read from them.
    Other(Vec<u8>),
}

impl Value {
    /// Whether this is a delete.
    pub fn is_delete(&self) -> bool {
        matches!(self, Self::Delete)
    }

    /// The text's bytes, or the other bytes. A delete has none.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Delete => &[],
            Self::Other(bytes) => bytes,
        }
    }

    /// SHA-256 of the text, or of the other bytes: what a tie at one
    /// revision is decided by. A delete has none.
    pub fn hash(&self) -> Option<[u8; 32]> {
        (!self.is_delete()).then(|| crate::sha256(self.bytes()))
    }

    /// What a chain names this value by: the first 16 bytes of its hash,
    /// or 16 bytes of zeros where it is a delete.
    pub fn chain_hash(&self) -> [u8; ENTRY_LINK_HASH_BYTES] {
        let mut named = [0u8; ENTRY_LINK_HASH_BYTES];
        if let Some(hash) = self.hash() {
            named.copy_from_slice(&hash[..ENTRY_LINK_HASH_BYTES]);
        }
        named
    }

    /// The byte that says which of the three a value is.
    fn kind(&self) -> u8 {
        match self {
            Self::Delete => KIND_DELETE,
            Self::Text(_) => KIND_TEXT,
            Self::Other(_) => KIND_OTHER,
        }
    }
}

const KIND_DELETE: u8 = 0;
const KIND_TEXT: u8 = 1;
const KIND_OTHER: u8 = 2;

// A value is not printed for debugging: what is shown is which of the
// three it is, and how long.
impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => write!(f, "Text({} bytes)", text.len()),
            Self::Delete => f.write_str("Delete"),
            Self::Other(bytes) => write!(f, "Other({} bytes)", bytes.len()),
        }
    }
}

/// One link of an entry's chain (decision 2026-10-04 §2.3): a version
/// that the entry descends from. It is 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// What the version held: the first 16 bytes of the SHA-256 of its
    /// text, or of its bytes that are not a text. All zeros stands for a
    /// delete.
    pub hash: [u8; ENTRY_LINK_HASH_BYTES],
    /// The first 16 bytes of the key that signed the entry the version
    /// was taken from.
    pub signer: [u8; ENTRY_LINK_SIGNER_BYTES],
}

impl Link {
    /// The link that an entry holding `value` and signed by the key
    /// `signer` is in the chain of what is written over it.
    pub fn of(value: &Value, signer: [u8; 32]) -> Self {
        Self {
            hash: value.chain_hash(),
            signer: Self::signer_of(&signer),
        }
    }

    /// What a link names the key `key` by: its first 16 bytes.
    pub fn signer_of(key: &[u8; 32]) -> [u8; ENTRY_LINK_SIGNER_BYTES] {
        let mut named = [0u8; ENTRY_LINK_SIGNER_BYTES];
        named.copy_from_slice(&key[..ENTRY_LINK_SIGNER_BYTES]);
        named
    }
}

/// Whether a version is known to follow what a folder agreed (decision
/// 2026-10-04 §7.3).
///
/// `chain` is the version's chain, or `None` where its entry lacks what it
/// should say. `agreed` is what a chain names the agreed value by
/// ([`Value::chain_hash`]): the start of the hash of the text, or zeros
/// where the folder agreed a delete. `counts` says whether a key counts,
/// and is asked about a key as a link names it: by its first 16 bytes
/// ([`Link::signer_of`]).
///
/// Yes, where some link has that hash and every link before it, which is
/// every version newer than it, was signed by a key that counts. Where
/// more than one link has that hash, the first of them decides.
///
/// No otherwise: where no link has that hash, where a version between was
/// signed by a key that does not count, where the chain is empty, and
/// where the entry lacks what it should say.
pub fn known_to_follow(
    chain: Option<&[Link]>,
    agreed: &[u8; ENTRY_LINK_HASH_BYTES],
    counts: impl Fn(&[u8; ENTRY_LINK_SIGNER_BYTES]) -> bool,
) -> bool {
    let Some(chain) = chain else {
        return false;
    };
    match chain.iter().position(|link| link.hash == *agreed) {
        None => false,
        Some(place) => chain[..place].iter().all(|link| counts(&link.signer)),
    }
}

/// What is inside an entry's ciphertext: its name, its value and its
/// chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inside {
    /// The entry's name: a file's name, as text. Its slot is derived from
    /// it under the channel's slot key, so a relay sees no names.
    pub name: String,
    pub value: Value,
    /// What the entry says it was written after: for each version it
    /// descends from, the newest first, a link. At most 100, none of them
    /// twice. Two links may have one hash, where two entries were one
    /// version, and a new name's chain is empty.
    ///
    /// `None` where the entry lacks what it should say: what its content
    /// holds after its value is not a chain and the fill. It shows
    /// nothing. No entry is made so.
    pub chain: Option<Vec<Link>>,
}

impl Inside {
    /// Whether an entry may be made that holds this.
    fn validate(&self) -> Result<(), EntryError> {
        if self.name.is_empty() {
            return Err(EntryError::NameEmpty);
        }
        within_the_bound(&self.name, &self.value)?;
        let chain = self.chain.as_ref().ok_or(EntryError::NoChain)?;
        if chain.len() > MAX_ENTRY_LINKS {
            return Err(EntryError::TooManyLinks(chain.len()));
        }
        if !each_once(chain) {
            return Err(EntryError::LinkTwice);
        }
        Ok(())
    }

    /// What this takes in an entry's content, before it is filled up. One
    /// that lacks its chain is written as far as its value.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_count(&mut out, self.name.len());
        out.extend_from_slice(self.name.as_bytes());
        out.push(self.value.kind());
        if !self.value.is_delete() {
            put_count(&mut out, self.value.bytes().len());
            out.extend_from_slice(self.value.bytes());
        }
        if let Some(chain) = &self.chain {
            put_count(&mut out, chain.len());
            for link in chain {
                out.extend_from_slice(&link.hash);
                out.extend_from_slice(&link.signer);
            }
        }
        out
    }

    /// Read what a content says, from all that its encryption held: the
    /// form above, and then the zeros that fill the content.
    ///
    /// A name and a value that are not in the form are no entry's content.
    /// What follows them is the chain, read strictly: where it cannot be
    /// read, the entry lacks what it should say.
    fn from_bytes(filled: &[u8]) -> Result<Self, EntryError> {
        let other = || EntryError::NotThisForm;
        let mut reader = Reader::new(filled);

        let length = reader.count().ok_or_else(other)?;
        let name = reader.take(length).ok_or_else(other)?.to_vec();
        let name = String::from_utf8(name).map_err(|_| other())?;
        if name.is_empty() {
            return Err(other());
        }

        let value = match reader.array::<1>().ok_or_else(other)?[0] {
            KIND_DELETE => Value::Delete,
            kind @ (KIND_TEXT | KIND_OTHER) => {
                let length = reader.count().ok_or_else(other)?;
                let held = reader.take(length).ok_or_else(other)?.to_vec();
                if kind == KIND_TEXT {
                    Value::Text(String::from_utf8(held).map_err(|_| other())?)
                } else {
                    Value::Other(held)
                }
            }
            _ => return Err(other()),
        };
        // An entry over the bound is said to be that, whatever follows.
        within_the_bound(&name, &value)?;

        let chain = chain_in(&mut reader, filled.len());
        Ok(Self { name, value, chain })
    }
}

/// Read an entry's chain, strictly: `reader` is at the chain's count, in
/// a content that held `filled` bytes. `None` where the entry lacks what
/// it should say:
///
/// - the count is not there, or is over 100;
/// - a link is not whole;
/// - a link is there twice (two links with one hash and two keys are two
///   links);
/// - something is left over after the last link: anything but zeros, or
///   more zeros than fill the smallest size that holds what is said.
fn chain_in(reader: &mut Reader, filled: usize) -> Option<Vec<Link>> {
    let count = reader.count()?;
    if count > MAX_ENTRY_LINKS {
        return None;
    }
    let mut chain = Vec::with_capacity(count);
    for _ in 0..count {
        chain.push(Link {
            hash: reader.array()?,
            signer: reader.array()?,
        });
    }
    if !each_once(&chain) {
        return None;
    }
    if !reader.rest().iter().all(|byte| *byte == 0) {
        return None;
    }
    let said = filled - reader.rest().len();
    if content_size(said) != Some(filled + ITEM_SEAL_OVERHEAD_BYTES) {
        return None;
    }
    Some(chain)
}

/// An entry as it travels and as it is stored. Nothing here has been
/// checked: [`Entry::check`] does that.
#[derive(Clone, PartialEq, Eq)]
pub struct Entry {
    /// The channel's ID: the public half of its signing key.
    pub channel: [u8; 32],
    /// The slot of the entry's name.
    pub slot: [u8; 32],
    /// The key that signed the entry, and so the key that wrote it.
    pub author: [u8; 32],
    pub rev: u64,
    /// Whether the entry is a delete.
    pub delete: bool,
    /// A nonce, a ciphertext and a tag.
    pub content: Vec<u8>,
    /// The author's signature, under the author's label.
    pub author_signature: [u8; 64],
    /// The signature of the channel's signing key, under the channel's
    /// label.
    pub channel_signature: [u8; 64],
}

/// An entry that passed [`Entry::check`]: both signatures hold, its
/// content is of an allowed size, and its revision is within its bound.
///
/// Only that check makes one, so what takes this type takes nothing
/// unchecked. It is read as the entry it holds, and cannot be changed.
///
/// ```compile_fail
/// use cordelia_crypto::entry::{CheckedEntry, Entry};
/// // Not made from an entry by anything but the check.
/// fn unchecked(entry: Entry) -> CheckedEntry {
///     CheckedEntry(entry)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedEntry(Entry);

impl Entry {
    /// Make an entry of the channel whose secret is `secret`, signed by
    /// `author` and by the channel's signing key, at revision `rev`, that
    /// holds `inside`.
    ///
    /// Refused, and never cut to fit: a revision that is not from 1 to
    /// 2^53 - 1; a name of no bytes; a name and a value over their bound
    /// together; no chain; a chain of more than 100 links; and a link that
    /// is in the chain twice.
    pub fn seal(
        secret: &[u8; 32],
        author: &NodeIdentity,
        rev: u64,
        inside: &Inside,
    ) -> Result<Self, EntryError> {
        check_revision(rev)?;
        inside.validate()?;

        let keys = ChannelKeys::of(secret)?;
        let slot = slot_id(&keys.slot_key, &inside.name);
        let content = sealed(&inside.to_bytes(), &keys, &slot, rev)?;
        let channel_key = derive::signing_key(secret).map_err(crypto)?;
        let delete = inside.value.is_delete();
        Ok(signed(&channel_key, author, slot, rev, delete, content))
    }

    /// What is signed of the entry (see the module's documentation).
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 4 + 8 + 1);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.slot);
        out.extend_from_slice(&self.author);
        out.extend_from_slice(&self.rev.to_be_bytes());
        out.push(u8::from(self.delete));
        out.extend_from_slice(&crate::sha256(&self.content));
        out
    }

    /// What the entry is named by, where a device asks a relay for one:
    /// SHA-256 of what is signed. The signatures are not part of it.
    pub fn id(&self) -> [u8; 32] {
        crate::sha256(&self.signed_bytes())
    }

    /// Check the entry without any key, as a relay does before it stores
    /// one and a device does with what it is sent (decision 2026-10-04
    /// §2.4, item 1).
    ///
    /// - Its revision is from 1 to 2^53 - 1.
    /// - Its content's length is a power of two from 256 bytes to 64 KB.
    /// - Its author's key and its channel's ID are usable public keys:
    ///   under a point of small order anyone can make a signature that is
    ///   accepted.
    /// - Both signatures hold, each under its own label.
    ///
    /// Whether the author counts is for the device that reads the entry to
    /// say, with the statement it has applied. A relay holds no list.
    pub fn check(self) -> Result<CheckedEntry, EntryError> {
        check_revision(self.rev)?;
        if !is_content_size(self.content.len()) {
            return Err(EntryError::ContentSize(self.content.len()));
        }
        if !is_usable_public_key(&self.author) {
            return Err(EntryError::AuthorKeyNotUsable);
        }
        if !is_usable_public_key(&self.channel) {
            return Err(EntryError::ChannelNotUsable);
        }
        let form = self.signed_bytes();
        if !verify_signature(
            &self.author,
            &under(LABEL_ENTRY_AUTHOR, &form),
            &self.author_signature,
        ) {
            return Err(EntryError::AuthorSignature);
        }
        if !verify_signature(
            &self.channel,
            &under(LABEL_ENTRY_CHANNEL, &form),
            &self.channel_signature,
        ) {
            return Err(EntryError::ChannelSignature);
        }
        Ok(CheckedEntry(self))
    }
}

impl CheckedEntry {
    /// The entry, given up as one that is checked.
    pub fn into_entry(self) -> Entry {
        self.0
    }

    /// Open the entry with its channel's secret: its name, its value and
    /// its chain.
    ///
    /// Each error is an entry that is no version (decision 2026-10-04
    /// §2.3), and says which:
    ///
    /// - [`EntryError::AnotherChannel`]: the secret is another channel's.
    /// - [`EntryError::DidNotOpen`]: the content is not under this
    ///   channel's key, or was sealed for another channel, slot or
    ///   revision.
    /// - [`EntryError::NotThisForm`]: it opens, and what it holds is not a
    ///   name and a value in an entry's form: a name of no bytes, a name
    ///   or a text that is not text, a kind of value that there is not.
    /// - [`EntryError::OverTheBound`]: its name and value are over their
    ///   bound together.
    /// - [`EntryError::AnotherSlot`]: its slot is not the slot of its name
    ///   under the channel's slot key.
    /// - [`EntryError::DeleteNotAsSigned`]: it is a delete in clear and
    ///   holds a value, or holds none and is no delete in clear.
    ///
    /// An entry whose chain cannot be read opens: it is a version, and it
    /// lacks what it should say ([`Inside::chain`]).
    pub fn open(&self, secret: &[u8; 32]) -> Result<Inside, EntryError> {
        self.open_with(&ChannelKeys::of(secret)?)
    }

    /// [`CheckedEntry::open`], with what the channel's secret gives.
    pub(crate) fn open_with(&self, keys: &ChannelKeys) -> Result<Inside, EntryError> {
        let entry = &self.0;
        if entry.channel != keys.id {
            return Err(EntryError::AnotherChannel);
        }
        let filled = item_decrypt(
            &keys.entry_key,
            &entry.content,
            &bound_to(&entry.channel, &entry.slot, entry.rev),
        )
        .map_err(|_| EntryError::DidNotOpen)?;
        let inside = Inside::from_bytes(&filled)?;
        if slot_id(&keys.slot_key, &inside.name) != entry.slot {
            return Err(EntryError::AnotherSlot);
        }
        if inside.value.is_delete() != entry.delete {
            return Err(EntryError::DeleteNotAsSigned);
        }
        Ok(inside)
    }
}

impl Deref for CheckedEntry {
    type Target = Entry;

    fn deref(&self) -> &Entry {
        &self.0
    }
}

/// What reading a channel's entries takes from its secret: its ID, its
/// entry key and its slot key.
pub(crate) struct ChannelKeys {
    pub(crate) id: [u8; 32],
    entry_key: [u8; 32],
    slot_key: [u8; 32],
}

impl ChannelKeys {
    pub(crate) fn of(secret: &[u8; 32]) -> Result<Self, EntryError> {
        Ok(Self {
            id: derive::channel_id(secret).map_err(crypto)?,
            entry_key: derive::entry_key(secret).map_err(crypto)?,
            slot_key: derive::slot_key(secret).map_err(crypto)?,
        })
    }
}

/// Whether an entry's content may be `bytes` long: a power of two from
/// 256 bytes to 64 KB.
pub fn is_content_size(bytes: usize) -> bool {
    bytes.is_power_of_two() && (MIN_ENTRY_CONTENT_BYTES..=MAX_ITEM_BYTES).contains(&bytes)
}

/// The size of the content that says `said` bytes: the smallest that holds
/// them with the nonce and the tag. `None` where that is over 64 KB.
fn content_size(said: usize) -> Option<usize> {
    let size = (said + ITEM_SEAL_OVERHEAD_BYTES)
        .next_power_of_two()
        .max(MIN_ENTRY_CONTENT_BYTES);
    (size <= MAX_ITEM_BYTES).then_some(size)
}

/// Seal what a content says: filled up with zeros to its size, under the
/// channel's entry key, and bound to the channel, the slot and the
/// revision.
pub(crate) fn sealed(
    said: &[u8],
    keys: &ChannelKeys,
    slot: &[u8; 32],
    rev: u64,
) -> Result<Vec<u8>, EntryError> {
    let needed = said.len() + ITEM_SEAL_OVERHEAD_BYTES;
    let size = content_size(said.len()).ok_or(EntryError::ContentSize(needed))?;
    let mut filled = said.to_vec();
    filled.resize(size - ITEM_SEAL_OVERHEAD_BYTES, 0);
    item_encrypt(&keys.entry_key, &filled, &bound_to(&keys.id, slot, rev)).map_err(crypto)
}

/// The entry with these clear fields, signed by its author and by its
/// channel's signing key, each under its own label. Nothing is checked
/// here: [`Entry::seal`] checks what it is given first.
pub(crate) fn signed(
    channel_key: &NodeIdentity,
    author: &NodeIdentity,
    slot: [u8; 32],
    rev: u64,
    delete: bool,
    content: Vec<u8>,
) -> Entry {
    let mut entry = Entry {
        channel: channel_key.public_key(),
        slot,
        author: author.public_key(),
        rev,
        delete,
        content,
        author_signature: [0u8; 64],
        channel_signature: [0u8; 64],
    };
    let form = entry.signed_bytes();
    entry.author_signature = author.sign(&under(LABEL_ENTRY_AUTHOR, &form));
    entry.channel_signature = channel_key.sign(&under(LABEL_ENTRY_CHANNEL, &form));
    entry
}

/// What a key signs: a signature's label, and what is signed of the entry.
fn under(label: &[u8], form: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(label.len() + form.len());
    signed.extend_from_slice(label);
    signed.extend_from_slice(form);
    signed
}

/// What a content's encryption is bound to: the content's label, the
/// channel's ID, the slot and the revision.
fn bound_to(channel: &[u8; 32], slot: &[u8; 32], rev: u64) -> Vec<u8> {
    let mut bound = Vec::with_capacity(LABEL_ENTRY_CONTENT.len() + 32 + 32 + 8);
    bound.extend_from_slice(LABEL_ENTRY_CONTENT);
    bound.extend_from_slice(channel);
    bound.extend_from_slice(slot);
    bound.extend_from_slice(&rev.to_be_bytes());
    bound
}

/// Whether `rev` can be an entry's revision at all: from 1 to 2^53 - 1.
/// Revision 0 is no entry's, under any statement.
fn check_revision(rev: u64) -> Result<(), EntryError> {
    if !(1..=MAX_REV).contains(&rev) {
        return Err(EntryError::Revision(rev));
    }
    Ok(())
}

/// Whether a name and a value are within their bound together.
fn within_the_bound(name: &str, value: &Value) -> Result<(), EntryError> {
    let together = name.len() + value.bytes().len();
    if together > MAX_ENTRY_NAME_AND_VALUE_BYTES {
        return Err(EntryError::OverTheBound(together));
    }
    Ok(())
}

/// Whether no link is in a chain twice, hash and key.
fn each_once(chain: &[Link]) -> bool {
    chain
        .iter()
        .enumerate()
        .all(|(place, link)| !chain[..place].contains(link))
}

fn crypto(e: crate::CryptoError) -> EntryError {
    EntryError::Crypto(e.to_string())
}

// An entry's content is up to 64 KB of ciphertext. What is shown for
// debugging is its length, and the keys and the slot by their first bytes.
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let short = |bytes: &[u8; 32]| hex::encode(&bytes[..4]);
        f.debug_struct("Entry")
            .field("channel", &short(&self.channel))
            .field("slot", &short(&self.slot))
            .field("author", &short(&self.author))
            .field("rev", &self.rev)
            .field("delete", &self.delete)
            .field("content", &self.content.len())
            .field("id", &hex::encode(&self.id()[..4]))
            .finish_non_exhaustive()
    }
}

/// What the tests of this module and of a slot's current version are made
/// from.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub(crate) const SECRET: [u8; 32] = [0x11; 32];
    pub(crate) const OTHER_SECRET: [u8; 32] = [0x12; 32];

    /// The device numbered `n`, with its key pair.
    pub(crate) fn device(n: u8) -> NodeIdentity {
        NodeIdentity::from_seed([n; 32]).unwrap()
    }

    pub(crate) fn key(n: u8) -> [u8; 32] {
        device(n).public_key()
    }

    /// The signing key of the channel whose secret is [`SECRET`].
    pub(crate) fn channel_key() -> NodeIdentity {
        derive::signing_key(&SECRET).unwrap()
    }

    /// The slot of `name` in the channel whose secret is [`SECRET`].
    pub(crate) fn slot_of(name: &str) -> [u8; 32] {
        slot_id(&derive::slot_key(&SECRET).unwrap(), name)
    }

    /// The link of a version that held the text `said`, taken from an
    /// entry that device `n` signed.
    pub(crate) fn link(said: &str, n: u8) -> Link {
        Link::of(&Value::Text(said.to_string()), key(n))
    }

    /// What a chain names the text `said` by: the start of its hash.
    pub(crate) fn named(said: &str) -> [u8; 16] {
        Value::Text(said.to_string()).chain_hash()
    }

    /// What a link names the key of device `n` by: its start.
    pub(crate) fn signer(n: u8) -> [u8; 16] {
        Link::signer_of(&key(n))
    }

    /// `name` holding `value`, in an entry of a new name: its chain is
    /// empty.
    pub(crate) fn holding(name: &str, value: Value) -> Inside {
        Inside {
            name: name.to_string(),
            value,
            chain: Some(Vec::new()),
        }
    }

    pub(crate) fn text(name: &str, text: &str) -> Inside {
        holding(name, Value::Text(text.to_string()))
    }

    /// An entry of [`SECRET`]'s channel that device `n` made at `rev`,
    /// checked.
    pub(crate) fn entry(n: u8, rev: u64, inside: &Inside) -> CheckedEntry {
        Entry::seal(&SECRET, &device(n), rev, inside)
            .unwrap()
            .check()
            .unwrap()
    }

    /// An entry of [`SECRET`]'s channel in the slot of `name`, signed by
    /// device `n` and by the channel, whose content says `said`, whatever
    /// that is. It passes the check: a relay cannot tell what it says.
    pub(crate) fn saying(n: u8, rev: u64, name: &str, said: &[u8], delete: bool) -> CheckedEntry {
        let keys = ChannelKeys::of(&SECRET).unwrap();
        let slot = slot_of(name);
        let content = sealed(said, &keys, &slot, rev).unwrap();
        signed(&channel_key(), &device(n), slot, rev, delete, content)
            .check()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use cordelia_core::protocol::{MAX_ENTRY_CHAIN_BYTES, REV_COUNT_BITS};

    /// The revision at `count` in `band`.
    fn at(band: u64, count: u64) -> u64 {
        (band << REV_COUNT_BITS) + count
    }

    /// An entry that descends from two versions.
    fn sample() -> Inside {
        Inside {
            name: "notes.md".to_string(),
            value: Value::Text("what the file holds".to_string()),
            chain: Some(vec![
                link("what it held before", 2),
                link("what it held first", 1),
            ]),
        }
    }

    /// The entry that device 1 made of [`sample`] at revision 5, before it
    /// is checked.
    fn made() -> Entry {
        Entry::seal(&SECRET, &device(1), 5, &sample()).unwrap()
    }

    /// The device, or the channel's signing key, that `key` is the public
    /// half of.
    fn holder_of(key: &[u8; 32]) -> NodeIdentity {
        let other_channel = derive::signing_key(&OTHER_SECRET).unwrap();
        [channel_key(), other_channel, device(1), device(2)]
            .into_iter()
            .find(|identity| identity.public_key() == *key)
            .unwrap()
    }

    /// The entry's author signs it again, as it now is.
    fn author_signs_again(entry: &mut Entry) {
        let form = entry.signed_bytes();
        entry.author_signature = holder_of(&entry.author).sign(&under(LABEL_ENTRY_AUTHOR, &form));
    }

    /// The entry's channel signs it again, as it now is.
    fn channel_signs_again(entry: &mut Entry) {
        let form = entry.signed_bytes();
        entry.channel_signature =
            holder_of(&entry.channel).sign(&under(LABEL_ENTRY_CHANNEL, &form));
    }

    /// A text of `length` bytes.
    fn text_of(length: usize) -> Value {
        Value::Text("x".repeat(length))
    }

    /// A chain of `links` links, each of another version and another key.
    fn chain_of(links: usize) -> Vec<Link> {
        (0..links)
            .map(|n| Link {
                hash: [n as u8; 16],
                signer: [0xd0 + (n % 8) as u8; 16],
            })
            .collect()
    }

    // ── Making one, and what it is ───────────────────────────────────

    #[test]
    fn an_entry_is_made_and_opens_to_what_it_was_made_from() {
        for value in [
            Value::Text("what the file holds".to_string()),
            // An empty text is a text, and no delete.
            Value::Text(String::new()),
            Value::Delete,
            // Bytes that are not a text.
            Value::Other(vec![0x00, 0x9f, 0x92, 0x96]),
            Value::Other(Vec::new()),
        ] {
            let inside = Inside {
                value: value.clone(),
                ..sample()
            };
            let entry = Entry::seal(&SECRET, &device(1), 5, &inside).unwrap();
            assert_eq!(entry.channel, derive::channel_id(&SECRET).unwrap());
            assert_eq!(entry.slot, slot_of("notes.md"));
            assert_eq!(entry.author, key(1));
            assert_eq!(entry.rev, 5);
            assert_eq!(entry.delete, value.is_delete(), "{value:?}");

            let checked = entry.clone().check().unwrap();
            assert_eq!(checked.open(&SECRET).unwrap(), inside, "{value:?}");
            // What is checked is the entry that was made, and no other.
            assert_eq!(*checked, entry);
            assert_eq!(checked.into_entry(), entry);
        }

        // Made again it is sealed afresh: another content and another
        // name, that open to the same.
        let (one, other) = (made(), made());
        assert_ne!(one.content, other.content);
        assert_ne!(one.id(), other.id());
        assert_eq!(
            one.check().unwrap().open(&SECRET).unwrap(),
            other.check().unwrap().open(&SECRET).unwrap()
        );
    }

    /// What is signed, byte by byte.
    #[test]
    fn what_is_signed_of_an_entry_has_one_form() {
        let entry = made();
        let mut form = Vec::new();
        form.extend_from_slice(&derive::channel_id(&SECRET).unwrap());
        form.extend_from_slice(&slot_of("notes.md"));
        form.extend_from_slice(&key(1));
        form.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]);
        form.push(0);
        form.extend_from_slice(&crate::sha256(&entry.content));
        assert_eq!(entry.signed_bytes(), form);
        assert_eq!(form.len(), 32 + 32 + 32 + 8 + 1 + 32);

        // At a revision of more than one byte, and a delete.
        let rev = at(3, 0x0102);
        let inside = holding("notes.md", Value::Delete);
        let entry = Entry::seal(&SECRET, &device(2), rev, &inside).unwrap();
        let mut form = Vec::new();
        form.extend_from_slice(&derive::channel_id(&SECRET).unwrap());
        form.extend_from_slice(&slot_of("notes.md"));
        form.extend_from_slice(&key(2));
        form.extend_from_slice(&[0, 0, 0x30, 0, 0, 0, 0x01, 0x02]);
        form.push(1);
        form.extend_from_slice(&crate::sha256(&entry.content));
        assert_eq!(entry.signed_bytes(), form);
        // The form is one length whatever the entry: nothing in it is there
        // for some entries and not for others.
        assert_eq!(form.len(), 137);
    }

    #[test]
    fn an_entry_is_named_by_the_hash_of_what_is_signed() {
        let entry = made();
        assert_eq!(entry.id(), crate::sha256(&entry.signed_bytes()));

        // The signatures are not part of the name.
        let mut unsigned = entry.clone();
        unsigned.author_signature = [0; 64];
        unsigned.channel_signature = [0; 64];
        assert_eq!(unsigned.id(), entry.id());

        // An author can sign two entries at one revision, and they have
        // two names.
        let other = Entry::seal(&SECRET, &device(1), 5, &text("notes.md", "another")).unwrap();
        assert_eq!(
            (other.author, other.slot, other.rev),
            (entry.author, entry.slot, entry.rev)
        );
        assert_ne!(other.id(), entry.id());
        // So have two authors' entries of one version.
        let by_another = Entry::seal(&SECRET, &device(2), 5, &sample()).unwrap();
        assert_ne!(by_another.id(), entry.id());
    }

    /// Each label, spelled here as it is published: a change to a label,
    /// or to what is signed under it, fails here.
    #[test]
    fn each_signature_is_under_a_label_of_its_own() {
        let entry = made();
        let form = entry.signed_bytes();
        let under_label = |label: &[u8]| [label, form.as_slice()].concat();

        assert!(verify_signature(
            &key(1),
            &under_label(b"cordelia v2 author"),
            &entry.author_signature
        ));
        assert!(verify_signature(
            &derive::channel_id(&SECRET).unwrap(),
            &under_label(b"cordelia v2 channel"),
            &entry.channel_signature
        ));
        // Neither is over what is signed alone, nor under the other's
        // label.
        for (signer, signature, others_label) in [
            (key(1), entry.author_signature, &b"cordelia v2 channel"[..]),
            (
                entry.channel,
                entry.channel_signature,
                &b"cordelia v2 author"[..],
            ),
        ] {
            assert!(!verify_signature(&signer, &form, &signature));
            assert!(!verify_signature(
                &signer,
                &under_label(others_label),
                &signature
            ));
        }
    }

    // ── The check that needs no key ──────────────────────────────────

    #[test]
    fn an_entry_with_either_signature_wrong_or_missing_is_refused() {
        // The control: as it was made, it passes.
        assert!(made().check().is_ok());

        // Missing: nothing where a signature is.
        let mut entry = made();
        entry.author_signature = [0; 64];
        assert_eq!(entry.check(), Err(EntryError::AuthorSignature));
        let mut entry = made();
        entry.channel_signature = [0; 64];
        assert_eq!(entry.check(), Err(EntryError::ChannelSignature));

        // Wrong by one bit, in either half of a signature.
        for place in [0, 31, 32, 63] {
            let mut entry = made();
            entry.author_signature[place] ^= 1;
            assert_eq!(entry.check(), Err(EntryError::AuthorSignature), "{place}");
            let mut entry = made();
            entry.channel_signature[place] ^= 1;
            assert_eq!(entry.check(), Err(EntryError::ChannelSignature), "{place}");
        }

        // Another device's signature in the author's place.
        let mut entry = made();
        let form = entry.signed_bytes();
        entry.author_signature = device(2).sign(&under(LABEL_ENTRY_AUTHOR, &form));
        assert_eq!(entry.check(), Err(EntryError::AuthorSignature));

        // Another channel's signature in the channel's place, and the
        // author's own: a device that does not hold the channel's secret
        // cannot make the second signature.
        for signer in [derive::signing_key(&OTHER_SECRET).unwrap(), device(1)] {
            let mut entry = made();
            entry.channel_signature = signer.sign(&under(LABEL_ENTRY_CHANNEL, &form));
            assert_eq!(entry.check(), Err(EntryError::ChannelSignature));
        }
    }

    /// Each clear field is under both signatures. Changed after signing,
    /// the entry is refused. So it is where its author signs it again,
    /// which a device that does not hold the channel's secret can do, and
    /// where the channel's key signs it again, which a device that holds
    /// the secret can do to another's entry.
    #[test]
    fn each_clear_field_changed_after_signing_is_refused() {
        let another = Entry::seal(&SECRET, &device(1), 5, &sample()).unwrap();
        type Change = Box<dyn Fn(&mut Entry)>;
        let changes: Vec<(&str, Change)> = vec![
            (
                "channel",
                Box::new(|e| e.channel = derive::channel_id(&OTHER_SECRET).unwrap()),
            ),
            ("slot", Box::new(|e| e.slot = slot_of("other.md"))),
            ("slot, by a bit", Box::new(|e| e.slot[31] ^= 1)),
            ("author", Box::new(|e| e.author = key(2))),
            ("revision, up", Box::new(|e| e.rev = 6)),
            ("revision, down", Box::new(|e| e.rev = 4)),
            ("revision, to another band", Box::new(|e| e.rev = at(1, 5))),
            ("delete", Box::new(|e| e.delete = true)),
            ("content, by a bit", Box::new(|e| e.content[40] ^= 1)),
            (
                "content, for another of its size",
                Box::new(move |e| e.content = another.content.clone()),
            ),
        ];
        let original = made();
        for (what, change) in &changes {
            let mut entry = original.clone();
            change(&mut entry);
            assert_ne!(entry.signed_bytes(), original.signed_bytes(), "{what}");
            assert_eq!(
                entry.clone().check(),
                Err(EntryError::AuthorSignature),
                "{what}"
            );

            let mut by_author = entry.clone();
            author_signs_again(&mut by_author);
            assert_eq!(
                by_author.check(),
                Err(EntryError::ChannelSignature),
                "{what}"
            );

            let mut by_channel = entry.clone();
            channel_signs_again(&mut by_channel);
            assert_eq!(
                by_channel.check(),
                Err(EntryError::AuthorSignature),
                "{what}"
            );

            // The control: signed again by both, it is another entry, and
            // passes.
            author_signs_again(&mut entry);
            channel_signs_again(&mut entry);
            assert!(entry.check().is_ok(), "{what}");
        }
    }

    #[test]
    fn the_two_signatures_are_not_interchangeable() {
        // Each in the other's place.
        let mut entry = made();
        std::mem::swap(&mut entry.author_signature, &mut entry.channel_signature);
        assert_eq!(entry.check(), Err(EntryError::AuthorSignature));

        // Where one key makes both, the two are still two: an entry whose
        // author is its channel's own signing key.
        let keys = ChannelKeys::of(&SECRET).unwrap();
        let slot = slot_of("notes.md");
        let content = sealed(&sample().to_bytes(), &keys, &slot, 5).unwrap();
        let both = signed(&channel_key(), &channel_key(), slot, 5, false, content);
        assert_eq!(both.author, both.channel);
        assert_ne!(both.author_signature, both.channel_signature);
        assert!(both.clone().check().is_ok());

        let mut swapped = both.clone();
        std::mem::swap(
            &mut swapped.author_signature,
            &mut swapped.channel_signature,
        );
        assert_eq!(swapped.check(), Err(EntryError::AuthorSignature));
        let mut authors_twice = both.clone();
        authors_twice.channel_signature = both.author_signature;
        assert_eq!(authors_twice.check(), Err(EntryError::ChannelSignature));
        let mut channels_twice = both.clone();
        channels_twice.author_signature = both.channel_signature;
        assert_eq!(channels_twice.check(), Err(EntryError::AuthorSignature));
    }

    #[test]
    fn an_entrys_revision_is_from_1_to_the_bound() {
        for rev in [1, 2, at(256, 0), MAX_REV - 1, MAX_REV] {
            let entry = Entry::seal(&SECRET, &device(1), rev, &text("a.md", "t")).unwrap();
            assert!(entry.check().is_ok(), "{rev}");
        }
        for rev in [0, MAX_REV + 1, 1 << 53, u64::MAX] {
            assert_eq!(
                Entry::seal(&SECRET, &device(1), rev, &text("a.md", "t")),
                Err(EntryError::Revision(rev))
            );
            // One that another implementation made, signed as any entry
            // is.
            let keys = ChannelKeys::of(&SECRET).unwrap();
            let slot = slot_of("a.md");
            let content = sealed(&text("a.md", "t").to_bytes(), &keys, &slot, rev).unwrap();
            let entry = signed(&channel_key(), &device(1), slot, rev, false, content);
            assert_eq!(entry.check(), Err(EntryError::Revision(rev)));
        }
    }

    /// Under a point of small order anyone can make a signature that is
    /// accepted, for any message. An entry that names such a key as its
    /// author, or as its channel, is refused before the signature is
    /// looked at.
    #[test]
    fn an_entry_under_a_key_that_anyone_can_sign_for_is_refused() {
        // The identity, and with it a signature that is the identity and
        // zero.
        let mut anyones = [0u8; 32];
        anyones[0] = 1;
        let mut signature = [0u8; 64];
        signature[0] = 1;

        let mut forged = made();
        forged.author = anyones;
        forged.author_signature = signature;
        channel_signs_again(&mut forged);
        // The control: both signatures are accepted as signatures.
        let form = forged.signed_bytes();
        assert!(verify_signature(
            &anyones,
            &under(LABEL_ENTRY_AUTHOR, &form),
            &signature
        ));
        assert!(verify_signature(
            &forged.channel,
            &under(LABEL_ENTRY_CHANNEL, &form),
            &forged.channel_signature
        ));
        assert_eq!(forged.check(), Err(EntryError::AuthorKeyNotUsable));

        let mut forged = made();
        forged.channel = anyones;
        forged.channel_signature = signature;
        author_signs_again(&mut forged);
        let form = forged.signed_bytes();
        assert!(verify_signature(
            &anyones,
            &under(LABEL_ENTRY_CHANNEL, &form),
            &signature
        ));
        assert!(verify_signature(
            &forged.author,
            &under(LABEL_ENTRY_AUTHOR, &form),
            &forged.author_signature
        ));
        assert_eq!(forged.check(), Err(EntryError::ChannelNotUsable));

        // Bytes that are no point at all are refused the same way.
        assert!(!is_usable_public_key(&[0x02; 32]));
        let mut entry = made();
        entry.author = [0x02; 32];
        assert_eq!(entry.check(), Err(EntryError::AuthorKeyNotUsable));
        let mut entry = made();
        entry.channel = [0x02; 32];
        assert_eq!(entry.check(), Err(EntryError::ChannelNotUsable));
    }

    // ── The content's size ───────────────────────────────────────────

    /// With a name of one byte and an empty chain, a content is its text
    /// and 36 bytes more: the nonce and the tag, the name with its length,
    /// the value's kind and its length, and the count of no links.
    #[test]
    fn a_content_is_one_of_nine_sizes() {
        let sizes = [256, 512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536];
        for (i, size) in sizes.into_iter().enumerate() {
            assert!(is_content_size(size), "{size}");
            // The least and the most text that this size holds. The most
            // that the largest holds is at the bound on a name and a
            // value.
            let least = if i == 0 { 0 } else { size / 2 - 35 };
            let most = (size - 36).min(MAX_ENTRY_NAME_AND_VALUE_BYTES - 1);
            for length in [least, most] {
                let inside = holding("n", text_of(length));
                assert_eq!(inside.to_bytes().len(), length + 8);
                let entry = Entry::seal(&SECRET, &device(1), 5, &inside).unwrap();
                assert_eq!(entry.content.len(), size, "{length}");
                let checked = entry.check().unwrap();
                assert_eq!(checked.open(&SECRET).unwrap(), inside, "{length}");
            }
        }

        // Any other length is refused, whoever signed the entry.
        for length in [
            0, 1, 27, 28, 128, 255, 257, 384, 511, 513, 1000, 65_535, 65_537, 131_072,
        ] {
            assert!(!is_content_size(length), "{length}");
            let entry = signed(
                &channel_key(),
                &device(1),
                slot_of("n"),
                5,
                false,
                vec![0x5a; length],
            );
            assert_eq!(entry.check(), Err(EntryError::ContentSize(length)));
        }
        // And one of an allowed length passes, whatever it holds: a relay
        // does not read it.
        let entry = signed(
            &channel_key(),
            &device(1),
            slot_of("n"),
            5,
            false,
            vec![0x5a; 256],
        );
        assert!(entry.check().is_ok());
    }

    #[test]
    fn the_padding_hides_the_length_within_a_size_class() {
        let content_of = |length: usize| {
            Entry::seal(&SECRET, &device(1), 5, &holding("n", text_of(length)))
                .unwrap()
                .content
        };
        // From no text to 220 bytes of it: one size.
        for length in [0, 1, 2, 100, 219, 220] {
            assert_eq!(content_of(length).len(), 256, "{length}");
        }
        // One byte more is the next size, and so is everything up to its
        // end.
        for length in [221, 300, 476] {
            assert_eq!(content_of(length).len(), 512, "{length}");
        }
        assert_eq!(content_of(477).len(), 1024);
        // A delete and a text are one size too.
        let delete = Entry::seal(&SECRET, &device(1), 5, &holding("n", Value::Delete));
        assert_eq!(delete.unwrap().content.len(), 256);

        // What fills a content is inside the encryption: zeros after what
        // it says, to the size less the nonce and the tag.
        let inside = holding("n", text_of(100));
        let keys = ChannelKeys::of(&SECRET).unwrap();
        let slot = slot_of("n");
        let content = sealed(&inside.to_bytes(), &keys, &slot, 5).unwrap();
        let filled =
            item_decrypt(&keys.entry_key, &content, &bound_to(&keys.id, &slot, 5)).unwrap();
        assert_eq!(filled.len(), 256 - ITEM_SEAL_OVERHEAD_BYTES);
        let said = inside.to_bytes();
        assert_eq!(filled[..said.len()], said);
        assert!(filled[said.len()..].iter().all(|byte| *byte == 0));
        assert!(filled.len() > said.len());
    }

    /// A name and a value may together be 60 KB, and not one byte more: a
    /// text, other bytes, and a name alone.
    #[test]
    fn a_name_and_a_value_over_their_bound_are_refused() {
        let bound = MAX_ENTRY_NAME_AND_VALUE_BYTES;
        assert_eq!(bound, 61_440);
        let long_name = "n".repeat(bound);
        let at_the_bound = [
            holding("n", text_of(bound - 1)),
            holding("n", Value::Other(vec![7; bound - 1])),
            holding("name", text_of(bound - 4)),
            holding(&long_name, Value::Delete),
            holding(&long_name, text_of(0)),
        ];
        for inside in &at_the_bound {
            let entry = Entry::seal(&SECRET, &device(1), 5, inside).unwrap();
            assert_eq!(entry.content.len(), 65_536);
            assert_eq!(&entry.check().unwrap().open(&SECRET).unwrap(), inside);
        }

        let longer_name = "n".repeat(bound + 1);
        let one_over = [
            holding("n", text_of(bound)),
            holding("n", Value::Other(vec![7; bound])),
            holding("name", text_of(bound - 3)),
            holding(&longer_name, Value::Delete),
            holding(&long_name, text_of(1)),
        ];
        for inside in &one_over {
            assert_eq!(
                Entry::seal(&SECRET, &device(1), 5, inside),
                Err(EntryError::OverTheBound(bound + 1))
            );
            // One that another implementation made: it passes the check,
            // which reads no content, and it is no version.
            let made = saying(
                1,
                5,
                &inside.name,
                &inside.to_bytes(),
                inside.value.is_delete(),
            );
            assert_eq!(made.content.len(), 65_536);
            assert_eq!(made.open(&SECRET), Err(EntryError::OverTheBound(bound + 1)));
        }

        // As much as a content can hold at all.
        let inside = holding("n", text_of(65_536 - 36));
        assert_eq!(
            Entry::seal(&SECRET, &device(1), 5, &inside),
            Err(EntryError::OverTheBound(65_501))
        );
        let made = saying(1, 5, "n", &inside.to_bytes(), false);
        assert_eq!(made.open(&SECRET), Err(EntryError::OverTheBound(65_501)));
    }

    /// Room is kept in every entry for what it says: at the bound on a
    /// name and a value, a chain of 100 links still fits.
    #[test]
    fn a_hundred_links_fit_beside_a_value_at_the_bound() {
        assert_eq!(MAX_ENTRY_LINKS, 100);
        let longest = Inside {
            chain: Some(chain_of(100)),
            ..holding("n", Value::Delete)
        };
        let nothing = holding("n", Value::Delete);
        // A link is 32 bytes: the start of a hash, and the start of a key.
        assert_eq!(
            longest.to_bytes().len() - nothing.to_bytes().len(),
            100 * 32
        );
        assert_eq!(
            longest.to_bytes().len() - nothing.to_bytes().len() + 2,
            MAX_ENTRY_CHAIN_BYTES
        );

        for value in [
            text_of(MAX_ENTRY_NAME_AND_VALUE_BYTES - 1),
            Value::Other(vec![7; MAX_ENTRY_NAME_AND_VALUE_BYTES - 1]),
        ] {
            let inside = Inside {
                name: "n".to_string(),
                value,
                chain: Some(chain_of(100)),
            };
            // The largest content there is: 64,675 bytes of the 65,536.
            let largest = inside.to_bytes().len() + ITEM_SEAL_OVERHEAD_BYTES;
            assert_eq!(largest, 64_675);
            assert_eq!(MAX_ITEM_BYTES - largest, 861);

            let entry = Entry::seal(&SECRET, &device(1), 9, &inside).unwrap();
            assert_eq!(entry.content.len(), MAX_ITEM_BYTES);
            let opened = entry.check().unwrap().open(&SECRET).unwrap();
            assert_eq!(opened, inside);
            assert_eq!(opened.chain.unwrap().len(), 100);
        }
    }

    // ── What may be made ─────────────────────────────────────────────

    #[test]
    fn an_entry_that_says_what_it_may_not_is_not_made() {
        let seal = |chain: Option<Vec<Link>>| {
            let inside = Inside {
                chain,
                ..text("a.md", "t")
            };
            Entry::seal(&SECRET, &device(1), 5, &inside).map(|_| ())
        };

        // A chain of more than 100 links.
        assert_eq!(seal(Some(chain_of(100))), Ok(()));
        for links in [101, 102, 200] {
            assert_eq!(
                seal(Some(chain_of(links))),
                Err(EntryError::TooManyLinks(links))
            );
        }

        // A link that is there twice, wherever the two are. Two links with
        // one hash and two keys are two links, and so are two with one key
        // and two hashes: two entries that were one version, and a device
        // that wrote twice.
        let (one, other_key, other_text) = (link("a", 1), link("a", 2), link("b", 1));
        assert_eq!(seal(Some(vec![one, other_key, other_text])), Ok(()));
        assert_eq!(seal(Some(vec![one, one])), Err(EntryError::LinkTwice));
        assert_eq!(
            seal(Some(vec![one, other_key, other_text, one])),
            Err(EntryError::LinkTwice)
        );
        assert_eq!(
            seal(Some(vec![other_text, one, other_key, other_key])),
            Err(EntryError::LinkTwice)
        );

        // No chain at all: an entry that is made says its chain, which is
        // empty for a new name.
        assert_eq!(seal(Some(Vec::new())), Ok(()));
        assert_eq!(seal(None), Err(EntryError::NoChain));

        // A name of no bytes names nothing.
        assert_eq!(
            Entry::seal(&SECRET, &device(1), 5, &text("", "t")),
            Err(EntryError::NameEmpty)
        );
    }

    // ── Opening one ──────────────────────────────────────────────────

    /// What a content says, byte by byte, before it is filled and sealed.
    #[test]
    fn what_a_content_says_is_laid_out_as_documented() {
        let inside = Inside {
            name: "a.md".to_string(),
            value: Value::Text("hey".to_string()),
            chain: Some(vec![
                Link {
                    hash: [0x7e; 16],
                    signer: [0xa1; 16],
                },
                Link {
                    hash: [0; 16],
                    signer: [0xb2; 16],
                },
            ]),
        };
        let mut said = Vec::new();
        said.extend_from_slice(&[0, 4]);
        said.extend_from_slice(b"a.md");
        said.extend_from_slice(&[1, 0, 3]);
        said.extend_from_slice(b"hey");
        said.extend_from_slice(&[0, 2]);
        said.extend_from_slice(&[0x7e; 16]);
        said.extend_from_slice(&[0xa1; 16]);
        said.extend_from_slice(&[0; 16]);
        said.extend_from_slice(&[0xb2; 16]);
        assert_eq!(inside.to_bytes(), said);
        assert_eq!(said.len(), 2 + 4 + 3 + 3 + 2 + 2 * 32);

        // Read back, with the zeros that fill a content after it.
        let mut filled = said.clone();
        filled.resize(228, 0);
        assert_eq!(Inside::from_bytes(&filled), Ok(inside));

        // A delete holds nothing, and other bytes are tagged so. An empty
        // chain is a count of no links.
        let delete = holding("a.md", Value::Delete);
        assert_eq!(
            delete.to_bytes(),
            [&[0, 4][..], b"a.md", &[0], &[0, 0]].concat()
        );
        let other = holding("a.md", Value::Other(vec![0xff, 0x00]));
        assert_eq!(
            other.to_bytes(),
            [&[0, 4][..], b"a.md", &[2, 0, 2, 0xff, 0x00], &[0, 0]].concat()
        );
        for inside in [delete, other] {
            let mut filled = inside.to_bytes();
            filled.resize(228, 0);
            assert_eq!(Inside::from_bytes(&filled), Ok(inside));
        }
    }

    #[test]
    fn an_entry_sealed_for_one_channel_slot_or_revision_does_not_open_under_another() {
        let keys = ChannelKeys::of(&SECRET).unwrap();
        let slot = slot_of("notes.md");
        let content = sealed(&sample().to_bytes(), &keys, &slot, 5).unwrap();
        let signed_as = |channel_key: &NodeIdentity, slot: [u8; 32], rev: u64| {
            signed(channel_key, &device(1), slot, rev, false, content.clone())
                .check()
                .unwrap()
        };

        // The control: where it was sealed for, it opens.
        let honest = signed_as(&channel_key(), slot, 5);
        assert_eq!(honest.open(&SECRET), Ok(sample()));

        // At another revision, above or below, in the same slot.
        for rev in [4, 6, at(1, 5)] {
            let moved = signed_as(&channel_key(), slot, rev);
            assert_eq!(moved.open(&SECRET), Err(EntryError::DidNotOpen), "{rev}");
        }
        // In another slot, at the same revision.
        let moved = signed_as(&channel_key(), slot_of("other.md"), 5);
        assert_eq!(moved.open(&SECRET), Err(EntryError::DidNotOpen));

        // In another channel: it is under another key there.
        let other_key = derive::signing_key(&OTHER_SECRET).unwrap();
        let moved = signed_as(&other_key, slot, 5);
        assert_eq!(moved.open(&OTHER_SECRET), Err(EntryError::DidNotOpen));
        // And it is bound to its channel's ID by itself: under the same
        // entry key, a content that names another channel does not open.
        let same_key = ChannelKeys {
            id: other_key.public_key(),
            entry_key: keys.entry_key,
            slot_key: keys.slot_key,
        };
        assert_eq!(moved.open_with(&same_key), Err(EntryError::DidNotOpen));
        assert_eq!(honest.open_with(&keys), Ok(sample()));

        // An entry is opened with its own channel's secret, and no other.
        assert_eq!(honest.open(&OTHER_SECRET), Err(EntryError::AnotherChannel));
        assert_eq!(moved.open(&SECRET), Err(EntryError::AnotherChannel));
    }

    /// What a content is bound to, byte by byte: its label, spelled here
    /// as it is published, the channel's ID, the slot, and the revision as
    /// eight bytes.
    #[test]
    fn a_content_is_bound_to_its_channel_slot_and_revision_under_its_label() {
        let entry = made();
        let entry_key = derive::entry_key(&SECRET).unwrap();
        let bound = [
            &b"cordelia v2 content"[..],
            &derive::channel_id(&SECRET).unwrap(),
            &slot_of("notes.md"),
            &[0, 0, 0, 0, 0, 0, 0, 5],
        ]
        .concat();
        assert_eq!(bound_to(&entry.channel, &entry.slot, entry.rev), bound);
        let filled = item_decrypt(&entry_key, &entry.content, &bound).unwrap();
        let said = sample().to_bytes();
        assert_eq!(filled[..said.len()], said);

        // Under the channel's entry key, and no other of its keys.
        let slot_key = derive::slot_key(&SECRET).unwrap();
        assert!(item_decrypt(&slot_key, &entry.content, &bound).is_err());
        assert!(item_decrypt(&SECRET, &entry.content, &bound).is_err());
        // Bound to nothing less: not to the channel alone, not to the
        // channel and the slot, and not without the label.
        for less in [&bound[19..], &bound[..19 + 32], &bound[..19 + 64], &[][..]] {
            assert!(item_decrypt(&entry_key, &entry.content, less).is_err());
        }
    }

    /// The slot is the slot of the name under the channel's slot key. An
    /// entry that sits in another slot than its name's does not open, even
    /// where its content was sealed for the slot it sits in.
    #[test]
    fn an_entry_whose_slot_is_not_the_slot_of_its_name_does_not_open() {
        let said = text("a.md", "t").to_bytes();
        assert_eq!(
            saying(1, 5, "a.md", &said, false).open(&SECRET),
            Ok(text("a.md", "t"))
        );
        let elsewhere = saying(1, 5, "b.md", &said, false);
        assert_eq!(elsewhere.slot, slot_of("b.md"));
        assert_eq!(elsewhere.open(&SECRET), Err(EntryError::AnotherSlot));

        // The slot is under this channel's slot key: the slot that another
        // channel gives the name is another slot.
        let other_slot = slot_id(&derive::slot_key(&OTHER_SECRET).unwrap(), "a.md");
        assert_ne!(other_slot, slot_of("a.md"));
        let keys = ChannelKeys::of(&SECRET).unwrap();
        let content = sealed(&said, &keys, &other_slot, 5).unwrap();
        let elsewhere = signed(&channel_key(), &device(1), other_slot, 5, false, content)
            .check()
            .unwrap();
        assert_eq!(elsewhere.open(&SECRET), Err(EntryError::AnotherSlot));
    }

    /// An entry is a delete in clear, where a relay sees it, and in its
    /// content, or in neither.
    #[test]
    fn an_entry_is_a_delete_in_clear_and_in_its_content_or_in_neither() {
        let a_text = text("a.md", "t").to_bytes();
        let a_delete = holding("a.md", Value::Delete).to_bytes();
        assert!(saying(1, 5, "a.md", &a_text, false).open(&SECRET).is_ok());
        assert!(saying(1, 5, "a.md", &a_delete, true).open(&SECRET).is_ok());
        assert_eq!(
            saying(1, 5, "a.md", &a_text, true).open(&SECRET),
            Err(EntryError::DeleteNotAsSigned)
        );
        assert_eq!(
            saying(1, 5, "a.md", &a_delete, false).open(&SECRET),
            Err(EntryError::DeleteNotAsSigned)
        );
    }

    /// Each of these passes the check, which reads no content, and opens
    /// under the channel's key. None holds a name and a value in an
    /// entry's form.
    #[test]
    fn content_that_is_not_in_an_entrys_form_is_no_version() {
        let open = |said: &[u8]| saying(1, 5, "a.md", said, false).open(&SECRET);
        let good = text("a.md", "hey").to_bytes();
        assert_eq!(good.len(), 2 + 4 + 1 + 2 + 3 + 2);
        assert_eq!(open(&good), Ok(text("a.md", "hey")));
        let changed = |place: usize, byte: u8| {
            let mut said = good.clone();
            said[place] = byte;
            said
        };

        // Nothing at all: a name of no bytes.
        assert_eq!(open(&[]), Err(EntryError::NotThisForm));
        assert_eq!(open(&[0, 0, 1, 0, 1, b't']), Err(EntryError::NotThisForm));
        // A name that goes on past the content's end.
        assert_eq!(open(&[0xea, 0x60, b'a']), Err(EntryError::NotThisForm));
        assert_eq!(open(&changed(1, 250)), Err(EntryError::NotThisForm));
        // A name that is not text.
        assert_eq!(open(&changed(2, 0xff)), Err(EntryError::NotThisForm));
        // A kind of value that there is not.
        for kind in [3, 4, 0x80, 0xff] {
            assert_eq!(
                open(&changed(6, kind)),
                Err(EntryError::NotThisForm),
                "{kind}"
            );
        }
        // A text that is not text. The same bytes, tagged as bytes that
        // are not a text, are a value.
        assert_eq!(open(&changed(9, 0xff)), Err(EntryError::NotThisForm));
        let mut other = changed(9, 0xff);
        other[6] = 2;
        assert_eq!(
            open(&other),
            Ok(holding("a.md", Value::Other(vec![0xff, b'e', b'y'])))
        );
        // A value that goes on past the content's end.
        assert_eq!(open(&changed(7, 0xff)), Err(EntryError::NotThisForm));
        // A name, and a kind, that the content ends before.
        let keys = ChannelKeys::of(&SECRET).unwrap();
        let slot = slot_of("a.md");
        let mut name_to_the_end = vec![b'a'; 228];
        name_to_the_end[..2].copy_from_slice(&[0, 226]);
        let content = item_encrypt(
            &keys.entry_key,
            &name_to_the_end,
            &bound_to(&keys.id, &slot, 5),
        )
        .unwrap();
        let ends_early = signed(&channel_key(), &device(1), slot, 5, false, content)
            .check()
            .unwrap();
        assert_eq!(ends_early.open(&SECRET), Err(EntryError::NotThisForm));
    }

    // ── Its chain ────────────────────────────────────────────────────

    /// A chain that cannot be read: the entry is a version all the same,
    /// with its name and its value, and lacks what it should say.
    #[test]
    fn an_entry_whose_chain_cannot_be_read_lacks_what_it_should_say() {
        let keys = ChannelKeys::of(&SECRET).unwrap();
        let slot = slot_of("a.md");
        // An entry whose content holds exactly `filled`.
        let open = |filled: &[u8]| {
            let content =
                item_encrypt(&keys.entry_key, filled, &bound_to(&keys.id, &slot, 5)).unwrap();
            signed(&channel_key(), &device(1), slot, 5, false, content)
                .check()
                .unwrap()
                .open(&SECRET)
                .unwrap()
        };
        // What an entry of `a.md` holding "hey" says, then `chain`, as it
        // is, and zeros to `size`.
        let with = |chain: &[u8], size: usize| {
            let mut filled = [&[0, 4][..], b"a.md", &[1, 0, 3], b"hey", chain].concat();
            assert!(filled.len() + ITEM_SEAL_OVERHEAD_BYTES <= size);
            filled.resize(size - ITEM_SEAL_OVERHEAD_BYTES, 0);
            filled
        };
        // A count, and the links after it.
        let counted = |count: u16, links: &[Link]| {
            let mut chain = count.to_be_bytes().to_vec();
            for link in links {
                chain.extend_from_slice(&link.hash);
                chain.extend_from_slice(&link.signer);
            }
            chain
        };
        let lacking = Inside {
            chain: None,
            ..text("a.md", "hey")
        };
        let saying = |chain: Vec<Link>| Inside {
            chain: Some(chain),
            ..text("a.md", "hey")
        };
        let (a, b, c) = (link("a", 1), link("a", 2), link("b", 1));

        // The controls: no links, two links, and 100 of them.
        assert_eq!(open(&with(&counted(0, &[]), 256)), saying(Vec::new()));
        assert_eq!(open(&with(&counted(2, &[a, b]), 256)), saying(vec![a, b]));
        assert_eq!(
            open(&with(&counted(100, &chain_of(100)), 4096)),
            saying(chain_of(100))
        );
        // Two links with one hash and two keys, and two with one key and
        // two hashes, are two links.
        assert_eq!(
            open(&with(&counted(3, &[a, b, c]), 256)),
            saying(vec![a, b, c])
        );

        // A count over 100, with every link there.
        for links in [101, 102, 120] {
            let chain = counted(links, &chain_of(usize::from(links)));
            assert_eq!(open(&with(&chain, 4096)), lacking, "{links}");
        }
        // A link that is there twice, next to itself and further on.
        assert_eq!(open(&with(&counted(2, &[a, a]), 256)), lacking);
        assert_eq!(open(&with(&counted(3, &[a, b, a]), 256)), lacking);
        assert_eq!(
            open(&with(&counted(4, &chain_of(4)), 256)),
            saying(chain_of(4))
        );
        let mut twice = chain_of(100);
        twice[99] = twice[0];
        assert_eq!(open(&with(&counted(100, &twice), 4096)), lacking);

        // Bytes left over after the last link: anything but zeros,
        // wherever it is.
        for place in [14, 15, 100, 227] {
            let mut filled = with(&counted(0, &[]), 256);
            filled[place] = 1;
            assert_eq!(open(&filled), lacking, "{place}");
        }
        let mut filled = with(&counted(2, &[a, b]), 256);
        filled[14 + 64] = 0xff;
        assert_eq!(open(&filled), lacking);
        // And more zeros than fill the smallest size that holds what is
        // said: a content in a larger size than it needs.
        for size in [512, 1024, 65_536] {
            assert_eq!(open(&with(&counted(0, &[]), size)), lacking, "{size}");
            assert_eq!(open(&with(&counted(2, &[a, b]), size)), lacking, "{size}");
        }

        // A link that is not whole: the content ends before the chain
        // does. Six links are there, three of them zeros, and 22 bytes of
        // a seventh.
        let chain = counted(7, &[a, b, c]);
        let filled = with(&chain, 256);
        assert_eq!(14 + 6 * 32 + 22, filled.len());
        assert_eq!(open(&filled), lacking);
        // A count that is not whole, and one that is not there: the value
        // ends one byte before the content does, and at its end.
        for text in [218usize, 219] {
            let mut filled = vec![b'x'; 228];
            filled[..9].copy_from_slice(&[0, 4, b'a', b'.', b'm', b'd', 1, 0, text as u8]);
            filled[9 + text..].fill(0);
            let opened = open(&filled);
            assert_eq!(opened.value, text_of(text), "{text}");
            assert_eq!(opened.chain, None, "{text}");
        }
    }

    /// Yes, where the first link has the hash of what the folder agreed:
    /// the version was published over that very text. No version stands
    /// between, so there is no signer to ask about, the first link's
    /// included.
    #[test]
    fn a_version_follows_the_text_of_its_first_link() {
        let chain = [link("agreed", 1), link("older", 2), link("oldest", 9)];
        let agreed = named("agreed");
        let nobody = |_: &[u8; 16]| false;
        let everyone = |_: &[u8; 16]| true;
        assert!(known_to_follow(Some(&chain), &agreed, everyone));
        assert!(known_to_follow(Some(&chain), &agreed, nobody));
        assert!(known_to_follow(Some(&chain[..1]), &agreed, nobody));
    }

    /// Yes, where a link further down has that hash and every link before
    /// it was signed by a key that counts.
    #[test]
    fn a_version_follows_a_link_further_down_where_every_newer_signer_counts() {
        let chain = [
            link("newest", 1),
            link("newer", 2),
            link("new", 1),
            link("agreed", 9),
            link("older", 8),
        ];
        let agreed = named("agreed");
        let counts = |by: &[u8; 16]| [signer(1), signer(2)].contains(by);
        assert!(known_to_follow(Some(&chain), &agreed, counts));
        // The signer of the agreed version itself is not asked about, nor
        // any signer below it: devices 9 and 8 do not count.
        assert!(!counts(&signer(9)) && !counts(&signer(8)));
        // The second link, and the last.
        assert!(known_to_follow(Some(&chain), &named("newer"), counts));
        let all = |by: &[u8; 16]| [signer(1), signer(2), signer(9)].contains(by);
        assert!(known_to_follow(Some(&chain), &named("older"), all));
    }

    /// No, where one link before it was signed by a key that does not
    /// count, wherever among them it is.
    #[test]
    fn a_version_does_not_follow_past_a_signer_that_does_not_count() {
        let agreed = named("agreed");
        let counts = |by: &[u8; 16]| [signer(1), signer(2)].contains(by);
        for place in 0..3 {
            let mut chain = vec![
                link("newest", 1),
                link("newer", 2),
                link("new", 1),
                link("agreed", 1),
            ];
            assert!(known_to_follow(Some(&chain), &agreed, counts));
            chain[place].signer = signer(9);
            assert!(!known_to_follow(Some(&chain), &agreed, counts), "{place}");
            // What is above that link is still followed, and the link's
            // own text.
            let own = chain[place].hash;
            assert!(known_to_follow(Some(&chain), &own, counts), "{place}");
        }
        // And where none of them counts.
        let chain = [link("newest", 8), link("agreed", 1)];
        assert!(!known_to_follow(Some(&chain), &agreed, counts));
    }

    /// No, where no link has the hash of what the folder agreed.
    #[test]
    fn a_version_does_not_follow_a_text_that_is_not_in_its_chain() {
        let chain = [link("newest", 1), link("newer", 2)];
        let everyone = |_: &[u8; 16]| true;
        assert!(!known_to_follow(Some(&chain), &named("agreed"), everyone));
        // A key is no hash, and a hash that differs in its last bit is
        // another text's.
        assert!(!known_to_follow(Some(&chain), &signer(1), everyone));
        let mut other = named("newest");
        other[15] ^= 1;
        assert!(!known_to_follow(Some(&chain), &other, everyone));
        assert!(known_to_follow(Some(&chain), &named("newest"), everyone));
    }

    /// Two entries that were one version are two links with one hash. The
    /// first of them decides: every link before it must count, and no
    /// link after it is asked about.
    #[test]
    fn of_two_links_with_one_hash_the_first_decides() {
        let agreed = named("agreed");
        let counts = |by: &[u8; 16]| [signer(1), signer(2)].contains(by);

        // Both below signers that count: yes, also where the second of
        // them was signed by a key that does not count.
        let chain = [link("newest", 1), link("agreed", 2), link("agreed", 9)];
        assert!(known_to_follow(Some(&chain), &agreed, counts));
        let chain = [link("newest", 1), link("agreed", 9), link("agreed", 2)];
        assert!(known_to_follow(Some(&chain), &agreed, counts));

        // The first of them at the top: yes, whatever stands between the
        // two.
        let chain = [link("agreed", 1), link("between", 9), link("agreed", 2)];
        assert!(known_to_follow(Some(&chain), &agreed, counts));

        // The first of them below a signer that does not count: no.
        let chain = [link("newest", 9), link("agreed", 1), link("agreed", 2)];
        assert!(!known_to_follow(Some(&chain), &agreed, counts));
    }

    #[test]
    fn a_version_with_an_empty_chain_follows_nothing() {
        let everyone = |_: &[u8; 16]| true;
        assert!(!known_to_follow(Some(&[]), &named("agreed"), everyone));
        // Not a delete either, which a chain names by zeros.
        assert!(!known_to_follow(Some(&[]), &[0; 16], everyone));
    }

    /// A chain names a delete by 16 bytes of zeros, and a delete is
    /// followed as a text is.
    #[test]
    fn a_delete_is_followed_as_a_text_is() {
        let counts = |by: &[u8; 16]| [signer(1), signer(2)].contains(by);
        let deleted = Value::Delete.chain_hash();
        assert_eq!(deleted, [0; 16]);

        let a_delete = Link::of(&Value::Delete, key(1));
        let chain = [a_delete, link("older", 2)];
        assert!(known_to_follow(Some(&chain), &deleted, counts));
        let chain = [link("newest", 2), a_delete, link("older", 9)];
        assert!(known_to_follow(Some(&chain), &deleted, counts));
        let chain = [link("newest", 9), a_delete];
        assert!(!known_to_follow(Some(&chain), &deleted, counts));
        // A folder that agreed a text is not followed by way of a delete,
        // nor one that agreed a delete by way of a text.
        let chain = [a_delete];
        assert!(!known_to_follow(Some(&chain), &named(""), counts));
        let chain = [link("", 1)];
        assert!(!known_to_follow(Some(&chain), &deleted, counts));
        // And a delete is passed as any version is.
        let chain = [Link::of(&Value::Delete, key(2)), link("agreed", 1)];
        assert!(known_to_follow(Some(&chain), &named("agreed"), counts));
        let chain = [Link::of(&Value::Delete, key(9)), link("agreed", 1)];
        assert!(!known_to_follow(Some(&chain), &named("agreed"), counts));
    }

    /// An entry that lacks what it should say is known to follow nothing.
    #[test]
    fn an_entry_that_lacks_what_it_should_say_follows_nothing() {
        let everyone = |_: &[u8; 16]| true;
        assert!(!known_to_follow(None, &named("agreed"), everyone));
        assert!(!known_to_follow(None, &[0; 16], everyone));

        // As it is opened: an entry whose chain names a link twice.
        let twice = Inside {
            chain: Some(vec![link("agreed", 1), link("agreed", 1)]),
            ..text("a.md", "t")
        };
        let opened = saying(1, 5, "a.md", &twice.to_bytes(), false)
            .open(&SECRET)
            .unwrap();
        assert_eq!(opened.chain, None);
        let agreed = named("agreed");
        assert!(!known_to_follow(opened.chain.as_deref(), &agreed, everyone));
        // The control: named once, it follows.
        let once = Inside {
            chain: Some(vec![link("agreed", 1)]),
            ..text("a.md", "t")
        };
        let opened = entry(1, 5, &once).open(&SECRET).unwrap();
        assert!(known_to_follow(opened.chain.as_deref(), &agreed, everyone));
    }

    /// A link is a version by the start of the hash of what it held, which
    /// is zeros for a delete, and the start of the key that signed the
    /// entry it was taken from: 16 bytes of each.
    #[test]
    fn a_link_names_a_value_by_its_hash_and_a_delete_by_zeros() {
        let text = Value::Text("hello".to_string());
        let hash = crate::sha256(b"hello");
        let made = Link::of(&text, key(1));
        assert_eq!(made.hash[..], hash[..16]);
        assert_eq!(made.signer[..], key(1)[..16]);
        assert_eq!(std::mem::size_of::<Link>(), 32);
        assert_eq!(text.chain_hash(), made.hash);
        assert_eq!(named("hello"), made.hash);
        assert_eq!(signer(1), made.signer);
        assert_eq!(Link::signer_of(&key(1)), made.signer);
        // The start of a hash, and of nothing else of it: a text whose
        // hash differs in its first 16 bytes is another, and one byte of
        // a key's first 16 is another key.
        assert_ne!(named("hello"), named("hello."));
        assert_ne!(signer(1), signer(2));

        let bytes = Value::Other(vec![0xff]);
        assert_eq!(
            Link::of(&bytes, key(2)).hash[..],
            crate::sha256(&[0xff])[..16]
        );
        assert_eq!(
            Link::of(&Value::Delete, key(2)),
            Link {
                hash: [0; 16],
                signer: signer(2)
            }
        );
        // An empty text is a text, and no delete.
        assert_ne!(Value::Text(String::new()).chain_hash(), [0; 16]);
    }

    // ── What is shown of one ─────────────────────────────────────────

    #[test]
    fn a_values_hash_is_of_its_text_or_of_its_bytes() {
        let text = Value::Text("hello".to_string());
        assert_eq!(text.hash(), Some(crate::sha256(b"hello")));
        assert_eq!(text.bytes(), b"hello");
        assert_eq!(
            Value::Other(vec![0xff, 0x00]).hash(),
            Some(crate::sha256(&[0xff, 0x00]))
        );
        // An empty text is a text: it has a hash, and a delete has none.
        assert_eq!(Value::Text(String::new()).hash(), Some(crate::sha256(b"")));
        assert_eq!(Value::Delete.hash(), None);
        assert!(Value::Delete.is_delete() && !Value::Text(String::new()).is_delete());
        assert!(Value::Delete.bytes().is_empty());
    }

    #[test]
    fn what_an_entry_holds_prints_none_of_its_text() {
        let inside = text("a.md", "the words of a memory");
        let shown = format!("{inside:?}");
        assert!(!shown.contains("words"), "{shown}");
        assert!(shown.contains("Text(21 bytes)"), "{shown}");
        let other = Value::Other(b"the words".to_vec());
        assert_eq!(format!("{other:?}"), "Other(9 bytes)");
        assert_eq!(format!("{:?}", Value::Delete), "Delete");

        // An entry is shown by its clear fields, and its content by its
        // length.
        let shown = format!("{:?}", made());
        assert!(shown.contains("content: 256"), "{shown}");
        assert!(shown.len() < 400, "{shown}");
    }
}
