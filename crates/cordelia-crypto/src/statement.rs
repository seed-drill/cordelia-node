//! The statement: which devices are a person's, and which keys are removed
//! (decision 2026-10-04 §4).
//!
//! There is one statement for each change of the person secret. It names
//! the devices that hold the new secret and commits to that secret, and
//! only the phrase's key signs one. A statement stands by itself: a device
//! that was off for two changes applies the second without having seen the
//! first, because the one it has applied is on the second's chain.
//!
//! ## Canonical form
//!
//! The fields in a fixed order. A number is eight bytes and a count or a
//! length is two, the higher byte first.
//!
//! ```text
//! number        8
//! maker         32                  the device it was made on
//! chain         count, then for each: number 8, hash 16
//! commitment    32                  to the new secret
//! devices       count, then for each: key 32, label's length, label
//! removed       count, then for each: key 32
//! phrase's key  32
//! reserved      length, which is 0
//! ```
//!
//! The chain is in order of number and then hash, and the removed keys are
//! in order: each list has one spelling. The devices keep the order their
//! maker gave them, which is the order of the secrets sealed to them in
//! the change entry. The last field is empty: it is kept for a later way
//! to replace the phrase, and a device refuses a statement in which it is
//! not empty. A signed statement is this form and then the signature's 64
//! bytes.
//!
//! Decoding refuses anything else: a statement that ends early, bytes
//! after its end, a list or a label over its bound, a list that is not in
//! its order, a key that is listed twice or in both lists, and a device's
//! key, or the maker's, that is not a usable public key.

use cordelia_core::protocol::{
    LABEL_COMMITMENT, LABEL_STATEMENT, MAX_DEVICE_LABEL_BYTES, MAX_STATEMENT_CHAIN,
    MAX_STATEMENT_DEVICES, MAX_STATEMENT_NUMBER, MAX_STATEMENT_REMOVED, STATEMENT_HASH_BYTES,
};
use sha2::{Digest, Sha256};

use crate::identity::{NodeIdentity, is_usable_public_key, verify_signature};

/// Why bytes are not a statement, why a statement was not made, or why one
/// was not judged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatementError {
    #[error("the statement ends before it is whole")]
    Truncated,

    #[error("there are bytes after the statement's end")]
    TrailingBytes,

    #[error("a statement's number is from 1 to 256, and this is {0}: a phrase makes no more")]
    Number(u64),

    #[error("a statement's chain names at most 256 statements, and this names {0}")]
    ChainTooLong(usize),

    #[error("a statement's chain is in order of number and hash, with none named twice")]
    ChainOrder,

    #[error("a statement's chain goes from the first statement to the one before it")]
    ChainNumbers,

    #[error("a statement lists at most 64 devices, and this lists {0}")]
    TooManyDevices(usize),

    #[error("a statement lists a device once")]
    DeviceTwice,

    #[error("the device a statement was made on is among its devices")]
    MakerNotListed,

    #[error("a device's key is not a usable public key")]
    DeviceKeyNotUsable,

    #[error("the key of the device a statement was made on is not a usable public key")]
    MakerKeyNotUsable,

    #[error("a device's label is from 1 to 64 bytes, and this is {0}")]
    LabelLength(usize),

    #[error("a device's label is printable ASCII text")]
    LabelNotPrintable,

    #[error("a device's label has no space at either end")]
    LabelSpaceAtAnEnd,

    #[error("a statement lists at most 256 removed keys, and this lists {0}")]
    TooManyRemoved(usize),

    #[error("a statement's removed keys are in order, with none listed twice")]
    RemovedOrder,

    #[error("a key is among a statement's devices and among its removed keys")]
    InBothLists,

    #[error("the field that a statement keeps empty is not empty")]
    Reserved,

    #[error("the key given to sign with is not the statement's phrase key")]
    NotThePhrasesKey,

    #[error("the statement's phrase key is not a usable public key")]
    PhraseKeyNotUsable,

    #[error("the statement is not signed by its phrase's key")]
    Signature,

    #[error("the statement is under another phrase")]
    AnotherPhrase,

    #[error("the two statements were not made apart")]
    NotApart,

    #[error(
        "the statement was made after the applied one, and lacks a key that the applied one removed"
    )]
    UndoesARemoval,
}

/// A device as a statement lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The device's Ed25519 public key.
    pub key: [u8; 32],
    /// The label the person knows it by, as shown at a prompt: 1 to 64
    /// bytes of printable ASCII, with no space at either end. It is what a
    /// person calls the device, kept as it was given: "Kitchen laptop" is
    /// a label.
    pub label: String,
}

impl Device {
    /// A device with the label `label`, as it is given. A label that is
    /// not one a statement may carry is refused, and not changed into one.
    pub fn new(key: [u8; 32], label: &str) -> Result<Self, StatementError> {
        check_label(label)?;
        Ok(Self {
            key,
            label: label.to_string(),
        })
    }
}

/// A statement as another names it on its chain: its number, and the first
/// 16 bytes of its hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Link {
    pub number: u64,
    pub hash: [u8; STATEMENT_HASH_BYTES],
}

/// One statement (decision 2026-10-04 §4.1). It has no kind: what it does
/// is in its lists and its chain. The first has no chain, a settlement's
/// chain holds two branches, and a recovery lists one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// One above the highest number on its chain: 1 for the first.
    pub number: u64,
    /// The key of the device it was made on, which is among its devices.
    pub maker: [u8; 32],
    /// Every statement it was made after, back to the first, in order of
    /// number and hash.
    pub chain: Vec<Link>,
    /// The commitment to the new secret ([`commitment`]).
    pub commitment: [u8; 32],
    /// The devices that hold the secret, in the order their maker gave.
    pub devices: Vec<Device>,
    /// Every key removed so far by the person's word, in order. None of
    /// them is among the devices.
    pub removed: Vec<[u8; 32]>,
    /// The public half of the phrase's signing key.
    pub phrase_key: [u8; 32],
}

/// A statement with the signature of its phrase's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStatement {
    pub statement: Statement,
    pub signature: [u8; 64],
}

/// What a statement that a device is shown is to that device, beside the
/// one it has applied (decision 2026-10-04 §4.2, §4.3, §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Judgement {
    /// It was made after the applied one, undoes no removal, and lists
    /// this device: the device applies it, where the secret that comes
    /// with it opens to its commitment.
    Applies,
    /// It is the applied one, or one on the applied one's chain. Nothing
    /// is done with it.
    Behind,
    /// It was made apart from the applied one: neither is on the other's
    /// chain. The device stops until the two are settled.
    Fork,
    /// It was made after the applied one, undoes no removal, and lists
    /// this device's key as removed. The device is no longer one of the
    /// person's.
    Removed,
    /// As [`Judgement::Removed`], but the key is in neither list: the
    /// device is added again by a person, or not at all.
    NotListed,
}

/// A new person secret (decision 2026-10-04 §3): 32 bytes from the system's
/// random numbers. It is never derived from the phrase: if it were, a
/// device that was removed could work out the next one.
pub fn new_secret() -> Result<[u8; 32], crate::CryptoError> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut secret = [0u8; 32];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| crate::CryptoError::KeyDerivationFailed("RNG failure".into()))?;
    Ok(secret)
}

/// The commitment to `secret`: SHA-256 of the commitment's label and the
/// secret. It says nothing of the channels that are derived from the
/// secret, which a hash of them would.
pub fn commitment(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_COMMITMENT);
    hasher.update(secret);
    hasher.finalize().into()
}

impl Statement {
    /// The first statement of a phrase: number 1, with no chain, made on
    /// the one device it lists, and removing nobody.
    pub fn first(
        maker: Device,
        secret: &[u8; 32],
        phrase_key: [u8; 32],
    ) -> Result<Self, StatementError> {
        let statement = Self {
            number: 1,
            maker: maker.key,
            chain: Vec::new(),
            commitment: commitment(secret),
            devices: vec![maker],
            removed: Vec::new(),
            phrase_key,
        };
        statement.validate()?;
        Ok(statement)
    }

    /// The statement that a device which has applied this one makes next
    /// (decision 2026-10-04 §4.5).
    ///
    /// It is numbered one above this one. Its chain is this one and this
    /// one's chain. It lists as removed every key that this one does, and
    /// those in `removed`: no statement brings a removed key back, so a
    /// device that is among them is refused. `devices` are the devices that
    /// will hold `secret`, the maker among them.
    ///
    /// Refused where it would be over a bound: a phrase makes 256
    /// statements and removes 256 keys, and no more.
    pub fn next(
        &self,
        maker: [u8; 32],
        secret: &[u8; 32],
        devices: Vec<Device>,
        removed: &[[u8; 32]],
    ) -> Result<Self, StatementError> {
        let mut chain = self.chain.clone();
        chain.push(self.link()?);
        let statement = Self {
            number: self.number + 1,
            maker,
            chain,
            commitment: commitment(secret),
            devices,
            removed: all_of(&[&self.removed, removed]),
            phrase_key: self.phrase_key,
        };
        statement.validate()?;
        Ok(statement)
    }

    /// The statement that settles two that were made apart (decision
    /// 2026-10-04 §4.5).
    ///
    /// It is numbered above both. Its chain holds both and their chains,
    /// so that a device on either branch can apply it. Its removed keys
    /// are every key that either removed, and those in `removed`: a
    /// settlement undoes nothing.
    ///
    /// Two statements of which one is the other, or is on the other's
    /// chain, were not made apart, and are not settled: the later one is
    /// simply the later one.
    pub fn settle(
        one: &Self,
        other: &Self,
        maker: [u8; 32],
        secret: &[u8; 32],
        devices: Vec<Device>,
        removed: &[[u8; 32]],
    ) -> Result<Self, StatementError> {
        if one.phrase_key != other.phrase_key {
            return Err(StatementError::AnotherPhrase);
        }
        let (a, b) = (one.link()?, other.link()?);
        if a == b || one.has_on_chain(&b) || other.has_on_chain(&a) {
            return Err(StatementError::NotApart);
        }
        let mut chain: Vec<Link> = one.chain.iter().chain(&other.chain).copied().collect();
        chain.extend([a, b]);
        chain.sort_unstable();
        chain.dedup();
        let statement = Self {
            number: one.number.max(other.number) + 1,
            maker,
            chain,
            commitment: commitment(secret),
            devices,
            removed: all_of(&[&one.removed, &other.removed, removed]),
            phrase_key: one.phrase_key,
        };
        statement.validate()?;
        Ok(statement)
    }

    /// Whether this is a statement at all: every rule of its form that
    /// does not need another statement to check.
    pub fn validate(&self) -> Result<(), StatementError> {
        if self.number < 1 || self.number > MAX_STATEMENT_NUMBER {
            return Err(StatementError::Number(self.number));
        }

        if self.chain.len() > MAX_STATEMENT_CHAIN {
            return Err(StatementError::ChainTooLong(self.chain.len()));
        }
        if !self.chain.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(StatementError::ChainOrder);
        }
        // The chain is every statement this one was made after, back to
        // the first, and this one is numbered one above the highest of
        // them. So its numbers start at 1 and leave none out up to the one
        // before this. Two statements that were made apart and then
        // settled have one number.
        let mut reached = 0;
        for link in &self.chain {
            if link.number == reached + 1 {
                reached += 1;
            } else if link.number != reached || reached == 0 {
                return Err(StatementError::ChainNumbers);
            }
        }
        if reached + 1 != self.number {
            return Err(StatementError::ChainNumbers);
        }

        if self.devices.len() > MAX_STATEMENT_DEVICES {
            return Err(StatementError::TooManyDevices(self.devices.len()));
        }
        for device in &self.devices {
            check_label(&device.label)?;
            // A device holds the secret, which is sealed to its key, and
            // signs entries with it. Nothing can be sealed to a key that
            // is no point, or a point of small order, and anyone can sign
            // for one.
            if !found_usable(&device.key) {
                return Err(StatementError::DeviceKeyNotUsable);
            }
        }
        let mut keys: Vec<&[u8; 32]> = self.devices.iter().map(|device| &device.key).collect();
        keys.sort_unstable();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StatementError::DeviceTwice);
        }
        if !found_usable(&self.maker) {
            return Err(StatementError::MakerKeyNotUsable);
        }
        if !self.lists(&self.maker) {
            return Err(StatementError::MakerNotListed);
        }

        if self.removed.len() > MAX_STATEMENT_REMOVED {
            return Err(StatementError::TooManyRemoved(self.removed.len()));
        }
        if !self.removed.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(StatementError::RemovedOrder);
        }
        if self.devices.iter().any(|device| self.removes(&device.key)) {
            return Err(StatementError::InBothLists);
        }
        Ok(())
    }

    /// Whether `key` is among the devices.
    pub fn lists(&self, key: &[u8; 32]) -> bool {
        self.devices.iter().any(|device| &device.key == key)
    }

    /// Whether `key` is among the removed keys.
    pub fn removes(&self, key: &[u8; 32]) -> bool {
        self.removed.contains(key)
    }

    /// Whether the statement that `link` names is on this one's chain.
    pub fn has_on_chain(&self, link: &Link) -> bool {
        self.chain.contains(link)
    }

    /// Whether this statement lists as removed every key that `before`
    /// does (decision 2026-10-04 §4.2, rule 5): a statement undoes no
    /// removal of one that it was made after.
    pub fn keeps_the_removals_of(&self, before: &Statement) -> bool {
        before.removed.iter().all(|key| self.removes(key))
    }

    /// Whether this statement commits to `secret`: the secret's hash,
    /// under the commitment's label, is the one the statement gives
    /// (decision 2026-10-04 §4.2, rule 4).
    pub fn commits_to(&self, secret: &[u8; 32]) -> bool {
        self.commitment == commitment(secret)
    }

    /// The canonical form (see the module's documentation). A statement
    /// that is not valid has none.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StatementError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.number.to_be_bytes());
        out.extend_from_slice(&self.maker);
        put_count(&mut out, self.chain.len());
        for link in &self.chain {
            out.extend_from_slice(&link.number.to_be_bytes());
            out.extend_from_slice(&link.hash);
        }
        out.extend_from_slice(&self.commitment);
        put_count(&mut out, self.devices.len());
        for device in &self.devices {
            out.extend_from_slice(&device.key);
            put_count(&mut out, device.label.len());
            out.extend_from_slice(device.label.as_bytes());
        }
        put_count(&mut out, self.removed.len());
        for key in &self.removed {
            out.extend_from_slice(key);
        }
        out.extend_from_slice(&self.phrase_key);
        // The field that is kept empty.
        put_count(&mut out, 0);
        Ok(out)
    }

    /// Read a statement from its canonical form, and from nothing else.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementError> {
        let short = || StatementError::Truncated;
        let mut reader = Reader::new(bytes);

        let number = reader.u64().ok_or_else(short)?;
        let maker = reader.array().ok_or_else(short)?;

        // Each count is checked against its bound before anything is read
        // or set aside for it.
        let links = reader.count().ok_or_else(short)?;
        if links > MAX_STATEMENT_CHAIN {
            return Err(StatementError::ChainTooLong(links));
        }
        let mut chain = Vec::with_capacity(links);
        for _ in 0..links {
            chain.push(Link {
                number: reader.u64().ok_or_else(short)?,
                hash: reader.array().ok_or_else(short)?,
            });
        }

        let commitment = reader.array().ok_or_else(short)?;

        let count = reader.count().ok_or_else(short)?;
        if count > MAX_STATEMENT_DEVICES {
            return Err(StatementError::TooManyDevices(count));
        }
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            let key = reader.array().ok_or_else(short)?;
            let length = reader.count().ok_or_else(short)?;
            if length > MAX_DEVICE_LABEL_BYTES {
                return Err(StatementError::LabelLength(length));
            }
            let label = reader.take(length).ok_or_else(short)?;
            let label =
                std::str::from_utf8(label).map_err(|_| StatementError::LabelNotPrintable)?;
            devices.push(Device {
                key,
                label: label.to_string(),
            });
        }

        let count = reader.count().ok_or_else(short)?;
        if count > MAX_STATEMENT_REMOVED {
            return Err(StatementError::TooManyRemoved(count));
        }
        let mut removed = Vec::with_capacity(count);
        for _ in 0..count {
            removed.push(reader.array().ok_or_else(short)?);
        }

        let phrase_key = reader.array().ok_or_else(short)?;
        if reader.count().ok_or_else(short)? != 0 {
            return Err(StatementError::Reserved);
        }
        if !reader.is_empty() {
            return Err(StatementError::TrailingBytes);
        }

        let statement = Self {
            number,
            maker,
            chain,
            commitment,
            devices,
            removed,
            phrase_key,
        };
        statement.validate()?;
        Ok(statement)
    }

    /// The statement's hash, as a chain names it: the first 16 bytes of
    /// SHA-256 of its canonical form. The signature is not part of it.
    pub fn hash(&self) -> Result<[u8; STATEMENT_HASH_BYTES], StatementError> {
        let digest = crate::sha256(&self.to_bytes()?);
        let mut hash = [0u8; STATEMENT_HASH_BYTES];
        hash.copy_from_slice(&digest[..STATEMENT_HASH_BYTES]);
        Ok(hash)
    }

    /// This statement as another names it on its chain.
    pub fn link(&self) -> Result<Link, StatementError> {
        Ok(Link {
            number: self.number,
            hash: self.hash()?,
        })
    }

    /// Sign the statement with the phrase's signing key
    /// ([`crate::phrase::Phrase::signing_key`]), under the statement's
    /// label. A key that is not the statement's phrase key is refused.
    pub fn sign(self, key: &NodeIdentity) -> Result<SignedStatement, StatementError> {
        if key.public_key() != self.phrase_key {
            return Err(StatementError::NotThePhrasesKey);
        }
        let signature = key.sign(&under_label(&self.to_bytes()?));
        Ok(SignedStatement {
            statement: self,
            signature,
        })
    }
}

impl SignedStatement {
    /// Whether the statement is one, and its phrase's key signed it.
    ///
    /// A phrase key that is not a usable public key is refused: under a
    /// point of small order anyone can make a signature that is accepted.
    pub fn verify(&self) -> Result<(), StatementError> {
        let bytes = self.statement.to_bytes()?;
        if !is_usable_public_key(&self.statement.phrase_key) {
            return Err(StatementError::PhraseKeyNotUsable);
        }
        if !verify_signature(
            &self.statement.phrase_key,
            &under_label(&bytes),
            &self.signature,
        ) {
            return Err(StatementError::Signature);
        }
        Ok(())
    }

    /// The statement's canonical form, and then its signature.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StatementError> {
        let mut out = self.statement.to_bytes()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Read a signed statement. The signature is not checked here:
    /// [`SignedStatement::verify`] and [`judge`] check it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementError> {
        let Some(split) = bytes.len().checked_sub(64) else {
            return Err(StatementError::Truncated);
        };
        let (statement, signature) = bytes.split_at(split);
        let mut signed = Self {
            statement: Statement::from_bytes(statement)?,
            signature: [0u8; 64],
        };
        signed.signature.copy_from_slice(signature);
        Ok(signed)
    }
}

/// Judge the statement `shown` to a device against the one it has
/// `applied` (decision 2026-10-04 §4.2, §4.3, §4.5). `device` is the
/// device's own key, and `follows` the phrase key that it follows.
///
/// Rules 1, 2, 3, 5 and 6 of §4.2 are decided here. Rule 4, that the
/// secret opens to the commitment, is decided where the change entry is
/// opened ([`crate::change_entry`]).
///
/// - Rule 1: the key the device follows signed it. A statement that fails
///   this is nothing to the device, and is an error here. Both statements
///   are under the followed phrase.
/// - Rule 2: its number is above the applied one's. One that is not is
///   [`Judgement::Behind`] where it is on the applied one's chain, and
///   otherwise a [`Judgement::Fork`].
/// - Rule 6: the applied one is on its chain, by number and hash. One made
///   apart is a fork, even where it removes everything the applied one
///   removed: what the applied one decided besides would be dropped.
/// - Rule 5: every key that the applied one removed is removed in it. One
///   that was made after the applied one and lacks a removal is an error,
///   as below.
/// - Rule 3: the device is among its devices, and it
///   [`Judgement::Applies`]. A device that is not is
///   [`Judgement::Removed`] or [`Judgement::NotListed`], and only by a
///   statement that passes every rule above.
///
/// Two things that those rules do not say outright:
///
/// - **The applied statement, shown again, is [`Judgement::Behind`].** It
///   has the applied one's number and hash. It is not above the applied
///   one and is not apart from it, and nothing is done with it.
/// - **A signed statement that is not well formed is an error, and not a
///   fork.** A key in both of its lists is one such (the second half of
///   rule 5), and so is anything else that [`Statement::validate`]
///   refuses. It is no statement, whoever signed it, so a device is not
///   stopped by it as a fork stops one.
/// - **A statement that has the applied one on its chain and lacks a
///   removal that the applied one has is an error too**
///   ([`StatementError::UndoesARemoval`]). A statement lists as removed
///   every key that any statement on its chain removes, so this one is
///   not well formed. And it is no fork: the two were not made apart, so
///   nothing could settle them, and a device that stopped for it would
///   stay stopped.
pub fn judge(
    shown: &SignedStatement,
    applied: &Statement,
    device: &[u8; 32],
    follows: &[u8; 32],
) -> Result<Judgement, StatementError> {
    if shown.statement.phrase_key != *follows || applied.phrase_key != *follows {
        return Err(StatementError::AnotherPhrase);
    }
    shown.verify()?;
    let shown = &shown.statement;
    let (ours, theirs) = (applied.link()?, shown.link()?);

    if theirs.number <= ours.number {
        return Ok(if theirs == ours || applied.has_on_chain(&theirs) {
            Judgement::Behind
        } else {
            Judgement::Fork
        });
    }
    if !shown.has_on_chain(&ours) {
        return Ok(Judgement::Fork);
    }
    if !shown.keeps_the_removals_of(applied) {
        return Err(StatementError::UndoesARemoval);
    }
    Ok(if shown.lists(device) {
        Judgement::Applies
    } else if shown.removes(device) {
        Judgement::Removed
    } else {
        Judgement::NotListed
    })
}

thread_local! {
    /// The keys that this thread has found to be usable public keys.
    static FOUND_USABLE: std::cell::RefCell<std::collections::HashSet<[u8; 32]>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

/// How many keys a thread remembers as usable before it starts again.
const FOUND_USABLE_KEPT: usize = 1024;

/// Whether `key` is a usable public key ([`is_usable_public_key`]).
///
/// The check costs a multiplication on the curve, and a statement's
/// devices are checked each time the statement is read, written, hashed
/// or judged. Whether a key is usable never changes, so a key that was
/// found usable is remembered, and the check is made once for it. A key
/// that is not usable is checked each time, and refused each time.
fn found_usable(key: &[u8; 32]) -> bool {
    if FOUND_USABLE.with(|found| found.borrow().contains(key)) {
        return true;
    }
    if !is_usable_public_key(key) {
        return false;
    }
    FOUND_USABLE.with(|found| {
        let mut found = found.borrow_mut();
        if found.len() >= FOUND_USABLE_KEPT {
            found.clear();
        }
        found.insert(*key);
    });
    true
}

/// What the phrase's key signs: the statement's label, and its canonical
/// form.
fn under_label(bytes: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(LABEL_STATEMENT.len() + bytes.len());
    signed.extend_from_slice(LABEL_STATEMENT);
    signed.extend_from_slice(bytes);
    signed
}

/// Whether `label` is one a statement may carry: 1 to 64 bytes of the
/// printable characters of ASCII (0x20 to 0x7E), which a prompt shows as
/// they are on any terminal, with no space at either end. Capitals and
/// spaces within it stay as they are.
fn check_label(label: &str) -> Result<(), StatementError> {
    if label.is_empty() || label.len() > MAX_DEVICE_LABEL_BYTES {
        return Err(StatementError::LabelLength(label.len()));
    }
    if !label.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(StatementError::LabelNotPrintable);
    }
    if label.starts_with(' ') || label.ends_with(' ') {
        return Err(StatementError::LabelSpaceAtAnEnd);
    }
    Ok(())
}

/// Every key of `lists`, in order, each once.
fn all_of(lists: &[&[[u8; 32]]]) -> Vec<[u8; 32]> {
    let mut all: Vec<[u8; 32]> = lists.iter().flat_map(|list| list.iter().copied()).collect();
    all.sort_unstable();
    all.dedup();
    all
}

/// Write a count or a length as two bytes. Every one written is within a
/// bound far below what two bytes hold: what it counts was checked first.
pub(crate) fn put_count(out: &mut Vec<u8>, count: usize) {
    out.extend_from_slice(&(count as u16).to_be_bytes());
}

/// Reads the fields of a canonical form from the front of some bytes.
/// Each read is `None` where the bytes end first.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The next `length` bytes.
    pub(crate) fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        if self.bytes.len() < length {
            return None;
        }
        let (taken, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        Some(taken)
    }

    /// The next `N` bytes: a key, a hash, a secret.
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    /// A number: eight bytes, the highest first.
    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }

    /// A count or a length: two bytes, the higher first.
    pub(crate) fn count(&mut self) -> Option<usize> {
        self.array()
            .map(|bytes| usize::from(u16::from_be_bytes(bytes)))
    }

    /// What has not been read.
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.bytes
    }

    /// Whether everything has been read.
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// What the tests of this module and of the change entry are made from.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::phrase::Phrase;

    pub(crate) const WORDS: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    pub(crate) const OTHER_WORDS: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

    pub(crate) fn phrase() -> Phrase {
        Phrase::parse(WORDS).unwrap()
    }

    /// The device numbered `n`, with its key pair.
    pub(crate) fn identity(n: u16) -> NodeIdentity {
        let mut seed = [0x5a; 32];
        seed[..2].copy_from_slice(&n.to_be_bytes());
        NodeIdentity::from_seed(seed).unwrap()
    }

    pub(crate) fn key(n: u16) -> [u8; 32] {
        identity(n).public_key()
    }

    pub(crate) fn device(n: u16) -> Device {
        Device::new(key(n), &format!("device {n}")).unwrap()
    }

    pub(crate) fn devices(numbers: &[u16]) -> Vec<Device> {
        numbers.iter().map(|n| device(*n)).collect()
    }

    pub(crate) fn secret(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// Statement 1 of `phrase`, made on device 0 and committing to secret
    /// 1.
    pub(crate) fn first(phrase: &Phrase) -> Statement {
        Statement::first(device(0), &secret(1), phrase.public_key().unwrap()).unwrap()
    }

    pub(crate) fn signed(statement: &Statement, phrase: &Phrase) -> SignedStatement {
        statement
            .clone()
            .sign(&phrase.signing_key().unwrap())
            .unwrap()
    }

    /// A statement at every bound together: number 256, 64 devices with
    /// labels of 64 bytes, 256 removed keys and a chain of 256. It commits
    /// to secret 9.
    pub(crate) fn at_every_bound(phrase: &Phrase) -> Statement {
        let devices = (0..64)
            .map(|n| Device {
                key: key(n),
                label: format!("{:x<64}", format!("device-{n:02}-")),
            })
            .collect();
        let removed = (0u16..256)
            .map(|n| {
                let mut key = [0xee; 32];
                key[30..].copy_from_slice(&n.to_be_bytes());
                key
            })
            .collect();
        // Every number from 1 to 255, and one of them twice: two statements
        // that were made apart, and settled.
        let mut chain: Vec<Link> = (1u64..=255)
            .map(|number| Link {
                number,
                hash: [number as u8; 16],
            })
            .collect();
        chain.push(Link {
            number: 255,
            hash: [0; 16],
        });
        chain.sort_unstable();
        Statement {
            number: 256,
            maker: key(0),
            chain,
            commitment: commitment(&secret(9)),
            devices,
            removed,
            phrase_key: phrase.public_key().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::phrase::Phrase;
    use cordelia_core::protocol::MAX_STATEMENT_BYTES;

    /// A statement with something in every list: number 3, made on device
    /// 1, listing devices 1 and 0 in that order and two removed keys.
    fn sample(phrase: &Phrase) -> Statement {
        Statement {
            number: 3,
            maker: key(1),
            chain: vec![
                Link {
                    number: 1,
                    hash: [0xa1; 16],
                },
                Link {
                    number: 2,
                    hash: [0xa2; 16],
                },
            ],
            commitment: [0xc0; 32],
            devices: vec![
                Device::new(key(1), "desktop").unwrap(),
                Device::new(key(0), "laptop").unwrap(),
            ],
            removed: vec![[0x0d; 32], [0xd0; 32]],
            phrase_key: phrase.public_key().unwrap(),
        }
    }

    /// A statement's form written field by field, so that a form that is
    /// not a statement's can be written too.
    #[derive(Clone)]
    struct Raw {
        number: u64,
        maker: [u8; 32],
        chain: Vec<(u64, [u8; 16])>,
        commitment: [u8; 32],
        devices: Vec<([u8; 32], Vec<u8>)>,
        removed: Vec<[u8; 32]>,
        phrase_key: [u8; 32],
        reserved: Vec<u8>,
    }

    impl Raw {
        fn of(statement: &Statement) -> Self {
            Self {
                number: statement.number,
                maker: statement.maker,
                chain: statement
                    .chain
                    .iter()
                    .map(|link| (link.number, link.hash))
                    .collect(),
                commitment: statement.commitment,
                devices: statement
                    .devices
                    .iter()
                    .map(|device| (device.key, device.label.clone().into_bytes()))
                    .collect(),
                removed: statement.removed.clone(),
                phrase_key: statement.phrase_key,
                reserved: Vec::new(),
            }
        }

        fn bytes(&self) -> Vec<u8> {
            let count = |n: usize| (n as u16).to_be_bytes();
            let mut out = Vec::new();
            out.extend_from_slice(&self.number.to_be_bytes());
            out.extend_from_slice(&self.maker);
            out.extend_from_slice(&count(self.chain.len()));
            for (number, hash) in &self.chain {
                out.extend_from_slice(&number.to_be_bytes());
                out.extend_from_slice(hash);
            }
            out.extend_from_slice(&self.commitment);
            out.extend_from_slice(&count(self.devices.len()));
            for (key, label) in &self.devices {
                out.extend_from_slice(key);
                out.extend_from_slice(&count(label.len()));
                out.extend_from_slice(label);
            }
            out.extend_from_slice(&count(self.removed.len()));
            for key in &self.removed {
                out.extend_from_slice(key);
            }
            out.extend_from_slice(&self.phrase_key);
            out.extend_from_slice(&count(self.reserved.len()));
            out.extend_from_slice(&self.reserved);
            out
        }

        /// What decoding says of this form with one thing changed.
        fn with(&self, change: impl FnOnce(&mut Raw)) -> Result<Statement, StatementError> {
            let mut raw = self.clone();
            change(&mut raw);
            Statement::from_bytes(&raw.bytes())
        }
    }

    /// What a statement is said to be with one thing changed.
    fn with(
        statement: &Statement,
        change: impl FnOnce(&mut Statement),
    ) -> Result<(), StatementError> {
        let mut statement = statement.clone();
        change(&mut statement);
        statement.validate()
    }

    // ── The canonical form ───────────────────────────────────────────

    /// The form, field by field: the order, and the width of each number.
    #[test]
    fn a_statement_has_one_canonical_form() {
        let phrase = phrase();
        let statement = sample(&phrase);

        let mut form = Vec::new();
        form.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 3]);
        form.extend_from_slice(&key(1));
        form.extend_from_slice(&[0, 2]);
        form.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        form.extend_from_slice(&[0xa1; 16]);
        form.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
        form.extend_from_slice(&[0xa2; 16]);
        form.extend_from_slice(&[0xc0; 32]);
        form.extend_from_slice(&[0, 2]);
        form.extend_from_slice(&key(1));
        form.extend_from_slice(&[0, 7]);
        form.extend_from_slice(b"desktop");
        form.extend_from_slice(&key(0));
        form.extend_from_slice(&[0, 6]);
        form.extend_from_slice(b"laptop");
        form.extend_from_slice(&[0, 2]);
        form.extend_from_slice(&[0x0d; 32]);
        form.extend_from_slice(&[0xd0; 32]);
        form.extend_from_slice(&phrase.public_key().unwrap());
        form.extend_from_slice(&[0, 0]);

        assert_eq!(statement.to_bytes().unwrap(), form);
        assert_eq!(Statement::from_bytes(&form).unwrap(), statement);
        assert_eq!(Raw::of(&statement).bytes(), form);
    }

    /// No two forms are one statement: whatever one changed bit of a form
    /// still decodes, decodes to a statement whose form is those bytes.
    #[test]
    fn a_statement_has_no_second_spelling() {
        let form = sample(&phrase()).to_bytes().unwrap();
        let mut still_statements = 0;
        for at in 0..form.len() {
            for bit in 0..8 {
                let mut changed = form.clone();
                changed[at] ^= 1 << bit;
                if let Ok(statement) = Statement::from_bytes(&changed) {
                    assert_eq!(statement.to_bytes().unwrap(), changed, "{at} {bit}");
                    still_statements += 1;
                }
            }
        }
        // A changed key or hash is another statement, and a changed count,
        // length or order is none.
        assert!(still_statements > 1000, "{still_statements}");
        assert!(
            still_statements < form.len() * 8 - 100,
            "{still_statements}"
        );
    }

    #[test]
    fn the_devices_keep_the_order_their_maker_gave() {
        let statement = sample(&phrase());
        assert!(statement.devices[0].key != statement.devices[1].key);
        let read = Statement::from_bytes(&statement.to_bytes().unwrap()).unwrap();
        assert_eq!(read.devices, statement.devices);

        // In the other order it is another statement, with another hash:
        // the secrets sealed with it follow this order.
        let mut other = statement.clone();
        other.devices.reverse();
        let read = Statement::from_bytes(&other.to_bytes().unwrap()).unwrap();
        assert_eq!(read.devices, other.devices);
        assert_ne!(read.devices, statement.devices);
        assert_ne!(other.hash().unwrap(), statement.hash().unwrap());
    }

    #[test]
    fn a_statement_that_ends_early_or_goes_on_is_refused() {
        let statement = sample(&phrase());
        let form = statement.to_bytes().unwrap();
        for length in 0..form.len() {
            assert_eq!(
                Statement::from_bytes(&form[..length]),
                Err(StatementError::Truncated),
                "{length}"
            );
        }
        for more in [vec![0], vec![0, 0], form.clone()] {
            let mut longer = form.clone();
            longer.extend_from_slice(&more);
            assert_eq!(
                Statement::from_bytes(&longer),
                Err(StatementError::TrailingBytes)
            );
        }
    }

    /// A statement keeps one field empty, for a later way to replace the
    /// phrase. A device refuses a statement in which it is not empty.
    #[test]
    fn a_statement_whose_empty_field_is_not_empty_is_refused() {
        let raw = Raw::of(&sample(&phrase()));
        assert!(raw.with(|_| ()).is_ok());
        for reserved in [vec![0], vec![1], vec![0; 32], vec![0xff; 600]] {
            assert_eq!(
                raw.with(|raw| raw.reserved = reserved),
                Err(StatementError::Reserved)
            );
        }
        // It is refused for what its length says, whatever follows.
        let mut form = raw.bytes();
        let end = form.len();
        form[end - 1] = 1;
        assert_eq!(Statement::from_bytes(&form), Err(StatementError::Reserved));
    }

    /// A count over its bound is refused where it is read, before anything
    /// is read or set aside for what it counts.
    #[test]
    fn a_list_over_its_bound_is_refused_where_its_count_is_read() {
        let raw = Raw::of(&sample(&phrase()));
        let form = raw.bytes();
        let count = |n: u16| n.to_be_bytes();

        // The chain's count is at 40: after the number and the maker.
        let mut cut = form[..40].to_vec();
        cut.extend_from_slice(&count(257));
        assert_eq!(
            Statement::from_bytes(&cut),
            Err(StatementError::ChainTooLong(257))
        );
        cut[40..].copy_from_slice(&count(256));
        assert_eq!(Statement::from_bytes(&cut), Err(StatementError::Truncated));

        // The devices' count is after the chain and the commitment.
        let devices_at = 42 + 2 * 24 + 32;
        let mut cut = form[..devices_at].to_vec();
        cut.extend_from_slice(&count(65));
        assert_eq!(
            Statement::from_bytes(&cut),
            Err(StatementError::TooManyDevices(65))
        );
        cut[devices_at..].copy_from_slice(&count(64));
        assert_eq!(Statement::from_bytes(&cut), Err(StatementError::Truncated));

        // A label's length is after its device's key.
        let label_at = devices_at + 2 + 32;
        let mut cut = form[..label_at].to_vec();
        cut.extend_from_slice(&count(65));
        assert_eq!(
            Statement::from_bytes(&cut),
            Err(StatementError::LabelLength(65))
        );
        cut[label_at..].copy_from_slice(&count(64));
        assert_eq!(Statement::from_bytes(&cut), Err(StatementError::Truncated));

        // The removed keys' count is after the two devices.
        let removed_at = devices_at + 2 + (32 + 2 + 7) + (32 + 2 + 6);
        let mut cut = form[..removed_at].to_vec();
        cut.extend_from_slice(&count(257));
        assert_eq!(
            Statement::from_bytes(&cut),
            Err(StatementError::TooManyRemoved(257))
        );
        cut[removed_at..].copy_from_slice(&count(256));
        assert_eq!(Statement::from_bytes(&cut), Err(StatementError::Truncated));
    }

    /// What decoding refuses of the lists: a duplicate key, a key in both
    /// lists, and a list that is not in its order.
    #[test]
    fn a_form_whose_lists_are_not_in_their_one_spelling_is_refused() {
        let raw = Raw::of(&sample(&phrase()));
        assert_eq!(
            raw.with(|raw| raw.removed.reverse()),
            Err(StatementError::RemovedOrder)
        );
        assert_eq!(
            raw.with(|raw| raw.removed[1] = raw.removed[0]),
            Err(StatementError::RemovedOrder)
        );
        assert_eq!(
            raw.with(|raw| raw.chain.reverse()),
            Err(StatementError::ChainOrder)
        );
        assert_eq!(
            raw.with(|raw| raw.devices[1].0 = raw.devices[0].0),
            Err(StatementError::DeviceTwice)
        );
        assert_eq!(
            raw.with(|raw| raw.removed[0] = raw.devices[1].0),
            Err(StatementError::InBothLists)
        );
        assert_eq!(
            raw.with(|raw| raw.devices[1].1 = vec![0xff, 0xfe]),
            Err(StatementError::LabelNotPrintable)
        );
        assert_eq!(
            raw.with(|raw| raw.devices[1].1 = b"laptop ".to_vec()),
            Err(StatementError::LabelSpaceAtAnEnd)
        );
        assert!(
            raw.with(|raw| raw.devices[1].1 = b"Kitchen laptop".to_vec())
                .is_ok()
        );
        assert_eq!(
            raw.with(|raw| raw.number = 0),
            Err(StatementError::Number(0))
        );
    }

    // ── What a statement is ──────────────────────────────────────────

    #[test]
    fn a_statements_number_is_from_1_to_256() {
        let phrase = phrase();
        let one = first(&phrase);
        assert_eq!(one.validate(), Ok(()));
        assert_eq!(with(&one, |s| s.number = 0), Err(StatementError::Number(0)));
        let last = at_every_bound(&phrase);
        assert_eq!(last.number, 256);
        assert_eq!(last.validate(), Ok(()));
        for over in [257, 258, 511, 512, u64::MAX] {
            assert_eq!(
                with(&last, |s| s.number = over),
                Err(StatementError::Number(over))
            );
        }
    }

    #[test]
    fn a_chain_is_in_order_with_no_statement_named_twice() {
        let statement = sample(&phrase());
        let link = |number, hash: u8| Link {
            number,
            hash: [hash; 16],
        };
        for chain in [
            vec![link(2, 0xa2), link(1, 0xa1)],
            vec![link(1, 0xa1), link(1, 0xa1), link(2, 0xa2)],
            vec![link(1, 0xa2), link(1, 0xa1), link(2, 0xa2)],
            vec![link(1, 0xa1), link(2, 0xa2), link(2, 0xa2)],
        ] {
            assert_eq!(
                with(&statement, |s| s.chain = chain),
                Err(StatementError::ChainOrder)
            );
        }
    }

    /// A statement is numbered one above the highest on its chain, and its
    /// chain goes back to the first: it starts at 1 and leaves no number
    /// out. Two statements that were made apart have one number.
    #[test]
    fn a_chain_goes_from_the_first_statement_to_the_one_before() {
        let statement = sample(&phrase());
        let link = |number, hash: u8| Link {
            number,
            hash: [hash; 16],
        };
        let chain_of = |numbers: &[u64]| -> Vec<Link> {
            numbers
                .iter()
                .enumerate()
                .map(|(i, number)| link(*number, i as u8))
                .collect()
        };
        let said = |number: u64, numbers: &[u64]| {
            with(&statement, |s| {
                s.number = number;
                s.chain = chain_of(numbers);
            })
        };
        // The first has no chain, and every other has one.
        assert_eq!(said(1, &[]), Ok(()));
        assert_eq!(said(2, &[1]), Ok(()));
        assert_eq!(said(3, &[1, 2]), Ok(()));
        // Two branches, settled: one number twice or more.
        assert_eq!(said(3, &[1, 2, 2]), Ok(()));
        assert_eq!(said(4, &[1, 1, 2, 2, 2, 3]), Ok(()));
        for (number, numbers) in [
            // Not one above the highest on its chain.
            (2, &[][..]),
            (1, &[1]),
            (2, &[1, 2]),
            (4, &[1, 2]),
            (5, &[1, 2]),
            // Not back to the first.
            (3, &[2]),
            (4, &[2, 3]),
            (1, &[0]),
            (2, &[0, 1]),
            // A number left out.
            (4, &[1, 3]),
            (5, &[1, 2, 4]),
            (5, &[1, 1, 3, 4]),
            // A statement that is not before it: one above its own number,
            // and one at it.
            (3, &[1, 2, 7]),
            (3, &[1, 2, 3]),
            (3, &[1, 2, 256]),
        ] {
            assert_eq!(
                said(number, numbers),
                Err(StatementError::ChainNumbers),
                "{number} {numbers:?}"
            );
        }
    }

    #[test]
    fn a_device_is_listed_once_and_the_maker_is_among_them() {
        let statement = sample(&phrase());
        assert_eq!(
            with(&statement, |s| s.devices[1].key = s.devices[0].key),
            Err(StatementError::DeviceTwice)
        );
        // Made on a device that it does not list.
        assert_eq!(
            with(&statement, |s| s.maker = key(7)),
            Err(StatementError::MakerNotListed)
        );
        assert_eq!(
            with(&statement, |s| {
                s.devices.remove(0);
            }),
            Err(StatementError::MakerNotListed)
        );
        // So a statement lists at least one device.
        assert_eq!(
            with(&statement, |s| s.devices.clear()),
            Err(StatementError::MakerNotListed)
        );
        // Two devices may have one label: a label is the word of whoever
        // added the device.
        assert_eq!(
            with(&statement, |s| s.devices[1].label =
                s.devices[0].label.clone()),
            Ok(())
        );
    }

    /// A device's key, and the key of the device a statement was made on,
    /// is a usable public key: a point of the order that every real key
    /// has. Nothing can be sealed to any other, and anyone can sign for a
    /// point of small order. A statement that lists one is no statement,
    /// where it is made and where it is read.
    #[test]
    fn a_devices_key_and_the_makers_are_usable_public_keys() {
        let phrase = phrase();
        let statement = sample(&phrase);
        // The identity, which is of small order, and bytes that are no
        // point at all.
        let mut small = [0u8; 32];
        small[0] = 1;
        let no_point = [0x02; 32];
        for unusable in [small, no_point] {
            assert!(!is_usable_public_key(&unusable));
            // A device that is not the maker, wherever it is listed.
            assert_eq!(
                with(&statement, |s| s.devices[1].key = unusable),
                Err(StatementError::DeviceKeyNotUsable)
            );
            assert_eq!(
                with(&statement, |s| s
                    .devices
                    .push(Device::new(unusable, "another").unwrap())),
                Err(StatementError::DeviceKeyNotUsable)
            );
            // The maker, which is among the devices.
            assert_eq!(
                with(&statement, |s| {
                    s.maker = unusable;
                    s.devices[0].key = unusable;
                }),
                Err(StatementError::DeviceKeyNotUsable)
            );
            // A maker that is not, and is no usable key either.
            assert_eq!(
                with(&statement, |s| s.maker = unusable),
                Err(StatementError::MakerKeyNotUsable)
            );

            // Where one is made: the first statement, and the next.
            let nobody = Device::new(unusable, "desktop").unwrap();
            assert_eq!(
                Statement::first(nobody.clone(), &secret(1), statement.phrase_key),
                Err(StatementError::DeviceKeyNotUsable)
            );
            let one = first(&phrase);
            assert_eq!(
                one.next(key(0), &secret(2), vec![device(0), nobody.clone()], &[]),
                Err(StatementError::DeviceKeyNotUsable)
            );
            assert_eq!(
                one.next(unusable, &secret(2), devices(&[0, 1]), &[]),
                Err(StatementError::MakerKeyNotUsable)
            );

            // Where one is read: the form says the same, and is refused. It
            // has no bytes, no hash and no signature of the phrase's.
            let raw = Raw::of(&statement);
            assert_eq!(
                raw.with(|r| r.devices[1].0 = unusable),
                Err(StatementError::DeviceKeyNotUsable)
            );
            assert_eq!(
                raw.with(|r| r.maker = unusable),
                Err(StatementError::MakerKeyNotUsable)
            );
            let mut listing = statement.clone();
            listing.devices[1].key = unusable;
            assert_eq!(listing.to_bytes(), Err(StatementError::DeviceKeyNotUsable));
            assert_eq!(listing.hash(), Err(StatementError::DeviceKeyNotUsable));
            assert_eq!(
                listing.clone().sign(&phrase.signing_key().unwrap()),
                Err(StatementError::DeviceKeyNotUsable)
            );
            // It is refused each time it is asked, and a statement of real
            // keys is one each time.
            assert_eq!(listing.validate(), Err(StatementError::DeviceKeyNotUsable));
            assert_eq!(statement.validate(), Ok(()));
            assert_eq!(statement.validate(), Ok(()));
        }

        // A key that was removed is a key that some statement listed, or
        // that a person declined: it is not held to this.
        assert_eq!(with(&statement, |s| s.removed = vec![small]), Ok(()));
    }

    /// A label is 1 to 64 bytes of printable ASCII, with no space at either
    /// end. It is what a person calls a device, and is kept as it is
    /// given: not tidied as a name is, and not put in lower case.
    #[test]
    fn a_label_is_printable_text_with_no_space_at_either_end() {
        let statement = sample(&phrase());
        let said = |label: &str| with(&statement, |s| s.devices[1].label = label.to_string());

        for label in [
            "a",
            "laptop",
            "Kitchen laptop",
            "work laptop (2)",
            "A  B",
            "~",
            "Laptop.git",
            "repo/",
            "!",
            &"x".repeat(64),
        ] {
            assert_eq!(said(label), Ok(()), "{label:?}");
            // And it is in the statement as it was given.
            assert_eq!(Device::new(key(1), label).unwrap().label, label);
        }
        // Every printable character of ASCII, the first and the last among
        // them, with one that is not a space at each end.
        let all: String = (0x21..=0x7e_u8).map(char::from).collect();
        assert_eq!(said(&all[..64]), Ok(()));
        assert_eq!(said(&all[30..]), Ok(()));
        assert_eq!(said("a b~"), Ok(()));

        assert_eq!(said(""), Err(StatementError::LabelLength(0)));
        assert_eq!(said(&"x".repeat(65)), Err(StatementError::LabelLength(65)));
        for label in [
            "lap\ttop",
            "lap\ntop",
            "lap\u{7f}top",
            "lap\u{1f}top",
            "\u{1b}[31m",
            "büro",
            "lap\u{a0}top",
            "lap\u{202e}top",
        ] {
            assert_eq!(
                said(label),
                Err(StatementError::LabelNotPrintable),
                "{label:?}"
            );
            assert_eq!(
                Device::new(key(1), label),
                Err(StatementError::LabelNotPrintable)
            );
        }
        for label in [" laptop", "laptop ", " Kitchen laptop ", " ", "  "] {
            assert_eq!(
                said(label),
                Err(StatementError::LabelSpaceAtAnEnd),
                "{label:?}"
            );
            // A device is not made with it, and it is not trimmed into one
            // that is.
            assert_eq!(
                Device::new(key(1), label),
                Err(StatementError::LabelSpaceAtAnEnd),
                "{label:?}"
            );
        }
        assert_eq!(Device::new(key(1), ""), Err(StatementError::LabelLength(0)));
        assert_eq!(
            Device::new(key(1), &"X".repeat(65)),
            Err(StatementError::LabelLength(65))
        );
    }

    #[test]
    fn the_removed_keys_are_in_order_and_none_is_a_device() {
        let statement = sample(&phrase());
        assert_eq!(
            with(&statement, |s| s.removed.reverse()),
            Err(StatementError::RemovedOrder)
        );
        assert_eq!(
            with(&statement, |s| s.removed[1] = s.removed[0]),
            Err(StatementError::RemovedOrder)
        );
        for device in 0..2 {
            assert_eq!(
                with(&statement, |s| s.removed = vec![s.devices[device].key]),
                Err(StatementError::InBothLists)
            );
            assert_eq!(
                with(&statement, |s| {
                    s.removed.push(s.devices[device].key);
                    s.removed.sort_unstable();
                }),
                Err(StatementError::InBothLists)
            );
        }
    }

    /// The bounds of a statement, each alone: one more than the bound is
    /// refused, in a statement that is at every bound.
    #[test]
    fn a_statement_over_a_bound_is_refused() {
        let phrase = phrase();
        let full = at_every_bound(&phrase);
        assert_eq!(full.validate(), Ok(()));
        assert_eq!(full.devices.len(), 64);
        assert_eq!(full.removed.len(), 256);
        assert_eq!(full.chain.len(), 256);
        assert!(full.devices.iter().all(|device| device.label.len() == 64));

        assert_eq!(
            with(&full, |s| s.devices.push(device(64))),
            Err(StatementError::TooManyDevices(65))
        );
        assert_eq!(
            with(&full, |s| s.removed.push([0xef; 32])),
            Err(StatementError::TooManyRemoved(257))
        );
        // One more statement on the chain, in its place: a chain that is
        // refused for its length alone.
        assert_eq!(
            with(&full, |s| {
                s.chain.push(Link {
                    number: 255,
                    hash: [0x01; 16],
                });
                s.chain.sort_unstable();
            }),
            Err(StatementError::ChainTooLong(257))
        );
        assert_eq!(
            with(&full, |s| s.devices[63].label.push('x')),
            Err(StatementError::LabelLength(65))
        );
    }

    /// At every bound together a statement is as large as the bound says:
    /// about 21 KB with its signature.
    #[test]
    fn a_statement_at_every_bound_is_as_large_as_the_bound_says() {
        let phrase = phrase();
        let full = signed(&at_every_bound(&phrase), &phrase);
        let form = full.statement.to_bytes().unwrap();
        assert_eq!(form.len(), 20_720);
        let bytes = full.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_STATEMENT_BYTES);
        assert_eq!(bytes.len(), 20_784);

        let read = SignedStatement::from_bytes(&bytes).unwrap();
        assert_eq!(read, full);
        assert_eq!(read.verify(), Ok(()));
    }

    // ── The hash, the commitment and the signature ───────────────────

    #[test]
    fn a_statements_hash_is_the_first_16_bytes_of_sha256_of_its_form() {
        let phrase = phrase();
        let statement = sample(&phrase);
        let digest = crate::sha256(&statement.to_bytes().unwrap());
        assert_eq!(statement.hash().unwrap(), digest[..16]);
        assert_eq!(
            statement.link().unwrap(),
            Link {
                number: 3,
                hash: digest[..16].try_into().unwrap()
            }
        );
        // The signature is no part of it.
        let signed = signed(&statement, &phrase);
        assert_eq!(signed.statement.hash().unwrap(), digest[..16]);
        // A statement that is not valid has no form, and so no hash.
        let mut not_one = statement.clone();
        not_one.removed.reverse();
        assert_eq!(not_one.hash(), Err(StatementError::RemovedOrder));
        assert_eq!(not_one.to_bytes(), Err(StatementError::RemovedOrder));
    }

    /// The commitment is a hash of the secret under the commitment's
    /// label, spelled here as it is published. A statement commits to one
    /// secret, and to no other.
    #[test]
    fn a_commitment_is_a_hash_of_the_secret_under_its_label() {
        let mut hashed = b"cordelia v2 commitment".to_vec();
        hashed.extend_from_slice(&secret(1));
        assert_eq!(commitment(&secret(1)), crate::sha256(&hashed));
        assert_ne!(commitment(&secret(1)), crate::sha256(&secret(1)));
        assert_ne!(commitment(&secret(1)), commitment(&secret(2)));

        let one = first(&phrase());
        assert_eq!(one.commitment, commitment(&secret(1)));
        assert!(one.commits_to(&secret(1)));
        // A secret that does not match the commitment.
        assert!(!one.commits_to(&secret(2)));
        assert!(!one.commits_to(&one.commitment));
        let mut nearly = secret(1);
        nearly[31] ^= 1;
        assert!(!one.commits_to(&nearly));
    }

    /// A new secret is 32 random bytes, another each time, and a statement
    /// commits to it as to any secret.
    #[test]
    fn a_new_secret_is_made_from_random_numbers() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let secret = new_secret().unwrap();
            assert!(seen.insert(secret), "the same secret twice");
            assert_ne!(secret, [0u8; 32]);
        }
        let secret = new_secret().unwrap();
        let phrase = phrase();
        let one = Statement::first(device(0), &secret, phrase.public_key().unwrap()).unwrap();
        assert!(one.commits_to(&secret));
        assert!(!one.commits_to(&new_secret().unwrap()));
    }

    /// The phrase's key signs the statement's label and its form. The
    /// label is spelled here as it is published.
    #[test]
    fn a_statement_is_signed_by_the_phrases_key_under_its_label() {
        let phrase = phrase();
        let key = phrase.signing_key().unwrap();
        let statement = sample(&phrase);
        let signed = statement.clone().sign(&key).unwrap();
        assert_eq!(signed.verify(), Ok(()));
        assert_eq!(signed.statement, statement);

        let form = statement.to_bytes().unwrap();
        let mut labelled = b"cordelia v2 statement".to_vec();
        labelled.extend_from_slice(&form);
        assert_eq!(signed.signature, key.sign(&labelled));

        // The same key's signature of the form alone, or under another
        // label, is not a statement's signature.
        let mut bare = signed.clone();
        bare.signature = key.sign(&form);
        assert_eq!(bare.verify(), Err(StatementError::Signature));
        let mut other_label = b"cordelia v2 commitment".to_vec();
        other_label.extend_from_slice(&form);
        bare.signature = key.sign(&other_label);
        assert_eq!(bare.verify(), Err(StatementError::Signature));

        // A statement that was changed after it was signed.
        let mut changed = signed.clone();
        changed.statement.commitment[0] ^= 1;
        assert_eq!(changed.verify(), Err(StatementError::Signature));
        let mut changed = signed.clone();
        changed.statement.devices[1].label = "desktop".into();
        assert_eq!(changed.verify(), Err(StatementError::Signature));
        let mut changed = signed.clone();
        changed.signature[63] ^= 0x10;
        assert_eq!(changed.verify(), Err(StatementError::Signature));
    }

    #[test]
    fn a_statement_is_signed_by_no_key_but_its_phrases() {
        let phrase = phrase();
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let statement = sample(&phrase);

        // Another phrase's key does not sign it.
        assert_eq!(
            statement.clone().sign(&other.signing_key().unwrap()),
            Err(StatementError::NotThePhrasesKey)
        );
        assert_eq!(
            statement.clone().sign(&identity(1)),
            Err(StatementError::NotThePhrasesKey)
        );
        // And its signature, put on the statement by hand, is refused.
        let form = statement.to_bytes().unwrap();
        let forged = SignedStatement {
            statement: statement.clone(),
            signature: other.signing_key().unwrap().sign(&under_label(&form)),
        };
        assert_eq!(forged.verify(), Err(StatementError::Signature));

        // A statement that is not valid is not signed, and does not verify.
        let mut not_one = statement.clone();
        not_one.removed.push(not_one.devices[0].key);
        not_one.removed.sort_unstable();
        assert_eq!(
            not_one.clone().sign(&phrase.signing_key().unwrap()),
            Err(StatementError::InBothLists)
        );
        let unsigned = SignedStatement {
            statement: not_one,
            signature: [0u8; 64],
        };
        assert_eq!(unsigned.verify(), Err(StatementError::InBothLists));
    }

    /// Under a point of small order anyone can make a signature that is
    /// accepted, for any message. A statement that names such a key as its
    /// phrase's is refused before the signature is looked at.
    #[test]
    fn a_statement_under_a_key_that_anyone_can_sign_for_is_refused() {
        // The identity, and with it a signature that is the identity and
        // zero.
        let mut anyones = [0u8; 32];
        anyones[0] = 1;
        let mut signature = [0u8; 64];
        signature[0] = 1;

        let mut statement = sample(&phrase());
        statement.phrase_key = anyones;
        let forged = SignedStatement {
            statement,
            signature,
        };
        // The control: the signature is accepted as a signature.
        let form = forged.statement.to_bytes().unwrap();
        assert!(verify_signature(&anyones, &under_label(&form), &signature));
        assert_eq!(forged.verify(), Err(StatementError::PhraseKeyNotUsable));
        // Bytes that are no point at all are refused the same way.
        let mut forged = forged;
        forged.statement.phrase_key = [0x02; 32];
        assert!(!is_usable_public_key(&[0x02; 32]));
        assert_eq!(forged.verify(), Err(StatementError::PhraseKeyNotUsable));
    }

    #[test]
    fn a_signed_statement_is_its_form_and_then_its_signature() {
        let phrase = phrase();
        let signed = signed(&sample(&phrase), &phrase);
        let bytes = signed.to_bytes().unwrap();
        let form = signed.statement.to_bytes().unwrap();
        assert_eq!(bytes.len(), form.len() + 64);
        assert_eq!(bytes[..form.len()], form);
        assert_eq!(bytes[form.len()..], signed.signature);
        assert_eq!(SignedStatement::from_bytes(&bytes).unwrap(), signed);

        // Too short to hold a signature, and too short to hold a statement
        // before it.
        for length in [0, 1, 63, 64, 65, bytes.len() - 1] {
            assert_eq!(
                SignedStatement::from_bytes(&bytes[..length]),
                Err(StatementError::Truncated),
                "{length}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            SignedStatement::from_bytes(&longer),
            Err(StatementError::TrailingBytes)
        );
        // Decoding does not check the signature: verifying does.
        let mut unsigned = bytes.clone();
        let end = unsigned.len();
        unsigned[end - 1] ^= 1;
        let read = SignedStatement::from_bytes(&unsigned).unwrap();
        assert_eq!(read.verify(), Err(StatementError::Signature));
    }

    // ── Making a statement ───────────────────────────────────────────

    #[test]
    fn the_first_statement_lists_one_device_and_has_no_chain() {
        let phrase = phrase();
        let one = first(&phrase);
        assert_eq!(one.number, 1);
        assert!(one.chain.is_empty());
        assert_eq!(one.maker, key(0));
        assert_eq!(one.devices, vec![device(0)]);
        assert!(one.removed.is_empty());
        assert_eq!(one.phrase_key, phrase.public_key().unwrap());
        assert!(one.commits_to(&secret(1)));
        assert_eq!(one.validate(), Ok(()));
    }

    /// A statement is numbered one above the highest on its chain, and its
    /// chain is the statement its maker had applied, with that one's chain.
    #[test]
    fn the_next_statement_is_numbered_one_above_and_names_every_one_before() {
        let phrase = phrase();
        let one = first(&phrase);
        let two = one.next(key(0), &secret(2), devices(&[0, 1]), &[]).unwrap();
        assert_eq!(two.number, 2);
        assert_eq!(two.chain, vec![one.link().unwrap()]);
        assert_eq!(two.maker, key(0));
        assert_eq!(two.devices, devices(&[0, 1]));
        assert!(two.removed.is_empty());
        assert_eq!(two.phrase_key, one.phrase_key);
        assert!(two.commits_to(&secret(2)) && !two.commits_to(&secret(1)));

        // Made on the device that was added, which lists itself first.
        let three = two
            .next(key(1), &secret(3), devices(&[1, 0, 2]), &[])
            .unwrap();
        assert_eq!(three.number, 3);
        assert_eq!(three.chain, vec![one.link().unwrap(), two.link().unwrap()]);
        assert_eq!(three.maker, key(1));
        assert_eq!(three.devices, devices(&[1, 0, 2]));
        assert_eq!(three.validate(), Ok(()));

        // The device that makes a statement is always among its devices.
        assert_eq!(
            two.next(key(1), &secret(3), devices(&[0, 2]), &[]),
            Err(StatementError::MakerNotListed)
        );
        // A statement that is not valid has no next.
        let mut not_one = two.clone();
        not_one.number = 7;
        assert_eq!(
            not_one.next(key(0), &secret(3), devices(&[0]), &[]),
            Err(StatementError::ChainNumbers)
        );
    }

    /// A statement lists as removed every key that any statement on its
    /// chain removes, and nothing brings a removed key back.
    #[test]
    fn the_next_statement_removes_every_key_removed_before() {
        let phrase = phrase();
        let one = first(&phrase);
        let two = one
            .next(key(0), &secret(2), devices(&[0, 2]), &[key(1)])
            .unwrap();
        assert_eq!(two.removed, vec![key(1)]);

        let three = two
            .next(key(0), &secret(3), devices(&[0]), &[key(2)])
            .unwrap();
        let mut both = vec![key(1), key(2)];
        both.sort_unstable();
        assert_eq!(three.removed, both);

        // A renewal removes nobody, and keeps what was removed. A key that
        // is removed twice is listed once.
        let four = three.next(key(0), &secret(4), devices(&[0]), &[]).unwrap();
        assert_eq!(four.removed, both);
        let five = four
            .next(
                key(0),
                &secret(5),
                devices(&[0, 3]),
                &[key(2), key(1), key(2)],
            )
            .unwrap();
        assert_eq!(five.removed, both);

        // A removed key is not a device again, under this statement or any
        // after it, and a key is not removed and kept at once.
        for (from, back) in [(&two, 1), (&three, 1), (&three, 2), (&four, 2), (&five, 1)] {
            assert_eq!(
                from.next(key(0), &secret(6), devices(&[0, back]), &[]),
                Err(StatementError::InBothLists),
                "{back}"
            );
        }
        assert_eq!(
            four.next(key(0), &secret(6), devices(&[0, 3]), &[key(3)]),
            Err(StatementError::InBothLists)
        );
        // Nor may the maker remove itself.
        assert_eq!(
            four.next(key(0), &secret(6), devices(&[0]), &[key(0)]),
            Err(StatementError::InBothLists)
        );
    }

    /// A phrase makes 256 statements in this format, and the next is
    /// refused.
    #[test]
    fn the_two_hundred_and_fifty_seventh_statement_is_refused() {
        let phrase = phrase();
        let mut latest = first(&phrase);
        for number in 2..=256u64 {
            latest = latest
                .next(key(0), &secret(number as u8), devices(&[0]), &[])
                .unwrap();
            assert_eq!(latest.number, number);
            assert_eq!(latest.chain.len() as u64, number - 1);
        }
        assert_eq!(latest.validate(), Ok(()));
        assert_eq!(
            latest.next(key(0), &secret(0), devices(&[0]), &[]),
            Err(StatementError::Number(257))
        );
    }

    /// A phrase removes 256 keys, and a statement that would list more is
    /// refused.
    #[test]
    fn a_statement_that_would_remove_more_than_256_keys_is_refused() {
        let phrase = phrase();
        let one = first(&phrase);
        let gone: Vec<[u8; 32]> = (0u16..257)
            .map(|n| {
                let mut key = [0xee; 32];
                key[30..].copy_from_slice(&n.to_be_bytes());
                key
            })
            .collect();
        let two = one
            .next(key(0), &secret(2), devices(&[0]), &gone[..200])
            .unwrap();
        assert_eq!(two.removed.len(), 200);
        let three = two
            .next(key(0), &secret(3), devices(&[0]), &gone[150..256])
            .unwrap();
        assert_eq!(three.removed.len(), 256);
        assert_eq!(
            three.next(key(0), &secret(4), devices(&[0]), &gone[256..]),
            Err(StatementError::TooManyRemoved(257))
        );
        assert_eq!(
            two.next(key(0), &secret(3), devices(&[0]), &gone[150..]),
            Err(StatementError::TooManyRemoved(257))
        );
        // With no room left a phrase still makes a statement that removes
        // nobody more.
        assert!(
            three
                .next(key(0), &secret(4), devices(&[0]), &gone[..9])
                .is_ok()
        );
    }

    // ── Two changes made apart ───────────────────────────────────────

    /// Two branches from one statement, as two devices make them before
    /// they have met.
    struct Apart {
        /// Statement 1, and statement 2, which lists devices 0, 1 and 2.
        one: Statement,
        two: Statement,
        /// Made on device 0: it removes device 2.
        a3: Statement,
        /// Made on device 1: it removes device 0, then adds device 5, then
        /// renews.
        b3: Statement,
        b4: Statement,
        b5: Statement,
    }

    fn apart(phrase: &Phrase) -> Apart {
        let one = first(phrase);
        let two = one
            .next(key(0), &secret(2), devices(&[0, 1, 2]), &[])
            .unwrap();
        let a3 = two
            .next(key(0), &secret(0xa3), devices(&[0, 1]), &[key(2)])
            .unwrap();
        let b3 = two
            .next(key(1), &secret(0xb3), devices(&[1, 2]), &[key(0)])
            .unwrap();
        let b4 = b3
            .next(key(1), &secret(0xb4), devices(&[1, 2, 5]), &[])
            .unwrap();
        let b5 = b4
            .next(key(1), &secret(0xb5), devices(&[1, 2, 5]), &[])
            .unwrap();
        Apart {
            one,
            two,
            a3,
            b3,
            b4,
            b5,
        }
    }

    /// A settlement is numbered above both, and its chain holds both and
    /// their chains.
    #[test]
    fn a_settlement_names_both_statements_and_their_chains() {
        let phrase = phrase();
        let Apart {
            one,
            two,
            a3,
            b3,
            b4,
            b5,
        } = apart(&phrase);

        let settled =
            Statement::settle(&a3, &b4, key(1), &secret(9), devices(&[1, 5]), &[]).unwrap();
        assert_eq!(settled.number, 5);
        let mut chain = vec![
            one.link().unwrap(),
            two.link().unwrap(),
            a3.link().unwrap(),
            b3.link().unwrap(),
            b4.link().unwrap(),
        ];
        chain.sort_unstable();
        assert_eq!(settled.chain, chain);
        assert_eq!(settled.maker, key(1));
        assert_eq!(settled.phrase_key, a3.phrase_key);
        assert!(settled.commits_to(&secret(9)));
        assert_eq!(settled.validate(), Ok(()));

        // Either way round it is the same statement, and it is numbered
        // above the higher of the two.
        assert_eq!(
            Statement::settle(&b4, &a3, key(1), &secret(9), devices(&[1, 5]), &[]).unwrap(),
            settled
        );
        let later = Statement::settle(&b5, &a3, key(1), &secret(9), devices(&[1, 5]), &[]).unwrap();
        assert_eq!(later.number, 6);
        assert_eq!(later.chain.len(), 6);
        // Two at one number.
        let level = Statement::settle(&a3, &b3, key(1), &secret(9), devices(&[1]), &[]).unwrap();
        assert_eq!(level.number, 4);
        assert_eq!(level.chain.len(), 4);
    }

    /// A settlement's removed keys are every key that either removed, and
    /// none of them is among its devices.
    #[test]
    fn a_settlement_undoes_nothing() {
        let phrase = phrase();
        let Apart { a3, b4, .. } = apart(&phrase);
        let mut both = vec![key(0), key(2)];
        both.sort_unstable();

        let settled =
            Statement::settle(&a3, &b4, key(1), &secret(9), devices(&[1, 5]), &[]).unwrap();
        assert_eq!(settled.removed, both);
        // And those the person says at the prompt are removed.
        let more =
            Statement::settle(&a3, &b4, key(1), &secret(9), devices(&[1]), &[key(5)]).unwrap();
        let mut all = vec![key(0), key(2), key(5)];
        all.sort_unstable();
        assert_eq!(more.removed, all);

        // A device that either branch removed is not kept, whichever
        // branch it is asked on.
        for back in [0, 2] {
            assert_eq!(
                Statement::settle(&a3, &b4, key(1), &secret(9), devices(&[1, back]), &[]),
                Err(StatementError::InBothLists),
                "{back}"
            );
        }
        assert_eq!(
            Statement::settle(&a3, &b4, key(0), &secret(9), devices(&[0, 1]), &[]),
            Err(StatementError::InBothLists)
        );
    }

    /// Only two statements that were made apart are settled. Where one is
    /// the other, or is on the other's chain, there is nothing to settle.
    #[test]
    fn two_statements_that_were_not_made_apart_are_not_settled() {
        let phrase = phrase();
        let Apart {
            one,
            two,
            a3,
            b3,
            b4,
            ..
        } = apart(&phrase);
        for (first, second) in [
            (&a3, &a3),
            (&two, &a3),
            (&a3, &two),
            (&one, &b4),
            (&b4, &b3),
            (&b3, &b4),
        ] {
            assert_eq!(
                Statement::settle(first, second, key(1), &secret(9), devices(&[1]), &[]),
                Err(StatementError::NotApart)
            );
        }
        // The control.
        assert!(Statement::settle(&a3, &b4, key(1), &secret(9), devices(&[1]), &[]).is_ok());

        // Nor are two statements under two phrases.
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let theirs = first(&other);
        assert_eq!(
            Statement::settle(&a3, &theirs, key(1), &secret(9), devices(&[1]), &[]),
            Err(StatementError::AnotherPhrase)
        );
    }

    /// A chain names at most 256 statements. Two long branches can have
    /// more between them than a settlement can name.
    #[test]
    fn a_settlement_whose_chain_would_be_over_the_bound_is_refused() {
        let phrase = phrase();
        let one = first(&phrase);
        let branch = |from: &Statement, steps: u64, salt: u8| {
            let mut latest = from.clone();
            for step in 0..steps {
                latest = latest
                    .next(key(0), &secret(salt ^ step as u8), devices(&[0]), &[])
                    .unwrap();
            }
            latest
        };
        // Each is 128 statements on from statement 1: the chain of a
        // settlement would name 1 + 128 + 128.
        let a = branch(&one, 128, 0x00);
        let b = branch(&one, 128, 0x80);
        assert_eq!((a.number, b.number), (129, 129));
        assert_eq!(
            Statement::settle(&a, &b, key(0), &secret(9), devices(&[0]), &[]),
            Err(StatementError::ChainTooLong(257))
        );
        // One statement fewer on one side, and it is made.
        let shorter = branch(&one, 127, 0x80);
        let settled =
            Statement::settle(&a, &shorter, key(0), &secret(9), devices(&[0]), &[]).unwrap();
        assert_eq!(settled.chain.len(), 256);
        assert_eq!(settled.number, 130);
    }

    // ── What a statement is to a device ──────────────────────────────

    /// The judgement of `shown`, signed by `phrase`, for device `n` that
    /// has applied `applied` and follows `phrase`.
    fn judged(
        phrase: &Phrase,
        shown: &Statement,
        applied: &Statement,
        n: u16,
    ) -> Result<Judgement, StatementError> {
        judge(
            &signed(shown, phrase),
            applied,
            &key(n),
            &phrase.public_key().unwrap(),
        )
    }

    #[test]
    fn a_statement_made_after_the_applied_one_applies() {
        let phrase = phrase();
        let Apart {
            one,
            two,
            a3,
            b3,
            b4,
            b5,
        } = apart(&phrase);
        assert_eq!(judged(&phrase, &two, &one, 0), Ok(Judgement::Applies));
        assert_eq!(judged(&phrase, &a3, &two, 0), Ok(Judgement::Applies));
        assert_eq!(judged(&phrase, &a3, &two, 1), Ok(Judgement::Applies));
        assert_eq!(judged(&phrase, &b3, &two, 2), Ok(Judgement::Applies));
        // A device that was off for one change, for two and for three
        // applies the latest without having seen the ones between.
        assert_eq!(judged(&phrase, &b4, &two, 1), Ok(Judgement::Applies));
        assert_eq!(judged(&phrase, &b5, &two, 1), Ok(Judgement::Applies));
        assert_eq!(judged(&phrase, &b5, &b3, 2), Ok(Judgement::Applies));
        let later = b5
            .next(key(1), &secret(6), devices(&[1, 2, 5]), &[])
            .unwrap();
        assert_eq!(judged(&phrase, &later, &two, 2), Ok(Judgement::Applies));
        assert_eq!(judged(&phrase, &later, &b3, 1), Ok(Judgement::Applies));
    }

    /// Rule 1. A statement that the phrase this device follows did not sign
    /// is nothing to the device, whatever it says.
    #[test]
    fn a_statement_that_the_followed_phrase_did_not_sign_is_not_judged() {
        let phrase = phrase();
        let other = Phrase::parse(OTHER_WORDS).unwrap();
        let ours = phrase.public_key().unwrap();
        let Apart { two, a3, .. } = apart(&phrase);
        assert_eq!(judged(&phrase, &a3, &two, 0), Ok(Judgement::Applies));

        // The same change, made and signed under another phrase.
        let mut theirs = a3.clone();
        theirs.phrase_key = other.public_key().unwrap();
        let theirs = signed(&theirs, &other);
        assert_eq!(theirs.verify(), Ok(()));
        assert_eq!(
            judge(&theirs, &two, &key(0), &ours),
            Err(StatementError::AnotherPhrase)
        );
        // It names this phrase, and the other phrase's key signed it.
        let form = a3.to_bytes().unwrap();
        let forged = SignedStatement {
            statement: a3.clone(),
            signature: other.signing_key().unwrap().sign(&under_label(&form)),
        };
        assert_eq!(
            judge(&forged, &two, &key(0), &ours),
            Err(StatementError::Signature)
        );
        // It was changed after the phrase signed it.
        let mut changed = signed(&a3, &phrase);
        changed.statement.devices.push(device(2));
        changed.statement.removed.clear();
        assert_eq!(
            judge(&changed, &two, &key(0), &ours),
            Err(StatementError::Signature)
        );
        // Rules 2, 5 and 6 are asked against a statement under the phrase
        // that the device follows now: a device that follows another
        // phrase than the one it applied under is told so.
        assert_eq!(
            judge(
                &signed(&a3, &phrase),
                &two,
                &key(0),
                &other.public_key().unwrap()
            ),
            Err(StatementError::AnotherPhrase)
        );
        let mut applied_elsewhere = two.clone();
        applied_elsewhere.phrase_key = other.public_key().unwrap();
        assert_eq!(
            judge(&signed(&a3, &phrase), &applied_elsewhere, &key(0), &ours),
            Err(StatementError::AnotherPhrase)
        );
    }

    /// A statement that is not well formed is no statement, whoever signed
    /// it: it is not judged.
    #[test]
    fn a_statement_that_is_not_well_formed_is_not_judged() {
        let phrase = phrase();
        let ours = phrase.public_key().unwrap();
        let Apart { two, a3, .. } = apart(&phrase);

        // A key in both of its lists.
        let mut both = a3.clone();
        both.devices.push(device(2));
        let signature = phrase
            .signing_key()
            .unwrap()
            .sign(&under_label(&Raw::of(&both).bytes()));
        let shown = SignedStatement {
            statement: both,
            signature,
        };
        assert_eq!(
            judge(&shown, &two, &key(0), &ours),
            Err(StatementError::InBothLists)
        );
        // And the one the device says it has applied is one too.
        let mut applied = two.clone();
        applied.devices.clear();
        assert_eq!(
            judge(&signed(&a3, &phrase), &applied, &key(0), &ours),
            Err(StatementError::MakerNotListed)
        );
    }

    /// Rule 2, and what is behind: the applied statement itself, and each
    /// statement on its chain. Nothing is done with it.
    #[test]
    fn a_statement_on_the_applied_ones_chain_is_behind() {
        let phrase = phrase();
        let Apart {
            one,
            two,
            b3,
            b4,
            b5,
            ..
        } = apart(&phrase);
        for (shown, applied) in [
            (&one, &two),
            (&one, &b5),
            (&two, &b3),
            (&two, &b5),
            (&b3, &b4),
            (&b3, &b5),
            (&b4, &b5),
            // The one it has applied.
            (&one, &one),
            (&b4, &b4),
            (&b5, &b5),
        ] {
            assert_eq!(
                judged(&phrase, shown, applied, 1),
                Ok(Judgement::Behind),
                "{} beside {}",
                shown.number,
                applied.number
            );
        }
        // Whether or not it lists the device: device 0 is in statement 2
        // and removed by b3, and a device that has applied b5 does nothing
        // with either.
        assert_eq!(judged(&phrase, &two, &b5, 0), Ok(Judgement::Behind));
        assert_eq!(judged(&phrase, &b3, &b5, 0), Ok(Judgement::Behind));
    }

    /// Rule 6. A statement that was made apart from the applied one is a
    /// fork: at one number, at a higher one and at a lower one, and two and
    /// three changes deep on one side, seen from each side.
    #[test]
    fn a_statement_made_apart_from_the_applied_one_is_a_fork() {
        let phrase = phrase();
        let Apart {
            two,
            a3,
            b3,
            b4,
            b5,
            ..
        } = apart(&phrase);
        // A branch that removes nobody, so that no removal is in question:
        // only that it was made apart.
        let renewed = two
            .next(key(0), &secret(0xa0), devices(&[0, 1, 2]), &[])
            .unwrap();
        for (shown, applied) in [
            // At one number, from each side.
            (&b3, &a3),
            (&a3, &b3),
            (&b3, &renewed),
            (&renewed, &b3),
            // At a higher number: one, two and three changes deep.
            (&b4, &a3),
            (&b5, &a3),
            (&b4, &renewed),
            (&b5, &renewed),
            // And seen from the deeper side, at a lower number.
            (&a3, &b4),
            (&a3, &b5),
            (&renewed, &b4),
            (&renewed, &b5),
        ] {
            for device in [0, 1, 2, 5, 7] {
                assert_eq!(
                    judged(&phrase, shown, applied, device),
                    Ok(Judgement::Fork),
                    "{} beside {} on device {device}",
                    shown.number,
                    applied.number
                );
            }
        }
        // The control: the same statements beside the one they were made
        // after.
        assert_eq!(judged(&phrase, &b4, &b3, 1), Ok(Judgement::Applies));
        assert_eq!(judged(&phrase, &renewed, &two, 1), Ok(Judgement::Applies));
    }

    /// Rule 5. A statement that was made after the applied one and lacks a
    /// removal that the applied one has is refused, as one that is not
    /// well formed is. It is no fork: the two were not made apart.
    #[test]
    fn a_statement_made_after_the_applied_one_that_lacks_a_removal_is_refused() {
        let phrase = phrase();
        let Apart { a3, .. } = apart(&phrase);
        assert_eq!(a3.removed, vec![key(2)]);

        let kept = a3
            .next(key(0), &secret(4), devices(&[0, 1]), &[key(9)])
            .unwrap();
        assert_eq!(judged(&phrase, &kept, &a3, 1), Ok(Judgement::Applies));

        // The same statement without the removal: as a maker with a fault
        // would have made it. It names the applied one on its chain, and
        // is refused for every device: one it lists, the one whose
        // removal it lacks, and a stranger.
        let mut undone = kept.clone();
        undone.removed.retain(|removed| *removed != key(2));
        assert_eq!(undone.removed, vec![key(9)]);
        assert!(undone.has_on_chain(&a3.link().unwrap()));
        assert_eq!(undone.validate(), Ok(()));
        for device in [0, 1, 2, 7] {
            assert_eq!(
                judged(&phrase, &undone, &a3, device),
                Err(StatementError::UndoesARemoval),
                "{device}"
            );
        }
        // And with the removed key among its devices again.
        let mut back = undone.clone();
        back.devices.push(device(2));
        assert_eq!(back.validate(), Ok(()));
        for device in [1, 2] {
            assert_eq!(
                judged(&phrase, &back, &a3, device),
                Err(StatementError::UndoesARemoval)
            );
        }
        // It is no fork: the two were not made apart, and nothing settles
        // them.
        assert_eq!(
            Statement::settle(&a3, &undone, key(0), &secret(5), devices(&[0, 1]), &[]),
            Err(StatementError::NotApart)
        );

        // One made after it, with the removal again, is judged for what
        // it is: it applies.
        let again = undone
            .next(key(0), &secret(5), devices(&[0, 1]), &[key(2)])
            .unwrap();
        assert!(again.has_on_chain(&a3.link().unwrap()));
        assert_eq!(judged(&phrase, &again, &a3, 1), Ok(Judgement::Applies));
        // To a device that had applied nothing later than the statement
        // before the removal, the one that lacks it undoes nothing.
        let Apart { two, .. } = apart(&phrase);
        assert!(two.removed.is_empty());
        assert_eq!(judged(&phrase, &undone, &two, 1), Ok(Judgement::Applies));
    }

    /// A removal undone by a later statement made apart: the other side
    /// never heard of the removal, and still lists the key as a device.
    #[test]
    fn a_removal_is_not_undone_by_a_statement_made_apart() {
        let phrase = phrase();
        let Apart { a3, b3, b4, b5, .. } = apart(&phrase);
        // Device 2 was removed by a3, and each statement of the other
        // branch lists it.
        for shown in [&b3, &b4, &b5] {
            assert!(shown.lists(&key(2)) && !shown.removes(&key(2)));
            for device in [1, 2] {
                assert_eq!(
                    judged(&phrase, shown, &a3, device),
                    Ok(Judgement::Fork),
                    "{} on device {device}",
                    shown.number
                );
            }
        }
    }

    /// Rule 3, and a statement that does not list this device: removed
    /// where its key is among the removed keys, and in no list otherwise.
    #[test]
    fn a_statement_that_does_not_list_this_device() {
        let phrase = phrase();
        let Apart {
            two, a3, b3, b4, ..
        } = apart(&phrase);
        // a3 was made on device 0, and removes device 2.
        assert_eq!(judged(&phrase, &a3, &two, 0), Ok(Judgement::Applies));
        assert_eq!(judged(&phrase, &a3, &two, 1), Ok(Judgement::Applies));
        assert_eq!(judged(&phrase, &a3, &two, 2), Ok(Judgement::Removed));
        // A device that the maker did not know of is in no list.
        assert_eq!(judged(&phrase, &a3, &two, 7), Ok(Judgement::NotListed));

        // A recovery lists one device, and removes those that are gone:
        // every other device reads that it is in no list.
        let recovered = b4
            .next(key(9), &secret(5), devices(&[9]), &[key(5)])
            .unwrap();
        assert_eq!(judged(&phrase, &recovered, &b4, 9), Ok(Judgement::Applies));
        assert_eq!(
            judged(&phrase, &recovered, &b4, 1),
            Ok(Judgement::NotListed)
        );
        assert_eq!(
            judged(&phrase, &recovered, &b3, 2),
            Ok(Judgement::NotListed)
        );
        assert_eq!(judged(&phrase, &recovered, &b4, 5), Ok(Judgement::Removed));
        // Removed before, and still removed.
        assert_eq!(judged(&phrase, &recovered, &two, 0), Ok(Judgement::Removed));

        // Only a statement that passes the other rules says so. One made
        // apart that removes this device is a fork: b3 removes device 0,
        // and device 0 has applied a3.
        assert!(b3.removes(&key(0)));
        assert_eq!(judged(&phrase, &b3, &a3, 0), Ok(Judgement::Fork));
        assert_eq!(judged(&phrase, &b4, &a3, 0), Ok(Judgement::Fork));
        // And one that is behind does nothing.
        assert_eq!(judged(&phrase, &two, &recovered, 1), Ok(Judgement::Behind));
    }

    /// A settlement is applied like any statement: from each branch, and
    /// by a device that had applied neither.
    #[test]
    fn a_settlement_applies_from_each_branch_and_from_before_them() {
        let phrase = phrase();
        let Apart {
            one,
            two,
            a3,
            b3,
            b4,
            b5,
        } = apart(&phrase);
        let settled =
            Statement::settle(&a3, &b4, key(1), &secret(9), devices(&[1, 5]), &[]).unwrap();
        for applied in [&a3, &b4, &b3, &two, &one] {
            assert_eq!(
                judged(&phrase, &settled, applied, 1),
                Ok(Judgement::Applies),
                "{}",
                applied.number
            );
            assert_eq!(
                judged(&phrase, &settled, applied, 5),
                Ok(Judgement::Applies)
            );
            // Each branch's removal stands, on both branches.
            assert_eq!(
                judged(&phrase, &settled, applied, 0),
                Ok(Judgement::Removed)
            );
            assert_eq!(
                judged(&phrase, &settled, applied, 2),
                Ok(Judgement::Removed)
            );
        }
        // Both branches are behind it then.
        for shown in [&a3, &b3, &b4, &two] {
            assert_eq!(judged(&phrase, shown, &settled, 1), Ok(Judgement::Behind));
        }
        // A statement made on one branch after the settlement's chain was
        // fixed is apart from it still.
        assert_eq!(judged(&phrase, &b5, &settled, 1), Ok(Judgement::Fork));
        assert_eq!(judged(&phrase, &settled, &b5, 1), Ok(Judgement::Fork));
    }
}
