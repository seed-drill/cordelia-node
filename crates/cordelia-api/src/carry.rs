//! A carry that a person asks for (decision 2026-10-04 §7.3, §7.5, §9).
//!
//! A device that applies a statement carries what it holds, and reads the
//! channels it left no more. What a relay holds of a generation that was
//! left, beyond what the remaining devices had taken, stays where it is:
//! after a removal it is not to be trusted without a person's word. A
//! person gives that word by a command: `cordelia sync carry`, `cordelia
//! sync map` for a name that the device comes to sync, and `cordelia
//! recover`.
//!
//! Such a command has the node read, at each relay, the name's channel in
//! a generation that was left. Nothing here opens a stream: what a relay
//! handed is given to [`read`], which reads it as a device reads a slot,
//! under that generation's statement and with the keys that are to be
//! read; and each version that it gives is given to [`bring`].
//!
//! **[`bring`] is the one function that judges a version for a carry.**
//! Whatever a command brings in, from whichever generation and by
//! whichever key, comes in through it and through nothing else:
//!
//! - A version comes in as **this device's own entry** in the name's
//!   channel of the generation applied, with the version's chain and a
//!   first link for the key that signed it, **at the revision it had**
//!   (or the one that the renumbering gives it, which every device gives
//!   it alike). It is never given another revision to get it in: a
//!   relay's copy can be older than what its writer last wrote, and an
//!   old version moved above a newer one would take its place.
//! - It comes in only where the new channel holds, in that slot,
//!   **neither that version nor an entry at a higher revision.**
//! - **A version that ties with an entry of this device's own** cannot be
//!   carried by this device, which has one entry in a slot. It is left,
//!   and said: another device can bring it.
//! - **What a key that does not count signed comes in only by a rule of
//!   its own** ([`Rule::EmptySlots`], [`Rule::Above`]), which a command
//!   uses only with the recovery phrase: into a slot where the new
//!   channel holds nothing, or, on a second yes that names the file,
//!   above a version that it holds. **A delete that such a key signed is
//!   never taken:** the file that it had deleted comes back.
//!
//! **What a command hands the node on the phrase's word is bound to
//! that word** (decision 2026-10-04 §16). A word names the device, the
//! change entry it keeps, a time after which it is void, and what it
//! allows ([`Word`], [`Allows`]). A word under which versions are handed
//! names a key that the command made for that one run, and each batch is
//! signed by that key over its number and its hash ([`batch_signed`]).
//! **The node takes each word once, and each batch once** ([`take_once`],
//! [`take_batch_once`]): a program that sees a word cross to the node can
//! do nothing with it.
//!
//! Plain functions over the node's database and the device's own key.

use std::collections::BTreeMap;

use rusqlite::Connection;

use cordelia_core::protocol::{
    CARRY_FROM_WORDS, CARRY_WORD_SECS, ENTRY_LINK_HASH_BYTES, ENTRY_LINK_SIGNER_BYTES,
    LABEL_CARRY_BATCH, LABEL_CARRY_WORD,
};
use cordelia_core::revision::{lifted, may_be_under};
use cordelia_crypto::entry::{CheckedEntry, Link, Value};
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::version::{self, Version};
use cordelia_crypto::{derive, sha256};
use cordelia_storage::entries::{self, Outcome};
use cordelia_storage::meta;

use crate::person::{PersonError, carried_entry, in_one};
use crate::publish::Standing;

/// What a relay handed of one channel of a generation that was left, as
/// it is read ([`read`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WasRead {
    /// Each slot's current version among the keys that are read, in order
    /// of the slots.
    pub versions: Vec<Version>,
    /// How many entries each key signed there, of every key, read or not,
    /// in order of key: each entry once, however many relays handed it.
    pub signed: Vec<([u8; 32], usize)>,
}

impl WasRead {
    /// How many entries the keys signed there of which `of` says so.
    pub fn signed_by(&self, of: impl Fn(&[u8; 32]) -> bool) -> usize {
        let counted = self.signed.iter().filter(|(key, _)| of(key));
        counted.map(|(_, entries)| entries).sum()
    }
}

/// Read what the relays handed of one channel of a generation that was
/// left (decision 2026-10-04 §7.3): each slot's current version among the
/// keys of which `reads` says that they are read, as a device reads a
/// slot under the statement of that generation ([`version::current`]).
///
/// `entries` is everything that was handed of the channel, by any relay:
/// an entry that was handed twice is read once, and an entry of another
/// channel is dropped. `secret` is the channel's secret in that
/// generation, and `number` the number of the generation's statement.
///
/// **Only an entry that a key which is read signed is looked at.** What
/// another key signed there is nothing here: it is counted, and that is
/// all. So a delete that a removed key signed is not the slot's version,
/// and the text that a key which is read wrote there is.
pub fn read(
    entries: &[CheckedEntry],
    secret: &[u8; 32],
    number: u64,
    reads: impl Fn(&[u8; 32]) -> bool,
) -> Result<WasRead, PersonError> {
    let channel = derive::channel_id(secret)?;
    let mut slots: BTreeMap<[u8; 32], Vec<CheckedEntry>> = BTreeMap::new();
    let mut seen: Vec<[u8; 32]> = Vec::new();
    let mut signed: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for entry in entries.iter().filter(|entry| entry.channel == channel) {
        let id = entry.id();
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        *signed.entry(entry.author).or_default() += 1;
        slots.entry(entry.slot).or_default().push(entry.clone());
    }
    let mut versions = Vec::new();
    for held in slots.values() {
        if let Some(version) = version::current(held, secret, number, &reads)?.current {
            versions.push(version);
        }
    }
    Ok(WasRead {
        versions,
        signed: signed.into_iter().collect(),
    })
}

/// Of several versions, the newest for each name (decision 2026-10-04
/// §7.3, §9): the one at the highest revision, as each crosses into the
/// generation applied ([`lifted`]); at one revision a text beats a
/// delete, and of two texts the one with the higher hash wins, as a tie
/// is decided anywhere. In order of name.
///
/// It is what a carry takes for a slot where it has read the slot in
/// more than one generation, or by more than one key: the newest version
/// among them, judged once.
pub fn newest(versions: Vec<Version>) -> Vec<Version> {
    let rank = |version: &Version| {
        let text = matches!(version.value, Value::Text(_));
        (lifted(version.rev), version.value.hash(), text)
    };
    let mut by_name: BTreeMap<String, Version> = BTreeMap::new();
    for version in versions {
        match by_name.get(&version.name) {
            Some(held) if rank(held) >= rank(&version) => {}
            _ => {
                by_name.insert(version.name.clone(), version);
            }
        }
    }
    by_name.into_values().collect()
}

/// By which rule a version is brought in ([`bring`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// A key that counts signed it: it comes in where the new channel
    /// holds, in that slot, neither that version nor an entry at a
    /// higher revision.
    Counts,
    /// A key that does not count signed it, and a person named that key
    /// with the phrase: it comes in only where the new channel holds
    /// nothing in that slot.
    EmptySlots,
    /// As [`Rule::EmptySlots`], and a second yes named the file: it comes
    /// in above a version that the new channel holds as well.
    Above,
}

/// What became of a version that a carry was to bring in ([`bring`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Brought {
    /// It was carried: it is this device's own entry in the new channel.
    Carried,
    /// The new channel holds that version. Nothing was written.
    Held,
    /// The new channel holds an entry at a higher revision in that slot.
    /// Nothing was written.
    Higher,
    /// It ties with an entry in that slot at its revision: one of this
    /// device's own, which has one entry in a slot; or, for a version
    /// that a key which does not count signed, any entry there. Nothing
    /// was written.
    Tie,
    /// A key that does not count signed it, and it stands above a
    /// version that the new channel holds: it comes in only on a second
    /// yes that names the file. Nothing was written.
    Above,
    /// A key that does not count signed it, and it is a delete: it is
    /// never taken. Nothing was written.
    Delete,
}

/// Judge one version for a carry, and bring it in where it may come
/// (see the module's documentation): `version` was read in the channel of
/// `name` in a generation that was left, and comes into the name's
/// channel of the generation applied, by `rule`.
///
/// It is this device's own entry there, at the revision that the
/// renumbering gives the version, with the version's chain and a first
/// link for the key that signed it ([`carried_entry`]). What the new
/// channel holds is what this device's store holds of it, read with the
/// keys that count.
///
/// Refused: on a device that follows no phrase or has stopped, and for a
/// name that the device does not hold.
pub fn bring(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    version: &Version,
    rule: Rule,
    now: i64,
) -> Result<Brought, PersonError> {
    in_one(conn, || {
        let standing = Standing::to_write(conn)?;
        let secret = standing.name_secret(conn, name)?;
        if let Some(left) = judged(conn, identity, &standing, &secret, version, rule)? {
            return Ok(left);
        }
        let entry = carried_entry(identity, &secret, version)?;
        Ok(match entries::store(conn, &entry, now)? {
            Outcome::Stored => Brought::Carried,
            Outcome::AlreadyHeld => Brought::Tie,
            Outcome::OlderThanHeld => Brought::Higher,
        })
    })
}

/// What [`bring`] would do with `version`, with nothing written: for a
/// command that says what it found before it asks its yes (decision
/// 2026-10-04 §7.3). [`Brought::Carried`] says that the version would be
/// carried.
pub fn would_bring(
    conn: &Connection,
    identity: &NodeIdentity,
    name: &str,
    version: &Version,
    rule: Rule,
) -> Result<Brought, PersonError> {
    let standing = Standing::to_write(conn)?;
    let secret = standing.name_secret(conn, name)?;
    let left = judged(conn, identity, &standing, &secret, version, rule)?;
    Ok(left.unwrap_or(Brought::Carried))
}

/// The one judgement of a version for a carry: why it is left, or `None`
/// where it may be carried into the channel whose secret is `secret`,
/// which is the name's in the generation applied.
fn judged(
    conn: &Connection,
    identity: &NodeIdentity,
    standing: &Standing,
    secret: &[u8; 32],
    version: &Version,
    rule: Rule,
) -> Result<Option<Brought>, PersonError> {
    let rev = lifted(version.rev);
    let of_a_key_that_counts = rule == Rule::Counts;
    if !of_a_key_that_counts && version.value == Value::Delete {
        return Ok(Some(Brought::Delete));
    }
    let slot = standing.slot(conn, secret, &version.name)?;
    let is_it = |held: &Version| held.rev == rev && held.value == version.value;
    if slot.current.iter().chain(&slot.lost).any(is_it) {
        return Ok(Some(Brought::Held));
    }
    match slot.highest {
        Some(highest) if highest > rev => return Ok(Some(Brought::Higher)),
        // An entry at that very revision, which is not this version.
        Some(highest) if highest == rev && !of_a_key_that_counts => {
            return Ok(Some(Brought::Tie));
        }
        Some(_) if rule == Rule::EmptySlots => return Ok(Some(Brought::Above)),
        _ => {}
    }
    // This device has one entry in a slot: where its own is at that
    // revision, the version ties with it, and is not written over it.
    let channel = derive::channel_id(secret)?;
    let slot_of_it = slot_id(&derive::slot_key(secret)?, &version.name);
    let own = entries::author_entry(conn, &channel, &slot_of_it, &identity.public_key())?;
    if own.is_some_and(|own| own.entry.rev == rev) {
        return Ok(Some(Brought::Tie));
    }
    Ok(None)
}

/// How many versions a carry brought in, and how many it left for each
/// reason, as a command says it (decision 2026-10-04 §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct Tally {
    /// Carried: each is this device's own entry in the new channel.
    pub carried: usize,
    /// The new channel held that version already.
    pub held: usize,
    /// Left, because the new channel holds a higher revision in that
    /// slot.
    pub higher: usize,
    /// Left, because it ties with an entry that this device cannot
    /// write over: each by the file's name.
    pub ties: Vec<String>,
    /// Of a key that does not count: left, because it stands above a
    /// version that the new channel holds, each by the file's name. A
    /// second yes brings these in.
    pub above: Vec<String>,
    /// Of a key that does not count: deletes, which are never taken.
    pub deletes: usize,
}

impl Tally {
    /// Count what became of the version of the file called `file`.
    pub fn count(&mut self, file: &str, brought: Brought) {
        match brought {
            Brought::Carried => self.carried += 1,
            Brought::Held => self.held += 1,
            Brought::Higher => self.higher += 1,
            Brought::Tie => self.ties.push(file.to_string()),
            Brought::Above => self.above.push(file.to_string()),
            Brought::Delete => self.deletes += 1,
        }
    }
}

/// What a version that a command read in its own process is handed to the
/// node as (decision 2026-10-04 §7.3): the command holds the secret of a
/// generation that this device never held, which the phrase opened, and
/// the node is handed no secret. It is the version in the clear, with the
/// key that signed the entry it was read from and that entry's chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Handed {
    /// The file's name.
    pub name: String,
    /// The revision it had in the generation it was read in.
    pub rev: u64,
    /// Its text; `None` for a delete.
    pub text: Option<String>,
    /// The key that signed the entry it was read from, in hex.
    pub signer: String,
    /// That entry's chain, each link as the hex of its bytes: `None`
    /// where the entry lacks its chain.
    pub chain: Option<Vec<String>>,
}

impl Handed {
    /// The version, as a command hands it: from one entry of it, this
    /// device's own where it signed one, and otherwise the one whose
    /// signer has the lowest key. `None` for a version that holds
    /// neither a text nor a delete: only those are handed.
    pub fn of(version: &Version, own: &[u8; 32]) -> Option<Self> {
        let from = version
            .entries
            .iter()
            .find(|entry| entry.author == *own)
            .or(version.entries.first())?;
        let text = match &version.value {
            Value::Text(text) => Some(text.clone()),
            Value::Delete => None,
            Value::Other(_) => return None,
        };
        Some(Self {
            name: version.name.clone(),
            rev: version.rev,
            text,
            signer: hex::encode(from.author),
            chain: from
                .chain
                .as_ref()
                .map(|chain| chain.iter().map(link_written).collect()),
        })
    }

    /// Whether the version may be an entry under the statement numbered
    /// `number`, which is the one applied: its revision, as it is once it
    /// has crossed into that generation ([`lifted`]), is one that an
    /// entry may have there ([`may_be_under`], decision 2026-10-04 §2.3).
    /// **A version that is handed at any other revision is refused:** the
    /// node did not read it, and takes its revision as it is written.
    pub fn may_be_under(&self, number: u64) -> bool {
        may_be_under(lifted(self.rev), number)
    }

    /// The version that was handed, as [`bring`] takes one. Refused where
    /// a key or a link is not one.
    pub fn version(&self) -> Result<Version, PersonError> {
        use cordelia_crypto::version::VersionEntry;
        let not = |what: &str| PersonError::Held(format!("a version that was handed: {what}"));
        let signer: [u8; 32] = hex::decode(&self.signer)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| not("its signer is no key"))?;
        let chain = match &self.chain {
            None => None,
            Some(links) => Some(
                links
                    .iter()
                    .map(|link| link_read(link))
                    .collect::<Option<Vec<Link>>>()
                    .ok_or_else(|| not("a link of its chain is none"))?,
            ),
        };
        let value = match &self.text {
            Some(text) => Value::Text(text.clone()),
            None => Value::Delete,
        };
        // What it is named by: the version itself, since the entry it
        // was read from is not handed.
        let mut named = Vec::new();
        named.extend_from_slice(&self.rev.to_be_bytes());
        named.extend_from_slice(self.name.as_bytes());
        named.extend_from_slice(&signer);
        Ok(Version {
            rev: self.rev,
            name: self.name.clone(),
            value,
            entries: vec![VersionEntry {
                id: sha256(&named),
                author: signer,
                chain,
            }],
        })
    }
}

// ── A person's word, given with the phrase ───────────────────────────

/// A person's word for a carry, given with the recovery phrase (decision
/// 2026-10-04 §7.3, §9): what may be taken that keys which do not count
/// signed, or that a command read in its own process, signed by the
/// phrase's key under a label of its own.
///
/// **It is what stands between the node's token and what a removed key
/// signed.** A program that holds the token can ask the node anything;
/// it cannot make this, since the node holds no phrase. The word is
/// bound to this device, to the change entry that the device keeps when
/// it is given (a later change ends it), and to a time: it stands for
/// ten minutes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Word {
    /// What it allows, as the text that was signed: whoever reads it
    /// reads these very bytes.
    pub what: String,
    /// Until when it stands, in seconds.
    pub until: i64,
    /// The signature of the phrase's key, in hex.
    pub signature: String,
}

impl Word {
    /// Give the word for `what`, with the phrase, on the device whose key
    /// is `device`, which keeps the change entry named `under`, at `now`.
    pub fn give(
        phrase: &cordelia_crypto::phrase::Phrase,
        device: &[u8; 32],
        under: &[u8; 32],
        what: String,
        now: i64,
    ) -> Result<Self, PersonError> {
        let until = now.saturating_add(CARRY_WORD_SECS);
        let signature = phrase
            .signing_key()?
            .sign(&word_signed(device, under, until, &what));
        Ok(Self {
            what,
            until,
            signature: hex::encode(signature),
        })
    }

    /// Whether the word holds at `now`: the key `phrase_key` signed it,
    /// for the device whose key is `device` and under the change entry
    /// named `under`, and its time has not gone by.
    pub fn holds(
        &self,
        phrase_key: &[u8; 32],
        device: &[u8; 32],
        under: &[u8; 32],
        now: i64,
    ) -> bool {
        let signature: Option<[u8; 64]> = hex::decode(&self.signature)
            .ok()
            .and_then(|bytes| bytes.try_into().ok());
        let Some(signature) = signature else {
            return false;
        };
        let stands = now <= self.until && self.until <= now.saturating_add(CARRY_WORD_SECS);
        stands
            && cordelia_crypto::identity::verify_signature(
                phrase_key,
                &word_signed(device, under, self.until, &self.what),
                &signature,
            )
    }
}

/// What a person's word allows ([`Word`]), as the text that is signed.
/// The node reads what it is to do from the signed text itself, and from
/// nothing beside it: a request that carried the same things apart could
/// say another thing than the phrase signed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Allows {
    /// `cordelia sync carry <name> --from`: what the removed keys in
    /// `keys` signed in the channel of `name`, in the generations that
    /// this device left, comes into slots where the new channel holds
    /// nothing; and, for each file in `above`, which a second yes named,
    /// above the version that the new channel holds. Each key in hex.
    From {
        name: String,
        keys: Vec<String>,
        above: Vec<String>,
    },
    /// `cordelia sync carry <name> --phrase`: what the command read of
    /// the channel of `name`, in generations whose secret this device
    /// never held and the phrase opened, comes in as a carry by command
    /// does, where a key that counts signed it. `run` is the public half
    /// of a key that the command made for this one run, in hex: each
    /// batch of versions handed under the word is signed by it
    /// ([`batch_signed`]).
    Handed { name: String, run: String },
    /// `cordelia recover`: the look, made once. The names that are
    /// carried, in their order, and the keys that it takes from, each in
    /// hex: the devices that the person still has, and those that are
    /// lost or broken.
    Look {
        names: Vec<String>,
        takes: Vec<String>,
    },
}

impl Allows {
    /// The text that the phrase signs for it.
    pub fn says(&self) -> Result<String, PersonError> {
        serde_json::to_string(self)
            .map_err(|e| PersonError::Held(format!("what a word allows: {e}")))
    }

    /// What `word` allows, read from the text that was signed: `None`
    /// where that text is none of these.
    pub fn of(word: &Word) -> Option<Self> {
        serde_json::from_str(&word.what).ok()
    }
}

/// A key in hex, as a word names one: `None` where it is none.
pub fn key_named(written: &str) -> Option<[u8; 32]> {
    hex::decode(written).ok()?.try_into().ok()
}

/// What the phrase's key signs for a word: its label, the device's key,
/// what the change entry is named by, until when, and the hash of what
/// it allows.
fn word_signed(device: &[u8; 32], under: &[u8; 32], until: i64, what: &str) -> Vec<u8> {
    let mut signed = Vec::with_capacity(LABEL_CARRY_WORD.len() + 32 + 32 + 8 + 32);
    signed.extend_from_slice(LABEL_CARRY_WORD);
    signed.extend_from_slice(device);
    signed.extend_from_slice(under);
    signed.extend_from_slice(&until.to_be_bytes());
    signed.extend_from_slice(&sha256(what.as_bytes()));
    signed
}

// ── A word is taken once, and so is each batch under one ─────────────

/// What the key of a run signs for one batch of versions that the
/// command hands the node under its word (decision 2026-10-04 §16): the
/// label, the batch's number, and the hash of the versions as they are
/// handed.
pub fn batch_signed(number: u64, versions: &[Handed]) -> Result<Vec<u8>, PersonError> {
    let handed = serde_json::to_vec(versions)
        .map_err(|e| PersonError::Held(format!("a batch of versions: {e}")))?;
    let mut signed = Vec::with_capacity(LABEL_CARRY_BATCH.len() + 8 + 32);
    signed.extend_from_slice(LABEL_CARRY_BATCH);
    signed.extend_from_slice(&number.to_be_bytes());
    signed.extend_from_slice(&sha256(&handed));
    Ok(signed)
}

/// Whether the key `run`, which a word names as the key of its run,
/// signed the batch numbered `number` that holds `versions`: `signature`
/// is in hex.
pub fn batch_holds(run: &[u8; 32], number: u64, versions: &[Handed], signature: &str) -> bool {
    let signature: Option<[u8; 64]> = hex::decode(signature)
        .ok()
        .and_then(|bytes| bytes.try_into().ok());
    let (Some(signature), Ok(signed)) = (signature, batch_signed(number, versions)) else {
        return false;
    };
    cordelia_crypto::identity::verify_signature(run, &signed, &signature)
}

/// What is said where a word was taken before.
pub const WORD_TAKEN: &str = "that word of the recovery phrase was taken before: a word is taken \
    once. Nothing was taken. Run the command again: it asks for the phrase again";

/// What is said where a batch was taken before under its word.
pub const BATCH_TAKEN: &str = "that batch of versions was taken before under this word of the \
    recovery phrase: each is taken once. Nothing was taken";

/// What is said where the key that a word names for its run did not sign
/// a batch.
pub const BATCH_NOT_SIGNED: &str = "that batch of versions is not signed by the key that the \
    word of the recovery phrase names for its run. Nothing was taken";

/// What is said where a version is handed at a revision that no entry
/// may have under the statement applied.
pub const REVISION_MAY_NOT_BE: &str = "a version was handed at a revision that no entry may have \
    under the change that this device has applied. Nothing was taken";

/// A word that this device has taken, for as long as the word stands.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TakenWord {
    /// The word's signature, in hex, as its bytes are written.
    word: String,
    /// Until when the word stands, in seconds: it is kept until then.
    until: i64,
    /// The numbers of the batches that were taken under it.
    #[serde(default)]
    batches: Vec<u64>,
}

/// What a word is kept by: its signature, in hex as its bytes are
/// written, whatever case it was handed in. `None` where it is none.
fn kept_by(word: &Word) -> Option<String> {
    let signature: [u8; 64] = hex::decode(&word.signature).ok()?.try_into().ok()?;
    Some(hex::encode(signature))
}

/// The words that this device has taken and that are not void at `now`.
fn taken_words(conn: &Connection, now: i64) -> Result<Vec<TakenWord>, PersonError> {
    let kept: Vec<TakenWord> = meta::get(conn, meta::PERSON_WORDS_TAKEN)?
        .and_then(|kept| serde_json::from_str(&kept).ok())
        .unwrap_or_default();
    Ok(kept.into_iter().filter(|one| one.until >= now).collect())
}

/// Keep `words` as the words that this device has taken.
fn keep_taken(conn: &Connection, words: &[TakenWord]) -> Result<(), PersonError> {
    if words.is_empty() {
        meta::remove(conn, meta::PERSON_WORDS_TAKEN)?;
        return Ok(());
    }
    let kept = serde_json::to_string(words)
        .map_err(|e| PersonError::Held(format!("the words that were taken: {e}")))?;
    meta::set(conn, meta::PERSON_WORDS_TAKEN, &kept)?;
    Ok(())
}

/// Whether `word` was taken before, and stands still.
pub fn is_taken(conn: &Connection, word: &Word, now: i64) -> Result<bool, PersonError> {
    let by = kept_by(word);
    let taken = taken_words(conn, now)?;
    Ok(taken.iter().any(|one| Some(&one.word) == by.as_ref()))
}

/// Take `word`, at `now`: **a word is taken once** (decision 2026-10-04
/// §16). The node keeps its signature until the word is void. Whoever
/// calls this has asked whether the word holds ([`Word::holds`]), and
/// does what the word allows in the same transaction: where that fails,
/// the word is not taken.
///
/// Refused where the word was taken before.
pub fn take_once(conn: &Connection, word: &Word, now: i64) -> Result<(), PersonError> {
    in_one(conn, || {
        let by = kept_by(word).ok_or(PersonError::NoWord)?;
        let mut taken = taken_words(conn, now)?;
        if taken.iter().any(|one| one.word == by) {
            return Err(PersonError::NotCarried(format!("{WORD_TAKEN}.")));
        }
        taken.push(TakenWord {
            word: by,
            until: word.until,
            batches: Vec::new(),
        });
        keep_taken(conn, &taken)
    })
}

/// Take the batch numbered `number` under `word`, at `now`: **each
/// number is taken once under a word** (decision 2026-10-04 §16).
/// Whoever calls this has asked whether the word holds, and whether the
/// key that it names for its run signed the batch ([`batch_holds`]).
///
/// Refused where a batch of that number was taken before under the word.
pub fn take_batch_once(
    conn: &Connection,
    word: &Word,
    number: u64,
    now: i64,
) -> Result<(), PersonError> {
    in_one(conn, || {
        let by = kept_by(word).ok_or(PersonError::NoWord)?;
        let mut taken = taken_words(conn, now)?;
        if !taken.iter().any(|one| one.word == by) {
            taken.push(TakenWord {
                word: by.clone(),
                until: word.until,
                batches: Vec::new(),
            });
        }
        let Some(of_it) = taken.iter_mut().find(|one| one.word == by) else {
            return Err(PersonError::NoWord);
        };
        if of_it.batches.contains(&number) {
            return Err(PersonError::NotCarried(format!("{BATCH_TAKEN}.")));
        }
        of_it.batches.push(number);
        keep_taken(conn, &taken)
    })
}

// ── Naming a removed key ─────────────────────────────────────────────

/// A removed key, as a person names one at `cordelia sync carry --from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    pub key: [u8; 32],
    /// What this device called it, where it knew it by a label: a
    /// statement lists removed keys bare.
    pub label: String,
}

/// The first words of the fingerprint of `key` that name a removed key:
/// six of them.
pub fn naming_words(key: &[u8; 32]) -> String {
    cordelia_crypto::fingerprint::words(key, CARRY_FROM_WORDS)
}

/// The removed key that `named` names, among `removed` (decision
/// 2026-10-04 §7.3): by the label that this device knew it by; by the
/// first six words of its key's fingerprint, however the words are
/// spaced and in either case; or **by the key itself, written whole**
/// (`cordelia_pk1...`).
///
/// **Refused where a label, or the words, match two removed keys,** and
/// where they match none. A removed key can go by a label that is another
/// key's six words, and those words then name two keys for good: a key
/// written whole is taken for that key and for nothing else, whatever a
/// key is labelled, so it always names one. `cordelia sync carry <name>
/// --from` with no key lists each removed key that signed there.
pub fn named_key(named: &str, removed: &[Removed]) -> Result<[u8; 32], String> {
    let tidy = |said: &str| -> String {
        let words: Vec<String> = said.split_whitespace().map(str::to_lowercase).collect();
        words.join(" ")
    };
    let asked = tidy(named);
    let names = |one: &&Removed| -> bool {
        // What is a key, written whole, names that key alone: it is no
        // label, and no words.
        match cordelia_crypto::bech32::decode_public_key(named.trim()) {
            Ok(key) => one.key == key,
            Err(_) => {
                naming_words(&one.key) == asked || (!one.label.is_empty() && one.label == named)
            }
        }
    };
    let mut matched: Vec<[u8; 32]> = removed.iter().filter(names).map(|one| one.key).collect();
    matched.sort_unstable();
    matched.dedup();
    match matched.as_slice() {
        [only] => Ok(*only),
        [] => Err(format!(
            "{named:?} names no removed key that this device knows of: give its label, the \
             first {CARRY_FROM_WORDS} words of its key's fingerprint, or its key written whole. \
             `--from` with no key lists the removed keys that signed there."
        )),
        _ => Err(format!(
            "{named:?} names {} removed keys: name the one that is meant by its key, written \
             whole. `--from` with no key lists the removed keys that signed there, and \
             `cordelia devices` shows each removed key with its key.",
            matched.len()
        )),
    }
}

/// Whether the first six words of the fingerprint of `key` name it among
/// `removed`, and no other key (decision 2026-10-04 §7.3). They do not
/// where another removed key goes by those words as its label: a command
/// then names the key written whole.
pub fn words_tell(key: &[u8; 32], removed: &[Removed]) -> bool {
    named_key(&naming_words(key), removed) == Ok(*key)
}

/// A link of a chain as it is handed: the hex of its hash and then of the
/// signer it names.
fn link_written(link: &Link) -> String {
    format!("{}{}", hex::encode(link.hash), hex::encode(link.signer))
}

/// A link that was handed, read: `None` where it is not one.
fn link_read(written: &str) -> Option<Link> {
    let bytes = hex::decode(written).ok()?;
    if bytes.len() != ENTRY_LINK_HASH_BYTES + ENTRY_LINK_SIGNER_BYTES {
        return None;
    }
    let (hash, signer) = bytes.split_at(ENTRY_LINK_HASH_BYTES);
    Some(Link {
        hash: hash.try_into().ok()?,
        signer: signer.try_into().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use cordelia_core::protocol::{REV_BAND_HALF, REV_COUNT_BITS};
    use cordelia_storage::person::State;

    use crate::several::{Machine, Several, entry_by, text};

    const LAB: &str = "lab";
    const FILE: &str = "notes.md";

    /// The revision at `count` in `band`.
    fn at(band: u64, count: u64) -> u64 {
        (band << REV_COUNT_BITS) + count
    }

    /// Three devices that hold the name, with one file that device 0
    /// wrote and each has taken.
    fn three() -> Several {
        let mut s = Several::of_one_person(3);
        s.hold(&[0, 1, 2], LAB);
        s.write(0, LAB, FILE, "first");
        s.meet(&[0, 1, 2]);
        s
    }

    /// What was read of `entries` in the channel whose secret is `old`,
    /// of the generation numbered `number`, with the keys that count for
    /// device `n` now.
    fn read_on(
        s: &Several,
        n: usize,
        entries: &[CheckedEntry],
        old: &[u8; 32],
        number: u64,
    ) -> WasRead {
        read(entries, old, number, |key| s[n].counts(key)).unwrap()
    }

    fn bring_on(s: &mut Several, n: usize, version: &Version, rule: Rule) -> Brought {
        let now = s.tick();
        bring(&s[n].conn, &s[n].identity, LAB, version, rule, now).unwrap()
    }

    /// What a device that never returned had sent to the relays is
    /// brought in by a carry that a person asks for (decision 2026-10-04
    /// §7.3): each version as this device's own entry, at the revision it
    /// had, with a first link for the key that signed it. Brought again,
    /// the new channel holds it, and nothing is written.
    #[test]
    fn test_a_carry_by_command_brings_in_what_a_device_that_never_returned_had_sent() {
        let mut s = three();
        // Device 2 edits, and only the relays are sent it.
        let old = s[2].own(LAB);
        s.write(2, LAB, FILE, "late");
        s.write(2, LAB, "only-there.md", "new");
        let at_the_relays = s[2].stored_in(&old);
        // A change is made, and device 2 never returns: it still counts.
        s.change(0, &[0, 1, 2], &[]);
        assert_eq!(s[0].text(LAB, FILE).as_deref(), Some("first"));
        assert_eq!(s[0].text(LAB, "only-there.md"), None);

        let was = read_on(&s, 0, &at_the_relays, &old, 1);
        assert_eq!(was.versions.len(), 2);
        assert_eq!(was.signed_by(|key| !s[0].counts(key)), 0);
        let mut tally = Tally::default();
        for version in &was.versions {
            let brought = bring_on(&mut s, 0, version, Rule::Counts);
            tally.count(&version.name, brought);
        }
        assert_eq!((tally.carried, tally.held, tally.higher), (2, 0, 0));
        assert_eq!(s[0].text(LAB, FILE).as_deref(), Some("late"));
        assert_eq!(s[0].text(LAB, "only-there.md").as_deref(), Some("new"));

        // It is this device's own entry, at the revision the version
        // had, with a first link for the key that signed it.
        let slot = s[0].slot(LAB, FILE);
        let current = slot.current.unwrap();
        assert_eq!(current.rev, 2);
        assert_eq!(current.entries.len(), 1);
        assert_eq!(current.entries[0].author, s.key(0));
        let chain = current.entries[0].chain.clone().unwrap();
        assert_eq!(chain[0], Link::of(&text("late"), s.key(2)));
        // And the version that it was written over stands behind that.
        assert_eq!(chain[1], Link::of(&text("first"), s.key(0)));

        // Brought again: the new channel holds each, and nothing is
        // written.
        let before = s[0].stored().len();
        for version in &was.versions {
            assert_eq!(bring_on(&mut s, 0, version, Rule::Counts), Brought::Held);
        }
        assert_eq!(s[0].stored().len(), before);
    }

    /// A version is never given another revision to get it in (decision
    /// 2026-10-04 §7.3): where the new channel holds an entry at a higher
    /// revision in that slot, it is left, and nothing is written. A
    /// relay's copy can be older than what its writer last wrote.
    #[test]
    fn test_a_carry_never_moves_a_version_to_another_revision() {
        let mut s = three();
        let old = s[2].own(LAB);
        s.write(2, LAB, FILE, "late");
        let at_the_relays = s[2].stored_in(&old);
        s.change(0, &[0, 1, 2], &[]);
        // Device 1 has edited the file twice since, in the new channel,
        // and device 0 has taken that: the entry at the higher revision
        // is another device's, and device 0's own is the one it carried.
        s.pass(0, 1);
        s.write(1, LAB, FILE, "newer");
        s.write(1, LAB, FILE, "newest");
        s.pass(1, 0);
        let slot = s[0].slot(LAB, FILE);
        assert_eq!(slot.current.unwrap().rev, 3);
        assert_eq!(slot.highest, Some(3));

        let was = read_on(&s, 0, &at_the_relays, &old, 1);
        assert_eq!(was.versions[0].rev, 2);
        let before = s[0].stored();
        assert_eq!(
            bring_on(&mut s, 0, &was.versions[0], Rule::Counts),
            Brought::Higher
        );
        assert_eq!(s[0].stored(), before);
        assert_eq!(s[0].text(LAB, FILE).as_deref(), Some("newest"));

        // Where the entry at the higher revision is this device's own,
        // the same: it comes in at its own revision, or not at all.
        s.write(0, LAB, FILE, "the last");
        assert_eq!(s[0].slot(LAB, FILE).current.unwrap().rev, 4);
        let before = s[0].stored();
        assert_eq!(
            bring_on(&mut s, 0, &was.versions[0], Rule::Counts),
            Brought::Higher
        );
        let fourth = Version {
            rev: 4,
            ..was.versions[0].clone()
        };
        assert_eq!(bring_on(&mut s, 0, &fourth, Rule::Counts), Brought::Tie);
        assert_eq!(s[0].stored(), before);
        assert_eq!(s[0].text(LAB, FILE).as_deref(), Some("the last"));
    }

    /// A version that ties with an entry of this device's own cannot be
    /// carried by this device, which has one entry in a slot (decision
    /// 2026-10-04 §7.3): it is left, and said. Where the entry at that
    /// revision is another device's, this device carries the version, and
    /// the tie is decided by the text, as any tie is.
    #[test]
    fn test_a_version_that_ties_with_this_devices_own_entry_is_left_and_said() {
        let mut s = three();
        let old = s[2].own(LAB);
        // Device 0 and device 2 each edit before they have met.
        s.write(0, LAB, FILE, "of device 0");
        s.write(2, LAB, FILE, "of device 2");
        let at_the_relays = s[2].stored_in(&old);
        s.change(0, &[0, 1, 2], &[]);
        // Device 0 carried its own edit: its own entry is at revision 2.
        let was = read_on(&s, 0, &at_the_relays, &old, 1);
        let version = &was.versions[0];
        assert_eq!((version.rev, &version.value), (2, &text("of device 2")));
        let before = s[0].stored();
        let brought = bring_on(&mut s, 0, version, Rule::Counts);
        assert_eq!(brought, Brought::Tie);
        assert_eq!(s[0].stored(), before);
        let mut tally = Tally::default();
        tally.count(&version.name, brought);
        assert_eq!(tally.ties, [FILE]);

        // Device 1 took nothing of either edit, and its own entry is at
        // revision 1: it can bring the version. It then holds a tie of
        // two devices' entries at revision 2, which the text decides.
        let change = s[0].latest();
        let now = s.tick();
        crate::take::take(&s[1].conn, &s[1].identity, &change, now).unwrap();
        assert_eq!(bring_on(&mut s, 1, version, Rule::Counts), Brought::Carried);
        s.pass(0, 1);
        let slot = s[1].slot(LAB, FILE);
        assert_eq!(slot.current.as_ref().unwrap().rev, 2);
        assert_eq!(slot.lost.len(), 1);
    }

    /// A delete that a removed key signed is not taken, and the file
    /// comes back (decision 2026-10-04 §7.3): only what keys that count
    /// signed is read, so the slot's version is the text that a device of
    /// the person's wrote there. What the removed key signed is counted,
    /// and that is all.
    #[test]
    fn test_a_delete_that_a_removed_key_signed_is_not_taken_and_the_file_comes_back() {
        let mut s = Several::of_one_person(3);
        // A name that only devices 1 and 2 sync.
        s.hold(&[1, 2], LAB);
        let old = s[1].own(LAB);
        s.write(1, LAB, FILE, "kept");
        s.pass(1, 2);
        // Device 2 deletes it, and the relays are sent the delete.
        let now = s.tick();
        let deleted = entry_by(&s[2].identity, &old, 2, FILE, Value::Delete, &[]);
        cordelia_storage::entries::store(&s[2].conn, &deleted, now).unwrap();
        let mut at_the_relays = s[1].stored_in(&old);
        at_the_relays.push(deleted);
        // Device 2 is removed, on device 0, which comes to hold the name.
        s.change(0, &[0, 1], &[2]);
        s.hold(&[0], LAB);

        let was = read_on(&s, 0, &at_the_relays, &old, 1);
        assert_eq!(was.versions.len(), 1);
        assert_eq!(was.versions[0].value, text("kept"));
        assert_eq!(was.signed_by(|key| !s[0].counts(key)), 1);
        let mut signed = vec![(s.key(1), 1), (s.key(2), 1)];
        signed.sort();
        assert_eq!(was.signed, signed);
        assert_eq!(
            bring_on(&mut s, 0, &was.versions[0], Rule::Counts),
            Brought::Carried
        );
        assert_eq!(s[0].text(LAB, FILE).as_deref(), Some("kept"));

        // Read with the removed key named, its delete is the version at
        // the highest revision there; and it is never taken, by either
        // rule for a key that does not count.
        let removed = s.key(2);
        let of_the_removed = read(&at_the_relays, &old, 1, |key| *key == removed).unwrap();
        assert_eq!(of_the_removed.versions[0].value, Value::Delete);
        for rule in [Rule::EmptySlots, Rule::Above] {
            let before = s[0].stored();
            let brought = bring_on(&mut s, 0, &of_the_removed.versions[0], rule);
            assert_eq!(brought, Brought::Delete);
            assert_eq!(s[0].stored(), before);
        }
    }

    /// What a key that does not count signed comes in only into a slot
    /// where the new channel holds nothing; above a version that it
    /// holds, only by the rule of a second yes; and never over an entry
    /// at that revision or a higher one (decision 2026-10-04 §7.3).
    #[test]
    fn test_what_a_removed_key_signed_comes_in_only_into_an_empty_slot_without_a_second_yes() {
        let mut s = three();
        let old = s[2].own(LAB);
        // The device that will be removed writes over the file, and
        // writes two that no other device takes.
        s.write(2, LAB, FILE, "over it");
        s.write(2, LAB, "empty.md", "into an empty slot");
        let at_the_relays = s[2].stored_in(&old);
        s.change(0, &[0, 1], &[2]);
        let removed = s.key(2);
        assert!(!s[0].counts(&removed));

        // Its versions are no versions to a carry of the keys that count.
        let counting = read_on(&s, 0, &at_the_relays, &old, 1);
        let of_those: Vec<&str> = counting.versions.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(of_those, [FILE]);
        assert_eq!(counting.versions[0].value, text("first"));

        let named = read(&at_the_relays, &old, 1, |key| *key == removed).unwrap();
        let version = |file: &str| -> Version {
            let found = named.versions.iter().find(|version| version.name == file);
            found.unwrap().clone()
        };
        // Into the empty slot: carried, as this device's own entry, with
        // a first link for the removed key.
        assert_eq!(
            bring_on(&mut s, 0, &version("empty.md"), Rule::EmptySlots),
            Brought::Carried
        );
        let current = s[0].slot(LAB, "empty.md");
        assert_eq!(
            current.current.as_ref().unwrap().entries[0].author,
            s.key(0)
        );
        let chain = current.current.unwrap().entries[0].chain.clone().unwrap();
        assert_eq!(chain[0], Link::of(&text("into an empty slot"), removed));
        // Above a version that the new channel holds: left without the
        // second yes, with nothing written; and carried with it.
        let before = s[0].stored();
        assert_eq!(
            bring_on(&mut s, 0, &version(FILE), Rule::EmptySlots),
            Brought::Above
        );
        assert_eq!(s[0].stored(), before);
        assert_eq!(s[0].text(LAB, FILE).as_deref(), Some("first"));
        assert_eq!(
            bring_on(&mut s, 0, &version(FILE), Rule::Above),
            Brought::Carried
        );
        assert_eq!(s[0].text(LAB, FILE).as_deref(), Some("over it"));
        // A folder that holds "first" is not told that this follows it:
        // the link ahead of it is a key's that does not count.
        assert!(!s[0].follows(LAB, FILE, "first"));

        // At the revision of an entry that the new channel holds, and
        // below one: never, by either rule.
        s.write(0, LAB, "held.md", "of device 0");
        let tied = Version {
            name: "held.md".into(),
            rev: 1,
            ..version(FILE)
        };
        let below = Version {
            name: FILE.into(),
            rev: 1,
            ..version(FILE)
        };
        for rule in [Rule::EmptySlots, Rule::Above] {
            let before = s[0].stored();
            assert_eq!(bring_on(&mut s, 0, &tied, rule), Brought::Tie);
            assert_eq!(bring_on(&mut s, 0, &below, rule), Brought::Higher);
            assert_eq!(s[0].stored(), before);
        }
    }

    /// Of several versions of one file, read in more than one generation
    /// or by more than one key, a carry takes the newest (decision
    /// 2026-10-04 §7.3, §9): the highest revision as each crosses into
    /// the generation applied; at one revision a text beats a delete, and
    /// of two texts the one with the higher hash wins.
    #[test]
    fn test_of_several_versions_of_a_file_the_newest_is_taken() {
        let version = |name: &str, rev: u64, value: Value| Version {
            rev,
            name: name.into(),
            value,
            entries: Vec::new(),
        };
        let (one, other) = ("one", "another");
        let higher = match sha256(one.as_bytes()) > sha256(other.as_bytes()) {
            true => one,
            false => other,
        };
        let taken = newest(vec![
            version("a.md", 2, text("older")),
            version("a.md", 5, text("newer")),
            version("a.md", 4, text("between")),
            version("b.md", 3, Value::Delete),
            version("b.md", 3, text("beats a delete")),
            version("c.md", 7, text(one)),
            version("c.md", 7, text(other)),
            // A revision in the top half of a band crosses into the
            // next: it is above one in the bottom half of its own.
            version("d.md", at(1, REV_BAND_HALF + 1), text("lifted")),
            version("d.md", at(1, 9), text("not lifted")),
        ]);
        let said: Vec<(&str, &Value)> = taken
            .iter()
            .map(|version| (version.name.as_str(), &version.value))
            .collect();
        assert_eq!(
            said,
            [
                ("a.md", &text("newer")),
                ("b.md", &text("beats a delete")),
                ("c.md", &text(higher)),
                ("d.md", &text("lifted")),
            ]
        );
        // In whichever order they are given.
        let turned = newest(vec![
            version("a.md", 5, text("newer")),
            version("a.md", 2, text("older")),
            version("b.md", 3, text("beats a delete")),
            version("b.md", 3, Value::Delete),
        ]);
        assert_eq!(turned[0].value, text("newer"));
        assert_eq!(turned[1].value, text("beats a delete"));
        assert!(newest(Vec::new()).is_empty());
    }

    /// What the relays handed is read as a device reads a slot, under the
    /// statement of that generation (decision 2026-10-04 §7.3): an entry
    /// of another channel is dropped, one that two relays handed is read
    /// once, and one in a band above the generation's is no version.
    #[test]
    fn test_what_the_relays_handed_is_read_under_its_own_generation() {
        let mut s = three();
        let old = s[2].own(LAB);
        let other_channel = s[2].own("another");
        s.write(2, LAB, FILE, "late");
        let mut handed = s[2].stored_in(&old);
        // The same entries again, as a second relay hands them.
        handed.extend(s[2].stored_in(&old));
        // An entry of another channel, and one in a band above.
        handed.push(entry_by(
            &s[2].identity,
            &other_channel,
            9,
            FILE,
            text("elsewhere"),
            &[],
        ));
        handed.push(entry_by(
            &s[1].identity,
            &old,
            at(2, 1),
            FILE,
            text("above"),
            &[],
        ));
        let was = read_on(&s, 0, &handed, &old, 1);
        assert_eq!(was.versions.len(), 1);
        assert_eq!(was.versions[0].value, text("late"));
        // Each entry of the channel is counted once for its signer.
        assert_eq!(was.signed, {
            let mut signed = vec![(s.key(0), 1), (s.key(1), 1), (s.key(2), 1)];
            signed.sort();
            signed
        });
        // Read under the generation after, the entry in its band is a
        // version: a channel is read under its own statement.
        let under_two = read(&handed, &old, 2, |_| true).unwrap();
        assert_eq!(under_two.versions[0].value, text("above"));
        // A secret that is no channel's of these reads nothing.
        assert_eq!(
            read_on(&s, 0, &handed, &s[0].personal(), 1),
            WasRead::default()
        );
    }

    /// A version that crosses a statement in the top half of a band comes
    /// in at the revision that the renumbering gives it, which every
    /// device gives it alike (decision 2026-10-04 §2.3, §7.3).
    #[test]
    fn test_a_version_is_brought_in_at_the_revision_that_the_renumbering_gives_it() {
        let mut s = three();
        let old = s[2].own(LAB);
        let jumped = at(1, REV_BAND_HALF + 4);
        let entry = entry_by(
            &s[2].identity,
            &old,
            jumped,
            "jumped.md",
            text("up there"),
            &[],
        );
        s.change(0, &[0, 1, 2], &[]);
        let was = read_on(&s, 0, &[entry], &old, 1);
        assert_eq!(
            bring_on(&mut s, 0, &was.versions[0], Rule::Counts),
            Brought::Carried
        );
        let current = s[0].slot(LAB, "jumped.md").current.unwrap();
        assert_eq!(current.rev, at(2, 4));
        assert_eq!(current.rev, lifted(jumped));
        // Brought again, the new channel holds it: it is the version at
        // the revision that the renumbering gave it.
        assert_eq!(
            bring_on(&mut s, 0, &was.versions[0], Rule::Counts),
            Brought::Held
        );
    }

    /// A carry brings nothing in on a device that follows no phrase, on
    /// one that has stopped, or for a name that the device does not hold
    /// (decision 2026-10-04 §4.3, §7.3).
    #[test]
    fn test_a_carry_is_refused_where_the_device_may_not_write() {
        let mut s = three();
        let old = s[2].own(LAB);
        s.write(2, LAB, FILE, "late");
        let at_the_relays = s[2].stored_in(&old);
        s.change(0, &[0, 1], &[2]);
        let was = read(&at_the_relays, &old, 1, |_| true).unwrap();
        let version = &was.versions[0];
        let now = s.tick();
        // Device 2 was removed: shown the change, it has stopped.
        let change = s[0].latest();
        crate::take::take(&s[2].conn, &s[2].identity, &change, now).unwrap();
        assert_eq!(s[2].state(), State::Removed);
        let stopped = bring(&s[2].conn, &s[2].identity, LAB, version, Rule::Counts, now);
        assert!(
            matches!(stopped, Err(PersonError::Stopped(State::Removed))),
            "{stopped:?}"
        );
        // A name that the device does not hold.
        let not_held = bring(
            &s[0].conn,
            &s[0].identity,
            "another",
            version,
            Rule::Counts,
            now,
        );
        assert!(
            matches!(not_held, Err(PersonError::NameNotHeld(_))),
            "{not_held:?}"
        );
        // A device that follows no phrase.
        let alone = Machine::new(9);
        let none = bring(
            &alone.conn,
            &alone.identity,
            LAB,
            version,
            Rule::Counts,
            now,
        );
        assert!(
            matches!(none, Err(PersonError::FollowsNoPhrase)),
            "{none:?}"
        );
    }

    /// A person's word for a carry is the phrase's (decision 2026-10-04
    /// §7.3, §9): it holds for the device it was given on, under the
    /// change entry that the device kept then, for ten minutes, and for
    /// the text that was signed. Another phrase's, another device's, one
    /// given under another change entry, one whose time has gone by or is
    /// set further ahead than a word stands, and one whose text was
    /// changed, do not hold.
    #[test]
    fn test_a_word_holds_only_as_the_phrase_gave_it() {
        use cordelia_crypto::phrase::Phrase;
        let s = three();
        let phrase_key = s.phrase.public_key().unwrap();
        let (device, under) = (s.key(0), s[0].latest().id());
        let allows = Allows::From {
            name: LAB.into(),
            keys: vec![hex::encode(s.key(2))],
            above: vec![FILE.into()],
        };
        let now = 1_000;
        let word = Word::give(&s.phrase, &device, &under, allows.says().unwrap(), now).unwrap();
        assert_eq!(word.until, now + CARRY_WORD_SECS);
        assert!(word.holds(&phrase_key, &device, &under, now));
        assert!(word.holds(&phrase_key, &device, &under, now + CARRY_WORD_SECS));
        assert_eq!(Allows::of(&word), Some(allows.clone()));
        // It travels as JSON, and holds there.
        let over: Word = serde_json::from_str(&serde_json::to_string(&word).unwrap()).unwrap();
        assert!(over.holds(&phrase_key, &device, &under, now));

        // Its time has gone by.
        assert!(!word.holds(&phrase_key, &device, &under, now + CARRY_WORD_SECS + 1));
        // Another device, and another change entry.
        assert!(!word.holds(&phrase_key, &s.key(1), &under, now));
        assert!(!word.holds(&phrase_key, &device, &[7; 32], now));
        // Another phrase gave it.
        let other = Phrase::parse(crate::several::OTHER_WORDS).unwrap();
        let theirs = Word::give(&other, &device, &under, allows.says().unwrap(), now).unwrap();
        assert!(!theirs.holds(&phrase_key, &device, &under, now));
        // The text was changed after it was signed: the name, a key, a
        // file.
        let changed = Allows::From {
            name: LAB.into(),
            keys: vec![hex::encode(s.key(2)), hex::encode(s.key(1))],
            above: vec![FILE.into()],
        };
        let forged = Word {
            what: changed.says().unwrap(),
            ..word.clone()
        };
        assert!(!forged.holds(&phrase_key, &device, &under, now));
        // A word whose time has gone by, said to stand a little longer:
        // the signature is over the time.
        let stretched = Word {
            until: word.until + 300,
            ..word.clone()
        };
        assert!(!stretched.holds(&phrase_key, &device, &under, now + CARRY_WORD_SECS + 100));
        // A time set further ahead than a word stands: the signature is
        // over the time, and a word that says more than ten minutes is
        // none, whoever signed it.
        let later = Word {
            until: word.until + 60,
            ..word.clone()
        };
        assert!(!later.holds(&phrase_key, &device, &under, now + 30));
        let far = Word::give(
            &s.phrase,
            &device,
            &under,
            allows.says().unwrap(),
            now + 3_600,
        )
        .unwrap();
        assert!(!far.holds(&phrase_key, &device, &under, now));
        // A signature that is none.
        let none = Word {
            signature: "zz".into(),
            ..word.clone()
        };
        assert!(!none.holds(&phrase_key, &device, &under, now));
        // What a word allows that is none of the things a word allows.
        let odd = Word {
            what: "{\"anything\":1}".into(),
            ..word
        };
        assert_eq!(Allows::of(&odd), None);
    }

    /// A removed key is named by the label that this device knew it by,
    /// or by the first six words of its key's fingerprint (decision
    /// 2026-10-04 §7.3). Where a label, or the words, match two removed
    /// keys, or none, it is refused.
    #[test]
    fn test_a_removed_key_is_named_by_its_label_or_by_six_words() {
        let s = three();
        let removed = vec![
            Removed {
                key: s.key(0),
                label: "laptop".into(),
            },
            Removed {
                key: s.key(1),
                label: "desktop".into(),
            },
            // A key that this device never knew by a label, and one that
            // goes by a label another has.
            Removed {
                key: s.key(2),
                label: String::new(),
            },
            Removed {
                key: [9; 32],
                label: "desktop".into(),
            },
        ];
        assert_eq!(named_key("laptop", &removed), Ok(s.key(0)));
        // By its words: six of them, however they are spaced, in either
        // case.
        let words = naming_words(&s.key(2));
        assert_eq!(words.split(' ').count(), CARRY_FROM_WORDS);
        assert_eq!(named_key(&words, &removed), Ok(s.key(2)));
        let spaced = format!("  {}  ", words.to_uppercase().replace(' ', "   "));
        assert_eq!(named_key(&spaced, &removed), Ok(s.key(2)));
        // A key with a label is named by its words too.
        assert_eq!(named_key(&naming_words(&s.key(1)), &removed), Ok(s.key(1)));
        // A label that two removed keys go by is refused, and each is
        // still named by its words.
        let two = named_key("desktop", &removed).unwrap_err();
        assert!(two.contains("names 2 removed keys"), "{two}");
        assert_eq!(named_key(&naming_words(&[9; 32]), &removed), Ok([9; 32]));
        // What names none: another label, fewer words than six, a label
        // in another case, and an empty one.
        let four = cordelia_crypto::fingerprint::shown(&s.key(2));
        for none in ["phone", four.as_str(), "Laptop", ""] {
            let refused = named_key(none, &removed).unwrap_err();
            assert!(
                refused.contains("names no removed key"),
                "{none}: {refused}"
            );
        }
        // **A key written whole names that key, and no other.** Here a
        // removed key goes by a label that is another key's six words:
        // those words name two keys, for good, and do not tell the key
        // apart. Its key, written whole, does.
        let written = |key: &[u8; 32]| cordelia_crypto::bech32::encode_public_key(key).unwrap();
        let mut removed = removed;
        removed.push(Removed {
            key: [8; 32],
            label: naming_words(&s.key(0)),
        });
        let two = named_key(&naming_words(&s.key(0)), &removed).unwrap_err();
        assert!(two.contains("names 2 removed keys"), "{two}");
        assert!(two.contains("by its key, written whole"), "{two}");
        assert!(!words_tell(&s.key(0), &removed));
        assert!(words_tell(&s.key(1), &removed) && words_tell(&[8; 32], &removed));
        for one in &removed {
            assert_eq!(named_key(&written(&one.key), &removed), Ok(one.key));
            let spaced = format!("  {}\n", written(&one.key));
            assert_eq!(named_key(&spaced, &removed), Ok(one.key));
        }
        // A key that is no removed key names none. And a key is never
        // taken for a label: a removed key that is labelled with another
        // key, written whole, is not named by it.
        let refused = named_key(&written(&[7; 32]), &removed).unwrap_err();
        assert!(refused.contains("names no removed key"), "{refused}");
        assert!(refused.contains("or its key written whole"), "{refused}");
        removed.push(Removed {
            key: [6; 32],
            label: written(&s.key(1)),
        });
        assert_eq!(named_key(&written(&s.key(1)), &removed), Ok(s.key(1)));
        // A key is in hex where a word names one.
        assert_eq!(key_named(&hex::encode(s.key(1))), Some(s.key(1)));
        assert_eq!(key_named("zz"), None);
        assert_eq!(key_named("00"), None);
    }

    /// **A word is taken once, and so is each batch that is handed under
    /// one** (decision 2026-10-04 §16). The node keeps a word that it has
    /// taken, by its signature, until the word is void: taken again, in
    /// whatever case its signature is written, it is refused. Under a
    /// word, each number is taken once. A word that is void is kept no
    /// longer.
    #[test]
    fn test_a_word_is_taken_once_and_each_batch_under_it_once() {
        let s = three();
        let conn = &s[0].conn;
        let (device, under) = (s.key(0), s[0].latest().id());
        let word = |says: &str, at: i64| {
            Word::give(&s.phrase, &device, &under, says.to_string(), at).unwrap()
        };
        let now = 5_000;
        let (one, other) = (word("one", now), word("other", now));
        let refused = |taken: Result<(), PersonError>, why: &str| {
            assert!(
                matches!(&taken, Err(PersonError::NotCarried(said)) if said.contains(why)),
                "{taken:?}"
            );
        };

        assert!(!is_taken(conn, &one, now).unwrap());
        take_once(conn, &one, now).unwrap();
        assert!(is_taken(conn, &one, now).unwrap());
        assert!(!is_taken(conn, &other, now).unwrap());
        refused(take_once(conn, &one, now + 1), WORD_TAKEN);
        // Its signature in capitals is the same signature.
        let in_capitals = Word {
            signature: one.signature.to_uppercase(),
            ..one.clone()
        };
        assert_ne!(in_capitals.signature, one.signature);
        assert!(is_taken(conn, &in_capitals, now).unwrap());
        refused(take_once(conn, &in_capitals, now + 1), WORD_TAKEN);
        // Another word is taken beside it. One whose signature is none
        // is no word.
        take_once(conn, &other, now).unwrap();
        let none = Word {
            signature: "zz".into(),
            ..one.clone()
        };
        assert!(matches!(
            take_once(conn, &none, now),
            Err(PersonError::NoWord)
        ));
        assert!(matches!(
            take_batch_once(conn, &none, 0, now),
            Err(PersonError::NoWord)
        ));

        // Under a word, each number is taken once: and under another
        // word, the same numbers are taken.
        let handed = word("handed", now);
        for number in [0, 1, 7] {
            take_batch_once(conn, &handed, number, now).unwrap();
        }
        for number in [0, 1, 7] {
            refused(take_batch_once(conn, &handed, number, now + 1), BATCH_TAKEN);
        }
        take_batch_once(conn, &handed, 2, now + 1).unwrap();
        take_batch_once(conn, &word("handed too", now), 0, now).unwrap();
        // A word under which a batch was taken is a word that was taken.
        assert!(is_taken(conn, &handed, now).unwrap());

        // What is kept is kept until the word is void, and no longer.
        let kept = |at: i64| taken_words(conn, at).unwrap().len();
        assert_eq!(kept(now), 4);
        assert_eq!(kept(one.until), 4);
        assert_eq!(kept(one.until + 1), 0);
        // A word that is given later stands longer, and is kept longer.
        let later = word("later", now + 100);
        take_once(conn, &later, now + 100).unwrap();
        assert_eq!(kept(one.until + 1), 1);
        // Once a word is taken after the others are void, they go.
        take_once(conn, &word("last", one.until + 1), one.until + 1).unwrap();
        let noted = meta::get(conn, meta::PERSON_WORDS_TAKEN).unwrap().unwrap();
        assert!(!noted.contains(&one.signature), "{noted}");
        assert!(noted.contains(&later.signature), "{noted}");
    }

    /// A batch of versions is signed by the key of its run over its
    /// number and the hash of its versions (decision 2026-10-04 §16):
    /// another key's signature, another number, and other versions do
    /// not hold. A signature under the label of a batch is no word's.
    #[test]
    fn test_a_batch_is_signed_by_the_key_of_its_run_over_its_number_and_its_hash() {
        let s = three();
        let run = &s[1].identity;
        let version = |file: &str, said: &str| Handed {
            name: file.into(),
            rev: 3,
            text: Some(said.into()),
            signer: hex::encode(s.key(2)),
            chain: Some(Vec::new()),
        };
        let batch = [version("a.md", "one"), version("b.md", "two")];
        let signature = hex::encode(run.sign(&batch_signed(4, &batch).unwrap()));
        assert!(batch_holds(&s.key(1), 4, &batch, &signature));
        assert!(batch_holds(&s.key(1), 4, &batch, &signature.to_uppercase()));
        // Another key, another number, other versions, fewer, none.
        assert!(!batch_holds(&s.key(0), 4, &batch, &signature));
        assert!(!batch_holds(&s.key(1), 5, &batch, &signature));
        let other = [version("a.md", "one"), version("b.md", "three")];
        assert!(!batch_holds(&s.key(1), 4, &other, &signature));
        let turned = [batch[1].clone(), batch[0].clone()];
        assert!(!batch_holds(&s.key(1), 4, &turned, &signature));
        assert!(!batch_holds(&s.key(1), 4, &batch[..1], &signature));
        assert!(!batch_holds(&s.key(1), 4, &[], &signature));
        assert!(!batch_holds(&s.key(1), 4, &batch, "zz"));
        assert!(!batch_holds(&s.key(1), 4, &batch, ""));
        // What is signed begins with the label of a batch.
        let signed = batch_signed(4, &batch).unwrap();
        assert!(signed.starts_with(LABEL_CARRY_BATCH));
        assert_eq!(signed.len(), LABEL_CARRY_BATCH.len() + 8 + 32);

        // A version may be handed only at a revision that an entry may
        // have under the statement applied, as it is once it has crossed
        // into that generation.
        let at_rev = |rev: u64| Handed {
            rev,
            ..batch[0].clone()
        };
        let top_half = REV_BAND_HALF + 4;
        assert!(at_rev(3).may_be_under(1));
        assert!(at_rev(at(2, 9)).may_be_under(2));
        // In the top half of band 0: it is lifted into band 1.
        assert!(at_rev(top_half).may_be_under(1));
        assert!(at_rev(top_half).may_be_under(2));
        assert!(!at_rev(0).may_be_under(1));
        assert!(!at_rev(at(2, 1)).may_be_under(1));
        assert!(!at_rev(at(1, top_half)).may_be_under(1));
        assert!(!at_rev(3).may_be_under(0));
    }

    /// Where two removed keys are named in one run, the newest version
    /// among them is taken for each empty slot, judged once (decision
    /// 2026-10-04 §7.3, §9). Named one at a time, the first key's
    /// versions fill the slots, and a newer version of the second's then
    /// stands above a version that the new channel holds: it needs the
    /// second yes.
    #[test]
    fn test_two_keys_named_in_one_run_give_the_newest_version_for_each_empty_slot() {
        // Devices 1 and 2 each wrote in a name that device 0 does not
        // sync, and each wrote the same file: device 2 last.
        let run = |one_at_a_time: bool| -> (Several, Vec<Brought>) {
            let mut s = Several::of_one_person(3);
            s.hold(&[1, 2], LAB);
            let old = s[1].own(LAB);
            s.write(1, LAB, FILE, "of device 1");
            s.write(1, LAB, "only-1.md", "one");
            s.pass(1, 2);
            s.write(2, LAB, FILE, "of device 2, written over it");
            s.write(2, LAB, "only-2.md", "two");
            let mut at_the_relays = s[1].stored_in(&old);
            at_the_relays.extend(s[2].stored_in(&old));
            s.change(0, &[0], &[1, 2]);
            s.hold(&[0], LAB);
            let (first, second) = (s.key(1), s.key(2));
            let of = |keys: &[[u8; 32]]| -> Vec<Version> {
                let was = read(&at_the_relays, &old, 1, |key| keys.contains(key)).unwrap();
                newest(was.versions)
            };
            let mut brought = Vec::new();
            match one_at_a_time {
                false => {
                    for version in of(&[first, second]) {
                        brought.push(bring_on(&mut s, 0, &version, Rule::EmptySlots));
                    }
                }
                true => {
                    for version in of(&[first]).into_iter().chain(of(&[second])) {
                        brought.push(bring_on(&mut s, 0, &version, Rule::EmptySlots));
                    }
                }
            }
            (s, brought)
        };
        // In one run: three files, each into an empty slot, and the file
        // that both wrote holds the newer text.
        let (s, brought) = run(false);
        assert_eq!(brought, [Brought::Carried; 3]);
        assert_eq!(
            s[0].text(LAB, FILE).as_deref(),
            Some("of device 2, written over it")
        );
        assert_eq!(s[0].text(LAB, "only-1.md").as_deref(), Some("one"));
        assert_eq!(s[0].text(LAB, "only-2.md").as_deref(), Some("two"));
        // Where each key's versions were read apart, as where each wrote
        // in a generation of its own, the newest among them is still the
        // one that is taken for a file.
        let old = s[1].own(LAB);
        let mut at_the_relays = s[1].stored_in(&old);
        at_the_relays.extend(s[2].stored_in(&old));
        let mut apart: Vec<Version> = Vec::new();
        for key in [s.key(1), s.key(2)] {
            let was = read(&at_the_relays, &old, 1, |signer| *signer == key).unwrap();
            apart.extend(was.versions);
        }
        assert_eq!(apart.iter().filter(|one| one.name == FILE).count(), 2);
        let taken = newest(apart);
        let of_the_file = taken.iter().find(|one| one.name == FILE).unwrap();
        assert_eq!(of_the_file.value, text("of device 2, written over it"));
        assert_eq!(taken.len(), 3);
        // One at a time: the first key's version fills the slot, and the
        // second's then stands above it, and is left.
        let (s, brought) = run(true);
        assert_eq!(
            brought,
            [
                Brought::Carried,
                Brought::Carried,
                Brought::Above,
                Brought::Carried
            ]
        );
        assert_eq!(s[0].text(LAB, FILE).as_deref(), Some("of device 1"));
    }

    /// A version that a command read in its own process is handed to the
    /// node in the clear, and is the same version there (decision
    /// 2026-10-04 §7.3): its name, its revision, its text or its delete,
    /// the key that signed the entry it was read from, and that entry's
    /// chain. What is no key, or no link, is refused.
    #[test]
    fn test_a_version_that_a_command_hands_the_node_is_the_same_version_there() {
        let mut s = three();
        let old = s[2].own(LAB);
        s.write(2, LAB, FILE, "late");
        let now = s.tick();
        let deleted = entry_by(&s[2].identity, &old, 1, "gone.md", Value::Delete, &[]);
        cordelia_storage::entries::store(&s[2].conn, &deleted, now).unwrap();
        let at_the_relays = s[2].stored_in(&old);
        s.change(0, &[0, 1, 2], &[]);
        let was = read_on(&s, 0, &at_the_relays, &old, 1);
        assert_eq!(was.versions.len(), 2);
        for version in &was.versions {
            let handed = Handed::of(version, &s.key(0)).unwrap();
            // It travels as JSON.
            let over = serde_json::to_string(&handed).unwrap();
            let handed: Handed = serde_json::from_str(&over).unwrap();
            let there = handed.version().unwrap();
            assert_eq!(
                (&there.name, there.rev, &there.value),
                (&version.name, version.rev, &version.value)
            );
            assert_eq!(there.entries.len(), 1);
            assert_eq!(there.entries[0].author, s.key(2));
            assert_eq!(there.entries[0].chain, version.entries[0].chain);
        }
        let late = was
            .versions
            .iter()
            .find(|version| version.name == FILE)
            .unwrap();
        let handed = Handed::of(late, &s.key(0)).unwrap();
        assert_eq!(handed.text.as_deref(), Some("late"));
        assert_eq!(handed.chain.as_ref().unwrap().len(), 1);
        // Brought in, it is what the version itself would have been.
        let there = handed.version().unwrap();
        assert_eq!(bring_on(&mut s, 0, &there, Rule::Counts), Brought::Carried);
        assert_eq!(bring_on(&mut s, 0, late, Rule::Counts), Brought::Held);
        // What is no key, and what is no link.
        let no_key = Handed {
            signer: "zz".into(),
            ..handed.clone()
        };
        assert!(no_key.version().is_err());
        let no_link = Handed {
            chain: Some(vec!["00".into()]),
            ..handed.clone()
        };
        assert!(no_link.version().is_err());
        // Bytes that are neither a text nor a delete are not handed.
        let other = Version {
            value: Value::Other(vec![1, 2, 3]),
            ..late.clone()
        };
        assert_eq!(Handed::of(&other, &s.key(0)), None);
    }
}
