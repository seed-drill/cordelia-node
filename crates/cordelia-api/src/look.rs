//! One place to look (decision 2026-10-04 §8): what a device knows of its
//! person's devices, and what it says of itself.
//!
//! [`look`] reads it all from the device's database in one transaction,
//! with where the device stands at its relays as the node last said it:
//!
//! - where the device stands: it follows no phrase, has applied a
//!   statement, or cannot go on, and why (§4.3, §4.5, §5.2);
//! - every device of the statement it has applied, with whether each has
//!   written that it has applied it;
//! - every device added since, with who added it, and every record that
//!   is not counted, with why (§6);
//! - every key the statement removed;
//! - every key that the device counted before the statement and that is
//!   in neither of its lists, by its label and never by its key: a key is
//!   not offered to copy from a list (§6);
//! - every device that has said it left (§5.2);
//! - for each relay, whether it holds the latest change entry, and
//!   whether the device has heard from it since it woke (§4.6);
//! - the keys that a person typed at `cordelia accept`, and what became
//!   of each (§5.1);
//! - **the notices**: a device added since the last change, a device that
//!   has left, and a key that is not in the last change, each shown until
//!   a person clears it on this device, at a terminal ([`clear`]).
//!
//! What it says is said in words here ([`Look::says`]), so that `cordelia
//! status`, `cordelia status --json` and `cordelia devices` say the same.
//!
//! Wherever a device is shown, the first four words of its key's
//! fingerprint are shown beside its label: a label is whatever the device
//! that added a key called it, and two keys can have one label (§6).
//!
//! What is not here is the adapter's: the names that no device lists yet
//! in the new generation, how much a device has written, and whether a
//! device has sent what it carried.

use rusqlite::Connection;
use serde::Serialize;

use cordelia_core::protocol::{
    MAX_STATEMENT_NUMBER, PAIR_KEY_TYPED_SECS, STATEMENTS_LEFT_SAID_BELOW,
};
use cordelia_crypto::addition::SignedAddition;
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::change_entry;
use cordelia_crypto::derive;
use cordelia_crypto::entry::Value;
use cordelia_crypto::fingerprint;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::slots::slot_id;
use cordelia_crypto::statement::Statement;
use cordelia_crypto::version;
use cordelia_storage::acts;
use cordelia_storage::entries;
use cordelia_storage::person::{self as held_rows, Kept, KeptAddition, State};

use crate::adding::within_its_hour;
use crate::leaving::{Among, among, left_name};
use crate::person::{
    Counting, Held, NotCounted, PersonError, applied_name, applied_secret, held, in_one,
    kept_entry, latest_entry,
};
use crate::state::{AtRelays, CannotGoOn};

/// A device, as it is shown to a person: its key, the label it is known
/// by, and the first words of its key's fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Shown {
    /// The key, as a device's key is written.
    pub key: String,
    /// What the person calls it: the statement's label, or the label of
    /// the record that added it. Empty where the device knows none.
    pub label: String,
    /// The first four words of the key's fingerprint.
    pub words: String,
}

impl Shown {
    fn of(key: &[u8; 32], label: &str) -> Result<Self, PersonError> {
        Ok(Self {
            key: encode_public_key(key)?,
            label: label.to_string(),
            words: fingerprint::shown(key),
        })
    }

    /// The device in a sentence: its label and its words, or its words
    /// alone where it has no label.
    pub fn named(&self) -> String {
        match self.label.is_empty() {
            true => format!("the device ({})", self.words),
            false => format!("{} ({})", self.label, self.words),
        }
    }
}

/// A device of the statement that this device has applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listed {
    #[serde(flatten)]
    pub device: Shown,
    pub this_device: bool,
    /// Whether the statement was made on it.
    pub maker: bool,
    /// The number of the statement that it says it has applied, in the
    /// personal channel of that statement's generation. `None` where this
    /// device holds no such word of it.
    pub applied: Option<u64>,
    /// Whether it has said that it left.
    pub left: bool,
}

/// A device added since the statement, or a record that is not counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddedSince {
    #[serde(flatten)]
    pub device: Shown,
    pub this_device: bool,
    /// The device that added it.
    pub by: Shown,
    /// When its record says it was added, in seconds.
    pub at: u64,
    /// Whether it counts.
    pub counted: bool,
    /// Why it does not, where it does not.
    pub why_not: Option<String>,
    pub applied: Option<u64>,
    pub left: bool,
}

/// A key that the device counted before the statement and that is in
/// neither of its lists. It is shown by its label and the words of its
/// fingerprint: its key is asked for as that device prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeftOutKey {
    pub label: String,
    pub words: String,
    /// The number of the statement that left it out.
    pub number: u64,
}

/// A statement's two lists, as a device that can read it shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lists {
    pub number: u64,
    /// The device it was made on.
    pub made_on: Shown,
    pub devices: Vec<Shown>,
    /// The keys it lists as removed: a statement lists them bare.
    pub removed: Vec<Shown>,
}

/// What a person is told until they clear it on this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notice {
    /// What the notice is named by, in hex: what [`clear`] is given.
    pub id: String,
    /// `added`, `left` or `left_out`.
    pub kind: &'static str,
    pub says: String,
}

/// A key that a person typed at `cordelia accept`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Accepting {
    pub key: String,
    pub words: String,
    pub typed_at: i64,
    /// When its hour ends.
    pub until: i64,
    /// Whether a hand-over was taken with it.
    pub taken: bool,
    /// Whether the node still asks for a hand-over with it.
    pub asking: bool,
    /// What became of the last hand-over that was read with it.
    pub said: Option<String>,
}

/// Where the device stands at one relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AtRelayLook {
    pub relay: String,
    pub holds_latest: Option<bool>,
    pub heard_since_woke: bool,
    /// The relay's last refusal for room, in words.
    pub no_room: Option<String>,
    /// How many entries of this device's own the relay holds in another
    /// form.
    pub another_form: usize,
    /// Why this device refuses the change that the relay holds, where it
    /// does.
    pub refuses: Option<String>,
}

/// Everything `cordelia devices` and `cordelia status` say of a device and
/// its person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Look {
    /// This device's key.
    pub this_device: String,
    /// `no_phrase`, `applied`, `fork`, `removed`, `not_listed` or
    /// `not_opened`.
    pub state: &'static str,
    /// `no_phrase`, `alone`, `several` or `stopped`.
    pub among: &'static str,
    /// How many other devices it is with, where it is one of several.
    pub others: usize,
    /// Whether this device may add another.
    pub may_add: bool,
    /// The number of the statement applied.
    pub change: Option<u64>,
    /// How many more statements the phrase can make, once fewer than 16
    /// are left.
    pub statements_left: Option<u64>,
    pub devices: Vec<Listed>,
    pub added: Vec<AddedSince>,
    pub removed: Vec<Shown>,
    pub left_out: Vec<LeftOutKey>,
    /// The statement made apart from the one applied, where the device is
    /// in a fork.
    pub apart: Option<Lists>,
    pub relays: Vec<AtRelayLook>,
    pub accepting: Vec<Accepting>,
    pub notices: Vec<Notice>,
    /// Why the device cannot go on, where it cannot.
    pub cannot_go_on: Option<String>,
    /// A few words for a line of status, where there is something to
    /// say.
    pub short: Option<String>,
    /// What a status says, a sentence each.
    pub says: Vec<String>,
}

/// What the statement of a device that follows no phrase says of itself
/// (decision 2026-10-04 §5.2).
pub const NO_PHRASE: &str = "no recovery phrase yet: memory stays on this machine. Make one here \
                             (`cordelia phrase`), or add this machine from one that has one.";

/// What is said in a few words of a device that follows no phrase
/// (decision 2026-10-04 §5.1).
pub const NOT_ADDED_YET: &str = "not added yet";

/// Look at what this device holds of its person, at `now` (see the
/// module's documentation). `at_relays` is where it stands at its relays,
/// as the node last said it.
pub fn look(
    conn: &Connection,
    identity: &NodeIdentity,
    at_relays: &AtRelays,
    now: i64,
) -> Result<Look, PersonError> {
    in_one(conn, || {
        let own = identity.public_key();
        let mut look = Look {
            this_device: encode_public_key(&own)?,
            state: "no_phrase",
            among: "no_phrase",
            others: 0,
            may_add: false,
            change: None,
            statements_left: None,
            devices: Vec::new(),
            added: Vec::new(),
            removed: Vec::new(),
            left_out: Vec::new(),
            apart: None,
            relays: relays(at_relays),
            accepting: accepting(conn, now)?,
            notices: Vec::new(),
            cannot_go_on: None,
            short: None,
            says: Vec::new(),
        };
        match held(conn)? {
            None => {
                look.short = Some(NOT_ADDED_YET.into());
                look.says.push(NO_PHRASE.into());
            }
            Some(held) => of_its_person(conn, identity, &held, at_relays, &mut look)?,
        }
        for notice in &look.notices {
            look.says.push(notice.says.clone());
        }
        // A relay says nothing to a device that follows no phrase: it has
        // nothing to show one.
        if look.state != "no_phrase" {
            for relay in &look.relays {
                look.says.extend(relay.says());
            }
        }
        for typed in &look.accepting {
            look.says.push(typed.says());
        }
        Ok(look)
    })
}

/// What a device that follows a phrase holds of its person.
fn of_its_person(
    conn: &Connection,
    identity: &NodeIdentity,
    held: &Held,
    at_relays: &AtRelays,
    look: &mut Look,
) -> Result<(), PersonError> {
    let own = identity.public_key();
    let statement = &held.statement.statement;
    let kept = held_rows::additions(conn)?;
    let counting = Counting::of(statement, &kept);
    let reader = Reader::of(conn, statement, &kept)?;

    look.state = match held.state {
        State::Applied => "applied",
        State::Fork => "fork",
        State::Removed => "removed",
        State::NotListed => "not_listed",
        State::NotOpened => "not_opened",
    };
    (look.among, look.others) = match among(conn, identity)? {
        Among::NoPhrase => ("no_phrase", 0),
        Among::Alone => ("alone", 0),
        Among::Several(others) => ("several", others),
        Among::Stopped(_) => ("stopped", 0),
    };
    look.may_add = held.state == State::Applied && counting.may_add(&own);
    look.change = Some(statement.number);
    look.statements_left = statements_left(statement.number);

    for device in &statement.devices {
        look.devices.push(Listed {
            device: Shown::of(&device.key, &device.label)?,
            this_device: device.key == own,
            maker: device.key == statement.maker,
            applied: reader.applied(conn, &device.key)?,
            left: reader.left(conn, &device.key)?.is_some(),
        });
    }
    for key in &statement.removed {
        look.removed.push(Shown::of(key, "")?);
    }

    // Those added since: for each key that the statement does not list,
    // the record it counts by, or the first that the device saw of it.
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for record in &kept {
        if statement.lists(&record.key) || seen.contains(&record.key) {
            continue;
        }
        seen.push(record.key);
        let of_the_key = kept.iter().filter(|other| other.key == record.key);
        let shown = of_the_key
            .clone()
            .find(|other| other.counted)
            .unwrap_or(record);
        let read = SignedAddition::from_bytes(&shown.record)?.addition;
        let why_not = match shown.counted {
            true => None,
            false => counting
                .why_not(&shown.key, &shown.adder)
                .map(|why| not_counted(why).to_string()),
        };
        look.added.push(AddedSince {
            device: Shown::of(&shown.key, &read.device.label)?,
            this_device: shown.key == own,
            by: Shown::of(&shown.adder, &reader.label(&shown.adder))?,
            at: read.at,
            counted: shown.counted,
            why_not,
            applied: reader.applied(conn, &shown.key)?,
            left: reader.left(conn, &shown.key)?.is_some(),
        });
    }

    for shown in acts::left_out(conn)? {
        look.left_out.push(LeftOutKey {
            label: shown.label,
            words: fingerprint::shown(&shown.key),
            number: shown.number,
        });
    }

    look.notices = notices(conn, identity, statement, &kept, &reader)?;

    // Why it cannot go on.
    let why = match held.state {
        State::Applied => match &at_relays.cannot_go_on {
            Some(CannotGoOn::NotApplied { relay, why }) => Some(format!(
                "this device was answered with a change by {relay} and could not apply it \
                 ({why}): it sends nothing and takes nothing in a channel of its own, and tries \
                 again at each pass"
            )),
            _ => None,
        },
        State::Removed => Some(
            "this device was removed. `cordelia init --new-key` gives it a new key; it is then \
             added as a new device"
                .into(),
        ),
        State::NotListed => Some(format!(
            "this device is not in a change made on {}: if it is yours, add it again from a \
             device that is",
            made_on(conn, held)?
        )),
        State::NotOpened => Some(format!(
            "a change made on {} could not be opened here: add this device again from a device \
             that has it",
            made_on(conn, held)?
        )),
        State::Fork => {
            look.apart = apart(conn, held)?;
            Some(
                "two changes were made apart: settle it with the phrase (`cordelia settle`)".into(),
            )
        }
    };
    if let Some(why) = &why {
        look.short = Some(
            match held.state {
                State::Removed => "this device was removed",
                State::NotListed => "this device is not in the last change",
                State::NotOpened => "a change could not be opened here",
                State::Fork => "two changes were made apart",
                State::Applied => "a change could not be applied",
            }
            .into(),
        );
        look.says.push(why.clone());
    }
    look.cannot_go_on = why;
    Ok(())
}

/// What the personal channel of the generation applied says of each
/// device, as this device's store holds it, and what each key is called.
struct Reader {
    /// The personal channel's secret, and the number of its statement.
    personal: [u8; 32],
    number: u64,
    /// Each key that a label is known for, with the label: the
    /// statement's devices, and then those that a record adds.
    labels: Vec<([u8; 32], String)>,
}

impl Reader {
    fn of(
        conn: &Connection,
        statement: &Statement,
        kept: &[KeptAddition],
    ) -> Result<Self, PersonError> {
        let mut labels: Vec<([u8; 32], String)> = statement
            .devices
            .iter()
            .map(|device| (device.key, device.label.clone()))
            .collect();
        for record in kept {
            if labels.iter().any(|(key, _)| *key == record.key) {
                continue;
            }
            let read = SignedAddition::from_bytes(&record.record)?.addition;
            labels.push((record.key, read.device.label));
        }
        Ok(Self {
            personal: derive::personal_secret(&applied_secret(conn, statement)?)?,
            number: statement.number,
            labels,
        })
    }

    /// The label that `key` is known by, or none.
    fn label(&self, key: &[u8; 32]) -> String {
        self.labels
            .iter()
            .find(|(known, _)| known == key)
            .map(|(_, label)| label.clone())
            .unwrap_or_default()
    }

    /// The word of the device whose key is `key`, under `name` in the
    /// personal channel: that device's own entry there, and no other
    /// key's. What it is named by comes with it.
    fn word(
        &self,
        conn: &Connection,
        key: &[u8; 32],
        name: &str,
    ) -> Result<Option<([u8; 32], Value)>, PersonError> {
        let channel = derive::channel_id(&self.personal)?;
        let slot = slot_id(&derive::slot_key(&self.personal)?, name);
        let held = entries::slot_entries(conn, &channel, &slot)?;
        let read = version::current(&held, &self.personal, self.number, |by| by == key)?;
        Ok(read.current.and_then(|version| {
            let id = version.entries.first()?.id;
            Some((id, version.value))
        }))
    }

    /// The number of the statement that the device says it has applied.
    fn applied(&self, conn: &Connection, key: &[u8; 32]) -> Result<Option<u64>, PersonError> {
        Ok(match self.word(conn, key, &applied_name(key)?)? {
            Some((_, Value::Text(number))) => number.parse().ok(),
            _ => None,
        })
    }

    /// What the device's word that it has left is named by, where it has
    /// said so.
    fn left(&self, conn: &Connection, key: &[u8; 32]) -> Result<Option<[u8; 32]>, PersonError> {
        Ok(match self.word(conn, key, &left_name(key)?)? {
            Some((id, Value::Text(_))) => Some(id),
            _ => None,
        })
    }
}

/// How many more statements a phrase can make after the one numbered
/// `number`, where that is to be said: once fewer than 16 are left
/// (decision 2026-10-04 §4.1).
pub fn statements_left(number: u64) -> Option<u64> {
    let left = MAX_STATEMENT_NUMBER.saturating_sub(number);
    (left < STATEMENTS_LEFT_SAID_BELOW).then_some(left)
}

/// Why a record does not count, in words.
fn not_counted(why: NotCounted) -> &'static str {
    match why {
        NotCounted::Removed => "its key was removed, and a removed key is not added again",
        NotCounted::CountsAlready => "it counts already",
        NotCounted::MayNotAdd => {
            "the device that added it was itself added, since the last change, by a device \
             added since"
        }
        NotCounted::NoRoom => "64 devices count already: a change makes room",
    }
}

/// What a notice of an addition is named by: the hash of a word of its
/// own and the record. Another record for the same key is another notice.
fn added_notice(record: &[u8]) -> [u8; 32] {
    let mut named = b"cordelia notice added".to_vec();
    named.extend_from_slice(record);
    cordelia_crypto::sha256(&named)
}

/// What the notice of a key that is not in the last change is named by.
fn left_out_notice(key: &[u8; 32]) -> [u8; 32] {
    let mut named = b"cordelia notice left out".to_vec();
    named.extend_from_slice(key);
    cordelia_crypto::sha256(&named)
}

/// One notice, with what clearing it does.
struct Told {
    notice: Notice,
    id: [u8; 32],
    /// The key that is shown as left out no more, where the notice is of
    /// one.
    left_out: Option<[u8; 32]>,
}

/// Every notice that the device has to show, cleared or not.
fn told(
    conn: &Connection,
    identity: &NodeIdentity,
    statement: &Statement,
    kept: &[KeptAddition],
    reader: &Reader,
) -> Result<Vec<Told>, PersonError> {
    let own = identity.public_key();
    let mut all = Vec::new();
    let tell = |id: [u8; 32], kind: &'static str, says: String, left_out| Told {
        notice: Notice {
            id: hex::encode(id),
            kind,
            says,
        },
        id,
        left_out,
    };
    // Each record of an addition (§6).
    for record in kept {
        let read = SignedAddition::from_bytes(&record.record)?.addition;
        let by = Shown::of(&record.adder, &reader.label(&record.adder))?;
        let says = match record.key == own {
            true => format!("this device was added from {}", by.named()),
            false => format!(
                "new device: {}, added from {}",
                Shown::of(&record.key, &read.device.label)?.named(),
                by.named()
            ),
        };
        all.push(tell(added_notice(&record.record), "added", says, None));
    }
    // Each device that has said it left (§5.2): of the statement, or
    // added since.
    let mut keys: Vec<[u8; 32]> = statement.devices.iter().map(|device| device.key).collect();
    for record in kept {
        if !keys.contains(&record.key) {
            keys.push(record.key);
        }
    }
    for key in keys.iter().filter(|key| **key != own) {
        let Some(id) = reader.left(conn, key)? else {
            continue;
        };
        let says = format!(
            "{} left, and started again under another phrase. It still holds the secret it \
             had, and is still listed: removing it, with the phrase, is what cuts it off \
             (`cordelia remove-device`)",
            Shown::of(key, &reader.label(key))?.named()
        );
        all.push(tell(id, "left", says, None));
    }
    // Each key that is not in the last change (§8).
    for shown in acts::left_out(conn)? {
        let says = format!(
            "{} ({}) is not in the last change: add it again, or it was meant to go",
            shown.label,
            fingerprint::shown(&shown.key)
        );
        all.push(tell(
            left_out_notice(&shown.key),
            "left_out",
            says,
            Some(shown.key),
        ));
    }
    Ok(all)
}

/// The notices that a person has not cleared on this device.
fn notices(
    conn: &Connection,
    identity: &NodeIdentity,
    statement: &Statement,
    kept: &[KeptAddition],
    reader: &Reader,
) -> Result<Vec<Notice>, PersonError> {
    let mut shown = Vec::new();
    for told in told(conn, identity, statement, kept, reader)? {
        if !acts::is_cleared(conn, &told.id)? {
            shown.push(told.notice);
        }
    }
    Ok(shown)
}

/// A person clears the notice named `id` on this device, at `now`: it is
/// shown here no more (decision 2026-10-04 §5.2, §6, §8). Returns the
/// notice that was cleared, or `None` where the device shows none that is
/// named so: nothing was cleared.
///
/// Clearing changes what this device shows, and nothing else: a device
/// that was added still counts, one that left is still listed, and a key
/// that is not in the last change still holds the secret before.
pub fn clear(
    conn: &Connection,
    identity: &NodeIdentity,
    id: &[u8; 32],
    now: i64,
) -> Result<Option<Notice>, PersonError> {
    in_one(conn, || {
        let Some(held) = held(conn)? else {
            return Ok(None);
        };
        let statement = &held.statement.statement;
        let kept = held_rows::additions(conn)?;
        let reader = Reader::of(conn, statement, &kept)?;
        let shown = told(conn, identity, statement, &kept, &reader)?;
        let Some(told) = shown.into_iter().find(|told| told.id == *id) else {
            return Ok(None);
        };
        if acts::is_cleared(conn, &told.id)? {
            return Ok(None);
        }
        match told.left_out {
            Some(key) => {
                acts::clear_left_out(conn, &key)?;
            }
            None => acts::clear_notice(conn, &told.id, now)?,
        }
        Ok(Some(told.notice))
    })
}

/// The device on which the statement was made that stopped this one, as a
/// person knows it: the statement is in the change entry that the device
/// keeps as the latest it has seen.
fn made_on(conn: &Connection, held: &Held) -> Result<String, PersonError> {
    Ok(lists_in(conn, held, Kept::Latest)?
        .map(|lists| lists.made_on.named())
        .unwrap_or_else(|| "another device".into()))
}

/// The lists of the statement made apart from the one applied.
fn apart(conn: &Connection, held: &Held) -> Result<Option<Lists>, PersonError> {
    lists_in(conn, held, Kept::Apart)
}

/// The lists of the statement in a change entry that the device keeps,
/// which every device that follows the phrase can read (§4.6).
fn lists_in(conn: &Connection, held: &Held, which: Kept) -> Result<Option<Lists>, PersonError> {
    let entry = match which {
        Kept::Latest => Some(latest_entry(conn)?),
        Kept::Apart => kept_entry(conn, Kept::Apart)?,
    };
    let Some(entry) = entry else {
        return Ok(None);
    };
    let following = &held.following;
    let Ok(read) = change_entry::open_statement(
        &entry,
        &following.phrase_key,
        &following.phrase_channel,
        &following.statement_key,
    ) else {
        return Ok(None);
    };
    Ok(Some(lists_of(&read.statement)?))
}

/// A statement's two lists, each device with the words of its key.
pub fn lists_of(statement: &Statement) -> Result<Lists, PersonError> {
    let label_of = |key: &[u8; 32]| {
        statement
            .devices
            .iter()
            .find(|device| device.key == *key)
            .map(|device| device.label.clone())
            .unwrap_or_default()
    };
    Ok(Lists {
        number: statement.number,
        made_on: Shown::of(&statement.maker, &label_of(&statement.maker))?,
        devices: statement
            .devices
            .iter()
            .map(|device| Shown::of(&device.key, &device.label))
            .collect::<Result<_, _>>()?,
        removed: statement
            .removed
            .iter()
            .map(|key| Shown::of(key, ""))
            .collect::<Result<_, _>>()?,
    })
}

/// Where the device stands at each relay, as the node last said it.
fn relays(at_relays: &AtRelays) -> Vec<AtRelayLook> {
    at_relays
        .relays
        .iter()
        .map(|relay| AtRelayLook {
            relay: relay.relay.clone(),
            holds_latest: relay.holds_latest,
            heard_since_woke: relay.heard_since_woke,
            no_room: relay.no_room.map(|refused| {
                format!(
                    "{} had no room for {} at {} ({})",
                    relay.relay,
                    match refused.of_the_change {
                        true => "the change",
                        false => "a new channel",
                    },
                    time_of_day(refused.at),
                    match refused.over_allowance {
                        true => "this address is over its allowance of new channels there",
                        false => "it is full",
                    }
                )
            }),
            another_form: relay.another_form,
            refuses: relay.refuses.clone(),
        })
        .collect()
}

impl AtRelayLook {
    /// What is said of the relay in a status, where there is something to
    /// say (decision 2026-10-04 §4.6, §8).
    pub fn says(&self) -> Vec<String> {
        let mut says = Vec::new();
        if !self.heard_since_woke {
            says.push(format!(
                "has not heard from {} since it woke: a change made while it was off may not \
                 have reached it",
                self.relay
            ));
        } else if self.holds_latest == Some(false) {
            says.push(format!(
                "{} does not hold the latest change yet",
                self.relay
            ));
        }
        says.extend(self.no_room.clone());
        if let Some(why) = &self.refuses {
            says.push(format!(
                "{} holds a change that this device does not take ({why}): this device \
                 neither sends there nor takes from there while it does",
                self.relay
            ));
        }
        match self.another_form {
            0 => {}
            1 => says.push(format!(
                "an entry of this device's own is at {} in another form: the file's next edit \
                 goes above both",
                self.relay
            )),
            several => says.push(format!(
                "{several} entries of this device's own are at {} in another form: each \
                 file's next edit goes above both",
                self.relay
            )),
        }
        says
    }
}

/// The keys that a person typed in the last day, and what became of
/// each.
fn accepting(conn: &Connection, now: i64) -> Result<Vec<Accepting>, PersonError> {
    let mut all = Vec::new();
    for typed in acts::typed_keys(conn)? {
        // What became of a key typed more than a day ago is said no more.
        if now.saturating_sub(typed.typed_at) >= 24 * PAIR_KEY_TYPED_SECS {
            continue;
        }
        let taken = typed.taken_at.is_some();
        all.push(Accepting {
            key: encode_public_key(&typed.key)?,
            words: fingerprint::shown(&typed.key),
            typed_at: typed.typed_at,
            until: typed.typed_at.saturating_add(PAIR_KEY_TYPED_SECS),
            taken,
            asking: !taken && within_its_hour(typed.typed_at, now),
            said: typed.said,
        });
    }
    Ok(all)
}

impl Accepting {
    /// What is said of a key that was typed, in a status (decision
    /// 2026-10-04 §5.1): the node asks for the hand-over until it is
    /// taken or the hour is gone, and says which.
    pub fn says(&self) -> String {
        let said = self.said.clone().unwrap_or_default();
        if self.taken {
            return format!("accepted the device ({}): {said}", self.words);
        }
        let so_far = match said.is_empty() {
            true => String::new(),
            false => format!(" So far: {said}."),
        };
        match self.asking {
            true => format!(
                "asking for what the device ({}) hands over, until {}.{so_far}",
                self.words,
                time_of_day(self.until)
            ),
            false => format!(
                "the hour in which the device ({}) could hand this one what it needs has gone, \
                 and nothing was taken: run `cordelia accept` again.{so_far}",
                self.words
            ),
        }
    }
}

/// A time in seconds as a person reads it: the hour and the minute, in
/// UTC, with the day where it is not today's.
fn time_of_day(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|at| at.format("%H:%M UTC on %Y-%m-%d").to_string())
        .unwrap_or_else(|| format!("{at}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adding::Accepted;
    use crate::leaving::begin;
    use crate::several::Several;
    use crate::state::{AtRelay, NoRoom};
    use crate::take::take;
    use cordelia_crypto::entry::CheckedEntry;

    fn seen(s: &Several, n: usize) -> Look {
        look(&s[n].conn, &s[n].identity, &AtRelays::default(), s.now).unwrap()
    }

    fn give(s: &mut Several, to: usize, entry: &CheckedEntry) {
        let now = s.tick();
        take(&s[to].conn, &s[to].identity, entry, now).unwrap();
    }

    fn kinds(look: &Look) -> Vec<&'static str> {
        look.notices.iter().map(|notice| notice.kind).collect()
    }

    /// A device that follows no phrase says so, in the words of the
    /// decision, and in two words for a line.
    #[test]
    fn test_a_device_that_follows_no_phrase_says_so() {
        let s = Several::new(1);
        let look = seen(&s, 0);
        assert_eq!(look.state, "no_phrase");
        assert_eq!(look.among, "no_phrase");
        assert_eq!(look.short.as_deref(), Some("not added yet"));
        assert_eq!(
            look.says,
            [
                "no recovery phrase yet: memory stays on this machine. Make one here \
              (`cordelia phrase`), or add this machine from one that has one."
            ]
        );
        assert!(look.devices.is_empty() && look.notices.is_empty());
        assert_eq!(look.cannot_go_on, None);
        assert!(!look.may_add);
    }

    /// The devices of the statement are listed with their labels, the
    /// words of their keys and whether each has written that it has
    /// applied the statement: its own word, and no other key's.
    #[test]
    fn test_the_devices_of_the_statement_and_whether_each_has_applied() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        // Device 0 has applied change 2, and nobody else has heard.
        let look = seen(&s, 0);
        assert_eq!(
            (look.state, look.among, look.others),
            ("applied", "several", 2)
        );
        assert_eq!(look.change, Some(2));
        assert_eq!(look.statements_left, None);
        let said: Vec<(String, bool, bool, Option<u64>)> = look
            .devices
            .iter()
            .map(|d| (d.device.label.clone(), d.this_device, d.maker, d.applied))
            .collect();
        assert_eq!(
            said,
            [
                ("device 0".to_string(), true, true, Some(2)),
                ("device 1".to_string(), false, false, None),
                ("device 2".to_string(), false, false, None),
            ]
        );
        for (n, listed) in look.devices.iter().enumerate() {
            assert_eq!(listed.device.words, fingerprint::shown(&s.key(n)));
            assert_eq!(listed.device.key, encode_public_key(&s.key(n)).unwrap());
        }
        assert!(look.added.is_empty() && look.removed.is_empty());
        assert!(look.may_add);

        // Device 1 applies, and device 0 is given its word.
        s.meet(&[0, 1]);
        let look = seen(&s, 0);
        assert_eq!(look.devices[1].applied, Some(2));
        assert_eq!(look.devices[2].applied, None);
        assert_eq!(seen(&s, 1).devices[0].applied, Some(2));
    }

    /// A device added since the statement is listed with who added it,
    /// and every device that keeps its record shows the addition until a
    /// person clears it there: the device that added it, every other,
    /// and the new device itself.
    #[test]
    fn test_a_device_added_since_is_shown_on_every_device_until_cleared_there() {
        let mut s = Several::of_one_person(3);
        // Devices 1 and 2 were added by device 0 under statement 1.
        for n in 0..3 {
            let look = seen(&s, n);
            // Each device lists them in the order it saw their records.
            let mut added: Vec<(String, String, bool)> = look
                .added
                .iter()
                .map(|a| (a.device.label.clone(), a.by.label.clone(), a.counted))
                .collect();
            added.sort();
            assert_eq!(
                added,
                [
                    ("device 1".to_string(), "device 0".to_string(), true),
                    ("device 2".to_string(), "device 0".to_string(), true),
                ],
                "{n}"
            );
            assert_eq!(kinds(&look), ["added", "added"], "{n}");
        }
        let words = |n: usize| fingerprint::shown(&s.key(n));
        assert_eq!(
            seen(&s, 0).notices[0].says,
            format!(
                "new device: device 1 ({}), added from device 0 ({})",
                words(1),
                words(0)
            )
        );
        // The new device says it of itself.
        assert_eq!(
            seen(&s, 1).notices[0].says,
            format!("this device was added from device 0 ({})", words(0))
        );
        assert!(seen(&s, 2).says.contains(&seen(&s, 2).notices[1].says));

        // Cleared on device 0, it is shown there no more, and on every
        // other device still.
        let first = seen(&s, 0).notices[0].clone();
        let id: [u8; 32] = hex::decode(&first.id).unwrap().try_into().unwrap();
        let now = s.tick();
        let cleared = clear(&s[0].conn, &s[0].identity, &id, now).unwrap();
        assert_eq!(cleared, Some(first.clone()));
        assert_eq!(seen(&s, 0).notices.len(), 1);
        assert!(!seen(&s, 0).says.contains(&first.says));
        assert_eq!(seen(&s, 1).notices.len(), 2);
        assert_eq!(seen(&s, 2).notices.len(), 2);
        // Cleared twice, or a notice that is none: nothing.
        assert_eq!(clear(&s[0].conn, &s[0].identity, &id, now).unwrap(), None);
        assert_eq!(
            clear(&s[0].conn, &s[0].identity, &[9; 32], now).unwrap(),
            None
        );
        // The device still counts: clearing changes what is shown.
        assert!(s[0].counts(&s.key(1)));
        assert_eq!(seen(&s, 0).added.len(), 2);

        // A statement that lists them ends the notices everywhere.
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        for n in 0..3 {
            assert!(seen(&s, n).notices.is_empty(), "{n}");
            assert!(seen(&s, n).added.is_empty(), "{n}");
        }
    }

    /// A record that is not counted is listed as that, with why.
    #[test]
    fn test_a_record_that_is_not_counted_is_listed_with_why() {
        let mut s = Several::of_one_person(4);
        // Device 1 was added by device 0, and adds device 9: device 9
        // may not add, so what it adds does not count.
        let now = s.tick();
        let nine = crate::several::Machine::new(9);
        let by_one =
            crate::adding::add_device(&s[1].conn, &s[1].identity, &nine.key(), "device 9", now)
                .unwrap();
        give(&mut s, 0, &by_one.record.clone().unwrap());
        assert!(s[0].counts(&nine.key()));
        let now = s.tick();
        // Device 9 joins, and adds a tenth.
        let accepted = crate::adding::accept(
            &nine.conn,
            &nine.identity,
            &s.key(1),
            now,
            false,
            &by_one.hand_over,
            now,
        )
        .unwrap();
        assert!(matches!(accepted, Accepted::Joined(_)));
        let ten = crate::several::Machine::new(10);
        assert!(matches!(
            crate::adding::add_device(&nine.conn, &nine.identity, &ten.key(), "device 10", now),
            Err(PersonError::MayNotAdd)
        ));
        // A record by device 9 all the same, as a device that does not
        // ask would write it: it is kept as not counted.
        let statement = &s[0].held().statement.statement;
        let record = cordelia_crypto::addition::Addition::under(
            statement,
            cordelia_crypto::statement::Device::new(ten.key(), "device 10").unwrap(),
            nine.key(),
            now as u64,
        )
        .unwrap()
        .sign(&nine.identity)
        .unwrap();
        crate::person::see_addition(&s[0].conn, &record, now).unwrap();
        let look = seen(&s, 0);
        let last = look.added.last().unwrap();
        assert_eq!(last.device.label, "device 10");
        assert_eq!(last.by.label, "device 9");
        assert!(!last.counted);
        assert_eq!(
            last.why_not.as_deref(),
            Some(
                "the device that added it was itself added, since the last change, by a \
                 device added since"
            )
        );
        // It is told of as any addition is.
        assert!(
            look.notices
                .iter()
                .any(|n| n.says.starts_with("new device: device 10"))
        );
    }

    /// The keys that the statement removed are listed, bare: a statement
    /// lists them so.
    #[test]
    fn test_the_keys_that_the_statement_removed_are_listed() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1], &[2]);
        let look = seen(&s, 0);
        assert_eq!(look.removed.len(), 1);
        assert_eq!(look.removed[0].key, encode_public_key(&s.key(2)).unwrap());
        assert_eq!(look.removed[0].words, fingerprint::shown(&s.key(2)));
        assert_eq!(look.removed[0].label, "");
        assert_eq!(look.devices.len(), 2);
    }

    /// A key that the device counted before a statement, and that is in
    /// neither of its lists, is shown as not in the last change, by its
    /// label and never by its key, until a person clears it or a later
    /// statement lists it.
    #[test]
    fn test_a_key_counted_before_and_in_neither_list_is_shown_until_cleared_or_listed() {
        let mut s = Several::of_one_person(3);
        // Statement 2 lists devices 0 and 1, and says nothing of device
        // 2, which was added since statement 1.
        let change = s.change(0, &[0, 1], &[]);
        let look = seen(&s, 0);
        assert_eq!(look.left_out.len(), 1);
        assert_eq!(look.left_out[0].label, "device 2");
        assert_eq!(look.left_out[0].words, fingerprint::shown(&s.key(2)));
        assert_eq!(look.left_out[0].number, 2);
        assert_eq!(kinds(&look), ["left_out"]);
        assert_eq!(
            look.notices[0].says,
            format!(
                "device 2 ({}) is not in the last change: add it again, or it was meant to go",
                fingerprint::shown(&s.key(2))
            )
        );
        // Its key is not offered: not in the notice, and not in the list.
        let key = encode_public_key(&s.key(2)).unwrap();
        assert!(!serde_json::to_string(&look).unwrap().contains(&key));

        // Device 1 applies the statement, and shows the same.
        give(&mut s, 1, &change);
        assert_eq!(kinds(&seen(&s, 1)), ["left_out"]);
        // The device that is left out shows nothing of it: it has stopped.
        give(&mut s, 2, &change);
        let stopped = seen(&s, 2);
        assert_eq!(stopped.state, "not_listed");
        assert!(stopped.left_out.is_empty());

        // Cleared on device 1, it is shown there no more.
        let id: [u8; 32] = hex::decode(&seen(&s, 1).notices[0].id)
            .unwrap()
            .try_into()
            .unwrap();
        let now = s.tick();
        assert!(
            clear(&s[1].conn, &s[1].identity, &id, now)
                .unwrap()
                .is_some()
        );
        assert!(seen(&s, 1).left_out.is_empty() && seen(&s, 1).notices.is_empty());
        assert_eq!(seen(&s, 0).left_out.len(), 1);

        // A later statement that lists it ends it on device 0: here, as
        // removed.
        s.change(0, &[0, 1], &[2]);
        let look = seen(&s, 0);
        assert!(look.left_out.is_empty() && look.notices.is_empty());
        assert_eq!(look.removed.len(), 1);
    }

    /// A device that has said it left is shown as that on each device it
    /// left, until a person clears it there. It is still listed.
    #[test]
    fn test_a_device_that_has_left_is_shown_until_cleared() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let now = s.tick();
        let word = begin(&s[2].conn, &s[2].identity, now)
            .unwrap()
            .word
            .unwrap();
        for n in [0, 1] {
            assert!(seen(&s, n).notices.is_empty());
            give(&mut s, n, &word);
            let look = seen(&s, n);
            assert_eq!(kinds(&look), ["left"], "{n}");
            assert!(look.devices[2].left);
            assert!(!look.devices[1].left);
            assert_eq!(
                look.notices[0].says,
                format!(
                    "device 2 ({}) left, and started again under another phrase. It still \
                     holds the secret it had, and is still listed: removing it, with the \
                     phrase, is what cuts it off (`cordelia remove-device`)",
                    fingerprint::shown(&s.key(2))
                )
            );
            assert_eq!(look.devices.len(), 3);
        }
        // The word of another key in that place is not the device's word.
        let forged = crate::several::entry_by(
            &s[1].identity,
            &s[1].personal(),
            cordelia_core::revision::next_under(None, 2).unwrap(),
            &left_name(&s.key(0)).unwrap(),
            Value::Text("1".into()),
            &[],
        );
        give(&mut s, 1, &forged);
        assert!(!seen(&s, 1).devices[0].left);

        let id: [u8; 32] = hex::decode(&seen(&s, 0).notices[0].id)
            .unwrap()
            .try_into()
            .unwrap();
        let now = s.tick();
        assert!(
            clear(&s[0].conn, &s[0].identity, &id, now)
                .unwrap()
                .is_some()
        );
        assert!(seen(&s, 0).notices.is_empty());
        // It is still shown as having left, in the list.
        assert!(seen(&s, 0).devices[2].left);
        assert_eq!(kinds(&seen(&s, 1)), ["left"]);
    }

    /// A device that cannot go on says why: it was removed, is in no
    /// list, or is in a fork, with the lists of the statement made
    /// apart.
    #[test]
    fn test_a_device_that_cannot_go_on_says_why() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        // Device 0 removes device 2. Device 1, apart, makes a change of
        // its own.
        let removal = s.change(0, &[0, 1], &[2]);
        let apart = s.change(1, &[0, 1, 2], &[]);
        give(&mut s, 2, &removal);
        let removed = seen(&s, 2);
        assert_eq!(removed.state, "removed");
        assert_eq!(removed.among, "stopped");
        assert_eq!(removed.short.as_deref(), Some("this device was removed"));
        assert_eq!(
            removed.cannot_go_on.as_deref(),
            Some(
                "this device was removed. `cordelia init --new-key` gives it a new key; it is \
                 then added as a new device"
            )
        );
        assert_eq!(removed.says[0], removed.cannot_go_on.clone().unwrap());
        assert!(!removed.may_add);

        give(&mut s, 0, &apart);
        let fork = seen(&s, 0);
        assert_eq!(fork.state, "fork");
        assert_eq!(
            fork.cannot_go_on.as_deref(),
            Some("two changes were made apart: settle it with the phrase (`cordelia settle`)")
        );
        // Both lists: its own, and the other's.
        assert_eq!(fork.change, Some(3));
        assert_eq!(fork.devices.len(), 2);
        assert_eq!(fork.removed.len(), 1);
        let other = fork.apart.unwrap();
        assert_eq!(other.number, 3);
        assert_eq!(other.made_on.label, "device 1");
        assert_eq!(other.devices.len(), 3);
        assert!(other.removed.is_empty());
        // A device that is in no fork shows no other statement.
        assert_eq!(seen(&s, 2).apart, None);

        // In no list: it says on which device the change was made.
        let mut s = Several::of_one_person(3);
        let change = s.change(0, &[0, 1], &[]);
        give(&mut s, 2, &change);
        let left_out = seen(&s, 2);
        assert_eq!(left_out.state, "not_listed");
        assert_eq!(
            left_out.cannot_go_on,
            Some(format!(
                "this device is not in a change made on device 0 ({}): if it is yours, add it \
                 again from a device that is",
                fingerprint::shown(&s.key(0))
            ))
        );
    }

    /// What the node says of each relay is said: one that the device has
    /// not heard from since it woke, one that does not hold the latest
    /// change, and one that had no room. And a change that could not be
    /// applied. A device that follows no phrase says nothing of a relay.
    #[test]
    fn test_what_the_node_says_of_its_relays_is_said() {
        let mut s = Several::new(1);
        let relay = |name: &str, holds, heard, no_room| AtRelay {
            relay: name.to_string(),
            holds_latest: holds,
            heard_since_woke: heard,
            no_room,
            another_form: 0,
            refuses: None,
        };
        let full = NoRoom {
            at: 1_800_000_000,
            over_allowance: true,
            of_the_change: false,
        };
        let mut at = AtRelays {
            relays: vec![
                relay("one.example:1", Some(true), true, None),
                relay("two.example:1", None, false, None),
                relay("three.example:1", Some(false), true, Some(full)),
            ],
            cannot_go_on: None,
        };
        let seen_at =
            |s: &Several, at: &AtRelays| look(&s[0].conn, &s[0].identity, at, s.now).unwrap();
        let none = seen_at(&s, &at);
        assert_eq!(none.relays.len(), 3);
        assert_eq!(none.says, [NO_PHRASE]);

        s.make_phrase(0);
        let look = seen_at(&s, &at);
        assert_eq!(
            look.says,
            [
                "has not heard from two.example:1 since it woke: a change made while it was \
                 off may not have reached it",
                "three.example:1 does not hold the latest change yet",
                "three.example:1 had no room for a new channel at 08:00 UTC on 2027-01-15 \
                 (this address is over its allowance of new channels there)",
            ]
        );
        assert_eq!(look.cannot_go_on, None);
        assert_eq!(look.relays[0].holds_latest, Some(true));
        assert!(!look.relays[1].heard_since_woke);

        // An entry of the device's own that a relay holds in another
        // form is said in a line, for that relay.
        at.relays[0].another_form = 1;
        at.relays[1].another_form = 3;
        let look = seen_at(&s, &at);
        assert!(
            look.says.contains(
                &"an entry of this device's own is at one.example:1 in another form: the file's \
              next edit goes above both"
                    .to_string()
            )
        );
        assert!(
            look.says.contains(
                &"3 entries of this device's own are at two.example:1 in another form: each \
              file's next edit goes above both"
                    .to_string()
            )
        );
        assert_eq!(look.relays[1].another_form, 3);
        at.relays[0].another_form = 0;
        at.relays[1].another_form = 0;
        // And a relay that holds a change which the device refuses.
        at.relays[0].refuses = Some("the statement undoes a removal".into());
        let look = seen_at(&s, &at);
        assert!(
            look.says.contains(
                &"one.example:1 holds a change that this device does not take (the statement \
              undoes a removal): this device neither sends there nor takes from there while \
              it does"
                    .to_string()
            )
        );
        at.relays[0].refuses = None;

        at.cannot_go_on = Some(CannotGoOn::NotApplied {
            relay: "one.example:1".into(),
            why: "the disk is full".into(),
        });
        let look = seen_at(&s, &at);
        assert_eq!(
            look.cannot_go_on.as_deref(),
            Some(
                "this device was answered with a change by one.example:1 and could not apply \
                 it (the disk is full): it sends nothing and takes nothing in a channel of its \
                 own, and tries again at each pass"
            )
        );
        assert_eq!(look.short.as_deref(), Some("a change could not be applied"));
    }

    /// A key that a person typed is shown with what became of it: the
    /// node asks until its hour ends, says when it was taken, and says
    /// when the hour has gone.
    #[test]
    fn test_a_typed_key_is_shown_with_what_became_of_it() {
        let s = Several::new(1);
        let (conn, key) = (&s[0].conn, [4u8; 32]);
        let seen_at = |now: i64| {
            look(conn, &s[0].identity, &AtRelays::default(), now)
                .unwrap()
                .accepting
        };
        acts::type_key(conn, &key, s.now).unwrap();
        let asking = seen_at(s.now + 10);
        assert_eq!(asking.len(), 1);
        assert!(asking[0].asking && !asking[0].taken);
        assert_eq!(asking[0].until, s.now + 3600);
        assert!(asking[0].says().starts_with(&format!(
            "asking for what the device ({}) hands over, until ",
            fingerprint::shown(&key)
        )));
        // The hour has gone.
        let gone = seen_at(s.now + 3600);
        assert!(!gone[0].asking && !gone[0].taken);
        assert!(gone[0].says().contains("has gone, and nothing was taken"));
        // Taken within it.
        acts::spend_typed_key(conn, &key, s.now, s.now + 20, "this device has joined").unwrap();
        let taken = seen_at(s.now + 30);
        assert!(taken[0].taken && !taken[0].asking);
        assert_eq!(
            taken[0].says(),
            format!(
                "accepted the device ({}): this device has joined",
                fingerprint::shown(&key)
            )
        );
        // A day on, it is said no more.
        assert!(seen_at(s.now + 24 * 3600).is_empty());
    }

    /// Once fewer than sixteen statements are left to a phrase, a look
    /// says how many: after statement 241, and not after statement 240.
    #[test]
    fn test_a_look_says_how_many_statements_are_left_once_fewer_than_sixteen_are() {
        assert_eq!(statements_left(1), None);
        assert_eq!(statements_left(240), None);
        assert_eq!(statements_left(241), Some(15));
        assert_eq!(statements_left(255), Some(1));
        assert_eq!(statements_left(256), Some(0));
        // A look says it of the statement applied.
        let mut s = Several::of_one_person(1);
        s.change(0, &[0], &[]);
        let look = seen(&s, 0);
        assert_eq!((look.change, look.statements_left), (Some(2), None));
    }
}
