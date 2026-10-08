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
//! The names that no device lists yet in the generation applied are here
//! too ([`crate::names::not_listed_yet`]), with whether each device says
//! that it has sent what it carried, and the files whose record a change
//! could not carry (§4.2, §7.3). What a device has still to send, by
//! name, is asked of what it keeps of each relay it reaches, and is the
//! caller's to add ([`crate::leaving::names_to_go`]).

use rusqlite::Connection;
use serde::Serialize;

use cordelia_core::protocol::{
    MAX_STATEMENT_NUMBER, PAIR_KEY_TYPED_SECS, STATEMENTS_LEFT_SAID_BELOW,
};
use cordelia_crypto::addition::SignedAddition;
use cordelia_crypto::bech32::{encode_channel_id, encode_public_key};
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
use cordelia_storage::meta;
use cordelia_storage::person::{self as held_rows, Kept, KeptAddition, State};
use cordelia_storage::sync_state;

use crate::adding::within_its_hour;
use crate::leaving::{Among, among, left_name};
use crate::names;
use crate::person::{
    Counting, Held, NotCounted, PersonError, applied_name, applied_secret, held, in_one,
    kept_entry, latest_entry, read_applied_word,
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

    /// The device in a sentence: its words and then its label, quoted, or
    /// its words alone where it has no label (decision 2026-10-04 §16).
    /// The label is whatever the device that added the key called it, and
    /// may hold brackets and words of the list: after the words, and in
    /// quotes, it cannot pass for the words of a fingerprint.
    pub fn named(&self) -> String {
        match self.label.is_empty() {
            true => format!("the device ({})", self.words),
            false => format!("({}) {:?}", self.words, self.label),
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
    /// Whether it says that it has sent what it carried when it applied
    /// the statement that this device has applied.
    pub sent: bool,
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
    /// As [`Listed::sent`].
    pub sent: bool,
    pub left: bool,
}

/// A name that a device had listed in a generation this device left, and
/// that no device lists yet in the one it has applied (decision
/// 2026-10-04 §7.3, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NameNotListed {
    pub name: String,
    /// The devices that had listed it and that count now.
    pub by: Vec<Shown>,
    /// The keys that had listed it and that count no longer. A name that
    /// only such keys had listed is shown apart, as that.
    pub by_gone: Vec<Shown>,
    /// How many days it can still be brought in for: the secret of the
    /// generation that listed it is kept for 90 days from when the device
    /// left it.
    pub days_left: i64,
}

/// A file whose record in a folder was dropped when the device applied
/// the statement (decision 2026-10-04 §4.2): the name it syncs under, and
/// the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct NotCarried {
    pub name: String,
    pub file: String,
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
    /// Its key, as a key is written, where a recovery left it out
    /// without showing it (decision 2026-10-04 §9, step 3): a person was
    /// shown it nowhere else, and nothing was asked of it. `None` for a
    /// key that was shown.
    pub key: Option<String>,
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
    /// When it was taken, in seconds, by this device's clock: when this
    /// device joined, or was handed a change, by that key. A command
    /// says nothing against a device that it has not heard from for the
    /// first minutes after it (decision 2026-10-04 §8).
    pub taken_at: Option<i64>,
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
    /// When that refusal was, in seconds, in UTC: a status counts it
    /// only while it is recent.
    pub no_room_at: Option<i64>,
    /// For how long the node has been connected to the relay, by its own
    /// clock, where it is: the node's route fills it in.
    pub connected_secs: Option<u64>,
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
    /// When this device applied it, in seconds, by its own clock, where
    /// it left a generation for it and still keeps that generation's
    /// secret: when it left. `None` on a device that has left none.
    pub applied_at: Option<i64>,
    /// Whether that statement removed a key that the statement which
    /// this device held before it did not, as the device found it when
    /// it applied the statement (decision 2026-10-04 §10.1). A renewal
    /// removes nobody, though it lists every key removed so far.
    pub removed_a_key: bool,
    /// What the change entry of that statement is named by, in hex: the
    /// latest that the device keeps. A command that made a change, and
    /// lost the node's answer, learns by it whether the node made it
    /// (§16).
    pub latest: Option<String>,
    /// The first words of the fingerprint of the key of the phrase that
    /// the device follows: what a person tells one phrase from another
    /// by.
    pub phrase_words: Option<String>,
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
    /// The names that no device lists yet in the generation applied, in
    /// order of name.
    pub names_not_listed: Vec<NameNotListed>,
    /// How many words of the personal channel, and names noted from a
    /// generation that was left, are no names as this version would map
    /// one (decision 2026-10-04 §16): they are counted, and never shown.
    pub names_not_shown: usize,
    /// The files whose record could not be carried when the device
    /// applied the statement, as it noted them then.
    pub not_carried: Vec<NotCarried>,
    /// Why the device cannot go on, where it cannot.
    pub cannot_go_on: Option<String>,
    /// A few words for a line of status, where there is something to
    /// say.
    pub short: Option<String>,
    /// What a status says, a sentence each.
    pub says: Vec<String>,
}

impl Look {
    /// The keys of the devices that have said that they left (decision
    /// 2026-10-04 §5.2, §7.1): of the statement's, and of those added
    /// since. A command that makes a change asks about each.
    pub fn said_left(&self) -> Vec<&str> {
        let listed = self.devices.iter().filter(|device| device.left);
        let added = self.added.iter().filter(|device| device.left);
        listed
            .map(|device| device.device.key.as_str())
            .chain(added.map(|device| device.device.key.as_str()))
            .collect()
    }
}

/// The second and third ways on for a machine that follows no phrase
/// (decision 2026-10-04 §5.1, §9), each on a line of its own: it is
/// added from a machine that has the phrase; or, where every device that
/// has the phrase is lost, a person recovers here with it. **No new
/// phrase is made first there:** `cordelia recover` refuses a machine
/// that follows a phrase.
macro_rules! add_or_recover {
    () => {
        "  - Another machine has the phrase: add this one from it (`cordelia add-device` \
         there, `cordelia accept` here).\n  - Every device that has the phrase is lost: recover \
         here with it (`cordelia recover`). Do not make a new phrase first."
    };
}

/// The three ways on for a machine that follows no phrase, as a new
/// install says them ([`WAYS_ON`]).
macro_rules! ways_on {
    () => {
        concat!(
            "  - This is your first machine: make a phrase here (`cordelia phrase`).\n",
            add_or_recover!()
        )
    };
}

/// The three ways on for a machine that follows no phrase, in the order
/// in which they are always said (decision 2026-10-04 §5.2, §5.1, §9),
/// each on a line of its own: a phrase is made here, on a person's first
/// machine; the machine is added from one that has the phrase; or a
/// person who has lost every device recovers here.
pub const WAYS_ON: &str = ways_on!();

/// What the statement of a device that follows no phrase says of itself
/// (decision 2026-10-04 §5.2): that it has none, and then the three ways
/// on ([`WAYS_ON`]).
pub const NO_PHRASE: &str = concat!(
    "no recovery phrase yet: memory stays on this machine.\n",
    ways_on!()
);

/// What is said in a few words of a device that follows no phrase and
/// took this version with what an earlier one held (decision 2026-10-04
/// §10, §10.1): its database was moved on, and it is to be added again.
pub const NOT_ADDED_YET: &str = "not added yet";

/// What such a device says of itself: that it is not added yet, and the
/// three ways on, in the order of [`WAYS_ON`]. The first begins on the
/// machine whose memory is the most up to date (decision 2026-10-04 §10,
/// steps 3 to 5).
pub const NOT_ADDED: &str = concat!(
    "not added yet: this device has taken a version of Cordelia in which every device is added \
     again, and memory stays on this machine until it is.\n",
    "  - No machine has a phrase yet: make it on the one whose memory is the most up to date \
     (`cordelia phrase`).\n",
    add_or_recover!()
);

/// What is said in a few words of a device that follows no phrase and
/// held nothing of an earlier version: a new install (decision
/// 2026-10-04 §5.2).
pub const NO_PHRASE_YET: &str = "no recovery phrase yet";

/// Whether the step of the first start on this version was made on this
/// database (decision 2026-10-04 §10.1): the device took this version
/// with what an earlier one held, and everything of the older kind went.
pub fn moved_on(conn: &Connection) -> Result<bool, cordelia_core::CordeliaError> {
    Ok(cordelia_storage::first_start::mark(conn)?.is_some_and(|mark| mark.stepped))
}

/// What a device that follows no phrase says of itself, in a few words
/// and in full (decision 2026-10-04 §10.1): "not added yet" where the
/// step of the first start was made (`moved_on`), and the words for a
/// new install where it was not. In full it is a sentence and then the
/// three ways on, each on a line of its own.
pub fn no_phrase_says(moved_on: bool) -> (&'static str, &'static str) {
    match moved_on {
        true => (NOT_ADDED_YET, NOT_ADDED),
        false => (NO_PHRASE_YET, NO_PHRASE),
    }
}

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
            applied_at: None,
            removed_a_key: false,
            latest: None,
            phrase_words: None,
            statements_left: None,
            devices: Vec::new(),
            added: Vec::new(),
            removed: Vec::new(),
            left_out: Vec::new(),
            apart: None,
            relays: relays(at_relays),
            accepting: accepting(conn, now)?,
            notices: Vec::new(),
            names_not_listed: Vec::new(),
            names_not_shown: 0,
            not_carried: Vec::new(),
            cannot_go_on: None,
            short: None,
            says: Vec::new(),
        };
        match held(conn)? {
            None => {
                let (short, says) = no_phrase_says(moved_on(conn)?);
                look.short = Some(short.into());
                // Where it stands, and then each way on, on a line of
                // its own: a status prints what is said a line each.
                look.says.extend(says.lines().map(str::to_string));
            }
            Some(held) => {
                of_its_person(conn, identity, &held, at_relays, &mut look)?;
                of_its_names(conn, &held, now, &mut look)?;
            }
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
        // What became of a key that was taken is said only while it is
        // so (decision 2026-10-04 §5.1): a device that was removed since,
        // or is in no list of the last change, has joined nobody. The key
        // is kept, and is still listed with what became of it.
        let stopped = matches!(look.state, "removed" | "not_listed");
        for typed in &look.accepting {
            if !(typed.taken && stopped) {
                look.says.push(typed.says());
            }
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
    // It left the generation before when it applied this one.
    let left = held_rows::secrets(conn)?;
    look.applied_at = left.iter().filter_map(|secret| secret.left_at).max();
    look.removed_a_key = meta::get(conn, meta::PERSON_REMOVED_A_KEY)?.is_some();
    look.latest = Some(hex::encode(latest_entry(conn)?.id()));
    look.phrase_words = Some(fingerprint::shown(&held.following.phrase_key));
    look.statements_left = statements_left(statement.number);

    // A word "left" that was kept across a statement counts as the word
    // in this generation's personal channel does (§7.1).
    let kept_left: Vec<[u8; 32]> = acts::left_words(conn)?
        .iter()
        .map(|word| word.key)
        .collect();
    for device in &statement.devices {
        look.devices.push(Listed {
            device: Shown::of(&device.key, &device.label)?,
            this_device: device.key == own,
            maker: device.key == statement.maker,
            applied: reader.applied(conn, &device.key)?,
            sent: reader.sent(conn, &device.key)?,
            left: reader.left(conn, &device.key)?.is_some() || kept_left.contains(&device.key),
        });
    }
    // A statement lists a removed key bare: it is shown by what this
    // device called it, where it knew it by a label.
    let labels = removed_labels(conn)?;
    for key in &statement.removed {
        let label = labels.iter().find(|(known, _)| known == key);
        look.removed
            .push(Shown::of(key, label.map_or("", |(_, label)| label))?);
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
            sent: reader.sent(conn, &shown.key)?,
            left: reader.left(conn, &shown.key)?.is_some(),
        });
    }

    let never_shown = not_shown(conn)?;
    for shown in acts::left_out(conn)? {
        // One whose notice a person cleared is shown no more.
        if shown.cleared_at.is_some() {
            continue;
        }
        let key = match never_shown.contains(&shown.key) {
            true => Some(Shown::of(&shown.key, "")?.key),
            false => None,
        };
        look.left_out.push(LeftOutKey {
            label: shown.label,
            words: fingerprint::shown(&shown.key),
            number: shown.number,
            key,
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

/// What is said of the things that a device lists as names and that are
/// no names as this version would map one (decision 2026-10-04 §16):
/// their number, and nothing of what they hold.
pub fn names_not_shown(how_many: usize) -> String {
    format!(
        "{} that cannot be shown {} listed by a device: what {} called is not a name as this \
         version writes one",
        counted(how_many, "name"),
        if how_many == 1 { "is" } else { "are" },
        if how_many == 1 { "it is" } else { "they are" },
    )
}

/// What a device that follows a phrase holds of the names of its person
/// that are not all in the generation it has applied (decision 2026-10-04
/// §4.2, §7.3, §8): the names that no device lists there yet, and the
/// files whose record could not be carried. A device that has stopped
/// says nothing of either: it is in no generation to bring a name into.
fn of_its_names(
    conn: &Connection,
    held: &Held,
    now: i64,
    look: &mut Look,
) -> Result<(), PersonError> {
    if held.state != State::Applied {
        return Ok(());
    }
    let statement = &held.statement.statement;
    let kept = held_rows::additions(conn)?;
    let reader = Reader::of(conn, statement, &kept)?;
    let shown = |keys: &[[u8; 32]]| -> Result<Vec<Shown>, PersonError> {
        keys.iter()
            .map(|key| Shown::of(key, &reader.label(key)))
            .collect()
    };
    for name in names::not_listed_yet(conn)? {
        look.names_not_listed.push(NameNotListed {
            by: shown(&name.by)?,
            by_gone: shown(&name.by_gone)?,
            days_left: (name.until.saturating_sub(now) / (24 * 60 * 60)).max(0),
            name: name.name,
        });
    }
    look.not_carried = not_carried(conn)?;
    // What a device listed that is no name: said as a number, and not
    // shown.
    let not_names: usize = names::not_names(conn)?.iter().map(|(_, words)| words).sum();
    look.names_not_shown = not_names + names::not_names_before(conn)?;
    if look.names_not_shown > 0 {
        look.says.push(names_not_shown(look.names_not_shown));
    }

    let (ours, gone): (Vec<&NameNotListed>, Vec<&NameNotListed>) = look
        .names_not_listed
        .iter()
        .partition(|name| !name.by.is_empty());
    let named = |names: &[&NameNotListed]| {
        let each: Vec<&str> = names.iter().map(|name| name.name.as_str()).collect();
        each.join(", ")
    };
    let days = |names: &[&NameNotListed]| names.iter().map(|name| name.days_left).min();
    if let Some(days) = days(&ours) {
        look.says.push(format!(
            "{} that your devices synced before the last change {} listed by no device yet: \
             {}. What the relays hold of {} can still be brought in for {days} day{}",
            counted(ours.len(), "name"),
            if ours.len() == 1 { "is" } else { "are" },
            named(&ours),
            if ours.len() == 1 { "it" } else { "them" },
            if days == 1 { "" } else { "s" },
        ));
    }
    if let Some(days) = days(&gone) {
        look.says.push(format!(
            "{} that only a device which no longer counts had synced {} listed by no device: \
             {}. {} behind, and can still be brought in for {days} day{}",
            counted(gone.len(), "name"),
            if gone.len() == 1 { "is" } else { "are" },
            named(&gone),
            if gone.len() == 1 {
                "It stays"
            } else {
                "They stay"
            },
            if days == 1 { "" } else { "s" },
        ));
    }
    if !look.not_carried.is_empty() {
        let each: Vec<String> = look
            .not_carried
            .iter()
            .map(|file| format!("{} in {}", name_shown(&file.file), file.name))
            .collect();
        look.says.push(format!(
            "what this device held of {} could not be read at the last change, and was not \
             carried: {}. Each meets its channel as a new file does",
            counted(each.len(), "file"),
            each.join(", ")
        ));
    }
    Ok(())
}

/// A file's name as far as it is put in a line that is shown (decision
/// 2026-10-04 §16): its first characters, and a mark where it was cut.
/// Another device may have written the name, at any length. (What a
/// command prints of it, it prints with control characters shown as
/// escapes.)
pub fn name_shown(name: &str) -> String {
    use cordelia_core::protocol::FILE_NAME_SHOWN_CHARS;
    let mut shown: String = name.chars().take(FILE_NAME_SHOWN_CHARS).collect();
    if shown.len() < name.len() {
        shown.push_str("...");
    }
    shown
}

/// A count with its noun: `1 name`, `3 names`.
fn counted(n: usize, noun: &str) -> String {
    match n {
        1 => format!("1 {noun}"),
        n => format!("{n} {noun}s"),
    }
}

/// The files whose record could not be carried when this device applied
/// its statement, as it noted them then ([`note_not_carried`]).
fn not_carried(conn: &Connection) -> Result<Vec<NotCarried>, PersonError> {
    Ok(meta::get(conn, meta::PERSON_NOT_CARRIED)?
        .and_then(|noted| serde_json::from_str(&noted).ok())
        .unwrap_or_default())
}

/// Note the files whose record could not be carried at the statement
/// that this device has just applied, for `cordelia devices` to say
/// (decision 2026-10-04 §4.2). What was noted at the statement before is
/// replaced. A file goes from the note once it has met its channel
/// ([`clear_not_carried_that_met`]).
pub(crate) fn note_not_carried(
    conn: &Connection,
    files: &[(String, String)],
) -> Result<(), PersonError> {
    if files.is_empty() {
        meta::remove(conn, meta::PERSON_NOT_CARRIED)?;
        return Ok(());
    }
    let noted: Vec<NotCarried> = files
        .iter()
        .map(|(name, file)| NotCarried {
            name: name.clone(),
            file: file.clone(),
        })
        .collect();
    let noted = serde_json::to_string(&noted)
        .map_err(|e| PersonError::Held(format!("the files that were not carried: {e}")))?;
    meta::set(conn, meta::PERSON_NOT_CARRIED, &noted)?;
    Ok(())
}

/// What this device called each key that a statement it applied
/// removed, where it knew the key by a label (decision 2026-10-04 §7.3,
/// §8): a statement lists removed keys bare.
pub fn removed_labels(conn: &Connection) -> Result<Vec<([u8; 32], String)>, PersonError> {
    let kept: std::collections::BTreeMap<String, String> =
        meta::get(conn, meta::PERSON_REMOVED_LABELS)?
            .and_then(|kept| serde_json::from_str(&kept).ok())
            .unwrap_or_default();
    Ok(kept
        .into_iter()
        .filter_map(|(key, label)| {
            let key: [u8; 32] = hex::decode(key).ok()?.try_into().ok()?;
            Some((key, label))
        })
        .collect())
}

/// Keep what this device called each of `removed`, keys that the
/// statement it has just applied removes, beside what it kept of those
/// removed before (decision 2026-10-04 §7.3). `statement` is that
/// statement: a label is kept only of a key that it lists as removed, and
/// what is kept of a key that it does not list so goes. An empty label is
/// none.
pub(crate) fn note_removed_labels(
    conn: &Connection,
    statement: &Statement,
    removed: &[([u8; 32], String)],
) -> Result<(), PersonError> {
    let mut kept = removed_labels(conn)?;
    for (key, label) in removed {
        if !label.is_empty() && !kept.iter().any(|(known, _)| known == key) {
            kept.push((*key, label.clone()));
        }
    }
    kept.retain(|(key, _)| statement.removes(key));
    if kept.is_empty() {
        meta::remove(conn, meta::PERSON_REMOVED_LABELS)?;
        return Ok(());
    }
    let as_kept: std::collections::BTreeMap<String, &String> = kept
        .iter()
        .map(|(key, label)| (hex::encode(key), label))
        .collect();
    let as_kept = serde_json::to_string(&as_kept)
        .map_err(|e| PersonError::Held(format!("the labels of the removed keys: {e}")))?;
    meta::set(conn, meta::PERSON_REMOVED_LABELS, &as_kept)?;
    Ok(())
}

/// The keys that a recovery made on this machine left out without
/// showing them (decision 2026-10-04 §9, step 3), as it noted them
/// ([`note_not_shown`]).
pub fn not_shown(conn: &Connection) -> Result<Vec<[u8; 32]>, PersonError> {
    let kept: Vec<String> = meta::get(conn, meta::PERSON_NOT_SHOWN)?
        .and_then(|kept| serde_json::from_str(&kept).ok())
        .unwrap_or_default();
    Ok(kept
        .iter()
        .filter_map(|key| hex::decode(key).ok()?.try_into().ok())
        .collect())
}

/// Note the keys that the recovery which was just made on this machine
/// left out without showing them (decision 2026-10-04 §9, step 3), so
/// that `cordelia devices` shows each with its key: a person was shown
/// it nowhere else. What was noted before is replaced.
pub(crate) fn note_not_shown(conn: &Connection, keys: &[[u8; 32]]) -> Result<(), PersonError> {
    if keys.is_empty() {
        meta::remove(conn, meta::PERSON_NOT_SHOWN)?;
        return Ok(());
    }
    let as_kept: Vec<String> = keys.iter().map(hex::encode).collect();
    let as_kept = serde_json::to_string(&as_kept)
        .map_err(|e| PersonError::Held(format!("the keys that were not shown: {e}")))?;
    meta::set(conn, meta::PERSON_NOT_SHOWN, &as_kept)?;
    Ok(())
}

/// Keep whether the statement that this device has just applied removes
/// a key that the statement before did not, for a status to go by
/// (decision 2026-10-04 §10.1). What was kept at the statement before is
/// replaced.
pub(crate) fn note_removed_a_key(conn: &Connection, removes: bool) -> Result<(), PersonError> {
    match removes {
        true => meta::set(conn, meta::PERSON_REMOVED_A_KEY, "1")?,
        false => meta::remove(conn, meta::PERSON_REMOVED_A_KEY)?,
    }
    Ok(())
}

/// Drop from the note of the files that were not carried
/// ([`note_not_carried`]) each file that has met its channel since
/// (decision 2026-10-04 §4.2): a folder has a record of it in the channel
/// of the name it syncs under, so the file was published there as this
/// device's own, or took the version that the channel had. Returns how
/// many went.
///
/// **A file goes only where its name is held and the file has met its
/// channel.** A name that is not held at the end of a cycle may be one
/// that could not be held in that cycle, for an error: its files have
/// met nothing, and stay noted. A name that the device stops on purpose
/// takes its files out of the note there ([`forget_not_carried_of`]).
///
/// The sync adapter does so at the end of a cycle. Until then the file is
/// said in `cordelia devices` and in a status, and no longer than that:
/// not until the next change.
pub fn clear_not_carried_that_met(conn: &Connection) -> Result<usize, PersonError> {
    in_one(conn, || {
        let noted = not_carried(conn)?;
        if noted.is_empty() {
            return Ok(0);
        }
        let mut still: Vec<(String, String)> = Vec::new();
        for file in &noted {
            let met = match held_rows::channel_of_name(conn, &file.name)? {
                Some(channel) => {
                    let written = encode_channel_id(&channel)?;
                    let recorded = sync_state::files(conn, &written)?;
                    recorded.iter().any(|(_, key)| *key == file.file)
                }
                None => false,
            };
            if !met {
                still.push((file.name.clone(), file.file.clone()));
            }
        }
        if still.len() != noted.len() {
            note_not_carried(conn, &still)?;
        }
        Ok(noted.len() - still.len())
    })
}

/// Note no longer the files under `name` whose record could not be
/// carried ([`note_not_carried`]): the device has stopped the name, and
/// none of them has a channel to meet here. Returns how many went.
pub(crate) fn forget_not_carried_of(conn: &Connection, name: &str) -> Result<usize, PersonError> {
    let noted = not_carried(conn)?;
    let still: Vec<(String, String)> = noted
        .iter()
        .filter(|file| file.name != name)
        .map(|file| (file.name.clone(), file.file.clone()))
        .collect();
    if still.len() != noted.len() {
        note_not_carried(conn, &still)?;
    }
    Ok(noted.len() - still.len())
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
        Ok(self.applied_word(conn, key)?.map(|(number, _)| number))
    }

    /// Whether the device says that it has sent what it carried when it
    /// applied the statement that this device has applied (decision
    /// 2026-10-04 §8). A word of another statement says nothing of this
    /// one.
    fn sent(&self, conn: &Connection, key: &[u8; 32]) -> Result<bool, PersonError> {
        Ok(self.applied_word(conn, key)? == Some((self.number, true)))
    }

    /// The device's word that it has applied a statement: the number, and
    /// whether it has sent what it carried.
    fn applied_word(
        &self,
        conn: &Connection,
        key: &[u8; 32],
    ) -> Result<Option<(u64, bool)>, PersonError> {
        Ok(match self.word(conn, key, &applied_name(key)?)? {
            Some((_, Value::Text(word))) => read_applied_word(&word),
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
    /// The key whose word "left" is kept no more, where the notice is of
    /// a word that was kept across a statement.
    kept_left: Option<[u8; 32]>,
}

/// What is said of a device that has said it left (decision 2026-10-04
/// §5.2).
fn left_says(device: &Shown) -> String {
    format!(
        "{} left, and started again under another phrase. It still holds the secret it had, \
         and is still listed: removing it, with the phrase, is what cuts it off (`cordelia \
         remove-device`)",
        device.named()
    )
}

/// Keep each device's word that it left across the statement that this
/// device applies at `now` (decision 2026-10-04 §7.1): the word is in the
/// personal channel of the generation that is left, which is read no
/// more. It is called in the transaction that applies `statement`, before
/// anything of the statement `leaving` is dropped.
///
/// A word is kept where the new statement still lists its device's key,
/// and nobody had cleared its notice here. A word that was kept at an
/// earlier statement stays for as long as each statement since lists the
/// key: it goes once one does not.
pub(crate) fn keep_left_words(
    conn: &Connection,
    identity: &NodeIdentity,
    leaving: &Statement,
    statement: &Statement,
    now: i64,
) -> Result<(), PersonError> {
    let own = identity.public_key();
    let kept = held_rows::additions(conn)?;
    let reader = Reader::of(conn, leaving, &kept)?;
    let mut keys: Vec<[u8; 32]> = leaving.devices.iter().map(|device| device.key).collect();
    for record in &kept {
        if !keys.contains(&record.key) {
            keys.push(record.key);
        }
    }
    for key in keys.iter().filter(|key| **key != own) {
        let Some(id) = reader.left(conn, key)? else {
            continue;
        };
        if statement.lists(key) && !acts::is_cleared(conn, &id)? {
            acts::note_left(conn, key, &id, leaving.number, now)?;
        }
    }
    for word in acts::left_words(conn)? {
        if !statement.lists(&word.key) {
            acts::clear_left(conn, &word.key)?;
        }
    }
    Ok(())
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
        kept_left: None,
    };
    // Each record of an addition (§6). A record for a key that the
    // statement lists adds no device, and tells of none: a device that
    // is handed the change again is handed it with no record.
    for record in kept.iter().filter(|record| !statement.lists(&record.key)) {
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
        let says = left_says(&Shown::of(key, &reader.label(key))?);
        all.push(tell(id, "left", says, None));
    }
    // Each word "left" that was kept across a statement (§7.1): its
    // device is still listed, and nobody has cleared it here. A device
    // whose word in this generation is shown above is shown once.
    for word in acts::left_words(conn)? {
        let shown_above = reader.left(conn, &word.key)?.is_some();
        if word.key == own || shown_above || !statement.lists(&word.key) {
            continue;
        }
        let says = left_says(&Shown::of(&word.key, &reader.label(&word.key))?);
        let mut told = tell(word.notice, "left", says, None);
        told.kept_left = Some(word.key);
        all.push(told);
    }
    // Each key that is not in the last change (§8), but those whose
    // notice a person cleared.
    let shown_left_out = acts::left_out(conn)?
        .into_iter()
        .filter(|shown| shown.cleared_at.is_none());
    let never_shown = not_shown(conn)?;
    for shown in shown_left_out {
        let of_it = Shown::of(&shown.key, &shown.label)?;
        let says = match never_shown.contains(&shown.key) {
            false => format!(
                "{} is not in the last change: add it again, or it was meant to go",
                of_it.named()
            ),
            // A row that the recovery could not show: its key is said,
            // since a person was shown it nowhere else (§9, step 3).
            true => format!(
                "{} is not in the last change, and the recovery could not show it or ask                  about it: its key is {}",
                of_it.named(),
                of_it.key
            ),
        };
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
        match (told.left_out, told.kept_left) {
            (Some(key), _) => {
                acts::clear_left_out(conn, &key, now)?;
            }
            (None, Some(key)) => {
                acts::clear_left(conn, &key)?;
            }
            (None, None) => acts::clear_notice(conn, &told.id, now)?,
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
            no_room_at: relay.no_room.map(|refused| refused.at),
            connected_secs: None,
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
            taken_at: typed.taken_at,
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

    /// A device is named by the words of its key's fingerprint first, and
    /// its label after them, quoted (decision 2026-10-04 §16): a label
    /// that holds brackets and words puts none ahead of the real ones.
    #[test]
    fn test_a_device_is_named_by_its_words_first_and_its_label_quoted() {
        let key = crate::several::Machine::new(3).key();
        let words = fingerprint::shown(&key);
        let named = |label: &str| Shown::of(&key, label).unwrap().named();
        assert_eq!(named("laptop"), format!("({words}) \"laptop\""));
        assert_eq!(named(""), format!("the device ({words})"));
        assert_eq!(
            named("laptop (acid acid acid acid)\" (zoo"),
            format!("({words}) \"laptop (acid acid acid acid)\\\" (zoo\"")
        );
    }

    /// A device that follows no phrase says so, in the words of the
    /// decision, and in two words for a line.
    #[test]
    fn test_a_device_that_follows_no_phrase_says_so() {
        let s = Several::new(1);
        let look = seen(&s, 0);
        assert_eq!((&look.latest, &look.phrase_words), (&None, &None));
        assert_eq!(look.state, "no_phrase");
        assert_eq!(look.among, "no_phrase");
        assert_eq!(look.short.as_deref(), Some("no recovery phrase yet"));
        // Where it stands, and then the three ways on, each on a line of
        // its own and in this order: a phrase is made here; the machine
        // is added from one that has the phrase; or a person who has
        // lost every device recovers here, and makes no new phrase
        // first.
        let add = "  - Another machine has the phrase: add this one from it (`cordelia \
                   add-device` there, `cordelia accept` here).";
        let recover = "  - Every device that has the phrase is lost: recover here with it \
                       (`cordelia recover`). Do not make a new phrase first.";
        assert_eq!(
            look.says,
            [
                "no recovery phrase yet: memory stays on this machine.",
                "  - This is your first machine: make a phrase here (`cordelia phrase`).",
                add,
                recover,
            ]
        );
        assert_eq!(look.says.join("\n"), NO_PHRASE);
        assert_eq!(look.says[1..].join("\n"), WAYS_ON);
        // Where the device took this version with what an earlier one
        // held, and the step of its first start was made: it is not
        // added yet (decision 2026-10-04 §10.1).
        assert!(!moved_on(&s[0].conn).unwrap());
        cordelia_storage::first_start::step(&s[0].conn, "0.2.0-test", chrono::Utc::now()).unwrap();
        assert!(moved_on(&s[0].conn).unwrap());
        let look = seen(&s, 0);
        assert_eq!(look.state, "no_phrase");
        assert_eq!(look.short.as_deref(), Some("not added yet"));
        // The same three ways, in the same order: the first begins on
        // the machine whose memory is the most up to date.
        assert_eq!(
            look.says,
            [
                "not added yet: this device has taken a version of Cordelia in which every \
                 device is added again, and memory stays on this machine until it is.",
                "  - No machine has a phrase yet: make it on the one whose memory is the most \
                 up to date (`cordelia phrase`).",
                add,
                recover,
            ]
        );
        assert_eq!(look.says.join("\n"), NOT_ADDED);
        // A mark that says there was nothing to step is a new install's.
        let fresh = Several::new(1);
        cordelia_storage::first_start::first_start(
            &fresh[0].conn,
            std::path::Path::new("/no/such/folder"),
            "0.2.0-test",
            chrono::Utc::now(),
            &cordelia_storage::first_start::room_not_known,
            &mut None,
        )
        .unwrap();
        assert!(!moved_on(&fresh[0].conn).unwrap());
        assert_eq!(
            seen(&fresh, 0).short.as_deref(),
            Some("no recovery phrase yet")
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
        // What the change entry of that statement is named by, and the
        // words that the phrase's key is told by.
        assert_eq!(look.latest, Some(hex::encode(s[0].latest().id())));
        assert_ne!(look.latest, seen(&s, 1).latest);
        assert_eq!(
            look.phrase_words,
            Some(fingerprint::shown(&s.phrase.public_key().unwrap()))
        );
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
                "new device: ({}) \"device 1\", added from ({}) \"device 0\"",
                words(1),
                words(0)
            )
        );
        // The new device says it of itself.
        assert_eq!(
            seen(&s, 1).notices[0].says,
            format!("this device was added from ({}) \"device 0\"", words(0))
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

        // A statement that lists them ends the notices everywhere, and
        // what a person cleared under the statement before is kept no
        // more.
        assert!(acts::is_cleared(&s[0].conn, &id).unwrap());
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        for n in 0..3 {
            assert!(seen(&s, n).notices.is_empty(), "{n}");
            assert!(seen(&s, n).added.is_empty(), "{n}");
        }
        assert!(!acts::is_cleared(&s[0].conn, &id).unwrap());
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
                .any(|n| n.says.starts_with("new device: (")
                    && n.says.contains(") \"device 10\", added from"))
        );
        // Device 9 counts, and may add nothing: its own look says so.
        // Device 0, which the statement lists, may.
        let nines = super::look(&nine.conn, &nine.identity, &AtRelays::default(), now).unwrap();
        assert_eq!((nines.state, nines.may_add), ("applied", false));
        assert!(seen(&s, 0).may_add);

        // A record for a key that the statement lists adds no device:
        // it is kept, is not listed as a device added since, and tells
        // of nothing.
        let told_before = seen(&s, 0).notices.len();
        let again = cordelia_crypto::addition::Addition::under(
            statement,
            cordelia_crypto::statement::Device::new(s.key(0), "the first again").unwrap(),
            s.key(1),
            now as u64,
        )
        .unwrap()
        .sign(&s[1].identity)
        .unwrap();
        let kept_before = held_rows::additions(&s[0].conn).unwrap().len();
        crate::person::see_addition(&s[0].conn, &again, now).unwrap();
        assert_eq!(
            held_rows::additions(&s[0].conn).unwrap().len(),
            kept_before + 1
        );
        let look = seen(&s, 0);
        assert!(
            look.added
                .iter()
                .all(|a| a.device.label != "the first again")
        );
        assert_eq!(look.notices.len(), told_before);
    }

    /// The keys that the statement removed are listed. A statement lists
    /// them bare: each is shown with the label that this device knew it
    /// by when it applied the statement that removed it (decision
    /// 2026-10-04 §7.3), and with none on a device that never knew it.
    #[test]
    fn test_the_keys_that_the_statement_removed_are_listed() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1], &[2]);
        let look = seen(&s, 0);
        assert_eq!(look.removed.len(), 1);
        assert_eq!(look.removed[0].key, encode_public_key(&s.key(2)).unwrap());
        assert_eq!(look.removed[0].words, fingerprint::shown(&s.key(2)));
        assert_eq!(look.removed[0].label, "device 2");
        assert_eq!(look.devices.len(), 2);
        assert_eq!(
            removed_labels(&s[0].conn).unwrap(),
            [(s.key(2), "device 2".to_string())]
        );
        // The label is kept across a later change, for as long as the
        // statement lists the key as removed.
        s.change(0, &[0, 1], &[]);
        assert_eq!(seen(&s, 0).removed[0].label, "device 2");
        // A device that leaves forgets them with everything else.
        let now = s.tick();
        crate::leaving::forget(&s[0].conn, &s[0].identity, false, now).unwrap();
        assert!(removed_labels(&s[0].conn).unwrap().is_empty());
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
                "({}) \"device 2\" is not in the last change: add it again, or it was meant to go",
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
        // It is kept, cleared (decision 2026-10-04 §16): adding that key
        // on device 1 still says that it was not in the last change, and
        // under which label this device knew it.
        let kept = acts::left_out(&s[1].conn).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].key, kept[0].cleared_at), (s.key(2), Some(now)));
        let would =
            crate::adding::would_add(&s[1].conn, &s[1].identity, &s.key(2), "device 2").unwrap();
        assert_eq!(
            would,
            crate::adding::WouldAdd::Adds {
                counts_already: false,
                left_out_as: Some("device 2".into()),
            }
        );
        // Cleared once: there is no such notice to clear again.
        assert_eq!(clear(&s[1].conn, &s[1].identity, &id, now).unwrap(), None);

        // A later statement that lists it ends it on device 0: here, as
        // removed.
        let removal = s.change(0, &[0, 1], &[2]);
        let look = seen(&s, 0);
        assert!(look.left_out.is_empty() && look.notices.is_empty());
        assert_eq!(look.removed.len(), 1);
        // And on device 1, where it was kept cleared: nothing is kept of
        // a key that a statement lists.
        give(&mut s, 1, &removal);
        assert!(acts::left_out(&s[1].conn).unwrap().is_empty());
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
        // The device that left is told nothing of itself.
        assert!(seen(&s, 2).notices.is_empty());
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
                    "({}) \"device 2\" left, and started again under another phrase. It still \
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

    /// A device's word that it left outlives the next change, for as long
    /// as its key is listed and nobody has cleared it (decision
    /// 2026-10-04 §7.1): on the device that makes the change, and on one
    /// that applies it later. The word itself is in the personal channel
    /// of the generation that was left, which nobody reads again.
    #[test]
    fn test_a_word_that_a_device_left_outlives_a_change_until_it_is_cleared() {
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let now = s.tick();
        let word = begin(&s[2].conn, &s[2].identity, now)
            .unwrap()
            .word
            .unwrap();
        for n in [0, 1] {
            give(&mut s, n, &word);
            assert_eq!(kinds(&seen(&s, n)), ["left"]);
        }
        let told = seen(&s, 0).notices[0].clone();
        let key_of_2 = seen(&s, 0).devices[2].device.key.clone();
        assert_eq!(seen(&s, 0).said_left(), [key_of_2.as_str()]);

        // Device 1 makes a change that still lists device 2.
        let change = s.change(1, &[0, 1, 2], &[]);
        let after = seen(&s, 1);
        assert_eq!(after.change, Some(3));
        assert_eq!(after.notices, std::slice::from_ref(&told));
        assert!(after.devices[2].left);
        assert_eq!(after.said_left(), [key_of_2.as_str()]);
        // Device 0 applies it later: the word is still shown there.
        give(&mut s, 0, &change);
        assert_eq!(seen(&s, 0).change, Some(3));
        assert_eq!(seen(&s, 0).notices, std::slice::from_ref(&told));
        assert!(seen(&s, 0).devices[2].left);

        // A person clears it on device 0: it is shown there no more, and
        // is still shown on device 1.
        let id: [u8; 32] = hex::decode(&told.id).unwrap().try_into().unwrap();
        let now = s.tick();
        let cleared = clear(&s[0].conn, &s[0].identity, &id, now).unwrap();
        assert_eq!(cleared, Some(told.clone()));
        assert_eq!(clear(&s[0].conn, &s[0].identity, &id, now).unwrap(), None);
        assert!(seen(&s, 0).notices.is_empty());
        assert!(!seen(&s, 0).devices[2].left);
        assert!(seen(&s, 0).said_left().is_empty());
        assert_eq!(kinds(&seen(&s, 1)), ["left"]);

        // A change later that lists it still: kept where it was kept, and
        // not shown again where it was cleared.
        let change = s.change(1, &[0, 1, 2], &[]);
        give(&mut s, 0, &change);
        assert_eq!(seen(&s, 1).notices, std::slice::from_ref(&told));
        assert!(seen(&s, 0).notices.is_empty());
        // And one that lists it no more: the word goes with the device.
        s.change(1, &[0, 1], &[2]);
        assert!(seen(&s, 1).notices.is_empty());
        assert!(acts::left_words(&s[1].conn).unwrap().is_empty());

        // A word that a person had cleared before a change is not kept
        // across it.
        let mut s = Several::of_one_person(3);
        s.change(0, &[0, 1, 2], &[]);
        s.meet(&[0, 1, 2]);
        let now = s.tick();
        let word = begin(&s[2].conn, &s[2].identity, now)
            .unwrap()
            .word
            .unwrap();
        give(&mut s, 0, &word);
        let id: [u8; 32] = hex::decode(&seen(&s, 0).notices[0].id)
            .unwrap()
            .try_into()
            .unwrap();
        clear(&s[0].conn, &s[0].identity, &id, now).unwrap();
        s.change(0, &[0, 1, 2], &[]);
        assert!(seen(&s, 0).notices.is_empty());
        assert!(!seen(&s, 0).devices[2].left);
        assert!(acts::left_words(&s[0].conn).unwrap().is_empty());
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
                "this device is not in a change made on ({}) \"device 0\": if it is yours, add it \
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
        assert_eq!(none.says.join("\n"), NO_PHRASE);

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
        acts::type_key(conn, &key, "no_phrase", s.now).unwrap();
        let asking = seen_at(s.now + 10);
        assert_eq!(asking.len(), 1);
        assert!(asking[0].asking && !asking[0].taken);
        assert_eq!(asking[0].taken_at, None);
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
        // When it was taken is said with it.
        assert_eq!(taken[0].taken_at, Some(s.now + 20));
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

    /// What became of a typed key that was taken ("this device has
    /// joined") is said in a status only while it is so (decision
    /// 2026-10-04 §5.1): a device that was removed since, or is in no
    /// list of the last change, has joined nobody. The key is kept, and
    /// is still listed with what became of it.
    #[test]
    fn test_a_joining_is_not_said_once_the_device_has_stopped() {
        for removed in [true, false] {
            let mut s = Several::of_one_person(3);
            let now = s.tick();
            let from = s.key(0);
            acts::type_key(&s[2].conn, &from, "no_phrase", now).unwrap();
            acts::spend_typed_key(&s[2].conn, &from, now, now, "this device has joined").unwrap();
            let joined = format!(
                "accepted the device ({}): this device has joined",
                fingerprint::shown(&from)
            );
            let before = seen(&s, 2);
            assert_eq!(before.state, "applied");
            assert!(before.says.contains(&joined), "{:?}", before.says);

            // It is removed, or left out of the next change.
            let change = match removed {
                true => s.change(0, &[0, 1], &[2]),
                false => s.change(0, &[0, 1], &[]),
            };
            give(&mut s, 2, &change);
            let after = seen(&s, 2);
            let stands = if removed { "removed" } else { "not_listed" };
            assert_eq!(after.state, stands);
            assert!(
                after.says.iter().all(|line| !line.contains("has joined")),
                "{stands}: {:?}",
                after.says
            );
            assert_eq!(after.says[0], after.cannot_go_on.clone().unwrap());
            // Nothing was deleted: the key is listed as it was.
            assert_eq!(after.accepting.len(), 1, "{stands}");
            assert!(after.accepting[0].taken, "{stands}");
            assert_eq!(after.accepting[0].says(), joined);
        }
        // A key that is still asked for is said, wherever the device
        // stands: that is so now.
        let mut s = Several::of_one_person(3);
        let now = s.tick();
        acts::type_key(&s[2].conn, &s.key(0), "no_phrase", now).unwrap();
        let change = s.change(0, &[0, 1], &[2]);
        give(&mut s, 2, &change);
        let asking = seen(&s, 2);
        assert_eq!(asking.state, "removed");
        assert!(
            asking
                .says
                .iter()
                .any(|line| line.starts_with("asking for what the device (")),
            "{:?}",
            asking.says
        );
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

    /// A file's name is put in a line of the status only as far as its
    /// first characters, with a mark where it was cut (decision
    /// 2026-10-04 §16): another device may have written it, at any
    /// length.
    #[test]
    fn test_a_files_name_is_cut_where_it_is_put_in_a_line() {
        use cordelia_core::protocol::FILE_NAME_SHOWN_CHARS;
        assert_eq!(FILE_NAME_SHOWN_CHARS, 120);
        assert_eq!(name_shown("notes.md"), "notes.md");
        // Characters are counted, and not bytes.
        let just = "\u{e9}".repeat(FILE_NAME_SHOWN_CHARS);
        assert_eq!(name_shown(&just), just);
        let long = format!("{just}x.md");
        assert_eq!(name_shown(&long), format!("{just}..."));

        let mut s = Several::new(1);
        s.make_phrase(0);
        note_not_carried(&s[0].conn, &[("lab".into(), long.clone())]).unwrap();
        let look = seen(&s, 0);
        assert_eq!(look.not_carried[0].file, long);
        let line = look
            .says
            .iter()
            .find(|line| line.contains("was not carried"))
            .expect("the look says what was not carried");
        assert!(line.contains(&format!("{just}... in lab")), "{line}");
        assert!(!line.contains("x.md"), "{line}");
    }
}
