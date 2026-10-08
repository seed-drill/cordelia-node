//! `cordelia recover`: a person who has no device left that they trust
//! types their recovery phrase on a new machine (decision 2026-10-04
//! §9).
//!
//! The command goes in the order that §9 gives:
//!
//! 1. It says first that a removal from a device that remains is the
//!    better way, and whose words a recovery phrase is. It is refused on
//!    a device that already follows a phrase. It then asks for the
//!    phrase, and reads the phrase's own channel at every relay that the
//!    machine is set up with, saying which it could not reach: the phrase
//!    proves that channel's key, which no device can.
//! 2. It takes the change entry with the highest number whose signatures
//!    hold and whose secret opens to its statement's commitment. Where
//!    another was handed that is not on that one's chain, the two were
//!    made apart: it shows both lists, asks which to recover from, and
//!    the statement it makes settles them.
//! 3. It reads that generation's personal channel and shows every
//!    device, each with the first words of its key's fingerprint and how
//!    much it signed there: the statement's devices first, always; then
//!    the keys added since that count; then the records that do not
//!    count; 256 rows in all. It says first where the answers could not
//!    all be kept: a statement has room for 256 removed keys. Of each
//!    device that counts it asks one of three things: the person still
//!    has it, it is lost or broken, or it may be in someone else's
//!    hands. No answer is suggested. A record that does not count is
//!    shown as that, and nothing is asked of it: unless it fails only
//!    for the bound of 64 counted devices, and a device of the statement
//!    signed it that was not said to be in someone else's hands. Such a
//!    key is asked about all the same: nothing is taken from it, and
//!    said to be gone it is removed.
//! 4. It shows the statement from the bytes that the phrase will sign
//!    (this machine as the only device, and as removed every device that
//!    is gone), the names that will be carried, and from whom the look
//!    takes; asks its yes; signs and seals; and hands the node the change
//!    entry. The node applies it and shows it to every relay at once,
//!    before anything is carried.
//! 5. The look is made once, by the node. The command goes on in a new
//!    process, which never held the phrase ([`recover_made`]): it stays
//!    until the look has ended, and says what it found.
//! 6. Each device that the person still has is added again by hand: the
//!    command says how.
//!
//! **The phrase stays in this process** (§5). It is typed with echo off,
//! proves the phrase's channel, opens the part of each change entry that
//! is for it, signs the statement, seals, signs a word for the look, and
//! is dropped before the node is handed anything. What crosses to the
//! node: proofs of a channel's key, each made for one connection; the
//! change entry; the phrase's statement key, which every device that
//! follows the phrase is given; the word for the look; and **the secrets
//! of the generation recovered from and of those before it,** which the
//! machine keeps as a device keeps a secret it left (§3, §9).

use std::time::Duration;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use cordelia_api::carry::{self, Allows, Word};
use cordelia_api::change::{prepare_recovery, read_with};
use cordelia_api::look::lists_of;
use cordelia_api::person::PersonError;
use cordelia_api::recover::{self, Answer, Candidate, Generation, Row};
use cordelia_core::protocol::{
    MAX_COUNTED_DEVICES, MAX_STATEMENT_REMOVED, RECOVERY_MAX_DEVICES_SHOWN, RECOVERY_MAX_NAMES,
};
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::statement::{Device, Statement, StatementError};
use cordelia_crypto::{derive, fingerprint};

use crate::carry_cmd::{Sessions, entries_handed, read_with_secret};
use crate::person_cmd::{
    NOT_A_YES, counted, default_label, file_shown, list, look, made_all_the_same, named,
    names_this_device, own_key, text, time_of, typed_phrase,
};
use crate::terminal::Terminal;
use crate::{Told, api_post_told, api_post_told_of, refuse_before_a_phrase, wipe_strings};

/// What `cordelia recover` says before it asks for anything (decision
/// 2026-10-04 §9).
const A_REMOVAL_IS_BETTER: &str = "\
Recovery is for when you have no device left that you trust. If a device of yours remains, do
not recover: remove the device that is gone from it (`cordelia remove-device <key>` there). That
stops nobody else, and each device that remains carries what it holds.

A recovery stops every other device of yours until each is added again by hand, and brings back
what the relays hold: a relay is a cache, and not a backup.";

/// Whose words a recovery phrase is, said where one is asked for at a
/// recovery (decision 2026-10-04 §5).
const WHOSE_WORDS: &str = "\
The recovery phrase is twelve words: Cordelia's recovery phrase for your devices. The words are
from the list that a wallet's seed phrase uses, and are no wallet's: never type a wallet's words
here, and never type these into a wallet.";

/// The three answers, as they are said before the first is asked.
const THREE_ANSWERS: &str = "\
Of each, say one of three things. No answer is suggested: each is typed.
  `have`   you still have it. It stops when it hears of this recovery, and is added again from
           this machine by hand, with its key read from the device itself.
  `lost`   it is lost or broken. Its key is removed, and what it wrote is brought back.
  `hands`  it may be in someone else's hands. Its key is removed, and nothing that it wrote is
           brought back by this recovery, nor what a device that it added wrote. That comes in
           only by `cordelia sync carry <name> --from <device>`, with the phrase, which says
           what it means.";

/// What is said of a record that does not count, in the place of a
/// question (decision 2026-10-04 §9, step 3). `removed` is whether the
/// change recovered from, or one made apart from it that the recovery
/// settles, lists the record's key as removed: a removed key stays
/// removed in every change after, and in the one that this recovery
/// makes.
fn not_asked_says(removed: bool) -> &'static str {
    match removed {
        false => {
            "  It is no device: nothing is asked of it, nothing that it wrote is brought \
             back, and its key is not removed."
        }
        true => {
            "  It is no device: nothing is asked of it, and nothing that it wrote is brought \
             back. Its key was removed before this recovery, and stays removed."
        }
    }
}

/// What is said, in the place of nothing, of a key that is asked about
/// though it does not count (decision 2026-10-04 §9, step 3): its record
/// fails only for the bound of 64 counted devices, and a device of the
/// statement signed it that was not said to be in someone else's hands
/// ([`recover::asked_for_room`]). What each answer does is another thing
/// for it than for a device that counts.
const ASKED_FOR_ROOM: &str = "  That is the one thing its record fails for, so it is asked \
    about all the same. Nothing that it wrote is brought back by this recovery, whatever is said \
    of it: `lost` or `hands` removes its key, and what it wrote then comes in by `cordelia sync \
    carry <name> --from <device>`, with the phrase; `have` leaves it to be added again by hand.";

/// What is said of a key that is asked about for the bound of 64 alone,
/// before its answer is asked: what is said of any row ([`row_says`]),
/// and what the answers do for it ([`ASKED_FOR_ROOM`]). `under` is the
/// device of the statement for whose record it is asked about: where
/// the row shows another that added it, this one is named too.
fn for_room_says(rows: &[Row], at: usize, number: u64, under: &[u8; 32]) -> String {
    let mut says = row_says(rows, at, number);
    if rows[at].added_by.is_some_and(|(shown, _)| shown != *under) {
        let label = rows.iter().find(|row| row.key == *under);
        let label = label.map(|row| row.label.as_str()).unwrap_or_default();
        says.push_str(&format!("\n  {} added it too.", named(label, under)));
    }
    format!("{says}\n{ASKED_FOR_ROOM}")
}

/// What is said before the first question where the answers could not
/// all be kept (decision 2026-10-04 §9, step 3): a statement has room for
/// 256 removed keys, and lists every key removed so far.
fn room_says(room: &recover::Room) -> Option<String> {
    if room.for_every_answer() {
        return None;
    }
    Some(format!(
        "\nNot every answer could be kept. A change has room for {MAX_STATEMENT_REMOVED} removed \
         keys, and lists every key removed so far: {} removed already, and {} asked about \
         here. At most {} of them can be said to be gone (`lost` or `hands`). Where more are, the \
         change cannot be made, and nothing is done.",
        match room.removed {
            1 => "1 is".to_string(),
            n => format!("{n} are"),
        },
        match room.asked {
            1 => "1 device is".to_string(),
            n => format!("{n} devices are"),
        },
        room.can_go
    ))
}

/// The command that a recovery goes on to when its change is made:
/// [`recover_made`], in a process of its own.
pub const MADE_COMMAND: &str = "recover-made";

/// How long the node is waited for where it reads at the relays.
const READ_WAITS: Duration = Duration::from_secs(60);

/// What the node answered, or its refusal as this command's own error.
fn told(asked: anyhow::Result<Told>) -> anyhow::Result<Value> {
    match asked? {
        Told::Yes(answer) => Ok(answer),
        Told::No { message, .. } => anyhow::bail!("{message}\nNothing was made."),
    }
}

/// Read the channel whose secret is `secret` at every relay, through the
/// node, and say of which relay it could not be read to its end. The
/// proofs are made over `sessions`: where a connection has changed since
/// those were said, they are asked for again, and the proofs are made
/// again ([`read_with_secret`], decision 2026-10-04 §16). Returns what
/// was handed, and what the node says of each relay.
fn read_channel(
    config_path: &str,
    secret: &[u8; 32],
    sessions: &mut Sessions,
    own: &[u8; 32],
    what: &str,
) -> anyhow::Result<(Vec<CheckedEntry>, Vec<Value>)> {
    let (entries, relays) = read_with_secret(config_path, secret, sessions, own)?;
    for (relay, read) in not_read_to_its_end(&relays) {
        println!("  Could not read {what} at {relay} to its end ({read}).");
    }
    Ok((entries, relays))
}

/// The relays at which a channel could not be read to its end, of what
/// the node says of each relay: each by its name.
fn not_read_at(relays: &[Value]) -> Vec<String> {
    let not_read = not_read_to_its_end(relays);
    not_read.into_iter().map(|(relay, _)| relay).collect()
}

/// Of what the node says of each relay, those at which a channel could
/// not be read to its end, with what is said of each: a relay that
/// handed the channel whole, or holds none of it, is not among them.
fn not_read_to_its_end(relays: &[Value]) -> Vec<(String, String)> {
    relays
        .iter()
        .filter(|relay| !matches!(text(relay, "read"), "whole" | "not held"))
        .map(|relay| (text(relay, "relay").into(), text(relay, "read").into()))
        .collect()
}

/// What is said where no change of the phrase was found (decision
/// 2026-10-04 §9, §16). Where every relay that was reached was read to
/// its end, none of them holds one. **Where one could not be read, that
/// is what is said, with the relay's name:** it is never said to hold
/// none for that.
fn none_found_says(not_read: &[String]) -> String {
    if not_read.is_empty() {
        return "no relay that was reached holds a change of this recovery phrase: there is \
                nothing to recover from. Either these are not the words of your devices' phrase, \
                or the relays have dropped what they held: a relay keeps what nobody has used \
                for 90 days, and no longer. Nothing was done."
            .to_string();
    }
    format!(
        "the recovery phrase's own channel could not be read to its end at {}, and no change of \
         this recovery phrase was found in what was read: whether a relay holds one is not \
         known. Run `cordelia recover` again. Nothing was done.",
        not_read.join(", ")
    )
}

/// What a recovery knows of one relay for a personal channel that it
/// read there (decision 2026-10-04 §16): one of four things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadAs {
    /// The relay handed the channel to its end.
    Whole,
    /// The relay handed one entry of the channel at least, and the read
    /// did not reach the channel's end.
    Part,
    /// The relay holds none of the channel.
    NotHeld,
    /// Nothing is known of what the relay holds: it was not reached, or
    /// the read ended before any entry of the channel was handed.
    Nothing,
}

/// Which of the four things the node's word of a relay is ([`ReadAs`]).
/// **A read that the node calls `part` handed an entry only where the
/// node says that it did:** it says how many entries of the channel
/// each relay handed, and a read in part with none is one of which
/// nothing is known. A relay that handed an entry at one reading, and
/// was not read to its end, was read in part, whatever was said of it at
/// a later reading.
fn read_as(relay: &Value) -> ReadAs {
    match (text(relay, "read"), entries_handed(relay)) {
        ("whole", _) => ReadAs::Whole,
        (_, 1..) => ReadAs::Part,
        ("not held", _) => ReadAs::NotHeld,
        _ => ReadAs::Nothing,
    }
}

/// What a recovery read of the personal channel of the change that it
/// recovers from, relay by relay (decision 2026-10-04 §16): each relay
/// that the node said anything of, by its name, in the node's order,
/// with which of the four things is known of it and what the node said
/// of the read there.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct PersonalRead {
    relays: Vec<(String, ReadAs, String)>,
}

impl PersonalRead {
    fn of(relays: &[Value]) -> Self {
        let of = |relay: &Value| {
            let (name, said) = (text(relay, "relay"), text(relay, "read"));
            (name.to_string(), read_as(relay), said.to_string())
        };
        Self {
            relays: relays.iter().map(of).collect(),
        }
    }

    /// The relays of which `known` is what is known, each by its name.
    fn at(&self, known: &[ReadAs]) -> Vec<String> {
        let relays = self.relays.iter();
        let of_those = relays.filter(|(_, read, _)| known.contains(read));
        of_those.map(|(relay, _, _)| relay.clone()).collect()
    }

    /// Whether any relay is one of which `known` is what is known.
    fn any(&self, known: ReadAs) -> bool {
        self.relays.iter().any(|(_, read, _)| *read == known)
    }
}

/// What a recovery is refused with, before it asks anything, where
/// nothing is known of the personal channel of the change it recovers
/// from, numbered `number` (decision 2026-10-04 §9, step 3; §16): **no
/// relay handed an entry of it, and none said that it holds none of
/// it.** Each relay was not reached, or its read ended with nothing: the
/// refusal names each, with what was said of it, and says to run the
/// command again.
///
/// `None` wherever something is known at one relay at least: the channel
/// was read there to its end or in part, or the relay holds none of it.
/// The command then goes on with what it could read, and says before its
/// yes what it could not ([`WasRead::lines`]).
fn personal_not_read_says(number: u64, read: &PersonalRead) -> Option<String> {
    let known = [ReadAs::Whole, ReadAs::Part, ReadAs::NotHeld];
    if known.iter().any(|known| read.any(*known)) {
        return None;
    }
    let each: Vec<String> = read
        .relays
        .iter()
        .map(|(relay, _, said)| match said.as_str() {
            "part" => format!("{relay} (the read ended before any entry of it was handed)"),
            said => format!("{relay} ({said})"),
        })
        .collect();
    let at = match each.is_empty() {
        true => "the node said nothing of any relay".to_string(),
        false => each.join(", "),
    };
    Some(format!(
        "nothing of the personal channel of change {number} was read at any relay: {at}. No relay \
         handed an entry of it, and none said that it holds none of it: which devices were added \
         since that change, and which names they sync, is not known. Run `cordelia recover` \
         again. Nothing was done."
    ))
}

/// What a recovery says before its yes of a device that is missing from
/// what it read (decision 2026-10-04 §9, step 3; §16): it is not asked
/// about, and nothing that it wrote is brought back until its key is
/// removed. The key is written whole for both commands: `cordelia
/// remove-device` takes a key that is in no list of the last change, and
/// `cordelia sync carry --from` then names that removed key by it.
const A_MISSING_DEVICE: &str = "A device that is missing is not asked about here, and nothing \
    that it wrote is brought back until its key is removed: `cordelia remove-device <key>` on \
    this machine, and then `cordelia sync carry <name> --from <key>`, with the phrase.";

/// What a recovery says before its yes of a name that is missing from
/// what it read (decision 2026-10-04 §9, step 5; §16). A carry that asks
/// for no phrase takes what keys that count signed, and after a recovery
/// this machine alone counts: so what a device that is gone wrote under
/// the name comes in by the command that names its removed key, with the
/// phrase, and what a device that the person still has holds of it comes
/// once that device is added again.
const A_MISSING_NAME: &str = "A name that is missing is not carried. What a device that is gone \
    wrote under it comes in by `cordelia sync carry <name> --from <device>`, with the phrase; \
    what a device that you still have holds of it comes once that device is added again and a \
    folder here is mapped to the name.";

/// What a recovery read of the personal channels, for what it says
/// before its yes of what it could not read (decision 2026-10-04 §16).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct WasRead {
    /// The number of the change recovered from.
    number: u64,
    /// Its personal channel, relay by relay.
    personal: PersonalRead,
    /// The personal channels of the generations before, which are read
    /// for names: each that was not read to its end at every relay, by
    /// its change's number, with the relays at which it was not.
    before: Vec<(u64, Vec<String>)>,
}

impl WasRead {
    /// Whether everything that the recovery read for was read to its
    /// end: the personal channel of the change recovered from at one
    /// relay at least, with no relay at which it was read in part or
    /// not at all, and each personal channel of a generation before.
    /// Only then is a name that is not listed said to be listed nowhere.
    fn to_the_end(&self) -> bool {
        let of = &self.personal;
        of.any(ReadAs::Whole)
            && !of.any(ReadAs::Part)
            && !of.any(ReadAs::Nothing)
            && self.before.is_empty()
    }

    /// What is said before the yes of what could not be read (decision
    /// 2026-10-04 §16), in lines. None where everything was read to its
    /// end ([`Self::to_the_end`]).
    ///
    /// - **Read to its end at one relay, and not at every relay:** at
    ///   which it was not, and that devices added since, and names, may
    ///   be missing.
    /// - **Read to its end at no relay, and in part at one at least:**
    ///   at which relays in part, and at which not at all; that devices
    ///   added since, and names, may be missing from what was read, and
    ///   what a read in part may be a sign of; and what that costs, for
    ///   a device and for a name, with the commands.
    /// - **No relay that answered holds the channel:** that, and at
    ///   which relays it was not read; and what that costs.
    /// - **A personal channel of a generation before** that was not read
    ///   to its end: at which relays, by the change's number.
    fn lines(&self) -> Vec<String> {
        let (number, of) = (self.number, &self.personal);
        let mut lines = Vec::new();
        let part = of.at(&[ReadAs::Part]);
        let nothing = of.at(&[ReadAs::Nothing]);
        if of.any(ReadAs::Whole) {
            let not_to_the_end = of.at(&[ReadAs::Part, ReadAs::Nothing]);
            if !not_to_the_end.is_empty() {
                lines.push(format!(
                    "The personal channel of the change recovered from could not be read to its \
                     end at {}: devices added since that change, and names, may be missing here.",
                    not_to_the_end.join(", ")
                ));
            }
        } else if !part.is_empty() {
            let not_at_all = match nothing.is_empty() {
                true => String::new(),
                false => format!(", and not at all at {}", nothing.join(", ")),
            };
            let none_held = match of.at(&[ReadAs::NotHeld]).as_slice() {
                [] => String::new(),
                [one] => format!(" {one} holds none of it."),
                more => format!(" {} hold none of it.", more.join(", ")),
            };
            lines.push(format!(
                "The personal channel of change {number} was read to its end at no relay: in part \
                 at {}{not_at_all}.{none_held} Devices added since that change, and names, may be \
                 missing from what was read. What a person's own devices write there is small: a \
                 read that does not reach the end may be a sign that a device of that change \
                 filled the channel.",
                part.join(", ")
            ));
            lines.push(A_MISSING_DEVICE.to_string());
            lines.push(A_MISSING_NAME.to_string());
        } else {
            let not_read = match nothing.is_empty() {
                true => String::new(),
                false => format!(" It was not read at {}.", nothing.join(", ")),
            };
            lines.push(format!(
                "No relay that answered holds the personal channel of change {number}: which \
                 devices were added since that change, and which names they sync, is not \
                 known.{not_read}"
            ));
            lines.push(A_MISSING_DEVICE.to_string());
            lines.push(A_MISSING_NAME.to_string());
        }
        for (before, not_read) in &self.before {
            lines.push(format!(
                "The personal channel of change {before}, which is read for names, could not be \
                 read to its end at {}: names that are listed only there may be missing.",
                not_read.join(", ")
            ));
        }
        lines
    }
}

/// What is said of two changes that were made apart, before the person
/// says which to recover from (decision 2026-10-04 §9, step 2):
/// `on_neither` is how many more changes the relays hold that are on the
/// chain of neither of the two. And what the recovery does with the two:
/// **what the devices of the other had not sent comes back only by
/// adding them again.**
fn apart_lines(on_neither: usize) -> Vec<String> {
    let mut lines = Vec::new();
    if on_neither > 0 {
        lines.push(format!(
            "{} besides those is on neither's chain, and is not settled by this recovery.",
            match on_neither {
                1 => "1 more change".to_string(),
                n => format!("{n} more changes"),
            }
        ));
    }
    lines.push(
        "The recovery is made from one of them, and the change it makes settles the two: every \
         key that either removed stays removed. The devices of the other that are not asked \
         about here are in no list after it, and what they had written and not sent to a relay \
         comes back only by adding them again."
            .to_string(),
    );
    lines
}

/// A statement's lists, a line each, read from the statement: each key
/// with the first four words of its fingerprint.
fn lists_lines(statement: &Statement, own: &[u8; 32]) -> anyhow::Result<Vec<String>> {
    let lists = lists_of(statement)?;
    let mut out = vec![format!("  made on {}", lists.made_on.named())];
    out.push(format!("  devices ({}):", lists.devices.len()));
    for (device, listed) in lists.devices.iter().zip(&statement.devices) {
        let this = match listed.key == *own {
            true => "  (this machine)",
            false => "",
        };
        out.push(format!("    {}{this}", device.named()));
    }
    if !statement.removed.is_empty() {
        out.push(format!("  removed keys ({}):", statement.removed.len()));
    }
    for key in &statement.removed {
        out.push(format!("    ({})", fingerprint::shown(key)));
    }
    Ok(out)
}

/// What is said of one device before its answer is asked (decision
/// 2026-10-04 §9, step 3): its words and its label, whether the
/// statement lists it or who added it since and when, and how much it
/// signed in the personal channel. A record that does not count is said
/// to be one, and where it fails only for the bound of 64 counted
/// devices, that is said.
fn row_says(rows: &[Row], at: usize, number: u64) -> String {
    let row = &rows[at];
    let label_of = |key: &[u8; 32]| {
        let known = rows.iter().find(|row| row.key == *key);
        known.map(|row| row.label.clone()).unwrap_or_default()
    };
    let whose = match row.added_by {
        None => format!("a device of change {number}"),
        Some((adder, at)) => format!(
            "added since change {number}, from {} at {}{}",
            named(&label_of(&adder), &adder),
            time_of(at),
            match (row.counts, row.no_room.is_empty()) {
                (true, _) => String::new(),
                (false, true) => ", by a record that does not count".to_string(),
                (false, false) => format!(
                    ", by a record that does not count: {MAX_COUNTED_DEVICES} devices counted \
                     already"
                ),
            }
        ),
    };
    format!(
        "\n{}, {whose}. It signed {} in the personal channel of that change.",
        named(&row.label, &row.key),
        counted(row.signed, "entry").replace("entrys", "entries")
    )
}

/// Ask one of the three things of a device. **No answer is suggested:**
/// pressing Enter answers nothing. Where the input ends at the question,
/// the command is refused.
fn asks_of(at: &Terminal, says: &str) -> anyhow::Result<Answer> {
    loop {
        let typed = at.answer(&format!("{says}\n  Type `have`, `lost` or `hands`: "))?;
        match typed.as_deref() {
            Some("have") => return Ok(Answer::Have),
            Some("lost") => return Ok(Answer::Lost),
            Some("hands") => return Ok(Answer::OtherHands),
            Some(_) => println!("  That is none of the answers. No answer is suggested: type one."),
            None => anyhow::bail!("the input ended before an answer was typed. Nothing was made."),
        }
    }
}

/// What a recovery will do, said before its yes (decision 2026-10-04
/// §9): from whom the look takes and from whom it takes nothing; the
/// names that are carried, and those that are left; and what stops.
///
/// `was_read` is what was read of the personal channels, relay by relay.
/// **What could not be read is said here** ([`WasRead::lines`], decision
/// 2026-10-04 §16): of the change recovered from, and of the generations
/// before, which are read for names. Where anything could not, no name
/// is said to be listed nowhere: none is listed in what was read.
fn will_do_lines(
    generation: &Generation,
    answers: &[Answer],
    names: &recover::Names,
    own: &[u8; 32],
    was_read: &WasRead,
) -> Vec<String> {
    let rows = &generation.rows;
    let taken = recover::takes(rows, answers);
    let mut lines = Vec::new();
    let shown = |keys: Vec<&Row>| -> String {
        let all: Vec<String> = keys.iter().map(|row| named(&row.label, &row.key)).collect();
        all.join(", ")
    };
    let from: Vec<&Row> = rows
        .iter()
        .filter(|row| taken.contains(&row.key) && row.key != *own)
        .collect();
    // From a device that may be in someone else's hands, and from what
    // it added; and from a key that does not count, which was asked
    // about for the bound of 64 alone and said to be gone.
    let gone = recover::gone(rows, answers);
    let nothing: Vec<&Row> = rows
        .iter()
        .enumerate()
        .filter(|(at, row)| {
            let nothing = match row.counts {
                true => recover::in_other_hands(rows, answers, *at),
                false => gone.contains(&row.key),
            };
            nothing && row.key != *own
        })
        .map(|(_, row)| row)
        .collect();
    match from.is_empty() {
        true => lines.push(
            "\nNothing that those devices wrote is brought back by this recovery. What a device \
             that may be in someone else's hands wrote comes in only by `cordelia sync carry \
             <name> --from <device>`, with the phrase, which says what that means."
                .to_string(),
        ),
        false => lines.push(format!(
            "\nThe look takes what these wrote, as the relays hold it now: {}.",
            shown(from)
        )),
    }
    if !nothing.is_empty() {
        lines.push(format!(
            "It takes nothing from: {}. What they wrote comes in only by `cordelia sync carry \
             <name> --from <device>`. Until then, a version of another device's that one of them \
             had written over is what is carried.",
            shown(nothing)
        ));
    }
    if !generation.not_shown.is_empty() {
        lines.push(format!(
            "{} more could not be shown: the look takes nothing from those, each is in no list, \
             and this machine keeps each as left out: `cordelia devices` shows it with its key.",
            counted(generation.not_shown.len(), "record of an addition")
                .replace("record of an additions", "records of additions")
        ));
    }
    let said = |all: &[String]| -> String {
        let all: Vec<String> = all.iter().map(|name| file_shown(name)).collect();
        all.join(", ")
    };
    match names.carried.is_empty() {
        true => lines.push(match was_read.to_the_end() {
            true => "No name is carried: none is listed.".to_string(),
            false => "No name is carried: none is listed in what was read.".to_string(),
        }),
        false => lines.push(format!(
            "{} carried: {}.",
            match names.carried.len() {
                1 => "1 name is".to_string(),
                n => format!("{n} names are"),
            },
            said(&names.carried)
        )),
    }
    lines.extend(was_read.lines());
    if !names.over_the_bound.is_empty() {
        lines.push(format!(
            "{} left, beyond the {RECOVERY_MAX_NAMES} that a recovery carries: {}.",
            match names.over_the_bound.len() {
                1 => "1 name is".to_string(),
                n => format!("{n} names are"),
            },
            said(&names.over_the_bound)
        ));
    }
    if !names.only_other_hands.is_empty() {
        lines.push(format!(
            "{} left, which only a device listed from which nothing is taken, or a key that \
             does not count: {}.",
            match names.only_other_hands.len() {
                1 => "1 name is".to_string(),
                n => format!("{n} names are"),
            },
            said(&names.only_other_hands)
        ));
    }
    lines.push(
        "Every other device of yours stops when it hears of this change. Each that you still \
         have is added again from this machine, by hand."
            .to_string(),
    );
    lines
}

/// `cordelia recover` (see the module's documentation).
pub fn recover(config_path: &str, name: Option<String>) -> anyhow::Result<()> {
    let at = Terminal::for_a_phrase()?;
    refuse_before_a_phrase(config_path)?;
    let own = own_key(config_path)?;
    let asked = told(api_post_told(
        config_path,
        "/api/v1/recover/look",
        json!({}),
        Some(READ_WAITS),
    ))?;
    names_this_device(&asked, &own)?;
    if asked["follows_a_phrase"] != false {
        anyhow::bail!(
            "this device already follows a recovery phrase: `cordelia recover` is for a machine \
             that follows none. If a device of yours is gone, remove it from here (`cordelia \
             remove-device <key>`). Nothing was done."
        );
    }
    println!("{A_REMOVAL_IS_BETTER}\n\n{WHOSE_WORDS}");
    let label = name.unwrap_or_else(default_label);
    // A label that a statement would refuse is refused before the
    // phrase is asked for.
    let maker = Device::new(own, &label)?;

    // The relays that the machine is set up with, and which is reached.
    let mut sessions: Sessions = Vec::new();
    for relay in list(&asked, "sessions") {
        match relay["session"].as_str().and_then(carry::key_named) {
            Some(session) => sessions.push((text(relay, "relay").to_string(), session)),
            None => println!(
                "\nCould not reach {}: what it holds is not read.",
                text(relay, "relay")
            ),
        }
    }
    if sessions.is_empty() {
        anyhow::bail!(
            "no relay is reached: there is nothing to recover from until one is. Nothing was \
             done."
        );
    }

    // 1. The phrase, and its own channel at every relay.
    let phrase = typed_phrase(&at)?;
    println!("Reading the recovery phrase's own channel at each relay...");
    let (handed, not_read) = {
        let secret = phrase.channel_secret()?;
        let (handed, relays) = read_channel(config_path, &secret, &mut sessions, &own, "it")?;
        (handed, not_read_at(&relays))
    };

    // 2. The change entry with the highest number, of those whose
    //    signatures hold and whose secret opens to the commitment.
    let candidates: Vec<Candidate> = handed
        .into_iter()
        .filter_map(|entry| {
            let (statement, _) = read_with(&phrase, &entry).ok()?;
            Some(Candidate { entry, statement })
        })
        .collect();
    let Some(found) = recover::found(candidates) else {
        anyhow::bail!("{}", none_found_says(&not_read));
    };
    let (from, apart) = match found.second() {
        None => (found.from.clone(), None),
        Some((other, on_neither)) => {
            println!(
                "\nTwo changes were made apart: the relays hold one that is not on the other's \
                 chain. Each is shown from its signed bytes."
            );
            for (n, candidate) in [(1, &found.from), (2, other)] {
                let statement = &candidate.statement.statement;
                println!("\n{n}. Change {}:", statement.number);
                for line in lists_lines(statement, &own)? {
                    println!("{line}");
                }
            }
            for line in apart_lines(on_neither) {
                println!("\n{line}");
            }
            loop {
                let typed = at.answer("  Type `1` or `2`, the one to recover from: ")?;
                match typed.as_deref() {
                    Some("1") => break (found.from.clone(), Some(other.clone())),
                    Some("2") => break (other.clone(), Some(found.from.clone())),
                    Some(_) => println!("  That is neither. No answer is suggested: type one."),
                    None => anyhow::bail!(
                        "the input ended before an answer was typed. Nothing was made."
                    ),
                }
            }
        }
    };

    // 3. That generation's personal channel, and every device.
    let (_, for_phrase) = read_with(&phrase, &from.entry).map_err(not_this_phrases)?;
    let statement = from.statement.statement.clone();
    let statement_key = phrase.statement_key()?;
    println!(
        "\nRecovering from change {}. Reading its personal channel at each relay...",
        statement.number
    );
    let (generation, personal_read) = {
        let personal = Zeroizing::new(derive::personal_secret(&for_phrase.secret)?);
        let what = "the personal channel";
        let (handed, relays) = read_channel(config_path, &personal, &mut sessions, &own, what)?;
        // It goes on with what it could read. Where no relay handed an
        // entry of the channel, and none said that it holds none of it,
        // nothing is known, and nothing is asked.
        let personal_read = PersonalRead::of(&relays);
        if let Some(refusal) = personal_not_read_says(statement.number, &personal_read) {
            anyhow::bail!("{refusal}");
        }
        let now = chrono::Utc::now().timestamp();
        let read =
            recover::read_generation(&from, &statement_key, &for_phrase.secret, &handed, now)?;
        (read, personal_read)
    };
    let rows = &generation.rows;
    println!(
        "\nThe devices of change {}, and those added since, each with the first words of its \
         key's fingerprint. A label is what the device that added it called it: the words are \
         what tells two apart.\n\n{THREE_ANSWERS}",
        statement.number
    );
    // Before anything is asked: whether the answers could all be kept.
    let apart_statement = apart.as_ref().map(|other| &other.statement.statement);
    if let Some(says) = room_says(&recover::room(&statement, apart_statement, rows, &own)) {
        println!("{says}");
    }
    let mut answers: Vec<Answer> = Vec::new();
    for at_row in 0..rows.len() {
        let says = row_says(rows, at_row, statement.number);
        if rows[at_row].key == own {
            println!("{says}\n  It is this machine: it is the one device of the change.");
            answers.push(Answer::Have);
            continue;
        }
        // A record that does not count is shown as that, and nothing is
        // asked of it: unless only the bound of 64 kept its key out, and
        // a device of the statement signed it that was not said to be
        // in someone else's hands.
        if !rows[at_row].counts {
            let Some((under, _)) = recover::asked_for_room(rows, &answers, at_row) else {
                let key = &rows[at_row].key;
                let removed = statement.removes(key)
                    || apart_statement.is_some_and(|other| other.removes(key));
                println!("{says}\n{}", not_asked_says(removed));
                answers.push(Answer::NotAsked);
                continue;
            };
            let says = for_room_says(rows, at_row, statement.number, &under);
            answers.push(asks_of(&at, &says)?);
            continue;
        }
        let mut says = says;
        // What was said of the device that added it bears on it.
        let adders_answer = rows[at_row]
            .added_by
            .and_then(|(adder, _)| rows.iter().position(|row| row.key == adder))
            .is_some_and(|adder| {
                let mut so_far = answers.clone();
                so_far.push(Answer::Have);
                recover::in_other_hands(rows, &so_far, adder)
            });
        if adders_answer {
            says.push_str(
                "\n  It was added by a device that may be in someone else's hands: nothing that \
                 it wrote is brought back, whatever is said of it.",
            );
        }
        answers.push(asks_of(&at, &says)?);
    }
    if !generation.not_shown.is_empty() {
        println!(
            "\n{} beyond the {RECOVERY_MAX_DEVICES_SHOWN} that are shown: nothing is asked of \
             those.",
            counted(generation.not_shown.len(), "more record")
        );
    }

    // The names: those of this generation, and those of the generations
    // before, where a key in either list of this statement listed them.
    let excluded: Vec<[u8; 32]> = (0..rows.len())
        .filter(|at_row| recover::in_other_hands(rows, &answers, *at_row))
        .map(|at_row| rows[at_row].key)
        .collect();
    let mut before: Vec<Vec<String>> = Vec::new();
    // What was read of the personal channels, for what is said before
    // the yes: nothing refuses for a generation before.
    let mut was_read = WasRead {
        number: statement.number,
        personal: personal_read,
        before: Vec::new(),
    };
    for earlier in &for_phrase.earlier {
        let personal = Zeroizing::new(derive::personal_secret(&earlier.secret)?);
        let what = format!("the personal channel of change {}", earlier.number);
        let (handed, relays) = read_channel(config_path, &personal, &mut sessions, &own, &what)?;
        let not_read = not_read_at(&relays);
        if !not_read.is_empty() {
            was_read.before.push((earlier.number, not_read));
        }
        before.push(recover::names_before(
            &handed,
            &earlier.secret,
            earlier.number,
            |key| (statement.lists(key) || statement.removes(key)) && !excluded.contains(key),
        )?);
    }
    let names = recover::names_in_order(&generation, &answers, &before, RECOVERY_MAX_NAMES);
    let takes = recover::takes(rows, &answers);
    let gone = recover::gone(rows, &answers);

    // 4. The statement, shown from the bytes that the phrase will sign.
    let prepared = prepare_recovery(
        &from.statement,
        apart.as_ref().map(|other| &other.statement),
        maker,
        &gone,
    )?;
    let signs = Statement::from_bytes(prepared.bytes())?;
    println!(
        "\nThe change that the recovery phrase will sign (change {}):",
        signs.number
    );
    for line in lists_lines(&signs, &own)? {
        println!("{line}");
    }
    for line in will_do_lines(&generation, &answers, &names, &own, &was_read) {
        println!("{line}");
    }
    if !at.yes("\nRecover on this machine?")? {
        println!("{NOT_A_YES}");
        return Ok(());
    }

    // The phrase signs and seals, gives its word for the look, and is
    // dropped: the node is handed nothing before that.
    let entry = prepared
        .sign(
            &phrase,
            &from.entry,
            apart.as_ref().map(|other| &other.entry),
        )
        .map_err(not_this_phrases)?;
    let allows = Allows::Look {
        names: names.carried.clone(),
        takes: takes.iter().map(hex::encode).collect(),
    };
    let now = chrono::Utc::now().timestamp();
    let word = Word::give(&phrase, &own, &entry.id(), allows.says()?, now)?;
    drop(phrase);

    // The secrets that the machine keeps: of the generation recovered
    // from, and of those before it that its entry gave the phrase.
    // (Each is written from where it lies: no copy of it is made on the
    // way, and the text that is made of it is overwritten once it is
    // sent.)
    let mut left = vec![json!({
        "number": statement.number,
        "secret": hex::encode(&for_phrase.secret[..]),
    })];
    for earlier in &for_phrase.earlier {
        left.push(json!({ "number": earlier.number, "secret": hex::encode(&earlier.secret[..]) }));
    }
    drop(for_phrase);
    let key_and_label =
        |row: &Row| -> Value { json!({ "key": hex::encode(row.key), "label": row.label }) };
    let labelled = |answer: fn(&Answer) -> bool| -> Vec<Value> {
        rows.iter()
            .zip(&answers)
            .filter(|(row, said)| answer(said) && row.key != own)
            .map(|(row, _)| key_and_label(row))
            .collect()
    };
    let not_shown: Vec<Value> = generation.not_shown.iter().map(key_and_label).collect();
    let mut body = json!({
        "entry": hex::encode(entry.to_wire()),
        "statement_key": hex::encode(*statement_key),
        "left": left,
        "gone": labelled(|said| matches!(said, Answer::Lost | Answer::OtherHands)),
        "still_have": labelled(|said| *said == Answer::Have),
        "not_shown": not_shown,
        "word": word,
    });
    drop(statement_key);
    let made = api_post_told_of(
        config_path,
        "/api/v1/recover/make",
        &body,
        Some(Duration::from_secs(60)),
    );
    // The secrets that the phrase opened are in the request as text:
    // what this process still holds of that text is overwritten.
    wipe_strings(&mut body);
    drop(body);
    match made {
        Ok(Told::Yes(_)) => {}
        Ok(Told::No { message, .. }) => anyhow::bail!("{message}\nNothing was made."),
        // The answer was lost, and the node may have made it all the
        // same: it is asked again before anything is said of it.
        Err(lost) => {
            println!("\n{lost}\nThe node's answer was lost. Asking it again...");
            if !made_all_the_same(config_path, &entry.id()) {
                anyhow::bail!(
                    "it is not known whether the node made the recovery: it does not say that \
                     it follows the phrase so far, and it may still. `cordelia devices` shows \
                     whether this machine follows a recovery phrase, and under which change: do \
                     not recover again until it does."
                );
            }
        }
    }
    println!(
        "\nThe change is made (change {}): this machine follows the recovery phrase, alone. It \
         is shown to every relay first, before anything is carried.",
        signs.number
    );
    let cut_short = generation.cut_short.map(|key| {
        let label = rows.iter().find(|row| row.key == key);
        named(
            &label.map(|row| row.label.clone()).unwrap_or_default(),
            &key,
        )
    });
    goes_on_in_a_new_process(config_path, signs.number, cut_short)
}

/// A refusal of the phrase's, in words: the phrase that was typed is not
/// the one that made what it is asked to open or sign.
fn not_this_phrases(e: PersonError) -> anyhow::Error {
    match e {
        PersonError::Statement(StatementError::AnotherPhrase) => anyhow::anyhow!(
            "that is a recovery phrase, and it is not the one that made this change: nothing \
             was made."
        ),
        other => anyhow::anyhow!("{other}: nothing was made."),
    }
}

/// Go on to the wait for the look ([`recover_made`]) in a new image of
/// this program, which takes the place of this one (decision 2026-10-04
/// §16): the memory that held the phrase, and what it opened, is gone
/// when the wait begins, and the process that waits never held it.
fn goes_on_in_a_new_process(
    config_path: &str,
    number: u64,
    cut_short: Option<String>,
) -> anyhow::Result<()> {
    use std::io::Write;
    std::io::stdout().flush()?;
    #[cfg(unix)]
    let failed = {
        use std::os::unix::process::CommandExt;
        match std::env::current_exe() {
            Ok(program) => {
                let mut command = std::process::Command::new(program);
                command
                    .arg("--config")
                    .arg(config_path)
                    .arg(MADE_COMMAND)
                    .arg(number.to_string());
                if let Some(cut_short) = &cut_short {
                    command.arg("--cut-short").arg(cut_short);
                }
                command.exec()
            }
            Err(e) => e,
        }
    };
    #[cfg(not(unix))]
    let failed = "it runs on a Unix system";
    let _ = cut_short;
    println!(
        "This command could not go on to say what the look found ({failed}). The node goes on \
         by itself: it looks at what the relays hold of each name, once, and sends what it \
         carried. `cordelia devices` shows whether each relay holds the change, and what this \
         machine has still to send. Keep this machine on until nothing is left to send."
    );
    Ok(())
}

/// What the look of a recovery found, in lines (decision 2026-10-04 §9,
/// step 5): how much was carried; which names and relays it could not
/// read; and, for each removed key, how much that key signed in what was
/// read that the new channels lack, with the command that brings it. A
/// key's words are worked out here, from the key.
fn look_lines(found: &Value) -> Vec<String> {
    let number = |field: &str| found[field].as_u64().unwrap_or(0) as usize;
    // Where the new channels could not be read, the look took nothing
    // (§7.3): which of their slots hold nothing was not known.
    if found["new_not_read"] == true {
        return vec![
            "The look took nothing: the new channels could not be read at a relay (no relay \
             answered, or the read did not end), so which of their slots hold nothing was not \
             known. It is not made again by itself. What the relays hold of each device that is \
             gone is brought in by `cordelia sync carry <name> --from <device>`, with the \
             phrase, once a relay can be read: with no device named, it lists the removed \
             keys that signed there."
                .to_string(),
        ];
    }
    let mut lines = vec![format!(
        "The look is made: {} read, and {} carried, in {}.",
        counted(number("names"), "name"),
        counted(number("carried"), "version"),
        counted(number("carried_names"), "name")
    )];
    if number("higher") > 0 {
        lines.push(format!(
            "  {} left: the new channels hold a higher revision.",
            counted(number("higher"), "version")
        ));
    }
    let ties: Vec<String> = list(found, "ties")
        .filter_map(Value::as_str)
        .map(file_shown)
        .collect();
    if !ties.is_empty() {
        lines.push(format!(
            "  {} left, tied with an entry of this machine's own: {}.",
            counted(ties.len(), "version"),
            ties.join(", ")
        ));
    }
    // What could not be read: each name once, with where.
    let mut not_read: Vec<String> = Vec::new();
    for missed in list(found, "not_read") {
        let relay = missed["relay"].as_str().map(|relay| format!(" at {relay}"));
        not_read.push(format!(
            "{} (change {}{}: {})",
            file_shown(text(missed, "name")),
            missed["change"].as_u64().unwrap_or(0),
            relay.unwrap_or_default(),
            text(missed, "read")
        ));
    }
    if !not_read.is_empty() {
        let more = not_read.len().saturating_sub(SAID_NOT_READ);
        not_read.truncate(SAID_NOT_READ);
        lines.push(format!(
            "  Could not read to the end: {}{}. `cordelia sync carry <name>` reads a name again.",
            not_read.join("; "),
            match more {
                0 => String::new(),
                more => format!("; and {more} more"),
            }
        ));
    }
    for failed in list(found, "failed").filter_map(Value::as_str) {
        lines.push(format!("  Could not carry {}.", file_shown(failed)));
    }
    for lacks in list(found, "lacking") {
        let Some(key) = carry::key_named(text(lacks, "key")) else {
            continue;
        };
        let words = carry::naming_words(&key);
        let names: Vec<String> = list(lacks, "names")
            .filter_map(Value::as_str)
            .map(file_shown)
            .collect();
        // The command that brings it in names the key by its six words:
        // and by the key written whole, where the node says that those
        // words name another removed key too (§7.3).
        let named = match lacks["by_words"] == false {
            true => crate::carry_cmd::key_written(&key),
            false => format!("\"{words}\""),
        };
        lines.push(format!(
            "  {} signed {} that the new channels lack, in: {}. It is brought in only with the \
             phrase: cordelia sync carry <name> --from {named}",
            crate::person_cmd::words_then(&words, text(lacks, "label")),
            counted(lacks["versions"].as_u64().unwrap_or(0) as usize, "version"),
            names.join(", ")
        ));
    }
    lines
}

/// How many of the names that could not be read are said one by one.
const SAID_NOT_READ: usize = 20;

/// `cordelia recover-made <number>`: what `cordelia recover` goes on to
/// once its change is made (decision 2026-10-04 §9, steps 5 and 6). It
/// asks nothing, and holds no phrase. It stays until the look has ended,
/// says what it found, says "keep this machine on" with how many names
/// are still to send, and says how each device that the person still has
/// is added again.
pub fn recover_made(
    config_path: &str,
    number: u64,
    cut_short: Option<String>,
) -> anyhow::Result<()> {
    // The change was made a moment before this process began.
    let began = std::time::Instant::now();
    println!(
        "Looking at what the relays hold of each name. The look is made once, and this command \
         stays until it has ended. Stopping it stops nothing: the node goes on."
    );
    let mut said_read = 0;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let asked = told(api_post_told(
            config_path,
            "/api/v1/recover/progress",
            json!({}),
            Some(Duration::from_secs(30)),
        ))?;
        let found = &asked["look"];
        if found.is_null() || found["change"].as_u64() != Some(number) {
            println!(
                "The look was interrupted: the node was started again before it had ended. It \
                 is not taken up again by itself. What this machine had carried by then is \
                 kept, and is sent. What is missing is brought in by `cordelia sync carry \
                 <name> --from <device>`, with the phrase."
            );
            break;
        }
        if found["finished"] == true {
            for line in look_lines(found) {
                println!("{line}");
            }
            break;
        }
        let read = found["read"].as_u64().unwrap_or(0);
        if read >= said_read + 16 {
            said_read = read;
            println!(
                "  read {read} of {} so far",
                counted(found["names"].as_u64().unwrap_or(0) as usize, "name")
            );
        }
    }
    if let Some(device) = cut_short {
        println!(
            "The device that this was recovered from, {device}, never wrote that it had sent \
             what it carried: a recovery, or a change, that was made on it was cut short. What \
             it had sent is brought back. What the devices that were gone before it wrote, in \
             the files it had not sent, is at the relays in the generation before: `cordelia \
             sync carry <name> --from <device>` brings it in, with the phrase, and lists those \
             devices where no device is named."
        );
    }
    let seen = look(config_path)?;
    // What a folder that is mapped here has still to publish is in no
    // store yet: whether one has still to sync for the first time is
    // asked of the node's sync status. Where that cannot be had, each
    // mapped folder is taken to.
    let mapped = seen["folders"].as_u64().unwrap_or(0) as usize;
    let first_syncs = match seen["sync_on"] == true && mapped > 0 {
        true => crate::api_post(config_path, "/api/v1/sync/status", json!({}))
            .map_or(mapped, |sync| first_syncs_to_come(&sync, began.elapsed())),
        false => 0,
    };
    for line in after_lines(&seen, first_syncs) {
        println!("{line}");
    }
    Ok(())
}

/// How many folders that this machine maps have still to sync for the
/// first time since the recovery (decision 2026-10-04 §9, step 5), as
/// the node's sync status `sync` says, `since` the change was made. A
/// folder's first cycle in a name waits until the look has read that
/// name. What it then publishes is to be sent, and until that cycle has
/// run none of it is in the store, where what waits is counted.
///
/// None where sync is off, or no folder is mapped. Otherwise every
/// mapped folder, where no cycle has reported since the change was made:
/// the node says for how long it has had no report. And where one has,
/// each folder of which the report says that it waits.
fn first_syncs_to_come(sync: &Value, since: Duration) -> usize {
    let mapped = list(sync, "mappings").count();
    if sync["enabled"] != true || mapped == 0 {
        return 0;
    }
    let no_report_for = sync["no_report_secs"].as_u64().unwrap_or(u64::MAX);
    if sync["report"].is_null() || no_report_for >= since.as_secs() {
        return mapped;
    }
    let waits = |folder: &&Value| folder["waiting"] == true;
    list(&sync["report"], "folders").filter(waits).count()
}

/// What is said once the look has ended, of what the node says of this
/// machine (decision 2026-10-04 §9, steps 5 and 6): which relay holds
/// the change; "keep this machine on" with how many names are still to
/// send; and, for each device that the person still has, how it is added
/// again.
///
/// **That nothing is waiting is said only where nothing is.** Beside
/// the names, the machine's personal channel is to be sent, which lists
/// them: the node says how many of the machine's channels wait at each
/// relay, and where no name does and a channel does, that is said. And
/// `first_syncs` folders that are mapped here have still to sync for the
/// first time since the recovery ([`first_syncs_to_come`]): what they
/// publish is not in the store yet.
fn after_lines(seen: &Value, first_syncs: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for relay in list(seen, "relays") {
        lines.push(match relay["holds_latest"].as_bool() {
            Some(true) => format!("{} holds the change.", text(relay, "relay")),
            _ => format!(
                "keep this machine on: {} does not hold the change yet.",
                text(relay, "relay")
            ),
        });
    }
    for relay in list(seen, "not_reached").filter_map(Value::as_str) {
        lines.push(format!(
            "keep this machine on: {relay} is not connected, and what is still to send there is \
             not known until it is."
        ));
    }
    let to_go = list(&seen["names"], "to_go").count();
    // The channels of this machine's own that wait at a relay which is
    // connected: its personal channel among them.
    let channels = |relay: &Value| relay["waits"].as_u64().unwrap_or(0);
    let channels_wait = list(seen, "waiting").any(|relay| channels(relay) > 0);
    match (to_go, channels_wait) {
        (0, false) if first_syncs == 0 => lines.push(
            "Nothing is waiting to be sent to a relay that is connected. `cordelia devices` \
             shows what each relay holds."
                .to_string(),
        ),
        (0, false) => {}
        (0, true) => lines.push(
            "keep this machine on: its personal channel, which lists the names, is still to \
             send"
                .to_string(),
        ),
        (to_go, _) => lines.push(format!(
            "keep this machine on: {} still to send",
            counted(to_go, "name")
        )),
    }
    if first_syncs > 0 {
        lines.push(format!(
            "keep this machine on: {} mapped here {} still to sync for the first time since \
             the recovery, and what {} is then to send",
            counted(first_syncs, "folder"),
            match first_syncs {
                1 => "has",
                _ => "have",
            },
            match first_syncs {
                1 => "it publishes",
                _ => "they publish",
            }
        ));
    }
    // A key that could not be shown is left out too, and is no device
    // that the person said they still have.
    let (not_shown, still): (Vec<&Value>, Vec<&Value>) =
        list(seen, "left_out").partition(|device| device["key"].is_string());
    if !not_shown.is_empty() {
        lines.push(format!(
            "{} could not be shown, and nothing was asked of {}: `cordelia devices` shows {} \
             with its key.",
            counted(not_shown.len(), "record of an addition")
                .replace("record of an additions", "records of additions"),
            match not_shown.len() {
                1 => "it",
                _ => "them",
            },
            match not_shown.len() {
                1 => "it",
                _ => "each",
            }
        ));
    }
    if !still.is_empty() {
        lines.push(
            "\nEach device that you still have has stopped, and is added again by hand, with \
             its key read from the device itself:"
                .to_string(),
        );
        for device in still {
            lines.push(format!(
                "  {}: on it, `cordelia id` prints its key. Here: cordelia add-device <that \
                 key>. Then on it: cordelia accept {}",
                crate::person_cmd::words_then(text(device, "words"), text(device, "label")),
                text(seen, "this_device")
            ));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(n: u8, label: &str, added_by: Option<u8>, counts: bool) -> Row {
        Row {
            key: [n; 32],
            label: label.into(),
            added_by: added_by.map(|adder| ([adder; 32], 1_800_000_000)),
            counts,
            signed: usize::from(n),
            no_room: Vec::new(),
        }
    }

    /// The rows of a test: a laptop and a desktop of the statement, a
    /// phone that the desktop added, and a tablet that the phone added.
    fn rows() -> Vec<Row> {
        vec![
            row(1, "laptop", None, true),
            row(2, "desktop", None, true),
            row(3, "phone", Some(2), true),
            row(4, "tablet", Some(3), false),
        ]
    }

    /// What is said of a device before its answer is asked (decision
    /// 2026-10-04 §9, step 3): the first words of its key's fingerprint
    /// and then its label, quoted; whether the statement lists it, or who
    /// added it since and when; and how much it signed.
    #[test]
    fn test_what_is_said_of_a_device_before_its_answer_is_asked() {
        let rows = rows();
        let laptop = row_says(&rows, 0, 7);
        assert_eq!(
            laptop,
            format!(
                "\n({}) \"laptop\", a device of change 7. It signed 1 entry in the personal \
                 channel of that change.",
                fingerprint::shown(&[1; 32])
            )
        );
        let phone = row_says(&rows, 2, 7);
        assert!(
            phone.contains(&format!(
                "\"phone\", added since change 7, from ({}) \"desktop\" at 2027-01-15 08:00 UTC. \
                 It signed 3 entries",
                fingerprint::shown(&[2; 32])
            )),
            "{phone}"
        );
        // A record that does not count is said to be one.
        let tablet = row_says(&rows, 3, 7);
        assert!(
            tablet.contains("by a record that does not count"),
            "{tablet}"
        );
        // A label is another device's word: quoted, it cannot pass for
        // what the command says itself.
        let odd = vec![row(9, "x\") (abandon ability", None, true)];
        let says = row_says(&odd, 0, 1);
        assert!(says.contains("\"x\\\") (abandon ability\""), "{says}");
    }

    /// A key that only the bound of 64 counted devices kept out is shown
    /// with that reason (decision 2026-10-04 §9, step 3). Where it is
    /// asked about, what each answer does for it is said before the
    /// question: nothing that it wrote is brought back, `lost` or
    /// `hands` removes its key, and `have` leaves it to be added again.
    /// Before the yes it is named among those from whom the look takes
    /// nothing, where it was said to be gone.
    #[test]
    fn test_what_is_said_of_a_key_that_only_the_bound_of_64_kept_out() {
        let mut rows = rows();
        // A watch that the desktop added, and the laptop too: its record
        // found no room.
        let mut watch = row(5, "watch", Some(1), false);
        watch.no_room = vec![([1; 32], 1_800_000_000), ([2; 32], 1_800_000_000)];
        rows.push(watch);
        let says = row_says(&rows, 4, 7);
        assert!(
            says.contains(&format!(
                "\"watch\", added since change 7, from ({}) \"laptop\" at 2027-01-15 08:00 UTC, \
                 by a record that does not count: 64 devices counted already. It signed 5 entries",
                fingerprint::shown(&[1; 32])
            )),
            "{says}"
        );
        // Asked about for the record that the device shown signed.
        let asked = for_room_says(&rows, 4, 7, &[1; 32]);
        assert!(asked.starts_with(&says), "{asked}");
        assert!(!asked.contains("added it too"), "{asked}");
        assert!(
            asked.ends_with(
                "\n  That is the one thing its record fails for, so it is asked about all the \
                 same. Nothing that it wrote is brought back by this recovery, whatever is said \
                 of it: `lost` or `hands` removes its key, and what it wrote then comes in by \
                 `cordelia sync carry <name> --from <device>`, with the phrase; `have` leaves it \
                 to be added again by hand."
            ),
            "{asked}"
        );
        // Asked about for the record of another device than the one
        // shown: that one is named too.
        let asked = for_room_says(&rows, 4, 7, &[2; 32]);
        assert!(
            asked.contains(&format!(
                "\n  ({}) \"desktop\" added it too.\n  That is the one thing",
                fingerprint::shown(&[2; 32])
            )),
            "{asked}"
        );

        // Before the yes: said to be lost, it is one of those from whom
        // the look takes nothing, with the command that brings what it
        // wrote. Said to be one that the person still has, it is not.
        let generation = Generation {
            rows: rows.clone(),
            ..Default::default()
        };
        let names = recover::Names::default();
        let lost = [
            Answer::Lost,
            Answer::Lost,
            Answer::Lost,
            Answer::NotAsked,
            Answer::Lost,
        ];
        let all = will_do_lines(&generation, &lost, &names, &[9; 32], &read_whole()).join("\n");
        assert!(
            all.contains(&format!(
                "It takes nothing from: ({}) \"watch\". What they wrote comes in only by \
                 `cordelia sync carry <name> --from <device>`.",
                fingerprint::shown(&[5; 32])
            )),
            "{all}"
        );
        let mut have = lost;
        have[4] = Answer::Have;
        let all = will_do_lines(&generation, &have, &names, &[9; 32], &read_whole()).join("\n");
        assert!(!all.contains("It takes nothing from"), "{all}");
        // Nor where each device that signed its record may be in someone
        // else's hands: nothing was asked of it, whatever stands there.
        let mut hands = lost;
        (hands[0], hands[1]) = (Answer::OtherHands, Answer::OtherHands);
        let all = will_do_lines(&generation, &hands, &names, &[9; 32], &read_whole()).join("\n");
        assert!(!all.contains("\"watch\""), "{all}");
    }

    /// Of two changes made apart, the command says how many more are on
    /// neither's chain, where any is, and what settling the two means
    /// (decision 2026-10-04 §9, step 2): what the devices of the other
    /// branch had not sent comes back only by adding them again.
    #[test]
    fn test_what_is_said_of_two_changes_made_apart() {
        let settles = apart_lines(0);
        assert_eq!(settles.len(), 1, "{settles:?}");
        assert!(
            settles[0].starts_with("The recovery is made from one of them"),
            "{settles:?}"
        );
        assert!(
            settles[0].ends_with(
                "are in no list after it, and what they had written and not sent to a relay \
                 comes back only by adding them again."
            ),
            "{settles:?}"
        );
        let one = apart_lines(1);
        assert_eq!(
            one[0],
            "1 more change besides those is on neither's chain, and is not settled by this \
             recovery."
        );
        assert_eq!(one[1], settles[0]);
        assert!(apart_lines(3)[0].starts_with("3 more changes besides those"));
    }

    /// Where no change of the phrase was found and a relay could not be
    /// read to its end, the command says which relay, and that it is not
    /// known whether one holds a change (decision 2026-10-04 §16): it
    /// says that no relay holds one only where each was read to its end.
    #[test]
    fn test_a_relay_that_was_not_read_is_never_said_to_hold_no_change() {
        let said = |relay: &str, read: &str| json!({ "relay": relay, "read": read });
        let changed = cordelia_api::carrying::CONNECTION_CHANGED;
        let relays = [
            said("one", "whole"),
            said("two", changed),
            said("three", "not held"),
            said("four", "part"),
        ];
        let not_read = not_read_to_its_end(&relays);
        assert_eq!(
            not_read,
            [
                ("two".to_string(), changed.to_string()),
                ("four".to_string(), "part".to_string())
            ]
        );
        let names: Vec<String> = not_read.into_iter().map(|(relay, _)| relay).collect();
        let says = none_found_says(&names);
        assert!(
            says.starts_with(
                "the recovery phrase's own channel could not be read to its end at two, four, \
                 and no change of this recovery phrase was found in what was read"
            ),
            "{says}"
        );
        assert!(says.contains("whether a relay holds one is not known"));
        assert!(!says.contains("no relay that was reached holds"), "{says}");
        assert!(says.ends_with("Nothing was done."));
        let none = none_found_says(&[]);
        assert!(
            none.starts_with("no relay that was reached holds a change of this recovery phrase"),
            "{none}"
        );
        assert!(none.ends_with("Nothing was done."));
    }

    /// What was read of the personal channels, for a test: the personal
    /// channel of change 3 as the node says of each relay, and nothing
    /// unread of a generation before.
    fn was_read(relays: &[Value]) -> WasRead {
        WasRead {
            number: 3,
            personal: PersonalRead::of(relays),
            before: Vec::new(),
        }
    }

    /// Everything read to its end, at the one relay.
    fn read_whole() -> WasRead {
        was_read(&[json!({ "relay": "one", "read": "whole", "entries": 4 })])
    }

    /// **A recovery goes on with what it could read of the personal
    /// channel of the change it recovers from, and says what it could
    /// not** (decision 2026-10-04 §9, step 3; §16). Of each relay one of
    /// four things is known: read to its end; read in part, with one
    /// entry handed at least; the relay holds none of it; or nothing. It
    /// is refused, before anything is asked, only where nothing is known
    /// of any relay, and the refusal names each relay and says to run
    /// the command again.
    ///
    /// Every combination of the four over two relays: the decision, and
    /// each sentence before the yes. A relay whose read is said to be in
    /// part with no entry handed is one of which nothing is known.
    #[test]
    fn test_a_recovery_goes_on_with_what_it_could_read_of_the_personal_channel() {
        use ReadAs::{NotHeld, Nothing, Part, Whole};
        let changed = cordelia_api::carrying::CONNECTION_CHANGED;
        let said = |relay: &str, read: &str, entries: u64| json!({ "relay": relay, "read": read, "entries": entries });
        // What the node says, and which of the four things it is.
        for (read, entries, is) in [
            ("whole", 4, Whole),
            ("whole", 0, Whole),
            ("part", 1, Part),
            ("part", 0, Nothing),
            ("not held", 0, NotHeld),
            ("not reached", 0, Nothing),
            (changed, 0, Nothing),
            ("not read: the node is held up", 0, Nothing),
            // Handed at an earlier reading, and not read to its end.
            ("not reached", 2, Part),
            (changed, 1, Part),
        ] {
            assert_eq!(read_as(&said("one", read, entries)), is, "{read} {entries}");
        }
        // A node that does not say how many entries a relay handed says
        // of no read in part that an entry was handed.
        assert_eq!(read_as(&json!({ "relay": "one", "read": "part" })), Nothing);

        let generation = Generation {
            rows: rows(),
            ..Default::default()
        };
        let answers = [Answer::Lost, Answer::Lost, Answer::Lost, Answer::NotAsked];
        let none = recover::Names::default();
        let lab = recover::Names {
            carried: vec!["lab".into()],
            ..Default::default()
        };
        let own = [9; 32];
        let of = |kind: ReadAs, relay: &str| match kind {
            Whole => said(relay, "whole", 4),
            Part => said(relay, "part", 2),
            NotHeld => said(relay, "not held", 0),
            // The read ended before any entry was handed.
            Nothing => said(relay, "part", 0),
        };
        let missing_device = "A device that is missing is not asked about here, and nothing that \
                              it wrote is brought back until its key is removed: `cordelia \
                              remove-device <key>` on this machine, and then `cordelia sync carry \
                              <name> --from <key>`, with the phrase.";
        let missing_name = "A name that is missing is not carried. What a device that is gone \
                            wrote under it comes in by `cordelia sync carry <name> --from \
                            <device>`, with the phrase; what a device that you still have holds \
                            of it comes once that device is added again and a folder here is \
                            mapped to the name.";
        let alone = "No name is carried: none is listed.\n";
        let in_what_was_read = "No name is carried: none is listed in what was read.\n";
        for first in [Whole, Part, NotHeld, Nothing] {
            for second in [Whole, Part, NotHeld, Nothing] {
                let relays = [of(first, "one"), of(second, "two")];
                let read = was_read(&relays);
                let refused = personal_not_read_says(3, &read.personal);
                let both = [first, second];
                let any = |kind: ReadAs| both.contains(&kind);
                let at = |kind: ReadAs| -> String {
                    let named = [(first, "one"), (second, "two")];
                    let of_it: Vec<&str> = named
                        .iter()
                        .filter(|(is, _)| *is == kind)
                        .map(|(_, relay)| *relay)
                        .collect();
                    of_it.join(", ")
                };
                // Refused only where nothing is known of either relay.
                assert_eq!(refused.is_some(), both == [Nothing, Nothing], "{both:?}");
                if refused.is_some() {
                    continue;
                }
                let lines = will_do_lines(&generation, &answers, &none, &own, &read);
                let all = lines.join("\n");
                let with_a_name = will_do_lines(&generation, &answers, &lab, &own, &read);
                let with_a_name = with_a_name.join("\n");
                assert!(
                    with_a_name.contains("1 name is carried: lab.\n"),
                    "{both:?}"
                );
                let said_of_it = |all: &str, sentence: &str| all.contains(sentence);
                if any(Whole) {
                    // Read to its end at one relay. Where the other was
                    // not, that is said, with the relay: and only then
                    // is a name that is not listed said so of what was
                    // read.
                    let not_read = match (any(Part), any(Nothing)) {
                        (true, _) => Some(at(Part)),
                        (_, true) => Some(at(Nothing)),
                        _ => None,
                    };
                    match not_read {
                        None => {
                            assert!(all.contains(alone), "{both:?}: {all}");
                            assert!(!all.contains("personal channel"), "{both:?}: {all}");
                        }
                        Some(relay) => {
                            let says = format!(
                                "The personal channel of the change recovered from could not be \
                                 read to its end at {relay}: devices added since that change, \
                                 and names, may be missing here.\n"
                            );
                            assert!(
                                all.contains(&format!("{in_what_was_read}{says}")),
                                "{both:?}: {all}"
                            );
                            assert!(with_a_name.contains(&says), "{both:?}: {with_a_name}");
                        }
                    }
                    for sentence in [missing_device, missing_name] {
                        assert!(!said_of_it(&all, sentence), "{both:?}: {all}");
                    }
                    continue;
                }
                // Read to its end at no relay: no name is said to be
                // listed nowhere, and what a missing device and a
                // missing name cost is said, with the commands.
                assert!(!all.contains(alone), "{both:?}: {all}");
                assert!(all.contains(in_what_was_read), "{both:?}: {all}");
                for all in [&all, &with_a_name] {
                    for sentence in [missing_device, missing_name] {
                        assert!(said_of_it(all, sentence), "{both:?}: {all}");
                    }
                }
                let says = match any(Part) {
                    // In part at one at least: at which in part, and at
                    // which not at all.
                    true => format!(
                        "The personal channel of change 3 was read to its end at no relay: in \
                         part at {}{}.{} Devices added since that change, and names, may be \
                         missing from what was read. What a person's own devices write there is \
                         small: a read that does not reach the end may be a sign that a device \
                         of that change filled the channel.\n",
                        at(Part),
                        match any(Nothing) {
                            true => format!(", and not at all at {}", at(Nothing)),
                            false => String::new(),
                        },
                        match any(NotHeld) {
                            true => format!(" {} holds none of it.", at(NotHeld)),
                            false => String::new(),
                        }
                    ),
                    // No relay that answered holds it.
                    false => format!(
                        "No relay that answered holds the personal channel of change 3: which \
                         devices were added since that change, and which names they sync, is not \
                         known.{}\n",
                        match any(Nothing) {
                            true => format!(" It was not read at {}.", at(Nothing)),
                            false => String::new(),
                        }
                    ),
                };
                assert!(all.contains(&says), "{both:?}: {all}\n{says}");
                assert!(with_a_name.contains(&says), "{both:?}: {with_a_name}");
            }
        }

        // The refusal: each relay, with what was said of it, and to run
        // the command again.
        let nothing = [said("one", "not reached", 0), said("two", "part", 0)];
        let refused = personal_not_read_says(3, &PersonalRead::of(&nothing)).unwrap();
        assert_eq!(
            refused,
            "nothing of the personal channel of change 3 was read at any relay: one (not \
             reached), two (the read ended before any entry of it was handed). No relay handed \
             an entry of it, and none said that it holds none of it: which devices were added \
             since that change, and which names they sync, is not known. Run `cordelia recover` \
             again. Nothing was done."
        );
        let one = personal_not_read_says(4, &PersonalRead::of(&[said("one", changed, 0)]));
        assert!(one.unwrap().starts_with(&format!(
            "nothing of the personal channel of change 4 was read at any relay: one \
                 ({changed}). No relay"
        )));
        // The node said nothing of any relay: nothing is known.
        let nowhere = personal_not_read_says(4, &PersonalRead::default()).unwrap();
        assert!(
            nowhere.starts_with(
                "nothing of the personal channel of change 4 was read at any relay: the node \
                 said nothing of any relay. No relay"
            ),
            "{nowhere}"
        );
        assert!(nowhere.ends_with("Run `cordelia recover` again. Nothing was done."));
        // One relay that says anything else, and it goes on.
        for known in [said("two", "part", 1), said("two", "not held", 0)] {
            let read = PersonalRead::of(&[said("one", "not reached", 0), known]);
            assert_eq!(personal_not_read_says(3, &read), None);
        }

        // Read in part at two relays, with a third that holds none.
        let read = was_read(&[
            said("one", "part", 1),
            said("two", "not held", 0),
            said("three", "part", 7),
            said("four", "not held", 0),
        ]);
        assert_eq!(
            read.lines()[0],
            "The personal channel of change 3 was read to its end at no relay: in part at one, \
             three. two, four hold none of it. Devices added since that change, and names, may \
             be missing from what was read. What a person's own devices write there is small: a \
             read that does not reach the end may be a sign that a device of that change filled \
             the channel."
        );
        assert_eq!(read.lines()[1..], [missing_device, missing_name]);

        // The personal channels of the generations before, which are
        // read for names: the relays at which one was not read to its
        // end are said too, by the change's number, and nothing is
        // refused for them. No name is then said to be listed nowhere.
        let mut before = read_whole();
        assert!(before.to_the_end() && before.lines().is_empty());
        before.before = vec![
            (2, vec!["two".into()]),
            (1, vec!["one".into(), "two".into()]),
        ];
        assert!(!before.to_the_end());
        assert_eq!(personal_not_read_says(3, &before.personal), None);
        let all = will_do_lines(&generation, &answers, &none, &own, &before).join("\n");
        assert!(
            all.contains(&format!(
                "{in_what_was_read}The personal channel of change 2, which is read for names, \
                 could not be read to its end at two: names that are listed only there may be \
                 missing.\nThe personal channel of change 1, which is read for names, could not \
                 be read to its end at one, two: names that are listed only there may be \
                 missing.\n"
            )),
            "{all}"
        );
        assert!(!all.contains(missing_device), "{all}");
    }

    /// Where the answers could not all be kept, that is said before the
    /// first question (decision 2026-10-04 §9, step 3): a statement has
    /// room for 256 removed keys. Nothing is said where they could.
    #[test]
    fn test_what_is_said_where_not_every_answer_could_be_kept() {
        let room = |removed: usize, asked: usize| recover::Room {
            removed,
            asked,
            can_go: MAX_STATEMENT_REMOVED - removed,
        };
        assert_eq!(room_says(&room(0, 64)), None);
        assert_eq!(room_says(&room(250, 6)), None);
        let says = room_says(&room(251, 6)).unwrap();
        assert!(
            says.contains(
                "Not every answer could be kept. A change has room for 256 removed keys, and \
                 lists every key removed so far: 251 are removed already, and 6 devices are \
                 asked about here. At most 5 of them can be said to be gone (`lost` or `hands`)."
            ),
            "{says}"
        );
        let one = room_says(&room(255, 2)).unwrap();
        assert!(one.contains("At most 1 of them"), "{one}");
        let full = room_says(&room(256, 1)).unwrap();
        assert!(
            full.contains("256 are removed already, and 1 device is asked about here. At most 0"),
            "{full}"
        );
    }

    /// What a command hands the node of the secrets that the phrase
    /// opened is text in a request: the command's own copy of that text
    /// is overwritten once the request is sent, wherever in the request
    /// it is (decision 2026-10-04 §16).
    #[test]
    fn test_the_text_of_a_request_is_overwritten_once_it_is_sent() {
        let mut body = json!({
            "entry": "aa",
            "left": [{ "number": 2, "secret": "0f0f" }, { "number": 1, "secret": "f0f0" }],
            "word": { "what": "said", "until": 5 },
        });
        wipe_strings(&mut body);
        assert_eq!(
            body,
            json!({
                "entry": "",
                "left": [{ "number": 2, "secret": "" }, { "number": 1, "secret": "" }],
                "word": { "what": "", "until": 5 },
            })
        );
    }

    /// What a recovery will do is said before its yes (decision
    /// 2026-10-04 §9): from whom the look takes, and from whom it takes
    /// nothing, with the command that brings what they wrote; the names
    /// that are carried, and those that are left and why.
    #[test]
    fn test_what_a_recovery_will_do_is_said_before_its_yes() {
        let generation = Generation {
            rows: rows(),
            not_shown: vec![row(5, "fifth", Some(1), false), row(6, "", Some(1), false)],
            names: Vec::new(),
            cut_short: None,
        };
        let names = recover::Names {
            carried: vec!["lab".into(), "no\u{1b}tes".into()],
            over_the_bound: vec!["beyond".into()],
            only_other_hands: vec!["theirs".into()],
        };
        // The laptop is lost; the desktop may be in someone else's
        // hands, and with it the phone it added.
        let answers = [Answer::Lost, Answer::OtherHands, Answer::Have, Answer::Have];
        let all = will_do_lines(&generation, &answers, &names, &[9; 32], &read_whole()).join("\n");
        assert!(
            all.contains(&format!(
                "The look takes what these wrote, as the relays hold it now: ({}) \"laptop\".",
                fingerprint::shown(&[1; 32])
            )),
            "{all}"
        );
        assert!(all.contains("It takes nothing from: "), "{all}");
        assert!(all.contains("\"desktop\", ("), "{all}");
        assert!(
            all.contains("\"phone\". What they wrote comes in only by"),
            "{all}"
        );
        assert!(
            all.contains("`cordelia sync carry <name> --from <device>`"),
            "{all}"
        );
        assert!(
            all.contains(
                "2 records of additions more could not be shown: the look takes nothing from \
                 those, each is in no list, and this machine keeps each as left out: `cordelia \
                 devices` shows it with its key."
            ),
            "{all}"
        );
        assert!(all.contains("2 names are carried: lab, "), "{all}");
        assert!(
            all.contains("1 name is left, beyond the 1024 that a recovery carries: beyond."),
            "{all}"
        );
        assert!(
            all.contains(
                "1 name is left, which only a device listed from which nothing is taken, or a \
                 key that does not count: theirs."
            ),
            "{all}"
        );
        assert!(all.contains("Every other device of yours stops"), "{all}");
        // A name is another device's word: it is printed safely.
        assert!(!all.chars().any(|c| c.is_control() && c != '\n'), "{all:?}");

        // Where nothing is taken from anyone, that is said, with the
        // command that brings it.
        let none = [
            Answer::OtherHands,
            Answer::OtherHands,
            Answer::Have,
            Answer::Have,
        ];
        let empty = recover::Names::default();
        let all = will_do_lines(&generation, &none, &empty, &[9; 32], &read_whole()).join("\n");
        assert!(
            all.contains("Nothing that those devices wrote is brought back by this recovery."),
            "{all}"
        );
        assert!(all.contains("No name is carried: none is listed."), "{all}");
    }

    /// What the look found is said at its end (decision 2026-10-04 §9,
    /// step 5): how much was carried; which names it could not read, and
    /// where; and, for each removed key, how much that key signed that
    /// the new channels lack, with the command that brings it, by six
    /// words that are worked out from the key.
    #[test]
    fn test_what_the_look_found_is_said_at_its_end() {
        let key = [7u8; 32];
        let mut not_read = Vec::new();
        for n in 0..SAID_NOT_READ + 3 {
            not_read.push(json!({
                "name": format!("name-{n}"), "change": 4, "relay": "one", "read": "part",
            }));
        }
        let found = json!({
            "finished": true, "names": 30, "carried": 12, "carried_names": 5, "higher": 2,
            "ties": ["lab: notes.md"],
            "not_read": not_read,
            "failed": ["lab: no room"],
            "lacking": [
                { "key": hex::encode(key), "label": "desktop", "versions": 3,
                  "names": ["lab", "notes"] },
                { "key": "no key", "label": "odd", "versions": 9, "names": [] },
                { "key": hex::encode([9u8; 32]), "label": "tablet", "versions": 1,
                  "names": ["lab"], "by_words": false },
            ],
        });
        let lines = look_lines(&found);
        let all = lines.join("\n");
        assert_eq!(
            lines[0],
            "The look is made: 30 names read, and 12 versions carried, in 5 names."
        );
        assert!(
            all.contains("2 versions left: the new channels hold a higher revision."),
            "{all}"
        );
        assert!(
            all.contains(
                "1 version left, tied with an entry of this machine's own: lab: notes.md."
            ),
            "{all}"
        );
        assert!(
            all.contains("Could not read to the end: name-0 (change 4 at one: part); name-1"),
            "{all}"
        );
        assert!(all.contains("; and 3 more."), "{all}");
        assert!(!all.contains("name-20 "), "{all}");
        assert!(all.contains("Could not carry lab: no room."), "{all}");
        let words = carry::naming_words(&key);
        assert!(
            all.contains(&format!(
                "({words}) \"desktop\" signed 3 versions that the new channels lack, in: lab, \
                 notes. It is brought in only with the phrase: cordelia sync carry <name> --from \
                 \"{words}\""
            )),
            "{all}"
        );
        // A key whose six words name another removed key too is named
        // by the key written whole, which the command works out too.
        let whole = cordelia_crypto::bech32::encode_public_key(&[9u8; 32]).unwrap();
        assert!(
            all.contains(&format!(
                "\"tablet\" signed 1 version that the new channels lack, in: lab. It is \
                 brought in only with the phrase: cordelia sync carry <name> --from {whole}"
            )),
            "{all}"
        );
        // What is no key is not shown.
        assert!(!all.contains("odd"), "{all}");

        // A look that could not read the new channels took nothing, and
        // says so, with the command that brings in what the relays hold.
        let not_read = json!({ "finished": true, "new_not_read": true, "names": 3, "carried": 0 });
        let lines = look_lines(&not_read);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with(
                "The look took nothing: the new channels could not be read at a relay"
            ),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("`cordelia sync carry <name> --from <device>`"),
            "{lines:?}"
        );

        // A look that found nothing more says the one line.
        let plain = json!({ "names": 1, "carried": 1, "carried_names": 1 });
        assert_eq!(
            look_lines(&plain),
            ["The look is made: 1 name read, and 1 version carried, in 1 name."]
        );
    }

    /// Once the look has ended the command says which relay holds the
    /// change, "keep this machine on" with how many names are still to
    /// send, and how each device that the person still has is added
    /// again (decision 2026-10-04 §9, steps 5 and 6).
    #[test]
    fn test_what_is_said_once_the_look_has_ended() {
        let seen = json!({
            "this_device": "cordelia1thismachine",
            "relays": [
                { "relay": "one", "holds_latest": true },
                { "relay": "two", "holds_latest": false },
            ],
            "not_reached": ["three"],
            "names": { "to_go": ["a", "b", "c"], "sent": ["d"] },
            "left_out": [
                { "label": "desktop", "words": "w1 w2 w3 w4", "number": 3 },
                { "label": "added 9", "words": "n1 n2 n3 n4", "number": 3, "key": "cordelia_pk1x" },
                { "label": "", "words": "m1 m2 m3 m4", "number": 3, "key": "cordelia_pk1y" },
            ],
        });
        let lines = after_lines(&seen, 0);
        let all = lines.join("\n");
        // What could not be shown is no device that the person said they
        // still have: it is said apart, and is not to be added again.
        assert!(
            all.contains(
                "2 records of additions could not be shown, and nothing was asked of them: \
                 `cordelia devices` shows each with its key."
            ),
            "{all}"
        );
        assert!(!all.contains("added 9"), "{all}");
        assert_eq!(all.matches("cordelia add-device <that key>").count(), 1);
        assert_eq!(lines[0], "one holds the change.");
        assert_eq!(
            lines[1],
            "keep this machine on: two does not hold the change yet."
        );
        assert!(
            all.contains("keep this machine on: three is not connected"),
            "{all}"
        );
        assert!(
            lines.contains(&"keep this machine on: 3 names still to send".to_string()),
            "{all}"
        );
        assert!(
            all.contains("Each device that you still have has stopped, and is added again by hand"),
            "{all}"
        );
        assert!(
            all.contains(
                "(w1 w2 w3 w4) \"desktop\": on it, `cordelia id` prints its key. Here: cordelia \
                 add-device <that key>. Then on it: cordelia accept cordelia1thismachine"
            ),
            "{all}"
        );

        // With nothing to send, and nobody to add again.
        let done = json!({
            "this_device": "k", "relays": [{ "relay": "one", "holds_latest": true }],
            "names": { "to_go": [], "sent": ["a"] }, "left_out": [],
        });
        let all = after_lines(&done, 0).join("\n");
        assert!(all.contains("Nothing is waiting to be sent"), "{all}");
        assert!(!all.contains("keep this machine on"), "{all}");
        assert!(!all.contains("added again"), "{all}");
        let one = json!({ "relays": [], "names": { "to_go": ["a"] } });
        assert!(
            after_lines(&one, 0)
                .contains(&"keep this machine on: 1 name still to send".to_string())
        );
    }

    /// That nothing is waiting to be sent is said only where nothing is
    /// (decision 2026-10-04 §9, step 5). The machine's personal channel,
    /// which lists the names, is to be sent too: where no name waits and
    /// a channel of the machine's own does, that is said. And a folder
    /// that is mapped here has its first cycle once the look has read
    /// its name: until it has synced, what it publishes is still to
    /// come, and that is said.
    #[test]
    fn test_nothing_is_said_to_wait_only_where_nothing_does() {
        let seen = |to_go: Value, waits: u64| {
            json!({
                "this_device": "k", "relays": [{ "relay": "one", "holds_latest": true }],
                "names": { "to_go": to_go, "sent": [] }, "left_out": [],
                "waiting": [{ "relay": "one", "waits": 0 }, { "relay": "two", "waits": waits }],
            })
        };
        let nothing = "Nothing is waiting to be sent to a relay that is connected. `cordelia \
                       devices` shows what each relay holds.";
        let list_waits = "keep this machine on: its personal channel, which lists the names, is \
                          still to send";
        // Nothing waits anywhere.
        let all = after_lines(&seen(json!([]), 0), 0);
        assert!(all.contains(&nothing.to_string()), "{all:?}");
        assert!(!all.join("\n").contains("keep this machine on"), "{all:?}");
        // No name waits, and a channel of the machine's own does, at one
        // relay: its personal channel.
        let all = after_lines(&seen(json!([]), 1), 0);
        assert!(all.contains(&list_waits.to_string()), "{all:?}");
        assert!(!all.join("\n").contains("Nothing is waiting"), "{all:?}");
        // Names wait: they are counted, as before.
        let all = after_lines(&seen(json!(["a", "b"]), 3), 0);
        assert!(
            all.contains(&"keep this machine on: 2 names still to send".to_string()),
            "{all:?}"
        );
        assert!(!all.contains(&list_waits.to_string()), "{all:?}");
        // A folder has still to sync for the first time: nothing is said
        // to be done, whatever waits in the store.
        let first = "keep this machine on: 1 folder mapped here has still to sync for the first \
                     time since the recovery, and what it publishes is then to send";
        let all = after_lines(&seen(json!([]), 0), 1);
        assert!(all.contains(&first.to_string()), "{all:?}");
        assert!(!all.join("\n").contains("Nothing is waiting"), "{all:?}");
        let all = after_lines(&seen(json!(["a"]), 1), 2).join("\n");
        assert!(
            all.contains("keep this machine on: 1 name still to send"),
            "{all}"
        );
        assert!(
            all.contains(
                "keep this machine on: 2 folders mapped here have still to sync for the first \
                 time since the recovery, and what they publish is then to send"
            ),
            "{all}"
        );

        // Which folders have still to sync, as the node's sync status
        // says. Sync is off, or nothing is mapped: none.
        let status = |enabled: bool, mapped: usize, no_report_secs: u64, report: Value| {
            let mappings: Vec<Value> = (0..mapped).map(|n| json!({ "name": n })).collect();
            json!({
                "enabled": enabled, "mappings": mappings, "no_report_secs": no_report_secs,
                "report": report,
            })
        };
        let folders = |waiting: &[bool]| {
            let folders: Vec<Value> = waiting.iter().map(|w| json!({ "waiting": w })).collect();
            json!({ "folders": folders })
        };
        let since = Duration::from_secs(10);
        let cycled = folders(&[false, false]);
        let one_waits = folders(&[false, true]);
        let to_come = |status: Value| first_syncs_to_come(&status, since);
        assert_eq!(to_come(status(false, 2, 1, one_waits.clone())), 0);
        assert_eq!(to_come(status(false, 2, 11, Value::Null)), 0);
        assert_eq!(to_come(status(true, 0, 1, one_waits.clone())), 0);
        // A cycle has reported since the change: each folder that it
        // says waits.
        assert_eq!(to_come(status(true, 2, 1, cycled.clone())), 0);
        assert_eq!(to_come(status(true, 2, 9, one_waits.clone())), 1);
        // None has, or there is no report: each mapped folder.
        assert_eq!(
            first_syncs_to_come(&status(true, 2, 10, cycled.clone()), since),
            2
        );
        assert_eq!(first_syncs_to_come(&status(true, 2, 11, cycled), since), 2);
        assert_eq!(
            first_syncs_to_come(&status(true, 3, 1, Value::Null), since),
            3
        );
        let unsaid = json!({ "enabled": true, "mappings": [{}], "report": one_waits });
        assert_eq!(first_syncs_to_come(&unsaid, since), 1);
    }

    /// Of a record that does not count nothing is asked, and its key is
    /// not removed by the recovery (decision 2026-10-04 §9, step 3):
    /// unless the change recovered from had removed that key already,
    /// and then it is said to stay removed.
    #[test]
    fn test_what_is_said_of_a_record_of_which_nothing_is_asked() {
        assert_eq!(
            not_asked_says(false),
            "  It is no device: nothing is asked of it, nothing that it wrote is brought back, \
             and its key is not removed."
        );
        assert_eq!(
            not_asked_says(true),
            "  It is no device: nothing is asked of it, and nothing that it wrote is brought \
             back. Its key was removed before this recovery, and stays removed."
        );
    }
}
