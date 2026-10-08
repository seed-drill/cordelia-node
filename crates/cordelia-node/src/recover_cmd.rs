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
//!    for the bound of 64 counted devices, and a key signed it that may
//!    add and is not in someone else's hands, by what was said of it and
//!    of the device that added it. Such a key is asked about all the
//!    same: nothing is taken from it, and said to be gone it is removed.
//!    Where it is not asked about, the command says how its key is
//!    removed afterwards, if it is a device of the person's. Where
//!    more records of additions were written than a recovery keeps, it
//!    says before the first question, and again before its yes, how many
//!    keys of records that it read have no row at all, and how many rows
//!    that do not count are of a key one of whose records it did not
//!    keep: the line of such a row, where nothing is asked of it, says
//!    how its key is removed afterwards too.
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

use crate::carry_cmd::{Sessions, entries_handed, key_written, read_with_secret};
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
///
/// **A key that fails only for the bound of 64 counted devices, and is
/// not asked about, may be a device of the person's:** each key that
/// added it may be in someone else's hands. The row says how its key is
/// removed afterwards, and what then brings in what it wrote, with the
/// key written whole, as both commands take it ([`removed_afterwards`]).
///
/// **So may a key one of whose records was read and is not among those
/// kept** ([`Row::record_let_go`]): the record that went may be the one
/// by which it would have been asked about. Its row says the same.
fn not_asked_says(row: &Row, removed: bool) -> String {
    // Whether the row may be of a device of the person's: a record of
    // its key fails only for the bound of 64, or one that was read for
    // its key is not among the records kept.
    let may_be_a_device = !row.no_room.is_empty() || row.record_let_go;
    match (removed, !may_be_a_device) {
        (true, _) => "  It is no device: nothing is asked of it, and nothing that it wrote is \
                      brought back. Its key was removed before this recovery, and stays removed."
            .to_string(),
        (false, true) => NOT_ASKED.to_string(),
        (false, false) => format!(
            "{NOT_ASKED} If it is a device of yours that is gone, {}. One that you still have is \
             added again by hand.",
            removed_afterwards(&key_written(&row.key))
        ),
    }
}

/// What is said of a record that does not count and whose key no change
/// has removed.
const NOT_ASKED: &str = "  It is no device: nothing is asked of it, nothing that it wrote is \
    brought back, and its key is not removed.";

/// How the key of a device that a recovery asked nothing of is removed
/// afterwards, on the machine that has recovered, and what then brings
/// in what that device wrote (decision 2026-10-04 §9, step 3). `key` is
/// the key written whole, or what stands for one.
///
/// `cordelia remove-device` takes a key that is in no list of the last
/// change: it says that this is no device it knows of, and asks a typed
/// word before the yes and the phrase. The key is then a removed key,
/// which `cordelia sync carry --from` names by that same writing, and
/// the machine still holds the secret of the generation recovered from.
fn removed_afterwards(key: &str) -> String {
    format!(
        "its key is removed afterwards, on this machine, by `cordelia remove-device {key}`, and \
         what it wrote then comes in by `cordelia sync carry <name> --from {key}`, with the phrase"
    )
}

/// What is said, in the place of nothing, of a key that is asked about
/// though it does not count (decision 2026-10-04 §9, step 3): its record
/// fails only for the bound of 64 counted devices, and a key signed it
/// that may add and is not in someone else's hands
/// ([`recover::asked_for_room`]). What each answer does is another thing
/// for it than for a device that counts. **Each key that is said to be
/// gone takes one of the removals that the phrase has left,** and `left`
/// is how many there are now.
fn asked_for_room_says(left: usize) -> String {
    format!(
        "  That is the one thing its record fails for, so it is asked about all the same. \
         Nothing that it wrote is brought back by this recovery, whatever is said of it: `lost` \
         or `hands` removes its key, and what it wrote then comes in by `cordelia sync carry \
         <name> --from <device>`, with the phrase; `have` leaves it to be added again by hand. \
         Each key that is removed takes one of the removals that the recovery phrase has left: \
         {left} of {MAX_STATEMENT_REMOVED}."
    )
}

/// What is said of a key that is asked about for the bound of 64 alone,
/// before its answer is asked: what is said of any row ([`row_says`]),
/// and what the answers do for it ([`asked_for_room_says`]). `under` is
/// the key for whose record it is asked about: where the row shows
/// another that added it, this one is named too. `left` is how many
/// removals the phrase has left.
fn for_room_says(rows: &[Row], at: usize, number: u64, under: &[u8; 32], left: usize) -> String {
    let mut says = row_says(rows, at, number);
    if rows[at].added_by.is_some_and(|(shown, _)| shown != *under) {
        let label = rows.iter().find(|row| row.key == *under);
        let label = label.map(|row| row.label.as_str()).unwrap_or_default();
        says.push_str(&format!("\n  {} added it too.", named(label, under)));
    }
    format!("{says}\n{}", asked_for_room_says(left))
}

/// The key for whose record a row that does not count is asked about
/// all the same ([`recover::asked_for_room`]): **none where a change has
/// removed the row's key already** (decision 2026-10-04 §9, step 3).
/// `removed` says whether one has: the change recovered from, or one
/// made apart from it, which the recovery settles. Such a key stays
/// removed whatever is said of it, so nothing is asked, and the row says
/// what a removed key's row says.
fn asked_though_it_does_not_count(
    rows: &[Row],
    answers: &[Answer],
    at: usize,
    removed: bool,
) -> Option<([u8; 32], u64)> {
    match removed {
        true => None,
        false => recover::asked_for_room(rows, answers, at),
    }
}

/// How many removals the phrase has left, as a row is asked about
/// (decision 2026-10-04 §9, step 3): what the change has room for
/// ([`recover::Room::can_go`]), less each key that was said to be gone
/// so far and that no change had removed.
fn removals_left(
    room: &recover::Room,
    rows: &[Row],
    answers: &[Answer],
    removed: impl Fn(&[u8; 32]) -> bool,
) -> usize {
    let said_gone = recover::gone(rows, answers);
    let taken = said_gone.iter().filter(|key| !removed(key)).count();
    room.can_go.saturating_sub(taken)
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

/// What is said of the records beyond the rows that are shown, where
/// there are any (decision 2026-10-04 §9, step 3): how many, and that
/// nothing is asked of them. A device of the person's may be among
/// them: the new machine keeps each key as left out, `cordelia devices`
/// shows it there, and its key is removed afterwards as that of a row
/// that was not asked about is ([`removed_afterwards`]).
fn not_shown_says(not_shown: usize) -> Option<String> {
    if not_shown == 0 {
        return None;
    }
    Some(format!(
        "{} beyond the {RECOVERY_MAX_DEVICES_SHOWN} that are shown: nothing is asked of those. \
         If one of them is a device of yours that is gone, `cordelia devices` on this machine \
         shows each with its key: {}.",
        counted(not_shown, "more record"),
        removed_afterwards("<key>")
    ))
}

/// What is said where a recovery did not keep every record of an
/// addition that it read (decision 2026-10-04 §9, step 3): a reader
/// keeps 256 records that do not count, the oldest it saw going first,
/// so where more were written, one that was read is not among them.
/// `number` is the number of the change recovered from. It gives two
/// numbers, and is said where either is not 0:
///
/// - **how many keys have no row at all** ([`Generation::no_row`]): no
///   record that was read for such a key was kept. Nothing is asked of
///   it, nothing that it wrote is brought back, and this machine does
///   not hold its key;
/// - **how many rows that do not count are of a key one of whose records
///   was not kept** ([`rows_of_a_record_let_go`]): the row is by another
///   record, and the one that went may be the one by which the key would
///   have been asked about. Where nothing is asked of such a row, its
///   line gives its key ([`not_asked_says`]).
///
/// **A device of the person's that was added since the change, and that
/// the bound of 64 kept out, may be among either.** Its key is removed
/// afterwards as that of a row that was not asked about is
/// ([`removed_afterwards`]), and one that the person still has is added
/// again by hand.
///
/// It is said before the first question ([`said_first`]), and again
/// before the yes ([`will_do_lines`]).
fn no_row_says(generation: &Generation, number: u64) -> Option<String> {
    let (no_row, rows) = (generation.no_row, rows_of_a_record_let_go(generation));
    if no_row == 0 && rows == 0 {
        return None;
    }
    let mut found = Vec::new();
    let mut of_each = String::new();
    if no_row > 0 {
        found.push(format!(
            "Records of additions were read for {} that {} not shown here at all",
            counted(no_row, "key"),
            match no_row {
                1 => "is",
                _ => "are",
            }
        ));
        of_each.push_str(
            " Nothing is asked of a device whose key is not shown, and nothing that it wrote is \
             brought back. This machine cannot show its key.",
        );
    }
    if rows > 0 {
        found.push(format!(
            "{} of a key one of whose records was read and not kept",
            match rows {
                1 => "1 row that does not count is".to_string(),
                n => format!("{n} rows that do not count are"),
            }
        ));
        of_each.push_str(
            " Where nothing is asked of such a row, nothing that its device wrote is brought \
             back, and its line gives its key.",
        );
    }
    Some(format!(
        "{}, because more were written than a recovery keeps. A device of yours that was added \
         since change {number} may be among them.{of_each} If it is a device of yours that is \
         gone, {}. One that you still have is added again by hand.",
        found.join(", and "),
        removed_afterwards("<key>")
    ))
}

/// How many of the rows that are shown do not count and are of a key
/// one of whose records was read and is not among those kept
/// ([`Row::record_let_go`]). A row that counts is asked about whatever
/// became of another record of its key, and is not among them.
fn rows_of_a_record_let_go(generation: &Generation) -> usize {
    let rows = generation.rows.iter();
    rows.filter(|row| !row.counts && row.record_let_go).count()
}

/// What is said before the first question, once the rows are introduced
/// (decision 2026-10-04 §9, step 3), each after an empty line: where the
/// answers could not all be kept ([`room_says`]), and where the recovery
/// did not keep every record that it read ([`no_row_says`]).
fn said_first(room: &recover::Room, generation: &Generation, number: u64) -> Vec<String> {
    let mut says: Vec<String> = room_says(room).into_iter().collect();
    says.extend(no_row_says(generation, number).map(|says| format!("\n{says}")));
    says
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
/// about, nothing that it wrote is brought back, and this machine cannot
/// show its key. **It may be a device that is gone, or one that the
/// person still has,** and `cordelia remove-device` removes a key for
/// good: so it is said as the line of a row that is not asked about says
/// it ([`not_asked_says`]). If it is a device that is gone, its key is
/// removed afterwards, and what it wrote then comes in
/// ([`removed_afterwards`], with the key written whole for both
/// commands); one that the person still has is added again by hand.
const A_MISSING_DEVICE: &str = "A device that is missing from what was read is not asked about \
    here, nothing that it wrote is brought back, and this machine cannot show its key. If it is a \
    device of yours that is gone, its key is removed afterwards, on this machine, by `cordelia \
    remove-device <key>`, and what it wrote then comes in by `cordelia sync carry <name> --from \
    <key>`, with the phrase. One that you still have is added again by hand.";

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
    /// Those of them that were read to their end at no relay, each by
    /// its change's number: where every relay says that it holds none of
    /// such a channel, or the node says nothing of any relay, nothing of
    /// it was read.
    before_at_no_relay: Vec<u64>,
}

impl WasRead {
    /// Note what was read of the personal channel of a generation
    /// before, of the change numbered `number`: `relays` is what the node
    /// says of each relay ([`Self::before`],
    /// [`Self::before_at_no_relay`]).
    fn read_before(&mut self, number: u64, relays: &[Value]) {
        let not_read = not_read_at(relays);
        if !not_read.is_empty() {
            self.before.push((number, not_read));
        }
        if !relays.iter().any(|relay| read_as(relay) == ReadAs::Whole) {
            self.before_at_no_relay.push(number);
        }
    }

    /// Whether everything that the recovery read for was read to its
    /// end: the personal channel of the change recovered from at one
    /// relay at least, with no relay at which it was read in part or
    /// not at all, and each personal channel of a generation before,
    /// **at one relay at least** and with no relay at which it was not.
    /// Only then is a name that is not listed said to be listed nowhere:
    /// a channel that no relay holds, or that the node said nothing of,
    /// was not read to its end.
    fn to_the_end(&self) -> bool {
        let of = &self.personal;
        of.any(ReadAs::Whole)
            && !of.any(ReadAs::Part)
            && !of.any(ReadAs::Nothing)
            && self.before.is_empty()
            && self.before_at_no_relay.is_empty()
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
/// §9): from whom the look takes and from whom it takes nothing; how
/// many records could not be shown, and where the recovery did not keep
/// every record that it read, how many keys have no row at all and how
/// many rows are of a key one of whose records went ([`no_row_says`]);
/// the names that are carried, and those that are left; and what stops.
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
    lines.extend(no_row_says(generation, was_read.number));
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
    // Before anything is asked: whether the answers could all be kept,
    // and how many keys a record was read for that have no row.
    let apart_statement = apart.as_ref().map(|other| &other.statement.statement);
    let room = recover::room(&statement, apart_statement, rows, &own);
    for says in said_first(&room, &generation, statement.number) {
        println!("{says}");
    }
    // Whether a change has removed a key already: the one recovered
    // from, or the one made apart from it.
    let removed_already = |key: &[u8; 32]| {
        statement.removes(key) || apart_statement.is_some_and(|other| other.removes(key))
    };
    let mut answers: Vec<Answer> = Vec::new();
    for at_row in 0..rows.len() {
        let says = row_says(rows, at_row, statement.number);
        if rows[at_row].key == own {
            println!("{says}\n  It is this machine: it is the one device of the change.");
            answers.push(Answer::Have);
            continue;
        }
        // A record that does not count is shown as that, and nothing is
        // asked of it: unless only the bound of 64 kept its key out, a
        // key signed it that may add and is not in someone else's
        // hands, and no change has removed its key already.
        if !rows[at_row].counts {
            let removed = removed_already(&rows[at_row].key);
            let under = asked_though_it_does_not_count(rows, &answers, at_row, removed);
            let Some((under, _)) = under else {
                println!("{says}\n{}", not_asked_says(&rows[at_row], removed));
                answers.push(Answer::NotAsked);
                continue;
            };
            let left = removals_left(&room, rows, &answers, removed_already);
            let says = for_room_says(rows, at_row, statement.number, &under, left);
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
    if let Some(says) = not_shown_says(generation.not_shown.len()) {
        println!("\n{says}");
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
        ..Default::default()
    };
    for earlier in &for_phrase.earlier {
        let personal = Zeroizing::new(derive::personal_secret(&earlier.secret)?);
        let what = format!("the personal channel of change {}", earlier.number);
        let (handed, relays) = read_channel(config_path, &personal, &mut sessions, &own, &what)?;
        was_read.read_before(earlier.number, &relays);
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
    let cut_short = CutShort::of(&generation, &was_read);
    goes_on_in_a_new_process(config_path, signs.number, cut_short)
}

/// The device that a recovery was made from, where its word that it had
/// sent what it carried is not among what was read (decision 2026-10-04
/// §8; §9, step 5): what is said of it once the look has ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutShort {
    /// The device, as it is shown.
    pub device: String,
    /// Whether the word may be in what was not read: the personal
    /// channel that it is written in was read to its end at no relay,
    /// and at one relay at least it was read in part, or not at all.
    /// (Where each relay that answered holds none of the channel,
    /// nothing of it was left unread.)
    pub read_in_part: bool,
}

impl CutShort {
    /// What a recovery knows of the device that it was made from, of
    /// what it read: `None` where the word was read, or the change lists
    /// more devices than one ([`Generation::cut_short`]).
    fn of(generation: &Generation, was_read: &WasRead) -> Option<Self> {
        let key = generation.cut_short?;
        let label = generation.rows.iter().find(|row| row.key == key);
        let label = label.map(|row| row.label.clone()).unwrap_or_default();
        let of = &was_read.personal;
        let not_read = of.any(ReadAs::Part) || of.any(ReadAs::Nothing);
        Some(Self {
            device: named(&label, &key),
            read_in_part: !of.any(ReadAs::Whole) && not_read,
        })
    }

    /// What hands this to the process that waits for the look
    /// ([`recover_made`]), as that command reads it.
    pub fn args(&self) -> Vec<String> {
        let mut args = vec!["--cut-short".to_string(), self.device.clone()];
        if self.read_in_part {
            args.push("--read-in-part".to_string());
        }
        args
    }

    /// What the process that waits for the look was handed
    /// ([`Self::args`]), as its command read it: the device, where one
    /// was named, and whether its channel was read to its end at no
    /// relay.
    pub fn handed(device: Option<String>, read_in_part: bool) -> Option<Self> {
        device.map(|device| Self {
            device,
            read_in_part,
        })
    }

    /// What is said of the device once the look has ended. **Where the
    /// channel was read to its end at a relay, or no relay that answered
    /// holds any of it, the device never wrote the word,** and a
    /// recovery, or a change, that was made on it was cut short. Where
    /// it was read to its end at no relay, and in part or not at all at
    /// one, the word was not found in what was read, and may be in what
    /// was not: the recovery or change may have been cut short.
    fn says(&self) -> String {
        let device = &self.device;
        let brings = "`cordelia sync carry <name> --from <device>` brings it in, with the \
                      phrase, and lists those devices where no device is named.";
        match self.read_in_part {
            false => format!(
                "The device that this was recovered from, {device}, never wrote that it had \
                 sent what it carried: a recovery, or a change, that was made on it was cut \
                 short. What it had sent is brought back. What the devices that were gone \
                 before it wrote, in the files it had not sent, is at the relays in the \
                 generation before: {brings}"
            ),
            true => format!(
                "The word of the device that this was recovered from, {device}, that it had \
                 sent what it carried was not found in what was read: its personal channel was \
                 read to its end at no relay, and the word may be in what was not read. A \
                 recovery, or a change, that was made on it may have been cut short. What it \
                 had sent is brought back. If it was cut short, what the devices that were gone \
                 before it wrote, in the files it had not sent, is at the relays in the \
                 generation before: {brings}"
            ),
        }
    }
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
    cut_short: Option<CutShort>,
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
                command.args(cut_short.iter().flat_map(CutShort::args));
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
    cut_short: Option<CutShort>,
) -> anyhow::Result<()> {
    // The change was made a moment before this process began: by the
    // clock that cannot go back, and by the time of day.
    let began = std::time::Instant::now();
    let began_at = chrono::Utc::now();
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
    if let Some(cut_short) = cut_short {
        println!("{}", cut_short.says());
    }
    // What a folder that is mapped here has still to publish is in no
    // store yet: whether each has synced since the recovery is asked of
    // the node's sync status, and then what the device holds. For how
    // long this process has run is read before either.
    let began = Began {
        for_secs: began.elapsed().as_secs(),
        at: began_at,
    };
    let (sync, seen) = status_then_holds(
        || crate::api_post(config_path, "/api/v1/sync/status", json!({})).ok(),
        || look(config_path),
    );
    let seen = seen?;
    let to_come = match &sync {
        Some(sync) => folders_to_come(sync, &began),
        // The status could not be had: with sync on, each folder that is
        // mapped is taken not to have synced.
        None if seen["sync_on"] == true => seen["folders"].as_u64().unwrap_or(0) as usize,
        None => 0,
    };
    for line in after_lines(&seen, to_come) {
        println!("{line}");
    }
    Ok(())
}

/// Read the sync status, and then what the device holds: **in that
/// order** (decision 2026-10-04 §16). What a folder's cycle publishes is
/// in the store before the cycle's report is. Read so, a cycle that ends
/// between the two readings is one whose report was not read, and its
/// folder is said to have still to sync. Read the other way, what it
/// published would be in neither: not in what the device held, and its
/// folder not among those still to sync.
fn status_then_holds<S, H>(status: impl FnOnce() -> S, holds: impl FnOnce() -> H) -> (S, H) {
    let status = status();
    (status, holds())
}

/// When `recover_made` began, which is a moment after the change of the
/// recovery was applied: never earlier than that.
struct Began {
    /// For how many whole seconds the process had run when it went on
    /// to ask for the sync status, by the clock that cannot go back.
    for_secs: u64,
    /// When it began, by the time of day.
    at: chrono::DateTime<chrono::Utc>,
}

/// Whether the report that the sync status `sync` carries is of a cycle
/// that began after the change of this recovery was applied (decision
/// 2026-10-04 §16).
///
/// The status does not say when a cycle began. It says when the cycle's
/// report was stored, which is never earlier than that: by the time of
/// day (the report's `at`), and by the node's own clock (for how long it
/// has stored none, `no_report_secs`). **A report that was stored after
/// the change is of a cycle that began after it:** a cycle reads the
/// count of changes to the settings first, a report is stored only where
/// that count still stands, and applying a change counts as one, under
/// the hold of the lock that it is applied under.
///
/// So the report counts only where both clocks say that it was stored
/// after this command began, which was after the change:
///
/// - by the node's own clock, it has stored none for less long than this
///   command had run when it asked. (After a start, the node counts from
///   its start: a report of an earlier run passes this.)
/// - by the time of day, the report was stored after this command
///   began. (A report of an earlier run, from before the recovery, does
///   not pass this.)
fn reported_since(sync: &Value, began: &Began) -> bool {
    let no_report_for = sync["no_report_secs"].as_u64().unwrap_or(u64::MAX);
    let by_its_own_clock = no_report_for < began.for_secs;
    let stored_at = sync["report"]["at"].as_str();
    let stored_at = stored_at.and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok());
    let by_the_time_of_day = stored_at.is_some_and(|at| at > began.at);
    by_its_own_clock && by_the_time_of_day
}

/// Whether the cycle of `report` synced the folder of `mapping`: the
/// report has a row for it, which did not end in error, was not broken
/// off, has no file that failed, and does not wait for its first cycle.
/// A folder that the cycle passed by has no row.
fn synced_in(report: &Value, mapping: &Value) -> bool {
    let of_it = |folder: &&Value| {
        folder["cwd"] == mapping["folder"] && folder["project"] == mapping["name"]
    };
    let failed = |folder: &Value| {
        list(folder, "failed").next().is_some() || folder["failed_more"].as_u64().unwrap_or(0) > 0
    };
    list(report, "folders").find(of_it).is_some_and(|folder| {
        folder["waiting"] != true
            && folder["error"].is_null()
            && folder["stopped"] != true
            && !failed(folder)
    })
}

/// How many folders that this machine maps are not known to have synced
/// since the recovery (decision 2026-10-04 §9, step 5; §16), as the
/// node's sync status `sync` says. A folder's first cycle in a name
/// waits until the look has read that name. What it then publishes is to
/// be sent, and until that cycle has run none of it is in the store,
/// where what waits is counted.
///
/// None where sync is off, or no folder is mapped: no cycle publishes
/// anything. Otherwise **every mapped folder, unless the report is of a
/// cycle that began after the change was applied** ([`reported_since`])
/// and that published: a cycle of a device that follows no phrase, or
/// has stopped, says that it publishes nothing. And of such a report,
/// each mapped folder that it does not show as synced ([`synced_in`]):
/// one that ended in error, one that the cycle passed by, and one that
/// has still to sync for the first time.
fn folders_to_come(sync: &Value, began: &Began) -> usize {
    let mapped: Vec<&Value> = list(sync, "mappings").collect();
    if sync["enabled"] != true || mapped.is_empty() {
        return 0;
    }
    // A status with no report says of none when it was stored.
    let report = &sync["report"];
    let published = report["publishes_nothing"].is_null();
    if !reported_since(sync, began) || !published {
        return mapped.len();
    }
    let not_synced = |mapping: &&&Value| !synced_in(report, mapping);
    mapped.iter().filter(not_synced).count()
}

/// What is said once the look has ended, of what the node says of this
/// machine (decision 2026-10-04 §9, steps 5 and 6): which relay holds
/// the change; "keep this machine on" with how many names are still to
/// send; and, for each device that the person still has, how it is added
/// again.
///
/// **That nothing is waiting is said only where that was read**
/// (decision 2026-10-04 §16), **and never beside a line that says to keep
/// the machine on:** a relay that does not hold the change yet, or one
/// that is not connected. Beside the names, the machine's personal
/// channel is to be sent, which lists them: the node says how many of
/// the machine's channels wait at each relay that is connected, and
/// where no name does and a channel does, that is said. `to_come`
/// folders that are mapped here are not known to have synced since the
/// recovery ([`folders_to_come`]): what they publish is not in the store
/// yet. And **with no relay connected, what waits is not known:** that
/// is said, and nothing is said to wait nowhere.
///
/// Whatever else is said says to keep the machine on, and names the
/// command that shows when nothing waits.
fn after_lines(seen: &Value, to_come: usize) -> Vec<String> {
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
    let not_reached: Vec<&str> = list(seen, "not_reached")
        .filter_map(Value::as_str)
        .collect();
    for relay in &not_reached {
        lines.push(format!(
            "keep this machine on: {relay} is not connected, and what is still to send there is \
             not known until it is."
        ));
    }
    // The node says what waits at each relay that is connected: with no
    // such row, none is, whether or not one was named as not reached.
    let connected = list(seen, "waiting").count();
    if connected == 0 && not_reached.is_empty() {
        lines.push(
            "keep this machine on: no relay is connected, and what is still to send is not \
             known until one is."
                .to_string(),
        );
    }
    let to_go = list(&seen["names"], "to_go").count();
    // The channels of this machine's own that wait at a relay which is
    // connected: its personal channel among them.
    let channels = |relay: &Value| relay["waits"].as_u64().unwrap_or(0);
    let channels_wait = list(seen, "waiting").any(|relay| channels(relay) > 0);
    // Whether a line above says to keep the machine on for a relay: one
    // that does not hold the change yet, or one that is not connected.
    // Nothing is said to be waiting nowhere beside such a line.
    let holds_the_change = |relay: &Value| relay["holds_latest"].as_bool() == Some(true);
    let keep_on = !not_reached.is_empty() || !list(seen, "relays").all(holds_the_change);
    match (to_go, channels_wait) {
        (0, false) if keep_on => {}
        (0, false) if to_come == 0 && connected > 0 => lines.push(
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
    if to_come > 0 {
        lines.push(format!(
            "keep this machine on: {} mapped here {} not known to have synced since the \
             recovery, and what {} is then to send. `cordelia sync status` shows each folder.",
            counted(to_come, "folder"),
            match to_come {
                1 => "is",
                _ => "are",
            },
            match to_come {
                1 => "it publishes",
                _ => "they publish",
            }
        ));
    }
    let nothing_waits = to_go == 0 && !channels_wait && to_come == 0 && connected > 0 && !keep_on;
    if !nothing_waits {
        lines.push(
            "`cordelia devices` shows what this machine has still to send, and when nothing is \
             left."
                .to_string(),
        );
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
            record_let_go: false,
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
    /// `hands` removes its key, and `have` leaves it to be added again;
    /// and each key that is removed takes one of the removals that the
    /// phrase has left, with how many are left. Before the yes it is
    /// named among those from whom the look takes nothing, where it was
    /// said to be gone.
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
        let asked = for_room_says(&rows, 4, 7, &[1; 32], 191);
        assert!(asked.starts_with(&says), "{asked}");
        assert!(!asked.contains("added it too"), "{asked}");
        assert!(
            asked.ends_with(
                "\n  That is the one thing its record fails for, so it is asked about all the \
                 same. Nothing that it wrote is brought back by this recovery, whatever is said \
                 of it: `lost` or `hands` removes its key, and what it wrote then comes in by \
                 `cordelia sync carry <name> --from <device>`, with the phrase; `have` leaves it \
                 to be added again by hand. Each key that is removed takes one of the removals \
                 that the recovery phrase has left: 191 of 256."
            ),
            "{asked}"
        );
        assert!(
            for_room_says(&rows, 4, 7, &[1; 32], 0).ends_with("has left: 0 of 256."),
            "the number that is left is said"
        );
        // How many are left, as the row is asked about: what the change
        // has room for, less each key that was said to be gone so far.
        // A key that a change had removed already takes none.
        let room = recover::Room {
            removed: 60,
            asked: 4,
            can_go: 196,
        };
        let so_far = [Answer::Lost, Answer::OtherHands, Answer::Have];
        assert_eq!(removals_left(&room, &rows, &[], |_| false), 196);
        assert_eq!(removals_left(&room, &rows, &so_far, |_| false), 194);
        let was_removed = |key: &[u8; 32]| *key == [2; 32];
        assert_eq!(removals_left(&room, &rows, &so_far, was_removed), 195);
        let none = recover::Room { can_go: 1, ..room };
        assert_eq!(removals_left(&none, &rows, &so_far, |_| false), 0);
        // Asked about for the record of another device than the one
        // shown: that one is named too.
        let asked = for_room_says(&rows, 4, 7, &[2; 32], 191);
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
            ..Default::default()
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
        // A device that is missing from what was read may be gone, or
        // one that the person still has: the line says how the key of
        // one that is gone is removed afterwards, as the line of a row
        // that is not asked about says it, and that one the person
        // still has is added again by hand. And that this machine
        // cannot show its key.
        let missing_device = "A device that is missing from what was read is not asked about \
                              here, nothing that it wrote is brought back, and this machine \
                              cannot show its key. If it is a device of yours that is gone, its \
                              key is removed afterwards, on this machine, by `cordelia \
                              remove-device <key>`, and what it wrote then comes in by `cordelia \
                              sync carry <name> --from <key>`, with the phrase. One that you still \
                              have is added again by hand.";
        assert_eq!(A_MISSING_DEVICE, missing_device);
        assert!(A_MISSING_DEVICE.contains(&format!(
            "If it is a device of yours that is gone, {}. One that you still have is added \
             again by hand.",
            removed_afterwards("<key>")
        )));
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
        // As the node says of each relay: the channel of change 2 was
        // read to its end at one relay and in part at the other, and
        // that of change 1 at no relay.
        before.read_before(2, &[said("one", "whole", 3), said("two", "part", 1)]);
        before.read_before(1, &[said("one", changed, 0), said("two", "part", 0)]);
        assert_eq!(
            before.before,
            [
                (2, vec!["two".to_string()]),
                (1, vec!["one".to_string(), "two".to_string()]),
            ]
        );
        assert_eq!(before.before_at_no_relay, [1]);
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

        // Read to its end at one relay and in part at the other: it was
        // not read to its end at every relay, and no name is said to be
        // listed nowhere.
        let mut at_one_only = read_whole();
        at_one_only.read_before(2, &[said("one", "whole", 3), said("two", "part", 1)]);
        assert_eq!(at_one_only.before, [(2, vec!["two".to_string()])]);
        assert!(at_one_only.before_at_no_relay.is_empty());
        assert!(!at_one_only.to_the_end());

        // **A personal channel of a generation before that no relay
        // holds, or of which the node said nothing of any relay, was
        // read to its end at no relay:** no name is then said to be
        // listed nowhere. None is listed in what was read.
        for relays in [
            vec![said("one", "not held", 0), said("two", "not held", 0)],
            Vec::new(),
        ] {
            let mut held_nowhere = read_whole();
            held_nowhere.read_before(2, &relays);
            assert!(held_nowhere.before.is_empty(), "{relays:?}");
            assert_eq!(held_nowhere.before_at_no_relay, [2], "{relays:?}");
            assert!(!held_nowhere.to_the_end(), "{relays:?}");
            let lines = will_do_lines(&generation, &answers, &none, &own, &held_nowhere);
            let all = lines.join("\n");
            assert!(all.contains(in_what_was_read), "{relays:?}: {all}");
            assert!(!all.contains(alone), "{relays:?}: {all}");
        }
        // Read to its end at one relay, where the other holds none of
        // it: it was read to its end, and so was everything.
        let mut held_at_one = read_whole();
        held_at_one.read_before(2, &[said("one", "not held", 0), said("two", "whole", 0)]);
        held_at_one.read_before(1, &[said("one", "whole", 2), said("two", "whole", 2)]);
        assert!(held_at_one.before.is_empty() && held_at_one.before_at_no_relay.is_empty());
        assert!(held_at_one.to_the_end());
        let all = will_do_lines(&generation, &answers, &none, &own, &held_at_one).join("\n");
        assert!(all.contains(alone), "{all}");
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

    /// Where a recovery did not keep every record of an addition that it
    /// read, the command says so (decision 2026-10-04 §9, step 3), with
    /// two numbers: how many keys have no row at all, and how many rows
    /// that do not count are of a key one of whose records was not kept.
    /// It says that a device of the person's added since the change may
    /// be among them; of a key that is not shown, that nothing is asked
    /// of it, that nothing it wrote is brought back, and that this
    /// machine cannot show its key; of such a row, that its line gives
    /// its key where nothing is asked of it; how a key is removed
    /// afterwards where its device is gone; and that one the person
    /// still has is added again by hand. It is said where either number
    /// is not 0: before the first question, after what is said where the
    /// answers could not all be kept, and again before the yes.
    #[test]
    fn test_what_is_said_of_the_keys_whose_record_was_read_and_that_have_no_row() {
        let ends = "If it is a device of yours that is gone, its key is removed afterwards, on \
                    this machine, by `cordelia remove-device <key>`, and what it wrote then comes \
                    in by `cordelia sync carry <name> --from <key>`, with the phrase. One that you \
                    still have is added again by hand.";
        let of_a_key = "Nothing is asked of a device whose key is not shown, and nothing that it \
                        wrote is brought back. This machine cannot show its key.";
        let of_a_row = "Where nothing is asked of such a row, nothing that its device wrote is \
                        brought back, and its line gives its key.";
        let because = "because more were written than a recovery keeps. A device of yours that \
                       was added since change 7 may be among them.";
        // The rows of a test, with `let_go` more: each a row that does
        // not count, of a key one of whose records was not kept.
        let of = |no_row: usize, let_go: u8| {
            let mut rows = rows();
            for n in 0..let_go {
                let mut flagged = row(10 + n, "watch", Some(3), false);
                flagged.record_let_go = true;
                rows.push(flagged);
            }
            Generation {
                rows,
                no_row,
                ..Default::default()
            }
        };
        // Keys with no row, and no such row.
        let two = format!(
            "Records of additions were read for 2 keys that are not shown here at all, {because} \
             {of_a_key} {ends}"
        );
        assert_eq!(no_row_says(&of(0, 0), 7), None);
        assert_eq!(no_row_says(&of(2, 0), 7), Some(two.clone()));
        let one = no_row_says(&of(1, 0), 3).unwrap();
        assert!(
            one.starts_with(
                "Records of additions were read for 1 key that is not shown here at all, because"
            ),
            "{one}"
        );
        assert!(
            one.contains("added since change 3 may be among them"),
            "{one}"
        );
        // Such a row, and every key has a row: the sentence is said for
        // the row alone.
        let a_row = format!(
            "1 row that does not count is of a key one of whose records was read and not kept, \
             {because} {of_a_row} {ends}"
        );
        assert_eq!(no_row_says(&of(0, 1), 7), Some(a_row.clone()));
        let rows_alone = no_row_says(&of(0, 3), 7).unwrap();
        assert!(
            rows_alone.starts_with(
                "3 rows that do not count are of a key one of whose records was read and not \
                 kept, because"
            ),
            "{rows_alone}"
        );
        // Both: each number, and what is said of each.
        let both = format!(
            "Records of additions were read for 2 keys that are not shown here at all, and 1 row \
             that does not count is of a key one of whose records was read and not kept, \
             {because} {of_a_key} {of_a_row} {ends}"
        );
        assert_eq!(no_row_says(&of(2, 1), 7), Some(both.clone()));
        // A row that counts is asked about whatever became of another
        // record of its key: it is not among them. Nor is a row that
        // could not be shown, which this machine keeps with its key.
        let mut counts = of(0, 0);
        counts.rows[0].record_let_go = true;
        let mut not_shown = row(20, "beyond", Some(1), false);
        not_shown.record_let_go = true;
        counts.not_shown.push(not_shown);
        assert_eq!(rows_of_a_record_let_go(&counts), 0);
        assert_eq!(no_row_says(&counts, 7), None);
        assert_eq!(rows_of_a_record_let_go(&of(0, 3)), 3);

        // Before the first question: after what is said where the
        // answers could not all be kept, each after an empty line.
        let room = |removed: usize, asked: usize| recover::Room {
            removed,
            asked,
            can_go: MAX_STATEMENT_REMOVED - removed,
        };
        let (kept, tight) = (room(0, 64), room(251, 6));
        assert!(said_first(&kept, &of(0, 0), 7).is_empty());
        assert_eq!(said_first(&kept, &of(2, 0), 7), [format!("\n{two}")]);
        assert_eq!(said_first(&kept, &of(0, 1), 7), [format!("\n{a_row}")]);
        assert_eq!(said_first(&kept, &of(2, 1), 7), [format!("\n{both}")]);
        let not_every = room_says(&tight).unwrap();
        assert_eq!(
            said_first(&tight, &of(0, 0), 7),
            std::slice::from_ref(&not_every)
        );
        assert_eq!(
            said_first(&tight, &of(2, 0), 7),
            [not_every, format!("\n{two}")]
        );

        // Before the yes: after the line for the records that could not
        // be shown, which this machine keeps with their keys.
        let mut generation = Generation {
            not_shown: vec![row(5, "fifth", Some(1), false)],
            ..of(2, 0)
        };
        let answers = [Answer::Lost, Answer::Lost, Answer::Lost, Answer::NotAsked];
        let names = recover::Names::default();
        let read = WasRead {
            number: 7,
            ..read_whole()
        };
        let all = will_do_lines(&generation, &answers, &names, &[9; 32], &read).join("\n");
        assert!(
            all.contains(&format!(
                "`cordelia devices` shows it with its key.\n{two}\nNo name is carried"
            )),
            "{all}"
        );
        generation.not_shown.clear();
        let all = will_do_lines(&generation, &answers, &names, &[9; 32], &read).join("\n");
        assert!(
            all.contains(&format!("\n{two}\nNo name is carried")),
            "{all}"
        );
        // Every key has a row, and none of them is such a row: nothing
        // is said of it.
        generation.no_row = 0;
        let all = will_do_lines(&generation, &answers, &names, &[9; 32], &read).join("\n");
        assert!(!all.contains("Records of additions were read"), "{all}");
        assert!(!all.contains("cannot show its key"), "{all}");
        assert!(!all.contains("was read and not kept"), "{all}");
        // Such a row, with every key shown: said before the yes too.
        let with_a_row = of(0, 1);
        let answers = [
            Answer::Lost,
            Answer::Lost,
            Answer::Lost,
            Answer::NotAsked,
            Answer::NotAsked,
        ];
        let all = will_do_lines(&with_a_row, &answers, &names, &[9; 32], &read).join("\n");
        assert!(
            all.contains(&format!("\n{a_row}\nNo name is carried")),
            "{all}"
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
            no_row: 0,
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

    /// Once the look has ended, the command says of the device that it
    /// recovered from whether a recovery or a change made on it was cut
    /// short (decision 2026-10-04 §8; §9, step 5): its word that it had
    /// sent what it carried is not among what was read. **Where the
    /// personal channel was read to its end at a relay, the device never
    /// wrote the word, and it was cut short. Where it was read to its
    /// end at no relay, the word may be in what was not read:** it was
    /// not found in what was read, and it may have been cut short.
    /// Which of the two it is goes to the process that waits for the
    /// look as that command reads it.
    #[test]
    fn test_what_is_said_of_a_device_whose_word_that_it_sent_was_not_read() {
        let said = |relay: &str, read: &str, entries: u64| json!({ "relay": relay, "read": read, "entries": entries });
        let generation = |cut_short: Option<[u8; 32]>| Generation {
            rows: rows(),
            cut_short,
            ..Default::default()
        };
        let laptop = named("laptop", &[1; 32]);
        let of = |relays: &[Value]| CutShort::of(&generation(Some([1; 32])), &was_read(relays));
        // Read to its end at one relay: the word is not there.
        let whole = of(&[said("one", "whole", 4)]).unwrap();
        assert_eq!(
            whole,
            CutShort {
                device: laptop.clone(),
                read_in_part: false
            }
        );
        let whole_at_one = of(&[said("one", "part", 2), said("two", "whole", 4)]);
        assert_eq!(whole_at_one, Some(whole.clone()));
        // Read to its end at no relay, and in part or not at all at
        // one: the word may be in what was not read.
        let in_part = of(&[said("one", "part", 2), said("two", "not reached", 0)]).unwrap();
        assert_eq!(
            in_part,
            CutShort {
                device: laptop.clone(),
                read_in_part: true
            }
        );
        for not_read in [said("two", "part", 3), said("two", "not reached", 0)] {
            let beside_none_held = of(&[said("one", "not held", 0), not_read]);
            assert_eq!(beside_none_held, Some(in_part.clone()));
        }
        // No relay that answered holds any of the channel: nothing of it
        // was left unread, and the word is not there.
        let held_by_none = of(&[said("one", "not held", 0), said("two", "not held", 0)]);
        assert_eq!(held_by_none, Some(whole.clone()));
        assert_eq!(of(&[said("one", "not held", 0)]), Some(whole.clone()));
        // The word was read, or the change lists more devices than one.
        let read = was_read(&[said("one", "part", 2)]);
        assert_eq!(CutShort::of(&generation(None), &read), None);

        assert_eq!(
            whole.says(),
            format!(
                "The device that this was recovered from, {laptop}, never wrote that it had \
                 sent what it carried: a recovery, or a change, that was made on it was cut \
                 short. What it had sent is brought back. What the devices that were gone \
                 before it wrote, in the files it had not sent, is at the relays in the \
                 generation before: `cordelia sync carry <name> --from <device>` brings it in, \
                 with the phrase, and lists those devices where no device is named."
            )
        );
        let said_in_part = in_part.says();
        assert_eq!(
            said_in_part,
            format!(
                "The word of the device that this was recovered from, {laptop}, that it had \
                 sent what it carried was not found in what was read: its personal channel was \
                 read to its end at no relay, and the word may be in what was not read. A \
                 recovery, or a change, that was made on it may have been cut short. What it \
                 had sent is brought back. If it was cut short, what the devices that were gone \
                 before it wrote, in the files it had not sent, is at the relays in the \
                 generation before: `cordelia sync carry <name> --from <device>` brings it in, \
                 with the phrase, and lists those devices where no device is named."
            )
        );
        assert!(!said_in_part.contains("never wrote"), "{said_in_part}");
        assert!(
            !said_in_part.contains("made on it was cut short"),
            "{said_in_part}"
        );

        // What the process that waits for the look is handed.
        assert_eq!(whole.args(), ["--cut-short", laptop.as_str()]);
        assert_eq!(
            in_part.args(),
            ["--cut-short", laptop.as_str(), "--read-in-part"]
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
            "waiting": [{ "relay": "one", "waits": 1 }, { "relay": "two", "waits": 1 }],
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

        // Whatever is still to send, the command that shows when
        // nothing is left is named.
        assert!(
            lines.contains(
                &"`cordelia devices` shows what this machine has still to send, and when \
                  nothing is left."
                    .to_string()
            ),
            "{all}"
        );

        // With nothing to send, and nobody to add again.
        let done = json!({
            "this_device": "k", "relays": [{ "relay": "one", "holds_latest": true }],
            "waiting": [{ "relay": "one", "waits": 0 }],
            "names": { "to_go": [], "sent": ["a"] }, "left_out": [],
        });
        let all = after_lines(&done, 0).join("\n");
        assert!(all.contains("Nothing is waiting to be sent"), "{all}");
        assert!(!all.contains("keep this machine on"), "{all}");
        assert!(!all.contains("has still to send"), "{all}");
        assert!(!all.contains("added again"), "{all}");
        let one = json!({ "relays": [], "names": { "to_go": ["a"] } });
        assert!(
            after_lines(&one, 0)
                .contains(&"keep this machine on: 1 name still to send".to_string())
        );
    }

    /// That nothing is waiting to be sent is said only where that was
    /// read (decision 2026-10-04 §9, step 5; §16). The machine's personal
    /// channel, which lists the names, is to be sent too: where no name
    /// waits and a channel of the machine's own does, that is said. A
    /// folder that is mapped here and is not known to have synced since
    /// the recovery has still to publish: that is said, with the command
    /// that shows each folder. With no relay connected, what waits is
    /// not known: that is said, and nothing is said to wait nowhere.
    /// Whatever is said in the place of "nothing is waiting" names the
    /// command that shows when nothing is.
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
        let shows = "`cordelia devices` shows what this machine has still to send, and when \
                     nothing is left.";
        // Nothing waits anywhere.
        let all = after_lines(&seen(json!([]), 0), 0);
        assert!(all.contains(&nothing.to_string()), "{all:?}");
        assert!(!all.join("\n").contains("keep this machine on"), "{all:?}");
        assert!(!all.contains(&shows.to_string()), "{all:?}");
        // No name waits, and a channel of the machine's own does, at one
        // relay: its personal channel.
        let all = after_lines(&seen(json!([]), 1), 0);
        assert!(all.contains(&list_waits.to_string()), "{all:?}");
        assert!(all.contains(&shows.to_string()), "{all:?}");
        assert!(!all.join("\n").contains("Nothing is waiting"), "{all:?}");
        // Names wait: they are counted, as before.
        let all = after_lines(&seen(json!(["a", "b"]), 3), 0);
        assert!(
            all.contains(&"keep this machine on: 2 names still to send".to_string()),
            "{all:?}"
        );
        assert!(all.contains(&shows.to_string()), "{all:?}");
        assert!(!all.contains(&list_waits.to_string()), "{all:?}");
        // A folder is not known to have synced since the recovery:
        // nothing is said to be done, whatever waits in the store.
        let first = "keep this machine on: 1 folder mapped here is not known to have synced \
                     since the recovery, and what it publishes is then to send. `cordelia sync \
                     status` shows each folder.";
        let all = after_lines(&seen(json!([]), 0), 1);
        assert!(all.contains(&first.to_string()), "{all:?}");
        assert!(all.contains(&shows.to_string()), "{all:?}");
        assert!(!all.join("\n").contains("Nothing is waiting"), "{all:?}");
        let all = after_lines(&seen(json!(["a"]), 1), 2).join("\n");
        assert!(
            all.contains("keep this machine on: 1 name still to send"),
            "{all}"
        );
        assert!(
            all.contains(
                "keep this machine on: 2 folders mapped here are not known to have synced since \
                 the recovery, and what they publish is then to send. `cordelia sync status` \
                 shows each folder."
            ),
            "{all}"
        );

        // With no relay connected, the node says of no relay what waits
        // there. The line that says so is said, and "nothing is waiting"
        // is not: of each relay that is named as not reached, and where
        // none is named.
        let not_connected = |not_reached: Value| {
            json!({
                "this_device": "k", "relays": [{ "relay": "one", "holds_latest": true }],
                "names": { "to_go": [], "sent": [] }, "left_out": [],
                "waiting": [], "not_reached": not_reached,
            })
        };
        let all = after_lines(&not_connected(json!(["one"])), 0);
        assert_eq!(
            all[1],
            "keep this machine on: one is not connected, and what is still to send there is not \
             known until it is."
        );
        assert_eq!(all[2..], [shows.to_string()], "{all:?}");
        let all = after_lines(&not_connected(json!([])), 0);
        assert_eq!(
            all[1..],
            [
                "keep this machine on: no relay is connected, and what is still to send is not \
                 known until one is."
                    .to_string(),
                shows.to_string()
            ],
            "{all:?}"
        );
        // **Nothing is said to be waiting beside a line that says to
        // keep the machine on.** One relay is connected, and one is not:
        // nothing waits at the one that is, and what is still to send
        // at the other is not known. The command that shows when
        // nothing is left is named.
        let mut one_of_two = not_connected(json!(["two"]));
        one_of_two["waiting"] = json!([{ "relay": "one", "waits": 0 }]);
        let all = after_lines(&one_of_two, 0);
        assert_eq!(
            all,
            [
                "one holds the change.",
                "keep this machine on: two is not connected, and what is still to send there is \
                 not known until it is.",
                shows
            ]
        );
        // A relay that is connected does not hold the change yet, and
        // nothing waits in the store: the machine is to be kept on, and
        // nothing is said to be waiting nowhere beside that.
        let mut not_held_yet = seen(json!([]), 0);
        not_held_yet["relays"] = json!([
            { "relay": "one", "holds_latest": true },
            { "relay": "two", "holds_latest": false },
        ]);
        let all = after_lines(&not_held_yet, 0);
        assert_eq!(
            all,
            [
                "one holds the change.",
                "keep this machine on: two does not hold the change yet.",
                shows
            ]
        );
        // So where the node does not say whether a relay holds it.
        not_held_yet["relays"] = json!([{ "relay": "one" }]);
        let all = after_lines(&not_held_yet, 0);
        assert_eq!(
            all,
            [
                "keep this machine on: one does not hold the change yet.",
                shows
            ]
        );
        // Each relay holds the change, and each is connected: said.
        not_held_yet["relays"] = json!([
            { "relay": "one", "holds_latest": true },
            { "relay": "two", "holds_latest": true },
        ]);
        let all = after_lines(&not_held_yet, 0);
        assert_eq!(
            all,
            ["one holds the change.", "two holds the change.", nothing]
        );
    }

    /// The sync status is read first, and what the device holds after
    /// it (decision 2026-10-04 §16): a first cycle that ends between the
    /// two readings is then one whose report was not read, and its
    /// folder is said to have still to sync.
    #[test]
    fn test_the_sync_status_is_read_before_what_the_device_holds() {
        let read = std::cell::RefCell::new(Vec::new());
        let reads = |what: &'static str| {
            read.borrow_mut().push(what);
            what
        };
        let both = status_then_holds(|| reads("the sync status"), || reads("what it holds"));
        assert_eq!(both, ("the sync status", "what it holds"));
        assert_eq!(*read.borrow(), ["the sync status", "what it holds"]);
    }

    /// Which folders are not known to have synced since the recovery, as
    /// the node's sync status says (decision 2026-10-04 §16). A folder is
    /// known to have synced only where the report is of a cycle that
    /// began after the change was applied, and that cycle published, and
    /// the folder neither ended in error there, nor was passed by, nor
    /// has still to sync for the first time.
    #[test]
    fn test_a_folder_has_synced_only_where_a_cycle_since_the_change_says_so() {
        use chrono::TimeZone;
        // This command began ten seconds ago, at this time of day.
        let at = chrono::Utc.with_ymd_and_hms(2027, 1, 15, 8, 0, 0).unwrap();
        let began = Began { for_secs: 10, at };
        let later = "2027-01-15T08:00:05+00:00";
        let earlier = "2027-01-15T07:59:59+00:00";
        let folder =
            |n: usize| json!({ "cwd": format!("/home/sam/{n}"), "project": format!("n{n}") });
        let status = |enabled: bool, mapped: usize, no_report_secs: u64, report: Value| {
            let mappings: Vec<Value> = (0..mapped)
                .map(|n| json!({ "folder": format!("/home/sam/{n}"), "name": format!("n{n}") }))
                .collect();
            json!({
                "enabled": enabled, "mappings": mappings, "no_report_secs": no_report_secs,
                "report": report,
            })
        };
        // A report that was stored at `at`, with a row for each of two
        // folders, changed as `edit` says.
        let report = |at: &str, edit: &dyn Fn(&mut Value)| {
            let mut report = json!({ "at": at, "folders": [folder(0), folder(1)] });
            edit(&mut report);
            report
        };
        let synced = |at: &str| report(at, &|_| {});
        let to_come = |status: Value| folders_to_come(&status, &began);

        // Sync is off, or nothing is mapped: none.
        assert_eq!(to_come(status(false, 2, 1, synced(later))), 0);
        assert_eq!(to_come(status(false, 2, 11, Value::Null)), 0);
        assert_eq!(to_come(status(true, 0, 1, synced(later))), 0);
        // A cycle that began since the change says that both synced.
        assert_eq!(to_come(status(true, 2, 1, synced(later))), 0);
        assert_eq!(to_come(status(true, 2, 9, synced(later))), 0);

        // One has still to sync for the first time.
        let waits = report(later, &|r| r["folders"][1]["waiting"] = json!(true));
        assert_eq!(to_come(status(true, 2, 1, waits)), 1);
        // One ended in error; one was broken off; in one a file failed.
        let in_error = report(later, &|r| r["folders"][0]["error"] = json!("no room"));
        assert_eq!(to_come(status(true, 2, 1, in_error)), 1);
        let stopped = report(later, &|r| r["folders"][0]["stopped"] = json!(true));
        assert_eq!(to_come(status(true, 2, 1, stopped)), 1);
        let failed = report(later, &|r| {
            r["folders"][1]["failed"] = json!([{ "name": "a.md" }])
        });
        assert_eq!(to_come(status(true, 2, 1, failed)), 1);
        let more = report(later, &|r| r["folders"][1]["failed_more"] = json!(3));
        assert_eq!(to_come(status(true, 2, 1, more)), 1);
        // One was passed by: the cycle has no row for it. So is each
        // where the cycle ended before it reached any.
        let passed_by = report(later, &|r| r["folders"] = json!([folder(1)]));
        assert_eq!(to_come(status(true, 2, 1, passed_by)), 1);
        let none = report(later, &|r| r["folders"] = json!([]));
        assert_eq!(to_come(status(true, 3, 1, none)), 3);
        // A row for another folder under the name is no row for it.
        let another = report(later, &|r| {
            r["folders"][0]["cwd"] = json!("/home/sam/other")
        });
        assert_eq!(to_come(status(true, 2, 1, another)), 1);

        // The report is of a cycle from before the change: each mapped
        // folder. By the node's own clock, it has stored none since this
        // command began, to the second.
        assert_eq!(to_come(status(true, 2, 10, synced(later))), 2);
        assert_eq!(to_come(status(true, 2, 11, synced(later))), 2);
        // By the time of day, it was stored before this command began:
        // a node that was started again counts from its start, and
        // still holds the report of its earlier run.
        assert_eq!(to_come(status(true, 2, 1, synced(earlier))), 2);
        let at_the_moment = "2027-01-15T08:00:00+00:00";
        assert_eq!(to_come(status(true, 2, 1, synced(at_the_moment))), 2);
        // A report that does not say when it was stored, or a status
        // that does not say for how long none was: each mapped folder.
        let unsaid = report(later, &|r| r["at"] = Value::Null);
        assert_eq!(to_come(status(true, 2, 1, unsaid)), 2);
        let mut no_clock = status(true, 2, 1, synced(later));
        no_clock["no_report_secs"] = Value::Null;
        assert_eq!(to_come(no_clock), 2);
        // There is no report.
        assert_eq!(to_come(status(true, 3, 1, Value::Null)), 3);
        // The cycle published nothing: the device followed no phrase
        // when it ran, and no folder is said to wait in its report.
        let no_phrase = report(later, &|r| {
            r["publishes_nothing"] = json!("this device follows no recovery phrase yet")
        });
        assert_eq!(to_come(status(true, 2, 1, no_phrase)), 2);
    }

    /// Of a record that does not count nothing is asked, and its key is
    /// not removed by the recovery (decision 2026-10-04 §9, step 3):
    /// unless the change recovered from had removed that key already,
    /// and then it is said to stay removed.
    ///
    /// **A key that only the bound of 64 kept out, and that is not asked
    /// about, may be a device of the person's.** Its row says how its
    /// key is removed afterwards, and what then brings in what it wrote,
    /// with the key written whole, as both commands take it. So does the
    /// line for the records beyond the rows that are shown. And a key
    /// that a change has removed already is not asked about, whatever
    /// kept it out: its row says what a removed key's row says.
    #[test]
    fn test_what_is_said_of_a_record_of_which_nothing_is_asked() {
        let rows = rows();
        let no_device = "  It is no device: nothing is asked of it, nothing that it wrote is \
                         brought back, and its key is not removed.";
        let stays_removed = "  It is no device: nothing is asked of it, and nothing that it wrote \
                             is brought back. Its key was removed before this recovery, and stays \
                             removed.";
        // The tablet: its record fails for another reason than the bound.
        assert_eq!(not_asked_says(&rows[3], false), no_device);
        assert_eq!(not_asked_says(&rows[3], true), stays_removed);

        // A watch that only the bound kept out, which the laptop added.
        let mut watch = row(5, "watch", Some(1), false);
        watch.no_room = vec![([1; 32], 1_800_000_000)];
        let key = cordelia_crypto::bech32::encode_public_key(&[5; 32]).unwrap();
        assert_eq!(
            not_asked_says(&watch, false),
            format!(
                "{no_device} If it is a device of yours that is gone, its key is removed \
                 afterwards, on this machine, by `cordelia remove-device {key}`, and what it \
                 wrote then comes in by `cordelia sync carry <name> --from {key}`, with the \
                 phrase. One that you still have is added again by hand."
            )
        );
        // The key is written as `cordelia remove-device` takes one, and
        // as `cordelia sync carry --from` names a removed key.
        assert_eq!(
            cordelia_crypto::bech32::decode_public_key(&key).unwrap(),
            [5; 32]
        );
        let removed = [carry::Removed {
            key: [5; 32],
            label: String::new(),
        }];
        assert_eq!(carry::named_key(&key, &removed), Ok([5; 32]));
        // A change has removed its key already: it stays removed, and
        // nothing is said of removing it.
        assert_eq!(not_asked_says(&watch, true), stays_removed);

        // Whether it is asked about. The laptop is lost: it is, for the
        // laptop's record. Unless a change has removed its key already.
        let mut with_the_watch = rows.clone();
        with_the_watch.push(watch);
        let so_far = [Answer::Lost, Answer::Lost, Answer::Lost, Answer::NotAsked];
        let under = Some(([1; 32], 1_800_000_000));
        let asked =
            |removed: bool| asked_though_it_does_not_count(&with_the_watch, &so_far, 4, removed);
        assert_eq!((asked(false), asked(true)), (under, None));
        // The tablet is not, whether or not its key is removed.
        for removed in [false, true] {
            let of_the_tablet =
                asked_though_it_does_not_count(&with_the_watch, &so_far, 3, removed);
            assert_eq!(of_the_tablet, None);
        }

        // **A row that does not count, of a key one of whose records was
        // read and is not among those kept, may be a device of the
        // person's too:** the record that went may be the one by which
        // it would have been asked about. Its line says how its key is
        // removed afterwards, with the key written whole, as the watch's
        // does: where nothing of it fails only for the bound. A row none
        // of whose records went keeps the bare line.
        let mut tablet = rows[3].clone();
        assert!(tablet.no_room.is_empty() && !tablet.record_let_go);
        assert_eq!(not_asked_says(&tablet, false), no_device);
        tablet.record_let_go = true;
        let key = cordelia_crypto::bech32::encode_public_key(&[4; 32]).unwrap();
        assert_eq!(
            not_asked_says(&tablet, false),
            format!(
                "{no_device} If it is a device of yours that is gone, its key is removed \
                 afterwards, on this machine, by `cordelia remove-device {key}`, and what it \
                 wrote then comes in by `cordelia sync carry <name> --from {key}`, with the \
                 phrase. One that you still have is added again by hand."
            )
        );
        // A change has removed its key already: it stays removed.
        assert_eq!(not_asked_says(&tablet, true), stays_removed);
        // It is not asked about for that: nothing of it fails only for
        // the bound.
        let mut with_the_tablet = rows.clone();
        with_the_tablet[3] = tablet;
        let so_far = [Answer::Lost, Answer::Lost, Answer::Lost];
        assert_eq!(
            asked_though_it_does_not_count(&with_the_tablet, &so_far, 3, false),
            None
        );

        // The records beyond the rows that are shown.
        assert_eq!(not_shown_says(0), None);
        assert_eq!(
            not_shown_says(46).unwrap(),
            "46 more records beyond the 256 that are shown: nothing is asked of those. If one of \
             them is a device of yours that is gone, `cordelia devices` on this machine shows \
             each with its key: its key is removed afterwards, on this machine, by `cordelia \
             remove-device <key>`, and what it wrote then comes in by `cordelia sync carry <name> \
             --from <key>`, with the phrase."
        );
        assert!(
            not_shown_says(1)
                .unwrap()
                .starts_with("1 more record beyond the 256 that are shown: nothing is asked")
        );
    }
}
