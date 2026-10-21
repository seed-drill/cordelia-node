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
//!    proves that channel's key, which no device can. Each relay at which
//!    it could not read that channel to its end is said again before the
//!    yes (decision 2026-10-17 §3.2): it may hold a later change.
//! 2. It takes the change entry with the highest number whose signatures
//!    hold and whose secret opens to its statement's commitment. Where
//!    another was handed that is not on that one's chain, the two were
//!    made apart: it shows both lists, asks which to recover from, and
//!    the statement it makes settles them.
//! 3. It reads that generation's personal channel, on from where each
//!    relay reached, round after round, for RECOVERY_READ_ON_MAX_SECS at
//!    most (decision 2026-10-17 §3.2), and shows every device, each with
//!    the first words of its key's fingerprint and how much it signed
//!    there: the statement's devices first, always; then
//!    the keys added since that count; then the records that do not
//!    count, in the order a reader keeps them, so that each device that
//!    may add has a row for its first three keys that the 64 kept out;
//!    256 rows in all. A key that several devices added is shown with
//!    each label beside the device that gave it (decision 2026-10-17
//!    §2.4). It says first where the answers could not
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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use cordelia_api::carry::{self, Allows, Word};
use cordelia_api::carrying::CONNECTION_CHANGED;
use cordelia_api::change::{prepare_recovery, read_with};
use cordelia_api::look::{CarriedWordLook, held_named, joined, lists_of};
use cordelia_api::person::PersonError;
use cordelia_api::recover::{self, Answer, Candidate, Generation, Judged, Row};
use cordelia_core::protocol::{
    CARRY_PROOFS_MADE_AGAIN, CARRY_READ_MAX_SECS, KEPT_OUT_PER_ADDER, MAX_COUNTED_DEVICES,
    MAX_ENTRY_CHANNEL_BYTES_AT_RELAY, MAX_STATEMENT_REMOVED, RECOVERY_MAX_DEVICES_SHOWN,
    RECOVERY_MAX_NAMES, RECOVERY_READ_ON_READS,
};
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::statement::{Device, Statement, StatementError};
use cordelia_crypto::{derive, fingerprint};

use crate::carry_cmd::{
    Sessions, bytes_handed, entries_handed, key_written, read_round, read_with_secret,
};
use crate::person_cmd::wait::{self, RecoveryEnd};
use crate::person_cmd::{
    NOT_A_YES, NOT_AT_EVERY_RELAY_STATUS, counted, default_label, file_shown, list, look,
    made_all_the_same, named, names_this_device, own_key, text, time_of, typed_phrase,
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
/// and what the answers do for it ([`asked_for_room_says`]). It is asked
/// under the first adder, in the order of the rows, that is not in
/// someone else's hands ([`recover::asked_for_room`]), and the row shows
/// every such adder, each with its label (decision 2026-10-17 §2.4).
/// `left` is how many removals the phrase has left.
fn for_room_says(rows: &[Row], answers: &[Answer], at: usize, number: u64, left: usize) -> String {
    let says = row_says(rows, answers, at, number);
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
/// keeps 256 records that do not count, in the order of keeping
/// (decision 2026-10-17 §2.2), so where more were written, one that was
/// read is not among them.
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
/// again by hand. **What is kept, and shown, leaves each adder that may
/// add its first `KEPT_OUT_PER_ADDER` such keys** (decision 2026-10-17
/// §2.2, §2.5): it says so, so that a person knows that only an adder
/// that added more than that can have left one of theirs out.
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
        "{}, because more were written than a recovery keeps. Each device that may add keeps a \
         row for at least the first {KEPT_OUT_PER_ADDER} devices that it added since change \
         {number} and that {MAX_COUNTED_DEVICES} devices counted already kept out: a device that \
         added more than that may have left one of them here. A device of yours that was added \
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

/// A number of bytes, in MiB, to one place after the point.
fn mib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0))
}

/// The mark of a holding that a relay answers under where it holds none
/// of a channel, as the node writes a mark.
fn no_mark() -> String {
    hex::encode(cordelia_storage::relay::NO_MARK)
}

/// How one relay stands while a recovery reads its personal channel on
/// (decision 2026-10-17 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadingOn {
    /// The relay, by its name.
    relay: String,
    /// What is said of the read there, as the node says it: `whole`,
    /// `part`, `not held`, or why it was not read.
    read: String,
    /// How many entries of the channel it handed, over every round.
    handed: u64,
    /// What those came to, as a relay counts them against a channel's
    /// cap.
    bytes: u64,
    /// The place that the read reached there, as the node said it: the
    /// mark of the relay's holding, and the place.
    place: Option<(String, u64)>,
    /// Whether it is asked again in the next round.
    on: bool,
    /// How many readings it was asked in, the first round's among them:
    /// RECOVERY_READ_ON_READS at most, its own, whatever another relay
    /// does.
    readings: u64,
    /// Why its reading on stopped, where it was read in part or not at
    /// all.
    why: Option<String>,
    /// Whether its last reading was one where its connection changed.
    changed: bool,
    /// The node key of the connection that its last reading was on, as
    /// the node said it: where it was read to its end, the key of the
    /// relay that this recovery read (decision 2026-10-19 §4, rule 10).
    key: Option<String>,
}

impl ReadingOn {
    /// How a relay stands after the first round, of what the node said
    /// of it last, where it was asked in `readings` readings of that
    /// round. It is read on where it was read in part and the read moved
    /// on from the start, and where its connection changed.
    fn first(said: &Value, readings: u64) -> Self {
        let mut at = Self {
            relay: text(said, "relay").to_string(),
            read: text(said, "read").to_string(),
            handed: entries_handed(said),
            bytes: bytes_handed(said),
            place: None,
            on: false,
            readings,
            why: None,
            changed: false,
            key: said["key"].as_str().map(str::to_string),
        };
        let place = place_of(said);
        if at.read == "whole" && place.as_ref().is_some_and(|(mark, _)| *mark == no_mark()) {
            // It answered that it holds none of the channel.
            at.read = match at.handed {
                0 => "not held".into(),
                _ => "part".into(),
            };
            if at.handed > 0 {
                at.why = Some("it holds none of it now".into());
            }
        }
        // Its connection changed at every reading of the first round: it
        // is read in the next round, from the start, over the connection
        // there is then.
        at.changed = at.read == CONNECTION_CHANGED;
        at.on = at.changed
            || (at.read == "part"
                && place
                    .as_ref()
                    .is_some_and(|(mark, next)| (mark.as_str(), *next) != (no_mark().as_str(), 0)));
        at.place = place;
        at
    }

    /// Take what the node said of the relay in a round after the first,
    /// where it was asked from its place: `None` where the node said
    /// nothing of it. Returns the line that is said of it after the
    /// round.
    ///
    /// - **Read to its end** at a place under a mark: it stops there.
    /// - **Read in part, and the place moved on:** it is asked again.
    /// - **Read in part, and the place did not move** (the round ended
    ///   before a page, or at a page of which nothing is an entry of the
    ///   channel): that is no progress, and it is not asked again.
    /// - **It holds none of the channel now** (it says so, or answers
    ///   to its end under no mark): where it handed part of it, it is
    ///   read in part; where it handed nothing, it holds none of it.
    /// - **Its connection changed:** it handed nothing, and is asked
    ///   again in the next round from the same place, over the connection
    ///   there is then, where it has a reading left.
    /// - **Anything else** (it was not reached, or not read): it is not
    ///   asked again, and stays as it was.
    fn round(&mut self, said: Option<&Value>) -> String {
        self.on = false;
        let read = said.map(|said| text(said, "read")).unwrap_or_default();
        self.changed = read == CONNECTION_CHANGED;
        let place = said.and_then(place_of);
        // What it handed in the round counts, however the round ended.
        if let Some(said) = said {
            self.handed += entries_handed(said);
            self.bytes += bytes_handed(said);
        }
        let holds_none = read == "not held"
            || (read == "whole" && place.as_ref().is_some_and(|(mark, _)| *mark == no_mark()));
        if holds_none && self.handed == 0 {
            self.read = "not held".into();
            return format!("  {}: it holds none of it.", self.relay);
        }
        if holds_none {
            return self.in_part("it holds none of it now");
        }
        if read == CONNECTION_CHANGED {
            self.on = true;
            return format!(
                "  {}: its connection changed; it is read again from where it was.",
                self.relay
            );
        }
        if !matches!(read, "whole" | "part") {
            let why = match read {
                "" => "the node said nothing of it".to_string(),
                read => format!("it was {read}"),
            };
            return self.in_part(&why);
        }
        if read == "whole" {
            self.read = "whole".into();
            self.place = place;
            self.key = said
                .and_then(|said| said["key"].as_str())
                .map(str::to_string);
            return format!(
                "  {}: read to its end, {} MiB.",
                self.relay,
                mib(self.bytes)
            );
        }
        if place.is_none() || place == self.place {
            return self.in_part("it handed nothing more");
        }
        self.place = place;
        self.on = true;
        format!("  {}: {} MiB read so far.", self.relay, mib(self.bytes))
    }

    /// Stop reading on at the relay for `why`: the line that says so. It
    /// is read in part where it handed an entry of the channel, and
    /// otherwise nothing of it was read there ([`read_as`]).
    fn in_part(&mut self, why: &str) -> String {
        self.on = false;
        self.why = Some(why.to_string());
        match self.handed {
            0 => format!("  {}: nothing of it was read: {why}.", self.relay),
            _ => format!(
                "  {}: read in part, {} MiB: {why}.",
                self.relay,
                mib(self.bytes)
            ),
        }
    }

    /// The place to ask from, as the node is handed it.
    fn from(&self) -> Option<Value> {
        let (mark, place) = self.place.as_ref()?;
        Some(json!({ "relay": self.relay, "mark": mark, "place": place }))
    }

    /// What is said of the relay once the reading on has ended, as the
    /// node says it of a read.
    fn said(&self) -> Value {
        let mut said = json!({ "relay": self.relay, "read": self.read, "entries": self.handed });
        if let Some(why) = &self.why {
            said["why"] = why.as_str().into();
        }
        if let Some(key) = &self.key {
            said["key"] = key.as_str().into();
        }
        said
    }
}

/// The place that the node said a read reached at a relay: the mark and
/// the place, where it said them.
fn place_of(said: &Value) -> Option<(String, u64)> {
    Some((said["mark"].as_str()?.to_string(), said["place"].as_u64()?))
}

/// Read the personal channel of the change numbered `number` on, from
/// where each relay reached, round after round (decision 2026-10-17
/// §3.2). `round` reads it once: at every relay where it is given no
/// relays, and otherwise at those it is given alone, each from its place
/// in what it is given. `say` says a line.
///
/// 1. **The first round is the read of today:** from the start, at every
///    relay, for CARRY_READ_MAX_SECS at most. **A relay whose connection
///    changed is read again in it,** alone and from the start, over the
///    connection there is then, as the read of today reads it again:
///    CARRY_PROOFS_MADE_AGAIN times at most, each one of its own readings.
/// 2. **Each relay that it read in part, where the read moved on, is
///    asked again from the place it reached, and no other.** After the
///    first round the command says that it reads on, and after each
///    round one line of each relay that it asked: how far it has read,
///    as a relay counts it against its cap.
/// 3. **It stops at a relay that has handed the channel to its end or
///    holds none of it, at one that was not reached in a round, at one
///    where a round did not move the place, and at one that has been
///    asked in RECOVERY_READ_ON_READS rounds:** each relay has its own
///    count, so what one relay does never costs another a reading. **In a
///    round after the first, a relay whose connection changed is asked
///    again in the next round,** from where it was, over the connection
///    there is then: that is one of its own readings, and no relay is read
///    again within such a round. So there are RECOVERY_READ_ON_READS rounds
///    at most, each one reading of CARRY_READ_MAX_SECS at every relay
///    asked but the first, which is up to CARRY_PROOFS_MADE_AGAIN readings
///    longer where a connection changed in it; and what a reading takes
///    beyond that never costs the reading that reaches a channel at its
///    cap. A relay that handed part and then holds none of it is read in
///    part, and one that handed nothing and holds none of it holds none.
///    Each relay read on that is not read to its end keeps why its reading
///    on stopped, and what is said of it says it (`why`).
///
/// Returns every entry handed, each once, and what is said of each relay
/// in the node's order, as the node says it of a read: a relay read on
/// is said `whole` where it was read to its end, and otherwise `part`,
/// with how many entries of the channel it handed in every round.
fn read_on(
    number: u64,
    mut round: impl FnMut(
        Option<&[String]>,
        &[Value],
    ) -> anyhow::Result<(Vec<CheckedEntry>, Vec<Value>)>,
    mut say: impl FnMut(String),
) -> anyhow::Result<(Vec<CheckedEntry>, Vec<Value>)> {
    let mut kept: HashSet<[u8; 32]> = HashSet::new();
    let mut entries: Vec<CheckedEntry> = Vec::new();
    let mut keep = |handed: Vec<CheckedEntry>| {
        for entry in handed {
            if kept.insert(entry.id()) {
                entries.push(entry);
            }
        }
    };
    let (first, mut relays) = round(None, &[])?;
    keep(first);
    // The read of today reads again, from the start, a relay whose
    // connection changed: the others answered, and what they said stands.
    let mut readings: HashMap<String, u64> = HashMap::new();
    for _ in 0..CARRY_PROOFS_MADE_AGAIN {
        let changed: Vec<String> = relays
            .iter()
            .filter(|said| text(said, "read") == CONNECTION_CHANGED)
            .map(|said| text(said, "relay").to_string())
            .collect();
        if changed.is_empty() {
            break;
        }
        let (handed, again) = round(Some(&changed), &[])?;
        keep(handed);
        for relay in &changed {
            *readings.entry(relay.clone()).or_insert(1) += 1;
        }
        for said in again {
            let of = relays.iter_mut().find(|of| of["relay"] == said["relay"]);
            if let Some(of) = of {
                *of = said;
            }
        }
    }
    let first = |said: &Value| {
        let readings = readings.get(text(said, "relay")).copied().unwrap_or(1);
        ReadingOn::first(said, readings)
    };
    let mut at: Vec<ReadingOn> = relays.iter().map(first).collect();
    for relay in &at {
        if !relay.on && !matches!(relay.read.as_str(), "whole" | "not held") {
            say(format!(
                "  Could not read the personal channel at {} to its end ({}).",
                relay.relay, relay.read
            ));
        }
    }
    // Only a relay that handed part of the channel says that it is larger
    // than one read: one whose connection changed handed nothing.
    let larger: Vec<&ReadingOn> = at.iter().filter(|r| r.on && !r.changed).collect();
    if let Some(left) = larger
        .iter()
        .map(|r| RECOVERY_READ_ON_READS.saturating_sub(r.readings))
        .max()
    {
        let names: Vec<&str> = larger.iter().map(|r| r.relay.as_str()).collect();
        say(format!(
            "\nThe personal channel of change {number} is larger than one read. Reading on at {}: a \
             relay may hold up to {} MiB of it, which takes up to {} reads: up to {left} more are \
             made, each of up to {} minutes and what it takes beyond that. Ctrl-C stops here, and \
             nothing is made.",
            names.join(", "),
            MAX_ENTRY_CHANNEL_BYTES_AT_RELAY / (1024 * 1024),
            RECOVERY_READ_ON_READS,
            CARRY_READ_MAX_SECS / 60
        ));
    }
    for relay in at.iter().filter(|relay| relay.on) {
        say(match relay.changed {
            true => format!(
                "  {}: its connection changed; it is read again from where it was.",
                relay.relay
            ),
            false => format!("  {}: {} MiB read so far.", relay.relay, mib(relay.bytes)),
        });
    }
    loop {
        // A relay that has been asked in so many rounds is asked no more.
        for relay in at.iter_mut().filter(|relay| relay.on) {
            if relay.readings >= RECOVERY_READ_ON_READS {
                let made = match relay.changed {
                    true => format!(
                        "its {RECOVERY_READ_ON_READS} reads were made, and its connection changed \
                         at the last"
                    ),
                    false => format!("its {RECOVERY_READ_ON_READS} reads were made"),
                };
                say(relay.in_part(&made));
            }
        }
        let asked: Vec<String> = at
            .iter()
            .filter(|r| r.on)
            .map(|r| r.relay.clone())
            .collect();
        if asked.is_empty() {
            break;
        }
        for relay in at.iter_mut().filter(|relay| relay.on) {
            relay.readings += 1;
        }
        let from: Vec<Value> = at
            .iter()
            .filter(|r| r.on)
            .filter_map(ReadingOn::from)
            .collect();
        let (handed, relays) = round(Some(&asked), &from)?;
        keep(handed);
        for relay in at.iter_mut().filter(|relay| asked.contains(&relay.relay)) {
            let said = relays
                .iter()
                .find(|said| text(said, "relay") == relay.relay);
            say(relay.round(said));
        }
    }
    Ok((entries, at.iter().map(ReadingOn::said).collect()))
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
    /// Why the reading on stopped at each relay that was read on and is
    /// read in part, by its name (decision 2026-10-17 §3.3).
    why: Vec<(String, String)>,
    /// The node key of the connection that it was read on, as a key is
    /// written, of each relay that the node said one of, by its name: what
    /// a relay that a device's carried word names is known by (decision
    /// 2026-10-19 §4, rule 10).
    keys: Vec<(String, String)>,
}

impl PersonalRead {
    fn of(relays: &[Value]) -> Self {
        let of = |relay: &Value| {
            let (name, said) = (text(relay, "relay"), text(relay, "read"));
            (name.to_string(), read_as(relay), said.to_string())
        };
        let why = relays.iter().filter_map(|relay| {
            let why = relay["why"].as_str()?;
            Some((text(relay, "relay").to_string(), why.to_string()))
        });
        let keys = relays.iter().filter_map(|relay| {
            let key = relay["key"].as_str()?;
            Some((text(relay, "relay").to_string(), key.to_string()))
        });
        Self {
            relays: relays.iter().map(of).collect(),
            why: why.collect(),
            keys: keys.collect(),
        }
    }

    /// The node key, as a key is written, of each relay that this
    /// recovery read (decision 2026-10-19 §4, rule 10): each at which it
    /// read the channel to its end, by the key of the connection that it
    /// read on.
    fn read_by(&self) -> Vec<String> {
        let whole = self.at(&[ReadAs::Whole]);
        let of_those = self.keys.iter().filter(|(relay, _)| whole.contains(relay));
        of_those.map(|(_, key)| key.clone()).collect()
    }

    /// The relays of which `known` is what is known, each by its name,
    /// and with why its reading on stopped, where that is known.
    fn at_with_why(&self, known: &[ReadAs]) -> Vec<String> {
        let why = |relay: &String| self.why.iter().find(|(of, _)| of == relay);
        let named = |relay: String| match why(&relay) {
            Some((_, why)) => format!("{relay} ({why})"),
            None => relay,
        };
        self.at(known).into_iter().map(named).collect()
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
/// before its yes of what it could not read (decision 2026-10-04 §16),
/// and of the phrase's own channel (decision 2026-10-17 §3.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct WasRead {
    /// The relays at which the phrase's own channel could not be read
    /// to its end, each by its name: a relay that holds none of it is
    /// not among them. Each may hold a later change than the one
    /// recovered from.
    phrase_not_read: Vec<String>,
    /// The number of the latest change in what was read of the phrase's
    /// own channel.
    latest: u64,
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
    /// What a recovery from the change numbered `number` read: of its
    /// personal channel, `personal`; and of the phrase's own channel,
    /// `phrase`, what the node said of each relay, where the latest
    /// change found was numbered `latest`.
    fn of(number: u64, personal: PersonalRead, phrase: &[Value], latest: u64) -> Self {
        Self {
            phrase_not_read: not_read_at(phrase),
            latest,
            number,
            personal,
            ..Default::default()
        }
    }

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
    ///
    /// And first, **where the phrase's own channel could not be read to
    /// its end at a relay** (decision 2026-10-17 §3.2): at which, that it
    /// may hold a later change, and which change this recovery is made
    /// from. It is said whether or not a change was found elsewhere.
    fn lines(&self) -> Vec<String> {
        let (number, of) = (self.number, &self.personal);
        let mut lines = Vec::new();
        if !self.phrase_not_read.is_empty() {
            let latest = match self.latest == number {
                true => ", the latest in what was read",
                false => "",
            };
            lines.push(format!(
                "The recovery phrase's own channel could not be read to its end at {}: it may \
                 hold a later change. This recovery is made from change {number}{latest}. Only \
                 the recovery phrase writes in that channel.",
                self.phrase_not_read.join(", ")
            ));
        }
        let part = of.at_with_why(&[ReadAs::Part]);
        let nothing = of.at_with_why(&[ReadAs::Nothing]);
        if of.any(ReadAs::Whole) {
            let not_to_the_end = of.at_with_why(&[ReadAs::Part, ReadAs::Nothing]);
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
                 missing from what was read. A relay that hands it more slowly than a channel at \
                 its largest needs, or stops, leaves it in part.",
                part.join(", "),
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
/// devices, that is said. `answers` are those given so far.
///
/// **A key that the 64 kept out, and that several adders added, is shown
/// with each label beside the adder that gave it** (decision 2026-10-17
/// §2.4, §1 property 3), in the order of the adders' rows, so that no one
/// adder's label stands for the key: where the labels differ, the row
/// says that the words are what tells two apart. An adder that may be in
/// someone else's hands ([`recover::adders_shown`]) is counted, and not
/// shown, also where it is the only one: the key is then shown by its
/// words alone ([`recover::label_shown`]). And where the key signed a record of an addition, the row says
/// that the device it added is not shown (§2.3).
fn row_says(rows: &[Row], answers: &[Answer], at: usize, number: u64) -> String {
    let row = &rows[at];
    let label_of = |key: &[u8; 32]| {
        let known = rows.iter().find(|row| row.key == *key);
        known.map(|row| row.label.clone()).unwrap_or_default()
    };
    let for_room =
        format!(", by a record that does not count: {MAX_COUNTED_DEVICES} devices counted already");
    let label = recover::label_shown(rows, answers, row);
    let (shown, hidden) = recover::adders_shown(rows, answers, row);
    let mut more = Vec::new();
    let whose = match row.added_by {
        None => format!("a device of change {number}"),
        // Several adders, or one that may be in someone else's hands: each
        // that is shown with its label, and the others counted.
        Some(_) if row.no_room.len() > 1 || hidden > 0 => {
            let from: Vec<String> = shown
                .iter()
                .map(|(adder, at, label)| {
                    let adder = named(&label_of(adder), adder);
                    format!("from {adder} at {} as {label:?}", time_of(*at))
                })
                .collect();
            let hands = match (shown.is_empty(), hidden) {
                (_, 0) => String::new(),
                (true, n) => format!(
                    " by {} that may be in someone else's hands",
                    counted(n, "device")
                ),
                (false, n) => {
                    format!(", and {n} more added it, which may be in someone else's hands")
                }
            };
            let labels: BTreeSet<&str> = shown.iter().map(|(_, _, label)| label.as_str()).collect();
            if labels.len() > 1 {
                more.push(
                    "  The labels differ. A label is what the device that added it called it: the \
                     words are what tells two apart.",
                );
            }
            let from = match from.is_empty() {
                true => String::new(),
                false => format!(", {}", from.join(", and ")),
            };
            format!("added since change {number}{from}{hands}{for_room}")
        }
        Some((adder, at)) => format!(
            "added since change {number}, from {} at {}{}",
            named(&label_of(&adder), &adder),
            time_of(at),
            match (row.counts, row.no_room.is_empty()) {
                (true, _) => String::new(),
                (false, true) => ", by a record that does not count".to_string(),
                (false, false) => for_room,
            }
        ),
    };
    if row.signed_a_record {
        more.push(
            "  A device that it added is not shown here: a device that does not count adds \
             nothing.",
        );
    }
    let mut says = format!(
        "\n{}, {whose}. It signed {} in the personal channel of that change.",
        named(label, &row.key),
        counted(row.signed, "entry").replace("entrys", "entries")
    );
    for line in more {
        says.push('\n');
        says.push_str(line);
    }
    says
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
/// is said to be listed nowhere: none is listed in what was read. **And
/// "none is listed" is said only where none is:** where names are
/// listed, and only by a device from which nothing is taken or a key
/// that does not count, no name is carried, and the line for the names
/// that are left follows.
fn will_do_lines(
    generation: &Generation,
    answers: &[Answer],
    names: &recover::Names,
    own: &[u8; 32],
    was_read: &WasRead,
    carried_elsewhere: Option<&str>,
) -> Vec<String> {
    let rows = &generation.rows;
    let taken = recover::takes(rows, answers);
    let mut lines = Vec::new();
    // Each by the label that its row showed (decision 2026-10-17 §2.4).
    let shown = |keys: Vec<&Row>| -> String {
        let all: Vec<String> = keys
            .iter()
            .map(|row| named(recover::label_shown(rows, answers, row), &row.key))
            .collect();
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
        // Names are listed, and none of them is carried: "none is
        // listed" is said only where none is. The line for the names
        // that are left says which they are, and why.
        true if !names.only_other_hands.is_empty() => lines.push("No name is carried.".into()),
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
    // R2, with the lines that say how the personal channel was read
    // (decision 2026-10-19 §4, rule 10).
    lines.extend(carried_elsewhere.map(str::to_string));
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

/// What the command does at one row of a recovery (decision 2026-10-04
/// §9, step 3): it says the row and answers it itself, or says it and
/// asks.
#[derive(Debug, PartialEq, Eq)]
enum AtARow {
    /// What is said, and the answer that stands for it: this machine
    /// itself, or a record of which nothing is asked.
    Said(String, Answer),
    /// What is said before the question.
    Asks(String),
}

/// What the command does at the row at `at`, with `answers` the answers
/// given so far, to every row before it: **what is said of a row turns
/// on them** (decision 2026-10-17 §2.4), since an adder that may be in
/// someone else's hands is not shown, nor its label. `number` is the
/// number of the change recovered from, `own` this machine's key, `room`
/// what the change has room for, and `removed_already` whether a change
/// has removed a key already: the one recovered from, or the one made
/// apart from it.
fn at_a_row(
    rows: &[Row],
    answers: &[Answer],
    at: usize,
    number: u64,
    own: &[u8; 32],
    room: &recover::Room,
    removed_already: &dyn Fn(&[u8; 32]) -> bool,
) -> AtARow {
    let says = row_says(rows, answers, at, number);
    if rows[at].key == *own {
        let says = format!("{says}\n  It is this machine: it is the one device of the change.");
        return AtARow::Said(says, Answer::Have);
    }
    // A record that does not count is shown as that, and nothing is
    // asked of it: unless only the bound of 64 kept its key out, a key
    // signed it that may add and is not in someone else's hands, and no
    // change has removed its key already.
    if !rows[at].counts {
        let removed = removed_already(&rows[at].key);
        if asked_though_it_does_not_count(rows, answers, at, removed).is_none() {
            let says = format!("{says}\n{}", not_asked_says(&rows[at], removed));
            return AtARow::Said(says, Answer::NotAsked);
        }
        let left = removals_left(room, rows, answers, removed_already);
        return AtARow::Asks(for_room_says(rows, answers, at, number, left));
    }
    let mut says = says;
    // What was said of the device that added it bears on it.
    let adders_answer = rows[at]
        .added_by
        .and_then(|(adder, _)| rows.iter().position(|row| row.key == adder))
        .is_some_and(|adder| {
            let mut so_far = answers.to_vec();
            so_far.push(Answer::Have);
            recover::in_other_hands(rows, &so_far, adder)
        });
    if adders_answer {
        says.push_str(
            "\n  It was added by a device that may be in someone else's hands: nothing that it \
             wrote is brought back, whatever is said of it.",
        );
    }
    AtARow::Asks(says)
}

/// The keys that the node is handed with the label of each (decision
/// 2026-10-04 §9, step 4): `gone`, each that the person said is gone;
/// `still_have`, each that they still have; and `not_shown`, each row
/// that could not be shown. **Each label is the one that its row was
/// shown by** ([`recover::label_shown`], decision 2026-10-17 §2.4): the
/// node keeps it, and `cordelia devices` shows it afterwards, so an adder
/// that may be in someone else's hands chooses none. Where every adder of
/// a key may be, the label is empty, which the node keeps as none: the
/// key is shown by its words alone, as its row was. `own` is this
/// machine's key, which is no key of these.
fn labels_for_the_node(generation: &Generation, answers: &[Answer], own: &[u8; 32]) -> Value {
    let rows = &generation.rows;
    let key_and_label = |row: &Row| -> Value {
        let label = recover::label_shown(rows, answers, row);
        json!({ "key": hex::encode(row.key), "label": label })
    };
    let labelled = |answer: fn(&Answer) -> bool| -> Vec<Value> {
        rows.iter()
            .zip(answers)
            .filter(|(row, said)| answer(said) && row.key != *own)
            .map(|(row, _)| key_and_label(row))
            .collect()
    };
    let not_shown: Vec<Value> = generation.not_shown.iter().map(key_and_label).collect();
    json!({
        "gone": labelled(|said| matches!(said, Answer::Lost | Answer::OtherHands)),
        "still_have": labelled(|said| *said == Answer::Have),
        "not_shown": not_shown,
    })
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
    let (handed, phrase_read) = {
        let secret = phrase.channel_secret()?;
        read_channel(config_path, &secret, &mut sessions, &own, "it")?
    };
    let not_read = not_read_at(&phrase_read);

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
    let latest = found.from.statement.statement.number;
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
        // It is read on from where each relay reached, round after
        // round (decision 2026-10-17 §3.2).
        let (handed, relays) = read_on(
            statement.number,
            |asked, from| {
                let (sessions, own) = (&mut sessions, &own);
                read_round(config_path, &personal, sessions, own, asked, from)
            },
            |line| println!("{line}"),
        )?;
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
        let removed = &removed_already;
        match at_a_row(
            rows,
            &answers,
            at_row,
            statement.number,
            &own,
            &room,
            removed,
        ) {
            AtARow::Said(says, answer) => {
                println!("{says}");
                answers.push(answer);
            }
            AtARow::Asks(says) => answers.push(asks_of(&at, &says)?),
        }
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
    let mut was_read = WasRead::of(statement.number, personal_read, &phrase_read, latest);
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
    let (cut_short, carried_elsewhere) = judged_before_the_yes(&generation, &was_read, &asked);
    for line in will_do_lines(
        &generation,
        &answers,
        &names,
        &own,
        &was_read,
        carried_elsewhere.as_deref(),
    ) {
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
    let labels = labels_for_the_node(&generation, &answers, &own);
    let mut body = json!({
        "entry": hex::encode(entry.to_wire()),
        "statement_key": hex::encode(*statement_key),
        "left": left,
        "gone": labels["gone"],
        "still_have": labels["still_have"],
        "not_shown": labels["not_shown"],
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
    goes_on_in_a_new_process(config_path, signs.number, cut_short)
}

/// How the personal channel was read in which a device writes that it
/// has sent what it carried (decision 2026-10-04 §8), where that word is
/// not among what was read: one of three things.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ChannelRead {
    /// To its end at one relay at least, and in part or not at all at
    /// none: what was read is all that the relays which answered hold of
    /// it, and the word is not there.
    Whole,
    /// In part, or not at all, at one relay at least: the word may be in
    /// what was not read, whatever was read elsewhere.
    InPart,
    /// No relay that answered holds any of it. A device that wrote
    /// nothing there, and a relay that has dropped the channel, both
    /// give this.
    HeldByNone,
}

impl ChannelRead {
    /// Which of the three it is, of what the node said of each relay.
    fn of(read: &PersonalRead) -> Self {
        if read.any(ReadAs::Part) || read.any(ReadAs::Nothing) {
            Self::InPart
        } else if read.any(ReadAs::Whole) {
            Self::Whole
        } else {
            Self::HeldByNone
        }
    }

    /// The word that names it where it is handed to another process.
    fn named(self) -> String {
        use clap::ValueEnum;
        let named = self.to_possible_value();
        named
            .map(|value| value.get_name().to_string())
            .unwrap_or_default()
    }
}

/// The relays at which the device that a recovery was made from wrote,
/// in its carried word, that what it carried is, where this recovery read
/// none of them (decision 2026-10-19 §4, rule 10, case 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarriedTo {
    /// The relays, in a sentence, as this machine names each (rule 6),
    /// and "and <m> more" where the word counts more: `<held>`.
    pub held: String,
    /// How many relays that is.
    pub relays: u64,
}

impl CarriedTo {
    /// What the carried word `word` names, with `known` each relay that
    /// this machine is set up with, by its name, with its key where this
    /// machine knows one.
    fn of(word: &CarriedWordLook, known: &[(String, Option<String>)]) -> Self {
        Self {
            held: held_named(word, &by_name_and_key(known)),
            relays: word.keys.len() as u64 + word.more,
        }
    }
}

/// `known` as [`held_named`] takes it.
fn by_name_and_key(known: &[(String, Option<String>)]) -> Vec<(&str, Option<&str>)> {
    known
        .iter()
        .map(|(name, key)| (name.as_str(), key.as_deref()))
        .collect()
}

/// Each relay that this machine is set up with, by its name, with its node
/// key, as a key is written, where this machine knows one (decision
/// 2026-10-19 §4, rule 10): the key that its configuration gives it, as
/// the node says (`asked`), and else the key of the connection that the
/// personal channel was read on there (`read`).
fn relays_known(asked: &Value, read: &PersonalRead) -> Vec<(String, Option<String>)> {
    list(asked, "relays")
        .map(|relay| {
            let name = text(relay, "relay");
            let connected = read.keys.iter().find(|(of, _)| of == name);
            let key = match relay["key"].as_str() {
                Some(key) => Some(key.to_string()),
                None => connected.map(|(_, key)| key.clone()),
            };
            (name.to_string(), key)
        })
        .collect()
}

/// R2 (decision 2026-10-19 §5): what a recovery says before its yes of
/// the one device that it recovers from, `device`, where that device's
/// carried word `word` names none of the relays that this machine read
/// (rule 10, case 3). The look is made once, so the remedy is offered
/// while nothing is made. `known` is each relay that this machine is set
/// up with, by its name, with its key where it knows one.
///
/// It ends one of two ways: where this machine is set up with a relay
/// that the word names, and did not read it, "reach it"; where it is set
/// up with none of them, set one up from the configuration of the device
/// named.
fn carried_elsewhere_says(
    device: &str,
    word: &CarriedWordLook,
    known: &[(String, Option<String>)],
) -> String {
    let to = CarriedTo::of(word, known);
    let them = match to.relays {
        1 => "it",
        _ => "them",
    };
    let mut said = vec![format!(
        "{device} wrote that it had sent what it carried to {}.",
        to.held
    )];
    if word.not_yet > 0 {
        said.push(format!(
            "It had not yet sent it to {} other relay{} that it was set up with.",
            word.not_yet,
            if word.not_yet == 1 { "" } else { "s" }
        ));
    }
    said.push(format!(
        "This machine has read none of {them}. The look of this recovery is made once, so what \
         that device carried may be only there."
    ));
    let set_up: Vec<String> = known
        .iter()
        .filter(|(_, key)| key.as_ref().is_some_and(|key| word.keys.contains(key)))
        .map(|(name, _)| name.clone())
        .collect();
    let reaches =
        match set_up.is_empty() {
            false => {
                let relay = joined(&set_up);
                said.push(format!(
                    "To bring it in by this recovery, answer no. Make sure this machine can reach \
                 {relay}, and run `cordelia recover` again."
                ));
                relay
            }
            true => {
                let key = word.keys.first().map(String::as_str).unwrap_or_default();
                // A relay that this machine is given no key for, and did not
                // reach, may be the one that the word names: reaching it is
                // then the remedy, and setting up another is not.
                let keyless: Vec<String> = known
                    .iter()
                    .filter(|(_, key)| key.is_none())
                    .map(|(name, _)| name.clone())
                    .collect();
                match keyless.is_empty() {
                true => said.push(format!(
                    "To bring it in by this recovery, answer no. On this machine, set up the \
                     relay whose key is {key}: the configuration of that device (its \
                     `[[network.bootnodes]]`) names it. Then run `cordelia recover` again."
                )),
                false => said.push(format!(
                    "To bring it in by this recovery, answer no. Make sure this machine can reach \
                     {}: the relay whose key is {key} may be {}. If it is not, set it up on this \
                     machine: the configuration of that device (its `[[network.bootnodes]]`) \
                     names it. Then run `cordelia recover` again.",
                    joined(&keyless),
                    if keyless.len() == 1 { "that one" } else { "one of them" }
                )),
            }
                "that relay".to_string()
            }
        };
    said.push(format!(
        "If you answer yes, it comes in later only by `cordelia sync carry <name> --from \
         <device>`, with the phrase, once this machine reaches {reaches}."
    ));
    said.join(" ")
}

/// What a recovery judges, before its yes, of the one device that it
/// recovers from, by that device's words and the relays that it read
/// (decision 2026-10-19 §4, rule 10), with `asked` what the node said
/// before anything else: what is said of the device once the look has
/// ended ([`CutShort`]), and R2, where its carried word names none of the
/// relays that this recovery read, which is said before the yes, while
/// nothing is made.
fn judged_before_the_yes(
    generation: &Generation,
    was_read: &WasRead,
    asked: &Value,
) -> (Option<CutShort>, Option<String>) {
    let known = relays_known(asked, &was_read.personal);
    let cut_short = CutShort::of(generation, was_read, &known);
    let carried_elsewhere = match generation.judged(&was_read.personal.read_by()) {
        Judged::CarriedElsewhere(word) => cut_short
            .as_ref()
            .map(|cut| carried_elsewhere_says(&cut.device, &word, &known)),
        _ => None,
    };
    (cut_short, carried_elsewhere)
}

/// The device that a recovery was made from, where its word that it had
/// sent what it carried is not among what was read (decision 2026-10-04
/// §8; §9, step 5): what is said of it once the look has ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutShort {
    /// The device, as it is shown.
    pub device: String,
    /// How the personal channel that the word is written in was read.
    pub read: ChannelRead,
    /// Where it wrote the carried word, and this recovery read none of
    /// the relays that it names (decision 2026-10-19 §4, rule 10, case
    /// 3): those relays. R3 is said in the place of the sentence that says
    /// it was cut short.
    pub carried_to: Option<CarriedTo>,
}

impl CutShort {
    /// What a recovery knows of the device that it was made from, of
    /// what it read: `None` where the word was read, or the change lists
    /// more devices than one ([`Generation::cut_short`]); and `None` where
    /// it wrote the carried word and one of the relays that the word names
    /// is a relay that this recovery read (decision 2026-10-19 §4, rule
    /// 10, case 2). `known` is each relay that this machine is set up
    /// with, by its name, with its key where it knows one.
    fn of(
        generation: &Generation,
        was_read: &WasRead,
        known: &[(String, Option<String>)],
    ) -> Option<Self> {
        let key = generation.cut_short?;
        let carried_to = match generation.judged(&was_read.personal.read_by()) {
            Judged::Sent | Judged::CarriedToARelayRead => return None,
            Judged::CarriedElsewhere(word) => Some(CarriedTo::of(&word, known)),
            Judged::NoWord => None,
        };
        let label = generation.rows.iter().find(|row| row.key == key);
        let label = label.map(|row| row.label.clone()).unwrap_or_default();
        Some(Self {
            device: named(&label, &key),
            read: ChannelRead::of(&was_read.personal),
            carried_to,
        })
    }

    /// What hands this to the process that waits for the look
    /// ([`recover_made`]), as that command reads it.
    pub fn args(&self) -> Vec<String> {
        let (device, read) = (self.device.clone(), self.read.named());
        let mut args: Vec<String> = [
            "--cut-short".to_string(),
            device,
            "--channel-read".to_string(),
            read,
        ]
        .into();
        if let Some(to) = &self.carried_to {
            // Joined to its flag: a relay's name that begins with "-" is
            // then never read as a flag of its own.
            args.extend([
                format!("--carried-to={}", to.held),
                "--carried-relays".to_string(),
                to.relays.to_string(),
            ]);
        }
        args
    }

    /// What the process that waits for the look was handed
    /// ([`Self::args`]), as its command read it: the device, where one
    /// was named, how its channel was read, and the relays that its
    /// carried word names, where it was handed them.
    pub fn handed(
        device: Option<String>,
        read: ChannelRead,
        carried_to: Option<String>,
        carried_relays: u64,
    ) -> Option<Self> {
        let carried_to = carried_to.map(|held| CarriedTo {
            held,
            relays: carried_relays,
        });
        device.map(|device| Self {
            device,
            read,
            carried_to,
        })
    }

    /// What is said of the device once the look has ended.
    ///
    /// - **That it never wrote the word, and that a recovery, or a
    ///   change, that was made on it was cut short, is said as that only
    ///   where the channel was read to its end** ([`ChannelRead::Whole`]):
    ///   at each relay that the node said anything of, and one of them
    ///   holds it.
    /// - Where it was read in part, or not at all, at one relay at least,
    ///   the word was not found in what was read, and may be in what was
    ///   not: the recovery or change may have been cut short.
    /// - Where no relay that answered holds any of the channel, the word
    ///   was not found for that. A device that wrote nothing there, and a
    ///   relay that has dropped the channel, both give this: the recovery
    ///   or change may have been cut short.
    ///
    /// What the recovery does is the same in each: only this differs.
    ///
    /// **Where the device wrote the carried word, and this recovery read
    /// none of the relays that it names,** R3 is said in their place
    /// (decision 2026-10-19 §5): what it carried that is not here is
    /// there.
    fn says(&self) -> String {
        let device = &self.device;
        if let Some(to) = &self.carried_to {
            let it = match to.relays {
                1 => "it",
                _ => "them",
            };
            return format!(
                "The device that this was recovered from, {device}, wrote that it had sent what it \
                 carried to {}. This recovery did not read {it}. What it carried that is not here \
                 is there. Once this machine reaches {it}, `cordelia sync carry <name> --from \
                 <device>` brings it in, with the phrase.",
                to.held
            );
        }
        let brings = "`cordelia sync carry <name> --from <device>` brings it in, with the \
                      phrase, and lists those devices where no device is named.";
        let may_have_been = format!(
            "A recovery, or a change, that was made on it may have been cut short. What it had \
             sent is brought back. If it was cut short, what the devices that were gone before \
             it wrote, in the files it had not sent, is at the relays in the generation before: \
             {brings}"
        );
        let the_word = format!(
            "The word of the device that this was recovered from, {device}, that it had sent \
             what it carried"
        );
        match self.read {
            ChannelRead::Whole => format!(
                "The device that this was recovered from, {device}, never wrote that it had \
                 sent what it carried: a recovery, or a change, that was made on it was cut \
                 short. What it had sent is brought back. What the devices that were gone \
                 before it wrote, in the files it had not sent, is at the relays in the \
                 generation before: {brings}"
            ),
            ChannelRead::InPart => format!(
                "{the_word} was not found in what was read: its personal channel was not read \
                 to its end at every relay, and the word may be in what was not read. \
                 {may_have_been}"
            ),
            ChannelRead::HeldByNone => format!(
                "{the_word} was not found: no relay that answered holds that device's personal \
                 channel. A device that wrote nothing there, and a relay that has dropped the \
                 channel, both give this. {may_have_been}"
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
///
/// Where the program cannot be run again, nothing waits in this process:
/// the command says where to look, and ends with the status of a recovery
/// that is made and not known to be at every relay ([`look_not_waited_for`]).
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
    let (said, status) = look_not_waited_for(&failed);
    println!("{said}");
    std::process::exit(status)
}

/// What a recovery says where the look cannot be waited for, and its exit
/// status: the recovery is made, and is not known to be at every relay
/// (decision 2026-10-19 §4, rule 9).
fn look_not_waited_for(failed: &dyn std::fmt::Display) -> (String, i32) {
    (
        format!(
            "This command could not go on to say what the look found ({failed}). The node goes \
             on by itself: it looks at what the relays hold of each name, once, and sends what \
             it carried. `cordelia devices` shows whether each relay holds the change, and what \
             this machine has still to send. Keep this machine on until nothing is left to send."
        ),
        NOT_AT_EVERY_RELAY_STATUS,
    )
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
/// is added again. Then it waits for the change at each relay (decision
/// 2026-10-19 §4, rule 9). Gives the command's exit status: 0 only where
/// every relay holds the change, and 3 otherwise, an error during the
/// wait among it, which is said on standard error first, with that the
/// change is made.
pub fn recover_made(config_path: &str, number: u64, cut_short: Option<CutShort>) -> i32 {
    let node = TheNode(config_path);
    let say = |line: String| println!("{line}");
    let say_error = |line: String| eprintln!("{line}");
    recovery_status(number, cut_short, &node, say, say_error)
}

/// [`recover_made`], of what `node` says: each line said by `say`, and an
/// error during the wait by `say_error`, with that the change is made.
fn recovery_status(
    number: u64,
    cut_short: Option<CutShort>,
    node: &impl AfterTheChange,
    say: impl FnMut(String),
    mut say_error: impl FnMut(String),
) -> i32 {
    let ended = after_the_recovery(number, cut_short, node, say);
    if let Err(e) = &ended {
        say_error(wait::could_not_go_on(number, e));
    }
    recovered_status(&ended)
}

/// How a recovery's command ended, once its change was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recovered {
    /// At one of the two ends of its wait (decision 2026-10-19 §4, rule
    /// 9).
    Ended(RecoveryEnd),
    /// The device has since applied another change: whether that one is
    /// at every relay is the business of the command that made it.
    Another,
    /// The device no longer stands in its phrase
    /// ([`wait::no_longer_stands`]).
    NoLongerStands,
}

/// The exit status of a recovery's command, as it ended (decision
/// 2026-10-19 §4, rule 9): 0 only where every relay holds the change; 3
/// where some relay lacks it, where the device has since applied another
/// change, and on any error during the wait.
fn recovered_status(ended: &anyhow::Result<Recovered>) -> i32 {
    match ended {
        Ok(Recovered::Ended(end)) => end.status(),
        Ok(Recovered::Another | Recovered::NoLongerStands) | Err(_) => NOT_AT_EVERY_RELAY_STATUS,
    }
}

/// What a recovery's command asks of the node once its change is made.
trait AfterTheChange {
    /// How far the look has gone.
    fn progress(&self) -> anyhow::Result<Value>;
    /// The node's sync status, where it could be had.
    fn sync_status(&self) -> Option<Value>;
    /// What the device holds of its person, and where it stands at each
    /// relay.
    fn look(&self) -> anyhow::Result<Value>;
    /// Why the node is of another version than this command, where it is
    /// ([`crate::node_of_another_version`]).
    fn another_version(&self) -> anyhow::Result<Option<String>>;
    /// The time between two askings.
    fn pause(&self);
}

/// The node of the configuration at the path it holds.
struct TheNode<'a>(&'a str);

impl AfterTheChange for TheNode<'_> {
    fn progress(&self) -> anyhow::Result<Value> {
        told(api_post_told(
            self.0,
            "/api/v1/recover/progress",
            json!({}),
            Some(Duration::from_secs(30)),
        ))
    }

    fn sync_status(&self) -> Option<Value> {
        crate::api_post(self.0, "/api/v1/sync/status", json!({})).ok()
    }

    fn look(&self) -> anyhow::Result<Value> {
        look(self.0)
    }

    fn another_version(&self) -> anyhow::Result<Option<String>> {
        crate::node_of_another_version(self.0)
    }

    fn pause(&self) {
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// What [`recover_made`] does, of what `node` says, with each line said
/// by `say`.
fn after_the_recovery(
    number: u64,
    cut_short: Option<CutShort>,
    node: &impl AfterTheChange,
    mut say: impl FnMut(String),
) -> anyhow::Result<Recovered> {
    // The change was made a moment before this process began: by the
    // clock that cannot go back, and by the time of day.
    let began = std::time::Instant::now();
    let began_at = chrono::Utc::now();
    say(
        "Looking at what the relays hold of each name. The look is made once, and this command \
         stays until it has ended. Stopping it stops nothing: the node goes on."
            .into(),
    );
    let mut said_read = 0;
    loop {
        node.pause();
        let asked = node.progress()?;
        let found = &asked["look"];
        if found.is_null() || found["change"].as_u64() != Some(number) {
            say(
                "The look was interrupted: the node was started again before it had ended. It \
                 is not taken up again by itself. What this machine had carried by then is \
                 kept, and is sent. What is missing is brought in by `cordelia sync carry \
                 <name> --from <device>`, with the phrase."
                    .into(),
            );
            break;
        }
        if found["finished"] == true {
            for line in look_lines(found) {
                say(line);
            }
            break;
        }
        let read = found["read"].as_u64().unwrap_or(0);
        if read >= said_read + 16 {
            said_read = read;
            say(format!(
                "  read {read} of {} so far",
                counted(found["names"].as_u64().unwrap_or(0) as usize, "name")
            ));
        }
    }
    if let Some(cut_short) = cut_short {
        say(cut_short.says());
    }
    // What a folder that is mapped here has still to publish is in no
    // store yet: whether each has synced since the recovery is asked of
    // the node's sync status, and then what the device holds. For how
    // long this process has run is read before either.
    let began = Began {
        for_secs: began.elapsed().as_secs(),
        at: began_at,
    };
    let (sync, seen) = status_then_holds(|| node.sync_status(), || node.look());
    let seen = seen?;
    let to_come = match &sync {
        Some(sync) => folders_to_come(sync, &began),
        // The status could not be had: with sync on, each folder that is
        // mapped is taken not to have synced.
        None if seen["sync_on"] == true => seen["folders"].as_u64().unwrap_or(0) as usize,
        None => 0,
    };
    for line in after_lines(&seen, to_come) {
        say(line);
    }
    waits_for_the_change(number, seen, node, say)
}

/// A recovery waits for the change at each relay (decision 2026-10-19
/// §4, rule 9), from the look `seen` that the lines before the wait were
/// said of. **Where every relay holds the change,** it says R1 and ends
/// with status 0. **Otherwise** it says R0, says S2 and S3 as they come,
/// and ends at the first of its two ends ([`wait::recovery_end_of`]),
/// with what that end says. There is no condition on what waits, nor on
/// the machine's own word: its look may stay pending until the next
/// statement, and then neither `sent` nor the carried word is written. It
/// never says that the machine may be closed.
///
/// **No end with status 0 is given on classes that are not of this
/// change** ([`wait::recovery_end_of_look`]), and S2 and S3 are said only
/// of a relay whose reach is about it. **A look that cannot be read, or a
/// node of another version, is an error:** the wait ends with status 3.
fn waits_for_the_change(
    number: u64,
    mut seen: Value,
    node: &impl AfterTheChange,
    mut say: impl FnMut(String),
) -> anyhow::Result<Recovered> {
    let mut said: Vec<String> = Vec::new();
    let mut first = true;
    loop {
        // A node of another version, put in this one's place during the
        // wait, may say what this command reads otherwise.
        if let Some(note) = node.another_version()? {
            anyhow::bail!(note);
        }
        if seen["change"].as_u64() != Some(number) {
            say("This device has since applied another change: `cordelia devices` says.".into());
            return Ok(Recovered::Another);
        }
        if let Some(line) = wait::no_longer_stands(&seen) {
            say(line);
            return Ok(Recovered::NoLongerStands);
        }
        let at = chrono::Utc::now().timestamp();
        let (relays, end) = wait::recovery_end_of_look(&seen)?;
        if first && end != Some(RecoveryEnd::Recovered) {
            say(format!("\n{}", wait::recovery_first_line()));
        }
        first = false;
        let now: Vec<String> = relays
            .iter()
            .filter(|relay| relay.out_of_reach() && wait::is_about_the_kept_entry(relay, &seen))
            .map(|relay| wait::out_of_reach_line(relay, at))
            .collect();
        for line in &now {
            if !said.contains(line) {
                say(format!("  {line}"));
            }
        }
        said = now;
        if let Some(end) = end {
            for line in wait::recovery_end_lines(end, &relays, at) {
                say(line);
            }
            return Ok(Recovered::Ended(end));
        }
        node.pause();
        seen = node.look()?;
    }
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
/// machine (decision 2026-10-04 §9, steps 5 and 6): "keep this machine
/// on" with how many names are still to send; and, for each device that
/// the person still has, how it is added again. They ask the person to
/// act, and come before the wait for the change at each relay, which says
/// of each relay whether it holds the change (decision 2026-10-19 §4,
/// rule 9): no line here says it.
///
/// **That nothing is waiting is said only where that was read**
/// (decision 2026-10-04 §16), **and never where a relay lacks the change,
/// or is not connected.** Beside the names, the machine's personal
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
    let not_reached: Vec<&str> = list(seen, "not_reached")
        .filter_map(Value::as_str)
        .collect();
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
    // Whether a relay lacks the change, as the node knows it (decision
    // 2026-10-19 §1), or is not connected: nothing is said to be waiting
    // nowhere then. A relay holds it only by what is known of it about the
    // kept entry: a look before the node's pass has found the change says
    // nothing of it.
    let holds = |r: &wait::RelayAt| r.holds() && wait::is_about_the_kept_entry(r, seen);
    let lacks = |relays: Vec<wait::RelayAt>| !relays.iter().all(holds);
    let keep_on = !not_reached.is_empty() || wait::relays_of(seen).map_or(true, lacks);
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

    use cordelia_core::protocol::RECOVERY_READ_ON_MAX_SECS;

    fn row(n: u8, label: &str, added_by: Option<u8>, counts: bool) -> Row {
        Row {
            key: [n; 32],
            label: label.into(),
            added_by: added_by.map(|adder| ([adder; 32], 1_800_000_000)),
            counts,
            signed: usize::from(n),
            no_room: Vec::new(),
            record_let_go: false,
            signed_a_record: false,
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
        let laptop = row_says(&rows, &[], 0, 7);
        assert_eq!(
            laptop,
            format!(
                "\n({}) \"laptop\", a device of change 7. It signed 1 entry in the personal \
                 channel of that change.",
                fingerprint::shown(&[1; 32])
            )
        );
        let phone = row_says(&rows, &[], 2, 7);
        assert!(
            phone.contains(&format!(
                "\"phone\", added since change 7, from ({}) \"desktop\" at 2027-01-15 08:00 UTC. \
                 It signed 3 entries",
                fingerprint::shown(&[2; 32])
            )),
            "{phone}"
        );
        // A record that does not count is said to be one.
        let tablet = row_says(&rows, &[], 3, 7);
        assert!(
            tablet.contains("by a record that does not count"),
            "{tablet}"
        );
        // A label is another device's word: quoted, it cannot pass for
        // what the command says itself.
        let odd = vec![row(9, "x\") (abandon ability", None, true)];
        let says = row_says(&odd, &[], 0, 1);
        assert!(says.contains("\"x\\\") (abandon ability\""), "{says}");
    }

    /// A key that only the bound of 64 counted devices kept out is shown
    /// with that reason (decision 2026-10-04 §9, step 3). Where it is
    /// asked about, what each answer does for it is said before the
    /// question: nothing that it wrote is brought back, `lost` or
    /// `hands` removes its key, and `have` leaves it to be added again;
    /// and each key that is removed takes one of the removals that the
    /// phrase has left, with how many are left. Where two adders added it,
    /// each label is shown beside the adder that gave it, and no adder is
    /// named apart (decision 2026-10-17 §2.4); where it signed a record,
    /// its row says that what it added is not shown (§2.3). Before the
    /// yes it is named among those from whom the look takes nothing,
    /// where it was said to be gone.
    #[test]
    fn test_what_is_said_of_a_key_that_only_the_bound_of_64_kept_out() {
        let mut rows = rows();
        // A watch that the laptop added: its record found no room.
        let mut watch = row(5, "watch", Some(1), false);
        watch.no_room = vec![([1; 32], 1_800_000_000, "watch".into())];
        rows.push(watch);
        let says = row_says(&rows, &[], 4, 7);
        assert_eq!(
            says,
            format!(
                "\n({}) \"watch\", added since change 7, from ({}) \"laptop\" at 2027-01-15 08:00 \
                 UTC, by a record that does not count: 64 devices counted already. It signed 5 \
                 entries in the personal channel of that change.",
                fingerprint::shown(&[5; 32]),
                fingerprint::shown(&[1; 32])
            ),
        );
        // Asked about for the record that the laptop signed.
        let asked = for_room_says(&rows, &[], 4, 7, 191);
        assert_eq!(
            asked,
            format!(
                "{says}\n  That is the one thing its record fails for, so it is asked about all \
                 the same. Nothing that it wrote is brought back by this recovery, whatever is \
                 said of it: `lost` or `hands` removes its key, and what it wrote then comes in \
                 by `cordelia sync carry <name> --from <device>`, with the phrase; `have` leaves \
                 it to be added again by hand. Each key that is removed takes one of the \
                 removals that the recovery phrase has left: 191 of 256."
            ),
        );
        assert!(
            for_room_says(&rows, &[], 4, 7, 0).ends_with("has left: 0 of 256."),
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

        // The desktop added it too, under another label, and it signed a
        // record of its own: both labels are shown, each beside its
        // adder, and the line of what it added follows. Neither adder is
        // named apart from the others.
        let mut two = rows.clone();
        two[4]
            .no_room
            .push(([2; 32], 1_800_000_060, "kitchen watch".into()));
        two[4].signed_a_record = true;
        let asked = for_room_says(&two, &[], 4, 7, 191);
        assert!(
            asked.contains(&format!(
                "from ({}) \"laptop\" at 2027-01-15 08:00 UTC as \"watch\", and from ({}) \
                 \"desktop\" at 2027-01-15 08:01 UTC as \"kitchen watch\", by a record",
                fingerprint::shown(&[1; 32]),
                fingerprint::shown(&[2; 32])
            )),
            "{asked}"
        );
        assert!(
            asked.contains(
                "\n  The labels differ. A label is what the device that added it called it: the \
                 words are what tells two apart.\n  A device that it added is not shown here: a \
                 device that does not count adds nothing.\n  That is the one thing"
            ),
            "{asked}"
        );
        assert!(!asked.contains("added it too"), "{asked}");

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
        let all =
            will_do_lines(&generation, &lost, &names, &[9; 32], &read_whole(), None).join("\n");
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
        let all =
            will_do_lines(&generation, &have, &names, &[9; 32], &read_whole(), None).join("\n");
        assert!(!all.contains("It takes nothing from"), "{all}");
        // Nor where each device that signed its record may be in someone
        // else's hands: nothing was asked of it, whatever stands there.
        let mut hands = lost;
        (hands[0], hands[1]) = (Answer::OtherHands, Answer::OtherHands);
        let all =
            will_do_lines(&generation, &hands, &names, &[9; 32], &read_whole(), None).join("\n");
        assert!(!all.contains("\"watch\""), "{all}");
    }

    /// What is said of a key that the 64 kept out and that two adders
    /// added under two labels (decision 2026-10-17 §2.5): the row shows
    /// each label beside the adder that gave it, in the order of the
    /// adders' rows, and says that the labels differ. An adder that may be
    /// in someone else's hands is counted, and not shown, nor is its label
    /// (§2.4): no one adder's label stands for the key.
    #[test]
    fn test_what_is_said_of_a_key_added_under_two_labels() {
        let mut rows = rows();
        // A key that the laptop added as a phone and the desktop as a
        // kitchen tablet. The label that the row holds is no adder's own
        // word here, so what is shown is the adders'.
        let mut phone = row(6, "not shown", Some(1), false);
        phone.no_room = vec![
            ([1; 32], 1_800_000_000, "phone".into()),
            ([2; 32], 1_800_123_400, "kitchen tablet".into()),
        ];
        phone.signed = 4;
        phone.signed_a_record = true;
        rows.push(phone);
        let (w1, w2, w6) = (
            fingerprint::shown(&[1; 32]),
            fingerprint::shown(&[2; 32]),
            fingerprint::shown(&[6; 32]),
        );
        let labels_differ = "  The labels differ. A label is what the device that added it \
                             called it: the words are what tells two apart.";
        let added_one = "  A device that it added is not shown here: a device that does not \
                         count adds nothing.";
        assert_eq!(
            row_says(&rows, &[Answer::Have, Answer::Lost], 4, 3),
            format!(
                "\n({w6}) \"phone\", added since change 3, from ({w1}) \"laptop\" at 2027-01-15 \
                 08:00 UTC as \"phone\", and from ({w2}) \"desktop\" at 2027-01-16 18:16 UTC as \
                 \"kitchen tablet\", by a record that does not count: 64 devices counted \
                 already. It signed 4 entries in the personal channel of that change.\
                 \n{labels_differ}\n{added_one}"
            )
        );
        // The laptop may be in someone else's hands: it is counted, and
        // neither it nor its label is shown.
        let hands = [Answer::OtherHands, Answer::Lost];
        let says = row_says(&rows, &hands, 4, 3);
        assert_eq!(
            says,
            format!(
                "\n({w6}) \"kitchen tablet\", added since change 3, from ({w2}) \"desktop\" at \
                 2027-01-16 18:16 UTC as \"kitchen tablet\", and 1 more added it, which may be in \
                 someone else's hands, by a record that does not count: 64 devices counted \
                 already. It signed 4 entries in the personal channel of that change.\
                 \n{added_one}"
            )
        );
        assert!(!says.contains("\"phone\"") && !says.contains(&w1), "{says}");
        // Both may be: neither is shown.
        let says = row_says(&rows, &[Answer::OtherHands, Answer::OtherHands], 4, 3);
        assert_eq!(
            says,
            format!(
                "\nthe device ({w6}), added since change 3 by 2 devices that may be in someone \
                 else's hands, by a record that does not count: 64 devices counted already. It \
                 signed 4 entries in the personal channel of that change.\n{added_one}"
            )
        );
        // An adder whose own adder may be in someone else's hands may be
        // too: a watch that the laptop added, and the phone, which the
        // desktop added. The phone was said to be one that the person
        // still has, and the desktop may be in someone else's hands: the
        // phone is counted, and its label is not shown.
        let mut watch = row(7, "not shown", Some(1), false);
        watch.no_room = vec![
            ([1; 32], 1_800_000_000, "watch".into()),
            ([3; 32], 1_800_000_000, "kitchen watch".into()),
        ];
        rows.push(watch);
        let chain = [Answer::Have, Answer::OtherHands, Answer::Have];
        let says = row_says(&rows, &chain, 5, 3);
        assert!(
            says.starts_with(&format!(
                "\n({}) \"watch\", added since change 3, from ({w1}) \"laptop\" at 2027-01-15 \
                 08:00 UTC as \"watch\", and 1 more added it, which may be in someone else's \
                 hands, by a record",
                fingerprint::shown(&[7; 32])
            )),
            "{says}"
        );
        assert!(!says.contains("kitchen watch"), "{says}");
        // One adder alone that may be in someone else's hands is counted
        // and not shown, as among several: the key is shown by its words.
        let mut pager = row(8, "pager", Some(1), false);
        pager.no_room = vec![([1; 32], 1_800_000_000, "pager".into())];
        rows.push(pager);
        assert_eq!(
            row_says(&rows, &[Answer::OtherHands], 6, 3),
            format!(
                "\nthe device ({}), added since change 3 by 1 device that may be in someone \
                 else's hands, by a record that does not count: 64 devices counted already. It \
                 signed 8 entries in the personal channel of that change.",
                fingerprint::shown(&[8; 32])
            )
        );
        let shown_alone = row_says(&rows, &[Answer::Have], 6, 3);
        assert!(
            shown_alone.contains(&format!(
                "\"pager\", added since change 3, from ({w1}) \"laptop\" at 2027-01-15 08:00 \
                 UTC, by a record that does not count: 64"
            )),
            "{shown_alone}"
        );

        // The same label from both: nothing is said of labels.
        rows[4].no_room[1].2 = "phone".into();
        let says = row_says(&rows, &[Answer::Have, Answer::Lost], 4, 3);
        assert!(says.contains("as \"phone\", and from"), "{says}");
        assert!(!says.contains("The labels differ"), "{says}");
    }

    /// The rows of a test, and a key that the 64 kept out, which the
    /// laptop added as a phone and the desktop as a kitchen tablet: its
    /// row holds the laptop's label, as a recovery reads it, the laptop's
    /// row being the first.
    fn rows_with_two_labels() -> Vec<Row> {
        let mut rows = rows();
        let mut kept_out = row(6, "phone", Some(1), false);
        kept_out.no_room = vec![
            ([1; 32], 1_800_000_000, "phone".into()),
            ([2; 32], 1_800_000_000, "kitchen tablet".into()),
        ];
        rows.push(kept_out);
        rows
    }

    /// What the command does at a row turns on the answers given so far
    /// (decision 2026-10-17 §2.4): an adder that was said to be in
    /// someone else's hands is not shown, whether the row is asked about
    /// or is not.
    #[test]
    fn test_what_is_said_at_a_row_turns_on_the_answers_so_far() {
        let rows = rows_with_two_labels();
        let room = recover::Room {
            removed: 0,
            asked: 5,
            can_go: 256,
        };
        let at = |answers: &[Answer], n: usize| {
            at_a_row(&rows, answers, n, 3, &[9; 32], &room, &|_| false)
        };
        // The laptop may be in someone else's hands, and the desktop is
        // kept: the key is asked about under the desktop, by its label.
        let so_far = [
            Answer::OtherHands,
            Answer::Have,
            Answer::Have,
            Answer::NotAsked,
        ];
        let AtARow::Asks(says) = at(&so_far, 4) else {
            panic!("the key is asked about");
        };
        assert_eq!(says, for_room_says(&rows, &so_far, 4, 3, 255));
        assert!(
            says.contains("\"kitchen tablet\", added since change 3"),
            "{says}"
        );
        assert!(says.contains("and 1 more added it"), "{says}");
        assert!(!says.contains("\"phone\""), "{says}");
        // Both may be: nothing is asked, and neither label is shown.
        let both = [
            Answer::OtherHands,
            Answer::OtherHands,
            Answer::Have,
            Answer::NotAsked,
        ];
        let AtARow::Said(says, Answer::NotAsked) = at(&both, 4) else {
            panic!("nothing is asked of the key");
        };
        assert!(says.starts_with("\nthe device ("), "{says}");
        assert!(
            !says.contains("\"phone\"") && !says.contains("kitchen"),
            "{says}"
        );
        // This machine is answered as one that the person has.
        let own = at_a_row(&rows, &[], 0, 3, &[1; 32], &room, &|_| false);
        assert!(matches!(own, AtARow::Said(_, Answer::Have)), "{own:?}");
    }

    /// **A row that does not count, has one adder, and was not kept out
    /// by the 64 follows the label shown as every other row does**
    /// (decision 2026-10-17 §2.4): where its adder may be in someone
    /// else's hands, the row, the lines before the yes and what the node
    /// keeps name the key by its words alone, and not by that adder's
    /// label. Where the adder is kept, its label is shown.
    #[test]
    fn test_a_row_that_does_not_count_shows_no_label_of_an_adder_in_someone_elses_hands() {
        let rows = rows();
        let generation = Generation {
            rows: rows.clone(),
            ..Default::default()
        };
        let room = recover::Room {
            removed: 0,
            asked: 4,
            can_go: 196,
        };
        // The desktop and the phone, which added the tablet, may be in
        // someone else's hands; the tablet's record does not count for
        // another reason.
        let answers = [Answer::Have, Answer::OtherHands, Answer::OtherHands];
        assert!(rows[3].no_room.is_empty() && !rows[3].counts);
        assert_eq!(recover::label_shown(&rows, &answers, &rows[3]), "");
        let AtARow::Said(says, _) = at_a_row(&rows, &answers, 3, 3, &[9; 32], &room, &|_| false)
        else {
            panic!("a record that does not count is not asked about");
        };
        let words = fingerprint::shown(&[4; 32]);
        assert!(
            says.starts_with(&format!("\nthe device ({words}), added since")),
            "{says}"
        );
        assert!(!says.contains("\"tablet\""), "{says}");
        let mut answered = answers.to_vec();
        answered.push(Answer::NotAsked);
        let labels = labels_for_the_node(&generation, &answered, &[9; 32]);
        assert!(!labels.to_string().contains("tablet"), "{labels}");
        // The phone kept: the tablet is shown by its label.
        let kept = [Answer::Have, Answer::Have, Answer::Have];
        assert_eq!(recover::label_shown(&rows, &kept, &rows[3]), "tablet");
        let AtARow::Said(says, _) = at_a_row(&rows, &kept, 3, 3, &[9; 32], &room, &|_| false)
        else {
            panic!("a record that does not count is not asked about");
        };
        assert!(says.contains("\"tablet\""), "{says}");
        // A row that counts keeps its label, though its adder, the
        // desktop, may be in someone else's hands: its own row says what
        // was said of it.
        assert_eq!(recover::label_shown(&rows, &answers, &rows[2]), "phone");
    }

    /// The label by which a key that the 64 kept out is named before the
    /// yes, and the label that the node is handed for it and keeps, is
    /// the one that its row was shown by (decision 2026-10-17 §2.4): that
    /// of the first adder that is not in someone else's hands. Where every
    /// adder may be, the label is empty, which the node keeps as none.
    #[test]
    fn test_a_key_kept_out_by_the_64_is_named_by_the_label_its_row_showed() {
        let mut rows = rows_with_two_labels();
        let not_shown = |n: u8| {
            let mut beyond = row(n, "beyond", Some(1), false);
            beyond.no_room = vec![([1; 32], 1_800_000_000, "beyond".into())];
            beyond
        };
        let generation = Generation {
            rows: rows.clone(),
            not_shown: vec![not_shown(20)],
            ..Default::default()
        };
        let names = recover::Names::default();
        // The laptop may be in someone else's hands; the desktop and the
        // phone are kept, and the key is lost.
        let answers = [
            Answer::OtherHands,
            Answer::Have,
            Answer::Have,
            Answer::NotAsked,
            Answer::Lost,
        ];
        let all =
            will_do_lines(&generation, &answers, &names, &[9; 32], &read_whole(), None).join("\n");
        assert!(
            all.contains(&format!(
                "It takes nothing from: ({}) \"laptop\", ({}) \"kitchen tablet\".",
                fingerprint::shown(&[1; 32]),
                fingerprint::shown(&[6; 32])
            )),
            "{all}"
        );
        let labels = labels_for_the_node(&generation, &answers, &[9; 32]);
        let labelled =
            |key: u8, label: &str| json!({ "key": hex::encode([key; 32]), "label": label });
        assert_eq!(
            labels["gone"],
            json!([labelled(1, "laptop"), labelled(6, "kitchen tablet")])
        );
        assert_eq!(
            labels["still_have"],
            json!([labelled(2, "desktop"), labelled(3, "phone")])
        );
        // The row that could not be shown was added by the laptop alone:
        // it has no label.
        assert_eq!(labels["not_shown"], json!([labelled(20, "")]));
        // With the laptop kept, each is by the laptop's label.
        let mut kept = answers;
        kept[0] = Answer::Have;
        let labels = labels_for_the_node(&generation, &kept, &[9; 32]);
        assert_eq!(labels["gone"], json!([labelled(6, "phone")]));
        assert_eq!(labels["not_shown"], json!([labelled(20, "beyond")]));
        // This machine is handed as none of them.
        rows[0].key = [9; 32];
        let generation = Generation {
            rows,
            ..Default::default()
        };
        let labels = labels_for_the_node(&generation, &kept, &[9; 32]);
        assert!(
            !labels["still_have"]
                .to_string()
                .contains(&hex::encode([9u8; 32]))
        );
    }

    /// The row of a key that the 64 kept out says that what it added is
    /// not shown where it signed a record of an addition, and not where it
    /// signed none (decision 2026-10-17 §2.3, §2.5).
    #[test]
    fn test_a_row_kept_out_by_the_64_says_that_what_it_added_is_not_shown() {
        let mut rows = rows();
        let mut tablet = row(5, "tablet", Some(1), false);
        tablet.no_room = vec![([1; 32], 1_800_000_000, "tablet".into())];
        rows.push(tablet);
        let line = "\n  A device that it added is not shown here: a device that does not count \
                    adds nothing.";
        let none = row_says(&rows, &[], 4, 7);
        assert!(!none.contains("A device that it added"), "{none}");
        rows[4].signed_a_record = true;
        let signed = row_says(&rows, &[], 4, 7);
        assert_eq!(signed, format!("{none}{line}"));
        // Asked about, the line is said before what the answers do.
        let asked = for_room_says(&rows, &[], 4, 7, 191);
        assert!(
            asked.starts_with(&format!("{signed}\n  That is the one thing")),
            "{asked}"
        );
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
                let lines = will_do_lines(&generation, &answers, &none, &own, &read, None);
                let all = lines.join("\n");
                let with_a_name = will_do_lines(&generation, &answers, &lab, &own, &read, None);
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
                         missing from what was read. A relay that hands it more slowly than a \
                         channel at its largest needs, or stops, leaves it in part.\n",
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
             be missing from what was read. A relay that hands it more slowly than a channel at \
             its largest needs, or stops, leaves it in part."
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
        let all = will_do_lines(&generation, &answers, &none, &own, &before, None).join("\n");
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
            let lines = will_do_lines(&generation, &answers, &none, &own, &held_nowhere, None);
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
        let all = will_do_lines(&generation, &answers, &none, &own, &held_at_one, None).join("\n");
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
    /// still has is added again by hand. After its first sentence it
    /// says that each device that may add keeps a row for at least its
    /// first three that the 64 kept out (decision 2026-10-17 §2.5). It
    /// is said where either number
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
        let because = "because more were written than a recovery keeps. Each device that may add \
                       keeps a row for at least the first 3 devices that it added since change 7 \
                       and that 64 devices counted already kept out: a device that added more \
                       than that may have left one of them here. A device of yours that was added \
                       since change 7 may be among them.";
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
        assert!(
            one.contains("the first 3 devices that it added since change 3 and that 64"),
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
        let all = will_do_lines(&generation, &answers, &names, &[9; 32], &read, None).join("\n");
        assert!(
            all.contains(&format!(
                "`cordelia devices` shows it with its key.\n{two}\nNo name is carried"
            )),
            "{all}"
        );
        generation.not_shown.clear();
        let all = will_do_lines(&generation, &answers, &names, &[9; 32], &read, None).join("\n");
        assert!(
            all.contains(&format!("\n{two}\nNo name is carried")),
            "{all}"
        );
        // Every key has a row, and none of them is such a row: nothing
        // is said of it.
        generation.no_row = 0;
        let all = will_do_lines(&generation, &answers, &names, &[9; 32], &read, None).join("\n");
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
        let all = will_do_lines(&with_a_row, &answers, &names, &[9; 32], &read, None).join("\n");
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
            carried_word: None,
        };
        let names = recover::Names {
            carried: vec!["lab".into(), "no\u{1b}tes".into()],
            over_the_bound: vec!["beyond".into()],
            only_other_hands: vec!["theirs".into()],
        };
        // The laptop is lost; the desktop may be in someone else's
        // hands, and with it the phone it added.
        let answers = [Answer::Lost, Answer::OtherHands, Answer::Have, Answer::Have];
        let all =
            will_do_lines(&generation, &answers, &names, &[9; 32], &read_whole(), None).join("\n");
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
        let all =
            will_do_lines(&generation, &none, &empty, &[9; 32], &read_whole(), None).join("\n");
        assert!(
            all.contains("Nothing that those devices wrote is brought back by this recovery."),
            "{all}"
        );
        assert!(all.contains("No name is carried: none is listed."), "{all}");

        // **"None is listed" is said only where none is.** Names are
        // listed, and only by a device from which nothing is taken, or
        // by a key that does not count: no name is carried, and the line
        // for the names that are left says which. So whatever was read.
        let left = recover::Names {
            only_other_hands: vec!["theirs".into(), "desk".into()],
            ..Default::default()
        };
        let in_part = was_read(&[json!({ "relay": "one", "read": "part", "entries": 2 })]);
        for read in [read_whole(), in_part] {
            let lines = will_do_lines(&generation, &none, &left, &[9; 32], &read, None);
            assert!(
                lines.contains(&"No name is carried.".to_string()),
                "{lines:?}"
            );
            let all = lines.join("\n");
            assert!(!all.contains("none is listed"), "{all}");
            assert!(
                all.contains(
                    "2 names are left, which only a device listed from which nothing is taken, \
                     or a key that does not count: theirs, desk."
                ),
                "{all}"
            );
            // And where none is listed, that is still said.
            let all = will_do_lines(&generation, &none, &empty, &[9; 32], &read, None).join("\n");
            assert!(all.contains("No name is carried: none is listed"), "{all}");
        }
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
    /// sent what it carried is not among what was read. **That the
    /// device never wrote the word, and was cut short, is said as that
    /// only where the personal channel was read to its end:** at each
    /// relay that the node said anything of, and one of them holds it.
    ///
    /// - Read in part, or not at all, at one relay at least, whatever was
    ///   read at another: the word was not found in what was read, may
    ///   be in what was not, and it may have been cut short.
    /// - No relay that answered holds any of the channel: the word was
    ///   not found for that. A device that wrote nothing there, and a
    ///   relay that has dropped the channel, both give this, and it may
    ///   have been cut short.
    ///
    /// Which of the three it is goes to the process that waits for the
    /// look as that command reads it.
    #[test]
    fn test_what_is_said_of_a_device_whose_word_that_it_sent_was_not_read() {
        use ChannelRead::{HeldByNone, InPart, Whole};
        let said = |relay: &str, read: &str, entries: u64| json!({ "relay": relay, "read": read, "entries": entries });
        let generation = |cut_short: Option<[u8; 32]>| Generation {
            rows: rows(),
            cut_short,
            ..Default::default()
        };
        let laptop = named("laptop", &[1; 32]);
        let of = |relays: &[Value]| {
            let cut_short =
                CutShort::of(&generation(Some([1; 32])), &was_read(relays), &[]).unwrap();
            assert_eq!(cut_short.device, laptop);
            cut_short.read
        };
        let (whole, part) = (said("one", "whole", 4), said("two", "part", 2));
        let (not_held, not_reached) =
            (said("three", "not held", 0), said("four", "not reached", 0));
        // The read ended before any entry of the channel was handed.
        let nothing = said("five", "part", 0);
        // Read to its end at each relay that holds any of it, and one
        // does: the word is not there.
        assert_eq!(of(std::slice::from_ref(&whole)), Whole);
        assert_eq!(of(&[whole.clone(), said("two", "whole", 4)]), Whole);
        assert_eq!(of(&[whole.clone(), not_held.clone()]), Whole);
        // In part, or not at all, at one relay at least: whatever was
        // read at another, to its end or as held by none.
        for not_read in [&part, &not_reached, &nothing] {
            assert_eq!(of(std::slice::from_ref(not_read)), InPart, "{not_read}");
            assert_eq!(of(&[whole.clone(), not_read.clone()]), InPart, "{not_read}");
            assert_eq!(
                of(&[not_held.clone(), not_read.clone()]),
                InPart,
                "{not_read}"
            );
        }
        // No relay that answered holds any of the channel.
        assert_eq!(of(std::slice::from_ref(&not_held)), HeldByNone);
        assert_eq!(
            of(&[not_held.clone(), said("six", "not held", 0)]),
            HeldByNone
        );
        // The word was read, or the change lists more devices than one.
        let read = was_read(std::slice::from_ref(&part));
        assert_eq!(CutShort::of(&generation(None), &read, &[]), None);

        let says = |read: ChannelRead| {
            let device = laptop.clone();
            let carried_to = None;
            CutShort {
                device,
                read,
                carried_to,
            }
            .says()
        };
        let brings = "`cordelia sync carry <name> --from <device>` brings it in, with the phrase, \
                      and lists those devices where no device is named.";
        assert_eq!(
            says(Whole),
            format!(
                "The device that this was recovered from, {laptop}, never wrote that it had \
                 sent what it carried: a recovery, or a change, that was made on it was cut \
                 short. What it had sent is brought back. What the devices that were gone \
                 before it wrote, in the files it had not sent, is at the relays in the \
                 generation before: {brings}"
            )
        );
        let may_have_been = format!(
            "A recovery, or a change, that was made on it may have been cut short. What it had \
             sent is brought back. If it was cut short, what the devices that were gone before \
             it wrote, in the files it had not sent, is at the relays in the generation before: \
             {brings}"
        );
        assert_eq!(
            says(InPart),
            format!(
                "The word of the device that this was recovered from, {laptop}, that it had \
                 sent what it carried was not found in what was read: its personal channel was \
                 not read to its end at every relay, and the word may be in what was not read. \
                 {may_have_been}"
            )
        );
        assert_eq!(
            says(HeldByNone),
            format!(
                "The word of the device that this was recovered from, {laptop}, that it had \
                 sent what it carried was not found: no relay that answered holds that device's \
                 personal channel. A device that wrote nothing there, and a relay that has \
                 dropped the channel, both give this. {may_have_been}"
            )
        );
        // It is said as fact in the one case, and in no other.
        for not_known in [InPart, HeldByNone] {
            let said = says(not_known);
            assert!(!said.contains("never wrote"), "{said}");
            assert!(!said.contains("made on it was cut short"), "{said}");
        }

        // What the process that waits for the look is handed.
        let handed = |read: ChannelRead| {
            let device = laptop.clone();
            let carried_to = None;
            CutShort {
                device,
                read,
                carried_to,
            }
            .args()
        };
        for (read, word) in [
            (Whole, "whole"),
            (InPart, "in-part"),
            (HeldByNone, "held-by-none"),
        ] {
            let with = ["--cut-short", laptop.as_str(), "--channel-read", word];
            assert_eq!(handed(read), with, "{read:?}");
        }
    }

    /// A relay as the node's look shows it, holding the change or lacking
    /// it, as the node knows it (decision 2026-10-19 §1).
    fn holding(relay: &str, holds: bool) -> Value {
        let holds = if holds { "holds" } else { "lacks" };
        json!({ "relay": relay,
                "reach": { "about": KEPT, "holds": holds, "reached": true, "reference": 0 } })
    }

    /// The change entry that the looks of these tests name as kept, and
    /// what [`holding`]'s reach is about.
    const KEPT: &str = "aa";

    /// Once the look has ended the command says "keep this machine on"
    /// with how many names are still to send, and how each device that
    /// the person still has is added again (decision 2026-10-04 §9, steps
    /// 5 and 6). Which relay holds the change is the wait's to say
    /// (decision 2026-10-19 §4, rule 9).
    #[test]
    fn test_what_is_said_once_the_look_has_ended() {
        let seen = json!({
            "this_device": "cordelia1thismachine", "latest": KEPT,
            "relays": [
                holding("one", true),
                holding("two", false),
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
        // Whether each relay holds the change is the wait's to say, and
        // no line here says it (decision 2026-10-19 §4, rule 9).
        assert!(!all.contains("holds the change"), "{all}");
        assert!(!all.contains("does not hold the change"), "{all}");
        assert!(!all.contains("is not connected"), "{all}");
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
            "this_device": "k", "latest": KEPT, "relays": [holding("one", true)],
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
                "this_device": "k", "latest": KEPT, "relays": [holding("one", true)],
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
                "this_device": "k", "latest": KEPT, "relays": [holding("one", true)],
                "names": { "to_go": [], "sent": [] }, "left_out": [],
                "waiting": [], "not_reached": not_reached,
            })
        };
        let all = after_lines(&not_connected(json!(["one"])), 0);
        assert_eq!(all, [shows.to_string()], "{all:?}");
        let all = after_lines(&not_connected(json!([])), 0);
        assert_eq!(
            all,
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
        assert_eq!(all, [shows]);
        // A relay that is connected does not hold the change yet, and
        // nothing waits in the store: the machine is to be kept on, and
        // nothing is said to be waiting nowhere beside that.
        let mut not_held_yet = seen(json!([]), 0);
        not_held_yet["relays"] = json!([holding("one", true), holding("two", false),]);
        let all = after_lines(&not_held_yet, 0);
        assert_eq!(all, [shows]);
        // So where the node does not say whether a relay holds it.
        not_held_yet["relays"] = json!([{ "relay": "one" }]);
        let all = after_lines(&not_held_yet, 0);
        assert_eq!(all, [shows]);
        // Each relay holds the change, and each is connected: said.
        not_held_yet["relays"] = json!([holding("one", true), holding("two", true),]);
        let all = after_lines(&not_held_yet, 0);
        assert_eq!(all, [nothing]);
        // Not where what is known of a relay is about the entry before the
        // change: the node's pass has not found the change yet.
        let mut stale = not_held_yet.clone();
        stale["relays"][1]["reach"]["about"] = "bb".into();
        assert_eq!(after_lines(&stale, 0), [shows]);
        let mut unnamed = not_held_yet.clone();
        unnamed.as_object_mut().unwrap().remove("latest");
        assert_eq!(after_lines(&unnamed, 0), [shows]);
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
        watch.no_room = vec![([1; 32], 1_800_000_000, "watch".into())];
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

    /// The entries of a channel of a test, `n` of them.
    fn channel_of(n: usize) -> Vec<CheckedEntry> {
        use cordelia_crypto::entry::{Entry, Inside, Value as Held};
        let author = cordelia_crypto::identity::NodeIdentity::generate().unwrap();
        (0..n)
            .map(|at| {
                let inside = Inside {
                    name: format!("{at}.md"),
                    value: Held::Text("x".into()),
                    chain: Some(Vec::new()),
                };
                let sealed = Entry::seal(&[9; 32], &author, 1, &inside).unwrap();
                sealed.check().unwrap()
            })
            .collect()
    }

    /// What a relay of a test counts each entry as, against a channel's
    /// cap: so that three come to 4.0 MiB.
    const COUNTED_AS: u64 = 1_398_102;

    /// The mark of the holding of a relay of a test.
    const MARK: [u8; 8] = [6; 8];

    /// What a relay named `relay`, which holds `held` under [`MARK`] and
    /// hands `per_read` entries in a read, hands when it is asked from
    /// `from`: from the place given for it under that mark, and from the
    /// start where none is. What the node says of it carries the place
    /// reached, as the command reads it.
    fn hands(
        relay: &str,
        held: &[CheckedEntry],
        from: &[Value],
        per_read: usize,
    ) -> (Vec<CheckedEntry>, Value) {
        let asked = from.iter().find(|place| place["relay"] == relay);
        let start = match asked {
            Some(place) if place["mark"] == hex::encode(MARK) => {
                place["place"].as_u64().unwrap() as usize
            }
            _ => 0,
        };
        let end = (start + per_read).min(held.len());
        let handed = held[start..end].to_vec();
        let said = json!({
            "relay": relay,
            "read": if end == held.len() { "whole" } else { "part" },
            "entries": handed.len(),
            "bytes": handed.len() as u64 * COUNTED_AS,
            "mark": hex::encode(MARK),
            "place": end,
        });
        (handed, said)
    }

    /// What one round of a test is asked: the relays named, where it
    /// names any, and the places.
    type Asked = Vec<(Option<Vec<String>>, Vec<Value>)>;

    /// Read on with `round`, each round taking CARRY_READ_MAX_SECS on a
    /// clock of the test's own: what was read, what is said of each
    /// relay, what each round was asked, and the lines said.
    fn reads_on(
        mut round: impl FnMut(usize, &[Value]) -> (Vec<CheckedEntry>, Vec<Value>),
    ) -> (Vec<CheckedEntry>, Vec<Value>, Asked, Vec<String>) {
        use std::cell::RefCell;
        let asked: RefCell<Asked> = RefCell::new(Vec::new());
        let mut lines = Vec::new();
        let (entries, said) = read_on(
            3,
            |relays, from| {
                let number = asked.borrow().len();
                asked
                    .borrow_mut()
                    .push((relays.map(<[String]>::to_vec), from.to_vec()));
                Ok(round(number, from))
            },
            |line| lines.push(line),
        )
        .unwrap();
        (entries, said, asked.into_inner(), lines)
    }

    /// The relays named, as a round is asked them.
    fn asked_of(relays: &[&str]) -> Option<Vec<String>> {
        Some(relays.iter().map(|relay| relay.to_string()).collect())
    }

    /// The place to ask from at a relay of a test.
    fn place(relay: &str, at: u64) -> Value {
        json!({ "relay": relay, "mark": hex::encode(MARK), "place": at })
    }

    /// **A recovery reads its personal channel on from the place each
    /// relay reached, round after round, until its end** (decision
    /// 2026-10-17 §3.2, §3.3; §1, property 10). The relay hands a third
    /// of the channel in a read. The first round reads from the start, at
    /// every relay; the second and third are asked of that relay alone,
    /// each from the place the last reached. Every entry is kept, each
    /// once, and the relay is said to have handed the channel to its end.
    /// The command says after the first round that it reads on, and after
    /// each round how far it has read.
    #[test]
    fn test_a_recovery_reads_its_personal_channel_on_until_its_end() {
        let held = channel_of(9);
        let (entries, said, asked, lines) = reads_on(|_, from| {
            let (handed, said) = hands("relay-one", &held, from, 3);
            (handed, vec![said])
        });
        assert_eq!(
            asked,
            [
                (None, vec![]),
                (asked_of(&["relay-one"]), vec![place("relay-one", 3)]),
                (asked_of(&["relay-one"]), vec![place("relay-one", 6)]),
            ]
        );
        let ids = |of: &[CheckedEntry]| of.iter().map(|e| e.id()).collect::<Vec<_>>();
        assert_eq!(ids(&entries), ids(&held));
        assert_eq!(
            said,
            [json!({ "relay": "relay-one", "read": "whole", "entries": 9 })]
        );
        assert_eq!(PersonalRead::of(&said).at(&[ReadAs::Whole]), ["relay-one"]);
        assert_eq!(
            lines.join("\n"),
            "\nThe personal channel of change 3 is larger than one read. Reading on at relay-one: \
             a relay may hold up to 16 MiB of it, which takes up to 5 reads: up to 4 more are \
             made, each of up to 2 minutes and what it takes beyond that. Ctrl-C stops here, and \
             nothing is made.\n  \
             relay-one: 4.0 MiB read so far.\n  \
             relay-one: 8.0 MiB read so far.\n  \
             relay-one: read to its end, 12.0 MiB."
        );

        // A channel read to its end at the first round is not read on,
        // and nothing more is said.
        let (entries, said, asked, lines) = reads_on(|_, from| {
            let (handed, said) = hands("relay-one", &held, from, 9);
            (handed, vec![said])
        });
        assert_eq!((entries.len(), asked.len()), (9, 1));
        assert_eq!(said[0]["read"], "whole");
        assert!(lines.is_empty(), "{lines:?}");
    }

    /// **A relay is asked in RECOVERY_READ_ON_READS rounds at most, its
    /// own count** (decision 2026-10-17 §3.2; §1, property 10). The relay
    /// hands one entry of a hundred in a read: five rounds are read, the
    /// relay is said to have been read in part, and why: its five reads
    /// were made.
    ///
    /// **A relay whose connection changed is read again in the first
    /// round, and after it is asked again in the next round, from where
    /// it was; each is one of its readings:** one whose connection changes
    /// at the first reading and at the two readings again of the first
    /// round is asked from the start in each of them, said once to be read
    /// again, and still read on in the two rounds it has left. It is not
    /// said to be larger than one read: it handed nothing.
    #[test]
    fn test_a_recovery_stops_reading_on_at_the_bound() {
        let held = channel_of(100);
        let (entries, said, asked, lines) = reads_on(|_, from| {
            let (handed, said) = hands("relay-one", &held, from, 1);
            (handed, vec![said])
        });
        assert_eq!(asked.len(), 5);
        assert_eq!(entries.len(), 5);
        assert_eq!(asked[4].1, [place("relay-one", 4)]);
        let made = "its 5 reads were made";
        assert_eq!(
            said,
            [json!({ "relay": "relay-one", "read": "part", "entries": 5, "why": made })]
        );
        assert_eq!(PersonalRead::of(&said).at(&[ReadAs::Part]), ["relay-one"]);
        assert_eq!(
            lines.last().unwrap(),
            "  relay-one: read in part, 6.7 MiB: its 5 reads were made."
        );
        // Five readings of a round's time are within the bound, and a
        // sixth is not.
        let readings = RECOVERY_READ_ON_READS * CARRY_READ_MAX_SECS;
        assert!(readings <= RECOVERY_READ_ON_MAX_SECS);
        assert!(readings + CARRY_READ_MAX_SECS > RECOVERY_READ_ON_MAX_SECS);

        // Its connection changed at the first three rounds.
        let changed = cordelia_api::carrying::CONNECTION_CHANGED;
        let (entries, said, asked, lines) = reads_on(|round, from| match round {
            0..=2 => {
                let of = json!({ "relay": "relay-one", "read": changed, "entries": 0 });
                (Vec::new(), vec![of])
            }
            _ => {
                let (handed, said) = hands("relay-one", &held, from, 1);
                (handed, vec![said])
            }
        });
        assert_eq!(asked.len(), 5);
        assert_eq!(
            asked[1..4],
            [
                (asked_of(&["relay-one"]), vec![]),
                (asked_of(&["relay-one"]), vec![]),
                (asked_of(&["relay-one"]), vec![]),
            ]
        );
        assert_eq!(asked[4].1, [place("relay-one", 1)]);
        assert_eq!(entries.len(), 2);
        assert_eq!(said[0]["why"], made);
        let again = "  relay-one: its connection changed; it is read again from where it was.";
        assert_eq!(lines[0], again);
        assert_eq!(lines.iter().filter(|line| *line == again).count(), 1);
        assert!(
            !lines.iter().any(|line| line.contains("larger")),
            "{lines:#?}"
        );
    }

    /// **The end of a channel is what the node says it is** (decision
    /// 2026-10-17 §3.2): a relay whose page leaves the place it was asked
    /// from is said to have handed the channel to its end, and is not
    /// asked again, though it said a place before the one it was asked
    /// from. So is one that answers to its end under another mark: it
    /// dropped the channel and took it again, and was read from the
    /// start.
    #[test]
    fn test_a_page_that_leaves_the_place_ends_the_reading_as_read_to_its_end() {
        let held = channel_of(9);
        // The page left the place: nothing more is handed. Under another
        // mark, what the relay holds now is handed from its start: the
        // first two entries, which were handed before and are kept once.
        for (mark, at, again) in [(MARK, 1u64, 0usize), ([8; 8], 2, 2)] {
            let (entries, said, asked, lines) = reads_on(|round, from| match round {
                0 => {
                    let (handed, said) = hands("relay-one", &held, from, 3);
                    (handed, vec![said])
                }
                _ => {
                    let left = json!({
                        "relay": "relay-one", "read": "whole", "entries": again,
                        "bytes": again as u64 * COUNTED_AS, "mark": hex::encode(mark),
                        "place": at,
                    });
                    (held[..again].to_vec(), vec![left])
                }
            });
            assert_eq!(asked.len(), 2, "{mark:?}");
            assert_eq!(entries.len(), 3);
            let handed = 3 + again;
            assert_eq!(
                said,
                [json!({ "relay": "relay-one", "read": "whole", "entries": handed })]
            );
            assert_eq!(
                *lines.last().unwrap(),
                format!(
                    "  relay-one: read to its end, {} MiB.",
                    mib(handed as u64 * COUNTED_AS)
                )
            );
        }
    }

    /// **A relay that is not reached in a round is not asked again, and a
    /// relay that handed part of the channel and then holds none of it is
    /// read in part** (decision 2026-10-17 §3.2; §1, property 10). Six
    /// relays hand a part of the channel at the first round. At the
    /// second: one is not reached; two answers that it holds none; three
    /// hands one entry more and then answers to its end under no mark,
    /// which is how a relay that drops the channel during a read answers,
    /// and that entry is counted; four hands nothing more, at the
    /// place it was asked from, which is no progress; the node says
    /// nothing of five; and six reads on. Only six is asked at the third
    /// round. Each of the five is read in part, with what it handed, and
    /// what is said of each says why it was not read on.
    ///
    /// At the first round, a relay that answers to its end under no mark
    /// holds none of it, where it handed nothing; and is read in part,
    /// and not read on, where it handed something. One whose read in part
    /// did not move from the start is not read on either.
    #[test]
    fn test_a_relay_not_reached_in_a_round_is_not_asked_again() {
        let held = channel_of(9);
        let none = hex::encode(cordelia_storage::relay::NO_MARK);
        let six = ["one", "two", "three", "four", "five", "six"];
        let (entries, said, asked, lines) = reads_on(|round, from| {
            let mut entries = Vec::new();
            let mut said = Vec::new();
            for relay in six {
                let (handed, mut of) = hands(relay, &held, from, 3);
                match (round, relay) {
                    (0, _) | (_, "six") => entries.extend(handed),
                    (_, "one") => {
                        of = json!({ "relay": "one", "read": "not reached", "entries": 0 })
                    }
                    (_, "two") => of = json!({ "relay": "two", "read": "not held", "entries": 0 }),
                    (_, "three") => {
                        of = json!({ "relay": "three", "read": "whole", "entries": 1,
                                     "bytes": COUNTED_AS, "mark": none, "place": 0 })
                    }
                    (_, "four") => {
                        of = json!({ "relay": "four", "read": "part", "entries": 0,
                                     "bytes": 0, "mark": hex::encode(MARK), "place": 3 })
                    }
                    _ => continue,
                }
                said.push(of);
            }
            if round == 0 {
                let dropped = json!({ "relay": "seven", "read": "whole", "entries": 0,
                                      "bytes": 0, "mark": none, "place": 0 });
                let dropped_after = json!({ "relay": "eight", "read": "whole", "entries": 2,
                                            "bytes": 2 * COUNTED_AS, "mark": none, "place": 0 });
                let at_the_start = json!({ "relay": "nine", "read": "part", "entries": 0,
                                           "bytes": 0, "mark": none, "place": 0 });
                said.extend([dropped, dropped_after, at_the_start]);
            }
            (entries, said)
        });
        let places: Vec<Value> = six.iter().map(|relay| place(relay, 3)).collect();
        assert_eq!(
            asked,
            [
                (None, vec![]),
                (asked_of(&six), places),
                (asked_of(&["six"]), vec![place("six", 6)]),
            ]
        );
        assert_eq!(entries.len(), 9);
        let read_as = |relay: &str| {
            let of = said.iter().find(|of| of["relay"] == relay).unwrap();
            (read_as(of), entries_handed(of))
        };
        for relay in ["one", "two", "four", "five"] {
            assert_eq!(read_as(relay), (ReadAs::Part, 3), "{relay}");
        }
        // What it handed in the round that ended so is counted.
        assert_eq!(read_as("three"), (ReadAs::Part, 4));
        assert_eq!(read_as("six"), (ReadAs::Whole, 9));
        assert_eq!(read_as("seven"), (ReadAs::NotHeld, 0));
        assert_eq!(read_as("eight"), (ReadAs::Part, 2));
        assert_eq!(read_as("nine"), (ReadAs::Nothing, 0));
        for line in [
            "  Could not read the personal channel at eight to its end (part).",
            "  Could not read the personal channel at nine to its end (part).",
            "  one: read in part, 4.0 MiB: it was not reached.",
            "  two: read in part, 4.0 MiB: it holds none of it now.",
            "  three: read in part, 5.3 MiB: it holds none of it now.",
            "  four: read in part, 4.0 MiB: it handed nothing more.",
            "  five: read in part, 4.0 MiB: the node said nothing of it.",
            "  six: read to its end, 12.0 MiB.",
        ] {
            assert!(lines.contains(&line.to_string()), "{line}: {lines:#?}");
        }
        assert!(
            !lines.iter().any(|line| line.contains("seven")),
            "{lines:#?}"
        );
    }

    /// **A recovery says before its yes each relay at which it could not
    /// read the phrase's own channel to its end** (decision 2026-10-17
    /// §3.2, §3.3; §1, property 11), where another relay held a change:
    /// it may hold a later one. A relay that holds none of it, and one
    /// that handed it whole, are not said. Where the change recovered
    /// from is not the latest that was read (two were made apart, and the
    /// other was chosen), that is not said to be the latest.
    #[test]
    fn test_a_phrase_channel_not_read_to_its_end_is_said_again_before_the_yes() {
        let phrase = [
            json!({ "relay": "relay-one", "read": "whole", "entries": 1 }),
            json!({ "relay": "relay-two", "read": "part", "entries": 0 }),
            json!({ "relay": "relay-three", "read": "not held", "entries": 0 }),
            json!({ "relay": "relay-four", "read": "not reached", "entries": 0 }),
        ];
        let personal = read_whole().personal;
        let was_read = WasRead::of(3, personal.clone(), &phrase, 3);
        let said = "The recovery phrase's own channel could not be read to its end at relay-two, \
                    relay-four: it may hold a later change. This recovery is made from change 3, \
                    the latest in what was read. Only the recovery phrase writes in that channel.";
        assert_eq!(was_read.lines(), [said]);
        let generation = Generation {
            rows: rows(),
            ..Default::default()
        };
        let names = recover::Names::default();
        let all = will_do_lines(
            &generation,
            &[Answer::Have; 4],
            &names,
            &[1; 32],
            &was_read,
            None,
        );
        assert!(all.contains(&said.to_string()), "{all:#?}");
        // From a change that is not the latest read.
        let apart = WasRead::of(3, personal.clone(), &phrase, 4);
        assert!(
            apart.lines()[0].contains("This recovery is made from change 3. Only"),
            "{:?}",
            apart.lines()
        );
        // Read whole, or held by none, at every relay: nothing is said.
        let whole = WasRead::of(3, personal, &[phrase[0].clone(), phrase[2].clone()], 3);
        assert!(whole.lines().is_empty(), "{:?}", whole.lines());
    }

    /// **A relay whose connection keeps changing costs no other relay a
    /// reading, and no round after the first is longer than one reading**
    /// (decision 2026-10-17 §3.2; §1, property 10). The read on, a round
    /// of it and the asking of only some relays, on a clock of the test's
    /// own where each reading takes CARRY_READ_MAX_SECS. Relay a hands ten
    /// entries of a hundred in a reading; b says at every reading that its
    /// connection changed. b is read again twice in the first round, as
    /// the read of today reads it, and then asked in the next round each
    /// time, each as one of its own readings; a gets its five readings,
    /// each from where the last ended; and the whole read ends within
    /// RECOVERY_READ_ON_READS readings and the CARRY_PROOFS_MADE_AGAIN of
    /// the first round. b handed nothing, and is said so, with why: its
    /// five reads were made, the last as its connection changed.
    #[test]
    fn test_a_relay_whose_connection_keeps_changing_costs_no_reading_beyond_the_bound() {
        use crate::carry_cmd::one_reading;
        use std::cell::{Cell, RefCell};
        let changed = cordelia_api::carrying::CONNECTION_CHANGED;
        let a = channel_of(100);
        let clock = Cell::new(0u64);
        let a_from: RefCell<Vec<u64>> = RefCell::new(Vec::new());
        let b_asked = Cell::new(0);
        let set_up: Sessions = vec![("a".into(), [1; 32]), ("b".into(), [2; 32])];
        let mut sessions = set_up.clone();
        let mut lines = Vec::new();
        let (_, said) = read_on(
            3,
            |asked, from| {
                let read = |of_those: &Sessions, places: &[Value]| {
                    clock.set(clock.get() + CARRY_READ_MAX_SECS);
                    let (mut entries, mut said) = (Vec::new(), Vec::new());
                    for (relay, _) in of_those {
                        if relay == "b" {
                            b_asked.set(b_asked.get() + 1);
                            said.push(json!({ "relay": "b", "read": changed, "entries": 0 }));
                            continue;
                        }
                        let at = places.iter().find(|place| place["relay"] == "a");
                        let at = at.map_or(0, |place| place["place"].as_u64().unwrap());
                        a_from.borrow_mut().push(at);
                        let (handed, of) = hands(relay, &a, places, 10);
                        entries.extend(handed);
                        said.push(of);
                    }
                    Ok((entries, said))
                };
                let ask = || Ok(set_up.clone());
                one_reading(&mut sessions, asked, from, read, ask)
            },
            |line| lines.push(line),
        )
        .unwrap();
        let readings = RECOVERY_READ_ON_READS + CARRY_PROOFS_MADE_AGAIN as u64;
        assert_eq!(clock.get(), readings * CARRY_READ_MAX_SECS);
        assert_eq!(*a_from.borrow(), [0, 10, 20, 30, 40]);
        assert_eq!(b_asked.get(), 5);
        let read_as = |relay: &str| {
            let of = said.iter().find(|of| of["relay"] == relay).unwrap();
            (read_as(of), entries_handed(of), of["why"].clone())
        };
        let made = "its 5 reads were made";
        let made_changed = format!("{made}, and its connection changed at the last");
        assert_eq!(read_as("a"), (ReadAs::Part, 50, json!(made)));
        assert_eq!(read_as("b"), (ReadAs::Nothing, 0, json!(made_changed)));
        let b = format!("  b: nothing of it was read: {made_changed}.");
        assert!(lines.contains(&b), "{lines:#?}");
        assert!(
            !lines
                .iter()
                .any(|line| line.starts_with("  b: read in part"))
        );
        // Before the yes, b is named with why.
        let was = WasRead::of(3, PersonalRead::of(&said), &[], 3);
        let line = &was.lines()[0];
        assert!(
            line.contains(&format!(
                "in part at a ({made}), and not at all at b ({made_changed})."
            )),
            "{line}"
        );
    }

    /// **What is said before the yes of a channel read in part says, for
    /// each relay read on, why its reading stopped, and nothing of how
    /// long it was read** (decision 2026-10-17 §3.3). Relay a is read in
    /// all its five readings and not to the end; b hands part of it in
    /// the first round and then says at every reading that its
    /// connection changed; c holds none of it at the second round. Each
    /// is named with its reason.
    #[test]
    fn test_what_is_said_of_a_read_in_part_says_why_each_relay_stopped() {
        let changed = cordelia_api::carrying::CONNECTION_CHANGED;
        let held = channel_of(100);
        let (_, said, _, _) = reads_on(|round, from| {
            let mut entries = Vec::new();
            let mut said = Vec::new();
            for relay in ["a", "b", "c"] {
                let (handed, mut of) = hands(relay, &held, from, 1);
                match (round, relay) {
                    (0, _) | (_, "a") => entries.extend(handed),
                    (_, "b") => of = json!({ "relay": "b", "read": changed, "entries": 0 }),
                    (_, _) => of = json!({ "relay": "c", "read": "not held", "entries": 0 }),
                }
                said.push(of);
            }
            (entries, said)
        });
        let read = PersonalRead::of(&said);
        let was = WasRead::of(3, read, &[], 3);
        let line = &was.lines()[0];
        assert!(
            line.starts_with(
                "The personal channel of change 3 was read to its end at no relay: in part at a \
                 (its 5 reads were made), b (its 5 reads were made, and its connection changed at \
                 the last), c (it holds none of it now). \
                 Devices added since that change, and names, may be missing from what was read. A \
                 relay that hands it more slowly than a channel at its largest needs, or stops, \
                 leaves it in part."
            ),
            "{line}"
        );
        assert!(!line.contains("minutes"), "{line}");
    }

    /// **A relay whose connection changed in the first round, and that
    /// holds none of the channel, is said to hold none of it** (decision
    /// 2026-10-17 §3.2, §3.3; §1, properties 10 and 11). Relay a holds two
    /// entries and hands them whole at the first reading; b says that its
    /// connection changed.
    ///
    /// - **b is read again within the first round,** alone and from the
    ///   start, as the read of today reads it, and holds none of it: no
    ///   line is said, nothing is read on, and nothing is said before the
    ///   yes. Every name not listed is then listed nowhere.
    /// - **Where its connection changes at every reading of the first
    ///   round,** it is read in the next, and only it is said to be read
    ///   again: the channel is not said to be larger than one read. There
    ///   it holds none of it, and is said to: it handed nothing.
    /// - **Where it is then not reached,** nothing of it was read, and it
    ///   is named before the yes with why.
    #[test]
    fn test_a_relay_whose_connection_changed_and_that_holds_none_is_said_to_hold_none() {
        let changed = cordelia_api::carrying::CONNECTION_CHANGED;
        let held = channel_of(2);
        let personal = |said: &[Value]| WasRead::of(3, PersonalRead::of(said), &[], 3);
        let b_said = |read: &str| json!({ "relay": "b", "read": read, "entries": 0 });
        // b's connection changed at the readings before `changes`, and it
        // says `then` at the reading after.
        let reads = |changes: usize, then: &'static str| {
            let held = held.clone();
            reads_on(move |round, from| match round {
                0 => {
                    let (handed, a) = hands("a", &held, from, 2);
                    (handed, vec![a, b_said(changed)])
                }
                n if n < changes => (Vec::new(), vec![b_said(changed)]),
                _ => (Vec::new(), vec![b_said(then)]),
            })
        };

        let (entries, said, asked, lines) = reads(1, "not held");
        assert_eq!(entries.len(), 2);
        assert_eq!(asked, [(None, vec![]), (asked_of(&["b"]), vec![])]);
        assert!(lines.is_empty(), "{lines:#?}");
        assert_eq!(
            said,
            [
                json!({ "relay": "a", "read": "whole", "entries": 2 }),
                json!({ "relay": "b", "read": "not held", "entries": 0 }),
            ]
        );
        let was = personal(&said);
        assert!(was.lines().is_empty(), "{:?}", was.lines());
        assert!(was.to_the_end());

        // Its connection changed at the three readings of the first round.
        let (_, said, asked, lines) = reads(3, "not held");
        assert_eq!(asked.len(), 4);
        assert_eq!(asked[3], (asked_of(&["b"]), vec![]));
        assert_eq!(
            lines,
            [
                "  b: its connection changed; it is read again from where it was.",
                "  b: it holds none of it.",
            ]
        );
        assert_eq!(
            said[1],
            json!({ "relay": "b", "read": "not held", "entries": 0 })
        );
        let was = personal(&said);
        assert!(was.lines().is_empty(), "{:?}", was.lines());
        assert!(was.to_the_end());

        // And then it was not reached.
        let (_, said, _, lines) = reads(3, "not reached");
        assert_eq!(
            lines[1..],
            ["  b: nothing of it was read: it was not reached."]
        );
        let was = personal(&said);
        assert_eq!(
            was.lines(),
            [
                "The personal channel of the change recovered from could not be read to its end at \
              b (it was not reached): devices added since that change, and names, may be missing \
              here."
            ]
        );
        assert!(!was.to_the_end());
    }

    // ── A relay out of reach (decision 2026-10-19 §4, rules 9 and 10) ──

    /// Two keys of relays, as a key is written.
    fn keys_ab() -> (String, String) {
        let written = |n: u8| cordelia_crypto::bech32::encode_public_key(&[n; 32]).unwrap();
        (written(0xa1), written(0xa2))
    }

    /// **The relays that a recovery read are those at which it read the
    /// personal channel to its end, each by the key of the connection
    /// that it read on** (decision 2026-10-19 §4, rule 10): a relay read
    /// in part, or that holds none of it, or not reached, is none of them,
    /// whatever its key. Read on, the key is that of the reading that
    /// reached the end.
    #[test]
    fn the_relays_that_a_recovery_read_are_those_read_to_their_end_by_their_keys() {
        let (a, b) = keys_ab();
        let read = PersonalRead::of(&[
            json!({ "relay": "one", "read": "whole", "entries": 2, "key": a }),
            json!({ "relay": "two", "read": "part", "entries": 1, "key": b }),
            json!({ "relay": "three", "read": "not held", "entries": 0, "key": b }),
            json!({ "relay": "four", "read": "whole", "entries": 2 }),
            json!({ "relay": "five", "read": "not reached", "entries": 0 }),
        ]);
        assert_eq!(read.read_by(), std::slice::from_ref(&a));
        // Each relay that the node said a key of is known by it.
        let asked = json!({ "relays": [
            { "relay": "one", "key": null },
            { "relay": "two", "key": null },
            { "relay": "four", "key": b },
            { "relay": "six", "key": null },
        ]});
        assert_eq!(
            relays_known(&asked, &read),
            [
                ("one".to_string(), Some(a.clone())),
                ("two".to_string(), Some(b.clone())),
                ("four".to_string(), Some(b.clone())),
                ("six".to_string(), None),
            ]
        );

        // Read on: in part on one connection, and then to its end on
        // another. The key is that of the reading that reached the end.
        let held = channel_of(4);
        let (_, said, _, _) = reads_on(|number, from| {
            let (handed, mut said) = hands("relay-one", &held, from, 2);
            said["key"] = if number == 0 { a.clone() } else { b.clone() }.into();
            (handed, vec![said])
        });
        assert_eq!(said[0]["read"], "whole");
        assert_eq!(said[0]["key"], b.as_str());
        assert_eq!(PersonalRead::of(&said).read_by(), std::slice::from_ref(&b));
        // Read to its end in the first round: by the key it was read on.
        let (_, said, _, _) = reads_on(|_, from| {
            let (handed, mut said) = hands("relay-one", &held, from, 4);
            said["key"] = a.clone().into();
            (handed, vec![said])
        });
        assert_eq!(PersonalRead::of(&said).read_by(), std::slice::from_ref(&a));
        // A relay read in part to the last keeps no key that it was read.
        let (_, said, _, _) = reads_on(|_, _| {
            let said = json!({ "relay": "relay-one", "read": "part", "entries": 0, "key": a });
            (Vec::new(), vec![said])
        });
        assert!(PersonalRead::of(&said).read_by().is_empty(), "{said:?}");
    }

    /// The one device of a recovery is judged by its words and the relays
    /// that the recovery read (decision 2026-10-19 §4, rule 10): where its
    /// carried word names a relay that was read, nothing is said of it,
    /// as for `sent`; where it names none, R3 is said in the place of the
    /// sentence that says that it was cut short, and handed on as that.
    #[test]
    fn a_recovery_says_nothing_of_a_device_whose_carried_word_names_a_relay_it_read() {
        let (a, b) = keys_ab();
        let word = CarriedWordLook {
            keys: vec![a.clone()],
            more: 0,
            not_yet: 1,
        };
        let generation = Generation {
            rows: rows(),
            cut_short: Some([1; 32]),
            carried_word: Some(word),
            ..Default::default()
        };
        let read_at = |key: &str| {
            was_read(&[json!({ "relay": "one", "read": "whole", "entries": 4, "key": key })])
        };
        let known = [("one".to_string(), Some(b.clone()))];
        // Read at the relay that the word names: not cut short.
        assert_eq!(CutShort::of(&generation, &read_at(&a), &[]), None);
        // Read at another: R3, by the name that this machine knows.
        let elsewhere = CutShort::of(&generation, &read_at(&b), &known).unwrap();
        let to = elsewhere.carried_to.clone().unwrap();
        assert_eq!(to.relays, 1);
        assert_eq!(to.held, format!("the relay whose key is {a}"));
        let says = elsewhere.says();
        assert!(
            says.starts_with("The device that this was recovered from"),
            "{says}"
        );
        assert!(!says.contains("cut short"), "{says}");
        let mut args = elsewhere.args();
        assert_eq!(
            args.split_off(4),
            [
                format!("--carried-to=the relay whose key is {a}"),
                "--carried-relays".to_string(),
                "1".to_string()
            ]
        );
        // A relay that this machine is set up with is named as it is.
        let known = [("relay-a.example:9474".to_string(), Some(a.clone()))];
        let named = CutShort::of(&generation, &read_at(&b), &known).unwrap();
        assert_eq!(named.carried_to.unwrap().held, "relay-a.example:9474");
        // The count of relays goes with the more that the word counts.
        let eight = CarriedWordLook {
            keys: (1..=8)
                .map(|n| cordelia_crypto::bech32::encode_public_key(&[n; 32]).unwrap())
                .collect(),
            more: 2,
            not_yet: 0,
        };
        assert_eq!(CarriedTo::of(&eight, &[]).relays, 10);
        // What is judged before the yes, of what the node said: R2 where
        // no relay that the word names was read, and nothing where one was.
        let asked = json!({ "relays": [{ "relay": "one", "key": null }] });
        let (cut, r2) = judged_before_the_yes(&generation, &read_at(&b), &asked);
        assert_eq!(cut, Some(elsewhere.clone()));
        let r2 = r2.unwrap();
        assert!(
            r2.starts_with(&format!("{} wrote that it had sent", elsewhere.device)),
            "{r2}"
        );
        assert!(
            r2.contains(&format!("set up the relay whose key is {a}")),
            "{r2}"
        );
        assert_eq!(
            judged_before_the_yes(&generation, &read_at(&a), &asked),
            (None, None)
        );
        // With no word, the sentences of today.
        let no_word = Generation {
            carried_word: None,
            ..generation.clone()
        };
        let cut = CutShort::of(&no_word, &read_at(&b), &known).unwrap();
        assert_eq!(cut.carried_to, None);
        assert!(cut.says().contains("was cut short"), "{}", cut.says());
        let (cut, r2) = judged_before_the_yes(&no_word, &read_at(&b), &asked);
        assert!(cut.is_some() && r2.is_none());
    }

    /// R0 to R3, word for word (decision 2026-10-19 §5), R2 with both of
    /// its endings, and R2 said with the lines that say how the personal
    /// channel was read, before the yes.
    #[test]
    fn r0_to_r3_word_for_word() {
        let (a, b) = keys_ab();
        assert_eq!(
            wait::recovery_first_line(),
            "This command stays until every relay holds the change. It ends sooner, with status \
             3, once each relay that is not known to hold it cannot be reached, or refuses it, \
             for five minutes. Stopping it stops nothing: the node goes on, and the recovery \
             stays made."
        );
        assert_eq!(
            wait::recovery_end_lines(RecoveryEnd::Recovered, &[], 0),
            ["Every relay holds the change."]
        );

        let laptop = "(w1 w2 w3 w4) \"laptop\"";
        let one = CarriedWordLook {
            keys: vec![a.clone()],
            more: 0,
            not_yet: 1,
        };
        // R2, where this machine is set up with the relay that the word
        // names, and did not read it.
        let set_up = [
            ("a.example:9474".to_string(), Some(a.clone())),
            ("b.example:9474".to_string(), Some(b.clone())),
        ];
        assert_eq!(
            carried_elsewhere_says(laptop, &one, &set_up),
            "(w1 w2 w3 w4) \"laptop\" wrote that it had sent what it carried to a.example:9474. \
             It had not yet sent it to 1 other relay that it was set up with. This machine has \
             read none of it. The look of this recovery is made once, so what that device \
             carried may be only there. To bring it in by this recovery, answer no. Make sure \
             this machine can reach a.example:9474, and run `cordelia recover` again. If you \
             answer yes, it comes in later only by `cordelia sync carry <name> --from \
             <device>`, with the phrase, once this machine reaches a.example:9474."
        );
        // R2, where it is not set up with any relay that the word names.
        let two = CarriedWordLook {
            keys: vec![a.clone(), b.clone()],
            more: 0,
            not_yet: 0,
        };
        let c = cordelia_crypto::bech32::encode_public_key(&[9; 32]).unwrap();
        let elsewhere = [("c.example:9474".to_string(), Some(c))];
        assert_eq!(
            carried_elsewhere_says(laptop, &two, &elsewhere),
            format!(
                "(w1 w2 w3 w4) \"laptop\" wrote that it had sent what it carried to the relay \
                 whose key is {a} and the relay whose key is {b}. This machine has read none of \
                 them. The look of this recovery is made once, so what that device carried may \
                 be only there. To bring it in by this recovery, answer no. On this machine, set \
                 up the relay whose key is {a}: the configuration of that device (its \
                 `[[network.bootnodes]]`) names it. Then run `cordelia recover` again. If you \
                 answer yes, it comes in later only by `cordelia sync carry <name> --from \
                 <device>`, with the phrase, once this machine reaches that relay."
            )
        );
        // R2, where it is set up with a relay that it is given no key for
        // and did not reach: that may be the relay the word names.
        let keyless = [
            ("c.example:9474".to_string(), None),
            ("d.example:9474".to_string(), None),
        ];
        for (relays, may_be) in [(&keyless[..1], "that one"), (&keyless[..], "one of them")] {
            let names = match relays.len() {
                1 => "c.example:9474",
                _ => "c.example:9474 and d.example:9474",
            };
            assert_eq!(
                carried_elsewhere_says(laptop, &one, relays),
                format!(
                    "(w1 w2 w3 w4) \"laptop\" wrote that it had sent what it carried to the relay \
                     whose key is {a}. It had not yet sent it to 1 other relay that it was set up \
                     with. This machine has read none of it. The look of this recovery is made \
                     once, so what that device carried may be only there. To bring it in by this \
                     recovery, answer no. Make sure this machine can reach {names}: the relay \
                     whose key is {a} may be {may_be}. If it is not, set it up on this machine: \
                     the configuration of that device (its `[[network.bootnodes]]`) names it. \
                     Then run `cordelia recover` again. If you answer yes, it comes in later only \
                     by `cordelia sync carry <name> --from <device>`, with the phrase, once this \
                     machine reaches that relay."
                )
            );
        }
        // Two relays not yet, and more relays counted.
        let more = CarriedWordLook {
            keys: (1..=8)
                .map(|n| cordelia_crypto::bech32::encode_public_key(&[n; 32]).unwrap())
                .collect(),
            more: 2,
            not_yet: 2,
        };
        let said = carried_elsewhere_says(laptop, &more, &elsewhere);
        assert!(said.contains(" and 2 more."), "{said}");
        assert!(
            said.contains("It had not yet sent it to 2 other relays that it was set up with."),
            "{said}"
        );
        assert!(
            said.contains("This machine has read none of them."),
            "{said}"
        );

        // R3, of one relay and of two.
        let r3 = |held: &str, relays: u64| {
            let carried_to = Some(CarriedTo {
                held: held.into(),
                relays,
            });
            let device = laptop.to_string();
            let read = ChannelRead::Whole;
            CutShort {
                device,
                read,
                carried_to,
            }
            .says()
        };
        assert_eq!(
            r3("a.example:9474", 1),
            "The device that this was recovered from, (w1 w2 w3 w4) \"laptop\", wrote that it \
             had sent what it carried to a.example:9474. This recovery did not read it. What it \
             carried that is not here is there. Once this machine reaches it, `cordelia sync \
             carry <name> --from <device>` brings it in, with the phrase."
        );
        assert_eq!(
            r3("a.example:9474 and b.example:9474", 2),
            "The device that this was recovered from, (w1 w2 w3 w4) \"laptop\", wrote that it \
             had sent what it carried to a.example:9474 and b.example:9474. This recovery did not \
             read them. What it carried that is not here is there. Once this machine reaches \
             them, `cordelia sync carry <name> --from <device>` brings it in, with the phrase."
        );

        // R2 comes with the lines that say how the personal channel was
        // read, after them, and before the lines of the names left.
        let generation = Generation {
            rows: rows(),
            ..Default::default()
        };
        let names = recover::Names {
            carried: vec!["lab".into()],
            over_the_bound: vec!["beyond".into()],
            ..Default::default()
        };
        let read = was_read(&[
            json!({ "relay": "one", "read": "whole", "entries": 4 }),
            json!({ "relay": "two", "read": "not reached", "entries": 0 }),
        ]);
        let r2 = carried_elsewhere_says(laptop, &one, &set_up);
        let lines = will_do_lines(&generation, &[], &names, &[9; 32], &read, Some(&r2));
        let at = |says: &str| lines.iter().position(|line| line.contains(says)).unwrap();
        let was = at("could not be read to its end at two");
        assert_eq!(at(&r2), was + 1, "{lines:?}");
        assert!(at("beyond the") > at(&r2), "{lines:?}");
        let without = will_do_lines(&generation, &[], &names, &[9; 32], &read, None);
        assert_eq!(without.len() + 1, lines.len());
    }

    /// What stands in for the node once a recovery's change is made: the
    /// progress of its look, and the looks it gives, one after another,
    /// the last again.
    struct Stands {
        progress: Value,
        looks: std::cell::RefCell<Vec<Value>>,
        fails: bool,
        asked: std::cell::Cell<usize>,
        version: Option<String>,
    }

    impl Stands {
        fn of(progress: Value, looks: Vec<Value>) -> Self {
            Self {
                progress,
                looks: std::cell::RefCell::new(looks),
                fails: false,
                asked: std::cell::Cell::new(0),
                version: None,
            }
        }
    }

    impl AfterTheChange for Stands {
        fn progress(&self) -> anyhow::Result<Value> {
            Ok(self.progress.clone())
        }
        fn sync_status(&self) -> Option<Value> {
            None
        }
        fn another_version(&self) -> anyhow::Result<Option<String>> {
            Ok(self.version.clone())
        }
        fn look(&self) -> anyhow::Result<Value> {
            // A wait that would never end fails the test at once.
            self.asked.set(self.asked.get() + 1);
            if self.asked.get() > 100 {
                anyhow::bail!("the wait did not end");
            }
            let mut looks = self.looks.borrow_mut();
            if self.fails && looks.len() == 1 {
                anyhow::bail!("the node did not answer");
            }
            match looks.len() {
                1 => Ok(looks[0].clone()),
                _ => Ok(looks.remove(0)),
            }
        }
        fn pause(&self) {}
    }

    /// A look after change 3 whose relays met the events of each scenario,
    /// built by the node's own functions, with this machine's own word
    /// none and no word to come: a look that stays pending.
    fn looked(scenarios: &[wait::tests::Scenario]) -> Value {
        use wait::tests::{look_at, reached};
        let relays: Vec<_> = scenarios.iter().map(|s| (*s, reached(*s))).collect();
        look_at(&relays, wait::OwnWord::None, false)
    }

    /// The look of change 3 has ended.
    fn finished(new_not_read: bool) -> Value {
        json!({ "look": {
            "change": 3, "finished": true, "new_not_read": new_not_read,
            "names": 1, "carried": 1, "carried_names": 1,
        }})
    }

    /// What a recovery's command says once its change is made, and how it
    /// ends, where the node is `node`.
    fn after(node: &Stands) -> (anyhow::Result<Recovered>, Vec<String>) {
        let mut said = Vec::new();
        let ended = after_the_recovery(3, None, node, |line| said.push(line));
        (ended, said)
    }

    /// **A recovery whose look stays pending ends at 3** (decision
    /// 2026-10-19 §4, rule 9; its first review, finding 6). The look says
    /// that the new channels were not read whole, so it stays pending,
    /// and neither `sent` nor the carried word is written. One relay is
    /// out of reach, and lacks the change: the wait ends, with S8, S9 and
    /// S10, and status 3, and never says that the machine may be closed.
    /// Where every relay holds the change, it ends at R1, with status 0,
    /// though the look stays pending: there is no condition on the word.
    #[test]
    fn a_recovery_whose_look_stays_pending_ends_at_3() {
        use wait::tests::Scenario::{Ok as Reached, OutHolding, OutLacking};
        let node = Stands::of(finished(true), vec![looked(&[Reached, OutLacking])]);
        let (ended, said) = after(&node);
        let all = said.join("\n");
        assert_eq!(ended.unwrap(), Recovered::Ended(RecoveryEnd::NotDone));
        assert_eq!(recovered_status(&after(&node).0), 3);
        assert!(all.contains("The look took nothing"), "{all}");
        assert!(all.contains(&wait::recovery_first_line()), "{all}");
        assert!(
            all.contains("  relay-1.example:9474 is not known to hold the change, and has not"),
            "{all}"
        );
        assert!(
            all.contains("A device of yours that reaches only relay-1.example:9474 may not have"),
            "{all}"
        );
        assert!(
            said.last().unwrap().starts_with(
                "The change is not known to be at relay-1.example:9474. This command ends here, \
                 with status 3."
            ),
            "{all}"
        );
        // S8 only of the relay that lacks it.
        assert!(!all.contains("relay-0.example:9474 holds"), "{all}");
        assert!(!all.contains("may be closed"), "{all}");
        assert!(!all.contains("You may close"), "{all}");

        // Every relay holds the change, one out of reach: R1, status 0,
        // and no R0.
        let node = Stands::of(finished(true), vec![looked(&[Reached, OutHolding])]);
        let (ended, said) = after(&node);
        assert_eq!(ended.unwrap(), Recovered::Ended(RecoveryEnd::Recovered));
        assert_eq!(said.last().unwrap(), "Every relay holds the change.");
        assert!(!said.contains(&format!("\n{}", wait::recovery_first_line())));
    }

    /// **A recovery waits for the change at each relay** (decision
    /// 2026-10-19 §4, rule 9). Where a relay does not hold it when the
    /// look has ended, it says R0, then S2 and S3 as they come, and ends
    /// at the first of its two ends: every relay holds the change (R1); or
    /// each relay that lacks it is OUT and lacking, or REFUSING. A relay
    /// that lacks it and is in no class yet holds the wait; one that holds
    /// it is asked nothing, whatever waits there.
    #[test]
    fn a_recovery_waits_for_the_change_at_each_relay() {
        use wait::tests::Scenario::{
            Dialling, LacksForAMoment, Moving, Ok as Reached, OutHolding, OutLacking, Refusing,
            Stuck,
        };
        // A relay that is dialled, and then out of reach: R0, then S3 and
        // S2 as they come, each once, then the end, with S8 only of the
        // relay that lacks the change.
        let node = Stands::of(
            finished(false),
            vec![
                looked(&[Reached, Dialling]),
                looked(&[OutHolding, Dialling]),
                looked(&[OutHolding, Dialling]),
                looked(&[OutHolding, OutLacking]),
            ],
        );
        let (ended, said) = after(&node);
        assert_eq!(ended.unwrap(), Recovered::Ended(RecoveryEnd::NotDone));
        let at = |says: &str| {
            let at = said.iter().position(|line| line.starts_with(says));
            at.unwrap_or_else(|| panic!("{says}: {said:?}"))
        };
        let r0 = at("\nThis command stays until every relay holds");
        let s3 = at("  relay-0.example:9474 holds the change, and ");
        let s2 = at(
            "  keep this machine on: relay-1.example:9474 is not known to hold the change yet, \
             and ",
        );
        assert!(r0 < s3 && s3 < s2, "{said:?}");
        let once = |says: &str| said.iter().filter(|line| line.starts_with(says)).count();
        assert_eq!(
            once("  relay-0.example:9474 holds the change"),
            1,
            "{said:?}"
        );
        assert_eq!(once("  keep this machine on: relay-1"), 1, "{said:?}");
        assert_eq!(
            once("  relay-1.example:9474 is not known to hold the change, and"),
            1
        );
        assert_eq!(
            once("  relay-0.example:9474 holds the change."),
            0,
            "{said:?}"
        );
        // A relay that refuses the change, beside one that holds it and
        // refuses what waits: not done, S8 of the one that refuses.
        let node = Stands::of(finished(false), vec![looked(&[Stuck, Refusing])]);
        let (ended, said) = after(&node);
        assert_eq!(ended.unwrap(), Recovered::Ended(RecoveryEnd::NotDone));
        let all = said.join("\n");
        assert!(
            all.contains("relay-1.example:9474 is reached, and has not taken the change"),
            "{all}"
        );
        assert!(
            !all.contains("relay-0.example:9474 holds the change. It has refused"),
            "{all}"
        );
        // Every relay holds the change, whatever waits: R1.
        for holding in [[Reached, Stuck], [Moving, OutHolding]] {
            let node = Stands::of(finished(false), vec![looked(&holding)]);
            let (ended, said) = after(&node);
            assert_eq!(
                ended.unwrap(),
                Recovered::Ended(RecoveryEnd::Recovered),
                "{said:?}"
            );
        }
        // A relay that lacks it for a moment, and then holds it: R0, then
        // R1.
        let node = Stands::of(
            finished(false),
            vec![
                looked(&[Reached, LacksForAMoment]),
                looked(&[Reached, Reached]),
            ],
        );
        let (ended, said) = after(&node);
        assert_eq!(ended.unwrap(), Recovered::Ended(RecoveryEnd::Recovered));
        assert!(
            said.iter()
                .any(|line| line.contains("This command stays until")),
            "{said:?}"
        );
        assert_eq!(said.last().unwrap(), "Every relay holds the change.");
        // No relay reached, none holding: S11, with its second part.
        let node = Stands::of(finished(false), vec![looked(&[OutLacking])]);
        let (_, said) = after(&node);
        assert!(
            said.last().unwrap().starts_with(
                "No relay can be reached from here. None is known to hold the change."
            ),
            "{said:?}"
        );
    }

    /// The statuses of a recovery once its change is made (decision
    /// 2026-10-19 §4, rule 9): 0 only where every relay holds the change;
    /// 3 where its wait ends not done, where the device has since applied
    /// another change, where the look cannot be waited for, and on an
    /// error during the wait.
    #[test]
    fn the_statuses_of_a_recovery() {
        use wait::tests::Scenario::{Ok as Reached, OutLacking};
        assert_eq!(
            recovered_status(&Ok(Recovered::Ended(RecoveryEnd::Recovered))),
            0
        );
        assert_eq!(
            recovered_status(&Ok(Recovered::Ended(RecoveryEnd::NotDone))),
            3
        );
        assert_eq!(recovered_status(&Ok(Recovered::Another)), 3);
        assert_eq!(recovered_status(&Ok(Recovered::NoLongerStands)), 3);
        assert_eq!(recovered_status(&Err(anyhow::anyhow!("no node"))), 3);
        let (said, status) = look_not_waited_for(&"it was moved");
        assert_eq!(status, 3);
        assert!(said.contains("(it was moved)"), "{said}");
        // Another change since.
        let mut another = looked(&[Reached, Reached]);
        another["change"] = 4.into();
        let node = Stands::of(finished(false), vec![another]);
        let (ended, said) = after(&node);
        assert_eq!(ended.unwrap(), Recovered::Another);
        assert!(
            said.last()
                .unwrap()
                .contains("since applied another change")
        );
        // The device no longer stands in its phrase: its node shows the
        // change to no relay, and no end would hold.
        let mut removed = looked(&[Reached, OutLacking]);
        removed["state"] = "removed".into();
        removed["cannot_go_on"] = "this device was removed".into();
        let node = Stands::of(finished(false), vec![removed]);
        let (ended, said) = after(&node);
        assert_eq!(ended.unwrap(), Recovered::NoLongerStands);
        assert!(
            said.last().unwrap().starts_with(
                "This device no longer stands in its phrase (this device was removed)"
            ),
            "{said:?}"
        );
        // The node stops answering during the wait.
        let mut node = Stands::of(
            finished(false),
            vec![
                looked(&[Reached, OutLacking]),
                looked(&[Reached, OutLacking]),
            ],
        );
        node.looks.borrow_mut()[0] = looked(&[Reached, wait::tests::Scenario::Dialling]);
        node.fails = true;
        let (ended, _) = after(&node);
        assert!(ended.is_err());
        assert_eq!(recovered_status(&ended), 3);
        // The error is said apart, with that the change is made.
        node.looks = std::cell::RefCell::new(vec![
            looked(&[Reached, wait::tests::Scenario::Dialling]),
            looked(&[Reached, OutLacking]),
        ]);
        let mut errors = Vec::new();
        let status = recovery_status(3, None, &node, |_| {}, |line| errors.push(line));
        assert_eq!(status, 3);
        assert_eq!(
            errors,
            [wait::could_not_go_on(
                3,
                &anyhow::anyhow!("the node did not answer")
            )]
        );
        // And nothing is said apart where the wait ends.
        let node = Stands::of(finished(false), vec![looked(&[Reached, OutLacking])]);
        let mut errors = Vec::new();
        assert_eq!(
            recovery_status(3, None, &node, |_| {}, |line| errors.push(line)),
            3
        );
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// **A recovery gives no R1 and no status 0 on classes that are not of
    /// its change** (decision 2026-10-19 §4, rule 9, as rule 8 has it):
    /// where every look's relays are about the entry kept before, the wait
    /// never says R1, and ends at the stand-in's bound as an error; where
    /// one look is stale and the next is of the change, it says R0 and then
    /// R1. **A look that cannot be read, or a node of another version,
    /// ends it with status 3,** with the error said apart.
    #[test]
    fn a_recovery_ends_only_on_classes_of_its_change_and_with_3_on_what_it_cannot_read() {
        use wait::tests::Scenario::{Ok as Reached, OutHolding, OutLacking};
        let stale = || {
            let mut seen = looked(&[Reached, OutHolding]);
            seen["latest"] = hex::encode([2u8; 32]).into();
            seen
        };
        let node = Stands::of(finished(false), vec![stale()]);
        let (ended, said) = after(&node);
        assert!(ended.is_err(), "{said:?}");
        assert!(
            !said
                .iter()
                .any(|line| line == "Every relay holds the change."),
            "{said:?}"
        );
        let node = Stands::of(
            finished(false),
            vec![stale(), stale(), looked(&[Reached, OutHolding])],
        );
        let (ended, said) = after(&node);
        assert_eq!(ended.unwrap(), Recovered::Ended(RecoveryEnd::Recovered));
        assert!(
            said.iter()
                .any(|line| line.contains("This command stays until")),
            "{said:?}"
        );
        assert_eq!(said.last().unwrap(), "Every relay holds the change.");
        // S2 and S3 are not said of a reach about the entry before: there
        // the relay held the entry kept before, and is out of reach.
        let mut one = looked(&[Reached, OutHolding]);
        one["relays"][1]["reach"]["about"] = hex::encode([2u8; 32]).into();
        let node = Stands::of(
            finished(false),
            vec![one.clone(), looked(&[Reached, OutLacking])],
        );
        let (_, said) = after(&node);
        let s3 = "  relay-1.example:9474 holds the change, and ";
        assert!(!said.iter().any(|line| line.starts_with(s3)), "{said:?}");
        let s2 = "  keep this machine on: relay-1.example:9474 is not known to hold";
        assert_eq!(
            said.iter().filter(|line| line.starts_with(s2)).count(),
            1,
            "{said:?}"
        );
        // A look whose relay cannot be read: status 3, with the error.
        let mut unread = looked(&[Reached, OutLacking]);
        unread["relays"][1]["reach"] = "what this command cannot read".into();
        let node = Stands::of(finished(false), vec![unread]);
        let mut errors = Vec::new();
        let status = recovery_status(3, None, &node, |_| {}, |line| errors.push(line));
        assert_eq!(status, 3);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("relay-1.example:9474"), "{errors:?}");
        // A node of another version: status 3, whatever its look says.
        let mut node = Stands::of(finished(false), vec![looked(&[Reached, Reached])]);
        node.version = Some("the node is of another version".into());
        let mut errors = Vec::new();
        let status = recovery_status(3, None, &node, |_| {}, |line| errors.push(line));
        assert_eq!(status, 3);
        assert!(
            errors[0].contains("the node is of another version"),
            "{errors:?}"
        );
    }
}
